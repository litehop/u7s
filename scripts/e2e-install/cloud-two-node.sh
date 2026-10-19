#!/usr/bin/env bash
# Two-node install + join on real GCP networking, from the published mirror.
#
# Usage: cloud-two-node.sh --release <tag> [--keep]
#   --release  mirror tag to install (https://u7s.dekiru.tech/<tag>/install.sh); needs a release
#              whose install.sh has --mint-join-token
#   --keep     leave every VPS this run created up and print how to reach them
#
# Creates VPSes cp and w1 (plus client when the release bundles beep), installs on cp, mints a
# join token there and passes it to w1 on stdin, then asserts in order: both nodes Ready; a pod
# pinned to w1 Running; logs/exec on it (apiserver -> InternalIP:10250); cross-node pod-to-pod;
# webhook-smoke.sh; and, with beep, that a LoadBalancer Service answers from the client VPS
# with its internal IP preserved. Without --keep only the VPSes this run created are deleted.
# Exit: 0 PASS, 1 FAIL, 2 usage, 3 PREEMPTED. Results: temp/e2e-install/<ts>/.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
GCP="$ROOT/scripts/gcp"
# shellcheck source=../gcp/lib.sh
. "$GCP/lib.sh"

usage() { sed -n '2,6p' "$0" >&2; exit 2; }

RELEASE=
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --release) [ $# -ge 2 ] || usage; RELEASE="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) usage ;;
  esac
done
[[ "$RELEASE" =~ ^v[0-9][0-9A-Za-z._-]*$ ]] || usage

TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ID="${U7S_E2E_RUN_ID:-$(date -u +%m%d%H%M%S)-$$}"
OUT="${U7S_E2E_RESULTS_DIR:-$ROOT/temp/e2e-install/$TS}"
SLEEP="${U7S_E2E_POLL_SLEEP:-10}"
CP="u7s-e2e-$RUN_ID-cp"
W1="u7s-e2e-$RUN_ID-w1"
CLIENT="u7s-e2e-$RUN_ID-client"
INSTALL_URL="https://u7s.dekiru.tech/$RELEASE/install.sh"
KC="sudo kubectl --kubeconfig /var/lib/u7s/kubeconfig"
AGNHOST=registry.k8s.io/e2e-test-images/agnhost:2.63.0

gcp_require_config
PROJECT="$(gcloud config get-value project 2>/dev/null)"
redact() { sed "s|$PROJECT|<project>|g"; }

mkdir -p "$OUT"
exec > >(redact | tee "$OUT/run.log") 2>&1

gcp_print_target | sed 's/^target: .*/target: <redacted>/'
echo "results: $OUT"
ZONE="$(gcp_zone)"

CREATED=()
RESULT=FAIL

vps() { "$GCP/vps.sh" "$@"; }
on_cp() { vps ssh "$CP" -- "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# step NAME cmd...: runs cmd (stdin passes through), keeping its output in $OUT/NAME.log.
step() {
  local name="$1"; shift
  if "$@" 2>&1 | redact >"$OUT/$name.log"; then
    echo "PASS: $name"
  else
    tail -n 20 "$OUT/$name.log" >&2
    fail "$name (full output: $OUT/$name.log)"
  fi
}

finish() {
  local rc=$? v
  trap - EXIT
  if [ "$rc" = 0 ]; then
    RESULT=PASS
  else
    for v in ${CREATED[@]+"${CREATED[@]}"}; do
      if gcp_vps_was_preempted "$v"; then RESULT=PREEMPTED; rc=3; break; fi
    done
  fi
  echo "$RESULT" >"$OUT/result.txt"
  echo "RESULT: $RESULT"
  for v in ${CREATED[@]+"${CREATED[@]}"}; do
    if [ "$KEEP" = 1 ]; then
      echo "kept: scripts/gcp/vps.sh ssh $v"
    else
      vps down "$v" || echo "warning: could not delete $v; check scripts/gcp/vps.sh list" >&2
    fi
  done
  [ "$KEEP" = 0 ] || echo "kubeconfig on $CP: /var/lib/u7s/kubeconfig (sudo kubectl --kubeconfig /var/lib/u7s/kubeconfig ...)"
  exit "$rc"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

up() {
  local n="$1"
  CREATED+=("$n")
  vps up "$n" 2>&1 | redact >"$OUT/up-$n.log" || fail "creating $n (see $OUT/up-$n.log)"
  for _ in $(seq 1 30); do
    vps ssh "$n" -- true >/dev/null 2>&1 && return 0
    sleep "$SLEEP"
  done
  fail "$n never became reachable over IAP ssh"
}

internal_ip() {
  gcloud compute instances describe "$1" --zone="$ZONE" --format='value(networkInterfaces[0].networkIP)'
}

pod_yaml() { # name node
  cat <<YAML
apiVersion: v1
kind: Pod
metadata: {name: $1, labels: {app: $1}}
spec:
  nodeName: $2
  containers:
  - {name: c, image: $AGNHOST, args: [netexec, --http-port=8080]}
YAML
}

# The join token only ever travels on stdin: never in argv, a log or the results directory.
join_w1() { printf '%s\n' "$1" | vps ssh "$W1" -- sudo bash /tmp/install.sh --join "https://$CP_IP:6443" --token - --ca-cert-hash "$2" --node-name "$W1"; }
apply_pods() { { pod_yaml pin "$W1"; echo ---; pod_yaml peer "$CP_NODE"; } | on_cp "$KC apply -f -"; }
webhook_smoke() {
  vps scp "$ROOT/scripts/e2e-workload/webhook-smoke.sh" "$CP:/tmp/webhook-smoke.sh" &&
    on_cp sudo bash /tmp/webhook-smoke.sh --kubeconfig /var/lib/u7s/kubeconfig
}
apply_lb() {
  {
    pod_yaml lb-backend "$W1"
    printf -- '---\napiVersion: v1\nkind: Service\nmetadata: {name: lb}\nspec:\n  type: LoadBalancer\n  selector: {app: lb-backend}\n  ports: [{port: 80, targetPort: 8080}]\n'
  } | on_cp "$KC apply -f -"
}

up "$CP"
up "$W1"
CP_IP="$(internal_ip "$CP")"
W1_IP="$(internal_ip "$W1")"
echo "cp=$CP ($CP_IP) w1=$W1"

step install-cp on_cp "curl -fsSL $INSTALL_URL -o /tmp/install.sh && sudo bash /tmp/install.sh"

mint="$(on_cp sudo bash /tmp/install.sh --mint-join-token)" || fail "mint-join-token on $CP"
token="$(sed -n 's/^Join token created.*: //p' <<<"$mint")"
ca_hash="$(grep -oE 'sha256:[0-9a-f]{64}' <<<"$mint" | head -1)" || true
unset mint
[ -n "$token" ] && [ -n "$ca_hash" ] || fail "could not parse the join token and CA hash from --mint-join-token output"

step fetch-w1 vps ssh "$W1" -- "curl -fsSL $INSTALL_URL -o /tmp/install.sh"
step join-w1 join_w1 "$token" "$ca_hash"
unset token

# The control plane registers under its hostname, which GCP makes an FQDN, so look the node up
# by the internal IP rather than assuming it is named like the VPS.
CP_NODE="$(on_cp "$KC get nodes -o wide --no-headers" | awk -v ip="$CP_IP" '$6 == ip {print $1}')"
[ -n "$CP_NODE" ] || fail "no node with InternalIP $CP_IP registered on $CP"
[ "$(wc -l <<<"$CP_NODE")" -eq 1 ] || fail "multiple nodes with InternalIP $CP_IP registered on $CP: $(tr '\n' ' ' <<<"$CP_NODE")"

step nodes-ready on_cp "$KC wait --for=condition=Ready node/$CP_NODE node/$W1 --timeout=300s"
step apply-pods apply_pods
step pinned-pod-running on_cp "$KC wait --for=condition=Ready pod/pin pod/peer --timeout=300s"
step logs-exec on_cp "$KC logs pin | grep -q . && $KC exec pin -- /agnhost hostname"
step cross-node-pod-to-pod on_cp "$KC exec peer -- /agnhost connect \$($KC get pod pin -o jsonpath='{.status.podIP}'):8080 --timeout=10s"
step webhook-smoke webhook_smoke

daemonsets="$(on_cp "$KC -n kube-system get ds -o name" 2>/dev/null)" || fail "listing kube-system DaemonSets on $CP"
if ! grep -qx 'daemonset.apps/servicelb-controller' <<<"$daemonsets"; then
  echo "SKIPPED: loadbalancer (release $RELEASE does not bundle beep)"
  exit 0
fi

up "$CLIENT"
CLIENT_IP="$(internal_ip "$CLIENT")"
step lb-backend apply_lb

ingress=
for _ in $(seq 1 30); do
  ingress="$(on_cp "$KC get svc lb -o jsonpath='{.status.loadBalancer.ingress[*].ip}'" 2>/dev/null)" || ingress=
  [ -n "$ingress" ] && break
  sleep "$SLEEP"
done
[ -n "$ingress" ] || fail "Service lb never got a LoadBalancer ingress IP"
echo "ingress IPs: $ingress; client $CLIENT ($CLIENT_IP)"
for node_ip in "$CP_IP" "$W1_IP"; do
  case " $ingress " in
    *" $node_ip "*) ;;
    *) fail "LoadBalancer ingress ($ingress) lacks node IP $node_ip; the via-pod-less-node path is untested" ;;
  esac
done
for ip in $ingress; do
  seen="$(vps ssh "$CLIENT" -- curl -fsS --max-time 15 "http://$ip/clientip")" || fail "curl http://$ip from $CLIENT"
  [ "${seen%:*}" = "$CLIENT_IP" ] || fail "backend saw client ${seen%:*} via $ip, expected $CLIENT_IP"
  echo "PASS: lb $ip answered and saw client $CLIENT_IP"
done

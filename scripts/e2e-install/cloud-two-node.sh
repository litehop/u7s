#!/usr/bin/env bash
# Two-node install + join on real GCP networking, from the published mirror.
#
# Usage: cloud-two-node.sh --release <tag> [--keep] [--dual-stack] [--machine-type <type>]
#   --release       mirror tag to install (https://u7s.dekiru.tech/<tag>/install.sh); needs a release
#                   whose install.sh has --mint-join-token
#   --keep          leave every VPS this run created up and print how to reach them
#   --dual-stack    IPv4+IPv6 cluster on IPV4_IPV6 VPSes (dual --cluster-cidr/--service-cidr; install.sh
#                   derives both node addresses from --iface), asserts both families end to end, needs
#                   beep, and finishes with the upstream IPv6DualStack sonobuoy focus
#   --machine-type  VPS machine type (default e2-micro; e2-standard-2 with --dual-stack, whose
#                   sonobuoy subset saturates e2-micro)
#
# Creates VPSes cp and w1 (plus client when the release bundles beep), installs on cp, mints a
# join token there and passes it to w1 on stdin, then asserts in order: both nodes Ready; a pod
# pinned to w1 Running; logs/exec on it (apiserver -> InternalIP:10250); cross-node pod-to-pod;
# webhook-smoke.sh; and, with beep, that a LoadBalancer Service answers from the client VPS
# with its internal IP preserved. Without --keep only the VPSes (and, with --dual-stack, the narrow
# IPv6 LoadBalancer firewall rule) this run created are deleted.
# Exit codes: see "Release-gate exit codes" in docs/dev-setup.md. INVALID here is a failure whose
# preemption lookup kept erroring. Results: temp/e2e-install/<ts>/.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
GCP="$ROOT/scripts/gcp"
# shellcheck source=../gcp/lib.sh
. "$GCP/lib.sh"

usage() { sed -n '2,11p' "$0" >&2; exit 2; }

RELEASE=
KEEP=0
DUAL=0
MACHINE_TYPE=
while [ $# -gt 0 ]; do
  case "$1" in
    --release) [ $# -ge 2 ] || usage; RELEASE="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --dual-stack) DUAL=1; shift ;;
    --machine-type) [ $# -ge 2 ] || usage; MACHINE_TYPE="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$RELEASE" =~ ^v[0-9][0-9A-Za-z._-]*$ ]] || usage
[ -z "$MACHINE_TYPE" ] || [[ "$MACHINE_TYPE" =~ ^[a-z0-9][a-z0-9-]*$ ]] || usage
[ -n "$MACHINE_TYPE" ] || { [ "$DUAL" = 1 ] && MACHINE_TYPE=e2-standard-2; } || true
[ -z "$MACHINE_TYPE" ] || export U7S_GCP_MACHINE_TYPE="$MACHINE_TYPE"

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
DNSUTILS=registry.k8s.io/e2e-test-images/jessie-dnsutils:1.7
DUAL_CLUSTER_CIDR=10.244.0.0/16,fd00:244::/56
DUAL_SERVICE_CIDR=10.96.0.0/12,fd00:96::/108
LB_PORT=80
SONOBUOY_VERSION="${U7S_E2E_SONOBUOY_VERSION:-0.57.3}"
SONOBUOY_FOCUS='IPv6DualStack|dual-stack|DualStack|ipFamilyPolicy'
SONOBUOY_POLLS="${U7S_E2E_SONOBUOY_POLLS:-360}"
SB="sudo sonobuoy --kubeconfig /var/lib/u7s/kubeconfig"

gcp_require_config
PROJECT="$(gcloud config get-value project 2>/dev/null)"
redact() { sed "s|$PROJECT|<project>|g"; }

mkdir -p "$OUT"
exec > >(redact | tee "$OUT/run.log") 2>&1

gcp_print_target | sed 's/^target: .*/target: <redacted>/'
echo "results: $OUT"
ZONE="$(gcp_zone)"

CREATED=()
FW_RULE=
STACK_ARGS=()
[ "$DUAL" = 0 ] || STACK_ARGS=(--stack-type IPV4_IPV6)
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
  local rc=$? v pre
  trap - EXIT
  if [ "$rc" = 0 ]; then
    RESULT=PASS
  else
    for v in ${CREATED[@]+"${CREATED[@]}"}; do
      pre=0; gcp_vps_was_preempted "$v" || pre=$?
      case "$pre" in
        0) RESULT=PREEMPTED; rc=3; break ;;
        1) ;;
        *) RESULT=INVALID; rc=3 ;;
      esac
    done
  fi
  echo "$RESULT" >"$OUT/result.txt"
  echo "RESULT: $RESULT"
  for v in ${CREATED[@]+"${CREATED[@]}"}; do
    if [ "$KEEP" = 1 ]; then
      echo "kept: scripts/gcp/vps.sh ssh $v"
    else
      vps down "$v" || { echo "LEAKED VPS $v: could not delete; check scripts/gcp/vps.sh list" >&2; echo "$v" >>"$OUT/leaked-vps.txt"; }
    fi
  done
  if [ -n "$FW_RULE" ]; then
    if [ "$KEEP" = 1 ]; then
      echo "kept: firewall rule $FW_RULE (gcloud compute firewall-rules delete $FW_RULE)"
    else
      gcloud compute firewall-rules delete "$FW_RULE" --quiet 2>&1 | redact || true
      # A rule that never got created also fails the delete; only a rule that still exists leaked.
      if gcloud compute firewall-rules describe "$FW_RULE" --format='value(name)' >/dev/null 2>&1; then
        echo "LEAKED FIREWALL RULE $FW_RULE: could not delete; check gcloud compute firewall-rules list" >&2
        echo "firewall-rule $FW_RULE" >>"$OUT/leaked-vps.txt"
      fi
    fi
  fi
  [ ! -s "$OUT/leaked-vps.txt" ] || [ "$rc" != 0 ] || { rc=4; echo "RESULT: PASS but LEAKED VPS: exit 4"; }
  [ "$KEEP" = 0 ] || echo "kubeconfig on $CP: /var/lib/u7s/kubeconfig (sudo kubectl --kubeconfig /var/lib/u7s/kubeconfig ...)"
  exit "$rc"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

up() {
  local n="$1"
  CREATED+=("$n")
  vps up ${STACK_ARGS[@]+"${STACK_ARGS[@]}"} "$n" 2>&1 | redact >"$OUT/up-$n.log" || fail "creating $n (see $OUT/up-$n.log)"
  for _ in $(seq 1 30); do
    vps ssh "$n" -- true >/dev/null 2>&1 && return 0
    sleep "$SLEEP"
  done
  fail "$n never became reachable over IAP ssh"
}

internal_ip() {
  gcloud compute instances describe "$1" --zone="$ZONE" --format='value(networkInterfaces[0].networkIP)'
}

external_ipv6() {
  gcloud compute instances describe "$1" --zone="$ZONE" --format='value(networkInterfaces[0].ipv6Address)'
}

# GCE hands each NIC a /96 of external IPv6; the VPS sources from an address inside it, so the
# firewall source is the whole /96 of the client, nothing wider. Only the LB port is opened, only
# to VPSes carrying the test tag, and the rule is deleted by finish().
create_lb_firewall() {
  gcloud compute firewall-rules create "$FW_RULE" --network="$GCP_NETWORK" --direction=INGRESS \
    --action=allow --rules="tcp:$LB_PORT" --target-tags="$GCP_VPS_TAG" --source-ranges="$1/96"
}

family_of() { case "$1" in *:*) echo 6 ;; *) echo 4 ;; esac; }
# first_of FAMILY "ip ip ..." prints the first address of that family; fails when there is none.
first_of() {
  local ip
  for ip in $2; do
    [ "$(family_of "$ip")" = "$1" ] && { echo "$ip"; return 0; }
  done
  return 1
}
# assert_dual WHAT "ip ip ..." [exact]: at least one address of each family (exactly two with "exact").
assert_dual() {
  first_of 4 "$2" >/dev/null && first_of 6 "$2" >/dev/null || fail "$1 lacks an IPv4 or IPv6 entry: '$2'"
  [ "${3:-}" != exact ] || [ "$(wc -w <<<"$2")" -eq 2 ] || fail "$1 must hold exactly one entry per family: '$2'"
  echo "PASS: $1 dual-stack ($2)"
}

node_ips() { on_cp "$KC get node $1 -o jsonpath='{.status.addresses[?(@.type==\"InternalIP\")].address}'"; }

assert_dual_nodes() {
  local n ips cidrs
  for n in "$CP_NODE" "$W1"; do
    ips="$(node_ips "$n")" || fail "reading InternalIPs of node $n"
    assert_dual "node $n InternalIP" "$ips"
    cidrs="$(on_cp "$KC get node $n -o jsonpath='{.spec.podCIDRs[*]}'")" || fail "reading podCIDRs of node $n"
    assert_dual "node $n podCIDRs" "$cidrs" exact
  done
}

ds_yaml() {
  printf -- '---\napiVersion: v1\nkind: Service\nmetadata: {name: ds}\nspec:\n  ipFamilyPolicy: PreferDualStack\n  selector: {app: pin}\n  ports: [{port: 80, targetPort: 8080}]\n'
  printf -- '---\napiVersion: v1\nkind: Pod\nmetadata: {name: dnsc}\nspec:\n  nodeName: %s\n  containers:\n  - {name: c, image: %s, command: [sleep, "3600"]}\n' "$W1" "$DNSUTILS"
}
apply_ds() { ds_yaml | on_cp "$KC apply -f -"; }

# dig NAME TYPE from a pod on w1: the answer must come through kube-dns across nodes.
dig_in_pod() { on_cp "$KC exec dnsc -- dig +short +time=5 $2 $1"; }

assert_dual_workload() {
  local cips v4 v6 pips pv4 pv6 a aaaa
  cips="$(on_cp "$KC get svc ds -o jsonpath='{.spec.clusterIPs[*]}'")" || fail "reading clusterIPs of Service ds"
  assert_dual "Service ds clusterIPs" "$cips" exact
  v4="$(first_of 4 "$cips")"; v6="$(first_of 6 "$cips")"
  a="$(dig_in_pod ds.default.svc.cluster.local. A)" || fail "dig A for Service ds"
  [ "$a" = "$v4" ] || fail "CoreDNS A answer '$a' != clusterIP $v4"
  aaaa="$(dig_in_pod ds.default.svc.cluster.local. AAAA)" || fail "dig AAAA for Service ds"
  [ "$aaaa" = "$v6" ] || fail "CoreDNS AAAA answer '$aaaa' != clusterIP $v6"
  echo "PASS: CoreDNS answers A $a and AAAA $aaaa for a PreferDualStack Service"
  pips="$(on_cp "$KC get pod pin -o jsonpath='{.status.podIPs[*].ip}'")" || fail "reading podIPs of pod pin"
  assert_dual "pod pin podIPs" "$pips" exact
  pv4="$(first_of 4 "$pips")"; pv6="$(first_of 6 "$pips")"
  on_cp "$KC exec peer -- /agnhost connect $pv4:8080 --timeout=10s" || fail "pod-to-pod over IPv4 ($pv4)"
  on_cp "$KC exec peer -- /agnhost connect '[$pv6]:8080' --timeout=10s" || fail "pod-to-pod over IPv6 ($pv6)"
  on_cp "$KC exec peer -- /agnhost connect $v4:80 --timeout=10s" || fail "pod-to-Service over IPv4 ($v4)"
  on_cp "$KC exec peer -- /agnhost connect '[$v6]:80' --timeout=10s" || fail "pod-to-Service over IPv6 ($v6)"
  echo "PASS: pod-to-pod and pod-to-Service answer over both families"
}

sonobuoy_dual() {
  local kver status results
  kver="$(on_cp "$KC get node $CP_NODE -o jsonpath='{.status.nodeInfo.kubeletVersion}'")" || fail "reading the kubelet version"
  on_cp "curl -fsSL https://github.com/vmware-tanzu/sonobuoy/releases/download/v$SONOBUOY_VERSION/sonobuoy_${SONOBUOY_VERSION}_linux_amd64.tar.gz | sudo tar -xz -C /usr/local/bin sonobuoy" || fail "installing sonobuoy $SONOBUOY_VERSION on $CP"
  on_cp "$SB run --plugin e2e --e2e-focus '$SONOBUOY_FOCUS' --kube-conformance-image registry.k8s.io/conformance:$kver" || fail "sonobuoy run"
  for _ in $(seq 1 "$SONOBUOY_POLLS"); do
    status="$(on_cp "$SB status" 2>/dev/null)" || status=
    case "$status" in *" complete "*) break ;; esac
    sleep "$SLEEP"
  done
  case "$status" in *" complete "*) ;; *) fail "sonobuoy never completed within $SONOBUOY_POLLS polls: $status" ;; esac
  results="$(on_cp "$SB retrieve /tmp && $SB results /tmp/*_sonobuoy_*.tar.gz --plugin e2e")" || fail "retrieving sonobuoy results"
  echo "$results"
  grep -qE '^Total: [1-9]' <<<"$results" || fail "sonobuoy focus '$SONOBUOY_FOCUS' ran no specs (a vacuous pass)"
  grep -qE '^Failed: 0$' <<<"$results" || fail "sonobuoy focus '$SONOBUOY_FOCUS' has failed specs"
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
  local policy=
  [ "$DUAL" = 0 ] || policy=$'  ipFamilyPolicy: PreferDualStack\n'
  {
    pod_yaml lb-backend "$W1"
    printf -- '---\napiVersion: v1\nkind: Service\nmetadata: {name: lb}\nspec:\n  type: LoadBalancer\n%s  selector: {app: lb-backend}\n  ports: [{port: %s, targetPort: 8080}]\n' \
      "$policy" "$LB_PORT"
  } | on_cp "$KC apply -f -"
}

up "$CP"
up "$W1"
CP_IP="$(internal_ip "$CP")"
W1_IP="$(internal_ip "$W1")"
echo "cp=$CP ($CP_IP) w1=$W1"

INSTALL_ARGS=
[ "$DUAL" = 0 ] || INSTALL_ARGS=" --cluster-cidr $DUAL_CLUSTER_CIDR --service-cidr $DUAL_SERVICE_CIDR"
step install-cp on_cp "curl -fsSL $INSTALL_URL -o /tmp/install.sh && sudo bash /tmp/install.sh$INSTALL_ARGS"

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
step logs-exec on_cp "$KC logs pin | grep -c . >/dev/null && $KC exec pin -- /agnhost etc-hosts"
step cross-node-pod-to-pod on_cp "$KC exec peer -- /agnhost connect \$($KC get pod pin -o jsonpath='{.status.podIP}'):8080 --timeout=10s"
step webhook-smoke webhook_smoke

if [ "$DUAL" = 1 ]; then
  step dual-nodes assert_dual_nodes
  step apply-ds apply_ds
  step dnsc-running on_cp "$KC wait --for=condition=Ready pod/dnsc --timeout=300s"
  step dual-workload assert_dual_workload
fi

daemonsets="$(on_cp "$KC -n kube-system get ds -o name" 2>/dev/null)" || fail "listing kube-system DaemonSets on $CP"
if ! grep -qx 'daemonset.apps/servicelb-controller' <<<"$daemonsets"; then
  [ "$DUAL" = 0 ] || fail "--dual-stack needs a release that bundles beep (no servicelb-controller DaemonSet)"
  echo "SKIPPED: loadbalancer (release $RELEASE does not bundle beep)"
  exit 0
fi

up "$CLIENT"
CLIENT_IP="$(internal_ip "$CLIENT")"
expect_ips="$CP_IP $W1_IP"
CLIENT_SEEN_IPS="$CLIENT_IP"
if [ "$DUAL" = 1 ]; then
  CLIENT_V6="$(external_ipv6 "$CLIENT")"
  [ -n "$CLIENT_V6" ] || fail "client $CLIENT has no external IPv6 address (is the VPS dual-stack?)"
  FW_RULE="u7s-e2e-$RUN_ID-lb-v6"   # set before creating so the cleanup trap covers a half-created rule
  step lb-firewall create_lb_firewall "$CLIENT_V6"
  # The LB must answer on every InternalIP of both nodes, v4 and v6.
  expect_ips="$(node_ips "$CP_NODE") $(node_ips "$W1")"
  CLIENT_SEEN_IPS="$CLIENT_IP $(vps ssh "$CLIENT" -- ip -6 -o addr show scope global | awk '{sub("/.*","",$4); print $4}')"
fi
step lb-backend apply_lb

ingress=
for _ in $(seq 1 30); do
  ingress="$(on_cp "$KC get svc lb -o jsonpath='{.status.loadBalancer.ingress[*].ip}'" 2>/dev/null)" || ingress=
  if [ -n "$ingress" ] && { [ "$DUAL" = 0 ] || { first_of 4 "$ingress" && first_of 6 "$ingress"; } >/dev/null 2>&1; }; then break; fi
  sleep "$SLEEP"
done
[ -n "$ingress" ] || fail "Service lb never got a LoadBalancer ingress IP"
[ "$DUAL" = 0 ] || { first_of 4 "$ingress" && first_of 6 "$ingress"; } >/dev/null || fail "Service lb ingress ($ingress) lacks an IPv4 or IPv6 address"
echo "ingress IPs: $ingress; client $CLIENT ($CLIENT_IP)"
for node_ip in $expect_ips; do
  case " $ingress " in
    *" $node_ip "*) ;;
    *) fail "LoadBalancer ingress ($ingress) lacks node IP $node_ip; the via-pod-less-node path is untested" ;;
  esac
done
for ip in $ingress; do
  if [ "$(family_of "$ip")" = 6 ]; then
    url="'http://[$ip]/clientip'"; fam=-6
  else
    url="http://$ip/clientip"; fam=-4
  fi
  seen="$(vps ssh "$CLIENT" -- curl $fam -g -fsS --max-time 15 "$url")" || fail "curl $fam $url from $CLIENT"
  seen="${seen%:*}"; seen="${seen#[}"; seen="${seen%]}"
  case " $CLIENT_SEEN_IPS " in
    *" $seen "*) ;;
    *) fail "backend saw client $seen via $ip, expected one of: $CLIENT_SEEN_IPS" ;;
  esac
  echo "PASS: lb $ip answered over IPv${fam#-} and saw client $seen"
done

if [ "$DUAL" = 1 ]; then
  step sonobuoy-dual sonobuoy_dual
  sed -n '/^Status:/,$p' "$OUT/sonobuoy-dual.log"
fi

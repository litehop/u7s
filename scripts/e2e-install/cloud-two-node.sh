#!/usr/bin/env bash
# Two-node install + join on real GCP networking, from the published mirror.
#
# Usage: cloud-two-node.sh --release <tag> [--keep] [--dual-stack] [--machine-type <type>] [--w1-subnet <subnet>]
#                          [--external-traffic-policy <policies>] [--beep-evidence <collector>] [--skip-sonobuoy]
#   --release       mirror tag to install (https://u7s.dekiru.tech/<tag>/install.sh); needs a release
#                   whose install.sh has --mint-join-token
#   --keep          leave every VPS this run created up and print how to reach them
#   --dual-stack    IPv4+IPv6 cluster on IPV4_IPV6 VPSes (dual --cluster-cidr/--service-cidr; install.sh
#                   derives both node addresses from --iface), asserts both families end to end, needs
#                   beep, and finishes with the upstream IPv6DualStack sonobuoy focus
#   --machine-type  VPS machine type (default e2-micro; e2-standard-2 with --dual-stack, whose
#                   sonobuoy subset saturates e2-micro)
#   --w1-subnet     w1's subnet of u7s-test (default u7s-test; u7s-test-b puts cp and w1 on different subnets)
#   --external-traffic-policy  Cluster (default), Local, Cluster,Local or Local,Cluster: the LB checks run
#                   once per policy, switching Service lb in place; under Local only w1 (the backend's
#                   node) may be published
#   --beep-evidence beep's scripts/real-cloud-evidence.sh: installs bpftool, tcpdump and jq on the nodes,
#                   wraps each evidence request in the collector (results <item>/<cp|w1>/) and requires
#                   the request's TCP 5-tuple in the ingress node's FLOW_TABLE, then runs the MTU step
#                   (e-mtu-*); with --dual-stack it first runs the v4-only --pod-cidr negative control
#   --skip-sonobuoy skip the --dual-stack sonobuoy focus
# Creates VPSes cp and w1 (plus client when the release bundles beep), installs on cp, mints a
# join token there and passes it to w1 on stdin, then asserts in order: both nodes Ready; a pod
# pinned to w1 Running; logs/exec on it (apiserver -> InternalIP:10250); cross-node pod-to-pod;
# webhook-smoke.sh; and, with beep, that a LoadBalancer Service answers from the client VPS
# with its internal IP preserved. With --dual-stack it also curls the LB over v4 and v6 from an
# e2-micro probe VM in the u7s-probe VPC (scripts/gcp/setup.sh): refused before the narrow per-family
# LB firewall rules exist (sources: the probe's /32 and /96), admitted after. Without --keep only the
# VPSes (probe included) and firewall rules this run created are deleted.
# Exit codes: see "Release-gate exit codes" in docs/dev-setup.md. INVALID here is a failure whose
# preemption lookup kept erroring. Results: temp/e2e-install/<ts>/.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
GCP="$ROOT/scripts/gcp"
# shellcheck source=../gcp/lib.sh
. "$GCP/lib.sh"

usage() { sed -n '2,22p' "$0" >&2; exit 2; }

RELEASE=
KEEP=0
DUAL=0
MACHINE_TYPE=
W1_SUBNET="$GCP_NETWORK"
POLICIES=
EVIDENCE=
SKIP_SONOBUOY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --release) [ $# -ge 2 ] || usage; RELEASE="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --dual-stack) DUAL=1; shift ;;
    --machine-type) [ $# -ge 2 ] || usage; MACHINE_TYPE="$2"; shift 2 ;;
    --w1-subnet) [ $# -ge 2 ] || usage; W1_SUBNET="$2"; shift 2 ;;
    --external-traffic-policy) [ $# -ge 2 ] || usage; POLICIES="$2"; shift 2 ;;
    --beep-evidence) [ $# -ge 2 ] || usage; EVIDENCE="$2"; shift 2 ;;
    --skip-sonobuoy) SKIP_SONOBUOY=1; shift ;;
    *) usage ;;
  esac
done
[[ "$RELEASE" =~ ^v[0-9][0-9A-Za-z._-]*$ ]] || usage
[ -z "$MACHINE_TYPE" ] || [[ "$MACHINE_TYPE" =~ ^[a-z0-9][a-z0-9-]*$ ]] || usage
case "$W1_SUBNET" in "$GCP_NETWORK"|"$GCP_SUBNET_B") ;; *) usage ;; esac
case "$POLICIES" in ""|Cluster|Local|Cluster,Local|Local,Cluster) ;; *) usage ;; esac
if [ -n "$EVIDENCE" ]; then
  [ -f "$EVIDENCE" ] && [ -r "$EVIDENCE" ] || { echo "--beep-evidence: $EVIDENCE is not a readable file" >&2; exit 2; }
  command -v jq >/dev/null || { echo "--beep-evidence needs jq locally (FLOW_TABLE check)" >&2; exit 2; }
fi
[ -n "$MACHINE_TYPE" ] || { [ "$DUAL" = 1 ] && MACHINE_TYPE=e2-standard-2; } || true
[ -z "$MACHINE_TYPE" ] || export U7S_GCP_MACHINE_TYPE="$MACHINE_TYPE"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ID="${U7S_E2E_RUN_ID:-$(date -u +%m%d%H%M%S)-$$}"
OUT="${U7S_E2E_RESULTS_DIR:-$ROOT/temp/e2e-install/$TS}"
SLEEP="${U7S_E2E_POLL_SLEEP:-10}"
CP="u7s-e2e-$RUN_ID-cp"
W1="u7s-e2e-$RUN_ID-w1"
CLIENT="u7s-e2e-$RUN_ID-client"
PROBE="u7s-e2e-$RUN_ID-probe"
INSTALL_URL="https://u7s.dekiru.tech/$RELEASE/install.sh"
KC="sudo kubectl --kubeconfig /var/lib/u7s/kubeconfig"
AGNHOST=registry.k8s.io/e2e-test-images/agnhost:2.63.0
DNSUTILS=registry.k8s.io/e2e-test-images/jessie-dnsutils:1.7
DUAL_CLUSTER_CIDR=10.244.0.0/16,fd00:244::/56
DUAL_SERVICE_CIDR=10.96.0.0/12,fd00:96::/108
LB_PORT=80
BULK_PORT=8081
BUSYBOX=docker.io/library/busybox:1.37.0
# The served file is the same bytes every run: a minstd LCG (seed 20260101) printed as 32-byte hex
# lines, 100 MiB, deterministic in busybox and any other awk (all state stays below 2^53).
BULK_AWK='BEGIN { x = 20260101; for (i = 0; i < 3276800; i++) { x = (x * 48271) % 2147483647; a = x; x = (x * 48271) % 2147483647; b = x; x = (x * 48271) % 2147483647; c = x; x = (x * 48271) % 2147483647; printf "%08x%08x%08x%07x\n", a, b, c, x % 268435456 } }'
BULK_SHA_FIXED=9a9d51d71548adf01a4cdfcc6ed472bfeacb6396b8fca69bc03dfef7d50f81a6
VPC_MTU=1460
EV_SCRIPT=/tmp/real-cloud-evidence.sh
EV_DIR=/tmp/beep-evidence
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
FW_RULES=()
STACK_ARGS=()
[ "$DUAL" = 0 ] || STACK_ARGS=(--stack-type IPV4_IPV6)
RESULT=FAIL
POD_CIDR_DROPPED=0
RECORD_ONLY=0

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
  if [ "$POD_CIDR_DROPPED" = 1 ]; then
    pod_cidr_v6 add || echo "NOT RESTORED: servicelb-controller on $CP may still have only the v4 --pod-cidr" >&2
  fi
  for v in ${CREATED[@]+"${CREATED[@]}"}; do
    if [ "$KEEP" = 1 ]; then
      echo "kept: scripts/gcp/vps.sh ssh $v (delete: scripts/gcp/vps.sh down $v)"
    else
      vps down "$v" || { echo "LEAKED VPS $v: could not delete; check scripts/gcp/vps.sh list" >&2; echo "$v" >>"$OUT/leaked-vps.txt"; }
    fi
  done
  for r in ${FW_RULES[@]+"${FW_RULES[@]}"}; do
    if [ "$KEEP" = 1 ]; then
      echo "kept: firewall rule $r (gcloud compute firewall-rules delete $r)"
    else
      gcloud compute firewall-rules delete "$r" --quiet 2>&1 | redact || true
      # A rule that never got created also fails the delete; only a rule that still exists leaked.
      if gcloud compute firewall-rules describe "$r" --format='value(name)' >/dev/null 2>&1; then
        echo "LEAKED FIREWALL RULE $r: could not delete; check gcloud compute firewall-rules list" >&2
        echo "firewall-rule $r" >>"$OUT/leaked-vps.txt"
      fi
    fi
  done
  [ ! -s "$OUT/leaked-vps.txt" ] || [ "$rc" != 0 ] || { rc=4; echo "RESULT: PASS but LEAKED VPS: exit 4"; }
  [ "$KEEP" = 0 ] || echo "kubeconfig on $CP: /var/lib/u7s/kubeconfig (sudo kubectl --kubeconfig /var/lib/u7s/kubeconfig ...)"
  exit "$rc"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

up() {
  local n="$1"; shift
  CREATED+=("$n")
  vps up ${STACK_ARGS[@]+"${STACK_ARGS[@]}"} "$@" "$n" 2>&1 | redact >"$OUT/up-$n.log" || fail "creating $n (see $OUT/up-$n.log)"
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
  gcloud compute instances describe "$1" --zone="$ZONE" --format='value(networkInterfaces[0].ipv6AccessConfigs[0].externalIpv6)'
}

external_ipv4() {
  gcloud compute instances describe "$1" --zone="$ZONE" --format='value(networkInterfaces[0].accessConfigs[0].natIP)'
}

# create_lb_firewall RULE SOURCE: GCE hands each NIC a /96 of external IPv6 and the VPS sources from
# an address inside it, so an IPv6 source is the probe's whole /96 and an IPv4 one its /32, nothing
# wider. A rule holds one family, hence one rule each. Only the LB port is opened, only to VPSes
# carrying the test tag, and the rules are deleted by finish().
create_lb_firewall() {
  gcloud compute firewall-rules create "$1" --network="$GCP_NETWORK" --direction=INGRESS \
    --action=allow --rules="tcp:$LB_PORT" --target-tags="$GCP_VPS_TAG" --source-ranges="$2"
}

# probe_target IP [PATH]: sets PROBE_FAM (-4/-6) and PROBE_URL (quoted for the remote shell; PATH
# defaults to /clientip).
probe_target() {
  if [ "$(family_of "$1")" = 6 ]; then PROBE_FAM=-6; PROBE_URL="'http://[$1]${2:-/clientip}'"
  else PROBE_FAM=-4; PROBE_URL="http://$1${2:-/clientip}"; fi
}

# curl_rc VM IP: VM's curl exit status travels back as data so a dead IAP tunnel (ssh fails) is never
# mistaken for the LB refusing VM.
curl_rc() {
  local out
  probe_target "$2"
  out="$(vps ssh "$1" -- "curl $PROBE_FAM -g -sS --max-time 10 $PROBE_URL >/dev/null 2>&1; echo curl-rc=\$?")" \
    || fail "ssh to $1 (tunnel failure is not a refusal)"
  out="${out##*curl-rc=}"
  [[ "$out" =~ ^[0-9]+$ ]] || fail "no curl exit status from $1"
  echo "$out"
}

# lb_request VM IP "SEEN_IPS": GET /clientip, then /hostname, from VM through the LB address IP. Fails
# unless the backend saw VM as one of SEEN_IPS (client IP preserved) and answered as pod lb-backend;
# prints "<seen ip> <VM's /clientip source port>", the client side of the flow as beep keys it.
lb_request() {
  local who="${1##*-}" out seen port host
  probe_target "$2"
  out="$(vps ssh "$1" -- curl "$PROBE_FAM" -g -fsS --max-time 15 "$PROBE_URL" -w ',%{local_port}')" \
    || fail "curl $PROBE_FAM $PROBE_URL from $1"
  port="${out##*,}"; seen="${out%,*}"; seen="${seen%:*}"; seen="${seen#[}"; seen="${seen%]}"
  case " $3 " in
    *" $seen "*) ;;
    *) fail "backend saw $who as $seen via $2, expected one of: $3" ;;
  esac
  [[ "$port" =~ ^[0-9]+$ ]] || fail "no source port from curl on $1 via $2: '$out'"
  probe_target "$2" /hostname
  host="$(vps ssh "$1" -- curl "$PROBE_FAM" -g -fsS --max-time 15 "$PROBE_URL")" || fail "curl $PROBE_FAM $PROBE_URL from $1"
  [ "$host" = lb-backend ] || fail "$2 answered $who as Hostname '$host', not the backend pod lb-backend"
  echo "$seen $port"
}

# Cross-VPC traffic to the LB's external addresses must be dropped while no rule admits it.
assert_probe_refused() {
  local ip rc
  for ip in $PROBE_TARGETS; do
    rc="$(curl_rc "$PROBE" "$ip")" || exit 1
    [ "$rc" != 0 ] || fail "probe reached $ip with no LB firewall rule: the rule is not what admits outside traffic"
    echo "PASS: probe refused by $ip before the LB rule (curl exit $rc)"
  done
}

assert_probe_admitted() {
  local ip seen
  for ip in $PROBE_TARGETS; do
    seen="$(lb_request "$PROBE" "$ip" "$PROBE_SEEN_IPS")" || exit 1
    echo "PASS: probe in $GCP_PROBE_NETWORK reached $ip over IPv$(family_of "$ip") and was seen as ${seen% *}"
  done
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
  local d=/tmp/sonobuoy-retrieve tarball= out attempt
  for attempt in 1 2 3; do
    if out="$(on_cp "sudo rm -rf $d && sudo mkdir -p $d && $SB retrieve $d && sudo sh -c 'ls $d/*.tar.gz'")"; then
      tarball="${out##*$'\n'}" # retrieve prints the path too; ls prints it last
      [ -z "$tarball" ] || break
    fi
    echo "sonobuoy retrieve attempt $attempt/3 yielded no tarball" >&2
    sleep "$SLEEP"
  done
  [ -n "$tarball" ] || fail "sonobuoy retrieve produced no results tarball after 3 attempts"
  results="$(on_cp "sudo sonobuoy results $tarball --plugin e2e")" || fail "reading sonobuoy results from $tarball"
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
# apply_lb [POLICY]: the LoadBalancer Service lb and its backend pod on w1; POLICY sets
# externalTrafficPolicy (omitted: the API default, Cluster).
apply_lb() {
  local policy=
  [ "$DUAL" = 0 ] || policy=$'  ipFamilyPolicy: PreferDualStack\n'
  [ -z "${1:-}" ] || policy="$policy  externalTrafficPolicy: $1"$'\n'
  {
    pod_yaml lb-backend "$W1"
    printf -- '---\napiVersion: v1\nkind: Service\nmetadata: {name: lb}\nspec:\n  type: LoadBalancer\n%s  selector: {app: lb-backend}\n  ports: [{port: %s, targetPort: 8080}]\n' \
      "$policy" "$LB_PORT"
  } | on_cp "$KC apply -f -"
}
set_policy() { on_cp "$KC patch svc lb --type=merge -p '{\"spec\":{\"externalTrafficPolicy\":\"$1\"}}'"; }

# wait_ingress SVC "WANT" ["UNWANT"]: polls until SVC's LoadBalancer ingress lists every WANT address
# and no UNWANT one; prints the last ingress seen, non-zero if that never happened.
wait_ingress() {
  local ing ip ok
  for _ in $(seq 1 30); do
    ing="$(on_cp "$KC get svc $1 -o jsonpath='{.status.loadBalancer.ingress[*].ip}'" 2>/dev/null)" || ing=
    ok=1
    for ip in $2; do case " $ing " in *" $ip "*) ;; *) ok=0 ;; esac; done
    for ip in ${3:-}; do case " $ing " in *" $ip "*) ok=0 ;; esac; done
    [ -z "$ing" ] || [ "$ok" = 0 ] || { echo "$ing"; return 0; }
    sleep "$SLEEP"
  done
  echo "$ing"
  return 1
}

# The collector reads the dataplane with bpftool and jq and captures with tcpdump; none ships on the
# GCE Ubuntu image. jq on cp also edits the beep DaemonSet for the --pod-cidr negative control.
install_evidence_tools() {
  local n
  for n in "$CP" "$W1"; do
    vps ssh "$n" -- 'sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "linux-tools-$(uname -r)" tcpdump jq && sudo bpftool version' \
      && vps scp "$EVIDENCE" "$n:$EV_SCRIPT" || return 1
  done
}

role_of() { if [ "$1" = "$CP" ]; then echo cp; else echo w1; fi; }

# ip_key_bytes IP: the 16 address bytes as beep keys FLOW_TABLE ("0xNN" words, as bpftool dumps a
# map without BTF); an IPv4 address is embedded as ::ffff:a.b.c.d.
ip_key_bytes() {
  local h=() t=() g=() i a b c d
  if [ "$(family_of "$1")" = 4 ]; then
    IFS=. read -r a b c d <<<"$1"
    printf '0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0xff 0xff '
    printf '0x%02x ' "$a" "$b" "$c" "$d"
    return
  fi
  case "$1" in
    *::*) [ -z "${1%%::*}" ] || IFS=: read -ra h <<<"${1%%::*}"; [ -z "${1#*::}" ] || IFS=: read -ra t <<<"${1#*::}" ;;
    *) IFS=: read -ra h <<<"$1" ;;
  esac
  g=(${h[@]+"${h[@]}"})
  for ((i = ${#h[@]} + ${#t[@]}; i < 8; i++)); do g+=(0); done
  g+=(${t[@]+"${t[@]}"})
  for i in "${g[@]}"; do printf '0x%02x 0x%02x ' $((16#$i >> 8)) $((16#$i & 255)); done
}
port_key_bytes() { printf '0x%02x 0x%02x ' $(($1 >> 8)) $(($1 & 255)); }

# flow_in_table DUMP CLIENT_IP CLIENT_PORT FRONT_IP FRONT_PORT: DUMP (bpftool --json of FLOW_TABLE)
# holds the TCP flow. Key: client ip[16] + front ip[16] + client port + front port (network order) +
# protocol (beep common::encode_tcp_flow_key).
flow_in_table() {
  local key
  key="$(ip_key_bytes "$2")$(ip_key_bytes "$4")$(port_key_bytes "$3")$(port_key_bytes "$5")0x06"
  # shellcheck disable=SC2086 # one positional jq argument per key byte
  jq -e '$ARGS.positional as $k | any(.[]; .key[0:37] == $k)' --args $key <"$1" >/dev/null
}

ev() { vps ssh "$1" -- sudo bash "$EV_SCRIPT" "$2" "$EV_DIR/$3"; }

fetch_evidence() {
  local dest
  dest="$OUT/$2/$(role_of "$1")"
  mkdir -p "$dest"
  vps ssh "$1" -- "sudo tar -czf /tmp/beep-ev.tgz -C $EV_DIR/$2 . && sudo chmod 644 /tmp/beep-ev.tgz" \
    && vps scp "$1:/tmp/beep-ev.tgz" "$dest.tgz" && tar -xzf "$dest.tgz" -C "$dest" && rm -f "$dest.tgz"
}

# collect_around ITEM INGRESS_VM FRONT_IP FRONT_PORT "CARRIER_VMS" PCAP cmd...: beep's (B) evidence
# around one request. cmd must print "<client ip> <client port>" last. Every node is snapshotted
# before and after (with a Geneve pcap when PCAP=1) into $OUT/ITEM/<cp|w1>/; the collector's
# geneve0-growth gate counts only on CARRIER_VMS, since a node the flow does not cross sees no
# Geneve. Fails unless INGRESS_VM's FLOW_TABLE holds the request's 5-tuple.
collect_around() {
  local item="$1" ingress="$2" front="$3" fport="$4" carriers="$5" pcap="$6" n out tuple bad=
  shift 6
  for n in "$CP" "$W1"; do
    ev "$n" before "$item" || fail "$item: collector 'before' on $n"
    [ "$pcap" = 0 ] || ev "$n" pcap-start "$item" || fail "$item: collector 'pcap-start' on $n"
  done
  out="$("$@")" || fail "$item: request failed"
  echo "$out"
  tuple="$(tail -n 1 <<<"$out")"
  for n in "$CP" "$W1"; do
    [ "$pcap" = 0 ] || ev "$n" pcap-stop "$item" || fail "$item: collector 'pcap-stop' on $n"
    if ! ev "$n" after "$item"; then
      case " $carriers " in *" $n "*) bad="$bad $n" ;; *) echo "$item: no geneve0 growth on $n, which the flow does not cross" ;; esac
    fi
    fetch_evidence "$n" "$item" || fail "$item: fetching the evidence from $n"
  done
  [ -z "$bad" ] || fail "$item: geneve0 rx/tx did not grow on$bad, which the flow crosses (evidence: $OUT/$item)"
  if [ "$RECORD_ONLY" = 1 ]; then
    case "$tuple" in -*) echo "RECORD: $item: no answer, so no flow to look up on $(role_of "$ingress")"; return 0 ;; esac
    # shellcheck disable=SC2086 # tuple is "<ip> <port>"
    if flow_in_table "$OUT/$item/$(role_of "$ingress")/after/flow_table.json" $tuple "$front" "$fport"; then
      echo "RECORD: $item: $(role_of "$ingress") FLOW_TABLE holds TCP ${tuple% *}:${tuple#* } -> $front:$fport"
    else
      echo "RECORD: $item: $(role_of "$ingress") FLOW_TABLE has NO TCP flow ${tuple% *}:${tuple#* } -> $front:$fport"
    fi
    return 0
  fi
  # The node the request entered holds its flow, so the table read is the ingress node's, not cp's.
  # shellcheck disable=SC2086 # tuple is "<ip> <port>"
  flow_in_table "$OUT/$item/$(role_of "$ingress")/after/flow_table.json" $tuple "$front" "$fport" \
    || fail "$item: $(role_of "$ingress") FLOW_TABLE has no TCP flow ${tuple% *}:${tuple#* } -> $front:$fport"
  echo "PASS: $item: $(role_of "$ingress") FLOW_TABLE holds TCP ${tuple% *}:${tuple#* } -> $front:$fport${carriers:+; geneve0 grew on $(for n in $carriers; do role_of "$n"; done | paste -sd, -)}"
}

controller_logs() { on_cp "$KC -n kube-system logs -l app.kubernetes.io/name=servicelb-controller -c servicelb-controller --prefix --tail=500"; }

# v6_rejected IP: one controller log line holds beep's admission-gate warning and IP.
v6_rejected() {
  local logs
  logs="$(controller_logs)" || return 1
  grep -F 'rejected from POD_TARGETS' <<<"$logs" | grep -F "$1" >/dev/null
}

# pod_cidr_v6 drop|add: the beep DaemonSet without/with the v6 --pod-cidr, rolled out.
pod_cidr_v6() {
  local edit
  if [ "$1" = drop ]; then
    edit='(.spec.template.spec.containers[0].args | index($a)) as $i | if $i == null then error("no " + $a) else .spec.template.spec.containers[0].args |= map(select(. != $a)) end'
  else
    edit='(.spec.template.spec.containers[0].args | index($a)) as $i | if $i == null then .spec.template.spec.containers[0].args += [$a] else . end'
  fi
  on_cp "$KC -n kube-system get ds servicelb-controller -o json | jq -e --arg a '--pod-cidr=${DUAL_CLUSTER_CIDR#*,}' '$edit' | $KC replace -f - && $KC -n kube-system rollout status ds/servicelb-controller --timeout=300s"
}

# With only the v4 --pod-cidr, beep must refuse the backend's v6 address: v4 through cp reaches the
# pod, the controller logs the rejection, and v6 through cp does not (beep
# scripts/smoke-k3s-controller-dualstack.sh step 13). Restores the v6 --pod-cidr afterwards.
pod_cidr_negative_control() {
  local pod_v6 cp_v6 rc seen=
  pod_v6="$(first_of 6 "$(on_cp "$KC get pod lb-backend -o jsonpath='{.status.podIPs[*].ip}'")")" || fail "pod lb-backend has no IPv6 address"
  cp_v6="$(first_of 6 "$CP_IPS")" || fail "cp has no IPv6 InternalIP"
  for _ in $(seq 1 30); do
    seen="$(lb_request "$CLIENT" "$CP_IP" "$CLIENT_SEEN_IPS" 2>/dev/null)" && break
    sleep "$SLEEP"
  done
  [ -n "$seen" ] || seen="$(lb_request "$CLIENT" "$CP_IP" "$CLIENT_SEEN_IPS")" || exit 1
  echo "PASS: v4 via $CP_IP reached lb-backend with only the v4 --pod-cidr (client seen as ${seen% *})"
  for _ in $(seq 1 30); do
    v6_rejected "$pod_v6" && break
    sleep "$SLEEP"
  done
  v6_rejected "$pod_v6" \
    || fail "no controller log 'rejected from POD_TARGETS' naming the pod's v6 address $pod_v6 with only the v4 --pod-cidr"
  rc="$(curl_rc "$CLIENT" "$cp_v6")" || exit 1
  [ "$rc" != 0 ] || fail "v6 via $cp_v6 reached lb-backend ($pod_v6) with only the v4 --pod-cidr: the admission gate is not what admits it"
  echo "PASS: v6 via $cp_v6 refused (curl exit $rc) while beep has only the v4 --pod-cidr"
  pod_cidr_v6 add || fail "restoring the v6 --pod-cidr"
}

# record_cp_unpublished TARGET: under Local cp has no backend and is not published; the probe asks
# it on its external address TARGET anyway. Only records what happens (answered or not, the client
# IP the backend saw, which backend), never fails; prints "<client ip> <port>" last ("- 0" when
# unanswered) for collect_around's record mode.
record_cp_unpublished() {
  local ip="$1" fam url hurl out rc seen host port
  probe_target "$ip"; fam="$PROBE_FAM"; url="$PROBE_URL"
  probe_target "$ip" /hostname; hurl="$PROBE_URL"
  out="$(vps ssh "$PROBE" -- "c=\$(curl $fam -g -sS --max-time 10 -w ',%{local_port}' $url); echo cp-rc=\$?; echo clientip=\$c; h=\$(curl $fam -g -sS --max-time 10 $hurl); echo hostname=\$h")" \
    || { echo "RECORD: cp $ip: unknown (ssh to $PROBE failed)"; echo "- 0"; return 0; }
  rc="$(sed -n 's/^cp-rc=//p' <<<"$out")"
  seen="$(sed -n 's/^clientip=//p' <<<"$out")"; port="${seen##*,}"; seen="${seen%,*}"; seen="${seen%:*}"; seen="${seen#[}"; seen="${seen%]}"
  host="$(sed -n 's/^hostname=//p' <<<"$out")"
  if [ "$rc" = 0 ]; then
    case " $PROBE_SEEN_IPS " in *" $seen "*) echo "RECORD: cp $ip answered under Local: backend saw $seen (client IP preserved), hostname '$host' (the pod runs on $W1, so cp forwarded to it)" ;;
      *) echo "RECORD: cp $ip answered under Local: backend saw $seen (NOT the probe's address), hostname '$host' (the pod runs on $W1, so cp forwarded to it)" ;; esac
    echo "$seen $port"
  else
    echo "RECORD: cp $ip did not answer under Local (curl exit ${rc:-?})"
    echo "- 0"
  fi
}

bulk_yaml() {
  local policy=
  [ "$DUAL" = 0 ] || policy=$'  ipFamilyPolicy: PreferDualStack\n'
  cat <<YAML
apiVersion: v1
kind: Pod
metadata: {name: bulk, labels: {app: bulk}}
spec:
  nodeName: $W1
  containers:
  - name: c
    image: $BUSYBOX
    command: [sh, -c]
    args:
    - |
      mkdir -p /www && awk '$BULK_AWK' >/www/f && exec httpd -f -p $BULK_PORT -h /www
    readinessProbe: {tcpSocket: {port: $BULK_PORT}, periodSeconds: 2}
---
apiVersion: v1
kind: Service
metadata: {name: bulk}
spec:
  type: LoadBalancer
$policy  selector: {app: bulk}
  ports: [{port: $BULK_PORT, targetPort: $BULK_PORT}]
YAML
}

# Interface MTUs on both nodes. The NIC must carry the VPC MTU; geneve0 sits below it by the
# encapsulation overhead: outer IPv4 20 + UDP 8 + Geneve 8 + inner Ethernet 14 = 50 B, or 70 B with an
# outer IPv6 header (40).
mtu_table() {
  local n out nic nic_mtu gen_mtu
  for n in "$CP" "$W1"; do
    echo "== $(role_of "$n")"
    out="$(vps ssh "$n" -- "ip -d link show; ip -o link show | awk '{print \$2, \$4, \$5}'; ip -o route show default | awk '{print \"nic=\" \$5; exit}'")" || return 1
    echo "$out"
    nic="$(sed -n 's/^nic=//p' <<<"$out")"
    [ -n "$nic" ] || fail "no default-route NIC on $(role_of "$n")"
    nic_mtu="$(awk -v n="$nic:" '$1 == n && $2 == "mtu" {print $3}' <<<"$out")"
    gen_mtu="$(awk '$1 == "geneve0:" && $2 == "mtu" {print $3}' <<<"$out")"
    [ "$nic_mtu" = "$VPC_MTU" ] || fail "$(role_of "$n") $nic MTU is '$nic_mtu', not the $VPC_MTU VPC MTU"
    case "$gen_mtu" in
      "$((VPC_MTU - 50))") echo "PASS: $(role_of "$n") $nic $nic_mtu, geneve0 $gen_mtu = $VPC_MTU - 50 (IPv4 underlay)" ;;
      "$((VPC_MTU - 70))") echo "PASS: $(role_of "$n") $nic $nic_mtu, geneve0 $gen_mtu = $VPC_MTU - 70 (IPv6 underlay)" ;;
      *) fail "$(role_of "$n") geneve0 MTU is '$gen_mtu', neither $((VPC_MTU - 50)) (IPv4 underlay) nor $((VPC_MTU - 70)) (IPv6 underlay)" ;;
    esac
  done
}

# mtu_ping_table: cp pings w1 with the DF bit at stepped payload sizes, per family, and records
# $OUT/e-mtu-v<N>/ping-table.txt. The underlay must carry exactly VPC_MTU minus the IP and ICMP
# headers (v4: 20 + 8, v6: 40 + 8): one byte more must not pass, else the VPC MTU is not what the
# path enforces. Geneve then leaves the tunnel 50 B (v4) / 70 B (v6) less, the geneve0 MTU above.
mtu_ping_table() {
  local fam dst hdr max sizes s out best dir
  for fam in 4 6; do
    [ "$fam" = 4 ] || [ "$DUAL" = 1 ] || continue
    if [ "$fam" = 4 ]; then dst="$W1_IP"; hdr=28; else dst="$(first_of 6 "$W1_IPS")" || fail "w1 has no IPv6 InternalIP"; hdr=48; fi
    max=$((VPC_MTU - hdr))
    sizes="1000 1200 1400 $((max - 1)) $max $((max + 1)) 1472"
    out="$(vps ssh "$CP" -- "for s in $sizes; do if ping -$fam -M do -c 2 -W 2 -s \$s $dst >/dev/null 2>&1; then echo size=\$s ok; else echo size=\$s fail; fi; done")" \
      || fail "ping table from $CP to $dst"
    dir="$OUT/e-mtu-v$fam"
    mkdir -p "$dir"
    {
      echo "ping -$fam -M do cp -> w1 $dst; expected max payload $max = $VPC_MTU - $hdr; tunnelled payload $((max - (fam == 4 ? 50 : 70)))"
      echo "$out"
    } | tee "$dir/ping-table.txt"
    best="$(awk -F'[= ]' '$3 == "ok" && $2 + 0 > m {m = $2 + 0} END {print m + 0}' <<<"$out")"
    [ "$best" = "$max" ] || fail "largest DF ping payload over IPv$fam is $best, expected $max ($VPC_MTU - $hdr)"
    echo "PASS: IPv$fam DF ping passes up to $best B and fails at $((max + 1)) B (VPC MTU $VPC_MTU)"
  done
}

# bulk_fetch VM IP CLIENT_ADDR: VM downloads the 100 MiB /f through the bulk Service at IP, sampling
# ss -ti (retransmits) while it runs; fails unless the sha256 matches the served file. Prints
# "CLIENT_ADDR <source port>".
bulk_fetch() {
  local url fam out sum port
  if [ "$(family_of "$2")" = 6 ]; then fam=-6; url="'http://[$2]:$BULK_PORT/f'"; else fam=-4; url="http://$2:$BULK_PORT/f"; fi
  out="$(vps ssh "$1" -- "curl $fam -g -fsS --max-time 900 -o /tmp/bulk -w '%{local_port}' $url >/tmp/bulk.port & p=\$!; while kill -0 \$p 2>/dev/null; do ss -tin '( dport = :$BULK_PORT )'; sleep 1; done >/tmp/bulk.ss; wait \$p && echo port=\$(cat /tmp/bulk.port) && sha256sum /tmp/bulk && cat /tmp/bulk.ss")" \
    || fail "bulk download through $2 from $1"
  echo "$out"
  sum="$(awk '$2 == "/tmp/bulk" {print $1}' <<<"$out")"
  port="$(sed -n 's/^port=//p' <<<"$out")"
  [ "$sum" = "$BULK_SHA" ] || fail "bulk download through $2 has sha256 '$sum', the pod serves $BULK_SHA"
  [[ "$port" =~ ^[0-9]+$ ]] || fail "no source port from the bulk download on $1"
  echo "PASS: 100 MiB through $2 matches sha256 $sum; last retransmit sample: $(grep -oE '(^| )retrans:[0-9/]+' <<<"$out" | tail -n 1 | tr -d ' ')"
  echo "$3 $port"
}

up "$CP"
up "$W1" --subnet "$W1_SUBNET"
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
CP_IPS="$CP_IP"
W1_IPS="$W1_IP"
CLIENT_SEEN_IPS="$CLIENT_IP"
if [ "$DUAL" = 1 ]; then
  # The probe lives in another VPC (e2-micro: it only runs curl); its IAP ssh readiness overlaps
  # the LB setup below.
  U7S_GCP_MACHINE_TYPE=e2-micro up "$PROBE" --network "$GCP_PROBE_NETWORK"
  PROBE_V4="$(external_ipv4 "$PROBE")"
  PROBE_V6="$(external_ipv6 "$PROBE")"
  [ -n "$PROBE_V4" ] || fail "probe $PROBE has no external IPv4 address"
  [ -n "$PROBE_V6" ] || fail "probe $PROBE has no external IPv6 address (is $GCP_PROBE_NETWORK dual-stack?)"
  PROBE_SEEN_IPS="$PROBE_V4 $(vps ssh "$PROBE" -- ip -6 -o addr show scope global | awk '{sub("/.*","",$4); print $4}')"
  # The LB must answer on every InternalIP of the published nodes, v4 and v6.
  CP_IPS="$(node_ips "$CP_NODE")"
  W1_IPS="$(node_ips "$W1")"
  CLIENT_SEEN_IPS="$CLIENT_IP $(vps ssh "$CLIENT" -- ip -6 -o addr show scope global | awk '{sub("/.*","",$4); print $4}')"
fi
POLICY_LIST="${POLICIES:-Cluster}"
if [ -n "$EVIDENCE" ]; then
  step evidence-tools install_evidence_tools
  # Negative control first: the backend's v6 address must be refused before beep may admit it.
  # Set first so the EXIT trap restores a --pod-cidr dropped by a run that fails or is interrupted.
  [ "$DUAL" = 0 ] || { POD_CIDR_DROPPED=1; step d-pod-cidr-v4-only pod_cidr_v6 drop; }
fi
# Only an explicit --external-traffic-policy sets the field, so the default Service is unchanged.
step lb-backend apply_lb ${POLICIES:+"${POLICY_LIST%%,*}"}
[ -z "$EVIDENCE" ] || [ "$DUAL" = 0 ] || {
  step lb-backend-running on_cp "$KC wait --for=condition=Ready pod/lb-backend --timeout=300s"
  step d-pod-cidr-negative-control pod_cidr_negative_control
  POD_CIDR_DROPPED=0
}

# One leg per policy: under Cluster every node is published and the backend is reached from cp
# over Geneve; under Local only w1, the backend's node, is published (beep v0.6+), and the flow
# stays on w1.
first=1
for policy in ${POLICY_LIST//,/ }; do
  pol="$(tr '[:upper:]' '[:lower:]' <<<"$policy")"
  sfx=; [ "$first" = 1 ] || sfx="-$pol"
  [ "$first" = 1 ] || step "etp$sfx" set_policy "$policy"
  if [ "$policy" = Local ]; then want="$W1_IPS"; unwant="$CP_IPS"; leg_vms="$W1"
  else want="$CP_IPS $W1_IPS"; unwant=; leg_vms="$CP $W1"; fi
  ingress="$(wait_ingress lb "$want" "$unwant")" || true
  [ -n "$ingress" ] || fail "Service lb never got a LoadBalancer ingress IP"
  [ "$DUAL" = 0 ] || { first_of 4 "$ingress" && first_of 6 "$ingress"; } >/dev/null || fail "Service lb ingress ($ingress) lacks an IPv4 or IPv6 address"
  echo "ingress IPs ($policy): $ingress; client $CLIENT ($CLIENT_IP)"
  for node_ip in $want; do
    case " $ingress " in
      *" $node_ip "*) ;;
      *) fail "LoadBalancer ingress ($ingress) lacks node IP $node_ip under $policy" ;;
    esac
  done
  for node_ip in $unwant; do
    case " $ingress " in *" $node_ip "*) fail "under Local, ingress ($ingress) lists $node_ip, a node without a local endpoint" ;; esac
  done
  for ip in $ingress; do
    seen="$(lb_request "$CLIENT" "$ip" "$CLIENT_SEEN_IPS")" || exit 1
    echo "PASS: lb $ip answered over IPv$(family_of "$ip") as lb-backend and saw client ${seen% *} ($policy)"
  done

  if [ "$DUAL" = 1 ]; then
    # The v4 ingress addresses are the nodes' internal IPs, which another VPC cannot reach; the
    # probe targets the published nodes' external IPv4 (GCE NATs it to the same NIC) and the v6
    # ingress as is.
    PROBE_TARGETS="$(for v in $leg_vms; do external_ipv4 "$v"; done | paste -sd' ' -)"
    for ip in $ingress; do [ "$(family_of "$ip")" = 6 ] && PROBE_TARGETS="$PROBE_TARGETS $ip"; done
    { first_of 4 "$PROBE_TARGETS" && first_of 6 "$PROBE_TARGETS"; } >/dev/null || fail "probe targets lack an IPv4 or IPv6 address: '$PROBE_TARGETS'"
    if [ "$first" = 1 ]; then
      # Negative first: with no rule the probe must be refused, else a later pass proves nothing.
      step probe-refused-without-rule assert_probe_refused
      # Set before creating so the cleanup trap covers a half-created rule.
      FW_RULES+=("u7s-e2e-$RUN_ID-lb-v4" "u7s-e2e-$RUN_ID-lb-v6")
      step lb-firewall-v4 create_lb_firewall "u7s-e2e-$RUN_ID-lb-v4" "$PROBE_V4/32"
      step lb-firewall-v6 create_lb_firewall "u7s-e2e-$RUN_ID-lb-v6" "$PROBE_V6/96"
    fi
    step "probe-reaches-lb$sfx" assert_probe_admitted
  fi

  if [ -n "$EVIDENCE" ]; then
    if [ "$policy" = Cluster ]; then
      # (a) in-subnet client -> cp's front -> the pod on w1 (another subnet with --w1-subnet):
      # Geneve on both nodes.
      for ip in $CP_IPS; do
        it="a-disjoint-$pol-v$(family_of "$ip")"
        step "$it" collect_around "$it" "$CP" "$ip" "$LB_PORT" "$CP $W1" 1 lb_request "$CLIENT" "$ip" "$CLIENT_SEEN_IPS"
      done
    fi
    if [ "$DUAL" = 1 ]; then
      # (b) outside-VPC probe -> a published node's external address; the probe's own public IP
      # must reach the pod. Under Local the pod is on the ingress node, so no Geneve is expected.
      ing_vm="$CP"; carriers="$CP $W1"
      [ "$policy" = Cluster ] || { ing_vm="$W1"; carriers=; }
      front_ips="$CP_IPS"; [ "$ing_vm" = "$CP" ] || front_ips="$W1_IPS"
      for ip in $front_ips; do
        target="$ip"; [ "$(family_of "$ip")" = 6 ] || target="$(external_ipv4 "$ing_vm")"
        it="b-external-$pol-v$(family_of "$ip")"
        step "$it" collect_around "$it" "$ing_vm" "$ip" "$LB_PORT" "$carriers" 1 lb_request "$PROBE" "$target" "$PROBE_SEEN_IPS"
      done
      if [ "$policy" = Local ]; then
        # cp holds no backend and is unpublished: record, in cp's own FLOW_TABLE, what it did.
        RECORD_ONLY=1
        for ip in $CP_IPS; do
          target="$ip"; [ "$(family_of "$ip")" = 6 ] || target="$(external_ipv4 "$CP")"
          it="b-cp-unpublished-local-v$(family_of "$ip")"
          step "$it" collect_around "$it" "$CP" "$ip" "$LB_PORT" "" 1 record_cp_unpublished "$target"
        done
        RECORD_ONLY=0
      fi
    fi
  fi
  first=0
done

if [ -n "$EVIDENCE" ]; then
  # (e) MTU: interface MTUs, the DF ping table, then the fixed-seed 100 MiB file served from w1 and
  # fetched from the client through cp's front per family (no pcap: the capture would be as large
  # as the transfer).
  step e-mtu-table mtu_table
  step e-mtu-ping mtu_ping_table
  step bulk-backend on_cp "$KC apply -f -" < <(bulk_yaml)
  step bulk-running on_cp "$KC wait --for=condition=Ready pod/bulk --timeout=600s"
  BULK_SHA="$(on_cp "$KC exec bulk -- sha256sum /www/f" | awk '{print $1}')" || fail "hashing the bulk file in pod bulk"
  [[ "$BULK_SHA" =~ ^[0-9a-f]{64}$ ]] || fail "no sha256 of the bulk file from pod bulk: '$BULK_SHA'"
  [ "$BULK_SHA" = "$BULK_SHA_FIXED" ] || fail "pod bulk serves sha256 $BULK_SHA, not the fixed-seed file's $BULK_SHA_FIXED"
  echo "$BULK_SHA  fixed-seed 100 MiB file (expected $BULK_SHA_FIXED)" | tee "$OUT/e-mtu-bulk-sha256.txt"
  wait_ingress bulk "$CP_IPS" >/dev/null || fail "Service bulk never published cp ($CP_IPS)"
  for ip in $CP_IPS; do
    caddr="$(first_of "$(family_of "$ip")" "$CLIENT_SEEN_IPS")" || fail "client has no IPv$(family_of "$ip") address"
    it="e-mtu-v$(family_of "$ip")"
    step "$it" collect_around "$it" "$CP" "$ip" "$BULK_PORT" "$CP $W1" 0 bulk_fetch "$CLIENT" "$ip" "$caddr"
  done
  step d-beep-state on_cp "$KC get svc,endpointslices -o wide && $KC -n kube-system get ds servicelb-controller -o jsonpath='{.spec.template.spec.containers[0].args}' && echo && $KC -n kube-system logs -l app.kubernetes.io/name=servicelb-controller -c servicelb-controller --prefix --tail=500"
fi

if [ "$DUAL" = 1 ]; then
  if [ "$SKIP_SONOBUOY" = 1 ]; then
    echo "SKIPPED: sonobuoy-dual (--skip-sonobuoy)"
  else
    step sonobuoy-dual sonobuoy_dual
    sed -n '/^Status:/,$p' "$OUT/sonobuoy-dual.log"
  fi
fi

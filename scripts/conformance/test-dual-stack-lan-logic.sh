#!/usr/bin/env bash
# Logic tests for the opt-in --dual-stack rig seeding (_lib.sh lan_v6_*).
#
# Why it matters: two VMs deriving the same v6 address, or a boot script that
# drops the static neighbour entries, silently breaks VM<->VM IPv6 (Lima's
# switch drops the multicast NDP that would otherwise resolve peers), and the
# default rig must stay untouched unless --dual-stack is passed.
# shellcheck disable=SC2016 # patterns match literal lima-start.sh source text
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

PASS=0
FAIL=0
check() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "PASS: $label"; PASS=$((PASS + 1))
  else
    echo "FAIL: $label -- expected '$expected', got '$actual'"; FAIL=$((FAIL + 1))
  fi
}

all_vms="lima-node lima-node-2 lima-node-3 lima-node-4 lima-node-5 lima-node-smoke"
seen=""
for vm in $all_vms; do seen+="$(lan_v6_addr_for "$vm")"$'\n'; done
check "every rig VM gets a distinct address (a collision breaks both VMs' v6)" \
  "6" "$(printf '%s' "$seen" | sort -u | grep -c .)"
check "lima-node-3 sits in the shared /64 so peers are on-link" \
  "fd85:0:0:1::3" "$(lan_v6_addr_for lima-node-3)"

if lan_v6_host_for lima-node-x1 >/dev/null 2>&1; then
  check "unknown VM names are refused rather than guessed" "refused" "accepted"
else
  check "unknown VM names are refused rather than guessed" "refused" "refused"
fi

script=$(lan_v6_script eth0 fd85:0:0:1::3 fd85:0:0:1::100 52:55:55:aa:bb:cc)
check "boot script assigns own ULA without DAD (no multicast to run DAD)" \
  "1" "$(printf '%s\n' "$script" | grep -cxF 'ip -6 addr replace fd85:0:0:1::3/64 dev eth0 nodad')"
check "boot script pins peer as a permanent neighbour (NDP is dropped by the switch)" \
  "1" "$(printf '%s\n' "$script" | grep -cxF 'ip -6 neigh replace fd85:0:0:1::100 lladdr 52:55:55:aa:bb:cc dev eth0 nud permanent')"
check "default boot script routes the default v6 Service CIDR (else node->v6 ClusterIP is ENETUNREACH before kube-proxy DNAT)" \
  "1" "$(printf '%s\n' "$script" | grep -cxF "ip -6 route replace fd00:96::/108 dev lo")"
custom_script=$(RIG_SERVICE_CIDR="10.97.0.0/16,fd00:97::/108" lan_v6_script eth0 fd85:0:0:1::3)
check "a custom v6 Service CIDR is routed (else a Service IP in that range is unreachable from the host path)" \
  "1" "$(printf '%s\n' "$custom_script" | grep -cxF "ip -6 route replace fd00:97::/108 dev lo")"
check "the default v6 range is not routed when a custom one is in use (stale route hides the misconfiguration)" \
  "0" "$(printf '%s\n' "$custom_script" | grep -cF "fd00:96::/108")"
check "a v6-primary Service CIDR order still routes the v6 half (it is not assumed to be second)" \
  "fd00:97::/108" "$(rig_service_cidr_v6 "fd00:97::/108,10.97.0.0/16")"
if RIG_SERVICE_CIDR="10.97.0.0/16" lan_v6_script eth0 fd85:0:0:1::3 >/dev/null 2>&1; then
  check "dual-stack with no v6 Service CIDR is refused (no route would be installed and v6 ClusterIPs would not exist)" "refused" "accepted"
else
  check "dual-stack with no v6 Service CIDR is refused (no route would be installed and v6 ClusterIPs would not exist)" "refused" "refused"
fi
check "run-all.sh exports the effective Service CIDR to the VM provisioning scripts (else lima-start routes the default)" \
  "1" "$(grep -cF 'export RIG_SERVICE_CIDR="$SERVICE_CIDR"' "$DIR/run-all.sh")"
check "lima-start.sh adds no v6 route itself, so the single-stack rig gets none (route lives only in the dual-stack boot script)" \
  "0" "$(grep -c 'ip -6 route' "$DIR/lima-start.sh" || true)"
check "script with no peers has no neighbour lines" \
  "0" "$(lan_v6_script eth0 fd85:0:0:1::3 | grep -c neigh || true)"

# Default rig must keep its per-node fd85:<octet>::1 and never source the mesh.
START="$DIR/lima-start.sh"
check "default path still uses the per-node ULA" \
  "1" "$(grep -cF 'NODE_IPV6="fd85:${POD_SUBNET_OCTET}::1"' "$START")"
check "mesh seeding is gated on --dual-stack" \
  "1" "$(grep -cF 'if [ "$DUAL_STACK" -eq 1 ]; then' "$START")"
for f in run-all.sh add-node.sh; do
  check "$f forwards --dual-stack to lima-start.sh" \
    "1" "$(grep -c -- '--dual-stack) _DUAL_STACK_ARG="--dual-stack"' "$DIR/$f")"
done

check "boot unit re-applies after a networkd restart (an apt systemd upgrade flushes the static ULA)" \
  "1" "$(grep -cxF 'PartOf=systemd-networkd.service' "$DIR/_lib.sh")"
check "peer discovery never pipes limactl list into grep -q (SIGPIPE under pipefail silently drops every peer)" \
  "0" "$(grep -c 'limactl list.*| grep -q' "$START")"

# Pod/Service v6 wiring. Without every piece, "this cluster is not configured
# for dual-stack services" and pods stay v4-only.
ROOT="$(cd "$DIR/../.." && pwd)"
check "dual-stack KCM gets both pod CIDRs and one mask flag per family (upstream rejects the single flag with two CIDRs)" \
  "--cluster-cidr=10.244.0.0/16,fd00:244::/56 --node-cidr-mask-size-ipv4=24 --node-cidr-mask-size-ipv6=64" "$(rig_kcm_cidr_flags 1)"
check "single-stack KCM flags stay as before" \
  "--cluster-cidr=10.244.0.0/16 --node-cidr-mask-size=24" "$(rig_kcm_cidr_flags 0)"
# stage <dual> <nic mtu> [port]: renders the shipped manifests/ the way lima-start.sh does
# and prints the directory. RIG_SERVICE_CIDR, when set, is the --service-cidr.
stage() {
  local d
  d="$(mktemp -d)"
  rig_stage_manifests "$d" eth0 "$2" "$1" 1.37.3 "${3:-6443}" || return 1
  echo "$d"
}
dual_dir=$(stage 1 1500)
single_dir=$(stage 0 1500)
check "dual-stack kube-proxy clusterCIDR lists both families" \
  "1" "$(grep -cF 'clusterCIDR: 10.244.0.0/16,fd00:244::/56' "$dual_dir/kube-proxy.yaml")"
check "single-stack kube-proxy clusterCIDR stays v4" \
  "1" "$(grep -cF 'clusterCIDR: 10.244.0.0/16' "$single_dir/kube-proxy.yaml")"
check "kube-proxy dials the slot's apiserver port on host.lima.internal, not the shipped 6443 (a wrong port leaves every Service VIP unprogrammed)" \
  "server: https://host.lima.internal:6444" "$(grep 'server: https' "$(stage 0 1500 6444)/kube-proxy.yaml" | sed 's/^ *//')"
flannel_dual=$(cat "$dual_dir/flannel.yaml")
check "dual-stack flannel keeps IPv6Network (lima-start used to delete it)" \
  "1" "$(printf '%s\n' "$flannel_dual" | grep -cF '"EnableIPv6": true, "IPv6Network": "fd00:244::/56"')"
flannel_single=$(cat "$single_dir/flannel.yaml")
check "single-stack flannel has no IPv6Network" \
  "0" "$(printf '%s\n' "$flannel_single" | grep -c 'IPv6Network"')"
check "rig single-stack flannel gets NIC MTU - 74 (a stale constant would diverge from install.sh)" \
  "1" "$(printf '%s\n' "$flannel_single" | grep -cE '^ +"mtu": 1426,$')"
check "rig dual-stack flannel gets NIC MTU - 94 (the larger IPv6 Geneve overhead)" \
  "1" "$(printf '%s\n' "$flannel_dual" | grep -cE '^ +"mtu": 1406,$')"
check "a rig NIC MTU of 1460 renders 1386, not a hard-coded value" \
  "1" "$(cat "$(stage 0 1460)/flannel.yaml" | grep -cE '^ +"mtu": 1386,$')"
check "no unresolved placeholder in either rig flannel render (an unrendered \"mtu\" breaks every pod's CNI setup)" \
  "0" "$(printf '%s\n%s\n' "$flannel_dual" "$flannel_single" | grep -cE '__[A-Z_]+__' || true)"
ci_render=$(cd "$ROOT" && bash -c '. scripts/lib/flannel-render.sh; render_flannel_for_nic eth0 1500 10.244.0.0/16 "" < manifests/flannel.yaml')
check "a CI-shaped render call (eth0, 1500 MTU) leaves no placeholder and carries a numeric mtu" \
  "1" "$(printf '%s\n' "$ci_render" | grep -cE '^ +"mtu": 1426,$')"
check "no placeholder survives a CI-shaped render" \
  "0" "$(printf '%s\n' "$ci_render" | grep -cE '__[A-Z_]+__' || true)"
check "render_flannel refuses to emit a manifest with an unknown placeholder left in it" \
  "1" "$(printf 'a: __NEW_THING__\n' | render_flannel eth0 10.244.0.0/16 "" 1426 >/dev/null 2>&1 && echo 0 || echo 1)"
check "dual-stack CoreDNS Service has a VIP per family, PreferDualStack" \
  "  clusterIP: 10.96.0.10|  clusterIPs:|  - 10.96.0.10|  - fd00:96::a|  ipFamilyPolicy: PreferDualStack" \
  "$(grep -A4 '^  clusterIP: ' "$dual_dir/coredns.yaml" | paste -sd'|' -)"
check "single-stack CoreDNS manifest is staged unchanged" \
  "$(cat "$ROOT/manifests/coredns.yaml")" "$(cat "$single_dir/coredns.yaml")"

# Pods resolve DNS only if kubelet's clusterDNS equals CoreDNS's Service IP, so
# both are derived from the one effective Service CIDR.
coredns_vips() {
  local d
  d=$(RIG_SERVICE_CIDR="$1" stage "${2:-1}" 1500)
  grep -A4 '^  clusterIP: ' "$d/coredns.yaml" | paste -sd'|' -
}
check "default dual CIDR keeps today's exact kubelet clusterDNS VIPs (an existing rig must not move)" \
  "10.96.0.10 fd00:96::a" "$(rig_kube_dns_ips "$RIG_SERVICE_CIDR_DUAL" | paste -sd' ' -)"
check "custom dual CIDR: CoreDNS Service VIPs come from that range (a hard-coded 10.96.0.10 is outside it and the apiserver rejects the Service)" \
  "  clusterIP: 10.97.0.10|  clusterIPs:|  - 10.97.0.10|  - fd00:97::a|  ipFamilyPolicy: PreferDualStack" \
  "$(coredns_vips "10.97.0.0/16,fd00:97::/108")"
check "custom dual CIDR: kubelet clusterDNS equals the CoreDNS VIPs (else pods' resolv.conf points at nothing)" \
  "10.97.0.10 fd00:97::a" "$(rig_kube_dns_ips "10.97.0.0/16,fd00:97::/108" | paste -sd' ' -)"
check "v6-primary CIDR order: the v6 VIP is clusterIP and the first clusterDNS (the apiserver's primary family)" \
  "  clusterIP: fd00:97::a|  clusterIPs:|  - fd00:97::a|  - 10.97.0.10|  ipFamilyPolicy: PreferDualStack" \
  "$(coredns_vips "fd00:97::/108,10.97.0.0/16")"
check "single-stack custom CIDR also moves the CoreDNS clusterIP" \
  "  clusterIP: 10.97.0.10" \
  "$(coredns_vips "10.97.0.0/16" 0 | cut -d'|' -f1)"
check "a mid-address zero run is compressed canonically (kubectl reports fd00:97:0:1::a, not an expanded form)" \
  "fd00:97:0:1::a" "$(rig_cidr_tenth_host "fd00:97:0:1::/64")"
check "an unaligned address is masked to its network before adding 10" \
  "10.97.0.10" "$(rig_cidr_tenth_host "10.97.3.7/16")"
if rig_cidr_tenth_host "10.97.0.0/30" >/dev/null 2>&1; then
  check "a range too small for a tenth host is refused loudly" "refused" "accepted"
else
  check "a range too small for a tenth host is refused loudly" "refused" "refused"
fi
if rig_kube_dns_ips "10.97.0.0/16,fd00:97::/126" >/dev/null 2>&1; then
  check "a too-small second-family range is refused too" "refused" "accepted"
else
  check "a too-small second-family range is refused too" "refused" "refused"
fi
check "u7s-start.sh no longer pins a dual --service-cidr to the default (the guard blocked custom ranges)" \
  "0" "$(grep -c 'must be \$RIG_SERVICE_CIDR_DUAL' "$ROOT/scripts/u7s-start.sh" || true)"
check "lima-start.sh rewrites kubelet clusterDNS from the effective Service CIDR" \
  "1" "$(grep -cF 'rig_kube_dns_ips "$(rig_effective_service_cidr "$DUAL_STACK")"' "$START")"

kcfg=$(mktemp)
printf 'resolvConf: /etc/resolv.conf\nclusterDNS:\n  - 10.96.0.10\nclusterDomain: cluster.local\n' > "$kcfg"
"$DIR/set-kubelet-clusterdns.sh" "$kcfg" 10.97.0.10 fd00:97::a
"$DIR/set-kubelet-clusterdns.sh" "$kcfg" 10.97.0.10 fd00:97::a
check "kubelet config clusterDNS is replaced (not appended) and idempotent, other keys intact" \
  "resolvConf: /etc/resolv.conf|clusterDNS:|  - 10.97.0.10|  - fd00:97::a|clusterDomain: cluster.local" "$(paste -sd'|' "$kcfg")"
rm -f "$kcfg"
check "04-start-kcm.sh takes its CIDR flags from the rig helper" \
  "1" "$(grep -cF '$KCM_CIDR_FLAGS' "$DIR/04-start-kcm.sh")"
check "run-all.sh forwards --dual-stack to lima-start.sh, which starts KCM" \
  "1" "$(grep -c 'lima-start.sh" --with-kcm.*_DUAL_STACK_ARG' "$DIR/run-all.sh")"
check "lima-start.sh forwards --dual-stack to KCM" \
  "1" "$(grep -cF 'KCM_ARGS+=(--dual-stack)' "$DIR/lima-start.sh")"
check "run-all.sh defaults a dual-stack apiserver to the dual Service range" \
  "1" "$(grep -cF 'SERVICE_CIDR="$RIG_SERVICE_CIDR_DUAL"' "$DIR/run-all.sh")"
check "lima-start.sh stages the shipped manifests through the dual-stack-aware helper" \
  "1" "$(grep -cE 'rig_stage_manifests .*"\$DUAL_STACK"' "$START")"

# The rig must run what install.sh ships: the staged set is exactly manifests/*.yaml, so a
# manifest added tomorrow (or beep today) reaches the rig with no edit to any rig script, and
# one removed from manifests/ stops being applied instead of lingering in the staging folder.
shipped=$(cd "$ROOT/manifests" && printf '%s\n' *.yaml | sort | paste -sd' ' -)
check "rig stages exactly manifests/*.yaml (a manifest the rig skips is never exercised by conformance)" \
  "$shipped" "$(cd "$single_dir" && printf '%s\n' *.yaml | sort | paste -sd' ' -)"
check "beep is among the staged manifests, with its uplink iface rendered" \
  "1" "$(grep -cF -- '--uplink-iface=eth0' "$single_dir/beep.yaml")"
check "dual-stack beep gets one --pod-cidr per family (install.sh's renderer, not a rig copy)" \
  "2" "$(grep -cE -- '--pod-cidr=' "$dual_dir/beep.yaml")"
check "no manifest keeps an install-time placeholder after staging (an unrendered one reaches the apiserver verbatim)" \
  "0" "$(cat "$single_dir"/*.yaml "$dual_dir"/*.yaml | grep -vE '^ *#' | grep -cE '__[A-Z_]+__' || true)"
stale_dir=$(mktemp -d)
echo 'kind: Stale' > "$stale_dir/removed-upstream.yaml"
rig_stage_manifests "$stale_dir" eth0 1500 0 1.37.3 6443
check "a manifest dropped from manifests/ disappears from the staging folder on the next run" \
  "0" "$([ -e "$stale_dir/removed-upstream.yaml" ] && echo 1 || echo 0)"

echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]

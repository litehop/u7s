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
check "dual-stack kube-proxy clusterCIDR lists both families" \
  "10.244.0.0/16,fd00:244::/56" "$(rig_kube_proxy_cluster_cidr 1)"
check "single-stack kube-proxy clusterCIDR stays v4" \
  "10.244.0.0/16" "$(rig_kube_proxy_cluster_cidr 0)"
flannel_dual=$(rig_render_flannel eth0 1 < "$ROOT/manifests/flannel.yaml")
check "dual-stack flannel keeps IPv6Network (lima-start used to delete it)" \
  "1" "$(printf '%s\n' "$flannel_dual" | grep -cF '"EnableIPv6": true, "IPv6Network": "fd00:244::/56"')"
flannel_single=$(rig_render_flannel eth0 0 < "$ROOT/manifests/flannel.yaml")
check "single-stack flannel has no IPv6Network" \
  "0" "$(printf '%s\n' "$flannel_single" | grep -c 'IPv6Network"')"
check "single-stack flannel render is byte-identical to the pre-dual-stack sed" \
  "$(sed -e 's/__IFACE__/eth0/g' -e 's#__POD_CLUSTER_CIDR_IPV4__#10.244.0.0/16#g' -e '/"IPv6Network"/d' "$ROOT/manifests/flannel.yaml")" "$flannel_single"
check "no unresolved placeholder in either flannel render" \
  "0" "$(printf '%s\n%s\n' "$flannel_dual" "$flannel_single" | grep -cE '__[A-Z0-9_]+__[",]' || true)"
check "dual-stack CoreDNS Service has a VIP per family, PreferDualStack" \
  "  clusterIP: 10.96.0.10|  clusterIPs:|  - 10.96.0.10|  - fd00:96::a|  ipFamilyPolicy: PreferDualStack" \
  "$(rig_render_coredns 1 < "$ROOT/manifests/coredns.yaml" | grep -A4 '^  clusterIP: ' | paste -sd'|' -)"
check "single-stack CoreDNS manifest is staged unchanged" \
  "$(cat "$ROOT/manifests/coredns.yaml")" "$(rig_render_coredns 0 < "$ROOT/manifests/coredns.yaml")"
check "04-start-kcm.sh takes its CIDR flags from the rig helper" \
  "1" "$(grep -cF '$KCM_CIDR_FLAGS' "$DIR/04-start-kcm.sh")"
check "run-all.sh forwards --dual-stack to KCM" \
  "1" "$(grep -c '04-start-kcm.sh.*_DUAL_STACK_ARG' "$DIR/run-all.sh")"
check "run-all.sh defaults a dual-stack apiserver to the dual Service range" \
  "1" "$(grep -cF 'SERVICE_CIDR="$RIG_SERVICE_CIDR_DUAL"' "$DIR/run-all.sh")"
check "lima-start.sh renders kube-proxy and flannel via the dual-stack-aware helpers" \
  "2" "$(grep -cE 'rig_kube_proxy_cluster_cidr "\$DUAL_STACK"|rig_render_flannel .*"\$DUAL_STACK"' "$START")"

echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]

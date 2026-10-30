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

echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]

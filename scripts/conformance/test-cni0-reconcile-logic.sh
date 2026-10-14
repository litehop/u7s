#!/usr/bin/env bash
# cni0 survives across sessions with the address from the node's PREVIOUS
# podCIDR; flannel then fails "failed to set bridge addr" and no pod sandbox
# on that node can be created. cni0_addr_is_stale() decides whether to delete
# it: stale iff its address is outside the node's CURRENT podCIDR.
set -euo pipefail

PASS=0
FAIL=0
assert_true() {
  local label="$1"
  shift
  if "$@"; then echo "PASS: $label"; PASS=$(( PASS + 1 )); else echo "FAIL: $label"; FAIL=$(( FAIL + 1 )); fi
}
assert_false() {
  local label="$1"
  shift
  if ! "$@"; then echo "PASS: $label"; PASS=$(( PASS + 1 )); else echo "FAIL: $label"; FAIL=$(( FAIL + 1 )); fi
}

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

assert_true "10.244.1.1/24 vs new podCIDR 10.244.2.0/24 is stale -- the live failure: flannel cannot set the bridge addr" \
  cni0_addr_is_stale 10.244.1.1/24 10.244.2.0/24
assert_false "10.244.2.1/24 inside 10.244.2.0/24 is kept -- deleting a matching bridge would needlessly break running pods" \
  cni0_addr_is_stale 10.244.2.1/24 10.244.2.0/24
assert_false "address without /len works the same as with it" \
  cni0_addr_is_stale 10.244.2.1 10.244.2.0/24
assert_true "a different /16 is stale" \
  cni0_addr_is_stale 10.245.2.1/24 10.244.2.0/24
assert_false "non-/24 podCIDR: 10.244.3.1 is inside 10.244.2.0/23" \
  cni0_addr_is_stale 10.244.3.1/23 10.244.2.0/23
assert_true "non-/24 podCIDR: 10.244.4.1 is outside 10.244.2.0/23" \
  cni0_addr_is_stale 10.244.4.1/23 10.244.2.0/23
assert_true "high-octet addresses do not overflow the mask math (192.168.1.1 vs 10.0.0.0/8)" \
  cni0_addr_is_stale 192.168.1.1/24 10.0.0.0/8

assert_false "/0 podCIDR contains every address -- a stale verdict would delete a bridge that cannot conflict" \
  cni0_addr_is_stale 10.244.1.1/24 0.0.0.0/0
assert_false "/32 podCIDR keeps its single exact address" \
  cni0_addr_is_stale 10.244.2.5/32 10.244.2.5/32
assert_true "/32 podCIDR: the neighbouring address is stale" \
  cni0_addr_is_stale 10.244.2.6/32 10.244.2.5/32
assert_false "the podCIDR network address (10.244.2.0) is inside the CIDR" \
  cni0_addr_is_stale 10.244.2.0/24 10.244.2.0/24
assert_false "the podCIDR broadcast address (10.244.2.255) is inside the CIDR" \
  cni0_addr_is_stale 10.244.2.255/24 10.244.2.0/24
assert_true "one past the broadcast address (10.244.3.0) is outside" \
  cni0_addr_is_stale 10.244.3.0/24 10.244.2.0/24

cni0_rc() { local rc=0; cni0_addr_is_stale "$@" 2>/dev/null || rc=$?; echo "$rc"; }
for bad in "" "garbage" "10.244.2" "10.244.2.1.1" "10.244.2.300/24" "/24"; do
  assert_true "malformed address '$bad' is rejected with rc 2, not reported stale -- an empty read would otherwise delete a healthy cni0" \
    [ "$(cni0_rc "$bad" 10.244.2.0/24)" = 2 ]
done
for bad in "" "10.244.2.0" "10.244.2.0/33" "10.244.2.0/" "10.244.2.0/x" "10.244.2/24"; do
  assert_true "malformed podCIDR '$bad' is rejected with rc 2, not reported stale" \
    [ "$(cni0_rc 10.244.2.1/24 "$bad")" = 2 ]
done

LIMACTL_CALLS=$(mktemp)
trap 'rm -f "$LIMACTL_CALLS"' EXIT
limactl() {
  if [ "$3" = ip ]; then echo "5: cni0    inet $STUB_ADDR scope global cni0"; return 0; fi
  echo "$*" >> "$LIMACTL_CALLS"
}
kubectl() { echo "[\"$STUB_CIDR\"]"; }
reconcile_rc() { local rc=0; STUB_ADDR="$1" STUB_CIDR="$2" reconcile_cni0 vm kc node >/dev/null 2>&1 || rc=$?; echo "$rc"; }

assert_false "reconcile_cni0 fails loud on an unjudgeable cni0 address -- otherwise run-all.sh proceeds into the broken-network failure it was meant to prevent" \
  [ "$(reconcile_rc 10.244.2.300/24 10.244.2.0/24)" = 0 ]
assert_true "reconcile_cni0 does not delete cni0 when it cannot judge the address" \
  [ ! -s "$LIMACTL_CALLS" ]
assert_true "reconcile_cni0 succeeds when the address matches" \
  [ "$(reconcile_rc 10.244.2.1/24 10.244.2.0/24)" = 0 ]
stale_cni0_deleted() {
  [ "$(reconcile_rc 10.244.1.1/24 10.244.2.0/24)" = 0 ] && grep -q "ip link delete cni0" "$LIMACTL_CALLS"
}
assert_true "reconcile_cni0 deletes a stale cni0" \
  stale_cni0_deleted

assert_true "run-all.sh reconciles cni0 for the primary node -- otherwise a warm reconnect of the primary still hits the stale bridge" \
  grep -q 'reconcile_cni0 "\${U7S_VM_NAME:-lima-node}"' "$DIR/run-all.sh"
assert_true "run-all.sh reconciles cni0 for the extra node -- otherwise a warm reconnect still hits the stale bridge" \
  grep -q 'reconcile_cni0 "\$EXTRA_NODE"' "$DIR/run-all.sh"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]

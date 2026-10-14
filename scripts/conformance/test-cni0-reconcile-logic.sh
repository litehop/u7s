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

assert_true "run-all.sh reconciles cni0 for the primary and extra node -- otherwise a warm reconnect still hits the stale bridge" \
  grep -q 'reconcile_cni0 "\$EXTRA_NODE"' "$DIR/run-all.sh"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]

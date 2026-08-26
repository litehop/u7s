#!/usr/bin/env bash
# Unit tests for lima-start.sh's NODE_SUFFIX default derivation.
#
# Root cause: NODE_SUFFIX used to default to "" unconditionally regardless of
# VM_NAME. add-node.sh is the only OTHER place that ever set --node-suffix
# (hardcoded "-2" for whichever VM it joins), so a bare `--vm lima-node-3`
# reprovision — e.g. `limactl delete lima-node-3` to pick up a new network
# default, then re-running lima-start.sh directly instead of add-node.sh —
# silently landed on NODE_SUFFIX="". That re-applied the konnectivity-agent
# Pod named plain "konnectivity-agent", which in a shared multi-node stack
# already belongs to whichever OTHER node was started without a suffix, and
# the apiserver correctly 422'd on spec.nodeName immutability trying to
# rebind it from that node's name to lima-node-3's. Deriving the suffix from
# VM_NAME itself makes re-provisioning idempotent no matter how it's invoked:
# the same VM_NAME always gets the same, collision-free suffix.
#
# Exits 0 on success, 1 on any assertion failure.
# shellcheck disable=SC2016 # file-wide: the structural grep pattern below
# intentionally matches the literal, unexpanded source text of lima-start.sh,
# not something meant to expand in this script's own shell.
set -euo pipefail

PASS=0
FAIL=0

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — expected '${expected}', got '${actual}'"
    FAIL=$(( FAIL + 1 ))
  fi
}
assert_true() {
  local label="$1"
  shift
  if "$@"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}
assert_false() {
  local label="$1"
  shift
  if ! "$@"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# node_suffix_for() -- mirrors lima-start.sh's NODE_SUFFIX case statement.
# ---------------------------------------------------------------------------
node_suffix_for() {
  local vm_name="$1" override="${2:-}"
  case "$vm_name" in
    lima-node-[0-9]*) echo "${override:-"-${vm_name#lima-node-}"}" ;;
    *) echo "${override:-}" ;;
  esac
}

assert_eq "primary 'lima-node' still defaults to no suffix" \
  "" "$(node_suffix_for lima-node)"
assert_eq "'lima-node-3' auto-derives '-3' without needing --node-suffix" \
  "-3" "$(node_suffix_for lima-node-3)"
assert_eq "'lima-node-2' auto-derives '-2' (matches add-node.sh's hardcoded value)" \
  "-2" "$(node_suffix_for lima-node-2)"
assert_eq "non-numbered 'lima-node-smoke' keeps the empty default (POD_SUBNET_OCTET can't parse a non-numeric suffix)" \
  "" "$(node_suffix_for lima-node-smoke)"
assert_eq "an explicit --node-suffix override still wins over auto-derivation" \
  "-9" "$(node_suffix_for lima-node-3 -9)"
assert_true "'lima-node' and 'lima-node-3' sharing one apiserver never collide (distinct suffixes -> distinct konnectivity-agent Pod names)" \
  test "$(node_suffix_for lima-node)" != "$(node_suffix_for lima-node-3)"

# ---------------------------------------------------------------------------
# Structural checks against the real script: the mirror function above proves
# the derivation is right, but not that lima-start.sh actually computes
# NODE_SUFFIX this way instead of the old flat, VM_NAME-agnostic default.
# ---------------------------------------------------------------------------
DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_START="$DIR/lima-start.sh"

assert_true "lima-start.sh auto-derives NODE_SUFFIX from VM_NAME for the numbered slots" \
  grep -qF 'lima-node-[0-9]*) NODE_SUFFIX="${_NODE_SUFFIX_OVERRIDE:-"-${VM_NAME#lima-node-}"}" ;;' "$LIMA_START"

# Regression guard: the pre-fix line set NODE_SUFFIX unconditionally at top
# level (no VM_NAME dispatch at all) -- prove that flat form is gone, not
# just that a working case arm also happens to exist elsewhere.
assert_false "(regression guard) NODE_SUFFIX is no longer a flat, VM_NAME-agnostic default" \
  grep -qE '^NODE_SUFFIX="\$\{_NODE_SUFFIX_OVERRIDE:-\}"$' "$LIMA_START"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

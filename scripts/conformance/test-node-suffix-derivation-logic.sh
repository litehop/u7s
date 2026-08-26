#!/usr/bin/env bash
# Unit tests for the shared NODE_SUFFIX derivation used by lima-start.sh
# (direct-start path) and add-node.sh (--extra-node join path).
#
# Root cause #1 (fixed first): NODE_SUFFIX used to default to "" unconditionally
# regardless of VM_NAME. add-node.sh was the only OTHER place that ever set
# --node-suffix (hardcoded "-2" for whichever VM it joins), so a bare
# `--vm lima-node-3` reprovision — e.g. `limactl delete lima-node-3` to pick up
# a new network default, then re-running lima-start.sh directly instead of
# add-node.sh — silently landed on NODE_SUFFIX="". That re-applied the
# konnectivity-agent Pod named plain "konnectivity-agent", which in a shared
# multi-node stack already belongs to whichever OTHER node was started without
# a suffix, and the apiserver correctly 422'd on spec.nodeName immutability
# trying to rebind it from that node's name to lima-node-3's.
#
# Root cause #2 (review fix, this revision): fixing #1 by having
# lima-start.sh auto-derive NODE_SUFFIX from VM_NAME reintroduced the exact
# same collision for the documented standard 2-node pairing
# (`--vm lima-node-2 --extra-node lima-node-3`): the primary now correctly
# auto-derives "-2" for itself, but add-node.sh still unconditionally hardcoded
# "-2" for whichever VM IT was starting (lima-node-3) — both land on "-2" and
# collide again. Fixed by moving the derivation into a single shared
# node_suffix_for() helper (_lib.sh) that BOTH scripts call, so the two can
# never independently drift back out of sync.
#
# Root cause #3 (review fix, this revision): fixing #2's helper had its
# catch-all branch return the empty default for ANY non-numbered-slot name,
# not just the primary "lima-node" -- so lima-node-smoke (also non-numbered)
# derived the SAME empty suffix as lima-node, and would collide with it on
# konnectivity-agent<suffix>/kubelet-serving<suffix> names once add-node.sh
# started calling node_suffix_for() too. Fixed by deriving a suffix from
# whatever follows "lima-node-" for any non-primary name, not just numbered
# ones; lima-start.sh's POD_SUBNET_OCTET arithmetic (which can't parse a
# non-numeric suffix) was updated in lockstep to treat non-numeric suffixes
# the same as the empty case instead of aborting under `set -u`.
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
# node_suffix_for() -- sourced from the REAL _lib.sh, not a hand-written copy.
# A hand-written mirror here would itself be a 2nd place the derivation logic
# lives, and could pass every assertion below even while the real scripts
# silently drifted from it -- exactly the failure mode that let root cause #2
# ship in the first place (a correct lima-start.sh and a stale, hardcoded
# add-node.sh). Sourcing the shared helper means these assertions exercise the
# exact code both scripts call.
# ---------------------------------------------------------------------------
DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_START="$DIR/lima-start.sh"
ADD_NODE="$DIR/add-node.sh"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

assert_eq "primary 'lima-node' still defaults to no suffix" \
  "" "$(node_suffix_for lima-node)"
assert_eq "'lima-node-3' auto-derives '-3' without needing --node-suffix" \
  "-3" "$(node_suffix_for lima-node-3)"
assert_eq "'lima-node-2' auto-derives '-2'" \
  "-2" "$(node_suffix_for lima-node-2)"
assert_eq "non-numbered 'lima-node-smoke' derives '-smoke' from its own name, not the primary's empty default" \
  "-smoke" "$(node_suffix_for lima-node-smoke)"
assert_eq "an explicit --node-suffix override still wins over auto-derivation" \
  "-9" "$(node_suffix_for lima-node-3 -9)"
assert_true "'lima-node' and 'lima-node-3' sharing one apiserver never collide (distinct suffixes -> distinct konnectivity-agent Pod names)" \
  test "$(node_suffix_for lima-node)" != "$(node_suffix_for lima-node-3)"
# Review fix: the catch-all branch used to return the empty default for ANY
# non-numbered-slot name, so lima-node (primary, empty suffix) and
# lima-node-smoke (also empty) collided on the same konnectivity-agent<suffix>
# Pod/Secret and kubelet-serving<suffix> cert names whenever paired via
# --extra-node -- a regression this PR's own 2nd round introduced by making
# add-node.sh call node_suffix_for() too.
assert_true "'lima-node' primary and 'lima-node-smoke' never collide (non-numbered names get distinct suffixes too)" \
  test "$(node_suffix_for lima-node)" != "$(node_suffix_for lima-node-smoke)"

# ---------------------------------------------------------------------------
# Standard 2-node pairing (dispatch-prompt-template.md's documented "most
# commonly joined via --extra-node" case): a lima-start.sh primary on
# lima-node-2 alongside an add-node.sh join of lima-node-3. Both sides must
# independently land on the SAME suffix a bare `--vm lima-node-N` invocation
# of either name would get on its own -- that's what makes reprovisioning
# idempotent regardless of which script started a given VM.
# ---------------------------------------------------------------------------
PRIMARY_SUFFIX="$(node_suffix_for lima-node-2)"
JOINED_SUFFIX="$(node_suffix_for lima-node-3)"
assert_eq "standard pairing: lima-node-2 primary auto-derives '-2'" "-2" "$PRIMARY_SUFFIX"
assert_eq "standard pairing: lima-node-3 join auto-derives '-3', not the primary's '-2'" "-3" "$JOINED_SUFFIX"
assert_true "standard pairing: lima-node-2 primary + lima-node-3 join never collide on konnectivity-agent<suffix>" \
  test "$PRIMARY_SUFFIX" != "$JOINED_SUFFIX"

# Higher numbered slots (lima-node-4/-5, also listed as --extra-node-joinable
# in dispatch-prompt-template.md's Lima VM protocol table) must be just as
# collision-free as the -2/-3 pair above -- the derivation is a general
# VM_NAME->suffix rule, not special-cased to slots 2/3 only.
assert_true "lima-node-4 primary + lima-node-5 join never collide" \
  test "$(node_suffix_for lima-node-4)" != "$(node_suffix_for lima-node-5)"

# ---------------------------------------------------------------------------
# Structural checks against the real scripts: the assertions above prove the
# derivation function itself is right, but not that lima-start.sh and
# add-node.sh actually call it instead of an inline copy or a hardcoded value.
# ---------------------------------------------------------------------------
assert_true "lima-start.sh computes NODE_SUFFIX via the shared node_suffix_for() helper" \
  grep -qF 'NODE_SUFFIX=$(node_suffix_for "$VM_NAME" "$_NODE_SUFFIX_OVERRIDE")' "$LIMA_START"

# Regression guard: the pre-fix line set NODE_SUFFIX unconditionally at top
# level (no VM_NAME dispatch at all) -- prove that flat form is gone, not
# just that a working case arm also happens to exist elsewhere.
assert_false "(regression guard) NODE_SUFFIX is no longer a flat, VM_NAME-agnostic default" \
  grep -qE '^NODE_SUFFIX="\$\{_NODE_SUFFIX_OVERRIDE:-\}"$' "$LIMA_START"

assert_true "add-node.sh sources _lib.sh for the shared node_suffix_for() helper" \
  grep -qF 'source "$DIR/_lib.sh"' "$ADD_NODE"
assert_true "add-node.sh derives its own --node-suffix from VM_NAME via node_suffix_for()" \
  grep -qF 'NODE_SUFFIX=$(node_suffix_for "$VM_NAME")' "$ADD_NODE"

# Regression guard (review fix): the pre-fix line forwarded a
# hardcoded "-2" to lima-start.sh no matter which VM add-node.sh was actually
# starting -- prove that literal is gone, not just that a correct call also
# happens to exist elsewhere. This is the exact line whose revert reintroduces
# the standard-pairing collision this test file's root-cause-#2 section above
# is named for.
assert_false "(regression guard) add-node.sh no longer hardcodes --node-suffix \"-2\"" \
  grep -qF -- '--node-suffix "-2"' "$ADD_NODE"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

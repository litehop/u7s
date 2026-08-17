#!/usr/bin/env bash
# Unit tests for scripts/conformance/run-all.sh's --network flag wire-through
# (mayor-c4syr).
#
# lima-start.sh (mayor-njq7j/PR #1194) accepts --network to isolate a VM onto
# its own Lima network -- the current mitigation for the Lima usernet ARP
# defect (mayor-o61zz), which otherwise lets one VM's daemon flaps take down
# every VM sharing its network. run-all.sh never forwarded --network to
# lima-start.sh at all: any operator or worker running
# `run-all.sh --vm lima-node --network user-v2-mayor --reset` got silently
# routed back onto lima-start.sh's own default (user-v2), defeating the
# isolation and re-exposing every VM on that shared network to the defect --
# exactly the "time-bomb" this bead calls out. This test proves run-all.sh
# actually builds and forwards a --network arg (not just accepts the flag)
# to BOTH lima-start.sh (the primary node, Step 3) and add-node.sh (a 2nd
# node via --extra-node) -- the multi-node case needs the SAME network on
# both sides, since two nodes on different networks would have no route to
# each other regardless of this bug.
#
# Exits 0 on success, 1 on any assertion failure.
# shellcheck disable=SC2016 # file-wide: every single-quoted grep pattern below
# intentionally matches the literal, unexpanded source text of run-all.sh /
# add-node.sh, not something meant to expand in this script's own shell.
set -euo pipefail

PASS=0
FAIL=0

assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
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
# network_arg_for() -- mirrors run-all.sh's / add-node.sh's own
# `[ -n "$NETWORK" ] && _NETWORK_ARG="--network $NETWORK"` gate. An absent
# --network must stay a no-op arg -- lima-start.sh's own user-v2 default is
# preserved for every caller that never passes the flag at all, so this fix
# cannot change behavior for the common case.
# ---------------------------------------------------------------------------
network_arg_for() {
  local network="$1"
  [ -n "$network" ] && echo "--network $network" || echo ""
}

assert "an absent --network produces no forwarded arg (unset default is preserved)" \
  "$([ "$(network_arg_for "")" = "" ] && echo 1 || echo 0)"
assert "a given --network value forwards verbatim as --network <value>" \
  "$([ "$(network_arg_for user-v2-mayor)" = "--network user-v2-mayor" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Structural checks against the real scripts: the mirror function above
# proves the decision logic is right, but not that run-all.sh / add-node.sh
# actually wire it into the lima-start.sh command lines that matter. Grep
# for the literal invocation lines (fixed-string) -- this is the part that
# actually regresses if a future edit to either script drops the forward
# while leaving the flag parsed (looks like it works, does nothing).
# ---------------------------------------------------------------------------
DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_ALL="$DIR/run-all.sh"
ADD_NODE="$DIR/add-node.sh"

assert_true "run-all.sh parses --network into a NETWORK variable" \
  grep -qE '^\s*--network\)\s*NETWORK="\$2"; shift 2 ;;\s*$' "$RUN_ALL"
assert_true "run-all.sh builds _NETWORK_ARG from NETWORK" \
  grep -qF '_NETWORK_ARG="--network $NETWORK"' "$RUN_ALL"
assert_true "run-all.sh forwards _NETWORK_ARG to the primary node's lima-start.sh call (Step 3)" \
  grep -qF 'bash "$DIR/lima-start.sh" ${_PORT_ARG} ${_KUBELET_PORT_ARG} ${_KONNECTIVITY_SERVER_PORT_ARG} ${_WORKDIR_ARG} ${_NETWORK_ARG} ${_VERBOSE_ARG}' "$RUN_ALL"
assert_true "run-all.sh forwards _NETWORK_ARG to add-node.sh (2nd node, --extra-node) so both nodes can share a network" \
  grep -qF 'bash "$DIR/add-node.sh" "$EXTRA_NODE" "$EXTRA_KUBELET_PORT" ${_PORT_ARG} ${_WORKDIR_ARG} ${_NETWORK_ARG} ${_VERBOSE_ARG}' "$RUN_ALL"

assert_true "add-node.sh parses --network into a _NETWORK_OVERRIDE variable" \
  grep -qE '^\s*--network\)\s*_NETWORK_OVERRIDE="\$2"; shift 2 ;;\s*$' "$ADD_NODE"
assert_true "add-node.sh forwards --network to its own lima-start.sh call" \
  grep -qF 'bash "$DIR/lima-start.sh" --vm "$VM_NAME" --kubelet-port "$KUBELET_PORT" --port "$PORT" ${_WORKDIR_ARG} ${_NETWORK_ARG} --node-suffix "-2" ${_VERBOSE_ARG}' "$ADD_NODE"

# Regression guard: prove the PRE-FIX invocation lines (no _NETWORK_ARG at
# all) are gone, not just that a working line also happens to be present
# elsewhere -- protects against a future edit that reintroduces a duplicate
# call site regressing back to the old, non-forwarding form.
assert_false "(regression guard) run-all.sh's Step 3 lima-start.sh call no longer omits --network forwarding" \
  grep -qF 'bash "$DIR/lima-start.sh" ${_PORT_ARG} ${_KUBELET_PORT_ARG} ${_KONNECTIVITY_SERVER_PORT_ARG} ${_WORKDIR_ARG} ${_VERBOSE_ARG}' "$RUN_ALL"
assert_false "(regression guard) run-all.sh's add-node.sh call no longer omits --network forwarding" \
  grep -qF 'bash "$DIR/add-node.sh" "$EXTRA_NODE" "$EXTRA_KUBELET_PORT" ${_PORT_ARG} ${_WORKDIR_ARG} ${_VERBOSE_ARG}' "$RUN_ALL"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

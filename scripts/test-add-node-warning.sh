#!/usr/bin/env bash
# Unit test for scripts/conformance/add-node.sh's restart-warning gating.
#
# PR #1422 added an unconditional stderr warning: a standalone
# add-node.sh invocation doesn't update an already-running apiserver's
# --node-kubelet-port mapping, so kubectl logs/exec against the joined node's
# pods 404 until the apiserver restarts. But run-all.sh --extra-node invokes
# this same script internally (scripts/conformance/run-all.sh:459-464+469) on
# the exact path that warning itself recommends -- _NODE_KUBELET_PORT_ARG
# already wired --node-kubelet-port into 02-start-apiserver.sh before
# add-node.sh runs there, so no 404 is possible. Ungated, every --extra-node
# run printed a scary warning about a problem that path doesn't have.
#
# Exercises the REAL add-node.sh as a subprocess (not a reimplementation of
# its warning logic), gated on the sentinel run-all.sh sets
# (U7S_ADD_NODE_FROM_RUN_ALL=1) at its internal call site. No live VM/apiserver
# needed: the warning (or its absence) is printed before add-node.sh's
# kubectl reachability check, so a fake VM name/port and an empty --workdir
# are enough to exercise the gating.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/conformance/add-node.sh"

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

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

WARNING_TEXT="does not update the running apiserver's --node-kubelet-port mapping"

# ---------------------------------------------------------------------------
# 1. Standalone invocation, no sentinel -- the actual "known-broken" path
#    PR #1422's warning exists for (a live apiserver that has no idea the
#    joining node's kubelet port exists). The warning must fire here; a user
#    running add-node.sh by hand against an already-started apiserver has no
#    other way to learn kubectl logs/exec will silently 404.
# ---------------------------------------------------------------------------
set +e
STDERR_BARE=$(env -u U7S_ADD_NODE_FROM_RUN_ALL bash "$SCRIPT" fake-vm 12345 --workdir "$WORKDIR/bare" 2>&1 >/dev/null)
set -e
assert "standalone add-node.sh invocation (no sentinel) prints the restart warning" \
  "$(echo "$STDERR_BARE" | grep -qF "$WARNING_TEXT" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. run-all.sh --extra-node's internal invocation (sentinel set) -- the
#    apiserver is already correctly configured before this script runs
#    (run-all.sh's _NODE_KUBELET_PORT_ARG, wired in at Step 2), so no 404 can
#    occur and the warning would only be noise on the exact "supported" path
#    it recommends. Must NOT fire here.
# ---------------------------------------------------------------------------
set +e
STDERR_SENTINEL=$(U7S_ADD_NODE_FROM_RUN_ALL=1 bash "$SCRIPT" fake-vm 12345 --workdir "$WORKDIR/sentinel" 2>&1 >/dev/null)
set -e
assert "run-all.sh's internal invocation (U7S_ADD_NODE_FROM_RUN_ALL=1) suppresses the warning" \
  "$(echo "$STDERR_SENTINEL" | grep -qF "$WARNING_TEXT" && echo 0 || echo 1)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

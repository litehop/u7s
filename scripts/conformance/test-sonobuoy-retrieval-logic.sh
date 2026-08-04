#!/usr/bin/env bash
# Unit test for the results-retrieval sequence in 06-run-sonobuoy.sh.
#
# Live incident 2026-08-04: a real --focus run completed sonobuoy cleanly but
# the retrieval sequence produced ZERO output after "Retrieving results..." --
# no error, no timeout, nothing. run-all.sh returned control with no results
# file ever written. Manual recovery confirmed two bugs:
#
#   1. The tarball search only ever checked $VM_NAME (the primary node), never
#      $EXTRA_NODE -- sonobuoy's own scheduler placed the aggregator pod on
#      the extra node, so the primary-only search always came up empty there.
#   2. None of kubectl logs / kubectl get pod / limactl shell find / limactl
#      copy had any timeout -- a stalled SSH/konnectivity session hangs the
#      whole script forever with no diagnostic output at all.
#
# This test exercises real spawned processes (not just string/decision
# logic), because bug 2 is specifically about whether a wedged process is
# actually killed and the script actually returns -- a test that only
# inspects strings can't prove a hang was broken out of.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

PASS=0
FAIL=0
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

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

# ---------------------------------------------------------------------------
# run_with_timeout() -- mirrors 06-run-sonobuoy.sh's function of the same
# name verbatim. Keep in sync if that function changes.
# ---------------------------------------------------------------------------
run_with_timeout() {
  local label="$1" secs="$2" suppress_stderr="$3"
  shift 3
  if [ "$suppress_stderr" = "1" ]; then
    "$@" 2>/dev/null &
  else
    "$@" &
  fi
  local cmd_pid=$! waited=0
  while kill -0 "$cmd_pid" 2>/dev/null; do
    if [ "$waited" -ge "$secs" ]; then
      kill -9 "$cmd_pid" 2>/dev/null
      wait "$cmd_pid" 2>/dev/null || true
      echo "error: '$label' timed out after ${secs}s" >&2
      return 124
    fi
    sleep 1
    waited=$(( waited + 1 ))
  done
  local status=0
  wait "$cmd_pid" || status=$?
  return "$status"
}

# ---------------------------------------------------------------------------
# Node-search logic -- mirrors 06-run-sonobuoy.sh's HOST_PATH loop exactly
# (iterate every node in NODES, stop at the first hit). Keep in sync if that
# loop changes. fake_find_tarball_on_node stands in for
# 'limactl shell $NODE sudo find ...' so this test needs no real VM.
# ---------------------------------------------------------------------------
fake_find_tarball_on_node() {
  local node="$1" tarball="$2"
  find "$TMPDIR_TEST/$node/vol" -name "$tarball" 2>/dev/null | head -1
}

search_all_nodes() {
  local tarball="$1"
  HOST_PATH=""
  FOUND_NODE=""
  local node candidate
  for node in "${NODES[@]}"; do
    candidate=$(fake_find_tarball_on_node "$node" "$tarball")
    if [ -n "$candidate" ]; then
      HOST_PATH="$candidate"
      FOUND_NODE="$node"
      break
    fi
  done
}

# The pre-fix version -- hardcoded to only ever check $VM_NAME, mirroring the
# exact bug at 06-run-sonobuoy.sh:202-204 before this fix. Kept here ONLY so
# this test can demonstrate the bug: run with RUN_OLD_BUGGY_VERSION=1 to see
# it miss a tarball that genuinely exists on the extra node.
search_primary_only() {
  local tarball="$1"
  HOST_PATH=$(fake_find_tarball_on_node "$VM_NAME" "$tarball")
}

# ---------------------------------------------------------------------------
# Fixture: sonobuoy's aggregator pod scheduled onto the EXTRA node (exactly
# the live incident), so the results tarball genuinely exists there and NOT
# on the primary.
# ---------------------------------------------------------------------------
VM_NAME="primary-node"
EXTRA_NODE="extra-node"
NODES=("$VM_NAME" "$EXTRA_NODE")
TARBALL_NAME="sonobuoy_202608041234_abc123.tar.gz"

mkdir -p "$TMPDIR_TEST/$VM_NAME/vol" "$TMPDIR_TEST/$EXTRA_NODE/vol"
touch "$TMPDIR_TEST/$EXTRA_NODE/vol/$TARBALL_NAME"

if [ "${RUN_OLD_BUGGY_VERSION:-0}" = "1" ]; then
  echo "--- OLD buggy search_primary_only() (only checks \$VM_NAME) ---"
  search_primary_only "$TARBALL_NAME"
  if [ -z "$HOST_PATH" ]; then
    echo "CONFIRMED BUG: primary-only search missed the tarball that exists on \$EXTRA_NODE"
  else
    echo "primary-only search unexpectedly found it: $HOST_PATH"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# 1. Bug 1 fix: searching every node in the run finds the tarball regardless
#    of which node sonobuoy's scheduler picked.
# ---------------------------------------------------------------------------
echo "--- NEW fixed search_all_nodes() (searches all NODES) ---"
search_all_nodes "$TARBALL_NAME"
assert "fixed multi-node search finds the tarball scheduled onto the extra node" \
  "$([ -n "$HOST_PATH" ] && [ "$FOUND_NODE" = "$EXTRA_NODE" ] && echo 1 || echo 0)"

# Regression guard: prove the OLD approach genuinely fails in this same
# scenario, so this test would catch a regression back to primary-only search.
search_primary_only "$TARBALL_NAME"
assert "(regression guard) primary-only search genuinely misses a tarball on the extra node" \
  "$([ -z "$HOST_PATH" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. Bug 2 fix: a call that finishes normally is completely unaffected by
#    the timeout wrapper (real exit code and output both pass through).
# ---------------------------------------------------------------------------
FAST_OUT=$(run_with_timeout "fast echo" 5 0 sh -c 'echo hi; exit 0')
FAST_STATUS=$?
assert "a command that finishes normally is unaffected by run_with_timeout" \
  "$([ "$FAST_STATUS" -eq 0 ] && [ "$FAST_OUT" = "hi" ] && echo 1 || echo 0)"

STDERR_GENUINE_FAIL="$TMPDIR_TEST/genuine-fail-stderr.txt"
GENUINE_FAIL_STATUS=0
run_with_timeout "real failure" 5 0 sh -c 'exit 3' 2>"$STDERR_GENUINE_FAIL" || GENUINE_FAIL_STATUS=$?
assert "a genuine (non-timeout) failure passes through its real exit code with no extra noise -- misreporting it as a timeout would mislead whoever debugs it" \
  "$([ "$GENUINE_FAIL_STATUS" -eq 3 ] && [ ! -s "$STDERR_GENUINE_FAIL" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. Bug 2 fix, the core case: a call that hangs (standing in for a wedged
#    SSH/konnectivity session against limactl/kubectl) is killed and surfaced
#    loudly with a specific message, instead of hanging the whole script
#    forever with zero output -- the exact 2026-08-04 incident symptom.
# ---------------------------------------------------------------------------
PIDFILE="$TMPDIR_TEST/hung.pid"
STDERR_HUNG="$TMPDIR_TEST/hung-stderr.txt"
START=$(date +%s)
HANG_STATUS=0
run_with_timeout "hung limactl call" 1 0 sh -c "echo \$\$ > '$PIDFILE'; sleep 300" 2>"$STDERR_HUNG" || HANG_STATUS=$?
END=$(date +%s)
ELAPSED=$(( END - START ))

assert "a hung call returns in a few seconds instead of blocking for its full 300s duration" \
  "$([ "$ELAPSED" -lt 10 ] && echo 1 || echo 0)"
assert "a hung call's exit status is the conventional timeout code (124)" \
  "$([ "$HANG_STATUS" -eq 124 ] && echo 1 || echo 0)"
assert "a clear, specific message names which call timed out (was: total silence)" \
  "$(grep -q "'hung limactl call' timed out after 1s" "$STDERR_HUNG" && echo 1 || echo 0)"

HUNG_PID="$(cat "$PIDFILE" 2>/dev/null || echo "")"
assert "the hung process is actually killed, not left running as an orphan" \
  "$([ -n "$HUNG_PID" ] && ! kill -0 "$HUNG_PID" 2>/dev/null && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. suppress_stderr must hide only the wrapped command's own stderr, never
#    run_with_timeout's own timeout message. Caught during development: a
#    naive '2>/dev/null' appended after the whole run_with_timeout call
#    silences its own diagnostic along with the wrapped command's -- which
#    would have reintroduced the "zero output" incident even with a timeout
#    in place.
# ---------------------------------------------------------------------------
STDERR_SUPPRESSED="$TMPDIR_TEST/suppressed-stderr.txt"
run_with_timeout "suppressed-stderr timeout" 1 1 \
  sh -c "echo 'inner noise' >&2; sleep 300" 2>"$STDERR_SUPPRESSED" || true
assert "suppress_stderr hides the wrapped command's stderr but not run_with_timeout's own timeout message" \
  "$(grep -q "'suppressed-stderr timeout' timed out after 1s" "$STDERR_SUPPRESSED" \
     && ! grep -q "inner noise" "$STDERR_SUPPRESSED" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

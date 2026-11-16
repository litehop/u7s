#!/usr/bin/env bash
# Unit test for the Phase-1/Phase-2 dhat heap-file diversion in u7s-start.sh.
#
# Bug: scripts/u7s-start.sh's --reset flow launches the
# apiserver TWICE on a fresh workdir -- Phase 1 (no --konnectivity-proxy-addr,
# while ca.crt doesn't exist yet) and Phase 2 (killed + restarted once
# konnectivity-server is up). Both phases inherited the SAME
# U7S_DHAT_HEAP_FILE, so under a --features dhat build, Phase 1's
# few-seconds bootstrap heap silently overwrote the operator-requested path
# via dhat's Drop-based flush before Phase 2 -- the real, many-minutes run --
# ever got SIGTERM'd. Observed live: run 0806-1102's first
# dhat-heap-apiserver-*.json contained only Phase 1's 2.6s bootstrap heap;
# the real run's heap only existed because an operator noticed 20+ minutes
# later and killed Phase 2 by hand.
#
# This test proves Phase 1 is diverted to a distinct scratch path and Phase 2
# is restored to the operator-requested path, mirroring u7s-start.sh's own
# diversion block (right before the --background launch, and right before
# the Phase 2 relaunch) -- keep in sync if that logic changes.
#
# Exits 0 on success, 1 on any assertion failure.
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

# ---------------------------------------------------------------------------
# Structural checks against the real u7s-start.sh source (a copied mirror of
# the logic cannot fail, so the script itself is the only meaningful guard):
# Phase 1 is diverted to a scratch path and Phase 2 restored to the
# operator-requested path. Fixed-string greps.
# ---------------------------------------------------------------------------
U7S_START="$(cd "$(dirname "$0")/.." && pwd)/u7s-start.sh"
assert "u7s-start.sh diverts Phase 1 to an mktemp file under \$WORKDIR" \
  "$(grep -qF 'mktemp "$WORKDIR/dhat-phase1.XXXXXX"' "$U7S_START" && echo 1 || echo 0)"
assert "u7s-start.sh restores the operator-requested dhat path for Phase 2" \
  "$(grep -qF 'export U7S_DHAT_HEAP_FILE="$_DHAT_HEAP_FILE_FINAL"' "$U7S_START" && echo 1 || echo 0)"
# A PID-derived /tmp name is guessable and attacker-pre-creatable (symlink
# clobber of the operator's files when dhat's Profiler drops).
assert "u7s-start.sh no longer uses a predictable /tmp dhat path" \
  "$(grep -qE '/tmp/u7s-dhat' "$U7S_START" && echo 0 || echo 1)"
assert "u7s-start.sh removes the Phase 1 scratch file" \
  "$(grep -qF 'rm -f "$_DHAT_PHASE1_FILE"' "$U7S_START" && echo 1 || echo 0)"
# dhat flushes on Drop after SIGTERM, so an rm before the process exits lets
# the file reappear and leak.
KILL_LN=$(grep -nF 'kill "$SERVER_PID" 2>/dev/null || true' "$U7S_START" | tail -1 | cut -d: -f1)
WAIT_LN=$(grep -nF 'kill -0 "$SERVER_PID" 2>/dev/null || break' "$U7S_START" | head -1 | cut -d: -f1)
RM_LN=$(grep -nF 'rm -f "$_DHAT_PHASE1_FILE"' "$U7S_START" | head -1 | cut -d: -f1)
assert "u7s-start.sh waits for Phase 1 exit between kill and scratch rm" \
  "$([ -n "$KILL_LN" ] && [ -n "$WAIT_LN" ] && [ -n "$RM_LN" ] && [ "$KILL_LN" -lt "$WAIT_LN" ] && [ "$WAIT_LN" -lt "$RM_LN" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

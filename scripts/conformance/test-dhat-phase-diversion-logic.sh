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
# resolve_phase_env() -- mirrors u7s-start.sh's diversion decision exactly:
# given the operator-requested U7S_DHAT_HEAP_FILE, whether this is a
# --background launch, and whether ca.crt exists yet, print the env value
# Phase 1 (this launch) and Phase 2 (the restart, if one happens) would each
# see. scratch_pid stands in for u7s-start.sh's own "$$".
# ---------------------------------------------------------------------------
resolve_phase_env() {
  local dhat_heap_file="$1" background="$2" ca_crt_exists="$3" scratch_pid="$4"
  local diverted=0 heap_file_final="" phase1_env="$dhat_heap_file" phase2_env="$dhat_heap_file"

  if [ -n "$dhat_heap_file" ] && [ "$background" -eq 1 ] && [ "$ca_crt_exists" -eq 0 ]; then
    diverted=1
    heap_file_final="$dhat_heap_file"
    phase1_env="/tmp/u7s-dhat-phase1-${scratch_pid}.json"
  fi

  [ "$diverted" -eq 1 ] && phase2_env="$heap_file_final"

  echo "${phase1_env}|${phase2_env}"
}

# The pre-fix version -- mirrors the exact bug: both phases share the same
# env var untouched, so Phase 1's Drop-based flush overwrites whatever Phase
# 2 would later write to the same path.
resolve_phase_env_old_buggy() {
  local dhat_heap_file="$1"
  echo "${dhat_heap_file}|${dhat_heap_file}"
}

# ---------------------------------------------------------------------------
# 1. Fresh --reset (ca.crt absent) + dhat build in play: Phase 1 must get a
#    scratch path DISTINCT from the operator-requested path, so its bootstrap
#    heap can't clobber it; Phase 2 must get the operator-requested path back.
# ---------------------------------------------------------------------------
RESULT=$(resolve_phase_env "/run/dhat-heap.json" 1 0 4242)
PHASE1="${RESULT%%|*}"
PHASE2="${RESULT##*|}"
assert "Phase 1 (ca.crt absent, dhat build) is diverted to a scratch path" \
  "$([ "$PHASE1" = "/tmp/u7s-dhat-phase1-4242.json" ] && echo 1 || echo 0)"
assert "Phase 1's scratch path differs from the operator-requested path" \
  "$([ "$PHASE1" != "/run/dhat-heap.json" ] && echo 1 || echo 0)"
assert "Phase 2 is restored to the operator-requested path" \
  "$([ "$PHASE2" = "/run/dhat-heap.json" ] && echo 1 || echo 0)"

# Regression guard: prove the OLD logic genuinely lets Phase 1 and Phase 2
# share one path -- the actual overwrite bug this fix closes. If this
# assertion ever failed, the "old buggy" mirror would no longer represent
# the bug, and the fix's necessity above couldn't be demonstrated.
OLD_RESULT=$(resolve_phase_env_old_buggy "/run/dhat-heap.json")
assert "(regression guard) pre-fix logic shares one path across both phases" \
  "$([ "${OLD_RESULT%%|*}" = "${OLD_RESULT##*|}" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. ca.crt already exists (e.g. a plain restart without --reset): no Phase 2
#    restart happens at all in u7s-start.sh, so the single launch must use
#    the operator-requested path directly -- no diversion needed or wanted.
# ---------------------------------------------------------------------------
RESULT=$(resolve_phase_env "/run/dhat-heap.json" 1 1 4242)
assert "ca.crt pre-existing (single launch, no Phase 2 restart) is not diverted" \
  "$([ "$RESULT" = "/run/dhat-heap.json|/run/dhat-heap.json" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. No dhat build in play (U7S_DHAT_HEAP_FILE unset): diversion must be a
#    complete no-op -- must stay unset through both phases, never
#    accidentally introducing a scratch path for a non-dhat build.
# ---------------------------------------------------------------------------
RESULT=$(resolve_phase_env "" 1 0 4242)
assert "no U7S_DHAT_HEAP_FILE set (non-dhat build) stays unset through both phases" \
  "$([ "$RESULT" = "|" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Structural check against the real u7s-start.sh source: the mirror function
# above proves the decision logic is right, but not that u7s-start.sh
# actually wires it up. Grep for the literal scratch-path assignment itself
# (fixed-string, not regex -- the pattern contains shell-special characters).
# ---------------------------------------------------------------------------
U7S_START="$(cd "$(dirname "$0")/.." && pwd)/u7s-start.sh"
assert "u7s-start.sh actually diverts Phase 1 to a distinct scratch path" \
  "$(grep -qF '/tmp/u7s-dhat-phase1-$$.json' "$U7S_START" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

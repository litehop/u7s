#!/usr/bin/env bash
# Unit test for run-all.sh's dhat-heap-flush teardown (the step that moves
# $DHAT_HEAP_FILE into a --profile run's temp/e2e/<slug>/ directory after
# SIGTERM'ing the apiserver).
#
# Bug: the teardown waited a FIXED 10s after SIGTERM for the apiserver to
# exit and flush its dhat heap (dhat::Profiler::drop only serializes the
# JSON on a graceful exit), then warned but PROCEEDED ANYWAY to `mv` whatever
# was sitting at the fixed $DHAT_HEAP_FILE path — with no check that the
# file it moved actually belonged to the PID that was just signalled. dhat
# only overwrites that fixed path on a graceful exit and never cleans it up
# on its own, so a STALE heap left over from an earlier, separately
# crashed/replaced --profile invocation can still be sitting there. On a
# real, long depth-20 profiled run, the real apiserver took measurably
# longer than 10s to serialize its ~92MB heap, so the teardown's `mv` grabbed
# an EARLIER aborted attempt's 14.5MB heap instead — silently mislabeling a
# ~2-minute aborted run's data as the real run's, with no error, only an
# easy-to-miss warning.
#
# This test proves the fixed decision logic (a) never moves a heap file
# whose embedded "pid" doesn't match the SIGTERM'd apiserver PID(s), in both
# the "wrong file present the whole time" and "right file lands late, after
# a wait" cases, and (b) the real run-all.sh source actually implements this
# check (a grep-based structural check, since exercising the real 5-minute
# wait loop end-to-end isn't practical here) — so reverting the fix fails
# this test, not just a same-bug-twice mirror.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_ALL="$REPO/scripts/conformance/run-all.sh"

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

write_heap() {
  local path="$1" pid="$2"
  printf '{"dhatFileVersion":2,"mode":"rust-heap","pid":%s,"te":123}\n' "$pid" > "$path"
}

# ---------------------------------------------------------------------------
# Fixed decision logic — mirrors run-all.sh's move step exactly: only move
# $heap_file to $dest if its embedded "pid" matches one of the PID(s) that
# were just SIGTERM'd. Echoes "moved" or "refused:<reason>".
# ---------------------------------------------------------------------------
dhat_heap_move_decision() {
  local heap_file="$1" dest="$2"; shift 2
  local -a expected_pids=("$@")

  if [ ! -f "$heap_file" ]; then
    echo "refused:missing"
    return
  fi

  local heap_pid
  heap_pid=$(grep -o '"pid":[0-9]*' "$heap_file" | head -1 | grep -o '[0-9]*' || true)

  local ok=0 expected
  for expected in "${expected_pids[@]:-}"; do
    [ -n "$expected" ] && [ "$heap_pid" = "$expected" ] && ok=1 && break
  done

  if [ "$ok" -eq 1 ]; then
    mv "$heap_file" "$dest"
    echo "moved"
  else
    echo "refused:pid-mismatch(heap=${heap_pid:-<none>})"
  fi
}

# The pre-fix version — moves unconditionally whenever the file exists,
# exactly mirroring the original bug (no pid awareness at all).
dhat_heap_move_decision_old_buggy() {
  local heap_file="$1" dest="$2"
  if [ -f "$heap_file" ]; then
    mv "$heap_file" "$dest"
    echo "moved"
  else
    echo "refused:missing"
  fi
}

# ---------------------------------------------------------------------------
# 1. Stale wrong-pid file sitting at the fixed path (the exact real-world
#    scenario: an earlier aborted --profile attempt's leftover heap). The
#    fixed logic must refuse to move it and must leave it in place.
# ---------------------------------------------------------------------------
HEAP="$TMPDIR_TEST/dhat-heap.json"
DEST="$TMPDIR_TEST/dhat-heap-apiserver-out.json"
write_heap "$HEAP" 99999
RESULT=$(dhat_heap_move_decision "$HEAP" "$DEST" 33371)
assert "stale wrong-pid file (99999 vs expected 33371) is refused, not moved" \
  "$([ "${RESULT%%:*}" = "refused" ] && echo 1 || echo 0)"
assert "stale file is left in place at the source path (never silently moved)" \
  "$([ -f "$HEAP" ] && echo 1 || echo 0)"
assert "no destination file was created from the stale source" \
  "$([ ! -f "$DEST" ] && echo 1 || echo 0)"

# Regression guard: prove the OLD logic genuinely grabs the stale file
# unconditionally — the actual mislabeling bug this fix closes. If this
# assertion ever failed, the "old buggy" mirror would no longer represent
# the bug, and the fix's necessity above couldn't be demonstrated.
HEAP2="$TMPDIR_TEST/dhat-heap2.json"
DEST2="$TMPDIR_TEST/dhat-heap-apiserver-out2.json"
write_heap "$HEAP2" 99999
OLD_RESULT=$(dhat_heap_move_decision_old_buggy "$HEAP2" "$DEST2")
assert "(regression guard) pre-fix logic silently moves the stale wrong-pid file" \
  "$([ "$OLD_RESULT" = "moved" ] && [ -f "$DEST2" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. The real apiserver's own file, matching the SIGTERM'd pid, is present.
#    Must be moved to the destination.
# ---------------------------------------------------------------------------
HEAP3="$TMPDIR_TEST/dhat-heap3.json"
DEST3="$TMPDIR_TEST/dhat-heap-apiserver-out3.json"
write_heap "$HEAP3" 33371
RESULT=$(dhat_heap_move_decision "$HEAP3" "$DEST3" 33371)
assert "matching-pid file (33371) is moved" "$([ "$RESULT" = "moved" ] && echo 1 || echo 0)"
assert "destination now holds the correct-pid file's content" \
  "$(grep -q '"pid":33371' "$DEST3" 2>/dev/null && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. lsof -ti can return MULTIPLE pids for one port; the file's pid only
#    needs to match ONE of them.
# ---------------------------------------------------------------------------
HEAP4="$TMPDIR_TEST/dhat-heap4.json"
DEST4="$TMPDIR_TEST/dhat-heap-apiserver-out4.json"
write_heap "$HEAP4" 5002
RESULT=$(dhat_heap_move_decision "$HEAP4" "$DEST4" 5001 5002 5003)
assert "file matching any one of several SIGTERM'd PIDs is moved" \
  "$([ "$RESULT" = "moved" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. Simulated "waits for and correctly picks up the real PID's file": a
#    stale wrong-pid file sits at the fixed path when the wait begins; a
#    background job overwrites it with the real apiserver's own pid shortly
#    before the (simulated, shortened) wait loop gives up. The move decision
#    taken AFTER the wait must see and move the real file, not the stale one
#    that was there when the wait started.
# ---------------------------------------------------------------------------
HEAP5="$TMPDIR_TEST/dhat-heap5.json"
DEST5="$TMPDIR_TEST/dhat-heap-apiserver-out5.json"
write_heap "$HEAP5" 99999
( sleep 0.3; write_heap "$HEAP5" 33371 ) &
BG_PID=$!
# Mirrors run-all.sh's any_alive wait loop, shortened for test speed: poll
# until the "apiserver" (BG_PID) exits, up to a bound, THEN make the move
# decision -- exercising the real "wait, then verify" sequencing, not just
# the pid-compare in isolation.
for _ in $(seq 1 20); do
  kill -0 "$BG_PID" 2>/dev/null || break
  sleep 0.05
done
wait "$BG_PID" 2>/dev/null || true
RESULT=$(dhat_heap_move_decision "$HEAP5" "$DEST5" 33371)
assert "late-arriving real-pid file (written after a wait) is correctly picked up" \
  "$([ "$RESULT" = "moved" ] && echo 1 || echo 0)"
assert "picked-up file's content is the real run's, not the stale one present at wait-start" \
  "$(grep -q '"pid":33371' "$DEST5" 2>/dev/null && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 5. Simulated "errors loudly if it can't be found": the wait loop's bound
#    is exhausted while the ONLY file present is still the stale one (the
#    real apiserver never finishes in time, in this run). The move decision
#    must refuse, not fall back to the stale file just because something is
#    present at the path.
# ---------------------------------------------------------------------------
HEAP6="$TMPDIR_TEST/dhat-heap6.json"
DEST6="$TMPDIR_TEST/dhat-heap-apiserver-out6.json"
write_heap "$HEAP6" 99999
for _ in $(seq 1 5); do
  sleep 0.02
done
RESULT=$(dhat_heap_move_decision "$HEAP6" "$DEST6" 33371)
assert "wait exhausted with only the stale file present still refuses to move it" \
  "$([ "${RESULT%%:*}" = "refused" ] && echo 1 || echo 0)"
assert "stale file from a still-pending real run is left in place, not misattributed" \
  "$([ -f "$HEAP6" ] && [ ! -f "$DEST6" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 6. A later run's own teardown must not be fooled by a wrong-pid file left
#    behind by an EARLIER run's failed/aborted attempt at this same fixed
#    path -- the pid check must catch it regardless of how the file got
#    there or how long ago.
# ---------------------------------------------------------------------------
HEAP7="$TMPDIR_TEST/dhat-heap7.json"
DEST7="$TMPDIR_TEST/dhat-heap-apiserver-out7.json"
write_heap "$HEAP7" 17258
RESULT=$(dhat_heap_move_decision "$HEAP7" "$DEST7" 33371)
assert "a later run's teardown refuses an earlier run's leftover pid'd file" \
  "$([ "${RESULT%%:*}" = "refused" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Structural check against the real run-all.sh source: the mirror function
# above proves the decision logic is right, but not that run-all.sh actually
# wires it up. Fails against the pre-fix source (no pid comparison existed
# at all), so reverting the fix fails this test.
# ---------------------------------------------------------------------------
assert "run-all.sh extracts the heap file's embedded pid before moving it" \
  "$(grep -qF '"pid":[0-9]*' "$RUN_ALL" && echo 1 || echo 0)"
assert "run-all.sh compares the extracted pid against the SIGTERM'd apiserver PID(s)" \
  "$(grep -qF 'HEAP_PID_OK' "$RUN_ALL" && echo 1 || echo 0)"
assert "run-all.sh errors loudly (not just warns) on a pid mismatch" \
  "$(grep -qF "does not match the SIGTERM'd apiserver PID" "$RUN_ALL" && echo 1 || echo 0)"
assert "run-all.sh's wait loop was extended well past the old 10s window" \
  "$(grep -qF 'seq 1 300' "$RUN_ALL" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

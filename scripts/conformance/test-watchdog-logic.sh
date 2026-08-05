#!/usr/bin/env bash
# Unit test for the namespace TTL watchdog decision logic in 06-run-sonobuoy.sh.
#
# Exercises the core body of watchdog_loop without a real cluster:
#   - System namespaces (default, kube-*, sonobuoy) must never be deleted.
#   - Active namespaces >= 10 min must be flagged for deletion.
#   - Any namespace >= 15 min must be flagged regardless of phase.
#   - Fresh namespaces (< 10 min) must be left alone even if Active.
#   - Terminating namespaces < 15 min must be left alone.
#   - A namespace still Active at the several-minute mark (the normal lifetime
#     of a legitimate [Slow] conformance test, e.g. a 5-minute gomega.Consistently
#     check) must be left alone — the watchdog is a leak/stuck-namespace safety
#     net, not a bound on how long a healthy test may run.
#   - An Active namespace >= 10 min old must be left alone (deferred to the
#     unconditional 15 min backstop) when another Active namespace is
#     independently also past 10 min in the same snapshot — a fixed 10-minute
#     threshold breaks whenever a whole run's pace is slower than baseline,
#     force-deleting legitimately-still-running [Slow] tests instead of just
#     the one that's actually stuck.
#   - The same namespace must still be force-deleted at 10 min when it has no
#     such old peer — the fix must not weaken the safety net for a genuinely
#     stuck/leaked namespace running alongside otherwise-healthy ones.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

PASS=0
FAIL=0

assert_deleted() {
  local label="$1" ns="$2" output="$3"
  if printf '%s' "$output" | grep -q "force-deleting namespace '${ns}'"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — expected '${ns}' to be force-deleted but it was not"
    echo "  output was: $output"
    FAIL=$(( FAIL + 1 ))
  fi
}

assert_not_deleted() {
  local label="$1" ns="$2" output="$3"
  if printf '%s' "$output" | grep -q "force-deleting namespace '${ns}'"; then
    echo "FAIL: $label — '${ns}' was force-deleted but should have been left alone"
    echo "  output was: $output"
    FAIL=$(( FAIL + 1 ))
  else
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# Isolated decision function — mirrors the watchdog_loop body without I/O.
# Arguments: now_epoch  ns  phase  created_rfc3339  [slow_active_count]
# slow_active_count is the number of Active non-system namespaces (including
# this one) that are already >= 10m old in the same snapshot — the peer
# signal 06-run-sonobuoy.sh's count_slow_active_namespaces() computes.
# Prints "force-deleting namespace '<ns>'" when the namespace should be deleted.
# ---------------------------------------------------------------------------
watchdog_decide() {
  local now="$1" ns="$2" phase="$3" created="$4" slow_active_count="${5:-0}"

  # Skip system namespaces.
  case "$ns" in
    default|sonobuoy|kube-*) return 0 ;;
  esac

  # Convert RFC3339 to epoch seconds on macOS.
  local created_s
  created_s=$(date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "${created}" "+%s" 2>/dev/null) || return 0
  local age_s=$(( now - created_s ))

  local should_delete=0 reason=""
  if [ "$age_s" -ge 900 ]; then
    should_delete=1
    reason="age=${age_s}s (>= 15m threshold, phase=${phase})"
  elif [ "$phase" = "Active" ] && [ "$age_s" -ge 600 ]; then
    # slow_active_count includes this namespace itself, so >= 2 means at
    # least one OTHER Active namespace is also past 10m right now — defer to
    # the unconditional 15m backstop above instead of force-deleting a
    # namespace that may just be a slow but healthy test in a slow run.
    if [ "$slow_active_count" -lt 2 ]; then
      should_delete=1
      reason="Active for ${age_s}s (>= 10m threshold)"
    fi
  fi

  if [ "$should_delete" -eq 1 ]; then
    echo "force-deleting namespace '${ns}' (${reason})"
  fi
}

# ---------------------------------------------------------------------------
# Build a fixed reference time so ages are deterministic.
# All "created" timestamps below are computed relative to NOW.
# ---------------------------------------------------------------------------
NOW=$(date -u +%s)

# Helper: subtract seconds from NOW and format as RFC3339.
ts_ago() {
  local secs="$1"
  date -j -u -r $(( NOW - secs )) "+%Y-%m-%dT%H:%M:%SZ"
}

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

# 1. Active namespace, 11 minutes old → must be deleted (>= 10m Active threshold).
OUT=$(watchdog_decide "$NOW" "e2e-test-abc" "Active" "$(ts_ago 660)")
assert_deleted "Active ns 11m old is force-deleted" "e2e-test-abc" "$OUT"

# 2. Active namespace, 2 minutes old → must NOT be deleted (below 10m threshold).
OUT=$(watchdog_decide "$NOW" "e2e-test-fresh" "Active" "$(ts_ago 120)")
assert_not_deleted "Active ns 2m old is left alone" "e2e-test-fresh" "$OUT"

# 3. Terminating namespace, 16 minutes old → must be deleted (>= 15m any-phase threshold).
OUT=$(watchdog_decide "$NOW" "e2e-test-stuck" "Terminating" "$(ts_ago 960)")
assert_deleted "Terminating ns 16m old is force-deleted" "e2e-test-stuck" "$OUT"

# 4. Terminating namespace, 4 minutes old → must NOT be deleted (below both thresholds).
OUT=$(watchdog_decide "$NOW" "e2e-test-draining" "Terminating" "$(ts_ago 240)")
assert_not_deleted "Terminating ns 4m old is left alone" "e2e-test-draining" "$OUT"

# 5. System namespace 'default', 1 hour old → must NOT be deleted.
OUT=$(watchdog_decide "$NOW" "default" "Active" "$(ts_ago 3600)")
assert_not_deleted "System ns 'default' is never touched" "default" "$OUT"

# 6. System namespace 'sonobuoy', 1 hour old → must NOT be deleted.
OUT=$(watchdog_decide "$NOW" "sonobuoy" "Active" "$(ts_ago 3600)")
assert_not_deleted "System ns 'sonobuoy' is never touched" "sonobuoy" "$OUT"

# 7. System namespace matching kube-* pattern, 1 hour old → must NOT be deleted.
OUT=$(watchdog_decide "$NOW" "kube-system" "Active" "$(ts_ago 3600)")
assert_not_deleted "System ns 'kube-system' is never touched" "kube-system" "$OUT"

# 8. Active namespace, exactly at 10m boundary (600s) → must be deleted (>= means inclusive).
OUT=$(watchdog_decide "$NOW" "e2e-test-boundary" "Active" "$(ts_ago 600)")
assert_deleted "Active ns exactly 10m old hits threshold" "e2e-test-boundary" "$OUT"

# 9. Any-phase namespace, exactly at 15m boundary (900s) → must be deleted.
OUT=$(watchdog_decide "$NOW" "e2e-test-boundary2" "Terminating" "$(ts_ago 900)")
assert_deleted "Terminating ns exactly 15m old hits threshold" "e2e-test-boundary2" "$OUT"

# 10. Active namespace, 599 seconds old → must NOT be deleted (just below threshold).
OUT=$(watchdog_decide "$NOW" "e2e-test-just-under" "Active" "$(ts_ago 599)")
assert_not_deleted "Active ns 599s old is below threshold" "e2e-test-just-under" "$OUT"

# 11. Regression: Active namespace, 6 minutes old → must NOT be deleted.
# This is the exact namespace age profile of "[sig-apps] CronJob should not
# schedule jobs when suspended", which keeps its namespace Active for a full
# 5-minute gomega.Consistently check (cronJobTimeout) plus setup overhead.
# With the old 5-minute Active threshold this watchdog force-deleted that
# namespace out from under the still-running, otherwise-healthy test — the
# CronJob object itself was never touched by the apiserver, but the test then
# failed with 'CronJob "suspended" not found' because its whole namespace was
# yanked mid-check. Fails on revert to the 300s threshold.
OUT=$(watchdog_decide "$NOW" "e2e-test-cronjob-suspended" "Active" "$(ts_ago 360)")
assert_not_deleted "Active ns 6m old (mid Consistently-check test) is left alone" \
  "e2e-test-cronjob-suspended" "$OUT"

# 12. Regression: Active namespace, 11 minutes old, with another Active
# namespace also independently past 10m in the same snapshot (slow_active_count=2)
# → must NOT be deleted. Live forensics traced a run at ~2.4x baseline
# wall-clock (2908s vs 1233s) where the OLD fixed 10-minute threshold
# force-deleted 6 different still-progressing [Slow] test namespaces
# (statefulset-4013 and 5 others) simply because the whole run was running
# slow, not because any of them were stuck — corrupting each test's own
# result and confusing the run's failure list. Fails on revert to the old
# logic that ignored slow_active_count entirely.
OUT=$(watchdog_decide "$NOW" "statefulset-4013" "Active" "$(ts_ago 660)" 2)
assert_not_deleted "Active ns 11m old with a same-age peer is left alone (run pace looks slow)" \
  "statefulset-4013" "$OUT"

# 13. Sanity: Active namespace, 11 minutes old, with NO other Active namespace
# past 10m (slow_active_count=1, itself only) → must still be deleted. The
# adaptive check above must only excuse a namespace when there is concrete
# peer evidence of a slow run; a lone namespace stuck at 11 minutes while
# every peer is comfortably young is exactly the leak/stuck case the
# watchdog exists to catch, and must still be reaped at 10 minutes.
OUT=$(watchdog_decide "$NOW" "e2e-test-lone-stuck" "Active" "$(ts_ago 660)" 1)
assert_deleted "Active ns 11m old with no old peer is still force-deleted (safety net intact)" \
  "e2e-test-lone-stuck" "$OUT"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

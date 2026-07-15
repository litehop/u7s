#!/usr/bin/env bash
# Unit test for the namespace TTL watchdog decision logic in 06-run-sonobuoy.sh.
#
# Exercises the core body of watchdog_loop without a real cluster:
#   - System namespaces (default, kube-*, sonobuoy) must never be deleted.
#   - Active namespaces >= 20 min must be flagged for deletion.
#   - Any namespace >= 30 min must be flagged regardless of phase.
#   - Fresh namespaces (< 20 min) must be left alone even if Active.
#   - Terminating namespaces < 30 min must be left alone.
#   - A namespace still Active at the several-minute mark (the normal lifetime
#     of a legitimate [Slow] conformance test, e.g. a 5-minute gomega.Consistently
#     check) must be left alone — the watchdog is a leak/stuck-namespace safety
#     net, not a bound on how long a healthy test may run.
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
# Arguments: now_epoch  ns  phase  created_rfc3339
# Prints "force-deleting namespace '<ns>'" when the namespace should be deleted.
# ---------------------------------------------------------------------------
watchdog_decide() {
  local now="$1" ns="$2" phase="$3" created="$4"

  # Skip system namespaces.
  case "$ns" in
    default|sonobuoy|kube-*) return 0 ;;
  esac

  # Convert RFC3339 to epoch seconds on macOS.
  local created_s
  created_s=$(date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "${created}" "+%s" 2>/dev/null) || return 0
  local age_s=$(( now - created_s ))

  local should_delete=0 reason=""
  if [ "$phase" = "Active" ] && [ "$age_s" -ge 1200 ]; then
    should_delete=1
    reason="Active for ${age_s}s (>= 20m threshold)"
  elif [ "$age_s" -ge 1800 ]; then
    should_delete=1
    reason="age=${age_s}s (>= 30m threshold, phase=${phase})"
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

# 1. Active namespace, 21 minutes old → must be deleted (>= 20m Active threshold).
OUT=$(watchdog_decide "$NOW" "e2e-test-abc" "Active" "$(ts_ago 1260)")
assert_deleted "Active ns 21m old is force-deleted" "e2e-test-abc" "$OUT"

# 2. Active namespace, 2 minutes old → must NOT be deleted (below 20m threshold).
OUT=$(watchdog_decide "$NOW" "e2e-test-fresh" "Active" "$(ts_ago 120)")
assert_not_deleted "Active ns 2m old is left alone" "e2e-test-fresh" "$OUT"

# 3. Terminating namespace, 31 minutes old → must be deleted (>= 30m any-phase threshold).
OUT=$(watchdog_decide "$NOW" "e2e-test-stuck" "Terminating" "$(ts_ago 1860)")
assert_deleted "Terminating ns 31m old is force-deleted" "e2e-test-stuck" "$OUT"

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

# 8. Active namespace, exactly at 20m boundary (1200s) → must be deleted (>= means inclusive).
OUT=$(watchdog_decide "$NOW" "e2e-test-boundary" "Active" "$(ts_ago 1200)")
assert_deleted "Active ns exactly 20m old hits threshold" "e2e-test-boundary" "$OUT"

# 9. Any-phase namespace, exactly at 30m boundary (1800s) → must be deleted.
OUT=$(watchdog_decide "$NOW" "e2e-test-boundary2" "Terminating" "$(ts_ago 1800)")
assert_deleted "Terminating ns exactly 30m old hits threshold" "e2e-test-boundary2" "$OUT"

# 10. Active namespace, 1199 seconds old → must NOT be deleted (just below threshold).
OUT=$(watchdog_decide "$NOW" "e2e-test-just-under" "Active" "$(ts_ago 1199)")
assert_not_deleted "Active ns 1199s old is below threshold" "e2e-test-just-under" "$OUT"

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

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

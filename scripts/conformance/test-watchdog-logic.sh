#!/usr/bin/env bash
# Unit test for the namespace TTL watchdog decision logic in 06-run-sonobuoy.sh.
#
# Exercises the core body of watchdog_loop without a real cluster:
#   - System namespaces (default, kube-*, sonobuoy) must never be deleted.
#   - Active namespaces >= 5 min must be flagged for deletion.
#   - Any namespace >= 10 min must be flagged regardless of phase.
#   - Fresh namespaces (< 5 min) must be left alone even if Active.
#   - Terminating namespaces < 10 min must be left alone.
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
  if [ "$phase" = "Active" ] && [ "$age_s" -ge 300 ]; then
    should_delete=1
    reason="Active for ${age_s}s (>= 5m threshold)"
  elif [ "$age_s" -ge 600 ]; then
    should_delete=1
    reason="age=${age_s}s (>= 10m threshold, phase=${phase})"
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

# 1. Active namespace, 6 minutes old → must be deleted (>= 5m Active threshold).
OUT=$(watchdog_decide "$NOW" "e2e-test-abc" "Active" "$(ts_ago 360)")
assert_deleted "Active ns 6m old is force-deleted" "e2e-test-abc" "$OUT"

# 2. Active namespace, 2 minutes old → must NOT be deleted (below 5m threshold).
OUT=$(watchdog_decide "$NOW" "e2e-test-fresh" "Active" "$(ts_ago 120)")
assert_not_deleted "Active ns 2m old is left alone" "e2e-test-fresh" "$OUT"

# 3. Terminating namespace, 11 minutes old → must be deleted (>= 10m any-phase threshold).
OUT=$(watchdog_decide "$NOW" "e2e-test-stuck" "Terminating" "$(ts_ago 660)")
assert_deleted "Terminating ns 11m old is force-deleted" "e2e-test-stuck" "$OUT"

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

# 8. Active namespace, exactly at 5m boundary (300s) → must be deleted (>= means inclusive).
OUT=$(watchdog_decide "$NOW" "e2e-test-boundary" "Active" "$(ts_ago 300)")
assert_deleted "Active ns exactly 5m old hits threshold" "e2e-test-boundary" "$OUT"

# 9. Any-phase namespace, exactly at 10m boundary (600s) → must be deleted.
OUT=$(watchdog_decide "$NOW" "e2e-test-boundary2" "Terminating" "$(ts_ago 600)")
assert_deleted "Terminating ns exactly 10m old hits threshold" "e2e-test-boundary2" "$OUT"

# 10. Active namespace, 299 seconds old → must NOT be deleted (just below threshold).
OUT=$(watchdog_decide "$NOW" "e2e-test-just-under" "Active" "$(ts_ago 299)")
assert_not_deleted "Active ns 299s old is below threshold" "e2e-test-just-under" "$OUT"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

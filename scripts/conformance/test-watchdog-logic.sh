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
#   - A CSI driver namespace (<parent-test-ns>-<random>, per upstream's
#     storageframework) must be left alone while its parent test namespace
#     still exists, regardless of age — reaping it kills the driver out from
#     under the still-running parent test and orphans its PVs.
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
# Arguments: now_epoch  ns  phase  created_rfc3339  [parent_exists_fn]
# parent_exists_fn is the name of a function taking one arg (a namespace name)
# and returning 0 if it exists, 1 otherwise — production wires this to a real
# `kubectl get ns`, tests inject a stub, so this function never shells out
# itself and stays hermetic.
# Prints "force-deleting namespace '<ns>'" when the namespace should be deleted.
# ---------------------------------------------------------------------------
watchdog_decide() {
  local now="$1" ns="$2" phase="$3" created="$4" parent_exists_fn="${5:-}"

  # Skip system namespaces.
  case "$ns" in
    default|sonobuoy|kube-*) return 0 ;;
  esac

  # Driver-namespace exemption: a namespace matching <slug>-<N>-<M> is the CSI
  # driver namespace upstream's storageframework provisions as a CHILD of
  # test namespace <slug>-<N> (test/e2e/storage/drivers/csi.go ->
  # CreateDriverNamespace -> framework/util.go's CreateTestingNS). Skip the
  # age-based reap entirely while the parent still exists — the driver may
  # still be needed for that test's ongoing operations, so its own age is not
  # a valid signal to reap it on.
  if [[ "$ns" =~ ^(.+-[0-9]+)-[0-9]+$ ]] && [ -n "$parent_exists_fn" ]; then
    local parent_ns="${BASH_REMATCH[1]}"
    if "$parent_exists_fn" "$parent_ns"; then
      return 0
    fi
  fi

  # Convert RFC3339 to epoch seconds. GNU date (Linux CI) understands -d
  # directly; BSD date (macOS dev host) has no -d at all and errors out
  # immediately with no stdout, so the fallback to -j -f is safe on both.
  local created_s
  created_s=$(date -u -d "${created}" "+%s" 2>/dev/null) || \
    created_s=$(date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "${created}" "+%s" 2>/dev/null) || return 0
  local age_s=$(( now - created_s ))

  local should_delete=0 reason=""
  if [ "$phase" = "Active" ] && [ "$age_s" -ge 600 ]; then
    should_delete=1
    reason="Active for ${age_s}s (>= 10m threshold)"
  elif [ "$age_s" -ge 900 ]; then
    should_delete=1
    reason="age=${age_s}s (>= 15m threshold, phase=${phase})"
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

# Helper: subtract seconds from NOW and format as RFC3339. GNU date accepts
# "@<epoch>" directly; BSD date has no -d at all and errors with no stdout,
# so falling back to -j -r is safe on both.
ts_ago() {
  local secs="$1"
  local epoch=$(( NOW - secs ))
  date -u -d "@${epoch}" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || \
    date -j -u -r "${epoch}" "+%Y-%m-%dT%H:%M:%SZ"
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

# ---------------------------------------------------------------------------
# Driver-namespace parent-existence stub — stands in for `kubectl get ns` so
# these cases never touch a real cluster. A namespace "exists" only if it is
# listed in EXISTING_PARENT_NAMESPACES for the current case.
# ---------------------------------------------------------------------------
EXISTING_PARENT_NAMESPACES=()
stub_parent_exists() {
  local candidate
  # "${arr[@]}" on a genuinely empty array is an unbound-variable error under
  # `set -u` in bash 3.2 (macOS's shipped /bin/bash) — the ":-" fallback keeps
  # the "no existing parents" case from crashing the whole test run.
  for candidate in "${EXISTING_PARENT_NAMESPACES[@]:-}"; do
    [ "$candidate" = "$1" ] && return 0
  done
  return 1
}

# 12. Driver namespace (multivolume-3161-7041), 11 minutes old, whose parent
# test namespace (multivolume-3161) is still Active. This is the actual bug:
# upstream's storageframework runs the CSI driver in this child namespace,
# and age-only reaping killed it out from under the still-running parent
# test, orphaning its PVs into 20-minute delete-wait timeouts. Fails on
# revert of the parent-existence check.
EXISTING_PARENT_NAMESPACES=("multivolume-3161")
OUT=$(watchdog_decide "$NOW" "multivolume-3161-7041" "Active" "$(ts_ago 660)" stub_parent_exists)
assert_not_deleted "Driver-ns is spared while its parent test namespace still exists" \
  "multivolume-3161-7041" "$OUT"

# 13. Same driver namespace, same age, but its parent test namespace is gone.
# A driver-ns that outlives its parent has no test left to serve it, so the
# exemption above must not become a permanent shield — it has to fall back to
# the unchanged 10m/15m thresholds once the causal reason to keep it is gone.
EXISTING_PARENT_NAMESPACES=()
OUT=$(watchdog_decide "$NOW" "multivolume-3161-7041" "Active" "$(ts_ago 660)" stub_parent_exists)
assert_deleted "Driver-ns reaps normally once its parent test namespace is gone" \
  "multivolume-3161-7041" "$OUT"

# 14. A regular test namespace with a single numeric suffix (no driver
# involved), 11 minutes old. Must keep reaping on the unchanged thresholds —
# the new driver-ns regex must never accidentally exempt an ordinary test
# namespace just because its name happens to end in digits.
EXISTING_PARENT_NAMESPACES=()
OUT=$(watchdog_decide "$NOW" "multivolume-3161" "Active" "$(ts_ago 660)" stub_parent_exists)
assert_deleted "Regular single-suffix test namespace still reaps unchanged" \
  "multivolume-3161" "$OUT"

# 15. Nested-suffix edge case: foo-1-2-3. The regex anchors on the TRAILING
# two numeric suffixes, so the parent lookup resolves to "foo-1-2" (dropping
# only the final "-3"), not "foo-1". Upstream never nests suffixes this deep
# in practice; this documents the deliberate choice (greedy match toward the
# longest valid parent candidate) rather than leaving the behavior undefined.
EXISTING_PARENT_NAMESPACES=("foo-1-2")
OUT=$(watchdog_decide "$NOW" "foo-1-2-3" "Active" "$(ts_ago 660)" stub_parent_exists)
assert_not_deleted "Nested-suffix foo-1-2-3 resolves its parent to foo-1-2 (trailing two suffixes), not foo-1" \
  "foo-1-2-3" "$OUT"

# 16. Adversarial: foo-9999-9999 whose would-be parent foo-9999 was never a
# real namespace. Guards against an implementation that treats any
# two-numeric-suffix name as automatically exempt without truly querying
# parent existence — it must still reap per the normal thresholds.
EXISTING_PARENT_NAMESPACES=()
OUT=$(watchdog_decide "$NOW" "foo-9999-9999" "Active" "$(ts_ago 660)" stub_parent_exists)
assert_deleted "foo-9999-9999 reaps normally when foo-9999 was never a real namespace" \
  "foo-9999-9999" "$OUT"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

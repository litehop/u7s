#!/usr/bin/env bash
# Unit test for scripts/conformance/aggregate-run-metrics.sh.
#
# sample-run-metrics.sh already writes rss.csv/vm-free.csv/ring-age.csv/
# metrics-NN-<label>.prom into every conformance run's temp/e2e/<slug>/
# monitoring/ directory, but nothing rolled them into a report an operator
# could read at a glance -- rss.csv alone routinely runs to 1000+ lines per
# run (see the real fixture referenced in aggregate-run-metrics.sh's own
# design notes), so "eyeball it" meant grepping by hand every time, the exact
# problem class sample-run-metrics.sh itself was built to remove from the
# SAMPLING side.
#
# This test invokes the REAL script as a subprocess against synthetic
# fixtures with hand-computed expected numbers baked into the CSV/prom
# content below -- not a copied-out mirror of its arithmetic -- so a
# regression in the real peak/delta/quantile logic (e.g. someone "simplifies"
# the histogram scan to grab the wrong bucket, or the RSS grouping regexes
# stop matching truncated `comm=` values) fails this test, not just a
# same-bug-twice mirror.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO/scripts/conformance/aggregate-run-metrics.sh"

PASS=0
FAIL=0
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label -- expected to find: $needle"
    echo "  --- actual output ---"
    echo "  ${haystack//$'\n'/$'\n'  }"
    FAIL=$(( FAIL + 1 ))
  fi
}

# ===========================================================================
# Fixture: a synthetic run directory with hand-computed expected peaks/deltas.
# ===========================================================================
RUN_DIR="$TMPDIR_TEST/0101-0000-conformance"
mkdir -p "$RUN_DIR/monitoring"
MON="$RUN_DIR/monitoring"

# --- rss.csv ---------------------------------------------------------------
# apiserver peaks at 20000 kb / 15000 kb footprint on its 2nd tick; scheduler
# only ever has one tick; kubelet/kube-controller/crio each get one VM row;
# "weirdproc" matches none of the tracked categories on purpose, to prove
# it lands in the "other processes" section instead of vanishing silently.
cat > "$MON/rss.csv" <<'CSV'
ts,scope,pid,comm,rss_kb,footprint_kb,cpu_seconds_cumulative
2026-01-01T00:00:00Z,host,100,apiserver,10000,8000,1.0
2026-01-01T00:00:30Z,host,100,apiserver,20000,15000,2.0
2026-01-01T00:00:00Z,host,101,scheduler,5000,4000,0.5
2026-01-01T00:00:00Z,lima-node,200,kubelet,50000,,3.0
2026-01-01T00:00:30Z,lima-node,200,kubelet,60000,,4.0
2026-01-01T00:00:00Z,lima-node,201,kube-controller,30000,,1.0
2026-01-01T00:00:00Z,lima-node,202,crio,40000,,1.0
2026-01-01T00:00:00Z,lima-node,203,weirdproc,99999,,1.0
CSV

# --- vm-free.csv -------------------------------------------------------------
# 3 ticks, 2 of which are under the default 100 MB threshold (80, then a new
# minimum of 50); only the 50 MB tick clears a tightened 60 MB threshold.
cat > "$MON/vm-free.csv" <<'CSV'
ts,vm,total_mb,used_mb,free_mb
2026-01-01T00:00:00Z,lima-node,4000,3000,1000
2026-01-01T00:00:30Z,lima-node,4000,3920,80
2026-01-01T00:01:00Z,lima-node,4000,3950,50
CSV

# --- ring-age.csv ------------------------------------------------------------
# /registry/pods/ peaks at 25 events / 12s span on its 2nd tick; configmaps
# never exceeds 3 events -- pods must rank first in the top-shards table.
cat > "$MON/ring-age.csv" <<'CSV'
ts,shard,events,span_secs
2026-01-01T00:00:00Z,/registry/pods/,10,5
2026-01-01T00:00:30Z,/registry/pods/,25,12
2026-01-01T00:00:00Z,/registry/configmaps/,3,1
CSV

# --- metrics snapshots -------------------------------------------------------
# Hand-computed deltas (see comment block below the fixtures):
#   5xx: 1 -> 6                    (delta 5)
#   watch events: 1000 -> 5000     (delta 4000)
#   longrunning gauge: 7 -> 10     (peak 10)
#   watch-open-duration buckets:   le=0.001 delta=40, le=0.01 delta=72, le=+Inf delta=80
#     -> p50 target=ceil(0.5*80)=40  -> first bucket clearing it: le=0.001
#     -> p99 target=ceil(0.99*80)=80 -> only +Inf clears it (tail case)
cat > "$MON/metrics-01-startup.prom" <<'PROM'
# TYPE apiserver_request_total counter
apiserver_request_total{code="200",resource="pods"} 100
apiserver_request_total{code="500",resource="pods"} 1
# TYPE apiserver_watch_events_total counter
apiserver_watch_events_total{resource="pods"} 1000
# TYPE apiserver_longrunning_requests gauge
apiserver_longrunning_requests{resource="pods"} 5
apiserver_longrunning_requests{resource="configmaps"} 2
# TYPE apiserver_watch_open_duration_seconds histogram
apiserver_watch_open_duration_seconds_bucket{resource="pods",le="0.001"} 10
apiserver_watch_open_duration_seconds_bucket{resource="pods",le="0.01"} 18
apiserver_watch_open_duration_seconds_bucket{resource="pods",le="+Inf"} 20
apiserver_watch_open_duration_seconds_sum{resource="pods"} 0.5
apiserver_watch_open_duration_seconds_count{resource="pods"} 20
PROM

cat > "$MON/metrics-02-pre-teardown.prom" <<'PROM'
# TYPE apiserver_request_total counter
apiserver_request_total{code="200",resource="pods"} 300
apiserver_request_total{code="500",resource="pods"} 4
apiserver_request_total{code="503",resource="configmaps"} 2
# TYPE apiserver_watch_events_total counter
apiserver_watch_events_total{resource="pods"} 5000
# TYPE apiserver_longrunning_requests gauge
apiserver_longrunning_requests{resource="pods"} 9
apiserver_longrunning_requests{resource="configmaps"} 1
# TYPE apiserver_watch_open_duration_seconds histogram
apiserver_watch_open_duration_seconds_bucket{resource="pods",le="0.001"} 50
apiserver_watch_open_duration_seconds_bucket{resource="pods",le="0.01"} 90
apiserver_watch_open_duration_seconds_bucket{resource="pods",le="+Inf"} 100
apiserver_watch_open_duration_seconds_sum{resource="pods"} 2.0
apiserver_watch_open_duration_seconds_count{resource="pods"} 100
PROM

# ===========================================================================
# 1. Peak RSS section -- tracked categories, "not observed" for absent ones,
#    and the uncategorized "weirdproc" landing in the other-processes table.
# ===========================================================================
OUT="$(bash "$SCRIPT" "$RUN_DIR")"

assert_contains "apiserver peak RSS reports its 2nd (higher) tick, in MB, not its 1st" \
  "$OUT" "| u7s-apiserver | 19.5 | 14.6 | 2 |"
assert_contains "scheduler peak RSS reflects its single sample" \
  "$OUT" "| u7s-scheduler | 4.9 | 3.9 | 1 |"
assert_contains "kubelet peak RSS reports its higher (2nd) VM-scope tick" \
  "$OUT" "| kubelet | 58.6 | -- | 2 |"
assert_contains "truncated comm=\"kube-controller\" is matched by prefix as kube-controller-manager" \
  "$OUT" "| kube-controller-manager | 29.3 | -- | 1 |"
assert_contains "comm=\"crio\" is matched as cri-o (the real /proc comm name, not the package name)" \
  "$OUT" "| cri-o | 39.1 | -- | 1 |"
assert_contains "a component with zero matching rows is reported as explicitly not-observed, not silently dropped from the table" \
  "$OUT" "| kube-proxy | not observed | -- | 0 |"
assert_contains "kube-network-policies with zero matching rows is also explicitly not-observed" \
  "$OUT" "| kube-network-policies | not observed | -- | 0 |"
assert_contains "an uncategorized process (weirdproc) is surfaced in the other-processes table instead of vanishing from the report" \
  "$OUT" "| weirdproc | 97.7 |"

# ===========================================================================
# 2. OOM proximity -- default 100 MB threshold, then a tightened 60 MB one.
# ===========================================================================
assert_contains "default 100 MB threshold counts both the 80 MB and 50 MB ticks as under-threshold, keyed to the true minimum's own timestamp" \
  "$OUT" "| lima-node | 3 | 2 | 50 | 2026-01-01T00:01:00Z |"

OUT_TIGHT="$(bash "$SCRIPT" "$RUN_DIR" --free-threshold-mb 60)"
assert_contains "--free-threshold-mb is actually wired to the counting logic, not just accepted and ignored" \
  "$OUT_TIGHT" "| lima-node | 3 | 1 | 50 | 2026-01-01T00:01:00Z |"

# ===========================================================================
# 3. Watch-ring saturation -- peak occupancy ranks shards, not first-seen order.
# ===========================================================================
assert_contains "the shard with the higher peak occupancy (pods, 25) ranks above one that never exceeds 3 (configmaps)" \
  "$OUT" "| /registry/pods/ | 25 | 12 |"
assert_contains "a low-occupancy shard is still reported (not truncated away below its true peak)" \
  "$OUT" "| /registry/configmaps/ | 3 | 1 |"

# ===========================================================================
# 4. /metrics delta -- proves the counter/gauge/histogram arithmetic, not
#    just that some numbers get printed.
# ===========================================================================
assert_contains "5xx delta sums BOTH 500 and 503 series across the interval (1 -> 6, delta 5), not just one status code" \
  "$OUT" "5xx responses** (apiserver_request_total): 1 -> 6 (delta: 5)"
assert_contains "watch-events counter delta is end-minus-start, not the raw end value" \
  "$OUT" "Watch events served** (apiserver_watch_events_total): 1000 -> 5000 (delta: 4000)"
assert_contains "longrunning gauge is summed across ALL resources at each snapshot, then the two snapshots' peak is reported (not a delta, since it's a gauge)" \
  "$OUT" "start=7, end=10, peak-of-the-two=10"
assert_contains "p50 lands on the first bucket whose delta clears the 50th-percentile rank (here the very first, tightest bucket)" \
  "$OUT" "p50: <= 0.001s (80 samples observed in interval)"
assert_contains "p99's target rank equals the total sample count exactly, so only the +Inf bucket clears it -- proves the tail case doesn't crash or silently pick a finite bucket that under-reports the real p99" \
  "$OUT" "p99: <= +Infs (80 samples observed in interval)"

# ---------------------------------------------------------------------------
# Regression guard: gauge-name auto-upgrade. If a future apiserver build
# starts emitting the bead's originally-requested apiserver_longrunning_gauge
# name, the report must prefer it over today's apiserver_longrunning_requests
# -- proves pick_gauge_metric's preference order is live, not just present in
# a comment.
# ---------------------------------------------------------------------------
RUN_DIR2="$TMPDIR_TEST/0101-0100-conformance"
mkdir -p "$RUN_DIR2/monitoring"
cat > "$RUN_DIR2/monitoring/metrics-01-startup.prom" <<'PROM'
# TYPE apiserver_longrunning_gauge gauge
apiserver_longrunning_gauge{resource="pods"} 3
PROM
cat > "$RUN_DIR2/monitoring/metrics-02-end.prom" <<'PROM'
# TYPE apiserver_longrunning_gauge gauge
apiserver_longrunning_gauge{resource="pods"} 7
PROM
OUT2="$(bash "$SCRIPT" "$RUN_DIR2")"
assert_contains "a snapshot containing the aspirational apiserver_longrunning_gauge name is preferred over the current apiserver_longrunning_requests fallback" \
  "$OUT2" "(apiserver_longrunning_gauge, gauge): start=3, end=7, peak-of-the-two=7"

# ===========================================================================
# 5. Missing-artifact robustness -- must degrade with a clear message, never
#    a stack trace or a silent empty section, since this is meant to run
#    unattended right after every conformance run.
# ===========================================================================
EMPTY_DIR="$TMPDIR_TEST/empty-run"
mkdir -p "$EMPTY_DIR"
set +e
OUT_EMPTY="$(bash "$SCRIPT" "$EMPTY_DIR" 2>&1)"
EMPTY_EXIT=$?
set -e
if [ "$EMPTY_EXIT" -eq 0 ]; then
  echo "PASS: a run directory with no sampler artifacts at all still exits 0 (report says why, doesn't fail the caller)"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: aggregate-run-metrics.sh exited $EMPTY_EXIT on an artifact-free directory: $OUT_EMPTY"
  FAIL=$(( FAIL + 1 ))
fi
assert_contains "a missing rss.csv is called out by name, not silently rendered as an empty table" \
  "$OUT_EMPTY" "rss.csv not found"
assert_contains "fewer than 2 metrics snapshots is reported as 'need at least a start and an end', not a bogus zero-delta" \
  "$OUT_EMPTY" "fewer than two metrics-*.prom snapshots"

# ===========================================================================
# 6. -o writes the same report to a file instead of stdout.
# ===========================================================================
OUT_FILE="$TMPDIR_TEST/report.md"
bash "$SCRIPT" "$RUN_DIR" -o "$OUT_FILE" >/dev/null
if [ -f "$OUT_FILE" ] && grep -q "u7s-apiserver | 19.5" "$OUT_FILE"; then
  echo "PASS: -o writes the full report to the given file"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: -o did not produce the expected report at $OUT_FILE"
  FAIL=$(( FAIL + 1 ))
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

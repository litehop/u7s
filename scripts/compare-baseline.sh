#!/usr/bin/env bash
# compare-baseline.sh — Diff a committed baseline latency JSON against a
# fresh scripts/bench-latency.sh run, so a perf PR can show a measured
# before/after instead of a vibe.
#
# Usage: compare-baseline.sh [--threshold-pct N] <baseline.json> <current.json>
#
# Exits 0 when none of p50_ms/p99_ms/mean_ms regressed by more than N%
# (default 10) past baseline. Exits 1 when at least one metric regressed past
# the threshold. Exits 2 on usage errors or malformed input JSON (missing
# fields) — distinct from 1 so a caller can tell "the gate failed" apart from
# "the gate could not even run".

set -euo pipefail

THRESHOLD_PCT=10
POSITIONAL=()

while [ $# -gt 0 ]; do
    case "$1" in
        --threshold-pct)
            THRESHOLD_PCT="${2:-}"
            shift 2
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [ "${#POSITIONAL[@]}" -ne 2 ]; then
    echo "Usage: $0 [--threshold-pct N] <baseline.json> <current.json>" >&2
    exit 2
fi

BASELINE_FILE="${POSITIONAL[0]}"
CURRENT_FILE="${POSITIONAL[1]}"

for f in "$BASELINE_FILE" "$CURRENT_FILE"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: file not found: $f" >&2
        exit 2
    fi
    if ! jq empty "$f" >/dev/null 2>&1; then
        echo "ERROR: $f is not valid JSON" >&2
        exit 2
    fi
done

# Only the fields this script actually reads are required — a JSON missing
# n/timestamp_utc (from an older bench-latency.sh, say) can still be diffed.
REQUIRED_FIELDS="p50_ms p99_ms mean_ms git_sha"

for f in "$BASELINE_FILE" "$CURRENT_FILE"; do
    for field in $REQUIRED_FIELDS; do
        if ! jq -e "has(\"$field\")" "$f" >/dev/null 2>&1; then
            echo "ERROR: $f is missing required field '$field' — hand-edited baseline with a broken schema?" >&2
            exit 2
        fi
    done
done

BASELINE_SHA=$(jq -r '.git_sha' "$BASELINE_FILE")
CURRENT_SHA=$(jq -r '.git_sha' "$CURRENT_FILE")

echo "baseline: $BASELINE_SHA vs current: $CURRENT_SHA"
echo ""
printf "%-10s %10s %10s %12s %10s\n" "metric" "baseline" "current" "delta_ms" "delta_pct"

REGRESSED=0

for metric in p50_ms p99_ms mean_ms; do
    BASE_VAL=$(jq -r ".${metric}" "$BASELINE_FILE")
    CUR_VAL=$(jq -r ".${metric}" "$CURRENT_FILE")
    DELTA_MS=$(awk -v b="$BASE_VAL" -v c="$CUR_VAL" 'BEGIN { printf "%.2f", c - b }')
    # delta_pct > 0 means current is slower than baseline (a regression);
    # guard b==0 so a degenerate zero baseline can't divide-by-zero in awk.
    DELTA_PCT=$(awk -v b="$BASE_VAL" -v c="$CUR_VAL" 'BEGIN {
        if (b == 0) { printf "0.00" } else { printf "%.2f", ((c - b) / b) * 100 }
    }')
    printf "%-10s %10s %10s %12s %9s%%\n" "$metric" "$BASE_VAL" "$CUR_VAL" "$DELTA_MS" "$DELTA_PCT"
    if awk -v pct="$DELTA_PCT" -v t="$THRESHOLD_PCT" 'BEGIN { exit !(pct > t) }'; then
        REGRESSED=1
    fi
done

echo ""
if [ "$REGRESSED" -eq 1 ]; then
    echo "FAIL: at least one metric regressed by more than ${THRESHOLD_PCT}% past baseline"
    exit 1
fi
echo "PASS: no metric regressed by more than ${THRESHOLD_PCT}% past baseline"

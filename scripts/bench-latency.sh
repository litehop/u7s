#!/usr/bin/env bash
# bench-latency.sh — Measure request latency of u7s-apiserver.
#
# Starts the server, fires 100 sequential GET /api requests, computes
# p50 and p99 wall-clock latency using sort + awk, saves results to
# ai/perf/. Does NOT enforce a latency threshold (too environment-sensitive).

set -euo pipefail

REQUESTS=100
SERVER_PID=""

TMPDIR="$(mktemp -d /tmp/u7s-bench-latency-XXXXXX)"
trap 'if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi' EXIT

echo "==> Building release binary..."
cargo build --release -p u7s-apiserver

echo "==> Starting apiserver (logs -> $TMPDIR/server.log)..."
BENCH_TOKEN="bench-token"
echo "$BENCH_TOKEN,bench-admin,uid0,system:masters" > "$TMPDIR/token-auth.csv"

./target/release/u7s-apiserver \
    --db "$TMPDIR/state.db" \
    --kubeconfig "$TMPDIR/kubeconfig" \
    --sa-key "$TMPDIR/sa.key" \
    --sa-pub "$TMPDIR/sa.pub" \
    --token-auth-file "$TMPDIR/token-auth.csv" \
    --advertise-address https://127.0.0.1:6443 \
    --service-cluster-ip-range "10.96.0.0/12" \
    >"$TMPDIR/server.log" 2>&1 &
SERVER_PID=$!

echo "==> Waiting for server to accept connections (up to 10s)..."
for i in $(seq 1 10); do
    nc -z 127.0.0.1 6443 2>/dev/null && break
    sleep 1
done
if ! nc -z 127.0.0.1 6443 2>/dev/null; then
    echo "ERROR: server did not start within 10s"
    cat "$TMPDIR/server.log" || true
    exit 1
fi

# Extract CA cert from kubeconfig for curl TLS verification
grep "certificate-authority-data" "$TMPDIR/kubeconfig" \
    | awk '{print $2}' \
    | base64 -d > "$TMPDIR/ca.pem"

TIMINGS_FILE="$TMPDIR/timings.txt"

echo "==> Firing $REQUESTS sequential GET /api requests..."
for i in $(seq 1 "$REQUESTS"); do
    curl \
        --silent \
        --output /dev/null \
        --write-out '%{time_total}\n' \
        --cacert "$TMPDIR/ca.pem" \
        -H "Authorization: Bearer $BENCH_TOKEN" \
        https://127.0.0.1:6443/api
done > "$TIMINGS_FILE"

# Compute p50, p99, and mean using sort + awk (no Python, no bc)
# time_total from curl is in seconds (e.g. 0.003142); convert to ms
P50=$(sort -n "$TIMINGS_FILE" | awk -v n="$REQUESTS" 'NR==int(n*0.50) {printf "%.2f", $1*1000}')
P99=$(sort -n "$TIMINGS_FILE" | awk -v n="$REQUESTS" 'NR==int(n*0.99) {printf "%.2f", $1*1000}')
# One extra unsorted pass over the same timings file for the mean (order does
# not matter for a sum), so a compare-baseline.sh regression is judged on more
# than just two percentile points.
MEAN=$(awk -v n="$REQUESTS" '{sum+=$1} END {printf "%.2f", (sum/n)*1000}' "$TIMINGS_FILE")

echo "p50: ${P50}ms  p99: ${P99}ms  mean: ${MEAN}ms"

# git_sha falls back to "unknown" rather than failing under set -e: this
# script's own conformance/CI runs always execute inside the repo, but a
# stray manual run from an extracted tarball should still produce a usable
# (if unattributable) JSON summary instead of aborting.
GIT_SHA=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
TIMESTAMP_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Save timestamped results
RESULTS_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)/ai/perf"
mkdir -p "$RESULTS_DIR"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RESULT_FILE="$RESULTS_DIR/latency-$TIMESTAMP.txt"
JSON_FILE="$RESULTS_DIR/latency-$TIMESTAMP.json"
{
    echo "u7s-apiserver latency benchmark"
    echo "Date: $(date -u)"
    echo "Requests: $REQUESTS"
    echo "p50: ${P50}ms"
    echo "p99: ${P99}ms"
    echo "mean: ${MEAN}ms"
    echo ""
    echo "Raw timings (seconds):"
    cat "$TIMINGS_FILE"
} > "$RESULT_FILE"

# Machine-readable twin of the .txt above, for scripts/compare-baseline.sh —
# the .txt stays the eyeballed form, this is the diffable form.
jq -n \
    --argjson p50_ms "$P50" \
    --argjson p99_ms "$P99" \
    --argjson mean_ms "$MEAN" \
    --argjson n "$REQUESTS" \
    --arg git_sha "$GIT_SHA" \
    --arg timestamp_utc "$TIMESTAMP_UTC" \
    '{p50_ms: $p50_ms, p99_ms: $p99_ms, mean_ms: $mean_ms, n: $n, git_sha: $git_sha, timestamp_utc: $timestamp_utc}' \
    > "$JSON_FILE"

echo "Results saved to: $RESULT_FILE"
echo "JSON results saved to: $JSON_FILE"

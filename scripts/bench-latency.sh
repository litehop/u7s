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

# Compute p50 and p99 using sort + awk (no Python, no bc)
# time_total from curl is in seconds (e.g. 0.003142); convert to ms
P50=$(sort -n "$TIMINGS_FILE" | awk -v n="$REQUESTS" 'NR==int(n*0.50) {printf "%.2f", $1*1000}')
P99=$(sort -n "$TIMINGS_FILE" | awk -v n="$REQUESTS" 'NR==int(n*0.99) {printf "%.2f", $1*1000}')

echo "p50: ${P50}ms  p99: ${P99}ms"

# Save timestamped results
RESULTS_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)/ai/perf"
mkdir -p "$RESULTS_DIR"
RESULT_FILE="$RESULTS_DIR/latency-$(date +%Y%m%d-%H%M%S).txt"
{
    echo "u7s-apiserver latency benchmark"
    echo "Date: $(date -u)"
    echo "Requests: $REQUESTS"
    echo "p50: ${P50}ms"
    echo "p99: ${P99}ms"
    echo ""
    echo "Raw timings (seconds):"
    cat "$TIMINGS_FILE"
} > "$RESULT_FILE"

echo "Results saved to: $RESULT_FILE"

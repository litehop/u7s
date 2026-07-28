#!/usr/bin/env bash
# bench-list-throughput.sh — Measure LIST request latency of u7s-apiserver
# as ConfigMap count grows (100/1000/5000), with and without a labelSelector,
# so a LIST-path perf PR has a reusable before/after instead of hand-collected
# numbers. Emits one JSON row per (item count, selector) combination.

set -euo pipefail

PORT="${U7S_BENCH_PORT:-18443}"
REQUESTS="${U7S_BENCH_REQUESTS:-50}"
COUNTS=(100 1000 5000)
NAMESPACE="bench-list-throughput"
SERVER_PID=""

TMPDIR="$(mktemp -d /tmp/u7s-bench-list-throughput-XXXXXX)"
trap 'if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi; rm -rf "$TMPDIR"' EXIT

echo "==> Building release binary..."
cargo build --release -p u7s-apiserver

echo "==> Starting apiserver on 127.0.0.1:$PORT (logs -> $TMPDIR/server.log)..."
BENCH_TOKEN="bench-token"
echo "$BENCH_TOKEN,bench-admin,uid0,system:masters" > "$TMPDIR/token-auth.csv"

./target/release/u7s-apiserver \
    --db "$TMPDIR/state.db" \
    --listen "127.0.0.1:$PORT" \
    --kubeconfig "$TMPDIR/kubeconfig" \
    --sa-key "$TMPDIR/sa.key" \
    --sa-pub "$TMPDIR/sa.pub" \
    --ca-key "$TMPDIR/ca.key" \
    --ca-cert "$TMPDIR/ca.crt" \
    --token-auth-file "$TMPDIR/token-auth.csv" \
    --advertise-address "https://127.0.0.1:$PORT" \
    --service-cluster-ip-range "10.96.0.0/12" \
    >"$TMPDIR/server.log" 2>&1 &
SERVER_PID=$!

echo "==> Waiting for server to accept connections (up to 10s)..."
for i in $(seq 1 10); do
    nc -z 127.0.0.1 "$PORT" 2>/dev/null && break
    sleep 1
done
if ! nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
    echo "ERROR: server did not start within 10s"
    cat "$TMPDIR/server.log" || true
    exit 1
fi

# Extract CA cert from kubeconfig for curl TLS verification
grep "certificate-authority-data" "$TMPDIR/kubeconfig" \
    | awk '{print $2}' \
    | base64 -d > "$TMPDIR/ca.pem"

BASE_URL="https://127.0.0.1:$PORT"
AUTH_HDR="Authorization: Bearer $BENCH_TOKEN"

echo "==> Creating namespace $NAMESPACE..."
curl --silent --show-error --fail --cacert "$TMPDIR/ca.pem" \
    -H "$AUTH_HDR" -H "Content-Type: application/json" \
    -X POST "$BASE_URL/api/v1/namespaces" \
    -d "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"$NAMESPACE\"}}" \
    >/dev/null

# Every seeded ConfigMap carries this label so labelSelector=bench-probe=all
# matches 100% of items — isolating the selector-matching pass's added cost
# rather than any speedup from filtering items out.
seed_configmaps() {
    local from="$1" to="$2"
    for i in $(seq "$from" "$to"); do
        curl --silent --show-error --fail --cacert "$TMPDIR/ca.pem" \
            -H "$AUTH_HDR" -H "Content-Type: application/json" \
            -X POST "$BASE_URL/api/v1/namespaces/$NAMESPACE/configmaps" \
            -d "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"bench-cm-$i\",\"labels\":{\"bench-probe\":\"all\"}},\"data\":{\"key\":\"value\"}}" \
            >/dev/null
        if [ "$((i % 1000))" -eq 0 ]; then
            echo "    ...seeded $i ConfigMaps"
        fi
    done
}

# Fires $REQUESTS sequential LISTs and records each curl time_total (seconds).
time_lists() {
    local query="$1" timings_file="$2"
    for i in $(seq 1 "$REQUESTS"); do
        curl --silent --output /dev/null --write-out '%{time_total}\n' \
            --cacert "$TMPDIR/ca.pem" -H "$AUTH_HDR" \
            "$BASE_URL/api/v1/namespaces/$NAMESPACE/configmaps$query"
    done > "$timings_file"
}

# Computes p50/p99/mean (ms) from a time_total timings file, same sort+awk
# approach as bench-latency.sh, and prints one JSON row via jq.
percentiles_json() {
    local timings_file="$1" count="$2" selector="$3"
    local p50 p99 mean
    p50=$(sort -n "$timings_file" | awk -v n="$REQUESTS" 'NR==int(n*0.50) {printf "%.2f", $1*1000}')
    p99=$(sort -n "$timings_file" | awk -v n="$REQUESTS" 'NR==int(n*0.99) {printf "%.2f", $1*1000}')
    mean=$(awk -v n="$REQUESTS" '{sum+=$1} END {printf "%.2f", (sum/n)*1000}' "$timings_file")
    jq -n \
        --argjson item_count "$count" \
        --arg label_selector "$selector" \
        --argjson p50_ms "$p50" \
        --argjson p99_ms "$p99" \
        --argjson mean_ms "$mean" \
        --argjson n "$REQUESTS" \
        '{item_count: $item_count, label_selector: $label_selector, p50_ms: $p50_ms, p99_ms: $p99_ms, mean_ms: $mean_ms, n: $n}'
}

RESULTS_FILE="$TMPDIR/results.jsonl"
: > "$RESULTS_FILE"
PREV_COUNT=0
for COUNT in "${COUNTS[@]}"; do
    echo "==> Seeding ConfigMaps $((PREV_COUNT + 1))..$COUNT in namespace $NAMESPACE..."
    seed_configmaps "$((PREV_COUNT + 1))" "$COUNT"
    PREV_COUNT="$COUNT"

    echo "==> Timing $REQUESTS sequential LISTs at $COUNT items (no selector)..."
    TIMINGS_PLAIN="$TMPDIR/timings-$COUNT-plain.txt"
    time_lists "" "$TIMINGS_PLAIN"
    percentiles_json "$TIMINGS_PLAIN" "$COUNT" "none" >> "$RESULTS_FILE"

    echo "==> Timing $REQUESTS sequential LISTs at $COUNT items (labelSelector=bench-probe=all)..."
    TIMINGS_SELECTOR="$TMPDIR/timings-$COUNT-selector.txt"
    time_lists "?labelSelector=bench-probe%3Dall" "$TIMINGS_SELECTOR"
    percentiles_json "$TIMINGS_SELECTOR" "$COUNT" "bench-probe=all" >> "$RESULTS_FILE"
done

GIT_SHA=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
TIMESTAMP_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

RESULTS_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)/ai/perf"
mkdir -p "$RESULTS_DIR"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
JSON_FILE="$RESULTS_DIR/list-throughput-$TIMESTAMP.json"

jq -s \
    --arg git_sha "$GIT_SHA" \
    --arg timestamp_utc "$TIMESTAMP_UTC" \
    '{git_sha: $git_sha, timestamp_utc: $timestamp_utc, results: .}' \
    "$RESULTS_FILE" > "$JSON_FILE"

echo "==> Results:"
cat "$JSON_FILE"
echo ""
echo "JSON results saved to: $JSON_FILE"

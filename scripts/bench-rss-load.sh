#!/usr/bin/env bash
# bench-rss-load.sh — Measure RSS delta under saturated inflight load.
#
# Saturates the server with:
#   - 50 concurrent GET requests cycling for 30 seconds
#   - 20 concurrent mutating (POST ConfigMap) requests cycling for 30 seconds
#
# Fails if RSS delta exceeds 20 MB (20480 kB) from baseline.
# Works on macOS and Linux.

set -euo pipefail

DELTA_THRESHOLD_KB=20480   # 20 MB
LOAD_DURATION_SECS=30
SERVER_PID=""
LOAD_PIDS=()

TMPDIR="$(mktemp -d /tmp/u7s-bench-load-XXXXXX)"
cleanup() {
    # Kill load workers first.
    for pid in "${LOAD_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    # Kill server.
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
    echo "Server log:"
    cat "$TMPDIR/server.log" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Build
# ---------------------------------------------------------------------------
echo "==> Building release binary..."
cargo build --release -p u7s-apiserver

# ---------------------------------------------------------------------------
# 2. Start server
# ---------------------------------------------------------------------------
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
    exit 1
fi

echo "==> Waiting 3s for memory to stabilize..."
sleep 3

# ---------------------------------------------------------------------------
# 3. Baseline RSS
# ---------------------------------------------------------------------------
BASELINE_KB=$(ps -o rss= -p "$SERVER_PID" | tr -d ' ')
if [ -z "$BASELINE_KB" ]; then
    echo "ERROR: could not sample baseline RSS for PID $SERVER_PID"
    exit 1
fi
echo "Baseline RSS: ${BASELINE_KB} kB"

# ---------------------------------------------------------------------------
# 4. Saturate with load
# ---------------------------------------------------------------------------
BASE_URL="https://127.0.0.1:6443"
CURL_OPTS="-k -s -o /dev/null -w '%{http_code}' --max-time 5"
AUTH_HDR="Authorization: Bearer $BENCH_TOKEN"

# ConfigMap body for POST requests.
CM_BODY='{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"bench-cm","namespace":"default"},"data":{"key":"value"}}'

# Ensure default namespace exists so POST configmaps works.
curl -k -s -o /dev/null \
    -X POST "$BASE_URL/api/v1/namespaces" \
    -H "Authorization: Bearer $BENCH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"default"}}' || true

echo "==> Starting load: ${LOAD_DURATION_SECS}s of 50 concurrent GETs + 20 concurrent POSTs..."

# Worker function: loop curl until the sentinel file appears.
STOP_FILE="$TMPDIR/stop"

read_worker() {
    while [ ! -f "$STOP_FILE" ]; do
        curl -k -s -o /dev/null --max-time 5 \
            -H "Authorization: Bearer $BENCH_TOKEN" \
            "$BASE_URL/api/v1/namespaces" 2>/dev/null || true
    done
}

mutating_worker() {
    while [ ! -f "$STOP_FILE" ]; do
        # POST; ignore 409 AlreadyExists and 429 TooManyRequests — both expected.
        curl -k -s -o /dev/null --max-time 5 \
            -X POST "$BASE_URL/api/v1/namespaces/default/configmaps" \
            -H "Authorization: Bearer $BENCH_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$CM_BODY" 2>/dev/null || true
    done
}

export STOP_FILE BASE_URL BENCH_TOKEN CM_BODY
export -f read_worker mutating_worker

# Start 50 GET workers.
for i in $(seq 1 50); do
    bash -c read_worker &
    LOAD_PIDS+=($!)
done

# Start 20 POST workers.
for i in $(seq 1 20); do
    bash -c mutating_worker &
    LOAD_PIDS+=($!)
done

# Run load for LOAD_DURATION_SECS seconds.
sleep "$LOAD_DURATION_SECS"

# Signal workers to stop.
touch "$STOP_FILE"

# Wait for all load workers to finish.
for pid in "${LOAD_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done
LOAD_PIDS=()

# ---------------------------------------------------------------------------
# 5. Sample peak RSS
# ---------------------------------------------------------------------------
PEAK_KB=$(ps -o rss= -p "$SERVER_PID" | tr -d ' ')
if [ -z "$PEAK_KB" ]; then
    echo "ERROR: could not sample post-load RSS for PID $SERVER_PID"
    exit 1
fi

DELTA_KB=$(( PEAK_KB - BASELINE_KB ))

echo "Baseline RSS : ${BASELINE_KB} kB"
echo "Peak RSS     : ${PEAK_KB} kB"
echo "Delta RSS    : ${DELTA_KB} kB (threshold: ${DELTA_THRESHOLD_KB} kB)"

# Disarm verbose exit trap — normal path, suppress log dump.
trap 'for pid in "${LOAD_PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done; if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi' EXIT

# ---------------------------------------------------------------------------
# 6. Verdict
# ---------------------------------------------------------------------------
if [ "$DELTA_KB" -le "$DELTA_THRESHOLD_KB" ]; then
    echo "PASS: RSS delta ${DELTA_KB} kB is within the 20 MB threshold"
    exit 0
else
    echo "FAIL: RSS delta ${DELTA_KB} kB exceeds the 20 MB threshold (${DELTA_THRESHOLD_KB} kB)"
    echo "Server log:"
    cat "$TMPDIR/server.log" || true
    exit 1
fi

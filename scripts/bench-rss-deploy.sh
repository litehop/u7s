#!/usr/bin/env bash
# bench-rss-deploy.sh — Measure RSS delta under a Deployment create/delete workload.
#
# Runs 50 sequential create+delete cycles against the apiserver (no kubelet needed).
# Holds for 30 seconds after all cycles complete, then samples RSS.
#
# Fails if RSS delta exceeds 10 MB (10240 kB) from baseline.
# Works on macOS and Linux.

set -euo pipefail

DELTA_THRESHOLD_KB=10240   # 10 MB
CYCLES=50
SERVER_PID=""

TMPDIR="$(mktemp -d /tmp/u7s-bench-deploy-XXXXXX)"
cleanup() {
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
# 4. Deployment create/delete cycles
# ---------------------------------------------------------------------------
BASE_URL="https://127.0.0.1:6443"

# Ensure default namespace exists.
curl -k -s -o /dev/null \
    -X POST "$BASE_URL/api/v1/namespaces" \
    -H "Authorization: Bearer $BENCH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"default"}}' || true

echo "==> Running ${CYCLES} sequential Deployment create+delete cycles..."

for i in $(seq 1 "$CYCLES"); do
    DEPLOY_NAME="bench-deploy-${i}"
    DEPLOY_BODY="{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\",\"metadata\":{\"name\":\"${DEPLOY_NAME}\",\"namespace\":\"default\"},\"spec\":{\"replicas\":1,\"selector\":{\"matchLabels\":{\"app\":\"bench\"}},\"template\":{\"metadata\":{\"labels\":{\"app\":\"bench\"}},\"spec\":{\"initContainers\":[{\"name\":\"init\",\"image\":\"busybox\"}],\"containers\":[{\"name\":\"app\",\"image\":\"nginx\"}]}}}}"

    # Create deployment; ignore errors (e.g. 409 on re-run).
    curl -k -s -o /dev/null \
        -X POST "$BASE_URL/apis/apps/v1/namespaces/default/deployments" \
        -H "Authorization: Bearer $BENCH_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$DEPLOY_BODY" || true

    # Delete deployment.
    curl -k -s -o /dev/null \
        -X DELETE "$BASE_URL/apis/apps/v1/namespaces/default/deployments/${DEPLOY_NAME}" \
        -H "Authorization: Bearer $BENCH_TOKEN" || true
done

echo "==> Holding 30s before sampling RSS..."
sleep 30

# ---------------------------------------------------------------------------
# 5. Sample peak RSS
# ---------------------------------------------------------------------------
PEAK_KB=$(ps -o rss= -p "$SERVER_PID" | tr -d ' ')
if [ -z "$PEAK_KB" ]; then
    echo "ERROR: could not sample post-workload RSS for PID $SERVER_PID"
    exit 1
fi

DELTA_KB=$(( PEAK_KB - BASELINE_KB ))

echo "Baseline RSS : ${BASELINE_KB} kB"
echo "Peak RSS     : ${PEAK_KB} kB"
echo "Delta RSS    : ${DELTA_KB} kB (threshold: ${DELTA_THRESHOLD_KB} kB)"

# Disarm verbose exit trap — normal path, suppress log dump.
trap 'if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi' EXIT

# ---------------------------------------------------------------------------
# 6. Verdict
# ---------------------------------------------------------------------------
if [ "$DELTA_KB" -le "$DELTA_THRESHOLD_KB" ]; then
    echo "PASS: RSS delta ${DELTA_KB} kB is within the 10 MB threshold"
    exit 0
else
    echo "FAIL: RSS delta ${DELTA_KB} kB exceeds the 10 MB threshold (${DELTA_THRESHOLD_KB} kB)"
    echo "Server log:"
    cat "$TMPDIR/server.log" || true
    exit 1
fi

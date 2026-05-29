#!/usr/bin/env bash
# bench-rss.sh — Measure idle RSS of u7s-apiserver + u7s-scheduler.
#
# Exits 0 if combined RSS <= 65536 kB (64 MB), exits 1 otherwise.
# Works on macOS and Linux.

set -euo pipefail

THRESHOLD_KB=65536  # 64 MB
SERVER_PID=""
SCHEDULER_PID=""

TMPDIR="$(mktemp -d /tmp/u7s-bench-XXXXXX)"
trap 'if [ -n "$SCHEDULER_PID" ]; then kill "$SCHEDULER_PID" 2>/dev/null || true; fi; if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi; echo "Server log:"; cat "$TMPDIR/server.log" 2>/dev/null || true' EXIT

echo "==> Building release binaries..."
cargo build --release -p u7s-apiserver
cargo build --release -p u7s-scheduler

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
    exit 1
fi

echo "==> Starting scheduler (logs -> $TMPDIR/scheduler.log)..."
./target/release/u7s-scheduler \
    --kubeconfig "$TMPDIR/kubeconfig" \
    >"$TMPDIR/scheduler.log" 2>&1 &
SCHEDULER_PID=$!

echo "==> Waiting 3s for memory to stabilize..."
sleep 3

SERVER_RSS_KB=$(ps -o rss= -p "$SERVER_PID" | tr -d ' ')
SCHEDULER_RSS_KB=$(ps -o rss= -p "$SCHEDULER_PID" | tr -d ' ')

if [ -z "$SERVER_RSS_KB" ]; then
    echo "ERROR: could not sample RSS for server PID $SERVER_PID"
    exit 1
fi
if [ -z "$SCHEDULER_RSS_KB" ]; then
    echo "ERROR: could not sample RSS for scheduler PID $SCHEDULER_PID"
    exit 1
fi

COMBINED_RSS_KB=$(( SERVER_RSS_KB + SCHEDULER_RSS_KB ))

echo "Apiserver RSS : ${SERVER_RSS_KB} kB"
echo "Scheduler RSS : ${SCHEDULER_RSS_KB} kB"
echo "Combined RSS  : ${COMBINED_RSS_KB} kB (threshold: ${THRESHOLD_KB} kB)"

# Disarm the EXIT trap — normal exit, suppress log dump
trap 'if [ -n "$SCHEDULER_PID" ]; then kill "$SCHEDULER_PID" 2>/dev/null || true; fi; if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi' EXIT

if [ "$COMBINED_RSS_KB" -le "$THRESHOLD_KB" ]; then
    echo "PASS: combined RSS ${COMBINED_RSS_KB} kB is within the 64 MB threshold"
    exit 0
else
    echo "FAIL: combined RSS ${COMBINED_RSS_KB} kB exceeds the 64 MB threshold (${THRESHOLD_KB} kB)"
    echo "Server log:"
    cat "$TMPDIR/server.log" || true
    echo "Scheduler log:"
    cat "$TMPDIR/scheduler.log" || true
    exit 1
fi

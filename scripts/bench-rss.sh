#!/usr/bin/env bash
# bench-rss.sh — Measure idle RSS of u7s-apiserver.
#
# Exits 0 if RSS <= 65536 kB (64 MB), exits 1 otherwise.
# Works on macOS and Linux.

set -euo pipefail

THRESHOLD_KB=65536  # 64 MB
SERVER_PID=""

TMPDIR="$(mktemp -d /tmp/u7s-bench-XXXXXX)"
trap 'if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi; echo "Server log:"; cat "$TMPDIR/server.log" 2>/dev/null || true' EXIT

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
    exit 1
fi

echo "==> Waiting 3s for memory to stabilize..."
sleep 3

RSS_KB=$(ps -o rss= -p "$SERVER_PID" | tr -d ' ')

if [ -z "$RSS_KB" ]; then
    echo "ERROR: could not sample RSS for PID $SERVER_PID"
    exit 1
fi

echo "RSS: ${RSS_KB} kB (threshold: ${THRESHOLD_KB} kB)"

# Disarm the EXIT trap — normal exit, suppress log dump
trap 'if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi' EXIT

if [ "$RSS_KB" -le "$THRESHOLD_KB" ]; then
    echo "PASS: RSS ${RSS_KB} kB is within the 64 MB threshold"
    exit 0
else
    echo "FAIL: RSS ${RSS_KB} kB exceeds the 64 MB threshold (${THRESHOLD_KB} kB)"
    echo "Server log:"
    cat "$TMPDIR/server.log" || true
    exit 1
fi

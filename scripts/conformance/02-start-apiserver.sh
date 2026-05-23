#!/usr/bin/env bash
# Start u7s-apiserver in the background for conformance testing.
#
# If port 6443 is already in use, warns and reuses the running instance.
# Server logs go to ./temp/u7s/apiserver.log (not stdout).
# Sets KUBECONFIG in the environment for subsequent steps.
#
# Part of the scripts/conformance/ orchestration sequence.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORKDIR="$REPO/temp/u7s"
BINARY="$REPO/target/release/u7s-apiserver"
PORT=6443
LOG="$WORKDIR/apiserver.log"

echo "=== [02] Start apiserver ==="

if [ ! -f "$BINARY" ]; then
  echo "error: binary not found — run 01-build.sh first" >&2
  exit 1
fi

if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
  echo "WARNING: port $PORT already in use — reusing existing apiserver instance" >&2
  echo "  Logs: (existing process)"
  export KUBECONFIG="$WORKDIR/kubeconfig"
  echo "KUBECONFIG=$KUBECONFIG"
  return 0 2>/dev/null || true
fi

mkdir -p "$WORKDIR"

echo "Starting u7s-apiserver (logs: $LOG) ..."
"$BINARY" \
  --db         "$WORKDIR/state.db" \
  --kubeconfig "$WORKDIR/kubeconfig" \
  --sa-key     "$WORKDIR/sa.key" \
  --sa-pub     "$WORKDIR/sa.pub" \
  --ca-key     "$WORKDIR/ca.key" \
  --ca-cert    "$WORKDIR/ca.crt" \
  > "$LOG" 2>&1 &
SERVER_PID=$!
disown "$SERVER_PID"

echo "Waiting for server to accept connections (PID $SERVER_PID) ..."
for i in $(seq 1 10); do
  if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "error: u7s-apiserver exited immediately — see $LOG" >&2
    tail -20 "$LOG" >&2
    exit 1
  fi
  sleep 1
done

if ! nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
  echo "error: server did not open port $PORT within 10s — see $LOG" >&2
  tail -20 "$LOG" >&2
  kill "$SERVER_PID" 2>/dev/null || true
  exit 1
fi

export KUBECONFIG="$WORKDIR/kubeconfig"
echo "u7s-apiserver running (PID $SERVER_PID, logs: $LOG)"
echo "KUBECONFIG=$KUBECONFIG"

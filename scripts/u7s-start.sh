#!/usr/bin/env bash
# Start u7s-apiserver for local development against a lima-node kubelet.
#
# State persists in ./temp/u7s/ across restarts so the CA and kubelet trust
# relationship survive a server restart without re-provisioning the VM.
#
# Usage:
#   scripts/u7s-start.sh [--reset] [--background]
#
#   --reset       Wipe ./temp/u7s/ and start fresh (rotates CA — kubelet will need
#                 to be re-joined via scripts/conformance/lima-start.sh after this).
#   --background  Start backgrounded (logs to ./temp/u7s/apiserver.log). If port
#                 is already in use, warns and exits 0 (reuses existing instance).
#
# After starting (foreground mode):
#   export KUBECONFIG=./temp/u7s/kubeconfig
#   scripts/conformance/lima-start.sh  # join kubelet (first run or after --reset)
#   kubectl get nodes
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="$REPO/temp/u7s"
BINARY="$REPO/target/release/u7s-apiserver"
PORT=6443

RESET=0
BACKGROUND=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1; shift ;;
    --background) BACKGROUND=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ ! -f "$BINARY" ]; then
  echo "error: binary not found — run: cargo build --release -p u7s-apiserver" >&2
  exit 1
fi

if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
  if [ "$BACKGROUND" -eq 1 ]; then
    echo "WARNING: port $PORT already in use — reusing existing apiserver instance" >&2
    echo "KUBECONFIG=$WORKDIR/kubeconfig"
    exit 0
  fi
  echo "error: port $PORT is already in use." >&2
  echo "If u7s is already running, set KUBECONFIG=$WORKDIR/kubeconfig and use it." >&2
  echo "To start fresh: scripts/u7s-start.sh --reset  (rotates CA, re-join kubelet needed)" >&2
  exit 1
fi

if [ "$RESET" -eq 1 ]; then
  echo "Resetting state in $WORKDIR ..."
  rm -rf "$WORKDIR"
fi

mkdir -p "$WORKDIR"

if [ "$BACKGROUND" -eq 1 ]; then
  LOG="$WORKDIR/apiserver.log"
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
else
  echo "Starting u7s-apiserver (state: $WORKDIR) ..."
  "$BINARY" \
    --db         "$WORKDIR/state.db" \
    --kubeconfig "$WORKDIR/kubeconfig" \
    --sa-key     "$WORKDIR/sa.key" \
    --sa-pub     "$WORKDIR/sa.pub" \
    --ca-key     "$WORKDIR/ca.key" \
    --ca-cert    "$WORKDIR/ca.crt" \
    &
  # No --advertise-address: server cert already includes localhost, 127.0.0.1,
  # and host.lima.internal unconditionally (see crates/apiserver/src/tls.rs).
  SERVER_PID=$!
fi

echo "Waiting for server to accept connections ..."
for i in $(seq 1 10); do
  if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    if [ "$BACKGROUND" -eq 1 ]; then
      echo "error: u7s-apiserver exited immediately — see $LOG" >&2
      tail -20 "$LOG" >&2
    else
      echo "error: u7s-apiserver exited immediately — check logs above" >&2
    fi
    exit 1
  fi
  sleep 1
done

if ! nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
  if [ "$BACKGROUND" -eq 1 ]; then
    echo "error: server did not open port $PORT within 10s — see $LOG" >&2
    tail -20 "$LOG" >&2
  else
    echo "error: server did not open port $PORT within 10s" >&2
  fi
  kill "$SERVER_PID" 2>/dev/null || true
  exit 1
fi

if [ "$BACKGROUND" -eq 1 ]; then
  echo "u7s-apiserver running (PID $SERVER_PID, logs: $LOG)"
  echo "KUBECONFIG=$WORKDIR/kubeconfig"
else
  echo ""
  echo "u7s is running (PID $SERVER_PID)"
  echo ""
  echo "  export KUBECONFIG=$WORKDIR/kubeconfig"
  echo ""
  echo "Next steps:"
  echo "  scripts/conformance/lima-start.sh  # join kubelet (first run or after --reset)"
  echo "  kubectl get nodes"
  echo ""
  echo "u7s logs are going to stdout/stderr of this process."
  echo "Press Ctrl-C to stop."
  echo ""
  wait "$SERVER_PID"
fi

#!/usr/bin/env bash
# Start u7s-apiserver for local development against a lima-node kubelet.
#
# State persists in ./temp/u7s/ across restarts so the CA and kubelet trust
# relationship survive a server restart without re-provisioning the VM.
#
# Usage:
#   scripts/u7s-start.sh [--reset]
#
#   --reset   Wipe ./temp/u7s/ and start fresh (rotates CA — kubelet will need
#             to be re-joined via scripts/lima-start.sh after this).
#
# After starting:
#   export KUBECONFIG=./temp/u7s/kubeconfig
#   scripts/lima-start.sh          # join kubelet (first run or after --reset)
#   kubectl get nodes
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="$REPO/temp/u7s"
BINARY="$REPO/target/release/u7s-apiserver"
PORT=6443

RESET=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# Check that the binary exists.
if [ ! -f "$BINARY" ]; then
  echo "error: binary not found — run: cargo build --release -p u7s-apiserver" >&2
  exit 1
fi

# Refuse to start if port is already in use.
if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
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

# Wait up to 10s for the port to open.
echo "Waiting for server to accept connections ..."
for i in $(seq 1 10); do
  if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "error: u7s-apiserver exited immediately — check logs above" >&2
    exit 1
  fi
  sleep 1
done

if ! nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
  echo "error: server did not open port $PORT within 10s" >&2
  kill "$SERVER_PID" 2>/dev/null || true
  exit 1
fi

echo ""
echo "u7s is running (PID $SERVER_PID)"
echo ""
echo "  export KUBECONFIG=$WORKDIR/kubeconfig"
echo ""
echo "Next steps:"
echo "  scripts/lima-start.sh    # join kubelet (first run or after --reset)"
echo "  kubectl get nodes"
echo ""
echo "u7s logs are going to stdout/stderr of this process."
echo "Press Ctrl-C to stop."
echo ""

# Wait for the server to exit so the terminal stays attached to its logs.
wait "$SERVER_PID"

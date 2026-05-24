#!/usr/bin/env bash
# Start u7s-scheduler on the host for conformance testing.
#
# u7s-scheduler is a Rust binary — it builds and runs natively on the Mac host,
# just like u7s-apiserver.  No Lima VM involvement.
#
# Usage:
#   scripts/scheduler-start.sh
#
# After starting:
#   tail -f ./temp/u7s/scheduler.log
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="$REPO/temp/u7s"
BINARY="$REPO/target/release/u7s-scheduler"
LOG="$WORKDIR/scheduler.log"

# Check that the binary exists.
if [ ! -f "$BINARY" ]; then
  echo "error: binary not found — run: cargo build --release -p u7s-scheduler" >&2
  exit 1
fi

# Check that the kubeconfig exists (apiserver must be started first).
if [ ! -f "$WORKDIR/kubeconfig" ]; then
  echo "error: kubeconfig not found at $WORKDIR/kubeconfig" >&2
  echo "Start u7s-apiserver first: scripts/u7s-start.sh" >&2
  exit 1
fi

mkdir -p "$WORKDIR"

# Kill any stale u7s-scheduler from a previous run.
pkill -f u7s-scheduler 2>/dev/null || true

echo "Starting u7s-scheduler (logs: $LOG) ..."
nohup "$BINARY" \
  --kubeconfig "$WORKDIR/kubeconfig" \
  > "$LOG" 2>&1 &
SCHEDULER_PID=$!
disown "$SCHEDULER_PID"

echo "u7s-scheduler running (PID $SCHEDULER_PID, logs: $LOG)"
echo "  tail -f $LOG"

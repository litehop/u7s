#!/usr/bin/env bash
# Start u7s-scheduler on the host (backgrounded) for conformance testing.
#
# u7s-scheduler is a Rust binary — it runs on the host, not inside the Lima VM.
#
# Part of the scripts/conformance/ orchestration sequence.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORKDIR="$REPO/temp/u7s"
BINARY="$REPO/target/release/u7s-scheduler"
LOG="$WORKDIR/scheduler.log"

echo "=== [05] Start u7s-scheduler (on host) ==="

if [ ! -f "$BINARY" ]; then
  echo "error: binary not found — run: cargo build --release -p u7s-scheduler" >&2
  exit 1
fi

if [ ! -f "$WORKDIR/kubeconfig" ]; then
  echo "error: kubeconfig not found at $WORKDIR/kubeconfig" >&2
  echo "Start u7s-apiserver first: scripts/u7s-start.sh" >&2
  exit 1
fi

mkdir -p "$WORKDIR"

pkill -f u7s-scheduler 2>/dev/null || true

echo "Starting u7s-scheduler (logs: $LOG) ..."
nohup "$BINARY" \
  --kubeconfig "$WORKDIR/kubeconfig" \
  > "$LOG" 2>&1 &
SCHEDULER_PID=$!
disown "$SCHEDULER_PID"

echo "u7s-scheduler running (PID $SCHEDULER_PID, logs: $LOG)"
echo "  tail -f $LOG"

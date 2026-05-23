#!/usr/bin/env bash
# Start u7s-scheduler inside the lima VM (backgrounded).
#
# u7s-scheduler must run on Linux to match the kubelet's node; this script
# shells into the Lima VM and runs scheduler-start.sh there.
# scheduler-start.sh handles the kubeconfig rewrite and building the binary.
#
# Part of the scripts/conformance/ orchestration sequence.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
VM_NAME="lima-node"
SCHEDULER_LOG="/tmp/scheduler.log"

echo "=== [05] Start u7s-scheduler (inside $VM_NAME) ==="

if ! command -v limactl &>/dev/null; then
  echo "error: limactl not found — install with: brew install lima" >&2
  exit 1
fi

# Kill any stale u7s-scheduler from a previous run before starting fresh.
limactl shell "$VM_NAME" bash -c \
  "pkill -f u7s-scheduler 2>/dev/null || true"

# The repo is mounted read-only inside lima at the same path as on the host.
# Use the host REPO path — lima mounts match host paths.
limactl shell "$VM_NAME" bash -c \
  "nohup bash \"$REPO/scripts/scheduler-start.sh\" > $SCHEDULER_LOG 2>&1 &"

echo "u7s-scheduler started inside $VM_NAME (log: $SCHEDULER_LOG inside VM)"
echo "To tail: limactl shell $VM_NAME tail -f $SCHEDULER_LOG"

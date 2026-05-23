#!/usr/bin/env bash
# Start kube-controller-manager inside the lima VM (backgrounded).
#
# kcm is a Linux binary — it must run inside the Lima VM on a Mac host.
# The script is sourced/run from the Mac; it shells into the VM to run kcm.
#
# Part of the scripts/conformance/ orchestration sequence.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
VM_NAME="lima-node"
KCM_LOG="/tmp/kcm.log"

echo "=== [04] Start kube-controller-manager (inside $VM_NAME) ==="

if ! command -v limactl &>/dev/null; then
  echo "error: limactl not found — install with: brew install lima" >&2
  exit 1
fi

# The repo is mounted read-only inside lima at the same path as on the host.
# Use the host REPO path — lima mounts match host paths.
limactl shell "$VM_NAME" bash -c \
  "nohup \"$REPO/scripts/kcm-start.sh\" > $KCM_LOG 2>&1 &"

echo "kube-controller-manager started inside $VM_NAME (log: $KCM_LOG inside VM)"
echo "To tail: limactl shell $VM_NAME tail -f $KCM_LOG"

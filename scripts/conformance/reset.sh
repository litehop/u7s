#!/usr/bin/env bash
# Full teardown for the conformance stack — kills host processes, kills
# in-VM processes, and deletes the lima-node VM so the next run starts clean.
#
# Usage:
#   scripts/conformance/reset.sh
#
# After this script:
#   - temp/u7s/ is gone (DB, certs, kubeconfig, PID files all wiped)
#   - lima-node VM is deleted (full disk wipe — no stale certs/containers)
#
# To resume a fresh run:
#   scripts/conformance/run-all.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORKDIR="$REPO/temp/u7s"

echo "=== [reset] Conformance teardown ==="

# ── 1. Kill host processes ────────────────────────────────────────────────────

echo "[reset] Stopping host processes ..."

for name in apiserver scheduler; do
  pidfile="$WORKDIR/${name}.pid"
  if [ -f "$pidfile" ]; then
    pid="$(cat "$pidfile")"
    if kill -0 "$pid" 2>/dev/null; then
      echo "[reset]   killing u7s-${name} (PID $pid)"
      kill "$pid" 2>/dev/null || true
    else
      echo "[reset]   u7s-${name} PID $pid already gone"
    fi
  fi
done

# Fallback: sweep any stray processes not tracked by PID files.
pkill -f u7s-apiserver 2>/dev/null || true
pkill -f u7s-scheduler 2>/dev/null || true

# ── 2. Wipe host state ────────────────────────────────────────────────────────

if [ -d "$WORKDIR" ]; then
  echo "[reset] Removing $WORKDIR ..."
  rm -rf "$WORKDIR"
else
  echo "[reset] $WORKDIR already absent"
fi

# ── 3. Kill in-VM processes (best-effort) ────────────────────────────────────

if limactl list --format '{{.Name}}' 2>/dev/null | grep -q '^lima-node$'; then
  vm_status="$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | awk '/^lima-node / {print $2}')"
  if [ "$vm_status" = "Running" ]; then
    echo "[reset] Stopping processes inside lima-node VM ..."
    limactl shell lima-node pkill -f kubelet                2>/dev/null || true
    limactl shell lima-node pkill -f kube-controller-manager 2>/dev/null || true
    limactl shell lima-node pkill -f sonobuoy              2>/dev/null || true
  else
    echo "[reset] lima-node VM exists but is not running (status: $vm_status) — skipping in-VM kill"
  fi
else
  echo "[reset] lima-node VM does not exist — skipping in-VM kill"
fi

# ── 4. Delete the VM ─────────────────────────────────────────────────────────

echo "[reset] Deleting lima-node VM (full disk wipe) ..."
limactl delete --force lima-node 2>/dev/null || true

echo "[reset] Done. Run scripts/conformance/run-all.sh for a fresh conformance run."

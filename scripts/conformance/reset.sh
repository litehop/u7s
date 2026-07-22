#!/usr/bin/env bash
# Full teardown for the conformance stack — kills host processes, kills
# in-VM processes, and deletes the VM so the next run starts clean.
#
# Usage:
#   scripts/conformance/reset.sh [--vm <name>] [--workdir <path>] [--port <N>]
#                                 [--extra-node <vm>]
#
# After this script:
#   - ./temp/u7s/ is gone (DB, certs, kubeconfig, PID files all wiped)
#   - The VM is deleted (full disk wipe — no stale certs/containers). If
#     --extra-node is given, that VM is deleted too — --reset means "fresh
#     everything", not "fresh primary, stale peer" (Lima only applies a yaml's
#     `networks:` stanza at instance creation, so an extra node left over from
#     before that stanza existed would otherwise be silently reused on a
#     network with no route to the freshly-recreated primary).
#
# To resume a fresh run:
#   scripts/conformance/run-all.sh
set -euo pipefail

WORKDIR="$PWD/temp/u7s"
VM_NAME="${U7S_VM_NAME:-lima-node}"
PORT="${U7S_PORT:-6443}"
EXTRA_NODE=""
_KONNECTIVITY_SERVER_PORT_OVERRIDE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --workdir) WORKDIR="$2"; shift 2 ;;
    --vm) VM_NAME="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --extra-node) EXTRA_NODE="$2"; shift 2 ;;
    --konnectivity-server-port) _KONNECTIVITY_SERVER_PORT_OVERRIDE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# Derive the same konnectivity ports u7s-start.sh / lima-start.sh use for this
# --port slot (server=N, agent=N-3, admin=N-2, health=N-1; default N=8135+offset*100).
if [ -n "$_KONNECTIVITY_SERVER_PORT_OVERRIDE" ]; then
  KONNECTIVITY_SERVER_PORT="$_KONNECTIVITY_SERVER_PORT_OVERRIDE"
else
  KONNECTIVITY_SERVER_PORT=$(( 8135 + (PORT - 6443) * 100 ))
fi
KONNECTIVITY_AGENT_PORT=$(( KONNECTIVITY_SERVER_PORT - 3 ))
KONNECTIVITY_ADMIN_PORT=$(( KONNECTIVITY_SERVER_PORT - 2 ))
KONNECTIVITY_HEALTH_PORT=$(( KONNECTIVITY_SERVER_PORT - 1 ))

# Resolve to absolute without requiring WORKDIR to exist (a fresh worktree's
# first --reset targets a WORKDIR that isn't there yet) so the pkill match
# below is worktree-unique instead of matching another worktree that was
# invoked with the same relative --workdir.
case "$WORKDIR" in
  /*) ;;
  *) WORKDIR="$PWD/$WORKDIR" ;;
esac

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

# Fallback: kill apiserver on this port and scheduler bound to this worktree.
API_PID=$(lsof -ti tcp:"$PORT" 2>/dev/null || true)
if [ -n "$API_PID" ]; then
  echo "[reset]   killing apiserver on port $PORT (PID $API_PID)"
  kill "$API_PID" 2>/dev/null || true
fi
pkill -f "u7s-scheduler.*${WORKDIR}/kubeconfig" 2>/dev/null || true

# konnectivity-server is started via `disown` (scripts/u7s-start.sh), so it survives
# even after its origin worktree is deleted, still bound to this port slot and still
# serving its old CA-signed cert. If left running, the next run's fresh CA/agent
# reject that stale cert with "certificate signed by unknown authority ... ECDSA
# verification failure" — kill whatever holds these ports before regenerating certs.
for kp in "$KONNECTIVITY_SERVER_PORT" "$KONNECTIVITY_AGENT_PORT" "$KONNECTIVITY_ADMIN_PORT" "$KONNECTIVITY_HEALTH_PORT"; do
  KP_PID=$(lsof -ti tcp:"$kp" 2>/dev/null || true)
  if [ -n "$KP_PID" ]; then
    echo "[reset]   killing konnectivity-server on port $kp (PID $KP_PID)"
    kill "$KP_PID" 2>/dev/null || true
  fi
done

# ── 2. Wipe host state ────────────────────────────────────────────────────────

if [ -d "$WORKDIR" ]; then
  echo "[reset] Removing $WORKDIR ..."
  rm -rf "$WORKDIR"
else
  echo "[reset] $WORKDIR already absent"
fi

# ── 3. Kill in-VM processes + delete the VM (best-effort) ───────────────────
# Applied to the primary VM and, if named, the --extra-node VM — see the
# --extra-node usage note above for why the extra node must not be skipped.

teardown_vm() {
  local vm="$1"
  if limactl list --format '{{.Name}}' 2>/dev/null | grep -q "^${vm}$"; then
    local vm_status
    vm_status="$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | awk "/^${vm} / {print \$2}")"
    if [ "$vm_status" = "Running" ]; then
      echo "[reset] Stopping processes inside $vm VM ..."
      limactl shell "$vm" pkill -f kubelet                2>/dev/null || true
      limactl shell "$vm" pkill -f kube-controller-manager 2>/dev/null || true
      limactl shell "$vm" pkill -f sonobuoy              2>/dev/null || true
    else
      echo "[reset] $vm VM exists but is not running (status: $vm_status) — skipping in-VM kill"
    fi
  else
    echo "[reset] $vm VM does not exist — skipping in-VM kill"
  fi

  echo "[reset] Deleting $vm VM (full disk wipe) ..."
  limactl delete --force "$vm" 2>/dev/null || true
}

teardown_vm "$VM_NAME"
if [ -n "$EXTRA_NODE" ]; then
  teardown_vm "$EXTRA_NODE"
fi

echo "[reset] Done. Run scripts/conformance/run-all.sh for a fresh conformance run."

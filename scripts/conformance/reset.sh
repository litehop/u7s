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

# SIGKILL is not synchronous: 'kill -0 $pid' checked immediately after
# 'kill -9 $pid' can still report the PID alive for a brief moment before the
# kernel finishes tearing the process down (confirmed live), which would
# otherwise make teardown_vm() spuriously fail a reset that actually worked.
# Poll briefly before concluding the kill genuinely failed.
pid_still_alive_after_kill() {
  local pid="$1"
  for _ in 1 2 3 4 5; do
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.2
  done
  kill -0 "$pid" 2>/dev/null
}

teardown_vm() {
  local vm="$1"
  local vm_dir="${HOME}/.lima/${vm}"
  local ha_pidfile="${vm_dir}/ha.pid"
  local ha_sock="${vm_dir}/ha.sock"

  # Capture the hostagent PID *before* delete, not after: a hostagent spawned
  # by a LATER provisioning step overwrites this same pidfile with its own
  # PID, so reading it post-delete can silently point at the wrong (new,
  # innocent) process instead of the one we're actually trying to reap.
  local ha_pid=""
  if [ -f "$ha_pidfile" ]; then
    ha_pid="$(cat "$ha_pidfile")"
  fi

  if limactl list --format '{{.Name}}' 2>/dev/null | grep -q "^${vm}$"; then
    local vm_status
    vm_status="$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | awk "/^${vm} / {print \$2}")"
    if [ "$vm_status" = "Running" ]; then
      echo "[reset] Stopping processes inside $vm VM ..."
      # limactl shell connects as the unprivileged 'lima' user; kubelet and
      # kube-controller-manager run as root in the guest, so a plain pkill
      # fails with "Operation not permitted" and never actually kills them
      # (confirmed live — 'sudo' is required here, not optional hardening).
      # '|| true' tolerates pkill's exit 1 ("no matching process"), which is
      # the normal case when a component already died or was never started;
      # stderr is left visible so a real sudo/permission regression shows up.
      limactl shell "$vm" sudo pkill -f kubelet                || true
      limactl shell "$vm" sudo pkill -f kube-controller-manager || true
      limactl shell "$vm" sudo pkill -f sonobuoy                || true
    else
      echo "[reset] $vm VM exists but is not running (status: $vm_status) — skipping in-VM kill"
    fi
  else
    echo "[reset] $vm VM does not exist — skipping in-VM kill"
  fi

  echo "[reset] Deleting $vm VM (full disk wipe) ..."
  # No '|| true': 'limactl delete --force' on an already-absent VM exits 0
  # with just a warning (confirmed live), so a nonzero exit here is a real
  # failure and 'set -e' should abort the reset rather than let a stale VM
  # silently linger with the next run's fresh CA layered on top of it.
  limactl delete --force "$vm"

  # 'limactl delete --force' is not reliable about actually terminating the
  # underlying hostagent OS process: it can survive, get reparented to
  # launchd, and keep squatting on the VM's forwarded kubelet port for hours
  # across later --reset cycles (confirmed live) — every exec/log/attach call
  # then silently hits the zombie's stale, now-CA-mismatched cert instead of
  # the freshly-provisioned guest, while everything else looks clean. Verify
  # the PID captured above is actually dead; if not, kill it and re-verify.
  if [ -n "$ha_pid" ] && kill -0 "$ha_pid" 2>/dev/null; then
    echo "[reset]   hostagent PID $ha_pid for $vm survived 'limactl delete' — killing it"
    # '|| true': tolerates the tiny race where the process dies between the
    # kill -0 check above and this kill -9; the re-check below still catches
    # a genuine failure to kill.
    kill -9 "$ha_pid" 2>/dev/null || true
    if pid_still_alive_after_kill "$ha_pid"; then
      echo "[reset] ERROR: hostagent PID $ha_pid for $vm still alive after SIGKILL" >&2
      return 1
    fi
  fi

  # Backstop beyond the pidfile: search by the VM's own socket path for any
  # other stray 'limactl hostagent' process still bound to it (e.g. one whose
  # PID was never in ha.pid to begin with). Match the full socket path, not a
  # bare VM-name substring — "lima-node" is a substring of "lima-node-2" and
  # "lima-node-3", so a name-only match could kill a sibling VM's hostagent.
  local stray_pids
  stray_pids="$(pgrep -f "limactl hostagent.*${ha_sock}" 2>/dev/null || true)"
  if [ -n "$stray_pids" ]; then
    echo "[reset]   found stray hostagent process(es) for $vm bound to $ha_sock — killing: $stray_pids"
    # shellcheck disable=SC2086 # word-split intentionally: pgrep can return multiple PIDs, one per line.
    kill -9 $stray_pids
    for p in $stray_pids; do
      if pid_still_alive_after_kill "$p"; then
        echo "[reset] ERROR: stray hostagent PID $p for $vm still alive after SIGKILL" >&2
        return 1
      fi
    done
  fi
}

teardown_vm "$VM_NAME"
if [ -n "$EXTRA_NODE" ]; then
  teardown_vm "$EXTRA_NODE"
fi

echo "[reset] Done. Run scripts/conformance/run-all.sh for a fresh conformance run."

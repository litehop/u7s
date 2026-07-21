#!/usr/bin/env bash
# Standalone join script: adds a 2nd node to an already-running conformance stack.
#
# THIS SCRIPT MUST NEVER CALL 04-start-kcm.sh OR 05-start-scheduler.sh.
# A 2nd kube-controller-manager would run every controller with no leader
# election (04-start-kcm.sh:119-121) and double-write cluster state; the
# scheduler must run exactly once for the whole cluster. This script provisions
# the VM, joins its kubelet, AND — via lima-start.sh reaching back over `limactl
# shell` — programs inter-node pod routes on every already-registered peer
# (including the primary). That reach-back is necessary: there is no CNI/BGP
# giving nodes a path to each other's pod subnet, so the joining node's setup is
# the only place that can teach the primary about the new node's subnet. It
# still never touches KCM/scheduler; that invariant is unrelated and must hold.
#
# Usage:
#   scripts/conformance/add-node.sh <vm-name> <kubelet-port> [--port <N>] [--workdir <path>]
#
# Delegates to lima-start.sh --node-suffix "-2" so the joining node's per-node
# resources (konnectivity-agent Pod/Secret, kubelet serving cert, pod CIDR) don't
# collide with the primary node's.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

if [ $# -lt 2 ]; then
  echo "usage: $0 <vm-name> <kubelet-port> [--port <N>] [--workdir <path>]" >&2
  exit 1
fi
VM_NAME="$1"
KUBELET_PORT="$2"
shift 2

_PORT_OVERRIDE=""
_WORKDIR_OVERRIDE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) _PORT_OVERRIDE="$2"; shift 2 ;;
    --workdir) _WORKDIR_OVERRIDE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done
PORT="${_PORT_OVERRIDE:-6443}"
if [ -n "$_WORKDIR_OVERRIDE" ]; then
  WORKDIR="$_WORKDIR_OVERRIDE"
else
  WORKDIR="$PWD/temp/u7s"
fi
KUBECONFIG_PATH="$WORKDIR/kubeconfig"

echo "=== [add-node] Joining $VM_NAME (kubelet port $KUBELET_PORT) ==="

# Verify the primary stack is reachable before touching the 2nd VM (mirror lima-start.sh).
if ! kubectl --kubeconfig="$KUBECONFIG_PATH" get namespaces &>/dev/null; then
  echo "error: cannot reach the primary cluster at $KUBECONFIG_PATH" >&2
  echo "Bring up the primary stack first (run-all.sh or lima-start.sh)." >&2
  exit 1
fi
echo "Primary cluster is reachable."

_WORKDIR_ARG=""
[ -n "$_WORKDIR_OVERRIDE" ] && _WORKDIR_ARG="--workdir $_WORKDIR_OVERRIDE"

# shellcheck disable=SC2086
bash "$DIR/lima-start.sh" --vm "$VM_NAME" --kubelet-port "$KUBELET_PORT" --port "$PORT" ${_WORKDIR_ARG} --node-suffix "-2"

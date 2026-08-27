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
#                                    [--network <name>] [--verbose]
#
# Delegates to lima-start.sh --node-suffix <derived>, computed from THIS node's
# own $VM_NAME via the same node_suffix_for() (_lib.sh) that lima-start.sh's
# direct-start path uses — so the joining node's per-node resources
# (konnectivity-agent Pod/Secret, kubelet serving cert, pod CIDR) never collide
# with the primary's regardless of which numbered slot either one is. A prior
# version hardcoded "-2" here regardless of $VM_NAME, which collided with a
# `lima-node-2` primary auto-deriving that same "-2" for itself.
# --network is forwarded to that same lima-start.sh call (not defaulted here)
# so a 2-node stack whose primary was isolated onto its own network (PR #1194)
# can put the 2nd node on the SAME network instead of silently defaulting to
# lima-start.sh's own user-v2 fallback, which would leave the two nodes with no
# route to each other.
#
# WARNING: this script only provisions the VM and joins the kubelet -- it does
# NOT update an already-running apiserver's --node-kubelet-port mapping (that
# mapping is read once at apiserver startup; there is no hot-reload path). Run
# standalone against a live apiserver, any pod later scheduled on <vm-name>
# falls back to the primary node's kubelet port, and `kubectl logs`/`kubectl
# exec` against it will 404. To add a node whose pods have working logs/exec,
# either start the whole stack fresh via run-all.sh --extra-node <vm>
# --extra-kubelet-port <port> (which wires --node-kubelet-port into
# 02-start-apiserver.sh before this script joins the node), or restart
# 02-start-apiserver.sh with an added --node-kubelet-port <vm-name>=<port>
# entry.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

if [ $# -lt 2 ]; then
  echo "usage: $0 <vm-name> <kubelet-port> [--port <N>] [--workdir <path>] [--network <name>] [--verbose]" >&2
  exit 1
fi
VM_NAME="$1"
KUBELET_PORT="$2"
shift 2

_PORT_OVERRIDE=""
_WORKDIR_OVERRIDE=""
_NETWORK_OVERRIDE=""
_VERBOSE_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) _PORT_OVERRIDE="$2"; shift 2 ;;
    --workdir) _WORKDIR_OVERRIDE="$2"; shift 2 ;;
    --network) _NETWORK_OVERRIDE="$2"; shift 2 ;;
    --verbose) _VERBOSE_ARG="--verbose"; shift ;;
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
echo "WARNING: this does not update the running apiserver's --node-kubelet-port mapping." >&2
echo "kubectl logs/exec against pods on $VM_NAME will 404 until the apiserver is restarted" >&2
echo "with --node-kubelet-port $VM_NAME=$KUBELET_PORT (or start fresh via run-all.sh" >&2
echo "--extra-node/--extra-kubelet-port instead)." >&2

# Verify the primary stack is reachable before touching the 2nd VM (mirror lima-start.sh).
if ! kubectl --kubeconfig="$KUBECONFIG_PATH" get namespaces &>/dev/null; then
  echo "error: cannot reach the primary cluster at $KUBECONFIG_PATH" >&2
  echo "Bring up the primary stack first (run-all.sh or lima-start.sh)." >&2
  exit 1
fi
echo "Primary cluster is reachable."

_WORKDIR_ARG=""
[ -n "$_WORKDIR_OVERRIDE" ] && _WORKDIR_ARG="--workdir $_WORKDIR_OVERRIDE"
_NETWORK_ARG=""
[ -n "$_NETWORK_OVERRIDE" ] && _NETWORK_ARG="--network $_NETWORK_OVERRIDE"

NODE_SUFFIX=$(node_suffix_for "$VM_NAME")

# shellcheck disable=SC2086
bash "$DIR/lima-start.sh" --vm "$VM_NAME" --kubelet-port "$KUBELET_PORT" --port "$PORT" ${_WORKDIR_ARG} ${_NETWORK_ARG} --node-suffix "$NODE_SUFFIX" ${_VERBOSE_ARG}

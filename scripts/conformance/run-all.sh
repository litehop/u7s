#!/usr/bin/env bash
# Full conformance run orchestrator.
#
# Runs all numbered steps in order:
#   01-build.sh            — build u7s-apiserver
#   02-start-apiserver.sh  — start apiserver (or reuse running instance)
#   lima-start.sh          — provision lima VM and join kubelet
#   04-start-kcm.sh        — start kube-controller-manager inside lima VM
#   05-start-scheduler.sh  — start u7s-scheduler on the host
#   06-run-sonobuoy.sh     — run sonobuoy and print results
#
# Usage:
#   scripts/conformance/run-all.sh [--reset] [--focus <regex>] [--vm <name>]
#                                  [--binary <path>] [--port <N>] [--workdir <path>]
#
#   --reset   Run reset.sh before building — kills host processes, deletes the
#             lima-node VM, and wipes ./temp/u7s/ (relative to CWD) for a fully clean run.
#   --focus   Passed through to sonobuoy to narrow test selection.
#             Also settable via SONOBUOY_FOCUS env var.
#   --vm      Lima VM name to use (default: lima-node). Sets U7S_VM_NAME so all
#             child scripts (lima-start, 04-start-kcm, 06-run-sonobuoy) use the
#             same VM. Allows multiple workers to run in parallel against their
#             own isolated VMs. Also settable via U7S_VM_NAME env var.
#   --ip      Host IP for the apiserver and konnectivity-server to bind to
#             (default: 127.0.0.1). Set to a loopback alias (e.g. 127.0.0.2) to
#             run multiple workers in parallel without port collisions. Exports
#             U7S_HOST_IP so u7s-start.sh uses the correct address.
#             Also settable via U7S_HOST_IP env var.
#   --binary  Path to the pre-built u7s-apiserver binary. Skips the build step
#             (01-build.sh) and sets U7S_BINARY so u7s-start.sh uses this binary.
#             Useful for running conformance against a worktree build without
#             polluting the main target directory.
#   --port    Apiserver listen port (default: 6443). Forwarded to u7s-start.sh and
#             lima-start.sh via U7S_PORT so both sides use the same port.
#   --kubelet-port  Host-side port the kubelet is reachable on (default: 10250). Must
#             match the lima portForward hostPort for the assigned VM. Forwarded to
#             u7s-start.sh so the apiserver dials the correct port for log/exec/attach.
#   --workdir Directory for apiserver state (DB, certs, kubeconfig). Forwarded to
#             u7s-start.sh and child scripts. Defaults to ./temp/u7s relative to CWD
#             (the active worktree root when invoked from a worktree).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DIR="$REPO/scripts/conformance"
WORKDIR="$PWD/temp/u7s"
FOCUS="${SONOBUOY_FOCUS:-}"
RESET=0
BINARY=""
PORT=""
KUBELET_PORT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1; shift ;;
    --focus) FOCUS="$2"; shift 2 ;;
    --verbose) export RUST_LOG=debug; shift ;;
    --vm) U7S_VM_NAME="$2"; export U7S_VM_NAME; shift 2 ;;
    --ip) U7S_HOST_IP="$2"; export U7S_HOST_IP; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --kubelet-port) KUBELET_PORT="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

banner() {
  echo ""
  echo "============================================================"
  echo " $*"
  echo "============================================================"
}

# Propagate binary override via env var (u7s-start.sh reads U7S_BINARY).
if [ -n "$BINARY" ]; then
  export U7S_BINARY="$BINARY"
fi

# Build optional CLI args for child scripts that accept --port / --workdir.
_PORT_ARG=""
_KUBELET_PORT_ARG=""
_WORKDIR_ARG=""
_VM_ARG=""
[ -n "$PORT" ]         && _PORT_ARG="--port $PORT"
[ -n "$KUBELET_PORT" ] && _KUBELET_PORT_ARG="--kubelet-port $KUBELET_PORT"
[ -n "$WORKDIR" ]      && _WORKDIR_ARG="--workdir $WORKDIR"
[ -n "${U7S_VM_NAME:-}" ] && _VM_ARG="--vm $U7S_VM_NAME"

if [ "$RESET" -eq 1 ]; then
  banner "Reset: tearing down stale state"
  # shellcheck disable=SC2086
  bash "$DIR/reset.sh" ${_VM_ARG} ${_PORT_ARG} ${_WORKDIR_ARG}
fi

# Step 01: Build — skipped when --binary is supplied (caller provides the binary).
if [ -n "$BINARY" ]; then
  banner "Step 1/6: Build (skipped — using pre-built binary)"
else
  banner "Step 1/6: Build"
  bash "$DIR/01-build.sh"
fi

# Step 02: Start apiserver — source so KUBECONFIG export propagates.
banner "Step 2/6: Start apiserver"
# shellcheck source=02-start-apiserver.sh
# shellcheck disable=SC2086
source "$DIR/02-start-apiserver.sh" ${_PORT_ARG} ${_KUBELET_PORT_ARG} ${_WORKDIR_ARG}

# KUBECONFIG is now set (either from the running instance or newly started).
if [ -z "${KUBECONFIG:-}" ]; then
  # Fallback: set from well-known path if source didn't export it.
  export KUBECONFIG="$WORKDIR/kubeconfig"
fi
echo "Using KUBECONFIG=$KUBECONFIG"

# Step 03: Start lima VM and join kubelet.
banner "Step 3/6: Start lima VM"
# shellcheck disable=SC2086
bash "$DIR/lima-start.sh" ${_PORT_ARG} ${_KUBELET_PORT_ARG} ${_WORKDIR_ARG}

# Step 04: Start kcm inside VM.
banner "Step 4/6: Start kube-controller-manager"
# shellcheck disable=SC2086
bash "$DIR/04-start-kcm.sh" ${_PORT_ARG} ${_WORKDIR_ARG}

# Step 05: Start scheduler inside VM.
banner "Step 5/6: Start u7s-scheduler"
bash "$DIR/05-start-scheduler.sh"

# Step 06: Run sonobuoy.
banner "Step 6/6: Run sonobuoy"
export SONOBUOY_FOCUS="$FOCUS"
# shellcheck disable=SC2086
bash "$DIR/06-run-sonobuoy.sh" ${_PORT_ARG} ${_WORKDIR_ARG}

banner "Done"

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
#   scripts/conformance/run-all.sh [--reset] [--focus <regex>] [--stack-only] [--vm <name>]
#                                  [--binary <path>] [--port <N>] [--workdir <path>]
#                                  [--konnectivity-server-port <N>]
#                                  [--extra-node <vm>] [--extra-kubelet-port <N>]
#
#   --reset      Run reset.sh before building — kills host processes, deletes the
#                lima-node VM (and the --extra-node VM too, if one is given on
#                the same command line, so a stale pre-existing extra node is
#                never silently reused on a network config it predates), and
#                wipes ./temp/u7s/ (relative to CWD) for a fully clean run.
#   --focus      Passed through to sonobuoy to narrow test selection.
#                Also settable via SONOBUOY_FOCUS env var.
#   --stack-only Bring up steps 1–5 (build, apiserver, kubelet, KCM, scheduler) and
#                then stop — skip step 6 (sonobuoy). The stack is left running so you
#                can use kubectl or inspect the DB directly. Useful for manual debugging
#                without triggering a sonobuoy run. Note: a bare invocation (no --focus,
#                no --stack-only) runs the FULL conformance suite (~6h at current state).
#                If --focus is also supplied it is ignored (warning printed to stderr).
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
#   --konnectivity-server-port  Server-facing port for konnectivity-server (default: 8135).
#             Agent/admin/health ports are derived as server_port-3/server_port-2/server_port-1.
#             Per-slot scheme: slot N uses 8135+N*100 (slot1→8235, slot2→8335, …).
#             Forwarded to u7s-start.sh (starts server) and lima-start.sh (agent pod).
#   --workdir Directory for apiserver state (DB, certs, kubeconfig). Forwarded to
#             u7s-start.sh and child scripts. Defaults to ./temp/u7s relative to CWD
#             (the active worktree root when invoked from a worktree).
#   --extra-node <vm>          Join a 2nd VM to the SAME cluster (delegates to
#             add-node.sh, which never touches KCM/scheduler — those run once for
#             the whole cluster). Must be paired with --extra-kubelet-port; absent,
#             the stack stays single-node (today's behavior, unchanged). Works with
#             --stack-only too (brings up a 2-node stack, still skips sonobuoy).
#   --extra-kubelet-port <N>   Host-side kubelet port for the 2nd node (see
#             --kubelet-port). Required together with --extra-node.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DIR="$REPO/scripts/conformance"
WORKDIR="$PWD/temp/u7s"
FOCUS="${SONOBUOY_FOCUS:-}"
RESET=0
VERBOSE=0
STACK_ONLY=0
BINARY=""
PORT=""
KUBELET_PORT=""
KONNECTIVITY_SERVER_PORT=""
EXTRA_NODE=""
EXTRA_KUBELET_PORT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1; shift ;;
    --focus) FOCUS="$2"; shift 2 ;;
    --verbose) export RUST_LOG=debug; VERBOSE=1; shift ;;
    --vm) U7S_VM_NAME="$2"; export U7S_VM_NAME; shift 2 ;;
    --ip) U7S_HOST_IP="$2"; export U7S_HOST_IP; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --kubelet-port) KUBELET_PORT="$2"; shift 2 ;;
    --konnectivity-server-port) KONNECTIVITY_SERVER_PORT="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --stack-only) STACK_ONLY=1; shift ;;
    --extra-node) EXTRA_NODE="$2"; shift 2 ;;
    --extra-kubelet-port) EXTRA_KUBELET_PORT="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ "$STACK_ONLY" -eq 1 ] && [ -n "$FOCUS" ]; then
  echo "--focus ignored with --stack-only" >&2
fi

# Both flags are required together: a 2nd node needs its own kubelet port, and a
# bare kubelet port with no VM to join is meaningless.
if [ -n "$EXTRA_NODE" ] && [ -z "$EXTRA_KUBELET_PORT" ]; then
  echo "error: --extra-node requires --extra-kubelet-port" >&2
  exit 1
fi
if [ -z "$EXTRA_NODE" ] && [ -n "$EXTRA_KUBELET_PORT" ]; then
  echo "error: --extra-kubelet-port requires --extra-node" >&2
  exit 1
fi

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
_KONNECTIVITY_SERVER_PORT_ARG=""
_WORKDIR_ARG=""
_VM_ARG=""
_KCM_V_ARG=""
_EXTRA_NODE_ARG=""
# When --verbose is set, raise kube-controller-manager verbosity to --v=4 so the
# disruption controller logs its pod list / expectedCount decisions (V(4)) — the
# view needed to diagnose why disruptedPods gets cleared.
[ "$VERBOSE" -eq 1 ] && _KCM_V_ARG="--kcm-v 4"
[ -n "$PORT" ]                    && _PORT_ARG="--port $PORT"
[ -n "$KUBELET_PORT" ]            && _KUBELET_PORT_ARG="--kubelet-port $KUBELET_PORT"
[ -n "$KONNECTIVITY_SERVER_PORT" ] && _KONNECTIVITY_SERVER_PORT_ARG="--konnectivity-server-port $KONNECTIVITY_SERVER_PORT"
_WORKDIR_ARG="--workdir $WORKDIR"
[ -n "${U7S_VM_NAME:-}" ] && _VM_ARG="--vm $U7S_VM_NAME"
[ -n "$EXTRA_NODE" ] && _EXTRA_NODE_ARG="--extra-node $EXTRA_NODE"

if [ "$RESET" -eq 1 ]; then
  banner "Reset: tearing down stale state"
  # shellcheck disable=SC2086
  bash "$DIR/reset.sh" ${_VM_ARG} ${_PORT_ARG} ${_WORKDIR_ARG} ${_KONNECTIVITY_SERVER_PORT_ARG} ${_EXTRA_NODE_ARG}
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
source "$DIR/02-start-apiserver.sh" ${_PORT_ARG} ${_KUBELET_PORT_ARG} ${_KONNECTIVITY_SERVER_PORT_ARG} ${_WORKDIR_ARG}

# KUBECONFIG is now set (either from the running instance or newly started).
if [ -z "${KUBECONFIG:-}" ]; then
  # Fallback: set from well-known path if source didn't export it.
  export KUBECONFIG="$WORKDIR/kubeconfig"
fi
echo "Using KUBECONFIG=$KUBECONFIG"

# Step 03: Start lima VM and join kubelet.
banner "Step 3/6: Start lima VM"
# shellcheck disable=SC2086
bash "$DIR/lima-start.sh" ${_PORT_ARG} ${_KUBELET_PORT_ARG} ${_KONNECTIVITY_SERVER_PORT_ARG} ${_WORKDIR_ARG}

# Step 04: Start kcm inside VM.
banner "Step 4/6: Start kube-controller-manager"
# shellcheck disable=SC2086
bash "$DIR/04-start-kcm.sh" ${_PORT_ARG} ${_WORKDIR_ARG} ${_KCM_V_ARG}

# Step 05: Start scheduler inside VM.
banner "Step 5/6: Start u7s-scheduler"
# shellcheck disable=SC2086
bash "$DIR/05-start-scheduler.sh" ${_WORKDIR_ARG}

# Extra node: join a 2nd VM to the same cluster (opt-in). Runs after KCM/scheduler
# are up (those must run exactly once) and before sonobuoy so the target tests see
# both nodes.
if [ -n "$EXTRA_NODE" ]; then
  banner "Extra node: join $EXTRA_NODE"
  # shellcheck disable=SC2086
  bash "$DIR/add-node.sh" "$EXTRA_NODE" "$EXTRA_KUBELET_PORT" ${_PORT_ARG} ${_WORKDIR_ARG}
fi

# Step 06: Run sonobuoy.
if [ "$STACK_ONLY" -eq 1 ]; then
  banner "Step 6/6: Run sonobuoy (skipped — --stack-only)"
else
  banner "Step 6/6: Run sonobuoy"
  export SONOBUOY_FOCUS="$FOCUS"
  # shellcheck disable=SC2086
  bash "$DIR/06-run-sonobuoy.sh" ${_PORT_ARG} ${_WORKDIR_ARG}
fi

banner "Done"

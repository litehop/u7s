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
#   scripts/conformance/run-all.sh [--reset] [--focus <regex>] [--all-e2e] [--stack-only]
#                                  [--vm <name>] [--binary <path>] [--port <N>]
#                                  [--workdir <path>] [--konnectivity-server-port <N>]
#                                  [--extra-node <vm>] [--extra-kubelet-port <N>]
#
#   --reset      Run reset.sh before building — kills host processes, deletes the
#                lima-node VM (and the --extra-node VM too, if one is given on
#                the same command line, so a stale pre-existing extra node is
#                never silently reused on a network config it predates), and
#                wipes ./temp/u7s/ (relative to CWD) for a fully clean run.
#   --focus      Passed through to sonobuoy to narrow test selection.
#                Also settable via SONOBUOY_FOCUS env var. Mutually exclusive
#                with --all-e2e (error if both given).
#   --all-e2e    Widen sonobuoy beyond the default --mode=certified-conformance
#                (the [Conformance]-tagged subset) to the full e2e ginkgo set via
#                --e2e-focus=".*" --e2e-skip="\[Disruptive\]|\[Flaky\]|\[Slow\]".
#                Surfaces plain ginkgo.It specs (e.g. SSA field-manager tests)
#                that certified-conformance never runs. Wall-clock: ~6-12h vs
#                certified's ~2h — a deliberate discovery/perf-baseline run, not
#                a default. Mutually exclusive with --focus (error if both
#                given — they're conceptually opposite: --focus narrows,
#                --all-e2e widens). If --stack-only is also given, --stack-only
#                wins and --all-e2e is ignored (warning printed to stderr), same
#                as --focus's existing interaction with --stack-only.
#   -v, -vv, -vvv  Repeatable-flag tiered debug logging, apt-style (--verbose is
#                kept as an alias for a single -v). -v scopes RUST_LOG to u7s's own
#                crates: u7s_apiserver=debug,u7s_store=debug,u7s_scheduler=debug,info.
#                -vv adds hyper=debug,rustls=debug (connection/handshake detail).
#                -vvv adds h2=debug (full HTTP/2 frame-level tracing). Levels add
#                (e.g. -v -vv == -vvv). A blanket RUST_LOG=debug is NOT the default
#                because it also enables h2's per-frame tracing, which on a real
#                conformance run was 89.9% of a 653MB apiserver.log — burying every
#                u7s debug! call under third-party noise. Any level >= 1 also raises
#                kube-controller-manager to --v=5 and kubelet/CRI-O to debug (see
#                --kcm-v and lima-start.sh's --verbose) — those aren't tiered since
#                they don't have a third-party-noise problem to scope away from.
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
#             --kubelet-port). Required together with --extra-node. Passed to the
#             apiserver as --node-kubelet-port at step 2 (before the node joins) so
#             kubectl logs/exec/attach/port-forward against a pod on the 2nd node
#             reach ITS kubelet forward instead of the primary's.
#   --profile  Rebuild u7s-apiserver with --features dhat after the normal build so
#             the conformance workload runs under dhat's allocation profiler. The
#             profile (dhat-heap.json) is written into --workdir, but only once the
#             apiserver actually exits — dhat flushes it from a Drop impl that never
#             runs while the server keeps serving, and run-all.sh intentionally leaves
#             the stack running at the end (for sonobuoy log retrieval / --stack-only
#             debugging). Ignored (with a warning) if --binary is also given, since
#             that binary's feature set is the caller's responsibility.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DIR="$REPO/scripts/conformance"
WORKDIR="$PWD/temp/u7s"
FOCUS="${SONOBUOY_FOCUS:-}"
ALL_E2E=0
RESET=0
VERBOSE=0
STACK_ONLY=0
BINARY=""
PORT=""
KUBELET_PORT=""
KONNECTIVITY_SERVER_PORT=""
EXTRA_NODE=""
EXTRA_KUBELET_PORT=""
PROFILE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1; shift ;;
    --focus) FOCUS="$2"; shift 2 ;;
    --all-e2e) ALL_E2E=1; shift ;;
    --verbose|-v) VERBOSE=$((VERBOSE + 1)); shift ;;
    -vv) VERBOSE=$((VERBOSE + 2)); shift ;;
    -vvv) VERBOSE=$((VERBOSE + 3)); shift ;;
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
    --profile) PROFILE=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# Tiered RUST_LOG, apt-style: -v scopes debug logging to u7s's own crates instead
# of a blanket `debug`, which also turns on h2's per-HTTP/2-frame tracing — on a
# real conformance run that noise alone was 89.9% of a 653MB apiserver.log,
# burying every u7s debug! call the project actually cares about. -vv/-vvv widen
# the scope for connection- and frame-level investigations. Untouched (whatever
# the caller's own RUST_LOG env var says, if anything) when no -v flag is given.
if [ "$VERBOSE" -ge 3 ]; then
  export RUST_LOG="u7s_apiserver=debug,u7s_store=debug,u7s_scheduler=debug,hyper=debug,rustls=debug,h2=debug,info"
elif [ "$VERBOSE" -eq 2 ]; then
  export RUST_LOG="u7s_apiserver=debug,u7s_store=debug,u7s_scheduler=debug,hyper=debug,rustls=debug,info"
elif [ "$VERBOSE" -ge 1 ]; then
  export RUST_LOG="u7s_apiserver=debug,u7s_store=debug,u7s_scheduler=debug,info"
fi

# --focus narrows test selection, --all-e2e widens it — conceptually opposite,
# so silently picking one would be a footgun. Error unconditionally (even
# under --stack-only, where neither would actually reach sonobuoy) rather than
# let the combination pass silently.
if [ "$ALL_E2E" -eq 1 ] && [ -n "$FOCUS" ]; then
  echo "error: --all-e2e and --focus are mutually exclusive (--focus narrows, --all-e2e widens)" >&2
  exit 1
fi

if [ "$STACK_ONLY" -eq 1 ] && [ -n "$FOCUS" ]; then
  echo "--focus ignored with --stack-only" >&2
fi

if [ "$STACK_ONLY" -eq 1 ] && [ "$ALL_E2E" -eq 1 ]; then
  echo "--all-e2e ignored with --stack-only" >&2
fi

if [ "$PROFILE" -eq 1 ] && [ -n "$BINARY" ]; then
  echo "--profile ignored with --binary (pre-built binary's features are not rebuilt)" >&2
  PROFILE=0
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
_VERBOSE_ARG=""
_EXTRA_NODE_ARG=""
_NODE_KUBELET_PORT_ARG=""
_ALL_E2E_ARG=""
# When any -v level is set (>= 1), raise kube-controller-manager verbosity to --v=5
# so both the disruption controller's pod-list / expectedCount decisions (V(4)) and
# the DaemonSet controller's replacement-reasoning lines ("candidate to replace" /
# "allowing replacements", V(5)) are visible — V(5) is the ceiling here (no V(6)
# call sites exist). Unlike RUST_LOG, this isn't tiered further at -vv/-vvv: KCM's
# own klog verbosity has no third-party-noise problem to scope away from.
[ "$VERBOSE" -ge 1 ] && _KCM_V_ARG="--kcm-v 5"
# Forwarded to lima-start.sh (and, via add-node.sh, to a 2nd node's lima-start.sh),
# which raises kubelet to --v=5 (PLEG relist detail) and flips CRI-O's crio.conf.d
# drop-in to log_level=debug — see lima-start.sh for why both live behind one flag.
# Same reasoning as _KCM_V_ARG above: a plain on/off, not tiered.
[ "$VERBOSE" -ge 1 ] && _VERBOSE_ARG="--verbose"
[ -n "$PORT" ]                    && _PORT_ARG="--port $PORT"
[ -n "$KUBELET_PORT" ]            && _KUBELET_PORT_ARG="--kubelet-port $KUBELET_PORT"
[ -n "$KONNECTIVITY_SERVER_PORT" ] && _KONNECTIVITY_SERVER_PORT_ARG="--konnectivity-server-port $KONNECTIVITY_SERVER_PORT"
_WORKDIR_ARG="--workdir $WORKDIR"
[ -n "${U7S_VM_NAME:-}" ] && _VM_ARG="--vm $U7S_VM_NAME"
[ -n "$EXTRA_NODE" ] && _EXTRA_NODE_ARG="--extra-node $EXTRA_NODE"
# The apiserver is started (step 2) before the extra node joins (after step 5) — but
# run-all.sh already knows the extra node's name and kubelet port from its own CLI args,
# so it tells the apiserver about that node's forward up front rather than needing any
# restart/reload once the node actually joins. See --node-kubelet-port in u7s-apiserver.
[ -n "$EXTRA_NODE" ] && _NODE_KUBELET_PORT_ARG="--node-kubelet-port ${EXTRA_NODE}=${EXTRA_KUBELET_PORT}"
[ "$ALL_E2E" -eq 1 ] && _ALL_E2E_ARG="--all-e2e"

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

DHAT_HEAP_FILE=""
if [ "$PROFILE" -eq 1 ]; then
  banner "Profile: rebuilding u7s-apiserver with --features dhat"
  # 01-build.sh builds u7s-apiserver and u7s-scheduler together with no
  # features enabled; this targeted rebuild overwrites just the apiserver
  # binary in place (same output path, only the feature set changes) so the
  # scheduler binary from the step above is left untouched.
  cargo build --release -p u7s-apiserver --features dhat --manifest-path "$REPO/Cargo.toml"
  DHAT_HEAP_FILE="$WORKDIR/dhat-heap.json"
  export U7S_DHAT_HEAP_FILE="$DHAT_HEAP_FILE"
fi

# Step 02: Start apiserver — source so KUBECONFIG export propagates.
banner "Step 2/6: Start apiserver"
# shellcheck source=02-start-apiserver.sh
# shellcheck disable=SC2086
source "$DIR/02-start-apiserver.sh" ${_PORT_ARG} ${_KUBELET_PORT_ARG} ${_KONNECTIVITY_SERVER_PORT_ARG} ${_WORKDIR_ARG} ${_NODE_KUBELET_PORT_ARG}

# KUBECONFIG is now set (either from the running instance or newly started).
if [ -z "${KUBECONFIG:-}" ]; then
  # Fallback: set from well-known path if source didn't export it.
  export KUBECONFIG="$WORKDIR/kubeconfig"
fi
echo "Using KUBECONFIG=$KUBECONFIG"

# Step 03: Start lima VM and join kubelet.
banner "Step 3/6: Start lima VM"
# shellcheck disable=SC2086
bash "$DIR/lima-start.sh" ${_PORT_ARG} ${_KUBELET_PORT_ARG} ${_KONNECTIVITY_SERVER_PORT_ARG} ${_WORKDIR_ARG} ${_VERBOSE_ARG}

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
  bash "$DIR/add-node.sh" "$EXTRA_NODE" "$EXTRA_KUBELET_PORT" ${_PORT_ARG} ${_WORKDIR_ARG} ${_VERBOSE_ARG}
fi

# Step 06: Run sonobuoy.
if [ "$STACK_ONLY" -eq 1 ]; then
  banner "Step 6/6: Run sonobuoy (skipped — --stack-only)"
else
  banner "Step 6/6: Run sonobuoy"
  export SONOBUOY_FOCUS="$FOCUS"
  # shellcheck disable=SC2086
  bash "$DIR/06-run-sonobuoy.sh" ${_PORT_ARG} ${_WORKDIR_ARG} ${_EXTRA_NODE_ARG} ${_ALL_E2E_ARG}
fi

if [ -n "$DHAT_HEAP_FILE" ]; then
  echo ""
  echo "Allocation profile: apiserver is running under dhat. dhat only flushes"
  echo "$DHAT_HEAP_FILE on a graceful exit, so it does not exist yet — stop the"
  echo "apiserver with SIGTERM when you're done exercising it, e.g.:"
  echo "  kill -TERM \$(lsof -ti tcp:${PORT:-6443} -sTCP:LISTEN)"
fi

banner "Done"

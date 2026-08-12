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
#   scripts/conformance/run-all.sh [--reset] [--focus <regex>] [--unsafe-focus] [--all-e2e]
#                                  [--stack-only] [--vm <name>] [--binary <path>] [--port <N>]
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
#   --unsafe-focus  Escape hatch for --focus only: wipes the FeatureGate
#                label-filter AND the [Flaky] skip for this invocation, so a
#                named test that would otherwise run 0 specs (its FeatureGate
#                label isn't in the allow-set) actually runs. The safe
#                default (bare --focus) keeps both filters applied so naming
#                a known-crashing test (e.g. the Beta-gated
#                HPAConfigurableTolerance spec that crashed vendored kcm 14
#                minutes into a 12.6h --all-e2e run) can't accidentally
#                re-trigger it without deliberate opt-in. Meaningless without
#                --focus -- --all-e2e and the bare certified-conformance run
#                always apply both filters regardless of this flag, so it's a
#                no-op there rather than an error (see 06-run-sonobuoy.sh for
#                the FeatureGate allow-set itself and this no-op-vs-error
#                choice).
#   --all-e2e    Widen sonobuoy beyond the default --mode=certified-conformance
#                (the [Conformance]-tagged subset) to the full e2e ginkgo set via
#                --e2e-focus=".*" --e2e-skip="\[Flaky\]" — a genuine superset of
#                certified-conformance (only upstream's known-unreliable
#                [Flaky] specs are excluded; [Disruptive]/[Slow] are NOT
#                skipped since some of those are also [Conformance], see
#                06-run-sonobuoy.sh). Surfaces plain ginkgo.It specs (e.g. SSA
#                field-manager tests) that certified-conformance never runs.
#                Wall-clock: ~6-12h vs certified's ~25min (PR #966 made
#                ginkgo's --procs=16 the default, replacing a silently-serial
#                certified-conformance path — re-measure if that default
#                ever changes) — a deliberate discovery/perf-baseline run,
#                not a default. Mutually exclusive with --focus (error if both
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
#                no --stack-only) runs the FULL conformance suite (~25min at current
#                state — PR #966's --procs=16 default replaced a silently-serial
#                certified-conformance path; re-measure if that default changes).
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
#   --profile  Rebuild u7s-apiserver with --features dhat before stack bring-up so
#             the conformance workload runs under dhat's allocation profiler — no
#             separate manual `cargo build --features dhat` step needed. dhat only
#             flushes its heap JSON from a Drop impl that runs on a graceful exit
#             (main.rs:29-33 catches SIGTERM), so once sonobuoy retrieval + log
#             evacuation finish, run-all.sh sends SIGTERM to the apiserver (plus
#             scheduler and konnectivity-server, for full cleanup) and waits for
#             exit before moving the flushed heap into THIS run's own
#             temp/e2e/<TIMESTAMP>-<slug>/ directory (alongside host-logs/, the
#             sonobuoy tarball, etc.) as dhat-heap-apiserver-<TIMESTAMP>.json — no
#             separate manual move step either. Skipped under --stack-only, which
#             leaves the whole stack running on purpose for kubectl exploration;
#             the apiserver keeps running under dhat there too, but the operator
#             must stop it manually to flush the heap (a reminder is printed).
#             Mutually exclusive with --binary (error if both given): --profile's
#             whole point is the --features dhat rebuild, which a pre-built
#             --binary bypasses by definition. A bare --profile (no --focus)
#             prints a wall-clock warning to stderr — see --dhat-depth below.
#   --dhat-depth  Sets U7S_DHAT_BACKTRACE_DEPTH in the apiserver's own child env
#             (only meaningful together with --profile). Controls how many stack
#             frames dhat keeps per allocation site. Defaults to 10 (dhat's own
#             crate default) when omitted — measured +13% wall-clock on a full
#             suite. Depth 50 attributes deep/recursive call chains more
#             precisely but measured +82% wall-clock and +318% peak apiserver
#             RSS on a full suite (almost entirely profiler overhead, not real
#             allocation growth) — reserve it for a --focus-scoped investigation,
#             not a bare full-suite run.
#   --sample-interval  Cadence in seconds for scripts/conformance/sample-run-metrics.sh,
#             which starts once the node topology is final (after step 5 and any
#             --extra-node join) and reaps at the same point run-all.sh's own
#             lifecycle ends (mirroring wherever the apiserver itself would be
#             stopped) — see that script for the three artifacts it produces
#             (host+VM RSS, /metrics snapshots, ring-gauge trajectory) and why
#             this replaced an operator-run-by-hand monitoring loop. Default: 30s,
#             matching that loop's own cadence.
set -euo pipefail

# Captured before the arg-parsing loop below shifts through "$@" -- needed
# verbatim by write-build-provenance.sh so a run's meta/build.json records
# exactly how this invocation was made, not a reconstruction of it.
ORIGINAL_ARGV=("$@")

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DIR="$REPO/scripts/conformance"
WORKDIR="$PWD/temp/u7s"
FOCUS="${SONOBUOY_FOCUS:-}"
ALL_E2E=0
UNSAFE_FOCUS=0
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
DHAT_DEPTH=""
SAMPLE_INTERVAL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1; shift ;;
    --focus) FOCUS="$2"; shift 2 ;;
    --all-e2e) ALL_E2E=1; shift ;;
    --unsafe-focus) UNSAFE_FOCUS=1; shift ;;
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
    --dhat-depth) DHAT_DEPTH="$2"; shift 2 ;;
    --sample-interval) SAMPLE_INTERVAL="$2"; shift 2 ;;
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
  echo "error: --profile and --binary are mutually exclusive — --profile always rebuilds with --features dhat, but --binary points at a pre-built binary whose feature set is the caller's responsibility" >&2
  exit 1
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

# --dhat-depth is forwarded verbatim to the apiserver's U7S_DHAT_BACKTRACE_DEPTH
# (crates/apiserver/src/main.rs parses it as a usize) -- reject it here with a
# clear message instead of letting a typo silently fall back to the apiserver's
# own default of 10, which would look like the flag was simply ignored.
if [ -n "$DHAT_DEPTH" ] && ! [[ "$DHAT_DEPTH" =~ ^[0-9]+$ ]]; then
  echo "error: --dhat-depth must be a non-negative integer, got '$DHAT_DEPTH'" >&2
  exit 1
fi

# A bare --profile (no --focus) runs the FULL suite under dhat instrumentation.
# Depth 10 (the default) measured +13% wall-clock on a full run; depth 50
# measured +82% wall-clock and +318% peak apiserver RSS, almost entirely
# profiler overhead. Either way a full-suite profiled run risks exceeding the
# ~25 min un-profiled budget and the watchdog's namespace-reap thresholds.
# Skipped under --stack-only, where sonobuoy (and therefore the whole-suite
# wall-clock this warns about) never runs at all.
if [ "$PROFILE" -eq 1 ] && [ -z "$FOCUS" ] && [ "$STACK_ONLY" -eq 0 ]; then
  echo "warning: dhat profiling on the full suite adds ~13-82% wall-clock (depends on --dhat-depth, default 10); expect the run to exceed the ~25 min un-profiled budget. Consider --focus for a depth-50 investigation." >&2
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
_UNSAFE_FOCUS_ARG=""
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
[ "$UNSAFE_FOCUS" -eq 1 ] && _UNSAFE_FOCUS_ARG="--unsafe-focus"
_SAMPLE_INTERVAL_ARG=""
[ -n "$SAMPLE_INTERVAL" ] && _SAMPLE_INTERVAL_ARG="--interval $SAMPLE_INTERVAL"

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
if [ "$PROFILE" -eq 1 ] && [ -n "$DHAT_DEPTH" ]; then
  # Set only in the apiserver's own child env (via a command-scoped prefix
  # assignment, not `export`) so U7S_DHAT_BACKTRACE_DEPTH never leaks into
  # run-all.sh's own environment or any later step (sonobuoy, the scheduler,
  # etc.) that has no business seeing it. Absent --dhat-depth, nothing is set
  # here at all -- main.rs's own default of 10 applies.
  # shellcheck source=02-start-apiserver.sh
  # shellcheck disable=SC2086
  U7S_DHAT_BACKTRACE_DEPTH="$DHAT_DEPTH" source "$DIR/02-start-apiserver.sh" ${_PORT_ARG} ${_KUBELET_PORT_ARG} ${_KONNECTIVITY_SERVER_PORT_ARG} ${_WORKDIR_ARG} ${_NODE_KUBELET_PORT_ARG}
else
  # shellcheck source=02-start-apiserver.sh
  # shellcheck disable=SC2086
  source "$DIR/02-start-apiserver.sh" ${_PORT_ARG} ${_KUBELET_PORT_ARG} ${_KONNECTIVITY_SERVER_PORT_ARG} ${_WORKDIR_ARG} ${_NODE_KUBELET_PORT_ARG}
fi

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

# Start the run-metrics sampler (host+VM RSS, ring-gauge trajectory, an
# initial /metrics snapshot) now that the final node topology is known — see
# sample-run-metrics.sh for the three artifacts it produces and mayor-zpvp2
# for why this replaced an operator-run-by-hand monitoring loop. Reaped
# below: right before the apiserver is torn down under --profile, or at the
# very end of this script otherwise (the apiserver is never stopped by a
# plain or --stack-only run, so neither is the sampler — same lifecycle).
banner "Start run-metrics sampler"
# shellcheck disable=SC2086
bash "$DIR/sample-run-metrics.sh" start ${_PORT_ARG} ${_WORKDIR_ARG} ${_VM_ARG} ${_EXTRA_NODE_ARG} ${_SAMPLE_INTERVAL_ARG}

# Step 06: Run sonobuoy.
if [ "$STACK_ONLY" -eq 1 ]; then
  banner "Step 6/6: Run sonobuoy (skipped — --stack-only)"
  if [ "$PROFILE" -eq 1 ]; then
    echo ""
    echo "Allocation profile: apiserver is running under dhat. --stack-only leaves"
    echo "it running on purpose (for kubectl exploration), so dhat's Drop-based"
    echo "flush ($DHAT_HEAP_FILE) hasn't fired yet — stop it yourself when done:"
    echo "  kill -TERM \$(lsof -ti tcp:${PORT:-6443} -sTCP:LISTEN)"
  fi
else
  banner "Step 6/6: Run sonobuoy"
  export SONOBUOY_FOCUS="$FOCUS"
  # shellcheck disable=SC2086
  bash "$DIR/06-run-sonobuoy.sh" ${_PORT_ARG} ${_WORKDIR_ARG} ${_EXTRA_NODE_ARG} ${_ALL_E2E_ARG} ${_UNSAFE_FOCUS_ARG}

  # Build provenance: record what was actually tested (git SHA, dhat feature/
  # depth, node topology, exact invocation) into this run's own meta/build.json
  # -- so two runs are never silently compared across different configurations.
  # 06-run-sonobuoy.sh has already created temp/e2e/<TIMESTAMP>-<slug>/ by the
  # time it returns above, so it's the most-recently-created entry under
  # temp/e2e/ -- same resolution the --profile teardown below uses for the
  # dhat heap relocation, computed independently here since this must run for
  # EVERY sonobuoy invocation, not just profiled ones.
  # shellcheck disable=SC2012 # `ls -t` for mtime-sort has no `find` equivalent; these dirs are our own sanitized TIMESTAMP-slug names, never adversarial filenames.
  RUN_DIR=$(ls -td "$WORKDIR"/../e2e/*/ 2>/dev/null | head -1) || true
  RUN_DIR="${RUN_DIR%/}"
  if [ -n "$RUN_DIR" ]; then
    ARGV_JSON="[]"
    if [ "${#ORIGINAL_ARGV[@]}" -gt 0 ]; then
      ARGV_JSON=$(printf '%s\n' "${ORIGINAL_ARGV[@]}" | jq -R . | jq -s .)
    fi
    _PROFILE_PROV_ARG=""
    [ "$PROFILE" -eq 1 ] && _PROFILE_PROV_ARG="--profile"
    _DHAT_DEPTH_PROV_ARG=""
    [ "$PROFILE" -eq 1 ] && [ -n "$DHAT_DEPTH" ] && _DHAT_DEPTH_PROV_ARG="--dhat-depth $DHAT_DEPTH"
    # shellcheck disable=SC2086
    bash "$DIR/write-build-provenance.sh" --run-dir "$RUN_DIR" --vm "${U7S_VM_NAME:-lima-node}" ${_EXTRA_NODE_ARG} ${_PROFILE_PROV_ARG} ${_DHAT_DEPTH_PROV_ARG} --argv-json "$ARGV_JSON"
  else
    echo "warning: could not resolve this run's temp/e2e/ output dir — build.json not written" >&2
  fi

  if [ "$PROFILE" -eq 1 ]; then
    banner "Profile: stopping apiserver to flush dhat heap"
    # main.rs:29-33 only writes $DHAT_HEAP_FILE from dhat::Profiler's Drop
    # impl, which runs on a graceful return from run() -- triggered by
    # SIGTERM, never by run-all.sh just exiting while the stack keeps
    # serving (the normal, non-profile workflow). Stop it now, right after
    # sonobuoy retrieval + log evacuation are done reading from the live
    # stack, so the real, full-run heap lands on disk instead of staying
    # trapped in a process nobody signals (observed live: PID 27958 sat
    # running for 20+ minutes after a run finished, dhat heap trapped in
    # memory, until an operator noticed and killed it by hand).
    # Snapshot /metrics and reap the sampler BEFORE the apiserver is signalled
    # below — a snapshot taken after would just get the graceful-empty case
    # (apiserver already down), the exact ordering mistake mayor-zpvp2 exists
    # to prevent. 06-run-sonobuoy.sh already copied an earlier "post-run"
    # snapshot + the rss/ring CSVs-so-far into this run's temp/e2e/ dir; this
    # is the FINAL snapshot, taken right at the point dhat's own heap capture
    # also considers "the run is over".
    bash "$DIR/sample-run-metrics.sh" snapshot --workdir "$WORKDIR" --label pre-teardown
    bash "$DIR/sample-run-metrics.sh" stop --workdir "$WORKDIR"

    # shellcheck disable=SC2207 # word-split intentionally: lsof -ti can return multiple PIDs, one per line.
    API_PIDS=($(lsof -ti tcp:"${PORT:-6443}" -sTCP:LISTEN 2>/dev/null || true))
    if [ "${#API_PIDS[@]}" -gt 0 ]; then
      echo "Sending SIGTERM to apiserver (PID(s): ${API_PIDS[*]}) ..."
      kill "${API_PIDS[@]}" 2>/dev/null || true
      # Poll the PID(s) themselves, not the listening port: tokio::select!
      # (main.rs:29-33) cancels the server's own future -- which drops its
      # listener and frees the port -- the instant SIGTERM is observed, but
      # dhat::Profiler::drop (serializing a real run's allocation trace to
      # JSON) keeps the process itself alive for measurably longer.
      # Confirmed live: a port-based check on a 1-minute --focus run raced
      # ahead of a 928,953-block/4.27MB heap file that hadn't finished
      # writing yet, even though the port had already closed.
      any_alive() {
        local pid
        for pid in "${API_PIDS[@]}"; do
          kill -0 "$pid" 2>/dev/null && return 0
        done
        return 1
      }
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        any_alive || break
        sleep 1
      done
      if any_alive; then
        echo "warning: apiserver (PID(s): ${API_PIDS[*]}) still running 10s after SIGTERM — dhat heap may not have flushed" >&2
      fi
    else
      echo "warning: no apiserver found listening on port ${PORT:-6443} — dhat heap may already be stale" >&2
    fi
    # scheduler + konnectivity-server aren't dhat-instrumented, but leaving
    # them running after the apiserver they talk to is gone just leaves
    # orphans — same full-cleanup scope as reset.sh.
    pkill -f "u7s-scheduler.*${WORKDIR}/kubeconfig" 2>/dev/null || true
    WORKDIR_ABS="$(cd "$WORKDIR" && pwd)"
    pkill -f "konnectivity-server.*${WORKDIR_ABS}" 2>/dev/null || true

    # Route the flushed heap into this run's own temp/e2e/<TIMESTAMP>-<slug>/
    # directory (same place as host-logs/, the sonobuoy tarball, etc.)
    # instead of leaving it under --workdir for the operator to move by
    # hand. That directory's TIMESTAMP is only known to 06-run-sonobuoy.sh
    # (stamped at retrieval time, long after this apiserver was launched
    # with $DHAT_HEAP_FILE) -- find it as the most-recently-created entry
    # under temp/e2e/ rather than duplicating that script's own slug logic
    # here. `|| true` on the assignment: an empty glob match makes `ls`
    # exit non-zero even with stderr suppressed, which `set -e` would
    # otherwise treat as fatal for what's meant to be a soft lookup.
    # shellcheck disable=SC2012 # `ls -t` for mtime-sort has no `find` equivalent; these dirs are our own sanitized TIMESTAMP-slug names, never adversarial filenames.
    RUN_DIR=$(ls -td "$WORKDIR"/../e2e/*/ 2>/dev/null | head -1) || true
    RUN_DIR="${RUN_DIR%/}"
    if [ -f "$DHAT_HEAP_FILE" ] && [ -n "$RUN_DIR" ]; then
      TIMESTAMP=$(basename "$RUN_DIR" | cut -d- -f1,2)
      DEST="$RUN_DIR/dhat-heap-apiserver-${TIMESTAMP}.json"
      if mv "$DHAT_HEAP_FILE" "$DEST" 2>/dev/null; then
        echo "Allocation profile: $DEST"
      else
        echo "warning: failed to move dhat heap to $DEST — left at $DHAT_HEAP_FILE" >&2
      fi
    elif [ -f "$DHAT_HEAP_FILE" ]; then
      echo "warning: could not resolve this run's temp/e2e/ output dir — dhat heap left at $DHAT_HEAP_FILE" >&2
    else
      echo "warning: $DHAT_HEAP_FILE was not produced — apiserver may not have exited cleanly" >&2
    fi

    # Re-copy the monitoring artifacts now that they cover the whole run:
    # 06-run-sonobuoy.sh already copied a "post-run" snapshot of these into
    # $RUN_DIR/monitoring/, but rss.csv/ring-age.csv kept growing afterward
    # and the "pre-teardown" snapshot above (taken after that copy ran) isn't
    # there yet either. $RUN_DIR was already resolved above for the dhat heap.
    if [ -n "$RUN_DIR" ]; then
      MONITORING_DIR="$RUN_DIR/monitoring"
      mkdir -p "$MONITORING_DIR"
      [ -f "$WORKDIR/rss.csv" ]      && cp "$WORKDIR/rss.csv" "$MONITORING_DIR/rss.csv"
      [ -f "$WORKDIR/vm-free.csv" ]  && cp "$WORKDIR/vm-free.csv" "$MONITORING_DIR/vm-free.csv"
      [ -f "$WORKDIR/ring-age.csv" ] && cp "$WORKDIR/ring-age.csv" "$MONITORING_DIR/ring-age.csv"
      cp "$WORKDIR"/metrics-*.prom "$MONITORING_DIR/" 2>/dev/null || true
      echo "Monitoring artifacts: $MONITORING_DIR"
    fi
  fi
fi

if [ "$PROFILE" -eq 0 ]; then
  # Non-profile paths never stop the apiserver (a plain sonobuoy run and
  # --stack-only both deliberately leave the whole stack running — see
  # ai/prompts/vm-operations.md) so "before the teardown that stops the
  # apiserver" is trivially satisfied by any point, including here. The
  # sampler itself is still reaped so it doesn't outlive this invocation of
  # run-all.sh; re-run "sample-run-metrics.sh start" by hand to keep
  # monitoring a --stack-only session left running for manual investigation.
  # shellcheck disable=SC2086
  bash "$DIR/sample-run-metrics.sh" snapshot ${_WORKDIR_ARG} --label pre-teardown
  # shellcheck disable=SC2086
  bash "$DIR/sample-run-metrics.sh" stop ${_WORKDIR_ARG}
fi

banner "Done"

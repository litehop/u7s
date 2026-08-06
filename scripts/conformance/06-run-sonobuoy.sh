#!/usr/bin/env bash
# Run sonobuoy conformance tests inside the lima VM.
#
# Reads --focus from SONOBUOY_FOCUS env var or CLI argument. --all-e2e widens
# the run to the full e2e ginkgo set instead of --mode=certified-conformance
# (see run-all.sh for the mutual-exclusivity/precedence rules with --focus).
#
# Part of the scripts/conformance/ orchestration sequence.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
VM_NAME="${U7S_VM_NAME:-lima-node}"
FOCUS="${SONOBUOY_FOCUS:-}"
ALL_E2E=0
ALL_E2E_TIMEOUT_SECONDS="${SONOBUOY_ALL_E2E_TIMEOUT_SECONDS:-43200}"
WORKDIR="$PWD/temp/u7s"
UNPACK=1
PORT="${U7S_PORT:-6443}"
EXTRA_NODE=""
# --unsafe-focus only has an effect inside the --focus branch below (it wipes
# that branch's FeatureGate/[Flaky] filters). Given with --all-e2e or bare
# (certified-conformance), it's a structural no-op: neither of those branches
# ever reads it, so there's nothing to "unsafely" wipe -- a deliberate choice
# over erroring, since --all-e2e/--focus are already mutually exclusive at
# run-all.sh, and erroring here too would just be a second enforcement of the
# same rule.
UNSAFE_FOCUS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --focus) FOCUS="$2"; shift 2 ;;
    --all-e2e) ALL_E2E=1; shift ;;
    --unsafe-focus) UNSAFE_FOCUS=1; shift ;;
    --no-unpack) UNPACK=0; shift ;;
    --vm) VM_NAME="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --extra-node) EXTRA_NODE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

echo "=== [06] Run sonobuoy ==="

if ! command -v limactl &>/dev/null; then
  echo "error: limactl not found — install with: brew install lima" >&2; exit 1
fi
if [ -z "${KUBECONFIG:-}" ] || [ ! -f "$KUBECONFIG" ]; then
  echo "error: KUBECONFIG not set or file not found — start u7s first" >&2; exit 1
fi
if ! kubectl --kubeconfig="$KUBECONFIG" get nodes -o name 2>/dev/null | grep -Fxq "node/$VM_NAME"; then
  echo "error: $VM_NAME not registered — run scripts/conformance/lima-start.sh first" >&2; exit 1
fi

# ---------------------------------------------------------------------------
# Namespace TTL watchdog — runs host-side via kubectl to force-delete test
# namespaces that get stuck terminating or are simply too old.
#
# Thresholds:
#   10 min — force-delete Active namespaces (namespace leak / stuck creation)
#   15 min — force-delete ANY non-system namespace regardless of phase
#
# The Active threshold must clear the longest-running legitimate [Slow]
# conformance test, not just the common case: "[sig-apps] CronJob should not
# schedule jobs when suspended" keeps its namespace Active for a full 5-minute
# gomega.Consistently check (cronJobTimeout). A 5-minute threshold here raced
# that test's own 5-minute check directly: the watchdog force-deleted the
# namespace out from under the still-running test, which then failed with
# "CronJob \"suspended\" not found" even though nothing was actually wrong
# with the CronJob. 10 min gives a full 5 minutes of buffer beyond that
# test's floor — enough to stop racing it — while staying meaningfully
# tighter than a larger threshold so a genuine future hang still gets reaped
# reasonably promptly. 15 min keeps the any-phase net comfortably above the
# Active threshold without letting a stuck Terminating namespace linger.
#
# System namespaces excluded: default, kube-*, sonobuoy
# ---------------------------------------------------------------------------
watchdog_loop() {
  local kubeconfig="$1"
  while true; do
    sleep 30
    local now
    now=$(date -u +%s)

    # Fetch all namespaces as JSON for reliable macOS-host parsing.
    local ns_json
    ns_json=$(kubectl --kubeconfig="$kubeconfig" get ns -o json 2>/dev/null) || continue

    while IFS= read -r line; do
      local ns phase created age_s
      ns=$(     printf '%s' "$line" | jq -r '.name')
      phase=$(  printf '%s' "$line" | jq -r '.phase')
      created=$(printf '%s' "$line" | jq -r '.created')

      # Skip system namespaces.
      case "$ns" in
        default|sonobuoy|kube-*) continue ;;
      esac

      # Convert RFC3339 creationTimestamp to epoch seconds on macOS.
      local created_s
      created_s=$(date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "${created}" "+%s" 2>/dev/null) || continue
      age_s=$(( now - created_s ))

      local should_delete=0 reason=""
      if [ "$phase" = "Active" ] && [ "$age_s" -ge 600 ]; then
        should_delete=1
        reason="Active for ${age_s}s (>= 10m threshold)"
      elif [ "$age_s" -ge 900 ]; then
        should_delete=1
        reason="age=${age_s}s (>= 15m threshold, phase=${phase})"
      fi

      if [ "$should_delete" -eq 1 ]; then
        echo "[watchdog] $(date -u +%Y-%m-%dT%H:%M:%SZ) force-deleting namespace '${ns}' (${reason})"
        # Strip finalizers first so the API server will honour the delete. Namespace
        # finalizers live in spec.finalizers, not metadata.finalizers (unlike every other
        # resource type) — patching the wrong field is a silent no-op.
        kubectl --kubeconfig="$kubeconfig" patch ns "$ns" \
          -p '{"spec":{"finalizers":[]}}' --type=merge 2>/dev/null || true
        kubectl --kubeconfig="$kubeconfig" delete ns "$ns" \
          --grace-period=0 --force 2>/dev/null || true
      fi
    done < <(printf '%s' "$ns_json" \
      | jq -c '.items[] | {name: .metadata.name, phase: .status.phase, created: .metadata.creationTimestamp}')
  done
}

# Rewrite kubeconfig server address for in-VM use
REWRITTEN=$(mktemp)
_WATCHDOG_PID=""
trap 'rm -f "$REWRITTEN"; [ -n "$_WATCHDOG_PID" ] && kill "$_WATCHDOG_PID" 2>/dev/null || true' EXIT
sed "s|https://127.0.0.1:${PORT}|https://host.lima.internal:${PORT}|g" "$KUBECONFIG" > "$REWRITTEN"
limactl shell "$VM_NAME" sudo rm -f /tmp/sonobuoy-kubeconfig
limactl copy "$REWRITTEN" "${VM_NAME}:/tmp/sonobuoy-kubeconfig"

echo "Cleaning up any previous sonobuoy run..."
limactl shell "$VM_NAME" sudo sonobuoy delete --all --wait \
  --kubeconfig /tmp/sonobuoy-kubeconfig 2>/dev/null || true

echo "Waiting for sonobuoy namespace to fully drain..."
until ! limactl shell "$VM_NAME" sudo sonobuoy status \
  --kubeconfig /tmp/sonobuoy-kubeconfig &>/dev/null; do
  sleep 2
done

# Allow-set for FeatureGate-tagged tests u7s knowingly supports beyond GA.
# Grow item-by-item as new gates surface, always checking the new gate
# against upstream's release-1.36 test/conformance/testdata/conformance.yaml
# for a [Conformance] overlap FIRST -- Go's RE2 has no negative lookahead, so
# "skip every FeatureGate:* except X" cannot be expressed as an --e2e-skip
# regex; a curated ginkgo --label-filter allow-set is the correct shape.
# VolumeAttributesClass is GA-since-1.34 and the ONLY FeatureGate-labeled
# spec that overlaps [Conformance] at release-1.36 -- the label itself is
# stale test metadata upstream hasn't removed yet (see
# ai/findings/featuregate-conformance-resolution-2026-08-06.md). Ginkgo's
# isSubsetOf semantics: a spec with no FeatureGate label always matches (the
# empty set), a spec tagged [FeatureGate:VolumeAttributesClass] matches, any
# OTHER [FeatureGate:X] is skipped -- this is what stops a Beta-gated spec
# like HPAConfigurableTolerance (which crashed vendored kcm 14 minutes into a
# 12.6h --all-e2e run, temp/e2e/0805-2202-conformance) from running at all.
FEATUREGATE_LABEL_FILTER='FeatureGate: isSubsetOf {VolumeAttributesClass}'

# build_filter_args populates the FILTER_ARGS array with the sonobuoy argv
# elements for this invocation. apply=1 wires in the FeatureGate allow-set
# above plus the existing [Flaky] skip; apply=0 (the --unsafe-focus escape
# hatch) omits both, carrying only --procs=16.
#
# The label-filter value needs an internal space ("FeatureGate: isSubsetOf
# {...}" -- ginkgo's own tokenizer requires it), so it must survive as ONE
# argv element end-to-end (this script -> limactl shell -> sonobuoy's own
# flag parser) -- hence building it into an array (never word-split, unlike
# $SONOBUOY_BASE_ARGS below) instead of appending it to that flat string.
# Separately, go-runner (the conformance image's entrypoint) space-splits
# E2E_EXTRA_GINKGO_ARGS by default before re-assembling ginkgo's own argv,
# which would tear the label-filter value apart at its internal space --
# E2E_EXTRA_ARGS_SEP repoints that split character to '|' instead.
build_filter_args() {
  local apply="$1"
  if [ "$apply" -eq 1 ]; then
    FILTER_ARGS=(
      "--plugin-env=e2e.E2E_EXTRA_GINKGO_ARGS=--procs=16|--label-filter=${FEATUREGATE_LABEL_FILTER}"
      "--plugin-env=e2e.E2E_EXTRA_ARGS_SEP=|"
      "--e2e-skip=\[Flaky\]"
    )
  else
    FILTER_ARGS=("--plugin-env=e2e.E2E_EXTRA_GINKGO_ARGS=--procs=16")
  fi
}

SONOBUOY_BASE_ARGS="run --plugin e2e --wait --kubeconfig /tmp/sonobuoy-kubeconfig"

echo "Running sonobuoy inside $VM_NAME..."
# Start the namespace TTL watchdog in the background now that sonobuoy is
# creating test namespaces.  The EXIT trap kills it when we leave this script.
watchdog_loop "$KUBECONFIG" &
_WATCHDOG_PID=$!
echo "[watchdog] started (pid=${_WATCHDOG_PID})"

# Run sonobuoy.  Allow non-zero exit so that partial results are retrieved
# even when the run fails.
SONOBUOY_EXIT=0
if [ -n "$FOCUS" ]; then
  # Filters apply by default even to a named --focus test: a test whose
  # FeatureGate label isn't in the allow-set above runs 0 specs rather than
  # silently re-triggering a known-crashing test (e.g. HPAConfigurableTolerance)
  # just because an operator happened to name it. --unsafe-focus is the
  # deliberate, explicit escape hatch for the rare case a filtered test needs
  # to actually run once (e.g. to reproduce a bug on record).
  APPLY_FILTERS=1
  [ "$UNSAFE_FOCUS" -eq 1 ] && APPLY_FILTERS=0
  build_filter_args "$APPLY_FILTERS"
  # shellcheck disable=SC2086
  limactl shell "$VM_NAME" sudo sonobuoy $SONOBUOY_BASE_ARGS "${FILTER_ARGS[@]}" "--e2e-focus=$FOCUS" || SONOBUOY_EXIT=$?
elif [ "$ALL_E2E" -eq 1 ]; then
  # Full ginkgo set (~7500 specs) instead of just the [Conformance]-tagged
  # subset — surfaces plain ginkgo.It cases (e.g. SSA field-manager tests)
  # certified-conformance never runs. [Flaky] is skipped: it's upstream's own
  # known-unreliable set (not signal), and by definition can never overlap
  # with [Conformance] (a certified suite must be deterministic), so skipping
  # it never drops conformance coverage. The FeatureGate allow-set above is
  # ALWAYS applied here too (never gated behind --unsafe-focus, which is only
  # meaningful for a named --focus test): --all-e2e's own ".*" focus is
  # exactly what surfaced the HPAConfigurableTolerance crash in the first
  # place, since certified-conformance never runs Beta+ gated specs at all.
  # [Disruptive] and [Slow] are deliberately NOT skipped (unlike an earlier
  # version of this script) — checked against upstream's release-1.36
  # test/conformance/testdata/conformance.yaml, 2 [Disruptive] and 6 [Slow]
  # specs are ALSO [Conformance]. Skipping them made --all-e2e silently drop
  # conformance-tagged tests that --mode=certified-conformance covers,
  # contradicting run-all.sh's --all-e2e doc comment ("widen sonobuoy beyond
  # certified-conformance" implies a superset, not a smaller, different set).
  # Running the [Disruptive] conformance tests needs real 2-node capability
  # (this script's own --extra-node flag, driven by run-all.sh's
  # --extra-node/--extra-kubelet-port) — this project has had that for weeks,
  # so the old comment claiming lima lacked multi-node infra was stale.
  # Wall-clock for this mode is ~6-12h (see run-all.sh's --all-e2e doc
  # comment); sonobuoy's own --timeout (aggregator wait-for-plugins budget,
  # in seconds) defaults to 21600 (6h), which killed a real overnight run at
  # exactly 6h00m00s. Raise it to match this mode's own documented budget
  # instead of an unrelated default silently truncating it.
  build_filter_args 1
  # shellcheck disable=SC2086
  limactl shell "$VM_NAME" sudo sonobuoy $SONOBUOY_BASE_ARGS "${FILTER_ARGS[@]}" \
    --e2e-focus=".*" \
    --timeout "$ALL_E2E_TIMEOUT_SECONDS" || SONOBUOY_EXIT=$?
else
  build_filter_args 0
  # shellcheck disable=SC2086
  limactl shell "$VM_NAME" sudo sonobuoy $SONOBUOY_BASE_ARGS "${FILTER_ARGS[@]}" --mode=certified-conformance || SONOBUOY_EXIT=$?
fi
if [ "$SONOBUOY_EXIT" -ne 0 ]; then
  echo "[06] sonobuoy exited with status ${SONOBUOY_EXIT} — attempting partial result retrieval"
fi

# NODES lists every node in the run (computed here, before evacuation, so
# both this step and the tarball search below use the same list).
NODES=("$VM_NAME")
[ -n "$EXTRA_NODE" ] && NODES+=("$EXTRA_NODE")

# Evacuate pod logs immediately — before namespace GC removes them.
# sonobuoy --wait returns after the e2e binary exits but before namespace teardown,
# so /var/log/pods/ still has the container logs at this point. Looped over every
# node in NODES, not just $VM_NAME: the sonobuoy e2e-job pod (and therefore
# /var/log/pods/ contents) can land on either node, and a primary-only evacuation
# silently lost every pod log on a 2-node --all-e2e run where the pod scheduled
# onto the extra node (temp/e2e/0805-2202-conformance). tar's own recursive walk
# of /var/log/pods/ already picks up rotated 0.log.YYYYMMDDT... variants
# alongside the live 0.log, so no separate glob is needed for those. stderr is
# no longer suppressed on the tar itself -- a failed evacuation must print a
# warning, not vanish silently (the exact failure mode that lost 0805-2202's logs).
echo "Evacuating pod logs from VM(s): ${NODES[*]}..."
for NODE in "${NODES[@]}"; do
  limactl shell "$NODE" sudo tar -czf /tmp/pod-logs-evacuation.tar.gz /var/log/pods/ \
    || echo "warning: pod log evacuation failed on $NODE" >&2
  limactl copy "${NODE}:/tmp/pod-logs-evacuation.tar.gz" "$WORKDIR/pod-logs-evacuation-${NODE}.tar.gz" 2>/dev/null || true
  limactl shell "$NODE" sudo rm -f /tmp/pod-logs-evacuation.tar.gz 2>/dev/null || true
done

echo "Retrieving results..."
# sonobuoy retrieve uses port-forward which produces an EOF against u7s.
# Instead, locate the tarball from pod logs + kubelet emptyDir on the VM.
#
# Live incident 2026-08-04: sonobuoy's own scheduler placed the aggregator
# pod on the extra node instead of the primary, and every blocking call
# below had no timeout -- the script hung with zero output and no error,
# even though it has explicit "tarball not found" exit paths, because those
# paths only fire if a call actually RETURNS. NODES (computed above, for log
# evacuation) lists every node in the run so the tarball search isn't
# hardcoded to the primary; run_with_timeout below bounds every blocking
# call so a stall surfaces loudly instead.
CALL_TIMEOUT=30

# run_with_timeout <label> <secs> <suppress_stderr:0|1> <cmd...>
# Kills <cmd...> if it hasn't finished within <secs> seconds and prints a
# specific "'<label>' timed out" message so a stalled call is diagnosable
# instead of hanging the whole script forever with no output. No
# 'timeout'/'gtimeout' binary is assumed present on the macOS host running
# this script (confirmed absent even with Homebrew coreutils uninstalled),
# so the deadline is enforced by polling with 'kill -0' rather than a second
# backgrounded 'wait' -- the latter was tried first and, under this script's
# own 'set -e', hung indefinitely in bash 3.2 (macOS's shipped /bin/bash)
# waiting on a SIGKILL-terminated background job; polling avoids that
# entirely. suppress_stderr redirects only <cmd...>'s own stderr (e.g.
# find's benign "No such file or directory" on nodes without the pod) -- it
# must NOT swallow this function's own timeout message below, so it is
# applied directly to the "$@" command, never to the whole function's output.
run_with_timeout() {
  local label="$1" secs="$2" suppress_stderr="$3"
  shift 3
  if [ "$suppress_stderr" = "1" ]; then
    "$@" 2>/dev/null &
  else
    "$@" &
  fi
  local cmd_pid=$! waited=0
  while kill -0 "$cmd_pid" 2>/dev/null; do
    if [ "$waited" -ge "$secs" ]; then
      kill -9 "$cmd_pid" 2>/dev/null
      wait "$cmd_pid" 2>/dev/null || true
      echo "error: '$label' timed out after ${secs}s" >&2
      return 124
    fi
    sleep 1
    waited=$(( waited + 1 ))
  done
  local status=0
  wait "$cmd_pid" || status=$?
  return "$status"
}

# Find tarball name from aggregator logs (host-side kubectl, no SPDY needed).
TARBALL_NAME=$(run_with_timeout "kubectl logs -n sonobuoy sonobuoy" "$CALL_TIMEOUT" 1 \
    kubectl --kubeconfig="$KUBECONFIG" logs -n sonobuoy sonobuoy \
  | grep "Results available at" \
  | tail -1 \
  | grep -oE '[^ /]+\.tar\.gz') || true

if [ -z "$TARBALL_NAME" ]; then
  if [ "${SONOBUOY_EXIT:-0}" -ne 0 ]; then
    echo "warning: no results tarball found in sonobuoy logs (run was killed before completion)" >&2
    exit "${SONOBUOY_EXIT}"
  fi
  echo "error: could not find results tarball name in sonobuoy logs" >&2; exit 1
fi

# Get the aggregator pod UID to locate its emptyDir on the VM.
POD_UID=$(run_with_timeout "kubectl get pod -n sonobuoy sonobuoy" "$CALL_TIMEOUT" 0 \
    kubectl --kubeconfig="$KUBECONFIG" get pod \
    -n sonobuoy sonobuoy \
    -o jsonpath='{.metadata.uid}') || true

# Search every node in the run -- sonobuoy's own scheduler can (and did,
# live) place the aggregator pod on the extra node, not just $VM_NAME.
HOST_PATH=""
FOUND_NODE=""
for NODE in "${NODES[@]}"; do
  CANDIDATE=$(run_with_timeout "limactl shell $NODE sudo find (results tarball)" "$CALL_TIMEOUT" 1 \
      limactl shell "$NODE" sudo find \
      "/var/lib/kubelet/pods/${POD_UID}/volumes/kubernetes.io~empty-dir" \
      -name "$TARBALL_NAME" | head -1) || true
  if [ -n "$CANDIDATE" ]; then
    HOST_PATH="$CANDIDATE"
    FOUND_NODE="$NODE"
    break
  fi
done

if [ -z "$HOST_PATH" ]; then
  if [ "${SONOBUOY_EXIT:-0}" -ne 0 ]; then
    echo "warning: results tarball not found under kubelet pod volume on any node (${NODES[*]}) (run was killed before completion)" >&2
    exit "${SONOBUOY_EXIT}"
  fi
  echo "error: tarball not found under kubelet pod volume for uid=${POD_UID} on any node (${NODES[*]})" >&2; exit 1
fi

if ! run_with_timeout "limactl shell $FOUND_NODE sudo cp (stage results tarball)" "$CALL_TIMEOUT" 0 \
    limactl shell "$FOUND_NODE" sudo cp "$HOST_PATH" /tmp/sonobuoy-results.tar.gz; then
  echo "error: failed to stage results tarball on $FOUND_NODE" >&2; exit 1
fi

TIMESTAMP=$(date -u +%m%d-%H%M)
FOCUS_SLUG=$(echo "${FOCUS:-conformance}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/-*$//')
OUTFILE="$WORKDIR/../e2e/${TIMESTAMP}-${FOCUS_SLUG}.tar.gz"
mkdir -p "$WORKDIR/../e2e"
if ! run_with_timeout "limactl copy results tarball from $FOUND_NODE" "$CALL_TIMEOUT" 0 \
    limactl copy "${FOUND_NODE}:/tmp/sonobuoy-results.tar.gz" "$OUTFILE"; then
  echo "error: failed to copy results tarball from $FOUND_NODE to host" >&2; exit 1
fi
echo "Results: $OUTFILE"

# Collect host-side and VM-side logs into <run>/host-logs/ for post-run diagnosis.
# Kubelet, CRI-O, and kube-proxy all run as systemd units on the Lima VM — their logs
# are in the journal, not a file. Without this, a kubelet crash-loop (as in run
# 0705-1409) or a PLEG-relist-miss needing CRI-O's own timeline is undiagnosable
# post-hoc; kube-proxy's own timeline is the only way to tell whether it saw an
# EndpointSlice event late or reprogrammed slowly (vs. u7s never delivering the event).
# Collected for every node in the run (not just the primary) — KCM/scheduler run once
# for the whole cluster so they stay unlisted here.
RUN_DIR="${OUTFILE%.tar.gz}"
HOST_LOGS_DIR="$RUN_DIR/host-logs"
mkdir -p "$HOST_LOGS_DIR"
[ -f "$WORKDIR/apiserver.log" ]              && cp "$WORKDIR/apiserver.log"   "$HOST_LOGS_DIR/apiserver.log"
[ -f "$WORKDIR/scheduler.log" ]              && cp "$WORKDIR/scheduler.log"   "$HOST_LOGS_DIR/scheduler.log"
[ -f "$WORKDIR/konnectivity-server.log" ]    && cp "$WORKDIR/konnectivity-server.log" "$HOST_LOGS_DIR/konnectivity-server.log"
# NODES was already computed above for the tarball search; reused here.
for NODE in "${NODES[@]}"; do
  SUFFIX=""
  [ "$NODE" != "$VM_NAME" ] && SUFFIX="-${NODE}"
  limactl shell "$NODE" sudo journalctl -u kubelet --no-pager --utc \
    > "$HOST_LOGS_DIR/kubelet${SUFFIX}.log" 2>/dev/null || true
  limactl shell "$NODE" sudo journalctl -u crio --no-pager --utc \
    > "$HOST_LOGS_DIR/crio${SUFFIX}.log" 2>/dev/null || true
  # Always node-qualified (unlike kubelet/crio's unsuffixed primary) so a single-node
  # run's file name is unambiguous when compared side-by-side with a multi-node run's.
  limactl shell "$NODE" sudo journalctl -u kube-proxy --no-pager --utc \
    > "$HOST_LOGS_DIR/kube-proxy-${NODE}.log" 2>/dev/null || true
done
limactl shell "$VM_NAME" sudo cat /tmp/kcm.log \
  > "$HOST_LOGS_DIR/kcm.log" 2>/dev/null || true
echo "Host logs: $HOST_LOGS_DIR"

if [ "$UNPACK" -eq 1 ]; then
  UNPACK_DIR="$RUN_DIR"
  mkdir -p "$UNPACK_DIR"
  tar xzf "$OUTFILE" -C "$UNPACK_DIR"
  JUNIT="$UNPACK_DIR/plugins/e2e/results/global/junit_01.xml"
  if [ -f "$JUNIT" ]; then
    # Extract totals from the testsuites element.
    TESTS=$(grep -o 'tests="[0-9]*"' "$JUNIT" | head -1 | grep -o '[0-9]*')
    FAILURES=$(grep -o 'failures="[0-9]*"' "$JUNIT" | head -1 | grep -o '[0-9]*')
    SKIPPED=$(grep -o 'skipped="[0-9]*"' "$JUNIT" | head -1 | grep -o '[0-9]*')
    RAN=$(( TESTS - ${SKIPPED:-0} ))
    echo ""
    echo "=== Results summary ==="
    echo "  Ran:    $RAN"
    echo "  Passed: $(( RAN - ${FAILURES:-0} ))"
    echo "  Failed: ${FAILURES:-0}"
    if [ "${FAILURES:-0}" -gt 0 ]; then
      echo ""
      echo "  Failing tests:"
      grep 'status="failed"' "$JUNIT" \
        | grep -o 'name="[^"]*"' \
        | sed 's/name="//;s/"$//' \
        | grep -v "BeforeSuite\|AfterSuite\|ReportBefore\|ReportAfter\|Synchronized" \
        | sed 's/^/    /'

      # Print container logs from the evacuated tarballs (one per node, copied before namespace GC).
      E2E_LOG="$UNPACK_DIR/plugins/e2e/results/global/e2e.log"
      POD_LOGS_DIR="$UNPACK_DIR/pod-logs"
      HAVE_POD_LOGS=0
      for NODE in "${NODES[@]}"; do
        EVAC_TARBALL="$WORKDIR/pod-logs-evacuation-${NODE}.tar.gz"
        if [ -f "$EVAC_TARBALL" ]; then
          mkdir -p "$POD_LOGS_DIR"
          tar -xzf "$EVAC_TARBALL" -C "$POD_LOGS_DIR" 2>/dev/null || true
          HAVE_POD_LOGS=1
        fi
      done
      if [ -f "$E2E_LOG" ] && [ "$HAVE_POD_LOGS" -eq 1 ]; then
        echo ""
        echo "  Pod logs from failed test namespaces:"
        FAIL_NAMESPACES=$(grep -oE 'namespace "[a-z0-9-]+"' "$E2E_LOG" | \
          awk '{print $2}' | tr -d '"' | sort -u | grep -v "^$\|^default$\|^kube-system$\|^sonobuoy$" | head -5)
        for NS in $FAIL_NAMESPACES; do
          find "$POD_LOGS_DIR/var/log/pods" -maxdepth 1 -type d -name "${NS}_*" 2>/dev/null | head -3 | while read -r POD_DIR; do
            echo "    --- ${POD_DIR##*/} ---"
            find "$POD_DIR" -name "*.log" | sort | while read -r LOG_FILE; do
              CONTAINER=$(basename "$(dirname "$LOG_FILE")")
              echo "      [container: $CONTAINER]"
              tail -30 "$LOG_FILE" | sed 's/^/        /'
            done
          done
        done
      fi
    fi
    echo "  Unpacked: $UNPACK_DIR"
  fi
fi

#!/usr/bin/env bash
# Run sonobuoy conformance tests inside the lima VM.
#
# Reads --focus from SONOBUOY_FOCUS env var or CLI argument.
#
# Part of the scripts/conformance/ orchestration sequence.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
VM_NAME="${U7S_VM_NAME:-lima-node}"
FOCUS="${SONOBUOY_FOCUS:-}"
WORKDIR="$PWD/temp/u7s"
UNPACK=1
PORT="${U7S_PORT:-6443}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --focus) FOCUS="$2"; shift 2 ;;
    --no-unpack) UNPACK=0; shift ;;
    --vm) VM_NAME="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
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
if ! kubectl --kubeconfig="$KUBECONFIG" get nodes 2>/dev/null | grep -q "$VM_NAME"; then
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
        # Strip finalizers first so the API server will honour the delete.
        kubectl --kubeconfig="$kubeconfig" patch ns "$ns" \
          -p '{"metadata":{"finalizers":[]}}' --type=merge 2>/dev/null || true
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

SONOBUOY_BASE_ARGS="run --plugin e2e --wait --e2e-parallel=true --kubeconfig /tmp/sonobuoy-kubeconfig --skip-preflight=dnscheck"

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
  # shellcheck disable=SC2086
  limactl shell "$VM_NAME" sudo sonobuoy $SONOBUOY_BASE_ARGS "--e2e-focus=$FOCUS" || SONOBUOY_EXIT=$?
else
  # shellcheck disable=SC2086
  limactl shell "$VM_NAME" sudo sonobuoy $SONOBUOY_BASE_ARGS --mode=non-disruptive-conformance || SONOBUOY_EXIT=$?
fi
if [ "$SONOBUOY_EXIT" -ne 0 ]; then
  echo "[06] sonobuoy exited with status ${SONOBUOY_EXIT} — attempting partial result retrieval"
fi

# Evacuate pod logs immediately — before namespace GC removes them.
# sonobuoy --wait returns after the e2e binary exits but before namespace teardown,
# so /var/log/pods/ still has the container logs at this point.
echo "Evacuating pod logs from VM..."
limactl shell "$VM_NAME" sudo tar -czf /tmp/pod-logs-evacuation.tar.gz /var/log/pods/ 2>/dev/null || true
limactl copy "${VM_NAME}:/tmp/pod-logs-evacuation.tar.gz" "$WORKDIR/pod-logs-evacuation.tar.gz" 2>/dev/null || true
limactl shell "$VM_NAME" sudo rm -f /tmp/pod-logs-evacuation.tar.gz 2>/dev/null || true

echo "Retrieving results..."
# sonobuoy retrieve uses port-forward which produces an EOF against u7s.
# Instead, locate the tarball from pod logs + kubelet emptyDir on the VM.

# Find tarball name from aggregator logs (host-side kubectl, no SPDY needed).
TARBALL_NAME=$(kubectl --kubeconfig="$KUBECONFIG" logs -n sonobuoy sonobuoy 2>/dev/null \
  | grep "Results available at" \
  | tail -1 \
  | grep -oE '[^ /]+\.tar\.gz')

if [ -z "$TARBALL_NAME" ]; then
  if [ "${SONOBUOY_EXIT:-0}" -ne 0 ]; then
    echo "warning: no results tarball found in sonobuoy logs (run was killed before completion)" >&2
    exit "${SONOBUOY_EXIT}"
  fi
  echo "error: could not find results tarball name in sonobuoy logs" >&2; exit 1
fi

# Get the aggregator pod UID to locate its emptyDir on the VM.
POD_UID=$(kubectl --kubeconfig="$KUBECONFIG" get pod \
    -n sonobuoy sonobuoy \
    -o jsonpath='{.metadata.uid}')

HOST_PATH=$(limactl shell "$VM_NAME" sudo find \
    "/var/lib/kubelet/pods/${POD_UID}/volumes/kubernetes.io~empty-dir" \
    -name "$TARBALL_NAME" 2>/dev/null | head -1)

if [ -z "$HOST_PATH" ]; then
  if [ "${SONOBUOY_EXIT:-0}" -ne 0 ]; then
    echo "warning: results tarball not found under kubelet pod volume (run was killed before completion)" >&2
    exit "${SONOBUOY_EXIT}"
  fi
  echo "error: tarball not found under kubelet pod volume for uid=${POD_UID}" >&2; exit 1
fi

limactl shell "$VM_NAME" sudo cp "$HOST_PATH" /tmp/sonobuoy-results.tar.gz

TIMESTAMP=$(date +%m%d-%H%M)
FOCUS_SLUG=$(echo "${FOCUS:-conformance}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/-*$//')
OUTFILE="$WORKDIR/../e2e/${TIMESTAMP}-${FOCUS_SLUG}.tar.gz"
mkdir -p "$WORKDIR/../e2e"
limactl copy "${VM_NAME}:/tmp/sonobuoy-results.tar.gz" "$OUTFILE"
echo "Results: $OUTFILE"

# Collect host-side and VM-side logs into <run>/host-logs/ for post-run diagnosis.
# Kubelet runs as a systemd unit on the Lima VM — its log is in the journal, not a file.
# Without this, a kubelet crash-loop (as in run 0705-1409) is undiagnosable post-hoc.
RUN_DIR="${OUTFILE%.tar.gz}"
HOST_LOGS_DIR="$RUN_DIR/host-logs"
mkdir -p "$HOST_LOGS_DIR"
[ -f "$WORKDIR/apiserver.log" ]              && cp "$WORKDIR/apiserver.log"   "$HOST_LOGS_DIR/apiserver.log"
[ -f "$WORKDIR/scheduler.log" ]              && cp "$WORKDIR/scheduler.log"   "$HOST_LOGS_DIR/scheduler.log"
[ -f "$WORKDIR/konnectivity-server.log" ]    && cp "$WORKDIR/konnectivity-server.log" "$HOST_LOGS_DIR/konnectivity-server.log"
limactl shell "$VM_NAME" sudo journalctl -u kubelet --no-pager \
  > "$HOST_LOGS_DIR/kubelet.log" 2>/dev/null || true
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

      # Print container logs from the evacuated tarball (copied before namespace GC).
      E2E_LOG="$UNPACK_DIR/plugins/e2e/results/global/e2e.log"
      if [ -f "$E2E_LOG" ] && [ -f "$WORKDIR/pod-logs-evacuation.tar.gz" ]; then
        POD_LOGS_DIR="$UNPACK_DIR/pod-logs"
        mkdir -p "$POD_LOGS_DIR"
        tar -xzf "$WORKDIR/pod-logs-evacuation.tar.gz" -C "$POD_LOGS_DIR" 2>/dev/null || true

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

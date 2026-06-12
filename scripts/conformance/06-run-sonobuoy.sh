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
_VM="${U7S_VM_NAME:-lima-node}"
if [ "$_VM" = "lima-node" ]; then
  WORKDIR="$REPO/temp/u7s"
else
  WORKDIR="$REPO/temp/u7s-${_VM}"
fi
UNPACK=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --focus) FOCUS="$2"; shift 2 ;;
    --no-unpack) UNPACK=0; shift ;;
    --vm) VM_NAME="$2"; shift 2 ;;
    --port) shift 2 ;;
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
# Sonobuoy progress stall detector — kills the entire sonobuoy run if
# result-counts (passed + failed) has not incremented for 15 minutes.
#
# This is a second independent kill switch that operates at the sonobuoy
# level, complementing the namespace TTL watchdog.  It catches the case where
# the apiserver is completely unresponsive and the namespace watchdog cannot
# unblock a stuck test.
#
# Lifecycle:
#   - Start after sonobuoy run begins.
#   - Skip the first 30s while sonobuoy initialises.
#   - Guard against sonobuoy not yet running: skip iterations where status
#     returns no valid JSON or no plugins array.
#   - Kill on EXIT trap alongside the namespace watchdog.
# ---------------------------------------------------------------------------
stall_watchdog_loop() {
  local vm_name="$1"
  local last_count=0
  local last_progress_time
  last_progress_time=$(date +%s)
  local stall_threshold=900  # 15 minutes in seconds

  # Initial delay — sonobuoy needs time to initialise before we start polling.
  sleep 30

  while true; do
    sleep 60

    # Poll sonobuoy status from inside the VM.
    local status_json
    status_json=$(limactl shell "$vm_name" sudo sonobuoy status --json \
      --kubeconfig /tmp/sonobuoy-kubeconfig 2>/dev/null) || { continue; }

    # Guard: skip if output is not valid JSON or has no plugins array.
    if ! printf '%s' "$status_json" | jq -e '.plugins' &>/dev/null; then
      continue
    fi

    # Sum result-counts.passed and result-counts.failed across all plugins.
    local current_count
    current_count=$(printf '%s' "$status_json" \
      | jq '[.plugins[]? | (."result-counts".passed // 0) + (."result-counts".failed // 0)] | add // 0')

    local now
    now=$(date +%s)

    if [ "$current_count" -gt "$last_count" ]; then
      last_count=$current_count
      last_progress_time=$now
    else
      local stall_s=$(( now - last_progress_time ))
      if [ "$stall_s" -ge "$stall_threshold" ]; then
        echo "[stall-watchdog] $(date -u +%Y-%m-%dT%H:%M:%SZ) no sonobuoy progress for ${stall_s}s (passed+failed=${current_count}) — killing run"
        limactl shell "$vm_name" sudo sonobuoy delete --all --wait \
          --kubeconfig /tmp/sonobuoy-kubeconfig 2>/dev/null || true
        return 0
      fi
    fi
  done
}

# ---------------------------------------------------------------------------
# Namespace TTL watchdog — runs host-side via kubectl to force-delete test
# namespaces that get stuck terminating or are simply too old.
#
# Thresholds:
#   5 min  — force-delete Active namespaces (namespace leak / stuck creation)
#   10 min — force-delete ANY non-system namespace regardless of phase
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
      if [ "$phase" = "Active" ] && [ "$age_s" -ge 300 ]; then
        should_delete=1
        reason="Active for ${age_s}s (>= 5m threshold)"
      elif [ "$age_s" -ge 600 ]; then
        should_delete=1
        reason="age=${age_s}s (>= 10m threshold, phase=${phase})"
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
_STALL_WATCHDOG_PID=""
trap 'rm -f "$REWRITTEN"; [ -n "$_WATCHDOG_PID" ] && kill "$_WATCHDOG_PID" 2>/dev/null || true; [ -n "$_STALL_WATCHDOG_PID" ] && kill "$_STALL_WATCHDOG_PID" 2>/dev/null || true' EXIT
sed 's|https://127.0.0.1:6443|https://host.lima.internal:6443|g' "$KUBECONFIG" > "$REWRITTEN"
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

stall_watchdog_loop "$VM_NAME" &
_STALL_WATCHDOG_PID=$!
echo "[stall-watchdog] started (pid=${_STALL_WATCHDOG_PID})"

# Run sonobuoy.  Allow non-zero exit so that a stall-detector kill (which
# causes sonobuoy --wait to exit with an error) does not abort the script
# before partial results are retrieved.
SONOBUOY_EXIT=0
if [ -n "$FOCUS" ]; then
  # shellcheck disable=SC2086
  limactl shell "$VM_NAME" sudo sonobuoy $SONOBUOY_BASE_ARGS "--e2e-focus=$FOCUS" || SONOBUOY_EXIT=$?
else
  # shellcheck disable=SC2086
  limactl shell "$VM_NAME" sudo sonobuoy $SONOBUOY_BASE_ARGS --mode=non-disruptive-conformance || SONOBUOY_EXIT=$?
fi
if [ "$SONOBUOY_EXIT" -ne 0 ]; then
  echo "[06] sonobuoy exited with status ${SONOBUOY_EXIT} (stall-detector kill or other error) — attempting partial result retrieval"
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
OUTFILE="$REPO/temp/e2e/${TIMESTAMP}-${FOCUS_SLUG}.tar.gz"
mkdir -p "$REPO/temp/e2e"
limactl copy "${VM_NAME}:/tmp/sonobuoy-results.tar.gz" "$OUTFILE"
echo "Results: $OUTFILE"

if [ "$UNPACK" -eq 1 ]; then
  UNPACK_DIR="${OUTFILE%.tar.gz}"
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

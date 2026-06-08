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

# Rewrite kubeconfig server address for in-VM use
REWRITTEN=$(mktemp)
trap 'rm -f "$REWRITTEN"' EXIT
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
if [ -n "$FOCUS" ]; then
  # shellcheck disable=SC2086
  limactl shell "$VM_NAME" sudo sonobuoy $SONOBUOY_BASE_ARGS "--e2e-focus=$FOCUS"
else
  # shellcheck disable=SC2086
  limactl shell "$VM_NAME" sudo sonobuoy $SONOBUOY_BASE_ARGS --mode=non-disruptive-conformance
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

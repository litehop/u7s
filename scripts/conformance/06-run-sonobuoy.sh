#!/usr/bin/env bash
# Run sonobuoy conformance tests inside the lima VM.
#
# Reads --focus from SONOBUOY_FOCUS env var or CLI argument.
#
# Part of the scripts/conformance/ orchestration sequence.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
VM_NAME="lima-node"
FOCUS="${SONOBUOY_FOCUS:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --focus) FOCUS="$2"; shift 2 ;;
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

SONOBUOY_ARGS="run --plugin e2e --wait --e2e-parallel=true --kubeconfig /tmp/sonobuoy-kubeconfig --skip-preflight=dnscheck"
if [ -n "$FOCUS" ]; then
  SONOBUOY_ARGS="$SONOBUOY_ARGS --e2e-focus=$FOCUS"
else
  SONOBUOY_ARGS="$SONOBUOY_ARGS --mode=non-disruptive-conformance"
fi

echo "Running sonobuoy inside $VM_NAME..."
# shellcheck disable=SC2086
limactl shell "$VM_NAME" sudo sonobuoy $SONOBUOY_ARGS

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

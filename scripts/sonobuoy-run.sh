#!/usr/bin/env bash
# Run sonobuoy conformance tests against u7s from inside the lima VM.
#
# Prerequisites:
#   u7s running on the host (KUBECONFIG env var set)
#   lima-node VM running with kubelet registered (scripts/lima-start.sh)
#
# Usage:
#   scripts/sonobuoy-run.sh [--focus <regex>]
#     --focus  Run only e2e tests matching this regex
set -euo pipefail

VM_NAME="lima-node"
FOCUS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --focus) FOCUS="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if ! command -v limactl &>/dev/null; then
  echo "error: limactl not found — install with: brew install lima" >&2; exit 1
fi
if [ -z "${KUBECONFIG:-}" ] || [ ! -f "$KUBECONFIG" ]; then
  echo "error: KUBECONFIG not set or file not found — start u7s first" >&2; exit 1
fi
if ! kubectl --kubeconfig="$KUBECONFIG" get nodes 2>/dev/null | grep -q "$VM_NAME"; then
  echo "error: $VM_NAME not registered — run scripts/lima-start.sh first" >&2; exit 1
fi

# Rewrite kubeconfig server address for in-VM use
REWRITTEN=$(mktemp)
trap 'rm -f "$REWRITTEN"' EXIT
sed 's|https://127.0.0.1:6443|https://host.lima.internal:6443|g' "$KUBECONFIG" > "$REWRITTEN"
limactl copy "$REWRITTEN" "${VM_NAME}:/tmp/sonobuoy-kubeconfig"

SONOBUOY_ARGS="run --mode=non-disruptive-conformance --wait --kubeconfig /tmp/sonobuoy-kubeconfig --skip-preflight=dnscheck"
if [ -n "$FOCUS" ]; then
  SONOBUOY_ARGS="$SONOBUOY_ARGS --e2e-focus=$FOCUS"
fi

echo "Running sonobuoy inside $VM_NAME (mode=non-disruptive-conformance)..."
# shellcheck disable=SC2086
limactl shell "$VM_NAME" sudo sonobuoy $SONOBUOY_ARGS

echo "Retrieving results..."
limactl shell "$VM_NAME" sudo sonobuoy retrieve \
  --kubeconfig /tmp/sonobuoy-kubeconfig \
  --filename /tmp/sonobuoy-results.tar.gz

OUTDIR=$(mktemp -d)
limactl copy "${VM_NAME}:/tmp/sonobuoy-results.tar.gz" "$OUTDIR/results.tar.gz"
echo "Results: $OUTDIR/results.tar.gz"

echo ""
echo "=== Failures ==="
limactl shell "$VM_NAME" sonobuoy results /tmp/sonobuoy-results.tar.gz --mode=detailed \
  | grep -E "^(FAIL|failed)" | sort -u || echo "(no failures or sonobuoy results parse failed)"

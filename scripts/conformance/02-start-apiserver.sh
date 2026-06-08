#!/usr/bin/env bash
# Start u7s-apiserver in the background for conformance testing.
#
# Delegates to scripts/u7s-start.sh --background, which handles:
#   - Port-already-in-use detection (warns and reuses)
#   - Backgrounding with log redirection and disown
#   - Port readiness wait
#
# This script is source'd by run-all.sh so KUBECONFIG propagates.
#
# Part of the scripts/conformance/ orchestration sequence.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
# Mirror the WORKDIR derivation from u7s-start.sh so KUBECONFIG is correct.
_VM="${U7S_VM_NAME:-lima-node}"
if [ "$_VM" = "lima-node" ]; then
  WORKDIR="$REPO/temp/u7s"
else
  WORKDIR="$REPO/temp/u7s-${_VM}"
fi

echo "=== [02] Start apiserver ==="

bash "$REPO/scripts/u7s-start.sh" --background

export KUBECONFIG="$WORKDIR/kubeconfig"
echo "KUBECONFIG=$KUBECONFIG"

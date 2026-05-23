#!/usr/bin/env bash
# Full conformance run orchestrator.
#
# Runs all numbered steps in order:
#   01-build.sh           — build u7s-apiserver
#   02-start-apiserver.sh — start apiserver (or reuse running instance)
#   03-start-lima.sh      — provision lima VM and join kubelet
#   04-start-kcm.sh       — start kube-controller-manager inside lima VM
#   05-run-sonobuoy.sh    — run sonobuoy and print results
#
# Usage:
#   scripts/conformance/run-all.sh [--focus <regex>]
#
#   --focus   Passed through to sonobuoy to narrow test selection.
#             Also settable via SONOBUOY_FOCUS env var.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DIR="$REPO/scripts/conformance"
WORKDIR="$REPO/temp/u7s"
FOCUS="${SONOBUOY_FOCUS:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --focus) FOCUS="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

banner() {
  echo ""
  echo "============================================================"
  echo " $*"
  echo "============================================================"
}

# Step 01: Build
banner "Step 1/5: Build"
bash "$DIR/01-build.sh"

# Step 02: Start apiserver — source so KUBECONFIG export propagates.
banner "Step 2/5: Start apiserver"
# shellcheck source=02-start-apiserver.sh
source "$DIR/02-start-apiserver.sh"

# KUBECONFIG is now set (either from the running instance or newly started).
if [ -z "${KUBECONFIG:-}" ]; then
  # Fallback: set from well-known path if source didn't export it.
  export KUBECONFIG="$WORKDIR/kubeconfig"
fi
echo "Using KUBECONFIG=$KUBECONFIG"

# Step 03: Start lima VM and join kubelet.
banner "Step 3/5: Start lima VM"
bash "$DIR/03-start-lima.sh"

# Step 04: Start kcm inside VM.
banner "Step 4/5: Start kube-controller-manager"
bash "$DIR/04-start-kcm.sh"

# Step 05: Run sonobuoy.
banner "Step 5/5: Run sonobuoy"
export SONOBUOY_FOCUS="$FOCUS"
bash "$DIR/05-run-sonobuoy.sh"

banner "Done"

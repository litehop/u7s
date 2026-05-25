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
#   scripts/conformance/run-all.sh [--reset] [--focus <regex>]
#
#   --reset   Run reset.sh before building — kills host processes, deletes the
#             lima-node VM, and wipes temp/u7s/ for a fully clean run.
#   --focus   Passed through to sonobuoy to narrow test selection.
#             Also settable via SONOBUOY_FOCUS env var.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DIR="$REPO/scripts/conformance"
WORKDIR="$REPO/temp/u7s"
FOCUS="${SONOBUOY_FOCUS:-}"
RESET=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1; shift ;;
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

if [ "$RESET" -eq 1 ]; then
  banner "Reset: tearing down stale state"
  bash "$DIR/reset.sh"
fi

# Step 01: Build
banner "Step 1/6: Build"
bash "$DIR/01-build.sh"

# Step 02: Start apiserver — source so KUBECONFIG export propagates.
banner "Step 2/6: Start apiserver"
# shellcheck source=02-start-apiserver.sh
source "$DIR/02-start-apiserver.sh"

# KUBECONFIG is now set (either from the running instance or newly started).
if [ -z "${KUBECONFIG:-}" ]; then
  # Fallback: set from well-known path if source didn't export it.
  export KUBECONFIG="$WORKDIR/kubeconfig"
fi
echo "Using KUBECONFIG=$KUBECONFIG"

# Step 03: Start lima VM and join kubelet.
banner "Step 3/6: Start lima VM"
bash "$DIR/lima-start.sh"

# Step 04: Start kcm inside VM.
banner "Step 4/6: Start kube-controller-manager"
bash "$DIR/04-start-kcm.sh"

# Step 05: Start scheduler inside VM.
banner "Step 5/6: Start u7s-scheduler"
bash "$DIR/05-start-scheduler.sh"

# Step 06: Run sonobuoy.
banner "Step 6/6: Run sonobuoy"
export SONOBUOY_FOCUS="$FOCUS"
bash "$DIR/06-run-sonobuoy.sh"

banner "Done"

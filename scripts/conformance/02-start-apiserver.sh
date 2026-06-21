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

_PORT_OVERRIDE=""
_KUBELET_PORT_OVERRIDE=""
_WORKDIR_OVERRIDE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) _PORT_OVERRIDE="$2"; shift 2 ;;
    --kubelet-port) _KUBELET_PORT_OVERRIDE="$2"; shift 2 ;;
    --workdir) _WORKDIR_OVERRIDE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ -n "$_WORKDIR_OVERRIDE" ]; then
  WORKDIR="$_WORKDIR_OVERRIDE"
else
  WORKDIR="$PWD/temp/u7s"
fi

echo "=== [02] Start apiserver ==="

EXTRA_ARGS=""
[ -n "$_PORT_OVERRIDE" ]         && EXTRA_ARGS="$EXTRA_ARGS --port $_PORT_OVERRIDE"
[ -n "$_KUBELET_PORT_OVERRIDE" ] && EXTRA_ARGS="$EXTRA_ARGS --kubelet-port $_KUBELET_PORT_OVERRIDE"
[ -n "$_WORKDIR_OVERRIDE" ]      && EXTRA_ARGS="$EXTRA_ARGS --workdir $_WORKDIR_OVERRIDE"

# shellcheck disable=SC2086
bash "$REPO/scripts/u7s-start.sh" --background $EXTRA_ARGS

export KUBECONFIG="$WORKDIR/kubeconfig"
echo "KUBECONFIG=$KUBECONFIG"

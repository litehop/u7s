#!/usr/bin/env bash
# Provision/start lima VM and join its kubelet to u7s.
#
# Thin wrapper around scripts/lima-start.sh.
# Requires KUBECONFIG to be set (done by 02-start-apiserver.sh).
#
# Part of the scripts/conformance/ orchestration sequence.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"

echo "=== [03] Start lima VM and join kubelet ==="

if [ -z "${KUBECONFIG:-}" ] || [ ! -f "$KUBECONFIG" ]; then
  echo "error: KUBECONFIG not set or file not found — run 02-start-apiserver.sh first" >&2
  exit 1
fi

exec "$REPO/scripts/lima-start.sh"

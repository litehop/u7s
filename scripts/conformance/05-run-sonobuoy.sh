#!/usr/bin/env bash
# Run sonobuoy conformance tests.
#
# Thin wrapper around scripts/sonobuoy-run.sh.
# Passes through --focus if the SONOBUOY_FOCUS env var is set,
# or if --focus is given as a CLI argument.
#
# Part of the scripts/conformance/ orchestration sequence.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
FOCUS="${SONOBUOY_FOCUS:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --focus) FOCUS="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

echo "=== [05] Run sonobuoy ==="

ARGS=()
if [ -n "$FOCUS" ]; then
  ARGS+=(--focus "$FOCUS")
fi

exec "$REPO/scripts/sonobuoy-run.sh" "${ARGS[@]+"${ARGS[@]}"}"

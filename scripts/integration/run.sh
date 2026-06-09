#!/usr/bin/env bash
set -euo pipefail
# Usage: KUBECONFIG=<path> scripts/integration/run.sh
# Runs all fixture dirs in scripts/integration/fixtures/ in order.
# Each fixture dir must contain a run.sh that exits 0 (pass) or non-zero (fail).
# Prints PASS/FAIL per fixture. Exits non-zero if any fixture fails.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

if [[ -z "${KUBECONFIG:-}" ]]; then
  echo "ERROR: KUBECONFIG must be set" >&2
  exit 1
fi

failed=0
for fixture_dir in "$FIXTURES_DIR"/*/; do
  name="$(basename "$fixture_dir")"
  runner="$fixture_dir/run.sh"
  if [[ ! -f "$runner" ]]; then
    echo "SKIP $name (run.sh missing)"
    continue
  fi
  if KUBECONFIG="$KUBECONFIG" bash "$runner"; then
    echo "PASS $name"
  else
    echo "FAIL $name"
    failed=1
  fi
done

if [[ "$failed" -eq 1 ]]; then
  exit 1
fi

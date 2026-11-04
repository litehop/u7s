#!/usr/bin/env bash
# build_filter_args must pass the e2e framework --num-nodes=<nodes in the run>.
# Without it, --provider=local leaves the node count at -1 and every
# SkipUnlessNodeCountIsAtLeast spec (13 dual-stack "Secondary IP Family"
# Granular specs) self-skips with "Requires at least 2 nodes (not -1)".
#
# Evaluates the real function extracted from 06-run-sonobuoy.sh.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO/scripts/conformance/06-run-sonobuoy.sh"

NPASS=0
NFAIL=0
assert() {
  if [ "$2" = "1" ]; then echo "PASS: $1"; NPASS=$(( NPASS + 1 )); else echo "FAIL: $1"; NFAIL=$(( NFAIL + 1 )); fi
}

FN="$(sed -n '/^build_filter_args() {$/,/^}$/p' "$SCRIPT")"
[ -n "$FN" ] || { echo "FAIL: build_filter_args not found in $SCRIPT"; exit 1; }
eval "$FN"

FEATUREGATE_LABEL_FILTER='FeatureGate: isSubsetOf {X}'
JSON_REPORT_PATH=/r.json
PROCS=4
PASS=""

e2e_args_for() {
  build_filter_args "$1"
  printf '%s\n' "${FILTER_ARGS[@]}" | grep '^--plugin-env=e2e.E2E_EXTRA_ARGS=' | cut -d= -f3-
}

run_case() {
  local label="$1" apply="$2" want="$3"
  shift 3
  NODES=("$@")
  local got
  got="$(e2e_args_for "$apply")"
  assert "$label" "$([ "$got" = "$want" ] && echo 1 || echo 0)"
  [ "$got" = "$want" ] || echo "  got:  $got" >&2
}

U='--progress-report-url=http://localhost:8099/progress'
run_case "single-node run passes --num-nodes=1 (apply=1, '|' separator matching E2E_EXTRA_ARGS_SEP)" 1 "$U|--num-nodes=1" lima-a
run_case "two-node run passes --num-nodes=2 so multi-node specs run instead of skipping on -1" 1 "$U|--num-nodes=2" lima-a lima-b
run_case "unsafe-focus shape (default space separator) passes --num-nodes=2" 0 "$U --num-nodes=2" lima-a lima-b

echo ""
echo "Results: ${NPASS} passed, ${NFAIL} failed"
[ "$NFAIL" -eq 0 ]

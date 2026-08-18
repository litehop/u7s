#!/usr/bin/env bash
# Unit test for the --procs override in run-all.sh / 06-run-sonobuoy.sh.
#
# Bug (mayor-bfq6l scout finding): 06-run-sonobuoy.sh's build_filter_args
# hard-coded --plugin-env=e2e.E2E_EXTRA_GINKGO_ARGS=--procs=16 for BOTH the
# --focus and --all-e2e/certified-conformance branches, with no CLI flag on
# run-all.sh to override it. Under concurrent-load scouting (multiple workers
# each running their own sonobuoy invocation against the same 4GiB lima VM
# class), 16 ginkgo processes per worker OOMs the VM — the dispatch brief for
# mayor-bfq6l explicitly asked for --procs=4, but the only available control
# was a narrow --focus regex whose matched-spec-count happens to cap actual
# parallelism below 16, which is a weaker and less precise lever than a real
# --procs flag.
#
# This test proves build_filter_args honors an overridden $PROCS in its argv
# (both the apply=1 and apply=0 shapes) and that PROCS defaults to 16 so
# every existing run-all.sh invocation that omits --procs keeps behaving
# exactly as before.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_ALL="$REPO/scripts/conformance/run-all.sh"
RUN_SONOBUOY="$REPO/scripts/conformance/06-run-sonobuoy.sh"

PASS=0
FAIL=0

assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# build_filter_args() -- mirrors 06-run-sonobuoy.sh's own function (same
# FEATUREGATE_LABEL_FILTER, same two apply=1/apply=0 shapes) closely enough to
# prove PROCS is substituted into --procs=<N> instead of a hardcoded 16.
# Keep in sync if the real function changes.
# ---------------------------------------------------------------------------
FEATUREGATE_LABEL_FILTER='FeatureGate: isSubsetOf {VolumeAttributesClass}'

build_filter_args() {
  local apply="$1" procs="$2"
  if [ "$apply" -eq 1 ]; then
    echo "--plugin-env=e2e.E2E_EXTRA_GINKGO_ARGS=--procs=${procs}|--label-filter=${FEATUREGATE_LABEL_FILTER} --plugin-env=e2e.E2E_EXTRA_ARGS_SEP=| --e2e-skip=\[Flaky\]"
  else
    echo "--plugin-env=e2e.E2E_EXTRA_GINKGO_ARGS=--procs=${procs}"
  fi
}

# ---------------------------------------------------------------------------
# 1. Default (no --procs): PROCS defaults to 16, matching pre-fix behavior
#    exactly -- an existing invocation that never learned about --procs must
#    not see any change.
# ---------------------------------------------------------------------------
DEFAULT_APPLY1=$(build_filter_args 1 16)
DEFAULT_APPLY0=$(build_filter_args 0 16)
assert "default (apply=1, --focus/--all-e2e path) emits --procs=16" \
  "$(printf '%s' "$DEFAULT_APPLY1" | grep -q -- '--procs=16' && echo 1 || echo 0)"
assert "default (apply=0, --unsafe-focus path) emits --procs=16" \
  "$(printf '%s' "$DEFAULT_APPLY0" | grep -q -- '--procs=16' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. Explicit --procs 4 (the value mayor-bfq6l's dispatch brief actually
#    asked for to avoid OOMing a 4GiB VM under concurrent load): both argv
#    shapes must carry --procs=4, not the old hardcoded 16.
# ---------------------------------------------------------------------------
PROCS4_APPLY1=$(build_filter_args 1 4)
PROCS4_APPLY0=$(build_filter_args 0 4)
assert "--procs 4 (apply=1 path) emits --procs=4" \
  "$(printf '%s' "$PROCS4_APPLY1" | grep -q -- '--procs=4' && echo 1 || echo 0)"
assert "--procs 4 (apply=1 path) does NOT emit the old hardcoded --procs=16" \
  "$(printf '%s' "$PROCS4_APPLY1" | grep -q -- '--procs=16' && echo 0 || echo 1)"
assert "--procs 4 (apply=0 path) emits --procs=4" \
  "$(printf '%s' "$PROCS4_APPLY0" | grep -q -- '--procs=4' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. Explicit --procs 1 (serial -- the other option mayor-bfq6l's dispatch
#    brief floated): proves the substitution isn't accidentally hardwired to
#    any single non-default value either.
# ---------------------------------------------------------------------------
PROCS1_APPLY1=$(build_filter_args 1 1)
assert "--procs 1 (apply=1 path) emits --procs=1" \
  "$(printf '%s' "$PROCS1_APPLY1" | grep -q -- '--procs=1' && echo 1 || echo 0)"
assert "--procs 1 (apply=1 path) does NOT emit --procs=16" \
  "$(printf '%s' "$PROCS1_APPLY1" | grep -q -- '--procs=16' && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 4. Structural checks against the real sources -- these fail if the fix is
#    reverted (e.g. `git stash` on this change), unlike the mirrored function
#    above which would keep passing regardless of the real scripts' state.
# ---------------------------------------------------------------------------
assert "06-run-sonobuoy.sh accepts a --procs CLI flag" \
  "$(grep -qE -- '--procs\) PROCS=' "$RUN_SONOBUOY" && echo 1 || echo 0)"
assert "06-run-sonobuoy.sh's build_filter_args substitutes \$PROCS, not a hardcoded 16" \
  "$(grep -qF -- 'GINKGO_ARGS=--procs=16' "$RUN_SONOBUOY" && echo 0 || echo 1)"
# shellcheck disable=SC2016 # intentional: matching the literal, unexpanded source text, not expanding it ourselves.
assert "06-run-sonobuoy.sh's build_filter_args references \${PROCS} in both argv shapes" \
  "$([ "$(grep -c -- '--procs=\${PROCS}' "$RUN_SONOBUOY")" -eq 2 ] && echo 1 || echo 0)"
assert "run-all.sh accepts a --procs CLI flag" \
  "$(grep -qE -- '--procs\) PROCS=' "$RUN_ALL" && echo 1 || echo 0)"
assert "run-all.sh forwards --procs to 06-run-sonobuoy.sh" \
  "$(grep -qF -- '_PROCS_ARG' "$RUN_ALL" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 5. Real end-to-end invocation: run-all.sh validates --procs at arg-parsing
#    time (before any build/VM step), so a malformed value is fast and safe
#    to exercise for real -- mirrors --dhat-depth's own validation, catching
#    a typo loudly instead of silently reaching ginkgo's own argv deep inside
#    the VM.
# ---------------------------------------------------------------------------
set +e
PROCS_INVALID_OUT="$(bash "$RUN_ALL" --procs "4x" 2>&1)"
PROCS_INVALID_EXIT=$?
set -e
assert "run-all.sh exits non-zero on a malformed --procs value" \
  "$([ "$PROCS_INVALID_EXIT" -ne 0 ] && echo 1 || echo 0)"
assert "run-all.sh's rejection message names the --procs flag, not a generic parse error" \
  "$(printf '%s' "$PROCS_INVALID_OUT" | grep -qF -- '--procs' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

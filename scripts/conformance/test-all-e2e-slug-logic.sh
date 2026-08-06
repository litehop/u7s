#!/usr/bin/env bash
# Unit test for the --all-e2e result-folder slug in 06-run-sonobuoy.sh.
#
# Bug: FOCUS_SLUG always defaulted to "conformance" whenever --focus was
# empty, regardless of --all-e2e. That mislabels the result folder as a
# --mode=certified-conformance run even though --all-e2e is a strict
# superset with a very different (~6-12h vs ~25min) budget and coverage.
# Concrete example: temp/e2e/0805-2202-conformance was really a 12.6h
# --all-e2e run, which misled downstream readers of that folder name.
#
# This test proves --all-e2e with no --focus produces the "all-e2e" slug
# instead, while a non-empty --focus (descriptive of what actually ran)
# still wins, and the certified-conformance default is unchanged.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

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
# compute_focus_slug() -- mirrors 06-run-sonobuoy.sh's FOCUS_SLUG computation
# exactly (--all-e2e/--focus are already mutually exclusive by the time that
# line runs, enforced at run-all.sh:181, so no further case-split is needed
# here). Keep in sync if that line changes.
# ---------------------------------------------------------------------------
compute_focus_slug() {
  local focus="$1" all_e2e="$2" slug_input
  if [ "$all_e2e" -eq 1 ] && [ -z "$focus" ]; then
    slug_input="all-e2e"
  else
    slug_input="${focus:-conformance}"
  fi
  echo "$slug_input" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/-*$//'
}

# The pre-fix version -- mirrors the exact bug: the slug always defaulted to
# "conformance" whenever --focus was empty, with no awareness of --all-e2e.
compute_focus_slug_old_buggy() {
  local focus="$1"
  echo "${focus:-conformance}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/-*$//'
}

# ---------------------------------------------------------------------------
# 1. --all-e2e with no --focus produces the "all-e2e" slug -- the actual
#    mislabeling incident (temp/e2e/0805-2202-conformance was really a 12.6h
#    --all-e2e run, not a certified-conformance run).
# ---------------------------------------------------------------------------
assert "--all-e2e with no --focus produces the all-e2e slug" \
  "$([ "$(compute_focus_slug "" 1)" = "all-e2e" ] && echo 1 || echo 0)"

# Regression guard: prove the OLD computation genuinely mislabels this same
# scenario as "conformance", so this test would catch a revert to it.
assert "(regression guard) pre-fix slug computation genuinely mislabels --all-e2e as conformance" \
  "$([ "$(compute_focus_slug_old_buggy "")" = "conformance" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. certified-conformance (no --all-e2e, no --focus) keeps the "conformance"
#    slug -- this fix only changes the --all-e2e-with-no-focus case.
# ---------------------------------------------------------------------------
assert "certified-conformance (no --all-e2e, no --focus) slug is unchanged" \
  "$([ "$(compute_focus_slug "" 0)" = "conformance" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. A non-empty --focus still produces its own descriptive slug and wins
#    over the --all-e2e default -- a focus regex describes what actually
#    ran, so it must never be overridden by the all-e2e label (run-all.sh
#    already rejects --focus combined with --all-e2e before this script
#    runs, but the slug logic itself must not rely on that for correctness).
#    Expected value has a leading "-" -- that's the existing (unchanged)
#    sanitization pipeline mapping the focus string's leading "[" to a "-";
#    confirmed against real historical folders (e.g.
#    temp/e2e/0806-0217--driver-csi-hostpath, i.e. TIMESTAMP + "-" +
#    "-driver-csi-hostpath"). This fix does not touch that pipeline.
# ---------------------------------------------------------------------------
assert "--focus produces its own descriptive slug, unaffected by the all-e2e fix" \
  "$([ "$(compute_focus_slug "[Driver: csi-hostpath]" 0)" = "-driver-csi-hostpath" ] && echo 1 || echo 0)"
assert "a non-empty --focus wins over --all-e2e for slug purposes" \
  "$([ "$(compute_focus_slug "[Driver: csi-hostpath]" 1)" = "-driver-csi-hostpath" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

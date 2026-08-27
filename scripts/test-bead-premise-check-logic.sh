#!/usr/bin/env bash
# Unit test for scripts/bead-premise-check.sh's pure functions.
#
# Exercises the REAL script as a subprocess via its `__call <fn> [args...]`
# entry point (same "real script, not a reimplementation" technique the
# sibling scripts/test-*-logic.sh suites use) -- a reimplementation of the
# extraction regex or presence check would keep passing even if the real
# logic regressed.
#
# Covers three things load-bearing for the dispatch loop's "is this bead's
# premise still true" check:
#   1. Pattern extraction (extract_target_pattern) -- the check's only
#      signal for what to grep for. Picking a throwaway symbol over a real
#      path, or vice versa, makes every downstream verdict wrong.
#   2. Pattern-presence check (check_pattern_present), including the
#      .beads/ exclusion: without it, every check would trivially match the
#      bead's own stored text and always report still-broken, making the
#      whole script a no-op that never catches an already-fixed bead.
#   3. End-to-end classification (classify_from_json) against synthetic
#      `bd show --json` output -- proves the three exit codes
#      (still-broken/no-longer-broken/cannot-verify) actually correspond to
#      0/1/2 and the right stdout string.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/bead-premise-check.sh"

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

call() {  # runs the real script's __call entry point, capturing stdout
  bash "$SCRIPT" __call "$@"
}

new_sandbox() {
  local dir="$1"
  git init -q -b main "$dir"
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name "Test"
}

commit_tree() {
  local dir="$1"
  git -C "$dir" add -A
  git -C "$dir" commit -q -m snapshot
}

SANDBOX_ROOT=$(mktemp -d)
trap 'rm -rf "$SANDBOX_ROOT"' EXIT

# ---------------------------------------------------------------------------
# 1. Pattern extraction.
# ---------------------------------------------------------------------------

assert "a path-shaped backtick span is extracted over a bare symbol" \
  "$([ "$(call extract_target_pattern 'still calls the old `some_symbol` helper from `scripts/old-thing.sh`')" = "scripts/old-thing.sh" ] && echo 1 || echo 0)"

assert "a bare symbol span is extracted when no path-shaped span exists" \
  "$([ "$(call extract_target_pattern 'the handler never calls `validate_input`')" = "validate_input" ] && echo 1 || echo 0)"

assert "a multi-word prose-in-backticks span (no path, has spaces) yields no pattern" \
  "$([ -z "$(call extract_target_pattern 'run `git commit` after this')" ] && echo 1 || echo 0)"

assert "text with no backtick spans at all yields no pattern" \
  "$([ -z "$(call extract_target_pattern 'plain prose describing a bug, no code spans')" ] && echo 1 || echo 0)"

assert "the FIRST path-shaped span wins when more than one is present" \
  "$([ "$(call extract_target_pattern 'see `scripts/first.sh` not `scripts/second.sh`')" = "scripts/first.sh" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. Pattern-presence check, including the .beads/ exclusion.
# ---------------------------------------------------------------------------

S1="$SANDBOX_ROOT/1-present"
new_sandbox "$S1"
mkdir -p "$S1/src"
printf 'fn old_broken_helper() {}\n' > "$S1/src/lib.rs"
commit_tree "$S1"
RC=0
BEAD_PREMISE_CHECK_REPO_ROOT="$S1" call check_pattern_present 'old_broken_helper' || RC=$?
assert "pattern present in a tracked source file is detected" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

S2="$SANDBOX_ROOT/2-absent"
new_sandbox "$S2"
mkdir -p "$S2/src"
printf 'fn fixed_helper() {}\n' > "$S2/src/lib.rs"
commit_tree "$S2"
RC=0
BEAD_PREMISE_CHECK_REPO_ROOT="$S2" call check_pattern_present 'old_broken_helper' || RC=$?
assert "pattern absent from the tree is reported not-present" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# The regression-guarding case: a pattern that ONLY exists inside .beads/
# (simulating the bead's own description text, which bd stores verbatim in
# .beads/issues.jsonl) must not count as "present in the tree" -- otherwise
# every premise check would trivially find its own source text and report
# still-broken forever, even after the real fix landed.
S3="$SANDBOX_ROOT/3-beads-only"
new_sandbox "$S3"
mkdir -p "$S3/src" "$S3/.beads"
printf 'fn fixed_helper() {}\n' > "$S3/src/lib.rs"
printf '{"description":"still calls old_broken_helper"}\n' > "$S3/.beads/issues.jsonl"
commit_tree "$S3"
RC=0
BEAD_PREMISE_CHECK_REPO_ROOT="$S3" call check_pattern_present 'old_broken_helper' || RC=$?
assert "a pattern that only appears in .beads/issues.jsonl (the bead's own stored text) does not count as present" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. End-to-end classification against synthetic `bd show --json` output.
# ---------------------------------------------------------------------------

S4="$SANDBOX_ROOT/4-still-broken"
new_sandbox "$S4"
mkdir -p "$S4/scripts"
printf '#!/usr/bin/env bash\necho hi\n' > "$S4/scripts/old-thing.sh"
commit_tree "$S4"
JSON_STILL_BROKEN='[{"description":"the handler still shells out via `scripts/old-thing.sh`","design":null,"acceptance_criteria":null}]'
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S4" call classify_from_json "$JSON_STILL_BROKEN") || RC=$?
assert "a still-present target pattern classifies as still-broken with exit 0" \
  "$([ "$OUT" = "still-broken" ] && [ "$RC" -eq 0 ] && echo 1 || echo 0)"

S5="$SANDBOX_ROOT/5-fixed"
new_sandbox "$S5"
mkdir -p "$S5/scripts"
printf '#!/usr/bin/env bash\necho hi\n' > "$S5/scripts/new-thing.sh"
commit_tree "$S5"
JSON_FIXED='[{"description":"the handler still shells out via `scripts/old-thing.sh`","design":null,"acceptance_criteria":null}]'
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S5" call classify_from_json "$JSON_FIXED") || RC=$?
assert "a target pattern no longer in the tree classifies as no-longer-broken with exit 1" \
  "$([ "$OUT" = "no-longer-broken" ] && [ "$RC" -eq 1 ] && echo 1 || echo 0)"

JSON_NO_PATTERN='[{"description":"plain prose, no code spans describing this bug at all","design":null,"acceptance_criteria":null}]'
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S5" call classify_from_json "$JSON_NO_PATTERN") || RC=$?
assert "text with no parseable target pattern classifies as cannot-verify with exit 2" \
  "$([ "$OUT" = "cannot-verify" ] && [ "$RC" -eq 2 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

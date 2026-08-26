#!/usr/bin/env bash
# Unit test for scripts/check-doc-budget.sh's word-budget ratchet.
#
# Exercises the REAL script as a subprocess against disposable sandbox git
# repos (same technique as test-build-provenance-logic.sh /
# test-sample-run-metrics-logic.sh), not a reimplementation of its
# fenced-code-stripping word count or its ratchet comparison — a
# reimplementation would keep passing even if the real script regressed.
#
# Covers the six branches PR #1322 verified by hand before this test existed:
#
#   1. Clean tree (no doc changes) -> passes.
#   2. A word-count-neutral reflow of an existing over-budget doc -> passes,
#      because `wc -w` (unlike a line-count cap) is invariant under joining
#      lines -- this is the whole reason the gate counts words, not lines.
#   3. Tracked doc grows past its budget -> fails.
#   4. A brand-new UNTRACKED doc over budget -> fails. This is the specific
#      case PR #1322 itself found and fixed mid-review (commit c8860b6d):
#      `git diff --name-only <base> -- '*.md'` alone is blind to untracked
#      paths, so a fresh over-budget doc silently passed until the gate also
#      unioned in `git ls-files --others --exclude-standard`. If that union
#      is ever dropped, this is the case that must catch it.
#   5. `kind: postmortem` doc grows past its budget -> passes by design
#      (postmortems are dated incident records, not maintained-down docs).
#   6. A real compression of an over-budget doc (still over budget, but
#      shrinking) -> passes, proving the RATCHET never blocks pre-existing
#      debt from shrinking even before it clears the budget.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/check-doc-budget.sh"

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

# Print $1 space-separated words to stdout, no trailing newline content beyond
# the words themselves -- lets scenarios build docs at an exact word count.
words() {
  printf 'w %.0s' $(seq 1 "$1")
}

# Fresh sandbox git repo at $1 with a single "old" commit on branch main.
# Scenarios then edit the working tree (without committing) to produce the
# "new" state the gate evaluates -- mirroring a real pre-push working tree.
new_sandbox() {
  local dir="$1"
  git init -q -b main "$dir"
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name "Test"
}

commit_old_state() {
  local dir="$1"
  git -C "$dir" add -A
  git -C "$dir" commit -q -m old
}

# Runs the real gate against sandbox $1 with the old commit as base ref.
# Returns the gate's exit code without tripping this script's `set -e`.
run_gate() {
  local dir="$1"
  set +e
  (cd "$dir" && bash "$SCRIPT" main) >"$dir/.gate-out" 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

SANDBOX_ROOT=$(mktemp -d)
trap 'rm -rf "$SANDBOX_ROOT"' EXIT

# ---------------------------------------------------------------------------
# 1. Clean tree: no doc edits at all after the old commit -> passes.
# ---------------------------------------------------------------------------
S1="$SANDBOX_ROOT/1-clean"
new_sandbox "$S1"
mkdir -p "$S1/docs/decisions"
printf '%s\n' "$(words 300)" > "$S1/docs/decisions/adr.md"
commit_old_state "$S1"
RC1=$(run_gate "$S1")
assert "clean tree (no doc changes) passes" "$([ "$RC1" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. No-op reflow: an already over-budget doc (450 words, budget 400) is
#    rewrapped onto many short lines with the same 450 words -- word count
#    is unchanged, so the ratchet (new > old) must not trip even though the
#    doc stays over budget the whole time.
# ---------------------------------------------------------------------------
S2="$SANDBOX_ROOT/2-reflow"
new_sandbox "$S2"
mkdir -p "$S2/docs/decisions"
printf '%s\n' "$(words 450)" > "$S2/docs/decisions/adr.md"
commit_old_state "$S2"
for w in $(words 450); do printf '%s\n' "$w"; done > "$S2/docs/decisions/adr.md"
RC2=$(run_gate "$S2")
assert "word-count-neutral reflow of an over-budget doc passes" \
  "$([ "$RC2" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. Over-budget growth: a tracked doc grows from under budget (350) to over
#    budget (450, budget 400) -> fails.
# ---------------------------------------------------------------------------
S3="$SANDBOX_ROOT/3-growth"
new_sandbox "$S3"
mkdir -p "$S3/docs/decisions"
printf '%s\n' "$(words 350)" > "$S3/docs/decisions/adr.md"
commit_old_state "$S3"
printf '%s\n' "$(words 450)" > "$S3/docs/decisions/adr.md"
RC3=$(run_gate "$S3")
assert "tracked doc growing past its budget fails" "$([ "$RC3" -ne 0 ] && echo 1 || echo 0)"
assert "over-budget growth failure names the offending file" \
  "$(grep -qF 'docs/decisions/adr.md' "$S3/.gate-out" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. New untracked file over budget: a brand-new doc (450 words, budget 400)
#    is never `git add`-ed. This is commit c8860b6d's regression case --
#    before that fix the gate only walked `git diff --name-only <base>`,
#    which is blind to untracked paths, so this file passed silently.
# ---------------------------------------------------------------------------
S4="$SANDBOX_ROOT/4-untracked"
new_sandbox "$S4"
mkdir -p "$S4/docs/decisions"
printf '%s\n' "$(words 10)" > "$S4/docs/decisions/existing.md"
commit_old_state "$S4"
printf '%s\n' "$(words 450)" > "$S4/docs/decisions/brand-new.md"
RC4=$(run_gate "$S4")
assert "new untracked doc over budget fails (c8860b6d regression case)" \
  "$([ "$RC4" -ne 0 ] && echo 1 || echo 0)"
assert "untracked-file failure names the new file, not just tracked ones" \
  "$(grep -qF 'docs/decisions/brand-new.md' "$S4/.gate-out" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 5. Postmortem exemption: a `kind: postmortem` doc grows well past its
#    budget -> still passes, by design (postmortems are dated incident
#    records, not docs an agent is expected to keep trimmed).
# ---------------------------------------------------------------------------
S5="$SANDBOX_ROOT/5-postmortem"
new_sandbox "$S5"
mkdir -p "$S5/ai/extended-context"
{
  printf 'kind: postmortem\n'
  printf '%s\n' "$(words 1300)"
} > "$S5/ai/extended-context/incident.md"
commit_old_state "$S5"
{
  printf 'kind: postmortem\n'
  printf '%s\n' "$(words 1400)"
} > "$S5/ai/extended-context/incident.md"
RC5=$(run_gate "$S5")
assert "kind: postmortem doc growing past budget still passes" \
  "$([ "$RC5" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 6. Real compression: an over-budget doc (500 words, budget 400) shrinks to
#    450 -- still over budget, but the ratchet only blocks growth, so this
#    must pass exactly like a full-recovery compression would.
# ---------------------------------------------------------------------------
S6="$SANDBOX_ROOT/6-compress"
new_sandbox "$S6"
mkdir -p "$S6/docs/decisions"
printf '%s\n' "$(words 500)" > "$S6/docs/decisions/adr.md"
commit_old_state "$S6"
printf '%s\n' "$(words 450)" > "$S6/docs/decisions/adr.md"
RC6=$(run_gate "$S6")
assert "real compression of an over-budget (still-over-budget) doc passes" \
  "$([ "$RC6" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

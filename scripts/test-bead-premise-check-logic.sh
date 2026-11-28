#!/usr/bin/env bash
# Unit test for scripts/bead-premise-check.sh's pure functions.
#
# Exercises the REAL script as a subprocess via its `__call <fn> [args...]`
# entry point (same "real script, not a reimplementation" technique the
# sibling scripts/test-*-logic.sh suites use) -- a reimplementation of the
# extraction regex or presence check would keep passing even if the real
# logic regressed.
#
# Covers what's load-bearing for the dispatch loop's "is this bead's
# premise still true" check, including two real false positives a
# critical-review found on this branch against real closed beads:
#   1. Path-candidate extraction, and why a cited path's mere EXISTENCE
#      must never confidently decide still-broken (one false positive's
#      first backtick span is an existing file the fix only added a
#      function to -- it exists before and after the fix).
#   2. The restricted-symbol filter (is_restricted_symbol_candidate) --
#      without it, a short common-word span like `enable` (the other false
#      positive) matches unrelated occurrences tree-wide and misclassifies
#      an already-fixed bead as still-broken.
#   3. Fenced-code-block extraction as a fallback candidate.
#   4. The Fix-section override and its inverted polarity -- without it,
#      a bug-description symbol that a fix's OWN doc comment also uses
#      (`NetworkPolicyPort.protocol`) can never distinguish "not fixed"
#      from "fixed, and the doc comment says so".
#   5. End-to-end classification, including synthetic beads that mirror
#      the exact shape of the two real false positives.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/drain-grep.sh"

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
# 1. Path-candidate extraction.
# ---------------------------------------------------------------------------

assert "a path-shaped backtick span is extracted" \
  "$([ "$(call extract_path_candidates 'see `scripts/old-thing.sh` for details' | head -1)" = "scripts/old-thing.sh" ] && echo 1 || echo 0)"

assert "the FIRST path-shaped span wins when more than one is present" \
  "$([ "$(call extract_path_candidates 'see `scripts/first.sh` not `scripts/second.sh`' | head -1)" = "scripts/first.sh" ] && echo 1 || echo 0)"

assert "a non-path backtick span is not returned as a path candidate" \
  "$([ -z "$(call extract_path_candidates 'the handler never calls \`validate_input\`')" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. Restricted-symbol filter -- the install-restart-bug regression guard.
# ---------------------------------------------------------------------------

RC=0
call is_restricted_symbol_candidate 'enable' || RC=$?
assert "a short common word (the install-restart bug's false-positive candidate 'enable', 6 chars) is rejected" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_restricted_symbol_candidate 'journalctl' || RC=$?
assert "a 10-char word with neither underscore nor a case transition (the install-restart bug's 'journalctl') is rejected" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_restricted_symbol_candidate 'default_networkpolicy' || RC=$?
assert "a snake_case identifier >= 8 chars is accepted" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_restricted_symbol_candidate 'NetworkPolicyPort' || RC=$?
assert "a CamelCase identifier (lowercase->uppercase transition), no underscore, is accepted" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_restricted_symbol_candidate 'validate' || RC=$?
assert "an all-lowercase word with no underscore, even if >= 8 chars, is rejected (no structure signal at all)" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_restricted_symbol_candidate 'git commit' || RC=$?
assert "a multi-word span (prose-in-backticks) is rejected regardless of length" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_restricted_symbol_candidate 'crates/foo/bar_baz.rs' || RC=$?
assert "a path-shaped span is rejected from the symbol bucket (handled by the path bucket instead)" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

assert "extract_symbol_candidates returns only qualifying spans, in order of appearance" \
  "$([ "$(call extract_symbol_candidates 'uses `enable` then `default_networkpolicy` and later `NetworkPolicyPort`' | head -1)" = "default_networkpolicy" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. Fenced-code-block extraction.
# ---------------------------------------------------------------------------

FENCED_TEXT='See the bug:
```bash
some_broken_command --flag
```
that is the problem.'
assert "the first non-blank line of the first fenced code block is extracted" \
  "$([ "$(call extract_fenced_code_pattern "$FENCED_TEXT")" = "some_broken_command --flag" ] && echo 1 || echo 0)"

assert "text with no fenced code block yields no fenced-code pattern" \
  "$([ -z "$(call extract_fenced_code_pattern 'plain prose, no code fences at all')" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. Fix-section extraction -- the netpol-defaulting-bug regression guard
#    for the "bug description and fix doc-comment share the same
#    terminology" case.
# ---------------------------------------------------------------------------

FIX_TEXT='The bug is that `WidgetSpec.enabled` is never defaulted.

Fix: add `default_widget_spec(obj)` to handle it.'
assert "extract_fix_section_text captures everything from the Fix: marker onward" \
  "$(call extract_fix_section_text "$FIX_TEXT" | drain_grep -qF 'default_widget_spec' && echo 1 || echo 0)"
assert "...and excludes text BEFORE the Fix: marker" \
  "$(! call extract_fix_section_text "$FIX_TEXT" | drain_grep -qF 'WidgetSpec.enabled' && echo 1 || echo 0)"

assert "a 'prefix:' line does not false-trigger the Fix: marker (must start a line, not just contain the substring)" \
  "$([ -z "$(call extract_fix_section_text 'set the prefix: value here, no real fix section')" ] && echo 1 || echo 0)"

assert "extract_fix_section_candidate picks the first qualifying symbol named in the Fix section" \
  "$([ "$(call extract_fix_section_candidate "$FIX_TEXT")" = "default_widget_spec(obj)" ] && echo 1 || echo 0)"

assert "with no Fix: marker at all, extract_fix_section_candidate yields nothing" \
  "$([ -z "$(call extract_fix_section_candidate 'no fix marker anywhere in this text')" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 5. path_exists_in_tree / content_present_in_tree, including the .beads/
#    exclusion regression guard.
# ---------------------------------------------------------------------------

S1="$SANDBOX_ROOT/1-path-exists"
new_sandbox "$S1"
mkdir -p "$S1/scripts"
printf '#!/usr/bin/env bash\necho hi\n' > "$S1/scripts/old-thing.sh"
commit_tree "$S1"
RC=0
BEAD_PREMISE_CHECK_REPO_ROOT="$S1" call path_exists_in_tree 'scripts/old-thing.sh' || RC=$?
assert "an existing tracked file is detected by path_exists_in_tree" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
BEAD_PREMISE_CHECK_REPO_ROOT="$S1" call path_exists_in_tree 'scripts/never-existed.sh' || RC=$?
assert "a file that was never created is reported absent by path_exists_in_tree" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

S2="$SANDBOX_ROOT/2-content"
new_sandbox "$S2"
mkdir -p "$S2/src" "$S2/.beads"
printf 'fn old_broken_helper() {}\n' > "$S2/src/lib.rs"
printf '{"description":"still calls old_broken_helper"}\n' > "$S2/.beads/issues.jsonl"
commit_tree "$S2"
RC=0
BEAD_PREMISE_CHECK_REPO_ROOT="$S2" call content_present_in_tree 'old_broken_helper' || RC=$?
assert "content_present_in_tree finds a pattern in tracked source content" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"
RC=0
BEAD_PREMISE_CHECK_REPO_ROOT="$S2" call content_present_in_tree 'fixed_helper_name' || RC=$?
assert "content_present_in_tree reports absent for a pattern nowhere in the tree" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"
RC=0
BEAD_PREMISE_CHECK_REPO_ROOT="$S2" call content_present_in_tree 'still calls old_broken_helper' || RC=$?
assert "a pattern that only appears in .beads/issues.jsonl (the bead's own stored text) does not count as present" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 6. End-to-end classification.
# ---------------------------------------------------------------------------

S3="$SANDBOX_ROOT/3-still-broken-symbol"
new_sandbox "$S3"
mkdir -p "$S3/src"
printf 'fn old_broken_helper() {}\n' > "$S3/src/lib.rs"
commit_tree "$S3"
JSON='[{"description":"the handler still calls `old_broken_helper` on every request","design":null,"acceptance_criteria":null}]'
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S3" call classify_from_json "$JSON") || RC=$?
assert "a bug-description symbol still present in the tree classifies as still-broken with exit 0" \
  "$([ "$OUT" = "still-broken" ] && [ "$RC" -eq 0 ] && echo 1 || echo 0)"

S4="$SANDBOX_ROOT/4-no-longer-broken-symbol"
new_sandbox "$S4"
mkdir -p "$S4/src"
printf 'fn fixed_helper() {}\n' > "$S4/src/lib.rs"
commit_tree "$S4"
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S4" call classify_from_json "$JSON") || RC=$?
assert "a bug-description symbol no longer in the tree classifies as no-longer-broken with exit 1" \
  "$([ "$OUT" = "no-longer-broken" ] && [ "$RC" -eq 1 ] && echo 1 || echo 0)"

JSON_NO_PATTERN='[{"description":"plain prose, no code spans describing this bug at all","design":null,"acceptance_criteria":null}]'
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S4" call classify_from_json "$JSON_NO_PATTERN") || RC=$?
assert "text with no parseable target pattern classifies as cannot-verify with exit 2" \
  "$([ "$OUT" = "cannot-verify" ] && [ "$RC" -eq 2 ] && echo 1 || echo 0)"

S5="$SANDBOX_ROOT/5-missing-path"
new_sandbox "$S5"
printf 'placeholder\n' > "$S5/README.md"
commit_tree "$S5"
JSON_MISSING_PATH='[{"description":"we still need `scripts/does-not-exist-yet.sh`","design":null,"acceptance_criteria":null}]'
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S5" call classify_from_json "$JSON_MISSING_PATH") || RC=$?
assert "a cited path that does not exist yet classifies as still-broken with exit 0" \
  "$([ "$OUT" = "still-broken" ] && [ "$RC" -eq 0 ] && echo 1 || echo 0)"

# Regression guard: a cited path that EXISTS must not stop the pipeline and
# confidently report still-broken on existence alone -- it must fall
# through to a symbol candidate. Without this fall-through, the real
# netpol-defaulting-bug premise (first backtick span is an existing file
# the fix only added a function to) misclassifies as still-broken forever.
S6="$SANDBOX_ROOT/6-path-exists-falls-through"
new_sandbox "$S6"
mkdir -p "$S6/crates/apiserver/src/handlers"
printf 'fn apply_defaults() {}\n' > "$S6/crates/apiserver/src/handlers/defaults.rs"
commit_tree "$S6"
JSON_PATH_EXISTS='[{"description":"`crates/apiserver/src/handlers/defaults.rs` has no `default_widget_spec_arm` at all","design":null,"acceptance_criteria":null}]'
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S6" call classify_from_json "$JSON_PATH_EXISTS") || RC=$?
assert "an EXISTING cited path does not short-circuit to still-broken -- it falls through to the (absent) symbol candidate, giving no-longer-broken" \
  "$([ "$OUT" = "no-longer-broken" ] && [ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 7. Synthetic beads mirroring the two real false-positive premises a
#    critical-review found on this branch, before this fix.
# ---------------------------------------------------------------------------

S7="$SANDBOX_ROOT/7-gtjmv-shape"
new_sandbox "$S7"
printf 'placeholder\n' > "$S7/README.md"
commit_tree "$S7"
JSON_GTJMV_SHAPE='[{"description":"every enable step uses `systemctl enable --now UNIT`; `enable --now` = `enable` + `start`; `start` is a no-op and the old binary keeps running until `journalctl` shows a restart.\n\nFix: replace `systemctl enable --now UNIT` with `systemctl enable UNIT` followed by `systemctl restart UNIT`.","design":null,"acceptance_criteria":null}]'
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S7" call classify_from_json "$JSON_GTJMV_SHAPE") || RC=$?
assert "install-restart-bug-shaped premise (only short/unstructured candidates, no qualifying symbol anywhere) classifies as cannot-verify, not a guessed still-broken" \
  "$([ "$OUT" = "cannot-verify" ] && [ "$RC" -eq 2 ] && echo 1 || echo 0)"

S8="$SANDBOX_ROOT/8-2dsqe-shape"
new_sandbox "$S8"
mkdir -p "$S8/crates/apiserver/src/handlers"
printf 'fn apply_defaults(obj: &mut Value) {\n    // Default WidgetSpec.enabled to false when absent, matching upstream.\n    default_widget_spec(obj);\n}\n\nfn default_widget_spec(obj: &mut Value) {}\n' \
  > "$S8/crates/apiserver/src/handlers/defaults.rs"
commit_tree "$S8"
JSON_2DSQE_SHAPE='[{"description":"`crates/apiserver/src/handlers/defaults.rs` has no arm for WidgetSpec: the `WidgetSpec.enabled` field is never defaulted (real Kubernetes defaults this; see how the fix below documents the same field name).\n\nFIX: add `default_widget_spec(obj)` to `crates/apiserver/src/handlers/defaults.rs` to default the field to false when absent.","design":null,"acceptance_criteria":null}]'
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S8" call classify_from_json "$JSON_2DSQE_SHAPE") || RC=$?
assert "netpol-defaulting-bug-shaped premise (fix's own doc comment echoes the bug-description symbol) classifies as no-longer-broken via the Fix-section override, not a false still-broken" \
  "$([ "$OUT" = "no-longer-broken" ] && [ "$RC" -eq 1 ] && echo 1 || echo 0)"

# Symmetric case: same shape, but the Fix-section symbol has NOT landed
# yet -- must report still-broken, proving the override is genuinely
# bidirectional and not just a hardcoded "always no-longer-broken" escape.
S9="$SANDBOX_ROOT/9-2dsqe-shape-not-fixed-yet"
new_sandbox "$S9"
mkdir -p "$S9/crates/apiserver/src/handlers"
printf 'fn apply_defaults() {}\n' > "$S9/crates/apiserver/src/handlers/defaults.rs"
commit_tree "$S9"
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S9" call classify_from_json "$JSON_2DSQE_SHAPE") || RC=$?
assert "the same Fix-section symbol, when NOT yet present in the tree, correctly reports still-broken (the override is bidirectional, not a one-way escape hatch)" \
  "$([ "$OUT" = "still-broken" ] && [ "$RC" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 8. Real-world citation shapes, exit-2 reasons, excluded dirs, time cap.
# ---------------------------------------------------------------------------

ERR="$SANDBOX_ROOT/stderr"

assert "bare (un-backticked) repo paths are extracted and the :line / ~:line suffix is stripped -- real beads cite 'file.rs ~:1523', so a literal match never finds the file" \
  "$([ "$(call extract_path_candidates 'see crates/apiserver/src/lib.rs ~:1523 and scripts/x.sh:10-20, also bootstrappolicy/policy.go and kubelet/node creds' | tr '\n' ' ')" = "crates/apiserver/src/lib.rs scripts/x.sh " ] && echo 1 || echo 0)"

assert "paths under ai/worktrees/, target/ and temp/ are never extracted as cited files" \
  "$([ -z "$(call extract_path_candidates 'see ai/worktrees/agent-1/crates/a.rs and temp/e2e/x.log')" ] && echo 1 || echo 0)"

S10="$SANDBOX_ROOT/10-landed-file"
new_sandbox "$S10"
mkdir -p "$S10/scripts"
printf '#!/bin/sh\n' > "$S10/scripts/new-tool.sh"
commit_tree "$S10"
JSON_MISSING_FILE='[{"description":"Answer: `scripts/new-tool.sh` is missing, so the loop cannot run.","design":null,"acceptance_criteria":null}]'
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S10" call classify_from_json "$JSON_MISSING_FILE" 2>/dev/null) || RC=$?
assert "a bead saying a file is missing, after that file landed, closes as no-longer-broken (exit 1) instead of being re-dispatched" \
  "$([ "$OUT" = "no-longer-broken" ] && [ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S5" call classify_from_json "$JSON_MISSING_FILE" 2>/dev/null) || RC=$?
assert "the same missing-file bead with the file still absent stays still-broken (exit 0) so it is dispatched" \
  "$([ "$OUT" = "still-broken" ] && [ "$RC" -eq 0 ] && echo 1 || echo 0)"

S11="$SANDBOX_ROOT/11-abstract"
new_sandbox "$S11"
mkdir -p "$S11/crates/apiserver/src/handlers"
printf 'fn create_resource() {}\n' > "$S11/crates/apiserver/src/handlers/resource.rs"
commit_tree "$S11"
JSON_ABSTRACT='[{"description":"Answer: add the missing regression tests. Deleting either restrict_node_create call in crates/apiserver/src/handlers/resource.rs (create_resource, ~:516) keeps every test green.","design":null,"acceptance_criteria":null}]'
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S11" call classify_from_json "$JSON_ABSTRACT" 2>"$ERR") || RC=$?
assert "a behavioural bead whose cited file exists exactly as described stays cannot-verify (exit 2), not a forced duplicate/dispatch verdict -- 'add the missing tests' near a path must not read as 'file missing'" \
  "$([ "$OUT" = "cannot-verify" ] && [ "$RC" -eq 2 ] && echo 1 || echo 0)"
assert "exit 2 explains itself on stderr, naming the cited path and why grep cannot decide, so the mayor knows it is behavioural and not a script failure" \
  "$(grep -qF 'handlers/resource.rs(exists)' "$ERR" && grep -qF 'behavioural' "$ERR" && echo 1 || echo 0)"

RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S11" call classify_from_json "$JSON_NO_PATTERN" 2>"$ERR") || RC=$?
assert "exit 2 for a bead with nothing extractable says so on stderr" \
  "$([ "$RC" -eq 2 ] && grep -qF 'nothing extractable' "$ERR" && echo 1 || echo 0)"

S12="$SANDBOX_ROOT/12-excluded-dirs"
new_sandbox "$S12"
mkdir -p "$S12/crates" "$S12/ai/worktrees/agent-1/crates" "$S12/target" "$S12/temp"
printf 'fn fixed_helper() {}\n' > "$S12/crates/lib.rs"
for d in ai/worktrees/agent-1/crates target temp; do
  printf 'fn old_broken_helper() {}\n' > "$S12/$d/copy.rs"
done
git -C "$S12" add -A -f
git -C "$S12" commit -q -m snapshot
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S12" call classify_from_json "$JSON" 2>/dev/null) || RC=$?
assert "a symbol present only in ai/worktrees/, target/ or temp/ copies does not count -- otherwise every fixed bead looks still-broken because worker worktrees hold stale copies of the repo" \
  "$([ "$OUT" = "no-longer-broken" ] && [ "$RC" -eq 1 ] && echo 1 || echo 0)"

MANY=$(for n in $(seq 1 3000); do printf '`other_symbol_%s` ' "$n"; done)
JSON_MANY=$(jq -cn --arg d "calls \`old_broken_helper\` then $MANY" '[{description:$d,design:null,acceptance_criteria:null}]')
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S3" call classify_from_json "$JSON_MANY" 2>/dev/null) || RC=$?
assert "a bead citing many symbols still classifies (no SIGPIPE 141 from taking only the first candidate) -- beads with several symbols were silently returning cannot-verify" \
  "$([ "$OUT" = "still-broken" ] && [ "$RC" -eq 0 ] && echo 1 || echo 0)"

JSON_PRESENT_PATH_BEHAVIOUR='[{"description":"Answer: crates/apiserver/src/lib.rs is missing the RBAC check on delete.","design":null,"acceptance_criteria":null}]'
S13="$SANDBOX_ROOT/13-present-path-behaviour"
new_sandbox "$S13"
mkdir -p "$S13/crates/apiserver/src"
printf 'fn delete() {}\n' > "$S13/crates/apiserver/src/lib.rs"
commit_tree "$S13"
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S13" call classify_from_json "$JSON_PRESENT_PATH_BEHAVIOUR" 2>"$ERR") || RC=$?
assert "'<existing path> is missing <behaviour>' must be exit 2 with a reason, never exit 1 -- exit 1 closes a real bug as already landed without anyone working it" \
  "$([ "$OUT" = "cannot-verify" ] && [ "$RC" -eq 2 ] && [ -s "$ERR" ] && echo 1 || echo 0)"

JSON_CREATE_BEHAVIOUR='[{"description":"Answer: create a regression test in crates/apiserver/src/lib.rs and add a new file-level check there.","design":null,"acceptance_criteria":null}]'
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S13" call classify_from_json "$JSON_CREATE_BEHAVIOUR" 2>"$ERR") || RC=$?
assert "'create <thing> in <existing path>' does not claim the file is absent, so it must not exit 1 -- only 'create <path>' / '<path> is missing.' about the file itself may" \
  "$([ "$RC" -eq 2 ] && echo 1 || echo 0)"

JSON_CREATE_FILE='[{"description":"Answer: create scripts/new-tool.sh so the loop can run.","design":null,"acceptance_criteria":null}]'
RC=0
OUT=$(BEAD_PREMISE_CHECK_REPO_ROOT="$S10" call classify_from_json "$JSON_CREATE_FILE" 2>/dev/null) || RC=$?
assert "'create <path>' with the file now present still closes as landed (exit 1) -- the intended path rule survives the anchoring" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"


STUB="$SANDBOX_ROOT/stub"
mkdir -p "$STUB"
printf '#!/bin/sh\nsleep 30 &\necho $! > "%s/childpid"\nwait\n' "$STUB" > "$STUB/bd"
chmod +x "$STUB/bd"
START=$(date +%s)
RC=0
OUT=$(PATH="$STUB:$PATH" BEAD_PREMISE_CHECK_TIMEOUT=1 bash "$SCRIPT" hung-bead 2>"$ERR") || RC=$?
ELAPSED=$(( $(date +%s) - START ))
assert "a hung bd call is cut off by the per-bead cap: exit 2, reason 'timeout' on stderr, well under the stub's 30s sleep -- a loop over all beads must never stall" \
  "$([ "$OUT" = "cannot-verify" ] && [ "$RC" -eq 2 ] && [ "$ELAPSED" -lt 10 ] && grep -qF 'timeout' "$ERR" && echo 1 || echo 0)"
CHILD=$(cat "$STUB/childpid" 2>/dev/null || echo 0)
assert "the timed-out bd's own sleep child is killed too, not orphaned -- leaked sleeps accumulate across a loop over every open bead" \
  "$([ "$CHILD" -gt 0 ] && ! kill -0 "$CHILD" 2>/dev/null && echo 1 || echo 0)"
assert "timeout stderr is exactly the one reason line, with no bash 'Terminated' job notice -- callers parse stderr as the reason" \
  "$([ "$(wc -l < "$ERR" | tr -d ' ')" -eq 1 ] && ! grep -qF 'Terminated' "$ERR" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

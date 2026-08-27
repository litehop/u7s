#!/usr/bin/env bash
# Test harness for scripts/critical-reviewer-dispatch.sh.
# Runs the hook against synthetic SubagentStop inputs and asserts:
#   - a queue file lands (or does not) as expected.
#   - the queue file's frontmatter carries the expected deliverable_type + ref.
#
# Invoke: bash scripts/test-critical-reviewer-hook.sh
# Exits 0 on all-pass, non-zero on any failure.

set -euo pipefail

PROJECT_DIR="$(git rev-parse --show-toplevel)"
HOOK="$PROJECT_DIR/scripts/critical-reviewer-dispatch.sh"
QUEUE_DIR="$PROJECT_DIR/.claude/review-queue"
LOG_DIR="$QUEUE_DIR/log"

FAILURES=0

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  FAILURES=$((FAILURES + 1))
}

pass() {
  printf 'ok: %s\n' "$1"
}

# Sandbox: run the hook against a scratch project dir so we do not pollute the
# real .claude/review-queue/ with test artefacts.
SANDBOX=$(mktemp -d)
trap 'rm -rf "$SANDBOX"' EXIT

mkdir -p "$SANDBOX/.claude"

run_hook() {
  local input="$1"
  CLAUDE_PROJECT_DIR="$SANDBOX" bash "$HOOK" <<< "$input"
}

count_queue_files() {
  find "$SANDBOX/.claude/review-queue" -maxdepth 1 -name '*.md' 2>/dev/null | wc -l | tr -d ' '
}

clear_sandbox() {
  # Preserve log/ across cases so the "logged for every fire" assertion is
  # meaningful; only clear the top-level *.md queue files.
  find "$SANDBOX/.claude/review-queue" -maxdepth 1 -name '*.md' -delete 2>/dev/null || true
}

# Case 1: PR opened → queued as "pr" with the URL as ref.
clear_sandbox
INPUT_PR=$(jq -n \
  --arg msg 'Done. Opened PR https://github.com/litehop/u7s/pull/9999 for review.' \
  '{agent_id:"agent-test1", agent_type:"worker", cwd:"/tmp/wt", session_id:"sess1", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
run_hook "$INPUT_PR"
if [ "$(count_queue_files)" = "1" ]; then
  QFILE=$(find "$SANDBOX/.claude/review-queue" -maxdepth 1 -name '*.md' | head -1)
  TYPE=$(grep -m1 '^deliverable_type:' "$QFILE" | awk '{print $2}')
  REF=$(grep -m1 '^deliverable_ref:' "$QFILE" | cut -d' ' -f2-)
  if [ "$TYPE" = "pr" ] && [ "$REF" = "https://github.com/litehop/u7s/pull/9999" ]; then
    pass "PR URL → queued with correct type + ref"
  else
    fail "PR URL detection: type=$TYPE ref=$REF (expected pr / …/pull/9999)"
  fi
else
  fail "PR URL: expected 1 queue file, got $(count_queue_files)"
fi

# Case 2: findings doc → queued as "findings" only when the file actually
# exists on disk (guards against false positives from arbitrary path strings).
clear_sandbox
FAKE_WT="$SANDBOX/wt/agent-test2"
mkdir -p "$FAKE_WT/ai/findings"
FAKE_DOC="$FAKE_WT/ai/findings/scratch-audit-2026-08-18.md"
printf 'test doc\n' > "$FAKE_DOC"
INPUT_FIND=$(jq -n \
  --arg msg "Audit complete. Wrote findings to $FAKE_DOC — 5 findings, 2 HIGH." \
  '{agent_id:"agent-test2", agent_type:"worker", cwd:"/tmp/wt", session_id:"sess2", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
run_hook "$INPUT_FIND"
if [ "$(count_queue_files)" = "1" ]; then
  QFILE=$(find "$SANDBOX/.claude/review-queue" -maxdepth 1 -name '*.md' | head -1)
  TYPE=$(grep -m1 '^deliverable_type:' "$QFILE" | awk '{print $2}')
  REF=$(grep -m1 '^deliverable_ref:' "$QFILE" | cut -d' ' -f2-)
  if [ "$TYPE" = "findings" ] && [ "$REF" = "$FAKE_DOC" ]; then
    pass "findings path → queued with correct type + ref"
  else
    fail "findings detection: type=$TYPE ref=$REF (expected findings / $FAKE_DOC)"
  fi
else
  fail "findings: expected 1 queue file, got $(count_queue_files)"
fi

# Case 3: bd close → queued as "bead-close" with the bead ID.
clear_sandbox
INPUT_CLOSE=$(jq -n \
  --arg msg 'Fix applied and tested. Ran: bd close mayor-abc12 -r "opened PR #42"' \
  '{agent_id:"agent-test3", agent_type:"worker", cwd:"/tmp/wt", session_id:"sess3", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
run_hook "$INPUT_CLOSE"
if [ "$(count_queue_files)" = "1" ]; then
  QFILE=$(find "$SANDBOX/.claude/review-queue" -maxdepth 1 -name '*.md' | head -1)
  TYPE=$(grep -m1 '^deliverable_type:' "$QFILE" | awk '{print $2}')
  REF=$(grep -m1 '^deliverable_ref:' "$QFILE" | awk '{print $2}')
  if [ "$TYPE" = "bead-close" ] && [ "$REF" = "mayor-abc12" ]; then
    pass "bd close → queued with correct type + bead ID"
  else
    fail "bd close detection: type=$TYPE ref=$REF (expected bead-close / mayor-abc12)"
  fi
else
  fail "bd close: expected 1 queue file, got $(count_queue_files)"
fi

# Case 4: no deliverable → NO queue file (but hook still exits 0 and logs a
# skip decision — the "definitely fired but nothing to do" audit trail).
clear_sandbox
INPUT_NOOP=$(jq -n \
  --arg msg 'Nothing to do — the file was already correct. No changes made.' \
  '{agent_id:"agent-test4", agent_type:"worker", cwd:"/tmp/wt", session_id:"sess4", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
run_hook "$INPUT_NOOP"
if [ "$(count_queue_files)" = "0" ]; then
  # $'...' ANSI-C quoting expands \t to a real tab byte before grep ever sees
  # the pattern -- a quoted 'skip\tno-deliverable' works on this host's ugrep
  # (which treats \t as tab even unquoted) but real GNU grep in default BRE
  # mode treats \t as literal "t", silently matching nothing on Linux CI.
  if [ -f "$SANDBOX/.claude/review-queue/log/decisions.tsv" ] && grep -q $'skip\tno-deliverable' "$SANDBOX/.claude/review-queue/log/decisions.tsv"; then
    pass "no deliverable → skipped, decision logged"
  else
    fail "no deliverable: hook did not log a skip decision"
  fi
else
  fail "no deliverable: expected 0 queue files, got $(count_queue_files)"
fi

# Case 5: empty message → skip, no crash.
clear_sandbox
INPUT_EMPTY=$(jq -n \
  '{agent_id:"agent-test5", agent_type:"worker", cwd:"/tmp/wt", session_id:"sess5", hook_event_name:"SubagentStop", last_assistant_message:""}')
run_hook "$INPUT_EMPTY"
if [ "$(count_queue_files)" = "0" ]; then
  pass "empty message → skipped without crash"
else
  fail "empty message: expected 0 queue files, got $(count_queue_files)"
fi

# Case 6: PR URL from the WRONG github org (proves we don't queue on
# arbitrary GH pull URLs).
clear_sandbox
INPUT_WRONG=$(jq -n \
  --arg msg 'Also referenced https://github.com/rootless-containers/usernetes/pull/1 in the diff.' \
  '{agent_id:"agent-test6", agent_type:"worker", cwd:"/tmp/wt", session_id:"sess6", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
run_hook "$INPUT_WRONG"
if [ "$(count_queue_files)" = "0" ]; then
  pass "PR URL from unrelated org → not queued"
else
  fail "wrong-org PR URL: expected 0 queue files, got $(count_queue_files)"
fi

# Case 7: critical-reviewer's own completion echoes the PR it just reviewed
# → NOT re-queued (would otherwise re-queue a review of the review just
# completed, unboundedly, if a future drain invoked critical-reviewer again).
clear_sandbox
INPUT_SELF_ECHO=$(jq -n \
  --arg msg 'I posted the critical-reviewer findings comment on PR #9999: https://github.com/litehop/u7s/pull/9999' \
  '{agent_id:"agent-test7", agent_type:"critical-reviewer", cwd:"/tmp/wt", session_id:"sess7", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
run_hook "$INPUT_SELF_ECHO"
if [ "$(count_queue_files)" = "0" ]; then
  # See the Case 4 comment above: $'...' is required so grep gets a literal
  # tab byte instead of relying on \t-as-tab, which real GNU grep does not do.
  if [ -f "$SANDBOX/.claude/review-queue/log/decisions.tsv" ] && grep -q $'skip\tself-review-echo' "$SANDBOX/.claude/review-queue/log/decisions.tsv"; then
    pass "critical-reviewer echoing its own reviewed PR → skipped, decision logged"
  else
    fail "critical-reviewer self-echo: hook did not log a self-review-echo skip decision"
  fi
else
  fail "critical-reviewer self-echo: expected 0 queue files, got $(count_queue_files)"
fi

# Bonus: only "queued" decisions get a raw-input log file (retention policy,
# 2026-08-21) -- of the 7 cases above, only 1/2/3 (pr, findings, bead-close)
# are queued; 4/5/6/7 are skips and must NOT produce a jsonl dump.
if [ -d "$SANDBOX/.claude/review-queue/log" ]; then
  LOG_COUNT=$(find "$SANDBOX/.claude/review-queue/log" -name '*.jsonl' | wc -l | tr -d ' ')
  if [ "$LOG_COUNT" = "3" ]; then
    pass "raw input logged only for queued decisions (3/3)"
  else
    fail "raw input log count: expected 3, got $LOG_COUNT"
  fi
else
  fail "raw input log dir missing"
fi

# Case 8: decisions.tsv rotation (mayor-p4ol7). Without rotation, a
# long-running mayor session grows this file unbounded (8856 lines and
# counting at bead file time) -- once it crosses ~1 MiB the hook must
# rotate it out of the way before appending, not just keep growing it.
DECISIONS_LOG="$SANDBOX/.claude/review-queue/log/decisions.tsv"
dd if=/dev/zero of="$DECISIONS_LOG" bs=1024 count=1100 2>/dev/null
printf 'OLD_GEN0_MARKER\n' >> "$DECISIONS_LOG"
clear_sandbox
INPUT_ROTATE=$(jq -n \
  --arg msg 'Nothing to do this round.' \
  '{agent_id:"agent-rotate1", agent_type:"worker", cwd:"/tmp/wt", session_id:"sessR1", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
run_hook "$INPUT_ROTATE"
if [ -f "$DECISIONS_LOG.1" ] && grep -q 'OLD_GEN0_MARKER' "$DECISIONS_LOG.1"; then
  pass "decisions.tsv >= 1 MiB rotates to .1, preserving the prior entries"
else
  fail "rotation at threshold: .1 missing or does not carry the pre-rotation content"
fi
if [ -f "$DECISIONS_LOG" ] && ! grep -q 'OLD_GEN0_MARKER' "$DECISIONS_LOG" && grep -q 'agent-rotate1' "$DECISIONS_LOG"; then
  pass "post-rotation decisions.tsv starts fresh with only the new decision"
else
  fail "post-rotation decisions.tsv unexpectedly still carries old content or is missing the new entry"
fi

# Case 9: a second rotation with a pre-existing .1 pushes it to .2 and
# discards whatever .2 already held -- the "oldest generation is dropped,
# not accumulated forever" half of the bound.
printf 'OLD_GEN2_MARKER_TO_BE_DISCARDED\n' > "$DECISIONS_LOG.2"
printf 'OLD_GEN1_MARKER\n' > "$DECISIONS_LOG.1"
dd if=/dev/zero of="$DECISIONS_LOG" bs=1024 count=1100 2>/dev/null
printf 'OLD_GEN0_MARKER_2\n' >> "$DECISIONS_LOG"
clear_sandbox
INPUT_ROTATE2=$(jq -n \
  --arg msg 'Nothing to do this round either.' \
  '{agent_id:"agent-rotate2", agent_type:"worker", cwd:"/tmp/wt", session_id:"sessR2", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
run_hook "$INPUT_ROTATE2"
if grep -q 'OLD_GEN1_MARKER' "$DECISIONS_LOG.2" 2>/dev/null && ! grep -q 'OLD_GEN2_MARKER_TO_BE_DISCARDED' "$DECISIONS_LOG.2" 2>/dev/null; then
  pass "second rotation shifts .1 into .2 and drops the previous .2 (bounded, not accumulating forever)"
else
  fail "second rotation: .2 does not reflect the shifted .1 content, or the old .2 was not discarded"
fi
if grep -q 'OLD_GEN0_MARKER_2' "$DECISIONS_LOG.1" 2>/dev/null; then
  pass "second rotation shifts the just-full decisions.tsv into .1"
else
  fail "second rotation: .1 does not carry the just-rotated decisions.tsv content"
fi

# Case 10: below the threshold, no rotation -- entries keep accumulating in
# the same file (the common case; rotation must not fire on every write).
rm -f "$DECISIONS_LOG.1" "$DECISIONS_LOG.2"
printf 'SMALL_FILE_MARKER\n' > "$DECISIONS_LOG"
clear_sandbox
INPUT_NOROTATE=$(jq -n \
  --arg msg 'Nothing to do this round, small log.' \
  '{agent_id:"agent-norotate", agent_type:"worker", cwd:"/tmp/wt", session_id:"sessNR", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
run_hook "$INPUT_NOROTATE"
if [ ! -f "$DECISIONS_LOG.1" ] && grep -q 'SMALL_FILE_MARKER' "$DECISIONS_LOG" && grep -q 'agent-norotate' "$DECISIONS_LOG"; then
  pass "decisions.tsv under threshold appends in place without rotating"
else
  fail "sub-threshold write unexpectedly rotated, or failed to append the new decision"
fi

if [ "$FAILURES" -eq 0 ]; then
  printf '\nall tests passed\n'
  exit 0
else
  printf '\n%d test(s) failed\n' "$FAILURES" >&2
  exit 1
fi

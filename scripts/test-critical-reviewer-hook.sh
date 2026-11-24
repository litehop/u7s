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
STUBDIR=$(mktemp -d)
trap 'rm -rf "$SANDBOX" "$STUBDIR"' EXIT

mkdir -p "$SANDBOX/.claude"

# Stub `gh` on PATH so the branch-lookup fallback never makes a live GitHub
# API call from this test suite -- that would make the suite network- and
# auth-dependent, and flaky in CI. Emulates exactly the one invocation the
# hook makes (`gh pr list --head <branch> --json url --limit 1 --jq
# '.[0].url // ""'`). Set TEST_GH_PR_LIST_URL to simulate a found PR, leave
# both unset to simulate "no PR for this branch yet" (exit 0, empty output
# -- the common case), or set TEST_GH_PR_LIST_FAIL to simulate an
# auth/network failure (non-zero exit) distinct from "genuinely no PR".
cat > "$STUBDIR/gh" <<'STUBEOF'
#!/usr/bin/env bash
if [ -n "${TEST_GH_PR_LIST_FAIL:-}" ]; then
  printf 'gh: authentication failed\n' >&2
  exit 1
fi
printf '%s' "${TEST_GH_PR_LIST_URL:-}"
STUBEOF
chmod +x "$STUBDIR/gh"

run_hook() {
  local input="$1"
  CLAUDE_PROJECT_DIR="$SANDBOX" PATH="$STUBDIR:$PATH" bash "$HOOK" <<< "$input"
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
  # A fresh worker whose message contains the URL directly must still go
  # through the primary path, not the branch-lookup fallback -- distinct
  # decision labels are how an audit tells the two apart (no regression to
  # the primary path once a branch-lookup fallback exists).
  if grep -q $'agent-test1\tqueued-via-url' "$SANDBOX/.claude/review-queue/log/decisions.tsv"; then
    pass "PR URL match is logged as queued-via-url, not the branch-lookup label"
  else
    fail "PR URL match: decisions.tsv missing the queued-via-url label for agent-test1"
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

# Case 7b: a read-only agent whose answer cites an existing ai/findings doc
# must NOT be queued -- a misattributed entry never auto-drains and costs the
# mayor a manual investigation. A worker citing the same doc still queues.
for RO_TYPE in Explore researcher bead-triager diff-summarizer dashboard-differ claude-code-guide statusline-setup; do
  clear_sandbox
  RO_WT="$SANDBOX/wt/ro-$RO_TYPE"
  mkdir -p "$RO_WT/ai/findings"
  RO_DOC="$RO_WT/ai/findings/already-committed.md"
  printf 'doc\n' > "$RO_DOC"
  INPUT_RO=$(jq -n --arg msg "The audit is in $RO_DOC — see section 2." --arg t "$RO_TYPE" \
    '{agent_id:"agent-ro", agent_type:$t, cwd:"/tmp/wt", session_id:"sessro", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
  run_hook "$INPUT_RO"
  if [ "$(count_queue_files)" = "0" ] && grep -q $'agent-ro\tskip\tread-only-agent' "$SANDBOX/.claude/review-queue/log/decisions.tsv"; then
    pass "$RO_TYPE citing an existing findings doc → not queued (would never auto-drain)"
  else
    fail "$RO_TYPE citing a findings doc: expected 0 queue files + read-only-agent skip, got $(count_queue_files)"
  fi
done
clear_sandbox
INPUT_WORKER_CITE=$(jq -n --arg msg "Wrote findings to $RO_DOC" \
  '{agent_id:"agent-wcite", agent_type:"worker", cwd:"/tmp/wt", session_id:"sesswc", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
run_hook "$INPUT_WORKER_CITE"
if [ "$(count_queue_files)" = "1" ]; then
  pass "worker citing a findings doc still queues (read-only skip must not swallow workers)"
else
  fail "worker findings: expected 1 queue file, got $(count_queue_files)"
fi

# Case 8: agent_type is a literal empty string (not missing) -- the
# upstream #27755 spurious SubagentStop harness event. Must exit before
# touching the log at all: a log write here would misrepresent "the hook
# genuinely fired and had nothing to do" as this noise event's fault.
clear_sandbox
DECISIONS_LOG_PRE="$SANDBOX/.claude/review-queue/log/decisions.tsv"
LINES_BEFORE=0
[ -f "$DECISIONS_LOG_PRE" ] && LINES_BEFORE=$(wc -l < "$DECISIONS_LOG_PRE" | tr -d ' ')
INPUT_EMPTY_TYPE=$(jq -n \
  --arg msg 'Opened PR https://github.com/litehop/u7s/pull/1 for review.' \
  '{agent_id:"agent-test8", agent_type:"", cwd:"/tmp/wt", session_id:"sess8", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
run_hook "$INPUT_EMPTY_TYPE"
LINES_AFTER=0
[ -f "$DECISIONS_LOG_PRE" ] && LINES_AFTER=$(wc -l < "$DECISIONS_LOG_PRE" | tr -d ' ')
if [ "$(count_queue_files)" = "0" ] && [ "$LINES_AFTER" = "$LINES_BEFORE" ]; then
  pass "empty agent_type → exits 0, no queue file, no log write (even with a real PR URL present)"
else
  fail "empty agent_type: expected 0 queue files and no new log line, got $(count_queue_files) queue file(s), decisions.tsv $LINES_BEFORE -> $LINES_AFTER lines"
fi

# Case 9: decisions.tsv rotation. Without rotation, a long-running mayor
# session grows this file unbounded (8856 lines and counting when this was
# written) -- once it crosses ~1 MiB the hook must rotate it out of the
# way before appending, not just keep growing it.
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

# Case 10: a second rotation with a pre-existing .1 pushes it to .2 and
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

# Case 11: below the threshold, no rotation -- entries keep accumulating in
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

# Case 12: resumed worker fallback. A worker resumed via SendMessage after a
# needs-changes fix reports a bare commit sha, not the full PR URL the
# primary regex needs -- without the branch-lookup fallback this would skip
# with no-deliverable and the mayor would never notice the follow-up fix was
# ready for re-review. The stub `gh` above stands in for the real GitHub
# API so this stays network-free.
clear_sandbox
INPUT_RESUMED=$(jq -n \
  --arg msg 'Pushed a new commit abc1234 on PR #4242 addressing the review feedback.' \
  '{agent_id:"agent-resumed1", agent_type:"worker", cwd:"/tmp/wt", session_id:"sessResumed", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
TEST_GH_PR_LIST_URL="https://github.com/litehop/u7s/pull/4242" run_hook "$INPUT_RESUMED"
if [ "$(count_queue_files)" = "1" ]; then
  QFILE=$(find "$SANDBOX/.claude/review-queue" -maxdepth 1 -name '*.md' | head -1)
  TYPE=$(grep -m1 '^deliverable_type:' "$QFILE" | awk '{print $2}')
  REF=$(grep -m1 '^deliverable_ref:' "$QFILE" | cut -d' ' -f2-)
  if [ "$TYPE" = "pr" ] && [ "$REF" = "https://github.com/litehop/u7s/pull/4242" ]; then
    pass "resumed worker with no URL in message → queued via branch lookup with correct PR ref"
  else
    fail "branch-lookup fallback: type=$TYPE ref=$REF (expected pr / …/pull/4242)"
  fi
  # The distinct label is the whole point of the fallback -- without it, an
  # audit can't tell "the worker's message itself proved the deliverable"
  # from "we had to ask GitHub directly".
  if grep -q $'agent-resumed1\tqueued-via-branch-lookup' "$SANDBOX/.claude/review-queue/log/decisions.tsv"; then
    pass "branch-lookup fallback is logged with the distinct queued-via-branch-lookup label"
  else
    fail "branch-lookup fallback: decisions.tsv missing the queued-via-branch-lookup label"
  fi
else
  fail "branch-lookup fallback: expected 1 queue file, got $(count_queue_files)"
fi

# Case 13: resumed worker whose branch genuinely has no open PR yet (stub
# returns empty, the default) -- must still fall through to the ordinary
# no-deliverable skip, not error out or fabricate a deliverable.
clear_sandbox
INPUT_NO_PR_YET=$(jq -n \
  --arg msg 'Pushed a new commit abc5678, still working on it.' \
  '{agent_id:"agent-resumed2", agent_type:"worker", cwd:"/tmp/wt", session_id:"sessResumed2", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
run_hook "$INPUT_NO_PR_YET"
if [ "$(count_queue_files)" = "0" ] && grep -q $'agent-resumed2\tskip\tno-deliverable' "$SANDBOX/.claude/review-queue/log/decisions.tsv"; then
  pass "branch-lookup fallback finding no PR falls through to the ordinary no-deliverable skip"
else
  fail "branch-lookup fallback with no PR found: expected a no-deliverable skip, got $(count_queue_files) queue file(s)"
fi

# Case 14: gh auth/network failure during the branch-lookup fallback must be
# distinguishable from "genuinely no PR yet" -- an operator staring at
# decisions.tsv otherwise cannot tell an outage from normal steady-state,
# which is the exact silent-failure mode this fallback exists to avoid. The
# hook must also still exit 0 (never crash) even though `gh` itself failed.
clear_sandbox
INPUT_GH_FAIL=$(jq -n \
  --arg msg 'Pushed a new commit def9999, addressing feedback.' \
  '{agent_id:"agent-ghfail", agent_type:"worker", cwd:"/tmp/wt", session_id:"sessGhFail", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
GH_FAIL_RC=0
TEST_GH_PR_LIST_FAIL=1 run_hook "$INPUT_GH_FAIL" || GH_FAIL_RC=$?
if [ "$GH_FAIL_RC" -eq 0 ] && [ "$(count_queue_files)" = "0" ] && grep -q $'agent-ghfail\tskip\tbranch-lookup-failed' "$SANDBOX/.claude/review-queue/log/decisions.tsv"; then
  pass "gh failure during branch-lookup is logged as branch-lookup-failed (distinct from no-deliverable) and the hook still exits 0"
else
  fail "gh failure during branch-lookup: expected exit 0 + a branch-lookup-failed skip line, got hook_rc=$GH_FAIL_RC, $(count_queue_files) queue file(s)"
fi

# Case 15: concurrency stress. Multiple subagents can hit SubagentStop
# within the same second (real: .claude/review-queue/log/*.jsonl shows
# overlapping subagents in one session). Without a lock serializing
# read-size -> rotate -> append, concurrent hook processes race the file
# renames and can silently discard an entry the retention policy promises
# survives two rotations -- reproduced with 5 concurrent hook invocations
# against a >1 MiB file. A race
# is timing-dependent: one round of 5 concurrent invocations does not
# reliably reproduce it on every machine/run, so this repeats 3 independent
# rounds and fails if ANY round loses or duplicates an entry -- with the
# lock in place this is fully deterministic (every round is serialized), so
# there is no added flakiness on the passing side.
DECISIONS_LOG_RACE="$SANDBOX/.claude/review-queue/log/decisions.tsv"
RACE_ROUNDS=3
RACE_CRASH_TOTAL=0
RACE_LOSS_TOTAL=0
RACE_MISSING_TOTAL=0
for round in 1 2 3; do
  rm -f "$DECISIONS_LOG_RACE" "$DECISIONS_LOG_RACE.1" "$DECISIONS_LOG_RACE.2" "$DECISIONS_LOG_RACE.lock"
  dd if=/dev/zero of="$DECISIONS_LOG_RACE" bs=1024 count=1100 2>/dev/null
  printf 'RACE_SURVIVOR_MARKER_%s\n' "$round" >> "$DECISIONS_LOG_RACE"
  clear_sandbox

  RACE_PIDS=()
  RACE_RC_FILES=()
  for i in 1 2 3 4 5; do
    RC_FILE="$SANDBOX/race-rc-$round-$i"
    RACE_RC_FILES+=("$RC_FILE")
    (
      INPUT_RACE=$(jq -n \
        --arg msg "Race round $round invocation $i, nothing to do." \
        --arg agent_id "agent-race${round}-${i}" \
        --arg session_id "sessRace${round}${i}" \
        '{agent_id:$agent_id, agent_type:"worker", cwd:"/tmp/wt", session_id:$session_id, hook_event_name:"SubagentStop", last_assistant_message:$msg}')
      # `|| RC=$?`, not a bare call: an unlocked rotation can make the hook
      # itself exit non-zero mid-race (an `mv` racing another process's
      # rename). Under this subshell's inherited `set -e`, an unguarded
      # failure here would skip the RC_FILE write entirely, and the
      # unguarded `wait` below would then abort the whole test script
      # before any assertion ran -- silently defeating the very check this
      # case exists to make (a crash IS a finding, not a reason to bail).
      RC=0
      run_hook "$INPUT_RACE" >/dev/null 2>&1 || RC=$?
      echo "$RC" > "$RC_FILE"
    ) &
    RACE_PIDS+=($!)
  done
  for pid in "${RACE_PIDS[@]}"; do
    wait "$pid" || true
  done

  for rc_file in "${RACE_RC_FILES[@]}"; do
    [ -f "$rc_file" ] && [ "$(cat "$rc_file")" = "0" ] || RACE_CRASH_TOTAL=$((RACE_CRASH_TOTAL + 1))
  done

  SURVIVOR_COUNT=0
  for f in "$DECISIONS_LOG_RACE" "$DECISIONS_LOG_RACE.1" "$DECISIONS_LOG_RACE.2"; do
    [ -f "$f" ] && grep -q "RACE_SURVIVOR_MARKER_$round" "$f" && SURVIVOR_COUNT=$((SURVIVOR_COUNT + 1))
  done
  [ "$SURVIVOR_COUNT" -eq 1 ] || RACE_LOSS_TOTAL=$((RACE_LOSS_TOTAL + 1))

  for i in 1 2 3 4 5; do
    FOUND=0
    for f in "$DECISIONS_LOG_RACE" "$DECISIONS_LOG_RACE.1" "$DECISIONS_LOG_RACE.2"; do
      if [ -f "$f" ] && grep -q "agent-race${round}-${i}" "$f"; then
        FOUND=1
        break
      fi
    done
    [ "$FOUND" -eq 1 ] || RACE_MISSING_TOTAL=$((RACE_MISSING_TOTAL + 1))
  done
done

if [ "$RACE_CRASH_TOTAL" -eq 0 ]; then
  pass "$((RACE_ROUNDS * 5)) concurrent hook invocations across $RACE_ROUNDS rounds all exit 0 (no crash from an unlocked mv race)"
else
  fail "$RACE_CRASH_TOTAL concurrent hook invocation(s) crashed (non-zero exit) during rotation across $RACE_ROUNDS rounds"
fi

if [ "$RACE_LOSS_TOTAL" -eq 0 ]; then
  pass "concurrent rotation preserves the pre-race entry exactly once in every one of $RACE_ROUNDS rounds (no data loss, no duplication)"
else
  fail "concurrent rotation lost or duplicated the pre-race entry in $RACE_LOSS_TOTAL of $RACE_ROUNDS rounds"
fi

if [ "$RACE_MISSING_TOTAL" -eq 0 ]; then
  pass "all concurrent decisions across $RACE_ROUNDS rounds are recorded somewhere in the rotated log tree (no silently dropped append)"
else
  fail "$RACE_MISSING_TOTAL of $((RACE_ROUNDS * 5)) concurrent decisions were silently dropped across $RACE_ROUNDS rounds"
fi

# Case 16: stale-lock liveness check regression case. The steal mechanism
# above must only evict a holder whose recorded PID is actually dead --
# stealing from a live holder would reintroduce the exact unlocked-mv race
# case 15 above proves is fixed.
DECISIONS_LOG_LIVENESS="$SANDBOX/.claude/review-queue/log/decisions.tsv"
LOCK_LIVENESS="$DECISIONS_LOG_LIVENESS.lock"

# 16a. A DEAD holder PID: the lock must be broken, and the hook must
# complete normally (not hang) -- a crashed hook must not wedge every later
# fire and silently stop all review queueing.
clear_sandbox
rm -f "$DECISIONS_LOG_LIVENESS" "$DECISIONS_LOG_LIVENESS.1" "$DECISIONS_LOG_LIVENESS.2"
rm -rf "$LOCK_LIVENESS"
( : ) & DEAD_PID=$!
wait "$DEAD_PID" 2>/dev/null || true  # guarantees DEAD_PID has already exited
ln -s "$DEAD_PID" "$LOCK_LIVENESS"

INPUT_DEAD=$(jq -n --arg msg 'Nothing to review here.' \
  '{agent_id:"agent-deadlock", agent_type:"worker", cwd:"/tmp/wt", session_id:"sessDead", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
# No `timeout` binary here (not on stock macOS, same constraint the lock
# itself works around) -- backgrounded + polled with a bounded wait instead,
# so a broken fix (infinite retry) fails this test rather than hanging the
# suite.
DEAD_RC_FILE="$SANDBOX/dead-lock-rc"
(
  RC=0
  CLAUDE_PROJECT_DIR="$SANDBOX" PATH="$STUBDIR:$PATH" \
    bash "$HOOK" <<< "$INPUT_DEAD" >/dev/null 2>&1 || RC=$?
  echo "$RC" > "$DEAD_RC_FILE"
) &
DEAD_HOOK_PID=$!
DEAD_WAITED=0
while [ ! -f "$DEAD_RC_FILE" ] && [ "$DEAD_WAITED" -lt 50 ]; do
  sleep 0.1
  DEAD_WAITED=$((DEAD_WAITED + 1))
done
kill "$DEAD_HOOK_PID" 2>/dev/null || true
wait "$DEAD_HOOK_PID" 2>/dev/null || true
DEAD_RC=$(cat "$DEAD_RC_FILE" 2>/dev/null || echo "timed-out")

if [ "$DEAD_RC" = "0" ] && [ ! -e "$LOCK_LIVENESS" ] && [ ! -L "$LOCK_LIVENESS" ] && grep -q 'agent-deadlock' "$DECISIONS_LOG_LIVENESS" 2>/dev/null; then
  pass "a lock whose recorded PID is dead is broken, and the hook completes normally and records its decision"
else
  fail "dead-PID lock was not broken (a crashed hook would wedge all later review queueing): hook_rc=$DEAD_RC, lock present=$([ -L "$LOCK_LIVENESS" ] && echo yes || echo no)"
fi
rm -f "$LOCK_LIVENESS"

# 16b. A LIVE holder PID: the lock must never be broken while its holder is
# alive -- evicting it puts two hooks in the critical section, which drops
# decisions (a PR silently never gets a critical review).
clear_sandbox
rm -f "$DECISIONS_LOG_LIVENESS" "$DECISIONS_LOG_LIVENESS.1" "$DECISIONS_LOG_LIVENESS.2"
rm -rf "$LOCK_LIVENESS"
sleep 30 & LIVE_PID=$!
ln -s "$LIVE_PID" "$LOCK_LIVENESS"

INPUT_LIVE=$(jq -n --arg msg 'Nothing to review here.' \
  '{agent_id:"agent-livelock", agent_type:"worker", cwd:"/tmp/wt", session_id:"sessLive", hook_event_name:"SubagentStop", last_assistant_message:$msg}')
# Backgrounded, not timeout-wrapped (no `timeout` binary on stock macOS):
# with the fix, this hook invocation never acquires the lock on its own
# (the holder never releases it) and would wait forever -- the explicit
# `kill` after the assertion below is what reaps it, same as the live
# holder process itself.
CLAUDE_PROJECT_DIR="$SANDBOX" PATH="$STUBDIR:$PATH" \
  bash "$HOOK" <<< "$INPUT_LIVE" >/dev/null 2>&1 &
LIVE_HOOK_PID=$!
sleep 2.5  # many poll cycles: a wrongly-breaking waiter would have fired by now

LIVE_SURVIVED_PID=$(readlink "$LOCK_LIVENESS" 2>/dev/null || true)
if [ "$LIVE_SURVIVED_PID" = "$LIVE_PID" ]; then
  pass "a lock whose recorded PID is still alive is NOT broken while the waiter polls"
else
  fail "live-PID lock was broken despite the holder still being alive (two hooks in the critical section drop decisions): lock owner=$LIVE_SURVIVED_PID, expected=$LIVE_PID"
fi

kill "$LIVE_PID" 2>/dev/null || true
kill "$LIVE_HOOK_PID" 2>/dev/null || true
wait "$LIVE_PID" 2>/dev/null || true
wait "$LIVE_HOOK_PID" 2>/dev/null || true
rm -f "$LOCK_LIVENESS"

# Case 17: a hook that wins the lock but is slow to finish taking it must
# not be evicted by waiters. `mkdir`/`ln` stubs sleep after creating the lock
# path, widening the acquire window that is a few microseconds in reality
# but is hit under CI load. An implementation that records the owner PID
# after creating the lock (mkdir + pid file) looks ownerless for the whole
# delay, so a waiter breaks it: two hooks in the critical section, a crashed
# hook and a dropped decision -- a PR that never gets reviewed.
SLOWDIR=$(mktemp -d)
for tool in mkdir ln; do
  cat > "$SLOWDIR/$tool" <<'STUBEOF'
#!/usr/bin/env bash
tool=$(basename "$0")
PATH=${PATH#*:}
"$tool" "$@" || exit $?
for a in "$@"; do
  case "$a" in *decisions.tsv.lock*) sleep 1 ;; esac
done
STUBEOF
  chmod +x "$SLOWDIR/$tool"
done

SLOW_LOG="$SANDBOX/.claude/review-queue/log/decisions.tsv"
clear_sandbox
rm -rf "$SLOW_LOG" "$SLOW_LOG.1" "$SLOW_LOG.2" "$SLOW_LOG.lock" "$SLOW_LOG.lock.d"
SLOW_PIDS=()
for i in 1 2 3; do
  (
    INPUT_SLOW=$(jq -n --arg id "agent-slow$i" \
      '{agent_id:$id, agent_type:"worker", cwd:"/tmp/wt", session_id:"sessSlow", hook_event_name:"SubagentStop", last_assistant_message:"nothing to do"}')
    RC=0
    CLAUDE_PROJECT_DIR="$SANDBOX" PATH="$SLOWDIR:$STUBDIR:$PATH" \
      bash "$HOOK" <<< "$INPUT_SLOW" >/dev/null 2>&1 || RC=$?
    echo "$RC" > "$SANDBOX/slow-rc-$i"
  ) &
  SLOW_PIDS+=($!)
done
for pid in "${SLOW_PIDS[@]}"; do
  wait "$pid" || true
done
rm -rf "$SLOWDIR"

SLOW_BAD=0
for i in 1 2 3; do
  [ "$(cat "$SANDBOX/slow-rc-$i" 2>/dev/null || echo missing)" = "0" ] || SLOW_BAD=$((SLOW_BAD + 1))
  grep -q "agent-slow$i" "$SLOW_LOG" 2>/dev/null || SLOW_BAD=$((SLOW_BAD + 1))
done
if [ "$SLOW_BAD" -eq 0 ]; then
  pass "hooks that are slow to take the decisions lock are not evicted: all 3 exit 0 and record their decision (no missed reviews)"
else
  fail "$SLOW_BAD crash/drop(s) when waiters met a lock whose owner was not yet recorded -- a dropped decision means a PR silently never gets a critical review"
fi

# Case 18: release must be owner-only. A hook whose lock was replaced by
# another live holder (e.g. it was wrongly evicted) must not delete the new
# holder's lock on its way out; doing so lets a waiter in while that holder is
# still writing, and a decision is dropped (a PR silently never gets a
# critical review). A `wc` stub, which runs inside the critical section,
# swaps the lock for one naming a live process.
REL_LOG="$SANDBOX/.claude/review-queue/log/decisions.tsv"
clear_sandbox
rm -f "$REL_LOG" "$REL_LOG.1" "$REL_LOG.2" "$REL_LOG.lock" "$REL_LOG.lock.break"
echo "seed" > "$REL_LOG"
sleep 30 & REL_OTHER_PID=$!
RELDIR=$(mktemp -d)
cat > "$RELDIR/wc" <<STUBEOF
#!/usr/bin/env bash
rm -f "$REL_LOG.lock"
ln -s "$REL_OTHER_PID" "$REL_LOG.lock"
PATH=\${PATH#*:}
exec wc "\$@"
STUBEOF
chmod +x "$RELDIR/wc"
INPUT_REL=$(jq -n '{agent_id:"agent-rel", agent_type:"worker", cwd:"/tmp/wt", session_id:"sessRel", hook_event_name:"SubagentStop", last_assistant_message:"nothing to do"}')
CLAUDE_PROJECT_DIR="$SANDBOX" PATH="$RELDIR:$STUBDIR:$PATH" \
  bash "$HOOK" <<< "$INPUT_REL" >/dev/null 2>&1 || true
REL_SURVIVED=$(readlink "$REL_LOG.lock" 2>/dev/null || true)
kill "$REL_OTHER_PID" 2>/dev/null || true
wait "$REL_OTHER_PID" 2>/dev/null || true
rm -rf "$RELDIR"
rm -f "$REL_LOG.lock"
if [ "$REL_SURVIVED" = "$REL_OTHER_PID" ]; then
  pass "a hook that no longer owns the decisions lock does not delete the real holder's lock on release"
else
  fail "release removed a lock owned by another live holder (a waiter enters mid-write and a decision is dropped, so a PR silently never gets a critical review): lock owner=$REL_SURVIVED, expected=$REL_OTHER_PID"
fi

# Case 19: breaking a dead holder's lock must not remove a fresh holder's
# lock. Breaker B reads dead holder H, is paused (readlink stub), meanwhile C
# takes the lock; B then resumes. A break that renames/removes whatever is at
# the lock path admits waiter D alongside C (the `mv` stub widens the window
# in which the lock is absent): two hooks in the critical section and a
# dropped decision -- a PR silently never gets a critical review. Expected:
# C's lock survives while C is alive, D waits, and after C finishes both B
# and D record their decisions.
BRK_LOG="$SANDBOX/.claude/review-queue/log/decisions.tsv"
clear_sandbox
rm -f "$BRK_LOG" "$BRK_LOG.1" "$BRK_LOG.2" "$BRK_LOG.lock" "$BRK_LOG.lock.break"
BRKDIR=$(mktemp -d)
BRK_PAUSE="$BRKDIR/pause-once"
touch "$BRK_PAUSE"
cat > "$BRKDIR/readlink" <<STUBEOF
#!/usr/bin/env bash
PATH=\${PATH#*:}
out=\$(readlink "\$@")
rc=\$?
printf '%s\n' "\$out"
case "\$*" in *decisions.tsv.lock) rm "$BRK_PAUSE" 2>/dev/null && sleep 1.5 ;; esac
exit \$rc
STUBEOF
cat > "$BRKDIR/mv" <<'STUBEOF'
#!/usr/bin/env bash
PATH=${PATH#*:}
mv "$@" || exit $?
case "$*" in *decisions.tsv.lock*) sleep 1.5 ;; esac
STUBEOF
chmod +x "$BRKDIR/readlink" "$BRKDIR/mv"
( : ) & BRK_DEAD_PID=$!
wait "$BRK_DEAD_PID" 2>/dev/null || true
sleep 30 & BRK_C_PID=$!
ln -s "$BRK_DEAD_PID" "$BRK_LOG.lock"
INPUT_B=$(jq -n '{agent_id:"agent-brkB", agent_type:"worker", cwd:"/tmp/wt", session_id:"sessBrk", hook_event_name:"SubagentStop", last_assistant_message:"nothing to do"}')
INPUT_D=$(jq -n '{agent_id:"agent-brkD", agent_type:"worker", cwd:"/tmp/wt", session_id:"sessBrk", hook_event_name:"SubagentStop", last_assistant_message:"nothing to do"}')
CLAUDE_PROJECT_DIR="$SANDBOX" PATH="$BRKDIR:$STUBDIR:$PATH" \
  bash "$HOOK" <<< "$INPUT_B" >/dev/null 2>&1 &
BRK_B_PID=$!
sleep 0.5
rm -f "$BRK_LOG.lock"
ln -s "$BRK_C_PID" "$BRK_LOG.lock"
sleep 1.5
CLAUDE_PROJECT_DIR="$SANDBOX" PATH="$STUBDIR:$PATH" \
  bash "$HOOK" <<< "$INPUT_D" >/dev/null 2>&1 &
BRK_D_PID=$!
sleep 1.2
BRK_OWNER=$(readlink "$BRK_LOG.lock" 2>/dev/null || true)
BRK_EARLY=$(grep -c 'agent-brk' "$BRK_LOG" 2>/dev/null || true)
kill "$BRK_C_PID" 2>/dev/null || true
wait "$BRK_C_PID" 2>/dev/null || true
wait "$BRK_B_PID" "$BRK_D_PID" 2>/dev/null || true
BRK_FINAL=$(grep -c 'agent-brk' "$BRK_LOG" 2>/dev/null || true)
rm -rf "$BRKDIR"
if [ "$BRK_OWNER" = "$BRK_C_PID" ] && [ "${BRK_EARLY:-0}" = "0" ] && [ "$BRK_FINAL" = "2" ]; then
  pass "breaking a dead holder's lock never removes a fresh holder's lock: one owner at a time and both decisions recorded"
else
  fail "dead-lock break admitted a second owner or dropped a decision (a PR silently never gets a critical review): owner=$BRK_OWNER expected=$BRK_C_PID, decisions written while C held the lock=$BRK_EARLY (want 0), final=$BRK_FINAL (want 2)"
fi

if [ "$FAILURES" -eq 0 ]; then
  printf '\nall tests passed\n'
  exit 0
else
  printf '\n%d test(s) failed\n' "$FAILURES" >&2
  exit 1
fi

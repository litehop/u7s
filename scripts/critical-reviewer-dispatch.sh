#!/usr/bin/env bash
# SubagentStop hook: detects reviewable deliverables in a subagent's final
# message and queues a review request under .claude/review-queue/.
#
# Design shape (2026-08-18): dumb-but-certain queueing, NOT auto-dispatch.
#   - The hook DEFINITELY fires (writes file) once a deliverable is seen.
#   - Mayor picks up the queue file on next turn and invokes
#     `.claude/agents/critical-reviewer.md` to actually review.
#   - Chose queueing over inline `claude -p` because upstream
#     anthropics/claude-code#27755 reports SubagentStop hooks configured via
#     settings.json are unreliable, and blocking the parent loop for a full
#     reviewer run (up to 600s hook timeout) would stall session throughput.
#
# Never spawn a reviewer synchronously from here. Never edit files outside
# .claude/review-queue/.
#
# Retention policy (2026-08-27): decisions.tsv rotates via simple counter
# rotation (.tsv -> .1 -> .2, oldest generation discarded)
# once it reaches ~1 MiB, so a long-running mayor session cannot grow it
# unbounded. Both "queued" and "skip" entries rotate together -- skips are
# already the majority of lines and untangling the two isn't worth the
# complexity. Queued (auditable) entries survive at least two rotations
# before being dropped, since nothing is discarded until it ages past the
# .2 generation.

set -euo pipefail

INPUT=$(cat)

# Hook I/O contract (per code.claude.com/docs/en/hooks.md, verified 2026-08-18):
#   stdin JSON has: session_id, transcript_path, cwd, hook_event_name,
#   agent_id, agent_type, last_assistant_message.
AGENT_ID=$(printf '%s' "$INPUT" | jq -r '.agent_id // "unknown"')
AGENT_TYPE=$(printf '%s' "$INPUT" | jq -r '.agent_type // "unknown"')
CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty')
MSG=$(printf '%s' "$INPUT" | jq -r '.last_assistant_message // empty')
SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.session_id // "unknown"')

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
QUEUE_DIR="$PROJECT_DIR/.claude/review-queue"
LOG_DIR="$QUEUE_DIR/log"

mkdir -p "$LOG_DIR"

DECISIONS_LOG="$LOG_DIR/decisions.tsv"
DECISIONS_LOG_MAX_BYTES=$((1024 * 1024)) # 1 MiB; see retention policy above.

# Counter rotation: decisions.tsv -> .1 -> .2, oldest (.2) discarded. Runs
# before every append so the live file never grows past
# DECISIONS_LOG_MAX_BYTES.
rotate_decisions_log() {
  [ -f "$DECISIONS_LOG" ] || return 0
  local size
  size=$(wc -c < "$DECISIONS_LOG" | tr -d ' ')
  [ "${size:-0}" -ge "$DECISIONS_LOG_MAX_BYTES" ] || return 0
  rm -f "$DECISIONS_LOG.2"
  [ -f "$DECISIONS_LOG.1" ] && mv "$DECISIONS_LOG.1" "$DECISIONS_LOG.2"
  mv "$DECISIONS_LOG" "$DECISIONS_LOG.1"
}

log_decision() {
  rotate_decisions_log
  printf '%s\n' "$1" >> "$DECISIONS_LOG"
}

TS=$(date -u +"%Y-%m-%dT%H-%M-%SZ")

# Detect reviewable deliverables. Empty MSG → nothing to review.
[ -z "$MSG" ] && exit 0

# A dispatched critical-reviewer's own completion report necessarily mentions
# the PR/deliverable it just reviewed (e.g. "I posted findings on PR #<N>:
# <url>"). Without this check that echo is indistinguishable from a worker
# having just opened a fresh PR, so the hook would re-queue a review of the
# review that was JUST completed -- and draining that queue entry would
# produce another critical-reviewer completion mentioning the same URL,
# re-queuing again unboundedly. Skip before running deliverable detection at
# all; there is nothing to discard, so no reason to regex the message first.
if [ "$AGENT_TYPE" = "critical-reviewer" ]; then
  log_decision "$(printf '%s\t%s\tskip\tself-review-echo\tagent_type=%s' \
    "$TS" "$AGENT_ID" "$AGENT_TYPE")"
  exit 0
fi

DELIVERABLE_TYPE=""
DELIVERABLE_REF=""

# 1. PR opened. Repo slug is github.com/litehop/u7s
PR_URL=$(printf '%s' "$MSG" | grep -oE 'https?://github\.com/litehop/u7s/pull/[0-9]+' | head -1 || true)
if [ -n "$PR_URL" ]; then
  DELIVERABLE_TYPE="pr"
  DELIVERABLE_REF="$PR_URL"
fi

# 2. Findings doc. Look for absolute paths to ai/findings/*.md that the worker
#    wrote inside its worktree.
if [ -z "$DELIVERABLE_TYPE" ]; then
  FINDINGS_PATH=$(printf '%s' "$MSG" | grep -oE '/[^ )"'"'"']+/ai/findings/[^ )"'"'"']+\.md' | head -1 || true)
  if [ -n "$FINDINGS_PATH" ] && [ -f "$FINDINGS_PATH" ]; then
    DELIVERABLE_TYPE="findings"
    DELIVERABLE_REF="$FINDINGS_PATH"
  fi
fi

# 3. Bead close. The worker reports `bd close mayor-XXXXX -r "..."` in output.
if [ -z "$DELIVERABLE_TYPE" ]; then
  BEAD_ID=$(printf '%s' "$MSG" | grep -oE 'bd close (mayor-[a-z0-9]+)' | head -1 | awk '{print $3}' || true)
  if [ -n "$BEAD_ID" ]; then
    DELIVERABLE_TYPE="bead-close"
    DELIVERABLE_REF="$BEAD_ID"
  fi
fi

# 4. Bead supersede. Both `bd supersede` and `bd relate --type supersedes`
#    are seen historically — accept either.
if [ -z "$DELIVERABLE_TYPE" ]; then
  SUPERSEDE=$(printf '%s' "$MSG" | grep -oE '(bd supersede|bd relate --type supersedes)[^\n]*mayor-[a-z0-9]+' | head -1 || true)
  if [ -n "$SUPERSEDE" ]; then
    DELIVERABLE_TYPE="bead-supersede"
    DELIVERABLE_REF="$SUPERSEDE"
  fi
fi

# No reviewable deliverable → skip. Log the reason so a future audit can tell
# "hook fired but had nothing to do" from "hook never fired" (upstream #27755).
if [ -z "$DELIVERABLE_TYPE" ]; then
  log_decision "$(printf '%s\t%s\tskip\tno-deliverable\tagent_type=%s' \
    "$TS" "$AGENT_ID" "$AGENT_TYPE")"
  exit 0
fi

# Retention policy (2026-08-21): only "queued" decisions get a raw JSONL
# payload logged. Skips (the vast majority of SubagentStop events — every
# non-deliverable-producing subagent stop) are already cheaply covered by
# the one-liner above; giving every one of them a full-payload file too is
# what grew log/ past 4000 files with no bound. The raw payload is still
# useful for queued events specifically, to debug the wire format if a
# future Claude Code release changes the JSON schema (upstream #27755).
printf '%s\n' "$INPUT" > "$LOG_DIR/$TS-$AGENT_ID.jsonl"

# Write the review-request queue file. Mayor sees it on next turn.
QUEUE_FILE="$QUEUE_DIR/$TS-$AGENT_ID.md"

{
  printf -- '---\n'
  printf 'deliverable_type: %s\n' "$DELIVERABLE_TYPE"
  printf 'deliverable_ref: %s\n' "$DELIVERABLE_REF"
  printf 'agent_id: %s\n' "$AGENT_ID"
  printf 'agent_type: %s\n' "$AGENT_TYPE"
  printf 'session_id: %s\n' "$SESSION_ID"
  printf 'queued_at: %s\n' "$TS"
  printf -- '---\n\n'
  printf '# Review request\n\n'
  printf 'Invoke `.claude/agents/critical-reviewer.md` with this deliverable.\n\n'
  printf '## Subagent final message\n\n'
  printf '```\n%s\n```\n' "$MSG"
} > "$QUEUE_FILE"

log_decision "$(printf '%s\t%s\tqueued\t%s\t%s' \
  "$TS" "$AGENT_ID" "$DELIVERABLE_TYPE" "$DELIVERABLE_REF")"

exit 0

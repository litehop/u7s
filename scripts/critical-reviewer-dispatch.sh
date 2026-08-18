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

TS=$(date -u +"%Y-%m-%dT%H-%M-%SZ")

# Always log raw hook input — enables debugging the wire format if a future
# Claude Code release changes the JSON schema (see upstream #27755 caveat).
printf '%s\n' "$INPUT" > "$LOG_DIR/$TS-$AGENT_ID.jsonl"

# Detect reviewable deliverables. Empty MSG → nothing to review.
[ -z "$MSG" ] && exit 0

DELIVERABLE_TYPE=""
DELIVERABLE_REF=""

# 1. PR opened. Repo slug is github.com/valerauko/u7s (verified via
#    `git remote -v` 2026-08-18; not github.com/rootless-containers/usernetes
#    — that is an unrelated project).
PR_URL=$(printf '%s' "$MSG" | grep -oE 'https?://github\.com/valerauko/u7s/pull/[0-9]+' | head -1 || true)
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
  printf '%s\t%s\tskip\tno-deliverable\tagent_type=%s\n' \
    "$TS" "$AGENT_ID" "$AGENT_TYPE" >> "$LOG_DIR/decisions.tsv"
  exit 0
fi

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

printf '%s\t%s\tqueued\t%s\t%s\n' \
  "$TS" "$AGENT_ID" "$DELIVERABLE_TYPE" "$DELIVERABLE_REF" >> "$LOG_DIR/decisions.tsv"

exit 0

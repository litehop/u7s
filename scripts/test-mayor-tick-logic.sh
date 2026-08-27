#!/usr/bin/env bash
# Unit test for scripts/mayor-tick.sh's pure functions and side-effect gate.
#
# Exercises the REAL script as a subprocess via its `__call <fn> [args...]`
# entry point (same "real script, not a reimplementation" technique as
# scripts/test-check-bead-id-refs-logic.sh and siblings) -- a
# reimplementation of the timestamp comparison, verdict regex, or exit-code
# selection would keep passing even if the real logic regressed.
#
# Covers the four areas load-bearing for the merge-PR pipeline:
#   1. Queue-drain detection (queue_is_drained / normalize_queued_at) --
#      the mechanism that decides whether a review-queue file gets rm'd or
#      stays queued for the mayor to dispatch a reviewer against.
#   2. Verdict parsing (parse_verdict) -- the merge gate's ONLY signal for
#      whether a CLEAN PR is safe to merge. A regression here either blocks
#      every merge (empty match) or, worse, waves through a needs-changes
#      PR.
#   3. Exit-code selection (compute_exit_code) -- what tells the mayor
#      there's something to do at all, and in the OR-able multi-signal
#      case, which one to look at first.
#   4. State-file JSON validity (write_state) -- the mayor's entire
#      read-decide-dispatch loop depends on this file parsing.
#
# Also covers run_cmd's dry-run gate (the mechanism THIS test suite itself
# relies on to never invoke a real `gh pr merge`/`git worktree remove`/
# `git branch -D`) and splice_dashboard_section's three shapes (first-run
# migration onto an existing freeform heading, steady-state in-place
# update, brand-new section append) -- a regression in any of those would
# either duplicate a dashboard heading or clobber mayor-owned prose outside
# the sentinel block.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/mayor-tick.sh"

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

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

# ---------------------------------------------------------------------------
# 1. Queue-drain detection.
# ---------------------------------------------------------------------------

# A review submitted AFTER the queue entry was queued -> drained. Dates use
# the hook's actual on-disk format (dashes) for queued_at and GitHub's
# actual format (colons) for submitted_at -- this exact format mismatch is
# what normalize_queued_at exists to bridge.
RC=0
call queue_is_drained '2026-08-21T03-39-02Z' '2026-08-21T03:39:03Z' || RC=$?
assert "queue entry with a review submitted AFTER queued_at is drained" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

# A review submitted BEFORE the queue entry was queued (a stale review from
# a prior round) must NOT be mistaken for having answered this entry --
# this is the exact class of bug PR #1336 hit at the PR-verdict layer
# (an older LGTM masking a newer needs-changes); here it's the queue side
# of the same "resolve by time, not presence" requirement.
RC=0
call queue_is_drained '2026-08-21T03-39-02Z' '2026-08-21T03:39:01Z' || RC=$?
assert "queue entry with a review submitted BEFORE queued_at is still pending" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# No review posted yet at all (empty submitted_at) -> pending. Without this
# check an empty string would still lexicographically compare against the
# normalized queued_at and could accidentally evaluate as "newer".
RC=0
call queue_is_drained '2026-08-21T03-39-02Z' '' || RC=$?
assert "queue entry with no review at all is pending, not drained" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. Verdict parsing.
# ---------------------------------------------------------------------------

assert "LGTM verdict is parsed" \
  "$([ "$(call parse_verdict '**Verdict**: LGTM')" = "LGTM" ] && echo 1 || echo 0)"
assert "LGTM-with-suggestions verdict is parsed (must not truncate at the hyphen)" \
  "$([ "$(call parse_verdict '**Verdict**: LGTM-with-suggestions')" = "LGTM-with-suggestions" ] && echo 1 || echo 0)"
assert "needs-changes verdict is parsed (the merge gate must see this, not LGTM)" \
  "$([ "$(call parse_verdict '**Verdict**: needs-changes')" = "needs-changes" ] && echo 1 || echo 0)"
assert "needs-discussion verdict is parsed" \
  "$([ "$(call parse_verdict '**Verdict**: needs-discussion')" = "needs-discussion" ] && echo 1 || echo 0)"

# Realistic multi-line findings body, Verdict line embedded mid-document --
# proves the parser finds the line rather than requiring the whole body to
# be just the Verdict line.
REALISTIC_BODY='## critical-reviewer findings — pr — #1234

**Verdict**: needs-changes

**Confirmed findings** (must be true, evidence cited):
- [HIGH] example finding.
'
assert "verdict is extracted from a realistic multi-line findings body" \
  "$([ "$(call parse_verdict "$REALISTIC_BODY")" = "needs-changes" ] && echo 1 || echo 0)"

# No Verdict line at all -> empty, not a false LGTM. A gate that defaulted
# a missing match to "LGTM" would merge PRs with no real verdict.
assert "a body with no Verdict line at all parses to empty (never a false LGTM)" \
  "$([ -z "$(call parse_verdict 'no verdict line here')" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. Exit-code selection -- highest signal wins when multiple fire.
# ---------------------------------------------------------------------------

assert "no signals -> exit 0 (noop)" \
  "$([ "$(call compute_exit_code 0 0 0)" = "0" ] && echo 1 || echo 0)"
assert "bd-ready only -> exit 10" \
  "$([ "$(call compute_exit_code 2 0 0)" = "10" ] && echo 1 || echo 0)"
assert "gate/queue exception only -> exit 20" \
  "$([ "$(call compute_exit_code 0 1 0)" = "20" ] && echo 1 || echo 0)"
assert "worktree anomaly only -> exit 30" \
  "$([ "$(call compute_exit_code 0 0 1)" = "30" ] && echo 1 || echo 0)"
# The load-bearing case: bd-ready AND a worktree anomaly fire in the same
# tick. If exit-code selection picked "first signal seen" instead of "max",
# a routine bd-ready (10) could mask a worktree anomaly (30) that needs
# investigation before the mayor safely dispatches anything new.
assert "bd-ready + worktree anomaly together -> 30 wins, not 10 (highest signal, not first)" \
  "$([ "$(call compute_exit_code 3 0 2)" = "30" ] && echo 1 || echo 0)"
assert "all three signals together -> 30 (the strictly highest)" \
  "$([ "$(call compute_exit_code 5 4 3)" = "30" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. State-file JSON validity.
# ---------------------------------------------------------------------------

STATE_OUT="$WORKDIR/state.json"
MAYOR_TICK_STATE_FILE="$STATE_OUT" call write_state 20 \
  '["a.md","b.md"]' '[123]' '[456]' '["mayor-abcd"]' \
  '[{"path":"/tmp/x","branch":"worker/agent-x","reason":"no-pr-for-branch"}]' \
  '[{"pr":789,"reason":"no-qualifying-review"}]'

assert "state file is valid JSON" \
  "$(jq empty "$STATE_OUT" >/dev/null 2>&1 && echo 1 || echo 0)"
assert "state file's exit_code round-trips" \
  "$([ "$(jq -r '.exit_code' "$STATE_OUT")" = "20" ] && echo 1 || echo 0)"
assert "state file's pending_reviews round-trips as a JSON number, not a string" \
  "$([ "$(jq -r '.pending_reviews[0] | type' "$STATE_OUT")" = "number" ] && echo 1 || echo 0)"
assert "state file's bd_ready_ids round-trips" \
  "$([ "$(jq -r '.bd_ready_ids[0]' "$STATE_OUT")" = "mayor-abcd" ] && echo 1 || echo 0)"
assert "state file's gate_exceptions carries the structured PR+reason payload"  \
  "$([ "$(jq -r '.gate_exceptions[0].reason' "$STATE_OUT")" = "no-qualifying-review" ] && echo 1 || echo 0)"
assert "state file's timestamp field is present and non-empty" \
  "$([ -n "$(jq -r '.timestamp' "$STATE_OUT")" ] && echo 1 || echo 0)"

# Empty-everything case -- must still be valid JSON with empty arrays, not a
# jq error from an unquoted/malformed empty-array literal.
STATE_EMPTY="$WORKDIR/state-empty.json"
MAYOR_TICK_STATE_FILE="$STATE_EMPTY" call write_state 0 '[]' '[]' '[]' '[]' '[]' '[]'
assert "state file with every field empty is still valid JSON" \
  "$(jq empty "$STATE_EMPTY" >/dev/null 2>&1 && echo 1 || echo 0)"
assert "state file with every field empty has exit_code 0" \
  "$([ "$(jq -r '.exit_code' "$STATE_EMPTY")" = "0" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 5. run_cmd dry-run gate -- the mechanism that keeps THIS test suite (and
#    any manual dry-run) from ever touching a real PR, worktree, or branch.
# ---------------------------------------------------------------------------

MARKER="$WORKDIR/marker"
OUT=$(MAYOR_TICK_DRY_RUN=1 call run_cmd touch "$MARKER")
assert "MAYOR_TICK_DRY_RUN=1 logs the command instead of running it" \
  "$(printf '%s' "$OUT" | grep -q 'would run: touch' && echo 1 || echo 0)"
assert "...and the gated command genuinely did not execute" \
  "$([ ! -e "$MARKER" ] && echo 1 || echo 0)"

call run_cmd touch "$MARKER" >/dev/null
assert "without MAYOR_TICK_DRY_RUN, run_cmd executes the real command" \
  "$([ -e "$MARKER" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 6. Dashboard splice -- three shapes, none of which may duplicate a
#    heading or touch content outside the sentinel block.
# ---------------------------------------------------------------------------

DASH="$WORKDIR/dashboard.md"
cat > "$DASH" <<'EOF'
# Dashboard

## 🎯 DECISION POINT
Mayor-owned content that must survive untouched.

## 🔎 Open PRs
Stale freeform text from before mayor-tick.sh existed.

## Repo state
Main @ deadbeef, clean.
EOF

MAYOR_TICK_DASHBOARD_FILE="$DASH" call splice_dashboard_section \
  "open-prs" '^## .*Open PRs' '🔎 Open PRs' "- #1 first run"

assert "first run onto an existing heading inserts exactly one sentinel pair" \
  "$([ "$(grep -c 'BEGIN AUTO: open-prs' "$DASH")" = "1" ] && echo 1 || echo 0)"
assert "...replaces the old freeform text under that heading" \
  "$(! grep -q 'Stale freeform text' "$DASH" && echo 1 || echo 0)"
assert "...does not duplicate the Open PRs heading" \
  "$([ "$(grep -c '^## .*Open PRs' "$DASH")" = "1" ] && echo 1 || echo 0)"
assert "...leaves an unrelated mayor-owned section (DECISION POINT) untouched" \
  "$(grep -q 'Mayor-owned content that must survive untouched' "$DASH" && echo 1 || echo 0)"

MAYOR_TICK_DASHBOARD_FILE="$DASH" call splice_dashboard_section \
  "open-prs" '^## .*Open PRs' '🔎 Open PRs' "- #2 second run"
assert "steady-state re-run updates content in place (no second sentinel pair)" \
  "$([ "$(grep -c 'BEGIN AUTO: open-prs' "$DASH")" = "1" ] && echo 1 || echo 0)"
assert "...and reflects the new content" \
  "$(grep -q '#2 second run' "$DASH" && echo 1 || echo 0)"
assert "...old content from the first run is gone" \
  "$(! grep -q '#1 first run' "$DASH" && echo 1 || echo 0)"

MAYOR_TICK_DASHBOARD_FILE="$DASH" call splice_dashboard_section \
  "review-queue" '^## .*Review queue' '📋 Review queue' "0 pending review-queue entries."
assert "a section with no matching heading yet is appended fresh" \
  "$(grep -q 'BEGIN AUTO: review-queue' "$DASH" && echo 1 || echo 0)"
assert "...still leaves the DECISION POINT section untouched" \
  "$(grep -q 'Mayor-owned content that must survive untouched' "$DASH" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

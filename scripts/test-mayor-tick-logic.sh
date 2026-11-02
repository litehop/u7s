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

file_mtime() {  # GNU first: GNU `stat -f` reports filesystem state, which shifts under parallel tests
  stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null
}

# Builds an isolated single-worktree scratch git repo (one worktree, no
# queue files, no worker PRs, no beads) WITHOUT invoking main() -- this
# actual dev checkout has live sibling worktrees/PRs/beads that would
# otherwise leak into assertions and mask a real regression. Split out from
# run_full_tick (below) so a caller can invoke main() more than once
# against the SAME repo/queue dir -- needed to observe cross-tick state
# (e.g. a dispatch marker) that a fresh scratch dir per call can't. $1, if
# given, is a worker agent-id; a second worktree on branch
# worker/agent-<id> is added, so check_worktree_anomalies has a real
# worker/agent-* branch to evaluate against --live-agents. Sets
# SCRATCH_REPO for the caller.
build_scratch_repo() {
  local worker_agent_id="${1:-}"
  local scratch="$WORKDIR/tick-$RANDOM$RANDOM"
  SCRATCH_REPO="$scratch/repo"
  mkdir -p "$SCRATCH_REPO/scripts" "$SCRATCH_REPO/.claude/review-queue"
  cp "$SCRIPT" "$SCRATCH_REPO/scripts/mayor-tick.sh"
  git init -q "$SCRATCH_REPO"
  git -C "$SCRATCH_REPO" config user.email test@example.com
  git -C "$SCRATCH_REPO" config user.name "Test"
  git -C "$SCRATCH_REPO" commit -q --allow-empty -m init
  if [ -n "$worker_agent_id" ]; then
    local wpath="$scratch/worker-worktree"
    git -C "$SCRATCH_REPO" worktree add -q -b "worker/agent-$worker_agent_id" "$wpath"
    git -C "$wpath" commit -q --allow-empty -m "worker commit"
  fi
}

# Invokes the REAL end-to-end main() (mayor-tick.sh __call main) against a
# scratch repo built by build_scratch_repo, with `gh`/`bd` replaced by
# fixtures under $1 (a directory of executable stub scripts prepended to
# PATH). $2=repo path. $3=dry-run flag (0 or 1, default 1 -- most callers
# want the side-effect-free default; the dispatch-marker lifecycle test
# below needs 0 to observe a marker actually persisting on disk across
# ticks). $4=state file path override (default: derived from $2, one level
# up) -- lets a caller invoking this more than once against the same repo
# capture a separate snapshot per tick instead of each call clobbering the
# last. $5=--live-agents value (comma-separated agent ids), omitted
# entirely (not passed as an empty flag) when unset -- mirrors how the
# mayor invokes the real script. Sets TICK_RC/TICK_OUT/TICK_STATE for the
# caller to assert on.
invoke_tick() {
  local stub_bin="$1" repo="$2" dry_run="${3:-1}" state_file="${4:-}" live_agents="${5:-}"
  TICK_STATE="${state_file:-$(dirname "$repo")/state.json}"
  TICK_RC=0
  local extra_args=()
  [ -n "$live_agents" ] && extra_args=(--live-agents "$live_agents")
  TICK_OUT=$(PATH="$stub_bin:$PATH" \
    MAYOR_TICK_QUEUE_DIR="$repo/.claude/review-queue" \
    MAYOR_TICK_STATE_FILE="$TICK_STATE" \
    MAYOR_TICK_DASHBOARD_FILE="$repo/no-such-dashboard.md" \
    MAYOR_TICK_DRY_RUN="$dry_run" \
    bash "$repo/scripts/mayor-tick.sh" __call main "${extra_args[@]+"${extra_args[@]}"}" 2>&1) || TICK_RC=$?
}

# One-shot convenience: build a fresh isolated repo, seed it from $2 (a
# directory of .md queue fixtures, or empty/omitted), and run a single
# dry-run tick against it. $3, see build_scratch_repo. $4=--live-agents
# value, see invoke_tick. Sets TICK_RC/TICK_OUT/TICK_STATE for the caller
# to assert on.
run_full_tick() {
  local stub_bin="$1" queue_seed="${2:-}" worker_agent_id="${3:-}" live_agents="${4:-}"
  build_scratch_repo "$worker_agent_id"
  if [ -n "$queue_seed" ]; then
    cp "$queue_seed"/*.md "$SCRATCH_REPO/.claude/review-queue/" 2>/dev/null || true
  fi
  invoke_tick "$stub_bin" "$SCRATCH_REPO" 1 "" "$live_agents"
}

WORKDIR=$(mktemp -d)
trap 'rc=$?; [ "$rc" -ne 0 ] && echo "FATAL: aborted (exit $rc) at line ${LINENO}: $BASH_COMMAND" >&2; rm -rf "$WORKDIR"; exit "$rc"' EXIT

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
# the same "resolve by time, not presence" requirement that stops an older
# superseded verdict from masking a newer one (see git history, not a PR
# number here that would rot once that PR closes).
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

# A missing/malformed queued_at must fail CLOSED (pending), not open
# (drained): an empty string normalizes to empty, and any non-empty
# submitted_at lexicographically compares as "greater than" empty, so
# without is_valid_queued_at's guard a broken queue file would get rm'd on
# the next tick even though we don't actually know whether the review
# answers it.
RC=0
call queue_is_drained '' '2026-08-27T10:00:00Z' || RC=$?
assert "empty queued_at fails CLOSED (pending), not open (drained)" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call queue_is_drained 'not-a-timestamp' '2026-08-27T10:00:00Z' || RC=$?
assert "malformed (non-ISO) queued_at also fails CLOSED, not open" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 1b. Latest-review resolution (the exact "older LGTM masks a newer
#     needs-changes" bug class) -- extracted into latest_reviewer_review so
#     it's directly testable with synthetic multi-review data instead of
#     only living as untested inline jq inside a network-calling function.
# ---------------------------------------------------------------------------

# Older LGTM, newer needs-changes -> must resolve to needs-changes. If this
# ever regressed to "first match" or "any qualifying review" instead of
# "latest by submittedAt", a real needs-changes verdict would be masked by
# a stale approval and the gate would merge a PR it shouldn't.
REVIEWS_OLDER_LGTM='[
  {"body": "## critical-reviewer findings — pr — #1\n\n**Verdict**: LGTM", "submittedAt": "2026-08-27T01:00:00Z"},
  {"body": "## critical-reviewer findings — pr — #1\n\n**Verdict**: needs-changes", "submittedAt": "2026-08-27T02:00:00Z"}
]'
LATEST=$(call latest_reviewer_review "$REVIEWS_OLDER_LGTM")
assert "older LGTM + newer needs-changes resolves to needs-changes (not the stale LGTM)" \
  "$([ "$(call parse_verdict "$(printf '%s' "$LATEST" | jq -r '.body')")" = "needs-changes" ] && echo 1 || echo 0)"

# Inverse: older needs-changes, newer LGTM -> must resolve to LGTM. Confirms
# the resolution is genuinely time-based in both directions, not just
# "needs-changes always wins" (which would wedge a PR forever even after a
# real fix earned a follow-up LGTM).
REVIEWS_OLDER_NEEDS_CHANGES='[
  {"body": "## critical-reviewer findings — pr — #1\n\n**Verdict**: needs-changes", "submittedAt": "2026-08-27T01:00:00Z"},
  {"body": "## critical-reviewer findings — pr — #1\n\n**Verdict**: LGTM", "submittedAt": "2026-08-27T02:00:00Z"}
]'
LATEST=$(call latest_reviewer_review "$REVIEWS_OLDER_NEEDS_CHANGES")
assert "older needs-changes + newer LGTM resolves to LGTM (a real fix can un-block the gate)" \
  "$([ "$(call parse_verdict "$(printf '%s' "$LATEST" | jq -r '.body')")" = "LGTM" ] && echo 1 || echo 0)"

# A newer review that ISN'T a critical-reviewer review (no marker header)
# must not be picked just for being newest -- it's a different review type,
# not an update to the verdict.
REVIEWS_NON_REVIEWER_NEWEST='[
  {"body": "## critical-reviewer findings — pr — #1\n\n**Verdict**: LGTM", "submittedAt": "2026-08-27T01:00:00Z"},
  {"body": "looks fine to me", "submittedAt": "2026-08-27T02:00:00Z"}
]'
LATEST=$(call latest_reviewer_review "$REVIEWS_NON_REVIEWER_NEWEST")
assert "a newer non-critical-reviewer comment does not displace the actual verdict review" \
  "$([ "$(call parse_verdict "$(printf '%s' "$LATEST" | jq -r '.body')")" = "LGTM" ] && echo 1 || echo 0)"

# A DISMISSED needs-changes review must not hold the merge gate: once
# needs-changes becomes a native REQUEST_CHANGES review, dismissing it is
# the operator's way of saying "this verdict no longer applies" -- if the
# gate still picked the dismissed review's body text, GitHub would unblock
# the PR while the mayor's text-parse gate kept refusing it, a deadlock
# neither side could release. The gate must fall back to the next
# surviving review instead.
REVIEWS_DISMISSED_BLOCKING='[
  {"body": "## critical-reviewer findings — pr — #1\n\n**Verdict**: LGTM", "submittedAt": "2026-08-27T01:00:00Z", "state": "COMMENTED"},
  {"body": "## critical-reviewer findings — pr — #1\n\n**Verdict**: needs-changes", "submittedAt": "2026-08-27T02:00:00Z", "state": "DISMISSED"}
]'
LATEST=$(call latest_reviewer_review "$REVIEWS_DISMISSED_BLOCKING")
assert "a DISMISSED needs-changes review does not hold the gate -- it falls back to the older surviving LGTM" \
  "$([ "$(call parse_verdict "$(printf '%s' "$LATEST" | jq -r '.body')")" = "LGTM" ] && echo 1 || echo 0)"

# Inverse: a NON-dismissed needs-changes review must still hold the gate --
# proves the fix is a state filter, not something that accidentally started
# ignoring needs-changes verdicts altogether.
REVIEWS_LIVE_BLOCKING='[
  {"body": "## critical-reviewer findings — pr — #1\n\n**Verdict**: needs-changes", "submittedAt": "2026-08-27T02:00:00Z", "state": "COMMENTED"}
]'
LATEST=$(call latest_reviewer_review "$REVIEWS_LIVE_BLOCKING")
assert "a non-dismissed needs-changes review still holds the gate" \
  "$([ "$(call parse_verdict "$(printf '%s' "$LATEST" | jq -r '.body')")" = "needs-changes" ] && echo 1 || echo 0)"

# A review with no "state" field at all (every review today, since the
# critical-reviewer still posts under the operator's own identity, not yet
# the litehop-reviewer[bot] identity that would set state) must be
# unaffected by the new filter -- proves the filter is a no-op until the
# App identity starts producing real DISMISSED states.
REVIEWS_NO_STATE_FIELD='[
  {"body": "## critical-reviewer findings — pr — #1\n\n**Verdict**: needs-changes", "submittedAt": "2026-08-27T02:00:00Z"}
]'
LATEST=$(call latest_reviewer_review "$REVIEWS_NO_STATE_FIELD")
assert "a review with no state field at all (today's operator-identity reality) is unaffected by the DISMISSED filter" \
  "$([ "$(call parse_verdict "$(printf '%s' "$LATEST" | jq -r '.body')")" = "needs-changes" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 1c. PR gate eligibility -- BEHIND PRs must be queued, not silently
#     skipped forever (the merge queue's job is to rebase them, not the
#     mayor's).
# ---------------------------------------------------------------------------

RC=0
call pr_gate_eligible CLEAN 0 0 || RC=$?
assert "a CLEAN PR with 0 pending/0 failed checks is gate-eligible" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call pr_gate_eligible BEHIND 0 0 || RC=$?
assert "a BEHIND PR with 0 pending/0 failed checks is gate-eligible too (the queue rebases it, not silently skipped forever)" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call pr_gate_eligible DIRTY 0 0 || RC=$?
assert "a DIRTY PR is not gate-eligible" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call pr_gate_eligible CLEAN 1 0 || RC=$?
assert "a CLEAN PR with a still-pending check is not gate-eligible yet" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call pr_gate_eligible CLEAN 0 1 || RC=$?
assert "a CLEAN PR with a failed check is not gate-eligible" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 1d. A draft PR is never gate-eligible even when otherwise CLEAN with no
#     pending/failed checks -- GitHub has been observed reporting
#     mergeStateStatus=CLEAN for a deliberately-held draft PR, and
#     `gh pr merge` unconditionally rejects a draft, which would otherwise
#     abort the whole tick under `set -e` instead of just skipping it.
# ---------------------------------------------------------------------------
RC=0
call pr_gate_eligible CLEAN 0 0 true || RC=$?
assert "a draft PR is not gate-eligible even though mss/pending/failed all look mergeable" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call pr_gate_eligible CLEAN 0 0 false || RC=$?
assert "an explicit non-draft flag does not change the otherwise-eligible outcome" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

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
  '[{"pr":789,"reason":"no-qualifying-review"}]' \
  '[{"file":"c.md","deliverable_type":"findings","deliverable_ref":"mayor-efgh"}]' \
  '[{"file":"d.md","reason":"missing-or-malformed-queued_at"}]'

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
# Non-PR queue entries (findings/bead-close/bead-supersede) must be visible
# to the mayor with their deliverable_type, not silently dropped from the
# queue with no trace -- the whole point of this field.
assert "state file's pending_non_pr_reviews carries deliverable_type + ref, not just a bare path" \
  "$([ "$(jq -r '.pending_non_pr_reviews[0].deliverable_type' "$STATE_OUT")" = "findings" ] && [ "$(jq -r '.pending_non_pr_reviews[0].deliverable_ref' "$STATE_OUT")" = "mayor-efgh" ] && echo 1 || echo 0)"
assert "state file's queue_warnings surfaces a malformed-frontmatter file for investigation" \
  "$([ "$(jq -r '.queue_warnings[0].reason' "$STATE_OUT")" = "missing-or-malformed-queued_at" ] && echo 1 || echo 0)"

# Empty-everything case -- must still be valid JSON with empty arrays, not a
# jq error from an unquoted/malformed empty-array literal.
STATE_EMPTY="$WORKDIR/state-empty.json"
MAYOR_TICK_STATE_FILE="$STATE_EMPTY" call write_state 0 '[]' '[]' '[]' '[]' '[]' '[]' '[]' '[]'
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

# A "dry run" that still mutates the dashboard on disk defeats both this
# test suite's own no-side-effects guarantee and the operator-preview use
# case run_cmd is advertised for. Cover both write paths: the in-place
# replace (sentinel already exists, from the steady-state re-run above) and
# the fresh-append (brand-new sentinel id, never seen before).
DASH_BEFORE_CONTENT=$(cat "$DASH")
DASH_BEFORE_MTIME=$(file_mtime "$DASH")
MAYOR_TICK_DASHBOARD_FILE="$DASH" MAYOR_TICK_DRY_RUN=1 call splice_dashboard_section \
  "open-prs" '^## .*Open PRs' '🔎 Open PRs' "- #999 should never actually be written" >/dev/null
MAYOR_TICK_DASHBOARD_FILE="$DASH" MAYOR_TICK_DRY_RUN=1 call splice_dashboard_section \
  "brand-new-dry-run-section" '^## .*Nonexistent Heading' 'Nonexistent Heading' "should never actually be written" >/dev/null
DASH_AFTER_CONTENT=$(cat "$DASH")
DASH_AFTER_MTIME=$(file_mtime "$DASH")
assert "MAYOR_TICK_DRY_RUN=1 leaves the dashboard file's mtime unchanged (replace path)" \
  "$([ "$DASH_BEFORE_MTIME" = "$DASH_AFTER_MTIME" ] && echo 1 || echo 0)"
assert "MAYOR_TICK_DRY_RUN=1 leaves the dashboard file's content byte-identical (replace + append paths)" \
  "$([ "$DASH_BEFORE_CONTENT" = "$DASH_AFTER_CONTENT" ] && echo 1 || echo 0)"
assert "...the dry-run replace content never actually lands in the file" \
  "$(! grep -q '#999 should never actually be written' "$DASH" && echo 1 || echo 0)"
assert "...the dry-run append content never actually lands in the file" \
  "$(! grep -q 'brand-new-dry-run-section\|Nonexistent Heading' "$DASH" && echo 1 || echo 0)"
assert "...no leftover .tmp file from the dry-run replace path" \
  "$([ ! -e "${DASH}.tmp" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 6b. Multi-line splice body -- regression coverage for the BSD-awk newline
#     bug. BSD awk
#     (macOS's /usr/bin/awk -- what the pre-push hook and CI actually run)
#     rejects a newline embedded in an `-v name=value` scalar with "newline
#     in string" and exits 2. `$content` IS multi-line whenever 2+ worker
#     worktrees or 2+ open PRs exist, so this crashed the real 15m tick loop
#     with no state-file write, silently, exactly when multi-worker
#     parallelism most needed it (observed live 2026-08-28). Exercise both
#     awk call sites (existing-sentinel replace, freeform-heading migration)
#     with a 2-line body so a regression here fails loud instead of quietly
#     killing the loop again.
# ---------------------------------------------------------------------------

MULTI=$'- `worker/agent-a` (`branch-a`)\n- `worker/agent-b` (`branch-b`)'

RC=0
MAYOR_TICK_DASHBOARD_FILE="$DASH" call splice_dashboard_section \
  "open-prs" '^## .*Open PRs' '🔎 Open PRs' "$MULTI" || RC=$?
assert "multi-line body on the existing-sentinel replace path does not crash awk" \
  "$([ "$RC" = "0" ] && echo 1 || echo 0)"
assert "...both lines of the multi-line body land between the sentinels" \
  "$(grep -q 'worker/agent-a' "$DASH" && grep -q 'worker/agent-b' "$DASH" && echo 1 || echo 0)"
assert "...still exactly one sentinel pair (no half-written file from an awk crash)" \
  "$([ "$(grep -c 'BEGIN AUTO: open-prs' "$DASH")" = "1" ] && echo 1 || echo 0)"

DASH2="$WORKDIR/dashboard-migrate.md"
cat > "$DASH2" <<'EOF'
# Dashboard

## 🌲 Worktrees / hygiene
Stale freeform text from before mayor-tick.sh existed.
EOF

RC=0
MAYOR_TICK_DASHBOARD_FILE="$DASH2" call splice_dashboard_section \
  "worktrees" '^## .*Worktrees' '🌲 Worktrees / hygiene' "$MULTI" || RC=$?
assert "multi-line body on the freeform-heading migration path does not crash awk" \
  "$([ "$RC" = "0" ] && echo 1 || echo 0)"
assert "...both lines of the multi-line body land in the migrated section" \
  "$(grep -q 'worker/agent-a' "$DASH2" && grep -q 'worker/agent-b' "$DASH2" && echo 1 || echo 0)"
assert "...replaces the stale freeform text instead of leaving it alongside the new body" \
  "$(! grep -q 'Stale freeform text' "$DASH2" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 7. route_deliverable -- process_review_queue's dtype-routing case
#    statement, extracted so each dtype's routing decision is directly
#    testable without a gh network call or global-array mutation.
#    A regression here either drops a real finding/
#    bead-close/bead-supersede review off the mayor's radar entirely, or
#    (for "pr") merges the wrong PR's review verdict onto the wrong number.
# ---------------------------------------------------------------------------

ROUTE=$(call route_deliverable 'q/pr.md' pr 'https://github.com/example/repo/pull/777')
assert "pr dtype routes to the 'pr' bucket with the PR number extracted from deliverable_ref" \
  "$([ "$ROUTE" = "$(printf 'pr\t777')" ] && echo 1 || echo 0)"

ROUTE=$(call route_deliverable 'q/findings.md' findings 'mayor-aaaa')
assert "findings dtype routes to the 'non-pr' bucket with deliverable_type+ref preserved" \
  "$([ "$(printf '%s' "$ROUTE" | cut -f2 | jq -r '.deliverable_type')" = "findings" ] && [ "$(printf '%s' "$ROUTE" | cut -f2 | jq -r '.deliverable_ref')" = "mayor-aaaa" ] && echo 1 || echo 0)"

ROUTE=$(call route_deliverable 'q/close.md' bead-close 'mayor-bbbb')
assert "bead-close dtype routes to the 'non-pr' bucket" \
  "$([ "$(printf '%s' "$ROUTE" | cut -f1)" = "non-pr" ] && [ "$(printf '%s' "$ROUTE" | cut -f2 | jq -r '.deliverable_type')" = "bead-close" ] && echo 1 || echo 0)"

ROUTE=$(call route_deliverable 'q/supersede.md' bead-supersede 'mayor-cccc')
assert "bead-supersede dtype routes to the 'non-pr' bucket" \
  "$([ "$(printf '%s' "$ROUTE" | cut -f1)" = "non-pr" ] && [ "$(printf '%s' "$ROUTE" | cut -f2 | jq -r '.deliverable_type')" = "bead-supersede" ] && echo 1 || echo 0)"

# The suspicion this cluster resolves: an unrecognized dtype
# used to leave pending_reviews/pending_non_pr_reviews/gate_exceptions/
# queue_warnings ALL empty while still forcing exit 20 via queue_files --
# the mayor would see "something's wrong" with zero clues why. Routing it
# into queue_warnings means it now always has a clue.
ROUTE=$(call route_deliverable 'q/mystery.md' mystery-type 'mayor-dddd')
assert "an unrecognized deliverable_type routes to the 'warning' bucket, not silently dropped" \
  "$([ "$(printf '%s' "$ROUTE" | cut -f1)" = "warning" ] && echo 1 || echo 0)"
assert "...the warning payload names the file, the unrecognized dtype itself, and a stable reason string" \
  "$([ "$(printf '%s' "$ROUTE" | cut -f2 | jq -r '.file')" = "q/mystery.md" ] && [ "$(printf '%s' "$ROUTE" | cut -f2 | jq -r '.deliverable_type')" = "mystery-type" ] && [ "$(printf '%s' "$ROUTE" | cut -f2 | jq -r '.reason')" = "unrecognized-deliverable-type" ] && echo 1 || echo 0)"

# Malformed frontmatter (frontmatter_field found no dtype at all) must
# degrade the same way as an unrecognized dtype -- surfaced, not dropped.
ROUTE=$(call route_deliverable 'q/malformed.md' '' '')
assert "an empty (malformed-frontmatter) deliverable_type also routes to 'warning', not dropped" \
  "$([ "$(printf '%s' "$ROUTE" | cut -f1)" = "warning" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 8. pr_already_queued -- the no-double-queue guard: a PR already
#    tracked by an active queue file must not also get a
#    reconciliation-synthesized duplicate pending_reviews entry. Tested
#    directly against a real (but throwaway) filesystem -- no network.
# ---------------------------------------------------------------------------

QSEED_DIR="$WORKDIR/qseed-already-queued"
mkdir -p "$QSEED_DIR"
cat > "$QSEED_DIR/x.md" <<'EOF'
---
deliverable_type: pr
deliverable_ref: https://github.com/example/repo/pull/99
queued_at: 2026-01-01T00-00-00Z
---
body
EOF

RC=0
MAYOR_TICK_QUEUE_DIR="$QSEED_DIR" call pr_already_queued 'https://github.com/example/repo/pull/99' || RC=$?
assert "pr_already_queued is true when an active queue file's deliverable_ref names this exact PR URL" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
MAYOR_TICK_QUEUE_DIR="$QSEED_DIR" call pr_already_queued 'https://github.com/example/repo/pull/12345' || RC=$?
assert "pr_already_queued is false for a PR with no matching queue file -- the exact gap reconciliation exists to catch" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
MAYOR_TICK_QUEUE_DIR="$WORKDIR/qseed-does-not-exist" call pr_already_queued 'https://github.com/example/repo/pull/99' || RC=$?
assert "pr_already_queued is false (not a crash) when the queue directory itself doesn't exist yet" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 9. Bash-3.2 empty-array guard mutation canary. See the
#    comment above the write_state call in main() (mayor-tick.sh) for why
#    the "${ARR[@]+"${ARR[@]}"}" idiom exists at all 8 call sites: macOS
#    ships bash 3.2 as /bin/bash (this script's own shebang target), and
#    3.2's `set -u` treats a *zero-element* array's `[@]` word-expansion as
#    an unbound variable. PR #1414's review proved this had ZERO coverage
#    by reverting all 8 guards to the bare form and confirming the
#    (then-)52-assertion suite still passed in full. This runs the REAL
#    main() against a queue with zero files, a stubbed gh/bd that always
#    report empty, and the isolated single-worktree scratch repo run_full_tick
#    builds -- the one combination that leaves every one of the 8 arrays
#    genuinely zero-length. Revert any one guard and this crashes with
#    "unbound variable" under bash 3.2 before ever reaching write_state
#    (mutation-verified manually before shipping: reverting all 8 produces
#    exactly that crash and a nonzero exit instead of the clean exit 0
#    below).
# ---------------------------------------------------------------------------

STUB_EMPTY_BIN="$WORKDIR/stub-empty-bin"
mkdir -p "$STUB_EMPTY_BIN"
# Always "fail" so every mayor-tick.sh gh/bd call site's own `|| echo
# '<empty-default>'` / `|| true` fallback fires -- simpler and just as
# deterministic as replicating gh's per-call `--jq` post-processing for an
# empty result.
cat > "$STUB_EMPTY_BIN/gh" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
cp "$STUB_EMPTY_BIN/gh" "$STUB_EMPTY_BIN/bd"
chmod +x "$STUB_EMPTY_BIN/gh" "$STUB_EMPTY_BIN/bd"

run_full_tick "$STUB_EMPTY_BIN"
assert "empty queue + empty PR list + empty bd ready: main() completes (exit 0), not an 'unbound variable' bash-3.2 crash" \
  "$([ "$TICK_RC" -eq 0 ] && echo 1 || echo 0)"
assert "...and never prints bash 3.2's 'unbound variable' error (the exact symptom of a reverted array guard)" \
  "$(! printf '%s' "$TICK_OUT" | grep -qi 'unbound variable' && echo 1 || echo 0)"
assert "...and the state file is actually written and valid (execution reached write_state, not an early abort)" \
  "$(jq empty "$TICK_STATE" >/dev/null 2>&1 && echo 1 || echo 0)"
assert "...with every one of the 8 guarded array fields empty, matching the genuinely-empty input state" \
  "$([ "$(jq -c '[.queue_files,.pending_reviews,.merged_prs,.bd_ready_ids,.worktree_anomalies,.gate_exceptions,.pending_non_pr_reviews,.queue_warnings] | map(length) | add' "$TICK_STATE" 2>/dev/null)" = "0" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 9b. dashboard_repo_state's "As of" stamp. The dashboard's hand-written
#     header timestamp used to drift silently (targeted line-edits never
#     bumped it) -- dashboard_repo_state now prepends the tick's own
#     TICK_TIMESTAMP so the AUTO repo-state line is an always-<=15m-fresh
#     freshness indicator. It must be the SAME instant as the state file's
#     .timestamp (both come from one TICK_TIMESTAMP computed once per
#     process), not two independent `date -u` calls a few pipeline steps
#     apart that could disagree -- undermining the "authoritative" claim.
# ---------------------------------------------------------------------------

ISO_RE='[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z'
DASH_REPO_STATE=$(call dashboard_repo_state)
assert "dashboard_repo_state's output embeds an ISO-8601 UTC timestamp" \
  "$(printf '%s' "$DASH_REPO_STATE" | grep -qE "$ISO_RE" && echo 1 || echo 0)"
assert "...stamped as 'As of <ts> (last tick) — Branch ...', not replacing the branch/sha/dirty/sync fields" \
  "$(printf '%s' "$DASH_REPO_STATE" | grep -qE "^As of $ISO_RE \(last tick\) — Branch \`" && echo 1 || echo 0)"

build_scratch_repo
DASH_E2E="$(dirname "$SCRATCH_REPO")/dashboard.md"
cat > "$DASH_E2E" <<'EOF'
# Dashboard

## Repo state
placeholder
EOF
STATE_E2E="$(dirname "$SCRATCH_REPO")/state-repo-state-ts.json"
# MAYOR_TICK_DRY_RUN=0 here (not the usual 1): the dashboard splice's actual
# file write is itself a run_cmd-gated side effect, so a dry run would leave
# $DASH_E2E untouched and this test would only ever be checking the
# "placeholder" fixture text. Safe against this isolated scratch repo (no
# queue files, gh/bd stubbed to fail) the same way the dispatch-marker
# lifecycle test above uses dry_run=0 to observe a real on-disk effect.
# `date` is shadowed so every ISO-stamp call returns a strictly later second
# than the previous one: with independent `date -u` calls the dashboard and
# state-file stamps then ALWAYS differ, instead of agreeing by luck whenever
# both calls land in the same wall-clock second. Non-stamp formats (+%s)
# pass through to the real date.
STUB_DATE_BIN="$WORKDIR/stub-date-bin"
mkdir -p "$STUB_DATE_BIN"
cp "$STUB_EMPTY_BIN"/* "$STUB_DATE_BIN/"
cat > "$STUB_DATE_BIN/date" <<EOF
#!/usr/bin/env bash
case "\$*" in
  *%Y-%m-%dT%H:%M:%SZ*)
    n=\$(cat "$WORKDIR/date-stub-counter" 2>/dev/null || echo 0)
    n=\$(( n + 1 ))
    echo "\$n" > "$WORKDIR/date-stub-counter"
    printf '2026-01-01T00:%02d:%02dZ\n' \$(( n / 60 )) \$(( n % 60 ))
    ;;
  *) exec "$(command -v date)" "\$@" ;;
esac
EOF
chmod +x "$STUB_DATE_BIN/date"
PATH="$STUB_DATE_BIN:$PATH" \
  MAYOR_TICK_QUEUE_DIR="$SCRATCH_REPO/.claude/review-queue" \
  MAYOR_TICK_STATE_FILE="$STATE_E2E" \
  MAYOR_TICK_DASHBOARD_FILE="$DASH_E2E" \
  MAYOR_TICK_DRY_RUN=0 \
  bash "$SCRATCH_REPO/scripts/mayor-tick.sh" __call main >/dev/null 2>&1 || true
DASH_TS=$(grep -oE "$ISO_RE" "$DASH_E2E" | head -1 || true)
STATE_TS=$(jq -r '.timestamp' "$STATE_E2E" 2>/dev/null || true)
assert "dashboard's spliced repo-state timestamp matches the state file's .timestamp from the SAME tick run (single source of truth, not independently-drifting clocks)" \
  "$([ -n "$DASH_TS" ] && [ "$DASH_TS" = "$STATE_TS" ] && echo 1 || echo 0)"
assert "...and the stubbed clock was actually the source of both stamps (guards against the stub being bypassed and the equality passing by wall-clock luck)" \
  "$([ "${DASH_TS:0:10}" = "2026-01-01" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 10. process_review_queue dtype routing, end-to-end through the REAL
#     main() pipeline -- one fixture file per dtype plus one
#     with no frontmatter at all, proving the routing in section 7 actually
#     lands in the write_state fields the mayor reads, not just in
#     route_deliverable's own return value.
# ---------------------------------------------------------------------------

QSEED_DTYPE="$WORKDIR/qseed-dtype-routing"
mkdir -p "$QSEED_DTYPE"
printf -- '---\ndeliverable_type: pr\ndeliverable_ref: https://github.com/example/repo/pull/100\nqueued_at: 2026-01-01T00-00-00Z\n---\nbody\n' > "$QSEED_DTYPE/pr-100.md"
printf -- '---\ndeliverable_type: findings\ndeliverable_ref: mayor-abc1\nqueued_at: 2026-01-01T00-00-00Z\n---\nbody\n' > "$QSEED_DTYPE/findings-1.md"
printf -- '---\ndeliverable_type: bead-close\ndeliverable_ref: mayor-abc2\nqueued_at: 2026-01-01T00-00-00Z\n---\nbody\n' > "$QSEED_DTYPE/bead-close-1.md"
printf -- '---\ndeliverable_type: bead-supersede\ndeliverable_ref: mayor-abc3\nqueued_at: 2026-01-01T00-00-00Z\n---\nbody\n' > "$QSEED_DTYPE/bead-supersede-1.md"
printf -- '---\ndeliverable_type: mystery\ndeliverable_ref: mayor-abc4\nqueued_at: 2026-01-01T00-00-00Z\n---\nbody\n' > "$QSEED_DTYPE/unknown-1.md"
printf 'this file has no frontmatter markers at all\n' > "$QSEED_DTYPE/malformed.md"

run_full_tick "$STUB_EMPTY_BIN" "$QSEED_DTYPE"
assert "pr dtype (gh reports no review yet): PR number lands in pending_reviews" \
  "$([ "$(jq -r '.pending_reviews | index(100) != null' "$TICK_STATE")" = "true" ] && echo 1 || echo 0)"
assert "findings/bead-close/bead-supersede dtypes: all three land in pending_non_pr_reviews with their real deliverable_type+ref, not dropped" \
  "$([ "$(jq -c '[.pending_non_pr_reviews[] | .deliverable_type] | sort' "$TICK_STATE")" = '["bead-close","bead-supersede","findings"]' ] && echo 1 || echo 0)"
assert "an unrecognized dtype ('mystery') surfaces in queue_warnings naming the actual dtype, not silently dropped" \
  "$([ "$(jq -r '.queue_warnings[] | select(.file | endswith("unknown-1.md")) | .deliverable_type' "$TICK_STATE")" = "mystery" ] && echo 1 || echo 0)"
assert "a totally malformed (no frontmatter) file is still handled correctly: surfaced in queue_warnings, not a crash" \
  "$([ "$(jq -r '[.queue_warnings[] | select(.file | endswith("malformed.md"))] | length' "$TICK_STATE")" -ge 1 ] && echo 1 || echo 0)"
assert "every queue file (even the malformed one) stays visible in queue_files, so exit_code reflects it" \
  "$([ "$(jq -r '.queue_files | length' "$TICK_STATE")" = "6" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 11. Self-heal reconciliation: an open worker PR with no
#     review-queue entry at all gets synthesized into pending_reviews, and
#     a PR that already HAS an active queue entry does not get
#     double-queued. Runs the REAL main() (reconcile_missing_queue_entries
#     is not itself network-free, so this is the only way to prove its
#     effect on the actual state file the mayor reads) against a stub `gh`
#     that reports one open worker/agent-* PR (#4242) with no reviews.
# ---------------------------------------------------------------------------

STUB_PR_BIN="$WORKDIR/stub-pr-bin"
mkdir -p "$STUB_PR_BIN"
# Canned single open worker PR (#4242, DIRTY so gate_and_merge_prs skips it
# without a review lookup) + empty reviews for any `pr view` call -- applies
# the real `--jq` filter argument (if present) via jq, so this one fixture
# answers every shape of `gh pr list`/`gh pr view` this script uses.
cat > "$STUB_PR_BIN/gh" <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *" view "* ]]; then
  base='{"reviews":[]}'
else
  base='[{"number":4242,"url":"https://github.com/example/repo/pull/4242","headRefName":"worker/agent-reconcile-test","mergeStateStatus":"DIRTY","statusCheckRollup":[]}]'
fi
jq_filter=""
prev=""
for a in "$@"; do
  [ "$prev" = "--jq" ] && jq_filter="$a"
  prev="$a"
done
if [ -n "$jq_filter" ]; then
  printf '%s' "$base" | jq "$jq_filter"
else
  printf '%s' "$base"
fi
EOF
cat > "$STUB_PR_BIN/bd" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$STUB_PR_BIN/gh" "$STUB_PR_BIN/bd"

run_full_tick "$STUB_PR_BIN"
assert "an open worker PR with no review-queue entry and no review is synthesized into pending_reviews after one tick" \
  "$([ "$(jq -r '.pending_reviews | index(4242) != null' "$TICK_STATE")" = "true" ] && echo 1 || echo 0)"
assert "...and the resulting exit_code is 20 (not silently 0) -- pending_reviews alone doesn't wake the mayor if exit_code stays 0" \
  "$([ "$TICK_RC" -eq 20 ] && echo 1 || echo 0)"
assert "...reconciliation logs with the distinct 'mayor-tick reconcile:' label so audits can tell script-detected from hook-queued" \
  "$(printf '%s' "$TICK_OUT" | grep -q 'mayor-tick reconcile:' && echo 1 || echo 0)"

QSEED_ALREADY_QUEUED="$WORKDIR/qseed-already-queued-pr"
mkdir -p "$QSEED_ALREADY_QUEUED"
printf -- '---\ndeliverable_type: pr\ndeliverable_ref: https://github.com/example/repo/pull/4242\nqueued_at: 2020-01-01T00-00-00Z\n---\nbody\n' > "$QSEED_ALREADY_QUEUED/pr-4242.md"

run_full_tick "$STUB_PR_BIN" "$QSEED_ALREADY_QUEUED"
assert "a PR already covered by an active queue file is NOT double-queued by reconciliation (appears exactly once)" \
  "$([ "$(jq -c '.pending_reviews' "$TICK_STATE")" = "[4242]" ] && echo 1 || echo 0)"
assert "...and reconciliation does not even log a synthesis message for a PR that's already queued" \
  "$(! printf '%s' "$TICK_OUT" | grep -q 'mayor-tick reconcile:' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 12. Self-heal reconciliation's OTHER skip branch: a PR with
#     NO active queue file but a critical-reviewer review ALREADY submitted
#     (mayor-tick.sh:570-573) must not be re-synthesized into pending_reviews
#     -- re-queuing an already-reviewed PR would waste a second reviewer
#     dispatch on a PR the mayor can just merge (or already merged/rejected).
#     pr_already_queued() only covers the active-queue-file case (section 11
#     above); this is the review-history case, previously uncovered --
#     deleting this branch left all other assertions green (reviewer
#     confirmed empirically), which is exactly what this test now closes.
# ---------------------------------------------------------------------------

STUB_PR_REVIEWED_BIN="$WORKDIR/stub-pr-reviewed-bin"
mkdir -p "$STUB_PR_REVIEWED_BIN"
# Canned single open worker PR (#4343, DIRTY so gate_and_merge_prs skips it
# without a merge attempt, isolating this test to reconciliation) whose
# `pr view --json reviews` already carries a critical-reviewer LGTM.
cat > "$STUB_PR_REVIEWED_BIN/gh" <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *" view "* ]]; then
  base='{"reviews":[{"body":"## critical-reviewer findings\n**Verdict**: LGTM","submittedAt":"2026-01-01T00:00:00Z"}]}'
else
  base='[{"number":4343,"url":"https://github.com/example/repo/pull/4343","headRefName":"worker/agent-reviewed-test","mergeStateStatus":"DIRTY","statusCheckRollup":[]}]'
fi
jq_filter=""
prev=""
for a in "$@"; do
  [ "$prev" = "--jq" ] && jq_filter="$a"
  prev="$a"
done
if [ -n "$jq_filter" ]; then
  printf '%s' "$base" | jq "$jq_filter"
else
  printf '%s' "$base"
fi
EOF
cat > "$STUB_PR_REVIEWED_BIN/bd" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$STUB_PR_REVIEWED_BIN/gh" "$STUB_PR_REVIEWED_BIN/bd"

run_full_tick "$STUB_PR_REVIEWED_BIN"
assert "a PR with no queue file but an already-submitted critical-reviewer review is NOT synthesized into pending_reviews" \
  "$([ "$(jq -r '.pending_reviews | index(4343) != null' "$TICK_STATE")" = "false" ] && echo 1 || echo 0)"
assert "...and reconciliation does not log a synthesis message for it either -- the skip is silent by design" \
  "$(! printf '%s' "$TICK_OUT" | grep -q 'mayor-tick reconcile:.*4343' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 13. In-flight awareness -- pure building blocks. Worktree anomalies and
#     pending_reviews are DIFFERENT problems and must NOT share a design:
#     a young worktree really is probably a healthy in-flight dispatch, so
#     AGE is the right signal there. But dispatch happens ONLY via
#     pending_reviews (see the mayor's own bootstrap doc), so a brand-new
#     queue entry's age is always near zero -- an age gate would misread
#     "just queued, nobody has dispatched a reviewer yet" as "already
#     dispatched, still running", delaying every entry's first dispatch by
#     a full tick. The discriminator there has to be dispatch STATE (a
#     marker this script itself stamps), not elapsed time.
# ---------------------------------------------------------------------------

NOW_EPOCH=$(date -u +%s)

# queue_entry_dispatch_suppressed: no marker at all is the FIRST-SIGHTING
# case and must NEVER be suppressed -- this is the exact bug an age-only
# gate had (a fresh entry's age is ~0, indistinguishable from "recently
# dispatched"). Getting this backwards silently delays every entry's first
# dispatch by a full tick, since dispatch happens only via pending_reviews.
RC=0
call queue_entry_dispatch_suppressed '' "$NOW_EPOCH" || RC=$?
assert "no dispatch marker at all (first sighting) is never suppressed -- it must surface immediately, since nothing else dispatches a reviewer" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# A marker stamped 2 minutes ago is still fresh -- the mayor plausibly
# dispatched a reviewer last tick and it's still running; re-surfacing now
# risks a second dispatch racing the first.
RC=0
call queue_entry_dispatch_suppressed "$(( NOW_EPOCH - 120 ))" "$NOW_EPOCH" || RC=$?
assert "a dispatch marker stamped 2 minutes ago suppresses re-surfacing -- a reviewer was plausibly just dispatched and is still running" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

# A marker stamped 20 minutes ago has outlived the 15m backstop -- the
# earlier presumed dispatch is treated as dead (crashed reviewer, or the
# mayor never actually acted on the prior listing) and the entry surfaces
# again rather than staying hidden forever.
RC=0
call queue_entry_dispatch_suppressed "$(( NOW_EPOCH - 1200 ))" "$NOW_EPOCH" || RC=$?
assert "a dispatch marker older than the backstop no longer suppresses -- a marked-but-dead dispatch must not hide the PR forever" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# is_live_agent_branch / agent_id_is_live: the ONLY reliable liveness
# signal for an in-process worker sub-agent -- a sub-agent cannot call
# ListAgents on itself, and `claude agents --json` doesn't enumerate
# in-process subagents (both confirmed directly). This replaces the old
# wall-clock/commit-epoch window entirely: for a worker that hasn't
# committed yet, "age since last commit" measured the BASE commit's time,
# not the worker's own dispatch time, so a live worker could flip to
# "stale" while genuinely still running, regardless of window size.
RC=0
call is_live_agent_branch 'worker/agent-abc123' 'abc123' || RC=$?
assert "a worker/agent-<id> branch whose id is the sole entry in --live-agents is classified in-flight -- a healthy dispatch must not trip exit 30" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'worker/agent-abc123' 'xyz999,abc123,def456' || RC=$?
assert "a worker/agent-<id> branch whose id is ANY entry in a comma-separated --live-agents list is classified in-flight, not just when it's the sole entry" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'worker/agent-gone999' 'abc123,def456' || RC=$?
assert "a worker/agent-<id> branch whose id is NOT in --live-agents is classified stale/reapable -- a genuinely stalled or crashed dispatch must still surface" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'worker/agent-abc123' '' || RC=$?
assert "an empty --live-agents set (the flag omitted) never classifies any branch as in-flight -- fail-toward-surfacing default, since an unknown agent must never be assumed live" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'main' 'main' || RC=$?
assert "a non-worker/agent-* branch name never matches, even if it coincidentally equals a --live-agents entry" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# --live-agents entries given as agent-<id> or worker/agent-<id> must still
# match: a mismatch reports live workers as stalled (exit 30).
for LIVE_FORM in 'abc123' 'agent-abc123' 'worker/agent-abc123' 'xyz999, agent-abc123' 'xyz999, worker/agent-abc123'; do
  RC=0
  call is_live_agent_branch 'worker/agent-abc123' "$LIVE_FORM" || RC=$?
  assert "--live-agents entry form '${LIVE_FORM}' classifies worker/agent-abc123 in-flight -- a prefixed id must not make a live worker look stalled" \
    "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"
done

RC=0
call is_live_agent_branch 'worker/agent-gone999' 'agent-abc123,worker/agent-def456' || RC=$?
assert "prefixed --live-agents entries still do not match an unrelated worker branch" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# Whitespace-tolerant --live-agents membership match. A comma-space-joined
# list (e.g. "a, b, c") must protect EVERY id, not just the first --
# without normalization, the naive ",${live_agents}," substring match
# leaves a leading space on every id after the first, so only the first id
# ever matches and every subsequent live worker's branch would misreport
# as stale/reapable (exit 30) even though its agent is confirmed running.
RC=0
call agent_id_is_live 'abc123' 'abc123, def456, ghi789' || RC=$?
assert "sanity: a comma-space-joined --live-agents list protects the FIRST id" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call agent_id_is_live 'def456' 'abc123, def456, ghi789' || RC=$?
assert "...and it protects the MIDDLE id too -- fails without normalization, since \", \" leaves the id as \" def456\", which never equals the bare \"def456\" the substring match searches for" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call agent_id_is_live 'ghi789' 'abc123, def456, ghi789' || RC=$?
assert "...and it protects the LAST id too, proving every id in a comma-space-joined list is protected, not just the first" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'worker/agent-def456' 'abc123, def456, ghi789' || RC=$?
assert "the same whitespace tolerance holds at the worktree-anomaly branch-guard level (is_live_agent_branch) -- this is what actually keeps a live worker's branch from tripping exit 30" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 14. pending_reviews dispatch-marker lifecycle, end-to-end through the
#     REAL main() pipeline against a REAL queue dir (MAYOR_TICK_DRY_RUN=0,
#     not run_full_tick's always-dry-run wrapper -- dry-run would never
#     actually stamp a marker on disk, so proving marker persistence
#     ACROSS ticks needs a real filesystem). Uses STUB_EMPTY_BIN (every
#     gh/bd call fails) so this exercises no real network or git mutation
#     beyond this script's own queue-dir/marker bookkeeping -- see
#     build_scratch_repo/invoke_tick's isolation guarantees above.
# ---------------------------------------------------------------------------

build_scratch_repo
QUEUED_AT_NOW=$(date -u +%Y-%m-%dT%H-%M-%SZ)
printf -- '---\ndeliverable_type: pr\ndeliverable_ref: https://github.com/example/repo/pull/5101\nqueued_at: %s\n---\nbody\n' "$QUEUED_AT_NOW" > "$SCRATCH_REPO/.claude/review-queue/pr-5101.md"

STATE_MARKER_1="$WORKDIR/state-marker-1.json"
invoke_tick "$STUB_EMPTY_BIN" "$SCRATCH_REPO" 0 "$STATE_MARKER_1"
assert "a brand-new queue entry (age ~0, no dispatch marker yet) surfaces in pending_reviews on its FIRST sighting -- an age-based gate would silently delay this first dispatch by a full tick, since dispatch happens only via pending_reviews" \
  "$([ "$(jq -r '.pending_reviews | index(5101) != null' "$STATE_MARKER_1")" = "true" ] && echo 1 || echo 0)"

MARKER_FILE=$(MAYOR_TICK_QUEUE_DIR="$SCRATCH_REPO/.claude/review-queue" call dispatch_marker_path "$SCRATCH_REPO/.claude/review-queue/pr-5101.md")
assert "tick 1 actually stamped a dispatch marker on disk -- the mechanism tick 2's suppression below depends on" \
  "$([ -f "$MARKER_FILE" ] && echo 1 || echo 0)"

STATE_MARKER_2="$WORKDIR/state-marker-2.json"
invoke_tick "$STUB_EMPTY_BIN" "$SCRATCH_REPO" 0 "$STATE_MARKER_2"
assert "the SAME entry, on the very next tick with the review still not posted, is suppressed -- the dispatch marker from tick 1 is still fresh, so re-surfacing risks the mayor dispatching a second reviewer that races the first" \
  "$([ "$(jq -r '.pending_reviews | index(5101) != null' "$STATE_MARKER_2")" = "false" ] && echo 1 || echo 0)"

# Backdate the marker past the backstop to simulate a dead/never-acted-on
# dispatch, without waiting 15 real minutes.
printf '%s' "$(( $(date -u +%s) - 1200 ))" > "$MARKER_FILE"

STATE_MARKER_3="$WORKDIR/state-marker-3.json"
invoke_tick "$STUB_EMPTY_BIN" "$SCRATCH_REPO" 0 "$STATE_MARKER_3"
assert "once the dispatch marker ages past the backstop with the review still not posted, the entry surfaces again -- a marked-but-dead dispatch must not hide the PR forever" \
  "$([ "$(jq -r '.pending_reviews | index(5101) != null' "$STATE_MARKER_3")" = "true" ] && echo 1 || echo 0)"

# A queue entry's OWN posted age is irrelevant to first-sighting
# suppression -- only marker presence matters. An entry queued long ago but
# never before examined by this script (no marker exists yet) must still
# surface immediately, not be mistaken for "already handled" just because
# its queued_at is old.
QSEED_STALLED="$WORKDIR/qseed-review-stalled"
mkdir -p "$QSEED_STALLED"
printf -- '---\ndeliverable_type: pr\ndeliverable_ref: https://github.com/example/repo/pull/5002\nqueued_at: 2026-01-01T00-00-00Z\n---\nbody\n' > "$QSEED_STALLED/pr-5002.md"

run_full_tick "$STUB_EMPTY_BIN" "$QSEED_STALLED"
assert "a queue entry with an old queued_at but no dispatch marker yet still surfaces on first sighting -- the entry's own posted age is not the discriminator, marker presence is" \
  "$([ "$(jq -r '.pending_reviews | index(5002) != null' "$TICK_STATE")" = "true" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 15. Worktree-anomaly liveness classification, end-to-end through the REAL
#     main() pipeline against a real second git worktree on a
#     worker/agent-<id> branch -- proves check_worktree_anomalies keys
#     in-flight/stale purely off --live-agents membership (the mayor's
#     ListAgents-derived set), not commit age. The old wall-clock-window
#     design measured a no-commit worker's BASE commit time, not its
#     dispatch time -- reverting to that could flip a genuinely live
#     worker to "stale" well within its own working window, exactly the
#     bug this fix closes.
# ---------------------------------------------------------------------------

run_full_tick "$STUB_EMPTY_BIN" "" "live-test-agent" "live-test-agent"
assert "a worker/agent-<id> branch with no PR, whose id IS in --live-agents, does not return exit 30 -- it's a confirmed-live dispatch, not a stalled one" \
  "$([ "$TICK_RC" -ne 30 ] && echo 1 || echo 0)"
assert "...and it still appears in worktree_anomalies for visibility (not silently dropped), tagged in-flight" \
  "$([ "$(jq -r '[.worktree_anomalies[] | select(.branch == "worker/agent-live-test-agent" and .reason == "no-pr-for-branch-in-flight")] | length' "$TICK_STATE")" -ge 1 ] && echo 1 || echo 0)"

run_full_tick "$STUB_EMPTY_BIN" "" "stale-test-agent" ""
assert "a worker/agent-<id> branch with no PR, whose id is NOT in --live-agents, returns exit 30 -- this is the fail-toward-surfacing default that replaces the old 45-minute grace window entirely" \
  "$([ "$TICK_RC" -eq 30 ] && echo 1 || echo 0)"
assert "...and it's tagged genuinely stale (no-pr-for-branch), not in-flight -- what worktree-hygiene.sh's destructive steps ultimately act on" \
  "$([ "$(jq -r '[.worktree_anomalies[] | select(.branch == "worker/agent-stale-test-agent" and .reason == "no-pr-for-branch")] | length' "$TICK_STATE")" -ge 1 ] && echo 1 || echo 0)"

run_full_tick "$STUB_EMPTY_BIN" "" "two" "one,two,three"
assert "a --live-agents value with multiple comma-separated ids correctly matches the worker's id even when it isn't first or last in the list" \
  "$([ "$TICK_RC" -ne 30 ] && echo 1 || echo 0)"

run_full_tick "$STUB_EMPTY_BIN" "" "two" "one, two, three"
assert "the SAME multi-id match still succeeds through the full main() pipeline when the mayor's --live-agents value is comma-SPACE joined -- a live worker in the middle of the list must not misreport exit 30 (stale) just because of list formatting" \
  "$([ "$TICK_RC" -ne 30 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 16. Stale-blocking-verdict reconcile -- pure-function building blocks.
#     verdict_is_blocking/has_commit_after are what let
#     reconcile_missing_queue_entries tell "fixed but never re-reviewed"
#     (queue a re-review) apart from "reviewed, nothing has changed since"
#     (leave it alone) and "already cleared" (leave it alone).
# ---------------------------------------------------------------------------

RC=0
call verdict_is_blocking needs-changes || RC=$?
assert "needs-changes blocks the gate (a self-heal target)" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"
RC=0
call verdict_is_blocking needs-discussion || RC=$?
assert "needs-discussion blocks the gate too (a self-heal target)" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"
RC=0
call verdict_is_blocking LGTM || RC=$?
assert "LGTM does not block the gate -- nothing to self-heal" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"
RC=0
call verdict_is_blocking LGTM-with-suggestions || RC=$?
assert "LGTM-with-suggestions does not block the gate -- nothing to self-heal" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"
RC=0
call verdict_is_blocking "" || RC=$?
assert "an empty/malformed verdict is treated as non-blocking, not a false self-heal trigger" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

COMMITS_AFTER='[{"oid":"a","committedDate":"2026-08-24T12:43:45Z"}]'
RC=0
call has_commit_after "$COMMITS_AFTER" "2026-08-24T12:25:12Z" || RC=$?
assert "a commit landed after the review's submittedAt is detected -- the discriminator for 'fixed but never re-reviewed'" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

COMMITS_BEFORE='[{"oid":"a","committedDate":"2026-08-24T12:00:00Z"}]'
RC=0
call has_commit_after "$COMMITS_BEFORE" "2026-08-24T12:25:12Z" || RC=$?
assert "no commit after the review's submittedAt -- nothing has changed since the blocking verdict, so nothing to re-review" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 17. Stale-blocking-verdict reconcile, end-to-end through the REAL main()
#     pipeline. This is the reconcile gap: a PR reviewed with a blocking
#     verdict, then fixed, previously sat invisible forever because
#     reconcile's old check only fired on "no review at all" -- ANY review,
#     even a stale blocking one, made it `continue`.
# ---------------------------------------------------------------------------

# Case A: blocking verdict + a commit landed after it -- the exact
# "fixed but never re-reviewed" gap. Must be queued.
STUB_STALE_BLOCKING_FIXED="$WORKDIR/stub-stale-blocking-fixed"
mkdir -p "$STUB_STALE_BLOCKING_FIXED"
cat > "$STUB_STALE_BLOCKING_FIXED/gh" <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *" view "* ]]; then
  if [[ " $* " == *"commits"* ]]; then
    base='{"commits":[{"oid":"deadbeef","committedDate":"2026-08-24T12:43:45Z"}]}'
  else
    base='{"reviews":[{"body":"## critical-reviewer findings\n**Verdict**: needs-changes","submittedAt":"2026-08-24T12:25:12Z","state":"COMMENTED"}]}'
  fi
else
  base='[{"number":6001,"url":"https://github.com/example/repo/pull/6001","headRefName":"worker/agent-stale-blocking-fixed","mergeStateStatus":"DIRTY","statusCheckRollup":[]}]'
fi
jq_filter=""
prev=""
for a in "$@"; do
  [ "$prev" = "--jq" ] && jq_filter="$a"
  prev="$a"
done
if [ -n "$jq_filter" ]; then
  printf '%s' "$base" | jq "$jq_filter"
else
  printf '%s' "$base"
fi
EOF
cat > "$STUB_STALE_BLOCKING_FIXED/bd" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$STUB_STALE_BLOCKING_FIXED/gh" "$STUB_STALE_BLOCKING_FIXED/bd"

run_full_tick "$STUB_STALE_BLOCKING_FIXED"
assert "a PR with a stale blocking verdict AND a commit landed after it is queued for re-review -- the fix earned another look, but nothing would ever trigger it otherwise" \
  "$([ "$(jq -r '.pending_reviews | index(6001) != null' "$TICK_STATE")" = "true" ] && echo 1 || echo 0)"
assert "...and reconciliation logs the distinct stale-verdict reason, not the generic no-review-at-all message" \
  "$(printf '%s' "$TICK_OUT" | grep -q 'stale needs-changes verdict' && echo 1 || echo 0)"

# Case B: same blocking verdict, but NO commit landed after it -- nothing
# has changed for a reviewer to look at. Must NOT be queued.
STUB_STALE_BLOCKING_UNFIXED="$WORKDIR/stub-stale-blocking-unfixed"
mkdir -p "$STUB_STALE_BLOCKING_UNFIXED"
cat > "$STUB_STALE_BLOCKING_UNFIXED/gh" <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *" view "* ]]; then
  if [[ " $* " == *"commits"* ]]; then
    base='{"commits":[{"oid":"deadbeef","committedDate":"2026-08-24T12:00:00Z"}]}'
  else
    base='{"reviews":[{"body":"## critical-reviewer findings\n**Verdict**: needs-changes","submittedAt":"2026-08-24T12:25:12Z","state":"COMMENTED"}]}'
  fi
else
  base='[{"number":6002,"url":"https://github.com/example/repo/pull/6002","headRefName":"worker/agent-stale-blocking-unfixed","mergeStateStatus":"DIRTY","statusCheckRollup":[]}]'
fi
jq_filter=""
prev=""
for a in "$@"; do
  [ "$prev" = "--jq" ] && jq_filter="$a"
  prev="$a"
done
if [ -n "$jq_filter" ]; then
  printf '%s' "$base" | jq "$jq_filter"
else
  printf '%s' "$base"
fi
EOF
cat > "$STUB_STALE_BLOCKING_UNFIXED/bd" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$STUB_STALE_BLOCKING_UNFIXED/gh" "$STUB_STALE_BLOCKING_UNFIXED/bd"

run_full_tick "$STUB_STALE_BLOCKING_UNFIXED"
assert "a PR with a blocking verdict and NO commit after it is NOT queued -- nothing has changed for the reviewer to look at" \
  "$([ "$(jq -r '.pending_reviews | index(6002) != null' "$TICK_STATE")" = "false" ] && echo 1 || echo 0)"

# Case C: latest verdict is non-blocking (LGTM), with a commit after it
# too -- must be left alone regardless of commit timing, since a
# non-blocking verdict was never something to self-heal in the first
# place.
STUB_NON_BLOCKING_WITH_COMMIT="$WORKDIR/stub-non-blocking-with-commit"
mkdir -p "$STUB_NON_BLOCKING_WITH_COMMIT"
cat > "$STUB_NON_BLOCKING_WITH_COMMIT/gh" <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *" view "* ]]; then
  if [[ " $* " == *"commits"* ]]; then
    base='{"commits":[{"oid":"deadbeef","committedDate":"2026-08-24T12:43:45Z"}]}'
  else
    base='{"reviews":[{"body":"## critical-reviewer findings\n**Verdict**: LGTM","submittedAt":"2026-08-24T12:25:12Z","state":"COMMENTED"}]}'
  fi
else
  base='[{"number":6003,"url":"https://github.com/example/repo/pull/6003","headRefName":"worker/agent-non-blocking-with-commit","mergeStateStatus":"DIRTY","statusCheckRollup":[]}]'
fi
jq_filter=""
prev=""
for a in "$@"; do
  [ "$prev" = "--jq" ] && jq_filter="$a"
  prev="$a"
done
if [ -n "$jq_filter" ]; then
  printf '%s' "$base" | jq "$jq_filter"
else
  printf '%s' "$base"
fi
EOF
cat > "$STUB_NON_BLOCKING_WITH_COMMIT/bd" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$STUB_NON_BLOCKING_WITH_COMMIT/gh" "$STUB_NON_BLOCKING_WITH_COMMIT/bd"

run_full_tick "$STUB_NON_BLOCKING_WITH_COMMIT"
assert "a PR whose latest verdict is non-blocking (LGTM) is untouched by reconcile even with a later commit -- there was never a blocking verdict to clear" \
  "$([ "$(jq -r '.pending_reviews | index(6003) != null' "$TICK_STATE")" = "false" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 18. Requeue-loop guard: reconcile writes a REAL queue file for case A
#     (not just an in-memory pending_reviews entry) specifically so
#     pr_already_queued's existing no-double-queue guard also covers this
#     branch -- without it, a blocking-verdict-plus-later-commit PR would
#     be re-queued on EVERY tick until a re-review actually posts, which is
#     exactly the second-reviewer-dispatch race section 14 guards against
#     for the hook-fed path. Runs reconcile directly (not through
#     run_full_tick's MAYOR_TICK_DRY_RUN=1) against a real queue dir so the
#     written file can be inspected and reconcile can be invoked a second
#     time against its own output.
# ---------------------------------------------------------------------------

QDIR_LOOP_GUARD="$WORKDIR/qdir-loop-guard"
mkdir -p "$QDIR_LOOP_GUARD"

run_reconcile_real() {  # $1 = queue dir (real, not dry-run)
  MAYOR_TICK_QUEUE_DIR="$1" MAYOR_TICK_DRY_RUN=0 \
    PATH="$STUB_STALE_BLOCKING_FIXED:$PATH" \
    call reconcile_missing_queue_entries
}

OUT1=$(run_reconcile_real "$QDIR_LOOP_GUARD" 2>&1)
COUNT_AFTER_FIRST=$(find "$QDIR_LOOP_GUARD" -maxdepth 1 -name '*.md' -type f | wc -l | tr -d ' ')
assert "the first reconcile pass on a stale-blocking-plus-later-commit PR writes exactly one real queue file (not just an in-memory pending_reviews entry)" \
  "$([ "$COUNT_AFTER_FIRST" = "1" ] && echo 1 || echo 0)"

OUT2=$(run_reconcile_real "$QDIR_LOOP_GUARD" 2>&1)
COUNT_AFTER_SECOND=$(find "$QDIR_LOOP_GUARD" -maxdepth 1 -name '*.md' -type f | wc -l | tr -d ' ')
assert "a second reconcile pass against the SAME unchanged PR does not write a second queue file -- pr_already_queued now sees the file from pass one" \
  "$([ "$COUNT_AFTER_SECOND" = "1" ] && echo 1 || echo 0)"
assert "...and the second pass does not even log a new queuing message -- pr_already_queued short-circuits before reconcile re-evaluates the verdict" \
  "$(! printf '%s' "$OUT2" | grep -q 'queuing re-review' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 19. True-concurrency collision guard. Section 18 above only proves the
#     SEQUENTIAL case (pr_already_queued sees the first run's file before a
#     second run starts) -- it doesn't cover two mayor-tick.sh processes
#     that BOTH pass that check before either has written anything, which
#     is the actual race: this script runs on a 15m cron AND can be
#     invoked inline on a task notification, so genuine overlap is real,
#     not hypothetical.
# ---------------------------------------------------------------------------

# _write_file_contents_if_absent is the atomicity primitive itself: the
# first writer must win and the file's content must be ITS content, never
# silently clobbered by a second racing writer.
RACE_FILE="$WORKDIR/race-file.md"
RC=0
call _write_file_contents_if_absent "$RACE_FILE" "first writer" || RC=$?
assert "the first call to the atomic create-if-absent write succeeds" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call _write_file_contents_if_absent "$RACE_FILE" "second writer (simulating a racing overlapping mayor-tick.sh run)" || RC=$?
assert "a second racing call to the same path fails instead of clobbering the first writer's content -- this is what stops two overlapping mayor-tick.sh runs from both succeeding at writing a duplicate reconcile entry" \
  "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
assert "...and the file on disk still holds the FIRST writer's content, proving noclobber genuinely blocked the second write rather than erroring after writing anyway" \
  "$([ "$(cat "$RACE_FILE")" = "first writer" ] && echo 1 || echo 0)"

# The atomicity primitive above only matters if two racing processes
# compute the SAME path to collide on in the first place -- a wall-clock
# timestamp in the filename would let each racing run pick a different
# name and never even engage the guard. Confirm reconcile's actual naming
# is deterministic: two independent runs against the identical PR/review
# fixture (same PR number, same submittedAt) must produce the same
# basename.
QDIR_DETERMINISM_A="$WORKDIR/qdir-determinism-a"
QDIR_DETERMINISM_B="$WORKDIR/qdir-determinism-b"
mkdir -p "$QDIR_DETERMINISM_A" "$QDIR_DETERMINISM_B"
MAYOR_TICK_QUEUE_DIR="$QDIR_DETERMINISM_A" MAYOR_TICK_DRY_RUN=0 \
  PATH="$STUB_STALE_BLOCKING_FIXED:$PATH" call reconcile_missing_queue_entries >/dev/null 2>&1
MAYOR_TICK_QUEUE_DIR="$QDIR_DETERMINISM_B" MAYOR_TICK_DRY_RUN=0 \
  PATH="$STUB_STALE_BLOCKING_FIXED:$PATH" call reconcile_missing_queue_entries >/dev/null 2>&1
NAME_A=$(basename "$(find "$QDIR_DETERMINISM_A" -maxdepth 1 -name '*.md' -type f)")
NAME_B=$(basename "$(find "$QDIR_DETERMINISM_B" -maxdepth 1 -name '*.md' -type f)")
assert "the reconcile queue filename is deterministic (PR number + the review's own submittedAt), not wall-clock-based -- two independent runs against the identical PR/review state compute the SAME name, which is what lets the noclobber guard actually engage across genuinely overlapping processes" \
  "$([ -n "$NAME_A" ] && [ "$NAME_A" = "$NAME_B" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 20. Draft-PR skip, end-to-end through the REAL gate_and_merge_prs (not
#     just the pure pr_gate_eligible check above): a CLEAN worker/agent-*
#     PR with an LGTM verdict AND isDraft=true must never reach `gh pr
#     merge`. Before this fix, GitHub's own rejection of a draft-merge
#     attempt ("Pull request is a draft") would abort the whole tick under
#     `set -e` with an unhandled exit code outside the 0/10/20/30 contract.
# ---------------------------------------------------------------------------

STUB_PR_DRAFT_BIN="$WORKDIR/stub-pr-draft-bin"
mkdir -p "$STUB_PR_DRAFT_BIN"
# Canned single open worker PR (#4444), CLEAN with an LGTM review but
# isDraft=true -- the exact shape observed to slip past a mss-only check.
cat > "$STUB_PR_DRAFT_BIN/gh" <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *" view "* ]]; then
  base='{"reviews":[{"body":"## critical-reviewer findings\n**Verdict**: LGTM","submittedAt":"2026-01-01T00:00:00Z"}]}'
else
  base='[{"number":4444,"url":"https://github.com/example/repo/pull/4444","headRefName":"worker/agent-draft-test","mergeStateStatus":"CLEAN","statusCheckRollup":[],"isDraft":true}]'
fi
jq_filter=""
prev=""
for a in "$@"; do
  [ "$prev" = "--jq" ] && jq_filter="$a"
  prev="$a"
done
if [ -n "$jq_filter" ]; then
  printf '%s' "$base" | jq "$jq_filter"
else
  printf '%s' "$base"
fi
EOF
cat > "$STUB_PR_DRAFT_BIN/bd" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$STUB_PR_DRAFT_BIN/gh" "$STUB_PR_DRAFT_BIN/bd"

run_full_tick "$STUB_PR_DRAFT_BIN"
assert "a draft PR is never enqueued via gh pr merge, even with a CLEAN mergeStateStatus and an LGTM verdict" \
  "$(! printf '%s' "$TICK_OUT" | grep -q 'would run: gh pr merge 4444' && echo 1 || echo 0)"
assert "...and the tick exits with a normal in-contract code (not an unhandled error from a rejected draft-merge attempt)" \
  "$([ "$TICK_RC" -eq 0 ] || [ "$TICK_RC" -eq 10 ] || [ "$TICK_RC" -eq 20 ] || [ "$TICK_RC" -eq 30 ] && echo 1 || echo 0)"

# Dry-run above masks GitHub's real rejection, so repeat with dry-run OFF and
# a gh whose `pr merge` fails exactly like GitHub does for a draft. If the
# draft guard regresses, the real merge call runs, exits 1 and (under set -e)
# aborts the tick outside the 0/10/20/30 contract.
STUB_PR_DRAFT_REAL_BIN="$WORKDIR/stub-pr-draft-real-bin"
MERGE_CALLS="$WORKDIR/draft-real-merge-calls"
mkdir -p "$STUB_PR_DRAFT_REAL_BIN"
: > "$MERGE_CALLS"
cp "$STUB_PR_DRAFT_BIN/bd" "$STUB_PR_DRAFT_REAL_BIN/bd"
{
  echo '#!/usr/bin/env bash'
  echo 'if [[ " $* " == *" pr merge "* ]]; then'
  echo "  echo \"\$*\" >> \"$MERGE_CALLS\""
  echo '  echo "Pull request is a draft and cannot be merged" >&2'
  echo '  exit 1'
  echo 'fi'
  tail -n +2 "$STUB_PR_DRAFT_BIN/gh"
} > "$STUB_PR_DRAFT_REAL_BIN/gh"
chmod +x "$STUB_PR_DRAFT_REAL_BIN/gh" "$STUB_PR_DRAFT_REAL_BIN/bd"

build_scratch_repo
pushd "$SCRATCH_REPO" >/dev/null
invoke_tick "$STUB_PR_DRAFT_REAL_BIN" "$SCRATCH_REPO" 0
popd >/dev/null
assert "a draft PR never reaches a real gh pr merge call (non-dry-run)" \
  "$([ ! -s "$MERGE_CALLS" ] && echo 1 || echo 0)"
assert "...so GitHub's draft rejection cannot abort the tick: exit stays inside the 0/10/20/30 contract (non-dry-run)" \
  "$([ "$TICK_RC" -eq 0 ] || [ "$TICK_RC" -eq 10 ] || [ "$TICK_RC" -eq 20 ] || [ "$TICK_RC" -eq 30 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 21. Draft-PR skip in reconcile_missing_queue_entries specifically -- the
#     sibling gap section 20 doesn't cover. gate_and_merge_prs's isDraft
#     exclusion only stops a draft from reaching `gh pr merge`; it says
#     nothing about reconcile's separate "no queue entry and no review yet"
#     synth branch, which mfh0s's fix never touched. Observed live: a
#     deliberately-held draft PR with no review kept getting synthesized
#     into pending_reviews every tick, nagging the mayor about a PR nobody
#     asked to be reviewed yet.
# ---------------------------------------------------------------------------

STUB_RECONCILE_DRAFT_BIN="$WORKDIR/stub-reconcile-draft-bin"
mkdir -p "$STUB_RECONCILE_DRAFT_BIN"
# One open worker PR (#5555), isDraft=true, with NO reviews at all -- the
# exact shape that hits reconcile's "no review-queue entry and no
# critical-reviewer review" synth branch if the draft check doesn't fire
# first.
cat > "$STUB_RECONCILE_DRAFT_BIN/gh" <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *" view "* ]]; then
  base='{"reviews":[]}'
else
  base='[{"number":5555,"url":"https://github.com/example/repo/pull/5555","headRefName":"worker/agent-draft-reconcile-test","mergeStateStatus":"CLEAN","statusCheckRollup":[],"isDraft":true}]'
fi
jq_filter=""
prev=""
for a in "$@"; do
  [ "$prev" = "--jq" ] && jq_filter="$a"
  prev="$a"
done
if [ -n "$jq_filter" ]; then
  printf '%s' "$base" | jq "$jq_filter"
else
  printf '%s' "$base"
fi
EOF
cat > "$STUB_RECONCILE_DRAFT_BIN/bd" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$STUB_RECONCILE_DRAFT_BIN/gh" "$STUB_RECONCILE_DRAFT_BIN/bd"

run_full_tick "$STUB_RECONCILE_DRAFT_BIN"
assert "a draft PR with no queue entry and no review is NOT synthesized into pending_reviews by reconcile -- a deliberately-held draft must not get nagged every tick" \
  "$([ "$(jq -r '.pending_reviews | index(5555) != null' "$TICK_STATE")" = "false" ] && echo 1 || echo 0)"
assert "...and reconcile never even logs the synthesizing message for it" \
  "$(! printf '%s' "$TICK_OUT" | grep -q 'synthesizing pending_reviews entry' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 22. Post-merge checkout refresh in cleanup_merged_worktrees against a REAL
#     remote: after a worker's PR is MERGED the tick must fetch origin main
#     and fast-forward the mayor's checkout to it. If either step regresses
#     the checkout silently stays behind origin and every later worker
#     worktree branches off stale main.
# ---------------------------------------------------------------------------

STUB_MERGED_BIN="$WORKDIR/stub-merged-bin"
mkdir -p "$STUB_MERGED_BIN"
# Only `gh pr list --head <branch>` answers, reporting that branch's PR as
# MERGED; every other gh query sees no open PRs.
cat > "$STUB_MERGED_BIN/gh" <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *" --head "* ]]; then
  printf '{"number":7777,"state":"MERGED"}'
else
  printf '[]'
fi
EOF
cat > "$STUB_MERGED_BIN/bd" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$STUB_MERGED_BIN/gh" "$STUB_MERGED_BIN/bd"

build_scratch_repo "merged-ff"
FF_ORIGIN="$(dirname "$SCRATCH_REPO")/origin.git"
FF_ADVANCER="$(dirname "$SCRATCH_REPO")/advancer"
git init -q --bare -b main "$FF_ORIGIN"
git -C "$SCRATCH_REPO" branch -M main
git -C "$SCRATCH_REPO" remote add origin "$FF_ORIGIN"
git -C "$SCRATCH_REPO" push -q -u origin main 2>/dev/null
git clone -q -b main "$FF_ORIGIN" "$FF_ADVANCER" 2>/dev/null
git -C "$FF_ADVANCER" config user.email test@example.com
git -C "$FF_ADVANCER" config user.name "Test"
git -C "$FF_ADVANCER" commit -q --allow-empty -m "merged worker PR lands on origin main"
git -C "$FF_ADVANCER" push -q origin HEAD:main 2>/dev/null
FF_BEFORE=$(git -C "$SCRATCH_REPO" rev-parse HEAD)
FF_ORIGIN_SHA=$(git -C "$FF_ADVANCER" rev-parse HEAD)
# Local origin/main is still the OLD sha here, so only the tick's own fetch
# can make the fast-forward possible.
# Run from a DIFFERENT repo (a decoy holding a same-named worker branch and
# worktree): every git mutation must target the script's own REPO_ROOT, never
# the caller's CWD.
FF_REPO="$SCRATCH_REPO"
FF_WORKTREE="$(dirname "$FF_REPO")/worker-worktree"
build_scratch_repo "merged-ff"
DECOY_REPO="$SCRATCH_REPO"
DECOY_WORKTREE="$(dirname "$DECOY_REPO")/worker-worktree"
SCRATCH_REPO="$FF_REPO"
pushd "$DECOY_REPO" >/dev/null
invoke_tick "$STUB_MERGED_BIN" "$FF_REPO" 0
popd >/dev/null
assert "cleanup removes the REPO_ROOT's merged worker worktree even when run from another repo" \
  "$([ ! -d "$FF_WORKTREE" ] && echo 1 || echo 0)"
assert "...and deletes the merged worker branch in REPO_ROOT, not just somewhere" \
  "$(! git -C "$FF_REPO" rev-parse --verify -q refs/heads/worker/agent-merged-ff >/dev/null && echo 1 || echo 0)"
assert "the caller's CWD repo keeps its same-named worker worktree: a wrong-repo remove would destroy unrelated work" \
  "$([ -d "$DECOY_WORKTREE" ] && echo 1 || echo 0)"
assert "...and keeps its same-named worker branch (no wrong-repo branch -D)" \
  "$(git -C "$DECOY_REPO" rev-parse --verify -q refs/heads/worker/agent-merged-ff >/dev/null && echo 1 || echo 0)"
assert "the tick exits normally (a wrong-repo worktree remove fails and aborts under set -e)" \
  "$([ "$TICK_RC" -eq 0 ] || [ "$TICK_RC" -eq 10 ] || [ "$TICK_RC" -eq 20 ] || [ "$TICK_RC" -eq 30 ] && echo 1 || echo 0)"
assert "fixture sanity: origin is ahead of the checkout before the tick" \
  "$([ "$FF_BEFORE" != "$FF_ORIGIN_SHA" ] && echo 1 || echo 0)"
assert "after a MERGED worker PR the checkout fast-forwards to origin's new main (fetch + merge --ff-only both ran)" \
  "$([ "$(git -C "$SCRATCH_REPO" rev-parse HEAD)" = "$FF_ORIGIN_SHA" ] && echo 1 || echo 0)"
assert "...and the merged PR is recorded in merged_prs, proving the cleanup path (not some other step) did the pull" \
  "$([ "$(jq -c '.merged_prs' "$TICK_STATE")" = "[7777]" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 23. A merged worker PR whose bead-snapshot commit touches a path the mayor
#     checkout holds a local edit of. bd regenerates .beads/issues.jsonl on
#     every write, so that path must be discarded and the pull must land;
#     any other dirty path blocks the pull and must surface as an in-contract
#     exit 20, never an exit 1 that skips cleanup and the dashboard refresh.
# ---------------------------------------------------------------------------

# $1=repo-relative path both origin's new commit and the local checkout edit.
# Sets FF_REPO/FF_ORIGIN_SHA, runs the tick, sets TICK_RC/TICK_STATE.
run_blocked_pull_tick() {
  local blocked_path="$1"
  build_scratch_repo "merged-ff"
  FF_REPO="$SCRATCH_REPO"
  local origin="$(dirname "$FF_REPO")/origin.git" advancer="$(dirname "$FF_REPO")/advancer"
  mkdir -p "$FF_REPO/$(dirname "$blocked_path")"
  echo base > "$FF_REPO/$blocked_path"
  git -C "$FF_REPO" add "$blocked_path"
  git -C "$FF_REPO" commit -q -m "track $blocked_path"
  git init -q --bare -b main "$origin"
  git -C "$FF_REPO" branch -M main
  git -C "$FF_REPO" remote add origin "$origin"
  git -C "$FF_REPO" push -q -u origin main 2>/dev/null
  git clone -q -b main "$origin" "$advancer" 2>/dev/null
  git -C "$advancer" config user.email test@example.com
  git -C "$advancer" config user.name "Test"
  echo upstream > "$advancer/$blocked_path"
  git -C "$advancer" commit -q -am "snapshot lands on origin main"
  git -C "$advancer" push -q origin HEAD:main 2>/dev/null
  FF_ORIGIN_SHA=$(git -C "$advancer" rev-parse HEAD)
  echo local-edit > "$FF_REPO/$blocked_path"
  invoke_tick "$STUB_MERGED_BIN" "$FF_REPO" 0
}

run_blocked_pull_tick ".beads/issues.jsonl"
assert "a locally regenerated .beads/issues.jsonl does not block the post-merge pull (checkout reaches origin main)" \
  "$([ "$(git -C "$FF_REPO" rev-parse HEAD)" = "$FF_ORIGIN_SHA" ] && echo 1 || echo 0)"
assert "...and the tick stays inside its 0/10/20/30 contract instead of exiting 1" \
  "$([ "$TICK_RC" -eq 0 ] || [ "$TICK_RC" -eq 10 ] || [ "$TICK_RC" -eq 20 ] || [ "$TICK_RC" -eq 30 ] && echo 1 || echo 0)"
assert "...and post-merge cleanup still ran (merged PR recorded)" \
  "$([ "$(jq -c '.merged_prs' "$TICK_STATE")" = "[7777]" ] && echo 1 || echo 0)"

run_blocked_pull_tick "src/other.txt"
assert "an unrelated dirty path is never discarded: the local edit survives" \
  "$([ "$(cat "$FF_REPO/src/other.txt")" = "local-edit" ] && echo 1 || echo 0)"
assert "an unrelated dirty path blocking the pull exits 20, not 1" \
  "$([ "$TICK_RC" -eq 20 ] && echo 1 || echo 0)"
assert "...surfaces checkout-pull-blocked in queue_warnings so the mayor sees why" \
  "$([ "$(jq -r '.queue_warnings[0].reason' "$TICK_STATE")" = "checkout-pull-blocked" ] && echo 1 || echo 0)"
assert "...and still runs the rest of cleanup (merged PR recorded)" \
  "$([ "$(jq -c '.merged_prs' "$TICK_STATE")" = "[7777]" ] && echo 1 || echo 0)"

# A failing .beads restore (here: a held index lock) is a blocked pull, not a
# tick abort: set -e must not turn it into exit 1.
build_scratch_repo "merged-ff"
FF_REPO="$SCRATCH_REPO"
mkdir -p "$FF_REPO/.beads"
echo base > "$FF_REPO/.beads/issues.jsonl"
git -C "$FF_REPO" add .beads/issues.jsonl
git -C "$FF_REPO" commit -q -m "track beads jsonl"
echo regenerated > "$FF_REPO/.beads/issues.jsonl"
touch "$FF_REPO/.git/index.lock"
invoke_tick "$STUB_MERGED_BIN" "$FF_REPO" 0
assert "a failed .beads JSONL restore exits 20 (checkout-pull-blocked), not 1 -- exit 1 skips cleanup and the dashboard refresh" \
  "$([ "$TICK_RC" -eq 20 ] && echo 1 || echo 0)"
assert "...and surfaces checkout-pull-blocked in queue_warnings" \
  "$([ "$(jq -r '.queue_warnings[0].reason' "$TICK_STATE")" = "checkout-pull-blocked" ] && echo 1 || echo 0)"
assert "...and still runs the rest of cleanup (merged PR recorded)" \
  "$([ "$(jq -c '.merged_prs' "$TICK_STATE")" = "[7777]" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 24. Beads close when their PR merges. The tick scans recently merged PRs
#     independent of any worktree, so beads of non-worker branches close, a
#     failed close is surfaced (exit 20) and retried on the next tick, and the
#     scan is bounded to a lookback window. Otherwise beads sit in_progress
#     after merge and `bd ready`/the dashboard drift from main.
# ---------------------------------------------------------------------------

# Bead-ID prefix, split so the bead-id-refs guard doesn't flag these fixtures.
B="mayo""r-"

# $1=case name, $2=JSON array of merged PRs the fake gh returns for the merged
# search, rest = "<bead-id>=<status>" pairs the fake bd reports. Builds the
# stubs once; BEAD_BIN/BEAD_DB/BEAD_CLOSE_LOG are then reused across ticks.
# A `$BEAD_DB/FAIL` file makes the fake `bd close` fail. Extra pairs
# "<id>.notes=<text>", "<id>.type=<type>" and "<id>.children=<open count>"
# feed the fake `bd show` / `bd children`.
setup_bead_stubs() {
  local name="$1" prs="$2" pair; shift 2
  BEAD_BIN="$WORKDIR/stub-bead-$name"; BEAD_DB="$WORKDIR/bead-db-$name"
  mkdir -p "$BEAD_BIN" "$BEAD_DB"
  BEAD_CLOSE_LOG="$WORKDIR/bead-close-$name.log"
  : > "$BEAD_CLOSE_LOG"
  printf '%s' "$prs" > "$BEAD_DB/prs.json"
  for pair in "$@"; do printf '%s' "${pair#*=}" > "$BEAD_DB/${pair%%=*}"; done
  cat > "$BEAD_BIN/gh" <<EOF
#!/usr/bin/env bash
if [[ " \$* " == *" --state merged "* ]]; then
  printf '%s\n' "\$*" > "$BEAD_DB/gh-args"
  cat "$BEAD_DB/prs.json"
else
  printf '[]'
fi
EOF
  cat > "$BEAD_BIN/bd" <<EOF
#!/usr/bin/env bash
case "\$1" in
  show) [ -f "$BEAD_DB/\$2" ] || exit 1
        jq -nc --arg id "\$2" --arg st "\$(cat "$BEAD_DB/\$2")" \\
          --arg notes "\$(cat "$BEAD_DB/\$2.notes" 2>/dev/null)" \\
          --arg type "\$(cat "$BEAD_DB/\$2.type" 2>/dev/null || echo task)" \\
          '[{id:\$id,status:\$st,notes:\$notes,issue_type:\$type}]' ;;
  children) n=\$(cat "$BEAD_DB/\$2.children" 2>/dev/null || echo 0)
            jq -nc --argjson n "\$n" '[range(\$n) | {status:"open"}] + [{status:"closed"}]' ;;
  list) cat "$BEAD_DB/inprogress.json" 2>/dev/null || echo '[]' ;;
  close) [ -f "$BEAD_DB/FAIL" ] && exit 1
         printf '%s\n' "\$*" >> "$BEAD_CLOSE_LOG"; printf closed > "$BEAD_DB/\$2" ;;
  *) exit 1 ;;
esac
EOF
  chmod +x "$BEAD_BIN/gh" "$BEAD_BIN/bd"
}

bead_tick() {
  build_scratch_repo
  invoke_tick "$BEAD_BIN" "$SCRATCH_REPO" 0
}

# No worktree exists at all here, so this also proves closing does not depend
# on a worker/agent-* worktree (e.g. a PR from a hand-named branch).
setup_bead_stubs merged \
  "[{\"number\":4242,\"title\":\"feat(x): thing (${B}aaa1, ${B}bbb2.3)\",\"mergeCommit\":{\"oid\":\"abcdef0123456789\"}}]" \
  ${B}aaa1=in_progress ${B}bbb2.3=open \
  "${B}aaa1.notes=PR #4242 opened: https://x/4242" "${B}bbb2.3.notes=PR #4242 opened: https://x/4242"
bead_tick
assert "a merged PR with no worker worktree closes every bead ID in its title, dotted child IDs included, citing PR and merge sha" \
  "$([ "$(sort "$BEAD_CLOSE_LOG")" = "$(printf 'close %saaa1 --reason merged in #4242 (abcdef0123)\nclose %sbbb2.3 --reason merged in #4242 (abcdef0123)' "$B" "$B")" ] && echo 1 || echo 0)"
bead_tick
assert "a second tick over the same merged PR does not close again (idempotent)" \
  "$([ "$(wc -l < "$BEAD_CLOSE_LOG" | tr -d ' ')" = "2" ] && echo 1 || echo 0)"
EXPECT_SINCE=$(date -u -v-3d +%Y-%m-%d 2>/dev/null || date -u -d "3 days ago" +%Y-%m-%d)
assert "the scan asks gh only for MERGED PRs since the 3-day lookback, with a limit (no unbounded history scan)" \
  "$(grep -q -- "--state merged" "$BEAD_DB/gh-args" && grep -q -- "merged:>=$EXPECT_SINCE" "$BEAD_DB/gh-args" && grep -q -- "--limit" "$BEAD_DB/gh-args" && echo 1 || echo 0)"

setup_bead_stubs skip \
  "[{\"number\":11,\"title\":\"fix: y (${B}ccc3, ${B}ddd4)\",\"mergeCommit\":{\"oid\":\"1111111111\"}},{\"number\":12,\"title\":\"chore(deps): update renovate\",\"mergeCommit\":{\"oid\":\"2222222222\"}},{\"number\":13,\"title\":\"feat: z x${B}eee5\",\"mergeCommit\":{\"oid\":\"3333333333\"}}]" \
  ${B}ccc3=closed ${B}ddd4=in_progress ${B}eee5=in_progress \
  "${B}ddd4.notes=PR #11 opened: u" "${B}eee5.notes=PR #13 opened: u"
bead_tick
assert "an already-closed bead is skipped while its open sibling closes; a no-bead-ID PR is a no-op; an ID glued to a word (x<id>) is not matched" \
  "$([ "$(cat "$BEAD_CLOSE_LOG")" = "close ${B}ddd4 --reason merged in #11 (1111111111)" ] && echo 1 || echo 0)"

setup_bead_stubs fail \
  "[{\"number\":21,\"title\":\"feat: w (${B}fff6)\",\"mergeCommit\":{\"oid\":\"4444444444\"}}]" \
  ${B}fff6=in_progress "${B}fff6.notes=PR #21 opened: u"
touch "$BEAD_DB/FAIL"
bead_tick
assert "a failed bd close exits 20 so the mayor sees it" \
  "$([ "$TICK_RC" -eq 20 ] && echo 1 || echo 0)"
assert "...and the failure names the PR and bead in gate_exceptions" \
  "$([ "$(jq -r '.gate_exceptions[0] | "\(.reason) \(.pr) \(.bead)"' "$TICK_STATE")" = "bead-close-failed 21 ${B}fff6" ] && echo 1 || echo 0)"
rm "$BEAD_DB/FAIL"
bead_tick
assert "the next tick retries the failed close (no worktree needed) and succeeds" \
  "$([ "$(cat "$BEAD_CLOSE_LOG")" = "close ${B}fff6 --reason merged in #21 (4444444444)" ] && echo 1 || echo 0)"
assert "...and the retried tick no longer reports the failure" \
  "$([ "$(jq '.gate_exceptions | length' "$TICK_STATE")" = "0" ] && echo 1 || echo 0)"

setup_bead_stubs missing \
  "[{\"number\":31,\"title\":\"feat: v (${B}ggg7)\",\"mergeCommit\":{\"oid\":\"5555555555\"}}]"
bead_tick
assert "a bead ID unknown to bd is logged and neither closed nor treated as a failure" \
  "$([ ! -s "$BEAD_CLOSE_LOG" ] && [ "$TICK_RC" -eq 0 ] && echo 1 || echo 0)"

# A PR title cannot tell a completing PR from a partial one, so only a worker
# note for THIS PR number authorises the close. Wrongly closing a bead with
# remaining work hides it from `bd ready` and the dashboard.
setup_bead_stubs gate \
  "[{\"number\":51,\"title\":\"feat: a (${B}ok01, ${B}oth02, ${B}par03, ${B}pre04, ${B}epi05, ${B}kid06, ${B}pre12)\",\"mergeCommit\":{\"oid\":\"6666666666\"}}]" \
  ${B}ok01=in_progress ${B}oth02=in_progress ${B}par03=in_progress ${B}pre04=in_progress \
  ${B}epi05=open ${B}kid06=in_progress ${B}pre12=in_progress \
  "${B}ok01.notes=PR #51 opened: https://x/51" \
  "${B}oth02.notes=PR #5 opened: https://x/5" \
  "${B}par03.notes=PR #51 opened (partial: item 2 left): https://x/51" \
  "${B}epi05.notes=PR #51 opened: https://x/51" "${B}epi05.type=epic" \
  "${B}kid06.notes=PR #51 opened: https://x/51" "${B}kid06.children=2" \
  "${B}pre12.notes=PR #512 opened: https://x/512"
bead_tick
assert "only the bead whose note says this PR completed it closes; other-PR-number, partial, no-note (pre-convention), epic, open-children and PR-number-prefix (#512 vs #51) beads stay open" \
  "$([ "$(cat "$BEAD_CLOSE_LOG")" = "close ${B}ok01 --reason merged in #51 (6666666666)" ] && echo 1 || echo 0)"
assert "...and skipping them is quiet: exit 0 with no gate exception (an epic close attempt used to raise bead-close-failed)" \
  "$([ "$TICK_RC" -eq 0 ] && [ "$(jq '.gate_exceptions | length' "$TICK_STATE")" = "0" ] && echo 1 || echo 0)"

# Worker PR titles usually carry no bead ID, so the PR's bead is found only
# through its in_progress "PR #N opened" note. Title-only discovery left every
# such bead in_progress after merge. The first PR's bead having open children
# must not stop the later PRs' beads from closing, and each skip says why.
setup_bead_stubs notefind \
  "[{\"number\":61,\"title\":\"fix(x): has parent (${B}par61)\",\"mergeCommit\":{\"oid\":\"7777777777\"}},{\"number\":62,\"title\":\"fix(y): no id in title\",\"mergeCommit\":{\"oid\":\"8888888888\"}},{\"number\":63,\"title\":\"fix(z): also no id\",\"mergeCommit\":{\"oid\":\"9999999999\"}},{\"number\":64,\"title\":\"chore: nothing\",\"mergeCommit\":{\"oid\":\"0000000000\"}}]" \
  ${B}par61=in_progress ${B}par61.children=1 "${B}par61.notes=PR #61 opened: u" \
  ${B}note62=in_progress "${B}note62.notes=PR #62 opened: https://x/62" \
  ${B}note63=in_progress "${B}note63.notes=PR #63 opened: https://x/63" \
  "inprogress.json=[{\"id\":\"${B}par61\",\"notes\":\"PR #61 opened: u\"},{\"id\":\"${B}note62\",\"notes\":\"PR #62 opened: https://x/62\"},{\"id\":\"${B}note63\",\"notes\":\"PR #63 opened: https://x/63\"}]"
bead_tick
assert "beads with no ID in the PR title close via their 'PR #N opened' note, even after an earlier PR's bead was skipped for open children" \
  "$([ "$(sort "$BEAD_CLOSE_LOG")" = "$(printf 'close %snote62 --reason merged in #62 (8888888888)\nclose %snote63 --reason merged in #63 (9999999999)' "$B" "$B")" ] && echo 1 || echo 0)"
assert "a skipped bead logs 'bead <id> not closed: <reason>'" \
  "$(printf '%s' "$TICK_OUT" | grep -q "mayor-tick: bead ${B}par61 not closed: has open children" && echo 1 || echo 0)"
assert "a merged PR with no discoverable bead logs a reason line instead of staying silent" \
  "$(printf '%s' "$TICK_OUT" | grep -q 'mayor-tick: PR #64 has no bead to close' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 25. The review gate enqueues (bare `gh pr merge N`) a CLEAN PR whose latest
#     reviewer review is LGTM, and every PR it declines logs why -- a silent
#     skip left CLEAN+APPROVED PRs un-enqueued with nothing in the log.
# ---------------------------------------------------------------------------

STUB_GATE_BIN="$WORKDIR/stub-gate-bin"
mkdir -p "$STUB_GATE_BIN"
cat > "$STUB_GATE_BIN/gh" <<'GHEOF'
#!/usr/bin/env bash
lgtm='[{"author":{"login":"litehop-reviewer"},"state":"APPROVED","body":"## critical-reviewer findings -- PR -- x\n\n**Verdict**: LGTM\n","submittedAt":"2026-01-01T00:00:00Z"}]'
chg='[{"author":{"login":"litehop-reviewer"},"state":"APPROVED","body":"## critical-reviewer findings -- PR -- x\n\n**Verdict**: LGTM\n","submittedAt":"2026-01-01T00:00:00Z"},{"author":{"login":"litehop-reviewer"},"state":"CHANGES_REQUESTED","body":"## critical-reviewer findings -- PR -- x (round 2)\n\n**Verdict**: needs-changes\n","submittedAt":"2026-01-01T01:00:00Z"}]'
prs='[
 {"number":71,"url":"u/71","headRefName":"worker/agent-a71","mergeStateStatus":"CLEAN","isDraft":false,"statusCheckRollup":[{"status":"COMPLETED","conclusion":"SUCCESS"}]},
 {"number":72,"url":"u/72","headRefName":"worker/agent-a72","mergeStateStatus":"CLEAN","isDraft":false,"statusCheckRollup":[]},
 {"number":73,"url":"u/73","headRefName":"worker/agent-a73","mergeStateStatus":"BLOCKED","isDraft":false,"statusCheckRollup":[]},
 {"number":74,"url":"u/74","headRefName":"worker/agent-a74","mergeStateStatus":"UNKNOWN","isDraft":false,"statusCheckRollup":[]},
 {"number":75,"url":"u/75","headRefName":"worker/agent-a75","mergeStateStatus":"CLEAN","isDraft":false,"statusCheckRollup":[{"status":"IN_PROGRESS","conclusion":null}]}
]'
if [[ " $* " == *" pr view "* ]]; then
  n=$3
  if [[ " $* " == *" mergeStateStatus "* ]]; then
    [ "$n" = 74 ] && base='{"mergeStateStatus":"CLEAN"}' || base='{"mergeStateStatus":"UNKNOWN"}'
  elif [[ " $* " == *" commits "* ]]; then
    base='{"commits":[]}'
  else
    case "$n" in
      71|74) base="{\"reviews\":$lgtm}" ;;
      72) base="{\"reviews\":$chg}" ;;
      *) base='{"reviews":[]}' ;;
    esac
  fi
elif [[ " $* " == *" --state open "* ]]; then
  base="$prs"
else
  base='[]'
fi
jq_filter=""; prev=""
for a in "$@"; do [ "$prev" = "--jq" ] && jq_filter="$a"; prev="$a"; done
if [ -n "$jq_filter" ]; then printf '%s' "$base" | jq -r "$jq_filter"; else printf '%s' "$base"; fi
GHEOF
cp "$STUB_GATE_BIN/gh" "$STUB_GATE_BIN/bd"
printf '#!/usr/bin/env bash\nexit 1\n' > "$STUB_GATE_BIN/bd"
chmod +x "$STUB_GATE_BIN/gh" "$STUB_GATE_BIN/bd"

run_full_tick "$STUB_GATE_BIN"
assert "a CLEAN PR whose latest reviewer review is LGTM gets a bare 'gh pr merge 71' (no flags)" \
  "$(printf '%s\n' "$TICK_OUT" | grep -qx '\[dry-run\] would run: gh pr merge 71' && echo 1 || echo 0)"
assert "a PR UNKNOWN in the list but CLEAN on re-query (lazy mergeability) is enqueued too" \
  "$(printf '%s\n' "$TICK_OUT" | grep -qx '\[dry-run\] would run: gh pr merge 74' && echo 1 || echo 0)"
assert "a PR whose latest review is CHANGES_REQUESTED/needs-changes is not merged and logs why" \
  "$(! printf '%s\n' "$TICK_OUT" | grep -q 'gh pr merge 72' && printf '%s' "$TICK_OUT" | grep -q "mayor-tick: PR #72 not enqueued: latest critical-reviewer verdict is 'needs-changes'" && echo 1 || echo 0)"
assert "a non-CLEAN PR logs its merge state instead of vanishing from the log" \
  "$(printf '%s' "$TICK_OUT" | grep -q 'mayor-tick: PR #73 not enqueued: mergeStateStatus is BLOCKED' && echo 1 || echo 0)"
assert "a PR with pending checks logs the pending count" \
  "$(printf '%s' "$TICK_OUT" | grep -q 'mayor-tick: PR #75 not enqueued: 1 check(s) still pending' && echo 1 || echo 0)"

CLUSTER_TITLE="tooling(mayor): full bead IDs in cluster titles (${B}aa001, ${B}bb002, ${B}cc003)"
assert "a Shape 2 cluster title lists every full bead ID, so extract_bead_ids returns all three and the tick can close them on merge" \
  "$([ "$(call extract_bead_ids "$CLUSTER_TITLE" | tr '\n' ' ')" = "${B}aa001 ${B}bb002 ${B}cc003 " ] && echo 1 || echo 0)"
assert "the old '(N beads incl. <id>)' title style yields at most the highlighted ID, never the whole cluster" \
  "$([ "$(call extract_bead_ids "x: y (3 beads incl. ${B}fkj56)" | wc -l | tr -d ' ')" = "1" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

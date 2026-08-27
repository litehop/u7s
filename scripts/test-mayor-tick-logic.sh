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

file_mtime() {  # portable GNU/BSD stat, matches the idiom used elsewhere in scripts/
  stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null
}

# Runs the REAL end-to-end main() (mayor-tick.sh __call main) -- not a
# single __call'd pure function -- inside an isolated single-worktree
# scratch git repo with `gh`/`bd` replaced by fixtures under $1 (a
# directory of executable stub scripts prepended to PATH) and the review
# queue seeded from $2 (a directory of .md fixtures, or empty/omitted).
# Copying the script into its own throwaway repo (one worktree, no queue
# files, no worker PRs, no beads) is what makes "genuinely empty state" and
# "exactly this one fixture PR" possible at all: this actual dev checkout
# has live sibling worktrees/PRs/beads that would otherwise leak into any
# of the three assertions below and mask a real regression. Sets
# TICK_RC/TICK_OUT/TICK_STATE for the caller to assert on.
run_full_tick() {
  local stub_bin="$1" queue_seed="${2:-}"
  local scratch="$WORKDIR/tick-$RANDOM$RANDOM" repo
  repo="$scratch/repo"
  mkdir -p "$repo/scripts" "$repo/.claude/review-queue"
  cp "$SCRIPT" "$repo/scripts/mayor-tick.sh"
  git init -q "$repo"
  if [ -n "$queue_seed" ]; then
    cp "$queue_seed"/*.md "$repo/.claude/review-queue/" 2>/dev/null || true
  fi
  TICK_STATE="$scratch/state.json"
  TICK_RC=0
  TICK_OUT=$(PATH="$stub_bin:$PATH" \
    MAYOR_TICK_QUEUE_DIR="$repo/.claude/review-queue" \
    MAYOR_TICK_STATE_FILE="$TICK_STATE" \
    MAYOR_TICK_DASHBOARD_FILE="$repo/no-such-dashboard.md" \
    MAYOR_TICK_DRY_RUN=1 \
    bash "$repo/scripts/mayor-tick.sh" __call main 2>&1) || TICK_RC=$?
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
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

#!/usr/bin/env bash
# Deterministic merge-PR pipeline + dashboard.md refresh for the mayor method.
#
# Replaces the mayor's per-turn model-driven work for the old 5m merge-PR
# loop and 10m dashboard-refresh loop. Session-log analysis
# (session 534747a7) showed those two loops firing on a tight cadence doing
# fully deterministic work -- queue drain, PR verdict parse, gh pr merge,
# post-merge cleanup, dashboard bookkeeping -- none of which needs a model
# turn. This script does that work; the mayor only wakes up when the exit
# code says there's a judgment call left.
#
# Split point: this script does `ls
# .claude/review-queue`, `gh pr list --json`, review-verdict parse, `gh pr
# merge` on gated CLEAN/BEHIND PRs, post-merge `git pull`/prune/worktree/branch
# cleanup, a self-heal reconciliation pass for any open worker PR the
# SubagentStop hook never queued at all (mayor-9syl7), and the deterministic
# slices of ai/dashboard.md. The mayor still does: dispatching
# critical-reviewer for undrained queue entries (this script cannot invoke a
# Claude subagent), cluster-shape decisions on new `bd ready` beads, and
# investigating anything below couldn't gate cleanly.
#
# Exit code taxonomy (OR-able -- if multiple signals fire, the HIGHEST wins):
#   0  = noop, nothing for the mayor to do this tick.
#   10 = new dispatchable beads in `bd ready` -- mayor picks cluster shape
#        and dispatches workers.
#   20 = a merge/gate exception (CLEAN/BEHIND PR with no qualifying review,
#        or a needs-changes/needs-discussion verdict) OR undrained
#        review-queue entries (PR or non-PR) -- mayor investigates or
#        dispatches critical-reviewer.
#   30 = a worker worktree/branch with no PR at all -- mayor investigates.
#
# State file: .claude/mayor-tick-state.json (path overridable via
# MAYOR_TICK_STATE_FILE for tests). Written on every run; this is what the
# mayor reads to decide follow-up action without re-deriving any of it.
#
# MAYOR_TICK_DRY_RUN=1 turns every side-effecting external command (gh pr
# merge, git worktree remove, git branch -D, rm of a queue file, git pull/
# prune) into a logged no-op -- see run_cmd(). Used by this script's own
# test suite (scripts/test-mayor-tick-logic.sh) so tests never touch a real
# PR, worktree, or branch.
#
# Testability: `mayor-tick.sh __call <fn> [args...]` invokes a single
# function from this file and exits -- lets the test suite exercise the
# REAL pure functions (verdict parsing, timestamp comparison, exit-code
# selection, state-JSON construction) as a subprocess, the same convention
# scripts/test-check-bead-id-refs-logic.sh and siblings use, without
# needing network access or a live gh/bd session.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUEUE_DIR="${MAYOR_TICK_QUEUE_DIR:-$REPO_ROOT/.claude/review-queue}"
STATE_FILE="${MAYOR_TICK_STATE_FILE:-$REPO_ROOT/.claude/mayor-tick-state.json}"
DASHBOARD_FILE="${MAYOR_TICK_DASHBOARD_FILE:-$REPO_ROOT/ai/dashboard.md}"

# ---------------------------------------------------------------------------
# Side-effect gate. Every destructive/external-state-changing command in
# this script goes through here so MAYOR_TICK_DRY_RUN=1 can turn the whole
# pipeline into a dry preview (used by tests and available to an operator
# who wants to see what a tick would do before it does it).
# ---------------------------------------------------------------------------
run_cmd() {
  if [ "${MAYOR_TICK_DRY_RUN:-0}" = "1" ]; then
    echo "[dry-run] would run: $*"
  else
    "$@"
  fi
}

# ---------------------------------------------------------------------------
# Pure helpers (unit-tested directly via `__call`).
# ---------------------------------------------------------------------------

# The SubagentStop hook (scripts/critical-reviewer-dispatch.sh) stamps
# `queued_at` as `%Y-%m-%dT%H-%M-%SZ` (dashes, not colons -- filesystem-safe
# for a filename). GitHub's review `submittedAt` is standard ISO-8601 with
# colons. Normalize the hook's format to GitHub's so a plain string compare
# orders them correctly.
normalize_queued_at() {
  printf '%s' "$1" | sed -E 's/^([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2})-([0-9]{2})-([0-9]{2})Z$/\1T\2:\3:\4Z/'
}

# True (exit 0) iff a string matches the SubagentStop hook's exact
# `queued_at` format. Used to fail CLOSED (not-drained) on a missing or
# malformed frontmatter field instead of silently treating it as
# already-drained: an empty queued_at compares as less than any non-empty
# submitted_at, so without this check a broken queue file would get rm'd
# on the next tick regardless of whether a review actually answers it.
is_valid_queued_at() {
  [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}Z$ ]]
}

# True (exit 0) iff a critical-reviewer review was submitted AFTER this
# queue entry was queued -- i.e. the queue entry is drained and its file
# can be removed. False (exit 1) for a missing/malformed queued_at
# (fail-closed -- see is_valid_queued_at), "no review yet" (empty
# submitted_at), or "review predates this queue entry" (a stale review
# from a prior round must not mask an unreviewed re-queue).
queue_is_drained() {
  local queued_at="$1" submitted_at="$2"
  is_valid_queued_at "$queued_at" || return 1
  [ -z "$submitted_at" ] && return 1
  local norm
  norm=$(normalize_queued_at "$queued_at")
  [[ "$submitted_at" > "$norm" ]]
}

# Extracts the value after "**Verdict**:" from a critical-reviewer findings
# body. Only LGTM / LGTM-with-suggestions satisfy the merge gate; anything
# else (needs-changes, needs-discussion, or no match at all -> empty) does
# not, even though the `## critical-reviewer findings` header is present.
parse_verdict() {
  printf '%s\n' "$1" | grep -oE '\*\*Verdict\*\*:[[:space:]]*[A-Za-z-]+' | head -1 \
    | sed -E 's/^\*\*Verdict\*\*:[[:space:]]*//'
}

# Given a JSON array of GitHub PR reviews (the `reviews` field from `gh pr
# view --json reviews`), returns the latest (by submittedAt) review object
# whose body starts with the critical-reviewer marker, as compact JSON --
# or empty if none qualify. Resolving by time, not mere marker presence, is
# what stops an older superseded LGTM from masking a newer needs-changes
# verdict (a real incident hit this exact gap at the PR-verdict layer; see
# git history, not a citation here that would rot once that PR closes).
latest_reviewer_review() {
  printf '%s' "$1" | jq -c \
    '[.[] | select(.body | startswith("## critical-reviewer findings"))] | sort_by(.submittedAt) | last // empty'
}

# True (exit 0) iff a PR's merge-queue/check state makes it eligible for
# the review-verdict gate at all. CLEAN and BEHIND both qualify -- queuing
# a BEHIND PR is the merge queue's job to rebase, not the mayor's, so it
# must not be silently skipped forever; anything else (DIRTY, BLOCKED,
# DRAFT, UNKNOWN, ...) does not. Checks must be genuinely complete and
# non-failing regardless of merge state.
pr_gate_eligible() {
  local mss="$1" pending="$2" failed="$3"
  case "$mss" in
    CLEAN|BEHIND) ;;
    *) return 1 ;;
  esac
  [ "${pending:-0}" -eq 0 ] || return 1
  [ "${failed:-0}" -eq 0 ] || return 1
  return 0
}

# Highest-signal-wins exit code selection: non-zero exit codes are OR-able
# -- the highest set signal wins if multiple fire. 30 (worktree/hygiene)
# outranks 20 (gate/queue exception) outranks 10 (new
# dispatchable work) -- a worktree anomaly is the kind of thing that can
# make a merge decision wrong, so it must not be masked by a same-tick
# routine bd-ready signal.
compute_exit_code() {
  local bd_ready="$1" exceptions="$2" worktree="$3"
  local code=0
  [ "$bd_ready" -gt 0 ] && [ "$code" -lt 10 ] && code=10
  [ "$exceptions" -gt 0 ] && [ "$code" -lt 20 ] && code=20
  [ "$worktree" -gt 0 ] && [ "$code" -lt 30 ] && code=30
  printf '%s' "$code"
}

# Reads one `key: value` field from a review-queue file's YAML frontmatter
# (the block between the first two `---` lines).
frontmatter_field() {
  local file="$1" field="$2"
  awk -v f="$field" '
    /^---[[:space:]]*$/ { c++; next }
    c==1 && $0 ~ "^"f":" { sub("^"f":[[:space:]]*",""); print; exit }
  ' "$file"
}

# Pure dtype-routing decision behind process_review_queue's case statement:
# given one queue entry's frontmatter (file/dtype/dref), decides which state
# bucket it belongs in -- "pr" (payload is the extracted PR number, empty if
# dref didn't end in one), "non-pr" (payload is the JSON object for
# pending_non_pr_reviews), or "warning" (payload is the JSON object for
# queue_warnings, covering any dtype -- missing or unrecognized -- this
# script doesn't know how to drain; see the queue_warnings comment on why
# that must surface for the mayor instead of silently vanishing). Extracted
# from process_review_queue so dtype routing is directly testable without a
# gh network call or global-array mutation. Output is "<bucket>\t<payload>"
# on one line.
route_deliverable() {
  local file="$1" dtype="$2" dref="$3"
  case "$dtype" in
    pr)
      printf 'pr\t%s' "$(printf '%s' "$dref" | grep -oE '[0-9]+$' || true)"
      ;;
    findings|bead-close|bead-supersede)
      printf 'non-pr\t%s' "$(jq -nc --arg file "$file" --arg dtype "$dtype" --arg dref "$dref" '{file:$file, deliverable_type:$dtype, deliverable_ref:$dref}')"
      ;;
    *)
      printf 'warning\t%s' "$(jq -nc --arg file "$file" --arg dtype "$dtype" --arg reason "unrecognized-deliverable-type" '{file:$file, deliverable_type:$dtype, reason:$reason}')"
      ;;
  esac
}

# True (exit 0) iff an active review-queue file's deliverable_ref names this
# exact PR URL -- mayor-9syl7's no-double-queue guard: a PR already tracked
# by an (undrained) queue file must not also get a reconciliation-synthesized
# duplicate pending_reviews entry. `processed/` is not checked -- it was
# deleted (mayor-hkhq0); a drained file's audit trail is git history plus
# the review on the PR itself, not an archive directory.
pr_already_queued() {
  local url="$1" f dref
  for f in "$QUEUE_DIR"/*.md; do
    [ -e "$f" ] || continue
    dref=$(frontmatter_field "$f" deliverable_ref)
    [ "$dref" = "$url" ] && return 0
  done
  return 1
}

json_array() {  # plain strings -> JSON array of strings
  if [ "$#" -eq 0 ]; then printf '[]'; return; fi
  printf '%s\n' "$@" | jq -R . | jq -s -c .
}

json_number_array() {  # plain integers -> JSON array of numbers
  if [ "$#" -eq 0 ]; then printf '[]'; return; fi
  printf '%s\n' "$@" | jq -R 'tonumber' | jq -s -c .
}

json_raw_array() {  # pre-built JSON object strings -> JSON array
  if [ "$#" -eq 0 ]; then printf '[]'; return; fi
  printf '%s\n' "$@" | jq -s -c .
}

# Writes the state file the mayor reads to decide follow-up action. Kept as
# a pure function of its arguments (no reliance on this script's own global
# arrays) so the test suite can call it directly with synthetic data and
# validate the JSON shape without running the rest of the pipeline.
write_state() {
  local exit_code="$1" queue_files_json="$2" pending_reviews_json="$3" \
    merged_prs_json="$4" bd_ready_json="$5" worktree_anomalies_json="$6" \
    gate_exceptions_json="$7" pending_non_pr_json="${8:-[]}" \
    queue_warnings_json="${9:-[]}"
  jq -n \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson exit_code "$exit_code" \
    --argjson queue_files "$queue_files_json" \
    --argjson pending_reviews "$pending_reviews_json" \
    --argjson merged_prs "$merged_prs_json" \
    --argjson bd_ready_ids "$bd_ready_json" \
    --argjson worktree_anomalies "$worktree_anomalies_json" \
    --argjson gate_exceptions "$gate_exceptions_json" \
    --argjson pending_non_pr_reviews "$pending_non_pr_json" \
    --argjson queue_warnings "$queue_warnings_json" \
    '{timestamp:$ts, exit_code:$exit_code, queue_files:$queue_files,
      pending_reviews:$pending_reviews, merged_prs:$merged_prs,
      bd_ready_ids:$bd_ready_ids, worktree_anomalies:$worktree_anomalies,
      gate_exceptions:$gate_exceptions,
      pending_non_pr_reviews:$pending_non_pr_reviews,
      queue_warnings:$queue_warnings}' \
    > "$STATE_FILE"
}

# ---------------------------------------------------------------------------
# Dashboard splice. ai/dashboard.md has judgment sections the mayor writes
# by hand (IN PROGRESS, DECISION POINT, WAVE plans) and deterministic
# sections this script owns, delimited by sentinel comments. Only the text
# between a BEGIN/END pair is ever touched.
# ---------------------------------------------------------------------------

# Actual dashboard-file mutations, isolated into their own tiny functions
# so run_cmd's dry-run gate (echo instead of exec) covers them exactly like
# every gh/git/rm call in this script -- a raw shell redirection (`mv`,
# `>>`) can't be passed through run_cmd's "$@" directly, so the mutation
# itself has to live behind a named command run_cmd CAN gate.
_dashboard_replace_from_tmp() {  # $1 = awk-computed tmp file to move into place
  mv "$1" "$DASHBOARD_FILE"
}
_dashboard_append_section() {  # $1 = fully-formed "## heading\n<sentinel>\n...\n" text
  printf '%s' "$1" >> "$DASHBOARD_FILE"
}

# $1=sentinel id  $2=ERE matching an existing "## ..." heading line (for
# first-run migration onto a pre-existing freeform section)  $3=heading text
# to use if no such heading exists yet (genuinely new dashboard)  $4=body.
splice_dashboard_section() {
  local id="$1" heading_re="$2" heading_text="$3" content="$4"
  local begin="<!-- BEGIN AUTO: ${id} -->"
  local end="<!-- END AUTO: ${id} -->"

  if grep -qF "$begin" "$DASHBOARD_FILE"; then
    awk -v b="$begin" -v e="$end" -v body="$content" '
      $0==b {print; print body; skip=1; next}
      $0==e {print; skip=0; next}
      skip {next}
      {print}
    ' "$DASHBOARD_FILE" > "${DASHBOARD_FILE}.tmp"
    run_cmd _dashboard_replace_from_tmp "${DASHBOARD_FILE}.tmp"
    rm -f "${DASHBOARD_FILE}.tmp"  # no-op if already mv'd; cleans up a dry-run's leftover
    return
  fi

  if grep -qE "$heading_re" "$DASHBOARD_FILE"; then
    # First run against a dashboard that already has this section as
    # freeform prose (pre-mayor-tick.sh): replace everything from that
    # heading up to (not including) the next "## " heading or EOF with the
    # sentinel-wrapped body, so the section becomes script-owned in place
    # instead of duplicating a second copy of the heading at the file end.
    awk -v re="$heading_re" -v b="$begin" -v e="$end" -v body="$content" '
      BEGIN{done=0}
      !done && $0 ~ re { print; print b; print body; print e; done=1; skip=1; next }
      skip && /^## / { skip=0 }
      skip { next }
      { print }
    ' "$DASHBOARD_FILE" > "${DASHBOARD_FILE}.tmp"
    run_cmd _dashboard_replace_from_tmp "${DASHBOARD_FILE}.tmp"
    rm -f "${DASHBOARD_FILE}.tmp"
  else
    run_cmd _dashboard_append_section "$(printf '\n## %s\n%s\n%s\n%s\n' "$heading_text" "$begin" "$content" "$end")"
  fi
}

dashboard_open_prs() {
  local json count
  json=$(gh pr list --state open --json number,title,headRefName,mergeStateStatus 2>/dev/null || echo '[]')
  count=$(printf '%s' "$json" | jq 'length' 2>/dev/null || echo 0)
  if [ "$count" -eq 0 ]; then
    printf 'None open.'
    return
  fi
  printf '%s' "$json" | jq -r '.[] | "- #\(.number) \(.title) (`\(.headRefName)`, \(.mergeStateStatus))"'
}

dashboard_worktrees() {
  local out="" path branch
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ "$path" = "$REPO_ROOT" ] && continue
    branch=$(git -C "$path" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')
    out="${out}${out:+$'\n'}- \`$path\` (\`$branch\`)"
  done < <(git -C "$REPO_ROOT" worktree list --porcelain | awk '/^worktree / {print $2}')
  if [ -z "$out" ]; then
    printf 'None (no active worker worktrees).'
  else
    printf '%s' "$out"
  fi
}

dashboard_cron_loops() {
  printf '15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene'
}

dashboard_repo_state() {
  local branch sha dirty counts ahead behind sync
  branch=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')
  sha=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo '?')
  if [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]; then dirty="dirty"; else dirty="clean"; fi
  git -C "$REPO_ROOT" fetch -q origin main 2>/dev/null || true
  counts=$(git -C "$REPO_ROOT" rev-list --left-right --count HEAD...origin/main 2>/dev/null || echo "0 0")
  ahead=$(printf '%s' "$counts" | awk '{print $1}')
  behind=$(printf '%s' "$counts" | awk '{print $2}')
  if [ "${ahead:-0}" = "0" ] && [ "${behind:-0}" = "0" ]; then
    sync="up to date with origin/main"
  else
    sync="${ahead:-0} ahead / ${behind:-0} behind origin/main"
  fi
  printf 'Branch `%s` @ `%s`, %s, %s.' "$branch" "$sha" "$dirty" "$sync"
}

dashboard_review_queue() {
  local count
  count=$(find "$QUEUE_DIR" -maxdepth 1 -name '*.md' -type f 2>/dev/null | wc -l | tr -d ' ')
  printf '%s pending review-queue entries.' "$count"
}

refresh_dashboard() {
  [ -f "$DASHBOARD_FILE" ] || return 0
  splice_dashboard_section "open-prs" '^## .*Open PRs' '🔎 Open PRs' "$(dashboard_open_prs)"
  splice_dashboard_section "worktrees" '^## .*Worktrees' '🌲 Worktrees / hygiene' "$(dashboard_worktrees)"
  splice_dashboard_section "cron-loops" '^## .*Cron loops' '🔁 Cron loops' "$(dashboard_cron_loops)"
  splice_dashboard_section "repo-state" '^## Repo state' 'Repo state' "$(dashboard_repo_state)"
  splice_dashboard_section "review-queue" '^## .*Review queue' '📋 Review queue' "$(dashboard_review_queue)"
}

# ---------------------------------------------------------------------------
# Pipeline steps. Populate the globals main() reads to compute the exit
# code and write the state file.
# ---------------------------------------------------------------------------

QUEUE_FILES_REMAINING=()
PENDING_REVIEW_PRS=()
PENDING_NON_PR_REVIEWS=()
QUEUE_WARNINGS=()
GATE_EXCEPTIONS=()
MERGED_PRS=()
BD_READY_IDS=()
WORKTREE_ANOMALIES=()

# Step 0: drain the review queue. This is NOT reviewer dispatch (this
# script cannot invoke a Claude subagent) -- it only confirms whether a
# queue entry's deliverable already got reviewed since it was queued, and
# if so removes the queue file (rm, not mv-to-processed/ -- the audit
# trail is git history plus the review posted on the PR itself, both
# durable and both outside .claude/). Anything still undrained stays
# queued for the mayor to dispatch critical-reviewer against.
#
# Only `pr` deliverables get an automated drain check: `gh pr view` gives
# an unambiguous per-review submittedAt to compare against queued_at.
# `findings`/`bead-close`/`bead-supersede` deliverables post to bd notes
# instead (see .claude/agents/critical-reviewer.md's "Output & posting"),
# and bd's CLI exposes no per-note timestamp; a bead-supersede ref can also
# legitimately resolve to either of two beads. Self-confirming those risks
# a false "drained" against the wrong bead's unrelated update, so they are
# always surfaced in PENDING_NON_PR_REVIEWS for the mayor to confirm by
# hand instead of silently sitting undrained with no visibility.
process_review_queue() {
  local f dtype dref queued_at prnum submitted_at reviews_json latest route bucket payload
  for f in "$QUEUE_DIR"/*.md; do
    [ -e "$f" ] || continue
    dtype=$(frontmatter_field "$f" deliverable_type)
    dref=$(frontmatter_field "$f" deliverable_ref)
    queued_at=$(frontmatter_field "$f" queued_at)
    if ! is_valid_queued_at "$queued_at"; then
      QUEUE_WARNINGS+=("$(jq -nc --arg file "$f" --arg reason "missing-or-malformed-queued_at" '{file:$file, reason:$reason}')")
    fi
    route=$(route_deliverable "$f" "$dtype" "$dref")
    bucket="${route%%$'\t'*}"
    payload="${route#*$'\t'}"
    case "$bucket" in
      pr)
        prnum="$payload"
        if [ -n "$prnum" ]; then
          reviews_json=$(gh pr view "$prnum" --json reviews --jq '.reviews' 2>/dev/null || echo '[]')
          latest=$(latest_reviewer_review "$reviews_json")
          submitted_at=$(printf '%s' "$latest" | jq -r '.submittedAt // empty' 2>/dev/null || true)
          if queue_is_drained "$queued_at" "$submitted_at"; then
            run_cmd rm -f "$f"
            continue
          fi
          PENDING_REVIEW_PRS+=("$prnum")
        fi
        ;;
      non-pr)
        PENDING_NON_PR_REVIEWS+=("$payload")
        ;;
      warning)
        # An unrecognized (or missing) deliverable_type: never auto-drained,
        # so it must surface here -- not silently leave all four
        # newly-documented state fields empty while still forcing exit 20
        # via queue_files (mayor-s7nn6's suspicion). See bootstrap.md's
        # queue_warnings bullet.
        QUEUE_WARNINGS+=("$payload")
        ;;
    esac
    QUEUE_FILES_REMAINING+=("$f")
  done
}

# Step 1-2: PR gate + merge. Only worker/agent-* branches are considered --
# operator/* branches never get a queued review in the first place (the
# SubagentStop hook that feeds the queue never fires for the mayor's own
# top-level turn), so gating them here would just wedge them forever.
gate_and_merge_prs() {
  local prs_json n pr mss pending failed reviews_json latest body verdict
  prs_json=$(gh pr list --state open --json number,headRefName,mergeStateStatus,statusCheckRollup 2>/dev/null || echo '[]')
  for n in $(printf '%s' "$prs_json" | jq -r '.[] | select(.headRefName | startswith("worker/agent-")) | .number' 2>/dev/null || true); do
    pr=$(printf '%s' "$prs_json" | jq -c --argjson n "$n" '.[] | select(.number==$n)')
    mss=$(printf '%s' "$pr" | jq -r '.mergeStateStatus')
    pending=$(printf '%s' "$pr" | jq '[.statusCheckRollup[]? | select(.status!=null and .status!="COMPLETED")] | length')
    failed=$(printf '%s' "$pr" | jq '[.statusCheckRollup[]? | select(.conclusion!=null and (.conclusion=="FAILURE" or .conclusion=="CANCELLED" or .conclusion=="TIMED_OUT" or .conclusion=="ACTION_REQUIRED"))] | length')
    pr_gate_eligible "$mss" "$pending" "$failed" || continue

    reviews_json=$(gh pr view "$n" --json reviews --jq '.reviews' 2>/dev/null || echo '[]')
    latest=$(latest_reviewer_review "$reviews_json")
    if [ -z "$latest" ] || [ "$latest" = "null" ]; then
      GATE_EXCEPTIONS+=("$(jq -nc --argjson pr "$n" '{pr:$pr, reason:"no-qualifying-review"}')")
      continue
    fi
    body=$(printf '%s' "$latest" | jq -r '.body')
    verdict=$(parse_verdict "$body")
    case "$verdict" in
      LGTM|LGTM-with-suggestions)
        run_cmd gh pr merge "$n"
        ;;
      *)
        GATE_EXCEPTIONS+=("$(jq -nc --argjson pr "$n" --arg verdict "$verdict" '{pr:$pr, verdict:$verdict, reason:"verdict-not-lgtm"}')")
        ;;
    esac
  done
}

# Step 3: post-merge cleanup. Driven off the actually-existing worker
# worktrees (bounded, small) rather than a "since last tick" timestamp
# window -- self-healing across a missed tick and needs no continuity with
# the previous state file.
cleanup_merged_worktrees() {
  local path branch pr_state st num did_pull=0
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ "$path" = "$REPO_ROOT" ] && continue
    branch=$(git -C "$path" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
    case "$branch" in
      worker/agent-*) ;;
      *) continue ;;
    esac
    pr_state=$(gh pr list --head "$branch" --state all --json number,state --jq '.[0] // empty' 2>/dev/null || true)
    [ -z "$pr_state" ] && continue
    st=$(printf '%s' "$pr_state" | jq -r '.state')
    num=$(printf '%s' "$pr_state" | jq -r '.number')
    if [ "$st" = "MERGED" ]; then
      if [ "$did_pull" -eq 0 ]; then
        run_cmd git -C "$REPO_ROOT" pull --ff-only
        run_cmd git -C "$REPO_ROOT" remote prune origin
        did_pull=1
      fi
      run_cmd git worktree remove "$path"
      run_cmd git branch -D "$branch"
      MERGED_PRS+=("$num")
    fi
  done < <(git -C "$REPO_ROOT" worktree list --porcelain | awk '/^worktree / {print $2}')
}

# Step 4: new dispatchable work. `bd ready` already excludes in_progress,
# blocked, deferred, and hooked issues (its own documented semantics), so
# no extra label-based "held" filter is needed on top of it -- decisions
# and epics are excluded here because they need mayor judgment on shape,
# not a worker dispatch.
check_bd_ready() {
  local out id
  out=$(bd ready --json --exclude-type decision,epic 2>/dev/null || echo '[]')
  while IFS= read -r id; do
    [ -n "$id" ] && BD_READY_IDS+=("$id")
  done < <(printf '%s' "$out" | jq -r '.[].id' 2>/dev/null || true)
}

# Step 5: worktree anomalies. Narrow on purpose -- host-process orphans,
# worktree-metadata pruning, and stale-branch deletion already belong to
# the (operator-kept, not scriptified here) 60m worktree-hygiene loop. This
# only flags a live worker worktree/branch with NO PR at all, which that
# loop's checks don't cover: it means a dispatch stalled before ever
# opening one.
check_worktree_anomalies() {
  local path branch count
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ "$path" = "$REPO_ROOT" ] && continue
    branch=$(git -C "$path" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
    case "$branch" in
      worker/agent-*) ;;
      *) continue ;;
    esac
    count=$(gh pr list --head "$branch" --state all --json number --jq 'length' 2>/dev/null || echo 0)
    if [ "${count:-0}" -eq 0 ]; then
      WORKTREE_ANOMALIES+=("$(jq -nc --arg path "$path" --arg branch "$branch" '{path:$path, branch:$branch, reason:"no-pr-for-branch"}')")
    fi
  done < <(git -C "$REPO_ROOT" worktree list --porcelain | awk '/^worktree / {print $2}')
}

# Step 6 (mayor-9syl7): self-heal reconciliation. Compensating layer for the
# SubagentStop hook missing a fire entirely (a push landing on a non-
# worker/agent-* head, upstream anthropics/claude-code#27755, or the hook
# exiting with an error) -- without this, an open worker PR with no queue
# entry AND no review sits invisible to the mayor until a manual audit
# catches it. Runs after process_review_queue so pr_already_queued sees
# this tick's queue state. Logged with the "mayor-tick reconcile:" prefix
# (distinct from process_review_queue's hook-fed path) so an audit can tell
# script-detected self-heal from hook-queued.
reconcile_missing_queue_entries() {
  local prs_json n url reviews_json latest
  prs_json=$(gh pr list --state open --json number,url,headRefName --jq \
    '[.[] | select(.headRefName | startswith("worker/agent-"))]' 2>/dev/null || echo '[]')

  for n in $(printf '%s' "$prs_json" | jq -r '.[].number' 2>/dev/null || true); do
    url=$(printf '%s' "$prs_json" | jq -r --argjson n "$n" '.[] | select(.number==$n) | .url')

    pr_already_queued "$url" && continue

    reviews_json=$(gh pr view "$n" --json reviews --jq '.reviews' 2>/dev/null || echo '[]')
    latest=$(latest_reviewer_review "$reviews_json")
    if [ -n "$latest" ] && [ "$latest" != "null" ]; then
      continue  # already reviewed despite no queue file -- nothing to self-heal
    fi

    echo "mayor-tick reconcile: PR #$n ($url) has no review-queue entry and no critical-reviewer review -- synthesizing pending_reviews entry" >&2
    PENDING_REVIEW_PRS+=("$n")
  done
}

main() {
  process_review_queue
  reconcile_missing_queue_entries
  gate_and_merge_prs
  cleanup_merged_worktrees
  check_bd_ready
  check_worktree_anomalies
  refresh_dashboard

  local bd_ready_count=${#BD_READY_IDS[@]}
  # PENDING_REVIEW_PRS is included here (not just QUEUE_FILES_REMAINING)
  # because reconcile_missing_queue_entries can append to it for a PR with
  # NO backing queue file at all -- without counting it directly, a
  # self-healed entry would leave exit_code at 0 (noop) and the mayor would
  # never read pending_reviews to dispatch it, defeating mayor-9syl7 outright.
  local exception_count=$(( ${#GATE_EXCEPTIONS[@]} + ${#QUEUE_FILES_REMAINING[@]} + ${#PENDING_REVIEW_PRS[@]} ))
  local worktree_count=${#WORKTREE_ANOMALIES[@]}
  local exit_code
  exit_code=$(compute_exit_code "$bd_ready_count" "$exception_count" "$worktree_count")

  # "${ARR[@]+"${ARR[@]}"}", not the bare "${ARR[@]}", at every call site
  # below: macOS ships bash 3.2 as /bin/bash (this script's own shebang
  # target), and 3.2's `set -u` treats a *zero-element* array's `[@]`
  # word-expansion as an unbound variable -- confirmed empirically, this
  # script errors out of main() entirely on a routine all-clear tick on any
  # unmodified macOS install. `${#ARR[@]}` (length, used above) is
  # unaffected; only the word-expansion form needs the guard.
  write_state "$exit_code" \
    "$(json_array "${QUEUE_FILES_REMAINING[@]+"${QUEUE_FILES_REMAINING[@]}"}")" \
    "$(json_number_array "${PENDING_REVIEW_PRS[@]+"${PENDING_REVIEW_PRS[@]}"}")" \
    "$(json_number_array "${MERGED_PRS[@]+"${MERGED_PRS[@]}"}")" \
    "$(json_array "${BD_READY_IDS[@]+"${BD_READY_IDS[@]}"}")" \
    "$(json_raw_array "${WORKTREE_ANOMALIES[@]+"${WORKTREE_ANOMALIES[@]}"}")" \
    "$(json_raw_array "${GATE_EXCEPTIONS[@]+"${GATE_EXCEPTIONS[@]}"}")" \
    "$(json_raw_array "${PENDING_NON_PR_REVIEWS[@]+"${PENDING_NON_PR_REVIEWS[@]}"}")" \
    "$(json_raw_array "${QUEUE_WARNINGS[@]+"${QUEUE_WARNINGS[@]}"}")"

  echo "mayor-tick: exit_code=$exit_code state=$STATE_FILE"
  exit "$exit_code"
}

if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  if [ "${1:-}" = "__call" ]; then
    shift
    "$@"
  else
    main "$@"
  fi
fi

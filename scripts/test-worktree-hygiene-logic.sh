#!/usr/bin/env bash
# Unit test for scripts/worktree-hygiene.sh's pure functions.
#
# Exercises the REAL script as a subprocess via its `__call <fn> [args...]`
# entry point (same "real script, not a reimplementation" technique the
# sibling scripts/test-*-logic.sh suites use) -- a reimplementation of the
# process-line parsing, branch-guard logic, or patch-id check would keep
# passing even if the real logic regressed.
#
# Covers the four areas the extraction from mayor-bootstrap.md is load-bearing
# for:
#   1. STEP A orphan detection (find_orphans / proc_type_from_psline /
#      extract_worktree_path_from_psline / kill_pattern_for) against
#      synthetic `ps aux` output -- a regression here either leaves a real
#      orphan process squatting on a VM slot's ports (never detected) or
#      kills a live worker's process (false positive on a live worktree).
#   2. STEP C's in-flight guard (checked_out_branches / is_checked_out) --
#      the mechanism that keeps a worker mid-dispatch from having its
#      branch force-deleted out from under it.
#   3. STEP C's patch-id merge check (is_unmerged_by_patch_id) -- the only
#      thing that distinguishes "safe to delete" from "would silently
#      destroy unmerged work," including the squash-merge case
#      `git branch --merged` would misjudge.
#   4. STEP D's gone-upstream match (gone_upstream_branches) -- must only
#      match branches whose upstream is actually `[gone]`, not ones with no
#      upstream configured at all (e.g. `investigation/*`).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/worktree-hygiene.sh"

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

SANDBOX_ROOT=$(mktemp -d)
trap 'rm -rf "$SANDBOX_ROOT"' EXIT

# ---------------------------------------------------------------------------
# 1. STEP A -- orphaned host process detection.
# ---------------------------------------------------------------------------

# Fixture argument styles match the real launchers in scripts/u7s-start.sh:
# apiserver/scheduler take `--kubeconfig <path>` space-separated; the
# konnectivity-server case below deliberately uses an `=`-joined flag
# (`--server-cert=<path>`, that binary's real style) to prove extraction
# doesn't leak the `--server-cert=` prefix into the matched worktree path.
# The sample-run-metrics.sh line matches its real launch shape (run-all.sh's
# `bash sample-run-metrics.sh start --workdir <path>/temp/u7s ...`, backgrounded
# via `sampler_loop &` so the surviving process keeps this exact argv) -- an
# orphan of this type is invisible resource use (RSS/vm-free polling against a
# VM slot that then looks free to the next dispatch), not a port bind, so it
# must be caught by the same pattern the other three types are.
PS_OUTPUT='alice  1111   0.0  0.1  123456  1234 s001  S+   10:00AM   0:00.05 target/release/u7s-apiserver --kubeconfig /Users/alice/worktrees/dead-worktree/temp/u7s/kubeconfig --port 6443
alice  1112   0.0  0.1  123456  1234 s001  S+   10:00AM   0:00.05 target/release/u7s-scheduler --kubeconfig /Users/alice/worktrees/live-worktree/temp/u7s/kubeconfig
alice  1113   0.0  0.1  123456  1234 s001  S+   10:00AM   0:00.05 konnectivity-server --logtostderr=true --server-cert=/Users/alice/worktrees/dead-worktree-2/temp/u7s/konnectivity-server.crt
alice  1114   0.0  0.1  123456  1234 s001  S+   10:00AM   0:00.05 bash scripts/conformance/sample-run-metrics.sh start --workdir /Users/alice/worktrees/dead-worktree-3/temp/u7s --port 6443 --vm lima-node-2'
LIVE_WORKTREES='/Users/alice/worktrees/live-worktree
/Users/alice/orchestrator-checkout'

ORPHANS=$(call find_orphans "$PS_OUTPUT" "$LIVE_WORKTREES")

assert "an apiserver process whose worktree is gone is flagged as an orphan" \
  "$(printf '%s\n' "$ORPHANS" | grep -qF '1111|apiserver|/Users/alice/worktrees/dead-worktree' && echo 1 || echo 0)"
assert "a konnectivity-server process whose worktree is gone is flagged as an orphan (its --flag=path style must not leak the '--server-cert=' prefix into the matched path)" \
  "$(printf '%s\n' "$ORPHANS" | grep -qF '1113|konnectivity-server|/Users/alice/worktrees/dead-worktree-2' && echo 1 || echo 0)"
assert "a sample-run-metrics.sh process whose worktree is gone is flagged as an orphan (regression: this type was dropped from STEP A's grep, letting it squat undetected)" \
  "$(printf '%s\n' "$ORPHANS" | grep -qF '1114|sample-run-metrics|/Users/alice/worktrees/dead-worktree-3' && echo 1 || echo 0)"
assert "a scheduler process whose worktree is still live is NOT flagged (must not kill a live worker's process)" \
  "$(! printf '%s\n' "$ORPHANS" | grep -q '^1112|' && echo 1 || echo 0)"
assert "exactly three orphans are found, not more (no false positives from the live-worktree line)" \
  "$([ "$(printf '%s\n' "$ORPHANS" | grep -c '|')" = "3" ] && echo 1 || echo 0)"

assert "an empty ps scan (no matching processes at all) yields no orphans" \
  "$([ -z "$(call find_orphans '' "$LIVE_WORKTREES")" ] && echo 1 || echo 0)"

assert "kill_pattern_for builds the apiserver pattern anchored on the dead worktree's kubeconfig path" \
  "$([ "$(call kill_pattern_for apiserver /dead)" = 'u7s-apiserver.*/dead/temp/u7s/kubeconfig' ] && echo 1 || echo 0)"
assert "kill_pattern_for builds the scheduler pattern anchored on the dead worktree's kubeconfig path" \
  "$([ "$(call kill_pattern_for scheduler /dead)" = 'u7s-scheduler.*/dead/temp/u7s/kubeconfig' ] && echo 1 || echo 0)"
assert "kill_pattern_for builds the konnectivity-server pattern anchored on the dead worktree's workdir (no /kubeconfig suffix)" \
  "$([ "$(call kill_pattern_for konnectivity-server /dead)" = 'konnectivity-server.*/dead/temp/u7s' ] && echo 1 || echo 0)"
assert "kill_pattern_for builds the sample-run-metrics.sh pattern anchored on the dead worktree's workdir (no /kubeconfig suffix -- it has no cert to serve, just polls the VM)" \
  "$([ "$(call kill_pattern_for sample-run-metrics /dead)" = 'sample-run-metrics.sh.*/dead/temp/u7s' ] && echo 1 || echo 0)"

assert "proc_type_from_psline classifies a sample-run-metrics.sh line as its own type (must not be silently ignored as an unmatched process)" \
  "$([ "$(call proc_type_from_psline 'bash scripts/conformance/sample-run-metrics.sh start --workdir /x/temp/u7s')" = 'sample-run-metrics' ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 1b. STEP A -- --live-agents protection. A worker whose worktree DIRECTORY
#     is already gone (the routine orphan case above) but whose agent-id
#     the mayor's ListAgents call still reports as running must never have
#     its host process killed -- path-existence alone is exactly the signal
#     that misclassified a genuinely live worker before this fix.
# ---------------------------------------------------------------------------

assert "agent_id_from_worktree_path extracts the trailing agent-<id> path component" \
  "$([ "$(call agent_id_from_worktree_path '/repo/ai/worktrees/agent-liveid123')" = "liveid123" ] && echo 1 || echo 0)"
assert "agent_id_from_worktree_path returns empty for a path with no ai/worktrees/agent-<id> suffix (e.g. the mayor's own checkout) -- never a candidate for the live-agents guard" \
  "$([ -z "$(call agent_id_from_worktree_path '/repo')" ] && echo 1 || echo 0)"

PS_OUTPUT_LIVE_AGENT='alice  2222   0.0  0.1  123456  1234 s001  S+   10:00AM   0:00.05 target/release/u7s-apiserver --kubeconfig /repo/ai/worktrees/agent-liveid123/temp/u7s/kubeconfig --port 6444'
RAW_ORPHAN_LIVE_AGENT=$(call find_orphans "$PS_OUTPUT_LIVE_AGENT" '')
assert "sanity: without the live-agents filter, this process is classified an orphan by path alone (its worktree isn't in the live-worktree-path list)" \
  "$(printf '%s\n' "$RAW_ORPHAN_LIVE_AGENT" | grep -qF '2222|apiserver|/repo/ai/worktrees/agent-liveid123' && echo 1 || echo 0)"

FILTERED_PROTECTED=$(call filter_orphans_by_live_agents "$RAW_ORPHAN_LIVE_AGENT" "liveid123")
assert "an orphan process whose embedded worktree belongs to an agent-id IN --live-agents is filtered out -- its host process must never be killed just because path-existence alone looks orphaned (the original bug: a ListAgents-confirmed-live worker's worktree/branch was reaped anyway)" \
  "$([ -z "$FILTERED_PROTECTED" ] && echo 1 || echo 0)"

FILTERED_STALE=$(call filter_orphans_by_live_agents "$RAW_ORPHAN_LIVE_AGENT" "some-other-agent")
assert "the SAME orphan record, with a --live-agents set that does NOT include its agent-id, survives filtering and remains a genuine kill target" \
  "$(printf '%s\n' "$FILTERED_STALE" | grep -qF '2222|apiserver|/repo/ai/worktrees/agent-liveid123' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. STEP C -- in-flight guard.
# ---------------------------------------------------------------------------

PORCELAIN='worktree /repo
HEAD abc123
branch refs/heads/main

worktree /worktrees/agent-live
HEAD def456
branch refs/heads/worker/agent-live'

CHECKED_OUT=$(call checked_out_branches "$PORCELAIN")
assert "checked_out_branches extracts every worktree's checked-out branch" \
  "$(printf '%s\n' "$CHECKED_OUT" | grep -qxF 'worker/agent-live' && printf '%s\n' "$CHECKED_OUT" | grep -qxF 'main' && echo 1 || echo 0)"

RC=0
call is_checked_out 'worker/agent-live' "$CHECKED_OUT" || RC=$?
assert "a branch checked out in a live worktree is guarded as in-flight (must not be force-deleted)" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_checked_out 'worker/agent-gone' "$CHECKED_OUT" || RC=$?
assert "a branch NOT checked out in any worktree is not guarded by the in-flight check" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. STEP C -- patch-id merge check. Runs real git (not synthetic text)
#    against a disposable sandbox repo with a real `origin` remote, since
#    patch-id comparison genuinely needs two commit graphs.
# ---------------------------------------------------------------------------

BARE="$SANDBOX_ROOT/origin.git"
git init -q --bare "$BARE"

S="$SANDBOX_ROOT/patchid-repo"
new_sandbox "$S"
printf 'line one\n' > "$S/file.txt"
git -C "$S" add -A
git -C "$S" commit -q -m initial
git -C "$S" remote add origin "$BARE"
git -C "$S" push -q origin main

# Genuinely unmerged: a worker branch with a commit `origin/main` has never
# seen at all.
git -C "$S" branch worker/agent-unmerged main
git -C "$S" checkout -q worker/agent-unmerged
printf 'line one\nunmerged addition\n' > "$S/file.txt"
git -C "$S" commit -q -am 'unmerged work'
git -C "$S" checkout -q main

RC=0
WORKTREE_HYGIENE_REPO_ROOT="$S" call is_unmerged_by_patch_id worker/agent-unmerged >/dev/null 2>&1 || RC=$?
assert "a branch with commits origin/main has never seen at all is flagged unmerged (skip deletion)" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

# Genuinely merged: a branch that is a literal ancestor of origin/main (its
# commit was pushed straight to main) -- `git cherry` reports no output at
# all, since every commit in the branch is already reachable from upstream.
git -C "$S" branch worker/agent-ff-merged main
printf 'line one\nff merged addition\n' > "$S/file.txt"
git -C "$S" commit -q -am 'ff-mergeable work'
git -C "$S" push -q origin main
RC=0
WORKTREE_HYGIENE_REPO_ROOT="$S" call is_unmerged_by_patch_id worker/agent-ff-merged >/dev/null 2>&1 || RC=$?
assert "a branch whose commits are already an ancestor of origin/main is NOT flagged unmerged (safe to delete)" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# The squash-merge case mayor-bootstrap.md's design specifically calls out:
# origin/main gains a NEW commit with the same net patch as the branch's
# commit (a different SHA, as a real squash-merge produces) --
# `git branch --merged` would call this branch unmerged (its commit SHA
# isn't an ancestor), but `git cherry` detects the patch-id match and still
# produces output (a `-`-prefixed line) -- so this branch is ALSO guarded
# as "has output, skip" under the loop body's literal semantics, same as
# the genuinely-unmerged case above (the loop is a conservative backstop,
# not the primary merge-cleanup path -- that's the merge/dashboard script's
# job once a PR is confirmed merged).
git -C "$S" checkout -q -b worker/agent-squashed main
printf 'line one\nsquash payload\n' > "$S/file.txt"
git -C "$S" commit -q -am 'squash payload'
git -C "$S" checkout -q main
printf 'line one\nsquash payload\n' > "$S/file.txt"
git -C "$S" commit -q -am 'squash payload (squash-merged onto main under a new SHA)'
git -C "$S" push -q origin main
RC=0
WORKTREE_HYGIENE_REPO_ROOT="$S" call is_unmerged_by_patch_id worker/agent-squashed >/dev/null 2>&1 || RC=$?
assert "a squash-merged branch (same patch, different SHA) still produces cherry output and is guarded, matching mayor-bootstrap.md's literal 'any output -> skip' rule" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3b. STEP C -- open-PR guard. Observed 2026-08-28: PR #1433's
#    commits reached main via a DIFFERENT PR (#1435) while #1433 itself was
#    still open -- patch-id alone would call #1433's branch safe to delete,
#    but deleting it would auto-close the still-open PR and destroy its
#    review state. This must be judged on PR state, not patch-id.
# ---------------------------------------------------------------------------
OPEN_PRS='worker/agent-has-open-pr
worker/agent-other-open-pr'

RC=0
call has_open_pr 'worker/agent-has-open-pr' "$OPEN_PRS" || RC=$?
assert "a branch with an open PR is guarded, even though its commits might already be merged elsewhere by patch-id" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call has_open_pr 'worker/agent-no-pr' "$OPEN_PRS" || RC=$?
assert "a branch with no open PR is not guarded by the open-PR check" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3c. STEP C -- live-worktree-directory guard. Observed
#    2026-08-28: a worker switched its worktree to a scratch branch
#    mid-dispatch, leaving worker/agent-<id> checked out nowhere --
#    is_checked_out alone is blind to this since it only sees what's
#    checked out RIGHT NOW, not which worktree directories still exist.
# ---------------------------------------------------------------------------
LIVE_AGENT_DIR="$SANDBOX_ROOT/live-agent-worktrees/ai/worktrees/agent-live123"
mkdir -p "$LIVE_AGENT_DIR"

RC=0
call has_live_worktree_dir 'worker/agent-live123' "$SANDBOX_ROOT/live-agent-worktrees" || RC=$?
assert "a worker/agent-<id> branch with a live worktree directory is guarded, regardless of what that worktree currently has checked out" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call has_live_worktree_dir 'worker/agent-gone456' "$SANDBOX_ROOT/live-agent-worktrees" || RC=$?
assert "a worker/agent-<id> branch with no matching worktree directory is not guarded by this check" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call has_live_worktree_dir 'main' "$SANDBOX_ROOT/live-agent-worktrees" || RC=$?
assert "a non-worker/agent-* branch name (e.g. main) never matches this check, even if a coincidentally-named directory existed" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3d. STEP C -- --live-agents guard. THE only reliable liveness signal for
#    an in-process worker sub-agent (a sub-agent cannot call ListAgents on
#    itself, and `claude agents --json` doesn't enumerate in-process
#    subagents -- both confirmed directly). Fires FIRST and unconditionally,
#    ahead of every other STEP C guard, since it's the only one that isn't
#    itself derivable from stale git/filesystem state.
# ---------------------------------------------------------------------------

RC=0
call is_live_agent_branch 'worker/agent-abc123' 'xyz999,abc123,def456' || RC=$?
assert "a worker/agent-<id> branch whose id is ANY entry in a comma-separated --live-agents list is protected" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'worker/agent-gone999' 'abc123,def456' || RC=$?
assert "a worker/agent-<id> branch whose id is NOT in --live-agents is not protected by this guard -- a genuinely stale branch must still be reapable" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'worker/agent-abc123' '' || RC=$?
assert "an empty --live-agents set protects nothing -- an unknown agent must never be assumed live" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'main' 'main' || RC=$?
assert "a non-worker/agent-* branch name never matches, even if it coincidentally equals a --live-agents entry" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# End-to-end: a worker branch that is ALREADY MERGED (ff-mergeable, so
# is_unmerged_by_patch_id says false), has no open PR, and no live worktree
# directory -- by every OTHER STEP C guard this branch is indistinguishable
# from a genuinely stale, safe-to-delete one. Only --live-agents membership
# can save it, proving the guard fires "unconditionally, regardless of dir
# existence or merge state" (the exact original bug: a ListAgents-confirmed-
# live worker's branch was force-deleted anyway because every OTHER signal
# said "safe").
BARE_LIVE="$SANDBOX_ROOT/origin-live.git"
git init -q --bare "$BARE_LIVE"

L="$SANDBOX_ROOT/step-c-live-agent-repo"
new_sandbox "$L"
printf 'line one\n' > "$L/file.txt"
git -C "$L" add -A
git -C "$L" commit -q -m initial
git -C "$L" remote add origin "$BARE_LIVE"
git -C "$L" push -q origin main

git -C "$L" branch worker/agent-liveagent456 main
printf 'line one\nmore work on main\n' > "$L/file.txt"
git -C "$L" commit -q -am 'advance main'
git -C "$L" push -q origin main

STUB_GH_NO_OPEN_PRS="$SANDBOX_ROOT/stub-gh-no-open-prs"
mkdir -p "$STUB_GH_NO_OPEN_PRS"
cat > "$STUB_GH_NO_OPEN_PRS/gh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$STUB_GH_NO_OPEN_PRS/gh"

LIVE_AGENTS="liveagent456" WORKTREE_HYGIENE_REPO_ROOT="$L" PATH="$STUB_GH_NO_OPEN_PRS:$PATH" \
  call step_c_stale_worker_branches >/dev/null 2>&1
assert "STEP C protects a worker/agent-<id> branch whose id IS in --live-agents even though it's already merged, has no open PR, and no live worktree directory -- every other guard alone would have called it safe to delete" \
  "$(git -C "$L" branch --list worker/agent-liveagent456 | grep -q worker/agent-liveagent456 && echo 1 || echo 0)"

LIVE_AGENTS="" WORKTREE_HYGIENE_REPO_ROOT="$L" PATH="$STUB_GH_NO_OPEN_PRS:$PATH" \
  call step_c_stale_worker_branches >/dev/null 2>&1
assert "...the SAME branch, with no matching --live-agents entry, is force-deleted -- proving the guard (not some accident of the other checks) is what protected it above" \
  "$(! git -C "$L" branch --list worker/agent-liveagent456 | grep -q worker/agent-liveagent456 && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. STEP D -- gone-upstream match.
# ---------------------------------------------------------------------------

FOR_EACH_REF='main [ahead 1]
worker/agent-done [gone]
investigation/scratch
worker/agent-active [behind 2]'

GONE=$(call gone_upstream_branches "$FOR_EACH_REF")
assert "a branch with a [gone] upstream is matched for deletion" \
  "$(printf '%s\n' "$GONE" | grep -qxF 'worker/agent-done' && echo 1 || echo 0)"
assert "a branch with no upstream configured at all (no track field) is NOT matched (only [gone] counts, not merely absent)" \
  "$(! printf '%s\n' "$GONE" | grep -qxF 'investigation/scratch' && echo 1 || echo 0)"
assert "a branch that is merely behind (not gone) is NOT matched" \
  "$(! printf '%s\n' "$GONE" | grep -qxF 'worker/agent-active' && echo 1 || echo 0)"
assert "a branch that is ahead (not gone) is NOT matched" \
  "$(! printf '%s\n' "$GONE" | grep -qxF 'main' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4b. STEP D -- checked-out guard, exercised end-to-end (not via a
#    reimplemented text check) against a disposable sandbox repo with a real
#    worktree, since the bug is a genuine `git branch -d` refusal, not a
#    text-matching mistake. Regression: observed 2026-09-06 twice (PRs
#    #1595, #1599) -- a worker branch's upstream goes `[gone]` the instant
#    the merge queue deletes its remote head, which can race ahead of the
#    tick that reaps its worktree. Unlike STEP C, STEP D had no
#    is_checked_out guard, so `git branch -d` on that still-checked-out
#    branch made git refuse, and this script's `set -e` turned that refusal
#    into a whole-run abort (skipping STEP E) on what is actually a benign,
#    self-resolving race.
# ---------------------------------------------------------------------------

BARE_D="$SANDBOX_ROOT/origin-d.git"
git init -q --bare "$BARE_D"

D="$SANDBOX_ROOT/step-d-repo"
new_sandbox "$D"
printf 'line one\n' > "$D/file.txt"
git -C "$D" add -A
git -C "$D" commit -q -m initial
git -C "$D" remote add origin "$BARE_D"
git -C "$D" push -q origin main

# A branch checked out in a second worktree, then merged and its remote
# head deleted -- exactly the merge-queue race: local upstream tracking
# still points at origin/worker/agent-gone, but that ref is gone.
git -C "$D" branch worker/agent-gone main
git -C "$D" push -q -u origin worker/agent-gone
git -C "$D" worktree add -q "$SANDBOX_ROOT/step-d-worktree" worker/agent-gone
git -C "$D" push -q origin --delete worker/agent-gone
git -C "$D" fetch -q --prune origin

RC=0
WORKTREE_HYGIENE_REPO_ROOT="$D" call step_d_gone_upstream_branches >/dev/null 2>&1 || RC=$?
assert "STEP D does not abort the whole hygiene tick (skipping STEP E) when a gone-upstream branch is still checked out in a live worktree" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"
assert "...and the branch itself survives -- skipped for the tick's reap, not force-deleted out from under the live worktree" \
  "$(git -C "$D" branch --list worker/agent-gone | grep -q worker/agent-gone && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4c. STEP D -- --live-agents guard, exercised end-to-end against a
#    gone-upstream branch that is NOT checked out anywhere (unlike 4b
#    above, which covers the is_checked_out guard specifically) -- by
#    STEP D's only OTHER guard this branch is fully reapable via `-d`.
#    Only --live-agents membership can save it.
# ---------------------------------------------------------------------------

BARE_D2="$SANDBOX_ROOT/origin-d2.git"
git init -q --bare "$BARE_D2"

D2="$SANDBOX_ROOT/step-d-live-agent-repo"
new_sandbox "$D2"
printf 'line one\n' > "$D2/file.txt"
git -C "$D2" add -A
git -C "$D2" commit -q -m initial
git -C "$D2" remote add origin "$BARE_D2"
git -C "$D2" push -q origin main

git -C "$D2" branch worker/agent-liveagent789 main
git -C "$D2" push -q -u origin worker/agent-liveagent789
git -C "$D2" push -q origin --delete worker/agent-liveagent789
git -C "$D2" fetch -q --prune origin

LIVE_AGENTS="liveagent789" WORKTREE_HYGIENE_REPO_ROOT="$D2" call step_d_gone_upstream_branches >/dev/null 2>&1
assert "STEP D protects a gone-upstream worker/agent-<id> branch whose id IS in --live-agents, even though it's not checked out anywhere (STEP D's only other guard)" \
  "$(git -C "$D2" branch --list worker/agent-liveagent789 | grep -q worker/agent-liveagent789 && echo 1 || echo 0)"

LIVE_AGENTS="" WORKTREE_HYGIENE_REPO_ROOT="$D2" call step_d_gone_upstream_branches >/dev/null 2>&1
assert "...the SAME branch, with no matching --live-agents entry, is deleted -- proving the guard is what saved it above" \
  "$(! git -C "$D2" branch --list worker/agent-liveagent789 | grep -q worker/agent-liveagent789 && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 5. run_cmd dry-run gate -- the mechanism that keeps THIS test suite (and
#    any manual dry-run) from ever killing a real process or deleting a
#    real branch.
# ---------------------------------------------------------------------------

MARKER="$SANDBOX_ROOT/marker"
OUT=$(DRY_RUN=1 call run_cmd touch "$MARKER")
assert "DRY_RUN=1 logs the command instead of running it" \
  "$(printf '%s' "$OUT" | grep -q 'would run: touch' && echo 1 || echo 0)"
assert "...and the gated command genuinely did not execute" \
  "$([ ! -e "$MARKER" ] && echo 1 || echo 0)"

call run_cmd touch "$MARKER" >/dev/null
assert "without DRY_RUN, run_cmd executes the real command" \
  "$([ -e "$MARKER" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 6. STEP E -- findings-enforcement drift backstop. Only the two pure
#    functions are covered here (bead-id extraction and staleness
#    classification, which together fully capture the branching logic);
#    step_e_stale_findings() itself isn't, since it calls live `bd show`
#    against this repo's real, mutable bead state -- referencing a real
#    bead ID here would make the test's outcome depend on that bead's
#    status at whatever moment CI happens to run, silently flipping
#    PASS/FAIL as unrelated bead lifecycle events occur elsewhere. This was
#    instead verified manually against real live bd state during
#    development (a scratch ai/findings/*.md staged against a genuinely
#    closed bead, a genuinely open bead, and a nonexistent bead ID all
#    produced the expected warn/silent split) -- the same "exercise the
#    real thing, not a synthetic stand-in" principle this suite follows
#    elsewhere, just not automatable here without a disposable bd database.
# ---------------------------------------------------------------------------

# Fixture suffixes below are intentionally 2 chars, one below the real
# generator's 3-5 char range (see check-bead-id-refs.sh), so these
# synthetic bead-ID-shaped strings don't trip that guard's rot check --
# they're placeholders for the parser test, not references to real beads.
FINDING_CLOSED="$SANDBOX_ROOT/finding-closed.md"
printf 'Bead: mayor-fx\n\nBody text.\n' > "$FINDING_CLOSED"
assert "bead_id_from_finding extracts the bead id from a well-formed header" \
  "$([ "$(call bead_id_from_finding "$FINDING_CLOSED")" = "mayor-fx" ] && echo 1 || echo 0)"

FINDING_NO_HEADER="$SANDBOX_ROOT/finding-no-header.md"
printf 'Just prose, no bead reference.\n' > "$FINDING_NO_HEADER"
assert "bead_id_from_finding returns empty for a file with no Bead: header (must not be treated as a match for any bead)" \
  "$([ -z "$(call bead_id_from_finding "$FINDING_NO_HEADER")" ] && echo 1 || echo 0)"

# Regression: a header with trailing descriptive text (e.g. a parenthetical
# naming related beads) used to be slurped whole, whitespace stripped, into
# one mangled compound token that matches no live bd record -- so a real,
# still-open finding got flagged stale and recommended for deletion. The
# parser must stop at the first bead-ID token and ignore everything after.
FINDING_TRAILING="$SANDBOX_ROOT/finding-trailing.md"
printf 'Bead: mayor-tp (decision-prep for mayor-ab Phase 3 / mayor-cd)\n\nBody text.\n' > "$FINDING_TRAILING"
EXTRACTED_TRAILING=$(call bead_id_from_finding "$FINDING_TRAILING")
assert "bead_id_from_finding stops at the bead-ID token instead of slurping trailing text (incl. other mayor-* mentions) into a mangled string that would never match any live bead" \
  "$([ "$EXTRACTED_TRAILING" = "mayor-tp" ] && echo 1 || echo 0)"

# Feeding the correctly-extracted id's status through is_stale_bead_status
# as "open" proves the fix, not a coincidental match, is what keeps a live
# finding with a trailing-parenthetical header from being flagged stale.
RC=0
call is_stale_bead_status "open" || RC=$?
assert "a trailing-parenthetical header for an open bead ($EXTRACTED_TRAILING) is NOT flagged stale once the id is extracted correctly" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_stale_bead_status "closed" || RC=$?
assert "is_stale_bead_status flags a closed bead as stale (the case check-findings-closed-bead-refs.sh already catches via the export)" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_stale_bead_status "" || RC=$?
assert "is_stale_bead_status flags an empty (no live bd record) status as stale -- the pruned-bead hole the export-based CI check cannot see" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_stale_bead_status "open" || RC=$?
assert "is_stale_bead_status does NOT flag an open bead -- must not warn on every routine in-flight finding" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_stale_bead_status "in_progress" || RC=$?
assert "is_stale_bead_status does NOT flag an in_progress bead" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 7. main()'s fail-safe refusal without --live-agents. STEP A/C/D are
#    destructive (process kill, branch delete); dir-existence and
#    merge-state checks alone already proved insufficient to tell a live
#    worker apart from a stale one, so a missing flag must abort the whole
#    run rather than guess "assume none live" or "assume all live". This
#    permanently forecloses the reap-a-live-worker bug class via
#    mis-invocation. Invokes the real script directly (not via __call,
#    which bypasses main()'s own argv parsing and this exact gate) with no
#    args at all -- safe because the refusal fires before any step runs, so
#    no real `ps aux`/git state is ever touched.
# ---------------------------------------------------------------------------

FAILSAFE_RC=0
FAILSAFE_OUT=$(bash "$SCRIPT" 2>&1) || FAILSAFE_RC=$?
assert "worktree-hygiene refuses to run at all when --live-agents is omitted, exiting non-zero instead of silently defaulting" \
  "$([ "$FAILSAFE_RC" -eq 2 ] && echo 1 || echo 0)"
assert "...and the refusal is explained on stderr naming the missing flag, not a silent no-op" \
  "$(printf '%s' "$FAILSAFE_OUT" | grep -q -- '--live-agents' && echo 1 || echo 0)"
assert "...and no destructive-step log output appears at all -- STEP A/B/C/D/E never even started" \
  "$(! printf '%s' "$FAILSAFE_OUT" | grep -qE '\[hygiene\]|worktree prune' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

#!/usr/bin/env bash
# Unit test for scripts/worktree-hygiene.sh's pure functions.
#
# Exercises the REAL script as a subprocess via its `__call <fn> [args...]`
# entry point (same "real script, not a reimplementation" technique the
# sibling scripts/test-*-logic.sh suites use) -- a reimplementation of the
# process-line parsing, branch-guard logic, or patch-id check would keep
# passing even if the real logic regressed.
#
# Covers the four areas the extraction from bootstrap.md is load-bearing
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
PS_OUTPUT='alice  1111   0.0  0.1  123456  1234 s001  S+   10:00AM   0:00.05 target/release/u7s-apiserver --kubeconfig /Users/alice/worktrees/dead-worktree/temp/u7s/kubeconfig --port 6443
alice  1112   0.0  0.1  123456  1234 s001  S+   10:00AM   0:00.05 target/release/u7s-scheduler --kubeconfig /Users/alice/worktrees/live-worktree/temp/u7s/kubeconfig
alice  1113   0.0  0.1  123456  1234 s001  S+   10:00AM   0:00.05 konnectivity-server --logtostderr=true --server-cert=/Users/alice/worktrees/dead-worktree-2/temp/u7s/konnectivity-server.crt'
LIVE_WORKTREES='/Users/alice/worktrees/live-worktree
/Users/alice/orchestrator-checkout'

ORPHANS=$(call find_orphans "$PS_OUTPUT" "$LIVE_WORKTREES")

assert "an apiserver process whose worktree is gone is flagged as an orphan" \
  "$(printf '%s\n' "$ORPHANS" | grep -qF '1111|apiserver|/Users/alice/worktrees/dead-worktree' && echo 1 || echo 0)"
assert "a konnectivity-server process whose worktree is gone is flagged as an orphan (its --flag=path style must not leak the '--server-cert=' prefix into the matched path)" \
  "$(printf '%s\n' "$ORPHANS" | grep -qF '1113|konnectivity-server|/Users/alice/worktrees/dead-worktree-2' && echo 1 || echo 0)"
assert "a scheduler process whose worktree is still live is NOT flagged (must not kill a live worker's process)" \
  "$(! printf '%s\n' "$ORPHANS" | grep -q '^1112|' && echo 1 || echo 0)"
assert "exactly two orphans are found, not more (no false positives from the live-worktree line)" \
  "$([ "$(printf '%s\n' "$ORPHANS" | grep -c '|')" = "2" ] && echo 1 || echo 0)"

assert "an empty ps scan (no matching processes at all) yields no orphans" \
  "$([ -z "$(call find_orphans '' "$LIVE_WORKTREES")" ] && echo 1 || echo 0)"

assert "kill_pattern_for builds the apiserver pattern anchored on the dead worktree's kubeconfig path" \
  "$([ "$(call kill_pattern_for apiserver /dead)" = 'u7s-apiserver.*/dead/temp/u7s/kubeconfig' ] && echo 1 || echo 0)"
assert "kill_pattern_for builds the scheduler pattern anchored on the dead worktree's kubeconfig path" \
  "$([ "$(call kill_pattern_for scheduler /dead)" = 'u7s-scheduler.*/dead/temp/u7s/kubeconfig' ] && echo 1 || echo 0)"
assert "kill_pattern_for builds the konnectivity-server pattern anchored on the dead worktree's workdir (no /kubeconfig suffix)" \
  "$([ "$(call kill_pattern_for konnectivity-server /dead)" = 'konnectivity-server.*/dead/temp/u7s' ] && echo 1 || echo 0)"

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

# The squash-merge case bootstrap.md's design specifically calls out:
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
assert "a squash-merged branch (same patch, different SHA) still produces cherry output and is guarded, matching bootstrap.md's literal 'any output -> skip' rule" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

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
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

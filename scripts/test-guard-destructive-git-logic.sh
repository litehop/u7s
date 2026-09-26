#!/usr/bin/env bash
# Unit test for scripts/guard-destructive-git.sh, the PreToolUse hook that
# blocks destructive git commands against `main` / the mayor checkout.
#
# Exercises the REAL script as a subprocess (full stdin-JSON hook path, plus
# its `__call <fn>` entry point for the two halves of the OR-condition) --
# same "real script, not a reimplementation" technique the sibling
# scripts/test-*-logic.sh suites use.
#
# Root incident this guards against: a critical-reviewer ran
# `git checkout pr-1687-review -- .` then `cd <mayor checkout> && git reset
# --hard HEAD` directly in the mayor checkout, wiping uncommitted work. Git
# has no pre-reset hook, so this guard lives at the Claude Code tool layer.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/guard-destructive-git.sh"

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

SANDBOX_ROOT=$(mktemp -d)
SANDBOX_ROOT=$(cd "$SANDBOX_ROOT" && pwd -P)  # macOS mktemp -d returns a /var symlink; canonicalize so raw paths match git's realpath'd output (e.g. /private/var/...) in the __call comparisons below
trap 'rm -rf "$SANDBOX_ROOT"' EXIT
ERR_FILE="$SANDBOX_ROOT/hook-stderr"

RC=0
# run_hook <command-string> <cwd> -- feeds real PreToolUse-shaped JSON on
# stdin (the actual hook input contract), sets $RC; stderr lands in $ERR_FILE.
run_hook() {
  local cmd="$1" cwd="$2"
  jq -n --arg cmd "$cmd" --arg cwd "$cwd" \
    '{cwd: $cwd, tool_input: {command: $cmd}}' \
    | bash "$SCRIPT" >/dev/null 2>"$ERR_FILE"
  RC=$?
}

blocked() { run_hook "$1" "$2"; [ "$RC" = "2" ] && echo 1 || echo 0; }
allowed() { run_hook "$1" "$2"; [ "$RC" = "0" ] && echo 1 || echo 0; }

# ---------------------------------------------------------------------------
# Sandbox: a main worktree on branch `main` plus a linked worktree on a
# worker branch, mirroring the real mayor checkout vs. worker worktree split.
# ---------------------------------------------------------------------------
MAIN="$SANDBOX_ROOT/main-checkout"
WORKER="$SANDBOX_ROOT/worker-worktree"

git init -q -b main "$MAIN"
git -C "$MAIN" config user.email test@example.com
git -C "$MAIN" config user.name "Test"
echo hello > "$MAIN/a.txt"
git -C "$MAIN" add a.txt
git -C "$MAIN" commit -q -m init
git -C "$MAIN" worktree add -q -b worker/agent-x "$WORKER" main

# ---------------------------------------------------------------------------
# 1. The reviewer's two exact commands from the incident.
# ---------------------------------------------------------------------------
assert "reviewer's exact 'cd <mayor> && git reset --hard HEAD' is blocked -- this is the literal command that wiped uncommitted work" \
  "$(blocked "cd $MAIN && git reset --hard HEAD" "$WORKER")"
assert "reviewer's exact 'git checkout pr-1687-review -- .' run from inside the mayor checkout is blocked -- the '-- .' form that pulled a whole PR tree onto disk" \
  "$(blocked "git checkout pr-1687-review -- ." "$MAIN")"

# ---------------------------------------------------------------------------
# 2. Each destructive form, blocked on main, allowed in the linked worktree.
#    If any of these regress to allowed-on-main, a worker/reviewer session
#    on main can silently discard uncommitted work again.
# ---------------------------------------------------------------------------
declare -a FORMS=(
  "git reset --hard HEAD|reset --hard discards uncommitted changes and unstaged history"
  "git checkout other -- .|checkout -- <path> overwrites worktree files from another ref"
  "git restore a.txt|restore with no --staged overwrites the worktree file from the index"
  "git stash|bare stash silently pockets uncommitted changes out of the worktree"
  "git stash push|stash push removes uncommitted changes from the worktree"
  "git stash drop|stash drop discards a stash entry with no way back"
  "git clean -fd|clean -f deletes untracked files with no trash/undo"
  "git switch -f other|switch -f discards local changes when switching branches"
  "git switch --discard-changes|switch --discard-changes is switch -f's long form"
)

for entry in "${FORMS[@]}"; do
  cmd="${entry%%|*}"
  why="${entry#*|}"
  assert "'$cmd' on main is blocked -- $why" "$(blocked "$cmd" "$MAIN")"
  assert "'$cmd' in the linked worker worktree is allowed -- destructive git on a worker's own branch is the normal workflow, not an incident" \
    "$(allowed "$cmd" "$WORKER")"
done

# ---------------------------------------------------------------------------
# 3. restore's --staged carve-out: unstaging never touches the worktree, so
#    it must not be blocked even on main; adding --worktree back in makes it
#    destructive again despite --staged also being present.
# ---------------------------------------------------------------------------
assert "'git restore --staged a.txt' on main is allowed -- unstaging alone cannot discard worktree edits" \
  "$(allowed "git restore --staged a.txt" "$MAIN")"
assert "'git restore --staged --worktree a.txt' on main is blocked -- --worktree overwrites the file even with --staged also given" \
  "$(blocked "git restore --staged --worktree a.txt" "$MAIN")"

# ---------------------------------------------------------------------------
# 4. stash/checkout forms the bead explicitly excludes must stay allowed --
#    over-blocking would make the guard train reviewers to route around it.
# ---------------------------------------------------------------------------
assert "'git stash list' on main is allowed -- inspecting the stash list is read-only" \
  "$(allowed "git stash list" "$MAIN")"
assert "'git stash apply' on main is allowed -- applying (not popping) leaves the stash entry intact" \
  "$(allowed "git stash apply" "$MAIN")"
assert "'git checkout other' (plain branch switch, no -- <path>) on main is allowed -- git itself refuses a switch that would clobber tracked changes" \
  "$(allowed "git checkout main" "$MAIN")"

# ---------------------------------------------------------------------------
# 5. git -C targeting: the protected repo is the one named by -C, not
#    whatever cwd the Bash tool happened to start in.
# ---------------------------------------------------------------------------
assert "'git -C <mayor> reset --hard HEAD' run from a worker cwd is blocked -- -C repoints the destructive command at the mayor checkout" \
  "$(blocked "git -C $MAIN reset --hard HEAD" "$WORKER")"
assert "'git -C <worker> reset --hard HEAD' run from the mayor cwd is allowed -- -C repoints it at the worker's own worktree" \
  "$(allowed "git -C $WORKER reset --hard HEAD" "$MAIN")"

# ---------------------------------------------------------------------------
# 6. Non-destructive git on main must pass untouched -- the guard must not
#    turn every git command into a manual-override chore.
# ---------------------------------------------------------------------------
assert "'git status' on main is allowed -- read-only commands are never in scope" \
  "$(allowed "git status" "$MAIN")"
assert "'git log --oneline -5' on main is allowed -- read-only commands are never in scope" \
  "$(allowed "git log --oneline -5" "$MAIN")"
assert "'git pull --ff-only' on main is allowed -- a fast-forward-only pull cannot discard local commits" \
  "$(allowed "git pull --ff-only" "$MAIN")"

# ---------------------------------------------------------------------------
# 7. Fail-open on missing/unparseable hook input -- a hook bug must never
#    block every Bash call in every session.
# ---------------------------------------------------------------------------
RC=0; : | bash "$SCRIPT" >/dev/null 2>"$ERR_FILE"; RC=$?
assert "empty stdin fails open (exit 0), not blocked -- a broken hook must not brick every Bash call" "$([ "$RC" = "0" ] && echo 1 || echo 0)"
assert "empty stdin logs a warning to stderr so the failure is visible, not silent" \
  "$(grep -qi 'fail' "$ERR_FILE" && echo 1 || echo 0)"

RC=0; echo '{"cwd":"'"$MAIN"'","tool_input":{}}' | bash "$SCRIPT" >/dev/null 2>"$ERR_FILE"; RC=$?
assert "hook input with no tool_input.command (e.g. a non-Bash tool call) fails open, not blocked" \
  "$([ "$RC" = "0" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 8. Isolate each half of is_target_protected's OR via __call, so this test
#    fails if EITHER half is deleted -- proving each half is load-bearing,
#    per CLAUDE.md Rule 14 (a regression test must fail if the fix reverts).
# ---------------------------------------------------------------------------
call() { bash "$SCRIPT" __call "$@"; }

RC=0
MAIN_ROOT=/nonexistent/does-not-match-anything call is_target_protected "$MAIN" >/dev/null 2>&1
RC=$?
assert "is_target_protected's branch=='main' check alone protects the mayor checkout, even with MAIN_ROOT pointing elsewhere -- deleting this arm would let a reviewer on main slip past when MAIN_ROOT is stale" \
  "$([ "$RC" = "0" ] && echo 1 || echo 0)"

RC=0
MAIN_ROOT="$WORKER" call is_target_protected "$WORKER" >/dev/null 2>&1
RC=$?
assert "is_target_protected's toplevel==MAIN_ROOT check alone protects a repo not on branch main -- deleting this arm would miss a detached-HEAD or renamed-default-branch mayor checkout" \
  "$([ "$RC" = "0" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 9. Bare-path checkout (no `--` at all) discards worktree changes exactly
#    like the `-- <path>` form, but has no `--` for the old regex to match.
#    Must block on main; -B branch creation, which the worker setup flow
#    depends on, must stay allowed even on a protected target.
# ---------------------------------------------------------------------------
assert "'git checkout .' on main is blocked -- with no '--' at all this silently discards every uncommitted worktree change" \
  "$(blocked "git checkout ." "$MAIN")"
assert "'git checkout a.txt' on main is blocked -- checking out an existing tracked path with no '--' overwrites it from the index" \
  "$(blocked "git checkout a.txt" "$MAIN")"
assert "'git checkout -B x origin/y' on main is allowed -- -B branch creation must survive the bare-path check even on a protected target" \
  "$(allowed "git checkout -B x origin/y" "$MAIN")"
assert "'git checkout -B x origin/y' in the linked worker worktree is allowed -- this is the exact 'checkout -B <branch> <remote-ref>' form the worker setup flow depends on" \
  "$(allowed "git checkout -B x origin/y" "$WORKER")"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

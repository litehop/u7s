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
# 10. MAIN_ROOT must identify the mayor checkout specifically, not "whatever
#     repo the hook happens to be checking" -- a standalone repo with no
#     linked worktrees is not the mayor just because it has no worktree
#     siblings, and a worker session naming the mayor via `-C` must still
#     resolve to the mayor's fixed identity regardless of the worker's own
#     branch/toplevel.
# ---------------------------------------------------------------------------
FRESH_STANDALONE="$SANDBOX_ROOT/fresh-standalone-repo"
git init -q -b master "$FRESH_STANDALONE"
git -C "$FRESH_STANDALONE" config user.email test@example.com
git -C "$FRESH_STANDALONE" config user.name "Test"
echo x > "$FRESH_STANDALONE/f.txt"
git -C "$FRESH_STANDALONE" add f.txt
git -C "$FRESH_STANDALONE" commit -q -m init

assert "'git reset --hard HEAD' in a fresh standalone repo with no linked worktrees (not the mayor checkout, not on branch main) is allowed -- having no worktree siblings must not make an unrelated repo see itself as the mayor" \
  "$(CLAUDE_PROJECT_DIR= allowed "git reset --hard HEAD" "$FRESH_STANDALONE")"

TRUNK_BRANCH_CHECKOUT="$SANDBOX_ROOT/trunk-branch-checkout"
git init -q -b trunk "$TRUNK_BRANCH_CHECKOUT"
git -C "$TRUNK_BRANCH_CHECKOUT" config user.email test@example.com
git -C "$TRUNK_BRANCH_CHECKOUT" config user.name "Test"
echo y > "$TRUNK_BRANCH_CHECKOUT/g.txt"
git -C "$TRUNK_BRANCH_CHECKOUT" add g.txt
git -C "$TRUNK_BRANCH_CHECKOUT" commit -q -m init

assert "'git -C <trunk-branch-checkout> reset --hard HEAD' from a worker cwd is blocked via CLAUDE_PROJECT_DIR even though this mayor checkout's branch isn't literally 'main' -- a worker's own branch/toplevel must never leak into the mayor's identity" \
  "$(CLAUDE_PROJECT_DIR="$TRUNK_BRANCH_CHECKOUT" blocked "git -C $TRUNK_BRANCH_CHECKOUT reset --hard HEAD" "$WORKER")"

# ---------------------------------------------------------------------------
# 11. A flag before/instead of the stash subcommand must not read as an
#     allowed subcommand -- `git stash -u` has no subcommand word at all
#     (it's an implicit `push -u`), exactly as destructive as bare
#     `git stash`, but a naive "match $2 against an exact list" missed it.
# ---------------------------------------------------------------------------
assert "'git stash -u' on main is blocked -- no subcommand word means implicit push, just as destructive as bare 'git stash'" \
  "$(blocked "git stash -u" "$MAIN")"
assert "'git stash --all' on main is blocked -- same implicit-push case with a different flag" \
  "$(blocked "git stash --all" "$MAIN")"
assert "'git stash -u' in the linked worker worktree is allowed -- destructive git on a worker's own branch is the normal workflow, not an incident" \
  "$(allowed "git stash -u" "$WORKER")"
assert "'git stash branch tmp-branch' on main is allowed -- branch never discards the stash entry, matching apply's carve-out" \
  "$(allowed "git stash branch tmp-branch" "$MAIN")"
assert "'git stash pop' on main is blocked -- pop removes uncommitted changes from the worktree, same as before this rewrite" \
  "$(blocked "git stash pop" "$MAIN")"

# ---------------------------------------------------------------------------
# 12. bd regenerates .beads/issues.jsonl + interactions.jsonl in the mayor
#     checkout on every write; after a bead-snapshot PR merges they block
#     `git pull --ff-only`. Discarding exactly those two files is safe (Dolt
#     DB is authoritative); every other discard stays protected.
# ---------------------------------------------------------------------------
J=".beads/issues.jsonl"
I=".beads/interactions.jsonl"
mkdir -p "$MAIN/.beads"
: > "$MAIN/$J"
: > "$MAIN/$I"
declare -a BEAD_ALLOWED=(
  "git restore --staged --worktree $J $I"
  "git restore --worktree $J"
  "git restore $I"
  "git restore --staged --worktree -- $J $I"
  "git checkout -- $J $I"
  "git -C $MAIN restore --staged --worktree $J $I"
)
for cmd in "${BEAD_ALLOWED[@]}"; do
  assert "'$cmd' on the mayor checkout is allowed -- the mayor must be able to discard regenerated bead exports to unblock git pull --ff-only after a bead snapshot merges" \
    "$(allowed "$cmd" "$MAIN")"
done

declare -a BEAD_BLOCKED=(
  "git restore --staged --worktree $J $I .beads/config.yaml"
  "git restore --staged --worktree $J a.txt"
  "git restore --staged --worktree .beads/*"
  "git restore --worktree *.jsonl"
  "git restore --worktree .beads"
  "git restore --worktree ."
  "git restore --worktree :/"
  "git restore --worktree :(glob)$J"
  "git restore --source=HEAD~1 --worktree $J"
  "git restore -p $J"
  "git restore --worktree"
  "git restore --worktree -- --staged"
  "git checkout -- $J a.txt"
  "git checkout -- .beads"
  "git checkout -- ."
  "git checkout HEAD~1 -- $J"
  "git checkout other -- $J $I"
  "git checkout $J"
  "git reset --hard HEAD"
  "git clean -fd .beads"
  "git stash push -- $J"
  "git stash drop"
)
for cmd in "${BEAD_BLOCKED[@]}"; do
  assert "'$cmd' on the mayor checkout stays blocked -- the bead-export exception covers only the two JSONL files, other discards stay protected" \
    "$(blocked "$cmd" "$MAIN")"
done
assert "'git restore --staged --worktree $J $I' stays blocked when chained after a blocked command -- the exception is per command segment" \
  "$(blocked "git reset --hard HEAD && git restore --staged --worktree $J $I" "$MAIN")"

# ---------------------------------------------------------------------------
# 13. Bypasses: aliases, line continuations, command substitution. Each hides
#     a destructive op from a naive "segment starts with `git <verb>`" match.
# ---------------------------------------------------------------------------
assert "'git -c alias.x=\"reset --hard\" x' on main is blocked -- an alias smuggles a destructive verb past the verb match" \
  "$(blocked "git -c alias.x='reset --hard' x" "$MAIN")"
assert "'git -c alias.x=!rm x' on main is blocked -- shell aliases run arbitrary commands" \
  "$(blocked "git -c alias.x=!true x" "$MAIN")"
assert "'git -C <main> -c alias.x=... x' from a worker cwd is blocked -- -C and -c combine" \
  "$(blocked "git -C $MAIN -c alias.x=reset x" "$WORKER")"
assert "'git -c alias.x=... x' in the worker worktree is allowed -- aliases only matter on protected targets" \
  "$(allowed "git -c alias.x=reset x" "$WORKER")"
assert "'git -c core.x=y reset --hard' on main is blocked -- a -c prefix must not hide the verb" \
  "$(blocked "git -c core.x=y reset --hard" "$MAIN")"
assert "'git -c color.ui=false status' on main is allowed -- benign -c config is not an alias" \
  "$(allowed "git -c color.ui=false status" "$MAIN")"

assert "backslash-newline split 'git reset \\\\\\n --hard' on main is blocked -- the shell joins the lines into one destructive command" \
  "$(blocked $'git reset \\\n--hard' "$MAIN")"
assert "backslash-newline split 'git \\\\\\n reset --hard' on main is blocked -- the verb itself can be split" \
  "$(blocked $'git \\\nreset --hard' "$MAIN")"
assert "multi-line command with a harmless first line and 'git status' second is allowed" \
  "$(allowed $'echo hi \\\n there\ngit status' "$MAIN")"

assert "'\$(true) git reset --hard' on main is blocked -- a substitution prefix must not hide the git segment" \
  "$(blocked '$(true) git reset --hard' "$MAIN")"
assert "'echo \$(git reset --hard)' on main is blocked -- the destructive op runs inside the substitution" \
  "$(blocked 'echo $(git reset --hard)' "$MAIN")"
assert "'echo \`git reset --hard\`' on main is blocked -- backtick substitution runs it too" \
  "$(blocked 'echo `git reset --hard`' "$MAIN")"
assert "'(git reset --hard)' on main is blocked -- subshell grouping runs it too" \
  "$(blocked '(git reset --hard)' "$MAIN")"
assert "'git checkout \$(git rev-parse HEAD)' on main is allowed -- a read-only substitution is not destructive" \
  "$(allowed 'git checkout $(git rev-parse HEAD)' "$MAIN")"
assert "'echo \$(git rev-parse HEAD)' on main is allowed -- read-only git inside a substitution" \
  "$(allowed 'echo $(git rev-parse HEAD)' "$MAIN")"
assert "'git reset --soft \$(git merge-base HEAD main)' on main is allowed -- merge-base is read-only and soft reset keeps the worktree" \
  "$(allowed 'git reset --soft $(git merge-base HEAD main)' "$MAIN")"
assert "'git checkout -b x \$(git merge-base HEAD main)' on main is allowed -- merge-base is a read-only start-point" \
  "$(allowed 'git checkout -b x $(git merge-base HEAD main)' "$MAIN")"
assert "'\$(git reset --hard)' in the worker worktree is allowed -- worker branches are unprotected" \
  "$(allowed 'echo $(git reset --hard)' "$WORKER")"

# ---------------------------------------------------------------------------
# 14. A ref name that is also a repo path resolves as a ref, not a path.
# ---------------------------------------------------------------------------
mkdir -p "$MAIN/main" "$MAIN/dirnotref"
echo x > "$MAIN/main/f"
echo x > "$MAIN/dirnotref/f"
assert "'git checkout main' on main with a main/ dir is allowed -- it is a branch switch, blocking it trains agents to route around the guard" \
  "$(allowed "git checkout main" "$MAIN")"
assert "'git checkout dirnotref' on main stays blocked -- a path that is not a ref is restored from the index" \
  "$(blocked "git checkout dirnotref" "$MAIN")"
assert "'git checkout main -- .' on main stays blocked -- an explicit -- is always a path restore" \
  "$(blocked "git checkout main -- ." "$MAIN")"
git -C "$MAIN" tag v1
echo x > "$MAIN/v1"
assert "'git checkout HEAD a.txt' on main is blocked -- the second positional is a pathspec and overwrites the file even though the first is a ref" \
  "$(blocked "git checkout HEAD a.txt" "$MAIN")"
assert "'git checkout HEAD main' on main is blocked -- a later positional that names a path is a pathspec even if it is also a branch" \
  "$(blocked "git checkout HEAD main" "$MAIN")"
assert "'git checkout v1 v1' on main is blocked -- tag then same-named file restores the file" \
  "$(blocked "git checkout v1 v1" "$MAIN")"
assert "'git checkout -b x main' on main is allowed -- the start-point is the first positional after the new branch name" \
  "$(allowed "git checkout -b x main" "$MAIN")"

# ---------------------------------------------------------------------------
# 15. mayor_root() fallback: CLAUDE_PROJECT_DIR is unset in subagent Bash
#     envs, so the first `git worktree list` entry must identify the mayor.
# ---------------------------------------------------------------------------
mkdir -p "$WORKER/scripts"
cp "$SCRIPT" "$WORKER/scripts/guard-destructive-git.sh"
RC=0
FALLBACK_ROOT=$(CLAUDE_PROJECT_DIR= bash "$WORKER/scripts/guard-destructive-git.sh" __call mayor_root)
assert "mayor_root with CLAUDE_PROJECT_DIR unset, run from a worker worktree's copy, returns the main worktree -- subagents have no CLAUDE_PROJECT_DIR" \
  "$([ "$FALLBACK_ROOT" = "$MAIN" ] && echo 1 || echo 0)"
rm -rf "$WORKER/scripts"

# ---------------------------------------------------------------------------
# 16. env / VAR= prefixes, --config-env, quoted -c values, substitution args.
# ---------------------------------------------------------------------------
assert "'env git reset --hard' on main is blocked -- env prefix must not hide git" \
  "$(blocked "env git reset --hard" "$MAIN")"
assert "'env -u X FOO=1 git reset --hard' on main is blocked" \
  "$(blocked "env -u X FOO=1 git reset --hard" "$MAIN")"
assert "'FOO=1 git reset --hard' on main is blocked -- VAR= prefix must not hide git" \
  "$(blocked "FOO=1 git reset --hard" "$MAIN")"
assert "'FOO=\"a b\" BAR= git reset --hard' on main is blocked -- quoted/empty VAR values" \
  "$(blocked 'FOO="a b" BAR= git reset --hard' "$MAIN")"
assert "'env FOO=1 git status' on main is allowed -- read-only" \
  "$(allowed "env FOO=1 git status" "$MAIN")"
assert "'FOO=1 git reset --hard' in worker is allowed" \
  "$(allowed "FOO=1 git reset --hard" "$WORKER")"
assert "'git --config-env=alias.x=VAR x' on main is blocked -- alias via env" \
  "$(blocked "git --config-env=alias.x=VAR x" "$MAIN")"
assert "'git --config-env alias.x=VAR x' on main is blocked" \
  "$(blocked "git --config-env alias.x=VAR x" "$MAIN")"
assert "'git --config-env=core.x=VAR status' on main is allowed -- not an alias" \
  "$(allowed "git --config-env=core.x=VAR status" "$MAIN")"
assert "'git -c core.x=\"a b\" reset --hard' on main is blocked -- a quoted -c value with a space must not eat the verb" \
  "$(blocked 'git -c core.x="a b" reset --hard' "$MAIN")"
assert "'git -c core.x=\"a b\" status' on main is allowed" \
  "$(allowed 'git -c core.x="a b" status' "$MAIN")"
assert "'git checkout \$(echo .)' on main is blocked -- substitution can expand to a path" \
  "$(blocked 'git checkout $(echo .)' "$MAIN")"
assert "'git reset \$(echo --hard)' on main is blocked" \
  "$(blocked 'git reset $(echo --hard)' "$MAIN")"
assert "'git reset \`echo --hard\`' on main is blocked" \
  "$(blocked 'git reset `echo --hard`' "$MAIN")"
assert "'git reset \$(echo --hard)' in worker is allowed" \
  "$(allowed 'git reset $(echo --hard)' "$WORKER")"
assert "'cd \$(pwd) && git reset --hard' on main is blocked -- an unresolvable cd target must not unprotect later commands" \
  "$(blocked 'cd $(pwd) && git reset --hard' "$MAIN")"
assert "'git commit -m \"x (git reset --hard HEAD)\"' on main is blocked -- known over-block, intended: prose is indistinguishable from a subshell" \
  "$(blocked 'git commit -m "x (git reset --hard HEAD)"' "$MAIN")"
assert "'gh pr view 1 --json title | jq \".title\"' on main is allowed" \
  "$(allowed 'gh pr view 1 --json title | jq ".title"' "$MAIN")"
assert "'gh pr create --body \"fix (parens)\" ' on main is allowed" \
  "$(allowed 'gh pr create --body "fix (parens) here"' "$MAIN")"
assert "'jq \"(.a | .b)\" f.json' on main is allowed" \
  "$(allowed 'jq "(.a | .b)" f.json' "$MAIN")"

# ---------------------------------------------------------------------------
# 17. HEAD-moving git in the mayor checkout (CLAUDE_PROJECT_DIR=$MAIN makes
#     $MAIN the mayor). A reviewer's `git checkout <pr-commit>` there left the
#     mayor on a worker branch; reviewers must read via fetch/show/diff or a
#     scratch worktree. The mayor's own ff-only sync and `checkout main` stay.
# ---------------------------------------------------------------------------
git -C "$MAIN" branch pr-ref main
declare -a HEAD_BLOCKED=(
  "git checkout pr-ref"
  "git checkout $(git -C "$MAIN" rev-parse HEAD)"
  "git checkout --detach main"
  "git checkout -b review main"
  "git switch pr-ref"
  "git switch -c review"
  "git merge pr-ref"
  "git pull"
  "git reset --soft HEAD~1"
  "git reset HEAD"
  "git rebase main"
  "git cherry-pick pr-ref"
  "git revert HEAD"
  "git am x.patch"
  "git -C $MAIN checkout pr-ref"
)
for cmd in "${HEAD_BLOCKED[@]}"; do
  assert "'$cmd' in the mayor checkout is refused -- it moves the mayor off main, which silently misdirects every later mayor command" \
    "$(CLAUDE_PROJECT_DIR="$MAIN" blocked "$cmd" "$MAIN")"
done
assert "'git -C <mayor> checkout pr-ref' from a worker cwd is refused -- -C must not launder the target" \
  "$(CLAUDE_PROJECT_DIR="$MAIN" blocked "git -C $MAIN checkout pr-ref" "$WORKER")"
assert "'git checkout pr-ref' on a main-branch repo that is NOT the mayor checkout stays allowed -- the new clause applies to the mayor checkout only" \
  "$(CLAUDE_PROJECT_DIR="$FRESH_STANDALONE" allowed "git checkout pr-ref" "$MAIN")"

declare -a HEAD_ALLOWED=(
  "git fetch origin main"
  "git show HEAD:a.txt"
  "git diff main..pr-ref"
  "git log --oneline -3"
  "git status"
  "git branch --list"
  "git rev-parse HEAD"
  "git worktree list"
  "git worktree add $SANDBOX_ROOT/scratch-wt pr-ref"
  "git pull --ff-only"
  "git merge --ff-only origin/main"
  "git checkout main"
  "git switch main"
  "git restore --staged a.txt"
  "git -C $WORKER checkout pr-ref"
)
for cmd in "${HEAD_ALLOWED[@]}"; do
  assert "'$cmd' in the mayor checkout is allowed -- read-only inspection and the mayor's own ff-only sync must keep working" \
    "$(CLAUDE_PROJECT_DIR="$MAIN" allowed "$cmd" "$MAIN")"
done
for cmd in "git checkout pr-ref" "git switch pr-ref" "git merge pr-ref" "git reset --soft HEAD~1" "git rebase main" "git cherry-pick pr-ref"; do
  assert "'$cmd' inside a worker worktree is allowed -- workers move their own HEAD constantly" \
    "$(CLAUDE_PROJECT_DIR="$MAIN" allowed "$cmd" "$WORKER")"
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

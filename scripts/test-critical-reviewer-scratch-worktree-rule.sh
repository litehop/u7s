#!/usr/bin/env bash
# Regression test for .claude/agents/critical-reviewer.md's "Scratch
# worktrees" hard rule: it must not contradict the Input section, which
# reads PRs via plain `gh pr diff`/`gh pr view` with no worktree at all.
# A reviewer who took the old blanket wording ("inspect PR code only in a
# scratch worktree, never in the mayor checkout") literally would have had
# to route even a plain `gh pr diff` through a worktree it doesn't need.
set -euo pipefail

DOC="$(git rev-parse --show-toplevel)/.claude/agents/critical-reviewer.md"
DOC_FLAT="$(tr '\n' ' ' < "$DOC")"

FAIL=0

if printf '%s' "$DOC_FLAT" | grep -qE 'gh pr diff.*gh pr view.*no worktree'; then
  echo "PASS: scratch-worktree rule exempts plain gh pr diff/gh pr view reads from needing a worktree"
else
  echo "FAIL: scratch-worktree rule no longer exempts gh pr diff/gh pr view reads -- this contradicts the Input section again"
  FAIL=1
fi

if grep -qE 'inspect PR code only in a scratch worktree, never in the' "$DOC"; then
  echo "FAIL: the old blanket 'inspect PR code only in a scratch worktree' wording is back -- it forbids the plain gh reads the Input section relies on"
  FAIL=1
else
  echo "PASS: the old blanket scratch-worktree-for-everything wording is gone"
fi

if [ "$FAIL" -eq 0 ]; then
  echo "all tests passed"
  exit 0
else
  exit 1
fi

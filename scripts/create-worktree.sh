#!/usr/bin/env bash
# WorktreeCreate hook. Creates worker worktrees at ai/worktrees/ instead
# of the default .claude/worktrees/, and copies gitignored config files.
set -euo pipefail

INPUT=$(cat)
BASE_PATH=$(printf '%s' "$INPUT" | jq -r '.base_path')
WORKTREE_NAME=$(printf '%s' "$INPUT" | jq -r '.worktree_name')
BRANCH_NAME=$(printf '%s' "$INPUT" | jq -r '.branch_name')

WORKTREE_DIR="$BASE_PATH/ai/worktrees/$WORKTREE_NAME"

mkdir -p "$BASE_PATH/ai/worktrees"

git -C "$BASE_PATH" worktree add "$WORKTREE_DIR" -b "$BRANCH_NAME" HEAD

# Copy gitignored config files that workers need
for f in .beads-credential-key; do
  if [ -f "$BASE_PATH/$f" ]; then
    cp -f "$BASE_PATH/$f" "$WORKTREE_DIR/$f"
  fi
done

printf '%s\n' "$WORKTREE_DIR"

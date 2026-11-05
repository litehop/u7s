#!/usr/bin/env bash
# WorktreeCreate hook. Creates worker worktrees at ai/worktrees/ instead
# of the default .claude/worktrees/, and copies gitignored config files.
set -euo pipefail

INPUT=$(cat)

# Harness provides: cwd (repo root), name (agent ID used as worktree name)
BASE_PATH=$(printf '%s' "$INPUT" | jq -r '.cwd')
WORKTREE_NAME=$(printf '%s' "$INPUT" | jq -r '.name')
BRANCH_NAME="worker/$WORKTREE_NAME"

if [ -z "$BASE_PATH" ] || [ "$BASE_PATH" = "null" ] || [ -z "$WORKTREE_NAME" ] || [ "$WORKTREE_NAME" = "null" ]; then
  printf 'create-worktree: missing cwd or name. INPUT=%s\n' "$INPUT" >&2
  exit 1
fi

WORKTREE_DIR="$BASE_PATH/ai/worktrees/$WORKTREE_NAME"

mkdir -p "$BASE_PATH/ai/worktrees"

# Parallel dispatches race inside `git worktree add` (one reads a sibling's
# half-written admin dir). Serialize with a mkdir lock (atomic on macOS, no flock);
# the owner PID lets waiters reclaim a lock left by a killed process.
GIT_COMMON_DIR=$(git -C "$BASE_PATH" rev-parse --path-format=absolute --git-common-dir)
LOCK_DIR="$GIT_COMMON_DIR/u7s-create-worktree.lock"
LOCK_WAIT_SECS="${U7S_CREATE_WORKTREE_LOCK_WAIT_SECS:-25}"

acquire_lock() {
  local deadline=$((SECONDS + LOCK_WAIT_SECS)) owner
  until mkdir "$LOCK_DIR" 2>/dev/null; do
    owner=$(cat "$LOCK_DIR/pid" 2>/dev/null || true)
    if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then
      # mv is atomic: only one waiter reclaims a given stale lock.
      if mv "$LOCK_DIR" "$LOCK_DIR.stale.$$" 2>/dev/null; then
        rm -rf "$LOCK_DIR.stale.$$"
      fi
      continue
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      printf 'create-worktree: timed out after %ss waiting for %s (owner pid: %s); remove it if no create-worktree is running\n' \
        "$LOCK_WAIT_SECS" "$LOCK_DIR" "${owner:-unknown}" >&2
      exit 1
    fi
    sleep 0.1
  done
  printf '%s\n' "$$" > "$LOCK_DIR/pid"
}

release_lock() {
  rm -rf "$LOCK_DIR"
}

acquire_lock
trap release_lock EXIT

BRANCH_EXISTED=0
if git -C "$BASE_PATH" show-ref --verify --quiet "refs/heads/$BRANCH_NAME"; then
  BRANCH_EXISTED=1
fi

# Test-only: lets a test observe whether two invocations overlap in the critical section.
if [ -n "${U7S_TEST_CRITICAL_SECTION_HOOK:-}" ]; then
  bash -c "$U7S_TEST_CRITICAL_SECTION_HOOK"
fi

if ! git -C "$BASE_PATH" worktree add "$WORKTREE_DIR" -b "$BRANCH_NAME" HEAD; then
  if [ "$BRANCH_EXISTED" -eq 0 ]; then
    git -C "$BASE_PATH" branch -D "$BRANCH_NAME" >/dev/null 2>&1 || true
  fi
  exit 1
fi
release_lock
trap - EXIT

# Copy gitignored config files that workers need
for f in .beads-credential-key; do
  if [ -f "$BASE_PATH/$f" ]; then
    cp -f "$BASE_PATH/$f" "$WORKTREE_DIR/$f"
  fi
done

# Sync .claude/settings.json so workers inherit the project's permission allowlist
mkdir -p "$WORKTREE_DIR/.claude"
cp -f "$BASE_PATH/.claude/settings.json" "$WORKTREE_DIR/.claude/settings.json"

printf '%s\n' "$WORKTREE_DIR"

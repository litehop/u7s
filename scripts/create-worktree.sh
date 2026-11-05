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
# half-written admin dir). Serialize with a symlink lock (no flock on macOS):
# `ln -s $$` creates the lock and records the owner PID in one atomic step, so
# a killed process can never leave an ownerless lock behind.
GIT_COMMON_DIR=$(git -C "$BASE_PATH" rev-parse --path-format=absolute --git-common-dir)
LOCK="$GIT_COMMON_DIR/u7s-create-worktree.lock"
# Kept below the 30 s hook timeout so a late acquirer still has time to add the worktree.
LOCK_WAIT_SECS="${U7S_CREATE_WORKTREE_LOCK_WAIT_SECS:-15}"

# Move the lock aside, verify the moved lock is still the dead owner's, and put
# it back if a live holder took over in between (two waiters saw the same dead owner).
reclaim_stale() {
  local dead="$1" aside="$LOCK.stale.$$" moved
  if [ -n "${U7S_TEST_RECLAIM_HOOK:-}" ]; then
    bash -c "$U7S_TEST_RECLAIM_HOOK"
  fi
  mv "$LOCK" "$aside" 2>/dev/null || return 0
  moved=$(readlink "$aside" 2>/dev/null || true)
  if [ -n "$moved" ] && [ "$moved" != "$dead" ]; then
    ln -s -n "$moved" "$LOCK" 2>/dev/null || true
  fi
  rm -f "$aside"
}

acquire_lock() {
  local deadline=$((SECONDS + LOCK_WAIT_SECS)) owner
  until ln -s -n "$$" "$LOCK" 2>/dev/null; do
    owner=$(readlink "$LOCK" 2>/dev/null || true)
    if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then
      reclaim_stale "$owner"
      continue
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      printf 'create-worktree: timed out after %ss waiting for %s (owner pid: %s); remove it if no create-worktree is running\n' \
        "$LOCK_WAIT_SECS" "$LOCK" "${owner:-unknown}" >&2
      exit 1
    fi
    sleep 0.1
  done
}

release_lock() {
  if [ "$(readlink "$LOCK" 2>/dev/null || true)" = "$$" ]; then
    rm -f "$LOCK"
  fi
}

trap release_lock EXIT
acquire_lock

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

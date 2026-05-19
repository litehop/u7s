#!/usr/bin/env bash
# PreToolUse hook for Edit|Write. Blocks edits targeting files outside the
# current git worktree root — catches apply_patch path-resolution leaks.
set -euo pipefail

INPUT=$(cat)
FILE_PATH=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty')

# No file_path: not a file-editing call we care about
[ -z "$FILE_PATH" ] && exit 0

# Require absolute path
if [[ "$FILE_PATH" != /* ]]; then
  FILE_PATH="$(pwd)/$FILE_PATH"
fi

GIT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "$GIT_ROOT" ]; then
  printf 'WORKTREE GUARD: Not in a git repository. Edit blocked.\n' >&2
  exit 2
fi

# Normalize: resolve symlinks, strip trailing slashes
NORM_FILE=$(cd "$(dirname "$FILE_PATH")" 2>/dev/null && pwd -P)/$(basename "$FILE_PATH") 2>/dev/null || NORM_FILE="$FILE_PATH"
NORM_ROOT=$(cd "$GIT_ROOT" && pwd -P)

if [[ "$NORM_FILE" == "$NORM_ROOT"/* ]] || [[ "$NORM_FILE" == "$NORM_ROOT" ]]; then
  exit 0
fi

printf 'WORKTREE GUARD: Edit target "%s" is outside git root "%s".\nThis looks like a path-resolution leak. Edit blocked.\n' \
  "$FILE_PATH" "$GIT_ROOT" >&2
exit 2

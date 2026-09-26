#!/usr/bin/env bash
# PreToolUse hook for Bash. Blocks git commands that discard uncommitted
# work (reset --hard, checkout ... -- <path> or a bare `.`/existing-path
# checkout with no `--`, restore, stash push/save/
# drop/clear/pop and bare `git stash`, clean -f*, switch -f/--discard-
# changes) when the target repo is on branch `main` or is the mayor
# checkout (the main worktree root). This is a string-match guardrail,
# not a sandbox.
#
# Hook input arrives as JSON on stdin: {cwd, tool_input: {command, ...}}.
# Missing/unparseable input fails OPEN (exit 0) so a hook bug can never
# block every Bash call.
#
# Testability: `guard-destructive-git.sh __call <fn> [args...]` invokes a
# single function from this file, the same convention scripts/worktree-
# hygiene.sh uses, so tests exercise the real logic, not a reimplementation.
set -uo pipefail

resolve_dir() {
  # resolve_dir <base> <maybe-relative-path> -- best-effort absolute path;
  # falls back to the unresolved join if the target doesn't exist on disk.
  local base="$1" target="$2" resolved
  if [ -z "$target" ]; then
    printf '%s' "$base"
    return
  fi
  if [[ "$target" == /* ]]; then
    resolved=$(cd "$target" 2>/dev/null && pwd -P) || resolved="$target"
  else
    resolved=$(cd "$base/$target" 2>/dev/null && pwd -P) || resolved="$base/$target"
  fi
  printf '%s' "$resolved"
}

mayor_root() {
  # mayor_root -- canonicalized path to the mayor checkout: CLAUDE_PROJECT_DIR
  # when Claude Code sets it (it stays fixed to the session's original
  # project directory even as a subagent's Bash cwd differs -- the same
  # assumption scripts/critical-reviewer-dispatch.sh already relies on for
  # a shared review-queue location), else the main worktree root of the
  # repo this script itself lives in. Never derived from the hook's target
  # dir -- that would make any standalone repo with no linked worktrees
  # see itself as "the mayor checkout".
  local root script_dir
  if [ -n "${CLAUDE_PROJECT_DIR:-}" ]; then
    root=$(cd "$CLAUDE_PROJECT_DIR" 2>/dev/null && pwd -P) || root=""
    [ -n "$root" ] && { printf '%s' "$root"; return; }
  fi
  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P) || return
  git -C "$script_dir" worktree list --porcelain 2>/dev/null | awk '/^worktree /{print $2; exit}'
}

is_target_protected() {
  # is_target_protected <dir> -- true if <dir>'s repo is checked out on
  # branch `main`, or <dir>'s worktree root is the mayor checkout
  # (MAIN_ROOT, set by the caller from `mayor_root`).
  local dir="$1"
  [ -z "$dir" ] && return 1
  local branch toplevel
  branch=$(git -C "$dir" branch --show-current 2>/dev/null || true)
  [ "$branch" = "main" ] && return 0
  toplevel=$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null || true)
  [ -n "${MAIN_ROOT:-}" ] && [ -n "$toplevel" ] && [ "$toplevel" = "$MAIN_ROOT" ] && return 0
  return 1
}

is_destructive_git_args() {
  # is_destructive_git_args <args> <target-dir> -- <args> is everything
  # after `git` (and after any leading `-C <dir>` has been stripped by the
  # caller). <target-dir> is only used by the `checkout` branch, to check
  # whether a bare argument names an existing path.
  local args="$1" target_dir="$2" first second tok
  first=$(printf '%s\n' "$args" | awk '{print $1}')
  case "$first" in
    reset)
      printf '%s' "$args" | grep -qE '(^|[[:space:]])--hard([[:space:]]|$)'
      ;;
    checkout)
      # `checkout -- <path>` / `checkout <ref> -- <path>` and bare
      # `checkout .` / `checkout <existing-path>` (no `--` at all) both
      # discard worktree changes; only `-B <branch> <ref>` and plain
      # branch switches (whose args never resolve to an existing path)
      # must stay allowed.
      for tok in $args; do
        if [ "$tok" = "." ] || [ "$tok" = "--" ]; then
          return 0
        fi
        case "$tok" in
          -*) continue ;;
        esac
        [ -e "$target_dir/$tok" ] && return 0
      done
      return 1
      ;;
    restore)
      if printf '%s' "$args" | grep -qE '(^|[[:space:]])--staged([[:space:]]|$)'; then
        printf '%s' "$args" | grep -qE '(^|[[:space:]])--worktree([[:space:]]|$)'
      else
        return 0
      fi
      ;;
    stash)
      second=$(printf '%s\n' "$args" | awk '{print $2}')
      case "$second" in
        ""|push|save|drop|clear|pop) return 0 ;;
        *) return 1 ;;
      esac
      ;;
    clean)
      printf '%s' "$args" | grep -qE -- '(^|[[:space:]])-[a-zA-Z]*f[a-zA-Z]*([[:space:]]|$)|(^|[[:space:]])--force([[:space:]]|$)'
      ;;
    switch)
      printf '%s' "$args" | grep -qE -- '(^|[[:space:]])-[a-zA-Z]*f[a-zA-Z]*([[:space:]]|$)|(^|[[:space:]])--discard-changes([[:space:]]|$)'
      ;;
    *)
      return 1
      ;;
  esac
}

BLOCK_MSG_TEMPLATE='BLOCKED: destructive git command against a protected branch/checkout.
  command: %s
  target : %s
Use a scratch worktree instead:
  git worktree add temp/review-scratch/<name> <ref>
  git -C temp/review-scratch/<name> <command>
'

check_command() {
  # check_command <command-string> <cwd> -- exit 2 (with reason on stderr)
  # if any segment is a destructive git command against a protected repo.
  local cmd="$1" cwd="$2" current_dir seg raw_seg cdarg rest target_dir

  MAIN_ROOT=$(mayor_root)
  current_dir="$cwd"

  while IFS= read -r raw_seg; do
    seg=$(printf '%s' "$raw_seg" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
    [ -z "$seg" ] && continue

    if [[ "$seg" =~ ^cd[[:space:]]+(.+)$ ]]; then
      cdarg=$(printf '%s' "${BASH_REMATCH[1]}" | sed -E "s/^[\"']//; s/[\"']\$//")
      current_dir=$(resolve_dir "$current_dir" "$cdarg")
      continue
    fi

    [[ "$seg" == git\ * ]] || continue

    rest="${seg#git }"
    target_dir="$current_dir"
    if [[ "$rest" =~ ^-C[[:space:]]+([^[:space:]]+)[[:space:]]+(.*)$ ]]; then
      target_dir=$(resolve_dir "$current_dir" "${BASH_REMATCH[1]}")
      rest="${BASH_REMATCH[2]}"
    fi

    if is_destructive_git_args "$rest" "$target_dir" && is_target_protected "$target_dir"; then
      # shellcheck disable=SC2059
      printf "$BLOCK_MSG_TEMPLATE" "$seg" "$target_dir" >&2
      return 2
    fi
  done <<< "$(printf '%s' "$cmd" | sed -E 's/(&&|\|\||;|\|)/\n/g')"

  return 0
}

main() {
  local input cmd cwd
  input=$(cat)
  if [ -z "$input" ]; then
    echo "guard-destructive-git: empty hook input, failing open" >&2
    exit 0
  fi

  cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)
  cwd=$(printf '%s' "$input" | jq -r '.cwd // empty' 2>/dev/null)

  if [ -z "$cmd" ]; then
    echo "guard-destructive-git: no tool_input.command in hook input, failing open" >&2
    exit 0
  fi
  [ -z "$cwd" ] && cwd=$(pwd)

  check_command "$cmd" "$cwd"
  exit $?
}

if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  if [ "${1:-}" = "__call" ]; then
    shift
    "$@"
  else
    main
  fi
fi

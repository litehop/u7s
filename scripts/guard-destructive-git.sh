#!/usr/bin/env bash
# PreToolUse hook for Bash. Blocks git commands that discard uncommitted
# work (reset --hard, checkout ... -- <path> or a bare `.`/existing-path
# checkout with no `--`, restore, any `stash` subcommand other than
# list/show/apply/branch (including a bare `git stash -u` with no
# subcommand word at all), clean -f*, switch -f/--discard-changes) when
# the target repo is on branch `main` or is the mayor checkout. This is a
# string-match guardrail, not a sandbox. It also refuses HEAD-moving git
# (checkout/switch to a ref other than main, reset, rebase, cherry-pick,
# revert, am, non-ff merge/pull) in the mayor checkout itself.
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

is_bead_export_discard() {
  # is_bead_export_discard <args> -- true only for `restore [--staged]
  # [--worktree] [--] <paths>` or `checkout -- <paths>` where every path is
  # exactly one of the two bd-generated JSONL exports, which the Dolt DB
  # regenerates; discarding them unblocks `git pull --ff-only`.
  local -a toks
  local tok sub npaths=0 seen_dd=0
  read -ra toks <<< "$1"
  sub="${toks[0]:-}"
  case "$sub" in
    restore|checkout) ;;
    *) return 1 ;;
  esac
  toks=("${toks[@]:1}")
  [ "$sub" = checkout ] && { [ "${toks[0]:-}" = "--" ] || return 1; }
  for tok in "${toks[@]}"; do
    case "$tok" in
      --) seen_dd=1 ;;
      --staged|--worktree)
        [ "$sub" = restore ] && [ "$seen_dd" = 0 ] || return 1
        ;;
      .beads/issues.jsonl|.beads/interactions.jsonl) npaths=$(( npaths + 1 )) ;;
      *) return 1 ;;
    esac
  done
  [ "$npaths" -gt 0 ]
}

SUBST_MARK=__U7S_SUBST__

is_destructive_git_args() {
  # is_destructive_git_args <args> <target-dir> -- <args> is everything
  # after `git` (and after any leading `-C <dir>` has been stripped by the
  # caller). <target-dir> is only used by the `checkout` branch, to check
  # whether a bare argument names an existing path.
  local args="$1" target_dir="$2" first second tok
  first=$(printf '%s\n' "$args" | awk '{print $1}')
  is_bead_export_discard "$args" && return 1
  # A non-read-only substitution in an argument can expand to anything
  # (`reset $(echo --hard)`, `checkout $(echo .)`); check_command marks it.
  case "$first" in
    reset|checkout|restore|clean)
      [[ " $args " == *" $SUBST_MARK "* ]] && return 0
      ;;
  esac
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
      local seen_pos=0 skip=1
      for tok in $args; do
        if [ "$skip" = 1 ]; then
          skip=0
          continue
        fi
        if [ "$tok" = "." ] || [ "$tok" = "--" ]; then
          return 0
        fi
        case "$tok" in
          -b|-B|--orphan) skip=1; continue ;;
          -*) continue ;;
        esac
        if [ -e "$target_dir/$tok" ]; then
          # Only the first positional can be a ref; any later one is a pathspec.
          [ "$seen_pos" = 1 ] && return 0
          git -C "$target_dir" rev-parse --verify --quiet "$tok" >/dev/null 2>&1 || return 0
        fi
        seen_pos=1
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
      # Default-deny: any subcommand other than the read-only `list`/`show`
      # or `apply`/`branch` (which never discard the pending stash) is
      # destructive -- including bare `git stash` (implicit push), any
      # flag-prefixed form like `git stash -u` (still implicit push, no
      # subcommand word at all), and any subcommand this list doesn't know
      # about yet. A flag in $second must not read as an allowed subcommand.
      second=$(printf '%s\n' "$args" | awk '{print $2}')
      case "$second" in
        list|show|apply|branch) return 1 ;;
        *) return 0 ;;
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

is_mayor_checkout() {
  # is_mayor_checkout <dir> -- true if <dir>'s worktree root is exactly the
  # mayor checkout (MAIN_ROOT), whatever branch it is on.
  local toplevel
  toplevel=$(git -C "$1" rev-parse --show-toplevel 2>/dev/null || true)
  [ -n "${MAIN_ROOT:-}" ] && [ -n "$toplevel" ] && [ "$toplevel" = "$MAIN_ROOT" ]
}

is_head_moving_args() {
  # is_head_moving_args <args> -- true for git commands that move HEAD or
  # rewrite the index/worktree of the mayor checkout and that the mayor never
  # needs: checkout/switch to anything but `main`, reset in any mode, rebase,
  # cherry-pick, revert, am, and merge/pull that are not --ff-only. Hook input
  # does not reliably tell a subagent's Bash call from the mayor's own, so
  # the mayor's `pull --ff-only` / `merge --ff-only` / `checkout main` stay
  # allowed for everyone.
  local args="$1" first tok npos=0
  first=$(printf '%s\n' "$args" | awk '{print $1}')
  is_bead_export_discard "$args" && return 1
  case "$first" in
    reset|rebase|cherry-pick|revert|am) return 0 ;;
    merge|pull)
      printf '%s' "$args" | grep -qE '(^|[[:space:]])--ff-only([[:space:]]|$)' && return 1
      return 0
      ;;
    checkout|switch)
      for tok in ${args#"$first"}; do
        case "$tok" in
          --) return 1 ;;
          -*) return 0 ;;
        esac
        [ "$tok" = main ] || return 0
        npos=$(( npos + 1 ))
      done
      [ "$npos" = 1 ] && return 1
      return 0
      ;;
    *) return 1 ;;
  esac
}

BLOCK_MSG_TEMPLATE='BLOCKED: destructive git command against a protected branch/checkout.
  command: %s
  target : %s
Use a scratch worktree instead:
  git worktree add temp/review-scratch/<name> <ref>
  git -C temp/review-scratch/<name> <command>
'

HEAD_MSG_TEMPLATE='BLOCKED: HEAD/index-changing git command in the mayor checkout.
  command: %s
  target : %s
Read PR code without moving the mayor checkout:
  gh pr diff <n>
  git fetch origin <branch>; git show <ref>:<path>; git diff <a>..<b>
  git worktree add temp/review-scratch/<name> <ref>; git -C temp/review-scratch/<name> <command>
'

check_command() {
  # check_command <command-string> <cwd> -- exit 2 (with reason on stderr)
  # if any segment is a destructive git command against a protected repo.
  local cmd="$1" cwd="$2" current_dir seg raw_seg cdarg rest target_dir has_alias
  local alias_re='^-c[[:space:]]*["'"'"']?[aA][lL][iI][aA][sS]\.'
  local tok_re='(("[^"]*"|'"'"'[^'"'"']*'"'"'|[^[:space:]"'"'"'])+)'
  local cfgenv_alias_re='^--config-env(=|[[:space:]]+)["'"'"']?[aA][lL][iI][aA][sS]\.'
  local env_seen next

  MAIN_ROOT=$(mayor_root)
  current_dir="$cwd"
  local line_cont=$'\\\n'
  cmd="${cmd//"$line_cont"/}"

  while IFS= read -r raw_seg; do
    seg=$(printf '%s' "$raw_seg" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
    [ -z "$seg" ] && continue

    if [[ "$seg" =~ ^cd[[:space:]]+(.+)$ ]]; then
      cdarg=$(printf '%s' "${BASH_REMATCH[1]}" | sed -E "s/^[\"']//; s/[\"']\$//")
      [[ "$cdarg" == *"$SUBST_MARK"* ]] || current_dir=$(resolve_dir "$current_dir" "$cdarg")
      continue
    fi

    env_seen=0
    while :; do
      if [[ "$seg" =~ ^env[[:space:]]+(.*)$ ]]; then
        env_seen=1
      elif [[ "$seg" =~ ^[A-Za-z_][A-Za-z0-9_]*=${tok_re}?[[:space:]]+(.*)$ ]]; then
        :
      elif [ "$env_seen" = 1 ] && [[ "$seg" =~ ^-[uCS][[:space:]]+[^[:space:]]+[[:space:]]+(.*)$ ]]; then
        :
      elif [ "$env_seen" = 1 ] && [[ "$seg" =~ ^-[^[:space:]]*[[:space:]]+(.*)$ ]]; then
        :
      else
        break
      fi
      seg="${BASH_REMATCH[$(( ${#BASH_REMATCH[@]} - 1 ))]}"
    done

    [[ "$seg" == git\ * ]] || continue

    rest="${seg#git }"
    target_dir="$current_dir"
    has_alias=0
    while :; do
      if [[ "$rest" =~ ^-C[[:space:]]+([^[:space:]]+)[[:space:]]+(.*)$ ]]; then
        target_dir=$(resolve_dir "$target_dir" "${BASH_REMATCH[1]}")
        rest="${BASH_REMATCH[2]}"
      elif [[ "$rest" =~ ^-c[[:space:]]*${tok_re}[[:space:]]+(.*)$ ]]; then
        next="${BASH_REMATCH[$(( ${#BASH_REMATCH[@]} - 1 ))]}"
        [[ "$rest" =~ $alias_re ]] && has_alias=1
        rest="$next"
      elif [[ "$rest" =~ ^--config-env(=|[[:space:]]+)${tok_re}[[:space:]]+(.*)$ ]]; then
        next="${BASH_REMATCH[$(( ${#BASH_REMATCH[@]} - 1 ))]}"
        [[ "$rest" =~ $cfgenv_alias_re ]] && has_alias=1
        rest="$next"
      else
        break
      fi
    done

    # An alias can expand to any destructive command, so refuse them outright.
    if { [ "$has_alias" = 1 ] || is_destructive_git_args "$rest" "$target_dir"; } && is_target_protected "$target_dir"; then
      # shellcheck disable=SC2059
      printf "$BLOCK_MSG_TEMPLATE" "$seg" "$target_dir" >&2
      return 2
    fi
    if is_head_moving_args "$rest" && is_mayor_checkout "$target_dir"; then
      # shellcheck disable=SC2059
      printf "$HEAD_MSG_TEMPLATE" "$seg" "$target_dir" >&2
      return 2
    fi
  done <<< "$(printf '%s' "$cmd" | sed -E "s/(\\\$\\(|\`)[[:space:]]*(git[[:space:]]+(rev-parse|rev-list|describe|merge-base))/\\
\\2/g; s/(\\\$\\(|\`)/ $SUBST_MARK\\
/g; s/(&&|\\|\\||;|\\||\\(|\\))/\\
/g")"

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

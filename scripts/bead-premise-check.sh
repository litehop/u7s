#!/usr/bin/env bash
# scripts/bead-premise-check.sh <bead-id>
#
# Replaces the mayor's per-dispatch model turn spent "grep to confirm the
# bead's target is still broken/missing (not already landed)" -- purely
# deterministic once you have the bead's own text, so it doesn't need a
# model call at all.
#
# Reads the bead via `bd show <id> --json`, best-effort extracts the
# backtick-quoted "target pattern" its description/design/acceptance
# criteria cite (a file path, symbol name, or stale-convention string), and
# checks whether that pattern is still present in the tracked tree. The
# bead is assumed to cite the pattern AS EVIDENCE OF THE BUG -- a stale
# symbol, a wrong convention, a reference to code that shouldn't exist
# anymore -- so presence means the bug is still there and absence means
# it's already been fixed.
#
# Prints one of the following to stdout and exits with the matching code:
#   still-broken      (0) -- pattern still present, dispatch as planned.
#   no-longer-broken  (1) -- pattern gone, likely already fixed; close as
#                            verified-duplicate instead of dispatching.
#   cannot-verify      (2) -- couldn't parse a target pattern, or `bd show`
#                            failed; a human/mayor call is still needed.
#
# Testability: `bead-premise-check.sh __call <fn> [args...]` invokes a
# single function from this file, the same convention used by other
# scripts/ tools (see scripts/test-check-bead-id-refs-logic.sh for the
# pattern this mirrors). The pure classification step (extract pattern ->
# check presence) is split into classify_from_json() so the test suite can
# feed synthetic `bd show --json` output and a sandbox git tree, with no
# live `bd` session or network call.
set -euo pipefail

REPO_ROOT="${BEAD_PREMISE_CHECK_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# ---------------------------------------------------------------------------
# Pure helpers (unit-tested directly via `__call`).
# ---------------------------------------------------------------------------

# Best-effort extraction of the "target pattern" a bead's text cites --
# a backtick-quoted markdown code span, the convention this repo's beads
# already use for file paths and symbol names (see any bead body via
# `bd show`). Prefers a path-shaped span (contains `/`) over a bare
# identifier: a path pins down one specific target, where a bare symbol
# name is more likely to recur coincidentally elsewhere in the tree.
extract_target_pattern() {
  local text="$1" candidates path_candidate symbol_candidate
  candidates=$(printf '%s' "$text" | grep -oE '`[^`]+`' | sed -E 's/^`(.*)`$/\1/') || true
  [ -z "$candidates" ] && { printf ''; return; }

  path_candidate=$(printf '%s\n' "$candidates" | grep -E '/' | head -1) || true
  if [ -n "$path_candidate" ]; then
    printf '%s' "$path_candidate"
    return
  fi

  # A bare code span with no slash: only trust it as a symbol/convention
  # target if it has no spaces. A multi-word span like `git commit` is
  # prose-in-backticks, not a grep-able target -- letting it through would
  # produce a literal multi-word match that can never actually appear in
  # source, silently masquerading as a real pattern.
  symbol_candidate=$(printf '%s\n' "$candidates" | grep -vE ' ' | grep -E '[A-Za-z0-9_]' | head -1) || true
  printf '%s' "$symbol_candidate"
}

# True (exit 0) iff `pattern` appears in the tracked tree. A path-shaped
# pattern (contains a `/`) is checked for FILE EXISTENCE first -- a bead
# citing `scripts/old-thing.sh` is usually citing the file itself, not a
# string occurrence of that path inside some other file's content, and a
# content-only grep would never find a file merely by its own name.
# Either way, the content-grep fallback excludes `.beads/`: without that
# exclusion, EVERY pattern extracted from a bead's own text would trivially
# match, because `.beads/issues.jsonl` stores that same text, making the
# check always report still-broken regardless of what the actual code
# looks like.
check_pattern_present() {
  local pattern="$1"
  case "$pattern" in
    */*)
      git -C "$REPO_ROOT" ls-files --error-unmatch -- "$pattern" >/dev/null 2>&1 && return 0
      ;;
  esac
  git -C "$REPO_ROOT" grep -qF -e "$pattern" -- . ':!.beads' 2>/dev/null
}

# Classifies a single `bd show <id> --json` result (a one-element array).
# Split out from main() so tests can feed synthetic JSON against a sandbox
# git tree, without a live `bd` session or network access -- the same
# "exercise the real logic, not a reimplementation" technique the sibling
# scripts/test-*-logic.sh suites use.
#
# Prints still-broken / no-longer-broken / cannot-verify and returns
# 0 / 1 / 2 respectively.
classify_from_json() {
  local json="$1" text pattern
  text=$(printf '%s' "$json" | jq -r '
    [.[0].description, .[0].design, .[0].acceptance_criteria]
    | map(select(. != null)) | join("\n")')
  pattern=$(extract_target_pattern "$text")
  if [ -z "$pattern" ]; then
    printf 'cannot-verify\n'
    return 2
  fi
  if check_pattern_present "$pattern"; then
    printf 'still-broken\n'
    return 0
  fi
  printf 'no-longer-broken\n'
  return 1
}

main() {
  local bead_id="${1:-}"
  if [ -z "$bead_id" ]; then
    echo "usage: bead-premise-check.sh <bead-id>" >&2
    printf 'cannot-verify\n'
    exit 2
  fi

  local json rc=0
  json=$(bd show "$bead_id" --json 2>/dev/null) || json=''
  if [ -z "$json" ] || [ "$json" = "null" ]; then
    printf 'cannot-verify\n'
    exit 2
  fi

  classify_from_json "$json" || rc=$?
  exit "$rc"
}

if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  if [ "${1:-}" = "__call" ]; then
    shift
    "$@"
  else
    main "$@"
  fi
fi

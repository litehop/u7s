#!/usr/bin/env bash
# Blocking gate invoked from .githooks/pre-push: if diff range $1 (in
# repo $2) touches a file pattern in .githooks/sensitive-conformance-focus.yaml,
# require evidence of a fresh sonobuoy --focus PASS for the matching spec(s)
# before letting the push through.
#
# Extracted from .githooks/pre-push into its own script (not a sourced
# function) so it's independently testable the same way
# scripts/check-doc-budget.sh is: run the REAL script as a subprocess against
# disposable sandbox git repos (see scripts/test-sensitive-conformance-gate-
# logic.sh), without also invoking pre-push's own `cargo test --workspace` /
# `cargo clippy` prefix on every test run.
#
# Usage: sensitive-conformance-gate.sh <diff-range> <target-repo-root>
#
#   <diff-range>       a git revision range, e.g. "abc123..def456" -- the
#                       push being gated. Old/new sides are read via `${1%%..*}`
#                       / `${1##*..}`, so this must be exactly one "A..B" pair
#                       (never "A...B"), matching how .githooks/pre-push
#                       always constructs it.
#   <target-repo-root>  the repo being gated (its git history, working tree,
#                       and temp/e2e/ results are all read from here). In
#                       production this is always the same checkout this
#                       script lives in; kept as an explicit argument (rather
#                       than re-deriving via `git rev-parse --show-toplevel`)
#                       so tests can point it at a disposable sandbox repo
#                       while still running against the REAL compiled
#                       u7s-junit-reuse-check binary.
#
# HOOK_ROOT below (derived from $0, not from git or $2) is deliberately a
# SEPARATE concept from <target-repo-root>: it's "where this tooling itself
# lives" (the registry yaml, scripts/conformance/run-all.sh, and the
# u7s-junit-reuse-check Cargo crate), which only diverges from
# <target-repo-root> under test.
#
# Exit 0: push allowed (no sensitive file touched, comment-only diff, or a
#         reusable prior PASS was found). Exit 1: push blocked.
#
# The two fast-path mechanisms below (difftastic comment-only-diff skip,
# junit-result reuse) both exist to avoid a redundant multi-minute live-VM
# sonobuoy run. See bd memory `conformance-pr-merge-gate` /
# `prefer-local-hook-over-ci-runner-for-conformance-gate` for why this gate
# exists at all (see also .githooks/pre-push's own header comment, which
# this script's logic used to live in verbatim).
set -euo pipefail

RANGE="${1:?usage: sensitive-conformance-gate.sh <diff-range> <target-repo-root>}"
TARGET_ROOT="${2:?usage: sensitive-conformance-gate.sh <diff-range> <target-repo-root>}"
HOOK_ROOT=$(cd "$(dirname "$0")/.." && pwd)
REGISTRY="$HOOK_ROOT/.githooks/sensitive-conformance-focus.yaml"

# Emits one "<file-pattern><TAB><focus-regex>" line per registry entry.
# Deliberately NOT a general YAML parser -- see the registry's own header
# comment for why a git hook can't depend on yq/python being installed, and
# the exact schema (2 meaningful lines per entry: "- file:" then "  focus:")
# this parser depends on. The "function:" line is intentionally not matched
# here -- it exists in the registry only as human-readable audit trail.
parse_registry() {
  [ -f "$REGISTRY" ] || return 0
  awk '
    /^[[:space:]]*-[[:space:]]*file:/ {
      sub(/^[[:space:]]*-[[:space:]]*file:[[:space:]]*/, "")
      file = $0
      next
    }
    /^[[:space:]]*focus:/ {
      sub(/^[[:space:]]*focus:[[:space:]]*/, "")
      focus = $0
      gsub(/^"|"$/, "", focus)
      if (file != "") { print file "\t" focus; file = "" }
      next
    }
  ' "$REGISTRY"
}

# True (exit 0) if a comment/whitespace-only diff of $2 vs $3 (old vs new
# git-show'd temp files) can be established via difftastic. False (exit 1)
# for a genuine syntactic change, a file added/removed on either side, or
# any difft outcome other than its own documented 0/1 exit codes -- treating
# an unexpected difft exit code as "real change" is the fail-safe direction:
# it only costs an unnecessary fresh run, never a skipped one.
#
# --ignore-comments is REQUIRED here: difftastic's default `--exit-code`
# behavior (verified empirically -- difft 0.70.0) reports a pure comment
# edit as a syntactic change, matching plain `diff`'s line-oriented view
# rather than the "ignores comments" tree-sitter-based semantics an operator
# might expect from the phrase "structural diff". Without this flag the
# mechanism below would almost never fire.
#
# The two `git show` outputs are staged into a temp DIRECTORY under their
# ORIGINAL basename (not bare `mktemp` files) -- difft picks its tree-sitter
# grammar from the filename extension (verified empirically: an extensionless
# temp file is treated as unrecognized "Text" and a pure comment edit then
# reports as a byte-level change, defeating this whole mechanism). `mktemp`
# has no portable `--suffix` flag across BSD (macOS) and GNU, so a
# subdirectory is the portable way to control the final filename.
diff_is_comment_only() {
  old_ref="$1"
  new_ref="$2"
  file="$3"
  base=$(basename "$file")
  tmp_dir=$(mktemp -d)
  old_path="$tmp_dir/old-$base"
  new_path="$tmp_dir/new-$base"
  old_ok=1
  new_ok=1
  git -C "$TARGET_ROOT" show "${old_ref}:${file}" >"$old_path" 2>/dev/null || old_ok=0
  git -C "$TARGET_ROOT" show "${new_ref}:${file}" >"$new_path" 2>/dev/null || new_ok=0

  result=1
  if [ "$old_ok" -eq 1 ] && [ "$new_ok" -eq 1 ]; then
    if difft --exit-code --check-only --ignore-comments "$old_path" "$new_path" >/dev/null 2>&1; then
      result=0
    fi
  fi
  rm -rf "$tmp_dir"
  return "$result"
}

check_sensitive_conformance_gate() {
  range="$1"
  changed_tmp=$(mktemp)
  git -C "$TARGET_ROOT" diff --name-only "$range" >"$changed_tmp" 2>/dev/null || true
  if [ ! -s "$changed_tmp" ]; then
    rm -f "$changed_tmp"
    return 0
  fi

  registry_tmp=$(mktemp)
  parse_registry >"$registry_tmp" 2>/dev/null || true
  if [ ! -s "$registry_tmp" ]; then
    rm -f "$changed_tmp" "$registry_tmp"
    return 0
  fi

  # focus: the "|"-joined focus regex across every matched registry entry
  # (unchanged from the original gate). files_tmp: the ACTUAL changed file
  # path(s) that matched a registry pattern (a pattern may be a path
  # substring, so this is not necessarily identical to the pattern text
  # itself) -- needed by both fast-path mechanisms below, which operate on
  # real paths, not registry substrings.
  focus=""
  matched=""
  files_tmp=$(mktemp)
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    pattern=$(printf '%s' "$line" | cut -f1)
    entry_focus=$(printf '%s' "$line" | cut -f2)
    [ -z "$pattern" ] && continue
    file_matches=$(grep -F "$pattern" "$changed_tmp" || true)
    if [ -n "$file_matches" ]; then
      matched="$matched $pattern"
      if [ -z "$focus" ]; then
        focus="$entry_focus"
      else
        focus="$focus|$entry_focus"
      fi
      printf '%s\n' "$file_matches" >>"$files_tmp"
    fi
  done <"$registry_tmp"
  rm -f "$changed_tmp" "$registry_tmp"

  if [ -z "$focus" ]; then
    rm -f "$files_tmp"
    return 0
  fi
  sort -u "$files_tmp" -o "$files_tmp"

  echo ""
  echo "================================================================"
  echo "[pre-push] BLOCKING GATE: push touches known-recurring-regression"
  echo "file(s):$matched"
  echo "[pre-push] Requires a fresh sonobuoy PASS for focus:"
  echo "    $focus"
  echo "================================================================"

  old_ref="${range%%..*}"
  new_ref="${range##*..}"

  # --- Mechanism 1: comment-only-diff skip (difftastic) -----------------
  echo ""
  echo "[pre-push] Checking for comment/whitespace-only diffs (difftastic)..."
  if ! command -v difft >/dev/null 2>&1; then
    echo "[pre-push] difft not installed (install: brew install difftastic) --"
    echo "[pre-push] skipping the comment-only-diff fast path, full check required."
    all_comment_only=0
  else
    all_comment_only=1
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      if diff_is_comment_only "$old_ref" "$new_ref" "$f"; then
        echo "[pre-push]   $f: comment/whitespace-only diff"
      else
        echo "[pre-push]   $f: syntactic change (or added/removed) -- real change"
        all_comment_only=0
      fi
    done <"$files_tmp"
  fi

  if [ "$all_comment_only" -eq 1 ]; then
    echo "[pre-push] All touched sensitive file(s) are comment/whitespace-only --"
    echo "[pre-push] skipping the sonobuoy requirement for this push."
    rm -f "$files_tmp"
    return 0
  fi

  # --- Mechanism 2: reuse a fresh matching junit result ------------------
  echo ""
  echo "[pre-push] Checking for a reusable prior sonobuoy result..."
  junit_tool_bin="$HOOK_ROOT/target/debug/u7s-junit-reuse-check"
  build_out=$(mktemp)
  if ! cargo build --quiet --manifest-path "$HOOK_ROOT/Cargo.toml" --bin u7s-junit-reuse-check >"$build_out" 2>&1; then
    echo "[pre-push] failed to build u7s-junit-reuse-check -- cannot check for a" >&2
    echo "[pre-push] reusable result, requiring a fresh run. Build output:" >&2
    cat "$build_out" >&2
    rm -f "$build_out"
  else
    rm -f "$build_out"
    # --ref is the actual pushed SHA (new_ref, derived from $RANGE below), NOT
    # the target repo's checked-out HEAD -- see u7s-junit-reuse-check's own
    # doc comment / GitFreshnessCheck::pushed_ref for why walking implicit
    # HEAD here would silently mis-scope the freshness check to whatever
    # branch happens to be checked out rather than what's being pushed.
    tool_args=(--repo-root "$TARGET_ROOT" --focus "$focus" --ref "$new_ref")
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      tool_args+=(--file "$f")
    done <"$files_tmp"

    reuse_stdout=$(mktemp)
    reuse_stderr=$(mktemp)
    if "$junit_tool_bin" "${tool_args[@]}" >"$reuse_stdout" 2>"$reuse_stderr"; then
      reused_path=$(cat "$reuse_stdout")
      cat "$reuse_stderr"
      echo "[pre-push] Reusing prior sonobuoy result: $reused_path"
      echo "[pre-push] Sensitive-conformance gate PASSED (reused $reused_path)."
      rm -f "$reuse_stdout" "$reuse_stderr" "$files_tmp"
      return 0
    fi
    cat "$reuse_stderr"
    rm -f "$reuse_stdout" "$reuse_stderr"
  fi
  rm -f "$files_tmp"

  # --- Fallback: require a FRESH sonobuoy run, unchanged from before -----
  #
  # Runs scripts/conformance/run-all.sh on the VM/port named by
  # U7S_CONFORMANCE_GATE_{VM,PORT,KUBELET_PORT} -- these have NO default. A
  # fallback here would silently reuse a shared/possibly-in-use slot (e.g.
  # the mayor's own lima-node:6443) instead of the pusher's actually-assigned
  # VM, which is exactly the hazard this gate exists to avoid elsewhere.
  # There is no way to auto-detect "the pusher's assigned VM slot" from
  # inside a git hook, so the pusher must set these three explicitly before
  # pushing a sensitive-file change -- see the error message below for the
  # exact form.
  gate_vm="${U7S_CONFORMANCE_GATE_VM:-}"
  gate_port="${U7S_CONFORMANCE_GATE_PORT:-}"
  gate_kubelet_port="${U7S_CONFORMANCE_GATE_KUBELET_PORT:-}"

  if [ -z "$gate_vm" ] || [ -z "$gate_port" ] || [ -z "$gate_kubelet_port" ]; then
    echo "[pre-push] BLOCKED: U7S_CONFORMANCE_GATE_VM/_PORT/_KUBELET_PORT are not" >&2
    echo "all set in this shell -- refusing to guess (a silent default would risk" >&2
    echo "reusing a shared/in-use VM slot, e.g. the mayor's own lima-node:6443)." >&2
    echo "Set them to YOUR assigned VM slot before pushing, e.g.:" >&2
    echo "  U7S_CONFORMANCE_GATE_VM=lima-node-2 U7S_CONFORMANCE_GATE_PORT=6444 \\" >&2
    echo "  U7S_CONFORMANCE_GATE_KUBELET_PORT=10251 git push ..." >&2
    return 1
  fi

  run_out=$(mktemp)
  set +e
  "$HOOK_ROOT/scripts/conformance/run-all.sh" \
    --vm "$gate_vm" --port "$gate_port" --kubelet-port "$gate_kubelet_port" \
    --focus "$focus" >"$run_out" 2>&1
  run_rc=$?
  set -e
  cat "$run_out"

  if [ "$run_rc" -ne 0 ]; then
    echo "[pre-push] BLOCKED: run-all.sh exited $run_rc -- see output above." >&2
    rm -f "$run_out"
    return 1
  fi

  run_dir=$(grep -m1 '^Results: ' "$run_out" | awk '{print $2}' | sed 's/\.tar\.gz$//')
  rm -f "$run_out"

  e2e_txt=""
  if [ -n "$run_dir" ]; then
    e2e_txt=$(find "$run_dir" -path '*/logs/e2e.txt' 2>/dev/null | head -1)
  fi

  if [ -z "$e2e_txt" ] || [ ! -f "$e2e_txt" ]; then
    echo "[pre-push] BLOCKED: could not locate e2e.txt for the focus run -- cannot confirm PASS." >&2
    return 1
  fi

  if ! grep -qE '^Ran [1-9][0-9]* of [0-9]+ Specs' "$e2e_txt"; then
    echo "[pre-push] BLOCKED: 0 specs matched focus regex -- cannot confirm PASS. See $e2e_txt" >&2
    return 1
  fi

  if ! grep -q '^SUCCESS! --' "$e2e_txt"; then
    echo "[pre-push] BLOCKED: focus run did NOT report SUCCESS -- see $e2e_txt" >&2
    return 1
  fi

  echo "[pre-push] Sensitive-conformance gate PASSED ($e2e_txt)."
}

check_sensitive_conformance_gate "$RANGE"

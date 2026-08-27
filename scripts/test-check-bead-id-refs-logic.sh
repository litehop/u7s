#!/usr/bin/env bash
# Unit test for scripts/check-bead-id-refs.sh's regex.
#
# Exercises the REAL script as a subprocess against disposable sandbox git
# repos (same technique as test-check-doc-budget-logic.sh), not a
# reimplementation of its regex -- a reimplementation would keep passing even
# if the real script regressed.
#
# Regression this guards: the original regex was `mayor-[a-z0-9]{5}`, which
# only matches EXACTLY 5-character bead-ID suffixes. Real bead IDs in this
# repo are 3, 4, or 5 characters (see .beads/issues.jsonl), plus an optional
# dotted sub-ID suffix (e.g. a 4-char base ID with a numeric sub-ID). The
# 5-char-only regex silently missed most real bead-ID references -- 164
# 3-char and 839 4-char IDs, more than half of all IDs in the tracker. This
# test enumerates each real length and the dotted-suffix shape, so a
# regression back to `{5}` fails loudly instead of shipping a guard that only
# catches a minority of violations.
#
# Fixtures below use synthetic bead-ID-shaped strings (not real, closeable
# bead IDs), same convention as scripts/test-critical-reviewer-hook.sh's
# "mayor-abc12" fixture -- this file is excluded from the guard's own sweep
# for exactly that reason (see check-bead-id-refs.sh's exclusion comment).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/check-bead-id-refs.sh"
source "$REPO/scripts/_git-env-guard.sh"

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

# Fresh sandbox git repo at $1 -- check-bead-id-refs.sh scans the whole
# tracked tree (no base-ref argument), so each scenario commits a single
# source file and runs the gate against it. Every git call here goes through
# run_git() (see scripts/_git-env-guard.sh) so an ambient GIT_DIR/GIT_CONFIG
# from this test's own enclosing .githooks/pre-commit invocation can't
# redirect these commands into the real repo instead of $dir.
new_sandbox() {
  local dir="$1"
  run_git init -q -b main "$dir"
  run_git -C "$dir" config user.email test@example.com
  run_git -C "$dir" config user.name "Test"
}

commit_tree() {
  local dir="$1"
  run_git -C "$dir" add -A
  run_git -C "$dir" commit -q -m snapshot
}

# Runs the real gate inside sandbox $1. Returns the gate's exit code without
# tripping this script's `set -e`.
run_gate() {
  local dir="$1"
  set +e
  (cd "$dir" && bash "$SCRIPT") >"$dir/.gate-out" 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

SANDBOX_ROOT=$(mktemp -d)
trap 'rm -rf "$SANDBOX_ROOT"' EXIT

# ---------------------------------------------------------------------------
# 1. Clean tree: ordinary source, no bead-ID-shaped token -> passes.
# ---------------------------------------------------------------------------
S1="$SANDBOX_ROOT/1-clean"
new_sandbox "$S1"
mkdir -p "$S1/src"
printf 'fn add(a: i32, b: i32) -> i32 { a + b }\n' > "$S1/src/lib.rs"
commit_tree "$S1"
RC1=$(run_gate "$S1")
assert "clean tree with no bead-ID refs passes" "$([ "$RC1" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. 3-char bead ID -> fails. The original `{5}` regex cannot match this at
#    all: this is the exact case that silently slipped through the buggy
#    guard.
# ---------------------------------------------------------------------------
S2="$SANDBOX_ROOT/2-three-char"
new_sandbox "$S2"
mkdir -p "$S2/src"
printf '// worked around the race here (mayor-9zk)\nfn f() {}\n' > "$S2/src/lib.rs"
commit_tree "$S2"
RC2=$(run_gate "$S2")
assert "3-char bead ID (mayor-9zk) is caught (missed entirely by the old {5}-only regex)" \
  "$([ "$RC2" -ne 0 ] && echo 1 || echo 0)"
assert "3-char bead ID failure names the offending file" \
  "$(grep -qF 'src/lib.rs' "$S2/.gate-out" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. 4-char bead ID -> fails. Also missed entirely by the old `{5}`-only
#    regex -- the exact shape critical review found live refs in that the
#    original sweep left behind (e.g. a 4-char suffix like "u6ju" or "sz59").
# ---------------------------------------------------------------------------
S3="$SANDBOX_ROOT/3-four-char"
new_sandbox "$S3"
mkdir -p "$S3/src"
printf '// see mayor-a1b2 for the compensating-control rationale\nfn f() {}\n' > "$S3/src/lib.rs"
commit_tree "$S3"
RC3=$(run_gate "$S3")
assert "4-char bead ID (mayor-a1b2) is caught (missed entirely by the old {5}-only regex)" \
  "$([ "$RC3" -ne 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. 5-char bead ID -> fails. This length already worked under the old
#    regex; kept here so the enumeration covers every real length, not just
#    the two the old regex missed.
# ---------------------------------------------------------------------------
S4="$SANDBOX_ROOT/4-five-char"
new_sandbox "$S4"
mkdir -p "$S4/src"
printf '// closes the race from mayor-a1b2c\nfn f() {}\n' > "$S4/src/lib.rs"
commit_tree "$S4"
RC4=$(run_gate "$S4")
assert "5-char bead ID (mayor-a1b2c) is caught" "$([ "$RC4" -ne 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 5. Dotted sub-ID (bd's shape for sub-issues: a base ID + `.N`) -> fails.
#    Confirms the sub-ID suffix doesn't confuse the match or leave a
#    dangling ".6" that reads as a false-clean gate.
# ---------------------------------------------------------------------------
S5="$SANDBOX_ROOT/5-dotted"
new_sandbox "$S5"
mkdir -p "$S5/src"
printf '// exactly the bug mayor-a1b2.6 fixed\nfn f() {}\n' > "$S5/src/lib.rs"
commit_tree "$S5"
RC5=$(run_gate "$S5")
assert "dotted sub-ID (mayor-a1b2.6) is caught" "$([ "$RC5" -ne 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 6. Ambient GIT_DIR/GIT_WORK_TREE leakage (simulating this test's own
#    .githooks/pre-commit invocation) must not redirect new_sandbox()/
#    commit_tree()'s git calls away from the intended sandbox dir -- the
#    exact mechanism (see scripts/_git-env-guard.sh) that corrupted the
#    mayor's real repository twice: a `git init`/`git commit` in a sandbox
#    fixture silently honoring an inherited GIT_DIR/GIT_WORK_TREE instead of
#    its own explicit -C target/positional path. Exports GIT_DIR/GIT_WORK_TREE
#    pointed at a disposable "victim" repo (never the real u7s repo) for the
#    duration of building the target sandbox, then asserts the victim's HEAD
#    is untouched AND the target sandbox was actually built (proving
#    run_git() fails safe by actually working, not merely by erroring out).
# ---------------------------------------------------------------------------
S6_VICTIM="$SANDBOX_ROOT/6-ambient-victim"
new_sandbox "$S6_VICTIM"
mkdir -p "$S6_VICTIM/src"
printf 'fn victim() {}\n' > "$S6_VICTIM/src/lib.rs"
commit_tree "$S6_VICTIM"
VICTIM_HEAD_BEFORE=$(run_git -C "$S6_VICTIM" rev-parse HEAD)

S6_TARGET="$SANDBOX_ROOT/6-ambient-target"
S6_HELPER_RC=0
(
  export GIT_DIR="$S6_VICTIM/.git"
  export GIT_WORK_TREE="$S6_VICTIM"
  new_sandbox "$S6_TARGET"
  mkdir -p "$S6_TARGET/src"
  printf '// worked around the race here (mayor-9zk)\nfn f() {}\n' > "$S6_TARGET/src/lib.rs"
  commit_tree "$S6_TARGET"
) || S6_HELPER_RC=$?

VICTIM_HEAD_AFTER=$(run_git -C "$S6_VICTIM" rev-parse HEAD)
assert "ambient GIT_DIR/GIT_WORK_TREE never redirects the sandbox helpers' git calls into the victim repo (HEAD unchanged)" \
  "$([ "$VICTIM_HEAD_BEFORE" = "$VICTIM_HEAD_AFTER" ] && echo 1 || echo 0)"
assert "...and the sandbox helpers still build a working target repo despite the ambient leak (not just 'fails safe by erroring')" \
  "$([ "$S6_HELPER_RC" -eq 0 ] && run_git -C "$S6_TARGET" rev-parse HEAD >/dev/null 2>&1 && echo 1 || echo 0)"
RC6=$(run_gate "$S6_TARGET")
assert "...and the real gate still catches the bead-ID ref in that correctly-built target" \
  "$([ "$RC6" -ne 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

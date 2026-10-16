#!/usr/bin/env bash
# Regression test: reset.sh accepts --workdir only when its physical path is a
# strict subdirectory of <checkout>/temp for a checkout listed by `git worktree
# list`. temp/ itself, prefix lookalikes (temp2/), a symlinked temp/, '..' and
# symlink escapes are refused in full and --host-only mode, deleting nothing.
# `--workdir .` run from a worktree root would otherwise `rm -rf` the whole
# worktree.
#
# Everything runs in a mktemp sandbox with its own `git init`. rm, pkill,
# pgrep and limactl are stubbed on PATH and only record their calls, so a
# regressed guard shows up as a recorded `rm` call and never as real deletion
# (the `/` case in particular is never allowed to reach a real rm).
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO/scripts/conformance/reset.sh"

PASS=0
FAIL=0

TMPROOT="$(cd "$(mktemp -d)" && pwd -P)"
trap 'rm -rf "$TMPROOT"' EXIT

STUBS="$TMPROOT/stubs"
CALLS="$TMPROOT/calls.log"
mkdir -p "$STUBS"
: >"$CALLS"
for cmd in rm pkill pgrep limactl; do
  printf '#!/bin/sh\necho "%s $*" >>"%s"\nexit 0\n' "$cmd" "$CALLS" >"$STUBS/$cmd"
  chmod +x "$STUBS/$cmd"
done

OUTER="$TMPROOT/outer"
REPO_SB="$OUTER/repo"
FAKE_HOME="$OUTER/home"
mkdir -p "$REPO_SB/temp/u7s" "$FAKE_HOME"
git -C "$REPO_SB" init -q
git -C "$REPO_SB" -c user.name=t -c user.email=t@t commit -q --allow-empty -m init
LINKED="$OUTER/linked"
git -C "$REPO_SB" worktree add -q --detach "$LINKED"
mkdir -p "$LINKED/temp/u7s" "$OUTER/sibling" "$OUTER/elsewhere" \
  "$REPO_SB/temp2/x" "$REPO_SB/temporary/x" "$LINKED/temp2/x" "$OUTER/symtarget/u7s"
SYM="$OUTER/symlinked"
git -C "$REPO_SB" worktree add -q --detach "$SYM"
ln -s "$OUTER/symtarget" "$SYM/temp"
ln -s "$OUTER/elsewhere" "$REPO_SB/temp/escape"
touch "$OUTER/symtarget/u7s/marker" "$REPO_SB/temp2/x/marker" "$REPO_SB/temporary/x/marker" "$LINKED/temp2/x/marker" \
  "$OUTER/marker-outer" "$REPO_SB/marker-repo" "$REPO_SB/temp/u7s/marker-state" "$FAKE_HOME/marker-home" \
  "$LINKED/temp/marker-linked-temp" "$OUTER/sibling/marker" "$OUTER/elsewhere/marker" "$REPO_SB/temp/marker-main-temp"

# run_reset <cwd> <home> <workdir> [reset.sh flag]: sets OUT/EXIT; clears recorded calls.
run_reset() {
  : >"$CALLS"
  set +e
  OUT="$(cd "$1" && HOME="$2" PATH="$STUBS:$PATH" bash "$SCRIPT" --workdir "$3" ${4:-} 2>&1)"
  EXIT=$?
  set -e
}

assert_refused() {
  local label="$1"
  if [ "$EXIT" -ne 0 ] && grep -q "refusing --workdir" <<<"$OUT" && ! grep -q '^rm ' "$CALLS" \
    && [ -e "$OUTER/marker-outer" ] && [ -e "$REPO_SB/marker-repo" ] && [ -e "$REPO_SB/temp/u7s/marker-state" ] \
    && [ -e "$FAKE_HOME/marker-home" ] && [ -e "$LINKED/temp/marker-linked-temp" ] \
    && [ -e "$OUTER/symtarget/u7s/marker" ] && [ -e "$REPO_SB/temp2/x/marker" ] \
    && [ -e "$REPO_SB/temporary/x/marker" ] && [ -e "$LINKED/temp2/x/marker" ] \
    && [ -e "$OUTER/sibling/marker" ] && [ -e "$OUTER/elsewhere/marker" ] && [ -e "$REPO_SB/temp/marker-main-temp" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — exit $EXIT, rm calls: $(grep '^rm ' "$CALLS" || echo none), output: $OUT"
    FAIL=$(( FAIL + 1 ))
  fi
}

run_reset "$REPO_SB" "$FAKE_HOME" .
assert_refused "--workdir . is refused (it would delete the caller's whole worktree)"

run_reset "$REPO_SB" "$FAKE_HOME" "$REPO_SB"
assert_refused "--workdir <repo root> is refused"

run_reset "$REPO_SB/temp" "$FAKE_HOME" "$REPO_SB"
assert_refused "--workdir <repo root> is refused from a subdirectory of the repo"

run_reset "$REPO_SB" "$FAKE_HOME" "$OUTER"
assert_refused "--workdir <parent of repo root> is refused (it contains the worktree)"

run_reset "$REPO_SB" "$FAKE_HOME" ..
assert_refused "--workdir .. is refused"

run_reset "$REPO_SB" "$FAKE_HOME" "$FAKE_HOME"
assert_refused "--workdir \$HOME is refused"

run_reset "$REPO_SB" "$FAKE_HOME" /
assert_refused "--workdir / is refused"

run_reset "$REPO_SB" "$FAKE_HOME" "$REPO_SB/temp"
assert_refused "--workdir <main>/temp itself is refused (strict subdirectory required)"

run_reset "$LINKED" "$FAKE_HOME" "$LINKED/temp"
assert_refused "--workdir <linked>/temp itself is refused"

run_reset "$REPO_SB" "$FAKE_HOME" "$OUTER/sibling"
assert_refused "--workdir a sibling dir outside every checkout's temp/ is refused"

run_reset "$REPO_SB" "$FAKE_HOME" ./temp/../../sibling
assert_refused "--workdir that only looks like temp/ via '..' is refused"

run_reset "$REPO_SB" "$FAKE_HOME" ./temp/escape
assert_refused "--workdir a symlink under temp/ pointing outside is refused (rm -rf would follow it)"

run_reset "$REPO_SB" "$FAKE_HOME" "$REPO_SB/temp2/x"
assert_refused "--workdir <main>/temp2/x is refused (temp is a path prefix, not a boundary)"

run_reset "$REPO_SB" "$FAKE_HOME" "$REPO_SB/temporary/x"
assert_refused "--workdir <main>/temporary/x is refused (temp is a path prefix, not a boundary)"

run_reset "$LINKED" "$FAKE_HOME" "$LINKED/temp2/x"
assert_refused "--workdir <linked>/temp2/x is refused (prefix boundary holds for linked worktrees)"

run_reset "$SYM" "$FAKE_HOME" "$SYM/temp/u7s"
assert_refused "--workdir under a symlinked <checkout>/temp is refused (would whitelist the symlink target)"

run_reset "$REPO_SB" "$FAKE_HOME" "$OUTER/symtarget/u7s"
assert_refused "--workdir the target of a symlinked temp/ is refused"

run_reset "$REPO_SB" "$FAKE_HOME" . --host-only
assert_refused "--host-only --workdir . is refused (the guard covers both modes)"

run_reset "$REPO_SB" "$FAKE_HOME" "$OUTER/sibling" --host-only
assert_refused "--host-only --workdir a sibling dir is refused"

run_reset "$REPO_SB" "$FAKE_HOME" "$REPO_SB/temp" --host-only
assert_refused "--host-only --workdir bare temp/ is refused"

run_reset "$REPO_SB" "$FAKE_HOME" "$REPO_SB/temp2/x" --host-only
assert_refused "--host-only --workdir <main>/temp2/x is refused"

NOGIT="$TMPROOT/nogit"
mkdir -p "$NOGIT/temp/u7s"
run_reset "$NOGIT" "$FAKE_HOME" ./temp/u7s
assert_refused "--workdir outside any git repo is refused"
rm -rf "$NOGIT"

assert_wiped() {
  local label="$1" want="$2"
  if [ "$EXIT" -eq 0 ] && grep -q "^rm -rf $want\$" "$CALLS"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — exit $EXIT, calls: $(cat "$CALLS"), output: $OUT"
    FAIL=$(( FAIL + 1 ))
  fi
}

run_reset "$REPO_SB" "$FAKE_HOME" ./temp/u7s
assert_wiped "./temp/u7s from the main checkout still resets (guard must not break real resets)" "$REPO_SB/temp/u7s"

run_reset "$LINKED" "$FAKE_HOME" ./temp/u7s
assert_wiped "./temp/u7s from a linked worktree still resets" "$LINKED/temp/u7s"

mkdir -p "$REPO_SB/temp/u7s" "$LINKED/temp/u7s"
run_reset "$REPO_SB" "$FAKE_HOME" "$LINKED/temp/u7s"
assert_wiped "<linked>/temp/u7s is accepted from the main checkout (any checkout's temp/ is allowed)" "$LINKED/temp/u7s"

run_reset "$LINKED" "$FAKE_HOME" "$REPO_SB/temp/u7s"
assert_wiped "<main>/temp/u7s is accepted from a linked worktree" "$REPO_SB/temp/u7s"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

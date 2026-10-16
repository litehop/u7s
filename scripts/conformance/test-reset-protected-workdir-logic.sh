#!/usr/bin/env bash
# Regression test: reset.sh (full mode) must refuse a --workdir that is the
# caller's cwd, the git repo root, an ancestor of it, $HOME or /, and must
# delete nothing. `--workdir .` run from a worktree root would otherwise
# `rm -rf` the whole worktree.
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
touch "$OUTER/marker-outer" "$REPO_SB/marker-repo" "$REPO_SB/temp/u7s/marker-state" "$FAKE_HOME/marker-home"

# run_reset <cwd> <home> <workdir>: sets OUT/EXIT; clears recorded calls.
run_reset() {
  : >"$CALLS"
  set +e
  OUT="$(cd "$1" && HOME="$2" PATH="$STUBS:$PATH" bash "$SCRIPT" --workdir "$3" 2>&1)"
  EXIT=$?
  set -e
}

assert_refused() {
  local label="$1"
  if [ "$EXIT" -ne 0 ] && grep -q "refusing --workdir" <<<"$OUT" && ! grep -q '^rm ' "$CALLS" \
    && [ -e "$OUTER/marker-outer" ] && [ -e "$REPO_SB/marker-repo" ] && [ -e "$REPO_SB/temp/u7s/marker-state" ] \
    && [ -e "$FAKE_HOME/marker-home" ]; then
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

run_reset "$REPO_SB" "$FAKE_HOME" ./temp/u7s
if [ "$EXIT" -eq 0 ] && grep -q "^rm -rf $REPO_SB/temp/u7s\$" "$CALLS"; then
  echo "PASS: normal ./temp/u7s workdir still reaches the wipe (guard must not break real resets)"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: normal workdir: exit $EXIT, calls: $(cat "$CALLS"), output: $OUT"
  FAIL=$(( FAIL + 1 ))
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

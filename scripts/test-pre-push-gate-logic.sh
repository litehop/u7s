#!/usr/bin/env bash
# The pre-push hook's cargo gate must run only when a pushed ref carries a commit
# not already on origin/main. Release tags from an unchanged main and remote
# branch deletes otherwise pay a full workspace test run and get blocked by
# unrelated local build-cache breakage. The real hook is driven in a temp repo
# with synthetic stdin and a PATH-stubbed cargo that records invocations.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK="$(cd "$DIR/.." && pwd)/.githooks/pre-push"

PASS=0
FAIL=0
check() {
  local label="$1" want="$2" got="$3"
  if [ "$want" = "$got" ]; then echo "PASS: $label"; PASS=$((PASS + 1)); else echo "FAIL: $label (want cargo_ran=$want, got $got)"; FAIL=$((FAIL + 1)); fi
}

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
mkdir "$T/bin"
printf '#!/bin/sh\necho "$@" >>"$CARGO_LOG"\n' >"$T/bin/cargo"
chmod +x "$T/bin/cargo"

R="$T/repo"
git init -q -b main "$R"
git -C "$R" config user.email t@t
git -C "$R" config user.name t
git -C "$R" commit -q --allow-empty -m on-main
MAIN=$(git -C "$R" rev-parse HEAD)
git -C "$R" update-ref refs/remotes/origin/main "$MAIN"
git -C "$R" checkout -q -b feature
git -C "$R" commit -q --allow-empty -m unmerged
NEW=$(git -C "$R" rev-parse HEAD)
ZERO=0000000000000000000000000000000000000000

# Echoes 1 if the hook ran cargo for stdin $1, else 0.
cargo_ran() {
  : >"$T/cargo.log"
  (cd "$R" && CARGO_LOG="$T/cargo.log" PATH="$T/bin:$PATH" sh "$HOOK" <<<"$1" >/dev/null 2>&1)
  [ -s "$T/cargo.log" ] && echo 1 || echo 0
}

check "release tag from unchanged main must not run the workspace test suite" 0 \
  "$(cargo_ran "refs/tags/v1 $MAIN refs/tags/v1 $ZERO")"
check "remote branch delete adds no code so must not run the workspace test suite" 0 \
  "$(cargo_ran "(delete) $ZERO refs/heads/old $NEW")"
check "branch with a new commit must still run the gate" 1 \
  "$(cargo_ran "refs/heads/feature $NEW refs/heads/feature $ZERO")"
check "tag on an unmerged commit must still run the gate" 1 \
  "$(cargo_ran "refs/tags/v2 $NEW refs/tags/v2 $ZERO")"
check "mixed push of main-tag plus new branch commit must run the gate" 1 \
  "$(cargo_ran "refs/tags/v1 $MAIN refs/tags/v1 $ZERO
refs/heads/feature $NEW refs/heads/feature $ZERO")"

git -C "$R" update-ref -d refs/remotes/origin/main
check "unresolvable origin/main must fail safe and run the gate" 1 \
  "$(cargo_ran "refs/tags/v1 $MAIN refs/tags/v1 $ZERO")"

echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]

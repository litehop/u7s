#!/usr/bin/env bash
# u7s-start.sh and conformance/05-start-scheduler.sh kill the previous
# konnectivity-server / u7s-scheduler of THEIR workdir before restarting. An
# unanchored `pkill -f "...${WORKDIR}"` also kills another live stack whose
# workdir merely contains this one (suffix or prefix collision, or a regex
# metacharacter in the path), tearing down a peer worker's cluster.
#
# The real pkill/pgrep lines are extracted from the real scripts and evaluated
# with a pkill wrapper that records its argv and then really kills; the targets
# are real sleepers whose argv mimics the daemons'.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/_kill-pattern.sh
source "$DIR/_kill-pattern.sh"

PASS=0
FAIL=0
assert_true() {
  local label="$1"
  shift
  if "$@"; then echo "PASS: $label"; PASS=$(( PASS + 1 )); else echo "FAIL: $label"; FAIL=$(( FAIL + 1 )); fi
}
alive() { kill -0 "$1" 2>/dev/null; }

T=$(mktemp -d)
PIDS=()
cleanup() {
  local p
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  rm -rf "$T"
}
trap cleanup EXIT

# spawn <argv0 string>: a sleeper whose full command line starts with it.
spawn() {
  ( exec -a "$1" sleep 300 ) &
  SPAWNED=$!
  disown "$SPAWNED"
  PIDS+=("$SPAWNED")
}

# Workdirs: A is the one restarting. B embeds A as a path suffix, C extends A
# (prefix), and D differs from "a.b" only where the unescaped '.' wildcard
# would match.
A="$T/wd/a.b"
B="/zz$A"
C="${A}2"
D="$T/wd/aXb"

CAPTURED=$(mktemp)
pkill() { printf '%s\n' "$*" >> "$CAPTURED"; command pkill "$@"; }

run_case() {
  local label="$1" daemon="$2" flagfmt="$3"
  local pa pb pc pd
  spawn "$daemon ${flagfmt//@/$A}"; pa=$SPAWNED
  spawn "$daemon ${flagfmt//@/$B}"; pb=$SPAWNED
  spawn "$daemon ${flagfmt//@/$C}"; pc=$SPAWNED
  spawn "$daemon ${flagfmt//@/$D}"; pd=$SPAWNED
  sleep 0.3
  : > "$CAPTURED"
  WORKDIR="$A"
  eval "$KILL_CODE"
  sleep 0.5
  assert_true "$label: issued a pkill" [ -s "$CAPTURED" ]
  assert_true "$label: kills its own workdir's process" bash -c "! kill -0 $pa 2>/dev/null"
  assert_true "$label: spares a stack whose workdir ends with this one (suffix collision)" alive "$pb"
  assert_true "$label: spares a stack whose workdir extends this one (prefix collision)" alive "$pc"
  assert_true "$label: spares a stack differing only where an unescaped '.' would match" alive "$pd"
}

# u7s-start.sh: every pkill line, exactly the two restart paths.
KILL_CODE=$(grep -E '^[[:space:]]*pkill -f ' "$DIR/u7s-start.sh")
assert_true "u7s-start.sh has exactly its two konnectivity-server pkill lines" \
  [ "$(grep -c 'konnectivity-server' <<< "$KILL_CODE")" = 2 ]
assert_true "u7s-start.sh sources the shared pattern builder" \
  grep -q '_kill-pattern.sh' "$DIR/u7s-start.sh"
run_case "u7s-start.sh konnectivity restart" konnectivity-server "--server-cert=@/konnectivity-server.crt --x"

# 05-start-scheduler.sh: the real pgrep-guarded restart block.
KILL_CODE=$(sed -n '/^if pgrep -f /,/^fi$/p' "$DIR/conformance/05-start-scheduler.sh")
assert_true "05-start-scheduler.sh restart block was extracted" grep -q 'pkill -f' <<< "$KILL_CODE"
assert_true "05-start-scheduler.sh sources the shared pattern builder" \
  grep -q '_kill-pattern.sh' "$DIR/conformance/05-start-scheduler.sh"
run_case "05-start-scheduler.sh scheduler restart" u7s-scheduler "--kubeconfig @/kubeconfig-scheduler"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

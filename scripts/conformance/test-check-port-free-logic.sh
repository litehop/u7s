#!/usr/bin/env bash
# Unit test for check_port_free() in _lib.sh.
#
# 'lsof -n -iTCP:$port -sTCP:LISTEN -t' exits 1 (not just empty stdout) when
# it finds no matching process — which is the EXPECTED, happy-path outcome of
# this check (port is free). check_port_free() runs under callers that all
# have `set -euo pipefail` (u7s-start.sh, run-all.sh's sourced
# 02-start-apiserver.sh). Before the fix, the unguarded pipeline
#   holder=$(lsof ... | head -1)
# let that nonzero exit code propagate through `pipefail`, tripping `set -e`
# and killing the ENTIRE calling script right there — before the intended
# `[ -n "$holder" ]` check ever ran. So on every genuinely free port (the
# common case on a fresh --reset, since nothing has bound the derived
# konnectivity ports yet), run-all.sh died silently mid-script with no error
# message, right after "Waiting for server to accept connections ...".
# Confirmed live 2026-08-07 (mayor-07zb7 scout): a fresh `run-all.sh --reset
# --stack-only` failed deterministically on this exact line.
#
# Exercises the REAL check_port_free() function against a REAL free TCP port
# under `set -euo pipefail`, because the bug is specifically about whether
# lsof's own exit code survives to trip errexit — a test that mocks lsof's
# stdout can't distinguish the buggy behavior (silent script death) from the
# fixed one (function returns normally).
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$REPO/scripts/conformance/_lib.sh"

PASS=0
FAIL=0

assert_true() {
  local label="$1" cond="$2"
  if [ "$cond" = "0" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

find_free_port() {
  local port
  for _ in $(seq 1 30); do
    port=$(( (RANDOM % 20000) + 20000 ))
    if ! lsof -n -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
      echo "$port"
      return 0
    fi
  done
  echo "ERROR: could not find a free port" >&2
  return 1
}

# ---------------------------------------------------------------------------
# check_port_free() on a genuinely free port must return normally (exit 0,
# no output) under `set -euo pipefail` — this is the exact scenario that
# used to kill the calling script silently before the fix.
# ---------------------------------------------------------------------------
FREE_PORT="$(find_free_port)"
if (check_port_free "$FREE_PORT" "test-free-port"); then
  assert_true "check_port_free() returns normally for a free port under set -euo pipefail" 0
else
  assert_true "check_port_free() returns normally for a free port under set -euo pipefail" 1
fi

# A caller script that runs check_port_free() and then a marker command must
# reach the marker — this is what actually broke (run-all.sh silently died
# right at the free-port check, never reaching subsequent steps).
OUTPUT="$(bash -c '
  set -euo pipefail
  source "'"$REPO"'/scripts/conformance/_lib.sh"
  check_port_free "'"$FREE_PORT"'" "test-free-port"
  echo MARKER_REACHED
' 2>&1)" || true
if [ "$OUTPUT" = "MARKER_REACHED" ]; then
  echo "PASS: caller script reaches the line AFTER check_port_free() on a free port"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: caller script did not reach the line after check_port_free() — got: [$OUTPUT]"
  FAIL=$(( FAIL + 1 ))
fi

# ---------------------------------------------------------------------------
# check_port_free() on an OCCUPIED port must still hard-fail (exit 1) with
# its intended error message — the fix must not weaken this branch.
# ---------------------------------------------------------------------------
OCC_PORT="$(find_free_port)"
nc -l "$OCC_PORT" </dev/null &>/dev/null &
LISTENER_PID=$!
trap 'kill -9 "$LISTENER_PID" 2>/dev/null || true' EXIT
sleep 0.5

set +e
ERR_OUTPUT="$(check_port_free "$OCC_PORT" "test-occupied-port" 2>&1)"
ERR_EXIT=$?
set -e
if [ "$ERR_EXIT" -eq 1 ] && echo "$ERR_OUTPUT" | grep -q "already bound"; then
  echo "PASS: check_port_free() still hard-fails on an occupied port"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: check_port_free() on an occupied port: exit=$ERR_EXIT output=[$ERR_OUTPUT]"
  FAIL=$(( FAIL + 1 ))
fi

kill -9 "$LISTENER_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

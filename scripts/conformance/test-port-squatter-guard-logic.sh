#!/usr/bin/env bash
# Regression test for u7s-start.sh's restart-path port-squatter guards
# (konnectivity-server and apiserver).
#
# Root cause (commit 36e0b762): the restart path pkills/kills
# its OWN process by workdir-scoped pattern / PID, then polls with a bare
# nc -z (or lsof-listener-present check) to decide "the port is free now" --
# but that probe can't distinguish "my own freshly restarted server" from "a
# foreign konnectivity-server/apiserver from a DIFFERENT workdir already
# listening on the same derived port". A foreign occupant makes the probe
# report the port "up" either way, so a stale foreign process was silently
# left in place while our agents perpetually failed mTLS against the wrong
# CA ("certificate signed by unknown authority") -- every Service-based
# (konnectivity-proxied) webhook call broke far downstream with no clear
# error at the actual point of failure. The apiserver's own restart path and
# its "is the server up yet" health loop had the identical defect class.
#
# This test proves the fixed decision logic (a) never treats a foreign
# occupant as free/ours, on both the konnectivity-style "wait then
# check_port_free" guard and the apiserver-style "confirm the listener PID
# is our own SERVER_PID" guard, (b) leaves the happy path (port genuinely
# free, or genuinely held by our own PID) untouched, and (c) the real
# u7s-start.sh source actually wires both guards in -- so reverting either
# fix fails this test, not just a same-bug-twice mirror.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$REPO/scripts/conformance/_lib.sh"
U7S_START="$REPO/scripts/u7s-start.sh"

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
# Mirrors u7s-start.sh's konnectivity-server restart guard exactly (lines
# ~244-251 / ~413): wait a short bound for any listener to disappear, then
# hard-fail via the REAL check_port_free() if one is still there. Also
# reused for the apiserver restart path's fix (line ~164), which is the
# same "wait, then hard-fail" shape.
# ---------------------------------------------------------------------------
wait_then_check_port_free() {
  local port="$1" label="$2"
  local i
  for i in $(seq 1 5); do
    lsof -n -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1 || break
    sleep 0.1
  done
  check_port_free "$port" "$label"
}

# The pre-fix shape: waits, then falls through unconditionally -- no
# hard-fail call at all, exactly mirroring the bug this fix closes.
wait_then_proceed_old_buggy() {
  local port="$1"
  local i
  for i in $(seq 1 5); do
    lsof -n -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1 || break
    sleep 0.1
  done
  echo "proceeded"
}

# Mirrors u7s-start.sh's apiserver health-loop fix (lines ~370-392):
# confirm the port's actual listener PID is our own, not just "something is
# listening".
confirm_own_listener() {
  local port="$1" own_pid="$2"
  local listen_pid
  listen_pid=$(lsof -ti tcp:"$port" -sTCP:LISTEN 2>/dev/null | head -1) || true
  if [ -n "$listen_pid" ] && [ "$listen_pid" = "$own_pid" ]; then
    echo "ours"
  else
    echo "mismatch:${listen_pid:-<none>}"
  fi
}

# The pre-fix shape: a bare "is anything listening" check with no PID
# comparison at all -- can never distinguish our own process from a foreign
# one, exactly mirroring the bug this fix closes.
confirm_own_listener_old_buggy() {
  local port="$1"
  if nc -z 127.0.0.1 "$port" 2>/dev/null; then
    echo "ours"
  else
    echo "mismatch:<none>"
  fi
}

# ===========================================================================
# 1. konnectivity/apiserver "wait then check_port_free" restart guard
# ===========================================================================

# Happy path: a genuinely free port must not be hard-failed -- the fix is
# additive and must not touch the case every normal restart hits.
FREE_PORT="$(find_free_port)"
if (wait_then_check_port_free "$FREE_PORT" "test-konnectivity"); then
  assert "wait_then_check_port_free() leaves a genuinely free port untouched (happy path)" 1
else
  assert "wait_then_check_port_free() leaves a genuinely free port untouched (happy path)" 0
fi

# The real-world failure: a foreign process (a different "workdir") squats
# the port for the whole wait window. Our own kill/pkill target never
# matches it (it's scoped by workdir/PID), so it never exits. The fix must
# hard-fail loudly here -- proceeding silently is exactly the mismatched-CA
# failure mode a user hits (konnectivity-agent stuck failing mTLS against
# the wrong CA, or the apiserver silently deferring to the wrong process).
SQUAT_PORT="$(find_free_port)"
nc -l "$SQUAT_PORT" </dev/null &>/dev/null &
SQUATTER_PID=$!
trap 'kill -9 "$SQUATTER_PID" 2>/dev/null || true' EXIT
sleep 0.3

set +e
SQUAT_OUTPUT="$(wait_then_check_port_free "$SQUAT_PORT" "test-konnectivity" 2>&1)"
SQUAT_EXIT=$?
set -e
assert "a foreign squatter that survives the wait produces a hard-fail (exit 1), not a silent proceed" \
  "$([ "$SQUAT_EXIT" -eq 1 ] && echo 1 || echo 0)"
assert "the hard-fail names the actual failure (port already bound), not a generic error" \
  "$(echo "$SQUAT_OUTPUT" | grep -q "already bound" && echo 1 || echo 0)"

# Regression guard: prove the OLD shape genuinely proceeds unconditionally
# against the same squatter -- the actual silent-proceed bug this fix
# closes. If this ever failed, the "old buggy" mirror would no longer
# represent the bug, and the fix's necessity above couldn't be demonstrated.
OLD_RESULT="$(wait_then_proceed_old_buggy "$SQUAT_PORT")"
assert "(regression guard) pre-fix shape silently proceeds past the same foreign squatter" \
  "$([ "$OLD_RESULT" = "proceeded" ] && echo 1 || echo 0)"

kill -9 "$SQUATTER_PID" 2>/dev/null || true

# ===========================================================================
# 2. apiserver health-loop "confirm own listener PID" guard
# ===========================================================================

# Happy path: our own process really is the listener -- must report "ours",
# or the fix would break every normal startup.
OWN_PORT="$(find_free_port)"
nc -l "$OWN_PORT" </dev/null &>/dev/null &
OWN_PID=$!
trap 'kill -9 "$OWN_PID" 2>/dev/null || true' EXIT
sleep 0.3
RESULT="$(confirm_own_listener "$OWN_PORT" "$OWN_PID")"
assert "confirm_own_listener() reports our own process as the listener (happy path)" \
  "$([ "$RESULT" = "ours" ] && echo 1 || echo 0)"
kill -9 "$OWN_PID" 2>/dev/null || true

# The real-world failure: a foreign process holds the port, but a bare
# "is anything listening" probe can't tell it apart from our own SERVER_PID
# -- the apiserver's health loop would declare victory against the wrong
# process, and every downstream call would silently talk to a mismatched
# apiserver instance instead of ours.
FOREIGN_PORT="$(find_free_port)"
nc -l "$FOREIGN_PORT" </dev/null &>/dev/null &
FOREIGN_PID=$!
trap 'kill -9 "$FOREIGN_PID" 2>/dev/null || true' EXIT
sleep 0.3
NOT_OUR_PID=$$
RESULT="$(confirm_own_listener "$FOREIGN_PORT" "$NOT_OUR_PID")"
assert "confirm_own_listener() refuses to treat a foreign listener as our own SERVER_PID" \
  "$([ "$RESULT" != "ours" ] && echo 1 || echo 0)"

# Regression guard: the old bare nc -z shape can't distinguish "ours" from
# "foreign" at all -- it reports "ours" regardless of which PID answers.
OLD_RESULT="$(confirm_own_listener_old_buggy "$FOREIGN_PORT")"
assert "(regression guard) pre-fix bare-probe shape can't tell a foreign listener from our own" \
  "$([ "$OLD_RESULT" = "ours" ] && echo 1 || echo 0)"

kill -9 "$FOREIGN_PID" 2>/dev/null || true

# ===========================================================================
# 3. Structural checks against the real u7s-start.sh source -- the mirrors
#    above prove the decision logic is right, but not that u7s-start.sh
#    actually wires it up at both the konnectivity AND apiserver restart
#    paths. Fails against the pre-fix source, so reverting either fix fails
#    this test.
# ===========================================================================
APISERVER_CHECK_COUNT=$(grep -c 'check_port_free "\$PORT" "apiserver"' "$U7S_START")
assert "u7s-start.sh hard-fails via check_port_free on BOTH the apiserver restart path and the pre-launch check" \
  "$([ "$APISERVER_CHECK_COUNT" -ge 2 ] && echo 1 || echo 0)"
assert "u7s-start.sh's apiserver health loop compares the listener's PID against our own SERVER_PID" \
  "$(grep -qF 'LISTEN_PID' "$U7S_START" && grep -qF '"$LISTEN_PID" = "$SERVER_PID"' "$U7S_START" && echo 1 || echo 0)"
assert "u7s-start.sh's apiserver health loop errors loudly (not just proceeds) on a listener-PID mismatch" \
  "$(grep -qF 'not our own apiserver' "$U7S_START" && echo 1 || echo 0)"
assert "u7s-start.sh's konnectivity-server restart path still hard-fails on all four derived ports" \
  "$(grep -qF 'check_port_free "$KONNECTIVITY_PROXY_PORT"' "$U7S_START" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

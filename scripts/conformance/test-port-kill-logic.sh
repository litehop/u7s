#!/usr/bin/env bash
# Unit test for the "kill whatever's on this port" fallback in reset.sh
# (the apiserver fallback and the konnectivity-server port-kill loop share
# this exact same logic shape).
#
# 'lsof -ti tcp:$PORT' can return MULTIPLE newline-separated PIDs for one
# port (e.g. a listener plus an accepted connection still holding that same
# local port, or two independent orphans left over from prior crashed runs).
# The old code did:
#   API_PID=$(lsof -ti tcp:"$PORT" 2>/dev/null || true)
#   kill "$API_PID" 2>/dev/null || true
# With multiple PIDs, $API_PID is a single string containing embedded
# newlines, so 'kill "$API_PID"' passes ONE argument like "111\n222" instead
# of two separate PID arguments — kill silently fails to parse that as a PID
# and returns nonzero, which the trailing '|| true' swallows. The log line
# still claims a kill happened, but every PID after the first survives.
# Confirmed live during a conformance dispatch: orphan processes accumulated
# across --reset cycles despite reset.sh's log claiming a clean teardown
# each time.
#
# Exercises real spawned processes genuinely bound to one real TCP port (not
# just string/decision logic), because the bug is specifically about how
# many argv words 'kill' receives — a test that only inspects strings can't
# distinguish the buggy single-arg form from the fixed multi-arg form.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

PASS=0
FAIL=0
LEFTOVER_PIDS=()

cleanup() {
  local p
  for p in "${LEFTOVER_PIDS[@]:-}"; do
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
  done
}
trap cleanup EXIT

assert_dead() {
  local label="$1" pid="$2"
  if kill -0 "$pid" 2>/dev/null; then
    echo "FAIL: $label — PID $pid is still alive, expected dead"
    FAIL=$(( FAIL + 1 ))
  else
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# Fixed logic — mirrors reset.sh's port-kill body exactly.
# ---------------------------------------------------------------------------
kill_all_on_port() {
  local port="$1"
  # shellcheck disable=SC2207 # word-split intentionally: lsof -ti can return multiple PIDs, one per line.
  local pids=($(lsof -ti tcp:"$port" 2>/dev/null || true))
  if [ "${#pids[@]}" -gt 0 ]; then
    echo "  killing PID(s) on port $port: ${pids[*]}"
    kill "${pids[@]}" 2>/dev/null || true
  fi
}

# The pre-fix version — a single-arg kill against whatever lsof returned,
# newlines and all. Kept here ONLY so this test can demonstrate the bug: run
# with RUN_OLD_BUGGY_VERSION=1 to see it fail to kill everything but the
# first PID.
kill_all_on_port_old_buggy() {
  local port="$1"
  local pid
  pid=$(lsof -ti tcp:"$port" 2>/dev/null || true)
  if [ -n "$pid" ]; then
    echo "  killing PID on port $port: $pid"
    kill "$pid" 2>/dev/null || true
  fi
}

find_free_port() {
  local port
  for _ in $(seq 1 30); do
    port=$(( (RANDOM % 20000) + 20000 ))
    if ! lsof -ti tcp:"$port" >/dev/null 2>&1; then
      echo "$port"
      return 0
    fi
  done
  echo "ERROR: could not find a free port" >&2
  return 1
}

# ---------------------------------------------------------------------------
# Get lsof -ti tcp:$PORT to genuinely return 2 distinct real PIDs for ONE
# port: a listener and a client connected to it, both with stdin held open
# via process substitution (a plain nc otherwise sees stdin EOF immediately
# in this non-interactive context and exits before the test can observe it).
# ---------------------------------------------------------------------------
PORT="$(find_free_port)"
nc -l "$PORT" < <(sleep 300) &
LISTENER_PID=$!
LEFTOVER_PIDS+=("$LISTENER_PID")
sleep 0.5
nc 127.0.0.1 "$PORT" < <(sleep 300) &
CLIENT_PID=$!
LEFTOVER_PIDS+=("$CLIENT_PID")
sleep 0.5

# shellcheck disable=SC2207 # word-split intentionally: lsof -ti can return multiple PIDs, one per line.
FOUND_PIDS=($(lsof -ti tcp:"$PORT" 2>/dev/null || true))
if [ "${#FOUND_PIDS[@]}" -lt 2 ]; then
  echo "FAIL: setup — expected lsof -ti tcp:$PORT to list 2+ PIDs, got: ${FOUND_PIDS[*]:-<none>}"
  echo "  This test requires a real multi-PID port to be meaningful; environment may not support it."
  FAIL=$(( FAIL + 1 ))
else
  echo "PASS: setup — lsof -ti tcp:$PORT lists ${#FOUND_PIDS[@]} real PIDs (${FOUND_PIDS[*]})"
  PASS=$(( PASS + 1 ))
fi

# ---------------------------------------------------------------------------
# Demonstrate the bug: the old single-arg kill leaves at least one of the
# two real PIDs on this port alive, despite claiming success.
# ---------------------------------------------------------------------------
if [ "${RUN_OLD_BUGGY_VERSION:-0}" = "1" ]; then
  echo "--- OLD buggy kill_all_on_port_old_buggy() ---"
  kill_all_on_port_old_buggy "$PORT"
  sleep 0.3
  if kill -0 "$LISTENER_PID" 2>/dev/null || kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "CONFIRMED BUG: old single-arg kill left at least one PID alive on the port"
  else
    echo "old single-arg kill happened to kill both this run (order-dependent — lsof's PID order can vary)"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# The fix: kill_all_on_port() must kill BOTH real PIDs bound to the port,
# not just the first one lsof happens to list.
# ---------------------------------------------------------------------------
echo "--- NEW fixed kill_all_on_port() ---"
kill_all_on_port "$PORT"
sleep 0.5
assert_dead "listener PID killed by fixed multi-arg kill" "$LISTENER_PID"
assert_dead "client PID killed by fixed multi-arg kill (the one the old bug left running)" "$CLIENT_PID"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

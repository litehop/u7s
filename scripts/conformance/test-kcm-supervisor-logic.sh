#!/usr/bin/env bash
# Regression test for kcm-supervisor.sh (04-start-kcm.sh's crash supervisor).
#
# Before this supervisor existed, kube-controller-manager ran as a bare
# 'setsid $KCM_BINARY ... &' with no restart, no alerting, no supervisor at
# all. A single panic (e.g. the HPA nil-deref that killed a real 12h37m
# conformance run 14 minutes in) silently blacked out ServiceAccount
# provisioning, Deployment/ReplicaSet reconciliation, GC, etc. for the rest
# of the run — cluster health checks never noticed, so the outage was only
# discovered ~12 hours later via a wall of unrelated e2e failures.
#
# Exercises real spawned processes (the real 'sleep' binary standing in for
# kube-controller-manager via the same "$KCM_BINARY $args" contract
# kcm-supervisor.sh uses in production) and real elapsed wall-clock time,
# because the bug being guarded against is specifically about process-restart
# *timing* — a test that only inspects strings can't distinguish "restarts
# immediately" (a crash-loop that would burn CPU/API-server load) from
# "restarts after a bounded backoff" (the fix).
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUPERVISOR="$SCRIPT_DIR/kcm-supervisor.sh"
CRASH_LOG="/tmp/kcm-crashes.log"
CRASH_MARKER="/tmp/kcm-crashed.marker"

# Stand-in for the real kcm binary: a real, independently-schedulable process
# (not just a string) that stays up until the test kills it. Using the real
# 'sleep' binary directly (rather than a fake script with a #!/bin/bash
# shebang) avoids kernel shebang-interpreter indirection, where the process's
# actual argv[0] would become "bash <script-path>" instead of the script path
# itself — that indirection made an earlier version of this test unable to
# tell the exec'd child apart from the supervisor wrapper (whose own argv
# also contains the fake binary's path as an argument).
SLEEP_BIN="$(command -v sleep || true)"
if [ -z "$SLEEP_BIN" ]; then
  # Unlike an optional external tool (e.g. limactl, absent by default on CI
  # runners), 'sleep' is the load-bearing kcm stand-in this whole file's
  # PID-matching design depends on -- an empty SLEEP_BIN would make
  # FAKE_PATTERN=" 300" accidentally match the supervisor wrapper's own
  # command line (its trailing "300" arg is always space-adjacent), turning
  # every assertion below into a false PASS instead of a clear failure. Fail
  # loud here instead of letting that vacuous-pass hazard through.
  echo "FAIL: 'sleep' binary not found on PATH -- required as this test's kube-controller-manager stand-in" >&2
  exit 1
fi
FAKE_PATTERN="${SLEEP_BIN} 300"

PASS=0
FAIL=0
LEFTOVER_PIDS=()

cleanup() {
  local p
  for p in "${LEFTOVER_PIDS[@]:-}"; do
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
  done
  pkill -9 -f "$FAKE_PATTERN" 2>/dev/null || true
}
trap cleanup EXIT

assert_alive() {
  local label="$1" pid="$2"
  if kill -0 "$pid" 2>/dev/null; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — PID $pid is not running"
    FAIL=$(( FAIL + 1 ))
  fi
}

assert_not_alive() {
  local label="$1" pid="$2"
  if kill -0 "$pid" 2>/dev/null; then
    echo "FAIL: $label — PID $pid is still running, expected it to have exited"
    FAIL=$(( FAIL + 1 ))
  else
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  fi
}

assert_file_exists() {
  local label="$1" file="$2"
  if [ -f "$file" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — $file does not exist"
    FAIL=$(( FAIL + 1 ))
  fi
}

assert_contains() {
  local label="$1" file="$2" needle="$3"
  if grep -q -- "$needle" "$file" 2>/dev/null; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — '$needle' not found in $file"
    echo "  --- $file ---"
    cat "$file" 2>/dev/null
    FAIL=$(( FAIL + 1 ))
  fi
}

assert_in_range() {
  local label="$1" value="$2" min="$3" max="$4"
  if [ "$value" -ge "$min" ] && [ "$value" -le "$max" ]; then
    echo "PASS: $label (measured ${value}s, expected [${min},${max}]s)"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label (measured ${value}s, expected [${min},${max}]s)"
    FAIL=$(( FAIL + 1 ))
  fi
}

# Starts the supervisor against the fake 'sleep 300' kcm stand-in and echoes
# the supervisor's own PID. Extra args are appended to the supervisor's own
# stdout/stderr redirect target.
start_supervisor() {
  local kcmlog="$1" redirect_to="$2"
  shift 2
  env "$@" bash "$SUPERVISOR" "$SLEEP_BIN" "$kcmlog" 300 > "$redirect_to" 2>&1 &
  echo $!
}

# Polls for a process matching 'pattern' whose PID is not 'exclude_pid', up
# to 'timeout' seconds. Echoes the first matching PID found, or nothing.
wait_for_new_pid() {
  local pattern="$1" exclude_pid="$2" timeout="$3"
  local deadline=$(( $(date +%s) + timeout ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    local found
    found="$(pgrep -f "$pattern" 2>/dev/null | grep -vx "$exclude_pid" || true)"
    if [ -n "$found" ]; then
      printf '%s\n' "$found" | head -1
      return 0
    fi
    sleep 0.3
  done
  return 0
}

# ---------------------------------------------------------------------------
# Test: supervisor_starts_kcm_and_returns_supervisor_pid
#
# Happy path. Matters because the outer 04-start-kcm.sh script relies on
# getting a live PID back immediately (it must "return after kcm is ready")
# — if wrapping kcm in a supervisor broke the basic launch, every conformance
# run would fail at step 04 instead of gaining crash protection.
# ---------------------------------------------------------------------------
test1_starts_and_returns_pid() {
  echo "--- supervisor_starts_kcm_and_returns_supervisor_pid ---"
  local kcmlog sup_pid kcm_pid
  kcmlog="$(mktemp)"

  sup_pid="$(start_supervisor "$kcmlog" /dev/null)"
  LEFTOVER_PIDS+=("$sup_pid")

  kcm_pid="$(wait_for_new_pid "$FAKE_PATTERN" "" 5)"

  assert_alive "supervisor process stays running so an operator can tell kcm is under supervision" "$sup_pid"
  if [ -n "$kcm_pid" ]; then
    echo "PASS: supervisor launches a real kcm process reachable via ps (PID $kcm_pid)"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: supervisor launches a real kcm process reachable via ps — none found"
    FAIL=$(( FAIL + 1 ))
  fi

  kill -9 "$sup_pid" 2>/dev/null || true
  pkill -9 -f "$FAKE_PATTERN" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Test: supervisor_restarts_kcm_on_exit_1_with_backoff
# Test: supervisor_writes_crash_event_on_restart
#
# These share one induced crash: the first verifies the restart itself is
# delayed (an immediate restart-loop would hammer a still-broken kcm and the
# API server it's watching), the second verifies the crash is durably
# recorded (an operator who missed the live stderr banner still needs to see
# it happened).
# ---------------------------------------------------------------------------
test2_and_3_restart_and_log() {
  echo "--- supervisor_restarts_kcm_on_exit_1_with_backoff ---"
  local kcmlog sup_pid pid1 pid2 t0 t1 elapsed lines
  kcmlog="$(mktemp)"

  sup_pid="$(start_supervisor "$kcmlog" /dev/null)"
  LEFTOVER_PIDS+=("$sup_pid")

  pid1="$(wait_for_new_pid "$FAKE_PATTERN" "" 5)"
  if [ -z "$pid1" ]; then
    echo "FAIL: supervisor_restarts_kcm_on_exit_1_with_backoff — kcm never started"
    FAIL=$(( FAIL + 1 ))
    kill -9 "$sup_pid" 2>/dev/null || true
    return
  fi

  t0="$(date +%s)"
  kill -9 "$pid1" 2>/dev/null || true

  pid2="$(wait_for_new_pid "$FAKE_PATTERN" "$pid1" 20)"
  t1="$(date +%s)"

  if [ -z "$pid2" ]; then
    echo "FAIL: supervisor_restarts_kcm_on_exit_1_with_backoff — kcm was never restarted after crashing"
    FAIL=$(( FAIL + 1 ))
  else
    elapsed=$(( t1 - t0 ))
    assert_in_range \
      "restart is delayed ~10s (bounded backoff), not an immediate crash-loop that would hammer a still-broken kcm" \
      "$elapsed" 6 16
  fi

  echo "--- supervisor_writes_crash_event_on_restart ---"
  lines="$(wc -l < "$CRASH_LOG" | tr -d ' ')"
  if [ "$lines" = "1" ]; then
    echo "PASS: exactly one crash event recorded for the one induced crash — a returning operator counting crashes needs one line per crash, not zero or duplicates"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: expected exactly 1 line in $CRASH_LOG after one crash, got $lines"
    cat "$CRASH_LOG" 2>/dev/null
    FAIL=$(( FAIL + 1 ))
  fi
  assert_contains "crash event records the real exit code (137 = SIGKILL) so an operator can tell a panic from a clean shutdown" "$CRASH_LOG" "exit_code=137"
  assert_contains "crash event is numbered as the 1st crash of this streak" "$CRASH_LOG" "crash_count=1"

  kill -9 "$sup_pid" 2>/dev/null || true
  [ -n "$pid2" ] && kill -9 "$pid2" 2>/dev/null || true
  pkill -9 -f "$FAKE_PATTERN" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Test: supervisor_gives_up_after_5_crashes_in_60s
#
# The poison-pill circuit breaker. Without it, a genuinely broken kcm build
# (bad flags, a cert mismatch, an immediate panic on every launch) would
# restart-loop forever, burning CPU/log space for the rest of an unattended
# run instead of surfacing a clear "give up and page someone" signal.
#
# Backoff base is overridden to 1s here purely for test speed: the production
# default (base 10s) reaches the 5th crash after ~150s of real backoff, which
# is the same code path just slower — the doubling/burst-limit logic under
# test is identical either way. The other tests exercise the real 10s
# default.
# ---------------------------------------------------------------------------
test4_circuit_breaker() {
  echo "--- supervisor_gives_up_after_5_crashes_in_60s ---"
  local kcmlog suplog sup_pid prev_pid pid i deadline
  kcmlog="$(mktemp)"
  suplog="$(mktemp)"

  sup_pid="$(start_supervisor "$kcmlog" "$suplog" KCM_BACKOFF_BASE_SECS=1)"
  LEFTOVER_PIDS+=("$sup_pid")

  prev_pid=""
  for i in 1 2 3 4 5; do
    pid="$(wait_for_new_pid "$FAKE_PATTERN" "$prev_pid" 15)"
    if [ -z "$pid" ]; then
      echo "FAIL: supervisor_gives_up_after_5_crashes_in_60s — kcm attempt #$i never started"
      FAIL=$(( FAIL + 1 ))
      kill -9 "$sup_pid" 2>/dev/null || true
      pkill -9 -f "$FAKE_PATTERN" 2>/dev/null || true
      return
    fi
    kill -9 "$pid" 2>/dev/null || true
    prev_pid="$pid"
  done

  deadline=$(( $(date +%s) + 10 ))
  while kill -0 "$sup_pid" 2>/dev/null && [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 0.3
  done

  assert_not_alive "supervisor process exits once the circuit breaker trips, instead of crash-looping forever against a poison pill" "$sup_pid"
  assert_contains "circuit-breaker banner is printed so an operator tailing the supervisor log sees WHY kcm stopped restarting" "$suplog" "CIRCUIT BREAKER TRIPPED"
  assert_file_exists "crash marker file exists for a returning operator/dashboard-poller to grep, since a live stderr banner is gone once the terminal session ends" "$CRASH_MARKER"

  pkill -9 -f "$FAKE_PATTERN" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Test: supervisor_backoff_doubles
#
# A flat retry interval would hammer a still-crashing kcm (and the API
# server it watches) at a constant rate forever; doubling backoff gives a
# still-broken process progressively more room before the next attempt.
# ---------------------------------------------------------------------------
test5_backoff_doubles() {
  echo "--- supervisor_backoff_doubles ---"
  local kcmlog sup_pid pid1 pid2 pid3 t0 t1 t2 t3 backoff1 backoff2
  kcmlog="$(mktemp)"

  sup_pid="$(start_supervisor "$kcmlog" /dev/null)"
  LEFTOVER_PIDS+=("$sup_pid")

  pid1="$(wait_for_new_pid "$FAKE_PATTERN" "" 5)"
  if [ -z "$pid1" ]; then
    echo "FAIL: supervisor_backoff_doubles — kcm never started"
    FAIL=$(( FAIL + 1 ))
    kill -9 "$sup_pid" 2>/dev/null || true
    return
  fi

  t0="$(date +%s)"
  kill -9 "$pid1" 2>/dev/null || true
  pid2="$(wait_for_new_pid "$FAKE_PATTERN" "$pid1" 20)"
  t1="$(date +%s)"
  backoff1=$(( t1 - t0 ))

  if [ -z "$pid2" ]; then
    echo "FAIL: supervisor_backoff_doubles — kcm was never restarted after the 1st crash"
    FAIL=$(( FAIL + 1 ))
    kill -9 "$sup_pid" 2>/dev/null || true
    pkill -9 -f "$FAKE_PATTERN" 2>/dev/null || true
    return
  fi

  t2="$(date +%s)"
  kill -9 "$pid2" 2>/dev/null || true
  pid3="$(wait_for_new_pid "$FAKE_PATTERN" "$pid2" 30)"
  t3="$(date +%s)"
  backoff2=$(( t3 - t2 ))

  if [ -z "$pid3" ]; then
    echo "FAIL: supervisor_backoff_doubles — kcm was never restarted after the 2nd crash"
    FAIL=$(( FAIL + 1 ))
  else
    assert_in_range \
      "2nd restart delay is ~20s, double the 1st (~${backoff1}s) — proves growth, not a fixed retry interval" \
      "$backoff2" 15 26
  fi

  kill -9 "$sup_pid" 2>/dev/null || true
  pkill -9 -f "$FAKE_PATTERN" 2>/dev/null || true
}

test1_starts_and_returns_pid
test2_and_3_restart_and_log
test4_circuit_breaker
test5_backoff_doubles

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

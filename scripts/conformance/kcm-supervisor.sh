#!/usr/bin/env bash
# Crash supervisor for kube-controller-manager: restart-on-exit with bounded
# exponential backoff, plus a circuit breaker that gives up (instead of
# looping forever) after repeated crashes with no stable run in between.
#
# Usage: kcm-supervisor.sh <binary> <log-file> [binary-args...]
#
# <binary> is a required argument rather than a hard-coded path so tests can
# substitute a fake process standing in for kube-controller-manager.
#
# Part of the scripts/conformance/ orchestration sequence — invoked by
# 04-start-kcm.sh, which backgrounds this whole script under setsid.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <binary> <log-file> [args...]" >&2
  exit 1
fi

KCM_BINARY="$1"
KCM_LOG="$2"
shift 2

CRASH_LOG="/tmp/kcm-crashes.log"
CRASH_MARKER="/tmp/kcm-crashed.marker"
BACKOFF_BASE="${KCM_BACKOFF_BASE_SECS:-10}"
BACKOFF_MAX="${KCM_BACKOFF_MAX_SECS:-160}"
STABLE_UPTIME="${KCM_STABLE_UPTIME_SECS:-60}"
BURST_LIMIT="${KCM_CRASH_BURST_LIMIT:-5}"

# Reset marker state on every supervisor start — a marker left over from a
# previous crash-looping run must not make a brand-new, healthy run look
# like it's still failing.
: > "$CRASH_LOG"
rm -f "$CRASH_MARKER"

crash_count=0

while true; do
  start_ts=$(date +%s)
  "$KCM_BINARY" "$@" > "$KCM_LOG" 2>&1 &
  kcm_pid=$!
  exit_code=0
  wait "$kcm_pid" || exit_code=$?
  end_ts=$(date +%s)
  uptime=$(( end_ts - start_ts ))

  # Reset the streak on sustained uptime rather than checking a sliding
  # window over crash timestamps: with backoff capped at 160s, cumulative
  # time to even the 4th crash (10+20+40=70s) already exceeds a 60s window,
  # so a literal "N crashes within the last 60 wall-clock seconds" check
  # could never trip once backoff takes over. Resetting only after kcm ran
  # healthily for STABLE_UPTIME seconds keeps "give up on a poison pill"
  # meaningful no matter how the backoff schedule compares to that window.
  if [ "$uptime" -ge "$STABLE_UPTIME" ]; then
    crash_count=0
  fi
  crash_count=$(( crash_count + 1 ))

  printf 'timestamp=%s exit_code=%s uptime_s=%s crash_count=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$exit_code" "$uptime" "$crash_count" >> "$CRASH_LOG"

  {
    echo ""
    echo "================================================================"
    echo "kube-controller-manager CRASHED (exit ${exit_code}, uptime ${uptime}s,"
    echo "crash ${crash_count}/${BURST_LIMIT} in current streak) — log: ${KCM_LOG}"
    echo "================================================================"
  } >&2

  if [ "$crash_count" -ge "$BURST_LIMIT" ]; then
    {
      echo ""
      echo "################################################################"
      echo "# CIRCUIT BREAKER TRIPPED"
      echo "# kube-controller-manager crashed ${crash_count} times without a"
      echo "# stable (>= ${STABLE_UPTIME}s) run in between. Giving up."
      echo "# See ${CRASH_MARKER} and ${CRASH_LOG}."
      echo "################################################################"
    } >&2
    {
      echo "crash_count=${crash_count}"
      echo "last_exit_code=${exit_code}"
      echo "tripped_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "--- last 100 lines of ${KCM_LOG} ---"
      tail -n 100 "$KCM_LOG" 2>/dev/null || true
    } > "$CRASH_MARKER"
    exit 1
  fi

  backoff=$(( BACKOFF_BASE * (1 << (crash_count - 1)) ))
  if [ "$backoff" -gt "$BACKOFF_MAX" ]; then
    backoff="$BACKOFF_MAX"
  fi
  echo "restarting kube-controller-manager in ${backoff}s (crash ${crash_count}/${BURST_LIMIT})" >&2
  sleep "$backoff"
done

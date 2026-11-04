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
# The supervisor's sleep and clock are replaced via KCM_SUPERVISOR_SLEEP /
# KCM_SUPERVISOR_NOW with a fake clock, and the kcm stand-in "runs" for a
# scripted number of fake seconds then crashes. The exact backoff schedule and
# circuit-breaker threshold are asserted with no wall-clock waits, so the
# result cannot depend on host load. Each case uses its own mktemp -d (crash
# log and marker included), so the file is safe to run in parallel.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUPERVISOR="$SCRIPT_DIR/kcm-supervisor.sh"

PASS=0
FAIL=0
TMPDIRS=()

cleanup() {
  local d
  for d in "${TMPDIRS[@]:-}"; do
    if [ -n "$d" ]; then rm -rf "$d"; fi
  done
}
trap cleanup EXIT

assert_eq() {
  local label="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — got '$got', want '$want'"
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

# Creates a case directory W with the fake clock, fake sleep and a fake kcm.
#   W/clock    current fake epoch seconds
#   W/sleeps   one line per supervisor sleep, in order (the backoff schedule)
#   W/uptimes  line N = fake seconds the Nth kcm launch runs before crashing
#              (missing lines = 0)
#   W/launches one line per kcm launch, recording its argv
# Sets W.
new_case() {
  local w
  w="$(mktemp -d)"
  TMPDIRS+=("$w")
  echo 1000 > "$w/clock"
  : > "$w/sleeps"
  : > "$w/launches"
  : > "$w/uptimes"
  cat > "$w/now" <<EOF
#!/usr/bin/env bash
read -r c < "$w/clock"; echo "\$c"
EOF
  cat > "$w/sleep" <<EOF
#!/usr/bin/env bash
echo "\$1" >> "$w/sleeps"
read -r c < "$w/clock"
echo \$(( c + \$1 )) > "$w/clock"
EOF
  cat > "$w/kcm" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "$w/launches"
n=0
while read -r _; do n=\$(( n + 1 )); done < "$w/launches"
up=0
i=0
while read -r line; do i=\$(( i + 1 )); [ "\$i" = "\$n" ] && up=\$line; done < "$w/uptimes"
read -r c < "$w/clock"
echo \$(( c + up )) > "$w/clock"
exit 137
EOF
  chmod +x "$w/now" "$w/sleep" "$w/kcm"
  W="$w"
}

# run_supervisor <case-dir> [ENV=VAL...] — runs the supervisor to completion
# (it must exit by itself via the circuit breaker) and echoes its exit status.
run_supervisor() {
  local w="$1" rc=0
  shift
  env KCM_SUPERVISOR_NOW="$w/now" KCM_SUPERVISOR_SLEEP="$w/sleep" \
    KCM_CRASH_LOG="$w/crashes.log" KCM_CRASH_MARKER="$w/crashed.marker" \
    "$@" bash "$SUPERVISOR" "$w/kcm" "$w/kcm.log" --flag one > /dev/null 2> "$w/stderr" || rc=$?
  echo "$rc"
}

schedule() { paste -sd' ' "$1/sleeps"; }
launches() { wc -l < "$1/launches" | tr -d ' '; }

# ---------------------------------------------------------------------------
# Default config, kcm crashing instantly every time.
#
# Doubling backoff gives a still-broken kcm progressively more room; a flat or
# immediate retry would hammer it and the API server it watches. The breaker
# must trip on the 5th crash so a poison-pill build stops crash-looping
# instead of burning CPU/log space for the rest of an unattended run.
# ---------------------------------------------------------------------------
test_default_schedule_and_breaker() {
  echo "--- default backoff schedule and circuit breaker ---"
  local w rc
  new_case; w="$W"
  rc="$(run_supervisor "$w")"

  assert_eq "backoff doubles from 10s and never sleeps after the tripping crash" "$(schedule "$w")" "10 20 40 80"
  assert_eq "kcm is launched exactly 5 times: 4 restarts then give up" "$(launches "$w")" "5"
  assert_eq "supervisor exits 1 once the breaker trips so 04-start-kcm.sh / pollers see failure" "$rc" "1"
  assert_eq "kcm receives the caller's arguments unchanged" "$(head -1 "$w/launches")" "--flag one"
  assert_contains "circuit-breaker banner tells an operator tailing the log WHY restarts stopped" "$w/stderr" "CIRCUIT BREAKER TRIPPED"
  assert_file_exists "crash marker exists for a returning operator/poller once the live banner is gone" "$w/crashed.marker"
  assert_contains "marker records the crash count" "$w/crashed.marker" "crash_count=5"
  assert_contains "marker records the real exit code (137 = SIGKILL)" "$w/crashed.marker" "last_exit_code=137"
  assert_eq "one crash-log line per crash" "$(wc -l < "$w/crashes.log" | tr -d ' ')" "5"
  assert_eq "crash-log counts run 1..5 so the streak is reconstructable" \
    "$(sed -E 's/.*crash_count=//' "$w/crashes.log" | paste -sd' ' -)" "1 2 3 4 5"
  assert_contains "crash log records exit code and zero uptime" "$w/crashes.log" "exit_code=137 uptime_s=0"
}

# ---------------------------------------------------------------------------
# Backoff is capped. Uncapped doubling would eventually park a recovering kcm
# for hours; the cap bounds worst-case recovery delay.
# ---------------------------------------------------------------------------
test_backoff_cap() {
  echo "--- backoff cap ---"
  local w
  new_case; w="$W"
  run_supervisor "$w" KCM_CRASH_BURST_LIMIT=8 > /dev/null
  assert_eq "default cap holds at 160s" "$(schedule "$w")" "10 20 40 80 160 160 160"

  new_case; w="$W"
  run_supervisor "$w" KCM_BACKOFF_MAX_SECS=30 > /dev/null
  assert_eq "KCM_BACKOFF_MAX_SECS clamps the doubling" "$(schedule "$w")" "10 20 30 30"
}

# ---------------------------------------------------------------------------
# Streak reset on stable uptime. A kcm that ran healthily for >= 60s before
# crashing is a fresh incident, not the continuation of a poison pill; without
# the reset a kcm that crashes once a day would eventually be abandoned.
# ---------------------------------------------------------------------------
test_stable_uptime_resets_streak() {
  echo "--- stable uptime resets the crash streak ---"
  local w
  new_case; w="$W"
  printf '0\n0\n60\n' > "$w/uptimes"
  run_supervisor "$w" > /dev/null
  assert_eq "a 60s run restarts the streak at 1: backoff drops back to 10s and breaker needs 5 more crashes" \
    "$(schedule "$w")" "10 20 10 20 40 80"
  assert_eq "kcm launched 7 times (2 crashes + stable crash + 4 more)" "$(launches "$w")" "7"

  new_case; w="$W"
  printf '0\n0\n59\n' > "$w/uptimes"
  run_supervisor "$w" > /dev/null
  assert_eq "a 59s run is below the stable threshold: no reset, breaker trips on crash 5" \
    "$(schedule "$w")" "10 20 40 80"
  assert_contains "crash log records the measured uptime" "$w/crashes.log" "uptime_s=59 crash_count=3"
}

# ---------------------------------------------------------------------------
# Env overrides of the breaker threshold and backoff base.
# ---------------------------------------------------------------------------
test_overrides() {
  echo "--- env overrides ---"
  local w
  new_case; w="$W"
  run_supervisor "$w" KCM_CRASH_BURST_LIMIT=2 KCM_BACKOFF_BASE_SECS=3 > /dev/null
  assert_eq "burst limit 2 gives one restart, at the overridden base" "$(schedule "$w")" "3"
}

test_default_schedule_and_breaker
test_backoff_cap
test_stable_uptime_resets_streak
test_overrides

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

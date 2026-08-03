#!/usr/bin/env bash
# Unit test for the post-delete hostagent reap logic in teardown_vm() (reset.sh).
#
# 'limactl delete --force' returning exit 0 does NOT guarantee the underlying
# 'limactl hostagent' OS process actually died — confirmed live: it can survive,
# get reparented to launchd, and keep squatting on the VM's forwarded kubelet
# port for hours across later --reset cycles, silently serving a stale,
# now-CA-mismatched cert to every exec/log/attach call while everything else
# (a fresh VM+cert from the next run's own provisioning) looks completely
# clean. reap_hostagent() below mirrors reset.sh's post-delete verification +
# backstop kill verbatim — keep them in sync if reset.sh's algorithm changes.
#
# Exercises real spawned processes (not just string/decision logic) because
# the bug is a process-lifecycle bug: a test that only asserts on strings
# cannot prove a process actually died.
#
#   - A PID captured before delete that is still alive afterward must be
#     SIGKILLed and confirmed dead (the core bug: trusting delete's exit code).
#   - A PID that already exited cleanly must be left alone with no error (the
#     normal, successful-delete case — must not be treated as a failure).
#   - A stray hostagent process with no captured PID at all (the exact race
#     from the bead: a LATER hostagent overwrites ha.pid before we read it,
#     so the pidfile-based path finds nothing) must still be found and killed
#     via the socket-path backstop.
#   - The backstop must match on the FULL socket path, not a bare VM-name
#     substring — "utest-vm" is a substring of "utest-vm-2", so a naive
#     name-only match would kill a sibling VM's hostagent too.
#
# All spawned test processes use a mktemp'd fake socket path unique to this
# run, so the backstop's pgrep can never match a real lima instance's actual
# hostagent running elsewhere on the same host.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

PASS=0
FAIL=0
LEFTOVER_PIDS=()
TMPDIR_TEST="$(mktemp -d)"

cleanup() {
  local p
  for p in "${LEFTOVER_PIDS[@]:-}"; do
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
  done
  rm -rf "$TMPDIR_TEST"
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

assert_alive() {
  local label="$1" pid="$2"
  if kill -0 "$pid" 2>/dev/null; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — PID $pid is dead, expected still alive"
    FAIL=$(( FAIL + 1 ))
  fi
}

# SIGKILL is not synchronous: 'kill -0 $pid' checked immediately after
# 'kill -9 $pid' can still report the PID alive for a brief moment before the
# kernel finishes tearing the process down (confirmed live — reproduced this
# exact race against a real spawned process while developing this test).
# Mirrors reset.sh's pid_still_alive_after_kill() verbatim.
pid_still_alive_after_kill() {
  local pid="$1"
  for _ in 1 2 3 4 5; do
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.2
  done
  kill -0 "$pid" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Isolated logic — mirrors teardown_vm()'s post-'limactl delete' body in
# reset.sh exactly, without any limactl/VM I/O.
# Arguments: vm  captured_ha_pid (may be empty)  ha_sock_path
# ---------------------------------------------------------------------------
reap_hostagent() {
  local vm="$1" ha_pid="$2" ha_sock="$3"

  if [ -n "$ha_pid" ] && kill -0 "$ha_pid" 2>/dev/null; then
    echo "  hostagent PID $ha_pid for $vm survived 'limactl delete' — killing it"
    kill -9 "$ha_pid" 2>/dev/null || true
    if pid_still_alive_after_kill "$ha_pid"; then
      echo "  ERROR: hostagent PID $ha_pid for $vm still alive after SIGKILL" >&2
      return 1
    fi
  fi

  local stray_pids
  stray_pids="$(pgrep -f "limactl hostagent.*${ha_sock}" 2>/dev/null || true)"
  if [ -n "$stray_pids" ]; then
    echo "  found stray hostagent process(es) for $vm bound to $ha_sock — killing: $stray_pids"
    # shellcheck disable=SC2086
    kill -9 $stray_pids
    for p in $stray_pids; do
      if pid_still_alive_after_kill "$p"; then
        echo "  ERROR: stray hostagent PID $p for $vm still alive after SIGKILL" >&2
        return 1
      fi
    done
  fi
}

# Spawns a background process whose full command line (as pgrep -f/ps sees it)
# looks like 'limactl hostagent ... --socket <sock> <name>', standing in for a
# real hostagent, without needing an actual limactl/VM. Echoes the spawned PID.
# NOTE: called via "$(...)" command substitution, which forks a subshell — do
# not rely on this function mutating the caller's LEFTOVER_PIDS array; callers
# must append the echoed PID themselves. Stdout/stderr are redirected away
# from that same command-substitution pipe for the reason noted above the
# SURVIVOR_PID assignment.
spawn_fake_hostagent() {
  local sock="$1" name="$2"
  bash -c "exec -a 'limactl hostagent --socket ${sock} ${name}' sleep 60" >/dev/null 2>&1 &
  echo $!
}

# ---------------------------------------------------------------------------
# 1. Captured PID still alive after delete → must be killed (the core bug:
#    'limactl delete --force' exiting 0 does not mean the hostagent died).
# ---------------------------------------------------------------------------
# Orphan via a subshell that exits immediately after backgrounding, so the
# spawned process reparents to launchd exactly like a real orphaned hostagent
# (and gets reaped by launchd on death) instead of staying a zombie under this
# script's own job control until an explicit 'wait' — which 'limactl delete'
# never does for a genuinely orphaned hostagent either. Stdout/stderr are
# redirected away from the command-substitution pipe below; left inherited,
# the backgrounded process keeps that pipe's write end open for its whole
# lifetime, and "$(...)" would block on it for the full sleep duration.
SURVIVOR_PID="$(sleep 60 >/dev/null 2>&1 & echo $!)"
LEFTOVER_PIDS+=("$SURVIVOR_PID")
reap_hostagent "utest-vm" "$SURVIVOR_PID" "${TMPDIR_TEST}/no-such-vm/ha.sock"
assert_dead "hostagent PID that survived delete is force-killed" "$SURVIVOR_PID"

# ---------------------------------------------------------------------------
# 2. Captured PID already gone (the normal, successful-delete case) → no-op,
#    must not error out just because there was nothing left to kill.
# ---------------------------------------------------------------------------
sleep 0.1 &
CLEAN_PID=$!
wait "$CLEAN_PID" 2>/dev/null || true
REAP_OUT="${TMPDIR_TEST}/reap-out"
if reap_hostagent "utest-vm" "$CLEAN_PID" "${TMPDIR_TEST}/no-such-vm/ha.sock" >"$REAP_OUT" 2>&1; then
  echo "PASS: already-dead PID is left alone with no error"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: already-dead PID caused reap_hostagent to fail — normal delete treated as an error"
  cat "$REAP_OUT"
  FAIL=$(( FAIL + 1 ))
fi

# ---------------------------------------------------------------------------
# 3. The actual race from the bead: a LATER hostagent overwrote ha.pid before
#    we could read the zombie's real PID, so the pidfile-based path has
#    nothing (ha_pid=""). The socket-path backstop must still find and kill
#    the zombie by its command line.
# ---------------------------------------------------------------------------
ZOMBIE_SOCK="${TMPDIR_TEST}/utest-vm/ha.sock"
ZOMBIE_PID="$(spawn_fake_hostagent "$ZOMBIE_SOCK" "utest-vm")"
LEFTOVER_PIDS+=("$ZOMBIE_PID")
sleep 0.2 # let the backgrounded exec -a actually take effect before pgrep -f
reap_hostagent "utest-vm" "" "$ZOMBIE_SOCK"
assert_dead "backstop kills a stray hostagent the pidfile never recorded" "$ZOMBIE_PID"

# ---------------------------------------------------------------------------
# 4. Substring-collision safety: "utest-vm" is a substring of "utest-vm-2".
#    Tearing down "utest-vm" must NOT also kill "utest-vm-2"'s hostagent.
# ---------------------------------------------------------------------------
SIBLING_SOCK="${TMPDIR_TEST}/utest-vm-2/ha.sock"
SIBLING_PID="$(spawn_fake_hostagent "$SIBLING_SOCK" "utest-vm-2")"
LEFTOVER_PIDS+=("$SIBLING_PID")
TARGET_SOCK="${TMPDIR_TEST}/utest-vm/ha.sock"
TARGET_PID="$(spawn_fake_hostagent "$TARGET_SOCK" "utest-vm")"
LEFTOVER_PIDS+=("$TARGET_PID")
sleep 0.2
reap_hostagent "utest-vm" "" "$TARGET_SOCK"
assert_dead "backstop kills the exact target VM's stray hostagent" "$TARGET_PID"
assert_alive "backstop leaves a substring-colliding sibling VM's hostagent untouched" "$SIBLING_PID"
kill -9 "$SIBLING_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

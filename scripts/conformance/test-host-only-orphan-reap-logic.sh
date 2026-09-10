#!/usr/bin/env bash
# Regression test for reset.sh's --host-only orphan reaping and
# verify-then-report exit status.
#
# Bug: an apiserver-less scheduler+konnectivity-server orphan pair whose pid
# files are stale/absent relies entirely on reset.sh's cmdline-pattern
# fallback (host_kill_pattern_for + pkill -f) to be reaped. That fallback
# fires unconditionally today, but reset.sh never re-checked whether the kill
# actually worked -- it printed "Done (host-only)." and exited 0 regardless,
# so a process immune to SIGTERM (or any other reason a targeted process
# survives) went undetected. This test runs the REAL script end-to-end (not
# a reimplementation) and proves all three halves of the fix:
#   1. An apiserver-less orphan pair with NO pid files is actually reaped by
#      --host-only, and the script reports success (exit 0).
#   2. A process that survives the kill attempt (SIGTERM-ignoring) makes the
#      script exit NONZERO and name the survivor -- it must never claim
#      "Done" while a targeted process is still alive.
#   3. That same verify-then-report gate must NOT fire on the full (non
#      --host-only) reset path -- a survivor there must not abort the reset,
#      since run-all.sh's --reset flow (and its "the VM is deleted"
#      postcondition) never passed --host-only and relies on this path
#      continuing to wipe $WORKDIR and tear down the VM regardless.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO/scripts/conformance/reset.sh"

PASS=0
FAIL=0
LEFTOVER_PIDS=()

cleanup() {
  local p
  for p in "${LEFTOVER_PIDS[@]:-}"; do
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
  done
  rm -rf "${TMPROOT:-}"
}
trap cleanup EXIT

assert_exit_code() {
  local label="$1" actual="$2" expected="$3"
  if [ "$actual" -eq "$expected" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — exit code $actual, expected $expected"
    FAIL=$(( FAIL + 1 ))
  fi
}

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

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — output did not contain '$needle'"
    FAIL=$(( FAIL + 1 ))
  fi
}

# Spawns a background process whose full command line (as pgrep -f/ps sees
# it) is exactly $1, standing in for a real u7s component without needing to
# build/run either. Echoes the spawned PID.
spawn_fake_process() {
  local cmdline="$1"
  bash -c "exec -a '${cmdline}' sleep 60" >/dev/null 2>&1 &
  echo $!
}

# Same, but ignores SIGTERM: standing in for a process reset.sh's pkill -f
# (SIGTERM) genuinely cannot reap, so the verify-then-report path has
# something real to catch. SIG_IGN dispositions (unlike caught handlers)
# survive exec, so the ignore set up before 'exec -a' carries into the
# process pgrep/pkill will actually see.
spawn_sigterm_immune_process() {
  local cmdline="$1"
  bash -c "trap '' TERM; exec -a '${cmdline}' sleep 60" >/dev/null 2>&1 &
  echo $!
}

# Stubs `limactl` on PATH so the full (non --host-only) reset path below can
# reach and complete teardown_vm() without a real Lima install -- this test
# suite (script-tests CI job) runs on ubuntu-latest with no limactl on PATH.
# `list` reports no VMs (so teardown_vm takes its "VM does not exist" branch)
# and every subcommand exits 0, matching a real already-absent VM.
setup_limactl_stub() {
  local bindir="$1"
  mkdir -p "$bindir"
  cat > "$bindir/limactl" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
  chmod +x "$bindir/limactl"
}

TMPROOT="$(mktemp -d)"

# ---------------------------------------------------------------------------
# 1. Apiserver-less orphan pair, NO pid files: --host-only must reap both via
#    the cmdline fallback alone and report success. Reverting the fix would
#    not regress THIS half (the fallback already existed) -- it exists to
#    pin down that reaping-without-pidfiles keeps working alongside the new
#    verify step, so a future change to either can't silently break it.
# ---------------------------------------------------------------------------
WORKDIR1="$TMPROOT/reapable/temp/u7s"
mkdir -p "$WORKDIR1"

SCHED_PID="$(spawn_fake_process "u7s-scheduler --db ${WORKDIR1}/sched.db --kubeconfig ${WORKDIR1}/kubeconfig-scheduler --other ${WORKDIR1}/kubeconfig")"
LEFTOVER_PIDS+=("$SCHED_PID")
KONN_PID="$(spawn_fake_process "proxy-server-darwin-arm64 --cluster-cert=${WORKDIR1}/konnectivity-server.crt --cluster-key=${WORKDIR1}/konnectivity-server.key")"
LEFTOVER_PIDS+=("$KONN_PID")
sleep 0.2 # let the backgrounded exec -a actually take effect

set +e
OUT1="$(bash "$SCRIPT" --host-only --workdir "$WORKDIR1" 2>&1)"
EXIT1=$?
set -e

assert_exit_code "reapable orphan pair: --host-only exits 0 when both dummies are actually reaped" "$EXIT1" 0
assert_dead "orphan scheduler (no pid file) is reaped by the cmdline fallback" "$SCHED_PID"
assert_dead "orphan konnectivity-server (no pid file) is reaped by the cmdline fallback" "$KONN_PID"

# ---------------------------------------------------------------------------
# 2. A SIGTERM-immune process matching the scheduler pattern: pkill -f cannot
#    actually kill it, so reset.sh must detect the survivor and exit nonzero
#    instead of printing "Done (host-only)." — reverting verify-then-report
#    (dropping the post-kill re-check) makes this assertion fail because the
#    old code exits 0 unconditionally after firing the kill commands.
# ---------------------------------------------------------------------------
WORKDIR2="$TMPROOT/unreapable/temp/u7s"
mkdir -p "$WORKDIR2"

IMMUNE_PID="$(spawn_sigterm_immune_process "u7s-scheduler --db ${WORKDIR2}/sched.db --kubeconfig ${WORKDIR2}/kubeconfig-scheduler --other ${WORKDIR2}/kubeconfig")"
LEFTOVER_PIDS+=("$IMMUNE_PID")
sleep 0.2

set +e
OUT2="$(bash "$SCRIPT" --host-only --workdir "$WORKDIR2" 2>&1)"
EXIT2=$?
set -e

assert_exit_code "surviving orphan: --host-only exits nonzero instead of claiming success" "$EXIT2" 1
assert_contains "surviving orphan: reset.sh names the survivor's PID in its output" "$OUT2" "$IMMUNE_PID"
if [[ "$OUT2" == *"Done"* ]]; then
  echo "FAIL: surviving orphan: reset.sh must not print 'Done' while a targeted process is still alive"
  FAIL=$(( FAIL + 1 ))
else
  echo "PASS: surviving orphan: reset.sh does not print 'Done' while a targeted process is still alive"
  PASS=$(( PASS + 1 ))
fi

# ---------------------------------------------------------------------------
# 3. Same SIGTERM-immune survivor, but on the FULL reset path (no
#    --host-only): run-all.sh's --reset flow calls reset.sh this way, and its
#    documented postcondition is "the VM is deleted" -- the verify-then-report
#    gate must not abort that path just because a host process survived.
#    Reverting the scoping fix (hoisting the gate back above the
#    --host-only check) makes this fail: the script would exit 1 and skip
#    $WORKDIR wipe / VM teardown instead of completing them.
# ---------------------------------------------------------------------------
WORKDIR3="$TMPROOT/full-reset/temp/u7s"
mkdir -p "$WORKDIR3"
STUBBIN="$TMPROOT/bin"
setup_limactl_stub "$STUBBIN"

IMMUNE_PID3="$(spawn_sigterm_immune_process "u7s-scheduler --db ${WORKDIR3}/sched.db --kubeconfig ${WORKDIR3}/kubeconfig-scheduler --other ${WORKDIR3}/kubeconfig")"
LEFTOVER_PIDS+=("$IMMUNE_PID3")
sleep 0.2

set +e
OUT3="$(PATH="$STUBBIN:$PATH" bash "$SCRIPT" --vm u7s-test-no-such-vm --workdir "$WORKDIR3" 2>&1)"
EXIT3=$?
set -e

assert_exit_code "full reset (no --host-only): surviving host process does not abort the reset" "$EXIT3" 0
if [[ "$OUT3" == *"ERROR: host process(es) survived"* ]]; then
  echo "FAIL: full reset (no --host-only): survivor gate must not fire outside --host-only"
  FAIL=$(( FAIL + 1 ))
else
  echo "PASS: full reset (no --host-only): survivor gate does not fire outside --host-only"
  PASS=$(( PASS + 1 ))
fi
if [ -d "$WORKDIR3" ]; then
  echo "FAIL: full reset (no --host-only): \$WORKDIR must still be wiped despite the surviving process"
  FAIL=$(( FAIL + 1 ))
else
  echo "PASS: full reset (no --host-only): \$WORKDIR is still wiped despite the surviving process"
  PASS=$(( PASS + 1 ))
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

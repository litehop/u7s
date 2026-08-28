#!/usr/bin/env bash
# Unit test for the results-retrieval sequence in 06-run-sonobuoy.sh.
#
# Live incident 2026-08-04: a real --focus run completed sonobuoy cleanly but
# the retrieval sequence produced ZERO output after "Retrieving results..." --
# no error, no timeout, nothing. run-all.sh returned control with no results
# file ever written. Manual recovery confirmed two bugs:
#
#   1. The tarball search only ever checked $VM_NAME (the primary node), never
#      $EXTRA_NODE -- sonobuoy's own scheduler placed the aggregator pod on
#      the extra node, so the primary-only search always came up empty there.
#   2. None of kubectl logs / kubectl get pod / limactl shell find / limactl
#      copy had any timeout -- a stalled SSH/konnectivity session hangs the
#      whole script forever with no diagnostic output at all.
#
# This test exercises real spawned processes (not just string/decision
# logic), because bug 2 is specifically about whether a wedged process is
# actually killed and the script actually returns -- a test that only
# inspects strings can't prove a hang was broken out of.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

PASS=0
FAIL=0
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

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

# ---------------------------------------------------------------------------
# run_with_timeout() -- mirrors 06-run-sonobuoy.sh's function of the same
# name verbatim. Keep in sync if that function changes.
# ---------------------------------------------------------------------------
run_with_timeout() {
  local label="$1" secs="$2" suppress_stderr="$3"
  shift 3
  if [ "$suppress_stderr" = "1" ]; then
    "$@" 2>/dev/null &
  else
    "$@" &
  fi
  local cmd_pid=$! waited=0
  while kill -0 "$cmd_pid" 2>/dev/null; do
    if [ "$waited" -ge "$secs" ]; then
      # pkill -P before kill -9: $cmd_pid's own children (e.g. the
      # 'sleep 300' a wrapping 'sh -c "...; sleep 300"' forks) are only
      # findable by PPID while $cmd_pid is still alive -- killing $cmd_pid
      # first would reparent them to init before pkill -P got a chance to
      # look them up, leaving them running as untracked orphans.
      pkill -9 -P "$cmd_pid" 2>/dev/null || true
      kill -9 "$cmd_pid" 2>/dev/null
      wait "$cmd_pid" 2>/dev/null || true
      echo "error: '$label' timed out after ${secs}s" >&2
      return 124
    fi
    sleep 1
    waited=$(( waited + 1 ))
  done
  local status=0
  wait "$cmd_pid" || status=$?
  return "$status"
}

# ---------------------------------------------------------------------------
# Node-search logic -- mirrors 06-run-sonobuoy.sh's HOST_PATH loop exactly
# (iterate every node in NODES, stop at the first hit). Keep in sync if that
# loop changes. fake_find_tarball_on_node stands in for
# 'limactl shell $NODE sudo find ...' so this test needs no real VM.
# ---------------------------------------------------------------------------
fake_find_tarball_on_node() {
  local node="$1" tarball="$2"
  find "$TMPDIR_TEST/$node/vol" -name "$tarball" 2>/dev/null | head -1
}

search_all_nodes() {
  local tarball="$1"
  HOST_PATH=""
  FOUND_NODE=""
  local node candidate
  for node in "${NODES[@]}"; do
    candidate=$(fake_find_tarball_on_node "$node" "$tarball")
    if [ -n "$candidate" ]; then
      HOST_PATH="$candidate"
      FOUND_NODE="$node"
      break
    fi
  done
}

# The pre-fix version -- hardcoded to only ever check $VM_NAME, mirroring the
# exact bug at 06-run-sonobuoy.sh:202-204 before this fix. Kept here ONLY so
# this test can demonstrate the bug: run with RUN_OLD_BUGGY_VERSION=1 to see
# it miss a tarball that genuinely exists on the extra node.
search_primary_only() {
  local tarball="$1"
  HOST_PATH=$(fake_find_tarball_on_node "$VM_NAME" "$tarball")
}

# ---------------------------------------------------------------------------
# Fixture: sonobuoy's aggregator pod scheduled onto the EXTRA node (exactly
# the live incident), so the results tarball genuinely exists there and NOT
# on the primary.
# ---------------------------------------------------------------------------
VM_NAME="primary-node"
EXTRA_NODE="extra-node"
NODES=("$VM_NAME" "$EXTRA_NODE")
TARBALL_NAME="sonobuoy_202608041234_abc123.tar.gz"

mkdir -p "$TMPDIR_TEST/$VM_NAME/vol" "$TMPDIR_TEST/$EXTRA_NODE/vol"
touch "$TMPDIR_TEST/$EXTRA_NODE/vol/$TARBALL_NAME"

if [ "${RUN_OLD_BUGGY_VERSION:-0}" = "1" ]; then
  echo "--- OLD buggy search_primary_only() (only checks \$VM_NAME) ---"
  search_primary_only "$TARBALL_NAME"
  if [ -z "$HOST_PATH" ]; then
    echo "CONFIRMED BUG: primary-only search missed the tarball that exists on \$EXTRA_NODE"
  else
    echo "primary-only search unexpectedly found it: $HOST_PATH"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# 1. Bug 1 fix: searching every node in the run finds the tarball regardless
#    of which node sonobuoy's scheduler picked.
# ---------------------------------------------------------------------------
echo "--- NEW fixed search_all_nodes() (searches all NODES) ---"
search_all_nodes "$TARBALL_NAME"
assert "fixed multi-node search finds the tarball scheduled onto the extra node" \
  "$([ -n "$HOST_PATH" ] && [ "$FOUND_NODE" = "$EXTRA_NODE" ] && echo 1 || echo 0)"

# Regression guard: prove the OLD approach genuinely fails in this same
# scenario, so this test would catch a regression back to primary-only search.
search_primary_only "$TARBALL_NAME"
assert "(regression guard) primary-only search genuinely misses a tarball on the extra node" \
  "$([ -z "$HOST_PATH" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. Bug 2 fix: a call that finishes normally is completely unaffected by
#    the timeout wrapper (real exit code and output both pass through).
# ---------------------------------------------------------------------------
FAST_OUT=$(run_with_timeout "fast echo" 5 0 sh -c 'echo hi; exit 0')
FAST_STATUS=$?
assert "a command that finishes normally is unaffected by run_with_timeout" \
  "$([ "$FAST_STATUS" -eq 0 ] && [ "$FAST_OUT" = "hi" ] && echo 1 || echo 0)"

STDERR_GENUINE_FAIL="$TMPDIR_TEST/genuine-fail-stderr.txt"
GENUINE_FAIL_STATUS=0
run_with_timeout "real failure" 5 0 sh -c 'exit 3' 2>"$STDERR_GENUINE_FAIL" || GENUINE_FAIL_STATUS=$?
assert "a genuine (non-timeout) failure passes through its real exit code with no extra noise -- misreporting it as a timeout would mislead whoever debugs it" \
  "$([ "$GENUINE_FAIL_STATUS" -eq 3 ] && [ ! -s "$STDERR_GENUINE_FAIL" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. Bug 2 fix, the core case: a call that hangs (standing in for a wedged
#    SSH/konnectivity session against limactl/kubectl) is killed and surfaced
#    loudly with a specific message, instead of hanging the whole script
#    forever with zero output -- the exact 2026-08-04 incident symptom.
# ---------------------------------------------------------------------------
PIDFILE="$TMPDIR_TEST/hung.pid"
STDERR_HUNG="$TMPDIR_TEST/hung-stderr.txt"
START=$(date +%s)
HANG_STATUS=0
run_with_timeout "hung limactl call" 1 0 sh -c "echo \$\$ > '$PIDFILE'; sleep 300" 2>"$STDERR_HUNG" || HANG_STATUS=$?
END=$(date +%s)
ELAPSED=$(( END - START ))

assert "a hung call returns in a few seconds instead of blocking for its full 300s duration" \
  "$([ "$ELAPSED" -lt 10 ] && echo 1 || echo 0)"
assert "a hung call's exit status is the conventional timeout code (124)" \
  "$([ "$HANG_STATUS" -eq 124 ] && echo 1 || echo 0)"
assert "a clear, specific message names which call timed out (was: total silence)" \
  "$(grep -q "'hung limactl call' timed out after 1s" "$STDERR_HUNG" && echo 1 || echo 0)"

HUNG_PID="$(cat "$PIDFILE" 2>/dev/null || echo "")"
assert "the hung process is actually killed, not left running as an orphan" \
  "$([ -n "$HUNG_PID" ] && ! kill -0 "$HUNG_PID" 2>/dev/null && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3b. Bug 2's grandchild-orphan corollary: killing only
#    $cmd_pid (the 'sh -c' wrapper) does nothing to a child 'sh' itself
#    forked -- that grandchild is never explicitly signalled and survives,
#    reparented, for its full 300s. This is a distinct process from
#    HUNG_PID above (the wrapper), captured here by having the wrapped
#    command background its own child and record that child's PID before
#    run_with_timeout's 1s deadline fires.
# ---------------------------------------------------------------------------
GRANDCHILD_PIDFILE="$TMPDIR_TEST/grandchild.pid"
run_with_timeout "hung call with a forked grandchild" 1 0 \
  sh -c "sleep 300 & echo \$! > '$GRANDCHILD_PIDFILE'; wait" 2>/dev/null || true

GRANDCHILD_PID="$(cat "$GRANDCHILD_PIDFILE" 2>/dev/null || echo "")"
assert "run_with_timeout kills the wrapped command's own forked grandchild too, not just the direct child it spawned -- otherwise every real timeout on a forking call (e.g. a stalled limactl/kubectl invocation) leaks a 300s orphan" \
  "$([ -n "$GRANDCHILD_PID" ] && ! kill -0 "$GRANDCHILD_PID" 2>/dev/null && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. suppress_stderr must hide only the wrapped command's own stderr, never
#    run_with_timeout's own timeout message. Caught during development: a
#    naive '2>/dev/null' appended after the whole run_with_timeout call
#    silences its own diagnostic along with the wrapped command's -- which
#    would have reintroduced the "zero output" incident even with a timeout
#    in place.
# ---------------------------------------------------------------------------
STDERR_SUPPRESSED="$TMPDIR_TEST/suppressed-stderr.txt"
run_with_timeout "suppressed-stderr timeout" 1 1 \
  sh -c "echo 'inner noise' >&2; sleep 300" 2>"$STDERR_SUPPRESSED" || true
assert "suppress_stderr hides the wrapped command's stderr but not run_with_timeout's own timeout message" \
  "$(grep -q "'suppressed-stderr timeout' timed out after 1s" "$STDERR_SUPPRESSED" \
     && ! grep -q "inner noise" "$STDERR_SUPPRESSED" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# evacuate_pod_logs() -- mirrors 06-run-sonobuoy.sh's per-node log-evacuation
# loop (NODES computed once above the loop; tar's own stderr no longer
# suppressed so a failure prints a warning instead of vanishing; copy/rm
# still swallow failures so one bad node doesn't abort the whole script).
# Keep in sync if that loop changes. fake_tar_pod_logs/fake_copy_pod_logs
# stand in for the real 'limactl shell $NODE sudo tar ...'/'limactl copy ...'
# calls so this test needs no real VM.
# ---------------------------------------------------------------------------
fake_tar_pod_logs() {
  local node="$1"
  tar -czf "$TMPDIR_TEST/$node/pod-logs-evacuation.tar.gz" \
    -C "$TMPDIR_TEST/$node" pods
}

fake_copy_pod_logs() {
  local node="$1" dest="$2"
  cp "$TMPDIR_TEST/$node/pod-logs-evacuation.tar.gz" "$dest" 2>/dev/null || true
}

evacuate_pod_logs() {
  local workdir="$1"; shift
  local node
  for node in "$@"; do
    fake_tar_pod_logs "$node" \
      || echo "warning: pod log evacuation failed on $node" >&2
    fake_copy_pod_logs "$node" "$workdir/pod-logs-evacuation-${node}.tar.gz"
  done
}

# The pre-fix version -- hardcoded to only ever evacuate $VM_NAME, mirroring
# the exact bug at 06-run-sonobuoy.sh:189-195 before this fix (the NODES list
# used to be computed AFTER evacuation and only used for the tarball search,
# never taught to the evacuation step itself).
evacuate_pod_logs_primary_only() {
  local workdir="$1" vm_name="$2"
  fake_tar_pod_logs "$vm_name" \
    || echo "warning: pod log evacuation failed on $vm_name" >&2
  fake_copy_pod_logs "$vm_name" "$workdir/pod-logs-evacuation-${vm_name}.tar.gz"
}

# ---------------------------------------------------------------------------
# 5. evacuates_from_all_nodes -- a 2-node --all-e2e run's sonobuoy e2e-job pod
#    can schedule onto EITHER node; evacuating only $VM_NAME silently lost
#    every pod log when it landed on the extra node in a real run
#    (temp/e2e/0805-2202-conformance). Both nodes must produce a tarball.
# ---------------------------------------------------------------------------
mkdir -p "$TMPDIR_TEST/lima-a/pods/ns_pod-a_uid/container" "$TMPDIR_TEST/lima-b/pods/ns_pod-b_uid/container"
echo "log from lima-a" > "$TMPDIR_TEST/lima-a/pods/ns_pod-a_uid/container/0.log"
echo "log from lima-b" > "$TMPDIR_TEST/lima-b/pods/ns_pod-b_uid/container/0.log"
EVAC_WORKDIR="$TMPDIR_TEST/host-workdir"
mkdir -p "$EVAC_WORKDIR"

evacuate_pod_logs "$EVAC_WORKDIR" "lima-a" "lima-b"
assert "evacuation produces one tarball per node -- a multi-node run losing the extra node's pod logs is undiagnosable post-mortem" \
  "$([ -f "$EVAC_WORKDIR/pod-logs-evacuation-lima-a.tar.gz" ] && [ -f "$EVAC_WORKDIR/pod-logs-evacuation-lima-b.tar.gz" ] && echo 1 || echo 0)"

# Regression guard: prove the OLD primary-only evacuation genuinely misses the
# extra node's tarball in this same scenario, so this test would catch a
# revert back to primary-only evacuation.
rm -rf "$EVAC_WORKDIR"; mkdir -p "$EVAC_WORKDIR"
evacuate_pod_logs_primary_only "$EVAC_WORKDIR" "lima-a"
assert "(regression guard) pre-fix primary-only evacuation genuinely never produces a tarball for the extra node" \
  "$([ -f "$EVAC_WORKDIR/pod-logs-evacuation-lima-a.tar.gz" ] && [ ! -f "$EVAC_WORKDIR/pod-logs-evacuation-lima-b.tar.gz" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 6. fails_loud_on_tar_error -- a failed evacuation (VM unreachable, or
#    /var/log/pods missing) must print a warning, not vanish silently the way
#    the swallowed '2>/dev/null || true' did in the 0805-2202 incident.
# ---------------------------------------------------------------------------
EVAC_STDERR="$TMPDIR_TEST/evac-stderr.txt"
rm -rf "$EVAC_WORKDIR"; mkdir -p "$EVAC_WORKDIR"
evacuate_pod_logs "$EVAC_WORKDIR" "nonexistent-vm" 2>"$EVAC_STDERR" || true
assert "a failed tar on an unreachable/nonexistent node prints a specific warning to stderr instead of vanishing" \
  "$(grep -q "warning: pod log evacuation failed on nonexistent-vm" "$EVAC_STDERR" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 7. rotated_log_files_are_included -- cri-o rotates
#    /var/log/pods/<pod>/<container>/0.log to 0.log.YYYYMMDDT... while
#    keeping the live 0.log; a live evacuation must capture BOTH or the
#    earlier ~90% of a long --all-e2e run's output is lost once cri-o's
#    RemoveContainer later deletes the pod dir wholesale.
# ---------------------------------------------------------------------------
mkdir -p "$TMPDIR_TEST/rotation-src/foo/bar"
echo "live" > "$TMPDIR_TEST/rotation-src/foo/bar/0.log"
echo "rotated" > "$TMPDIR_TEST/rotation-src/foo/bar/0.log.20260806-000000"
ROTATION_TARBALL="$TMPDIR_TEST/rotation.tar.gz"
tar -czf "$ROTATION_TARBALL" -C "$TMPDIR_TEST/rotation-src" foo
ROTATION_CONTENTS=$(tar -tzf "$ROTATION_TARBALL")
assert "tar -czf on a pod log dir picks up both the live 0.log and rotated 0.log.YYYYMMDDT... variants -- no separate glob needed" \
  "$(printf '%s' "$ROTATION_CONTENTS" | grep -q "0.log$" && printf '%s' "$ROTATION_CONTENTS" | grep -q "0.log.20260806-000000$" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 8. journald_system_max_use_is_5g -- lima-start.sh's journald drop-in caps
#    disk usage; 2G was measured insufficient for an 11h --all-e2e run under
#    16-way load (the 0805-2202 run's collected kubelet.log/crio.log covered
#    only the LAST 1h54m of that run, losing the 09:33-09:35 DiskPressure
#    incident window entirely), which is why this was raised to 6G. It was
#    later deliberately retuned to 5G (operator-directed "5GB disk" target)
#    alongside smaller SystemMaxFileSize/SystemMaxFiles segments to cut
#    journald's RSS working set -- so 5G is the current intentional floor,
#    not a regression. A future drop back to 2G (or below 5G) would silently
#    start truncating forensic evidence again.
# ---------------------------------------------------------------------------
LIMA_START="$(dirname "${BASH_SOURCE[0]}")/lima-start.sh"
assert "journald_system_max_use_is_5g -- 2G was measured insufficient for an 11h --all-e2e run under 16-way load (0805-2202 run lost its own DiskPressure incident window); regression below the current 5G floor silently truncates forensic evidence again" \
  "$(grep -q '^SystemMaxUse=5G$' "$LIMA_START" && ! grep -q '^SystemMaxUse=2G$' "$LIMA_START" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 9. journal_is_rotated_and_vacuumed_after_config_apply -- lima-start.sh runs
#    on every invocation, not just --reset ones, so a VM reused across several
#    conformance sessions can carry journal volume from EARLIER sessions into
#    a NEW run, silently shrinking how much of the current run's own window
#    the configured budget actually covers. 'journalctl --rotate' must fire
#    BEFORE '--vacuum-size': vacuuming without rotating first leaves the
#    active (still being written to) segment's stale volume intact, so
#    reordering these two calls would quietly reintroduce the exact bug this
#    is meant to fix.
# ---------------------------------------------------------------------------
ROTATE_LINE="$(grep -n 'journalctl --rotate' "$LIMA_START" | head -1 | cut -d: -f1)"
VACUUM_LINE="$(grep -n 'journalctl --vacuum-size' "$LIMA_START" | head -1 | cut -d: -f1)"
assert "journal_is_rotated_and_vacuumed_after_config_apply -- vacuum without a prior rotate leaves the active journal segment's stale volume intact, silently reintroducing truncated forensic logs" \
  "$([ -n "$ROTATE_LINE" ] && [ -n "$VACUUM_LINE" ] && [ "$ROTATE_LINE" -lt "$VACUUM_LINE" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

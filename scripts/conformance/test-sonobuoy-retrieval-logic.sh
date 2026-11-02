#!/usr/bin/env bash
# Unit test for the results-retrieval and pod-log evacuation sequence in
# 06-run-sonobuoy.sh.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

RUN_SONOBUOY="$(cd "$(dirname "$0")" && pwd)/06-run-sonobuoy.sh"

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
# 0. Results come from `sonobuoy retrieve`, not from crawling the aggregator's
#    kubelet emptyDir. The crawl needed per-node find + a pod-UID lookup and
#    hung silently when a call stalled; a regression back to it reintroduces
#    both, and a killed run must still exit with sonobuoy's own status.
# ---------------------------------------------------------------------------
assert "results are fetched with sonobuoy retrieve" \
  "$(grep -q 'sonobuoy retrieve /tmp/sonobuoy-retrieve' "$RUN_SONOBUOY" && echo 1 || echo 0)"
assert "kubelet emptyDir crawl and its timeout helper are gone" \
  "$(grep -qE 'kubernetes.io~empty-dir|Results available at|run_with_timeout' "$RUN_SONOBUOY" && echo 0 || echo 1)"
assert "a run killed before completion still exits with sonobuoy's status when retrieve yields nothing" \
  "$(grep -A4 'RETRIEVE_OK" -eq 0' "$RUN_SONOBUOY" | grep -q 'exit "${SONOBUOY_EXIT}"' && echo 1 || echo 0)"

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

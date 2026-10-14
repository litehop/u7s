#!/usr/bin/env bash
# Unit test for the [Disruptive] serial-pass split in 06-run-sonobuoy.sh and the
# rig SSH key helpers in _lib.sh.
#
# [Disruptive] specs restart kubelets; run inside the --procs=16 pool they broke
# unrelated specs' exec/logs (3 collateral failures in one csi-hostpath run).
# The parallel pass must therefore skip them and a --procs=1 pass must run only
# them -- in every mode, since the harness deliberately never drops [Disruptive].
#
# Runs the REAL build_filter_args extracted from 06-run-sonobuoy.sh, the REAL
# wrapper (with a fake `bash` for the child passes), and the REAL authorized_keys
# command from _lib.sh.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$DIR/06-run-sonobuoy.sh"
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
contains() { case "$1" in *"$2"*) echo 1 ;; *) echo 0 ;; esac; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------------------
# 1. build_filter_args per pass, for both filter shapes (apply=1: focus/all-e2e;
#    apply=0: certified-conformance and --unsafe-focus).
# ---------------------------------------------------------------------------
FUNC_FILE="$TMP/build_filter_args.sh"
sed -n '/^build_filter_args() {/,/^}/p' "$SCRIPT" > "$FUNC_FILE"
assert "build_filter_args was extracted from the real script" \
  "$([ -s "$FUNC_FILE" ] && echo 1 || echo 0)"

filter_args() {
  local pass="$1" apply="$2" procs="$3"
  (
    PASS="$pass"; PROCS="$procs"
    FEATUREGATE_LABEL_FILTER='FeatureGate: isSubsetOf {A}'
    JSON_REPORT_PATH=/r.json
    # shellcheck disable=SC1090
    source "$FUNC_FILE"
    build_filter_args "$apply"
    printf '%s\n' "${FILTER_ARGS[@]}"
  )
}

for apply in 1 0; do
  P_ARGS="$(filter_args parallel "$apply" 16)"
  if [ "$apply" = 1 ]; then
    assert "parallel pass (apply=1) skips [Disruptive] so kubelet restarts cannot hit the pool" \
      "$(contains "$P_ARGS" '--e2e-skip=\[')"
    assert "parallel pass (apply=1) skip regex names [Disruptive]" \
      "$(contains "$P_ARGS" '\[Disruptive\]')"
  else
    assert "parallel pass (apply=0) excludes Disruptive by label so kubelet restarts cannot hit the pool" \
      "$(contains "$P_ARGS" '--label-filter=!Disruptive')"
    assert "parallel pass (apply=0) passes no --e2e-skip: sonobuoy rejects it alongside --mode and the pass runs 0 specs" \
      "$(contains "$P_ARGS" '--e2e-skip' | tr 01 10)"
  fi
  assert "parallel pass (apply=$apply) keeps --procs=16" \
    "$(contains "$P_ARGS" '--procs=16')"
  assert "parallel pass (apply=$apply) has no Disruptive label selection" \
    "$(( $(contains "$P_ARGS" 'label-filter=Disruptive') + $(contains "$P_ARGS" '&& Disruptive') == 0 ? 1 : 0 ))"
  S_ARGS="$(filter_args disruptive "$apply" 1)"
  assert "disruptive pass (apply=$apply) runs with --procs=1" \
    "$(contains "$S_ARGS" '--procs=1')"
  assert "disruptive pass (apply=$apply) selects only Disruptive specs" \
    "$(( $(contains "$S_ARGS" 'label-filter=Disruptive') + $(contains "$S_ARGS" '&& Disruptive') > 0 ? 1 : 0 ))"
  assert "disruptive pass (apply=$apply) does not skip [Disruptive]" \
    "$(contains "$S_ARGS" '\[Disruptive\]' | tr 01 10)"
done
assert "disruptive pass keeps the FeatureGate allow-set ANDed in" \
  "$(contains "$(filter_args disruptive 1 1)" '(FeatureGate: isSubsetOf {A}) && Disruptive')"
assert "disruptive pass keeps the [Flaky] skip" \
  "$(contains "$(filter_args disruptive 1 1)" '--e2e-skip=\[Flaky\]')"

# Suite-level cap: a total hang must end at ginkgo's --timeout, not its 24h
# default; unset (--all-e2e keeps its 12h budget) must add no ginkgo --timeout.
timeout_filter_args() {
  local apply="$1" gt="$2"
  (
    PASS=parallel; PROCS=16
    FEATUREGATE_LABEL_FILTER='FeatureGate: isSubsetOf {A}'
    JSON_REPORT_PATH=/r.json
    if [ -n "$gt" ]; then GINKGO_SUITE_TIMEOUT="$gt"; fi
    # shellcheck disable=SC1090
    source "$FUNC_FILE"
    build_filter_args "$apply"
    printf '%s\n' "${FILTER_ARGS[@]}"
  )
}
for apply in 1 0; do
  assert "apply=$apply carries ginkgo --timeout=3600s when a suite cap is set" \
    "$(contains "$(timeout_filter_args "$apply" 3600s)" '--timeout=3600s')"
  assert "apply=$apply adds no ginkgo --timeout when no cap is set (--all-e2e keeps its own budget)" \
    "$(contains "$(timeout_filter_args "$apply" "")" '--timeout' | tr 01 10)"
done
assert "apply=1 keeps the cap inside the '|'-separated E2E_EXTRA_GINKGO_ARGS value" \
  "$(contains "$(timeout_filter_args 1 3600s)" '|--timeout=3600s')"

SUITE_FUNC="$TMP/suite_timeout_seconds.sh"
sed -n '/^suite_timeout_seconds() {/,/^}/p' "$SCRIPT" > "$SUITE_FUNC"
# shellcheck disable=SC1090
source "$SUITE_FUNC"
assert "no-focus (full certified conformance) gets 5400s because it includes storage specs that can run 43 min; 3600s would cut a passing run off" \
  "$([ "$(suite_timeout_seconds '')/$(suite_timeout_seconds 'ConfigMap')" = "5400/3600" ] && echo 1 || echo 0)"
for f in 'External Storage \[Driver: csi-hostpath\]' '\[sig-storage\]' 'CSI Volumes' 'PersistentVolumes' 'Volume expand'; do
  assert "storage/CSI focus '$f' gets 5400s so a 43 min passing run is not cut off" \
    "$([ "$(suite_timeout_seconds "$f")" = "5400" ] && echo 1 || echo 0)"
done
assert "U7S_SUITE_TIMEOUT_S overrides the selected cap" \
  "$([ "$(U7S_SUITE_TIMEOUT_S=7200 suite_timeout_seconds 'ConfigMap')/$(U7S_SUITE_TIMEOUT_S=120 suite_timeout_seconds 'CSI')" = "7200/120" ] && echo 1 || echo 0)"

# Run the REAL 06 (parallel pass) against stub limactl/kubectl and inspect the
# sonobuoy argv it builds: ginkgo --timeout and sonobuoy --timeout must both
# derive from the same cap, in every mode except --all-e2e.
STUB="$TMP/stub"
mkdir -p "$STUB"
cat > "$STUB/limactl" <<'STUBEOF'
#!/bin/sh
printf '%s\n' "$*" >> "$LIMA_LOG"
case "$*" in *"sonobuoy status"*) exit 1 ;; esac
exit 0
STUBEOF
cat > "$STUB/kubectl" <<'STUBEOF'
#!/bin/sh
case "$*" in
  *"-f -") cat > /dev/null ;;
  *" get nodes"*) echo node/lima-node ;;
esac
STUBEOF
chmod +x "$STUB/limactl" "$STUB/kubectl"
: > "$TMP/kubeconfig"
# CAP, when set, is passed as U7S_SUITE_TIMEOUT_S.
run06() {
  : > "$TMP/lima.log"
  (
    cd "$DIR/../.."
    PATH="$STUB:$PATH" LIMA_LOG="$TMP/lima.log" KUBECONFIG="$TMP/kubeconfig" \
      U7S_SUITE_TIMEOUT_S="${CAP:-}" "$SCRIPT" --pass parallel --workdir "$TMP/wd" "$@" >/dev/null 2>&1 || true
  )
  grep 'sudo sonobuoy run ' "$TMP/lima.log" | head -1
}
has_all() { local argv="$1"; shift; local p; for p in "$@"; do case "$argv" in *"$p"*) ;; *) echo 0; return ;; esac; done; echo 1; }
ARGV="$(run06 --focus 'CSI Volumes')"
assert "06 storage focus run: ginkgo --timeout=5400s and sonobuoy --timeout 6000 (cap + margin)" \
  "$(has_all "$ARGV" '--timeout=5400s' '--timeout 6000' '--e2e-focus=CSI Volumes')"
ARGV="$(run06 --focus 'ConfigMap')"
assert "06 non-storage focus run: 3600s ginkgo cap and sonobuoy --timeout 4200" \
  "$(has_all "$ARGV" '--timeout=3600s' '--timeout 4200')"
ARGV="$(run06)"
assert "06 certified-conformance run: 5400s ginkgo cap (storage specs run in the full suite), sonobuoy --timeout 6000" \
  "$(has_all "$ARGV" '--timeout=5400s' '--timeout 6000' '--mode=certified-conformance')"
ARGV="$(CAP=100 run06 --focus 'CSI')"
assert "06 honours U7S_SUITE_TIMEOUT_S in both the ginkgo and sonobuoy timeouts" \
  "$(has_all "$ARGV" '--timeout=100s' '--timeout 700')"
ARGV="$(run06 --all-e2e)"
assert "06 --all-e2e keeps its 12h sonobuoy budget and adds no ginkgo suite cap" \
  "$([ "$(has_all "$ARGV" '--timeout 43200')$(contains "$ARGV" ' --timeout=')" = "10" ] && echo 1 || echo 0)"
: > "$TMP/lima.log"
BAD_RC=0
(
  cd "$DIR/../.."
  PATH="$STUB:$PATH" LIMA_LOG="$TMP/lima.log" KUBECONFIG="$TMP/kubeconfig" U7S_SUITE_TIMEOUT_S=abc \
    "$SCRIPT" --pass parallel --workdir "$TMP/wd" >/dev/null 2>&1
) || BAD_RC=$?
assert "an invalid U7S_SUITE_TIMEOUT_S fails 06 before any limactl call, so a typo never boots work on the VM" \
  "$([ "$BAD_RC" -ne 0 ] && [ ! -s "$TMP/lima.log" ] && echo 1 || echo 0)"


# ---------------------------------------------------------------------------
# 2. The wrapper runs BOTH passes (disruptive first) and fails if either fails.
# ---------------------------------------------------------------------------
FAKEBIN="$TMP/bin"
mkdir -p "$FAKEBIN"
cat > "$FAKEBIN/bash" <<'EOF'
#!/bin/sh
echo "$*" >> "$FAKE_BASH_LOG"
case "$*" in
  *"--pass disruptive"*) echo "  Ran:    11"; echo "  Passed: 11"; echo "  Failed: 0"; exit "${FAKE_DISRUPTIVE_EXIT:-0}" ;;
  *"--pass parallel"*) [ -n "${FAKE_PARALLEL_NO_SUMMARY:-}" ] && exit "${FAKE_PARALLEL_EXIT:-0}"; echo "  Ran:    ${FAKE_PARALLEL_RAN:-96}"; echo "  Passed: $(( ${FAKE_PARALLEL_RAN:-96} - ${FAKE_PARALLEL_FAILED:-0} ))"; echo "  Failed: ${FAKE_PARALLEL_FAILED:-0}"; exit "${FAKE_PARALLEL_EXIT:-0}" ;;
esac
EOF
chmod +x "$FAKEBIN/bash"

run_wrapper() {
  : > "$TMP/calls.log"
  FAKE_BASH_LOG="$TMP/calls.log" PATH="$FAKEBIN:$PATH" "$@" > "$TMP/out.log" 2>&1 || return $?
}

RC=0
run_wrapper env FAKE_DISRUPTIVE_EXIT=0 FAKE_PARALLEL_EXIT=0 FAKE_PARALLEL_FAILED=2 /bin/bash "$SCRIPT" --focus csi-hostpath --port 6444 || RC=$?
CALLS="$(cat "$TMP/calls.log")"
assert "wrapper invokes exactly two child passes" \
  "$([ "$(wc -l < "$TMP/calls.log" | tr -d ' ')" = "2" ] && echo 1 || echo 0)"
assert "first child is the disruptive pass (so the parallel run is the newest temp/e2e dir)" \
  "$(contains "$(sed -n 1p "$TMP/calls.log")" '--pass disruptive')"
assert "second child is the parallel pass" \
  "$(contains "$(sed -n 2p "$TMP/calls.log")" '--pass parallel')"
assert "wrapper forwards the original flags to both children" \
  "$(contains "$CALLS" '--focus csi-hostpath --port 6444')"
OUT="$(cat "$TMP/out.log")"
assert "combined summary reports the disruptive pass counts" \
  "$(contains "$OUT" '[disruptive] Ran: 11 Passed: 11 Failed: 0')"
assert "combined summary reports the parallel pass counts" \
  "$(contains "$OUT" '[parallel] Ran: 96 Passed: 94 Failed: 2')"
assert "combined summary totals failures across both passes" \
  "$(contains "$OUT" 'Total failed across passes: 2')"
# sonobuoy exits 0 even when specs failed (a 1-failed-spec run once exited 0),
# so a child that exited 0 but reported failures must still fail the script.
assert "specs failed in a pass whose child exited 0 -> script exits 10 (spec failures), not 0 and not an infra code" \
  "$([ "$RC" = 10 ] && echo 1 || echo 0)"
RC=0
run_wrapper env FAKE_DISRUPTIVE_EXIT=0 FAKE_PARALLEL_EXIT=10 FAKE_PARALLEL_FAILED=2 /bin/bash "$SCRIPT" --focus x || RC=$?
assert "a child that already reports spec-failure exit 10 stays 10 (not mistaken for an infra error)" \
  "$([ "$RC" = 10 ] && echo 1 || echo 0)"
RC=0
run_wrapper env FAKE_DISRUPTIVE_EXIT=3 FAKE_PARALLEL_EXIT=0 FAKE_PARALLEL_FAILED=2 /bin/bash "$SCRIPT" --focus x || RC=$?
assert "an infra error in one pass masks spec failures in the other: results may be incomplete" \
  "$([ "$RC" = 3 ] && echo 1 || echo 0)"
RC=0
run_wrapper env FAKE_DISRUPTIVE_EXIT=0 FAKE_PARALLEL_EXIT=0 /bin/bash "$SCRIPT" --focus csi-hostpath || RC=$?
assert "all passes report 0 failed and exit 0 -> script exits 0" "$([ "$RC" = 0 ] && echo 1 || echo 0)"

RC=0
run_wrapper env FAKE_DISRUPTIVE_EXIT=3 FAKE_PARALLEL_EXIT=0 /bin/bash "$SCRIPT" --focus x || RC=$?
assert "a failing disruptive pass fails the script even though the parallel pass succeeded" \
  "$([ "$RC" = 3 ] && echo 1 || echo 0)"
assert "a failing disruptive pass does not prevent the parallel pass from running" \
  "$([ "$(wc -l < "$TMP/calls.log" | tr -d ' ')" = "2" ] && echo 1 || echo 0)"
RC=0
run_wrapper env FAKE_DISRUPTIVE_EXIT=0 FAKE_PARALLEL_EXIT=4 /bin/bash "$SCRIPT" --focus x || RC=$?
assert "a failing parallel pass fails the script" "$([ "$RC" = 4 ] && echo 1 || echo 0)"

# A pass that never ran specs must not read as "failed 0": the sonobuoy
# --mode/--e2e-skip conflict made the parallel pass exit before running anything
# and the run still looked green in the summary.
RC=0
run_wrapper env FAKE_PARALLEL_NO_SUMMARY=1 /bin/bash "$SCRIPT" --port 6444 || RC=$?
OUT="$(cat "$TMP/out.log")"
assert "a pass that produced no results is flagged in the summary" \
  "$(contains "$OUT" '[parallel] NO RESULTS')"
assert "a pass that produced no results counts as a failure in the total" \
  "$(contains "$OUT" 'Total failed across passes: 1')"
assert "a pass that produced no results exits 1 (infra), distinct from spec-failure 10, even if its child exited 0" \
  "$([ "$RC" = 1 ] && echo 1 || echo 0)"
RC=0
run_wrapper env FAKE_PARALLEL_RAN=0 /bin/bash "$SCRIPT" --port 6444 || RC=$?
OUT="$(cat "$TMP/out.log")"
assert "a bare certified-conformance pass that ran 0 specs is flagged" \
  "$(contains "$OUT" '[parallel] RAN 0 SPECS')"
assert "a bare certified-conformance pass that ran 0 specs fails the script" \
  "$([ "$RC" != 0 ] && echo 1 || echo 0)"
RC=0
run_wrapper env FAKE_PARALLEL_RAN=0 /bin/bash "$SCRIPT" --focus only-disruptive-specs || RC=$?
OUT="$(cat "$TMP/out.log")"
assert "a --focus pass that legitimately selects 0 specs is not flagged" \
  "$(contains "$OUT" 'RAN 0 SPECS' | tr 01 10)"

# sonobuoy refuses --mode together with --e2e-focus/--e2e-skip. The bare path
# (apply=0) appends --mode=certified-conformance, so its filter args must never
# carry either flag, in any pass.
assert "bare path appends --mode=certified-conformance after build_filter_args 0" \
  "$(grep -A3 'build_filter_args 0' "$SCRIPT" | grep -q -- '--mode=certified-conformance' && echo 1 || echo 0)"
for pass in parallel disruptive; do
  A="$(filter_args "$pass" 0 4)"
  assert "bare path ($pass) filter args never carry --e2e-skip/--e2e-focus that sonobuoy rejects with --mode" \
    "$(( $(contains "$A" '--e2e-skip') + $(contains "$A" '--e2e-focus') == 0 ? 1 : 0 ))"
done

# ---------------------------------------------------------------------------
# 3. Results-dir naming: the disruptive pass gets its own dir, and the slug is
#    capped so the suffixed name stays under the 255-byte filename limit.
# ---------------------------------------------------------------------------
assert "disruptive pass results get a distinct -disruptive slug suffix" \
  "$(grep -q 'FOCUS_SLUG="${FOCUS_SLUG}-disruptive"' "$SCRIPT" && echo 1 || echo 0)"
assert "slug is capped before the suffix is appended" \
  "$(grep -q 'FOCUS_SLUG="${FOCUS_SLUG:0:100}"' "$SCRIPT" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3b. run-all resolves the parallel results dir from the record 06 writes, never
#     from "newest temp/e2e entry" (which is the disruptive dir whenever the
#     parallel pass dies before retrieving results).
# ---------------------------------------------------------------------------
RUN_ALL="$DIR/run-all.sh"
assert "run-all.sh no longer guesses the results dir by mtime" \
  "$(grep -q 'ls -td' "$RUN_ALL" && echo 0 || echo 1)"
assert "run-all.sh reads the parallel pass's recorded results dir (build.json + dhat heap)" \
  "$([ "$(grep -c 'cat "$(sonobuoy_results_dir_file "\$WORKDIR" parallel)"' "$RUN_ALL")" = 2 ] && echo 1 || echo 0)"
# Execute the real `rm -f` line from run-all.sh (the line itself is the unit; the
# rest of run-all.sh needs a whole rig) against a stale record.
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"
RM_LINE="$(grep -m1 '^  rm -f "$(sonobuoy_results_dir_file "$WORKDIR" parallel)"' "$RUN_ALL" || true)"
WORKDIR="$TMP/wd-stale"; mkdir -p "$WORKDIR"
echo /old/run > "$(sonobuoy_results_dir_file "$WORKDIR" parallel)"
[ -n "$RM_LINE" ] && eval "$RM_LINE"
assert "run-all.sh removes a stale parallel record before invoking 06 so an early 06 death cannot reuse an old run's dir" \
  "$([ -n "$RM_LINE" ] && [ ! -e "$(sonobuoy_results_dir_file "$WORKDIR" parallel)" ] && echo 1 || echo 0)"
# 06 against stubs that die at sonobuoy: a stale record must not survive the run.
mkdir -p "$TMP/wd"
echo /old/run > "$(sonobuoy_results_dir_file "$TMP/wd" parallel)"
run06 --focus x >/dev/null
assert "06-run-sonobuoy.sh clears the stale record at pass start (a pass that dies early leaves none)" \
  "$([ ! -e "$(sonobuoy_results_dir_file "$TMP/wd" parallel)" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. One source of truth for the e2e-ssh key path: both scripts derive it from
#    the kubeconfig directory via the shared helper.
# ---------------------------------------------------------------------------
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"
assert "exit code table: clean=0, spec failures=10, infra error passes through and masks spec failures" \
  "$([ "$(sonobuoy_exit_code 0 0)/$(sonobuoy_exit_code 0 3)/$(sonobuoy_exit_code 1 0)/$(sonobuoy_exit_code 2 3)" = "0/10/1/2" ] && echo 1 || echo 0)"
assert "key path derives from the kubeconfig dir" \
  "$([ "$(e2e_ssh_key_path /w/temp/u7s/kubeconfig)" = "/w/temp/u7s/e2e-ssh/id_ed25519" ] && echo 1 || echo 0)"
assert "lima-start.sh uses the shared key-path helper" \
  "$(grep -q 'e2e_ssh_key_path "\$KUBECONFIG_PATH"' "$DIR/lima-start.sh" && echo 1 || echo 0)"
assert "06-run-sonobuoy.sh uses the shared key-path helper, not its own --workdir" \
  "$(grep -q 'e2e_ssh_key_path "\$KUBECONFIG"' "$SCRIPT" && echo 1 || echo 0)"
assert "06-run-sonobuoy.sh no longer builds the key path from \$WORKDIR" \
  "$(grep -q 'WORKDIR/e2e-ssh' "$SCRIPT" && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 5. authorized_keys holds exactly one rig key after repeated provisioning with
#    different keys (workdir wiped, VM kept), and foreign keys survive.
# ---------------------------------------------------------------------------
FAKEHOME="$TMP/home"
mkdir -p "$FAKEHOME/.ssh"
echo "ssh-ed25519 AAAAforeign someone@laptop" > "$FAKEHOME/.ssh/authorized_keys"
KEY1="ssh-ed25519 AAAAkey1 $E2E_SSH_KEY_COMMENT"
KEY2="ssh-ed25519 AAAAkey2 $E2E_SSH_KEY_COMMENT"
for k in "$KEY1" "$KEY1" "$KEY2"; do
  HOME="$FAKEHOME" /bin/bash -c "$(authorized_keys_replace_cmd "$k")"
done
AK="$(cat "$FAKEHOME/.ssh/authorized_keys")"
assert "exactly one rig key line remains after re-provisioning with a new key" \
  "$([ "$(grep -c "$E2E_SSH_KEY_COMMENT" "$FAKEHOME/.ssh/authorized_keys")" = 1 ] && echo 1 || echo 0)"
assert "the remaining rig key is the newest one" "$(contains "$AK" 'AAAAkey2')"
assert "stale rig key is gone" "$(contains "$AK" 'AAAAkey1' | tr 01 10)"
assert "a foreign authorized key survives" "$(contains "$AK" 'AAAAforeign')"
assert "no temp file is left behind" \
  "$([ ! -e "$FAKEHOME/.ssh/authorized_keys.new" ] && echo 1 || echo 0)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

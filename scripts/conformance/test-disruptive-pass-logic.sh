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
  *"--pass parallel"*) [ -n "${FAKE_PARALLEL_NO_SUMMARY:-}" ] && exit "${FAKE_PARALLEL_EXIT:-0}"; echo "  Ran:    ${FAKE_PARALLEL_RAN:-96}"; echo "  Passed: 94"; echo "  Failed: 2"; exit "${FAKE_PARALLEL_EXIT:-0}" ;;
esac
EOF
chmod +x "$FAKEBIN/bash"

run_wrapper() {
  : > "$TMP/calls.log"
  FAKE_BASH_LOG="$TMP/calls.log" PATH="$FAKEBIN:$PATH" "$@" > "$TMP/out.log" 2>&1 || return $?
}

RC=0
run_wrapper env FAKE_DISRUPTIVE_EXIT=0 FAKE_PARALLEL_EXIT=0 /bin/bash "$SCRIPT" --focus csi-hostpath --port 6444 || RC=$?
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
assert "clean children -> exit 0" "$([ "$RC" = 0 ] && echo 1 || echo 0)"

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
assert "a pass that produced no results fails the script even if its child exited 0" \
  "$([ "$RC" != 0 ] && echo 1 || echo 0)"
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
# 4. One source of truth for the e2e-ssh key path: both scripts derive it from
#    the kubeconfig directory via the shared helper.
# ---------------------------------------------------------------------------
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"
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

#!/usr/bin/env bash
# Logic test for the release-gate verdict (scripts/release-gate/lib.sh) from canned
# samples. The gate decides whether a release may ship, so the failure modes that
# matter are a false PASS (a bad build ships) and a missing-data PASS (a run that died
# halfway looks green). No VM needed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

PASS=0; FAIL=0
assert() {
  local label="$1" ok="$2"
  if [ "$ok" = 1 ]; then echo "PASS: $label"; PASS=$((PASS + 1)); else echo "FAIL: $label"; FAIL=$((FAIL + 1)); fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

good() {
  cat <<'EOF'
install_ok=1
oom_host=0
oom_kubesystem=0
oom_victims=
notready_events=0
node_ready_final=True
burst20_secs=12
burst_pods=50
burst_secs=140
wp_ok=1
marker_ok=1
webhook_ok=1
EOF
}

# verdict_of <results-file> -> sets V_OUT, V_RC
verdict_of() { V_RC=0; V_OUT="$(rg_verdict "$1")" || V_RC=$?; }

# mutate <key> <value>: the good file with one key replaced (or removed when value is "-")
mutate() {
  local f="$TMP/m.env"
  good | grep -v "^$1=" > "$f"
  [ "$2" = "-" ] || echo "$1=$2" >> "$f"
  echo "$f"
}

good > "$TMP/good.env"
verdict_of "$TMP/good.env"
assert "all criteria met -> exit 0 and RESULT: PASS (a clean run must not be reported as failing)" \
  "$([ "$V_RC" = 0 ] && echo "$V_OUT" | grep -q '^RESULT: PASS' && echo 1 || echo 0)"

# Each criterion alone must flip the verdict, and only its own row.
expect_fail() {
  local label="$1" key="$2" val="$3" row="$4"
  verdict_of "$(mutate "$key" "$val")"
  assert "$label" \
    "$([ "$V_RC" != 0 ] && echo "$V_OUT" | grep -q "^FAIL $row " && echo "$V_OUT" | grep -q '^RESULT: FAIL' && echo 1 || echo 0)"
}
expect_fail "(a) host process OOM-killed -> FAIL: a dead apiserver/kubelet takes the whole node down" oom_host 1 '(a)'
expect_fail "(a) kube-system pod OOM-killed -> FAIL: CoreDNS dying breaks cluster DNS (the 2026-10-01 failure)" oom_kubesystem 2 '(a)'
expect_fail "(b) node went not-Ready during the run -> FAIL" notready_events 1 '(b)'
expect_fail "(b) node not Ready at the end -> FAIL even with no recorded flap" node_ready_final False '(b)'
expect_fail "(c) 20-pod burst over the cap -> FAIL: pods stuck Pending is the user-visible symptom of thrash" burst20_secs 301 '(c)'
expect_fail "(c) 50-pod burst hit the hard kill -> FAIL" burst_secs timeout '(c)'
expect_fail "(d) WordPress dead after the burst -> FAIL: the workload the node exists to serve" wp_ok 0 '(d)'
expect_fail "(d) DB marker gone (recreated emptyDir MariaDB) -> FAIL even though WordPress still answers: its installer 302 is not a healthy site" marker_ok 0 '(d)'
expect_fail "(e) webhook smoke failed -> FAIL: only gate for the shipped webhook dial path" webhook_ok 0 '(e)'
expect_fail "install failed -> FAIL" install_ok 0 install

verdict_of "$(mutate burst20_secs 300)"
assert "burst exactly at the 300 s cap passes (cap is inclusive: 'within 5 min')" "$([ "$V_RC" = 0 ] && echo 1 || echo 0)"

# Missing data must never pass.
for key in oom_host oom_kubesystem notready_events node_ready_final burst20_secs burst_pods burst_secs wp_ok marker_ok webhook_ok install_ok; do
  verdict_of "$(mutate "$key" -)"
  assert "missing $key -> FAIL: a run that died before producing it must not look green" "$([ "$V_RC" != 0 ] && echo 1 || echo 0)"
done
: > "$TMP/empty.env"
verdict_of "$TMP/empty.env"
assert "empty results (VM never came up) -> FAIL" "$([ "$V_RC" != 0 ] && echo 1 || echo 0)"

BURST_CAP_SECS=100 verdict_of "$TMP/good.env"
assert "lowered BURST_CAP_SECS flips a 140 s burst to FAIL (forced-failure lever used to prove the gate can fail)" \
  "$([ "$V_RC" != 0 ] && echo 1 || echo 0)"

# OOM victim classification from canned kernel lines.
UIDS="aaaa_1111 bbbb_2222"
klog() { echo "kernel: oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=x,mems_allowed=0,global_oom,task_memcg=$2,task=$1,pid=42,uid=0"; }
out="$( { klog php-fpm /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podcccc_3333.slice/crio-x.scope
          klog coredns /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podbbbb_2222.slice/crio-y.scope
          klog u7s-apiserver /system.slice/u7s-apiserver.service
          klog kubelet /system.slice/kubelet.service
          echo "kernel: Out of memory: Killed process 42 (php-fpm)"; } | rg_oom_victims "$UIDS")"
assert "workload pod victim classed other (does not fail criterion (a))" "$(echo "$out" | grep -qx 'other php-fpm' && echo 1 || echo 0)"
assert "kube-system pod victim matched by pod UID in its cgroup path" "$(echo "$out" | grep -qx 'kube-system coredns' && echo 1 || echo 0)"
assert "apiserver victim classed host" "$(echo "$out" | grep -qx 'host u7s-apiserver' && echo 1 || echo 0)"
assert "kubelet victim classed host" "$(echo "$out" | grep -qx 'host kubelet' && echo 1 || echo 0)"
assert "one victim per oom-kill line (the 'Killed process' companion line is not double counted)" "$([ "$(echo "$out" | wc -l | tr -d ' ')" = 4 ] && echo 1 || echo 0)"
assert "host process classified by cgroup even if comm is unknown (e.g. renamed unit binary)" \
  "$([ "$(rg_classify_oom mystery /system.slice/crio.service "$UIDS")" = host ] && echo 1 || echo 0)"

# Experiment-flag parsing, with a stub limactl that fails every call so no VM is ever created;
# gate.env is staged before the first VM and shows what the VM would receive.
mkdir -p "$TMP/tb" "$TMP/bin"
printf '#!/bin/sh\n[ "$1" = list ] && exit 0\nexit 1\n' > "$TMP/bin/limactl"; chmod +x "$TMP/bin/limactl"
printf '#!/bin/sh\necho 100\n' > "$TMP/bin/idle100"; chmod +x "$TMP/bin/idle100"
export RG_IDLE_PROBE="$TMP/bin/idle100" QUIET_RECHECK_SECS=1 RG_RETRY_WAIT_SECS=0
PATH="$TMP/bin:$PATH"
gate_env() { "$HERE/burst-gate.sh" --runs 1 --tarball-dir "$TMP/tb" --out "$TMP/out-$1" "${@:2}" >/dev/null 2>&1; cat "$TMP/out-$1/stage/gate.env"; }
assert "--zram-mib 512 reaches the VM env" "$(gate_env z512 --zram-mib 512 | grep -qx 'ZRAM_MIB=512' && echo 1 || echo 0)"
assert "--zram-mib 0 is accepted and means no swap" "$(gate_env z0 --zram-mib 0 | grep -qx 'ZRAM_MIB=0' && echo 1 || echo 0)"
assert "--zram-mib defaults to off" "$(gate_env zdef | grep -qx 'ZRAM_MIB=0' && echo 1 || echo 0)"
assert "--coredns-requests reaches the VM env" "$(gate_env cd --coredns-requests | grep -qx 'COREDNS_REQ=1' && echo 1 || echo 0)"
assert "--coredns-requests defaults to off" "$(gate_env cddef | grep -qx 'COREDNS_REQ=0' && echo 1 || echo 0)"
for bad in abc -5 1.5 ""; do
  rc=0; err="$("$HERE/burst-gate.sh" --runs 1 --tarball-dir "$TMP/tb" --out "$TMP/out-bad" --zram-mib "$bad" 2>&1 >/dev/null)" || rc=$?
  assert "--zram-mib '$bad' rejected on the host with exit 2 before any VM exists (a bad size must not look like 'zram did not help')" \
    "$([ "$rc" = 2 ] && echo "$err" | grep -q 'non-negative integer' && [ ! -e "$TMP/out-bad/stage" ] && echo 1 || echo 0)"
done

# --runs validation: BSD `seq 1 0` counts down, so --runs 0 once created a real VM.
printf '#!/bin/sh\necho "$*" >> "$LIMA_CALLS"\n[ "$1" = list ] && exit 0\nexit 1\n' > "$TMP/bin/limactl"
export LIMA_CALLS="$TMP/lima-calls"
for bad in 0 00 -1 abc 1.5 ""; do
  : > "$LIMA_CALLS"; rm -rf "$TMP/out-runs"
  rc=0; err="$("$HERE/burst-gate.sh" --runs "$bad" --tarball-dir "$TMP/tb" --out "$TMP/out-runs" 2>&1 >/dev/null)" || rc=$?
  assert "--runs '$bad' rejected with exit 2 and zero limactl calls (a bad count must not spawn a VM)" \
    "$([ "$rc" = 2 ] && echo "$err" | grep -q 'positive integer' && [ ! -s "$LIMA_CALLS" ] && echo 1 || echo 0)"
done
: > "$LIMA_CALLS"; rm -rf "$TMP/out-runs"
"$HERE/burst-gate.sh" --runs 1 --tarball-dir "$TMP/tb" --out "$TMP/out-runs" >/dev/null 2>&1 || true
assert "--runs 1 creates exactly one VM" "$([ "$(grep -c '^create ' "$LIMA_CALLS")" = 1 ] && echo 1 || echo 0)"
: > "$LIMA_CALLS"; rm -rf "$TMP/out-runs"
"$HERE/burst-gate.sh" --runs 2 --tarball-dir "$TMP/tb" --out "$TMP/out-runs" >/dev/null 2>&1 || true
assert "--runs 2 creates exactly two VMs" "$([ "$(grep -c '^create ' "$LIMA_CALLS")" = 2 ] && echo 1 || echo 0)"

# Watch-stream reader: a burst is done only when readyReplicas reaches the target.
assert "rg_wait_ready succeeds when readyReplicas reaches the target mid-stream" \
  "$(printf '1\n\n12\n20\n' | rg_wait_ready 20 && echo 1 || echo 0)"
assert "rg_wait_ready fails when the stream ends short (dropped watch must not look like success)" \
  "$(printf '1\n12\n19\n' | rg_wait_ready 20 && echo 0 || echo 1)"
assert "rg_wait_ready does not match 2 against 20 (prefix) or an empty line" \
  "$(printf '20\n\n' | rg_wait_ready 2 && echo 0 || echo 1)"

printf '100 True\n200 False\n300 Unknown\n400 unreachable\n500 True\n' > "$TMP/nr.log"
assert "rg_notready_since counts only observations at/after the burst start" "$([ "$(rg_notready_since "$TMP/nr.log" 300)" = 2 ] && echo 1 || echo 0)"
assert "rg_notready_since counts False, Unknown and unreachable: a dead API is the worst not-Ready and must fail (b)" "$([ "$(rg_notready_since "$TMP/nr.log" 0)" = 3 ] && echo 1 || echo 0)"

# Node-watch stamping: the watch replays install-time flaps on (re)connect.
T0=$(( $(date +%s) - 3600 ))
iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ; }
PRE="$(iso $((T0 - 600)))"; POST="$(iso $((T0 + 60)))"
printf 'False %s\nTrue %s\n' "$PRE" "$(iso $((T0 - 500)))" | rg_node_watch_stamp > "$TMP/w1.log"
assert "replayed pre-burst False (lastTransitionTime < burst start) is not counted: install flaps must not fail (b)" \
  "$([ "$(rg_notready_since "$TMP/w1.log" "$T0")" = 0 ] && echo 1 || echo 0)"
printf 'True %s\nFalse %s\n' "$PRE" "$POST" | rg_node_watch_stamp > "$TMP/w2.log"
assert "False transition after burst start is counted: a real flap during the burst must fail (b)" \
  "$([ "$(rg_notready_since "$TMP/w2.log" "$T0")" = 1 ] && echo 1 || echo 0)"
printf 'False %s\nFalse %s\nFalse %s\n' "$POST" "$POST" "$POST" | rg_node_watch_stamp > "$TMP/w3.log"
assert "duplicate watch lines are deduped: one flap is one observation" \
  "$([ "$(wc -l < "$TMP/w3.log" | tr -d ' ')" = 1 ] && [ "$(rg_notready_since "$TMP/w3.log" "$T0")" = 1 ] && echo 1 || echo 0)"
printf 'False %s\n' "$PRE" | rg_node_watch_stamp > "$TMP/w4.log"
ramp_env_stuck="$(printf 'ramp_30_secs=20\nramp_30_oom_host=0\nramp_30_oom_kubesystem=0\nramp_30_notready=%s\nramp_30_ready_final=False\nramp_30_wp_ok=1\nramp_30_marker_ok=1\n' "$(rg_notready_since "$TMP/w4.log" "$T0")")"
printf '%s\n' "$ramp_env_stuck" > "$TMP/stuck.env"
assert "node still False from before the burst is not counted as a flap but fails (b) via the final-Ready check" \
  "$([ "$(rg_ramp_step "$TMP/stuck.env" 30)" = "PASS FAIL PASS PASS" ] && echo 1 || echo 0)"
printf 'True %s\n' "$PRE" | rg_node_watch_stamp > "$TMP/w5.log"
assert "a lastTransitionTime is stamped as its own epoch, not the read time" "$([ "$(cut -d' ' -f1 "$TMP/w5.log")" = "$((T0 - 600))" ] && echo 1 || echo 0)"

printf '1\tburst30\tMEM\t204800\n2\tburst30\tMEM\t102400\n3\tburst30\tkubelet\t1\t1\n4\tburst40\tMEM\t51200\n' > "$TMP/s.tsv"
assert "rg_phase_memmin takes the per-phase minimum in MiB" "$([ "$(rg_phase_memmin "$TMP/s.tsv" burst30)" = 100 ] && echo 1 || echo 0)"
assert "rg_phase_memmin reports - for a phase that never ran" "$([ "$(rg_phase_memmin "$TMP/s.tsv" burst70)" = - ] && echo 1 || echo 0)"

assert "rg_parse_ramp accepts 30,40,50" "$([ "$(rg_parse_ramp 30,40,50)" = "30 40 50" ] && echo 1 || echo 0)"
for bad in "" abc 30,,40 30, ,30 0,10 40,30 30,30 30,x -5; do
  assert "rg_parse_ramp rejects '$bad' (a malformed list must not start an hour-long probe)" "$(rg_parse_ramp "$bad" >/dev/null && echo 0 || echo 1)"
done

ramp_env() {
  printf 'install_ok=1\n'
  local n
  for n in "$@"; do
    case "$n" in
      *:bad) n="${n%:bad}"; printf 'ramp_%s_secs=timeout\nramp_%s_oom_host=0\nramp_%s_oom_kubesystem=0\nramp_%s_notready=1\nramp_%s_ready_final=False\nramp_%s_wp_ok=0\nramp_%s_marker_ok=0\n' "$n" "$n" "$n" "$n" "$n" "$n" "$n" ;;
      *) printf 'ramp_%s_secs=20\nramp_%s_oom_host=0\nramp_%s_oom_kubesystem=0\nramp_%s_notready=0\nramp_%s_ready_final=True\nramp_%s_wp_ok=1\nramp_%s_marker_ok=1\n' "$n" "$n" "$n" "$n" "$n" "$n" "$n" ;;
    esac
  done
}
ramp_env 30 40 50:bad > "$TMP/ramp.env"
out="$(rg_ramp_verdict "$TMP/ramp.env" "30 40 50 60" "$TMP/s.tsv")" && rrc=0 || rrc=$?
assert "ramp candidate is the largest size before the first failure, labelled approximate" \
  "$(echo "$out" | grep -q '^RAMP: candidate N=40 -- approximate (single VM, state carryover)' && [ "$rrc" = 0 ] && echo 1 || echo 0)"
assert "ramp table shows the failed size and the size never run" \
  "$(echo "$out" | grep -E '^50 +PASS +FAIL +FAIL +FAIL' >/dev/null && echo "$out" | grep -q '^60 .*not run' && echo 1 || echo 0)"
assert "ramp summary states webhook-smoke (e) is not evaluated per size" \
  "$(echo "$out" | grep -q '^RAMP: criterion (e) webhook-smoke is NOT evaluated per size' && echo 1 || echo 0)"
assert "ramp summary says stopped at the first criterion failure (50), not VM death" \
  "$(echo "$out" | grep -q '^RAMP: stopped at the first criterion failure (50-pod burst)' && echo 1 || echo 0)"
ramp_env 30 40 > "$TMP/rampd.env"
out="$(rg_ramp_verdict "$TMP/rampd.env" "30 40 50 60" "$TMP/s.tsv")" || true
assert "ramp that ends with sizes unrun and no failure is reported as VM death / cap, not as a criterion failure" \
  "$(echo "$out" | grep -q '^RAMP: ended early with no criterion failure; sizes not run: 50 60' && echo 1 || echo 0)"
ramp_env 30 40 | grep -v '^ramp_40_ready_final=' > "$TMP/rampu.env"
out="$(rg_ramp_verdict "$TMP/rampu.env" "30 40" "$TMP/s.tsv")" || true
assert "ramp step with no node status (API unreachable) is reported as unreachable" \
  "$(echo "$out" | grep -q '^RAMP: API unreachable at the end of the 40-pod step' && echo 1 || echo 0)"
ramp_env 30:bad > "$TMP/ramp0.env"
out="$(rg_ramp_verdict "$TMP/ramp0.env" "30 40" "$TMP/s.tsv")" && rrc=0 || rrc=$?
assert "ramp with a failing first size has no candidate and exits non-zero" "$([ "$rrc" != 0 ] && echo "$out" | grep -q 'no size passed' && echo 1 || echo 0)"
for key in secs oom_host oom_kubesystem notready ready_final wp_ok marker_ok; do
  ramp_env 30 | grep -v "^ramp_30_$key=" > "$TMP/rampm.env"
  assert "ramp step missing ramp_30_$key is not a pass (a step that died midway must not become the candidate)" \
    "$(rg_ramp_step "$TMP/rampm.env" 30 >/dev/null && echo 0 || echo 1)"
done
ramp_env 30 | sed 's/^ramp_30_oom_kubesystem=0/ramp_30_oom_kubesystem=1/' > "$TMP/rampo.env"
assert "ramp step with a kube-system OOM fails criterion (a) only" "$([ "$(rg_ramp_step "$TMP/rampo.env" 30)" = "FAIL PASS PASS PASS" ] && echo 1 || echo 0)"
ramp_env 30 | sed 's/^ramp_30_secs=20/ramp_30_secs=181/' > "$TMP/rampc.env"
assert "ramp step slower than the burst cap fails (c)" "$(BURST_CAP_SECS=180 rg_ramp_step "$TMP/rampc.env" 30 >/dev/null && echo 0 || echo 1)"
printf 'install_ok=0\n' > "$TMP/rampi.env"
assert "ramp with failed install fails" "$(rg_ramp_verdict "$TMP/rampi.env" "30" "$TMP/s.tsv" >/dev/null && echo 0 || echo 1)"

assert "verdict names the gated pod count so release notes can cite it" \
  "$(verdict_of "$TMP/good.env"; echo "$V_OUT" | grep -q '^RESULT: PASS (50-pod burst)' && echo 1 || echo 0)"
verdict_of "$(mutate burst_pods -)"
assert "missing burst_pods fails (c): a verdict that cannot name its pod count is not citable" "$([ "$V_RC" != 0 ] && echo 1 || echo 0)"

# Confirm mode: ceiling is the first size (50, then 40) passing every run.
out="$(rg_confirm_verdict 50:3:3:3)" && crc=0 || crc=$?
assert "50 passes 3/3 -> gated ceiling 50 (the highest tried size wins)" \
  "$([ "$crc" = 0 ] && echo "$out" | grep -q 'gated no-swap burst ceiling = 50 pods' && echo 1 || echo 0)"
out="$(rg_confirm_verdict 50:2:3:3 40:3:3:3)" && crc=0 || crc=$?
assert "50 fails once -> falls to 40 and gates at 40: one flaky run at 50 must not ship a 50-pod claim" \
  "$([ "$crc" = 0 ] && echo "$out" | grep -q 'gated no-swap burst ceiling = 40 pods' && ! echo "$out" | grep -q 'ceiling = 50' && echo 1 || echo 0)"
out="$(rg_confirm_verdict 50:1:3:3 40:2:3:3)" && crc=0 || crc=$?
assert "40 also fails -> FAIL with no ceiling: the release must not claim a burst size it did not confirm" \
  "$([ "$crc" != 0 ] && echo "$out" | grep -q '^CONFIRM: FAIL' && ! echo "$out" | grep -q 'ceiling =' && echo 1 || echo 0)"
rg_confirm_verdict 50:0:0:0 >/dev/null && crc=0 || crc=$?
assert "0/0 runs is not a pass (a gate that ran nothing must not confirm a ceiling)" "$([ "$crc" != 0 ] && echo 1 || echo 0)"
out="$(rg_confirm_verdict 50:2:2:3 40:3:3:3)" && crc=0 || crc=$?
assert "50 ran out of valid runs (noise, no FAIL) -> INVALID exit 3, never falls to 40: noise must not lower the gated ceiling" \
  "$([ "$crc" = 3 ] && echo "$out" | grep -q '^CONFIRM: INVALID' && ! echo "$out" | grep -q 'ceiling =' && echo 1 || echo 0)"
out="$(rg_confirm_verdict 50:1:2:3 40:3:3:3)" && crc=0 || crc=$?
assert "a valid FAIL at 50 is final even when other runs were INVALID -> falls to 40" \
  "$([ "$crc" = 0 ] && echo "$out" | grep -q 'ceiling = 40 pods' && echo 1 || echo 0)"

rc=0; "$HERE/burst-gate.sh" --burst-pods 0 --tarball-dir "$TMP/tb" --out "$TMP/out-bp" >/dev/null 2>&1 || rc=$?
assert "--burst-pods 0 rejected" "$([ "$rc" = 2 ] && echo 1 || echo 0)"
rc=0; "$HERE/burst-gate.sh" --confirm --ramp 30,40 --tarball-dir "$TMP/tb" --out "$TMP/out-bp" >/dev/null 2>&1 || rc=$?
assert "--confirm with --ramp rejected" "$([ "$rc" = 2 ] && echo 1 || echo 0)"

# Ramp/capture flags: malformed lists never reach a VM; valid ones reach the VM env.
for bad in abc 30,30 40,30 30,; do
  : > "$LIMA_CALLS"; rm -rf "$TMP/out-ramp"
  rc=0; "$HERE/burst-gate.sh" --ramp "$bad" --tarball-dir "$TMP/tb" --out "$TMP/out-ramp" >/dev/null 2>&1 || rc=$?
  assert "--ramp '$bad' rejected with exit 2 and zero limactl calls" "$([ "$rc" = 2 ] && [ ! -s "$LIMA_CALLS" ] && echo 1 || echo 0)"
done
rc=0; "$HERE/burst-gate.sh" --probe-kill 0 --tarball-dir "$TMP/tb" --out "$TMP/out-ramp" >/dev/null 2>&1 || rc=$?
assert "--probe-kill 0 rejected (a zero hard-kill would fail every size instantly)" "$([ "$rc" = 2 ] && echo 1 || echo 0)"
: > "$LIMA_CALLS"; rm -rf "$TMP/out-ramp"
"$HERE/burst-gate.sh" --ramp 30,40 --runs 5 --tarball-dir "$TMP/tb" --out "$TMP/out-ramp" >/dev/null 2>&1 || true
assert "--ramp reaches the VM env with the default 180 s probe kill" \
  "$(grep -qx 'RAMP=30,40' "$TMP/out-ramp/stage/gate.env" && grep -qx 'RAMP_KILL_SECS=180' "$TMP/out-ramp/stage/gate.env" && echo 1 || echo 0)"
assert "--ramp uses a single VM regardless of --runs (one install is the point)" "$([ "$(grep -c '^create ' "$LIMA_CALLS")" = 1 ] && echo 1 || echo 0)"
assert "--probe-kill reaches the VM env" "$("$HERE/burst-gate.sh" --ramp 30 --probe-kill 90 --tarball-dir "$TMP/tb" --out "$TMP/out-pk" >/dev/null 2>&1; grep -qx 'RAMP_KILL_SECS=90' "$TMP/out-pk/stage/gate.env" && echo 1 || echo 0)"
assert "vm-capture is off by default (its kubectl probes cost memory on the 1 GiB node)" "$(grep -qx 'CAPTURE=0' "$TMP/out-runs/stage/gate.env" && echo 1 || echo 0)"
"$HERE/burst-gate.sh" --capture --runs 1 --tarball-dir "$TMP/tb" --out "$TMP/out-cap" >/dev/null 2>&1 || true
assert "--capture opts vm-capture in" "$(grep -qx 'CAPTURE=1' "$TMP/out-cap/stage/gate.env" && echo 1 || echo 0)"

assert "default burst is 50 pods, reaching the VM env" "$(grep -qx 'BURST_PODS=50' "$TMP/out-runs/stage/gate.env" && echo 1 || echo 0)"
rm -rf "$TMP/out-conf"
rc=0; out="$("$HERE/burst-gate.sh" --confirm --runs 1 --tarball-dir "$TMP/tb" --out "$TMP/out-conf" 2>/dev/null)" || rc=$?
assert "--confirm with every run failing tries 50 then falls to 40 and ends FAIL (exit non-zero)" \
  "$([ "$rc" != 0 ] && grep -qx 'BURST_PODS=50' "$TMP/out-conf/burst-50/stage/gate.env" && grep -qx 'BURST_PODS=40' "$TMP/out-conf/burst-40/stage/gate.env" && echo "$out" | grep -q '^CONFIRM: FAIL' && echo 1 || echo 0)"

# --- marker (item: criterion (d) false pass) ---
assert "marker read back equal -> ok" "$([ "$(rg_marker_ok rg-1 rg-1)" = 1 ] && echo 1 || echo 0)"
assert "empty read (recreated DB, table missing) -> not ok: the false-PASS path through the installer 302" \
  "$([ "$(rg_marker_ok rg-1 '')" = 0 ] && echo 1 || echo 0)"
assert "empty expected never matches an empty read (failed marker write must not pass)" \
  "$([ "$(rg_marker_ok '' '')" = 0 ] && echo 1 || echo 0)"
assert "a different marker (DB re-seeded by another pod) -> not ok" "$([ "$(rg_marker_ok rg-1 rg-2)" = 0 ] && echo 1 || echo 0)"

# --- vm-gate collectors ---
UIDLIST="$(printf 'kube-system 11-aa\ndefault 22-bb\nkube-flannel 33-cc\nkube-system-extra 44-dd\n' | rg_kubesystem_uids | tr '\n' ' ')"
assert "UID map keeps kube-system and kube-flannel pods only (workload pods must not be classed kube-system)" \
  "$([ "$UIDLIST" = '11-aa 33-cc ' ] && echo 1 || echo 0)"
printf '11-aa\n11-aa\n33-cc\n' > "$TMP/uids.txt"
assert "UID file -> cgroup spelling, deduped (kernel cgroup paths use underscores)" \
  "$([ "$(rg_uids_cgroup "$TMP/uids.txt")" = '11_aa 33_cc ' ] && echo 1 || echo 0)"
printf 'host u7s-apiserver\nhost kubelet\nkube-system coredns\nother php-fpm\nkube-systemx y\n' > "$TMP/victims.txt"
assert "OOM counts: host and kube-system tallied separately, other ignored, prefix lookalikes not counted" \
  "$([ "$(rg_oom_counts < "$TMP/victims.txt")" = '2 1' ] && echo 1 || echo 0)"
assert "OOM counts of an empty victim list are 0 0 (a clean run reports zeros, not blanks)" \
  "$([ "$(rg_oom_counts < /dev/null)" = '0 0' ] && echo 1 || echo 0)"
assert "coredns killed with a UID never recorded (pod died between snapshots / API outage) is still kube-system by comm" \
  "$([ "$(rg_classify_oom coredns /kubepods.slice/kubepods-besteffort-podffff_9999.slice/crio-z.scope '')" = kube-system ] && echo 1 || echo 0)"
assert "an unrecorded workload pod stays other" \
  "$([ "$(rg_classify_oom php-fpm /kubepods.slice/kubepods-besteffort-podffff_9999.slice/crio-z.scope "$UIDS")" = other ] && echo 1 || echo 0)"
out="$({ klog coredns /kubepods.slice/x.slice/crio-a.scope; klog kubelet /system.slice/kubelet.service; } | rg_oom_victims "" | rg_oom_counts)"
assert "kernel log -> victims -> counts end to end with an empty UID map" "$([ "$out" = '1 1' ] && echo 1 || echo 0)"

# --- host contention / INVALID ---
LIST="$(printf 'NAME STATUS SSH\nu7s-rg-1 Running 127.0.0.1:1\nother Running 127.0.0.1:2\nstopped Stopped -\n')"
assert "rg_other_vms excludes the gate's own VM and stopped VMs (own VM was listed as 'running' in host_state end)" \
  "$([ "$(echo "$LIST" | rg_other_vms u7s-rg-1)" = other ] && echo 1 || echo 0)"
assert "rg_other_vms is empty when only the gate's own VM runs" \
  "$([ -z "$(echo "$LIST" | grep -v '^other' | rg_other_vms u7s-rg-1)" ] && echo 1 || echo 0)"
assert "idle % parsed from the LAST top sample (the first is since-boot)" \
  "$([ "$(printf 'CPU usage: 1.0%% user, 1.0%% sys, 98.0%% idle\nCPU usage: 20.1%% user, 10.0%% sys, 69.9%% idle\n' | rg_idle_from_top)" = 69 ] && echo 1 || echo 0)"
assert "idle % parsed from the last vmstat row" \
  "$([ "$(printf 'procs\n r b swpd\n 1 0 0 1 2 3 4 5 6 7 8 9 10 11 99\n 1 0 0 1 2 3 4 5 6 7 8 9 10 11 55\n' | rg_idle_from_vmstat)" = 55 ] && echo 1 || echo 0)"
q="$TMP/q.log"
rg_quiet_line 1 95 0 > "$q"; rg_quiet_line 2 70 0 >> "$q"
assert "quiet log at/above 70% idle with no other VMs -> no reasons (70 is inclusive)" "$([ -z "$(rg_quiet_log_reasons "$q")" ] && echo 1 || echo 0)"
rg_quiet_line 3 69 0 >> "$q"
assert "idle below 70% -> contended (load average is not a usable threshold; idle is)" "$(rg_quiet_log_reasons "$q" | grep -q '69% < 70%' && echo 1 || echo 0)"
rg_quiet_line 1 95 1 > "$q"
assert "another running VM -> contended" "$(rg_quiet_log_reasons "$q" | grep -q 'other Lima VMs' && echo 1 || echo 0)"
rg_quiet_line 1 '' 0 > "$q"
assert "unmeasurable idle -> contended (quiet cannot be proven)" "$(rg_quiet_log_reasons "$q" | grep -q 'not measurable' && echo 1 || echo 0)"
rg_quiet_line 1 95 '' > "$q"
assert "unmeasurable VM list -> contended" "$([ -n "$(rg_quiet_log_reasons "$q")" ] && echo 1 || echo 0)"
assert "missing quiet log -> no reasons (nothing observed)" "$([ -z "$(rg_quiet_log_reasons "$TMP/nonexistent")" ] && echo 1 || echo 0)"
rg_quiet_line 1 95 0 > "$TMP/quiet.log"; rg_quiet_line 1 40 0 > "$TMP/noisy.log"
cal_env() { printf 'cal_ref_ms=%s\ncal_ref_n=%s\ncal_idle_ms=%s\ncal_idle_n=%s\n' "$1" "$2" "$3" "$4" > "$TMP/cal.env"; }
cal_env 100 3 150 3
assert "idle calibration exactly 1.5x the baseline is not contention" "$([ -z "$(rg_cal_reason "$TMP/cal.env")" ] && echo 1 || echo 0)"
cal_env 100 3 151 3
assert "idle calibration over 1.5x the pre-install baseline -> contention reason" "$(rg_cal_reason "$TMP/cal.env" | grep -q '151ms > 1.5x pre-install baseline 100ms' && echo 1 || echo 0)"
cal_env 100 3 400 3
assert "uniform sustained contention (every idle sample slow vs the baseline) is detected; slowest-vs-fastest could not see it" \
  "$([ -n "$(rg_cal_reason "$TMP/cal.env")" ] && echo 1 || echo 0)"
cal_env 100 2 400 3
assert "too few baseline samples -> unmeasured, judges nothing (a missing probe must not launder a FAIL into INVALID)" \
  "$([ -z "$(rg_cal_reason "$TMP/cal.env")" ] && [ -n "$(rg_cal_unmeasured "$TMP/cal.env")" ] && echo 1 || echo 0)"
cal_env 100 3 400 1
assert "too few idle samples (a single slow sample) -> unmeasured, cannot trip INVALID alone" \
  "$([ -z "$(rg_cal_reason "$TMP/cal.env")" ] && [ -n "$(rg_cal_unmeasured "$TMP/cal.env")" ] && echo 1 || echo 0)"
assert "missing calibration data is unmeasured (loudly), not contention" \
  "$([ -z "$(rg_cal_reason "$TMP/empty.env")" ] && [ -n "$(rg_cal_unmeasured "$TMP/empty.env")" ] && echo 1 || echo 0)"
cal_env 100 3 120 3
assert "measured calibration prints no unmeasured note" "$([ -z "$(rg_cal_unmeasured "$TMP/cal.env")" ] && echo 1 || echo 0)"

# Only install (baseline) and idle samples feed the verdict; slow settle samples are u7s's own teardown load.
: > "$TMP/cal.log"
for ms in 100 102 98; do echo "1 install $ms" >> "$TMP/cal.log"; done
for ms in 105 101 99; do echo "2 idle $ms" >> "$TMP/cal.log"; done
for ms in 900 1200 800; do echo "3 settle20 $ms" >> "$TMP/cal.log"; echo "4 settlen $ms" >> "$TMP/cal.log"; done
assert "cal summary of the baseline phase is the median and count" "$([ "$(rg_cal_summary "$TMP/cal.log" install)" = "100 3" ] && echo 1 || echo 0)"
assert "cal summary of the idle phase ignores slow settle-phase samples" "$([ "$(rg_cal_summary "$TMP/cal.log" idle)" = "101 3" ] && echo 1 || echo 0)"
read -r cm cn <<< "$(rg_cal_summary "$TMP/cal.log" install)"; read -r cim cin <<< "$(rg_cal_summary "$TMP/cal.log" idle)"
cal_env "$cm" "$cn" "$cim" "$cin"
assert "settle-phase slowdown after a burst stays FAIL, never INVALID (u7s thrash is the thing under test)" \
  "$([ "$(rg_run_status 1 "$TMP/quiet.log" "$TMP/cal.env")" = FAIL ] && echo 1 || echo 0)"
: > "$TMP/cal-empty.log"
assert "empty cal.log summarises to '- 0' (unmeasured)" "$([ "$(rg_cal_summary "$TMP/cal-empty.log" idle)" = "- 0" ] && echo 1 || echo 0)"
cal_env - 0 - 0
assert "empty cal.log: a real FAIL stays FAIL" "$([ "$(rg_run_status 1 "$TMP/quiet.log" "$TMP/cal.env")" = FAIL ] && echo 1 || echo 0)"

# Gate VM's own load.
assert "VM allowance = vCPUs/host cores (1 of 8 -> 12)" "$([ "$(rg_vm_cpu_allow_pct 1 8)" = 12 ] && echo 1 || echo 0)"
assert "unknown core count -> allowance 0 (stricter)" "$([ "$(rg_vm_cpu_allow_pct 1 '')" = 0 ] && echo 1 || echo 0)"
rg_quiet_line 1 60 0 12 > "$TMP/q-own.log"
assert "idle 60% with a 12% gate-VM allowance is not contention (the gate VM bursting must not make a FAIL INVALID)" \
  "$([ -z "$(rg_quiet_log_reasons "$TMP/q-own.log")" ] && echo 1 || echo 0)"
rg_quiet_line 1 60 0 0 > "$TMP/q-own.log"
assert "same idle with no allowance (pre-flight, no VM) is contention" "$([ -n "$(rg_quiet_log_reasons "$TMP/q-own.log")" ] && echo 1 || echo 0)"
rg_quiet_line 1 40 0 12 > "$TMP/q-own.log"
assert "foreign load beyond the allowance still reads as contention" "$([ -n "$(rg_quiet_log_reasons "$TMP/q-own.log")" ] && echo 1 || echo 0)"

# Marker write failure is a harness error.
printf 'harness_error=marker write to MariaDB failed before the bursts\n' > "$TMP/harness.env"
assert "harness error on a quiet host -> INVALID, not FAIL (the harness broke, not u7s)" \
  "$([ "$(rg_run_status 1 "$TMP/quiet.log" "$TMP/harness.env")" = INVALID ] && echo 1 || echo 0)"
assert "a failed marker READ after the bursts (marker_ok=0, no harness error) stays FAIL" \
  "$([ "$(rg_run_status 1 "$TMP/quiet.log" "$(mutate marker_ok 0)")" = FAIL ] && echo 1 || echo 0)"

# Quiet loop waits for the in-flight sample.
slow_sample() { sleep 2; echo sampled >> "$1"; }
rm -f "$TMP/qloop.stop" "$TMP/qloop.log"
rg_quiet_loop "$TMP/qloop.stop" "$TMP/qloop.log" 0 slow_sample &
qpid=$!
sleep 1; touch "$TMP/qloop.stop"; wait "$qpid"
assert "stopping the quiet loop waits for the in-flight sample so the verdict reads a complete quiet.log" \
  "$([ "$(cat "$TMP/qloop.log" 2>/dev/null)" = sampled ] && echo 1 || echo 0)"
assert "PASS under contention stays PASS (a green run on a noisy host is still evidence u7s survives)" \
  "$([ "$(rg_run_status 0 "$TMP/noisy.log" "$TMP/empty.env")" = PASS ] && echo 1 || echo 0)"
assert "FAIL under contention -> INVALID (the failure cannot be blamed on u7s)" \
  "$([ "$(rg_run_status 1 "$TMP/noisy.log" "$TMP/empty.env")" = INVALID ] && echo 1 || echo 0)"
assert "FAIL on a quiet host stays FAIL" "$([ "$(rg_run_status 1 "$TMP/quiet.log" "$TMP/empty.env")" = FAIL ] && echo 1 || echo 0)"
cal_env 100 3 400 3
assert "FAIL with a slow idle-boundary calibration on a quiet-looking host -> INVALID (steal the host probe missed)" \
  "$([ "$(rg_run_status 1 "$TMP/quiet.log" "$TMP/cal.env")" = INVALID ] && echo 1 || echo 0)"

# --- watchdog kills the in-VM workload ---
for cmd in 'bash /var/tmp/rg/vm-gate.sh' 'bash /var/tmp/rg/vm-sampler.sh /var/tmp/rg/out 5' 'bash /var/tmp/rg/webhook-smoke.sh --kubeconfig x' 'bash /var/tmp/rg/install.sh'; do
  assert "kill pattern matches '$cmd' (a surviving in-VM workload keeps loading the host after the cap)" \
    "$(echo "$cmd" | grep -qE "$RG_VM_KILL_PATTERN" && echo 1 || echo 0)"
done
for cmd in 'bash -c sudo pkill -KILL -f ^bash /var/tmp/rg/vm-gate.sh' 'pkill -KILL -f x /var/tmp/rg/vm-gate.sh' 'kubectl get node'; do
  assert "kill pattern does not match '$cmd' (the killer must not kill itself or unrelated processes)" \
    "$(echo "$cmd" | grep -qE "$RG_VM_KILL_PATTERN" && echo 0 || echo 1)"
done

# --- forced failure must fail in the burst, not the install ---
good | sed 's/^burst_secs=.*/burst_secs=timeout/' > "$TMP/ff-burst.env"
printf 'burst20\n' > "$TMP/ph-burst"; printf 'idle\n' > "$TMP/ph-idle"
assert "forced failure that failed (c) in the burst phase -> OK" \
  "$(rg_forced_failure_check "$TMP/ff-burst.env" "$TMP/ph-burst" >/dev/null && echo 1 || echo 0)"
assert "forced failure that never left the idle phase is NOT OK (it proved nothing about the burst)" \
  "$(rg_forced_failure_check "$TMP/ff-burst.env" "$TMP/ph-idle" >/dev/null && echo 0 || echo 1)"
assert "forced failure with a failed install is NOT OK (the earlier 640 MiB run died in tar, not in the burst)" \
  "$(good | sed 's/^install_ok=.*/install_ok=0/' > "$TMP/ff-inst.env"; rg_forced_failure_check "$TMP/ff-inst.env" "$TMP/ph-burst" >/dev/null && echo 0 || echo 1)"
assert "forced failure whose run passed is NOT OK (the gate failed to fail)" \
  "$(rg_forced_failure_check "$TMP/good.env" "$TMP/ph-burst" >/dev/null && echo 0 || echo 1)"
assert "forced failure failing only (e) webhook is NOT OK (not a burst/OOM criterion)" \
  "$(good | sed 's/^webhook_ok=.*/webhook_ok=0/' > "$TMP/ff-wh.env"; rg_forced_failure_check "$TMP/ff-wh.env" "$TMP/ph-burst" >/dev/null && echo 0 || echo 1)"

# --- burst-gate.sh end to end with stubs ---
assert "--mem-hog-mib reaches the VM env" "$("$HERE/burst-gate.sh" --runs 1 --mem-hog-mib 400 --tarball-dir "$TMP/tb" --out "$TMP/out-hog" >/dev/null 2>&1; grep -qx 'HOG_MIB=400' "$TMP/out-hog/stage/gate.env" && echo 1 || echo 0)"
assert "HOG_MIB defaults to 0" "$(grep -qx 'HOG_MIB=0' "$TMP/out-runs/stage/gate.env" && echo 1 || echo 0)"
rc=0; "$HERE/burst-gate.sh" --mem-hog-mib x --tarball-dir "$TMP/tb" --out "$TMP/out-bad" >/dev/null 2>&1 || rc=$?
assert "--mem-hog-mib x rejected with exit 2" "$([ "$rc" = 2 ] && echo 1 || echo 0)"

printf '#!/bin/sh\necho 30\n' > "$TMP/bin/idle30"; chmod +x "$TMP/bin/idle30"
: > "$LIMA_CALLS"; rm -rf "$TMP/out-noisy"
rc=0; RG_IDLE_PROBE="$TMP/bin/idle30" "$HERE/burst-gate.sh" --runs 2 --tarball-dir "$TMP/tb" --out "$TMP/out-noisy" >/dev/null 2>&1 || rc=$?
assert "noisy host at pre-flight: exit 3 INVALID, no VM created (a noisy host must neither pass nor fail the release)" \
  "$([ "$rc" = 3 ] && ! grep -q '^create ' "$LIMA_CALLS" && [ "$(cat "$TMP/out-noisy/valid")" = 0 ] && [ "$(cat "$TMP/out-noisy/passed")" = 0 ] && echo 1 || echo 0)"
assert "INVALID attempts are retried up to MAX_INVALID_RUNS (3) and never counted toward RUNS" \
  "$([ "$(ls -d "$TMP"/out-noisy/run-* | wc -l | tr -d ' ')" = 3 ] && echo 1 || echo 0)"
: > "$LIMA_CALLS"; rm -rf "$TMP/out-quiet"
rc=0; "$HERE/burst-gate.sh" --runs 1 --tarball-dir "$TMP/tb" --out "$TMP/out-quiet" >/dev/null 2>&1 || rc=$?
assert "quiet host + VM that cannot start -> FAIL exit 1 (not INVALID: no contention was observed)" \
  "$([ "$rc" = 1 ] && [ "$(cat "$TMP/out-quiet/valid")" = 1 ] && echo 1 || echo 0)"
rm -rf "$TMP/out-conf2"
rc=0; out="$(RG_IDLE_PROBE="$TMP/bin/idle30" "$HERE/burst-gate.sh" --confirm --runs 1 --tarball-dir "$TMP/tb" --out "$TMP/out-conf2" 2>/dev/null)" || rc=$?
assert "--confirm on a noisy host: INVALID exit 3, and it never falls through to 40 pods" \
  "$([ "$rc" = 3 ] && echo "$out" | grep -q '^CONFIRM: INVALID' && [ ! -e "$TMP/out-conf2/burst-40" ] && echo 1 || echo 0)"

echo "---- $PASS passed, $FAIL failed ----"
[ "$FAIL" = 0 ]

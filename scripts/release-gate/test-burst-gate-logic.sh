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
: > "$TMP/tb/u7s-gate-test.tar.gz"
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

for n in 0 2; do
  rm -rf "$TMP/tb$n" "$TMP/out-tb$n"; mkdir -p "$TMP/tb$n"
  i=0; while [ "$i" -lt "$n" ]; do i=$((i + 1)); : > "$TMP/tb$n/u7s-gate-$i.tar.gz"; done
  rc=0; err="$("$HERE/burst-gate.sh" --runs 1 --tarball-dir "$TMP/tb$n" --out "$TMP/out-tb$n" 2>&1 >/dev/null)" || rc=$?
  assert "$n staged gate tarballs -> exit 2 naming the stage dir and count (an ambiguous or missing gate tarball must stop the run, not install the wrong build)" \
    "$([ "$rc" = 2 ] && echo "$err" | grep -q "exactly one u7s-gate-\*.tar.gz in $TMP/out-tb$n/stage, found $n" && echo 1 || echo 0)"
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
rg_ramp_verdict "$TMP/ramp.env" "30 40 50 60" "$TMP/s.tsv" > "$TMP/ramp.verdict" || true
assert "ramp knee is read from the verdict (40), so the summary can report where the node broke" \
  "$([ "$(rg_ramp_knee "$TMP/ramp.verdict")" = 40 ] && echo 1 || echo 0)"
out="$(rg_ramp_summary "30 40 50 60" " $(rg_ramp_knee "$TMP/ramp.verdict")" PASS /o)"
assert "ramp summary reports the knee and never 'passed at <max> pods' for a run that broke at 50 (operators read this line as the result)" \
  "$(echo "$out" | grep -q 'knee.*: 40 ' && ! echo "$out" | grep -qE 'passed at [0-9]+ pods' && echo 1 || echo 0)"
rg_ramp_verdict "$TMP/ramp0.env" "30 40" "$TMP/s.tsv" > "$TMP/ramp0.verdict" || true
assert "ramp with no passing step has knee none" "$([ "$(rg_ramp_knee "$TMP/ramp0.verdict")" = none ] && echo 1 || echo 0)"
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

assert "default burst is 20 pods, reaching the VM env: the operator-decided gate size must not drift to a size a 1 GiB node cannot hold" "$(grep -qx 'BURST_PODS=20' "$TMP/out-runs/stage/gate.env" && echo 1 || echo 0)"
rm -rf "$TMP/out-conf"
rc=0; out="$("$HERE/burst-gate.sh" --confirm --runs 1 --tarball-dir "$TMP/tb" --out "$TMP/out-conf" 2>/dev/null)" || rc=$?
assert "--confirm is a single 3/3 gate at 20 pods with no smaller fall-back size, and a failing gate ends FAIL" \
  "$([ "$rc" != 0 ] && grep -qx 'BURST_PODS=20' "$TMP/out-conf/burst-20/stage/gate.env" && [ "$(ls -d "$TMP"/out-conf/burst-* | wc -l)" -eq 1 ] && echo "$out" | grep -q '^CONFIRM: FAIL' && echo 1 || echo 0)"

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

# Idle judged only before the gate's own load starts (load_t0): the thrashing guest's hypervisor
# disk reads cost host cores that are not a neighbour.
Q="$TMP/q-phase.log"; : > "$Q"
for t in 100 130 160; do rg_quiet_line "$t" 80 0 8 >> "$Q"; done
for t in 190 220 250; do rg_quiet_line "$t" 48 0 8 >> "$Q"; done
printf 'load_t0=170\n' > "$TMP/lt.env"
assert "idle dropping only after load_t0 with no other VMs is VALID: the gate VM's own hypervisor disk-read load must not make overload runs INVALID" \
  "$([ -z "$(rg_contention_reasons "$Q" "$TMP/lt.env")" ] && echo 1 || echo 0)"
assert "without load_t0 (VM died before the load began) the same log is judged in full" \
  "$([ -n "$(rg_contention_reasons "$Q" "$TMP/empty.env")" ] && echo 1 || echo 0)"
: > "$Q"
rg_quiet_line 100 55 0 8 >> "$Q"; rg_quiet_line 190 80 0 8 >> "$Q"
assert "foreign load before load_t0 is still INVALID" \
  "$([ -n "$(rg_contention_reasons "$Q" "$TMP/lt.env")" ] && echo 1 || echo 0)"
: > "$Q"
rg_quiet_line 100 80 0 8 >> "$Q"; rg_quiet_line 190 48 1 8 >> "$Q"
assert "another Lima VM starting during the bursts is still INVALID (only the idle floor is waived after load_t0)" \
  "$([ -n "$(rg_contention_reasons "$Q" "$TMP/lt.env")" ] && echo 1 || echo 0)"

# Marker write failure is a harness error.
# The vm-gate call site: fake `k` answers the two failure-time probes (API_MODE, POD_MODE).
k() {
  if [ "$1" = get ]; then   # /readyz
    case "$API_MODE" in
      ok) echo ok; return 0 ;;
      unhealthy) echo 'Error from server (InternalError): an error on the server ("[-]etcd failed") has prevented the request from succeeding' >&2; return 1 ;;
      down) echo 'The connection to the server 127.0.0.1:6443 was refused' >&2; return 1 ;;
      cmderr) echo 'error: stat /nonexistent: no such file or directory' >&2; return 1 ;;
    esac
  else
    case "$POD_MODE" in
      True) echo True; return 0 ;;
      False) echo False; return 0 ;;
      cmderr) echo 'error: stat /nonexistent: no such file or directory' >&2; return 1 ;;
    esac
  fi
}
marker_case() { # name was_ready api_mode pod_mode expected-status expected-reason-substring why
  : > "$TMP/$1.env"
  API_MODE="$3" POD_MODE="$4" rg_probe_and_record_marker_failure "$TMP/$1.env" "$2" 2>/dev/null
  assert "$7" "$([ "$(rg_run_status 1 "$TMP/quiet.log" "$TMP/$1.env")" = "$5" ] && echo 1 || echo 0)"
  verdict_of "$TMP/$1.env"
  assert "$1: reports its reason ($6)" "$([[ "$V_OUT$(rg_get "$TMP/$1.env" harness_error)" == *"$6"* ]] && echo 1 || echo 0)"
}
marker_case harness 1 ok True INVALID "mariadb-0 is Ready and the API answers" \
  "marker write fails with mariadb-0 Ready and API up -> INVALID (the harness broke, not u7s)"
marker_case nopod 0 ok False FAIL "never became Ready" \
  "mariadb-0 never Ready -> FAIL, a pod-start regression must not be laundered into INVALID"
marker_case unready 1 ok False FAIL "became not Ready" \
  "mariadb-0 Ready at the wait but not at write time -> FAIL (re-probed, not the stale snapshot)"
marker_case apidown 1 down True FAIL "API unreachable" \
  "API unreachable after marker write failure -> FAIL, not INVALID"
marker_case apibad 1 unhealthy True FAIL "answered /readyz with an error" \
  "API answering unhealthy (non-2xx) -> FAIL with its own reason, distinct from unreachable"
marker_case cmderr 1 cmderr cmderr INVALID "probe command errored" \
  "kubectl command error (bad kubeconfig) -> INVALID: the harness broke, nothing says u7s failed"
marker_case podgone 1 cmderr False FAIL "became not Ready" \
  "a probe command error never hides a u7s failure seen by the other probe -> FAIL"
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
assert "PASS under contention -> INVALID (validity must not depend on outcome, or only failures get discarded and A/B arms are biased)" \
  "$([ "$(rg_run_status 0 "$TMP/noisy.log" "$TMP/empty.env")" = INVALID ] && echo 1 || echo 0)"
assert "FAIL under contention -> INVALID (the failure cannot be blamed on u7s)" \
  "$([ "$(rg_run_status 1 "$TMP/noisy.log" "$TMP/empty.env")" = INVALID ] && echo 1 || echo 0)"
assert "PASS on a quiet host stays PASS (the contention rule must not discard clean passes)" \
  "$([ "$(rg_run_status 0 "$TMP/quiet.log" "$TMP/empty.env")" = PASS ] && echo 1 || echo 0)"
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

# --- overload recovery metric ---
rl() { printf '%s\n' "$@" > "$TMP/rec.log"; rg_recovery_secs "$TMP/rec.log" 1000 120 15; }
assert "recovery is the start of the first all-OK streak held for the hold time (a brief OK during the thrash is not recovery)" \
  "$({ echo '1010 0'; echo '1020 1'; echo '1030 0'; for t in $(seq 1040 10 1160); do echo "$t 1"; done; } > "$TMP/rec.log"; [ "$(rg_recovery_secs "$TMP/rec.log" 1000 120 15)" = 40 ] && echo 1 || echo 0)"
assert "an OK streak shorter than the hold is not recovered" \
  "$([ "$(rl '1010 0' '1020 1' '1100 1' '1130 1')" = none ] && echo 1 || echo 0)"
assert "a probe gap above the max gap breaks the streak (an unobserved freeze is not held health)" \
  "$([ "$(rl '1010 1' '1200 1')" = none ] && echo 1 || echo 0)"
assert "a freeze bracketed by two OK probes is not 'held 120 s'; the streak restarts after it" \
  "$({ echo '1010 1'; for t in $(seq 1140 10 1270); do echo "$t 1"; done; } > "$TMP/rec.log"; [ "$(rg_recovery_secs "$TMP/rec.log" 1000 120 15)" = 140 ] && echo 1 || echo 0)"
assert "probes within the max gap keep a streak (slow-but-answering probes still count)" \
  "$({ for t in $(seq 1010 15 1130); do echo "$t 1"; done; } > "$TMP/rec.log"; [ "$(rg_recovery_secs "$TMP/rec.log" 1000 120 15)" = 10 ] && echo 1 || echo 0)"
assert "no probes at all is not recovered" "$([ "$(rl)" = none ] && echo 1 || echo 0)"
assert "a worst-case probe cycle (3 calls all timing out) fits the max gap: otherwise a starved-but-alive node can never be observed recovering" \
  "$([ $((3 * RG_PROBE_TIMEOUT)) -le "$RG_PROBE_MAX_GAP" ] && echo 1 || echo 0)"
assert "a slow-but-alive node answering every ~12 s (worst bounded cycle) is observed recovering" \
  "$({ for t in $(seq 1012 $((3 * RG_PROBE_TIMEOUT)) 1180); do echo "$t 1"; done; } > "$TMP/rec.log"; [ "$(rg_recovery_secs "$TMP/rec.log" 1000 120 "$RG_PROBE_MAX_GAP")" = 12 ] && echo 1 || echo 0)"
PL="$TMP/probes.log"; : > "$PL"
rc=0; rg_probe_step "$PL" node bash -c 'sleep 1; exit 3' || rc=$?
assert "a probe step returns the probe's status and logs '<epoch> <name> <rc> <secs>' (slow probes must be visible after a run)" \
  "$([ "$rc" = 3 ] && awk '$2 == "node" && $3 == 3 && $4 >= 1 && $1 > 1000000000 { f = 1 } END { exit !f }' "$PL" && echo 1 || echo 0)"
rc=0; rg_probe_step "$PL" readyz true || rc=$?
assert "a passing probe step logs rc 0" "$([ "$rc" = 0 ] && tail -n 1 "$PL" | awk '$2 == "readyz" && $3 == 0 { f = 1 } END { exit !f }' && echo 1 || echo 0)"
PT="$TMP/pt.rec"; : > "$PT"
# shellcheck disable=SC2329
k() { echo "k ${K_TIMEOUT-unset}" >> "$PT"; case "$*" in "get node"*) echo True ;; esac; }
# shellcheck disable=SC2329
wp_code() { echo "wp ${WP_TIMEOUT-unset}" >> "$PT"; echo 200; }
NODE=n1; rc=0; rg_probe_cycle "$TMP/pc.log" 0 || rc=$?
assert "every probe call in a cycle carries RG_PROBE_TIMEOUT: an unbounded call lets one hung API server stretch the cycle past the max gap so recovery is never observed" \
  "$([ "$rc" = 0 ] && [ "$(sort "$PT" | uniq -c | tr -s ' ' | tr '\n' ';')" = " 2 k $RG_PROBE_TIMEOUT; 1 wp $RG_PROBE_TIMEOUT;" ] && echo 1 || echo 0)"
unset -f k wp_code
good > "$TMP/ov.env"
printf 'overload_pods=40\noverload_mib=60\nrecovery_hold_secs=120\noverload_window_secs=420\noverload_final=node=True overload-pods: Running=30 restarts=12\nrecovery_secs=95\n' >> "$TMP/ov.env"
assert "overload verdict is RECOVERED with exit 0 when the recovery metric is numeric" \
  "$(rg_overload_verdict "$TMP/ov.env" | grep -q 'RECOVERED 95s after overload start (40 pods x 60 MiB)' && echo 1 || echo 0)"
{ grep -v '^recovery_secs=' "$TMP/ov.env"; echo recovery_secs=none; } > "$TMP/ov2.env"; mv "$TMP/ov2.env" "$TMP/ov.env"
assert "overload verdict is NOT RECOVERED with non-zero exit, naming the final pod state" \
  "$(rg_overload_verdict "$TMP/ov.env" > "$TMP/ov.out"; rc=$?; [ "$rc" != 0 ] && grep -q 'NOT RECOVERED.*Running=30 restarts=12' "$TMP/ov.out" && echo 1 || echo 0)"
assert "overload args: pods without mib is refused (an allocator of 0 MiB is not an overload)" "$([ -n "$(rg_overload_args_error 40 0 0 '' 0 420)" ] && echo 1 || echo 0)"
assert "overload args: --no-workload without an overload is refused" "$([ -n "$(rg_overload_args_error 0 0 1 '' 0 420)" ] && echo 1 || echo 0)"
assert "overload args: overload plus --ramp is refused" "$([ -n "$(rg_overload_args_error 40 60 0 30,40 0 420)" ] && echo 1 || echo 0)"
assert "overload args: valid combination is accepted" "$([ -z "$(rg_overload_args_error 40 60 1 '' 0 420)" ] && echo 1 || echo 0)"

# --- vm-sampler.sh attribution records ---
SR="$TMP/sroot"; SO="$TMP/sout"
mkdir -p "$SR/proc/pressure" "$SR/proc/42" "$SR/sys/fs/cgroup/init.scope" "$SR/sys/fs/cgroup/system.slice/snapd.service" "$SR/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice" "$SO"
echo wordpress > "$SO/phase"
echo 'some avg10=72.00 avg60=50.00 avg300=20.00 total=123456' > "$SR/proc/pressure/io"
printf 'some avg10=0.00 avg60=0.00 avg300=0.00 total=7\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=5\n' > "$SR/proc/pressure/cpu"
echo 'some avg10=0.00 avg60=0.00 avg300=0.00 total=1' > "$SR/proc/pressure/memory"
echo 'cpu  100 5 50 1000 300 0 0 40 0 0' > "$SR/proc/stat"
printf '   8       0 sda 111 0 2222 0 333 0 4444 0 0 555 0\n   8       1 sda1 1 0 2 0 3 0 4 0 0 5 0\n   7       0 loop0 9 0 9 0 9 0 9 0 0 9 0\n' > "$SR/proc/diskstats"
printf '%s\n' 'MemAvailable:   500000 kB' 'AnonPages:   111 kB' 'Active(file):   222 kB' 'Inactive(file):   333 kB' 'Slab:   444 kB' \
  'SReclaimable:   400 kB' 'SUnreclaim:   44 kB' 'PageTables:   555 kB' 'KernelStack:   66 kB' 'Shmem:   77 kB' 'Cached:   9999 kB' > "$SR/proc/meminfo"
echo '42 (my proc) S 1 1 1 0 -1 0 0 0 0 0 70 30 5 0 20 0 1 0 1 0 0' > "$SR/proc/42/stat"
mkdir -p "$SR/proc/50" "$SR/proc/51" "$SR/proc/52" "$SR/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc.slice"
echo conmon > "$SR/proc/50/comm"; echo conmon > "$SR/proc/51/comm"; echo sshd > "$SR/proc/52/comm"
printf 'Pss:   100 kB\nRss:   200 kB\nPss_Anon:   30 kB\nPss_File:   60 kB\n' > "$SR/proc/50/smaps_rollup"
printf 'Pss:   10 kB\nRss:   20 kB\nPss_Anon:   3 kB\nPss_File:   6 kB\n' > "$SR/proc/51/smaps_rollup"
printf 'Pss:   9999 kB\nRss:   9999 kB\nPss_Anon:   9999 kB\nPss_File:   9999 kB\n' > "$SR/proc/52/smaps_rollup"
printf 'anon 4096\nfile 8192\nslab 1024\nworkingset_refault_file 321\nworkingset_refault_anon 9\n' > "$SR/sys/fs/cgroup/system.slice/snapd.service/memory.stat"
printf 'some avg10=0.00 avg60=0.00 avg300=0.00 total=700\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=600\n' > "$SR/sys/fs/cgroup/system.slice/snapd.service/memory.pressure"
printf 'anon 1\nfile 2\nslab 3\nworkingset_refault_file 4\n' > "$SR/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc.slice/memory.stat"
printf 'some avg10=0.00 avg60=0.00 avg300=0.00 total=8\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=7\n' > "$SR/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc.slice/memory.pressure"
printf 'rchar: 1\nwchar: 2\nread_bytes: 8192\nwrite_bytes: 4096\n' > "$SR/proc/42/io"
printf 'usage_usec 5000000\nthrottled_usec 250\n' > "$SR/sys/fs/cgroup/system.slice/snapd.service/cpu.stat"
printf '8:0 rbytes=1000 wbytes=2000 rios=3 wios=4 dbytes=0 dios=0\n' > "$SR/sys/fs/cgroup/system.slice/snapd.service/io.stat"
printf 'usage_usec 900\nthrottled_usec 800\n' > "$SR/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/cpu.stat"
printf 'usage_usec 42\nthrottled_usec 0\n' > "$SR/sys/fs/cgroup/init.scope/cpu.stat"
printf 'oom_kill 3\npgfault 9\npgmajfault 77\nworkingset_refault_file 1234\nworkingset_refault_anon 55\npgscan_kswapd 600\npgscan_direct 70\npgsteal_kswapd 500\npgsteal_direct 60\nworkingset_refault 1289\n' > "$SR/proc/vmstat"
echo 123456789 > "$SR/sys/fs/cgroup/system.slice/snapd.service/memory.current"
echo 987654321 > "$SR/sys/fs/cgroup/kubepods.slice/memory.current"
SAMPLER_ROOT="$SR" SAMPLER_SELF=42 SAMPLER_ONCE=1 bash "$HERE/vm-sampler.sh" "$SO" 1 >/dev/null 2>&1
SO3="$TMP/sout3"; mkdir -p "$SO3"; echo burstn > "$SO3/phase"
SAMPLER_ROOT="$SR" bash "$HERE/vm-sampler.sh" "$SO3" 1000 >/dev/null 2>&1 & sp3=$!
sleep 5; kill "$sp3" 2>/dev/null || true; wait "$sp3" 2>/dev/null || true
SO2="$TMP/sout2"; mkdir -p "$SO2"
SAMPLER_ROOT="$SR" SAMPLER_ONCE=1 SAMPLER_PROC_INTERVAL=100000000000 bash "$HERE/vm-sampler.sh" "$SO2" 1 >/dev/null 2>&1
attrib_has() { awk -F'\t' -v w="$1" '{l=$3; for (i=4;i<=NF;i++) l=l "\t" $i; if (l == w && $2 == "wordpress") f=1} END {exit !f}' "$SO/attrib.tsv"; }
assert "sampler records io PSI total (the 72% io stall was previously only hand-read)" "$(attrib_has "$(printf 'PSI\tio\t123456\t0')" && echo 1 || echo 0)"
assert "sampler records cpu PSI some and full totals" "$(attrib_has "$(printf 'PSI\tcpu\t7\t5')" && echo 1 || echo 0)"
assert "sampler records /proc/stat steal and iowait (separates platform steal from our load)" "$(attrib_has "$(printf 'STAT\t105\t50\t300\t40')" && echo 1 || echo 0)"
assert "sampler records boot-disk sectors and ops but not partitions/loop devices" \
  "$(attrib_has "$(printf 'DISK\tsda\t111\t2222\t333\t4444\t555')" && ! grep -qE 'DISK.sda1|DISK.loop' "$SO/attrib.tsv" && echo 1 || echo 0)"
assert "sampler attributes CPU and throttling to each system.slice unit" "$(attrib_has "$(printf 'CG\t/system.slice/snapd.service\t5000000\t250')" && echo 1 || echo 0)"
assert "sampler attributes IO bytes/ops to each system.slice unit" "$(attrib_has "$(printf 'CGIO\t/system.slice/snapd.service\t1000\t2000\t3\t4')" && echo 1 || echo 0)"
assert "sampler attributes CPU to kubepods sub-slices" "$(attrib_has "$(printf 'CG\t/kubepods.slice/kubepods-burstable.slice\t900\t800')" && echo 1 || echo 0)"
assert "sampler attributes CPU to init.scope (PID 1 work is otherwise missing from the per-cgroup sum)" "$(attrib_has "$(printf 'CG\t/init.scope\t42\t0')" && echo 1 || echo 0)"
assert "sampler records per-process CPU ticks and read/write bytes with spaces in comm" "$(attrib_has "$(printf 'PROC\t42\tmy proc\t100\t8192\t4096')" && echo 1 || echo 0)"
assert "per-pid walk is skipped between PROC intervals while PSI still sampled (per-pid cost must not run inside the gate's measured window every 5 s)" \
  "$(! grep -q "PROC" "$SO2/attrib.tsv" && grep -q "PSI.io" "$SO2/attrib.tsv" && echo 1 || echo 0)"
assert "sampler records file/anon refault counters (the only way to tell page-cache thrash from pull I/O)" \
  "$(attrib_has "$(printf 'VM\tworkingset_refault_file\t1234')" && attrib_has "$(printf 'VM\tworkingset_refault_anon\t55')" && echo 1 || echo 0)"
assert "sampler records pgmajfault and pgscan/pgsteal per reclaimer but not unrelated vmstat counters" \
  "$(attrib_has "$(printf 'VM\tpgmajfault\t77')" && attrib_has "$(printf 'VM\tpgscan_direct\t70')" && attrib_has "$(printf 'VM\tpgsteal_kswapd\t500')" && ! grep -qE 'VM.(pgfault|workingset_refault)	' "$SO/attrib.tsv" && echo 1 || echo 0)"
assert "sampler records memory.current of system.slice units and kubepods.slice (who holds the memory)" \
  "$(attrib_has "$(printf 'CGMEM\t/system.slice/snapd.service\t123456789')" && attrib_has "$(printf 'CGMEM\t/kubepods.slice\t987654321')" && echo 1 || echo 0)"
assert "sampler still writes MemAvailable to samples.tsv (the gate verdict reads it)" "$(grep -q "MEM.500000" "$SO/samples.tsv" && echo 1 || echo 0)"
assert "sampler splits the MemAvailable drop into anon/file/slab/pagetables/kstack/shmem (PSS alone cannot tell anon growth from file eviction)" \
  "$(attrib_has "$(printf 'MEMI\t111\t222\t333\t444\t400\t44\t555\t66\t77\t500000')" && echo 1 || echo 0)"
assert "sampler sums Pss_Anon and Pss_File over all pids of a component and ignores other comms" \
  "$(grep -q "$(printf 'wordpress\tconmon\t110\t220\t33\t66$')" "$SO/samples.tsv" && ! grep -q 9999 "$SO/samples.tsv" && echo 1 || echo 0)"
assert "sampler records per-cgroup anon/file/slab and refault_file (which cgroup is being evicted)" \
  "$(attrib_has "$(printf 'CGSTAT\t/system.slice/snapd.service\t4096\t8192\t1024\t321')" && attrib_has "$(printf 'CGSTAT\t/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc.slice\t1\t2\t3\t4')" && echo 1 || echo 0)"
assert "sampler records per-cgroup memory PSI some/full for system.slice units and kubepods pod slices" \
  "$(attrib_has "$(printf 'CGPSI\t/system.slice/snapd.service\t700\t600')" && attrib_has "$(printf 'CGPSI\t/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc.slice\t8\t7')" && echo 1 || echo 0)"
assert "sampler records the kernel oom_kill counter (OOM events during the run)" "$(attrib_has "$(printf 'VM\toom_kill\t3')" && echo 1 || echo 0)"
assert "sampler records its own CPU jiffies including reaped children (the probe must not hide its cost on 1 vCPU)" "$(attrib_has "$(printf 'SELF\t105')" && echo 1 || echo 0)"
assert "meminfo is sampled every 2 s in a burst phase even when the full sample interval is long" \
  "$([ "$(grep -c "MEMI" "$SO3/attrib.tsv")" -ge 3 ] && [ "$(grep -c "PSI.io" "$SO3/attrib.tsv")" = 1 ] && echo 1 || echo 0)"

oomev="$(printf '%s\n' 'Nov 05 kernel: Out of memory: Killed process 4242 (rg-alloc) total-vm:60000kB, anon-rss:51200kB, file-rss:100kB, shmem-rss:0kB, UID:0 pgtables:200kB oom_score_adj:1000' 'Nov 05 kernel: Killed process 77 (u7s-apiserver) total-vm:1kB, anon-rss:9kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:2kB oom_score_adj:0' 'unrelated line' | rg_oom_events)"
assert "OOM events carry victim comm, oom_score_adj and anon rss (shows whether the killer picked the overload or the control plane)" \
  "$([ "$oomev" = "$(printf 'rg-alloc 1000 51200\nu7s-apiserver 0 9')" ] && echo 1 || echo 0)"

# --- burst-gate.sh end to end with stubs ---
assert "--overload-pods/--overload-mib/--no-workload reach the VM env" "$("$HERE/burst-gate.sh" --runs 1 --overload-pods 40 --overload-mib 60 --no-workload --tarball-dir "$TMP/tb" --out "$TMP/out-ov" >/dev/null 2>&1; grep -qx 'OVERLOAD_PODS=40' "$TMP/out-ov/stage/gate.env" && grep -qx 'OVERLOAD_MIB=60' "$TMP/out-ov/stage/gate.env" && grep -qx 'NO_WORKLOAD=1' "$TMP/out-ov/stage/gate.env" && echo 1 || echo 0)"
assert "OVERLOAD_PODS defaults to 0 (a normal gate run must not overload)" "$(grep -qx 'OVERLOAD_PODS=0' "$TMP/out-runs/stage/gate.env" && echo 1 || echo 0)"
rc=0; "$HERE/burst-gate.sh" --overload-pods 40 --tarball-dir "$TMP/tb" --out "$TMP/out-bad" >/dev/null 2>&1 || rc=$?
assert "--overload-pods without --overload-mib rejected with exit 2" "$([ "$rc" = 2 ] && echo 1 || echo 0)"
rc=0; "$HERE/burst-gate.sh" --mem-hog-mib 400 --tarball-dir "$TMP/tb" --out "$TMP/out-bad" >/dev/null 2>&1 || rc=$?
assert "the unkillable tmpfs --mem-hog-mib is gone (it produced a harness-artefact wedge)" "$([ "$rc" = 2 ] && echo 1 || echo 0)"

printf '#!/bin/sh\necho 30\n' > "$TMP/bin/idle30"; chmod +x "$TMP/bin/idle30"
: > "$LIMA_CALLS"; rm -rf "$TMP/out-noisy"
rc=0; RG_IDLE_PROBE="$TMP/bin/idle30" "$HERE/burst-gate.sh" --runs 2 --tarball-dir "$TMP/tb" --out "$TMP/out-noisy" >/dev/null 2>&1 || rc=$?
assert "noisy host at pre-flight: exit 3 INVALID, no VM created (a noisy host must neither pass nor fail the release)" \
  "$([ "$rc" = 3 ] && ! grep -q '^create ' "$LIMA_CALLS" && [ "$(cat "$TMP/out-noisy/valid")" = 0 ] && [ "$(cat "$TMP/out-noisy/passed")" = 0 ] && echo 1 || echo 0)"
assert "INVALID attempts are retried up to MAX_INVALID_RUNS (3) and never counted toward RUNS" \
  "$([ "$(ls -d "$TMP"/out-noisy/run-* | wc -l | tr -d ' ')" = 3 ] && echo 1 || echo 0)"
: > "$LIMA_CALLS"; rm -rf "$TMP/out-term"
RG_IDLE_PROBE="$TMP/bin/idle30" RG_RETRY_WAIT_SECS=60 "$HERE/burst-gate.sh" --runs 1 --tarball-dir "$TMP/tb" --out "$TMP/out-term" >/dev/null 2>&1 & tpid=$!
sleep 4; t0=$SECONDS; kill -TERM "$tpid"; rc=0; wait "$tpid" || rc=$?
assert "TERM during the INVALID-retry wait exits promptly (a plain foreground sleep defers the trap for the whole wait)" \
  "$([ "$rc" = 143 ] && [ $((SECONDS - t0)) -lt 10 ] && echo 1 || echo 0)"
: > "$LIMA_CALLS"; rm -rf "$TMP/out-quiet"
rc=0; "$HERE/burst-gate.sh" --runs 1 --tarball-dir "$TMP/tb" --out "$TMP/out-quiet" >/dev/null 2>&1 || rc=$?
assert "quiet host + VM that cannot start -> FAIL exit 1 (not INVALID: no contention was observed)" \
  "$([ "$rc" = 1 ] && [ "$(cat "$TMP/out-quiet/valid")" = 1 ] && echo 1 || echo 0)"
rm -rf "$TMP/out-conf2"
rc=0; out="$(RG_IDLE_PROBE="$TMP/bin/idle30" "$HERE/burst-gate.sh" --confirm --runs 1 --tarball-dir "$TMP/tb" --out "$TMP/out-conf2" 2>/dev/null)" || rc=$?
assert "--confirm on a noisy host: INVALID exit 3, and it never falls through to 40 pods" \
  "$([ "$rc" = 3 ] && echo "$out" | grep -q '^CONFIRM: INVALID' && [ ! -e "$TMP/out-conf2/burst-40" ] && echo 1 || echo 0)"

# --- gcp backend: steal-based INVALID, PREEMPTED, backend selection ---
CPU_A='cpu  1000 0 500 8000 100 0 0 0 0 0'
assert "steal % = steal delta over total delta (100 of 1000 ticks -> 10.0)" \
  "$([ "$(rg_steal_pct "$CPU_A" 'cpu  1400 0 500 8500 100 0 0 100 0 0')" = 10.0 ] && echo 1 || echo 0)"
assert "steal % is empty when no time passed or the line is unusable (never a fake 0)" \
  "$([ -z "$(rg_steal_pct "$CPU_A" "$CPU_A")" ] && [ -z "$(rg_steal_pct "$CPU_A" garbage)" ] && echo 1 || echo 0)"
steal_env() { { good; echo "steal_idle_pct=$1"; } > "$TMP/steal.env"; echo "$TMP/steal.env"; }
printf '1 100 0 0\n' > "$TMP/q-ok.log"
BACKEND=lima
assert "steal is not judged on Lima (its host-side checks own contention; a Lima FAIL must not change meaning)" \
  "$([ "$(rg_run_status 1 "$TMP/q-ok.log" "$(steal_env 25.0)")" = FAIL ] && echo 1 || echo 0)"
BACKEND=gcp
assert "steal above 10% on a non-pass -> INVALID (a stolen shared core must not be blamed on u7s)" \
  "$([ "$(rg_run_status 1 "$TMP/q-ok.log" "$(steal_env 25.0)")" = INVALID ] && echo 1 || echo 0)"
assert "steal above 10% on a PASS -> INVALID (a stolen core must discard passes and failures alike)" \
  "$([ "$(rg_run_status 0 "$TMP/q-ok.log" "$(steal_env 25.0)")" = INVALID ] && echo 1 || echo 0)"
assert "steal at 2% on a non-pass stays FAIL (ordinary shared-core jitter must not launder a u7s failure)" \
  "$([ "$(rg_run_status 1 "$TMP/q-ok.log" "$(steal_env 2.0)")" = FAIL ] && echo 1 || echo 0)"
assert "unmeasured steal judges nothing: a non-pass without steal_idle_pct stays FAIL" \
  "$([ "$(rg_run_status 1 "$TMP/q-ok.log" "$TMP/good.env")" = FAIL ] && echo 1 || echo 0)"
assert "a reclaimed instance's non-pass is PREEMPTED, not FAIL/INVALID" \
  "$([ "$(rg_apply_preemption FAIL 1)" = PREEMPTED ] && [ "$(rg_apply_preemption INVALID 1)" = PREEMPTED ] && echo 1 || echo 0)"
assert "a PASS stays PASS even if the instance was reclaimed afterwards; no preemption changes nothing" \
  "$([ "$(rg_apply_preemption PASS 1)" = PASS ] && [ "$(rg_apply_preemption FAIL 0)" = FAIL ] && echo 1 || echo 0)"

printf '%s\n' '#!/bin/sh' 'echo "$*" >> "$GCLOUD_CALLS"' 'case "$*" in' \
  '  "config configurations describe"*) exit 0 ;;' \
  '  "config get-value project") echo p-secret ;;' \
  '  "config get-value compute/zone") echo z-1 ;;' \
  '  "compute instances create"*) echo "created p-secret" ;;' \
  '  "compute operations list"*) [ "${GCLOUD_OPS_ERR:-0}" = 1 ] && { echo "ERROR: operations denied for p-secret" >&2; exit 1; }; [ "${GCLOUD_PREEMPTED:-0}" = 1 ] && echo op-1; exit 0 ;;' \
  '  "compute instances describe"*) [ "${GCLOUD_DESCRIBE_ERR:-0}" = 1 ] && exit 1; echo 1 ;;' \
  '  "compute ssh"*vm-gate.sh*) [ "${GCLOUD_SSH_HANG:-0}" = 1 ] || exit 0; sleep 300 & echo $! > "$GCLOUD_HANG_PID"; wait ;;' \
  '  "compute ssh"*) echo "ERROR: ssh to x.c.p-secret.internal failed" >&2; [ "${GCLOUD_SSH_OK:-0}" = 1 ] && exit 0; exit 1 ;;' \
  '  "compute scp"*) for a; do d="$a"; done; case "$*" in *:/var/tmp/rg/out*) mkdir -p "$d"; echo "host x.c.p-secret.internal" > "$d/install.log"; [ -z "${GCLOUD_RESULTS:-}" ] || cp "$GCLOUD_RESULTS" "$d/results.env" ;; esac; exit 0 ;;' \
  'esac' 'exit 0' > "$TMP/bin/gcloud"
chmod +x "$TMP/bin/gcloud"
export GCLOUD_CALLS="$TMP/gcloud-calls" GCP_SSH_TRIES=1 GCP_SSH_SLEEP=0 GCP_OPS_SLEEP=0 GCP_DELETE_SLEEP=0
gcp_gate() { # out-dir, extra args...; sets rc
  : > "$GCLOUD_CALLS"; : > "$LIMA_CALLS"; rm -rf "$TMP/$1"
  rc=0; "$HERE/burst-gate.sh" --backend gcp --release v9.9.9-test --out "$TMP/$1" "${@:2}" >"$TMP/$1.out" 2>&1 || rc=$?
}
for bad in "--backend gcp" "--backend lima --release v1.0.0" "--backend gcp --release v1.0.0 --memory 2" "--backend gcp --release v1.0.0 --tarball-dir $TMP/tb" "--backend gcp --release not-a-tag" "--backend vmware"; do
  : > "$GCLOUD_CALLS"; : > "$LIMA_CALLS"; rc=0
  # shellcheck disable=SC2086
  "$HERE/burst-gate.sh" $bad --out "$TMP/out-gbad" >/dev/null 2>&1 || rc=$?
  assert "'$bad' rejected with exit 2 before any VM exists (a mis-targeted gate run must not create billable or local VMs)" \
    "$([ "$rc" = 2 ] && ! grep -q 'instances create' "$GCLOUD_CALLS" && [ ! -s "$LIMA_CALLS" ] && echo 1 || echo 0)"
done
gcp_gate out-gfail --runs 1
assert "gcp backend uses gcloud and never limactl or a local tarball build" \
  "$(grep -q 'instances create' "$GCLOUD_CALLS" && [ ! -s "$LIMA_CALLS" ] && [ ! -e "$TMP/out-gfail/dist" ] && echo 1 || echo 0)"
assert "gcp VPS never reachable (stockout/quota/IAP flake) -> INVALID exit 3, retried to the cap, never FAIL (infrastructure is not a u7s verdict)" \
  "$([ "$rc" = 3 ] && [ "$(cat "$TMP/out-gfail/valid")" = 0 ] && [ "$(grep -c 'instances create' "$GCLOUD_CALLS")" = 3 ] && grep -q 'GATE: 0/1 runs passed.*INVALID' "$TMP/out-gfail.out" && ! grep -q 'GATE:.*FAIL' "$TMP/out-gfail.out" && echo 1 || echo 0)"
assert "gcp VPS is deleted at the end of the run (a gate VM left up keeps billing)" \
  "$(grep -q 'instances delete u7s-rg-' "$GCLOUD_CALLS" && echo 1 || echo 0)"
assert "gcp VM names are valid GCE names (lowercase) and run-unique" \
  "$(grep 'instances create' "$GCLOUD_CALLS" | grep -qE 'create u7s-rg-[0-9a-z-]+ ' && echo 1 || echo 0)"
assert "gate VMs are the custom n1 1 vCPU 1 GiB (e2-micro has 0.25 sustained vCPU; e2 custom shared-core caps one thread at half a core)" \
  "$(grep 'instances create' "$GCLOUD_CALLS" | grep -q -- '--machine-type=n1-custom-1-1024 ' && ! grep 'instances create' "$GCLOUD_CALLS" | grep -q 'e2-micro' && echo 1 || echo 0)"
U7S_GCP_MACHINE_TYPE=e2-standard-2 gcp_gate out-gshape --runs 1
assert "an ambient U7S_GCP_MACHINE_TYPE cannot change the release-authoritative shape" \
  "$(grep 'instances create' "$GCLOUD_CALLS" | grep -q -- '--machine-type=n1-custom-1-1024 ' && ! grep 'instances create' "$GCLOUD_CALLS" | grep -q 'e2-standard' && echo 1 || echo 0)"
gcp_gate out-gfail --runs 1
assert "gcp verdict line says release-authoritative and names the mirror release" \
  "$(grep -q 'release-authoritative: x86_64 GCP n1-custom-1-1024 Spot, mirror release v9.9.9-test' "$TMP/out-gfail.out" && grep -q 'release-authoritative=yes' "$TMP/out-gfail/backend.txt" && echo 1 || echo 0)"
assert "the gcloud project id never reaches the run logs (redacted)" \
  "$(grep -rq 'p-secret' "$TMP/out-gfail" "$TMP/out-gfail.out" && echo 0 || echo 1)"
export GCLOUD_PREEMPTED=1
gcp_gate out-gpre --runs 1
assert "preempted gcp VPS -> PREEMPTED exit 3, counted as no valid run, retried up to the cap (a reclaimed Spot VM is not a u7s FAIL)" \
  "$([ "$rc" = 3 ] && [ "$(cat "$TMP/out-gpre/valid")" = 0 ] && [ "$(grep -c 'instances create' "$GCLOUD_CALLS")" = 3 ] && grep -q 'GATE: 0/1 runs passed.*PREEMPTED' "$TMP/out-gpre.out" && echo 1 || echo 0)"
unset GCLOUD_PREEMPTED
export GCLOUD_SSH_OK=1
RG_IDLE_PROBE="$TMP/bin/idle30" gcp_gate out-gquiet --runs 1
assert "gcp ignores the local host's idle probe (the guest is the host): a busy laptop must not make a VPS run INVALID; a reachable VPS with no results is a valid FAIL" \
  "$([ "$rc" = 1 ] && [ "$(cat "$TMP/out-gquiet/valid")" = 1 ] && echo 1 || echo 0)"
assert "the project id is scrubbed from console gcloud stderr and the copied-out install.log, not only the run logs" \
  "$(! grep -rq 'p-secret' "$TMP/out-gquiet" "$TMP/out-gquiet.out" && grep -q 'x.c.<project>.internal' "$TMP/out-gquiet/run-1/out/install.log" && echo 1 || echo 0)"
export GCLOUD_OPS_ERR=1
gcp_gate out-gops --runs 1
assert "a failed run whose preemption lookup keeps erroring -> INVALID exit 3, never FAIL (a preempted run must not be scored as u7s broken)" \
  "$([ "$rc" = 3 ] && [ "$(cat "$TMP/out-gops/valid")" = 0 ] && ! grep -q 'GATE:.*FAIL' "$TMP/out-gops.out" && echo 1 || echo 0)"
assert "the preemption lookup is retried before giving up (one IAP/API blip must not decide the verdict)" \
  "$([ "$(grep -c 'operations list' "$GCLOUD_CALLS")" -ge 3 ] && echo 1 || echo 0)"
assert "the project id is scrubbed from the console stderr of a failing preemption lookup (pasted logs must not carry it)" \
  "$(! grep -q 'p-secret' "$TMP/out-gops.out" && grep -q 'operations denied for <project>' "$TMP/out-gops.out" && echo 1 || echo 0)"
unset GCLOUD_OPS_ERR
export GCLOUD_DESCRIBE_ERR=1
gcp_gate out-gdel --runs 2
assert "a VPS delete that keeps failing never aborts the gate: every attempt still runs, and the leaked VPS is named loudly" \
  "$([ "$rc" = 1 ] && [ "$(grep -c 'instances create' "$GCLOUD_CALLS")" = 2 ] && grep -q 'LEAKED GCP VPS u7s-rg-' "$TMP/out-gdel.out" && grep -q 'GATE: 0/2' "$TMP/out-gdel.out" && [ -s "$TMP/out-gdel/leaked-vps.txt" ] && echo 1 || echo 0)"
assert "a failed delete is retried (a transient describe error must not leak a billing VPS)" \
  "$([ "$(grep -c 'instances describe' "$GCLOUD_CALLS")" -ge 8 ] && echo 1 || echo 0)"
GCLOUD_RESULTS="$TMP/good.env" gcp_gate out-gleak --runs 1
assert "a PASS verdict with a leaked VPS exits 4, not 0 (a green gate must not hide a billing VPS)" \
  "$([ "$rc" = 4 ] && [ "$(cat "$TMP/out-gleak/passed")" = 1 ] && grep -q 'LEAKED VPS' "$TMP/out-gleak.out" && echo 1 || echo 0)"
GCLOUD_RESULTS="$TMP/good.env" gcp_gate out-gcleak --confirm --runs 1
assert "--confirm PASS with a VPS leaked in a sub-gate exits 4 and the top-level leaked-vps.txt names it (a green confirm must not hide a billing VPS)" \
  "$([ "$rc" = 4 ] && [ -s "$TMP/out-gcleak/leaked-vps.txt" ] && grep -q 'CONFIRM: PASS' "$TMP/out-gcleak.out" && grep -q 'LEAKED VPS' "$TMP/out-gcleak.out" && echo 1 || echo 0)"
unset GCLOUD_DESCRIBE_ERR
GCLOUD_RESULTS="$TMP/good.env" gcp_gate out-gpass --runs 1
assert "a PASS verdict with no leak still exits 0" "$([ "$rc" = 0 ] && echo 1 || echo 0)"
GCLOUD_RESULTS="$TMP/good.env" gcp_gate out-gcpass --confirm --runs 1
assert "--confirm PASS with no leak still exits 0" "$([ "$rc" = 0 ] && [ ! -s "$TMP/out-gcpass/leaked-vps.txt" ] && echo 1 || echo 0)"
assert "gcp vm-gate.log is fully written (redactor waited for) before the run proceeds" \
  "$([ ! -e "$TMP/out-gpass/run-1/vm-gate.fifo" ] && [ -f "$TMP/out-gpass/run-1/vm-gate.log" ] && echo 1 || echo 0)"
export GCLOUD_HANG_PID="$TMP/hang.pid"
rm -f "$GCLOUD_HANG_PID"
: > "$GCLOUD_CALLS"; : > "$LIMA_CALLS"; rm -rf "$TMP/out-ghang"
GCLOUD_SSH_HANG=1 RG_RUN_WALL_SECS=2 "$HERE/burst-gate.sh" --backend gcp --release v9.9.9-test --out "$TMP/out-ghang" --runs 1 >"$TMP/out-ghang.out" 2>&1 &
gate_bg=$!
# A watchdog that fails to kill the ssh client leaves the gate waiting forever; bound the test.
for _ in $(seq 1 40); do kill -0 "$gate_bg" 2>/dev/null || break; sleep 1; done
gate_ended=1; kill -0 "$gate_bg" 2>/dev/null && { gate_ended=0; pkill -P "$gate_bg" 2>/dev/null; kill "$gate_bg" 2>/dev/null; }
hang_pid="$(cat "$GCLOUD_HANG_PID" 2>/dev/null || true)"
alive=0; [ -z "$hang_pid" ] || ! kill -0 "$hang_pid" 2>/dev/null || alive=1
[ -z "$hang_pid" ] || kill "$hang_pid" 2>/dev/null || true
assert "the wall-clock watchdog kills the ssh client under the redaction pipe, so a hung run ends instead of waiting forever" \
  "$([ -n "$hang_pid" ] && [ "$alive" = 0 ] && [ "$gate_ended" = 1 ] && grep -q 'wall-clock cap 2s hit' "$TMP/out-ghang.out" && echo 1 || echo 0)"
unset GCLOUD_SSH_OK

# --- experiment mode: an unpublished tarball must never be mistaken for a release verdict ---
XP="$TMP/xp"; mkdir -p "$XP"
SHA40=0123456789abcdef0123456789abcdef01234567
: > "$XP/u7s-gate-experiment-0123456789ab-x86_64.tar.gz"; echo '#!/bin/sh' > "$XP/install.sh"
echo "ref=origin/main sha=$SHA40" > "$XP/u7s-gate-experiment-0123456789ab-x86_64.tar.gz.source"
XT="$XP/u7s-gate-experiment-0123456789ab-x86_64.tar.gz"
xp_gate() { # out-dir, extra args...; sets rc
  : > "$GCLOUD_CALLS"; : > "$LIMA_CALLS"; rm -rf "$TMP/$1"
  rc=0; "$HERE/burst-gate.sh" "${@:2}" --out "$TMP/$1" >"$TMP/$1.out" 2>&1 || rc=$?
}
for bad in "--backend gcp --tarball $XT --release v1.0.0" "--backend lima --tarball $XT" "--backend gcp --tarball $XT --confirm" \
           "--backend gcp --tarball $TMP/missing.tar.gz" "--backend gcp --install-only --release v1.0.0"; do
  : > "$GCLOUD_CALLS"; : > "$LIMA_CALLS"; rc=0
  # shellcheck disable=SC2086
  "$HERE/burst-gate.sh" $bad --out "$TMP/out-xbad" >/dev/null 2>&1 || rc=$?
  assert "'${bad//$TMP/<tmp>}' rejected with exit 2 before any VM exists (an experiment must not blur into the release gate or bill a VM)" \
    "$([ "$rc" = 2 ] && ! grep -q 'instances create' "$GCLOUD_CALLS" && echo 1 || echo 0)"
done
echo "ref=origin/main sha=short" > "$XP/bad.tar.gz.source"; : > "$XP/bad.tar.gz"
xp_gate out-xnosha --backend gcp --tarball "$XP/bad.tar.gz"
assert "a tarball whose .source lacks a full sha is refused (an experiment must say exactly what it ran)" \
  "$([ "$rc" = 2 ] && ! grep -q 'instances create' "$GCLOUD_CALLS" && echo 1 || echo 0)"
export GCLOUD_SSH_OK=1 GCLOUD_RESULTS="$TMP/good.env"
xp_gate out-xpass --backend gcp --tarball "$XT" --runs 1
assert "experiment run installs the uploaded tarball and install.sh, not the mirror (the point is to test unpublished code)" \
  "$(grep -q 'compute scp.*u7s-gate-experiment-0123456789ab-x86_64.tar.gz' "$GCLOUD_CALLS" && ! grep -q 'u7s.dekiru.tech' "$GCLOUD_CALLS" && grep -q '^INSTALL_TARBALL=/var/tmp/rg/u7s-gate-experiment-0123456789ab-x86_64.tar.gz$' "$TMP/out-xpass/stage/gate.env" && echo 1 || echo 0)"
assert "every experiment artefact carries EXPERIMENT and the sha: out dir, run dir, verdict file, backend.txt, GATE line" \
  "$([ -f "$TMP/out-xpass/EXPERIMENT.txt" ] && [ -d "$TMP/out-xpass/EXPERIMENT-run-1" ] && head -1 "$TMP/out-xpass/EXPERIMENT-run-1/verdict.txt" | grep -q '^EXPERIMENT .*sha=0123456789ab' && grep -q 'experiment=yes' "$TMP/out-xpass/backend.txt" && grep -q '^==== GATE: .*EXPERIMENT PASS' "$TMP/out-xpass.out" && echo 1 || echo 0)"
assert "an experiment is never release-authoritative, even when it passes" \
  "$(grep -q 'release-authoritative=no' "$TMP/out-xpass/backend.txt" && ! grep -q 'release-authoritative=yes\|release-authoritative: ' "$TMP/out-xpass/backend.txt" "$TMP/out-xpass.out" && echo 1 || echo 0)"
xp_gate out-xdefault --backend gcp --tarball "$XT" --runs 1 --install-only
assert "--install-only reaches the VM and an install-only experiment is judged on install alone (the smoke must not need bursts)" \
  "$(grep -q '^INSTALL_ONLY=1$' "$TMP/out-xdefault/stage/gate.env" && [ "$rc" = 0 ] && grep -q 'install and node Ready only' "$TMP/out-xdefault/EXPERIMENT-run-1/verdict.txt" && echo 1 || echo 0)"
unset GCLOUD_SSH_OK GCLOUD_RESULTS
assert "release path unchanged: gate.env of a --release run installs zero-arg (no INSTALL_TARBALL)" \
  "$(grep -q '^INSTALL_TARBALL=$' "$TMP/out-gpass/stage/gate.env" && echo 1 || echo 0)"
mkdir -p "$TMP/tbl"; : > "$TMP/tbl/u7s-gate-testarch.tar.gz"; : > "$TMP/tbl/u7s-gate-testarch.tar.gz.sha256"; : > "$TMP/tbl/install.sh"
"$HERE/burst-gate.sh" --runs 1 --tarball-dir "$TMP/tbl" --out "$TMP/out-lima-tb" >/dev/null 2>&1 || true
assert "the Lima gate installs its locally built, unsigned tarball by the staged file's name, or every Lima run fails at install on the signature check" \
  "$(grep -qx 'INSTALL_TARBALL=/var/tmp/rg/u7s-gate-testarch.tar.gz' "$TMP/out-lima-tb/stage/gate.env" && echo 1 || echo 0)"

# --- vm-gate sampler lifecycle ---
VG="$TMP/vg"; mkdir -p "$VG/out"
cp "$HERE/lib.sh" "$VG/lib.sh"
echo 'RG_CAL_MIN_SAMPLES=0' > "$VG/gate.env"
cat > "$VG/vm-sampler.sh" <<'STUB'
#!/usr/bin/env bash
echo "SAMPLER_LEAK_OUT"; echo "SAMPLER_LEAK_ERR" >&2
echo $$ > "$(dirname "$0")/sampler.pid"
exec sleep 300
STUB
cat > "$VG/install.sh" <<'STUB'
#!/usr/bin/env bash
sleep 1
[ -s "$(dirname "$0")/sampler.pid" ] && echo up > "$(dirname "$0")/sampler-up-at-install"
exit 1
STUB
vg_t0=$SECONDS; vg_rc=0
RG_DIR="$VG" timeout 60 bash "$HERE/vm-gate.sh" > "$TMP/vg.out" 2>&1 || vg_rc=$?
vg_secs=$((SECONDS - vg_t0))
sleep 0.5
assert "sampler is already running when install.sh starts (the install-time memory spike is the thing to see)" \
  "$([ -f "$VG/sampler-up-at-install" ] && echo 1 || echo 0)"
assert "a failed install exits non-zero and promptly" "$([ "$vg_rc" = 1 ] && [ "$vg_secs" -lt 20 ] && echo 1 || echo 0)"
assert "a failed install leaves no sampler running (an orphan would hold the ssh session open)" \
  "$(kill -0 "$(cat "$VG/sampler.pid")" 2>/dev/null && echo 0 || echo 1)"
assert "sampler stdout/stderr go to its own log, not the gate's stream (a held pipe stalls ssh/limactl)" \
  "$(! grep -q SAMPLER_LEAK "$TMP/vg.out" && grep -q SAMPLER_LEAK_OUT "$VG/out/sampler.log" && echo 1 || echo 0)"

# --- evidence survives a wedge (final tally absent) ---
good | grep -vE '^(oom_host|oom_kubesystem|notready_events|node_ready_final|webhook_ok|wp_ok|marker_ok)=' > "$TMP/dead.env"
echo "watch_t0=250" >> "$TMP/dead.env"
printf '100 True\n200 False\n300 unreachable\n' > "$TMP/dead-nr.log"
rg_fill_tally "$TMP/dead.env" "$TMP/dead-nr.log"
verdict_of "$TMP/dead.env"
assert "dead run: observed not-Ready evidence replaces 'missing' in criterion (b) (1 observation after watch start, final=unreachable)" \
  "$(grep -qE '^FAIL +\(b\).*observations=1, final=unreachable' <<< "$V_OUT" && echo 1 || echo 0)"
assert "dead run: the verdict says the tally was rebuilt and OOM counts are unknown, not silently green" \
  "$(echo "$V_OUT" | grep -q 'OOM counts unknown' && echo 1 || echo 0)"
good | grep -vE '^(notready_events|node_ready_final)=' > "$TMP/dead2.env"
printf '100 True\n' > "$TMP/dead2-nr.log"
rg_fill_tally "$TMP/dead2.env" "$TMP/dead2-nr.log"
assert "dead run whose log ends at a stale Ready=True is 'unconfirmed', never a (b) PASS: a vanished guest must not look green" \
  "$(rg_get "$TMP/dead2.env" node_ready_final | grep -qx unconfirmed && echo 1 || echo 0)"
good > "$TMP/full.env"; cp "$TMP/full.env" "$TMP/full2.env"
rg_fill_tally "$TMP/full2.env" "$TMP/dead-nr.log"
assert "a complete tally is never overwritten by the host-side rebuild" "$(cmp -s "$TMP/full.env" "$TMP/full2.env" && echo 1 || echo 0)"

out="$(printf 'kube-system coredns Running True\ndefault mariadb-0 Pending \ndefault job-x Succeeded False\ndefault rg-burst-abc Pending \nkube-system kcm Running False\n' | rg_notready_pods)"
assert "not-Ready pods are listed incl. a Pending pod with no Ready condition (mariadb-0 never Ready must get diagnostics)" \
  "$([ "$out" = "$(printf 'default mariadb-0\nkube-system kcm')" ] && echo 1 || echo 0)"
assert "finished pods and the burst workload are excluded (50 describes would flood a wedged guest)" \
  "$(echo "$out" | grep -qE 'job-x|rg-burst' && echo 0 || echo 1)"

eval "$(sed -n '/^res() {/,/^}/p' "$HERE/vm-gate.sh")"
OUT="$TMP/resout"; mkdir -p "$OUT"; : > "$OUT/results.env"
set +e; res oom_host 0; res notready_events 0; res oom_host 2; set -e
assert "res replaces a key: the final tally must override the partial one (rg_get reads the first match)" \
  "$([ "$(rg_get "$OUT/results.env" oom_host)" = 2 ] && [ "$(grep -c '^oom_host=' "$OUT/results.env")" = 1 ] && [ "$(rg_get "$OUT/results.env" notready_events)" = 0 ] && echo 1 || echo 0)"

# --- wedge detection: a wedged burst must end in ~60 s, not after the 600 s hard kill ---
NOW=10000
wedge() { RG_WEDGE_IOWAIT_PCT="${IO-90}" RG_WEDGE_SECS="${W:-60}" rg_wedge_reason "$NOW" "$1" "${2:-/dev/null}" "${3:-/dev/null}"; }
printf '%s True\n%s False\n' $((NOW - 500)) $((NOW - 60)) > "$TMP/wn1.log"
assert "node not Ready for exactly 60 s is a wedge (abort within the ~60-90 s budget)" \
  "$(wedge "$TMP/wn1.log" | grep -qx 'node Ready=False for 60s' && echo 1 || echo 0)"
printf '%s True\n%s False\n' $((NOW - 500)) $((NOW - 59)) > "$TMP/wn2.log"
assert "node not Ready for 59 s is not yet a wedge (a brief flap must not kill a passing run)" "$([ -z "$(wedge "$TMP/wn2.log")" ] && echo 1 || echo 0)"
printf '%s True\n%s Unknown\n%s unreachable\n%s unreachable\n' $((NOW - 500)) $((NOW - 90)) $((NOW - 40)) $((NOW - 5)) > "$TMP/wn3.log"
assert "the not-Ready run is timed from its first observation and an unreachable API is named as such" \
  "$(wedge "$TMP/wn3.log" | grep -qx 'API unreachable for 90s' && echo 1 || echo 0)"
printf '%s True\n%s False\n%s True\n' $((NOW - 500)) $((NOW - 200)) $((NOW - 100)) > "$TMP/wn4.log"
assert "a node that recovered (trailing True) is not a wedge: only a current outage aborts" "$([ -z "$(wedge "$TMP/wn4.log")" ] && echo 1 || echo 0)"
assert "RG_WEDGE_SECS=0 disables detection (--wedge-secs 0 for deliberate long-stall studies)" "$([ -z "$(W=0 wedge "$TMP/wn1.log")" ] && echo 1 || echo 0)"
: > "$TMP/empty.log"
stat_rows() { # <iowait jiffies per 5 s sample> <samples> <last-ts>
  local i
  for i in $(seq 0 $(($2 - 1))); do printf '%s\tburstn\tSTAT\t10\t10\t%s\t0\n' $(($3 - (($2 - 1 - i)) * 5)) $(( i * $1 )); done
}
stat_rows 475 14 $((NOW - 2)) > "$TMP/io95.tsv"
assert "95% iowait over the last 60 s is a wedge even while the node still reports Ready (the 94%-iowait hang)" \
  "$(wedge "$TMP/empty.log" "$TMP/io95.tsv" | grep -q '^iowait 9[0-9]% over the last 6[0-9]s$' && echo 1 || echo 0)"
stat_rows 250 14 $((NOW - 2)) > "$TMP/io50.tsv"
assert "50% iowait is a slow burst, not a wedge: do not abort a run that could still pass" "$([ -z "$(wedge "$TMP/empty.log" "$TMP/io50.tsv")" ] && echo 1 || echo 0)"
stat_rows 475 14 $((NOW - 100)) > "$TMP/iostale.tsv"
assert "stale sampler rows (older than the window) judge nothing" "$([ -z "$(wedge "$TMP/empty.log" "$TMP/iostale.tsv")" ] && echo 1 || echo 0)"
stat_rows 475 5 $((NOW - 2)) > "$TMP/ioshort.tsv"
assert "high iowait seen for only 20 s is not a wedge (window not covered)" "$([ -z "$(wedge "$TMP/empty.log" "$TMP/ioshort.tsv")" ] && echo 1 || echo 0)"

# --- reclaim-thrash wedge: node Ready, iowait ~0, burst stuck ---
pwedge() { RG_WEDGE_STALL_SECS="${S:-0}" IO=0 wedge "$@"; }
stat_rows 0 14 $((NOW - 2)) > "$TMP/io0.tsv"
printf '%s 0\n%s 1\n' $((NOW - 400)) $((NOW - 150)) > "$TMP/prog-stuck.log"
assert "ready-pod count stuck for 150 s (120 s limit) in a burst past the 300 s cap is a wedge with node Ready and iowait 0, the reclaim-thrash that ran to the 600 s kill; the reason names the pod count" \
  "$(S=120 pwedge "$TMP/empty.log" "$TMP/io0.tsv" "$TMP/prog-stuck.log" | grep -qx 'no burst progress for 150s (1 pods Ready)' && echo 1 || echo 0)"
printf '%s 0\n%s 1\n' $((NOW - 200)) $((NOW - 150)) > "$TMP/prog-early.log"
assert "the same stall inside the 300 s cap is NOT a wedge: the burst may still finish and pass (c), and a healthy slow-pull burst must never be failed by the monitor" \
  "$([ -z "$(S=120 pwedge "$TMP/empty.log" "$TMP/io0.tsv" "$TMP/prog-early.log")" ] && echo 1 || echo 0)"
printf '%s 0\n' $((NOW - 250)) > "$TMP/prog-late.log"
assert "zero Ready for 250 s with the first wave still to land (late healthy burst) is not a wedge" \
  "$([ -z "$(S=120 pwedge "$TMP/empty.log" "$TMP/io0.tsv" "$TMP/prog-late.log")" ] && echo 1 || echo 0)"
printf '%s 0\n%s 1\n%s 5\n' $((NOW - 400)) $((NOW - 350)) $((NOW - 30)) > "$TMP/prog-ok.log"
assert "a burst whose ready count last moved 30 s ago is progressing, not wedged" "$([ -z "$(S=120 pwedge "$TMP/empty.log" /dev/null "$TMP/prog-ok.log")" ] && echo 1 || echo 0)"
assert "an empty progress log (no burst running) judges nothing" "$([ -z "$(S=120 pwedge "$TMP/empty.log" /dev/null "$TMP/empty.log")" ] && echo 1 || echo 0)"
assert "stall limit 0 disables the no-progress signal" "$([ -z "$(S=0 pwedge "$TMP/empty.log" /dev/null "$TMP/prog-stuck.log")" ] && echo 1 || echo 0)"
assert "iowait signal is off by default: healthy bursts that pass (c) hit 84-88% over 60 s (wedge-calibrate.sh), so 90% would FAIL a good attempt" \
  "$([ -z "$(RG_WEDGE_SECS=60 rg_wedge_reason "$NOW" "$TMP/empty.log" "$TMP/io95.tsv" /dev/null)" ] && echo 1 || echo 0)"
assert "--wedge-stall-secs reaches the VM env with the burst cap it is measured against" \
  "$(wsenv="$(gate_env ws --wedge-stall-secs 77 --burst-cap 250)"; grep -qx 'WEDGE_STALL_SECS=77' <<< "$wsenv" && grep -qx 'BURST_CAP_SECS=250' <<< "$wsenv" && echo 1 || echo 0)"
assert "--wedge-stall-secs defaults to 120" "$(gate_env wsd | grep -qx 'WEDGE_STALL_SECS=120' && echo 1 || echo 0)"
rc=0; "$HERE/burst-gate.sh" --runs 1 --tarball-dir "$TMP/tb" --out "$TMP/out-badws" --wedge-stall-secs x >/dev/null 2>&1 || rc=$?
assert "--wedge-stall-secs x rejected with exit 2" "$([ "$rc" = 2 ] && echo 1 || echo 0)"
assert "stall signal is on by default (a gate that only waits for the 600 s kill leaves hours of nothing)" "$([ "$RG_WEDGE_STALL_SECS" -gt 0 ] && echo 1 || echo 0)"
printf '3\n3\n4\n\n4\n' | rg_wait_ready 9 "$TMP/prog-w.log" || true
assert "rg_wait_ready logs only changes of the ready count (a watch re-print must not reset the stall clock); empty means 0" \
  "$([ "$(wc -l < "$TMP/prog-w.log" | tr -d ' ')" = 4 ] && [ "$(awk '{print $2}' "$TMP/prog-w.log" | tr '\n' ' ')" = '3 4 0 4 ' ] && echo 1 || echo 0)"
printf '5 5\n' > "$TMP/prog-w2.log"
printf '5\n5\n' | rg_wait_ready 9 "$TMP/prog-w2.log" || true
assert "a re-established watch re-printing the current count does not reset the stall clock" "$([ "$(wc -l < "$TMP/prog-w2.log" | tr -d ' ')" = 1 ] && echo 1 || echo 0)"

# --- the wedge monitor must never kill a reused PID ---
mkdir -p "$TMP/proc/111" "$TMP/proc/222"
printf 'timeout\0600\0kubectl\0--kubeconfig\0k\0get\0deployment\0rg-burst\0-w\0' > "$TMP/proc/111/cmdline"
printf 'sleep\0300\0' > "$TMP/proc/222/cmdline"
echo 111 > "$TMP/wp1.pid"; echo 222 > "$TMP/wp2.pid"; echo 333 > "$TMP/wp3.pid"; : > "$TMP/wp4.pid"
assert "the live burst watch's PID is returned" "$([ "$(rg_burst_watch_pid "$TMP/wp1.pid" "$TMP/proc")" = 111 ] && echo 1 || echo 0)"
assert "a PID reused by an unrelated process is not returned (killing it would hit a random guest process)" \
  "$([ -z "$(rg_burst_watch_pid "$TMP/wp2.pid" "$TMP/proc")" ] && echo 1 || echo 0)"
assert "an exited PID, an empty pid file and a missing pid file are all not returned" \
  "$([ -z "$(rg_burst_watch_pid "$TMP/wp3.pid" "$TMP/proc")" ] && [ -z "$(rg_burst_watch_pid "$TMP/wp4.pid" "$TMP/proc")" ] && [ -z "$(rg_burst_watch_pid "$TMP/nope.pid" "$TMP/proc")" ] && echo 1 || echo 0)"

# --- evidence survives a host-side kill ---
printf '%s\n' '#!/bin/sh' 'echo "$*" >> "$LIMA_CALLS"' \
  'case "$*" in list*) exit 0;; *vm-gate.sh*) exec sleep 8;; "copy -r"*:/var/tmp/rg/out*) d=""; for a; do d="$a"; done; mkdir -p "$d"; echo "wedge evidence" > "$d/run.log";; esac' 'exit 0' > "$TMP/bin/limactl"
: > "$LIMA_CALLS"; rm -rf "$TMP/out-term"
RG_RUN_WALL_SECS=300 "$HERE/burst-gate.sh" --runs 1 --tarball-dir "$TMP/tbl" --out "$TMP/out-term" >/dev/null 2>&1 & gpid=$!
for _ in $(seq 1 100); do grep -q 'vm-gate.sh' "$LIMA_CALLS" 2>/dev/null && break; sleep 0.2; done
kill -TERM "$gpid" 2>/dev/null; wait "$gpid" 2>/dev/null || true
assert "SIGTERM (host cap) mid-run pulls /var/tmp/rg/out from the VM before deleting it, or a killed run leaves no evidence" \
  "$(grep -q 'copy -r u7s-rg-.*:/var/tmp/rg/out' "$LIMA_CALLS" && [ "$(cat "$TMP"/out-term/*run-1/out/run.log 2>/dev/null)" = 'wedge evidence' ] && awk '/copy -r .*:\/var\/tmp\/rg\/out/ {c = NR} /delete/ {d = NR} END {exit !(c && d && c < d)}' "$LIMA_CALLS" && echo 1 || echo 0)"
sleep 3
assert "a SIGTERMed gate leaves no background subshell behind (the quiet-sample loop otherwise loops forever as an orphan)" \
  "$(ps -axo command | grep -F -- "--out $TMP/out-term" | grep -qv grep && echo 0 || echo 1)"
printf '#!/bin/sh\necho "$*" >> "$LIMA_CALLS"\n[ "$1" = list ] && exit 0\nexit 1\n' > "$TMP/bin/limactl"

# --- ramp stops at the first failing step, wedge or not ---
eval "$(sed -n '/^res() {/,/^}/p;/^run_ramp() {/,/^}/p;/^note_wedge() {/,/^}/p' "$HERE/vm-gate.sh")"
ramp_run() { # <burst outcomes "30=20 40=wedge ...">; sets RAN, leaves OUT/results.env
  OUT="$TMP/ro-$1"; rm -rf "$OUT"; mkdir -p "$OUT"; echo install_ok=1 > "$OUT/results.env"; : > "$OUT/ran"; : > "$OUT/node-ready.log"
  OUTCOMES="$2"; RAMP="30,40,50,60"; SETTLE_STEP=0; NODE=n; export OUT
  phase() { :; }; log() { :; }; snap() { echo "snap $1" >> "$OUT/ran"; }; burst_cleanup() { :; }; wait_node_ready() { :; }
  record_uids() { :; }; oom_since() { echo "0 0"; }; k() { echo True; }; wp_ok_poll() { echo 1; }; marker_ok() { echo 1; }; write_tally() { :; }
  run_burst() {
    echo "burst $1" >> "$OUT/ran"
    local o v
    for o in $OUTCOMES; do
      [ "${o%%=*}" = "$1" ] || continue
      v="${o#*=}"; [ "$v" != wedge ] || echo wedge > "$OUT/wedge.txt"
      echo "$v"
    done
  }
  set +e; run_ramp; set -e
  RAN="$(grep '^burst' "$OUT/ran" | cut -d' ' -f2 | tr '\n' ' ')"
}
ramp_run ok "30=20 40=20 50=20 60=20"
assert "ramp sanity: with every step passing all four sizes run" "$([ "$RAN" = "30 40 50 60 " ] && echo 1 || echo 0)"
ramp_run slow "30=20 40=timeout 50=20 60=20"
assert "ramp stops at the first failing step (40 hit the probe hard-kill): 50/60 never run, no wasted climb" \
  "$([ "$RAN" = "30 40 " ] && echo 1 || echo 0)"
ramp_run wedge "30=20 40=wedge 50=20 60=20"
assert "a wedged step ends the ramp at once: recorded as ramp_40_secs=wedge with the reason" \
  "$([ "$RAN" = "30 40 " ] && [ "$(rg_get "$OUT/results.env" ramp_40_secs)" = wedge ] && rg_get "$OUT/results.env" wedge_reason | grep -q . && echo 1 || echo 0)"
assert "a wedged step runs no scale-down/settle/snapshot on the dead guest (they would burn minutes)" \
  "$(grep -q 'snap burst40' "$OUT/ran" && echo 0 || echo 1)"
rg_ramp_verdict "$OUT/results.env" "30 40 50 60" /dev/null > "$TMP/wedge.ramp" || true
assert "ramp verdict keeps 30 as the candidate and names the wedge" \
  "$(grep -q 'candidate N=30' "$TMP/wedge.ramp" && grep -q 'WEDGE, burst aborted early' "$TMP/wedge.ramp" && echo 1 || echo 0)"
good | sed 's/^burst_secs=140/burst_secs=wedge/' > "$TMP/wedge-full.env"; echo "wedge_reason=API unreachable for 61s" >> "$TMP/wedge-full.env"
verdict_of "$TMP/wedge-full.env"
assert "a wedged full run FAILs (c) and the verdict says why" \
  "$([ "$V_RC" != 0 ] && echo "$V_OUT" | grep -qE '^FAIL +\(c\)' && echo "$V_OUT" | grep -q 'WEDGE: burst aborted early, API unreachable for 61s' && echo 1 || echo 0)"
rc=0; "$HERE/burst-gate.sh" --wedge-secs x --tarball-dir "$TMP/tb" --out "$TMP/out-ws" >/dev/null 2>&1 || rc=$?
assert "--wedge-secs x rejected" "$([ "$rc" = 2 ] && echo 1 || echo 0)"
assert "--wedge-secs reaches the VM env" "$(gate_env ws --wedge-secs 90 | grep -qx 'WEDGE_SECS=90' && echo 1 || echo 0)"

# --- Lima VM trim to GCP parity ---
printf '#!/bin/sh\necho "$*" >> "$LIMA_CALLS"\nexit 0\n' > "$TMP/bin/limactl"
: > "$LIMA_CALLS"
(BACKEND=lima; . "$HERE/backend.sh"; vm_trim u7s-rg-x)
trim_call="$(cat "$LIMA_CALLS")"
trim_ok=1
for u in udisks2 ModemManager multipathd multipathd.socket polkit; do
  echo "$trim_call" | grep -q "mask --now .*$u" || trim_ok=0
done
echo "$trim_call" | grep -q 'disable --now lima-guestagent' || trim_ok=0
[ "$(echo "$trim_call" | grep -c 'mask --now.*lima-guestagent')" = 0 ] || trim_ok=0
assert "Lima trim masks every oversized daemon and disables (not masks: it is a real unit file, mask fails live and aborts the trim) the guest agent; each left running costs 7-22 MiB of a 1 GiB node and makes Lima knees pessimistic vs GCP" "$trim_ok"
assert "Lima trim sets MALLOC_ARENA_MAX=1 for kubelet before install (8 arm64 glibc arenas = 16 MiB)" \
  "$(echo "$trim_call" | grep -q 'kubelet.service.d' && echo "$trim_call" | grep -q 'MALLOC_ARENA_MAX=1' && echo 1 || echo 0)"
: > "$LIMA_CALLS"
(BACKEND=gcp; . "$HERE/backend.sh"; vm_trim x)
assert "GCP is never trimmed (its agents are real production cost the gate must model)" "$([ ! -s "$LIMA_CALLS" ] && echo 1 || echo 0)"
printf '#!/bin/sh\necho "$*" >> "$LIMA_CALLS"\ncase "$*" in list*) exit 0;; "copy -r"*:/var/tmp/rg/out*) mkdir -p "${@: -1}";; esac\nexit 0\n' > "$TMP/bin/limactl"
: > "$LIMA_CALLS"
RG_RUN_WALL_SECS=30 "$HERE/burst-gate.sh" --runs 1 --tarball-dir "$TMP/tbl" --out "$TMP/out-trim" >/dev/null 2>&1 || true
assert "the Lima gate trims the VM after boot and before the gate scripts run (otherwise the trim never reaches a real run)" \
  "$(awk '/mask --now/ {t = NR} /vm-gate.sh/ {g = NR} END {exit !(t && g && t < g)}' "$LIMA_CALLS" && echo 1 || echo 0)"

echo "---- $PASS passed, $FAIL failed ----"
[ "$FAIL" = 0 ]

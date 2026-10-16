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
burst80_secs=140
wp_ok=1
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
expect_fail "(c) 80-pod burst hit the hard kill -> FAIL" burst80_secs timeout '(c)'
expect_fail "(d) WordPress dead after the burst -> FAIL: the workload the node exists to serve" wp_ok 0 '(d)'
expect_fail "(e) webhook smoke failed -> FAIL: only gate for the shipped webhook dial path" webhook_ok 0 '(e)'
expect_fail "install failed -> FAIL" install_ok 0 install

verdict_of "$(mutate burst20_secs 300)"
assert "burst exactly at the 300 s cap passes (cap is inclusive: 'within 5 min')" "$([ "$V_RC" = 0 ] && echo 1 || echo 0)"

# Missing data must never pass.
for key in oom_host oom_kubesystem notready_events node_ready_final burst20_secs burst80_secs wp_ok webhook_ok install_ok; do
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
printf '#!/bin/sh\nexit 1\n' > "$TMP/bin/limactl"; chmod +x "$TMP/bin/limactl"
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
printf '#!/bin/sh\necho "$*" >> "$LIMA_CALLS"\nexit 1\n' > "$TMP/bin/limactl"
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

echo "---- $PASS passed, $FAIL failed ----"
[ "$FAIL" = 0 ]

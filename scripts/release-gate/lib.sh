#!/usr/bin/env bash
# Pure decision logic for the 1 GiB burst release gate (burst-gate.sh). Sourced by the
# harness and by test-burst-gate-logic.sh; no VM access here.
#
# Results file format: one `key=value` per line, written by burst-gate.sh per run.
#   install_ok=1|0           zero-arg install.sh finished and the node went Ready
#   oom_host=N               kernel OOM victims that were control-plane host processes
#   oom_kubesystem=N         kernel OOM victims inside kube-system pods
#   oom_victims=...          free text, informational
#   notready_events=N        node Ready!=True observations during the run
#   node_ready_final=True|False|Unknown
#   burst20_secs=N|timeout   seconds until all 20 pods Ready, or "timeout" (hard cap hit)
#   burst_pods=N             size of the large burst (the gated no-swap ceiling candidate)
#   burst_secs=N|timeout     seconds until all burst_pods Ready
#   wp_ok=1|0                WordPress page answered after the burst settled
#   marker_ok=1|0            the marker row written to MariaDB before the bursts is still readable
#   webhook_ok=1|0           scripts/e2e-workload/webhook-smoke.sh passed
#   cal_ref_ms / cal_ref_n   median / count of in-guest CPU calibration loops before install (baseline)
#   cal_idle_ms / cal_idle_n same, at the idle boundary before the first burst (contention probe)
#   marker_fail=TEXT         why the marker could not be written (set with marker_ok=0)
#   harness_error=TEXT       the harness itself broke before the bursts (not a u7s verdict)
# Ramp mode writes install_ok plus, per burst size N: ramp_N_secs (N|timeout),
# ramp_N_oom_host, ramp_N_oom_kubesystem, ramp_N_notready, ramp_N_ready_final, ramp_N_wp_ok,
# ramp_N_marker_ok.
# A missing key is a FAIL, never a pass: a run that died halfway must not look green.
#
# A run's status is PASS, FAIL or INVALID. INVALID means host contention was observed
# (rg_contention_reasons) on a run that did not pass: the failure cannot be blamed on u7s,
# so the run is repeated and never counted. A PASS under contention stays a PASS.

BURST_CAP_SECS="${BURST_CAP_SECS:-300}"
RG_IDLE_MIN_PCT=70
RG_CAL_MAX_RATIO_X10=15
RG_CAL_MIN_SAMPLES=3
# Pattern for pkill -f inside the VM: every script the gate runs there is started as
# `bash /var/tmp/rg/<name>.sh`. Anchored so the pkill's own wrapper shell never matches.
RG_VM_KILL_PATTERN='^bash /var/tmp/rg/[a-z-]+\.sh'

rg_get() {
  local file="$1" key="$2"
  grep -m1 "^${key}=" "$file" 2>/dev/null | cut -d= -f2-
}

# Classifies one kernel OOM victim: host | kube-system | other.
# $1 comm of the killed task, $2 task_memcg cgroup path, $3 space-separated kube-system
# pod UIDs in cgroup spelling (underscores instead of dashes).
rg_classify_oom() {
  local task="$1" memcg="$2" uids="$3" uid
  case "$task" in
    u7s-apiserver|u7s-scheduler|kube-controller|kubelet|crio) echo host; return ;;
    # By comm too: a pod created and killed between two UID snapshots (or during an API
    # outage) is missing from the UID map and would otherwise be classed "other".
    coredns|kube-proxy|flanneld) echo kube-system; return ;;
  esac
  case "$memcg" in
    */system.slice/u7s-*.service*|*/system.slice/kubelet.service*|*/system.slice/crio.service*) echo host; return ;;
  esac
  for uid in $uids; do
    case "$memcg" in *"$uid"*) echo kube-system; return ;; esac
  done
  echo other
}

# Reads kernel log text on stdin, prints "<class> <task>" for every `oom-kill:` line.
rg_oom_victims() {
  local uids="$1" line task memcg
  while IFS= read -r line; do
    case "$line" in *"oom-kill:"*) ;; *) continue ;; esac
    task="${line#*,task=}"; task="${task%%,*}"
    memcg="${line#*task_memcg=}"; memcg="${memcg%%,*}"
    echo "$(rg_classify_oom "$task" "$memcg" "$uids") $task"
  done
}

_rg_is_num() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

# Reads `kubectl get deployment -w -o jsonpath={.status.readyReplicas}` lines on stdin;
# returns 0 once a line equals $1 (all replicas Ready), 1 if the stream ends first. An
# unset readyReplicas prints an empty line, which never equals a positive target.
rg_wait_ready() {
  local want="$1" line
  while IFS= read -r line; do
    [ "$line" = "$want" ] && return 0
  done
  return 1
}

# Turns `kubectl get node -w` output ("<status> <lastTransitionTime>" per line) into
# node-ready.log lines ("<epoch> <status>"). The watch replays condition history on
# (re)connect, so the epoch is the condition's own lastTransitionTime (the read time only
# when that is missing/unparseable); rg_notready_since then drops replayed pre-burst flaps.
# Consecutive identical lines are collapsed.
rg_node_watch_stamp() {
  local s tt t last=""
  while read -r s tt; do
    t=""
    if [ -n "$tt" ]; then
      t="$(date -d "$tt" +%s 2>/dev/null || date -u -j -f %Y-%m-%dT%H:%M:%SZ "$tt" +%s 2>/dev/null)" || t=""
    fi
    [ -n "$t" ] || t="$(date +%s)"
    [ "$t $s" = "$last" ] || printf '%s %s\n' "$t" "${s:-Unknown}"
    last="$t $s"
  done
}

# Counts Ready!=True observations with epoch >= $2 in a node-ready.log ("<epoch> <status>").
# An "unreachable" poll (API down: a dead apiserver is the worst not-Ready) counts too.
rg_notready_since() {
  awk -v t0="$2" '$1 >= t0 && ($2 == "False" || $2 == "Unknown" || $2 == "unreachable") {n++} END {print n + 0}' "$1"
}

# --- collectors (pure: take kernel-log / kubectl text on stdin) ---

# Reads "<namespace> <uid>" lines, prints the UIDs of kube-system / kube-flannel pods.
rg_kubesystem_uids() {
  awk '$1 == "kube-system" || $1 == "kube-flannel" {print $2}'
}

# UID file (one per line, dashes) -> cgroup spelling (underscores), space separated, unique.
rg_uids_cgroup() {
  sort -u "$1" | tr - _ | tr '\n' ' '
}

# Reads rg_oom_victims output on stdin, prints "<host count> <kube-system count>".
rg_oom_counts() {
  local v
  v="$(cat)"
  echo "$(echo "$v" | grep -c '^host ') $(echo "$v" | grep -c '^kube-system ')"
}

# Marker check for criterion (d): the row written to the DB before the bursts must read back
# equal. An empty expected value never matches, so a recreated (empty) emptyDir DB, which
# WordPress answers with a 302 to its installer, cannot pass.
rg_marker_ok() {
  [ -n "$1" ] && [ "$1" = "$2" ] && echo 1 || echo 0
}

# --- host contention (INVALID verdict) ---

# Reads `limactl list` on stdin, prints names of Running VMs other than $1.
rg_other_vms() {
  awk -v own="$1" '$2 == "Running" && $1 != own {print $1}'
}

# `top -l 2` (macOS) output on stdin -> idle CPU % of the last sample (the first is since boot).
rg_idle_from_top() {
  awk '/^CPU usage:/ {for (i = 1; i <= NF; i++) if ($i == "idle") {x = $(i - 1); sub("%", "", x); v = x}}
       END {if (v != "") printf "%d\n", v}'
}

# `vmstat N 2` (Linux) output on stdin -> idle CPU % of the last sample.
rg_idle_from_vmstat() {
  awk 'NF >= 15 && $15 ~ /^[0-9]+$/ {v = $15} END {if (v != "") print v}'
}

# Idle CPU % of the host over QUIET_SAMPLE_SECS (default 30). RG_IDLE_PROBE overrides the
# measurement with a command printing the percentage. Prints nothing on failure.
rg_host_idle_pct() {
  local s="${QUIET_SAMPLE_SECS:-30}"
  if [ -n "${RG_IDLE_PROBE:-}" ]; then "$RG_IDLE_PROBE"
  elif [ "$(uname)" = Darwin ]; then top -l 2 -s "$s" -n 0 2>/dev/null | rg_idle_from_top
  else vmstat "$((s > 0 ? s : 1))" 2 2>/dev/null | rg_idle_from_vmstat
  fi
}

# Share of the host CPU (percentage points) the gate VM itself can take: its vCPUs over the
# host's cores. Its own bursting must not read as foreign contention. $1 vCPUs, $2 host cores.
rg_vm_cpu_allow_pct() {
  _rg_is_num "$1" && _rg_is_num "$2" && [ "$2" -gt 0 ] || { echo 0; return; }
  echo $((100 * $1 / $2))
}

# One quiet.log line: "<epoch> <idle%|?> <other running VMs|?> <gate VM CPU allowance %>".
# "?" = could not be measured. The allowance is 0 before the VM exists.
rg_quiet_line() {
  printf '%s %s %s %s\n' "$1" "${2:-?}" "${3:-?}" "${4:-0}"
}

# Prints a reason for every contended line of a quiet.log; an unmeasurable sample counts
# as contended because quiet cannot be proven. The idle floor is lowered by the gate VM's
# own possible CPU share ($4).
rg_quiet_log_reasons() {
  [ -f "$1" ] || return 0
  awk -v min="$RG_IDLE_MIN_PCT" '
    $2 !~ /^[0-9]+$/ {printf "host idle CPU not measurable at %s\n", $1; next}
    {floor = min - ($4 ~ /^[0-9]+$/ ? $4 : 0)}
    $2 < floor {printf "host idle CPU %d%% < %d%% (gate VM allowance %d%%) at %s\n", $2, floor, min - floor, $1}
    $3 != 0 {printf "other Lima VMs running (%s) at %s\n", $3, $1}' "$1"
}

# Runs `$4 $2` (a sampler appending to quiet.log $2) every $3 seconds until file $1 exists.
# A sample in flight at stop time is finished and appended before this returns, so the
# verdict never reads a half-written log and no probe leaks into the next attempt.
rg_quiet_loop() {
  local stop="$1" log="$2" every="$3" sampler="$4" t
  while :; do
    t=0
    while [ "$t" -lt "$every" ] && [ ! -e "$stop" ]; do sleep 1; t=$((t + 1)); done
    [ -e "$stop" ] && return 0
    "$sampler" "$log"
  done
}

# Reads cal.log ("<epoch> <phase> <ms>") for phase $2, prints "<median ms> <count>" or "- 0".
rg_cal_summary() {
  awk -v ph="$2" '$2 == ph && $3 ~ /^[0-9]+$/ {print $3}' "$1" 2>/dev/null | sort -n \
    | awk '{v[NR] = $1} END {if (NR) print v[int(NR / 2) + 1], NR; else print "- 0"}'
}

# The CPU probe judges only when both the pre-install baseline and the idle-boundary phase
# have at least RG_CAL_MIN_SAMPLES samples. Otherwise it is unmeasured and judges nothing:
# a missing probe must not turn a u7s FAIL into INVALID, and host contention is still
# covered by quiet.log. Prints the unmeasured note (empty when measured).
rg_cal_unmeasured() {
  local ref ref_n idle idle_n
  ref="$(rg_get "$1" cal_ref_ms)"; ref_n="$(rg_get "$1" cal_ref_n)"
  idle="$(rg_get "$1" cal_idle_ms)"; idle_n="$(rg_get "$1" cal_idle_n)"
  if _rg_is_num "$ref" && _rg_is_num "$idle" && _rg_is_num "$ref_n" && _rg_is_num "$idle_n" \
     && [ "$ref" -gt 0 ] && [ "$ref_n" -ge "$RG_CAL_MIN_SAMPLES" ] && [ "$idle_n" -ge "$RG_CAL_MIN_SAMPLES" ]; then
    return 0
  fi
  echo "in-guest CPU calibration unmeasured (baseline n=${ref_n:-0}, idle n=${idle_n:-0}, need ${RG_CAL_MIN_SAMPLES} each): judging on the host checks alone"
}

# Prints a reason when the idle-boundary calibration median exceeds 1.5x the pre-install
# baseline taken in the same VM. Only idle boundaries are sampled: u7s's own teardown load
# after a burst is the thing under test and must never read as contention.
rg_cal_reason() {
  [ -z "$(rg_cal_unmeasured "$1")" ] || return 0
  local ref idle
  ref="$(rg_get "$1" cal_ref_ms)"; idle="$(rg_get "$1" cal_idle_ms)"
  [ $((idle * 10)) -le $((ref * RG_CAL_MAX_RATIO_X10)) ] \
    || echo "in-guest CPU calibration ${idle}ms > 1.5x pre-install baseline ${ref}ms"
}

# Contention evidence for a run: $1 quiet.log, $2 results file. Empty output = none.
rg_contention_reasons() {
  rg_quiet_log_reasons "$1"
  rg_cal_reason "$2"
}

# PASS / FAIL / INVALID for one run. $1 verdict exit code, $2 quiet.log, $3 results file.
# PASS stays PASS under contention; a non-pass under contention is INVALID.
rg_run_status() {
  if [ "$1" = 0 ]; then echo PASS
  elif [ -n "$(rg_get "$3" harness_error)" ]; then echo INVALID
  elif [ -n "$(rg_contention_reasons "$2" "$3")" ]; then echo INVALID
  else echo FAIL
  fi
}

# Classifies a kubectl probe: $1 exit code, $2 combined output. Echoes
#   ok          the probe ran and succeeded
#   answered    the API answered with an error (non-2xx, NotFound): a u7s answer
#   unreachable refused / timeout / hang: the API is not answering (u7s)
#   error       anything else (bad kubeconfig, missing binary): a harness problem
rg_probe_kind() {
  local rc="$1" out="$2"
  if [ "$rc" = 0 ]; then echo ok
  elif [[ "$out" == *"Error from server"* ]]; then echo answered
  elif [ "$rc" = 124 ] || [[ "$out" == *refused* || "$out" == *"Unable to connect"* || "$out" == *timeout* || "$out" == *EOF* || "$out" == *"no route"* ]]; then echo unreachable
  else echo error
  fi
}

# Records a failed pre-burst marker write into results file $1. $2 = mariadb-0 was Ready at the
# earlier wait (1|0). Probes taken now, at failure time: $3/$4 = exit code/output of
# `kubectl get --raw /readyz`, $5/$6 = exit code/output of the mariadb-0 Ready-condition status.
# Mapping: any probe showing u7s misbehaving (API unreachable or answering an error, pod not
# Ready) is marker_ok=0 (FAIL), checked first so ambiguity goes to FAIL. Only when no probe shows
# u7s failing is it harness_error (INVALID): a probe command that itself errored, or everything
# healthy while the write still failed.
rg_record_marker_write_failure() {
  local f="$1" was_ready="$2" ak rk pod=ready
  ak="$(rg_probe_kind "$3" "$4")"
  rk="$(rg_probe_kind "$5" "$6")"
  case "$rk" in
    ok) [ "$(echo "$6" | tr -d '[:space:]')" = True ] || pod=notready ;;
    answered | unreachable) pod=notready ;;
    error) pod=error ;;
  esac
  if [ "$ak" = unreachable ]; then
    echo "marker_ok=0" >> "$f"
    echo "marker_fail=API unreachable after the marker write failed (u7s failure)" >> "$f"
  elif [ "$ak" = answered ]; then
    echo "marker_ok=0" >> "$f"
    echo "marker_fail=API answered /readyz with an error after the marker write failed (u7s failure)" >> "$f"
  elif [ "$pod" = notready ] && [ "$was_ready" = 1 ]; then
    echo "marker_ok=0" >> "$f"
    echo "marker_fail=mariadb-0 became not Ready before the marker write, marker not written (u7s failure)" >> "$f"
  elif [ "$pod" = notready ]; then
    echo "marker_ok=0" >> "$f"
    echo "marker_fail=mariadb-0 never became Ready, marker not written (u7s pod-start failure)" >> "$f"
  elif [ "$ak" = error ] || [ "$pod" = error ]; then
    echo "harness_error=marker write failed and a probe command errored (kubectl/kubeconfig), cannot attribute to u7s" >> "$f"
  else
    echo "harness_error=marker write to MariaDB failed although mariadb-0 is Ready and the API answers" >> "$f"
  fi
}

# Call-site decision for a failed marker write: runs the failure-time probes via the caller's
# `k` (timeout-wrapped kubectl) and records the classification into results file $1. $2 = was Ready.
rg_probe_and_record_marker_failure() {
  local f="$1" was_ready="$2" aout arc pout prc
  arc=0 prc=0
  aout="$(k get --raw /readyz 2>&1)" || arc=$?
  pout="$(k -n default get pod mariadb-0 -o 'jsonpath={.status.conditions[?(@.type=="Ready")].status}' 2>&1)" || prc=$?
  rg_record_marker_write_failure "$f" "$was_ready" "$arc" "$aout" "$prc" "$pout"
}

# Forced-failure self-check: $1 results file, $2 the VM's phase file. OK (0) only when install
# succeeded, the run got to the burst phases, and a burst criterion (a)-(c) FAILed there.
rg_forced_failure_check() {
  local f="$1" phase verdict
  phase="$(cat "$2" 2>/dev/null)"
  [ "$(rg_get "$f" install_ok)" = 1 ] || { echo "forced-failure NOT OK: install did not succeed"; return 1; }
  case "$phase" in
    burst*|settle*|wpcheck|webhook|collect) ;;
    *) echo "forced-failure NOT OK: run never reached the burst phases (last phase: ${phase:-none})"; return 1 ;;
  esac
  verdict="$(rg_verdict "$f")" || true
  echo "$verdict" | grep -qE '^FAIL +\((a|b|c)\) ' \
    || { echo "forced-failure NOT OK: no burst criterion (a)-(c) failed"; return 1; }
  echo "forced-failure OK: burst reached and failed there"
}

# Minimum MemAvailable (MiB) over samples.tsv rows of phase $2, or "-" when none.
rg_phase_memmin() {
  awk -F'\t' -v ph="$2" '$2 == ph && $3 == "MEM" {v = $4 / 1024; if (!s || v < m) {m = v; s = 1}} END {if (s) printf "%.0f\n", m; else print "-"}' "$1"
}

# Validates a ramp list ("30,40,50": strictly increasing positive integers) and prints it
# space-separated. Non-zero on anything else.
rg_parse_ramp() {
  local list="$1" part prev=0 out=""
  [ -n "$list" ] || return 1
  case "$list" in *,|,*|*,,*) return 1 ;; esac
  local IFS=,
  for part in $list; do
    _rg_is_num "$part" || return 1
    [ "$part" -gt "$prev" ] || return 1
    prev="$part"; out="$out $part"
  done
  echo "${out# }"
}

# One ramp step's criteria (a)-(d) from the results file. Prints "<a> <b> <c> <d>" as
# PASS/FAIL, or "notrun" when the step produced no burst result. Returns 0 iff all PASS.
# Criterion (e) (webhook-smoke) is not per-size and is left to the full-gate confirmation.
rg_ramp_step() {
  local f="$1" n="$2" secs oomh oomk nr rf wp mk a=FAIL b=FAIL c=FAIL d=FAIL
  secs="$(rg_get "$f" "ramp_${n}_secs")"
  [ -n "$secs" ] || { echo notrun; return 1; }
  oomh="$(rg_get "$f" "ramp_${n}_oom_host")"; oomk="$(rg_get "$f" "ramp_${n}_oom_kubesystem")"
  nr="$(rg_get "$f" "ramp_${n}_notready")"; rf="$(rg_get "$f" "ramp_${n}_ready_final")"
  wp="$(rg_get "$f" "ramp_${n}_wp_ok")"
  mk="$(rg_get "$f" "ramp_${n}_marker_ok")"
  if _rg_is_num "$oomh" && _rg_is_num "$oomk" && [ "$oomh" -eq 0 ] && [ "$oomk" -eq 0 ]; then a=PASS; fi
  if _rg_is_num "$nr" && [ "$nr" -eq 0 ] && [ "$rf" = True ]; then b=PASS; fi
  if _rg_is_num "$secs" && [ "$secs" -le "$BURST_CAP_SECS" ]; then c=PASS; fi
  [ "$wp" = 1 ] && [ "$mk" = 1 ] && d=PASS
  echo "$a $b $c $d"
  [ "$a $b $c $d" = "PASS PASS PASS PASS" ]
}

# Ramp summary: $1 results file, $2 space-separated sizes, $3 samples.tsv. Prints the
# per-size table and the candidate N (largest size before the first failure). Returns 0
# iff install succeeded and at least one size passed.
rg_ramp_verdict() {
  local f="$1" sizes="$2" samples="$3" n cand="" stopped="" row secs ok failed="" unreach="" skipped=""
  printf '%-6s %-5s %-5s %-5s %-5s %-9s %s\n' size '(a)' '(b)' '(c)' '(d)' burst_s memavail_min_MiB
  for n in $sizes; do
    row="$(rg_ramp_step "$f" "$n")" && ok=1 || ok=0
    if [ "$row" = notrun ]; then
      printf '%-6s not run\n' "$n"; skipped="$skipped $n"; continue
    fi
    secs="$(rg_get "$f" "ramp_${n}_secs")"
    printf '%-6s %-5s %-5s %-5s %-5s %-9s %s\n' "$n" $row "$secs" "$(rg_phase_memmin "$samples" "burst$n")"
    if [ "$ok" = 1 ] && [ -z "$stopped" ]; then cand="$n"; else stopped=1; fi
    [ "$ok" = 1 ] || failed="${failed:-$n}"
    [ -n "$(rg_get "$f" "ramp_${n}_ready_final")" ] || unreach="${unreach:-$n}"
  done
  echo "RAMP: criterion (e) webhook-smoke is NOT evaluated per size; it runs only in the full-gate confirmation runs"
  if [ -n "$unreach" ]; then
    echo "RAMP: API unreachable at the end of the $unreach-pod step (VM or control plane died); later sizes were not tested"
  elif [ -n "$failed" ]; then
    echo "RAMP: stopped at the first criterion failure ($failed-pod burst)"
  elif [ -n "$skipped" ]; then
    echo "RAMP: ended early with no criterion failure; sizes not run:$skipped (VM died or run hit its wall-clock cap)"
  fi
  if [ "$(rg_get "$f" install_ok)" != 1 ]; then
    echo "RAMP: install failed (install_ok=$(rg_get "$f" install_ok))"; return 1
  fi
  if [ -n "$cand" ]; then
    echo "RAMP: candidate N=$cand -- approximate (single VM, state carryover); confirm with fresh full-gate runs"
    return 0
  fi
  echo "RAMP: no size passed"; return 1
}

_rg_row() { printf '%-4s %-5s %s\n' "$1" "$2" "$3"; }

# Prints the per-criterion table for one results file; returns 1 if any criterion FAILs.
rg_verdict() {
  local f="$1" cap="$BURST_CAP_SECS" rc=0
  local install oomh oomk notready ready_final b20 bn np wp mk wh

  install="$(rg_get "$f" install_ok)"
  oomh="$(rg_get "$f" oom_host)"
  oomk="$(rg_get "$f" oom_kubesystem)"
  notready="$(rg_get "$f" notready_events)"
  ready_final="$(rg_get "$f" node_ready_final)"
  b20="$(rg_get "$f" burst20_secs)"
  bn="$(rg_get "$f" burst_secs)"; np="$(rg_get "$f" burst_pods)"
  wp="$(rg_get "$f" wp_ok)"
  mk="$(rg_get "$f" marker_ok)"
  wh="$(rg_get "$f" webhook_ok)"

  _check() {
    local id="$1" ok="$2" detail="$3"
    if [ "$ok" = 1 ]; then _rg_row PASS "$id" "$detail"; else _rg_row FAIL "$id" "$detail"; rc=1; fi
  }
  _is_num() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
  _burst_ok() { _is_num "$1" && [ "$1" -le "$cap" ] && echo 1 || echo 0; }

  _check install "$([ "$install" = 1 ] && echo 1 || echo 0)" "install.sh + node Ready (install_ok=${install:-missing})"

  local a=0
  if _is_num "$oomh" && _is_num "$oomk" && [ "$oomh" -eq 0 ] && [ "$oomk" -eq 0 ]; then a=1; fi
  _check "(a)" "$a" "no OOM kill of control-plane host process or kube-system pod (host=${oomh:-missing} kube-system=${oomk:-missing} victims: $(rg_get "$f" oom_victims))"

  local b=0
  if _is_num "$notready" && [ "$notready" -eq 0 ] && [ "$ready_final" = True ]; then b=1; fi
  _check "(b)" "$b" "node Ready throughout (not-Ready observations=${notready:-missing}, final=${ready_final:-missing})"

  local c=0
  if [ "$(_burst_ok "$b20")" = 1 ] && [ "$(_burst_ok "$bn")" = 1 ] && _is_num "$np"; then c=1; fi
  _check "(c)" "$c" "each burst within ${cap}s (20-pod=${b20:-missing}$(_is_num "$b20" && echo s), ${np:-?}-pod=${bn:-missing}$(_is_num "$bn" && echo s))"

  _check "(d)" "$([ "$wp" = 1 ] && [ "$mk" = 1 ] && echo 1 || echo 0)" "WordPress responds and the pre-burst DB marker survived (wp_ok=${wp:-missing} marker_ok=${mk:-missing}$(rg_get "$f" marker_fail | sed 's/^./; &/'))"
  _check "(e)" "$([ "$wh" = 1 ] && echo 1 || echo 0)" "webhook-smoke.sh passes (webhook_ok=${wh:-missing})"

  # Not a criterion: kubelet memory-pressure evictions delete pods without an OOM kill.
  _rg_row INFO "" "evicted pods: $(rg_get "$f" evicted_pods) api-unreachable polls: $(rg_get "$f" api_unreachable_polls)"

  if [ "$rc" -eq 0 ]; then echo "RESULT: PASS (${np:-?}-pod burst)"; else echo "RESULT: FAIL (${np:-?}-pod burst)"; fi
  return "$rc"
}

# Confirm-mode decision. Args: one "<pods>:<passed>:<valid>:<total>" per size tried, largest
# first (valid = runs not INVALID). The gated no-swap ceiling is the first size where every
# run passed. A size with a valid FAIL is failed for good and the next smaller size is tried;
# a size that merely ran out of valid runs (host noise) ends the confirmation INVALID (exit 3)
# instead of dropping to a smaller size. Returns 1 when none confirmed.
rg_confirm_verdict() {
  local t pods passed valid total
  for t in "$@"; do
    IFS=: read -r pods passed valid total <<< "$t"
    echo "CONFIRM: ${pods}-pod burst passed ${passed}/${total} runs (${valid} valid)"
    if [ "${total:-0}" -ge 1 ] && [ "$passed" = "$total" ]; then
      echo "CONFIRM: PASS -- gated no-swap burst ceiling = ${pods} pods (${passed}/${total} on a quiet host)"
      return 0
    fi
    if [ "$passed" = "$valid" ]; then
      echo "CONFIRM: INVALID -- only ${valid}/${total} valid runs at ${pods} pods (host contention); re-run on a quiet host"
      return 3
    fi
  done
  echo "CONFIRM: FAIL -- no size passed on every run; no gated no-swap ceiling"
  return 1
}

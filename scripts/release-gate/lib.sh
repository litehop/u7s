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
#   steal_idle_pct=N.N       in-guest steal time over the idle window (a shared-core host's noise)
#   steal_run_pct=N.N        steal over the whole run so far (informational; never judged)
#   watch_t0=EPOCH           when the node-ready watch started (notready_events counts from here)
#   wedge_reason=TEXT        the burst was aborted early because the guest wedged (rg_wedge_reason)
#   tally_note=TEXT         set when the node tally was rebuilt host-side (rg_fill_tally)
#   marker_fail=TEXT        why the marker could not be written (set with marker_ok=0)
#   harness_error=TEXT       the harness itself broke before the bursts (not a u7s verdict)
# Ramp mode writes install_ok plus, per burst size N: ramp_N_secs (N|timeout),
# ramp_N_oom_host, ramp_N_oom_kubesystem, ramp_N_notready, ramp_N_ready_final, ramp_N_wp_ok,
# ramp_N_marker_ok.
# A missing key is a FAIL, never a pass: a run that died halfway must not look green.
#
# A run's status is PASS, FAIL or INVALID. INVALID means host contention was observed
# (rg_contention_reasons) or the harness errored, whatever the verdict: validity never depends
# on the outcome, so a contended PASS and a contended FAIL are both repeated and never counted.

BURST_CAP_SECS="${BURST_CAP_SECS:-300}"
RG_IDLE_MIN_PCT=70
RG_CAL_MAX_RATIO_X10=15
RG_CAL_MIN_SAMPLES=3
RG_STEAL_MAX_PCT=10
RG_WEDGE_SECS=60
RG_WEDGE_IOWAIT_PCT=0
RG_WEDGE_STALL_SECS=120
RG_JIFFIES_PER_SEC=100
# Pattern for pkill -f inside the VM: every script the gate runs there is started as
# `bash /var/tmp/rg/<name>.sh`. Anchored so the pkill's own wrapper shell never matches.
RG_VM_KILL_PATTERN='^bash /var/tmp/rg/[a-z-]+\.sh'

# Kills PID and every descendant (the ssh client sits several processes below a backgrounded
# shell function); descendants are listed first because killing the parent reparents them.
rg_kill_tree() {
  local pids="$1" p i=1
  while [ "$i" -le "$(wc -w <<<"$pids")" ]; do
    p="$(cut -d' ' -f"$i" <<<"$pids")"
    pids="$pids $(pgrep -P "$p" 2>/dev/null | tr '\n' ' ')"
    i=$((i + 1))
  done
  # shellcheck disable=SC2086
  kill $pids 2>/dev/null
  return 0
}

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

# Kernel-log "Killed process" lines on stdin -> "<comm> <oom_score_adj> <anon-rss kB>" per victim.
rg_oom_events() {
  local line comm adj rss
  while IFS= read -r line; do
    case "$line" in *"Killed process "*) ;; *) continue ;; esac
    comm="${line#*Killed process * (}"; comm="${comm%%)*}"
    adj="${line##*oom_score_adj:}"; adj="${adj%% *}"
    rss="${line#*anon-rss:}"; rss="${rss%%kB*}"
    echo "$comm $adj $rss"
  done
}

_rg_is_num() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

# Reads `kubectl get deployment -w -o jsonpath={.status.readyReplicas}` lines on stdin;
# returns 0 once a line equals $1 (all replicas Ready), 1 if the stream ends first. An
# unset readyReplicas prints an empty line, which never equals a positive target.
rg_wait_ready() {
  local want="$1" prog="${2:-/dev/null}" line last
  last="$(tail -n 1 "$prog" 2>/dev/null | cut -d' ' -f2)" || true
  while IFS= read -r line; do
    [ "${line:-0}" = "$last" ] || printf '%s %s\n' "$(date +%s)" "${line:-0}" >> "$prog"
    last="${line:-0}"
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

# Wedge detection during a burst. $1 now (epoch), $2 node-ready.log, $3 attrib.tsv (STAT rows,
# jiffies; see vm-sampler.sh), $4 burst-progress.log ("<epoch> <ready pods>" per change, first
# line at burst start). Prints a reason when the node has been not Ready / the API unreachable
# for >= RG_WEDGE_SECS, or the Ready-pod count has not changed for RG_WEDGE_STALL_SECS once the
# burst has run BURST_CAP_SECS (catches reclaim thrash: node Ready, iowait ~0, sys CPU ~100%, without
# waiting for the 600 s kill; a burst that stalls early but finishes inside the cap passes criterion
# (c), so the signal is held back until the cap and never FAILs a would-be pass), or the CPU spent >= RG_WEDGE_IOWAIT_PCT
# of the last RG_WEDGE_SECS in iowait (RG_JIFFIES_PER_SEC = vCPUs x USER_HZ). Prints nothing
# otherwise. A threshold of 0 disables that signal; RG_WEDGE_SECS=0 disables all. Memory PSI
# "full" is deliberately not a signal: healthy bursts that pass criterion (c) reach 40-68% over
# 60 s windows (wedge-calibrate.sh), so no threshold separates them from a thrash; a stalled
# ready count does.
rg_wedge_reason() {
  local now="$1" w="${RG_WEDGE_SECS:-60}" r
  [ "$w" -gt 0 ] 2>/dev/null || return 0
  r="$(awk -v now="$now" -v w="$w" '
    $2 == "True" {run = 0; next}
    NF >= 2 {if (!run) {run = 1; start = $1}; st = $2}
    END {
      if (run && now - start >= w) {
        if (st == "unreachable") printf "API unreachable for %ds\n", now - start
        else printf "node Ready=%s for %ds\n", st, now - start
      }
    }' "$2" 2>/dev/null)"
  if [ -n "$r" ]; then echo "$r"; return 0; fi
  r="$(awk -F'\t' -v now="$now" -v w="$w" -v thr="${RG_WEDGE_IOWAIT_PCT:-0}" -v jps="${RG_JIFFIES_PER_SEC:-100}" '
    $3 == "STAT" {n++; ts[n] = $1; io[n] = $6}
    END {
      if (thr <= 0 || !n || now - ts[n] > w) exit
      for (i = 1; i < n && ts[i] < ts[n] - w; i++) ;
      span = ts[n] - ts[i]
      if (span < w * 0.8) exit
      pct = 100 * (io[n] - io[i]) / (span * jps)
      if (pct >= thr) printf "iowait %.0f%% over the last %ds\n", pct, span
    }' "$3" 2>/dev/null)"
  if [ -n "$r" ]; then echo "$r"; return 0; fi
  awk -v now="$now" -v s="${RG_WEDGE_STALL_SECS:-0}" -v cap="${BURST_CAP_SECS:-300}" '
    NF >= 2 {if (!b) b = $1; t = $1; n = $2}
    END { if (s > 0 && t && now - b >= cap && now - t >= s) printf "no burst progress for %ds (%d pods Ready)\n", now - t, n }' "${4:-/dev/null}" 2>/dev/null
  return 0
}

# Prints the PID in pidfile $1 only if it is still the burst watch (cmdline under proc root $2,
# default /proc): a watch that exited leaves its PID free for an unrelated process, and the
# wedge monitor must never kill that.
rg_burst_watch_pid() {
  local pid cmd
  pid="$(cat "$1" 2>/dev/null)" || return 0
  case "$pid" in ''|*[!0-9]*) return 0 ;; esac
  [ -r "${2:-/proc}/$pid/cmdline" ] || return 0
  cmd="$(tr '\0' ' ' < "${2:-/proc}/$pid/cmdline")" || return 0
  case "$cmd" in *"get deployment rg-burst"*) echo "$pid" ;; esac
}

# Reads `kubectl get pods -A` lines "<ns> <name> <phase> <Ready status>" on stdin and prints
# "<ns> <name>" of pods that are not Ready (finished pods and the burst workload excluded), max 20.
rg_notready_pods() {
  awk '{r = (NF >= 4 ? $4 : "")} $3 != "Succeeded" && r != "True" && $2 !~ /^rg-burst-/ {print $1, $2}' | head -n 20
}

# Fills the node tally into results file $1 from node-ready.log $2 when the run died before the
# final tally was written (no notready_events key). A dead guest's last Ready=True is stale, so
# node_ready_final stays "unconfirmed" unless the last observation was itself not Ready.
rg_fill_tally() {
  local f="$1" log="$2" last t0
  [ -z "$(rg_get "$f" notready_events)" ] && [ -s "$log" ] || return 0
  last="$(tail -n 1 "$log" | cut -d' ' -f2)" || true
  t0="$(rg_get "$f" watch_t0)" || true
  {
    echo "notready_events=$(rg_notready_since "$log" "${t0:-0}")"
    echo "api_unreachable_polls=$(grep -c ' unreachable$' "$log")"
    echo "node_ready_final=$([ "$last" = True ] && echo unconfirmed || echo "$last")"
    echo "tally_note=run died before the final tally; node figures rebuilt from node-ready.log, OOM counts unknown"
  } >> "$f"
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

# Steal time over a window, from two `cpu` lines of /proc/stat ($1 before, $2 after): percent
# of all CPU time with one decimal. Prints nothing when the lines are unusable or no time passed.
rg_steal_pct() {
  printf '%s\n%s\n' "$1" "$2" | awk '
    $1 == "cpu" && NF >= 9 {
      t = 0; for (i = 2; i <= 9; i++) t += $i
      n++; tot[n] = t; st[n] = $9
    }
    END {
      if (n == 2 && tot[2] > tot[1] && st[2] >= st[1]) printf "%.1f\n", 100 * (st[2] - st[1]) / (tot[2] - tot[1])
    }'
}

# Prints a reason when the idle-window steal time (results key steal_idle_pct, recorded in the
# guest) exceeds RG_STEAL_MAX_PCT. Only idle windows are judged: throttling under the burst is
# the shared-core host's behaviour under u7s's own load, which is what the gate measures. A
# missing value judges nothing, like an unmeasured calibration. Only the gcp backend (BACKEND)
# judges steal: on Lima the host-side checks own contention.
rg_steal_reason() {
  local v
  [ "${BACKEND:-}" = gcp ] || return 0
  v="$(rg_get "$1" steal_idle_pct)"
  [ -n "$v" ] || return 0
  awk -v v="$v" -v max="$RG_STEAL_MAX_PCT" 'BEGIN {exit !(v ~ /^[0-9]+(\.[0-9]+)?$/ && v + 0 > max + 0)}' \
    && echo "in-guest steal time ${v}% over the idle window > ${RG_STEAL_MAX_PCT}% (shared-core host contention)"
  return 0
}

# Contention evidence for a run: $1 quiet.log, $2 results file. Empty output = none.
rg_contention_reasons() {
  rg_quiet_log_reasons "$1"
  rg_cal_reason "$2"
  rg_steal_reason "$2"
}

# Final status of one run on a Spot backend. $1 status from rg_run_status, $2 1 when the
# instance was preempted. A PASS stays PASS; any other outcome of a reclaimed instance is
# PREEMPTED, never FAIL or INVALID: the run was cut short by the platform, not judged.
rg_apply_preemption() {
  if [ "$1" != PASS ] && [ "$2" = 1 ]; then echo PREEMPTED; else echo "$1"; fi
}

# PASS / FAIL / INVALID for one run. $1 verdict exit code, $2 quiet.log, $3 results file.
# Contention or a harness error makes the run INVALID regardless of the verdict.
rg_run_status() {
  if [ -n "$(rg_get "$3" harness_error)" ]; then echo INVALID
  elif [ -n "$(rg_contention_reasons "$2" "$3")" ]; then echo INVALID
  elif [ "$1" = 0 ]; then echo PASS
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

# Recovery probe log: "<epoch> <1|0>" per probe, 1 = node Ready AND API /readyz AND WordPress 200
# (WordPress only when deployed). Prints seconds from $2 (overload start) to the first probe of a
# streak of 1s that lasted at least $3 seconds, or "none". A 0, or a gap above $4 seconds between
# consecutive probes (a hung or frozen node cannot be shown to have held), breaks the streak; the
# next 1 starts a new one. The vm-gate probes every 5 s, so it passes 15 (3 intervals).
rg_recovery_secs() {
  awk -v t0="$2" -v hold="$3" -v gap="$4" '
    $2 == 1 { if (s && $1 - last > gap) s = 0; if (!s) s = $1; last = $1; if ($1 - s >= hold) { print s - t0; found = 1; exit } }
    $2 != 1 { s = 0 }
    END { if (!found) print "none" }' "$1"
}

# Overload verdict from results file $1: a measurement, not a PASS. 0 only when the node recovered.
rg_overload_verdict() {
  local f="$1" rec
  [ "$(rg_get "$f" install_ok)" = 1 ] || { echo "RESULT: FAIL (install or node Ready; no overload ran)"; return 1; }
  rec="$(rg_get "$f" recovery_secs)"
  if _rg_is_num "$rec"; then
    echo "RESULT: RECOVERED ${rec}s after overload start ($(rg_get "$f" overload_pods) pods x $(rg_get "$f" overload_mib) MiB), held $(rg_get "$f" recovery_hold_secs)s; final: $(rg_get "$f" overload_final)"
    return 0
  fi
  echo "RESULT: NOT RECOVERED within $(rg_get "$f" overload_window_secs)s of overload start ($(rg_get "$f" overload_pods) pods x $(rg_get "$f" overload_mib) MiB); final: $(rg_get "$f" overload_final)"
  return 1
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
  [ -z "$(rg_get "$f" wedge_reason)" ] || echo "RAMP: WEDGE, burst aborted early: $(rg_get "$f" wedge_reason)"
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

# Largest passing step of one ramp verdict file ($1), or "none".
rg_ramp_knee() {
  local n
  n="$(sed -n 's/^RAMP: candidate N=\([0-9][0-9]*\) .*/\1/p' "$1")"
  echo "${n:-none}"
}

# Final line of a ramp invocation. $1 sizes, $2 knee per valid run (space-separated), $3 verdict,
# $4 out dir. A ramp's knee is not a gate pass at the top step, so no "passed at N pods".
rg_ramp_summary() {
  echo "==== RAMP: steps [$1], knee (largest passing step) per valid run:${2:- none} -> $3 (results in $4) ===="
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
  _rg_row INFO "" "evicted pods: $(rg_get "$f" evicted_pods) api-unreachable polls: $(rg_get "$f" api_unreachable_polls) steal-run: $(rg_get "$f" steal_run_pct)%"
  [ -z "$(rg_get "$f" wedge_reason)" ] || _rg_row INFO "" "WEDGE: burst aborted early, $(rg_get "$f" wedge_reason)"
  [ -z "$(rg_get "$f" tally_note)" ] || _rg_row INFO "" "$(rg_get "$f" tally_note)"

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

# Experiment mode (burst-gate.sh --backend gcp --tarball): an unpublished tarball, never a release.
# Echoes why the flag combination is refused, or nothing. $1 backend, $2 --release, $3 --tarball,
# $4 --confirm (0|1), $5 --install-only (0|1).
rg_experiment_args_error() {
  if [ -n "$3" ] && [ -n "$2" ]; then echo "--tarball and --release are mutually exclusive (an experiment installs an unpublished tarball, a release run installs from the mirror)"
  elif [ -n "$3" ] && [ "$1" != gcp ]; then echo "--tarball is only for --backend gcp (lima builds its own tarball; use --tarball-dir)"
  elif [ -n "$3" ] && [ "$4" = 1 ]; then echo "--confirm is the release gate and refuses an EXPERIMENT (unpublished tarball) run"
  elif [ -z "$3" ] && [ "$5" = 1 ]; then echo "--install-only is only for an experiment (--tarball)"
  fi
}

# Echoes why the overload flags are refused, or nothing. $1 --overload-pods, $2 --overload-mib,
# $3 --no-workload (0|1), $4 --ramp, $5 --confirm (0|1), $6 --overload-window-secs.
rg_overload_args_error() {
  local p="$1" m="$2"
  case "$p$m$6" in *[!0-9]*) echo "--overload-pods, --overload-mib and --overload-window-secs must be non-negative integers"; return ;; esac
  if [ "$p" -gt 0 ] && [ "$m" -eq 0 ]; then echo "--overload-pods needs --overload-mib (each pod's anonymous allocation)"
  elif [ "$p" -eq 0 ] && [ "$m" -gt 0 ]; then echo "--overload-mib needs --overload-pods"
  elif [ "$p" -eq 0 ] && [ "$3" = 1 ]; then echo "--no-workload is only for an overload run (--overload-pods)"
  elif [ "$p" -gt 0 ] && { [ -n "$4" ] || [ "$5" = 1 ]; }; then echo "--overload-pods cannot be combined with --ramp or --confirm"
  elif [ "$p" -gt 0 ] && [ "$6" -eq 0 ]; then echo "--overload-window-secs must be positive"
  fi
}

# One-line EXPERIMENT tag from a build-experiment-tarball.sh ".source" file ($1); non-zero if the
# file does not name a ref and sha (an experiment must say what it ran).
rg_experiment_tag() {
  local src ref sha
  src="$(cat "$1" 2>/dev/null)" || return 1
  ref="$(echo "$src" | sed -n 's/^ref=\([^ ]*\) sha=.*/\1/p')"
  sha="$(echo "$src" | sed -n 's/^ref=[^ ]* sha=\([0-9a-f]\{40\}\)$/\1/p')"
  [ -n "$ref" ] && [ -n "$sha" ] || return 1
  echo "EXPERIMENT (unpublished tarball, ref=$ref sha=${sha:0:12}; NOT a release verdict)"
}

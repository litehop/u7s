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
#   burst80_secs=N|timeout
#   wp_ok=1|0                WordPress page answered after the burst settled
#   webhook_ok=1|0           scripts/e2e-workload/webhook-smoke.sh passed
# Ramp mode writes install_ok plus, per burst size N: ramp_N_secs (N|timeout),
# ramp_N_oom_host, ramp_N_oom_kubesystem, ramp_N_notready, ramp_N_ready_final, ramp_N_wp_ok.
# A missing key is a FAIL, never a pass: a run that died halfway must not look green.

BURST_CAP_SECS="${BURST_CAP_SECS:-300}"

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
# "unreachable" is not counted, matching criterion (b) of the full gate.
rg_notready_since() {
  awk -v t0="$2" '$1 >= t0 && ($2 == "False" || $2 == "Unknown") {n++} END {print n + 0}' "$1"
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
  local f="$1" n="$2" secs oomh oomk nr rf wp a=FAIL b=FAIL c=FAIL d=FAIL
  secs="$(rg_get "$f" "ramp_${n}_secs")"
  [ -n "$secs" ] || { echo notrun; return 1; }
  oomh="$(rg_get "$f" "ramp_${n}_oom_host")"; oomk="$(rg_get "$f" "ramp_${n}_oom_kubesystem")"
  nr="$(rg_get "$f" "ramp_${n}_notready")"; rf="$(rg_get "$f" "ramp_${n}_ready_final")"
  wp="$(rg_get "$f" "ramp_${n}_wp_ok")"
  if _rg_is_num "$oomh" && _rg_is_num "$oomk" && [ "$oomh" -eq 0 ] && [ "$oomk" -eq 0 ]; then a=PASS; fi
  if _rg_is_num "$nr" && [ "$nr" -eq 0 ] && [ "$rf" = True ]; then b=PASS; fi
  if _rg_is_num "$secs" && [ "$secs" -le "$BURST_CAP_SECS" ]; then c=PASS; fi
  [ "$wp" = 1 ] && d=PASS
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
  local install oomh oomk notready ready_final b20 b80 wp wh

  install="$(rg_get "$f" install_ok)"
  oomh="$(rg_get "$f" oom_host)"
  oomk="$(rg_get "$f" oom_kubesystem)"
  notready="$(rg_get "$f" notready_events)"
  ready_final="$(rg_get "$f" node_ready_final)"
  b20="$(rg_get "$f" burst20_secs)"
  b80="$(rg_get "$f" burst80_secs)"
  wp="$(rg_get "$f" wp_ok)"
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
  if [ "$(_burst_ok "$b20")" = 1 ] && [ "$(_burst_ok "$b80")" = 1 ]; then c=1; fi
  _check "(c)" "$c" "each burst within ${cap}s (20-pod=${b20:-missing}$(_is_num "$b20" && echo s), 80-pod=${b80:-missing}$(_is_num "$b80" && echo s))"

  _check "(d)" "$([ "$wp" = 1 ] && echo 1 || echo 0)" "WordPress responds after burst settles (wp_ok=${wp:-missing})"
  _check "(e)" "$([ "$wh" = 1 ] && echo 1 || echo 0)" "webhook-smoke.sh passes (webhook_ok=${wh:-missing})"

  # Not a criterion: kubelet memory-pressure evictions delete pods without an OOM kill.
  _rg_row INFO "" "evicted pods: $(rg_get "$f" evicted_pods) api-unreachable polls: $(rg_get "$f" api_unreachable_polls)"

  if [ "$rc" -eq 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
  return "$rc"
}

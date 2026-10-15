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

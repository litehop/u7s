#!/usr/bin/env bash
# Runs inside the gate VM as root (driven by burst-gate.sh). Installs u7s with the
# zero-argument baked install.sh, deploys WordPress+MariaDB, runs the 20- and 80-pod
# bursts with hard wall-clock caps, runs webhook-smoke.sh, and writes
# $RG/out/results.env (format: see lib.sh) plus raw samples.
#
# Burst workload: pause-image Deployment (BestEffort, like the 2026-10-01 run). Time is
# measured from scaling the warmed-up 1-replica Deployment to N until readyReplicas == N.
set -uo pipefail

RG=/var/tmp/rg
OUT="$RG/out"
KCFG=/var/lib/u7s/kubeconfig
SETTLE_IDLE="${SETTLE_IDLE:-180}"
SETTLE_STEP="${SETTLE_STEP:-60}"
HARD_KILL_SECS=600
PAUSE_IMAGE=registry.k8s.io/pause:3.10

# shellcheck source=lib.sh
. "$RG/lib.sh"
COREDNS_REQ=0; ZRAM_MIB=0; CAPTURE=0; RAMP=""; RAMP_KILL_SECS=180
[ -f "$RG/gate.env" ] && . "$RG/gate.env"
[ -n "$RAMP" ] && HARD_KILL_SECS="$RAMP_KILL_SECS"

mkdir -p "$OUT"
: > "$OUT/results.env"
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }
res() { echo "$1=$2" >> "$OUT/results.env"; }
phase() { echo "$1" > "$OUT/phase"; log "phase: $1"; }
k() { timeout 30 kubectl --kubeconfig "$KCFG" "$@"; }
kw() { kubectl --kubeconfig "$KCFG" "$@"; }

# Scales deployment rg-burst to $1 replicas; echoes seconds until all Ready or "timeout".
# One long-lived `get -w` instead of a kubectl fork per poll: each fork is a fresh Go
# process on a memory-starved node. A dropped watch is re-established after 5 s.
run_burst() {
  local n="$1" start now wpid
  start="$(date +%s)"
  k scale deployment/rg-burst --replicas="$n" >/dev/null 2>&1
  while :; do
    now="$(date +%s)"
    if [ $((now - start)) -ge "$HARD_KILL_SECS" ]; then echo timeout; return; fi
    exec 3< <(exec timeout $((HARD_KILL_SECS - (now - start))) kubectl --kubeconfig "$KCFG" \
      get deployment rg-burst -w -o jsonpath='{.status.readyReplicas}{"\n"}' 2>/dev/null)
    wpid=$!
    if rg_wait_ready "$n" <&3; then
      kill "$wpid" 2>/dev/null; exec 3<&-
      echo $(( $(date +%s) - start )); return
    fi
    exec 3<&-
    sleep 5
  done
}

# Kube-system/flannel pod UIDs, appended to ks-uids.txt. An evicted-and-recreated pod gets a
# new UID, and the kernel OOM log can only be mapped back to a pod through the UID in its
# cgroup path; evicted pods stay listed, so sampling between bursts is enough.
record_uids() {
  k get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.uid}{"\n"}{end}' 2>/dev/null \
    | awk '$1 == "kube-system" || $1 == "kube-flannel" {print $2}' >> "$OUT/ks-uids.txt"
}

# Kernel-log OOM victims since epoch $1, as "<host count> <kube-system count>".
oom_since() {
  local victims
  victims="$(journalctl -k --no-pager --since "$(date -d "@$1" '+%Y-%m-%d %H:%M:%S')" 2>/dev/null \
    | rg_oom_victims "$(sort -u "$OUT/ks-uids.txt" | tr - _ | tr '\n' ' ')")"
  echo "$(echo "$victims" | grep -c '^host ') $(echo "$victims" | grep -c '^kube-system ')"
}

# Memory breakdown while a burst's pods are still running, for per-pod overhead:
# /proc/meminfo kernel-side counters, PSS of the per-pod helper processes, and the
# memory.current of the top-level cgroups (does kubepods.slice or system.slice dominate).
snap() {
  {
    echo "== $1 pods_running=$(pgrep -c -x pause) conmon=$(pgrep -c -x conmon)"
    grep -E '^(MemTotal|MemAvailable|Cached|Active\(file\)|Inactive\(file\)|AnonPages|Slab|SReclaimable|SUnreclaim|PageTables|KernelStack|Percpu|Shmem):' /proc/meminfo
    for comm in conmon pause crio kubelet kube-controller u7s-apiserver; do
      for p in $(pgrep -x "$comm" || true); do cat "/proc/$p/smaps_rollup" 2>/dev/null; done \
        | awk -v n="$comm" '/^Pss:/ {pss+=$2} END {printf "pss_kb %s %d\n", n, pss}'
    done
    for c in /sys/fs/cgroup/*.slice /sys/fs/cgroup/*/*.slice; do
      [ -f "$c/memory.current" ] && echo "cgroup $c $(( $(cat "$c/memory.current") / 1024 )) kB"
    done
    echo "system.slice memory.low=$(cat /sys/fs/cgroup/system.slice/memory.low) memory.min=$(cat /sys/fs/cgroup/system.slice/memory.min)"
    echo "cgroup-of-kubelet $(cut -d: -f3 /proc/$(pgrep -x kubelet | head -1)/cgroup) crio $(cut -d: -f3 /proc/$(pgrep -x crio | head -1)/cgroup)"
    awk '$1 == "kmalloc-256" || /^(cred_jar|task_struct|veth|kmalloc-cg-)/ {printf "slab %s objs=%s\n", $1, $2}' /proc/slabinfo 2>/dev/null
  } >> "$OUT/snap.txt"
}

burst_cleanup() {
  k scale deployment/rg-burst --replicas=1 >/dev/null 2>&1
  local i
  for i in $(seq 1 60); do
    [ "$(k get pods -l app=rg-burst --no-headers 2>/dev/null | wc -l)" -le 1 ] && return 0
    sleep 5
  done
  log "WARNING: burst pods not scaled down within 300s; continuing with leftover pods"
  res "burst_cleanup_timeout_$(cat "$OUT/phase")" 1
}

wait_node_ready() {
  local i
  for i in $(seq 1 60); do
    [ "$(k get node "$NODE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ] && return 0
    sleep 5
  done
  return 1
}

if [ "$ZRAM_MIB" -gt 0 ]; then
  zram_fail() {
    log "zram_setup=failed:$1"; res zram_setup "failed:$1"; res install_ok 0
    exit 1
  }
  modprobe zram num_devices=1 || zram_fail modprobe
  [ -e /sys/block/zram0 ] || cat /sys/class/zram-control/hot_add > /dev/null || zram_fail hot_add
  echo zstd > /sys/block/zram0/comp_algorithm || zram_fail comp_algorithm
  echo "${ZRAM_MIB}M" > /sys/block/zram0/disksize || zram_fail disksize
  mkswap /dev/zram0 > /dev/null || zram_fail mkswap
  swapon -p 100 /dev/zram0 || zram_fail swapon
  sysctl -q vm.page-cluster=0 || zram_fail page-cluster
  res zram_setup ok
  echo "zram swap ${ZRAM_MIB} MiB: $(swapon --show --noheadings | tr -s ' ')" | tee -a "$OUT/run.log"
fi

phase install
log "zero-arg install.sh"
if ! bash "$RG/install.sh" > "$OUT/install.log" 2>&1; then
  log "install.sh failed (tail of $OUT/install.log):"; tail -20 "$OUT/install.log" | tee -a "$OUT/run.log"
  res install_ok 0; exit 1
fi
ready_wait_ok=0
for _ in $(seq 1 120); do
  [ "$(k get nodes -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ] && { ready_wait_ok=1; break; }
  sleep 2
done
if [ "$ready_wait_ok" != 1 ]; then log "node never Ready after install"; res install_ok 0; exit 1; fi
res install_ok 1
NODE="$(k get nodes -o jsonpath='{.items[0].metadata.name}')"
rm -f "$RG"/u7s-gate-*.tar.gz*

: > "$OUT/node-ready.log"
: > "$OUT/ks-uids.txt"
record_uids
# One long-lived node watch instead of a get every 10 s. The watch replays the node's
# condition history on (re)connect, so each line is stamped with the condition's own
# lastTransitionTime, not the read time; callers count transitions at/after WATCH_T0, which
# leaves the replay of install-time Unknown/False flaps out. A broken watch is logged as
# "unreachable" and re-established.
WATCH_T0="$(date +%s)"
( while :; do
    kubectl --kubeconfig "$KCFG" get node "$NODE" -w \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].status} {.status.conditions[?(@.type=="Ready")].lastTransitionTime}{"\n"}' 2>/dev/null \
      | rg_node_watch_stamp >> "$OUT/node-ready.log"
    [ -e "$OUT/watch-stop" ] && break
    printf '%(%s)T unreachable\n' -1 >> "$OUT/node-ready.log"
    sleep 5
  done ) &
WATCH_PID=$!
bash "$RG/vm-sampler.sh" "$OUT" 5 &
SAMPLER_PID=$!
CAPTURE_PID=""
[ "$CAPTURE" = 1 ] && { bash "$RG/vm-capture.sh" "$OUT" "$KCFG" 5 & CAPTURE_PID=$!; }
stop_bg() {
  touch "$OUT/watch-stop"
  pkill -P "$WATCH_PID" 2>/dev/null
  kill "$WATCH_PID" "$SAMPLER_PID" $CAPTURE_PID 2>/dev/null
}
trap stop_bg EXIT
if [ "$COREDNS_REQ" = 1 ]; then
  k -n kube-system set resources deployment/coredns --requests=cpu=100m,memory=70Mi >> "$OUT/run.log" 2>&1
  kw -n kube-system rollout status deployment/coredns --timeout=180s >> "$OUT/run.log" 2>&1 || log "coredns rollout not complete"
  log "coredns requests applied"
fi

phase idle
sleep "$SETTLE_IDLE"

phase wordpress
k apply -f "$RG/wordpress/mariadb-emptydir.yaml" -f "$RG/wordpress/wordpress.yaml" >> "$OUT/run.log" 2>&1
for _ in $(seq 1 60); do k -n default get pod mariadb-0 >/dev/null 2>&1 && break; sleep 2; done
kw -n default wait --for=condition=Ready pod/mariadb-0 --timeout=300s >> "$OUT/run.log" 2>&1 || log "mariadb-0 not Ready in 300s"
kw -n default wait --for=condition=Available deployment/pehelypress --timeout=300s >> "$OUT/run.log" 2>&1 || log "pehelypress not Available in 300s"
WP_IP="$(k get svc pehelypress -o jsonpath='{.spec.clusterIP}')"
wp_code() { curl -s -o /dev/null -m 10 -w '%{http_code}' "http://$WP_IP/"; }
for _ in $(seq 1 100); do wp_code >/dev/null; done
log "wordpress warm-up GET / -> $(wp_code)"
sleep "$SETTLE_STEP"

phase warmup
k create deployment rg-burst --image="$PAUSE_IMAGE" --replicas=1 >> "$OUT/run.log" 2>&1
kw wait --for=condition=Available deployment/rg-burst --timeout=300s >> "$OUT/run.log" 2>&1 || log "warm-up pod not Available"

wp_ok_poll() {
  local _
  for _ in $(seq 1 24); do
    case "$(wp_code)" in 200|301|302) echo 1; return ;; esac
    sleep 5
  done
  echo 0
}

# Ramp: one install + WordPress, bursts of increasing size with a probe hard-kill, each
# followed by scale-down, node-Ready wait and settle. Stops at the first failing size.
run_ramp() {
  local n t0 oomh oomk secs
  for n in ${RAMP//,/ }; do
    t0="$(date +%s)"
    phase "burst$n"
    secs="$(run_burst "$n")"; log "$n-pod burst: $secs s"
    snap "burst$n"
    burst_cleanup; phase "settle$n"; wait_node_ready || log "node not Ready after $n-pod burst"
    sleep "$SETTLE_STEP"
    record_uids
    read -r oomh oomk <<< "$(oom_since "$t0")"
    res "ramp_${n}_secs" "$secs"
    res "ramp_${n}_oom_host" "$oomh"
    res "ramp_${n}_oom_kubesystem" "$oomk"
    res "ramp_${n}_notready" "$(rg_notready_since "$OUT/node-ready.log" "$t0")"
    res "ramp_${n}_ready_final" "$(k get node "$NODE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)"
    res "ramp_${n}_wp_ok" "$(wp_ok_poll)"
    if ! rg_ramp_step "$OUT/results.env" "$n" >/dev/null; then log "ramp stopped: $n-pod burst failed"; break; fi
  done
}

run_full() {
  phase burst20
  b20="$(run_burst 20)"; res burst20_secs "$b20"; log "20-pod burst: $b20 s"
  snap burst20
  burst_cleanup; phase settle20; sleep "$SETTLE_STEP"
  record_uids

  phase burst80
  b80="$(run_burst 80)"; res burst80_secs "$b80"; log "80-pod burst: $b80 s"
  snap burst80
  burst_cleanup; phase settle80; sleep "$SETTLE_STEP"
  record_uids

  phase wpcheck
  wp_ok="$(wp_ok_poll)"
  res wp_ok "$wp_ok"; log "WordPress after settle: ok=$wp_ok"

  phase webhook
  if timeout 900 bash "$RG/webhook-smoke.sh" --kubeconfig "$KCFG" > "$OUT/webhook-smoke.log" 2>&1; then
    res webhook_ok 1
  else
    res webhook_ok 0; tail -15 "$OUT/webhook-smoke.log" | tee -a "$OUT/run.log"
  fi
  log "webhook-smoke webhook_ok=$(rg_get "$OUT/results.env" webhook_ok)"
}

snap pre-burst
if [ -n "$RAMP" ]; then run_ramp; else run_full; fi

phase collect
stop_bg
record_uids
journalctl -u kubelet --no-pager -o short-iso > "$OUT/kubelet-full.log" 2>&1
journalctl -u u7s-kcm --no-pager -o short-iso > "$OUT/kcm-full.log" 2>&1
journalctl -u u7s-apiserver --no-pager -o short-iso > "$OUT/apiserver-full.log" 2>&1
journalctl -u crio --no-pager -o short-iso > "$OUT/crio-full.log" 2>&1
k get events -A -o custom-columns=LAST:.lastTimestamp,REASON:.reason,OBJ:.involvedObject.name,MSG:.message --no-headers > "$OUT/events-all.txt" 2>&1
k describe node "$NODE" > "$OUT/describe-node.txt" 2>&1
journalctl -k --no-pager -o short-iso > "$OUT/kernel.log" 2>&1
journalctl -u kubelet --no-pager -o short-iso 2>&1 | grep -iE 'evict|PLEG is not healthy|NodeNotReady|memory pressure|oom' > "$OUT/kubelet-pressure.log"
k get pods -A -o wide > "$OUT/pods.txt" 2>&1
k get events -A --field-selector reason=Evicted -o custom-columns=NS:.metadata.namespace,OBJ:.involvedObject.name --no-headers > "$OUT/evictions.txt" 2>/dev/null
k get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} restarts={.status.containerStatuses[*].restartCount} last={.status.containerStatuses[*].lastState.terminated.reason}{"\n"}{end}' > "$OUT/pod-restarts.txt" 2>&1
KS_UIDS="$(sort -u "$OUT/ks-uids.txt" | tr - _ | tr '\n' ' ')"
rg_oom_victims "$KS_UIDS" < "$OUT/kernel.log" > "$OUT/oom-victims.txt"
res oom_host "$(grep -c '^host ' "$OUT/oom-victims.txt")"
res oom_kubesystem "$(grep -c '^kube-system ' "$OUT/oom-victims.txt")"
res oom_victims "$(awk '{print $1":"$2}' "$OUT/oom-victims.txt" | sort | uniq -c | awk '{printf "%s x%s; ", $2, $1}')"
res notready_events "$(rg_notready_since "$OUT/node-ready.log" "$WATCH_T0")"
res api_unreachable_polls "$(grep -c ' unreachable$' "$OUT/node-ready.log")"
res evicted_pods "$(awk '{print $1"/"$2}' "$OUT/evictions.txt" | sort | uniq -c | awk '{printf "%s x%s; ", $2, $1}')"
res node_ready_final "$(k get node "$NODE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)"
log "collected"

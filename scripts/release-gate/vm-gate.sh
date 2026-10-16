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
COREDNS_REQ=0; ZRAM_MIB=0
[ -f "$RG/gate.env" ] && . "$RG/gate.env"

mkdir -p "$OUT"
: > "$OUT/results.env"
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }
res() { echo "$1=$2" >> "$OUT/results.env"; }
phase() { echo "$1" > "$OUT/phase"; log "phase: $1"; }
k() { timeout 30 kubectl --kubeconfig "$KCFG" "$@"; }
kw() { kubectl --kubeconfig "$KCFG" "$@"; }

# Scales deployment rg-burst to $1 replicas; echoes seconds until all Ready or "timeout".
run_burst() {
  local n="$1" start now ready
  start="$(date +%s)"
  k scale deployment/rg-burst --replicas="$n" >/dev/null 2>&1
  while :; do
    now="$(date +%s)"
    ready="$(k get deployment rg-burst -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
    if [ "${ready:-0}" = "$n" ]; then echo $((now - start)); return; fi
    if [ $((now - start)) -ge "$HARD_KILL_SECS" ]; then echo timeout; return; fi
    sleep 2
  done
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
  for i in $(seq 1 150); do
    [ "$(k get pods -l app=rg-burst --no-headers 2>/dev/null | wc -l)" -le 1 ] && break
    sleep 2
  done
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
# Polled rather than `get -w`: a re-established watch replays the node's whole condition
# history, which would be counted as fresh not-Ready observations. The poll also records
# kube-system/kube-flannel pod UIDs: an evicted-and-recreated pod gets a new UID, and the
# kernel OOM log can only be mapped back to a pod through the UID in its cgroup path.
( while :; do
    s="$(k get node "$NODE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)"
    echo "$(date +%s) ${s:-unreachable}" >> "$OUT/node-ready.log"
    k get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.uid}{"\n"}{end}' 2>/dev/null \
      | awk '$1 == "kube-system" || $1 == "kube-flannel" {print $2}' >> "$OUT/ks-uids.txt"
    sleep 10
  done ) &
WATCH_PID=$!
bash "$RG/vm-sampler.sh" "$OUT" 5 &
SAMPLER_PID=$!
bash "$RG/vm-capture.sh" "$OUT" "$KCFG" 2 &
CAPTURE_PID=$!
trap 'kill $WATCH_PID $SAMPLER_PID $CAPTURE_PID 2>/dev/null' EXIT
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

snap pre-burst
phase burst20
b20="$(run_burst 20)"; res burst20_secs "$b20"; log "20-pod burst: $b20 s"
snap burst20
burst_cleanup; phase settle20; sleep "$SETTLE_STEP"

phase burst80
b80="$(run_burst 80)"; res burst80_secs "$b80"; log "80-pod burst: $b80 s"
snap burst80
burst_cleanup; phase settle80; sleep "$SETTLE_STEP"

phase wpcheck
wp_ok=0
for _ in $(seq 1 60); do
  case "$(wp_code)" in 200|301|302) wp_ok=1; break ;; esac
  sleep 2
done
res wp_ok "$wp_ok"; log "WordPress after settle: ok=$wp_ok"

phase webhook
if timeout 900 bash "$RG/webhook-smoke.sh" --kubeconfig "$KCFG" > "$OUT/webhook-smoke.log" 2>&1; then
  res webhook_ok 1
else
  res webhook_ok 0; tail -15 "$OUT/webhook-smoke.log" | tee -a "$OUT/run.log"
fi
log "webhook-smoke webhook_ok=$(rg_get "$OUT/results.env" webhook_ok)"

phase collect
kill "$WATCH_PID" "$SAMPLER_PID" "$CAPTURE_PID" 2>/dev/null
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
res notready_events "$(grep -cE ' (False|Unknown)$' "$OUT/node-ready.log")"
res api_unreachable_polls "$(grep -c ' unreachable$' "$OUT/node-ready.log")"
res evicted_pods "$(awk '{print $1"/"$2}' "$OUT/evictions.txt" | sort | uniq -c | awk '{printf "%s x%s; ", $2, $1}')"
res node_ready_final "$(k get node "$NODE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)"
log "collected"

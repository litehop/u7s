#!/usr/bin/env bash
# Runs inside the gate VM as root (driven by burst-gate.sh). Installs u7s with the
# zero-argument baked install.sh, deploys WordPress+MariaDB, runs the 20- and BURST_PODS-pod
# bursts with hard wall-clock caps, runs webhook-smoke.sh, and writes
# $RG/out/results.env (format: see lib.sh) plus raw samples.
#
# Burst workload: pause-image Deployment (BestEffort, like the 2026-10-01 run). Time is
# measured from scaling the warmed-up 1-replica Deployment to N until readyReplicas == N.
set -uo pipefail

RG="${RG_DIR:-/var/tmp/rg}"
OUT="$RG/out"
KCFG=/var/lib/u7s/kubeconfig
SETTLE_IDLE="${SETTLE_IDLE:-180}"
SETTLE_STEP="${SETTLE_STEP:-60}"
HARD_KILL_SECS=600
PAUSE_IMAGE=registry.k8s.io/pause:3.10

# shellcheck source=lib.sh
. "$RG/lib.sh"
COREDNS_REQ=0; ZRAM_MIB=0; CAPTURE=0; RAMP=""; RAMP_KILL_SECS=180; BURST_PODS=20; OVERLOAD_PODS=0; OVERLOAD_MIB=0; NO_WORKLOAD=0
OVERLOAD_WINDOW_SECS=600; RECOVERY_HOLD_SECS=120; RECOVERY_MAX_GAP_SECS=$RG_PROBE_MAX_GAP
INSTALL_TARBALL=""; INSTALL_ONLY=0; WEDGE_SECS=60; WEDGE_STALL_SECS=120
[ -f "$RG/gate.env" ] && . "$RG/gate.env"
[ -n "$RAMP" ] && HARD_KILL_SECS="$RAMP_KILL_SECS"
RG_WEDGE_SECS="$WEDGE_SECS"
RG_WEDGE_STALL_SECS="$WEDGE_STALL_SECS"
RG_JIFFIES_PER_SEC=$(( $(nproc 2>/dev/null || echo 1) * 100 ))

mkdir -p "$OUT"
: > "$OUT/results.env"
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }
# Last write wins: the tally is rewritten after every burst so a dead guest leaves what was
# observed so far, and rg_get reads the first match.
res() {
  { grep -v "^$1=" "$OUT/results.env" 2>/dev/null; echo "$1=$2"; } > "$OUT/results.tmp"
  mv "$OUT/results.tmp" "$OUT/results.env"
}
phase() { { echo "# $(cat "$OUT/phase" 2>/dev/null)"; cat "$OUT/burst-progress.log" 2>/dev/null; } >> "$OUT/burst-progress.hist"; : > "$OUT/burst-progress.log"; echo "$1" > "$OUT/phase"; log "phase: $1"; }
k() { timeout -k 1 "${K_TIMEOUT:-30}" kubectl --kubeconfig "$KCFG" "$@"; }
kw() { kubectl --kubeconfig "$KCFG" "$@"; }

# Scales deployment rg-burst to $1 replicas; echoes seconds until all Ready or "timeout".
# One long-lived `get -w` instead of a kubectl fork per poll: each fork is a fresh Go
# process on a memory-starved node. A dropped watch is re-established after 5 s.
run_burst() {
  local n="$1" start now wpid
  start="$(date +%s)"
  echo "$start 0" > "$OUT/burst-progress.log"
  k scale deployment/rg-burst --replicas="$n" >/dev/null 2>&1
  while :; do
    now="$(date +%s)"
    if [ -e "$OUT/wedge.txt" ]; then echo wedge; return; fi
    if [ $((now - start)) -ge "$HARD_KILL_SECS" ]; then rm -f "$OUT/burst-watch.pid"; echo timeout; return; fi
    exec 3< <(exec timeout $((HARD_KILL_SECS - (now - start))) kubectl --kubeconfig "$KCFG" \
      get deployment rg-burst -w -o jsonpath='{.status.readyReplicas}{"\n"}' 2>/dev/null)
    wpid=$!
    echo "$wpid" > "$OUT/burst-watch.pid"
    if rg_wait_ready "$n" "$OUT/burst-progress.log" <&3; then
      kill "$wpid" 2>/dev/null; exec 3<&-
      rm -f "$OUT/burst-watch.pid"
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
  local pods
  pods="$(k get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.uid}{"\n"}{end}' 2>/dev/null)" \
    || { log "WARNING: pod UID snapshot failed (API unreachable); OOM victims of pods created since the last snapshot are classed by comm only"; return; }
  echo "$pods" | rg_kubesystem_uids >> "$OUT/ks-uids.txt"
}

# Kernel-log OOM victims since epoch $1, as "<host count> <kube-system count>".
oom_since() {
  journalctl -k --no-pager --since "$(date -d "@$1" '+%Y-%m-%d %H:%M:%S')" 2>/dev/null \
    | rg_oom_victims "$(rg_uids_cgroup "$OUT/ks-uids.txt")" | rg_oom_counts
}

# In-guest CPU speed probe. Run only at true idle boundaries (before install, before the first
# burst), never after a burst: u7s's own teardown load there is the thing under test. A
# slowdown against the pre-install baseline is host steal. Also records CPU pressure (PSI).
calibrate() {
  local s e i=0
  s="$(date +%s%N)"
  while [ "$i" -lt 200000 ]; do i=$((i + 1)); done
  e="$(date +%s%N)"
  echo "$(date +%s) $(cat "$OUT/phase" 2>/dev/null) $(( (e - s) / 1000000 ))" >> "$OUT/cal.log"
  echo "$(date +%s) $(cat "$OUT/phase" 2>/dev/null) $(head -1 /proc/pressure/cpu 2>/dev/null)" >> "$OUT/psi-cpu.log"
}

calibrate_boundary() {
  local _
  for _ in $(seq 1 "$RG_CAL_MIN_SAMPLES"); do calibrate; done
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
    echo "cgroup-of-kubelet $(cut -d: -f3 /proc/$(pgrep -x kubelet | sed -n 1p)/cgroup) crio $(cut -d: -f3 /proc/$(pgrep -x crio | sed -n 1p)/cgroup)"
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

# While a burst phase runs, checks every 5 s whether the guest has wedged (rg_wedge_reason from
# node-ready.log and the sampler's STAT rows: no new processes beyond one awk pass over the
# sampler's last rows). On a wedge writes wedge.txt and kills the burst watch so run_burst returns.
wedge_monitor() {
  local why pid
  while [ ! -e "$OUT/watch-stop" ]; do
    sleep 5
    case "$(cat "$OUT/phase" 2>/dev/null)" in burst*) ;; *) continue ;; esac
    why="$(rg_wedge_reason "$(date +%s)" "$OUT/node-ready.log" <(tail -n 4000 "$OUT/attrib.tsv") "$OUT/burst-progress.log")"
    [ -n "$why" ] || continue
    pid="$(rg_burst_watch_pid "$OUT/burst-watch.pid")"
    [ -n "$pid" ] || continue
    echo "$why" > "$OUT/wedge.txt"
    kill "$pid" 2>/dev/null
    return
  done
}

# Run after a wedged burst: the guest is barely answering, so keep each kubectl short.
note_wedge() {
  K_TIMEOUT=10
  res wedge_reason "$(cat "$OUT/wedge.txt")"
  log "WEDGE: $(cat "$OUT/wedge.txt"); aborting the burst and collecting evidence"
}

# Node tally and run-wide steal as observed so far. Rewritten after each burst and at collect.
write_tally() {
  local oomh oomk
  journalctl -k --no-pager 2>/dev/null | rg_oom_victims "$(rg_uids_cgroup "$OUT/ks-uids.txt")" | rg_oom_counts > "$OUT/tally-oom.tmp"
  read -r oomh oomk < "$OUT/tally-oom.tmp"
  res oom_host "$oomh"
  res oom_kubesystem "$oomk"
  res notready_events "$(rg_notready_since "$OUT/node-ready.log" "$WATCH_T0")"
  res api_unreachable_polls "$(grep -c ' unreachable$' "$OUT/node-ready.log")"
  res node_ready_final "$(k get node "$NODE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)"
  res steal_run_pct "$(rg_steal_pct "$CPU_RUN0" "$(head -1 /proc/stat)")"
}

# describe + logs of every pod that is not Ready, into pod-diag/<tag>/, so the cause (OOM, probe
# timeout, image pull, CPU) can be read after the VM is deleted.
diag_pods() {
  local d="$OUT/pod-diag/$1" ns name
  mkdir -p "$d"
  k get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name} {.status.phase} {.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null \
    | rg_notready_pods > "$d/pods.txt"
  while read -r ns name; do
    { k -n "$ns" describe pod "$name"
      k -n "$ns" logs "$name" --all-containers --tail=200
      k -n "$ns" logs "$name" --all-containers --previous --tail=200
    } > "$d/${ns}_$name.txt" 2>&1 < /dev/null
  done < "$d/pods.txt"
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
CPU_RUN0="$(head -1 /proc/stat)"
calibrate_boundary
WATCH_PID=""; CAPTURE_PID=""; MONITOR_PID=""
stop_bg() {
  touch "$OUT/watch-stop"
  [ -n "$WATCH_PID" ] && pkill -P "$WATCH_PID" 2>/dev/null
  kill $WATCH_PID $SAMPLER_PID $CAPTURE_PID $MONITOR_PID 2>/dev/null
}
trap stop_bg EXIT
bash "$RG/vm-sampler.sh" "$OUT" 5 </dev/null >> "$OUT/sampler.log" 2>&1 &
SAMPLER_PID=$!
install_args=()
if [ -n "$INSTALL_TARBALL" ]; then log "install.sh --tarball $INSTALL_TARBALL (experiment)"; install_args=(--tarball "$INSTALL_TARBALL"); else log "zero-arg install.sh"; fi
install_t0=$SECONDS
if ! bash "$RG/install.sh" ${install_args[@]+"${install_args[@]}"} > "$OUT/install.log" 2>&1; then
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
res install_secs "$((SECONDS - install_t0))"
if [ "$INSTALL_ONLY" = 1 ]; then log "install-only: stopping after node Ready"; exit 0; fi
NODE="$(k get nodes -o jsonpath='{.items[0].metadata.name}')"
rm -f "$RG"/u7s-gate-*.tar.gz*

: > "$OUT/node-ready.log"
: > "$OUT/ks-uids.txt"
record_uids
# One long-lived node watch instead of a get every 10 s. The watch replays the node's
# condition history on (re)connect, so each line is stamped with the condition's own
# lastTransitionTime, not the read time; callers count transitions at/after WATCH_T0, which
# leaves the replay of install-time Unknown/False flaps out. A watch that ends while the API
# does not answer is logged as "unreachable" (counted by criterion (b)) and re-established.
WATCH_T0="$(date +%s)"
res watch_t0 "$WATCH_T0"
( while :; do
    kubectl --kubeconfig "$KCFG" get node "$NODE" -w \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].status} {.status.conditions[?(@.type=="Ready")].lastTransitionTime}{"\n"}' 2>/dev/null \
      | rg_node_watch_stamp >> "$OUT/node-ready.log"
    [ -e "$OUT/watch-stop" ] && break
    k get node "$NODE" -o name >/dev/null 2>&1 || printf '%(%s)T unreachable\n' -1 >> "$OUT/node-ready.log"
    sleep 5
  done ) &
WATCH_PID=$!
wedge_monitor & MONITOR_PID=$!
[ "$CAPTURE" = 1 ] && { bash "$RG/vm-capture.sh" "$OUT" "$KCFG" 5 & CAPTURE_PID=$!; }
if [ "$COREDNS_REQ" = 1 ]; then
  k -n kube-system set resources deployment/coredns --requests=cpu=100m,memory=70Mi >> "$OUT/run.log" 2>&1
  kw -n kube-system rollout status deployment/coredns --timeout=180s >> "$OUT/run.log" 2>&1 || log "coredns rollout not complete"
  log "coredns requests applied"
fi

phase idle
cpu_before="$(head -1 /proc/stat)"
sleep "$SETTLE_IDLE"
res steal_idle_pct "$(rg_steal_pct "$cpu_before" "$(head -1 /proc/stat)")"
calibrate_boundary

phase wordpress
if [ "$NO_WORKLOAD" = 1 ]; then
  log "no-workload: WordPress and MariaDB not deployed"
else
k apply -f "$RG/wordpress/mariadb-emptydir.yaml" -f "$RG/wordpress/wordpress.yaml" >> "$OUT/run.log" 2>&1
for _ in $(seq 1 60); do k -n default get pod mariadb-0 >/dev/null 2>&1 && break; sleep 2; done
MARIADB_READY=1
kw -n default wait --for=condition=Ready pod/mariadb-0 --timeout=300s >> "$OUT/run.log" 2>&1 || { MARIADB_READY=0; log "mariadb-0 not Ready in 300s"; diag_pods mariadb-not-ready; }
kw -n default wait --for=condition=Available deployment/pehelypress --timeout=300s >> "$OUT/run.log" 2>&1 || log "pehelypress not Available in 300s"
WP_IP="$(k get svc pehelypress -o jsonpath='{.spec.clusterIP}')"
wp_code() { curl -s -o /dev/null -m "${WP_TIMEOUT:-10}" -w '%{http_code}' "http://$WP_IP/"; }
for _ in $(seq 1 100); do wp_code >/dev/null; done
log "wordpress warm-up GET / -> $(wp_code)"

# MariaDB is on emptyDir: a recreated pod is an empty DB that WordPress answers with a 302 to
# its installer. The marker row must read back after the bursts.
MARKER="rg-$(date +%s)-$RANDOM"
mysql_k() { k -n default exec mariadb-0 -- mariadb -uvalerauko -puserpw-phase3 valenet -N -B -e "$1"; }
mysql_k "CREATE TABLE rg_marker (v VARCHAR(64) NOT NULL); INSERT INTO rg_marker VALUES ('$MARKER')" >> "$OUT/run.log" 2>&1 \
  || {
    log "marker write failed (was_ready=$MARIADB_READY)"
    rg_probe_and_record_marker_failure "$OUT/results.env" "$MARIADB_READY"
    exit 1
  }
marker_ok() {
  local i v=""
  for i in $(seq 1 12); do
    v="$(mysql_k 'SELECT v FROM rg_marker' 2>/dev/null)" && [ -n "$v" ] && break
    sleep 5
  done
  rg_marker_ok "$MARKER" "$v"
}
fi
sleep "$SETTLE_STEP"

phase warmup
k create deployment rg-burst --image="$PAUSE_IMAGE" --replicas=1 >> "$OUT/run.log" 2>&1
kw wait --for=condition=Available deployment/rg-burst --timeout=300s >> "$OUT/run.log" 2>&1 || log "warm-up pod not Available"

if [ "$OVERLOAD_PODS" -gt 0 ]; then
  # BestEffort pods (oom_score_adj 1000, killable) that each hold OVERLOAD_MIB of anonymous memory in a
  # shell variable. nginx:alpine is the image WordPress already pulled, and busybox ash has head/tr.
  k apply -f - >> "$OUT/run.log" 2>&1 <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rg-overload
spec:
  replicas: 1
  selector:
    matchLabels:
      app: rg-overload
  template:
    metadata:
      labels:
        app: rg-overload
    spec:
      containers:
        - name: alloc
          image: nginx:alpine
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c"]
          args:
            - 'x=\$(head -c \$((${OVERLOAD_MIB} * 1048576)) /dev/zero | tr "\\0" x); while :; do sleep 3600; done'
EOF
  kw wait --for=condition=Available deployment/rg-overload --timeout=300s >> "$OUT/run.log" 2>&1 || log "overload warm-up pod not Available"
fi

# Scales rg-overload to OVERLOAD_PODS and probes every 5 s until node Ready + API /readyz + WordPress 200
# have held RECOVERY_HOLD_SECS, or OVERLOAD_WINDOW_SECS pass. The overload pods stay: a user's overload
# does not go away on its own.
run_overload() {
  local t0 c0 ok fin
  phase overload
  t0="$(date +%s)"
  res overload_t0 "$t0"; res overload_pods "$OVERLOAD_PODS"; res overload_mib "$OVERLOAD_MIB"
  res overload_window_secs "$OVERLOAD_WINDOW_SECS"; res recovery_hold_secs "$RECOVERY_HOLD_SECS"
  : > "$OUT/recovery.log"
  k scale deployment/rg-overload --replicas="$OVERLOAD_PODS" >/dev/null 2>&1
  : > "$OUT/probes.log"
  while [ $(( $(date +%s) - t0 )) -lt "$OVERLOAD_WINDOW_SECS" ]; do
    c0="$(date +%s)"
    ok=0
    if rg_probe_cycle "$OUT/probes.log" "$NO_WORKLOAD"; then ok=1; fi
    echo "$(date +%s) $ok" >> "$OUT/recovery.log"
    [ "$(rg_recovery_secs "$OUT/recovery.log" "$t0" "$RECOVERY_HOLD_SECS" "$RECOVERY_MAX_GAP_SECS")" != none ] && break
    [ $(( $(date +%s) - c0 )) -lt 5 ] && sleep $(( 5 - ($(date +%s) - c0) ))
  done
  res recovery_secs "$(rg_recovery_secs "$OUT/recovery.log" "$t0" "$RECOVERY_HOLD_SECS" "$RECOVERY_MAX_GAP_SECS")"
  fin="$(K_TIMEOUT=10 k get pods -l app=rg-overload -o jsonpath='{range .items[*]}{.status.phase} {.status.containerStatuses[0].restartCount}{"\n"}{end}' 2>/dev/null \
    | awk '{c[$1]++; r += $2} END {for (p in c) printf "%s=%d ", p, c[p]; printf "restarts=%d", r}')"
  res overload_final "node=$(K_TIMEOUT=10 k get node "$NODE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null) overload-pods: $fin"
  log "overload: recovery_secs=$(rg_get "$OUT/results.env" recovery_secs) final: $(rg_get "$OUT/results.env" overload_final)"
  write_tally
}

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
    if [ "$secs" = wedge ]; then res "ramp_${n}_secs" wedge; note_wedge; break; fi
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
    res "ramp_${n}_marker_ok" "$(marker_ok)"
    write_tally
    if ! rg_ramp_step "$OUT/results.env" "$n" >/dev/null; then log "ramp stopped: $n-pod burst failed"; break; fi
  done
}

run_full() {
  phase burst20
  b20="$(run_burst 20)"; res burst20_secs "$b20"; log "20-pod burst: $b20 s"
  if [ "$b20" = wedge ]; then note_wedge; return; fi
  snap burst20
  burst_cleanup; phase settle20; sleep "$SETTLE_STEP"
  record_uids
  write_tally

  phase burstn
  bn="$(run_burst "$BURST_PODS")"; res burst_pods "$BURST_PODS"; res burst_secs "$bn"; log "$BURST_PODS-pod burst: $bn s"
  if [ "$bn" = wedge ]; then note_wedge; return; fi
  snap burstn
  burst_cleanup; phase settlen; sleep "$SETTLE_STEP"
  record_uids
  write_tally

  phase wpcheck
  wp_ok="$(wp_ok_poll)"
  res wp_ok "$wp_ok"; log "WordPress after settle: ok=$wp_ok"
  diag_pods wpcheck
  res marker_ok "$(marker_ok)"; log "DB marker after settle: marker_ok=$(rg_get "$OUT/results.env" marker_ok)"

  phase webhook
  if timeout 900 bash "$RG/webhook-smoke.sh" --kubeconfig "$KCFG" > "$OUT/webhook-smoke.log" 2>&1; then
    res webhook_ok 1
  else
    res webhook_ok 0; tail -15 "$OUT/webhook-smoke.log" | tee -a "$OUT/run.log"
  fi
  log "webhook-smoke webhook_ok=$(rg_get "$OUT/results.env" webhook_ok)"
}

snap pre-burst
# Guest clock; quiet.log is host clock, so a few seconds of skew only shifts the judged boundary.
res load_t0 "$(date +%s)"
if [ "$OVERLOAD_PODS" -gt 0 ]; then run_overload; elif [ -n "$RAMP" ]; then run_ramp; else run_full; fi

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
rg_oom_victims "$(rg_uids_cgroup "$OUT/ks-uids.txt")" < "$OUT/kernel.log" > "$OUT/oom-victims.txt"
rg_oom_events < "$OUT/kernel.log" > "$OUT/oom-events.txt"
read -r oomh oomk <<< "$(rg_oom_counts < "$OUT/oom-victims.txt")"
res oom_host "$oomh"
res oom_kubesystem "$oomk"
read -r cal_ms cal_n <<< "$(rg_cal_summary "$OUT/cal.log" install)"; res cal_ref_ms "$cal_ms"; res cal_ref_n "$cal_n"
read -r cal_ms cal_n <<< "$(rg_cal_summary "$OUT/cal.log" idle)"; res cal_idle_ms "$cal_ms"; res cal_idle_n "$cal_n"
res oom_victims "$(awk '{print $1":"$2}' "$OUT/oom-victims.txt" | sort | uniq -c | awk '{printf "%s x%s; ", $2, $1}')"
res evicted_pods "$(awk '{print $1"/"$2}' "$OUT/evictions.txt" | sort | uniq -c | awk '{printf "%s x%s; ", $2, $1}')"
write_tally
diag_pods collect
log "collected"

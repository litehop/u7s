#!/usr/bin/env bash
# Memory/metrics sampler for a live conformance stack.
#
# Before this script existed, RSS/ring/metrics data for a conformance run was
# an operator-run-by-hand bash loop living outside the repo: uncommitted, so
# its cadence and columns were whatever happened to be running that day, and
# absent entirely on any run the operator forgot to babysit.
# This script folds that loop into the repo and into run-all.sh's own
# lifecycle so every run gets the same three artifacts with no operator
# action:
#
#   rss.csv       ts,scope,pid,comm,rss_kb,footprint_kb,cpu_seconds_cumulative
#                 One row per sampled process per tick. scope is "host" for
#                 the host processes (apiserver, konnectivity-server, plus a
#                 separate "scheduler" row IF u7s-scheduler is running as its
#                 own standalone process -- run-all.sh's default pipeline
#                 still does this via 05-start-scheduler.sh, but
#                 --embedded-scheduler true folds scheduling into the
#                 apiserver's own RSS instead; in that mode
#                 resolve_scheduler_pid() below simply finds no PID and the
#                 "scheduler" row has 0 samples for the whole run, which is
#                 correct, not a sampler bug) or a VM name for the --top-n busiest
#                 processes inside that VM (kubelet, crio, kube-proxy,
#                 kube-controller-manager, ...). footprint_kb is macOS-only
#                 (from `footprint -p <pid>`, which needs no VM/host
#                 elevation for same-user processes) — ps -o rss= alone
#                 overstates real memory on macOS by ~30% (measured: 135 MB
#                 ps RSS vs 103 MB physical footprint on a live apiserver).
#                 Empty on Linux/VM rows, where there is no footprint tool.
#                 cpu_seconds_cumulative is ps's own `time=` field (total CPU
#                 time consumed since the process started) converted to a
#                 plain number of seconds — deliberately a raw cumulative
#                 counter, not `pcpu`/`%cpu`, whose value is that same
#                 cumulative time divided by wall-clock process age, i.e. a
#                 LIFETIME AVERAGE that can never show a spike or a recent
#                 idle period once a process has run for a while (this was
#                 measured directly: it is the only reason every "CPU"
#                 number in that findings doc was a single misleading
#                 snapshot). A real instantaneous rate for the interval
#                 between two ticks is (cpu_seconds_cumulative[N] -
#                 cpu_seconds_cumulative[N-1]) / (ts[N] - ts[N-1]) — the same
#                 math Prometheus's own process collector and PromQL's
#                 rate(process_cpu_seconds_total[...]) use, computed by
#                 whatever reads this CSV rather than baked in here, since a
#                 cumulative counter can always be turned into a rate later
#                 but a rate can never be turned back into the counter.
#

#   vm-free.csv   ts,vm,total_mb,used_mb,free_mb
#                 `free -m` totals per VM, so VM-level memory pressure is
#                 visible even when no single process is the culprit.
#
#   ring-age.csv  ts,shard,events,span_secs
#                 u7s_watch_ring_occupancy (still a plain gauge) joined with
#                 u7s_watch_ring_span_seconds per shard, into one row —
#                 matches the shape the operator's own by-hand CSV used, so
#                 existing eyeballing scripts still work. u7s_watch_ring_span
#                 _seconds became a HISTOGRAM in bd:ukbhp (a polled gauge
#                 could not see this metric's own decision-relevant minimum),
#                 so there is no single "current value" left to scrape —
#                 span_secs here is the smallest bucket boundary with a
#                 nonzero cumulative count, i.e. the tightest known upper
#                 bound on the worst-case minimum span this shard has EVER
#                 produced. Cumulative buckets only ever tighten, so this
#                 column is a running worst-case trajectory across the run,
#                 not a per-tick instantaneous reading.
#                 Deliberately does NOT include replay depth: that is also a
#                 cumulative histogram, and it is fully covered by the
#                 /metrics snapshots below instead.
#
# Plus periodic full-text /metrics snapshots, one file per snapshot
# (metrics-<seq>-<label>.prom) rather than one operator-appended file —
# appending repeated `kubectl get --raw /metrics` dumps into one file
# silently breaks naive parsing (last-wins on gauges, duplicated histogram
# bucket series). A snapshot is taken once at "start" (the pre-load
# baseline) and once via the "snapshot" subcommand right before whatever
# teardown next stops the apiserver — two cumulative-histogram snapshots
# subtract to give the distribution for exactly that interval, e.g.
# separating "the tail came from the startup burst" from "this is steady
# state" for u7s_watch_replay_depth.
#
# This is a SEPARATE script from run-all.sh (not an inline background job)
# so it reaps cleanly (SIGTERM + poll, mirroring reset.sh's own hostagent
# reap pattern) and so it can be run standalone against an already-up stack
# for manual investigation, same as u7s-start.sh/lima-start.sh already are.
#
# Usage:
#   sample-run-metrics.sh start    [--workdir <dir>] [--port <N>] [--vm <name>]
#                                   [--extra-node <name>] [--interval <secs>]
#                                   [--top-n <N>] [--kubeconfig <path>]
#   sample-run-metrics.sh stop     [--workdir <dir>]
#   sample-run-metrics.sh snapshot [--workdir <dir>] [--kubeconfig <path>]
#                                   [--label <name>]
#
# "start" launches a backgrounded, disowned loop (PID recorded in
# $WORKDIR/sample-run-metrics.pid) and returns immediately — same shape as
# u7s-start.sh --background. "stop" is idempotent: robust to a stale pidfile,
# an already-dead PID, or no pidfile at all (never errors on the "nothing to
# stop" case, since run-all.sh must always be able to call it in its
# teardown path without knowing in advance whether a sampler is running).
set -euo pipefail

SUBCOMMAND="${1:-}"
case "$SUBCOMMAND" in
  start|stop|snapshot) shift ;;
  *)
    echo "usage: $0 <start|stop|snapshot> [flags] — see script header for flags" >&2
    exit 1
    ;;
esac

WORKDIR="$PWD/temp/u7s"
PORT="6443"
VM="lima-node"
EXTRA_NODE=""
INTERVAL=30
TOP_N=15
LABEL="manual"
KUBECONFIG_OVERRIDE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workdir) WORKDIR="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --vm) VM="$2"; shift 2 ;;
    --extra-node) EXTRA_NODE="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --top-n) TOP_N="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --kubeconfig) KUBECONFIG_OVERRIDE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# Resolve to absolute so the pgrep matches below (scheduler/konnectivity-server,
# scoped by WORKDIR substring) are worktree-unique, same reasoning as
# 05-start-scheduler.sh's own WORKDIR resolution.
mkdir -p "$WORKDIR"
WORKDIR="$(cd "$WORKDIR" && pwd)"
KUBECONFIG_PATH="${KUBECONFIG_OVERRIDE:-$WORKDIR/kubeconfig}"

PIDFILE="$WORKDIR/sample-run-metrics.pid"
LOGFILE="$WORKDIR/sample-run-metrics.log"
RSS_CSV="$WORKDIR/rss.csv"
VM_FREE_CSV="$WORKDIR/vm-free.csv"
RING_CSV="$WORKDIR/ring-age.csv"
SEQFILE="$WORKDIR/.sample-run-metrics.seq"

DARWIN=0
[ "$(uname)" = "Darwin" ] && DARWIN=1
TAB="$(printf '\t')"

# ---------------------------------------------------------------------------
# Host-side process discovery. Re-resolved every tick (not cached) because
# the whole point is to survive a process not existing yet or dying mid-run —
# a cached PID from tick 1 would silently sample the wrong (recycled) PID, or
# a dead one, for the rest of the loop. Each ends in '|| true': under
# set -o pipefail, 'pgrep ... | head -1' propagates pgrep's exit 1 ("no match
# found" — the normal case before a process starts, not a real error) through
# the whole pipeline, which would otherwise be indistinguishable from a
# genuine failure to the caller.
# ---------------------------------------------------------------------------
resolve_apiserver_pid() {
  lsof -ti tcp:"$PORT" -sTCP:LISTEN 2>/dev/null | head -1 || true
}

resolve_scheduler_pid() {
  # Finds nothing (harmlessly -- sample_one_host_process already skips an empty pid) when
  # u7s-scheduler is running embedded in the apiserver (--embedded-scheduler true)
  # rather than as its own process; that's a real "no separate PID exists"
  # answer, not a resolver bug.
  pgrep -f "u7s-scheduler.*${WORKDIR}/kubeconfig" 2>/dev/null | head -1 || true
}

resolve_konnectivity_pid() {
  pgrep -f "konnectivity-server.*${WORKDIR}" 2>/dev/null | head -1 || true
}

# macOS-only: ps -o rss= overstates real memory by counting clean, evictable,
# file-backed pages (mostly resident __TEXT) that the kernel can drop under
# pressure without writing anything out. `footprint` reports the same
# "phys_footprint" the kernel itself uses for memory-pressure decisions, and
# — unlike vmmap, whose -summary output needs more parsing for the same
# number — needs no root/sudo for a same-user PID, matching how apiserver/
# scheduler/konnectivity-server all run as the operator's own user here.
footprint_kb() {
  local pid="$1" line val unit
  line="$(footprint -p "$pid" 2>/dev/null | grep -m1 '^[[:space:]]*phys_footprint:')" || return 1
  [ -z "$line" ] && return 1
  val="$(echo "$line" | awk '{print $2}')"
  unit="$(echo "$line" | awk '{print $3}')"
  case "$unit" in
    KB) printf '%.0f' "$val" ;;
    MB) awk -v v="$val" 'BEGIN{printf "%.0f", v*1024}' ;;
    GB) awk -v v="$val" 'BEGIN{printf "%.0f", v*1024*1024}' ;;
    B)  awk -v v="$val" 'BEGIN{printf "%.0f", v/1024}' ;;
    *) return 1 ;;
  esac
}

# Both BSD (macOS) and GNU (Linux/procps) `ps` report cumulative CPU time via
# the `time=` keyword as a formatted [[DD-]HH:]MM:SS[.ss] duration, not a raw
# seconds value — there is no portable `cputimes=`-style keyword that works on
# both (BSD ps rejects it outright). Splitting on both '-' and ':' handles
# every field count ps can produce (MM:SS, HH:MM:SS, DD-HH:MM:SS) uniformly,
# so this is the one parser both sample_one_host_process and sample_vm_rss
# need, regardless of how long the sampled process has been running.
cpu_time_to_seconds() {
  local t="$1"
  [ -z "$t" ] && return 0
  awk -F'[-:]' '{
    n = NF
    total = $n + 0
    if (n >= 2) total += $(n-1) * 60
    if (n >= 3) total += $(n-2) * 3600
    if (n >= 4) total += $(n-3) * 86400
    printf "%.2f", total
  }' <<< "$t"
}

sample_one_host_process() {
  local ts="$1" name="$2" pid="$3"
  [ -z "$pid" ] && return 0
  local rss cputime
  read -r rss cputime < <(ps -o rss=,time= -p "$pid" 2>/dev/null) || true
  # Process died between resolve and sample (real race on a short-lived
  # restart) — skip this tick's row for it rather than aborting the loop.
  [ -z "$rss" ] && return 0
  local fp=""
  if [ "$DARWIN" -eq 1 ]; then
    fp="$(footprint_kb "$pid")" || fp=""
  fi
  echo "${ts},host,${pid},${name},${rss},${fp},$(cpu_time_to_seconds "$cputime")" >> "$RSS_CSV"
}

sample_vm_rss() {
  local ts="$1" vm="$2" out
  out="$(limactl shell "$vm" -- ps -eo pid=,rss=,time=,comm= --sort=-rss 2>/dev/null | head -n "$TOP_N")" || return 0
  [ -z "$out" ] && return 0
  local pid rss cputime comm
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    pid="$(echo "$line" | awk '{print $1}')"
    rss="$(echo "$line" | awk '{print $2}')"
    cputime="$(echo "$line" | awk '{print $3}')"
    comm="$(echo "$line" | awk '{print $4}')"
    echo "${ts},${vm},${pid},${comm},${rss},,$(cpu_time_to_seconds "$cputime")" >> "$RSS_CSV"
  done <<< "$out"
}

sample_vm_free() {
  local ts="$1" vm="$2" line
  line="$(limactl shell "$vm" -- free -m 2>/dev/null | awk '/^Mem:/{print $2, $3, $4}')" || return 0
  [ -z "$line" ] && return 0
  local total used free
  total="$(echo "$line" | awk '{print $1}')"
  used="$(echo "$line" | awk '{print $2}')"
  free="$(echo "$line" | awk '{print $3}')"
  echo "${ts},${vm},${total},${used},${free}" >> "$VM_FREE_CSV"
}

# Pulls u7s_watch_ring_occupancy (IntGaugeVec) and u7s_watch_ring_span_seconds
# (HistogramVec since bd:ukbhp -- a polled gauge could not see this metric's
# own decision-relevant minimum, so it was converted and there is no single
# "current value" left to scrape) out of one /metrics scrape and joins them
# on the shard label into ts,shard,events,span_secs rows. Both are set/observed
# together at the same push_event_locked call site (crates/store/src/sqlite.rs),
# so in steady state their shard sets match; join simply drops any shard that
# (transiently) only has one side rather than emitting a half-populated row.
# span_secs is read as the smallest bucket boundary (le) with a nonzero
# cumulative count for that shard -- the tightest known upper bound on the
# worst-case minimum span ever observed, i.e. exactly the reading the
# histogram's own doc calls out as decision-relevant (crates/store/src/metrics.rs).
sample_ring_gauges() {
  local ts="$1" raw
  raw="$(kubectl --kubeconfig "$KUBECONFIG_PATH" get --raw /metrics 2>/dev/null)" || raw=""
  [ -z "$raw" ] && return 0

  local occ_tmp span_tmp
  occ_tmp="$(mktemp)"
  span_tmp="$(mktemp)"
  echo "$raw" \
    | grep -E '^u7s_watch_ring_occupancy\{' \
    | sed -E 's/^u7s_watch_ring_occupancy\{shard="([^"]*)"\} ([0-9.eE+-]+)$/\1\t\2/' \
    | LC_ALL=C sort -t "$TAB" -k1,1 > "$occ_tmp" || true
  # "le" values are plain finite numbers ("1", "2", ... "1024") for every
  # bucket except the required "+Inf" sentinel -- excluding it is why the
  # grep/sed character class below has no letters, rather than a separate
  # grep -v step.
  echo "$raw" \
    | grep -E '^u7s_watch_ring_span_seconds_bucket\{shard="[^"]*",le="[0-9.eE+-]+"\} ' \
    | sed -E 's/^u7s_watch_ring_span_seconds_bucket\{shard="([^"]*)",le="([0-9.eE+-]+)"\} ([0-9.eE+-]+)$/\1\t\2\t\3/' \
    | awk -F "$TAB" '
        $3 + 0 > 0 {
          le = $2 + 0
          if (!(($1) in minle) || le < minle[$1]) minle[$1] = le
        }
        END { for (s in minle) print s "\t" minle[s] }
      ' \
    | LC_ALL=C sort -t "$TAB" -k1,1 > "$span_tmp" || true

  local shard events span
  while IFS="$TAB" read -r shard events span; do
    [ -z "$shard" ] && continue
    echo "${ts},${shard},${events},${span}" >> "$RING_CSV"
  done < <(join -t "$TAB" -j1 "$occ_tmp" "$span_tmp" 2>/dev/null || true)

  rm -f "$occ_tmp" "$span_tmp"
}

take_snapshot() {
  local label="$1" seq=0
  [ -f "$SEQFILE" ] && seq="$(cat "$SEQFILE" 2>/dev/null || echo 0)"
  seq=$(( seq + 1 ))
  echo "$seq" > "$SEQFILE"
  local out
  out="$WORKDIR/metrics-$(printf '%02d' "$seq")-${label}.prom"
  if kubectl --kubeconfig "$KUBECONFIG_PATH" get --raw /metrics > "$out" 2>/dev/null; then
    echo "metrics snapshot (${label}): $out"
  else
    echo "warning: failed to capture /metrics snapshot (label=${label}) — apiserver may be down" >&2
    rm -f "$out"
  fi
}

sample_tick() {
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  sample_one_host_process "$ts" "apiserver" "$(resolve_apiserver_pid)"
  sample_one_host_process "$ts" "scheduler" "$(resolve_scheduler_pid)"
  sample_one_host_process "$ts" "konnectivity-server" "$(resolve_konnectivity_pid)"
  sample_vm_rss "$ts" "$VM"
  sample_vm_free "$ts" "$VM"
  if [ -n "$EXTRA_NODE" ]; then
    sample_vm_rss "$ts" "$EXTRA_NODE"
    sample_vm_free "$ts" "$EXTRA_NODE"
  fi
  sample_ring_gauges "$ts"
}

sampler_loop() {
  # This loop's one job is "sample forever until signalled, never abort on a
  # transient error" — a VM hiccup or a mid-restart process gap must cost one
  # skipped row, not the whole run's monitoring data for everything after it.
  # Disabling errexit here (this function only ever runs in the backgrounded
  # subshell from cmd_start, never in the foreground CLI path) is simpler and
  # more robust than auditing every pipeline in the sample_* functions above
  # for pipefail interactions.
  set +e
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) sampler loop starting (interval=${INTERVAL}s, vm=${VM}${EXTRA_NODE:+,${EXTRA_NODE}})"
  while true; do
    sample_tick
    sleep "$INTERVAL"
  done
}

cmd_start() {
  # Idempotent: replace any sampler already running for this workdir instead
  # of accumulating duplicate background loops across repeated non-reset
  # run-all.sh invocations (mirrors 05-start-scheduler.sh's own
  # kill-and-restart-if-already-running check).
  if [ -f "$PIDFILE" ]; then
    local old_pid
    old_pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
      echo "sampler already running (PID $old_pid) for $WORKDIR — stopping it first"
      cmd_stop
    fi
  fi

  [ -f "$RSS_CSV" ]     || echo "ts,scope,pid,comm,rss_kb,footprint_kb,cpu_seconds_cumulative" > "$RSS_CSV"
  [ -f "$VM_FREE_CSV" ] || echo "ts,vm,total_mb,used_mb,free_mb" > "$VM_FREE_CSV"
  [ -f "$RING_CSV" ]    || echo "ts,shard,events,span_secs" > "$RING_CSV"

  sampler_loop >>"$LOGFILE" 2>&1 &
  local loop_pid=$!
  disown "$loop_pid"
  echo "$loop_pid" > "$PIDFILE"
  echo "sampler started (PID $loop_pid, interval ${INTERVAL}s) — $WORKDIR"

  # Startup baseline snapshot: the pre-load reading that a later "snapshot
  # --label pre-teardown" subtracts against to isolate this run's own
  # interval instead of everything since process start.
  take_snapshot "startup"
}

cmd_stop() {
  if [ ! -f "$PIDFILE" ]; then
    echo "no sampler pidfile at $PIDFILE — nothing to stop"
    return 0
  fi
  local pid
  pid="$(cat "$PIDFILE" 2>/dev/null || true)"
  rm -f "$PIDFILE"
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
    echo "sampler PID (from pidfile) already gone"
    return 0
  fi
  echo "stopping sampler (PID $pid) ..."
  kill -TERM "$pid" 2>/dev/null || true
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$pid" 2>/dev/null || { echo "sampler stopped"; return 0; }
    sleep 0.5
  done
  echo "sampler PID $pid still alive 5s after SIGTERM — sending SIGKILL" >&2
  kill -9 "$pid" 2>/dev/null || true
}

cmd_snapshot() {
  take_snapshot "$LABEL"
}

case "$SUBCOMMAND" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  snapshot) cmd_snapshot ;;
esac

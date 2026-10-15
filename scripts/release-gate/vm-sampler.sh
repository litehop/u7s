#!/usr/bin/env bash
# Runs inside the gate VM (as root). Every INTERVAL seconds appends to $OUT/samples.tsv:
#   <epoch>\t<phase>\tMEM\t<MemAvailable kB>
#   <epoch>\t<phase>\t<component>\t<PSS kB>\t<RSS kB>     (summed over all pids of a comm)
# <phase> is the current content of $OUT/phase. Pure /proc reads: no kubectl, no forks
# beyond pgrep, so the probe stays cheap on a 1 vCPU box.
set -u
OUT="${1:?usage: $0 <out-dir> [interval-secs]}"
INTERVAL="${2:-5}"

# component:comm (comm is the kernel's 15-char truncated process name)
COMPONENTS="apiserver:u7s-apiserver kcm:kube-controller kubelet:kubelet crio:crio kube-proxy:kube-proxy coredns:coredns flanneld:flanneld mariadb:mariadbd php-fpm:php-fpm nginx:nginx"

while true; do
  ts="$(date +%s)"
  phase="$(cat "$OUT/phase" 2>/dev/null || echo none)"
  awk -v ts="$ts" -v ph="$phase" '/^MemAvailable:/ {printf "%s\t%s\tMEM\t%s\n", ts, ph, $2}' /proc/meminfo >> "$OUT/samples.tsv"
  for entry in $COMPONENTS; do
    name="${entry%%:*}"; comm="${entry#*:}"
    pids="$(pgrep -x "$comm" || true)"
    [ -n "$pids" ] || continue
    for p in $pids; do cat "/proc/$p/smaps_rollup" 2>/dev/null; done \
      | awk -v ts="$ts" -v ph="$phase" -v n="$name" '/^Pss:/ {pss+=$2} /^Rss:/ {rss+=$2} END {printf "%s\t%s\t%s\t%d\t%d\n", ts, ph, n, pss, rss}' >> "$OUT/samples.tsv"
  done
  sleep "$INTERVAL"
done

#!/usr/bin/env bash
# Runs inside the gate VM (as root). Every INTERVAL seconds appends to $OUT/capture.tsv:
#   <epoch>\t<phase>\tPSI\t<cpu some total us>\t<cpu full total us>\t<mem some total us>\t<mem full total us>
#   <epoch>\t<phase>\tSTAT\t<user>\t<nice>\t<system>\t<idle>\t<iowait>\t<irq>\t<softirq>\t<steal>   (jiffies)
#   <epoch>\t<phase>\tPROC\t<component>\t<utime+stime jiffies>       (summed over pids of a comm)
#   <epoch>\t<phase>\tNODE\t<Ready status>\t<node Lease renewTime>
# and <epoch>\t<counter>\t<value> for pgmajfault/workingset_refault/pswp* to $OUT/vmstat.tsv.
set -u
OUT="${1:?usage: $0 <out-dir> <kubeconfig> [interval-secs]}"
KCFG="${2:?kubeconfig}"
INTERVAL="${3:-2}"
COMPONENTS="apiserver:u7s-apiserver kcm:kube-controller kubelet:kubelet crio:crio kube-proxy:kube-proxy coredns:coredns flanneld:flanneld mariadb:mariadbd php-fpm:php-fpm"
NODE="$(kubectl --kubeconfig "$KCFG" get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"

while true; do
  ts="$(date +%s)"
  phase="$(cat "$OUT/phase" 2>/dev/null || echo none)"
  {
    awk -v ts="$ts" -v ph="$phase" '
      FNR == 1 {n++}
      $1 == "some" || $1 == "full" {t = $5; sub("total=", "", t); v[n "," $1] = t}
      END {printf "%s\t%s\tPSI\t%s\t%s\t%s\t%s\n", ts, ph, v["1,some"], v["1,full"], v["2,some"], v["2,full"]}
    ' /proc/pressure/cpu /proc/pressure/memory
    awk -v ts="$ts" -v ph="$phase" '/^cpu / {printf "%s\t%s\tSTAT\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ts, ph, $2,$3,$4,$5,$6,$7,$8,$9}' /proc/stat
    for entry in $COMPONENTS; do
      name="${entry%%:*}"; comm="${entry#*:}"
      for p in $(pgrep -x "$comm" || true); do cut -d' ' -f14,15 "/proc/$p/stat" 2>/dev/null; done \
        | awk -v ts="$ts" -v ph="$phase" -v n="$name" '{j+=$1+$2; seen=1} END {if (seen) printf "%s\t%s\tPROC\t%s\t%d\n", ts, ph, n, j}'
    done
    ready="$(timeout 5 kubectl --kubeconfig "$KCFG" get node "$NODE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)"
    lease="$(timeout 5 kubectl --kubeconfig "$KCFG" -n kube-node-lease get lease "$NODE" -o jsonpath='{.spec.renewTime}' 2>/dev/null)"
    printf '%s\t%s\tNODE\t%s\t%s\n' "$ts" "$phase" "${ready:-unreachable}" "${lease:-unreachable}"
  } >> "$OUT/capture.tsv"
  awk -v ts="$ts" '/^(pgmajfault|workingset_refault_file|workingset_refault_anon|pswpin|pswpout) / {printf "%s\t%s\t%s\n", ts, $1, $2}' /proc/vmstat >> "$OUT/vmstat.tsv"
  sleep "$INTERVAL"
done

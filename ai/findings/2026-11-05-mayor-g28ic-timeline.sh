#!/usr/bin/env bash
# usage: timeline.sh <out-dir> <phase> [pre_s=30] [post_s=30]
# Aligned timeline, t=0 at the first sample labelled <phase>. Columns:
#   t_s  phase  sumPSS_MiB  MemAvail_MiB  refault_file/s  memPSI_full_%  memPSI_some_%  pgscan/s  iowait_jiffies/s
# Rates are deltas against the previous attrib row (blank when none exists).
# sumPSS is the sum of every component row carrying that exact epoch.
set -eu
att() { [ -f "$1/attrib.tsv" ] && echo "$1/attrib.tsv" || echo /dev/null; }
d="$1"; ph="$2"; pre="${3:-30}"; post="${4:-30}"
t0=$(awk -F'\t' -v p="$ph" '$2==p{print $1; exit}' "$d/samples.tsv")
t1=$(awk -F'\t' -v p="$ph" '$2==p{e=$1} END{print e}' "$d/samples.tsv")
[ -n "$t0" ] || { echo "no phase $ph" >&2; exit 1; }
awk -F'\t' -v t0="$t0" -v t1="$t1" -v pre="$pre" -v post="$post" '
FNR==1 { fileno++ }
fileno==1 {
  if ($3=="MEM") { mem[$1]=$4; phs[$1]=$2; ts[++n]=$1 }
  else sum[$1]+=$4
  next
}
$3=="VM" && $4=="workingset_refault_file" { rf[$1]=$5 }
$3=="VM" && ($4=="pgscan_file"||$4=="pgscan_anon") { sc[$1]+=$5 }
$3=="PSI" && $4=="memory" { pf[$1]=$6; ps[$1]=$5 }
$3=="STAT" { io[$1]=$6 }
{ ae[$1]=1 }
END {
  for (e in ae) a[++m]=e+0
  for (i=2;i<=m;i++) { v=a[i]; j=i-1; while (j>0 && a[j]>v) { a[j+1]=a[j]; j-- } a[j+1]=v }
  for (i=2;i<=m;i++) prev[a[i]]=a[i-1]
  for (i=1;i<=n;i++) { e=ts[i]; if (e<t0-pre || e>t1+post) continue
    p=prev[e]; r=""; f=""; s=""; sc_=""; iw=""
    if (p>0) { dt=e-p
      r=sprintf("%.0f",(rf[e]-rf[p])/dt); f=sprintf("%.1f",(pf[e]-pf[p])/dt/10000)
      s=sprintf("%.1f",(ps[e]-ps[p])/dt/10000); sc_=sprintf("%.0f",(sc[e]-sc[p])/dt); iw=sprintf("%.0f",(io[e]-io[p])/dt) }
    printf "%d\t%s\t%.0f\t%.0f\t%s\t%s\t%s\t%s\t%s\n", e-t0, phs[e], sum[e]/1024, mem[e]/1024, r, f, s, sc_, iw
  }
}' "$d/samples.tsv" "$(att "$d")"

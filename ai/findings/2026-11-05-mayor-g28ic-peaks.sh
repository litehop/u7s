#!/usr/bin/env bash
# usage: peaks.sh <samples.tsv>
# One row per (phase, component): phase, component, start_kB (first sample in phase), peak_kB,
# peak offset seconds into phase, end_kB, phase duration s. Component rows only (PSS column).
awk -F'\t' '
$3=="MEM" { next }
{
  ph=$2; c=$3; k=ph SUBSEP c
  if (!(ph in t0)) { t0[ph]=$1; order[++np]=ph }
  if (!(k in seen)) { seen[k]=1; comps[ph]=comps[ph] " " c; start[k]=$4; peak[k]=-1 }
  if ($4>peak[k]) { peak[k]=$4; poff[k]=$1-t0[ph] }
  end[k]=$4; tl[ph]=$1-t0[ph]
}
END {
  for (i=1;i<=np;i++) { ph=order[i]; n=split(comps[ph],a," ")
    for (j=1;j<=n;j++) { k=ph SUBSEP a[j]
      printf "%s\t%s\t%d\t%d\t%d\t%d\t%d\n", ph, a[j], start[k], peak[k], poff[k], end[k], tl[ph] } }
}' "$1"

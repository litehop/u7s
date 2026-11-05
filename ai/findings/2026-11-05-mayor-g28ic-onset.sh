#!/usr/bin/env bash
# usage: onset.sh <out-dir> <phase>
# Cause-vs-effect probe on the first burst: per run, baseline = mean over the 60 s before t=0 of
# summed component PSS (MiB) and refault/s. Prints the first t (s, t=0 = burst phase start) where
# refault/s exceeds 5x baseline and mem PSI full exceeds 10 %, and the first t where summed PSS
# exceeds baseline + 15 MiB, plus the summed-PSS delta vs baseline at the refault onset.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
"$here/2026-11-05-mayor-g28ic-timeline.sh" "$1" "$2" 60 120 | awk -F'\t' '
$1<-5 && $5!="" { sb+=$3; rb+=$5; nb++ }
{ t[NR]=$1; s[NR]=$3; r[NR]=$5; f[NR]=$6; n=NR }
END {
  sb/=nb; rb/=nb
  for (i=1;i<=n;i++) {
    if (!ro && t[i]>=-5 && r[i]!="" && r[i]>5*rb) { ro=t[i]; rs=s[i]-sb }
    if (!fo && t[i]>=-5 && f[i]!="" && f[i]>10) fo=t[i]
    if (!so && t[i]>=-5 && s[i]>sb+15) so=t[i]
  }
  printf "baseSum=%.0f baseRefault=%.0f refaultOnset=%s fullOnset=%s sumRiseOnset=%s sumDeltaAtRefaultOnset=%+.0f\n", sb, rb, (ro==""?"none":ro), (fo==""?"none":fo), (so==""?"none":so), rs
}'

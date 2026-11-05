#!/usr/bin/env bash
# usage: agg.sh <label> <run-dir> [outcome-override]
# <run-dir> holds verdict.txt and out/{samples,attrib}.tsv. Emits one TSV row per burst phase:
#   label phase outcome dur_s nsamp sum0_MiB sumMax_MiB sumMaxOff_s mem0_MiB memMin_MiB memMinOff_s
#   refMax/s refMaxOff_s fullMax% fullMaxOff_s  comps
# comps = "name:+dMiB@off_s" for every component whose in-phase peak exceeds its first in-phase
# sample by >= 3 MiB (off = seconds after the phase's first sample). Outcome: ramp-table rows
# need (a)-(d) all PASS; legacy verdicts only record whether the burst finished within 300 s.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
label="$1"; run="$2"; out="$run/out"
phases=$(awk -F'\t' '$2 ~ /^burst/ && !s[$2]++ {print $2}' "$out/samples.tsv")
for ph in $phases; do
  n="${ph#burst}"
  if [ "$n" = n ]; then n=$(sed -n 's/^RESULT: .*(\([0-9]*\)-pod burst).*/\1/p' "$run/verdict.txt"); fi
  outcome=$(awk -v n="$n" '
    /^size   \(a\)/ { tbl=1; next }
    tbl && $1==n { if ($2=="not") print "NA"; else print ($2=="PASS"&&$3=="PASS"&&$4=="PASS"&&$5=="PASS") ? "PASS" : "FAIL"; found=1 }
    !tbl && /^(PASS|FAIL) \(c\)/ { if (match($0, n "-pod=[0-9]+s")) { v=substr($0, RSTART, RLENGTH); sub(/.*=/, "", v); sub(/s/, "", v); print (v+0<300) ? "c-ok" : "c-FAIL"; found=1 } }
    END { if (!found) print "?" }' "$run/verdict.txt")
  comps=$("$here/2026-11-05-mayor-g28ic-peaks.sh" "$out/samples.tsv" | awk -F'\t' -v p="$ph" '
    $1==p && $2!="" { d=($4-$3)/1024; if (d>=3) printf "%s:+%.0f@%d ", $2, d, $5 }')
  "$here/2026-11-05-mayor-g28ic-timeline.sh" "$out" "$ph" 0 0 | awk -F'\t' -v l="$label" -v p="$ph" -v o="${3:-$outcome}" -v c="$comps" '
    $2==p {
      n++; if (n==1) { s0=$3; m0=$4; mm=$4; mmo=0; sm=$3; smo=0 }
      if ($3>sm) { sm=$3; smo=$1 } ; if ($4<mm) { mm=$4; mmo=$1 }
      if ($5!="" && $5+0>rm) { rm=$5+0; rmo=$1 } ; if ($6!="" && $6+0>fm) { fm=$6+0; fmo=$1 }
      last=$1
    }
    END { if (n) printf "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n", l, p, o, last, n, s0, sm, smo, m0, mm, mmo, rm, rmo, fm, fmo, c }'
done

#!/usr/bin/env bash
# usage: all.sh [e2e-root]   -> TSV of agg.sh rows for every run dir holding a burst phase.
# label = run dir relative to root; observers column: streaming observers present (y/n/?).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
root="${1:-/Users/balint.erdos/litehop/u7s/temp/e2e}"
printf 'label\tobs\tphase\toutcome\tdur_s\tnsamp\tsum0\tsumMax\tsumMaxOff\tmem0\tmemMin\tmemMinOff\trefMax\trefMaxOff\tfullMax\tfullMaxOff\tcomps\n'
find "$root" -name samples.tsv -size +1k | sort | while read -r f; do
  out="$(dirname "$f")"; run="$(dirname "$out")"
  [ -f "$run/verdict.txt" ] || continue
  grep -q "$(printf '\tburst')" "$f" || continue
  label="${run#"$root"/}"
  case "$label" in
    9ygmh/run-A1/*|9ygmh/run-A3/*|9ygmh/run-Bp*|kutwm/*) obs=y ;;
    9ygmh/run-A0*|9ygmh/run-A2/*|e5idl/*) obs=n ;;
    *) obs='?' ;;
  esac
  "$here/2026-11-05-mayor-g28ic-agg.sh" "$label" "$run" | awk -F'\t' -v o="$obs" 'BEGIN{OFS="\t"} {$1=$1 FS o; print}'
done

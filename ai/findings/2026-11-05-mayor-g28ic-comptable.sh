#!/usr/bin/env bash
# usage: comptable.sh <out-dir> <phase>  -> per-component start / peak (delta) / peak offset / end, MiB
here="$(cd "$(dirname "$0")" && pwd)"
"$here/2026-11-05-mayor-g28ic-peaks.sh" "$1/samples.tsv" | awk -F'\t' -v p="$2" '$1==p {
  printf "%s\t%.0f\t%.0f\t%+.0f\t%d/%d\t%.0f\n", $2, $3/1024, $4/1024, ($4-$3)/1024, $5, $7, $6/1024 }'

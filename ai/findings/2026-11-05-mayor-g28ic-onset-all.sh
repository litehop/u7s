#!/usr/bin/env bash
# usage: onset-all.sh [e2e-root]  -> onset.sh over the runs that carry attrib.tsv (first burst phase only).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
root="${1:-/Users/balint.erdos/litehop/u7s/temp/e2e}"
find "$root" -name attrib.tsv -size +1k | sort | while read -r a; do
  out="$(dirname "$a")"
  grep -q "$(printf '\tburst20\t')" "$out/samples.tsv" || continue
  printf '%s\t%s\n' "${out#"$root"/}" "$("$here/2026-11-05-mayor-g28ic-onset.sh" "$out" burst20)"
done

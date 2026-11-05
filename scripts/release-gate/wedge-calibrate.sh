#!/usr/bin/env bash
# Prints, per burst phase of one run's attrib.tsv, the highest values the wedge signals
# (lib.sh rg_wedge_reason) would have seen over any RG_WEDGE_SECS window, and the longest time
# the ready-pod count stayed unchanged if a burst-progress.log sits beside it. Every wedge
# threshold must sit above these numbers for passing runs.
# Usage: wedge-calibrate.sh <out-dir> [vcpus] [window-secs]
set -euo pipefail
DIR="${1:?usage: $0 <out-dir> [vcpus] [window-secs]}"
JPS=$(( ${2:-1} * 100 ))
W="${3:-60}"
awk -F'\t' -v jps="$JPS" -v w="$W" '
  $2 ~ /^burst/ && $3 == "STAT" {n++; ts[n] = $1; io[n] = $6; ph[n] = $2}
  $2 ~ /^burst/ && $3 == "PSI" && $4 == "memory" {m++; pts[m] = $1; pf[m] = $6; pph[m] = $2}
  END {
    for (j = 1; j <= n; j++) {
      for (i = 1; i < j && ts[i] < ts[j] - w; i++) ;
      sp = ts[j] - ts[i]; if (sp < w * 0.8) continue
      p = 100 * (io[j] - io[i]) / (sp * jps); if (p > mio[ph[j]]) mio[ph[j]] = p
      seen[ph[j]] = 1
    }
    for (j = 1; j <= m; j++) {
      for (i = 1; i < j && pts[i] < pts[j] - w; i++) ;
      sp = pts[j] - pts[i]; if (sp < w * 0.8) continue
      p = 100 * (pf[j] - pf[i]) / (sp * 1000000); if (p > mp[pph[j]]) mp[pph[j]] = p
      seen[pph[j]] = 1
    }
    for (k in seen) printf "%s: max iowait %.1f%%, max memory PSI full %.1f%% over %ds windows\n", k, mio[k], mp[k], w
  }' "$DIR/attrib.tsv"
if [ -s "$DIR/burst-progress.hist" ]; then
  awk '
    /^#/ { if (seg ~ /^burst/ && prev) printf "%s: longest ready-count gap %ds, last change at +%ds\n", seg, gap, prev - first; seg = $2; gap = 0; prev = 0; next }
    NF { if (!prev) first = $1; else if ($1 - prev > gap) gap = $1 - prev; prev = $1 }
    END { if (seg ~ /^burst/ && prev) printf "%s: longest ready-count gap %ds, last change at +%ds\n", seg, gap, prev - first }' "$DIR/burst-progress.hist"
fi

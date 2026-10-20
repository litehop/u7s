#!/usr/bin/env bash
# Prints the burstn-window numbers of one gate run's out/ directory:
# refault/s, pgmajfault/s, memory PSI full %, MemAvailable min (MiB), gated-burst time.
# Usage: burstn-stats.sh <run-out-dir>
set -euo pipefail
OUT="${1:?usage: $0 <run-out-dir>}"
awk -F'\t' '$2 == "burstn" {if (!s) s = $1; e = $1} END {print s, e}' "$OUT/capture.tsv" | {
  read -r s e
  d=$((e - s))
  awk -F'\t' -v s="$s" -v e="$e" '
    $1 >= s && $1 <= e && $2 == "workingset_refault_file" {if (!r0) r0 = $3; r1 = $3}
    $1 >= s && $1 <= e && $2 == "pgmajfault" {if (!m0) m0 = $3; m1 = $3}
    END {printf "window=%ds refault/s=%d pgmajfault/s=%d\n", e - s, (r1 - r0) / (e - s), (m1 - m0) / (e - s)}
  ' "$OUT/vmstat.tsv"
  awk -F'\t' '$2 == "burstn" && $3 == "PSI" {if (!f0) f0 = $7; f1 = $7} END {printf "mem_psi_full=%.0f%%\n", (f1 - f0) / 1e6 / '"$d"' * 100}' "$OUT/capture.tsv"
  awk -F'\t' '$2 == "burstn" && $3 == "MEM" {if (!m || $4 < m) m = $4} END {printf "memavail_min_MiB=%d\n", m / 1024}' "$OUT/samples.tsv"
}
grep -E '^(burst20_secs|burst_pods|burst_secs|notready_events)=' "$OUT/results.env"

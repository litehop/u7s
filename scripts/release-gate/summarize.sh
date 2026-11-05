#!/usr/bin/env bash
# Summarises one gate run's samples.tsv (from vm-sampler.sh) as a markdown table:
# MemAvailable min per phase (the overall min excludes the install phase), and
# per-component PSS/RSS (MiB) at the end of the idle phase, at the end of the wordpress phase, and the peak over the whole run.
#
# Usage: summarize.sh <run-out-dir>
set -euo pipefail
S="${1:?usage: $0 <run-out-dir>}/samples.tsv"
[ -s "$S" ] || { echo "no samples in $S" >&2; exit 1; }

awk -F'\t' '
  $3 == "MEM" {
    v = $4 / 1024
    if (!($2 in memmin) || v < memmin[$2]) memmin[$2] = v
    if (($2 != "install") && (!seen_all || v < allmin)) { allmin = v; seen_all = 1 }
    if (!($2 in phase_seen)) { phase_seen[$2] = 1; order[++np] = $2 }
    next
  }
  {
    c = $3; pss = $4 / 1024; rss = $5 / 1024
    if (!(c in comp_seen)) { comp_seen[c] = 1; corder[++nc] = c }
    lastpss[$2, c] = pss; lastrss[$2, c] = rss
    if (pss > peakpss[c]) peakpss[c] = pss
    if (rss > peakrss[c]) peakrss[c] = rss
    if ($6 / 1024 > peakan[c]) peakan[c] = $6 / 1024
    if ($7 / 1024 > peakfi[c]) peakfi[c] = $7 / 1024
  }
  END {
    if (seen_all) printf "MemAvailable min over run (post-install phases; install has its own row below): %.0f MiB\n\n", allmin
    else printf "MemAvailable min over run (post-install phases): n/a\n\n"
    printf "| phase | MemAvailable min (MiB) |\n|---|---|\n"
    for (i = 1; i <= np; i++) printf "| %s | %.0f |\n", order[i], memmin[order[i]]
    printf "\n| component | idle PSS/RSS | wordpress PSS/RSS | peak PSS | peak RSS | peak Pss_Anon | peak Pss_File |\n|---|---|---|---|---|---|---|\n"
    for (i = 1; i <= nc; i++) {
      c = corder[i]
      printf "| %s | %.1f / %.1f | %.1f / %.1f | %.1f | %.1f | %.1f | %.1f |\n", c, \
        lastpss["idle", c], lastrss["idle", c], lastpss["wordpress", c], lastrss["wordpress", c], peakpss[c], peakrss[c], peakan[c], peakfi[c]
    }
  }' "$S"

A="$(dirname "$S")/attrib.tsv"
[ -s "$A" ] || exit 0
# Kernel-side split per phase (MiB): where MemAvailable went. file = Active(file)+Inactive(file).
awk -F'\t' '
  $3 == "MEMI" {
    if (!($2 in seen)) { seen[$2] = 1; order[++n] = $2 }
    p = $2
    if (!(p in c) || $4 > anon[p]) anon[p] = $4
    f = $5 + $6; if (!(p in c) || f < filemin[p]) filemin[p] = f
    if (!(p in c) || $7 > slab[p]) slab[p] = $7
    if (!(p in c) || $10 > pt[p]) pt[p] = $10
    if (!(p in c) || $12 > shm[p]) shm[p] = $12
    c[p]++
  }
  $3 == "SELF" { if (!sf) sf = $4; sl = $4; st0 = (st0 ? st0 : $1); st1 = $1 }
  END {
    if (n) {
      printf "\n| phase | MEMI samples | max AnonPages | min file (Active+Inactive) | max Slab | max PageTables | max Shmem |\n|---|---|---|---|---|---|---|\n"
      for (i = 1; i <= n; i++) { p = order[i]; printf "| %s | %d | %.0f | %.0f | %.0f | %.0f | %.0f |\n", p, c[p], anon[p] / 1024, filemin[p] / 1024, slab[p] / 1024, pt[p] / 1024, shm[p] / 1024 }
    }
    if (st1 > st0) printf "\nsampler CPU: %.2f%% of one core over %d s (%d jiffies)\n", (sl - sf) / (st1 - st0), st1 - st0, sl - sf
  }' "$A"

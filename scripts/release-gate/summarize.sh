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
  }
  END {
    if (seen_all) printf "MemAvailable min over run (post-install phases; install has its own row below): %.0f MiB\n\n", allmin
    else printf "MemAvailable min over run (post-install phases): n/a\n\n"
    printf "| phase | MemAvailable min (MiB) |\n|---|---|\n"
    for (i = 1; i <= np; i++) printf "| %s | %.0f |\n", order[i], memmin[order[i]]
    printf "\n| component | idle PSS/RSS | wordpress PSS/RSS | peak PSS | peak RSS |\n|---|---|---|---|---|\n"
    for (i = 1; i <= nc; i++) {
      c = corder[i]
      printf "| %s | %.1f / %.1f | %.1f / %.1f | %.1f | %.1f |\n", c, \
        lastpss["idle", c], lastrss["idle", c], lastpss["wordpress", c], lastrss["wordpress", c], peakpss[c], peakrss[c]
    }
  }' "$S"

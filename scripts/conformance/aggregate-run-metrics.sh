#!/usr/bin/env bash
# Rolls the raw artifacts sample-run-metrics.sh already produces for every
# conformance run (rss.csv, vm-free.csv, ring-age.csv, metrics-NN-<label>.prom)
# into one markdown report readable at a glance.
#
# Before this script existed, those artifacts landed in a run's
# temp/e2e/<TIMESTAMP>-<slug>/monitoring/ directory (see run-all.sh's own
# "Re-copy the monitoring artifacts" step) and were only useful if an operator
# opened rss.csv by hand and eyeballed it — exactly the by-hand-loop problem
# sample-run-metrics.sh itself was built to remove from the SAMPLING side,
# just moved one step downstream to the READING side instead.
#
# Usage:
#   aggregate-run-metrics.sh <run-dir> [-o <output-file>] [--free-threshold-mb <N>] [--free-threshold-pct <N>]
#
# <run-dir> may be either:
#   - a finished run's temp/e2e/<TIMESTAMP>-<slug>/ directory (artifacts live
#     under its monitoring/ subdirectory), or
#   - a raw sampler --workdir (e.g. temp/u7s/, or any --workdir passed
#     straight to sample-run-metrics.sh) that holds the CSVs/.prom files
#     directly, for investigating a still-running or --stack-only session.
#
# Metric-name note: the design this script follows was written
# against aspirational metric names (apiserver_request_duration_seconds,
# apiserver_longrunning_gauge) that this apiserver has never actually emitted
# -- it exports apiserver_watch_open_duration_seconds (the one request-latency
# histogram it has: watch-open latency) and apiserver_longrunning_requests
# (the actual gauge name) instead. Rather than hard-code either the
# aspirational or the current names forever, this script prefers the
# aspirational name IF a snapshot ever contains it (so a future apiserver that
# grows a real apiserver_request_duration_seconds/apiserver_longrunning_gauge
# is picked up with no change here) and falls back to today's real metric
# otherwise -- see pick_histogram_metric/pick_gauge_metric below.
set -euo pipefail

usage() {
  echo "usage: $0 <run-dir> [-o <output-file>] [--free-threshold-mb <N>] [--free-threshold-pct <N>]" >&2
  exit 1
}

RUN_DIR=""
OUT_FILE=""
FREE_THRESHOLD_MB=""
FREE_THRESHOLD_PCT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) OUT_FILE="$2"; shift 2 ;;
    --free-threshold-mb) FREE_THRESHOLD_MB="$2"; shift 2 ;;
    --free-threshold-pct) FREE_THRESHOLD_PCT="$2"; shift 2 ;;
    -h|--help) usage ;;
    -*) echo "Unknown flag: $1" >&2; usage ;;
    *)
      if [ -z "$RUN_DIR" ]; then
        RUN_DIR="$1"
      else
        echo "Unexpected extra argument: $1" >&2
        usage
      fi
      shift
      ;;
  esac
done
[ -z "$RUN_DIR" ] && usage
[ -d "$RUN_DIR" ] || { echo "error: not a directory: $RUN_DIR" >&2; exit 1; }

# A caller who explicitly names only one threshold means exactly that one --
# e.g. an existing script pinning --free-threshold-mb to some value must keep
# seeing pure fixed-MB counting, not a silently-added percentage check that
# changes its output. Only when NEITHER is given do both defaults apply.
if [ -z "$FREE_THRESHOLD_MB" ] && [ -z "$FREE_THRESHOLD_PCT" ]; then
  FREE_THRESHOLD_MB=100
  FREE_THRESHOLD_PCT=5
fi

# A finished run's temp/e2e/<slug>/ has the artifacts under monitoring/ (see
# run-all.sh's re-copy step); a raw sampler --workdir has them directly. A
# monitoring/ subdirectory is only ever created by that re-copy step, so its
# mere existence -- not which specific files happen to be present in it, e.g.
# a run where the CSVs are all still under --workdir but only the sonobuoy
# pre-run .prom snapshot has landed here -- is what distinguishes the two
# layouts.
if [ -d "$RUN_DIR/monitoring" ]; then
  ART_DIR="$RUN_DIR/monitoring"
else
  ART_DIR="$RUN_DIR"
fi

RSS_CSV="$ART_DIR/rss.csv"
VM_FREE_CSV="$ART_DIR/vm-free.csv"
RING_CSV="$ART_DIR/ring-age.csv"

# ---------------------------------------------------------------------------
# Peak RSS per component (rss.csv: ts,scope,pid,comm,rss_kb,footprint_kb,cpu_seconds_cumulative)
# ---------------------------------------------------------------------------
rss_peak_for() {
  local scope_kind="$1" comm_re="$2"
  awk -F, -v scope_kind="$scope_kind" -v comm_re="$comm_re" '
    NR == 1 { next }
    {
      is_host = ($2 == "host") ? 1 : 0
      if (scope_kind == "host" && is_host == 0) next
      if (scope_kind == "vm" && is_host == 1) next
      if ($4 !~ comm_re) next
      if ($5 + 0 > maxrss) maxrss = $5 + 0
      if ($6 != "" && $6 + 0 > maxfp) maxfp = $6 + 0
      n++
    }
    END { printf "%d\t%d\t%d\n", maxrss + 0, maxfp + 0, n + 0 }
  ' "$RSS_CSV"
}

# comm= is truncated to 15 chars by `ps`/`comm=` on both macOS and Linux, so
# multi-word process names (kube-controller-manager, kube-network-policies)
# are matched by prefix, not exact equality -- an exact match would silently
# report "not observed" for every real run, the opposite of the bead's intent.
#
# The "u7s-scheduler" category below reads "not observed" for any run started with
# --embedded-scheduler true: scheduling then runs as a task inside
# u7s-apiserver rather than its own process, so its RSS is folded into the
# "u7s-apiserver" row instead of a separate "u7s-scheduler" one -- that is the
# expected, memory-saving outcome this flag exists for, not a missing sample.
peak_rss_section() {
  echo "## Peak RSS per component"
  echo ""
  if [ ! -f "$RSS_CSV" ]; then
    echo "_rss.csv not found under $ART_DIR -- sampler may not have run for this conformance run._"
    return
  fi
  echo "| Component | Peak RSS (MB) | Peak footprint (MB) | Samples |"
  echo "|---|---:|---:|---:|"
  local name scope_kind comm_re line maxrss maxfp n rss_mb fp_str
  while IFS='|' read -r name scope_kind comm_re; do
    line="$(rss_peak_for "$scope_kind" "$comm_re")"
    IFS="$(printf '\t')" read -r maxrss maxfp n <<< "$line"
    if [ "${n:-0}" -eq 0 ]; then
      echo "| $name | not observed | -- | 0 |"
      continue
    fi
    rss_mb="$(awk -v k="$maxrss" 'BEGIN { printf "%.1f", k / 1024 }')"
    if [ "$maxfp" -gt 0 ]; then
      fp_str="$(awk -v k="$maxfp" 'BEGIN { printf "%.1f", k / 1024 }')"
    else
      fp_str="--"
    fi
    printf '| %s | %s | %s | %d |\n' "$name" "$rss_mb" "$fp_str" "$n"
  done <<'CATEGORIES'
u7s-apiserver|host|^apiserver$
u7s-scheduler|host|^scheduler$
konnectivity-server|host|^konnectivity-server$
kubelet|vm|^kubelet$
kube-proxy|vm|^kube-proxy$
kube-controller-manager|vm|^kube-controller
cri-o|vm|^cri-?o$
kube-network-policies|vm|^kube-network
sonobuoy control pods|vm|^sonobuoy$
CATEGORIES

  echo ""
  echo "Other VM processes observed (top 5 by peak RSS, not individually tracked above):"
  echo ""
  echo "| Process | Peak RSS (MB) |"
  echo "|---|---:|"
  local skip_re='^kubelet$|^kube-proxy$|^kube-controller|^cri-?o$|^kube-network|^sonobuoy$'
  local other_rows
  other_rows="$(awk -F, -v skip_re="$skip_re" '
    NR == 1 { next }
    $2 == "host" { next }
    $4 ~ skip_re { next }
    { if ($5 + 0 > max[$4]) max[$4] = $5 + 0 }
    END { for (c in max) print max[c] "\t" c }
  ' "$RSS_CSV" | sort -rn | head -5)"
  if [ -z "$other_rows" ]; then
    echo "| _(none)_ | -- |"
  else
    local rss comm
    while IFS="$(printf '\t')" read -r rss comm; do
      printf '| %s | %.1f |\n' "$comm" "$(awk -v k="$rss" 'BEGIN { printf "%.1f", k / 1024 }')"
    done <<< "$other_rows"
  fi
}

# ---------------------------------------------------------------------------
# OOM proximity (vm-free.csv: ts,vm,total_mb,used_mb,free_mb)
#
# A fixed MB floor doesn't scale with the VM's total memory -- 100MB free on
# an 8GB VM is a much thinner margin (~1.3%) than the same floor would be on
# a 16GB VM. --free-threshold-pct catches that class of signal regardless of
# VM size; when both thresholds are active, either one being crossed trips
# the alert for that tick.
# ---------------------------------------------------------------------------
oom_proximity_section() {
  local mb_active=0 pct_active=0 desc=""
  if [ -n "$FREE_THRESHOLD_MB" ]; then
    mb_active=1
    desc="free < ${FREE_THRESHOLD_MB} MB"
  fi
  if [ -n "$FREE_THRESHOLD_PCT" ]; then
    pct_active=1
    if [ -n "$desc" ]; then
      desc="${desc} or < ${FREE_THRESHOLD_PCT}% of total"
    else
      desc="free < ${FREE_THRESHOLD_PCT}% of total"
    fi
  fi
  echo "## OOM proximity (${desc})"
  echo ""
  if [ ! -f "$VM_FREE_CSV" ]; then
    echo "_vm-free.csv not found under $ART_DIR -- sampler may not have run for this conformance run._"
    return
  fi
  echo "| VM | Ticks | Ticks under threshold | Min free (MB) | At |"
  echo "|---|---:|---:|---:|---|"
  awk -F, -v mb_thresh="${FREE_THRESHOLD_MB:-0}" -v mb_active="$mb_active" \
         -v pct_thresh="${FREE_THRESHOLD_PCT:-0}" -v pct_active="$pct_active" '
    NR == 1 { next }
    {
      vm = $2; tot_mb = $3 + 0; free = $5 + 0; ts = $1
      total[vm]++
      crossed = 0
      if (mb_active == 1 && free < mb_thresh) crossed = 1
      if (pct_active == 1 && tot_mb > 0 && (free / tot_mb * 100) < pct_thresh) crossed = 1
      if (crossed) {
        under[vm]++
        if (!(vm in minfree) || free < minfree[vm]) { minfree[vm] = free; mints[vm] = ts }
      }
    }
    END {
      for (vm in total) {
        u = under[vm] + 0
        if (u > 0) {
          printf "%s\t%d\t%d\t%d\t%s\n", vm, total[vm], u, minfree[vm], mints[vm]
        } else {
          printf "%s\t%d\t%d\t--\t--\n", vm, total[vm], u
        }
      }
    }
  ' "$VM_FREE_CSV" | sort | while IFS="$(printf '\t')" read -r vm total under minfree mints; do
    printf '| %s | %s | %s | %s | %s |\n' "$vm" "$total" "$under" "$minfree" "$mints"
  done
}

# ---------------------------------------------------------------------------
# Watch-ring saturation (ring-age.csv: ts,shard,events,span_secs)
# ---------------------------------------------------------------------------
watch_ring_section() {
  echo "## Watch-ring saturation"
  echo ""
  if [ ! -f "$RING_CSV" ]; then
    echo "_ring-age.csv not found under $ART_DIR -- sampler may not have run for this conformance run._"
    return
  fi
  local n_lines n_rows first_ts last_ts
  n_lines="$(wc -l < "$RING_CSV" | tr -d ' ')"
  n_rows=$(( n_lines - 1 ))
  if [ "$n_rows" -le 0 ]; then
    echo "_ring-age.csv has no data rows (apiserver /metrics was never reachable during this run)._"
    return
  fi
  first_ts="$(awk -F, 'NR == 2 { print $1 }' "$RING_CSV")"
  last_ts="$(tail -n 1 "$RING_CSV" | awk -F, '{ print $1 }')"
  echo "Observed from ${first_ts} to ${last_ts} (${n_rows} shard-ticks total)."
  echo ""
  echo "Top 5 shards by peak occupancy:"
  echo ""
  echo "| Shard | Peak occupancy (events) | Peak span (s) |"
  echo "|---|---:|---:|"
  local ev sp shard
  awk -F, '
    NR == 1 { next }
    {
      shard = $2; events = $3 + 0; span = $4 + 0
      if (events > maxev[shard]) maxev[shard] = events
      if (span > maxsp[shard]) maxsp[shard] = span
    }
    END { for (s in maxev) printf "%d\t%d\t%s\n", maxev[s], maxsp[s], s }
  ' "$RING_CSV" | sort -t "$(printf '\t')" -k1,1rn | head -5 |
    while IFS="$(printf '\t')" read -r ev sp shard; do
      printf '| %s | %d | %d |\n' "$shard" "$ev" "$sp"
    done
}

# ---------------------------------------------------------------------------
# apiserver /metrics delta: first snapshot vs last snapshot.
# ---------------------------------------------------------------------------

# Sums the value field across every series whose metric+label-selector text
# matches the given extended-regex PATTERN (anchored at line start). Used both
# for a bare "every series of this metric" sum (apiserver_watch_events_total)
# and a label-filtered sum (apiserver_request_total{...code="5xx"...}). The
# trailing `|| true` matters: under `set -o pipefail`, a `grep` that matches
# nothing (the normal case for a 5xx count on a healthy run) exits 1, which
# would otherwise abort this whole script even though the "0" answer awk
# already printed is correct.
sum_metric() {
  local pattern="$1" file="$2"
  grep -E "$pattern" "$file" 2>/dev/null | awk '{ s += $2 } END { printf "%d\n", s + 0 }' || true
}

pick_histogram_metric() {
  local start_file="$1" end_file="$2"
  if grep -q -m1 '^apiserver_request_duration_seconds_bucket{' "$start_file" "$end_file" 2>/dev/null; then
    echo "apiserver_request_duration_seconds"
  else
    echo "apiserver_watch_open_duration_seconds"
  fi
}

pick_gauge_metric() {
  local start_file="$1" end_file="$2"
  if grep -q -m1 '^apiserver_longrunning_gauge{' "$start_file" "$end_file" 2>/dev/null; then
    echo "apiserver_longrunning_gauge"
  else
    echo "apiserver_longrunning_requests"
  fi
}

# Prometheus histogram buckets are already CUMULATIVE ("le" bucket = count of
# observations <= le since the process started), so end-minus-start per le is
# already the cumulative count for exactly this interval -- no further
# running-sum step is needed, and it's monotonic non-decreasing in le by
# construction (a superset relationship as le grows), which is what makes the
# "smallest le whose delta clears the target rank" scan below valid.
histogram_quantile_line() {
  local metric="$1" start_file="$2" end_file="$3" frac="$4" label="$5"
  local rows total target le_hit
  rows="$(awk -v metric="$metric" '
    FNR == 1 { fidx++ }
    index($0, metric "_bucket{") == 1 {
      idx = index($0, "le=\"")
      if (idx == 0) next
      rest = substr($0, idx + 4)
      endq = index(rest, "\"")
      le = substr(rest, 1, endq - 1)
      val = $2 + 0
      if (fidx == 1) { s[le] += val } else { e[le] += val }
      seen[le] = 1
    }
    END {
      for (le in seen) {
        d = (e[le] + 0) - (s[le] + 0)
        if (d < 0) d = 0
        lenum = (le == "+Inf") ? 999999999 : le + 0
        printf "%.6f\t%s\t%d\n", lenum, le, d
      }
    }
  ' "$start_file" "$end_file")"

  if [ -z "$rows" ]; then
    echo "  - ${label}: ${metric} not present in these snapshots"
    return
  fi

  total="$(printf '%s\n' "$rows" | awk -F'\t' '$2 == "+Inf" { print $3 }')"
  if [ -z "$total" ] || [ "$total" -le 0 ]; then
    echo "  - ${label}: no samples observed in this interval"
    return
  fi

  target="$(awk -v f="$frac" -v t="$total" 'BEGIN { r = f * t; tgt = int(r); if (r > tgt) tgt++; print tgt }')"
  # Guaranteed to find a match: the le="+Inf" row's delta always equals
  # `total`, and target <= total for any frac <= 1, so the scan below can
  # never fall through to end-of-input un-found.
  le_hit="$(printf '%s\n' "$rows" | sort -t "$(printf '\t')" -k1,1n | awk -F'\t' -v target="$target" '
    $3 + 0 >= target { print $2; exit }
  ')"
  echo "  - ${label}: <= ${le_hit}s (${total} samples observed in interval)"
}

metrics_delta_section() {
  echo "## apiserver /metrics delta (first vs last snapshot)"
  echo ""
  local prom_files=()
  while IFS= read -r f; do
    [ -n "$f" ] && prom_files+=("$f")
  done < <(find "$ART_DIR" -maxdepth 1 -name 'metrics-*.prom' 2>/dev/null | sort)

  if [ "${#prom_files[@]}" -lt 2 ]; then
    echo "_fewer than two metrics-*.prom snapshots found under $ART_DIR -- need at least a start and an end snapshot to compute a delta (found ${#prom_files[@]})._"
    return
  fi

  local start_file="${prom_files[0]}"
  local end_file="${prom_files[$(( ${#prom_files[@]} - 1 ))]}"
  echo "Comparing \`$(basename "$start_file")\` -> \`$(basename "$end_file")\`."
  echo ""

  local start_5xx end_5xx
  start_5xx="$(sum_metric '^apiserver_request_total\{[^}]*code="5[0-9][0-9]"' "$start_file")"
  end_5xx="$(sum_metric '^apiserver_request_total\{[^}]*code="5[0-9][0-9]"' "$end_file")"
  echo "- **5xx responses** (apiserver_request_total): ${start_5xx} -> ${end_5xx} (delta: $(( end_5xx - start_5xx )))"

  local start_we end_we
  start_we="$(sum_metric '^apiserver_watch_events_total\{' "$start_file")"
  end_we="$(sum_metric '^apiserver_watch_events_total\{' "$end_file")"
  echo "- **Watch events served** (apiserver_watch_events_total): ${start_we} -> ${end_we} (delta: $(( end_we - start_we )))"

  local gauge_metric start_lr end_lr peak_lr
  gauge_metric="$(pick_gauge_metric "$start_file" "$end_file")"
  start_lr="$(sum_metric "^${gauge_metric}\\{" "$start_file")"
  end_lr="$(sum_metric "^${gauge_metric}\\{" "$end_file")"
  peak_lr=$(( start_lr > end_lr ? start_lr : end_lr ))
  echo "- **Long-running requests in flight**, summed across all resources (${gauge_metric}, gauge): start=${start_lr}, end=${end_lr}, peak-of-the-two=${peak_lr}"

  local hist_metric
  hist_metric="$(pick_histogram_metric "$start_file" "$end_file")"
  echo "- **${hist_metric}** delta over the interval:"
  histogram_quantile_line "$hist_metric" "$start_file" "$end_file" 0.50 "p50"
  histogram_quantile_line "$hist_metric" "$start_file" "$end_file" 0.99 "p99"
}

generate_report() {
  echo "# Conformance run metrics summary"
  echo ""
  echo "- Run directory: \`$RUN_DIR\`"
  echo "- Artifacts directory: \`$ART_DIR\`"
  echo ""
  peak_rss_section
  echo ""
  oom_proximity_section
  echo ""
  watch_ring_section
  echo ""
  metrics_delta_section
}

if [ -n "$OUT_FILE" ]; then
  generate_report > "$OUT_FILE"
  echo "Report written to: $OUT_FILE"
else
  generate_report
fi

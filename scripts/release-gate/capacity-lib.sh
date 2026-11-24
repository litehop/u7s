#!/usr/bin/env bash
# Pure logic for capacity-benchmark.sh: turns one burst-gate.sh ramp run directory into the
# stamped benchmark JSON and markdown. Sourced by the script and by test-capacity-benchmark.sh;
# no VM access here. Needs jq and lib.sh (rg_get, rg_ramp_step, rg_phase_memmin).

# "<component> <PSS MiB> <RSS MiB>" per component, from the last idle-phase sample in $1
# (samples.tsv). Components with no resident memory are dropped.
cap_idle_components() {
  awk -F'\t' '
    $3 != "MEM" && $2 == "idle" { p[$3] = $4 / 1024; r[$3] = $5 / 1024; if (!($3 in seen)) { seen[$3] = 1; order[++n] = $3 } }
    END { for (i = 1; i <= n; i++) if (p[order[i]] > 0) printf "%s %.1f %.1f\n", order[i], p[order[i]], r[order[i]] }' "$1"
}

# Last MemAvailable (MiB) of phase $2 in samples.tsv $1, or "-".
cap_phase_memlast() {
  awk -F'\t' -v ph="$2" '$2 == ph && $3 == "MEM" { v = $4 / 1024; s = 1 } END { if (s) printf "%.0f\n", v; else print "-" }' "$1"
}

# Minimum MemAvailable (MiB) over every phase except install, or "-".
cap_run_memmin() {
  awk -F'\t' '$3 == "MEM" && $2 != "install" { v = $4 / 1024; if (!s || v < m) { m = v; s = 1 } } END { if (s) printf "%.0f\n", m; else print "-" }' "$1"
}

_cap_get() { rg_get "$@" || true; }
_cap_num_or_null() { case "$1" in ''|*[!0-9.]*) echo null ;; *) echo "$1" ;; esac; }

# Builds the benchmark JSON on stdout.
# $1 run dir (<burst-gate out>/run-N, holding out/results.env, out/samples.tsv, contention.txt)
# $2 ramp sizes, space-separated   $3 u7s version   $4 git sha (full)   $5 git dirty (1|0)
# $6 date (YYYY-MM-DD)             $7 provider (lima|gcp)              $8 provider detail
# $9 requested memory GiB          $10 past-envelope JSON array
cap_build_json() {
  local run="$1" sizes="$2" version="$3" sha="$4" dirty="$5" date="$6" provider="$7" detail="$8" memgib="$9" past="${10}"
  local res="$run/out/results.env" samples="$run/out/samples.tsv" shape="$run/out/vm-shape.env"
  local label authoritative=false contention n secs row memmin pass bursts="[]" max=0 comps
  if [ "$provider" = gcp ]; then authoritative=true; label="provider=gcp ($detail)"
  else label="provider=$provider (non-authoritative)"; fi
  contention="$(cat "$run/contention.txt" 2>/dev/null || true)"
  [ -z "$contention" ] || authoritative=false
  for n in $sizes; do
    secs="$(_cap_get "$res" "ramp_${n}_secs")"
    row="$(rg_ramp_step "$res" "$n")" && pass=true || pass=false
    [ "$row" != notrun ] || { pass=null; secs=""; }
    [ "$pass" != true ] || max="$n"
    memmin="$(rg_phase_memmin "$samples" "burst$n")"
    bursts="$(jq -c --argjson n "$n" --arg secs "$secs" --argjson pass "$pass" --arg mm "$memmin" --arg row "$row" \
      '. + [{pods: $n, ready_secs: (if $secs == "" then null elif ($secs | test("^[0-9]+$")) then ($secs | tonumber) else $secs end), passed: $pass, criteria_abcd: (if $row == "notrun" then null else $row end), mem_available_min_mib: (if $mm == "-" then null else ($mm | tonumber) end)}]' <<<"$bursts")"
  done
  comps="$(cap_idle_components "$samples" | jq -R -s -c 'split("\n") | map(select(length > 0) | split(" ") | {component: .[0], pss_mib: (.[1] | tonumber), rss_mib: (.[2] | tonumber)})')"
  local kernel vcpus memtotal swaptotal arch os
  kernel="$(_cap_get "$shape" kernel)"; vcpus="$(_cap_get "$shape" vcpus)"; arch="$(_cap_get "$shape" arch)"; os="$(_cap_get "$shape" os)"
  memtotal="$(_cap_get "$shape" mem_total_kb)"; swaptotal="$(_cap_get "$shape" swap_total_kb)"
  jq -n \
    --arg version "$version" --arg sha "$sha" --argjson dirty "$([ "$dirty" = 1 ] && echo true || echo false)" --arg date "$date" \
    --arg provider "$provider" --arg label "$label" --argjson authoritative "$authoritative" --arg contention "$contention" \
    --arg kernel "$kernel" --arg os "$os" --arg arch "$arch" --arg memgib "$memgib" \
    --argjson vcpus "$(_cap_num_or_null "$vcpus")" --argjson memtotal "$(_cap_num_or_null "$memtotal")" --argjson swaptotal "$(_cap_num_or_null "$swaptotal")" \
    --argjson comps "$comps" --argjson bursts "$bursts" --argjson max "$max" --argjson past "$past" \
    --arg idle_avail "$(cap_phase_memlast "$samples" idle)" --arg run_min "$(cap_run_memmin "$samples")" \
    --arg install_ok "$(_cap_get "$res" install_ok)" \
    '{
      schema: 1,
      u7s_version: $version,
      git_sha: $sha,
      git_dirty: $dirty,
      date: $date,
      provider: $provider,
      provider_label: $label,
      authoritative: $authoritative,
      contention: (if $contention == "" then null else $contention end),
      shape: {
        vcpus: $vcpus,
        mem_total_mib: (if $memtotal == null then null else ($memtotal / 1024 | floor) end),
        swap_mib: (if $swaptotal == null then null else ($swaptotal / 1024 | floor) end),
        requested_memory_gib: (if $memgib == "" then null else ($memgib | tonumber) end),
        kernel: $kernel, os: $os, arch: $arch
      },
      install_ok: ($install_ok == "1"),
      idle_components: $comps,
      idle_total_pss_mib: ($comps | map(.pss_mib) | add // 0 | . * 10 | round / 10),
      headroom: {
        mem_available_idle_mib: (if $idle_avail == "-" then null else ($idle_avail | tonumber) end),
        mem_available_min_run_mib: (if $run_min == "-" then null else ($run_min | tonumber) end)
      },
      bursts: $bursts,
      gate_burst_20: ($bursts | map(select(.pods == 20)) | first // null),
      max_passing_burst_pods: (if $max == 0 then null else $max end),
      past_envelope: $past
    }'
}

# Fails (non-zero, reason on stderr) unless the JSON on $1 carries the stamp: a YYYY-MM-DD
# date, a hex git SHA, a version and the provider label. An unstamped benchmark cannot be
# cited from a release.
cap_validate_json() {
  local f="$1" bad=""
  jq -e '.date | strings | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")' "$f" >/dev/null 2>&1 || bad="$bad date"
  jq -e '.git_sha | strings | test("^[0-9a-f]{7,40}$")' "$f" >/dev/null 2>&1 || bad="$bad git_sha"
  jq -e '.u7s_version | strings | length > 0' "$f" >/dev/null 2>&1 || bad="$bad u7s_version"
  jq -e '.provider_label | strings | test("^provider=")' "$f" >/dev/null 2>&1 || bad="$bad provider_label"
  [ -z "$bad" ] || { echo "benchmark JSON $f is not stamped; missing or malformed:$bad" >&2; return 1; }
}

# Renders the benchmark markdown on stdout from the JSON on $1.
cap_render_md() {
  local f="$1"
  jq -r '
    def v: if . == null then "n/a" else tostring end;
    "# Capacity benchmark \(.date) @ \(.git_sha[0:8])\n",
    "**\(.provider_label)**" + (if .authoritative then "" else ". Not the release-authoritative shape: use for orientation, not as a gate." end) + "\n",
    "| | |\n|---|---|",
    "| u7s version | \(.u7s_version)" + (if .git_dirty then " (working tree dirty)" else "" end) + " |",
    "| git SHA | `\(.git_sha)` |",
    "| date (UTC) | \(.date) |",
    "| provider | \(.provider_label) |",
    "| vCPU | \(.shape.vcpus | v) |",
    "| RAM (MemTotal) | \(.shape.mem_total_mib | v) MiB |",
    "| swap | \(.shape.swap_mib | v) MiB |",
    "| kernel / OS / arch | \(.shape.kernel | v) / \(.shape.os | v) / \(.shape.arch | v) |",
    (if .contention then "| host contention | \(.contention | gsub("\n"; "; ")) |" else empty end),
    "",
    "## Idle footprint (WordPress + MariaDB not yet deployed)\n",
    "| component | PSS (MiB) | RSS (MiB) |\n|---|---|---|",
    (.idle_components[] | "| \(.component) | \(.pss_mib) | \(.rss_mib) |"),
    "",
    "Total idle PSS: \(.idle_total_pss_mib) MiB. MemAvailable at idle: \(.headroom.mem_available_idle_mib | v) MiB; minimum over the whole run after install: \(.headroom.mem_available_min_run_mib | v) MiB.\n",
    "## Bursts to Ready\n",
    "The 20-pod burst is the release gate. Larger bursts are documented, not gated. The ramp stops at the first failing size.\n",
    "| pods | Ready after (s) | passed (a-d) | MemAvailable min (MiB) |\n|---|---|---|---|",
    (.bursts[] | "| \(.pods) | \(.ready_secs | v) | \(if .passed == null then "not run" elif .passed then "yes" else "NO (\(.criteria_abcd))" end) | \(.mem_available_min_mib | v) |"),
    "",
    "Criteria: (a) no OOM kill of a control-plane process or kube-system pod, (b) node Ready throughout, (c) Ready within 300 s, (d) WordPress still answers and the MariaDB marker row survives.\n",
    "Largest passing burst: \(.max_passing_burst_pods | v) pods, all Ready at once on this shape, with WordPress and MariaDB resident.\n",
    "## Past the envelope\n",
    (.past_envelope[] | "- " + .)
  ' "$f"
}

#!/usr/bin/env bash
# Pure logic for the KCM memory harness (kcm-mem-run.sh, kcm-mem-ab.sh). Sourced; no VM access
# except kcm_stage_sample, which runs kcm_sample_procs inside the VM. Needs jq.
#
# kcm-mem.json (schema_version 1), one per run:
#   kcm_mode R|T, ported_controllers [], kcm_controllers (effective --controllers flag),
#   kcm_restarts, git_sha, git_dirty, date, vm {name, kernel, vcpus, mem_total_kb, arch},
#   host {os, ncpu}, stages {<name>: {kcm_mib, apiserver_mib, samples_mib: {kcm, apiserver}}}
# All sizes are Pss_Anon in MiB.

KCM_MEM_SCHEMA_VERSION=1

# Runs in the VM as root. Prints "<name> <pid> <Pss_Anon kB>" for each KCM / apiserver process.
# $KCM_MEM_PROC_ROOT prefixes /proc (tests).
kcm_sample_procs() {
  local d c n kb r="${KCM_MEM_PROC_ROOT:-}"
  for d in "$r"/proc/[0-9]*; do
    read -r c < "$d/comm" 2>/dev/null || continue
    case "$c" in
      kube-controller) n=kcm ;;
      u7s-apiserver) n=apiserver ;;
      *) continue ;;
    esac
    kb="$(awk '/^Pss_Anon:/ { print $2 }' "$d/smaps_rollup" 2>/dev/null)" || continue
    [ -n "$kb" ] || continue
    echo "$n ${d##*/} $kb"
  done
}

# stdin: kcm_sample_procs lines. stdout: "<kcm MiB> <apiserver MiB>", each summed over its pids.
# Fails when either process is missing: a stage without a process is not a measurement.
kcm_parse_sample() {
  awk '
    { kb[$1] += $3; seen[$1] = 1 }
    END {
      if (!seen["kcm"] || !seen["apiserver"]) exit 1
      printf "%.2f %.2f\n", kb["kcm"] / 1024, kb["apiserver"] / 1024
    }'
}

# stdin: numbers, one per line. stdout: the median (mean of the middle two when even).
kcm_median() {
  jq -s 'sort | if length == 0 then null elif length % 2 == 1 then .[length / 2 | floor] else (.[length / 2 - 1] + .[length / 2]) / 2 end'
}

# $1 vm, $2 samples, $3 interval secs. stdout: stage JSON {kcm_mib, apiserver_mib, samples_mib},
# the headline value being the median of the samples.
kcm_stage_sample() {
  local vm="$1" n="$2" interval="$3" i line kcm="" api="" k a
  for i in $(seq 1 "$n"); do
    line="$(limactl shell "$vm" sudo bash -c "$(declare -f kcm_sample_procs); kcm_sample_procs" | kcm_parse_sample)" \
      || { echo "kcm-mem: kube-controller or u7s-apiserver not found in $vm" >&2; return 1; }
    read -r k a <<<"$line"
    kcm="$kcm$k"$'\n'; api="$api$a"$'\n'
    [ "$i" = "$n" ] || sleep "$interval"
  done
  jq -n --argjson kcm "$(printf '%s' "$kcm" | jq -s -c .)" --argjson api "$(printf '%s' "$api" | jq -s -c .)" \
    --argjson km "$(printf '%s' "$kcm" | kcm_median)" --argjson am "$(printf '%s' "$api" | kcm_median)" \
    '{kcm_mib: $km, apiserver_mib: $am, samples_mib: {kcm: $kcm, apiserver: $api}}'
}

# $1 mode  $2 effective controllers flag  $3 restarts  $4 sha  $5 dirty 1|0  $6 date
# $7 vm JSON  $8 host JSON  $9 stages JSON (object)
kcm_mem_json() {
  jq -n --argjson v "$KCM_MEM_SCHEMA_VERSION" --arg mode "$1" --arg flag "$2" --argjson restarts "$3" \
    --arg sha "$4" --argjson dirty "$([ "$5" = 1 ] && echo true || echo false)" --arg date "$6" \
    --argjson vm "$7" --argjson host "$8" --argjson stages "$9" \
    '{schema_version: $v, kcm_mode: $mode, ported_controllers: [], kcm_controllers: $flag, kcm_restarts: $restarts,
      git_sha: $sha, git_dirty: $dirty, date: $date, vm: $vm, host: $host, stages: $stages}'
}

# $@ kcm-mem.json files (any mix of modes). stdout: per mode and stage the medians over runs, and
# the R-minus-T differences with the Phase 0 verdict (every stage's KCM difference >= $KCM_MEM_MIN_DIFF_MIB).
kcm_aggregate() {
  jq -s --argjson min "${KCM_MEM_MIN_DIFF_MIB:-5}" '
    def median: sort | if length == 0 then null elif length % 2 == 1 then .[length / 2 | floor] else (.[length / 2 - 1] + .[length / 2]) / 2 end;
    def med($all; $mode; $stage; $proc): [$all[] | select(.kcm_mode == $mode) | .stages[$stage][$proc]] | median;
    . as $all
    | ([.[].stages | keys[]] | unique) as $stages
    | {
        runs: (group_by(.kcm_mode) | map({key: .[0].kcm_mode, value: length}) | from_entries),
        stages: ($stages | map(. as $s | {key: $s, value: {
          R: {kcm_mib: med($all; "R"; $s; "kcm_mib"), apiserver_mib: med($all; "R"; $s; "apiserver_mib")},
          T: {kcm_mib: med($all; "T"; $s; "kcm_mib"), apiserver_mib: med($all; "T"; $s; "apiserver_mib")}}}) | from_entries)
      }
    | .stages |= with_entries(.value.kcm_diff_mib = ((.value.R.kcm_mib - .value.T.kcm_mib) * 100 | round / 100))
    | .min_diff_mib = $min
    | .phase0_pass = ([.stages[].kcm_diff_mib >= $min] | all)
  ' "$@"
}

# stdin: JSON lines {controller, kcm_mib}; controller "R" is the untrimmed baseline measured
# between the leave-one-out runs. stdout: {baseline_mib (median of the R rows), baseline_spread_mib
# (max - min of the R rows: the noise floor), rows: [{controller, kcm_mib, saved_mib}]} with
# saved_mib = baseline - kcm_mib, sorted by saved_mib descending. A row whose saved_mib is inside
# the spread is not distinguishable from noise.
kcm_loo_table() {
  jq -s '
    def median: sort | if length == 0 then null elif length % 2 == 1 then .[length / 2 | floor] else (.[length / 2 - 1] + .[length / 2]) / 2 end;
    def r2: . * 100 | round / 100;
    ([.[] | select(.controller == "R") | .kcm_mib]) as $r
    | ($r | median) as $b
    | {baseline_mib: ($b | r2), baseline_spread_mib: ((($r | max) - ($r | min)) | r2),
       rows: ([.[] | select(.controller != "R") | {controller, kcm_mib, saved_mib: (($b - .kcm_mib) | r2)}] | sort_by(-.saved_mib))}'
}

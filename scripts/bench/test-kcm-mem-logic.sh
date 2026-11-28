#!/usr/bin/env bash
# Logic tests for the KCM memory harness: the Pss_Anon sampler against a fake /proc, median and
# R/T aggregation, the kcm-mem.json shape, and the R/T mode transform of the installed unit.
# No VM needed.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=scripts/bench/kcm-mem-lib.sh
. "$REPO/scripts/bench/kcm-mem-lib.sh"
# shellcheck source=scripts/conformance/kcm-mode.sh
. "$REPO/scripts/conformance/kcm-mode.sh"
set +e

PASS=0; FAIL=0
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
check() { # label expected actual
  if [ "$2" = "$3" ]; then PASS=$((PASS + 1)); echo "PASS: $1"
  else FAIL=$((FAIL + 1)); echo "FAIL: $1"; echo "  expected: $2"; echo "  actual:   $3"; fi
}

# Fake /proc: kcm (pid 10), apiserver (pid 20), an unrelated process, and a pid whose
# smaps_rollup is unreadable. Pss and Pss_File must not leak into Pss_Anon.
mkproc() { # pid comm pss_anon_kb
  mkdir -p "$T/proc/$1"; echo "$2" > "$T/proc/$1/comm"
  printf 'Rss:               99999 kB\nPss:               88888 kB\nPss_Anon:          %s kB\nPss_File:          77777 kB\nPss_Shmem:             0 kB\n' "$3" > "$T/proc/$1/smaps_rollup"
}
mkproc 10 kube-controller 40960
mkproc 20 u7s-apiserver 30720
mkproc 30 kubelet 55555
mkdir -p "$T/proc/40"; echo kube-controller > "$T/proc/40/comm"

sample="$(KCM_MEM_PROC_ROOT="$T" kcm_sample_procs)"
check "sampler reads Pss_Anon, not Pss/Rss/Pss_File, so file-backed binary pages cannot mask the KCM saving" \
  $'kcm 10 40960\napiserver 20 30720' "$sample"
check "sampler skips processes outside the KCM/apiserver set and unreadable smaps_rollup" "2" "$(wc -l <<<"$sample" | tr -d ' ')"
check "kB are reported as MiB per process" "40.00 30.00" "$(kcm_parse_sample <<<"$sample")"
check "several pids of one component are summed" "3.00 2.00" "$(printf 'kcm 1 1024\nkcm 2 2048\napiserver 3 2048\n' | kcm_parse_sample)"
printf 'kcm 1 1024\n' | kcm_parse_sample >/dev/null 2>&1
check "a stage without the apiserver is an error, not a zero: a missing process must not read as a saving" "1" "$?"

check "median of an odd count" "7" "$(printf '9\n7\n3\n' | kcm_median)"
check "median of an even count is the mean of the middle two" "6" "$(printf '10\n2\n8\n4\n' | kcm_median)"

run() { # mode idle_kcm wp_kcm idle_api wp_api [burst_kcm, default wp_kcm]
  local st; st="$(jq -n -c --argjson ik "$2" --argjson wk "$3" --argjson ia "$4" --argjson wa "$5" --argjson bk "${6:-$3}" \
    '{idle: {kcm_mib: $ik, apiserver_mib: $ia}, wordpress: {kcm_mib: $wk, apiserver_mib: $wa}, burst: {kcm_mib: $bk, apiserver_mib: $wa}}')"
  kcm_mem_json "$1" "--controllers=x" 0 deadbeef 0 2026-11-25 '{"name":"vm"}' '{"os":"h"}' "$st"
}
mkdir -p "$T/pass" "$T/fail" "$T/passb" "$T/failb"
# R medians 40/42 (runs 40,44,38 / 42,45,41); T medians 33/35 (33,31,36 / 35,34,38). apiserver is not a gate input.
i=0; for v in "R 40 42" "R 44 45" "R 38 41" "T 33 35" "T 31 34" "T 36 41"; do
  set -- $v; i=$((i + 1)); run "$1" "$2" "$3" 28 30 > "$T/pass/$i.json"
done
agg="$(kcm_aggregate "$T"/pass/*.json)"
check "idle R median over 3 runs" "40" "$(jq '.stages.idle.R.kcm_mib' <<<"$agg")"
check "wordpress T median over 3 runs" "35" "$(jq '.stages.wordpress.T.kcm_mib' <<<"$agg")"
check "R-T is the difference of medians, not of means" "7" "$(jq '.stages.wordpress.kcm_diff_mib' <<<"$agg")"
check "Phase 0 passes when every stage differs by at least 5 MiB" "true" "$(jq '.phase0_pass' <<<"$agg")"
check "run counts are recorded per mode" '{"R":3,"T":3}' "$(jq -c '.runs' <<<"$agg")"

i=0; for v in "R 40 42" "R 44 45" "R 38 41" "T 33 41" "T 31 40" "T 36 41"; do
  set -- $v; i=$((i + 1)); run "$1" "$2" "$3" 28 30 > "$T/fail/$i.json"
done
agg="$(kcm_aggregate "$T"/fail/*.json)"
check "Phase 0 fails when one stage saves under 5 MiB even if the other passes" "false" "$(jq '.phase0_pass' <<<"$agg")"

i=0; for v in "R 40 42 46" "R 44 45 47" "R 38 41 45" "T 33 35 38" "T 31 34 36" "T 36 41 44"; do
  set -- $v; i=$((i + 1)); run "$1" "$2" "$3" 28 30 "$4" > "$T/passb/$i.json"
done
i=0; for v in "R 40 42 46" "R 44 45 47" "R 38 41 45" "T 33 35 44" "T 31 34 43" "T 36 41 45"; do
  set -- $v; i=$((i + 1)); run "$1" "$2" "$3" 28 30 "$4" > "$T/failb/$i.json"
done
agg="$(kcm_aggregate "$T"/passb/*.json)"
check "burst R and T medians are aggregated and gate-passing at 7 MiB" "46 38 true" \
  "$(jq -r '"\(.stages.burst.R.kcm_mib) \(.stages.burst.T.kcm_mib) \(.phase0_pass)"' <<<"$agg")"
agg="$(kcm_aggregate "$T"/failb/*.json)"
check "Phase 0 fails when only the burst stage saves under 5 MiB: the gate needs all three stages" "false" "$(jq '.phase0_pass' <<<"$agg")"
check "the failing burst diff is reported on the burst stage" "true" "$(jq '.stages.burst.kcm_diff_mib < 5 and .stages.idle.kcm_diff_mib >= 5' <<<"$agg")"

check "the gate has exactly idle, wordpress and burst stages" "idle wordpress burst" "$KCM_MEM_STAGES"
for s in $KCM_MEM_STAGES; do
  check "kcm-mem-run.sh writes the $s stage, otherwise the A/B silently passes without it" "1" \
    "$(grep -c -E "$s: \\\$[a-z]" "$REPO/scripts/bench/kcm-mem-run.sh")"
done
burst="$(kcm_burst_manifest)"
check "burst deploys the gate's 50 pause pods" "50 registry.k8s.io/pause:3.10" \
  "$(jq -r '"\(.spec.replicas) \(.spec.template.spec.containers[0].image)"' <<<"$burst")"
check "burst replica count is overridable" "5" "$(kcm_burst_manifest 5 | jq '.spec.replicas')"
check "burst pods are the Deployment's own, so the Deployment and ReplicaSet controllers are exercised" "true" \
  "$(jq '.kind == "Deployment" and (.spec.selector.matchLabels == .spec.template.metadata.labels)' <<<"$burst")"

j="$(cat "$T/pass/1.json")"
check "kcm-mem.json carries the schema version" "1" "$(jq '.schema_version' <<<"$j")"
check "run-meta fields are present: mode, ported list, sha, vm, host" \
  'true' "$(jq '(.kcm_mode == "R") and (.ported_controllers == []) and (.git_sha == "deadbeef") and has("vm") and has("host") and has("kcm_restarts")' <<<"$j")"

golden="$(cat "$REPO/scripts/testdata/install-golden-ipv4/u7s-kcm.allow0.ExecStart")"
check "R writes no drop-in, so the shipped unit is what runs" "" "$(printf '%s\n' "$golden" | kcm_mode_dropin R)"
t_body="$(printf '%s\n' "$golden" | kcm_mode_dropin T)"
check "T drop-in resets ExecStart before redefining it (systemd would otherwise reject two ExecStart)" \
  $'[Service]\nExecStart=' "$(sed -n '1,2p' <<<"$t_body")"
want="${golden/,-service-cidr-controller /,-service-cidr-controller,$KCM_TRIM_EXCLUDE }"
check "T keeps the shipped ExecStart and only appends exclusions to --controllers" "$want" "$(sed -n '3p' <<<"$t_body")"
check "T excludes HPA and TTL, the controllers the trim exists to drop" "2" \
  "$(grep -o -e '-horizontal-pod-autoscaler-controller' -e '-ttl-controller' <<<"$t_body" | wc -l | tr -d ' ')"
printf '%s\n' "$golden" | kcm_mode_dropin X >/dev/null 2>&1
check "an unknown mode is rejected" "2" "$?"

# Exit-time revert: a fake VM whose drop-in is a file under $T. The stubbed limactl maps the
# drop-in path into $T and ignores everything else (systemctl).
FAKE_VM="$T/vm"; mkdir -p "$FAKE_VM"
kcm_revert_probe() { # signal|exit
  rm -rf "$FAKE_VM"; mkdir -p "$FAKE_VM"
  (
    limactl() { shift 2; [ "$1" = sudo ] && shift; [ "$1" = rm ] && rm -f "$FAKE_VM/dropin"; return 0; }
    KCM_DROPIN=/x
    kcm_mode_revert_on_exit fakevm
    : > "$FAKE_VM/dropin"
    [ "$1" = signal ] && kill -TERM $BASHPID
    exit 0
  ) 2>/dev/null
  [ -e "$FAKE_VM/dropin" ] && echo present || echo absent
}
check "an A/B run that ends normally leaves no KCM drop-in (mode R), so the next install.sh boots the shipped KCM" \
  absent "$(kcm_revert_probe exit)"
check "an A/B run killed by TERM leaves no KCM drop-in (mode R), so an interrupted run cannot leak the trim" \
  absent "$(kcm_revert_probe signal)"
kcm_hang_probe() {
  local start=$SECONDS
  (
    limactl() { sleep 60; }
    KCM_REVERT_TIMEOUT_S=2
    kcm_mode_revert_on_exit deadvm
    exit 0
  ) 2>"$T/hang.err"
  echo "$((SECONDS - start))"
}
hang_s="$(kcm_hang_probe)"
[ "$hang_s" -lt 20 ]
check "a dead VM (limactl hangs) cannot hang the exit-trap revert past KCM_REVERT_TIMEOUT_S, so a driver never wedges at exit (took ${hang_s}s)" "0" "$?"
grep -q "revert to R timed out" "$T/hang.err"
check "an expired revert warns, so the operator knows teardown must clear the drop-in" "0" "$?"
grep -q '^kcm_mode_revert_on_exit "\$VM"$' "$REPO/scripts/bench/kcm-mem-ab.sh"
check "kcm-mem-ab.sh installs the revert before its first run" "0" "$?"

# Leave-one-out table: savings are measured against the median of the interleaved baselines, and
# the baseline spread is reported so a "saving" inside the noise is not read as one.
loo="$(printf '%s\n' '{"controller":"R","kcm_mib":40.0}' '{"controller":"a","kcm_mib":37.0}' \
  '{"controller":"R","kcm_mib":42.0}' '{"controller":"b","kcm_mib":41.5}' '{"controller":"R","kcm_mib":41.0}' | kcm_loo_table)"
check "baseline is the median of the R rows" "41" "$(jq -r .baseline_mib <<<"$loo")"
check "the R rows' spread is the noise floor" "2" "$(jq -r .baseline_spread_mib <<<"$loo")"
check "rows are ordered by saving and R rows are not listed" "a b" "$(jq -r '[.rows[].controller] | join(" ")' <<<"$loo")"
check "saving is baseline minus the run (a negative one is kept, not clamped)" "4 -0.5" "$(jq -r '[.rows[].saved_mib | tostring] | join(" ")' <<<"$loo")"
check "KCM_TRIM_EXCLUDE from the environment replaces the default trim, so the sweep excludes exactly one controller" \
  "ExecStart=x --controllers=*,-only-this y" "$(KCM_TRIM_EXCLUDE=-only-this bash -c '. "$1"; echo "ExecStart=x --controllers=* y" | kcm_trim_execstart' _ "$REPO/scripts/conformance/kcm-mode.sh")"

echo "kcm-mem logic:$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

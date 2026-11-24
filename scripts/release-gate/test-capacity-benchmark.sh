#!/usr/bin/env bash
# Logic test for the capacity benchmark artefact (scripts/release-gate/capacity-lib.sh) from a
# canned burst-gate ramp run. A benchmark that a release cites must carry the date and git SHA
# it was measured at and say which provider produced it; an unstamped or unlabelled number
# cannot be traced back to a build, and a Lima number must never pass as the authoritative one.
# No VM needed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
# shellcheck source=capacity-lib.sh
. "$HERE/capacity-lib.sh"

PASS=0; FAIL=0
assert() {
  if [ "$2" = 1 ]; then echo "PASS: $1"; PASS=$((PASS + 1)); else echo "FAIL: $1"; FAIL=$((FAIL + 1)); fi
}
yes_if() { if "$@" >/dev/null 2>&1; then echo 1; else echo 0; fi; }
no_if() { if "$@" >/dev/null 2>&1; then echo 0; else echo 1; fi; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
RUN="$TMP/run-1"; mkdir -p "$RUN/out"
SHA=0123456789abcdef0123456789abcdef01234567

cat > "$RUN/out/results.env" <<'EOF'
install_ok=1
ramp_20_secs=41
ramp_20_oom_host=0
ramp_20_oom_kubesystem=0
ramp_20_notready=0
ramp_20_ready_final=True
ramp_20_wp_ok=1
ramp_20_marker_ok=1
ramp_30_secs=timeout
ramp_30_oom_host=1
ramp_30_oom_kubesystem=0
ramp_30_notready=2
ramp_30_ready_final=False
ramp_30_wp_ok=0
ramp_30_marker_ok=1
EOF
cat > "$RUN/out/vm-shape.env" <<'EOF'
kernel=7.0.0-test
arch=aarch64
vcpus=1
os=Ubuntu 26.04
mem_total_kb=970000
swap_total_kb=0
EOF
printf '1\tidle\tMEM\t512000\n2\tburst20\tMEM\t210000\n3\tburst30\tMEM\t90000\n4\tinstall\tMEM\t5000\n' > "$RUN/out/samples.tsv"
printf '1\tidle\tu7s-apiserver\t40960\t51200\t30000\t10000\n1\tidle\tkubelet\t20480\t30720\t15000\t5000\n1\tidle\tmariadbd\t0\t0\t0\t0\n' >> "$RUN/out/samples.tsv"
PAST='["past-envelope note"]'

json() { cap_build_json "$RUN" "20 30 40" v0.4.7-1-gabc "$SHA" 0 2026-11-25 lima "" 1 "$PAST"; }
json > "$TMP/b.json"

assert "stamp: a complete artefact validates" "$(yes_if cap_validate_json "$TMP/b.json")"
assert "stamp: git SHA and date are recorded verbatim" "$(yes_if jq -e --arg s "$SHA" '.git_sha == $s and .date == "2026-11-25"' "$TMP/b.json")"
for field in git_sha date u7s_version provider_label; do
  jq "del(.$field)" "$TMP/b.json" > "$TMP/bad.json"
  assert "stamp: validation fails when $field is missing (an unstamped benchmark cannot be cited)" "$(no_if cap_validate_json "$TMP/bad.json")"
done
jq '.git_sha = "not-a-sha"' "$TMP/b.json" > "$TMP/bad.json"
assert "stamp: a non-hex SHA is rejected" "$(no_if cap_validate_json "$TMP/bad.json")"
jq '.date = "yesterday"' "$TMP/b.json" > "$TMP/bad.json"
assert "stamp: a non-ISO date is rejected" "$(no_if cap_validate_json "$TMP/bad.json")"

assert "provider: lima is labelled non-authoritative so it is never mistaken for the release shape" \
  "$(yes_if jq -e '.provider_label == "provider=lima (non-authoritative)" and .authoritative == false' "$TMP/b.json")"
cap_build_json "$RUN" "20 30" v0.4.7 "$SHA" 0 2026-11-25 gcp "n1-custom-1-1024 pd-balanced, authoritative" 1 "$PAST" > "$TMP/g.json"
assert "provider: a quiet gcp run is authoritative" "$(yes_if jq -e '.authoritative == true' "$TMP/g.json")"
echo "host idle 40% < 70%" > "$RUN/contention.txt"
cap_build_json "$RUN" "20 30" v0.4.7 "$SHA" 0 2026-11-25 gcp "n1-custom-1-1024 pd-balanced, authoritative" 1 "$PAST" > "$TMP/g.json"
assert "provider: contention downgrades even a gcp run (a noisy number must not read as authoritative)" "$(yes_if jq -e '.authoritative == false and .contention != null' "$TMP/g.json")"
rm -f "$RUN/contention.txt"

assert "bursts: the 20-pod gate burst time is recorded" "$(yes_if jq -e '.gate_burst_20.ready_secs == 41 and .gate_burst_20.passed == true' "$TMP/b.json")"
assert "bursts: a failed size is recorded as failed, with the timeout kept" "$(yes_if jq -e '(.bursts[] | select(.pods == 30)) | .passed == false and .ready_secs == "timeout"' "$TMP/b.json")"
assert "bursts: an unrun size is not reported as passed" "$(yes_if jq -e '(.bursts[] | select(.pods == 40)) | .passed == null and .ready_secs == null' "$TMP/b.json")"
assert "capacity: max passing burst is the largest size before the first failure" "$(yes_if jq -e '.max_passing_burst_pods == 20' "$TMP/b.json")"
assert "idle: per-component PSS/RSS in MiB, zero-RSS components dropped" "$(yes_if jq -e '(.idle_components | length) == 2 and (.idle_components[] | select(.component == "u7s-apiserver") | .pss_mib == 40 and .rss_mib == 50)' "$TMP/b.json")"
assert "headroom: idle MemAvailable and the min over the run, install excluded" "$(yes_if jq -e '.headroom.mem_available_idle_mib == 500 and .headroom.mem_available_min_run_mib == 88' "$TMP/b.json")"
assert "shape: vCPU, RAM, swap, kernel come from the guest" "$(yes_if jq -e '.shape.vcpus == 1 and .shape.mem_total_mib == 947 and .shape.swap_mib == 0 and .shape.kernel == "7.0.0-test"' "$TMP/b.json")"

cap_render_md "$TMP/b.json" > "$TMP/b.md"
assert "markdown: carries the SHA, date and provider label" \
  "$(yes_if grep -q "$SHA" "$TMP/b.md" && grep -q 2026-11-25 "$TMP/b.md" && grep -q 'provider=lima (non-authoritative)' "$TMP/b.md")"
assert "markdown: lists the failed burst as NO" "$(yes_if grep -q '^| 30 | timeout | NO' "$TMP/b.md")"
assert "markdown: includes the past-envelope notes" "$(yes_if grep -q 'past-envelope note' "$TMP/b.md")"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]

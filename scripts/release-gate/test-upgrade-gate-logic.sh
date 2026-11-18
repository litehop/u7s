#!/usr/bin/env bash
# Logic test for the upgrade gate's decisions (scripts/release-gate/upgrade-lib.sh) from canned
# inputs. The gate decides whether users can upgrade in place, so the failure modes that matter
# are a false PASS (a lost CA, recreated pods, a long outage, or the old binary still serving
# looks green) and a run that died halfway being read as a PASS. No VM needed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
# shellcheck source=upgrade-lib.sh
. "$HERE/upgrade-lib.sh"

PASS=0; FAIL=0
assert() {
  local label="$1" ok="$2"
  if [ "$ok" = 1 ]; then echo "PASS: $label"; PASS=$((PASS + 1)); else echo "FAIL: $label"; FAIL=$((FAIL + 1)); fi
}
yes_if() { if "$@"; then echo 1; else echo 0; fi; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---- previous-release selection ----
git -C "$TMP" init -q repo
R="$TMP/repo"
git -C "$R" -c user.name=t -c user.email=t@t commit -q --allow-empty -m a
git -C "$R" tag v0.4.5
git -C "$R" -c user.name=t -c user.email=t@t commit -q --allow-empty -m b
git -C "$R" tag v0.4.6
git -C "$R" -c user.name=t -c user.email=t@t commit -q --allow-empty -m c
git -C "$R" tag v0.4.7-snapshot.1
got="$(cd "$R" && ug_default_from)"
assert "default previous release skips a newer snapshot tag (upgrading from a prerelease is not the supported path)" "$(yes_if [ "$got" = v0.4.6 ])"
empty="$TMP/empty"; git -C "$TMP" init -q empty
git -C "$empty" -c user.name=t -c user.email=t@t commit -q --allow-empty -m a
git -C "$empty" tag v0.1.0-snapshot.1
assert "no release tag reachable fails instead of guessing a previous release" "$(yes_if bash -c "cd '$empty' && . '$HERE/upgrade-lib.sh' && ! ug_default_from >/dev/null")"
assert "tag validation accepts releases and snapshots" "$(yes_if bash -c ". '$HERE/upgrade-lib.sh'; ug_tag_valid v0.4.6 && ug_tag_valid v0.4.7-snapshot.2")"
assert "tag validation rejects a path-like value that would reach a mirror URL" "$(yes_if bash -c ". '$HERE/upgrade-lib.sh'; ! ug_tag_valid 'v0.4.6/../x' && ! ug_tag_valid latest")"

# ---- version ----
assert "same version before and after is a problem: the old binary may still be serving" \
  "$(yes_if [ -n "$(ug_version_problem v1.37.1+u7s-0.4.6 v1.37.1+u7s-0.4.6 0.4.6)" ])"
assert "a changed version that is not the candidate is a problem (wrong tarball installed)" \
  "$(yes_if [ -n "$(ug_version_problem v1.37.1+u7s-0.4.5 v1.37.1+u7s-0.4.6 0.4.7-snapshot.1)" ])"
assert "the candidate's stamped version passes" \
  "$(yes_if [ -z "$(ug_version_problem v1.37.1+u7s-0.4.5 v1.37.1+u7s-0.4.7-snapshot.1 0.4.7-snapshot.1)" ])"
assert "an unreadable server version is a problem, not a silent pass" \
  "$(yes_if [ -n "$(ug_version_problem v1.37.1+u7s-0.4.5 '' 0.4.7)" ])"
assert "release 0.4.7 does not match a 0.4.7-snapshot.1 server (suffix match is exact)" \
  "$(yes_if [ -n "$(ug_version_problem v1.37.1+u7s-0.4.5 v1.37.1+u7s-0.4.7-snapshot.1 0.4.7)" ])"

# ---- downtime ----
healthy="$TMP/healthy.log"
for t in 100 102 104 106 108 110; do echo "$t.5 200"; done > "$healthy"
assert "a healthy 2 s poll reports a 2 s gap and no failures" \
  "$(yes_if [ "$(ug_downtime_summary "$healthy" 100 111)" = "max_gap=2 failed=0 samples=6" ])"
blip="$TMP/blip.log"
{ echo "100 200"; echo "102 200"; echo "104 FAIL"; echo "106 FAIL"; echo "108 200"; echo "110 200"; } > "$blip"
s="$(ug_downtime_summary "$blip" 100 110)"
assert "failed samples widen the gap to the next 200 (outage upper bound, 102 -> 108)" "$(yes_if [ "$s" = "max_gap=6 failed=2 samples=6" ])"
assert "a few seconds of outage is within bound (reported, not failed)" "$(yes_if ug_downtime_ok "$s")"
long="$TMP/long.log"
{ echo "100 200"; echo "103 FAIL"; echo "170 200"; } > "$long"
s="$(ug_downtime_summary "$long" 100 170)"
assert "a 70 s outage fails the bound (users would see a long control-plane outage)" "$(yes_if bash -c ". '$HERE/upgrade-lib.sh'; ! ug_downtime_ok '$s'")"
never="$TMP/never.log"
{ echo "100 FAIL"; echo "102 FAIL"; } > "$never"
s="$(ug_downtime_summary "$never" 100 400)"
assert "an API that never answered inside the window counts the whole window as down" "$(yes_if bash -c ". '$HERE/upgrade-lib.sh'; [ '$s' = 'max_gap=300 failed=2 samples=2' ] && ! ug_downtime_ok '$s'")"
before="$TMP/before.log"
{ echo "50 FAIL"; echo "100 200"; echo "102 200"; } > "$before"
assert "samples outside the window (an earlier blip) are not charged to this phase" \
  "$(yes_if [ "$(ug_downtime_summary "$before" 100 102)" = "max_gap=2 failed=0 samples=2" ])"

# ---- pod continuity ----
pre="$TMP/pre.txt"
printf 'default/dep-a aaa 0,\ndefault/dep-b bbb 0,\ndefault/ds-x ccc 0,0,\n' > "$pre"
same="$TMP/same.txt"; cp "$pre" "$same"
assert "identical pods are continuity" "$(yes_if [ -z "$(ug_continuity_problems "$pre" "$same")" ])"
printf 'default/dep-a aaa 0,\ndefault/dep-b zzz 0,\ndefault/ds-x ccc 0,0,\n' > "$TMP/recreated.txt"
out="$(ug_continuity_problems "$pre" "$TMP/recreated.txt")"
assert "a recreated pod (new UID) is named: the upgrade disrupted a user workload" "$(yes_if [ "$out" = "default/dep-b: recreated (uid bbb -> zzz)" ])"
printf 'default/dep-a aaa 0,\ndefault/dep-b bbb 1,\ndefault/ds-x ccc 0,0,\n' > "$TMP/restarted.txt"
out="$(ug_continuity_problems "$pre" "$TMP/restarted.txt")"
assert "a container restart under the same UID is caught (restart is disruption even without recreation)" "$(yes_if [ "$out" = "default/dep-b: restarted (0 -> 1)" ])"
printf 'default/dep-a aaa 0,\ndefault/ds-x ccc 0,0,\n' > "$TMP/gone.txt"
out="$(ug_continuity_problems "$pre" "$TMP/gone.txt")"
assert "a pod that vanished is a problem" "$(yes_if [ "$out" = "default/dep-b: gone" ])"
{ cat "$pre"; echo 'default/extra eee 0,'; } > "$TMP/extra.txt"
assert "an additional pod does not fail continuity" "$(yes_if [ -z "$(ug_continuity_problems "$pre" "$TMP/extra.txt")" ])"

# ---- verdict ----
good="$TMP/good.env"
{
  for k in cand_install version ca sa_pub marker workload downtime rerun_install rerun_quiet; do echo "$k=1"; done
  echo "done=1"
} > "$good"
assert "all checks passing is PASS (exit 0)" "$(yes_if ug_run_status "$good")"
bad="$TMP/bad.env"; sed 's/^ca=1/ca=0/' "$good" > "$bad"
rc=0; ug_run_status "$bad" || rc=$?
assert "a lost CA fails the run (exit 1): every node identity would be invalid" "$(yes_if [ "$rc" = 1 ])"
assert "the verdict table names the failed check" "$(yes_if grep -q '^FAIL  CA' <(ug_verdict "$bad"))"
short="$TMP/short.env"; grep -v '^downtime=' "$good" > "$short"
rc=0; ug_run_status "$short" || rc=$?
assert "a check that never ran is a FAIL, not a silent pass" "$(yes_if [ "$rc" = 1 ])"
nodone="$TMP/nodone.env"; grep -v '^done=' "$good" > "$nodone"
rc=0; ug_run_status "$nodone" || rc=$?
assert "a guest driver that died before the end is INVALID (exit 3), not a verdict" "$(yes_if [ "$rc" = 3 ])"
he="$TMP/he.env"; { cat "$good"; echo "harness_error=previous release install.sh failed"; } > "$he"
rc=0; ug_run_status "$he" || rc=$?
assert "a failed previous-release install is INVALID (exit 3): the candidate was never tested" "$(yes_if [ "$rc" = 3 ])"
dtbad="$TMP/dt.env"; sed 's/^downtime=1/downtime=0/' "$good" > "$dtbad"
rc=0; ug_run_status "$dtbad" || rc=$?
assert "an out-of-bound outage fails the run" "$(yes_if [ "$rc" = 1 ])"

echo "---- $PASS passed, $FAIL failed ----"
[ "$FAIL" = 0 ]

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
git -C "$R" tag -d v0.4.7-snapshot.1 >/dev/null
git -C "$R" checkout -q v0.4.6
got="$(cd "$R" && ug_default_from)"
assert "HEAD exactly on a release tag picks the previous release, not itself (upgrading a release to itself tests nothing)" "$(yes_if [ "$got" = v0.4.5 ])"
git -C "$R" -c user.name=t -c user.email=t@t commit -q --allow-empty -m d
got="$(cd "$R" && ug_default_from)"
assert "HEAD past a release tag picks that release" "$(yes_if [ "$got" = v0.4.6 ])"
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

trail="$TMP/trail.log"
{ echo "100 200"; echo "102 200"; echo "104 FAIL"; echo "170 FAIL"; } > "$trail"
s="$(ug_downtime_summary "$trail" 100 170)"
assert "an API that answers then stays down to the window end fails the bound (trailing outage)" \
  "$(yes_if bash -c ". '$HERE/upgrade-lib.sh'; [ '$s' = 'max_gap=68 failed=2 samples=4' ] && ! ug_downtime_ok '$s'")"
lead="$TMP/lead.log"
{ echo "100 FAIL"; echo "165 200"; echo "167 200"; echo "169 200"; } > "$lead"
s="$(ug_downtime_summary "$lead" 100 170)"
assert "an API that is down from the window start until late fails the bound (leading outage)" \
  "$(yes_if bash -c ". '$HERE/upgrade-lib.sh'; [ '$s' = 'max_gap=65 failed=1 samples=4' ] && ! ug_downtime_ok '$s'")"

# ---- state files preserved ----
printf 'aaa  ca.key\nbbb  ca.crt\n' > "$TMP/h-pre.txt"
cp "$TMP/h-pre.txt" "$TMP/h-same.txt"
assert "an unchanged hash is preserved" "$(yes_if ug_hash_preserved "$TMP/h-pre.txt" "$TMP/h-same.txt" ca.key)"
printf 'zzz  ca.key\nbbb  ca.crt\n' > "$TMP/h-changed.txt"
assert "a changed hash is not preserved (regenerated CA)" "$(yes_if bash -c ". '$HERE/upgrade-lib.sh'; ! ug_hash_preserved '$TMP/h-pre.txt' '$TMP/h-changed.txt' ca.key")"
assert "a file missing before and after is not preserved (empty == empty must not pass)" "$(yes_if bash -c ". '$HERE/upgrade-lib.sh'; ! ug_hash_preserved '$TMP/h-pre.txt' '$TMP/h-same.txt' sa.pub")"
printf 'bbb  ca.crt\n' > "$TMP/h-lost.txt"
assert "a file deleted by the upgrade is not preserved" "$(yes_if bash -c ". '$HERE/upgrade-lib.sh'; ! ug_hash_preserved '$TMP/h-pre.txt' '$TMP/h-lost.txt' ca.key")"

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
  for k in cand_install node_ready version ca sa_pub marker workload downtime rerun_install rerun_quiet; do echo "$k=1"; done
  echo "done=1"
} > "$good"
assert "all checks passing is PASS (exit 0)" "$(yes_if ug_run_status "$good")"
bad="$TMP/bad.env"; sed 's/^ca=1/ca=0/' "$good" > "$bad"
rc=0; ug_run_status "$bad" || rc=$?
assert "a lost CA fails the run (exit 1): every node identity would be invalid" "$(yes_if [ "$rc" = 1 ])"
assert "the verdict table names the failed check" "$(yes_if grep -q '^FAIL  CA' <<<"$(ug_verdict "$bad")")"
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

nrbad="$TMP/nr.env"; sed 's/^node_ready=1/node_ready=0/' "$good" > "$nrbad"
rc=0; ug_run_status "$nrbad" || rc=$?
assert "a node that never returns Ready fails the run" "$(yes_if [ "$rc" = 1 ])"
assert "the verdict table names the node check" "$(yes_if grep -q '^FAIL  node Ready' <<<"$(ug_verdict "$nrbad")")"

# ---- a signal during VM start must delete the VM ----
# vm_create is the longest step (limactl start, IAP ssh retries); a foreground one defers the
# TERM/INT trap until it returns, so a cancelled run kept a VM billing for up to 16 h.
# Runs "$@" in the background, waits (bounded) for $marker, sends SIG, waits (bounded) for exit.
# Sets hs_ready (marker appeared), hs_ended (exited by itself within the bound), hs_rc.
hold_and_signal() { # sig marker cmd...
  local sig="$1" marker="$2" p i; shift 2
  set -m; "$@" >/dev/null 2>&1 & p=$!; set +m
  hs_ready=0; hs_ended=0; hs_rc=0
  for i in $(seq 1 80); do [ ! -e "$marker" ] || { hs_ready=1; break; }; kill -0 "$p" 2>/dev/null || break; sleep 0.25; done
  kill "-$sig" "$p" 2>/dev/null || true
  for i in $(seq 1 120); do kill -0 "$p" 2>/dev/null || { hs_ended=1; break; }; sleep 0.25; done
  if [ "$hs_ended" = 1 ]; then wait "$p" || hs_rc=$?; else pkill -KILL -P "$p" 2>/dev/null || true; kill -KILL "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; fi
}
pid_alive() { local p; p="$(cat "$1" 2>/dev/null || true)"; [ -n "$p" ] && kill -0 "$p" 2>/dev/null; }
reap_hang() { local p; p="$(cat "$1" 2>/dev/null || true)"; [ -z "$p" ] || kill "$p" 2>/dev/null || true; }

export GCLOUD_CALLS="$TMP/gcloud-calls" LIMA_CALLS="$TMP/lima-calls" GCP_SSH_TRIES=1 GCP_SSH_SLEEP=0 GCP_OPS_SLEEP=0 GCP_DELETE_SLEEP=0
export GCLOUD_HANG_PID="$TMP/gcloud-hang.pid" LIMA_HANG_PID="$TMP/lima-hang.pid"
mkdir -p "$TMP/bin-hold" "$TMP/prev" "$TMP/cand"
printf '%s\n' '#!/bin/sh' 'echo "$*" >> "$GCLOUD_CALLS"' 'case "$*" in' \
  '  "config configurations describe"*) exit 0 ;;' \
  '  "config get-value project") echo p-secret ;;' \
  '  "config get-value compute/zone") echo z-1 ;;' \
  '  "compute instances create"*) echo created ;;' \
  '  "compute ssh"*) echo $$ > "$GCLOUD_HANG_PID"; exec sleep 300 ;;' \
  'esac' 'exit 0' > "$TMP/bin-hold/gcloud"
printf '%s\n' '#!/bin/sh' 'echo "$*" >> "$LIMA_CALLS"' \
  'case "$1" in list) exit 0 ;; start) echo $$ > "$LIMA_HANG_PID"; exec sleep 300 ;; esac' 'exit 0' > "$TMP/bin-hold/limactl"
chmod +x "$TMP/bin-hold/gcloud" "$TMP/bin-hold/limactl"
for d in prev cand; do : > "$TMP/$d/u7s-gate-x.tar.gz"; : > "$TMP/$d/u7s-gate-x.tar.gz.sha256"; : > "$TMP/$d/install.sh"; done

for sigspec in TERM:143 INT:130; do
  sig="${sigspec%%:*}"; want="${sigspec##*:}"
  rm -f "$GCLOUD_HANG_PID"; : > "$GCLOUD_CALLS"; rm -rf "$TMP/out-gsig"
  hold_and_signal "$sig" "$GCLOUD_HANG_PID" env PATH="$TMP/bin-hold:$PATH" \
    "$HERE/upgrade-gate.sh" --backend gcp --from v0.0.1 --release v0.0.2-snapshot.1 --out "$TMP/out-gsig"
  vmname="$(grep 'instances create' "$GCLOUD_CALLS" | head -1 | sed -E 's/.*instances create (u7s-upg-[^ ]*) .*/\1/')"
  alive=0; ! pid_alive "$GCLOUD_HANG_PID" || alive=1; reap_hang "$GCLOUD_HANG_PID"
  assert "gcp $sig during VM start reached the start phase (the signal must land after create, or the test proves nothing)" \
    "$(yes_if [ "$hs_ready" = 1 ] && [ -n "$vmname" ])"
  assert "gcp $sig during VM start exits $want within the bound (a deferred trap leaves the VM billing until start returns)" \
    "$(yes_if [ "$hs_ended" = 1 ] && [ "$hs_rc" = "$want" ])"
  assert "gcp $sig during VM start deletes the VM exactly once (a gate VM left up after Ctrl-C keeps billing for up to 16 h)" \
    "$(yes_if [ -n "$vmname" ] && [ "$(grep -c "instances delete $vmname " "$GCLOUD_CALLS")" = 1 ])"
  assert "gcp $sig during VM start leaves no orphaned ssh client (it would hold the IAP session open)" \
    "$(yes_if [ "$alive" = 0 ])"

  rm -f "$LIMA_HANG_PID"; : > "$LIMA_CALLS"; rm -rf "$TMP/out-lsig"
  hold_and_signal "$sig" "$LIMA_HANG_PID" env PATH="$TMP/bin-hold:$PATH" \
    "$HERE/upgrade-gate.sh" --from v0.0.1 --prev-dir "$TMP/prev" --cand-dir "$TMP/cand" --out "$TMP/out-lsig"
  vmname="$(grep '^create ' "$LIMA_CALLS" | head -1 | sed -E 's/.*--name ([^ ]+) .*/\1/')"
  alive=0; ! pid_alive "$LIMA_HANG_PID" || alive=1; reap_hang "$LIMA_HANG_PID"
  assert "lima $sig during VM start reached the start phase (the signal must land after create)" \
    "$(yes_if [ "$hs_ready" = 1 ] && [ -n "$vmname" ])"
  assert "lima $sig during VM start exits $want within the bound" \
    "$(yes_if [ "$hs_ended" = 1 ] && [ "$hs_rc" = "$want" ])"
  assert "lima $sig during VM start deletes the VM exactly once (a stranded Lima VM holds the host's RAM and disk until someone notices)" \
    "$(yes_if [ -n "$vmname" ] && [ "$(grep -c "^delete -f $vmname\$" "$LIMA_CALLS")" = 1 ])"
  assert "lima $sig during VM start leaves no orphaned limactl child" \
    "$(yes_if [ "$alive" = 0 ])"
done

echo "---- $PASS passed, $FAIL failed ----"
[ "$FAIL" = 0 ]

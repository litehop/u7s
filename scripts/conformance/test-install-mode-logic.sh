#!/usr/bin/env bash
# Regression test for run-all.sh --install mode's argument handling, run-archive topology
# stamping and tunnel teardown. Runs the real scripts; no VM needed.
#
# Why it matters: a host-rig PASS is not a delivered-behaviour PASS. If an archive can lack
# or mislabel its topology, a release sign-off can silently rest on the wrong rig; if
# --install quietly ignores a host-rig option (--profile, --binary, ...), the operator thinks
# they measured something they did not; if reset kills a recycled PID, it hits an unrelated
# process.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PASS=0
FAIL=0
LEFTOVER_PIDS=()
TMP="$REPO/temp/test-install-mode-$$"
mkdir -p "$TMP"
cleanup() {
  local p
  for p in "${LEFTOVER_PIDS[@]:-}"; do
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

# shellcheck source=scripts/conformance/_lib.sh
source "$REPO/scripts/conformance/_lib.sh"

ok() { echo "PASS: $1"; PASS=$(( PASS + 1 )); }
bad() { echo "FAIL: $1"; FAIL=$(( FAIL + 1 )); }
assert_eq() {
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 — got '$2', expected '$3'"; fi
}

# 1. Stamping: both topologies, and a typo must not produce an unlabelled archive.
write_run_meta "$TMP/rig" host-rig
assert_eq "host-rig archive is stamped topology=host-rig so it is never read as a sign-off run" \
  "$(cat "$TMP/rig/run-meta")" "topology=host-rig"
write_run_meta "$TMP/inst" install
assert_eq "install archive is stamped topology=install" "$(sed -n 1p "$TMP/inst/run-meta")" "topology=install"
assert_eq "install archive lists the rig-only add-ons that are not shipped by install.sh" \
  "$(sed -n 2p "$TMP/inst/run-meta")" "rig_only_addons=$INSTALL_RIG_ONLY_ADDONS"
if write_run_meta "$TMP/bogus" hostrig 2>/dev/null; then bad "unknown topology must be refused"; else ok "unknown topology is refused instead of writing a mislabelled archive"; fi
[ ! -e "$TMP/bogus/run-meta" ] && ok "refused topology leaves no run-meta behind" || bad "refused topology wrote run-meta"

# 06 must stamp every pass's archive, defaulting to host-rig; install-run must select install.
grep -q 'TOPOLOGY="${U7S_TOPOLOGY:-host-rig}"' "$REPO/scripts/conformance/06-run-sonobuoy.sh" \
  && ok "06-run-sonobuoy.sh defaults the topology to host-rig" || bad "06-run-sonobuoy.sh no longer defaults to host-rig"
grep -q 'write_run_meta "\$RUN_DIR" "\$TOPOLOGY"' "$REPO/scripts/conformance/06-run-sonobuoy.sh" \
  && ok "06-run-sonobuoy.sh stamps each run archive" || bad "06-run-sonobuoy.sh does not stamp run archives"
grep -q 'export U7S_TOPOLOGY=install' "$REPO/scripts/conformance/install-run.sh" \
  && ok "install-run.sh marks its archives topology=install" || bad "install-run.sh does not export U7S_TOPOLOGY=install"

# 2. Host-rig-only options are listed, empty ones are not.
assert_eq "no host-rig options given -> nothing flagged" "$(install_mode_incompatible_flags --binary= --profile=)" ""
assert_eq "given host-rig options are named" \
  "$(install_mode_incompatible_flags --binary=/x --profile= --extra-node=vm2 | paste -sd' ' -)" "--binary --extra-node"

# 3. The real run-all.sh refuses them under --install, before touching a VM or building.
for flag in "--binary /x" "--profile" "--extra-node vm2 --extra-kubelet-port 1" "--dual-stack" "--embedded-scheduler true" "--pki-test-lifetime 30"; do
  # shellcheck disable=SC2086
  rejection=$(bash "$REPO/scripts/conformance/run-all.sh" --install $flag 2>&1) && rc=0 || rc=$?
  if [ "$rc" -ne 0 ] && [[ "$rejection" == *"not supported with it"* || "$rejection" == *"mutually exclusive"* || "$rejection" == *"requires"* ]]; then
    ok "--install $flag is rejected loudly (rc=$rc)"
  else
    bad "--install $flag was not rejected (rc=$rc): $rejection"
  fi
done

# 4. Teardown: reset.sh --host-only reaps this workdir's tunnel, and only if the pid is an ssh -L.
WD="$TMP/u7s"
mkdir -p "$WD"
bash -c "exec -a 'ssh -F cfg -N -L 127.0.0.1:6444:10.0.0.5:6443 lima-x' sleep 60" >/dev/null 2>&1 &
TUNNEL_PID=$!
LEFTOVER_PIDS+=("$TUNNEL_PID")
sleep 0.3
echo "$TUNNEL_PID" > "$WD/install-tunnel.pid"
bash "$REPO/scripts/conformance/reset.sh" --host-only --workdir "$WD" >/dev/null 2>&1 && rc=0 || rc=$?
assert_eq "reset.sh --host-only succeeds in an install-mode workdir (no host apiserver exists)" "$rc" "0"
sleep 0.3
kill -0 "$TUNNEL_PID" 2>/dev/null && bad "tunnel survived reset.sh --host-only" || ok "reset.sh --host-only kills the install-mode tunnel"
[ ! -e "$WD/install-tunnel.pid" ] && ok "tunnel pidfile is removed" || bad "tunnel pidfile left behind"

sleep 60 &
INNOCENT_PID=$!
LEFTOVER_PIDS+=("$INNOCENT_PID")
echo "$INNOCENT_PID" > "$WD/install-tunnel.pid"
bash "$REPO/scripts/conformance/reset.sh" --host-only --workdir "$WD" >/dev/null 2>&1 || true
kill -0 "$INNOCENT_PID" 2>/dev/null && ok "a stale pidfile pointing at an unrelated process does not kill it" \
  || bad "reset.sh killed an unrelated process via a stale tunnel pidfile"

# 5. Keep-VM teardown must cover every unit install.sh enables, or the leftover units
# (u7s-kcm-restart.path was the one that survived) break the next host-rig bring-up.
for unit in $(grep -o 'systemctl enable u7s-[a-z-]*\.[a-z]*' "$REPO/scripts/install.sh" | awk '{print $3}'); do
  grep -q "$unit" "$REPO/scripts/conformance/install-teardown.sh" \
    && ok "install-teardown.sh removes $unit" || bad "install-teardown.sh does not remove $unit, which install.sh enables"
done

echo ""
echo "install-mode logic: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

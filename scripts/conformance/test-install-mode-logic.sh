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
  "$(sed -n 1p "$TMP/rig/run-meta")" "topology=host-rig"
assert_eq "host-rig archive records the rig-only host setup -- DNS specs pass only with it, so an archive must say it was applied" \
  "$(sed -n 2p "$TMP/rig/run-meta")" "rig_only_host_setup=apparmor-dig-nslookup"
write_run_meta "$TMP/inst" install
assert_eq "install archive is stamped topology=install" "$(sed -n 1p "$TMP/inst/run-meta")" "topology=install"
assert_eq "install archive lists the rig-only add-ons that are not shipped by install.sh" \
  "$(sed -n 2p "$TMP/inst/run-meta")" "rig_only_addons=$INSTALL_RIG_ONLY_ADDONS"
assert_eq "install archive records the same rig-only host setup as the host rig" \
  "$(sed -n 3p "$TMP/inst/run-meta")" "rig_only_host_setup=apparmor-dig-nslookup"
for s in lima-start.sh install-bringup.sh; do
  grep -qx 'rig_apply_host_apparmor "\$VM_NAME"' "$REPO/scripts/conformance/$s" \
    && ok "$s applies the shared rig host AppArmor setup -- without it dig/nslookup in pods segfault (rc 139) and 7 DNS/Service specs fail in that mode" \
    || bad "$s does not call rig_apply_host_apparmor -- DNS specs fail in that mode"
done
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
echo "$TUNNEL_PID 6444" > "$WD/install-tunnel.pid"
bash "$REPO/scripts/conformance/reset.sh" --host-only --workdir "$WD" >/dev/null 2>&1 && rc=0 || rc=$?
assert_eq "reset.sh --host-only succeeds in an install-mode workdir (no host apiserver exists)" "$rc" "0"
sleep 0.3
kill -0 "$TUNNEL_PID" 2>/dev/null && bad "tunnel survived reset.sh --host-only" || ok "reset.sh --host-only kills the install-mode tunnel"
[ ! -e "$WD/install-tunnel.pid" ] && ok "tunnel pidfile is removed" || bad "tunnel pidfile left behind"

sleep 60 &
INNOCENT_PID=$!
LEFTOVER_PIDS+=("$INNOCENT_PID")
echo "$INNOCENT_PID 6444" > "$WD/install-tunnel.pid"
bash "$REPO/scripts/conformance/reset.sh" --host-only --workdir "$WD" >/dev/null 2>&1 || true
kill -0 "$INNOCENT_PID" 2>/dev/null && ok "a stale pidfile pointing at an unrelated process does not kill it" \
  || bad "reset.sh killed an unrelated process via a stale tunnel pidfile"

# A recycled pid that is now ANOTHER slot's tunnel (different forwarded port) must survive:
# killing it would drop a concurrent slot's apiserver connection.
bash -c "exec -a 'ssh -F cfg -N -L 127.0.0.1:6555:10.0.0.9:6443 lima-y' sleep 60" >/dev/null 2>&1 &
OTHER_SLOT_PID=$!
LEFTOVER_PIDS+=("$OTHER_SLOT_PID")
sleep 0.3
echo "$OTHER_SLOT_PID 6444" > "$WD/install-tunnel.pid"
bash "$REPO/scripts/conformance/reset.sh" --host-only --workdir "$WD" >/dev/null 2>&1 || true
kill -0 "$OTHER_SLOT_PID" 2>/dev/null && ok "reset.sh --host-only leaves another slot's ssh -L tunnel alone" \
  || bad "reset.sh killed another slot's tunnel (forwarding 6555) via this slot's pidfile (port 6444)"
is_install_tunnel_pid "$OTHER_SLOT_PID" 6555 && ok "the same process is recognised as the tunnel of its own port" \
  || bad "is_install_tunnel_pid rejects a tunnel for its own port"
if is_install_tunnel_pid "$OTHER_SLOT_PID" ""; then bad "a pidfile without a port must never authorise a kill"; else ok "a pidfile without a port authorises no kill"; fi

# 5. Keep-VM teardown must cover every unit install.sh enables, or the leftover units
# (u7s-kcm-restart.path was the one that survived) break the next host-rig bring-up.
# The real teardown runs against a stubbed limactl (which executes the remote script locally)
# with stubbed systemctl/rm, so the assertions see the calls the unit list actually produces.
STUBS="$TMP/stubs"
CALLS="$TMP/calls"
mkdir -p "$STUBS" "$TMP/tw"
: > "$CALLS"
cat > "$STUBS/limactl" <<'EOF'
#!/usr/bin/env bash
shift 2
[ "$1" = sudo ] && shift
exec "$@"
EOF
cat > "$STUBS/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_CALLS"
EOF
cat > "$STUBS/rm" <<'EOF'
#!/usr/bin/env bash
echo "rm $*" >> "$STUB_CALLS"
EOF
for s in findmnt ip; do printf '#!/usr/bin/env bash\nexit 0\n' > "$STUBS/$s"; done
chmod +x "$STUBS"/*
STUB_CALLS="$CALLS" PATH="$STUBS:$PATH" bash "$REPO/scripts/conformance/install-teardown.sh" --vm stub --workdir "$TMP/tw" >/dev/null 2>&1 && rc=0 || rc=$?
assert_eq "install-teardown.sh completes against a stubbed VM" "$rc" "0"
enabled=$(grep -oE 'systemctl enable (u7s-[a-z-]+\.[a-z]+|kubelet\.service)' "$REPO/scripts/install.sh" | awk '{print $3}' | sort -u)
[ -n "$enabled" ] && ok "install.sh enables u7s units to cover ($(echo "$enabled" | paste -sd' ' -))" || bad "found no units enabled by install.sh"
for unit in $enabled; do
  grep -qxF "systemctl disable --now $unit" "$CALLS" \
    && ok "teardown stops and disables $unit" || bad "teardown never runs 'systemctl disable --now $unit', so it keeps running on the kept VM"
  grep -qxF "rm -f /etc/systemd/system/$unit" "$CALLS" \
    && ok "teardown removes the $unit file" || bad "teardown never removes /etc/systemd/system/$unit, so it returns on reboot"
done
grep -qxF "systemctl daemon-reload" "$CALLS" && ok "teardown reloads systemd after removing units" || bad "teardown skips daemon-reload"

# 6. Host-rig bring-up clears leftover native units. The stubbed systemctl reports only
# u7s-kcm.service as running, as on a slot where install.sh ran earlier.
cat > "$STUBS/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_CALLS"
[ "$1 $2 $3" = "is-active --quiet u7s-kcm.service" ] && exit 0
[ "$1" = is-active ] || [ "$1" = is-enabled ] && exit 3
exit 0
EOF
: > "$CALLS"
out=$(STUB_CALLS="$CALLS" PATH="$STUBS:$PATH" bash "$REPO/scripts/conformance/clear-native-units.sh" 2>&1)
case "$out" in
  *"removed leftover native u7s units: u7s-kcm.service") ok "a running native u7s-kcm is detected and reported alone" ;;
  *) bad "bring-up did not report exactly the running leftover u7s-kcm.service; got: $out" ;;
esac
for unit in $enabled; do
  case "$unit" in kubelet.service) continue ;; esac
  grep -qxF "systemctl disable --now $unit" "$CALLS" && grep -qxF "rm -f /etc/systemd/system/$unit" "$CALLS" \
    && ok "bring-up stops, disables and removes $unit" || bad "bring-up leaves $unit enabled, so it fights the rig's own control plane"
done
grep -q "kubelet.service" "$CALLS" && bad "bring-up touched kubelet.service, which the rig itself runs" || ok "bring-up leaves the rig's kubelet.service alone"
grep -q "u7s-lan-v6" "$CALLS" && bad "bring-up touched the rig's u7s-lan-v6 unit" || ok "bring-up leaves the rig's u7s-lan-v6 unit alone"
: > "$CALLS"
out=$(STUB_CALLS="$CALLS" PATH="$STUBS:$PATH" bash -c 'systemctl() { [ "$1" = is-active ] && return 3; [ "$1" = is-enabled ] && return 1; return 0; }; export -f systemctl; bash "$0"' "$REPO/scripts/conformance/clear-native-units.sh" 2>&1)
case "$out" in *"no leftover native u7s units") ok "a clean slot reports nothing to remove" ;; *) bad "clean slot output wrong: $out" ;; esac
# install.sh's kubelet.service Requires=u7s-apiserver.service; left in place after the
# apiserver unit is removed it fails every rig kubelet start ("Unit u7s-apiserver.service not found").
UD="$TMP/unitdir"
mkdir -p "$UD"
printf '[Unit]\nRequires=crio.service u7s-apiserver.service\n' > "$UD/kubelet.service"
out=$(U7S_UNIT_DIR="$UD" STUB_CALLS="$CALLS" PATH="$STUBS:$PATH" bash "$REPO/scripts/conformance/clear-native-units.sh" 2>&1)
grep -qxF "rm -f $UD/kubelet.service" "$CALLS" && ok "install.sh's kubelet.service (requires u7s-apiserver) is removed" \
  || bad "install.sh's kubelet.service still requires the removed u7s-apiserver, so the rig kubelet cannot start"
case "$out" in *kubelet.service) ok "the removed kubelet.service is reported" ;; *) bad "kubelet.service removal not reported: $out" ;; esac
printf '[Service]\nExecStart=/usr/bin/kubelet\n' > "$UD/kubelet.service"
: > "$CALLS"
U7S_UNIT_DIR="$UD" STUB_CALLS="$CALLS" PATH="$STUBS:$PATH" bash "$REPO/scripts/conformance/clear-native-units.sh" >/dev/null 2>&1
! grep -qF "kubelet.service" "$CALLS" && ok "a kubelet.service that does not require u7s-apiserver is left alone" \
  || bad "bring-up removed a kubelet.service that is not install.sh's"
grep -q 'clear-native-units.sh' "$REPO/scripts/conformance/lima-start.sh" \
  && ok "lima-start.sh runs the leftover-unit clearing" || bad "lima-start.sh never clears leftover native units, so a post-install slot breaks the rig bring-up"
grep -q 'clear-native-units.sh' "$REPO/scripts/conformance/install-teardown.sh" \
  && ok "install-teardown.sh shares the unit list" || bad "install-teardown.sh carries its own unit list"

# One network-default table, shared by lima-start.sh and install-bringup.sh.
assert_eq "lima-node defaults to its own network" "$(default_network_for_vm lima-node)" "user-v2-mayor"
assert_eq "lima-node-3 defaults to worker network a" "$(default_network_for_vm lima-node-3)" "user-v2-workers-a"
assert_eq "lima-node-smoke defaults to worker network b" "$(default_network_for_vm lima-node-smoke)" "user-v2-workers-b"
assert_eq "an unknown VM falls back to user-v2" "$(default_network_for_vm scratch)" "user-v2"
for f in lima-start.sh install-bringup.sh; do
  if grep -q 'lima-node-2|' "$REPO/scripts/conformance/$f"; then bad "$f carries its own copy of the network table"; else ok "$f reads the shared network table"; fi
  grep -q 'default_network_for_vm' "$REPO/scripts/conformance/$f" || bad "$f does not call default_network_for_vm"
done

echo ""
echo "install-mode logic: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

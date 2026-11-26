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
# The full expected run-meta, literal: adding a rig-only step without deciding its token
# here (and in _lib.sh) fails this test, so a result always says what extra it ran with.
APPARMOR_TOKENS="apparmor-u7s-default-dig-nslookup,apparmor-host-dig-nslookup,apparmor-host-dig-results-write"
COMMON_TOKENS="$APPARMOR_TOKENS,crio-test-handler-runtime,e2e-ssh-key,sonobuoy-aggregator-limitrange,vm-nfs-common,vm-journald-limits,vm-logrotate-interval"
ADDONS="metrics-server,external-snapshotter,kube-network-policies"
U7S_RIG_BUILD_FEATURES="rig-test-knobs,pki-test-knobs"
write_run_meta "$TMP/rig" host-rig
assert_eq "host-rig run-meta lists every rig-only addition and deviation (add-ons, setup, konnectivity/host apiserver, kubelet overlay, build features)" \
  "$(cat "$TMP/rig/run-meta")" "topology=host-rig
rig_only_addons=$ADDONS
rig_only_setup=$COMMON_TOKENS,kubelet-unit-dropin-tz-nofile
rig_only_deviations=host-side-apiserver,konnectivity-server,konnectivity-agent
rig_only_kubelet_config=$RIG_ONLY_KUBELET_CONFIG
rig_only_build_features=rig-test-knobs,pki-test-knobs"
write_run_meta "$TMP/inst" install
assert_eq "install run-meta lists every rig-only addition on top of what install.sh delivers" \
  "$(cat "$TMP/inst/run-meta")" "topology=install
rig_only_addons=$ADDONS
rig_only_setup=$COMMON_TOKENS"

# Each token must still correspond to code that applies it; a removed step must lose its token.
token_anchor() { # <token> <file> <fixed string>
  grep -qF -- "$3" "$REPO/$2" && ok "token $1 is backed by code in $2" || bad "token $1 has no applying code ($3 not in $2): drop the token or restore the step"
}
token_anchor crio-test-handler-runtime lima/kubelet.yaml '20-test-handler.conf'
token_anchor e2e-ssh-key scripts/conformance/lima-start.sh 'ssh-keygen'
token_anchor e2e-ssh-key scripts/conformance/install-bringup.sh 'ssh-keygen'
token_anchor sonobuoy-aggregator-limitrange scripts/conformance/06-run-sonobuoy.sh 'LimitRange'
token_anchor vm-nfs-common scripts/conformance/_lib.sh 'install -y nfs-common'
token_anchor vm-journald-limits scripts/conformance/_lib.sh 'journald.conf.d/conformance.conf'
token_anchor vm-logrotate-interval scripts/conformance/_lib.sh 'logrotate.timer.d'
token_anchor kubelet-unit-dropin-tz-nofile scripts/conformance/lima-start.sh 'rig_kubelet_unit_script'
token_anchor host-side-apiserver scripts/conformance/02-start-apiserver.sh 'bash "$REPO/scripts/u7s-start.sh" --background'
token_anchor konnectivity-agent scripts/conformance/lima-start.sh 'name: konnectivity-agent${NODE_SUFFIX}'
token_anchor konnectivity-server scripts/u7s-start.sh '--mode=http-connect'
token_anchor rig-build-features scripts/conformance/01-build.sh 'rig-test-knobs'

# Both profiling and PKI knobs alter the binary under test; recording only one hides the other.
assert_eq "default rig build is rig-test-knobs only" "$(rig_build_features 0 0 0)" "rig-test-knobs"
assert_eq "dhat build is recorded" "$(rig_build_features 0 1 0)" "rig-test-knobs,dhat"
assert_eq "pki build is recorded" "$(rig_build_features 0 0 1)" "rig-test-knobs,pki-test-knobs"
assert_eq "dhat and pki together are both recorded, neither overrides the other" "$(rig_build_features 0 1 1)" "rig-test-knobs,dhat,pki-test-knobs"
assert_eq "a prebuilt binary's features are unknowable, never claimed as rig-test-knobs" "$(rig_build_features 1 0 0)" "prebuilt-binary"
grep -qF 'rig_build_features "$_PREBUILT" "$PROFILE" "$_PKI"' "$REPO/scripts/conformance/run-all.sh" \
  && ok "run-all.sh derives U7S_RIG_BUILD_FEATURES through rig_build_features" \
  || bad "run-all.sh does not use rig_build_features: run-meta would not match the build"

# Add-ons are derived from the manifests dir: a new rig-only manifest without an add-on
# entry (and so without the label) fails here.
for m in "$REPO"/scripts/conformance/manifests/*.yaml; do
  name="$(basename "$m" .yaml)"
  case ",$RIG_ONLY_ADDONS," in
    *",$name,"*) ok "manifest $name is a recorded rig-only add-on" ;;
    *) bad "scripts/conformance/manifests/$name.yaml is not in RIG_ONLY_ADDONS: it would run unrecorded and unlabelled" ;;
  esac
done
assert_eq "RIG_ONLY_ADDONS is exactly the add-ons in the expected run-meta" "$RIG_ONLY_ADDONS" "$ADDONS"
grep -qF 'label --overwrite -f "$REPO/scripts/conformance/manifests/${addon}.yaml" "$RIG_ONLY_LABEL"' "$REPO/scripts/conformance/run-all.sh" \
  && ok "host rig labels every recorded add-on with the rig-only label, as install mode does" \
  || bad "run-all.sh does not label the host-rig add-ons"
for f in lima-start.sh install-bringup.sh; do
  grep -q "rig_apply_apparmor_rig_setup" "$REPO/scripts/conformance/$f" \
    && ok "$f applies both AppArmor layers via the shared step -- without them dig/nslookup in pods abort (rc 139) and 7 DNS/Service specs fail in that mode" \
    || bad "$f does not call rig_apply_apparmor_rig_setup -- DNS specs fail in that mode"
done
# The shared step against a stubbed limactl: each layer must be issued, since either one
# missing still denies the stacked peer.
AASTUB="$TMP/aastub"
AALOG="$TMP/aalog"
mkdir -p "$AASTUB"
: > "$AALOG"
cat > "$AASTUB/limactl" <<'EOF'
#!/usr/bin/env bash
shift 2
[ "$1" = sudo ] && shift
case "$*" in
  "cat /etc/apparmor.d/u7s-default") printf '  signal (send,receive) peer=u7s-default//&*,\n' ;;
  tee*) echo "TEE $(cat)" >> "$AA_LOG" ;;
  bash\ -c*) printf "%s\n" "$3" > "$AA_LOG.host" ;;
  apparmor_parser*) echo "RELOAD $*" >> "$AA_LOG" ;;
  sh\ -c*) ;;
esac
EOF
chmod +x "$AASTUB/limactl"
AA_LOG="$AALOG" PATH="$AASTUB:$PATH" rig_apply_apparmor_rig_setup stubvm >/dev/null 2>&1 && rc=0 || rc=$?
assert_eq "shared AppArmor step succeeds against a stubbed VM" "$rc" "0"
grep -qF "TEE   signal (send,receive) peer=u7s-default//&*,"$'\n'"  signal (send,receive) peer={dig,nslookup}//&u7s-default," "$AALOG" \
  && ok "u7s-default layer: the rule is written into the profile" \
  || bad "u7s-default layer missing: container dig/nslookup is denied at profile=u7s-default"
grep -qF "RELOAD apparmor_parser -r -W /etc/apparmor.d/u7s-default" "$AALOG" \
  && ok "u7s-default layer: the profile is reloaded so the kernel enforces the rule" \
  || bad "u7s-default is not reloaded, so the rule never takes effect"
grep -qF 'peer=@{profile_name}//&u7s-default,' "$AALOG.host" \
  && grep -qF '/etc/apparmor.d/local/' "$AALOG.host" \
  && ok "host layer: dig/nslookup local overrides are written -- the host profiles deny the stacked peer too" \
  || bad "host layer missing: container dig/nslookup is denied at profile=dig/nslookup"
grep -qF 'owner /results/** w,' "$AALOG.host" \
  && ok "host layer: dig may write /results/** -- else it aborts on its redirected stdout (file_inherit DENIED) and the DNS ExternalName spec reads an empty file" \
  || bad "host dig override lacks write on /results/**: dig aborts and DNS ExternalName services fails"
# Behavioural: run the real host script with stubbed tools; the file rule must reach local/dig only.
HOSTROOT="$TMP/hostroot"
mkdir -p "$HOSTROOT/apparmor.d/local" "$HOSTROOT/sys"
touch "$HOSTROOT/apparmor.d/dig" "$HOSTROOT/apparmor.d/nslookup"
printf 'dig (enforce)\nnslookup (enforce)\n' > "$HOSTROOT/sys/profiles"
printf '#!/bin/sh\nexit 0\n' > "$AASTUB/apparmor_parser"
chmod +x "$AASTUB/apparmor_parser"
hs="${RIG_AA_HOST_SCRIPT//\/etc\/apparmor.d/$HOSTROOT/apparmor.d}"
hs="${hs//\/sys\/kernel\/security\/apparmor\/profiles/$HOSTROOT/sys/profiles}"
PATH="$AASTUB:$PATH" bash -c "$hs" >/dev/null 2>&1 && rc=0 || rc=$?
assert_eq "host script runs against a stubbed host" "$rc" "0"
grep -qF 'owner /results/** w,' "$HOSTROOT/apparmor.d/local/dig" \
  && ok "local/dig carries the /results write rule" || bad "local/dig lacks the /results write rule: DNS ExternalName services fails"
grep -qF '/results' "$HOSTROOT/apparmor.d/local/nslookup" \
  && bad "nslookup got a /results write grant it does not need" || ok "nslookup override stays signal-only (narrowest grant)"
grep -qF 'peer=@{profile_name}//&u7s-default,' "$HOSTROOT/apparmor.d/local/dig" \
  && ok "local/dig keeps the signal rule" || bad "local/dig lost the signal rule"
grep -qF 'apparmor_parser -r /etc/apparmor.d/$p' "$AALOG.host" \
  && grep -qF 'rm -f $f' "$AALOG.host" \
  && ok "host layer reloads both profiles and undoes the override when the reload fails" \
  || bad "host layer does not reload or does not roll back a failed reload"
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
for flag in "--binary /x" "--profile" "--extra-node vm2" "--dual-stack" "--embedded-scheduler true" "--pki-test-lifetime 30"; do
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
# The cleared list must be every u7s unit install.sh writes, plus the standalone scheduler it
# retires; a unit missing here (u7s-scheduler.service once was) survives on the slot and collides
# with the rig's own processes.
install_units=$({
  grep -oE 'cat > /etc/systemd/system/u7s-[a-z-]+\.[a-z]+' "$REPO/scripts/install.sh" | sed 's|.*/||'
  grep -oE 'systemctl (enable|disable) u7s-[a-z-]+\.[a-z]+' "$REPO/scripts/install.sh" | awk '{print $3}'
} | sort -u)
cleared_units=$(sed -n 's/^units="\(.*\)"$/\1/p' "$REPO/scripts/conformance/clear-native-units.sh" | tr ' ' '\n' | sort -u)
[ -n "$install_units" ] && [ -n "$cleared_units" ] || bad "could not read the u7s unit lists (install: '$install_units', cleared: '$cleared_units')"
assert_eq "clear-native-units.sh clears exactly the u7s units install.sh writes or retires, so no install leftover survives a rig bring-up" \
  "$cleared_units" "$install_units"
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
: > "$CALLS"
U7S_UNIT_DIR="$UD" STUB_CALLS="$CALLS" PATH="$STUBS:$PATH" bash "$REPO/scripts/conformance/clear-native-units.sh" >/dev/null 2>&1
grep -qF "$UD/u7s-kcm.service.d" "$CALLS" \
  && ok "teardown removes the u7s-kcm.service.d drop-in dir" \
  || bad "teardown leaves u7s-kcm.service.d, so the next install.sh boots a KCM left trimmed by the A/B harness"
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

# --kcm-mode is shared by the host rig (04-start-kcm.sh appends the trim) and --install (systemd
# drop-in); a typo must fail before any VM is touched instead of running an untrimmed "trimmed"
# conformance run that would be read as a pass.
out=$("$REPO/scripts/conformance/run-all.sh" --kcm-mode X --stack-only 2>&1 || true)
case "$out" in *"must be R or T"*) ok "--kcm-mode rejects values other than R or T on the host rig" ;; *) bad "--kcm-mode X accepted on the host rig: $out" ;; esac
out=$("$REPO/scripts/conformance/04-start-kcm.sh" --kcm-mode X 2>&1 || true)
case "$out" in *"must be R or T"*) ok "04-start-kcm.sh rejects an unknown --kcm-mode before touching a VM" ;; *) bad "04-start-kcm.sh accepted --kcm-mode X: $out" ;; esac
out=$("$REPO/scripts/conformance/run-all.sh" --install --kcm-mode X 2>&1 || true)
case "$out" in *"must be R or T"*) ok "--kcm-mode rejects values other than R or T" ;; *) bad "--kcm-mode X accepted: $out" ;; esac

echo ""
echo "install-mode logic:$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

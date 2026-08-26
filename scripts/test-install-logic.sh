#!/usr/bin/env bash
# Unit tests for scripts/install.sh's systemd-unit-authoring logic.
#
# Structural (grep-against-literal-source) tests, following the pattern in
# scripts/conformance/test-network-flag-logic.sh: install.sh runs apt-get,
# writes to /etc/systemd/system, and needs root, so it cannot be executed
# directly by a unit test -- these assertions instead pin down the exact
# source text that a future edit must not silently regress.
#
# Primary regression this file exists for: u7s-kcm.service's ExecStart line
# originally wrapped kube-controller-manager in `bash -c '...'` so a single
# ExecStart could both convert the CA (openssl) and exec the real binary.
# That string contained an UNQUOTED `--controllers=*,-cloud-node-lifecycle-
# controller,...` -- when systemd hands a bash -c string to a real shell,
# that shell glob-expands the bare `*` against WorkingDirectory's contents
# (/var/lib/u7s, which is non-empty by the time KCM actually starts: ca.crt,
# kubeconfig, etc. all exist post-apiserver-bootstrap), silently corrupting
# the --controllers flag into a list of filenames instead of the intended
# "every built-in controller except these five" set. The fix splits this
# into ExecStartPre (cert conversion) + a plain ExecStart (no shell, so
# systemd's own line-splitting never globs).
#
# Also covers two smaller review findings: kubelet.service must depend on
# u7s-apiserver.service exactly like scheduler/kcm (all three read files
# that only exist after apiserver's first run), and binary staging must
# reject a non-executable match instead of silently installing it.
#
# Exits 0 on success, 1 on any assertion failure.
# shellcheck disable=SC2016 # file-wide: single-quoted grep patterns below
# intentionally match install.sh's literal, unexpanded source text.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL="$DIR/install.sh"

PASS=0
FAIL=0

assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}
assert_true() {
  local label="$1"
  shift
  if "$@"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}
assert_false() {
  local label="$1"
  shift
  if ! "$@"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# Regression guard: the bash -c glob-injection bug. This is the load-bearing
# assertion -- it fails if someone reverts the ExecStartPre+plain-ExecStart
# fix back to wrapping kube-controller-manager's launch in a shell.
# ---------------------------------------------------------------------------
assert_false "(regression guard) install.sh no longer wraps any ExecStart in 'bash -c' (the wrapper that let the unquoted --controllers=* glob-expand against WorkingDirectory's contents at runtime)" \
  grep -qF 'ExecStart=/bin/bash -c' "$INSTALL"

assert_true "u7s-kcm.service converts the CA from DER to PEM via ExecStartPre, separately from the real launch" \
  grep -qF 'ExecStartPre=/usr/bin/openssl x509 -inform DER -in $STATE_DIR/ca.crt -out $STATE_DIR/ca.pem' "$INSTALL"

assert_true "u7s-kcm.service's ExecStart invokes kube-controller-manager directly as argv, not through a shell" \
  grep -qF 'ExecStart=$BIN_DIR/kube-controller-manager --kubeconfig=$STATE_DIR/kcm-kubeconfig' "$INSTALL"

# ---------------------------------------------------------------------------
# Consistency: every unit that reads a file u7s-apiserver's first run
# generates (kubeconfig, ca.crt, sa.key, ...) must wait on it the same way.
# Previously kubelet.service was missing this despite the script's own
# comment claiming the race applies uniformly to all three dependents.
# ---------------------------------------------------------------------------
requires_apiserver_count="$(grep -cE '^Requires=.*u7s-apiserver\.service' "$INSTALL")"
assert "all three apiserver-dependent units (u7s-scheduler, u7s-kcm, kubelet) declare Requires=u7s-apiserver.service, matching the script's own stated bootstrap-race reasoning" \
  "$([ "$requires_apiserver_count" = "3" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Binary staging must fail loud on a non-executable match instead of
# silently installing it (e.g. a stray non-binary file that happens to share
# a required binary's name inside the tarball).
# ---------------------------------------------------------------------------
assert_true "tarball binary staging rejects a found-but-non-executable match instead of installing it" \
  grep -qF 'if [ ! -x "$found" ]; then' "$INSTALL"

# ---------------------------------------------------------------------------
# iface_filter() -- drives its regex from install.sh's OWN source at test
# time, not a hand-duplicated second copy. An earlier version of this test
# hardcoded the regex literal here; critical review proved that copy was
# decoupled from install.sh's real behavior -- reverting install.sh to the
# exact blacklist this whitelist replaced (docker0/veth*/cni*/br-*/virbr*/
# flannel*/cali*, via grep -Ev) only tripped 1 of 9 assertions (a brittle
# literal-string check), while the "matches physical / excludes virtual"
# assertions below stayed green because they were exercising THIS FILE's
# own untouched copy of the regex, not install.sh's. Extracting the pattern
# here closes that gap: these assertions now fail if install.sh's real
# regex regresses, not just if someone edits this file's copy out of sync.
#
# Physical-NIC names cover both systemd predictable naming (en*/wl*/ww*:
# eno1, ens33, enp0s3, enp2s0f1, enx<mac>, wlo1, wlp2s0, wlx<mac>, wwan0,
# wwp0s20u4i6) and the legacy eth0 kernel fallback -- checking our own 5-VM
# Ubuntu 26.04 Lima fleet (identical template) found it split 2/5 enp0s1 vs
# 3/5 eth0, so eth0 is a real, live case, not just a theoretical old-kernel
# one.
# ---------------------------------------------------------------------------
# `|| true`: grep legitimately exits non-zero if install.sh no longer has a
# line shaped like this at all (e.g. reverted to grep -Ev/-v, neither of
# which contain the literal substring "grep -E '") -- this must produce a
# clear FAIL below, not a silent script-wide abort under set -e/pipefail.
iface_regex_line="$(grep -m1 "grep -E '" "$INSTALL")" || true
IFACE_REGEX="${iface_regex_line#*grep -E \'}"
IFACE_REGEX="${IFACE_REGEX%%\'*}"
assert "install.sh's --iface whitelist regex was successfully extracted from its real source line (if this fails, the tests below are testing nothing -- a change to how/where the regex is written broke extraction)" \
  "$([ -n "$IFACE_REGEX" ] && echo 1 || echo 0)"

iface_filter() {
  grep -E "$IFACE_REGEX"
}

PHYSICAL_NAMES="eno1
ens33
enp0s3
enp2s0f1
enx78e7d1ea46da
wlo1
wlp2s0
wlx0013eff01234
wwan0
wwp0s20u4i6
eth0
eth1
enp0s1"

VIRTUAL_NAMES="lo
docker0
veth9cbe0b5c
cni0
br-abcdef123456
virbr0
flannel.1
cali1234abcd
kube-ipvs0
tun0
tailscale0"

# `|| true` on each: iface_filter (grep) legitimately exits non-zero when it
# finds zero matches (the whole point of the "leaked" case below), and that
# would otherwise trip this script's own `set -e`/pipefail before the
# assertion even runs.
matched="$(printf '%s\n' "$PHYSICAL_NAMES" | iface_filter | wc -l | tr -d ' ')" || true
expected="$(printf '%s\n' "$PHYSICAL_NAMES" | wc -l | tr -d ' ')"
assert "default --iface whitelist matches every real physical-NIC naming variant (systemd predictable en*/wl*/ww* plus the eth0 legacy fallback observed live on our own Lima fleet)" \
  "$([ "$matched" = "$expected" ] && echo 1 || echo 0)"

leaked="$(printf '%s\n' "$VIRTUAL_NAMES" | iface_filter | wc -l | tr -d ' ')" || true
assert "default --iface whitelist excludes every virtual/container-runtime/VPN interface (docker0, veth*, cni*, br-*, virbr*, flannel*, cali*, tun*, tailscale*) -- picking one of these as the cluster-traffic interface would be wrong" \
  "$([ "$leaked" = "0" ] && echo 1 || echo 0)"

assert_false "(regression guard) install.sh's default --iface detection uses no negated blacklist (grep -Ev / grep -v) to exclude virtual interfaces -- BOTH prior designs (the naive 'exclude only lo' and the docker0/veth*/cni*/... list) were negated blacklists; a positive whitelist (plain grep -E, asserted above) is what actually closes the class of bug critical review found, so reintroducing either shape must fail this suite" \
  grep -qE 'grep -Ev|grep -v' "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: the CRI-O/CNI-plugins gap found running install.sh end to
# end for the first time against a genuinely fresh box. CRI-O's apt package
# only Recommends (does not Depend on) a CNI-plugins package, and Ubuntu
# cloud-image apt defaults disable installing recommends -- so without an
# explicit install, CRI-O validates its bridge CNI config against a plugin
# directory (/opt/cni/bin/) containing zero actual plugin binaries, and every
# node sits NotReady forever ("failed to find plugin \"bridge\""). This never
# showed up in review because it only reproduces on a box that never had
# recommends installed by anything else first -- a full VM run is what caught
# it, and this assertion is what stops a silent revert from reintroducing it
# without another full VM run to catch it again.
# ---------------------------------------------------------------------------
assert_true "install.sh installs kubernetes-cni (the actual /opt/cni/bin/ plugin binaries CRI-O's bridge config references) alongside kubectl, not just kubectl alone" \
  grep -qF 'apt-get install -y kubectl kubernetes-cni' "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: apiserver-to-kubelet proxy (kubectl logs/exec) BadGateway
# on a host-level single-box install. Root cause had two independent halves,
# each with its own live-VM-confirmed failure mode -- both assertions below
# must hold or the specific symptom that was fixed comes back:
#   1. kubelet's default self-signed serving cert on :10250 is untrusted by
#      the apiserver's kubelet-client (pinned to the cluster CA), surfacing
#      as a TLS "unknown CA" alert wrapped in reqwest's opaque "error sending
#      request" -- confirmed via `curl -v https://<node-ip>:10250/`.
#   2. even with a trusted serving cert, kubelet has no clientCAFile to
#      authenticate the apiserver's own client cert against, so it treats
#      the (now-TLS-trusted) request as anonymous and 401s it -- confirmed
#      via a direct unauthenticated curl to kubelet's /containerLogs.
# ---------------------------------------------------------------------------
assert_true "kubelet-config.yaml points tlsCertFile/tlsPrivateKeyFile at a serving cert signed by the cluster CA, not kubelet's own default self-signed fallback" \
  grep -qF 'tlsCertFile: $STATE_DIR/kubelet-serving.crt' "$INSTALL"

assert_true "kubelet.service mints that serving cert (ExecStartPre) with an IP SAN matching the node's own cluster-traffic address, since apiserver dials kubelet by IP" \
  grep -qF 'subjectAltName=IP:$IFACE_IP' "$INSTALL"

# extendedKeyUsage=serverAuth: rustls-webpki's EKU check is currently
# required_if_present (an absent EKU still passes), so this isn't fixing a
# live failure -- it matches the more defensive pattern scripts/conformance/
# lima-start.sh already uses for the same kind of cert, so this cert doesn't
# silently rely on one TLS library's lenient-by-default EKU handling.
assert_true "the minted kubelet serving cert declares extendedKeyUsage=serverAuth, matching lima-start.sh's existing pattern for the same kind of cert rather than relying on webpki's lenient absent-EKU handling" \
  grep -qF 'extendedKeyUsage=serverAuth' "$INSTALL"

assert_true "kubelet-config.yaml sets authentication.x509.clientCAFile to the cluster CA, so kubelet can authenticate apiserver's client cert instead of treating proxied requests as anonymous" \
  grep -qF 'clientCAFile: $STATE_DIR/ca.pem' "$INSTALL"

# ---------------------------------------------------------------------------
# Tarball sourcing: --tarball (local path) / --tarball-url / the URL baked in
# at release time. A script piped into `sh` cannot discover the URL it came
# from, so the published copy carries it as a literal that
# .github/workflows/release-tarball.yaml substitutes in -- these assertions
# pin the two halves of that contract together.
# ---------------------------------------------------------------------------

# The single most damaging way this can regress: someone commits a real URL
# here. Every git checkout would then silently fetch and install THAT
# release's binaries instead of failing loud, and `curl | bash` users of a
# later release would get a script pinned to an older one. This literal is
# also the exact anchor the release workflow's sed matches on, so renaming
# the variable breaks publishing -- caught here at commit time rather than
# mid-release.
assert_true "DEFAULT_TARBALL_URL is empty in the repo copy, so a checkout fails loud instead of silently installing whichever release a committed URL pointed at (and the release workflow's sed anchor still matches)" \
  grep -qxF 'DEFAULT_TARBALL_URL=""' "$INSTALL"

# Asserted on the message, not just a non-zero exit: this check has to run
# BEFORE the root gate, or a non-root operator gets "must be run as root",
# fixes that, and only then learns their flags conflict. Exit-code-only would
# pass either way and so could not fail when that ordering regresses.
conflict_out="$(bash "$INSTALL" --tarball /x --tarball-url http://y 2>&1 || true)"
conflict_ok=0
printf '%s' "$conflict_out" | grep -q 'mutually exclusive' && conflict_ok=1
assert "passing both --tarball and --tarball-url is rejected by name before the root check, so the operator learns their flags conflict on the first run rather than after re-running under sudo" \
  "$conflict_ok"

# A local path the operator already has must never trigger a download, even
# on a released copy where DEFAULT_TARBALL_URL is always non-empty (so an
# unguarded fetch would run on every install).
assert_true "--tarball short-circuits the download entirely, rather than fetching the baked URL and discarding it" \
  grep -qF 'if [ -z "$TARBALL" ]; then' "$INSTALL"

# Ordering guard. The download used to sit next to `tar -xzf`, well after apt
# had installed and started CRI-O -- so a 404 (the expected state until a
# non-prerelease release exists) left the host half-configured. Fetching
# first means a bad URL leaves it untouched.
fetch_line="$(grep -n 'fetch_tarball "$TARBALL_URL"' "$INSTALL" | cut -d: -f1)"
apt_line="$(grep -n '^apt-get update -qq' "$INSTALL" | head -n1 | cut -d: -f1)"
assert "the tarball is downloaded before apt installs anything, so an unreachable or wrong URL aborts with the host untouched instead of half-configured with CRI-O running" \
  "$([ -n "$fetch_line" ] && [ -n "$apt_line" ] && [ "$fetch_line" -lt "$apt_line" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Regression guard: KCM disabled node-ipam-controller with no
# --cluster-cidr, so Node.spec.podCIDR was never allocated and every node's
# CRI-O bridge plugin picked the same uncoordinated default subnet -- a
# cross-node ClusterIP Service was unreachable. Confirmed live on two Lima
# VMs; this is what stops a silent revert from reintroducing that without
# another full 2-node VM run to catch it again.
# ---------------------------------------------------------------------------
assert_false "(regression guard) node-ipam-controller is not in u7s-kcm.service's --controllers disable-list -- disabling it (with no --cluster-cidr) is exactly what left Node.spec.podCIDR unallocated and broke cross-node Service routing" \
  grep -qF -- '-node-ipam-controller' "$INSTALL"

assert_true "u7s-kcm.service's ExecStart allocates per-node pod CIDRs (--allocate-node-cidrs=true --cluster-cidr=...), which node-ipam-controller needs to stamp Node.spec.podCIDR at all" \
  grep -qF -- '--allocate-node-cidrs=true --cluster-cidr=$POD_CLUSTER_CIDR' "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: the other half -- fixing IPAM allocation alone
# does not fix cross-node routing, since CRI-O's stock bridge plugin never
# consumes Node.spec.podCIDR for cross-node routing at all. Flannel is the
# actual CNI closing that gap; losing this deployment step (or the
# crio-bridge-disable pairing below) silently reintroduces the original
# unreachable-cross-node-Service symptom even with podCIDR correctly
# allocated.
# ---------------------------------------------------------------------------
assert_true "install.sh deploys Flannel's DaemonSet (kube-flannel-ds) as the real CNI, not just relying on CRI-O's default bridge plugin" \
  grep -qF 'name: kube-flannel-ds' "$INSTALL"

assert_true "install.sh disables CRI-O's own default bridge CNI conflist(s) once Flannel supplies the real one -- CRI-O picks whichever CNI config file sorts first alphabetically, so leaving 10-crio-bridge.conflist active would silently keep winning over Flannel's 10-flannel.conflist" \
  grep -qF 'mv "$CNI_DIR/$f" "$CNI_DIR/$f.disabled"' "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: Flannel's vxlan backend hard-fails at startup ("Failed to
# check br_netfilter: stat /proc/sys/net/bridge/bridge-nf-call-iptables: no
# such file or directory") on a fresh Ubuntu cloud image, which does not load
# br_netfilter by default -- confirmed live. Losing this would leave every
# Flannel pod crash-looping on any host that has not already loaded the
# module some other way.
# ---------------------------------------------------------------------------
assert_true "install.sh loads br_netfilter, a hard prerequisite for Flannel's vxlan backend that a fresh Ubuntu cloud image doesn't enable by default" \
  grep -qF 'modprobe br_netfilter' "$INSTALL"

assert_true "br_netfilter is persisted via modules-load.d so it survives a reboot, not just the install run" \
  grep -qF '/etc/modules-load.d/u7s-br-netfilter.conf' "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: 'systemctl enable --now UNIT' is enable+
# start; start on an already-active unit is a no-op, so a re-run of
# install.sh staged new binaries into place but the running process never
# re-exec'd against them -- an "upgrade" that silently kept the old binary
# running until a manual restart or reboot.
# ---------------------------------------------------------------------------
assert_false "(regression guard) install.sh no longer uses 'systemctl enable --now', which silently no-ops a re-run against an already-active unit instead of restarting it onto the newly staged binary" \
  grep -qF 'enable --now' "$INSTALL"

assert_true "the apiserver restart step fails loud with a systemctl status/journalctl pointer on failure, instead of a bare set -e trace" \
  grep -qF 'error: failed to restart u7s-apiserver.service (check: systemctl status u7s-apiserver, journalctl -u u7s-apiserver)' "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: kube-proxy's own kubeconfig pointed at the
# "kubernetes" Service's ClusterIP (10.96.0.1:443) -- reachable only via
# iptables DNAT rules that kube-proxy itself is responsible for installing,
# a bootstrap deadlock that left every ClusterIP unreachable cluster-wide.
# ---------------------------------------------------------------------------
assert_false "(regression guard) kube-proxy's kubeconfig no longer points at the kubernetes Service's ClusterIP (10.96.0.1:443), which is only reachable via DNAT rules kube-proxy itself has not yet installed at bootstrap" \
  grep -qF '10.96.0.1:443' "$INSTALL"

assert_true "kube-proxy's kubeconfig points at the real advertised apiserver address (\$IFACE_IP:6443), reachable without depending on kube-proxy's own DNAT rules" \
  grep -qF 'server: https://$IFACE_IP:6443' "$INSTALL"

# ---------------------------------------------------------------------------
# Regression guard: `sh install.sh` on Ubuntu (where /bin/sh is
# dash) used to die on the `set -euo pipefail` line with a bare "Illegal
# option -o pipefail", exit 2, before ever reaching fetch_tarball's checksum
# verification -- undermining the "always require a passing checksum" policy
# on the exact invocation deploy/get-u7s/README.md documents. The guard must
# sit before that `set` line so dash lives long enough to print it.
# ---------------------------------------------------------------------------
bash_version_line="$(grep -n 'BASH_VERSION' "$INSTALL" | head -n1 | cut -d: -f1)"
pipefail_line="$(grep -n '^set -euo pipefail' "$INSTALL" | head -n1 | cut -d: -f1)"
assert "the bash-required guard appears before the 'set -euo pipefail' line dash cannot parse, so dash survives long enough to print it instead of dying first" \
  "$([ -n "$bash_version_line" ] && [ -n "$pipefail_line" ] && [ "$bash_version_line" -lt "$pipefail_line" ] && echo 1 || echo 0)"

if command -v dash >/dev/null 2>&1; then
  dash_out="$(dash "$INSTALL" --help 2>&1)" && dash_status=0 || dash_status=$?
  assert "running install.sh under dash (Ubuntu's /bin/sh) exits non-zero with a clear bash-required message, instead of dash's bare 'Illegal option -o pipefail' parse crash" \
    "$([ "$dash_status" -ne 0 ] && printf '%s' "$dash_out" | grep -qi 'requires bash' && echo 1 || echo 0)"
else
  echo "SKIP: dash not installed on this runner -- cannot exercise the dash-rejection path directly"
fi

bash_out="$(bash "$INSTALL" --help 2>&1)" && bash_status=0 || bash_status=$?
assert "running install.sh under bash (a real invocation) is unaffected by the guard and proceeds past it" \
  "$([ "$bash_status" -eq 0 ] && printf '%s' "$bash_out" | grep -q '^Usage:' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Regression guard: A re-run of install.sh against an existing
# node used to look identical to a fresh install in its own output, giving
# the operator no signal that CA/cluster state was being preserved rather
# than built from scratch. Extracted verbatim from install.sh's own source
# (the same "exercise the real logic, not a hand-copy" approach as
# test-install-checksum.sh's fetch_tarball extraction), so this fails if the
# shipped heuristic regresses, not just a copy of it kept here.
# ---------------------------------------------------------------------------
write_detection_runner() {
  local install_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'STATE_DIR="$1"'
    awk '/^EXISTING_INSTALL=0$/,/^fi$/' "$install_script"
    echo 'echo "EXISTING_INSTALL=$EXISTING_INSTALL"'
  } > "$runner"
}

DETECT_WORK="$(mktemp -d)"
trap 'rm -rf "$DETECT_WORK"' EXIT
DETECT_RUNNER="$DETECT_WORK/detect.sh"
write_detection_runner "$INSTALL" "$DETECT_RUNNER"

fresh_dir="$DETECT_WORK/fresh"
mkdir -p "$fresh_dir"
fresh_out="$(bash "$DETECT_RUNNER" "$fresh_dir" 2>&1)"
assert "a genuinely fresh node (no ca.key, no kubeconfig on disk yet) is NOT flagged as an existing install -- a false positive here would print a confusing 'upgrading' message on someone's very first run" \
  "$(printf '%s' "$fresh_out" | grep -q '^EXISTING_INSTALL=0$' && ! printf '%s' "$fresh_out" | grep -qi 'existing u7s install detected' && echo 1 || echo 0)"

cp_dir="$DETECT_WORK/control-plane"
mkdir -p "$cp_dir"
touch "$cp_dir/ca.key"
cp_out="$(bash "$DETECT_RUNNER" "$cp_dir" 2>&1)"
assert "a control-plane node with an existing ca.key IS detected as an existing install -- ca.key only exists once apiserver's own load_or_generate_ca has actually run and succeeded, unlike the systemd unit file which install.sh writes even on a failed first attempt" \
  "$(printf '%s' "$cp_out" | grep -q '^EXISTING_INSTALL=1$' && printf '%s' "$cp_out" | grep -qi 'existing u7s install detected' && echo 1 || echo 0)"

worker_dir="$DETECT_WORK/worker"
mkdir -p "$worker_dir"
touch "$worker_dir/kubeconfig"
worker_out="$(bash "$DETECT_RUNNER" "$worker_dir" 2>&1)"
assert "an already-joined worker node (kubeconfig present, ca.key absent -- join_cluster never writes a CA key on a worker) IS detected as an existing install" \
  "$(printf '%s' "$worker_out" | grep -q '^EXISTING_INSTALL=1$' && printf '%s' "$worker_out" | grep -qi 'existing u7s install detected' && echo 1 || echo 0)"

assert_false "(regression guard) the detection message does not reference a --force-reinstall flag, which does not exist in this bead's shipped scope -- mentioning it would send operators looking for a flag install.sh would reject as unknown" \
  grep -qF -- '--force-reinstall' "$INSTALL"

# ---------------------------------------------------------------------------
# Worker-node re-run safety: join_cluster() is one-shot (fresh CSR against a
# single-use bootstrap token, unconditional kubeconfig/kubelet-client.*
# overwrite). Re-running it against an already-joined worker -- an operator
# re-passing --join/--token out of habit, or install.sh naively re-running
# with no flags and guessing wrong -- would silently rotate the node's
# client identity and likely fail outright anyway. Extracted verbatim from
# install.sh's own source, same approach as the EXISTING_INSTALL detection
# test above.
# ---------------------------------------------------------------------------
write_worker_mode_runner() {
  local install_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'STATE_DIR="$1"'
    echo 'JOIN_SERVER="$2"'
    awk '/^JOIN_MODE=0$/,/^  WORKER_MODE=1$/' "$install_script"
    echo 'fi'
    echo 'echo "JOIN_MODE=$JOIN_MODE"'
    echo 'echo "EXISTING_WORKER=$EXISTING_WORKER"'
    echo 'echo "WORKER_MODE=$WORKER_MODE"'
  } > "$runner"
}

WORKER_MODE_WORK="$(mktemp -d)"
# Replaces the DETECT_WORK-only trap above (only the latest EXIT trap
# fires), so it must still cover DETECT_WORK too.
trap 'rm -rf "$DETECT_WORK" "$WORKER_MODE_WORK"' EXIT
WORKER_MODE_RUNNER="$WORKER_MODE_WORK/worker-mode.sh"
write_worker_mode_runner "$INSTALL" "$WORKER_MODE_RUNNER"

# Case A: the acceptance criterion this bead exists for -- --join against an
# already-joined worker (kubeconfig present, no ca.key) must refuse loudly
# and exit non-zero, rather than re-running the CSR flow and rotating this
# node's identity.
already_joined_dir="$WORKER_MODE_WORK/already-joined"
mkdir -p "$already_joined_dir"
touch "$already_joined_dir/kubeconfig"
rejoin_status=0
rejoin_out="$(bash "$WORKER_MODE_RUNNER" "$already_joined_dir" "https://1.2.3.4:6443" 2>&1)" || rejoin_status=$?
assert "--join against an already-joined worker (kubeconfig present, no ca.key) is refused loudly with a non-zero exit, instead of silently re-running the one-shot CSR flow and rotating the node's client identity" \
  "$([ "$rejoin_status" -ne 0 ] && printf '%s' "$rejoin_out" | grep -qi 'refusing' && echo 1 || echo 0)"

# Case B: --join against a genuinely fresh node (no kubeconfig, no ca.key at
# all) must proceed normally -- the guard must not misfire on the one case
# --join actually exists for.
fresh_join_dir="$WORKER_MODE_WORK/fresh-join"
mkdir -p "$fresh_join_dir"
fresh_join_out="$(bash "$WORKER_MODE_RUNNER" "$fresh_join_dir" "https://1.2.3.4:6443" 2>&1)"
assert "--join against a genuinely fresh node proceeds normally (JOIN_MODE=1, WORKER_MODE=1) -- the refuse-loud guard must not misfire on a real first-time join" \
  "$(printf '%s' "$fresh_join_out" | grep -q '^JOIN_MODE=1$' && printf '%s' "$fresh_join_out" | grep -q '^WORKER_MODE=1$' && echo 1 || echo 0)"

# Case C: a bare re-run (no --join/--token, the "curl | sudo bash" upgrade
# UX) against an already-joined worker must resolve to WORKER_MODE=1 with
# JOIN_MODE=0 -- the upgrade path that stages kubelet alone and never
# re-enters join_cluster(), rather than an operator naively re-running
# install.sh with no flags falling through to the control-plane path.
worker_upgrade_dir="$WORKER_MODE_WORK/worker-upgrade"
mkdir -p "$worker_upgrade_dir"
touch "$worker_upgrade_dir/kubeconfig"
worker_upgrade_out="$(bash "$WORKER_MODE_RUNNER" "$worker_upgrade_dir" "" 2>&1)"
assert "a bare re-run (no --join/--token) against an already-joined worker resolves to WORKER_MODE=1 with JOIN_MODE=0 -- upgrades kubelet in place without ever re-entering join_cluster() or touching kubeconfig/kubelet-client.*" \
  "$(printf '%s' "$worker_upgrade_out" | grep -q '^JOIN_MODE=0$' && printf '%s' "$worker_upgrade_out" | grep -q '^EXISTING_WORKER=1$' && printf '%s' "$worker_upgrade_out" | grep -q '^WORKER_MODE=1$' && echo 1 || echo 0)"

# Case D: a bare re-run against a control-plane node (ca.key present) must
# stay on the full control-plane path (WORKER_MODE=0) -- this guard is
# worker-specific and must not misclassify the other node role.
cp_upgrade_dir="$WORKER_MODE_WORK/cp-upgrade"
mkdir -p "$cp_upgrade_dir"
touch "$cp_upgrade_dir/ca.key"
cp_upgrade_out="$(bash "$WORKER_MODE_RUNNER" "$cp_upgrade_dir" "" 2>&1)"
assert "a bare re-run against a control-plane node (ca.key present) stays on the full control-plane path (WORKER_MODE=0) -- a control-plane upgrade must not be misclassified as a worker one" \
  "$(printf '%s' "$cp_upgrade_out" | grep -q '^WORKER_MODE=0$' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Mutation self-check (CLAUDE.md rule 14): prove the refuse-loud guard
# assertion above would actually catch a reverted fix, not just document
# today's behavior. Bypass the guard in a scratch copy of install.sh and
# rerun the exact already-joined-worker scenario against it -- if the guard
# is gone, --join must instead proceed (WORKER_MODE=1 printed, no refusal).
# ---------------------------------------------------------------------------
MUTATED_INSTALL="$WORKER_MODE_WORK/install-mutated.sh"
sed 's/if \[ "\$JOIN_MODE" -eq 1 \] && \[ "\$EXISTING_WORKER" -eq 1 \]; then/if false; then/' "$INSTALL" > "$MUTATED_INSTALL"
if diff -q "$INSTALL" "$MUTATED_INSTALL" > /dev/null 2>&1; then
  assert "mutation self-check: the refuse-loud guard's condition line exists in install.sh to mutate (if this fails, the line was renamed/reshaped and this suite no longer exercises it)" 0
else
  MUTATED_RUNNER="$WORKER_MODE_WORK/worker-mode-mutated.sh"
  write_worker_mode_runner "$MUTATED_INSTALL" "$MUTATED_RUNNER"
  mutated_status=0
  mutated_out="$(bash "$MUTATED_RUNNER" "$already_joined_dir" "https://1.2.3.4:6443" 2>&1)" || mutated_status=$?
  assert "mutation self-check: with the refuse-loud guard bypassed, a --join re-run against an already-joined worker is wrongly allowed to proceed -- proving the refusal test above would fail if this fix were ever reverted" \
    "$([ "$mutated_status" -eq 0 ] && printf '%s' "$mutated_out" | grep -q '^WORKER_MODE=1$' && echo 1 || echo 0)"
fi

# ---------------------------------------------------------------------------
# --manifest-output-dir: default value, flag parsing, and env-var fallback
# must match the existing --iface/U7S_IFACE convention -- an operator relying
# on that convention for --iface would reasonably expect the same shape here.
# ---------------------------------------------------------------------------
assert_true "MANIFEST_OUTPUT_DIR defaults to /etc/u7s/manifests (the apiserver's well-known auto-applied folder) when neither the flag nor U7S_MANIFEST_OUTPUT_DIR is set" \
  grep -qF 'MANIFEST_OUTPUT_DIR="${U7S_MANIFEST_OUTPUT_DIR:-/etc/u7s/manifests}"' "$INSTALL"

assert_true "--manifest-output-dir is parsed as a flag, overriding the default/env-var value" \
  grep -qF -- '--manifest-output-dir) MANIFEST_OUTPUT_DIR="$2"; shift 2 ;;' "$INSTALL"

# ---------------------------------------------------------------------------
# Vendored-manifest copy step: extracted verbatim from install.sh's own
# source (same approach as fetch_tarball's extraction in
# test-install-checksum.sh), so these assertions fail if the shipped logic
# regresses, not just a hand-copy kept here.
# ---------------------------------------------------------------------------
write_manifest_copy_runner() {
  local install_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'STAGE_DIR="$1"'
    echo 'MANIFEST_OUTPUT_DIR="$2"'
    echo 'WORKER_MODE="$3"'
    awk '/^if \[ "\$WORKER_MODE" -eq 0 \]; then$/,/^fi$/' "$install_script"
  } > "$runner"
}

MANIFEST_WORK="$(mktemp -d)"
# Replaces the DETECT_WORK-only trap above (only the latest EXIT trap fires),
# so it must still cover DETECT_WORK too.
trap 'rm -rf "$DETECT_WORK" "$MANIFEST_WORK"' EXIT
MANIFEST_RUNNER="$MANIFEST_WORK/manifest-copy.sh"
write_manifest_copy_runner "$INSTALL" "$MANIFEST_RUNNER"

# Case 1: tarball carries manifests/*.yaml, default well-known destination --
# the common case once the release-pipeline vendoring bead lands. Files must
# actually reach the folder apiserver's own boot-time scan reads.
stage1="$MANIFEST_WORK/stage1"
mkdir -p "$stage1/manifests"
echo 'kind: ConfigMap' > "$stage1/manifests/coredns.yaml"
dest1="$MANIFEST_WORK/dest1"
bash "$MANIFEST_RUNNER" "$stage1" "$dest1" 0
assert_true "a manifests/*.yaml file found in the extracted tarball is copied into the (default well-known) output directory" \
  test -f "$dest1/coredns.yaml"

# Case 2: operator points --manifest-output-dir elsewhere (GitOps entry
# point) -- the well-known folder must end up with NOTHING, not a partial
# copy, or apiserver's boot-time scan would auto-apply files the operator
# meant to manage themselves.
stage2="$MANIFEST_WORK/stage2"
mkdir -p "$stage2/manifests"
echo 'kind: ConfigMap' > "$stage2/manifests/kube-proxy.yaml"
wellknown2="$MANIFEST_WORK/wellknown2"
altdest2="$MANIFEST_WORK/altdest2"
mkdir -p "$wellknown2"
bash "$MANIFEST_RUNNER" "$stage2" "$altdest2" 0
assert_true "an alternate --manifest-output-dir receives the vendored manifest file" \
  test -f "$altdest2/kube-proxy.yaml"
assert "an alternate --manifest-output-dir leaves the well-known folder untouched (empty) -- the GitOps contract this bead exists for: apiserver's own scan of the well-known folder must find nothing to auto-apply" \
  "$([ -z "$(ls -A "$wellknown2" 2>/dev/null)" ] && echo 1 || echo 0)"

# Case 3: WORKER_MODE=1 (a --join worker install, or an upgrade re-run
# against an already-joined worker -- no apiserver on either to apply
# anything) must skip the copy entirely, even if the tarball happens to
# carry a manifests/ dir.
stage3="$MANIFEST_WORK/stage3"
mkdir -p "$stage3/manifests"
echo 'kind: ConfigMap' > "$stage3/manifests/flannel.yaml"
dest3="$MANIFEST_WORK/dest3"
bash "$MANIFEST_RUNNER" "$stage3" "$dest3" 1
assert_false "a worker node (WORKER_MODE=1: fresh --join or an already-joined worker's upgrade) skips the manifest copy step entirely -- neither runs an apiserver, so there is nothing to auto-apply" \
  test -e "$dest3"

# Case 4: a checkout's tarball with no manifests/ dir at all (true until the
# release-pipeline vendoring bead lands separately) must be a silent no-op,
# not a fatal error that breaks every install in the meantime.
stage4="$MANIFEST_WORK/stage4"
mkdir -p "$stage4"
dest4="$MANIFEST_WORK/dest4"
copy_status=0
bash "$MANIFEST_RUNNER" "$stage4" "$dest4" 0 || copy_status=$?
assert "a tarball with no manifests/ dir at all is treated as an empty set, not an error -- required until the release-pipeline vendoring bead (mayor-liiv1) actually lands manifests into the tarball" \
  "$([ "$copy_status" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Persisted install config ($STATE_DIR/config): IFACE/NODE_NAME feed into
# --advertise-address, which the apiserver embeds into every kubeconfig it
# rewrites (tls.rs). Regression this guards: a re-run with a different
# --iface used to silently rebake a different address into a live cluster,
# breaking any kubeconfig already distributed off-box (mayor-htnrs). Operator
# decision (2026-08-26): refuse loudly on a mismatch rather than silently
# override or auto-wipe state -- deleting $CONFIG_FILE is the only escape
# hatch. Both the write step and the read-back+refusal logic are extracted
# verbatim from install.sh's own source, same approach as the other
# extractions in this file.
# ---------------------------------------------------------------------------

write_persist_config_write_runner() {
  local install_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'STATE_DIR="$1"'
    echo 'CONFIG_FILE="$STATE_DIR/config"'
    echo 'NODE_NAME="$2"'
    echo 'IFACE="$3"'
    grep -A3 -F 'cat > "$CONFIG_FILE" <<EOF' "$install_script"
  } > "$runner"
}

write_persist_config_check_runner() {
  local install_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'STATE_DIR="$1"'
    echo 'CONFIG_FILE="$STATE_DIR/config"'
    echo 'EXISTING_INSTALL="$2"'
    echo 'NODE_NAME="$3"'
    echo 'IFACE="$4"'
    awk '/^PERSISTED_NODE_NAME=""$/,/^# --- Defaults: node name, network interface/ { if ($0 !~ /^# --- Defaults: node name, network interface/) print }' "$install_script"
    echo 'echo "NODE_NAME=$NODE_NAME"'
    echo 'echo "IFACE=$IFACE"'
  } > "$runner"
}

PERSIST_WORK="$(mktemp -d)"
# Replaces the earlier EXIT traps above (only the latest fires), so it must
# still cover every dir those relied on cleaning up.
trap 'rm -rf "$DETECT_WORK" "$WORKER_MODE_WORK" "$MANIFEST_WORK" "$PERSIST_WORK"' EXIT
PERSIST_WRITE_RUNNER="$PERSIST_WORK/persist-write.sh"
PERSIST_CHECK_RUNNER="$PERSIST_WORK/persist-check.sh"
write_persist_config_write_runner "$INSTALL" "$PERSIST_WRITE_RUNNER"
write_persist_config_check_runner "$INSTALL" "$PERSIST_CHECK_RUNNER"

# Case 1: a fresh install writes the resolved node-name/iface to
# $STATE_DIR/config -- the write half of the contract; nothing to read back
# on the very next run without this.
fresh_write_dir="$PERSIST_WORK/fresh-write"
mkdir -p "$fresh_write_dir"
bash "$PERSIST_WRITE_RUNNER" "$fresh_write_dir" "node-a" "eth0"
assert_true "a fresh install persists the resolved node-name to \$STATE_DIR/config" \
  grep -qF 'NODE_NAME="node-a"' "$fresh_write_dir/config"
assert_true "a fresh install persists the resolved iface to \$STATE_DIR/config" \
  grep -qF 'IFACE="eth0"' "$fresh_write_dir/config"

# Case 2: an upgrade re-run with no --iface/--node-name flags (NODE_NAME/IFACE
# arrive empty, exactly as install.sh's own flag-parsing leaves them unset)
# must default to what a prior install persisted, not fall through to
# hostname/auto-detection as if this were a fresh box.
upgrade_no_flags_dir="$PERSIST_WORK/upgrade-no-flags"
mkdir -p "$upgrade_no_flags_dir"
{
  echo 'NODE_NAME="old-node"'
  echo 'IFACE="eth0"'
} > "$upgrade_no_flags_dir/config"
no_flags_out="$(bash "$PERSIST_CHECK_RUNNER" "$upgrade_no_flags_dir" 1 "" "" 2>&1)"
assert "an upgrade re-run with no --iface/--node-name defaults both to the values persisted at install time, instead of recomputing a fresh hostname/auto-detected interface" \
  "$(printf '%s' "$no_flags_out" | grep -q '^NODE_NAME=old-node$' && printf '%s' "$no_flags_out" | grep -q '^IFACE=eth0$' && echo 1 || echo 0)"

# Case 3: an upgrade re-run with an explicit --iface that DISAGREES with the
# persisted value must refuse loudly and exit non-zero, naming $CONFIG_FILE
# as the file to delete -- the acceptance criterion this bead exists for.
# Silently overriding here is exactly what would rebake a different
# --advertise-address into a live cluster, breaking any kubeconfig already
# distributed off-box.
upgrade_mismatch_dir="$PERSIST_WORK/upgrade-mismatch"
mkdir -p "$upgrade_mismatch_dir"
{
  echo 'NODE_NAME="node-a"'
  echo 'IFACE="eth0"'
} > "$upgrade_mismatch_dir/config"
mismatch_status=0
mismatch_out="$(bash "$PERSIST_CHECK_RUNNER" "$upgrade_mismatch_dir" 1 "node-a" "eth1" 2>&1)" || mismatch_status=$?
assert "an upgrade with a --iface that disagrees with the persisted value is refused loudly (non-zero exit, mentions the persisted 'eth0'), instead of silently rebaking a new --advertise-address into a live cluster" \
  "$([ "$mismatch_status" -ne 0 ] && printf '%s' "$mismatch_out" | grep -qi 'conflicts' && printf '%s' "$mismatch_out" | grep -q 'eth0' && echo 1 || echo 0)"
assert "the --iface mismatch refusal names the exact file to delete (\$STATE_DIR/config), per the operator's decision that this is the only escape hatch (no override flag)" \
  "$(printf '%s' "$mismatch_out" | grep -qF "$upgrade_mismatch_dir/config" && echo 1 || echo 0)"

# Case 3b: the same guard on --node-name -- a distinct if-block in
# install.sh, not exercised by the --iface case above.
upgrade_name_mismatch_dir="$PERSIST_WORK/upgrade-name-mismatch"
mkdir -p "$upgrade_name_mismatch_dir"
{
  echo 'NODE_NAME="node-a"'
  echo 'IFACE="eth0"'
} > "$upgrade_name_mismatch_dir/config"
name_mismatch_status=0
name_mismatch_out="$(bash "$PERSIST_CHECK_RUNNER" "$upgrade_name_mismatch_dir" 1 "node-b" "eth0" 2>&1)" || name_mismatch_status=$?
assert "an upgrade with a --node-name that disagrees with the persisted value is refused loudly (non-zero exit, mentions the persisted 'node-a'), instead of silently rebaking a new kubelet --hostname-override into a live cluster" \
  "$([ "$name_mismatch_status" -ne 0 ] && printf '%s' "$name_mismatch_out" | grep -qi 'conflicts' && printf '%s' "$name_mismatch_out" | grep -q 'node-a' && echo 1 || echo 0)"

# Case 4: an upgrade re-run with an explicit --iface that MATCHES the
# persisted value is not a real mismatch -- it must proceed normally, or
# every upgrade script that always passes --iface explicitly (rather than
# relying on the env-var/no-flags convention) would be refused every time.
upgrade_match_dir="$PERSIST_WORK/upgrade-match"
mkdir -p "$upgrade_match_dir"
{
  echo 'NODE_NAME="node-a"'
  echo 'IFACE="eth0"'
} > "$upgrade_match_dir/config"
match_out="$(bash "$PERSIST_CHECK_RUNNER" "$upgrade_match_dir" 1 "node-a" "eth0" 2>&1)"
assert "an upgrade with an explicit --iface/--node-name that MATCHES the persisted value proceeds normally -- the guard only fires on a genuine mismatch, not on any explicit flag" \
  "$(printf '%s' "$match_out" | grep -q '^NODE_NAME=node-a$' && printf '%s' "$match_out" | grep -q '^IFACE=eth0$' && echo 1 || echo 0)"

# Case 5: a genuinely fresh install (EXISTING_INSTALL=0, no persisted config
# file at all) must never trigger the mismatch guard, even with explicit
# flags passed -- this guard is upgrade-only.
fresh_install_dir="$PERSIST_WORK/fresh-install"
mkdir -p "$fresh_install_dir"
fresh_install_out="$(bash "$PERSIST_CHECK_RUNNER" "$fresh_install_dir" 0 "node-a" "eth0" 2>&1)"
assert "a genuinely fresh install (no persisted config, EXISTING_INSTALL=0) never trips the mismatch guard, even with explicit --iface/--node-name flags -- the guard is upgrade-only" \
  "$(printf '%s' "$fresh_install_out" | grep -q '^NODE_NAME=node-a$' && printf '%s' "$fresh_install_out" | grep -q '^IFACE=eth0$' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Mutation self-check (CLAUDE.md rule 14): prove the --iface refusal assertion
# above would actually catch a reverted fix. Bypass the guard in a scratch
# copy of install.sh and rerun the exact mismatch scenario -- if the guard is
# gone, the mismatched --iface must instead win silently (IFACE=eth1 printed,
# no refusal), which is precisely the silent-override behavior the operator
# rejected in favor of refuse-loud.
# ---------------------------------------------------------------------------
MUTATED_PERSIST_INSTALL="$PERSIST_WORK/install-mutated.sh"
sed 's/elif \[ "\$IFACE" != "\$PERSISTED_IFACE" \]; then/elif false; then/' "$INSTALL" > "$MUTATED_PERSIST_INSTALL"
if diff -q "$INSTALL" "$MUTATED_PERSIST_INSTALL" > /dev/null 2>&1; then
  assert "mutation self-check: the --iface mismatch guard's condition line exists in install.sh to mutate (if this fails, the line was renamed/reshaped and this suite no longer exercises it)" 0
else
  MUTATED_PERSIST_RUNNER="$PERSIST_WORK/persist-check-mutated.sh"
  write_persist_config_check_runner "$MUTATED_PERSIST_INSTALL" "$MUTATED_PERSIST_RUNNER"
  mutated_persist_status=0
  mutated_persist_out="$(bash "$MUTATED_PERSIST_RUNNER" "$upgrade_mismatch_dir" 1 "node-a" "eth1" 2>&1)" || mutated_persist_status=$?
  assert "mutation self-check: with the --iface mismatch guard bypassed, a disagreeing --iface is wrongly allowed to silently win -- proving the refusal test above would fail if this fix were ever reverted" \
    "$([ "$mutated_persist_status" -eq 0 ] && printf '%s' "$mutated_persist_out" | grep -q '^IFACE=eth1$' && echo 1 || echo 0)"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

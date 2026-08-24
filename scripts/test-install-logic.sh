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
# release's binaries instead of failing loud, and `curl | sh` users of a
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

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

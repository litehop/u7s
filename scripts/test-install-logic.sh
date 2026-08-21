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
# iface_filter() -- mirrors install.sh's own default-interface regex. The
# first version of this logic was a BLACKLIST of virtual-interface names
# (docker0/veth*/cni*/br-*/virbr*/flannel*/cali*), which can only ever cover
# the names its author happened to think of. This proves the whitelist that
# replaced it actually discriminates real physical-NIC names from virtual
# ones -- not just that some filter exists (a purely structural grep check
# can't tell "discriminates correctly" from "matches nothing" or "matches
# everything"). Physical-NIC names cover both systemd predictable naming
# (en*/wl*/ww*: eno1, ens33, enp0s3, enp2s0f1, enx<mac>, wlo1, wlp2s0,
# wlx<mac>, wwan0, wwp0s20u4i6) and the legacy eth0 kernel fallback --
# checking our own 5-VM Ubuntu 26.04 Lima fleet (identical template) found
# it split 2/5 enp0s1 vs 3/5 eth0, so eth0 is a real, live case, not just a
# theoretical old-kernel one.
# ---------------------------------------------------------------------------
iface_filter() {
  grep -E '^(en|wl|ww)[a-zA-Z0-9]+$|^eth[0-9]+$'
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

assert_true "install.sh's actual --iface default is wired to this exact whitelist regex, not a hand-duplicated copy that could silently drift out of sync" \
  grep -qF "grep -E '^(en|wl|ww)[a-zA-Z0-9]+\$|^eth[0-9]+\$'" "$INSTALL"

assert_false "(regression guard) install.sh's default --iface no longer relies on the naive 'exclude only lo' blacklist that let any unrecognized virtual interface slip through" \
  grep -qF "grep -v '^lo\$'" "$INSTALL"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

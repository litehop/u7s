#!/usr/bin/env bash
# lima-unrig.sh must remove every rig-written unit that makes an install.sh
# kubelet start with the rig's flags: the kubelet drop-in (its bare ExecStart=
# overrides install.sh's kubelet.service) and kube-proxy.service. If it stops
# removing either, install.sh-path verifications silently run the rig's kubelet
# again and need manual deletion on the VM.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
printf '#!/bin/sh\necho "$*" >> "%s/calls"\n' "$TMP" > "$TMP/bin/limactl"
chmod +x "$TMP/bin/limactl"

PASS=0
FAIL=0
assert() {
  if [ "$2" = 1 ]; then echo "PASS: $1"; PASS=$((PASS + 1)); else echo "FAIL: $1"; FAIL=$((FAIL + 1)); fi
}

PATH="$TMP/bin:$PATH" "$DIR/lima-unrig.sh" --vm vm-x
CALLS="$(cat "$TMP/calls")"
has() { printf '%s' "$CALLS" | grep -qF -- "$1" && echo 1 || echo 0; }

assert "targets the named VM" "$(has 'shell vm-x sudo')"
assert "removes kubelet drop-in (else its ExecStart= hijacks install.sh's kubelet.service)" \
  "$(has '/etc/systemd/system/kubelet.service.d/u7s.conf')"
assert "removes kube-proxy.service (else it keeps programming iptables beside install.sh's stack)" \
  "$(has '/etc/systemd/system/kube-proxy.service')"
assert "stops and disables the rig's kubelet and kube-proxy" \
  "$([ "$(has 'disable --now kube-proxy.service')" = 1 ] && [ "$(has 'disable --now kubelet.service')" = 1 ] && echo 1 || echo 0)"
assert "reloads systemd so removal takes effect" "$(has 'daemon-reload')"

rc=0
PATH="$TMP/bin:$PATH" "$DIR/lima-unrig.sh" >/dev/null 2>&1 || rc=$?
assert "missing --vm is rejected (exit 2) rather than guessing a VM" "$([ "$rc" = 2 ] && echo 1 || echo 0)"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]

#!/usr/bin/env bash
# install.sh-path verifications on a rig VM must never see the rig's kubelet
# drop-in (its bare ExecStart= overrides install.sh's kubelet.service) or
# kube-proxy.service. Covers: lima-unrig.sh removes both; --check fails loudly
# when the drop-in is present; lima-install-test.sh unrigs and checks BEFORE
# running install.sh and never runs install.sh if the check fails.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/drain-grep.sh"

DIR="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
# Fake limactl: logs args; `sudo test -e` fails/succeeds per $TMP/dropin.
cat > "$TMP/bin/limactl" <<EOF
#!/bin/sh
echo "\$*" >> "$TMP/calls"
case "\$*" in
  *"sudo test -e"*) [ -e "$TMP/dropin" ] ;;
esac
EOF
chmod +x "$TMP/bin/limactl"

PASS=0
FAIL=0
assert() {
  if [ "$2" = 1 ]; then echo "PASS: $1"; PASS=$((PASS + 1)); else echo "FAIL: $1"; FAIL=$((FAIL + 1)); fi
}
CALLS=""
has() { printf '%s' "$CALLS" | drain_grep -qF -- "$1" && echo 1 || echo 0; }
line_of() { printf '%s\n' "$CALLS" | grep -nF -- "$1" | sed -n 1p | cut -d: -f1; }
run() { : > "$TMP/calls"; rc=0; PATH="$TMP/bin:$PATH" "$@" >/dev/null 2>"$TMP/err" || rc=$?; CALLS="$(cat "$TMP/calls")"; }

run "$DIR/lima-unrig.sh" --vm vm-x
assert "targets the named VM" "$(has 'shell vm-x sudo')"
assert "removes kubelet drop-in (else its ExecStart= hijacks install.sh's kubelet.service)" \
  "$(has '/etc/systemd/system/kubelet.service.d/u7s.conf')"
assert "removes kube-proxy.service (else it keeps programming iptables beside install.sh's stack)" \
  "$(has '/etc/systemd/system/kube-proxy.service')"
assert "stops and disables the rig's kubelet and kube-proxy" \
  "$([ "$(has 'disable --now kube-proxy.service')" = 1 ] && [ "$(has 'disable --now kubelet.service')" = 1 ] && echo 1 || echo 0)"
assert "reloads systemd so removal takes effect" "$(has 'daemon-reload')"
kcm_pat="$(printf '%s\n' "$CALLS" | sed -n 's/.*"\(\[k\]ube-controller-manager[^"]*\)".*/\1/p' | sed -n 1p)"
matches() { [[ "$1" =~ $kcm_pat ]] && echo 1 || echo 0; }
assert "kills the rig KCM (else it keeps :10257 and install.sh's u7s-kcm cannot bind)" \
  "$(matches '/bin/bash /tmp/x /home/u/.cache/u7s/kcm/kube-controller-manager-1.37.3-linux-arm64 --kubeconfig=/w/kcm-kubeconfig')"
assert "does not kill an installed u7s-kcm (unrig on an --install stack must leave the control plane running)" \
  "$([ -n "$kcm_pat" ] && [ "$(matches '/opt/u7s/bin/kube-controller-manager --kubeconfig=/var/lib/u7s/kcm-kubeconfig --controllers=*')" = 0 ] && echo 1 || echo 0)"
assert "kills the KCM supervisor (else it respawns the KCM that was just killed)" \
  "$(has 'pkill -f "[k]cm-supervisor.sh"')"
assert "stops the signing-key sync loop and removes its mirror dir" \
  "$([ "$(has '[u]7s-kcm-signing-sync')" = 1 ] && [ "$(has 'rm -rf /var/tmp/u7s-kcm-signing')" = 1 ] && echo 1 || echo 0)"
assert "deletes the rig's cni0 bridge (else install.sh's flannel inherits a stale pod CIDR)" \
  "$(has 'ip link delete cni0')"
assert "deletes flannel.1 and the rig flannel CNI conflist and run state" \
  "$([ "$(has 'ip link delete flannel.1')" = 1 ] && [ "$(has '/etc/cni/net.d/10-flannel.conflist')" = 1 ] && [ "$(has 'rm -rf /run/flannel')" = 1 ] && echo 1 || echo 0)"

run "$DIR/lima-unrig.sh"
assert "missing --vm is rejected (exit 2) rather than guessing a VM" "$([ "$rc" = 2 ] && echo 1 || echo 0)"

touch "$TMP/dropin"
run "$DIR/lima-unrig.sh" --vm vm-x --check
assert "--check fails when the rig drop-in is present (reboot-reverts-unrig trap)" "$([ "$rc" = 1 ] && echo 1 || echo 0)"
assert "--check message names the drop-in and the fix" \
  "$(grep -q 'u7s.conf' "$TMP/err" && grep -q 'lima-install-test.sh' "$TMP/err" && echo 1 || echo 0)"
assert "--check removes nothing" "$([ "$(has 'daemon-reload')" = 0 ] && echo 1 || echo 0)"
rm "$TMP/dropin"
run "$DIR/lima-unrig.sh" --vm vm-x --check
assert "--check passes on a clean VM" "$([ "$rc" = 0 ] && echo 1 || echo 0)"

# Entry point: unrig, then guard, then install.sh with the passed args.
run "$DIR/lima-install-test.sh" --vm vm-x -- --tarball /h/t.tgz
u=$(line_of 'daemon-reload'); c=$(line_of 'sudo test -e'); i=$(line_of 'install.sh --tarball /h/t.tgz')
assert "install entry point unrigs automatically, no manual step" "$([ -n "$u" ] && echo 1 || echo 0)"
assert "order is unrig, guard, install.sh (guard must see the post-unrig state)" \
  "$([ -n "$u" ] && [ -n "$c" ] && [ -n "$i" ] && [ "$u" -lt "$c" ] && [ "$c" -lt "$i" ] && echo 1 || echo 0)"

# Guard firing: unrig cannot remove the drop-in (simulated by it persisting) -> abort before install.sh.
touch "$TMP/dropin"
run "$DIR/lima-install-test.sh" --vm vm-x -- --tarball /h/t.tgz
assert "install entry point aborts when the drop-in survives unrig" "$([ "$rc" = 1 ] && echo 1 || echo 0)"
assert "install.sh not invoked after a failed guard" "$([ "$(has 'install.sh')" = 0 ] && echo 1 || echo 0)"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]

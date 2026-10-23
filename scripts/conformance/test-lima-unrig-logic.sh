#!/usr/bin/env bash
# install.sh-path verifications on a rig VM must never see the rig's kubelet
# drop-in (its bare ExecStart= overrides install.sh's kubelet.service) or
# kube-proxy.service. Covers: lima-unrig.sh removes both; --check fails loudly
# when the drop-in is present; lima-install-test.sh unrigs and checks BEFORE
# running install.sh and never runs install.sh if the check fails.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

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
has() { printf '%s' "$CALLS" | grep -qF -- "$1" && echo 1 || echo 0; }
line_of() { printf '%s\n' "$CALLS" | grep -nF -- "$1" | head -1 | cut -d: -f1; }
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

#!/usr/bin/env bash
# A VM cloned from lima-golden boots the golden's frozen copy of lima/kubelet.yaml's provision
# script, so a pin bump never reached clones (the suite then ran a different CRI-O than the
# repo names), and an install-mode VM that rebooted got rig state written over install.sh's.
# Covers: the rig syncs a clone's provision script before first boot, asserts the package pins
# afterwards and fails loud on drift; the provision script writes no kubelet/CNI state.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
LIMA_YAML="$REPO/lima/kubelet.yaml"
FETCH="$REPO/scripts/lib/release-fetch.sh"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/home/.lima/vm-x"
PASS=0
FAIL=0
assert() { if [ "$2" = 1 ]; then echo "PASS: $1"; PASS=$((PASS + 1)); else echo "FAIL: $1"; FAIL=$((FAIL + 1)); fi; }

# Fake limactl: `template yq FILE EXPR` prints FILE; `shell VM dpkg-query ... PKG` answers
# from $TMP/dpkg.<pkg>; everything else is logged.
cat > "$TMP/bin/limactl" <<EOF
#!/bin/sh
echo "\$*" >> "$TMP/calls"
case "\$1 \$2" in
  "template yq") cat "\$3" ;;
  "shell vm-x") for last; do :; done; cat "$TMP/dpkg.\$last" 2>/dev/null; exit 0 ;;
esac
EOF
chmod +x "$TMP/bin/limactl"
export PATH="$TMP/bin:$PATH"

crio_pin="$(lima_yaml_pin "$LIMA_YAML" CRIO_VERSION)"
kubelet_pin="$(lima_yaml_pin "$LIMA_YAML" KUBELET_PKG_VERSION)"
cni_pin="$(sed -n 's/^CNI_PLUGINS_VERSION="\([^"]*\)"$/\1/p' "$FETCH")"
assert "the cri-o and kubelet pins are read from lima/kubelet.yaml's provision script" \
  "$([ -n "$crio_pin" ] && [ -n "$kubelet_pin" ] && echo 1 || echo 0)"

set_installed() { printf '%s' "$1" > "$TMP/dpkg.cri-o"; printf '%s' "$2" > "$TMP/dpkg.kubelet"; printf '%s' "$3" > "$TMP/dpkg.kubernetes-cni"; }
check() { assert_vm_package_pins vm-x "$LIMA_YAML" "$FETCH" 2>"$TMP/err" && echo 0 || echo 1; }

set_installed "$crio_pin" "$kubelet_pin" "${cni_pin}-1.1"
assert "a VM on the pinned cri-o, kubelet and CNI plugins passes (the apt package adds a revision to the plugin version)" \
  "$([ "$(check)" = 0 ] && echo 1 || echo 0)"

set_installed "1.37.1-3.1" "$kubelet_pin" "${cni_pin}-1.1"
assert "a clone still on the golden's older cri-o fails loud, naming it (the suite would otherwise silently run another runtime than the repo pins)" \
  "$([ "$(check)" = 1 ] && grep -q "cri-o '1.37.1-3.1' but the rig pins '$crio_pin'" "$TMP/err" && echo 1 || echo 0)"

set_installed "$crio_pin" "9.9.9-1.1" "${cni_pin}-1.1"
assert "a kubelet package that differs from the pin fails loud" \
  "$([ "$(check)" = 1 ] && grep -q "kubelet '9.9.9-1.1'" "$TMP/err" && echo 1 || echo 0)"

set_installed "$crio_pin" "$kubelet_pin" "0.0.1-1.1"
assert "CNI plugins at another version than install tarballs ship fail loud (rig CNI binaries must be install's)" \
  "$([ "$(check)" = 1 ] && grep -q 'kubernetes-cni' "$TMP/err" && echo 1 || echo 0)"

rm -f "$TMP/dpkg.cri-o"
assert "a missing package fails loud rather than passing as empty" \
  "$([ "$(check)" = 1 ] && grep -q 'not installed' "$TMP/err" && echo 1 || echo 0)"

# --- provision sync -----------------------------------------------------------------------
printf 'golden-script' > "$TMP/golden.yaml"
printf 'current-script' > "$TMP/current.yaml"
cp "$TMP/golden.yaml" "$TMP/home/.lima/vm-x/lima.yaml"
: > "$TMP/calls"
HOME="$TMP/home" lima_sync_provision vm-x "$TMP/current.yaml" >/dev/null 2>&1 || true
assert "a clone whose provision differs from lima/kubelet.yaml is edited to the current one before it boots" \
  "$(grep -q '^edit vm-x --tty=false --set .provision = ' "$TMP/calls" && echo 1 || echo 0)"
: > "$TMP/calls"
cp "$TMP/current.yaml" "$TMP/home/.lima/vm-x/lima.yaml"
HOME="$TMP/home" lima_sync_provision vm-x "$TMP/current.yaml" >/dev/null 2>&1
assert "an up-to-date VM is not edited (no needless instance rewrite)" \
  "$(grep -q '^edit' "$TMP/calls" && echo 0 || echo 1)"

# --- structure ----------------------------------------------------------------------------
LIMA_START="$DIR/lima-start.sh"
BRINGUP="$DIR/install-bringup.sh"
for f in "$LIMA_START" "$BRINGUP"; do
  assert "$(basename "$f") syncs the clone's provision script before starting it" \
    "$([ "$(grep -c 'lima_sync_provision' "$f")" -ge 2 ] && echo 1 || echo 0)"
  assert "$(basename "$f") asserts the package pins once the VM is up" \
    "$(grep -qF 'assert_vm_package_pins' "$f" && echo 1 || echo 0)"
  assert "$(basename "$f") clones without --start so the sync lands before the first boot" \
    "$(grep -q -e '--start' "$f" && echo 0 || echo 1)"
done

# --- provision script writes no rig kubelet/CNI state -------------------------------------
SCRIPT="$(cat "$LIMA_YAML")"
no() { printf '%s' "$SCRIPT" | grep -v '^ *#' | grep -qF -- "$1" && echo 0 || echo 1; }
assert "provision (runs every boot) does not rewrite the kubelet config" "$(no '/etc/kubelet-config.yaml')"
assert "provision (runs every boot) does not write the kubelet drop-in over install.sh's kubelet.service" "$(no 'kubelet.service.d/u7s.conf')"
assert "provision (runs every boot) does not re-enable the CRI-O bridge conflist ahead of flannel's" "$(no '10-crio-bridge.conflist')"
assert "provision does not undo install.sh's enabled kubelet.service on reboot" \
  "$(printf '%s' "$SCRIPT" | grep -qF '[ -d /var/lib/u7s ] || systemctl disable kubelet' && echo 1 || echo 0)"
assert "no comment claims a golden clone re-runs this file's script" \
  "$(grep -qi 'incl. golden clones' "$LIMA_YAML" && echo 0 || echo 1)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]

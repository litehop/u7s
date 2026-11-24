#!/usr/bin/env bash
# The host rig must run the node config install.sh writes, so a spec that passes on the rig
# also passes on a real install. Covers: the rig kubelet config is install.sh's
# write_kubelet_config_yaml output plus exactly the recorded rig-only overlay, and the rig's
# CRI-O memory drop-in, br_netfilter and persisted sysctls are install.sh's own node-prep
# block replayed (IPv6 forwarding included for dual-stack).
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
INSTALL_SH="$REPO/scripts/install.sh"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
assert() { if [ "$2" = 1 ]; then ok "$1"; else bad "$1"; fi; }
has_line() { grep -qxF -- "$2" "$1" && echo 1 || echo 0; }

# Stubs: systemctl logs and reports systemd-resolved active; modprobe/sysctl log only.
cat > "$TMP/bin/systemctl" <<EOF
#!/bin/sh
echo "systemctl \$*" >> "$TMP/calls"
[ "\$1" != is-active ] || [ "\${FAKE_RESOLVED:-1}" = 1 ]
EOF
for c in modprobe sysctl; do
  printf '#!/bin/sh\necho "%s $*" >> "%s/calls"\n' "$c" "$TMP" > "$TMP/bin/$c"
done
chmod +x "$TMP/bin/"*

# Runs a generated in-VM script locally with /etc paths redirected under $2.
run_in_fake_vm() {
  local script="$1" root="$2"
  mkdir -p "$root"
  sed -e "s#/etc/#$root/etc/#g" -e "s#/var/lib/#$root/var/lib/#g" <<<"$script" > "$root/run.sh"
  mkdir -p "$root/etc/crio/crio.conf.d" "$root/etc/modules-load.d" "$root/etc/sysctl.d"
  : > "$TMP/calls"
  PATH="$TMP/bin:$PATH" bash "$root/run.sh"
}

# --- kubelet config -----------------------------------------------------------------------
# Same fake root for both renders so the redirected paths compare equal.
RIG="$TMP/rig"
RIG_CFG="$RIG/etc/u7s-rig/kubelet-config.yaml"
PLAIN_SCRIPT="$(printf 'set -euo pipefail\nSTATE_DIR=/etc/u7s-rig\nCLUSTER_DNS=10.96.0.10\nmkdir -p /etc/u7s-rig\n%s\nwrite_kubelet_config_yaml 0\n' "$(install_sh_function write_kubelet_config_yaml "$INSTALL_SH")")"
run_in_fake_vm "$PLAIN_SCRIPT" "$RIG" >/dev/null
PLAIN_CFG="$TMP/plain-kubelet-config.yaml"
cp "$RIG_CFG" "$PLAIN_CFG"
run_in_fake_vm "$(rig_kubelet_config_script 10.96.0.10 "$INSTALL_SH")" "$RIG" >/dev/null

EXTRA="$(grep -vxFf "$PLAIN_CFG" "$RIG_CFG" || true)"
assert "rig kubelet config differs from install.sh's own output only by the recorded overlay (a hand-written rig config would diverge: the rig would pass specs a real install cannot)" \
  "$([ "$EXTRA" = "$RIG_KUBELET_OVERLAY" ] && echo 1 || echo 0)"
assert "install.sh's own lines are all present in the rig config (nothing dropped)" \
  "$([ -z "$(grep -vxFf "$RIG_CFG" "$PLAIN_CFG" || true)" ] && echo 1 || echo 0)"
assert "rig staticPodPath is install.sh's /etc/u7s/static-pods, not a rig-private /tmp dir" \
  "$(has_line "$RIG_CFG" "staticPodPath: $RIG/etc/u7s/static-pods")"
assert "rig carries clientCAFile in the config (as install does), not via a --client-ca-file flag" \
  "$(grep -qE '^    clientCAFile: .*/ca-bundle.pem$' "$RIG_CFG" && echo 1 || echo 0)"
assert "rig kubelet rotates its client cert and bootstraps its serving cert like install (else the node cert expires, logs/exec break)" \
  "$([ "$(has_line "$RIG_CFG" 'rotateCertificates: true')$(has_line "$RIG_CFG" 'serverTLSBootstrap: true')" = 11 ] && echo 1 || echo 0)"
assert "resolvConf follows systemd-resolved (CoreDNS would otherwise forward to the 127.0.0.53 stub and loop)" \
  "$(has_line "$RIG_CFG" 'resolvConf: /run/systemd/resolve/resolv.conf')"
assert "the single rig-only feature gate is not baked into the rendered config (merged by set-kubelet-featuregate.sh and recorded in run-meta)" \
  "$(grep -q 'AtomicWriteVolumeUserFields' "$RIG_CFG" && echo 0 || echo 1)"

# Derivation, not copy: a key added to install.sh's function must reach the rig.
MUTATED="$TMP/install-mutated.sh"
sed 's/^rotateCertificates: true$/rotateCertificates: true\nshutdownGracePeriod: 7s/' "$INSTALL_SH" > "$MUTATED"
run_in_fake_vm "$(rig_kubelet_config_script 10.96.0.10 "$MUTATED")" "$TMP/mutated" >/dev/null
assert "a key added to install.sh's kubelet config reaches the rig without a rig edit (the rig derives its config, so it cannot drift)" \
  "$(has_line "$TMP/mutated/etc/u7s-rig/kubelet-config.yaml" 'shutdownGracePeriod: 7s')"

assert "rendering fails loud when install.sh no longer defines write_kubelet_config_yaml" \
  "$(rig_kubelet_config_script 10.96.0.10 /dev/null 2>/dev/null && echo 0 || echo 1)"

for knob in serializeImagePulls=false maxParallelImagePulls=10 registryPullQPS=0 "featureGates.${RIG_KUBELET_GATE}=true"; do
  assert "rig-only kubelet knob $knob is recorded in the run-meta of host-rig archives" \
    "$(write_run_meta "$TMP/meta-rig" host-rig && grep -qF "$knob" "$TMP/meta-rig/run-meta" && echo 1 || echo 0)"
done
write_run_meta "$TMP/meta-inst" install
assert "install archives record no rig kubelet overlay (install-mode kubelet runs install.sh's config unmodified)" \
  "$(grep -q rig_only_kubelet_config "$TMP/meta-inst/run-meta" && echo 0 || echo 1)"

# --- node prep ----------------------------------------------------------------------------
V4="$TMP/v4"
run_in_fake_vm "$(rig_node_prep_script 0 "$INSTALL_SH")" "$V4" >/dev/null
assert "rig writes install.sh's CRI-O memory drop-in (stream_idle_timeout)" \
  "$(grep -qxF 'stream_idle_timeout = "5m"' "$V4/etc/crio/crio.conf.d/10-memory.conf" && echo 1 || echo 0)"
assert "rig persists br_netfilter and its bridge sysctls (a reboot would otherwise break kube-proxy DNAT until lima-start.sh re-ran)" \
  "$([ "$(has_line "$V4/etc/sysctl.d/u7s-br-netfilter.conf" 'net.bridge.bridge-nf-call-iptables = 1')$(has_line "$V4/etc/modules-load.d/u7s-br-netfilter.conf" br_netfilter)" = 11 ] && echo 1 || echo 0)"
assert "rig persists net.ipv4.ip_forward" \
  "$(has_line "$V4/etc/sysctl.d/u7s-ip-forward.conf" 'net.ipv4.ip_forward = 1')"
assert "single-stack rig writes no IPv6 forwarding sysctl (same as install)" \
  "$([ -e "$V4/etc/sysctl.d/u7s-ipv6-forwarding.conf" ] && echo 0 || echo 1)"
assert "first run restarts CRI-O so the new drop-in takes effect" \
  "$(grep -qxF 'systemctl restart crio' "$TMP/calls" && echo 1 || echo 0)"
run_in_fake_vm "$(rig_node_prep_script 0 "$INSTALL_SH")" "$V4" >/dev/null
assert "an unchanged drop-in does not restart CRI-O again (a restart on every lima-start would bounce running pods' runtime)" \
  "$(grep -qxF 'systemctl restart crio' "$TMP/calls" && echo 0 || echo 1)"

V6="$TMP/v6"
run_in_fake_vm "$(rig_node_prep_script 1 "$INSTALL_SH")" "$V6" >/dev/null
assert "dual-stack rig forwards IPv6 (without it the node drops routed IPv6 pod/Service packets)" \
  "$(has_line "$V6/etc/sysctl.d/u7s-ipv6-forwarding.conf" 'net.ipv6.conf.all.forwarding = 1')"

BROKEN="$TMP/install-broken.sh"
grep -vF 'sysctl --system >/dev/null' "$INSTALL_SH" > "$BROKEN"
assert "node prep fails loud when install.sh's block markers move (silent no-op would leave the rig unprepared)" \
  "$(rig_node_prep_script 0 "$BROKEN" >/dev/null 2>&1 && echo 0 || echo 1)"

# --- structure: the rig no longer carries its own copies ------------------------------------
LIMA_START="$DIR/lima-start.sh"
LIMA_YAML="$REPO/lima/kubelet.yaml"
assert "lima-start.sh applies install.sh's node-prep block" \
  "$(grep -qF 'rig_node_prep_script' "$LIMA_START" && echo 1 || echo 0)"
assert "lima-start.sh has no private ip_forward/bridge sysctl -w copies left" \
  "$(grep -qE 'sysctl -w' "$LIMA_START" && echo 0 || echo 1)"
assert "lima-start.sh renders the kubelet config with install.sh's function" \
  "$(grep -qF 'rig_kubelet_config_script' "$LIMA_START" && echo 1 || echo 0)"
assert "kubelet drop-in has no --client-ca-file flag (clientCAFile is in the config)" \
  "$(grep -qF -- '--client-ca-file' "$LIMA_START" && echo 0 || echo 1)"
assert "provision script no longer writes a kubelet config" \
  "$(grep -qF 'kubelet-config.yaml' "$LIMA_YAML" && echo 0 || echo 1)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]

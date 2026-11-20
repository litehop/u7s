#!/usr/bin/env bash
# Runs as root ON a VM (`limactl shell <vm> sudo bash -s < this-file`). Stops, disables and
# removes the u7s units scripts/install.sh leaves behind, and reports each one it found.
# The host rig runs its own apiserver, KCM and scheduler, so a leftover native u7s-kcm
# collides on :10257 and a leftover u7s-apiserver races it for node podCIDRs ("node has no
# IPv4 podCIDR"). Owns the single list of install.sh's u7s units.
#
# kubelet.service is shared with the rig: install.sh's copy in the unit dir is removed only
# when it still requires u7s-apiserver.service (otherwise it would fail to start once that
# unit is gone), which exposes the distro unit the rig's drop-in configures.
set -u
unit_dir="${U7S_UNIT_DIR:-/etc/systemd/system}"
units="u7s-kcm-restart.path u7s-kcm-restart.service u7s-kcm.service u7s-apiserver.service u7s-scheduler.service"
found=""
for u in $units; do
  if systemctl is-active --quiet "$u" 2>/dev/null || systemctl is-enabled --quiet "$u" 2>/dev/null \
     || [ -e "$unit_dir/$u" ]; then
    found="$found $u"
  fi
  systemctl disable --now "$u" 2>/dev/null || true
  rm -f "$unit_dir/$u"
done
rm -rf "$unit_dir/u7s-apiserver.service.d"
if grep -qs 'u7s-apiserver.service' "$unit_dir/kubelet.service"; then
  found="$found kubelet.service"
  systemctl stop kubelet.service 2>/dev/null || true
  rm -f "$unit_dir/kubelet.service"
fi
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true
if [ -n "$found" ]; then
  echo "[native-units] stopped, disabled and removed leftover native u7s units:$found"
else
  echo "[native-units] no leftover native u7s units"
fi

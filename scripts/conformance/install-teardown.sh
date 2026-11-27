#!/usr/bin/env bash
# Returns a VM that ran install.sh (run-all.sh --install) to a state the host rig can reuse:
# every u7s systemd unit is stopped, disabled and removed, install state and pod workloads
# are wiped, and the host-side apiserver tunnel is reaped. Without this, u7s-apiserver,
# u7s-kcm and u7s-kcm-restart.path keep running on the VM and the next host-rig bring-up
# fights them (e.g. "node has no IPv4 podCIDR").
#
# Deleting the VM (scripts/conformance/reset.sh --vm <vm> --workdir <workdir>) is the
# cleaner alternative; use this when the VM must be kept.
#
# Usage: scripts/conformance/install-teardown.sh --vm <name> [--workdir <path>]
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

VM_NAME="${U7S_VM_NAME:-lima-node}"
WORKDIR="$PWD/temp/u7s"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm) VM_NAME="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ -f "$WORKDIR/install-tunnel.pid" ]; then
  read -r pid port < "$WORKDIR/install-tunnel.pid" || true
  if is_install_tunnel_pid "$pid" "$port"; then kill "$pid" 2>/dev/null || true; fi
  rm -f "$WORKDIR/install-tunnel.pid"
fi
# The install kubeconfig points at a CA that no longer exists; the host rig mints its own.
rm -f "$WORKDIR/kubeconfig" "$WORKDIR/install-tunnel.log"

echo "[install-teardown] stopping and removing u7s units on $VM_NAME"
limactl shell "$VM_NAME" sudo bash -s < "$DIR/clear-native-units.sh"
# kubelet.service is removed unconditionally on purpose: install.sh's unit runs against
# /var/lib/u7s, which this script wipes, and the rig writes its own (rig_kubelet_unit_script)
# on the next bring-up. The distro package's unit lives in /usr/lib, so it is untouched.
# A legacy rig's kube-proxy.service is removed too: left behind it makes the VM probe as rig
# state, so the next run-all.sh --install would unrig (and wipe the pods of) a torn-down VM.
limactl shell "$VM_NAME" sudo bash -c '
  set -u
  systemctl disable --now kubelet.service 2>/dev/null || true
  systemctl disable --now kube-proxy.service 2>/dev/null || true
  rm -f '"$RIG_STATE_LEGACY_UNIT"'
  if command -v crictl >/dev/null 2>&1; then crictl rmp -fa >/dev/null 2>&1 || true; fi
  rm -f /etc/systemd/system/kubelet.service
  rm -rf /etc/systemd/system/kubelet.service.d
  systemctl daemon-reload
  systemctl reset-failed 2>/dev/null || true
  findmnt -rn -o TARGET | grep -e "^/var/lib/kubelet/" -e "^/run/netns/" | sort -r | xargs -r umount -l 2>/dev/null || true
  rm -rf /var/lib/u7s /etc/u7s /var/lib/kubelet /run/flannel
  rm -f /etc/cni/net.d/10-flannel.conflist
  ip link delete flannel.1 2>/dev/null || true
  ip link delete cni0 2>/dev/null || true
  for ipt in iptables ip6tables; do
    "$ipt-save" 2>/dev/null | grep -v -e "KUBE-" -e "FLANNEL" -e "CNI-" | "$ipt-restore" 2>/dev/null || true
  done
  leftovers=$(systemctl list-units --all --plain --no-legend "u7s-*" | awk "{print \$1}")
  [ -z "$leftovers" ] || { echo "units still present: $leftovers" >&2; exit 1; }
  rm -f '"$INSTALL_STATE_MARKER"'
'
echo "[install-teardown] done: $VM_NAME has no u7s units; run the host rig with run-all.sh --stack-only"

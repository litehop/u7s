#!/usr/bin/env bash
# Removes the conformance rig's own systemd units from a Lima VM so a
# scripts/install.sh-path test starts from a node the rig never configured.
#
# lima-start.sh writes /etc/systemd/system/kubelet.service.d/u7s.conf, whose bare
# `ExecStart=` reset replaces the ExecStart of the kubelet.service install.sh
# writes with the rig's flags/kubeconfig; lima-start.sh also installs
# kube-proxy.service. install.sh does not know about either.
#
# Do not run this by hand before install.sh tests: use lima-install-test.sh,
# which unrigs, verifies, and runs install.sh in one step so a reboot cannot
# revert the cleanup in between.
#
# Usage: scripts/conformance/lima-unrig.sh --vm <name> [--check]
#   --check   remove nothing; exit 1 if the rig drop-in is present
set -euo pipefail

VM_NAME=""
CHECK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --vm) VM_NAME="$2"; shift 2 ;;
    --check) CHECK=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$VM_NAME" ] || { echo "usage: $0 --vm <name> [--check]" >&2; exit 2; }

if [ "$CHECK" = 1 ]; then
  if limactl shell "$VM_NAME" sudo test -e /etc/systemd/system/kubelet.service.d/u7s.conf; then
    echo "error: rig kubelet drop-in /etc/systemd/system/kubelet.service.d/u7s.conf is present on $VM_NAME;" >&2
    echo "       its ExecStart= overrides install.sh's kubelet. Run scripts/conformance/lima-install-test.sh (a reboot re-creates the drop-in)." >&2
    exit 1
  fi
  exit 0
fi

limactl shell "$VM_NAME" sudo bash -c '
  # 04-start-kcm.sh runs KCM as a setsid supervisor (which respawns it) plus a signing-key
  # sync loop, outside systemd; left alive, KCM holds :10257 and the installed u7s-kcm cannot start its own.
  # The [x] bracket keeps each pattern from matching this shell'\''s own command line.
  pkill -f "[k]cm-supervisor.sh" || true
  pkill -f "[u]7s-kcm-signing-sync" || true
  # The rig runs the cached versioned binary (kube-controller-manager-<ver>-linux-<arch>); the installed
  # u7s-kcm runs the unversioned $BIN_DIR/kube-controller-manager and must survive.
  pkill -f "[k]ube-controller-manager-[0-9]" || true
  rm -rf /var/tmp/u7s-kcm-signing
  systemctl disable --now kube-proxy.service 2>/dev/null || true
  systemctl disable --now kubelet.service 2>/dev/null || true
  # Runtime-wide: unrig is only for rig VMs, never a node with workloads that must survive.
  # The rig'\''s flannel pods and CNI state (cni0 keeps the rig'\''s pod CIDR; the installed stack needs its own).
  if command -v crictl >/dev/null 2>&1; then crictl rmp -fa >/dev/null 2>&1 || true; fi
  ip link delete cni0 2>/dev/null || true
  ip link delete flannel.1 2>/dev/null || true
  rm -rf /run/flannel
  rm -f /etc/cni/net.d/10-flannel.conflist
  rm -f /etc/systemd/system/kube-proxy.service /etc/systemd/system/kubelet.service.d/u7s.conf
  rmdir /etc/systemd/system/kubelet.service.d 2>/dev/null || true
  systemctl daemon-reload
'

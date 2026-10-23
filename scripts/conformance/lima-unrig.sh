#!/usr/bin/env bash
# Removes the conformance rig's own systemd units from a Lima VM so a
# scripts/install.sh-path test starts from a node the rig never configured.
#
# lima-start.sh (and lima/kubelet.yaml's provision script) write
# /etc/systemd/system/kubelet.service.d/u7s.conf, whose bare `ExecStart=`
# reset replaces the ExecStart of the kubelet.service install.sh writes with the
# rig's flags/kubeconfig; lima-start.sh also installs kube-proxy.service. Neither
# is ever removed by the rig, and install.sh does not know about them.
#
# Run this before any install.sh test on a rig VM. Re-running run-all.sh /
# lima-start.sh against the VM re-creates them (and a VM reboot re-runs the
# provision script, which rewrites the kubelet drop-in).
#
# Usage: scripts/conformance/lima-unrig.sh --vm <name>
set -euo pipefail

VM_NAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --vm) VM_NAME="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$VM_NAME" ] || { echo "usage: $0 --vm <name>" >&2; exit 2; }

limactl shell "$VM_NAME" sudo bash -c '
  systemctl disable --now kube-proxy.service 2>/dev/null || true
  systemctl disable --now kubelet.service 2>/dev/null || true
  rm -f /etc/systemd/system/kube-proxy.service /etc/systemd/system/kubelet.service.d/u7s.conf
  rmdir /etc/systemd/system/kubelet.service.d 2>/dev/null || true
  systemctl daemon-reload
'

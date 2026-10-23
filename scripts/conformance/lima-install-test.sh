#!/usr/bin/env bash
# Runs scripts/install.sh inside a rig Lima VM from a node the rig never
# configured: unrigs (lima-unrig.sh), fails fast if the rig kubelet drop-in is
# still present, then runs the checkout's install.sh as root. ~ is mounted in
# the VM, so --tarball paths under it resolve unchanged.
#
# Usage: scripts/conformance/lima-install-test.sh --vm <name> [-- <install.sh args>]
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
VM_NAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --vm) VM_NAME="$2"; shift 2 ;;
    --) shift; break ;;
    *) echo "unknown argument: $1 (install.sh args go after --)" >&2; exit 2 ;;
  esac
done
[ -n "$VM_NAME" ] || { echo "usage: $0 --vm <name> [-- <install.sh args>]" >&2; exit 2; }

"$DIR/lima-unrig.sh" --vm "$VM_NAME"
"$DIR/lima-unrig.sh" --vm "$VM_NAME" --check
exec limactl shell "$VM_NAME" sudo bash "$DIR/../install.sh" "$@"

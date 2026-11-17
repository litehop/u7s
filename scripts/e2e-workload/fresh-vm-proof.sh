#!/usr/bin/env bash
# Fresh-VM proof: brand-new GCP Spot VM -> install.sh from a published x86_64 release
# tarball -> csi-hostpath v1.17.1 -> scripts/e2e-workload/wordpress-smoke.sh, using only
# committed artifacts. The VM is deleted on exit.
#
# Usage: fresh-vm-proof.sh --tag TAG [--install-sh PATH] [--machine-type TYPE] [--keep]
#   --tag           release tag whose x86_64 tarball is installed (required)
#   --install-sh    install.sh to run on the VM (default: scripts/install.sh of this checkout)
#   --machine-type  default e2-standard-2 (MariaDB + WordPress do not fit in 1 GiB)
#   --keep          do not delete the VM on exit
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VPS="$ROOT/scripts/gcp/vps.sh"
TAG=""
INSTALL_SH="$ROOT/scripts/install.sh"
MACHINE_TYPE="e2-standard-2"
KEEP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --install-sh) INSTALL_SH="$2"; shift 2 ;;
    --machine-type) MACHINE_TYPE="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[[ -n "$TAG" ]] || { echo "error: --tag is required" >&2; exit 1; }
[[ -f "$INSTALL_SH" ]] || { echo "error: $INSTALL_SH not found" >&2; exit 1; }

VM="u7s-fresh-proof-$(date +%s)"
TARBALL_URL="https://github.com/litehop/u7s/releases/download/$TAG/u7s-$TAG-x86_64-unknown-linux-gnu.tar.gz"
BUNDLE="$(mktemp -d)"

cleanup() {
  rm -rf "$BUNDLE"
  if [[ "$KEEP" -eq 0 ]]; then "$VPS" down "$VM" || echo "WARN: failed to delete $VM" >&2; fi
}
trap cleanup EXIT

vm() { "$VPS" ssh "$VM" -- "$@"; }

echo "== creating $VM ($MACHINE_TYPE) =="
"$VPS" up --machine-type "$MACHINE_TYPE" "$VM"

echo "== waiting for ssh =="
for _ in $(seq 1 30); do vm true >/dev/null 2>&1 && break; sleep 10; done
vm true

echo "== VM facts =="
vm 'uname -r; . /etc/os-release; echo "$PRETTY_NAME"'
# shellcheck source=../gcp/lib.sh
(. "$ROOT/scripts/gcp/lib.sh"; gcloud compute disks describe "$VM" --zone="$(gcp_zone)" --format='value(sourceImage)')

echo "== staging committed artifacts (git archive HEAD) =="
git -C "$ROOT" archive --prefix=u7s/ -o "$BUNDLE/repo.tar" HEAD
cp "$INSTALL_SH" "$BUNDLE/install.sh"
"$VPS" scp "$BUNDLE/repo.tar" "$BUNDLE/install.sh" "$VM:"
vm 'tar xf repo.tar'

echo "== install.sh --tarball-url $TARBALL_URL =="
vm "sudo bash ./install.sh --tarball-url '$TARBALL_URL'"

echo "== csi-hostpath v1.17.1 =="
vm 'git clone --depth 1 --branch v1.17.1 https://github.com/kubernetes-csi/csi-driver-host-path.git'
# deploy.sh's snapshotclass step hard-fails without VolumeSnapshot CRDs (documented as harmless).
vm 'cd csi-driver-host-path/deploy/kubernetes-latest && sudo env KUBECONFIG=/var/lib/u7s/kubeconfig ./deploy.sh' || echo "(deploy.sh nonzero: snapshotclass without CRDs is expected)"

echo "== wordpress-smoke.sh =="
vm 'cd u7s && sudo env PATH="$PATH" scripts/e2e-workload/wordpress-smoke.sh --kubeconfig /var/lib/u7s/kubeconfig'

echo "== final pod status =="
vm 'sudo kubectl --kubeconfig /var/lib/u7s/kubeconfig get pods -A -o wide'

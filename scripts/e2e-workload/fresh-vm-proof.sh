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

# shellcheck source=../gcp/lib.sh
. "$ROOT/scripts/gcp/lib.sh"
# shellcheck source=../release-gate/backend.sh
BACKEND=gcp
. "$ROOT/scripts/release-gate/backend.sh"
gcp_require_config

VM="u7s-fresh-proof-$(date +%s)"
TARBALL_URL="https://github.com/litehop/u7s/releases/download/$TAG/u7s-$TAG-x86_64-unknown-linux-gnu.tar.gz"
BUNDLE="$(mktemp -d)"

cleanup() {
  local rc=$?
  trap - EXIT
  rm -rf "$BUNDLE"
  if [[ "$KEEP" -eq 0 ]] && ! "$VPS" down "$VM"; then
    echo "ERROR: failed to delete $VM; it is still running and billing, delete it manually" >&2
    [[ "$rc" -ne 0 ]] || rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

vm() { "$VPS" ssh "$VM" -- "$@"; }

echo "== creating $VM ($MACHINE_TYPE) =="
"$VPS" up --machine-type "$MACHINE_TYPE" "$VM"

echo "== waiting for ssh =="
for _ in $(seq 1 30); do vm true >/dev/null 2>&1 && break; sleep 10; done
vm true

echo "== VM facts =="
vm 'uname -r; . /etc/os-release; echo "$PRETTY_NAME"'
PLATFORM="$(vm_platform "$VM")" || { echo "error: could not record the image and kernel of $VM; a PASS without a platform is not evidence" >&2; exit 1; }
echo "platform: $PLATFORM"

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
DEPLOY_OUT="$BUNDLE/deploy.out"
if ! vm 'cd csi-driver-host-path/deploy/kubernetes-latest && sudo env KUBECONFIG=/var/lib/u7s/kubeconfig ./deploy.sh' 2>&1 | tee "$DEPLOY_OUT"; then
  grep -q 'no matches for kind "VolumeSnapshotClass"' "$DEPLOY_OUT" \
    || { echo "error: deploy.sh failed for a reason other than the expected missing-VolumeSnapshotClass-CRD error" >&2; exit 1; }
  echo "(deploy.sh nonzero: snapshotclass without CRDs is expected)"
fi

echo "== wordpress-smoke.sh =="
vm 'cd u7s && sudo env PATH="$PATH" scripts/e2e-workload/wordpress-smoke.sh --kubeconfig /var/lib/u7s/kubeconfig'

echo "== final pod status =="
vm 'sudo kubectl --kubeconfig /var/lib/u7s/kubeconfig get pods -A -o wide'

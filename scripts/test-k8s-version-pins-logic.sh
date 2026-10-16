#!/usr/bin/env bash
# The kubelet + kube-controller-manager in the release tarball must be the
# same Kubernetes patch version conformance (e2e matrix, rig) tests against;
# otherwise users run a version nobody validated. Grep-based comparison of
# the pins that define the shipped/primary version.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
FAIL=0

check() {
  local label="$1" want="$2" got="$3"
  if [ -n "$got" ] && [ "$want" = "$got" ]; then
    echo "PASS: $label = $want"
  else
    echo "FAIL: $label is '${got:-<not found>}', tarball ships '$want' -- pins drifted; bump them together"
    FAIL=1
  fi
}

tarball="$(sed -n 's/^K8S_VERSION="\([0-9.]*\)"$/\1/p' "$REPO/scripts/build-release-tarball.sh")"
minor="${tarball%.*}"

version_crate="$(sed -n 's/^pub const K8S_VERSION: &str = "\([0-9.]*\)";$/\1/p' "$REPO/crates/version/src/lib.rs")"
check "crates/version K8S_VERSION (reported by /version)" "$tarball" "$version_crate"

matrix_newest="$(grep -E '^\s*k8s: \[' "$REPO/.github/workflows/e2e-focus.yaml" \
  | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1)"
check "e2e-focus matrix newest entry" "$tarball" "$matrix_newest"

kcm_default="$(sed -n 's/^DEFAULT_VERSION="\([0-9.]*\)"$/\1/p' "$REPO/scripts/conformance/04-start-kcm.sh")"
check "04-start-kcm.sh DEFAULT_VERSION" "$tarball" "$kcm_default"

kubelet_pkg="$(sed -n 's/^ *KUBELET_PKG_VERSION="\([0-9.]*\)-.*"$/\1/p' "$REPO/lima/kubelet.yaml")"
check "lima/kubelet.yaml KUBELET_PKG_VERSION" "$tarball" "$kubelet_pkg"

crio_pkg="$(sed -n 's/^ *CRIO_VERSION="\([0-9]*\.[0-9]*\)\..*"$/\1/p' "$REPO/lima/kubelet.yaml")"
check "lima/kubelet.yaml CRIO_VERSION minor" "$minor" "$crio_pkg"

install_crio="$(grep -oE 'isv:/cri-o:/stable:/v[0-9]+\.[0-9]+/' "$REPO/scripts/install.sh" | sort -u | sed 's#.*:/v\(.*\)/#\1#')"
check "install.sh CRI-O repo minor" "$minor" "$install_crio"

exit "$FAIL"

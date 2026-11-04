#!/usr/bin/env bash
# Builds the u7s release tarball for linux/x86_64: cargo-builds
# u7s-apiserver + u7s-scheduler for x86_64-unknown-linux-gnu, downloads the
# matching kubelet + kube-controller-manager + kubectl from dl.k8s.io (checksum- and
# cosign-verified; the .sig/.cert ship alongside) plus the CNI plugins CRI-O and
# flannel call (SHA-256 pinned below), and packages them into the layout scripts/install.sh
# expects (it finds each binary by name anywhere in the extracted tree, so
# internal layout is not load-bearing --
# docs/decisions/upstream-component-shipping-shape.md).
#
# x86_64 only for now (operator direction, YAGNI-first) -- aarch64 is
# deliberately deferred until there's real demand, not built speculatively.
#
# Called by .github/workflows/release-tarball.yaml; also runnable locally
# for manual reproduction, e.g.:
#   scripts/build-release-tarball.sh v0.1.0
#
# Requires: cargo/rustup (with the x86_64-unknown-linux-gnu target
# installable), curl, sha256sum, tar, cosign.
set -euo pipefail

# Same Kubernetes version pinned elsewhere in this project (e2e-focus.yaml's
# matrix, scripts/conformance/04-start-kcm.sh, lima/kubelet.yaml's CRI-O repo,
# install.sh's CRI-O repo); scripts/test-k8s-version-pins-logic.sh enforces it.
K8S_VERSION="1.37.1"
TARGET="x86_64-unknown-linux-gnu"
K8S_ARCH="amd64"

if [ $# -ne 1 ]; then
  echo "Usage: $0 <version>" >&2
  echo "  e.g.: $0 v0.1.0" >&2
  exit 1
fi

VERSION="$1"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/dist"
STAGE_NAME="u7s-${VERSION}-${TARGET}"
WORK_DIR="$(mktemp -d)"
STAGE_DIR="$WORK_DIR/$STAGE_NAME"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$STAGE_DIR" "$OUT_DIR"

echo "==> Building u7s-apiserver + u7s-scheduler for $TARGET" >&2
rustup target add "$TARGET" >&2
# Stamped into --version and /version (crates/version); the tag's leading 'v'
# is dropped so gitVersion reads v<k8s>+u7s-<release>.
U7S_RELEASE="${VERSION#v}" \
U7S_GIT_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)" \
U7S_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  cargo build --locked --release --target "$TARGET" --manifest-path "$ROOT_DIR/Cargo.toml" -p u7s-apiserver -p u7s-scheduler

cp "$ROOT_DIR/target/$TARGET/release/u7s-apiserver" "$STAGE_DIR/"
cp "$ROOT_DIR/target/$TARGET/release/u7s-scheduler" "$STAGE_DIR/"

# Shared with scripts/release-gate/build-arm64-tarball.sh: kubectl fetch +
# sha256 + cosign, and the pinned CNI plugin fetch.
# shellcheck source=lib/release-fetch.sh
. "$ROOT_DIR/scripts/lib/release-fetch.sh"

if ! command -v cosign >/dev/null 2>&1; then
  echo "error: cosign not found on PATH -- it verifies the upstream kubelet/kube-controller-manager/kubectl signatures" >&2
  exit 1
fi

echo "==> Fetching kubelet + kube-controller-manager + kubectl v$K8S_VERSION for linux/$K8S_ARCH" >&2
for bin in kubelet kube-controller-manager kubectl; do
  fetch_k8s_binary "$STAGE_DIR" "$K8S_ARCH" "$bin"
done

chmod +x "$STAGE_DIR/u7s-apiserver" "$STAGE_DIR/u7s-scheduler"

echo "==> Fetching CNI plugins v$CNI_PLUGINS_VERSION ($CNI_PLUGINS) for linux/$K8S_ARCH" >&2
fetch_cni_plugins_for_arch "$STAGE_DIR/cni-plugins" "$K8S_ARCH"

# Apache-2.0 section 4 requires redistributing this license text alongside
# the unmodified kubelet/kube-controller-manager/kubectl binaries and CNI
# plugins fetched above.
cp "$ROOT_DIR/THIRD_PARTY_LICENSES.md" "$STAGE_DIR/"

# manifests/*.yaml (repo root, see manifests/README.md) is the well-known-
# folder vendoring location (docs/decisions/well-known-manifest-folder.md)
# install.sh copies into --manifest-output-dir at install time -- no
# install-time network fetch, since some target nodes have no GitHub
# connectivity at all. Staged even when empty (true until the per-component
# migration beads land real files here) so the tarball layout install.sh
# already expects is never missing.
echo "==> Staging vendored in-cluster manifests" >&2
mkdir -p "$STAGE_DIR/manifests"
if [ -d "$ROOT_DIR/manifests" ]; then
  shopt -s nullglob
  manifest_files=("$ROOT_DIR"/manifests/*.yaml)
  shopt -u nullglob
  if [ "${#manifest_files[@]}" -gt 0 ]; then
    cp "${manifest_files[@]}" "$STAGE_DIR/manifests/"
  fi
fi

TARBALL="$OUT_DIR/${STAGE_NAME}.tar.gz"
tar -czf "$TARBALL" -C "$WORK_DIR" "$STAGE_NAME"

echo "==> Wrote $TARBALL" >&2
tar tzf "$TARBALL"

#!/usr/bin/env bash
# Builds the u7s release tarball for linux/x86_64: cargo-builds
# u7s-apiserver + u7s-scheduler for x86_64-unknown-linux-gnu, downloads the
# matching kubelet + kube-controller-manager from dl.k8s.io (checksum-
# verified), and packages all four into the flat layout scripts/install.sh
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
# installable), curl, sha256sum, tar.
set -euo pipefail

# Same Kubernetes version pinned elsewhere in this project (e2e-focus.yaml's
# matrix, scripts/conformance/04-start-kcm.sh, lima/kubelet.yaml's CRI-O repo).
K8S_VERSION="1.36.4"
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
cargo build --release --target "$TARGET" --manifest-path "$ROOT_DIR/Cargo.toml" -p u7s-apiserver -p u7s-scheduler

cp "$ROOT_DIR/target/$TARGET/release/u7s-apiserver" "$STAGE_DIR/"
cp "$ROOT_DIR/target/$TARGET/release/u7s-scheduler" "$STAGE_DIR/"

echo "==> Fetching kubelet + kube-controller-manager v$K8S_VERSION for linux/$K8S_ARCH" >&2
for bin in kubelet kube-controller-manager; do
  url="https://dl.k8s.io/release/v${K8S_VERSION}/bin/linux/${K8S_ARCH}/${bin}"
  curl -fL --retry 3 --retry-connrefused -o "$STAGE_DIR/$bin" "$url"

  # dl.k8s.io publishes a raw-hex sha256 sidecar alongside every binary --
  # verify it rather than trusting -fL's exit code alone (a proxy could serve
  # a truncated-but-200 response, or a corrupted-in-transit file).
  expected="$(curl -fsSL --retry 3 --retry-connrefused "${url}.sha256")"
  actual="$(sha256sum "$STAGE_DIR/$bin" | cut -d' ' -f1)"
  if [ "$expected" != "$actual" ]; then
    echo "error: checksum mismatch for $bin: expected $expected, got $actual" >&2
    exit 1
  fi
  chmod +x "$STAGE_DIR/$bin"
done

chmod +x "$STAGE_DIR/u7s-apiserver" "$STAGE_DIR/u7s-scheduler"

# Apache-2.0 section 4 requires redistributing this license text alongside
# the unmodified kubelet/kube-controller-manager binaries fetched above.
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

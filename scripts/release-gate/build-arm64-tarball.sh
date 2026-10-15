#!/usr/bin/env bash
# Builds an aarch64 release tarball from the current checkout, in the same flat layout
# as scripts/build-release-tarball.sh (which is x86_64 only), for the Lima arm64 gate VM.
# Also writes the install.sh baked with a file:// DEFAULT_TARBALL_URL (the same sed the
# release workflow applies) plus the .sha256 sidecar, so the gate runs the real
# zero-argument install path.
#
# Usage: build-arm64-tarball.sh <out-dir>
# Requires: cargo-zigbuild + zig, rustup target aarch64-unknown-linux-gnu, curl, shasum.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:?usage: $0 <out-dir>}"
TARGET="aarch64-unknown-linux-gnu"
K8S_VERSION="$(grep -m1 '^K8S_VERSION=' "$ROOT_DIR/scripts/build-release-tarball.sh" | cut -d'"' -f2)"
CACHE="${U7S_GATE_CACHE:-$HOME/.cache/u7s/release-gate}/k8s-$K8S_VERSION-arm64"
TARBALL_NAME="u7s-gate-$TARGET.tar.gz"
GUEST_DIR="/var/tmp/rg"

mkdir -p "$OUT" "$CACHE"
STAGE="$(mktemp -d)/u7s-gate-$TARGET"
trap 'rm -rf "$(dirname "$STAGE")"' EXIT
mkdir -p "$STAGE/manifests"

echo "==> cargo zigbuild u7s-apiserver + u7s-scheduler ($TARGET)" >&2
cargo zigbuild --release --target "$TARGET.2.35" --manifest-path "$ROOT_DIR/Cargo.toml" \
  -p u7s-apiserver -p u7s-scheduler >&2
cp "$ROOT_DIR/target/$TARGET/release/u7s-apiserver" "$ROOT_DIR/target/$TARGET/release/u7s-scheduler" "$STAGE/"

for bin in kubelet kube-controller-manager; do
  if [ ! -x "$CACHE/$bin" ]; then
    url="https://dl.k8s.io/release/v${K8S_VERSION}/bin/linux/arm64/${bin}"
    echo "==> fetching $url" >&2
    curl -fL --retry 3 -o "$CACHE/$bin.tmp" "$url"
    expected="$(curl -fsSL --retry 3 "${url}.sha256")"
    actual="$(shasum -a 256 "$CACHE/$bin.tmp" | cut -d' ' -f1)"
    [ "$expected" = "$actual" ] || { echo "error: sha256 mismatch for $bin" >&2; exit 1; }
    chmod +x "$CACHE/$bin.tmp"
    mv "$CACHE/$bin.tmp" "$CACHE/$bin"
  fi
  cp "$CACHE/$bin" "$STAGE/"
done

cp "$ROOT_DIR/THIRD_PARTY_LICENSES.md" "$STAGE/"
cp "$ROOT_DIR"/manifests/*.yaml "$STAGE/manifests/"

tar -czf "$OUT/$TARBALL_NAME" -C "$(dirname "$STAGE")" "$(basename "$STAGE")"
echo "$(shasum -a 256 "$OUT/$TARBALL_NAME" | cut -d' ' -f1)  $TARBALL_NAME" > "$OUT/$TARBALL_NAME.sha256"

url="file://$GUEST_DIR/$TARBALL_NAME"
sed "s|^DEFAULT_TARBALL_URL=\"\"$|DEFAULT_TARBALL_URL=\"$url\"|" "$ROOT_DIR/scripts/install.sh" > "$OUT/install.sh"
grep -qxF "DEFAULT_TARBALL_URL=\"$url\"" "$OUT/install.sh" || { echo "error: failed to bake DEFAULT_TARBALL_URL" >&2; exit 1; }
chmod +x "$OUT/install.sh"
echo "==> wrote $OUT/$TARBALL_NAME (+ .sha256, baked install.sh)" >&2

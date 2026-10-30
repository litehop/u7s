#!/usr/bin/env bash
# Cross-builds an UNPUBLISHED x86_64 u7s tarball for any git ref, for burst-gate.sh --backend gcp
# --tarball (experiments / A-B of branches). Nothing is published and the release workflow is not
# involved. The layout mirrors scripts/build-release-tarball.sh at that ref (u7s-apiserver,
# u7s-scheduler, kubelet, kube-controller-manager, THIRD_PARTY_LICENSES.md, manifests/*.yaml).
# Unlike the release build, the upstream binaries are sha256-checked only (no cosign), and the
# result is an experiment artefact, never a release.
#
# Writes to <out-dir> (default: ./temp/experiment-tarball/<sha12>):
#   u7s-gate-experiment-<sha12>-x86_64.tar.gz
#   install.sh                       scripts/install.sh at the same ref, unmodified
#   <tarball>.source                 "ref=<ref> sha=<full sha>", read by burst-gate.sh
#
# Usage: build-experiment-tarball.sh <ref> [out-dir]
# Requires: cargo-zigbuild + zig, rustup, curl, shasum, git.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REF="${1:?usage: $0 <ref> [out-dir]}"
SHA="$(git -C "$ROOT_DIR" rev-parse --verify "$REF^{commit}")"
SHA12="${SHA:0:12}"
OUT="${2:-$PWD/temp/experiment-tarball/$SHA12}"
TARGET="x86_64-unknown-linux-gnu"
TARBALL_NAME="u7s-gate-experiment-$SHA12-x86_64.tar.gz"
CACHE_ROOT="${U7S_GATE_CACHE:-$HOME/.cache/u7s/release-gate}"

mkdir -p "$OUT" "$CACHE_ROOT"
WORK="$(mktemp -d)"
SRC="$WORK/src"
cleanup() { git -C "$ROOT_DIR" worktree remove --force "$SRC" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT
git -C "$ROOT_DIR" worktree add --detach "$SRC" "$SHA" >&2

K8S_VERSION="$(grep -m1 '^K8S_VERSION=' "$SRC/scripts/build-release-tarball.sh" | cut -d'"' -f2)"
[ -n "$K8S_VERSION" ] || { echo "error: no K8S_VERSION in $REF's build-release-tarball.sh" >&2; exit 1; }
CACHE="$CACHE_ROOT/k8s-$K8S_VERSION-amd64"
mkdir -p "$CACHE"

rustup target add "$TARGET" >&2
echo "==> cargo zigbuild u7s-apiserver + u7s-scheduler ($TARGET, $REF @ $SHA12)" >&2
U7S_RELEASE="experiment-$SHA12" U7S_GIT_COMMIT="$SHA" U7S_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
CARGO_TARGET_DIR="${U7S_EXPERIMENT_TARGET_DIR:-$CACHE_ROOT/experiment-target}" \
  cargo zigbuild --locked --release --target "$TARGET.2.35" --manifest-path "$SRC/Cargo.toml" \
    -p u7s-apiserver -p u7s-scheduler >&2

STAGE_NAME="u7s-gate-experiment-$SHA12"
STAGE="$WORK/$STAGE_NAME"
mkdir -p "$STAGE/manifests"
BIN_DIR="${U7S_EXPERIMENT_TARGET_DIR:-$CACHE_ROOT/experiment-target}/$TARGET/release"
cp "$BIN_DIR/u7s-apiserver" "$BIN_DIR/u7s-scheduler" "$STAGE/"

for bin in kubelet kube-controller-manager; do
  if [ ! -x "$CACHE/$bin" ]; then
    url="https://dl.k8s.io/release/v${K8S_VERSION}/bin/linux/amd64/${bin}"
    echo "==> fetching $url" >&2
    curl --proto '=https' --tlsv1.2 -fL --retry 3 -o "$CACHE/$bin.tmp" "$url"
    expected="$(curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "${url}.sha256")"
    actual="$(shasum -a 256 "$CACHE/$bin.tmp" | cut -d' ' -f1)"
    [ "$expected" = "$actual" ] || { echo "error: sha256 mismatch for $bin" >&2; exit 1; }
    chmod +x "$CACHE/$bin.tmp"
    mv "$CACHE/$bin.tmp" "$CACHE/$bin"
  fi
  cp "$CACHE/$bin" "$STAGE/"
done

cp "$SRC/THIRD_PARTY_LICENSES.md" "$STAGE/"
shopt -s nullglob
manifest_files=("$SRC"/manifests/*.yaml)
shopt -u nullglob
[ "${#manifest_files[@]}" -eq 0 ] || cp "${manifest_files[@]}" "$STAGE/manifests/"

tar -czf "$OUT/$TARBALL_NAME" -C "$WORK" "$STAGE_NAME"
cp "$SRC/scripts/install.sh" "$OUT/install.sh"
chmod +x "$OUT/install.sh"
echo "ref=$REF sha=$SHA" > "$OUT/$TARBALL_NAME.source"
echo "==> wrote $OUT/$TARBALL_NAME (+ install.sh, .source); EXPERIMENT artefact, not a release" >&2
echo "$OUT/$TARBALL_NAME"

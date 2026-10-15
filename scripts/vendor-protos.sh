#!/usr/bin/env bash
# Re-vendors every generated.proto under crates/proto-generated/proto-include
# from the kubernetes tag recorded in UPSTREAM_VERSION (or the tag given as $1),
# then rewrites PROTO_SHA256SUMS from the files on disk. The set of files is the
# set already in the tree; add a new file to the tree first (any content), then
# run this to overwrite it with upstream.
#
# usage: vendor-protos.sh [tag]
#   tag given: also rewrites UPSTREAM_VERSION.
#
# Internal: `--manifest <dir>` prints the manifest ("<sha256>  <relpath>", sorted
# by path) for every generated.proto under <dir> (used by
# scripts/test-vendor-protos-logic.sh). The Rust guard
# vendored_protos_match_advertised_kubernetes_version checks the committed
# manifest against the files on disk.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
INC="$REPO/crates/proto-generated/proto-include"

manifest() {
  local dir="$1"
  (cd "$dir" && find . -type f -name generated.proto | sed 's|^\./||' | LC_ALL=C sort \
    | while IFS= read -r f; do
        printf '%s  %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$f"
      done)
}

if [ "${1:-}" = "--manifest" ]; then
  manifest "$2"
  exit 0
fi

tag="${1:-$(tr -d '[:space:]' < "$INC/UPSTREAM_VERSION")}"

while IFS= read -r rel; do
  tmp="$(mktemp)"
  gh api "repos/kubernetes/kubernetes/contents/staging/src/$rel?ref=$tag" \
    -H "Accept: application/vnd.github.raw" > "$tmp"
  [ -s "$tmp" ] || { echo "empty response for $rel at $tag" >&2; exit 1; }
  mv "$tmp" "$INC/$rel"
done < <(cd "$INC" && find . -type f -name generated.proto | sed 's|^\./||' | LC_ALL=C sort)

printf '%s\n' "$tag" > "$INC/UPSTREAM_VERSION"
manifest "$INC" > "$INC/PROTO_SHA256SUMS"

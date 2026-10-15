#!/usr/bin/env bash
# Regenerates crates/apiserver/data/k3s-shipped-manifests.json: for each k3s
# tag, the Addon names k3s creates from the files under k3s-io/k3s manifests/
# at that tag (Addon name = file basename without extension, per
# pkg/deploy/controller.go).
#
# usage: gen-k3s-shipped-manifests.sh [tag...]
#   With tags: add or replace those entries, keeping the rest.
#   Without:   re-fetch every tag already in the file.
# To support a new k3s version, run it with the new tag, then add the tag to
# SUPPORTED_TAGS in crates/apiserver/src/migrate_tables.rs.
#
# Internal: `--from-tree-json <tag>` reads a git-trees API response on stdin
# and prints {tag: [names]} (used by scripts/test-gen-k3s-shipped-manifests-logic.sh).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/crates/apiserver/data/k3s-shipped-manifests.json"

tree_to_entry() {
  jq -e --arg tag "$1" '
    if .truncated then error("tree response truncated") else . end
    | [.tree[] | select(.type == "blob" and (.path | startswith("manifests/")))
       | .path | split("/")[-1] | sub("\\.[^.]+$"; "")]
    | unique
    | if length == 0 then error("no manifests/ blobs at tag " + $tag) else . end
    | {($tag): .}'
}

if [ "${1:-}" = "--from-tree-json" ]; then
  tree_to_entry "$2"
  exit 0
fi

if [ "$#" -gt 0 ]; then
  tags=("$@")
else
  tags=()
  while IFS= read -r t; do tags+=("$t"); done < <(jq -r 'keys[]' "$OUT")
fi

acc='{}'
[ -f "$OUT" ] && acc="$(cat "$OUT")"
for tag in "${tags[@]}"; do
  entry="$(gh api "repos/k3s-io/k3s/git/trees/${tag}?recursive=1" | tree_to_entry "$tag")"
  acc="$(jq -S --argjson e "$entry" '. + $e' <<<"$acc")"
done
mkdir -p "$(dirname "$OUT")"
jq -S . <<<"$acc" >"$OUT"
echo "wrote $OUT (${#tags[@]} tag(s) refreshed)"

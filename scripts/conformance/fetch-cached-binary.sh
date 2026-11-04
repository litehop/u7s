#!/usr/bin/env bash
# Usage: fetch-cached-binary.sh <url> <dest>
#
# Keep <dest> a checksum-verified executable fetched from <url>, whose
# published <url>.sha256 sidecar is the reference. The verified digest is
# stored in <dest>.sha256, so a cache hit is checked offline against it. A
# cached file that fails the check (e.g. truncated by an interrupted download,
# or cached before the local digest existed) is deleted and re-fetched; the
# download lands at a temp name beside <dest> and is renamed into place only
# after verification, so <dest> is never partial.
set -euo pipefail

url="$1"
dest="$2"
local_sum="$dest.sha256"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

if [ -e "$dest" ] || [ -e "$local_sum" ]; then
  if [ -x "$dest" ] && [ -f "$local_sum" ] && [ "$(sha256_of "$dest")" = "$(tr -d '[:space:]' < "$local_sum")" ]; then
    echo "Using cached $dest (sha256 verified)"
    exit 0
  fi
  echo "WARNING: cached $dest is corrupt, truncated, not executable or has no local sha256 record; deleting and re-fetching" >&2
  rm -f "$dest" "$local_sum"
fi

expected="$(curl -fsSL "$url.sha256" | tr -d '[:space:]')" || {
  echo "error: cannot fetch checksum $url.sha256" >&2
  exit 1
}
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || {
  echo "error: $url.sha256 is not a sha256 digest: '$expected'" >&2
  exit 1
}

mkdir -p "$(dirname "$dest")"
tmp="$dest.tmp.$$"
tmp_sum="$local_sum.tmp.$$"
trap 'rm -f "$tmp" "$tmp_sum"' EXIT
echo "Downloading $url ..."
curl -fsSL "$url" -o "$tmp"
actual="$(sha256_of "$tmp")"
if [ "$actual" != "$expected" ]; then
  echo "error: sha256 mismatch for $url: expected $expected, got $actual" >&2
  exit 1
fi
chmod +x "$tmp"
echo "$expected" > "$tmp_sum"
mv "$tmp_sum" "$local_sum"
mv "$tmp" "$dest"
echo "Cached at $dest"

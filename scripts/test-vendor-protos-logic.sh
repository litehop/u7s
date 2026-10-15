#!/usr/bin/env bash
# Offline test for scripts/vendor-protos.sh --manifest: the manifest must cover
# only generated.proto files, be sorted by path, and change when any byte of a
# vendored proto changes (otherwise a hand edit would survive the guard).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GEN="$REPO/scripts/vendor-protos.sh"
fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1: got '$2' want '$3'"; fail=1; fi; }

d="$(mktemp -d)"
trap 'rm -rf "$d"' EXIT
mkdir -p "$d/k8s.io/b/v1" "$d/k8s.io/a"
printf 'x' > "$d/k8s.io/b/v1/generated.proto"
printf 'y' > "$d/k8s.io/a/generated.proto"
printf 'z' > "$d/k8s.io/a/other.proto"
printf 'v1' > "$d/UPSTREAM_VERSION"

sha_x="$(printf 'x' | shasum -a 256 | cut -d' ' -f1)"
sha_y="$(printf 'y' | shasum -a 256 | cut -d' ' -f1)"
want="$sha_y  k8s.io/a/generated.proto
$sha_x  k8s.io/b/v1/generated.proto"

got="$("$GEN" --manifest "$d")"
check "sorted, generated.proto only" "$got" "$want"

printf 'x2' > "$d/k8s.io/b/v1/generated.proto"
got2="$("$GEN" --manifest "$d")"
if [ "$got2" != "$want" ]; then check "hand edit changes manifest" ok ok
else check "hand edit changes manifest" unchanged changed; fi

exit "$fail"

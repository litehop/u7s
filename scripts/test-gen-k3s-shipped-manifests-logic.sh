#!/usr/bin/env bash
# Offline test for scripts/gen-k3s-shipped-manifests.sh: a git-trees response
# must become Addon names (basename sans extension, nested dirs flattened,
# non-manifests paths ignored), and a truncated or empty tree must fail rather
# than write a short list that would classify distro objects as user data.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GEN="$REPO/scripts/gen-k3s-shipped-manifests.sh"
fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1: got '$2' want '$3'"; fail=1; fi; }

tree='{"truncated":false,"tree":[
 {"path":"manifests","type":"tree"},
 {"path":"manifests/coredns.yaml","type":"blob"},
 {"path":"manifests/metrics-server","type":"tree"},
 {"path":"manifests/metrics-server/auth-reader.yaml","type":"blob"},
 {"path":"pkg/deploy/zz.yaml","type":"blob"}]}'

got="$("$GEN" --from-tree-json t <<<"$tree" | jq -c .)"
check "names are basenames without extension" "$got" '{"t":["auth-reader","coredns"]}'

if "$GEN" --from-tree-json t <<<'{"truncated":true,"tree":[]}' 2>/dev/null; then
  check "truncated tree rejected" ok rejected
else check "truncated tree rejected" rejected rejected; fi

if "$GEN" --from-tree-json t <<<'{"truncated":false,"tree":[{"path":"README.md","type":"blob"}]}' 2>/dev/null; then
  check "empty manifests rejected" ok rejected
else check "empty manifests rejected" rejected rejected; fi

exit "$fail"

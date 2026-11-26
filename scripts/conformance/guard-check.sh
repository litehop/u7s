#!/usr/bin/env bash
# Verifies (or, with --update, rewrites) scripts/conformance/guard.sha256: the pin over the files
# that decide which conformance specs run, what the KCM trim excludes, and the committed
# baseline spec/failure sets. A change to any pinned file fails the check until the pin is
# regenerated in the same PR, and CODEOWNERS routes pin changes to the operator, so a spec set
# cannot be narrowed silently to make a port look green.
#
# Not pinned yet because they do not exist: the memory projection script and a committed
# kcm-mem.json.
#
# Usage: scripts/conformance/guard-check.sh [--update] [--root <dir>]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
UPDATE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --update) UPDATE=1; shift ;;
    --root) ROOT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

PINNED=(
  scripts/conformance/sonobuoy-plugin-e2e.yaml
  scripts/conformance/06-run-sonobuoy.sh
  scripts/conformance/kcm-mode.sh
  scripts/conformance/kcm-pod-bytes.txt
  scripts/conformance/kcm-baseline-specs.txt
  scripts/conformance/kcm-baseline-failures.txt
  scripts/conformance/kcm-multinode-specs.txt
  .githooks/sensitive-conformance-focus.yaml
)
PIN="$ROOT/scripts/conformance/guard.sha256"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
compute() {
  local f
  for f in "${PINNED[@]}"; do
    [ -f "$ROOT/$f" ] || { echo "guard-check: pinned file missing: $f" >&2; return 1; }
    printf '%s  %s\n' "$(sha256_of "$ROOT/$f")" "$f"
  done
}

if [ "$UPDATE" -eq 1 ]; then
  compute > "$PIN.tmp"
  mv "$PIN.tmp" "$PIN"
  echo "guard-check: rewrote $PIN"
  exit 0
fi

[ -f "$PIN" ] || { echo "guard-check: $PIN missing" >&2; exit 1; }
got="$(compute)"
if [ "$got" != "$(cat "$PIN")" ]; then
  echo "guard-check: pinned conformance inputs changed; diff (pin vs now):" >&2
  diff "$PIN" <(printf '%s\n' "$got") >&2 || true
  echo "guard-check: if intended, run scripts/conformance/guard-check.sh --update and get operator review (CODEOWNERS)" >&2
  exit 1
fi
echo "guard-check: ok (${#PINNED[@]} files)"

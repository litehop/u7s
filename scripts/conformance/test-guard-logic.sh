#!/usr/bin/env bash
# The guard pin exists so a port PR cannot make the conformance spec set smaller (a skip list, a
# focus label, the trim list, the baseline itself) without the operator seeing it. These cases
# prove the check fails when any pinned input changes, passes after an explicit --update, and
# that the committed pin matches the tree.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CHECK="$REPO/scripts/conformance/guard-check.sh"
PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

PINNED=$(sed -n '/^PINNED=(/,/^)/p' "$CHECK" | grep -v -E '^PINNED=|^\)' | tr -d ' ')
[ -n "$PINNED" ] || { echo "FAIL: could not read PINNED from guard-check.sh"; exit 1; }

"$CHECK" >/dev/null 2>&1 && ok "committed guard.sha256 matches the tree" \
  || bad "committed guard.sha256 is stale: a pinned conformance input changed without --update"

for f in $PINNED scripts/conformance/guard.sha256; do
  grep -q "^/$f[[:space:]]" "$REPO/.github/CODEOWNERS" && ok "CODEOWNERS routes $f to the operator" \
    || bad "$f is pinned but not in CODEOWNERS; a pin change would not need operator review"
done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for f in $PINNED; do
  mkdir -p "$TMP/$(dirname "$f")"
  cp "$REPO/$f" "$TMP/$f"
done

"$CHECK" --root "$TMP" --update >/dev/null
"$CHECK" --root "$TMP" >/dev/null 2>&1 && ok "fresh pin verifies" || bad "fresh pin does not verify"

for f in $PINNED; do
  cp "$TMP/$f" "$TMP/$f.orig"
  echo "# tamper" >> "$TMP/$f"
  if "$CHECK" --root "$TMP" >/dev/null 2>&1; then
    bad "editing $f did not fail the guard; a spec-narrowing edit would pass unreviewed"
  else
    ok "editing $f fails the guard"
  fi
  mv "$TMP/$f.orig" "$TMP/$f"
done

"$CHECK" --root "$TMP" >/dev/null 2>&1 && ok "restoring the files makes the guard pass again" || bad "guard still failing after restore"

first=$(echo "$PINNED" | sed -n 1p)
rm "$TMP/$first"
"$CHECK" --root "$TMP" >/dev/null 2>&1 && bad "a deleted pinned file passed the guard" || ok "a deleted pinned file fails the guard"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

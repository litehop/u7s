#!/usr/bin/env bash
# Regression test for scripts/changelog-section.sh: a non-snapshot release must
# never publish with missing or empty notes, and must publish only its own
# section (not a neighbour's or Unreleased's).
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$DIR/changelog-section.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

PASS=0
FAIL=0
assert() {
  if [ "$2" = "1" ]; then echo "PASS: $1"; PASS=$((PASS + 1)); else echo "FAIL: $1"; FAIL=$((FAIL + 1)); fi
}

cat > "$tmp/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

### Added
- unreleased thing

## [0.4.6] - 2026-11-20

### Fixed
- fixed thing

### Breaking
- broke thing

## [0.4.5] - 2026-11-10

### Added
- old thing

## [0.4.4]

## [0.4.60] - 2026-11-30

- wrong neighbour
EOF

rc=0; out="$(bash "$SCRIPT" v0.4.6 "$tmp/CHANGELOG.md" 2>"$tmp/err")" || rc=$?
assert "v-prefixed version extracts its section" "$([ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'fixed thing' && echo 1 || echo 0)"
assert "section spans its ### subsections" "$(printf '%s' "$out" | grep -q 'broke thing' && echo 1 || echo 0)"
assert "section stops at the next release (no old notes leak into this release)" "$(printf '%s' "$out" | grep -q 'old thing' && echo 0 || echo 1)"
assert "Unreleased content is not published as a release" "$(printf '%s' "$out" | grep -q 'unreleased thing' && echo 0 || echo 1)"
assert "version 0.4.6 does not match 0.4.60" "$(printf '%s' "$out" | grep -q 'wrong neighbour' && echo 0 || echo 1)"

rc=0; out="$(bash "$SCRIPT" 0.4.5 "$tmp/CHANGELOG.md" 2>/dev/null)" || rc=$?
assert "bare version also works" "$([ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'old thing' && echo 1 || echo 0)"

rc=0; bash "$SCRIPT" v9.9.9 "$tmp/CHANGELOG.md" >"$tmp/out" 2>"$tmp/err" || rc=$?
assert "missing section fails (release would otherwise publish without notes)" "$([ "$rc" != 0 ] && grep -q "no '## \[9.9.9\]' section" "$tmp/err" && echo 1 || echo 0)"
assert "missing section prints nothing to stdout" "$([ ! -s "$tmp/out" ] && echo 1 || echo 0)"

rc=0; bash "$SCRIPT" v0.4.4 "$tmp/CHANGELOG.md" >"$tmp/out" 2>"$tmp/err" || rc=$?
assert "empty section fails (an empty heading is not curated notes)" "$([ "$rc" != 0 ] && grep -q 'is empty' "$tmp/err" && echo 1 || echo 0)"

rc=0; bash "$SCRIPT" v0.4.6 "$tmp/nope.md" >/dev/null 2>&1 || rc=$?
assert "missing file fails" "$([ "$rc" != 0 ] && echo 1 || echo 0)"

rc=0; bash "$SCRIPT" >/dev/null 2>&1 || rc=$?
assert "no version argument fails" "$([ "$rc" != 0 ] && echo 1 || echo 0)"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

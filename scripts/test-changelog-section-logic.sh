#!/usr/bin/env bash
# Regression test for scripts/changelog-section.sh: a non-snapshot release must
# never publish with missing or empty notes, and must publish only its own
# section (not a neighbour's or Unreleased's).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/drain-grep.sh"

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

## [0.4.60] - 2026-11-30

- sixty neighbour

## [0.4.6] - 2026-11-20

### Fixed
- fixed thing

### Breaking
- broke thing

## [0.4.5] - 2026-11-10

### Added
- old thing

## [0.4.4]

## [0.1.0] - 2026-01-01

- last thing

[Unreleased]: https://example.invalid/compare/v0.4.6...HEAD
[0.1.0]: https://example.invalid/releases/tag/v0.1.0
EOF

rc=0; out="$(bash "$SCRIPT" v0.4.6 "$tmp/CHANGELOG.md" 2>"$tmp/err")" || rc=$?
assert "v-prefixed version extracts its section" "$([ "$rc" = 0 ] && printf '%s' "$out" | drain_grep -q 'fixed thing' && echo 1 || echo 0)"
assert "section spans its ### subsections" "$(printf '%s' "$out" | drain_grep -q 'broke thing' && echo 1 || echo 0)"
assert "section stops at the next release (no old notes leak into this release)" "$(printf '%s' "$out" | drain_grep -q 'old thing' && echo 0 || echo 1)"
assert "Unreleased content is not published as a release" "$(printf '%s' "$out" | drain_grep -q 'unreleased thing' && echo 0 || echo 1)"
assert "0.4.6 does not pick up the preceding 0.4.60 section" "$(printf '%s' "$out" | drain_grep -q 'sixty neighbour' && echo 0 || echo 1)"

rc=0; out="$(bash "$SCRIPT" 0.4.60 "$tmp/CHANGELOG.md" 2>/dev/null)" || rc=$?
assert "0.4.60 stops at the next '## [' heading (0.4.6 notes must not leak into it)" "$([ "$rc" = 0 ] && printf '%s' "$out" | drain_grep -q 'sixty neighbour' && ! printf '%s' "$out" | drain_grep -q 'fixed thing' && echo 1 || echo 0)"

rc=0; out="$(bash "$SCRIPT" 0.1.0 "$tmp/CHANGELOG.md" 2>/dev/null)" || rc=$?
assert "last section in the file is extracted" "$([ "$rc" = 0 ] && printf '%s' "$out" | drain_grep -q 'last thing' && echo 1 || echo 0)"
assert "link-reference footers are not published in the notes" "$(printf '%s' "$out" | drain_grep -q 'example.invalid' && echo 0 || echo 1)"

printf '## [1.0.0] - 2026-01-01\n\n[1.0.0]: https://example.invalid/x\n' > "$tmp/footer-only.md"
rc=0; bash "$SCRIPT" v1.0.0 "$tmp/footer-only.md" >"$tmp/out" 2>"$tmp/err" || rc=$?
assert "footer-only section is empty and fails (links are not release notes)" "$([ "$rc" != 0 ] && grep -q 'is empty' "$tmp/err" && echo 1 || echo 0)"

rc=0; out="$(bash "$SCRIPT" 0.4.5 "$tmp/CHANGELOG.md" 2>/dev/null)" || rc=$?
assert "bare version also works" "$([ "$rc" = 0 ] && printf '%s' "$out" | drain_grep -q 'old thing' && echo 1 || echo 0)"

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

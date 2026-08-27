#!/usr/bin/env bash
# Unit test for scripts/bd-prime-slim.sh's render_slim_prime() transform.
#
# Sources the REAL script and calls its render_slim_prime() function against
# fixture files (not live `bd` state) -- a reimplementation of the
# header/footer split or the index formatting would keep passing even if the
# real script regressed. Fixtures are small and deterministic, unlike the
# live memory bank, so the assertions below are exact-match, not "roughly
# smaller".
#
# Regression this guards: bd-prime-slim.sh replaced `bd prime`'s ~300KB
# output (full memory bodies, re-read on every SessionStart/PreCompact and
# cached across most turns in between) with an index-only form. If the marker
# strings this script splits on ever drift out of sync with bd's actual
# `bd prime --export` template, the slimming would either silently ship the
# full 300KB body again or truncate the command-reference footer -- both
# regressions this test catches without needing a live bd install.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/bd-prime-slim.sh"

PASS=0
FAIL=0

assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

# shellcheck source=bd-prime-slim.sh
source "$SCRIPT"

SANDBOX=$(mktemp -d)
trap 'rm -rf "$SANDBOX"' EXIT

LONG_BODY_1="This is the first memory body. It is intentionally long so the truncation logic has something real to cut, well past seventy characters of content."
LONG_BODY_2="Second memory body, also long enough to exceed the default snippet length so we can confirm it too gets truncated with a trailing ellipsis marker."

# ---------------------------------------------------------------------------
# 1. Well-formed `bd prime --export` fixture: header preserved verbatim,
#    memory bodies replaced by a truncated one-line index, footer (session
#    close protocol onward) preserved verbatim, schema_version excluded.
# ---------------------------------------------------------------------------
EXPORT_1="$SANDBOX/export-1.md"
cat > "$EXPORT_1" <<EOF
# Beads Workflow Context

> some header prose

## Persistent Memories (2)

Stored via \`bd remember\`.

### memory-one
$LONG_BODY_1

### memory-two
$LONG_BODY_2


# 🚨 SESSION CLOSE PROTOCOL 🚨

some footer prose that must survive untouched
EOF

MEM_1="$SANDBOX/memories-1.json"
cat > "$MEM_1" <<EOF
{
  "memory-one": $(printf '%s' "$LONG_BODY_1" | jq -Rs .),
  "memory-two": $(printf '%s' "$LONG_BODY_2" | jq -Rs .),
  "schema_version": 1
}
EOF

OUT_1=$(render_slim_prime "$EXPORT_1" "$MEM_1")

assert "header prose before the memories section is preserved verbatim" \
  "$(printf '%s' "$OUT_1" | grep -qF '> some header prose' && echo 1 || echo 0)"
assert "footer (session close protocol onward) is preserved verbatim" \
  "$(printf '%s' "$OUT_1" | grep -qF 'some footer prose that must survive untouched' && echo 1 || echo 0)"
assert "memory count excludes the schema_version metadata key (2, not 3)" \
  "$(printf '%s' "$OUT_1" | grep -qE '^## Persistent Memories \(2\)' && echo 1 || echo 0)"
assert "index lists memory-one as a one-line entry" \
  "$(printf '%s' "$OUT_1" | grep -qE '^- memory-one: ' && echo 1 || echo 0)"
assert "index lists memory-two as a one-line entry" \
  "$(printf '%s' "$OUT_1" | grep -qE '^- memory-two: ' && echo 1 || echo 0)"
assert "the FULL body text is NOT present -- this is the whole point of the index" \
  "$(printf '%s' "$OUT_1" | grep -qF "$LONG_BODY_1" && echo 0 || echo 1)"
assert "schema_version itself never appears as an index entry" \
  "$(printf '%s' "$OUT_1" | grep -qE '^- schema_version: ' && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 2. DESC_LEN controls snippet length: a short cap must actually shorten the
#    rendered snippet, proving the cap is wired through to jq and not just a
#    dead variable.
# ---------------------------------------------------------------------------
OUT_SHORT=$(DESC_LEN=10 render_slim_prime "$EXPORT_1" "$MEM_1")
SNIPPET=$(printf '%s' "$OUT_SHORT" | grep -E '^- memory-one: ' | head -1)
assert "DESC_LEN=10 actually shortens the snippet (proves the cap isn't dead code)" \
  "$([ "${#SNIPPET}" -lt 40 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. bd's default template drifts (marker missing) -> fail loud: pass the
#    real content through UNMODIFIED rather than silently corrupting it
#    (dropping the footer) or silently no-op'ing back to the full 300KB body.
# ---------------------------------------------------------------------------
EXPORT_2="$SANDBOX/export-2-no-marker.md"
printf 'some content with no recognizable bd prime markers at all\n' > "$EXPORT_2"
MEM_2="$SANDBOX/memories-2.json"
printf '{"foo": "bar"}' > "$MEM_2"

OUT_2=$(render_slim_prime "$EXPORT_2" "$MEM_2" 2>"$SANDBOX/stderr-2")
assert "marker-drift fallback passes the original content through unmodified" \
  "$(printf '%s' "$OUT_2" | grep -qF 'some content with no recognizable bd prime markers at all' && echo 1 || echo 0)"
assert "marker-drift fallback warns on stderr instead of failing silently" \
  "$(grep -qF 'marker not found' "$SANDBOX/stderr-2" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

#!/usr/bin/env bash
# Fails if a bead-ID-shaped reference (mayor-XXXXX) appears in tracked source.
#
# Bead IDs rot: a comment citing one reads fine the day it's written, but once
# that bead closes it's an unexplained token nobody can resolve (see PR #1371,
# critical-reviewer's follow-on finding that prompted this guard). Historical
# context belongs in git/PR history, not a live token in source.
#
# Exclusions, same rationale as the sweep this guard backstops:
#   .beads/  -- bd's own JSONL export legitimately contains bead IDs.
#   ai/      -- findings/decisions docs legitimately cite the bead they came from.
#   docs/    -- same.
#   .github/ -- workflow configs may reference bead IDs in commit-adjacent context.
#   CONTRIBUTING.md -- "the mayor method" is a real phrase (docs/the-mayor-method/),
#     not a bead ID; mayor-[a-z0-9]{5} happens to also match its first 5 letters
#     ("mayor-metho"). git grep's -E engine has no \b support to disambiguate,
#     so the file is excluded outright rather than false-positiving forever.
#   scripts/test-critical-reviewer-hook.sh -- its "mayor-abc12" fixture exercises
#     critical-reviewer-dispatch.sh's own hardcoded `bd close (mayor-[a-z0-9]+)`
#     regex; it is synthetic test input, not a reference to a real, closeable bead.
#   this file -- documenting the two exclusions above requires spelling out
#     the exact strings that trip the regex.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

matches=$(git grep -n -E 'mayor-[a-z0-9]{5}' -- . \
  ':!.beads' ':!ai' ':!docs' ':!.github' \
  ':!CONTRIBUTING.md' ':!scripts/test-critical-reviewer-hook.sh' \
  ':!scripts/check-bead-id-refs.sh' \
  2>/dev/null || true)

if [ -n "$matches" ]; then
  echo "bead-id-refs: found bead-ID reference(s) that will rot once the bead closes:" >&2
  echo "$matches" >&2
  echo "Strip the mayor-XXXXX token -- the context lives in git/PR history instead." >&2
  exit 1
fi

echo "bead-id-refs: ok"

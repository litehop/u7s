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
#     not a bead ID; mayor-[a-z0-9]{3,5} happens to also match its first letters
#     ("mayor-metho"). git grep's -E engine has no \b support to disambiguate,
#     so the file is excluded outright rather than false-positiving forever.
#   scripts/test-critical-reviewer-hook.sh -- excluded from the blanket sweep
#     below because its "mayor-abc12" fixture (exercising
#     critical-reviewer-dispatch.sh's own hardcoded `bd close (mayor-[a-z0-9]+)`
#     regex) is synthetic test input, not a reference to a real, closeable
#     bead -- but a whole-file skip once masked a REAL bead-ID reference too
#     (mayor-kfabq, landed in a comment by the very PR that tightened
#     mayor-tick.sh's own exclusion below, then stripped once discovered).
#     Same fix as mayor-tick.sh: CRITICAL_REVIEWER_HOOK_ALLOWED_TOKENS below
#     re-scans this file match-by-match and only tolerates "mayor-abc12".
#   scripts/test-check-bead-id-refs-logic.sh -- this guard's own regression test;
#     its fixtures are synthetic bead-ID-shaped strings (one per real length,
#     3/4/5-char plus dotted sub-ID) that must trip the regex to prove it works,
#     not references to real, closeable beads.
#   this file -- documenting the exclusions above requires spelling out
#     the exact strings that trip the regex.
#   crates/apiserver/src/handlers/pods.rs -- registered in
#     .githooks/sensitive-conformance-focus.yaml; ANY push touching it
#     (comment-only or not) is blocked by .githooks/pre-push without a fresh
#     sonobuoy PASS on an owned VM slot. Tracked in mayor-e49sl -- remove this
#     exclusion once that bead lands the remaining 7 refs (5 distinct IDs).
#   .gitignore -- same "mayor-metho" class of false positive as
#     CONTRIBUTING.md above: the script name "mayor-tick" it references
#     matches mayor-[a-z0-9]{3,5} by coincidence and is a permanent script
#     name, not a bead ID that will close and rot.
#   scripts/mayor-tick.sh, scripts/test-mayor-tick-logic.sh -- excluded from
#     the blanket sweep below for the same "mayor-tick" self-reference
#     reason as .gitignore, but a whole-file exclusion here once silently
#     masked THREE real, since-closed bead-ID references in these files'
#     own comments (mayor-9syl7, mayor-s7nn6, mayor-hkhq0 -- all stripped).
#     A blanket per-file skip can't tell "permanent self-reference" apart
#     from "real bead ID that will rot" -- only an exact-token allowlist
#     can. MAYOR_TICK_ALLOWED_TOKENS below re-scans just these two files
#     and only tolerates the specific known-safe tokens (the "mayor-tick"
#     self-reference, the prose adjective "mayor-owned", and this test
#     file's synthetic bead-ID-shaped fixtures -- same rationale as
#     test-critical-reviewer-hook.sh's fixture above); anything else still
#     fails the guard.
#
# Bead IDs are `mayor-` + a 3-5 char alphanumeric suffix (bd's ID generator;
# see .beads/issues.jsonl for the observed range), optionally followed by a
# dotted sub-ID suffix (e.g. `mayor-a1b2.6`). A fixed `{5}` here would silently
# skip most real IDs -- most are 3 or 4 characters, not 5.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

matches=$(git grep -n -E 'mayor-[a-z0-9]{3,5}(\.[0-9]+)?' -- . \
  ':!.beads' ':!ai' ':!docs' ':!.github' \
  ':!CONTRIBUTING.md' ':!scripts/test-critical-reviewer-hook.sh' \
  ':!scripts/test-check-bead-id-refs-logic.sh' \
  ':!scripts/check-bead-id-refs.sh' \
  ':!crates/apiserver/src/handlers/pods.rs' \
  ':!scripts/mayor-tick.sh' ':!scripts/test-mayor-tick-logic.sh' \
  ':!.gitignore' \
  2>/dev/null || true)

# scripts/mayor-tick.sh + scripts/test-mayor-tick-logic.sh are skipped
# above (their own name matches the regex), but that must not silently
# swallow a real bead-ID reference landing in their body content -- see
# the exclusion-list comment above. Re-scan the two files match-by-match
# (not whole-file) and only tolerate the exact known-safe tokens.
MAYOR_TICK_ALLOWED_TOKENS='mayor-(tick|owned|abcd|efgh|aaaa|bbbb|cccc|dddd|abc[1-4])$'
mayor_tick_matches=$(git grep -n -oE 'mayor-[a-z0-9]{3,5}(\.[0-9]+)?' -- \
  scripts/mayor-tick.sh scripts/test-mayor-tick-logic.sh 2>/dev/null \
  | grep -vE ":${MAYOR_TICK_ALLOWED_TOKENS}" || true)
if [ -n "$mayor_tick_matches" ]; then
  matches="${matches:+$matches
}$mayor_tick_matches"
fi

# scripts/test-critical-reviewer-hook.sh is skipped above (its "mayor-abc12"
# fixture is synthetic test input, not a real bead ID), but the same
# whole-file-skip-can't-tell-fixture-from-rot flaw as mayor-tick.sh applies --
# see the exclusion-list comment above for the real bead ID (mayor-kfabq)
# it once let rot undetected. Re-scan match-by-match and only tolerate the
# fixture token.
CRITICAL_REVIEWER_HOOK_ALLOWED_TOKENS='mayor-abc12$'
critical_reviewer_hook_matches=$(git grep -n -oE 'mayor-[a-z0-9]{3,5}(\.[0-9]+)?' -- \
  scripts/test-critical-reviewer-hook.sh 2>/dev/null \
  | grep -vE ":${CRITICAL_REVIEWER_HOOK_ALLOWED_TOKENS}" || true)
if [ -n "$critical_reviewer_hook_matches" ]; then
  matches="${matches:+$matches
}$critical_reviewer_hook_matches"
fi

if [ -n "$matches" ]; then
  echo "bead-id-refs: found bead-ID reference(s) that will rot once the bead closes:" >&2
  echo "$matches" >&2
  echo "Strip the mayor-XXXXX token -- the context lives in git/PR history instead." >&2
  exit 1
fi

echo "bead-id-refs: ok"

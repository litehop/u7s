#!/usr/bin/env bash
# Decide whether a diff touches a known-recurring-regression file registered in
# .githooks/sensitive-conformance-focus.yaml and, if so, emit the sonobuoy
# --focus regex and the exact spec count the sensitive-e2e-guard CI job must run.
#
# Consumed by .github/workflows/e2e-focus.yaml's sensitive-e2e-guard job (its
# stdout is appended to $GITHUB_OUTPUT) and unit-tested by
# scripts/test-sensitive-focus-for-diff-logic.sh.
#
# Usage: sensitive-focus-for-diff.sh <changed-files-list> <registry-yaml>
#   <changed-files-list>  file with one changed path per line
#   <registry-yaml>       .githooks/sensitive-conformance-focus.yaml
#
# Output (stdout, GitHub-Actions key=value form):
#   sensitive=false                         # nothing registered was touched
# ...or...
#   sensitive=true
#   focus=<pipe-joined focus across every matched entry>
#   expected_specs=<sum of matched entries' specs>
#
# The registry is awk-parsed, NOT read with a YAML library -- a git hook / CI
# step must not depend on yq/python being installed. Schema per entry: `- file:`,
# `function:` (ignored here), `focus:`, `specs:`. A matched entry MISSING a
# numeric `specs:` is a HARD error (fail-closed: never silently guard a
# sensitive file with an unknown expected count).
set -euo pipefail

CHANGED="${1:?usage: sensitive-focus-for-diff.sh <changed-files-list> <registry-yaml>}"
REGISTRY="${2:?usage: sensitive-focus-for-diff.sh <changed-files-list> <registry-yaml>}"

# Emit "file<TAB>focus<TAB>specs" per registry entry. Accumulates across an
# entry's lines and flushes at the next `- file:` (or EOF) so an entry whose
# `specs:` is absent still flushes (with an empty specs field) rather than
# vanishing -- the caller turns that empty field into a hard error below.
parse_registry() {
  [ -f "$REGISTRY" ] || return 0
  awk '
    function flush() {
      if (file != "") print file "\t" focus "\t" specs
      file = ""; focus = ""; specs = ""
    }
    /^[[:space:]]*-[[:space:]]*file:/ {
      flush()
      sub(/^[[:space:]]*-[[:space:]]*file:[[:space:]]*/, "")
      file = $0
      next
    }
    /^[[:space:]]*focus:/ {
      sub(/^[[:space:]]*focus:[[:space:]]*/, "")
      focus = $0
      gsub(/^"|"$/, "", focus)
      next
    }
    /^[[:space:]]*specs:/ {
      sub(/^[[:space:]]*specs:[[:space:]]*/, "")
      specs = $0
      next
    }
    END { flush() }
  ' "$REGISTRY"
}

matched_focus=""
total_specs=0
any=0

while IFS=$'\t' read -r pattern focus specs; do
  [ -z "$pattern" ] && continue
  # A registry `file:` is a path (or path substring) matched against the
  # changed-file list (grep -F substring match).
  grep -Fq -- "$pattern" "$CHANGED" || continue
  if ! printf '%s' "$specs" | grep -qE '^[0-9]+$'; then
    echo "sensitive-focus-for-diff: registry entry for '$pattern' has no valid 'specs:' count (got '$specs')" >&2
    exit 1
  fi
  any=1
  if [ -z "$matched_focus" ]; then
    matched_focus="$focus"
  else
    matched_focus="$matched_focus|$focus"
  fi
  total_specs=$(( total_specs + specs ))
done < <(parse_registry)

if [ "$any" -eq 1 ]; then
  printf 'sensitive=true\n'
  printf 'focus=%s\n' "$matched_focus"
  printf 'expected_specs=%s\n' "$total_specs"
else
  printf 'sensitive=false\n'
fi

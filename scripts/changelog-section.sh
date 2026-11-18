#!/usr/bin/env bash
# Prints the body of the `## [<version>]` section of CHANGELOG.md (heading excluded).
# Fails if the section is missing or has no content, so a non-snapshot release
# cannot publish without curated notes.
#
# Usage: scripts/changelog-section.sh <version> [changelog-file]
#   <version> may carry a leading "v" (v0.4.6 and 0.4.6 select `## [0.4.6]`).
set -euo pipefail

version="${1:-}"
if [ -z "$version" ]; then
  echo "usage: $0 <version> [changelog-file]" >&2
  exit 2
fi
version="${version#v}"
file="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md}"

if [ ! -f "$file" ]; then
  echo "error: $file not found" >&2
  exit 1
fi

body="$(awk -v want="## [$version]" '
  /^## / {
    if (found) exit
    if (index($0, want) == 1 && (length($0) == length(want) || substr($0, length(want) + 1, 1) == " ")) found = 1
    next
  }
  found && !/^\[[^]]+\]:[ \t]/ { print }
  END { if (!found) exit 3 }
' "$file")" || rc=$?

if [ "${rc:-0}" -eq 3 ]; then
  echo "error: $file has no '## [$version]' section -- rename '## [Unreleased]' to '## [$version] - <date>' before tagging" >&2
  exit 1
fi

if [ -z "$(printf '%s' "$body" | tr -d '[:space:]')" ]; then
  echo "error: '## [$version]' section in $file is empty" >&2
  exit 1
fi

printf '%s\n' "$body" | sed -e :a -e '/^[[:space:]]*$/{$d;N;ba' -e '}' | sed '/./,$!d'

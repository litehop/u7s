#!/usr/bin/env bash
# Advisory Vale prose lint over human-facing docs (and Rust comments for the
# u7s-code rules). Config: .vale.ini; rule map: .vale/README.md.
#
# Usage: scripts/vale-report.sh [--strict] [--github] [PATH...]
#   --strict  exit 1 when a deterministic u7s/ rule fires at error level
#   --github  also print GitHub Actions ::warning annotations
# Without --strict the exit code is 0 unless Vale itself fails to run.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

STRICT=0
GITHUB=0
PATHS=()
for arg in "$@"; do
  case "$arg" in
    --strict) STRICT=1 ;;
    --github) GITHUB=1 ;;
    *) PATHS+=("$arg") ;;
  esac
done
if [ "${#PATHS[@]}" -eq 0 ]; then
  PATHS=(README.md CONTRIBUTING.md CHANGELOG.md docs crates)
fi

if ! command -v vale >/dev/null 2>&1; then
  echo "vale-report: vale not installed (https://vale.sh)" >&2
  exit 2
fi

if [ ! -d .vale/styles/Google ]; then
  vale sync >&2
fi

ERR="$(mktemp)"
trap 'rm -f "$ERR"' EXIT

# --no-exit: alerts alone never fail the run; a non-zero status here means
# Vale could not run (bad config, missing styles, unreadable path).
if ! JSON="$(vale --no-exit --output=JSON "${PATHS[@]}" 2>"$ERR")"; then
  cat "$ERR" >&2
  echo "vale-report: vale failed to run" >&2
  exit 2
fi
# Grammar-not-installed notices are expected: Rust comments are read by delimiter.
grep -v '^W101 ' "$ERR" >&2 || true

echo "== Vale advisory report =="
echo "$JSON" | jq -r '
  to_entries | map(select(.value | length > 0)) |
  (map(.value | length) | add // 0) as $total |
  "alerts: \($total) in \(length) file(s)",
  "",
  "-- per file --",
  (sort_by(-(.value | length))[] | "\(.value | length)\t\(.key)"),
  "",
  "-- per rule --",
  ([.[] | .value[]] | group_by(.Check) | map({c: .[0].Check, n: length}) | sort_by(-.n)[] | "\(.n)\t\(.c)")'

echo
echo "-- u7s rules (house-rule enforcement) --"
echo "$JSON" | jq -r '
  [to_entries[] | .key as $f | .value[] | select(.Check | startswith("u7s")) |
   "\($f):\(.Line):\(.Span[0]): [\(.Severity)] \(.Check): \(.Message)"] |
  if length == 0 then "none" else .[] end'

if [ "$GITHUB" = 1 ]; then
  echo "$JSON" | jq -r '
    to_entries[] | .key as $f | .value[] |
    "::warning file=\($f),line=\(.Line),title=\(.Check)::\(.Message | gsub("\n"; " "))"'
fi

if [ "$STRICT" = 1 ]; then
  N="$(echo "$JSON" | jq '[to_entries[] | .value[] | select((.Check | startswith("u7s")) and .Severity == "error")] | length')"
  if [ "$N" -gt 0 ]; then
    echo "vale-report: $N u7s error(s)" >&2
    exit 1
  fi
fi
exit 0

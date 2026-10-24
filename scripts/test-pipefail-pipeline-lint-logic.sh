#!/usr/bin/env bash
# Lint: under `set -o pipefail`, a multi-stage pipeline (>= 2 pipes) ending in
# `grep -q` / `grep -m` / `head` can false-FAIL. The sink exits as soon as it
# has its answer, the upstream stage dies of SIGPIPE (141) on its next write,
# and pipefail reports the pipeline as failed even though the match succeeded.
# A required CI check must never false-FAIL on timing, so such a pipeline must
# capture first and match after (`out="$(a | b)"; [[ $out == *x* ]]`), use a
# sink that drains its input (`sed -n 1p`), or carry an audited
# `# pipefail-ok: <reason>` marker on the same line.
#
# Lines already guarded with `|| true` / `; true` / `|| :` cannot propagate the
# failure and are skipped. Quoted-string contents are not parsed; a `|` inside
# a double-quoted string can be a false positive -- mark it.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

# Prints "<file>:<line>:<text>" for each offending logical line of $1.
lint_file() {
  awk -v file="$1" '
    function check(s, n,   segs, i, seg, pre) {
      if (s ~ /pipefail-ok:/) return
      if (s ~ /(\|\||;)[ \t]*(true|:)([ \t;)}"]|$)/) return
      gsub(/\$\(/, " ; ", s)
      gsub(/\047[^\047]*\047/, "", s)
      gsub(/\|\||&&|[();{}]/, ";", s)
      n = split(s, segs, ";")
      for (i = 1; i <= n; i++) {
        seg = segs[i]
        if (match(seg, /\|[ \t]*(grep[ \t]+(-[a-zA-Z]*[qm][0-9]*|--quiet|--max-count)|head)([ \t]|$)/)) {
          pre = substr(seg, 1, RSTART - 1)
          if (pre ~ /\|/) return 1
        }
      }
      return 0
    }
    {
      if (acc == "") { start = NR }
      line = $0
      if (line ~ /^[ \t]*#/ && acc == "") next
      sub(/[ \t]#[ \t].*$/, "", line) # trailing comment unless marker
      if ($0 ~ /pipefail-ok:/) line = line " pipefail-ok:"
      joined = acc line
      if (line ~ /\\[ \t]*$/) { sub(/\\[ \t]*$/, " ", line); acc = acc line; next }
      if (line ~ /\|[ \t]*$/) { acc = acc line " "; next }
      if (check(joined)) printf "%s:%d:%s\n", file, start, joined
      acc = ""
    }
  ' "$1"
}

PASS=0
FAIL=0
assert_true() {
  local label="$1"
  shift
  if "$@"; then echo "PASS: $label"; PASS=$(( PASS + 1 )); else echo "FAIL: $label"; FAIL=$(( FAIL + 1 )); fi
}

SELF_DIR="$(mktemp -d)"
trap 'rm -rf "$SELF_DIR"' EXIT

clean() { ! flags "$@"; }
flags() { printf '%s\n' "$1" >"$SELF_DIR/f.sh"; [ -n "$(lint_file "$SELF_DIR/f.sh")" ]; }

assert_true "multi-stage pipeline into grep -q is rejected (SIGPIPE false-FAIL)" \
  flags 'a | b | grep -q x || fail y'
assert_true "multi-stage pipeline into head -1 is rejected" \
  flags 'X="$(pgrep -f p | sort | head -1)"'
assert_true "grep -m1 sink is rejected" \
  flags 'a | b | grep -m1 x'
assert_true "pipeline split across a trailing backslash is still seen" \
  flags $'a | b \\\n  | grep -q x'
assert_true "single-stage producer | grep -q is allowed (policy is multi-stage)" \
  clean 'printf "%s" "$x" | grep -q y'
assert_true "two independent single-stage pipelines joined by && are not one multi-stage pipeline" \
  clean 'printf a | grep -q a && printf b | grep -q b'
assert_true "pipeline guarded with || true cannot propagate the failure" \
  clean 'X="$(a | b | head -1 || true)"'
assert_true "pipefail-ok marker with a reason exempts the line" \
  clean 'a | b | head -1 # pipefail-ok: input is two lines'
assert_true "capture-then-match form is clean" \
  clean 'out="$(a | b)"; [[ $out == *x* ]]'
assert_true "sed -n 1p drains its input and is clean" \
  clean 'a | b | sed -n 1p'
assert_true "pipes inside single quotes are not pipeline stages" \
  clean "a | grep -oE 'x|y|z' | sed 1q"

NFILES=0
HITS=""
while IFS= read -r f; do
  NFILES=$(( NFILES + 1 ))
  HITS+="$(lint_file "$f")"$'\n'
done < <(grep -rlE 'set (-[a-zA-Z]*o pipefail|-o pipefail)' --include='*.sh' "$DIR" | sort)
HITS="$(printf '%s' "$HITS" | sed '/^$/d')"
[ "$NFILES" -gt 0 ] || { echo "FAIL: no pipefail scripts discovered -- discovery is broken"; exit 1; }
assert_true "no scripts under scripts/ have an unaudited multi-stage '| grep -q/-m/head' pipeline under pipefail" \
  test -z "$HITS"
if [ -n "$HITS" ]; then
  echo "offending lines (capture-then-match, use 'sed -n 1p', or add '# pipefail-ok: <reason>'):" >&2
  printf '%s\n' "$HITS" >&2
fi

echo "pipefail-pipeline-lint: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

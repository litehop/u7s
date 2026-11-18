#!/usr/bin/env bash
# Unit test for scripts/vale-report.sh's exit-code contract.
#
# Runs the REAL script as a subprocess with a stub `vale` on PATH that emits
# canned JSON, so the test needs no Vale install and can fail in CI. The
# contract matters because CI runs the script advisory-only: if alerts ever
# made the default mode exit non-zero, every prose nit would block merges; if
# --strict stopped failing on deterministic u7s/ errors, the future gate would
# silently pass; if a Vale crash exited 0, a broken config would look clean.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/vale-report.sh"

PASS=0
FAIL=0
assert() {
  if [ "$2" = "1" ]; then
    echo "PASS: $1"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $1"
    FAIL=$(( FAIL + 1 ))
  fi
}

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
mkdir "$SANDBOX/bin"
cat > "$SANDBOX/bin/vale" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "sync" ]; then exit 0; fi
cat "$STUB_JSON"
exit "${STUB_RC:-0}"
EOF
chmod +x "$SANDBOX/bin/vale"

alert() { # check severity
  printf '{"Check":"%s","Severity":"%s","Line":1,"Span":[1,2],"Message":"m","Match":"x"}' "$1" "$2"
}

# Exit code of the script against canned vale output $1 (JSON) and exit $2.
code() {
  printf '%s' "$1" > "$SANDBOX/out.json"
  set +e
  PATH="$SANDBOX/bin:$PATH" STUB_JSON="$SANDBOX/out.json" STUB_RC="$2" \
    "$SCRIPT" "${@:3}" >/dev/null 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

U7S_ERR="{\"a.md\":[$(alert u7s.FindingsPath error)]}"
U7S_WARN="{\"a.md\":[$(alert u7s.Minimizing warning)]}"
OTHER_ERR="{\"a.md\":[$(alert ai-tells.EmDashUsage error)]}"

assert "clean output passes --strict" \
  "$([ "$(code '{}' 0 --strict)" = 0 ] && echo 1 || echo 0)"
assert "u7s error exits 0 without --strict (advisory must never block)" \
  "$([ "$(code "$U7S_ERR" 0)" = 0 ] && echo 1 || echo 0)"
assert "u7s error fails --strict (deleted-on-close findings file is a broken reference)" \
  "$([ "$(code "$U7S_ERR" 0 --strict)" = 1 ] && echo 1 || echo 0)"
assert "u7s warning does not fail --strict (only deterministic errors gate)" \
  "$([ "$(code "$U7S_WARN" 0 --strict)" = 0 ] && echo 1 || echo 0)"
assert "non-u7s error does not fail --strict (third-party rules are not deterministic)" \
  "$([ "$(code "$OTHER_ERR" 0 --strict)" = 0 ] && echo 1 || echo 0)"
assert "vale crash exits 2 (a broken config must not look clean)" \
  "$([ "$(code '' 1)" = 2 ] && echo 1 || echo 0)"

printf '%s' "$U7S_WARN" > "$SANDBOX/out.json"
OUT="$(PATH="$SANDBOX/bin:$PATH" STUB_JSON="$SANDBOX/out.json" "$SCRIPT" --github 2>&1)"
assert "report lists the u7s rule that fired" \
  "$(grep -q 'u7s.Minimizing' <<<"$OUT" && echo 1 || echo 0)"
assert "--github emits an annotation" \
  "$(grep -q '^::warning file=a.md,line=1' <<<"$OUT" && echo 1 || echo 0)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]

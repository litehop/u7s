#!/usr/bin/env bash
# Guard: every `pkill -f` / `pgrep -f` (and any `killall`) under scripts/ must
# build its pattern with workdir_kill_pattern (scripts/_kill-pattern.sh), or be
# an explicitly allowlisted fixed-name / test-only site. A hand-rolled
# `pkill -f "...${WORKDIR}"` is an unanchored substring match: it also kills
# another live stack whose workdir merely contains this one (suffix/prefix
# collision, or a '.' in the path acting as a wildcard), tearing down a peer
# worker's cluster. Each new raw site re-introduced the bug; this makes the next
# one fail CI instead.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

PASS=0
FAIL=0
assert_true() {
  local label="$1"
  shift
  if "$@"; then echo "PASS: $label"; PASS=$(( PASS + 1 )); else echo "FAIL: $label"; FAIL=$(( FAIL + 1 )); fi
}

# "<path relative to scripts/>::<ERE matched against the offending line>::why".
# Matching an entry exempts that line only; a new raw line in the same file
# still fails unless it also matches.
ALLOW=(
  'conformance/reset.sh::pgrep -f "\$pattern"::pattern is workdir_kill_pattern output (assigned on the previous line)'
  '_kill-pattern.sh::pgrep -f "\$pattern"::pattern is workdir_kill_pattern output (assigned on the previous line)'
  'conformance/reset.sh::sudo pkill -f (kubelet|kube-controller-manager|sonobuoy)::fixed process names inside the guest VM, no path'
  'conformance/04-start-kcm.sh::kube-controller-manager-\[0-9\]::fixed binary-name pattern inside the guest VM, no path'
  'conformance/test-host-only-kill-scope-logic.sh::pkill -f "\$(APISERVER|KONNECTIVITY)_PATTERN"::pattern variables are workdir_kill_pattern output'
  'conformance/test-kcm-supervisor-logic.sh::FAKE_PATTERN::pattern is the test'"'"'s own sleeper binary path, no workdir'
  'conformance/test-kcm-supervisor-logic.sh::pgrep -f "\$pattern"::helper over the test'"'"'s own fixed sleeper patterns'
  'test-restart-kill-scope-logic.sh::.::asserts on and extracts the real scripts'"'"' lines; issues no pkill of its own pattern'
  'test-worktree-hygiene-logic.sh::.::asserts on dry-run output text; issues no real pkill'
  'test-kill-sites-logic.sh::.::extracts and drives the real scripts'"'"' lines against its own sleepers'
  'release-gate/burst-gate.sh::pkill -KILL -f "\$RG_VM_KILL_PATTERN"::runs inside the gate'"'"'s dedicated VM against a line-anchored fixed /var/tmp/rg/*.sh pattern, no host workdir'
  'release-gate/test-burst-gate-logic.sh::for cmd in .bash -c sudo pkill::fixture command strings fed to the kill pattern regex; no pkill is run'
  'conformance/run-all.sh::echo "  pkill -TERM -f ::an echo printing a hint with the expanded workdir_kill_pattern, not a pkill (the guard scans echo text; separate bug)'
  'test-kill-pattern-guard-logic.sh::.::fixtures for this guard'
)

# flagged_lines <file>: non-comment commands (backslash continuations joined)
# that run pkill/pgrep with -f/--full, or any killall, unless the pattern
# argument is itself a workdir_kill_pattern call or a variable assigned from
# one earlier in the file. Prints "line_no:line" (first physical line).
flagged_lines() {
  local joined n line arg var wkp_vars=" "
  joined="$(sed -E "s/[[:space:]]+#.*$//" "$1" | awk '
    { if (sub(/\\$/, "")) { if (!start) start = NR; buf = buf $0; next }
      print (start ? start : NR) ":" buf $0; buf = ""; start = 0 }
    END { if (start) print start ":" buf }')"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    n="${line%%:*}"; line="${line#*:}"
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ([A-Za-z_][A-Za-z0-9_]*)=\"?\$\(workdir_kill_pattern ]]; then
      wkp_vars+="${BASH_REMATCH[1]} "
    fi
    if [[ "$line" =~ (^|[^A-Za-z0-9_-])killall([^A-Za-z0-9_-]|$) ]]; then
      printf '%s:%s\n' "$n" "$line"; continue
    fi
    [[ "$line" =~ (^|[^A-Za-z0-9_-])(pkill|pgrep)[[:space:]]([^\|\;\&]*[[:space:]])?(-[A-Za-z0-9]*f|--full)([^A-Za-z0-9_-]|$)(.*)$ ]] || continue
    arg="${BASH_REMATCH[6]#"${BASH_REMATCH[6]%%[![:space:]]*}"}"
    if [[ "$arg" =~ ^\"?\$\(workdir_kill_pattern([^A-Za-z0-9_]|$) ]]; then continue; fi
    if [[ "$arg" =~ ^\"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?\"?([^A-Za-z0-9_]|$) ]]; then
      var="${BASH_REMATCH[1]}"
      [[ "$wkp_vars" == *" $var "* ]] && continue
    fi
    printf '%s:%s\n' "$n" "$line"
  done <<< "$joined"
}

# unallowed_lines <rel-path> <file>: flagged lines no ALLOW entry covers.
unallowed_lines() {
  local rel="$1" file="$2" line entry e_path e_re ok
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    ok=0
    for entry in "${ALLOW[@]}"; do
      e_path="${entry%%::*}"
      e_re="${entry#*::}"; e_re="${e_re%%::*}"
      [ "$e_path" = "$rel" ] || continue
      if [[ "${line#*:}" =~ $e_re ]]; then ok=1; break; fi
    done
    [ "$ok" = 1 ] || printf '%s:%s\n' "$rel" "$line"
  done < <(flagged_lines "$file")
}

# --- the real tree ---------------------------------------------------------
OFFENDERS=""
while IFS= read -r f; do
  rel="${f#"$DIR"/}"
  OFFENDERS+="$(unallowed_lines "$rel" "$f")"$'\n'
done < <(find "$DIR" -type f -name '*.sh' | sort)
if [ -n "${OFFENDERS//$'\n'/}" ]; then
  echo "unanchored pkill/pgrep -f sites (use workdir_kill_pattern from scripts/_kill-pattern.sh):" >&2
  printf '%s\n' "$OFFENDERS" | grep -v '^$' >&2
fi
assert_true "no pkill/pgrep -f under scripts/ builds a path pattern without workdir_kill_pattern" [ -z "${OFFENDERS//$'\n'/}" ]

# --- the guard itself must be able to fail ---------------------------------
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
cat > "$T/bad.sh" <<'EOF'
pkill -f "u7s-scheduler.*${WORKDIR}/kubeconfig" 2>/dev/null || true
if pgrep -f "konnectivity-server.*${WORKDIR}" >/dev/null; then :; fi
  pkill -9 -f "$WORKDIR"
killall u7s-apiserver
x=$(pgrep -f "limactl hostagent.*${ha_sock}")
EOF
cat > "$T/good.sh" <<'EOF'
# pkill -f "$WORKDIR" in a comment is not a kill
pkill -f "$(workdir_kill_pattern scheduler "$WORKDIR")" 2>/dev/null || true
pkill -9 -P "$pid"
pat="$(workdir_kill_pattern apiserver "$WORKDIR")"
pkill --full "$pat"
pkill \
  -f \
  "$(workdir_kill_pattern kcm "$WORKDIR")"
EOF
assert_true "guard flags every raw pkill/pgrep -f and killall line (5 of 5)" \
  [ "$(flagged_lines "$T/bad.sh" | wc -l | tr -d ' ')" = 5 ]
cat > "$T/long.sh" <<'EOF'
pkill --full "$WORKDIR"
EOF
assert_true "guard flags the long option --full, which is -f spelled out and kills the same peer stacks" \
  [ "$(flagged_lines "$T/long.sh" | wc -l | tr -d ' ')" = 1 ]
cat > "$T/cont.sh" <<'EOF'
pkill -9 \
  -f "u7s.*${WORKDIR}"
EOF
assert_true "guard flags a pkill whose -f sits on a backslash-continued line, reported at the first line" \
  [ "$(flagged_lines "$T/cont.sh")" = '1:pkill -9   -f "u7s.*${WORKDIR}"' ]
cat > "$T/subst.sh" <<'EOF'
pkill -f "$WORKDIR"; x=$(workdir_kill_pattern a "$WORKDIR")
pkill -f "u7s-$(workdir_kill_pattern a "$WORKDIR")-extra"
EOF
assert_true "a raw pattern is still flagged when workdir_kill_pattern merely appears elsewhere on the line" \
  [ "$(flagged_lines "$T/subst.sh" | wc -l | tr -d ' ')" = 2 ]
cat > "$T/squote.sh" <<'EOF'
pkill -f '$(workdir_kill_pattern scheduler "$WORKDIR")'
EOF
assert_true "a single-quoted \$(workdir_kill_pattern ...) is flagged: pkill would get the literal unexpanded text and match nothing, silently leaving the peer-safe kill a no-op" \
  [ "$(flagged_lines "$T/squote.sh" | wc -l | tr -d ' ')" = 1 ]
assert_true "guard accepts workdir_kill_pattern lines, comments and pkill -P" \
  [ -z "$(flagged_lines "$T/good.sh")" ]
assert_true "an un-allowlisted file with a raw line is reported" \
  [ -n "$(unallowed_lines "conformance/new-script.sh" "$T/bad.sh")" ]
assert_true "an allowlist entry for one file does not cover another file" \
  [ -n "$(unallowed_lines "conformance/reset.sh" "$T/bad.sh")" ]

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

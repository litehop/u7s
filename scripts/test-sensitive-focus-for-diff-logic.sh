#!/usr/bin/env bash
# Unit test for scripts/sensitive-focus-for-diff.sh -- the CI-side detector that
# decides whether a diff touches a registered known-recurring-regression file
# and, if so, what sonobuoy --focus / expected spec-count the sensitive-e2e-guard
# job must run.
#
# SAFETY-relevant: if the detector wrongly reports sensitive=false for a diff
# that DID touch pods.rs, the guard job skips and a validate_pod_spec_immutable
# regression (the exact 3x-recurring bug this machinery exists for) merges
# unguarded. The assertions below prove the detector FIRES on a real sensitive
# change against the REAL registry, stays quiet otherwise (so unrelated PRs
# don't pay for a needless ~10-min sonobuoy run), sums specs across multiple
# matched entries, and fails LOUD when a matched entry has no specs count.
#
# Runs the REAL script as a subprocess against fixture changed-file lists and
# registries -- not a reimplementation of its awk/matching logic.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/sensitive-focus-for-diff.sh"
REAL_REGISTRY="$REPO/.githooks/sensitive-conformance-focus.yaml"
SPEC_A="ReplicationController should release no longer matching pods"
SPEC_B="Job should adopt matching orphans and release non-matching pods"

PASS=0
FAIL=0

assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"; PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"; FAIL=$(( FAIL + 1 ))
  fi
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# --- Scenario A: a diff touching the real registered pods.rs fires the guard,
#     carrying BOTH real registered specs and their summed count. If this
#     regresses, a pods.rs regression merges unguarded.
printf '%s\n' \
  'crates/apiserver/src/handlers/pods.rs' \
  'crates/apiserver/src/handlers/services.rs' > "$WORK/changed-sensitive.txt"
OUT=$("$SCRIPT" "$WORK/changed-sensitive.txt" "$REAL_REGISTRY")
assert "sensitive pods.rs diff -> sensitive=true" \
  "$(printf '%s\n' "$OUT" | grep -Fqx 'sensitive=true' && echo 1 || echo 0)"
FOCUS_LINE=$(printf '%s\n' "$OUT" | grep '^focus=' || true)
assert "sensitive pods.rs diff -> focus carries both registered specs" \
  "$([[ "$FOCUS_LINE" == *"$SPEC_A"* && "$FOCUS_LINE" == *"$SPEC_B"* ]] && echo 1 || echo 0)"
assert "sensitive pods.rs diff -> expected_specs=2 (real registry)" \
  "$(printf '%s\n' "$OUT" | grep -Fqx 'expected_specs=2' && echo 1 || echo 0)"

# --- Scenario B: a diff touching NOTHING registered stays quiet so the guard
#     job quick-succeeds; a false positive would run a needless sonobuoy on
#     every unrelated PR.
printf '%s\n' \
  'crates/apiserver/src/handlers/services.rs' \
  'README.md' > "$WORK/changed-clean.txt"
OUT=$("$SCRIPT" "$WORK/changed-clean.txt" "$REAL_REGISTRY")
assert "non-sensitive diff -> sensitive=false" \
  "$(printf '%s\n' "$OUT" | grep -Fqx 'sensitive=false' && echo 1 || echo 0)"
assert "non-sensitive diff -> emits no focus line" \
  "$(printf '%s\n' "$OUT" | grep -q '^focus=' && echo 0 || echo 1)"

# --- Scenario C: multiple matched entries join focuses with | and SUM specs --
#     the reason specs is an explicit per-entry field, not inferred from the
#     alternation count.
cat > "$WORK/registry-multi.yaml" <<'YAML'
- file: crates/apiserver/src/handlers/pods.rs
  function: validate_pod_spec_immutable
  focus: "Spec A|Spec B"
  specs: 2
- file: crates/apiserver/src/handlers/jobs.rs
  function: some_other_guard
  focus: "Spec C"
  specs: 1
YAML
printf '%s\n' \
  'crates/apiserver/src/handlers/pods.rs' \
  'crates/apiserver/src/handlers/jobs.rs' > "$WORK/changed-multi.txt"
OUT=$("$SCRIPT" "$WORK/changed-multi.txt" "$WORK/registry-multi.yaml")
assert "two matched entries -> expected_specs summed (2+1=3)" \
  "$(printf '%s\n' "$OUT" | grep -Fqx 'expected_specs=3' && echo 1 || echo 0)"
assert "two matched entries -> focuses joined with |" \
  "$(printf '%s\n' "$OUT" | grep -Fqx 'focus=Spec A|Spec B|Spec C' && echo 1 || echo 0)"

# --- Scenario D: a matched entry MISSING specs fails loud (fail-closed) --
#     never silently guard a sensitive file with an unknown expected count.
cat > "$WORK/registry-nospecs.yaml" <<'YAML'
- file: crates/apiserver/src/handlers/pods.rs
  function: validate_pod_spec_immutable
  focus: "Spec A"
YAML
printf '%s\n' 'crates/apiserver/src/handlers/pods.rs' > "$WORK/changed-nospecs.txt"
if "$SCRIPT" "$WORK/changed-nospecs.txt" "$WORK/registry-nospecs.yaml" >/dev/null 2>&1; then
  assert "matched entry missing specs -> script fails loud" 0
else
  assert "matched entry missing specs -> script fails loud" 1
fi

echo ""
echo "sensitive-focus-for-diff: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

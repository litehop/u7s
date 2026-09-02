#!/usr/bin/env bash
# Unit tests for batch-focus.sh's pure logic: spec-regex escaping, the
# file:line-prefix strip in the -list-tests enumeration pipeline, and the
# batch-chunking arithmetic. None of this touches limactl/kubectl/a real
# cluster — it is exactly the class of logic a live-VM run can't cheaply
# regression-test on every change (a wrong escape or off-by-one here doesn't
# fail loud, it silently mis-scopes which specs a batch actually runs).
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO/scripts/conformance/batch-focus.sh"

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

# ---------------------------------------------------------------------------
# escape_spec() -- mirrors batch-focus.sh's own function verbatim. Keep in
# sync if the real function changes.
# ---------------------------------------------------------------------------
escape_spec() {
  printf '%s' "$1" | sed -E 's/(\]|\[|\.|\^|\$|\*|\+|\?|\(|\)|\{|\}|\||\\)/\\\1/g'
}

# 1. A spec name loaded with regex metacharacters must escape every one of
#    them -- an unescaped '(' in "(block volmode)" would be parsed as a
#    capture group and could accidentally change what the alternation as a
#    whole matches.
SPEC='[sig-storage] CSI Volumes [Driver: csi-hostpath] [Testpattern: Dynamic PV (block volmode)] multiVolume [Slow] should test.*with a dot+plus'
ESCAPED=$(escape_spec "$SPEC")
assert "escape_spec backslash-escapes every [ ] ( ) . * + character" \
  "$([ "$ESCAPED" = '\[sig-storage\] CSI Volumes \[Driver: csi-hostpath\] \[Testpattern: Dynamic PV \(block volmode\)\] multiVolume \[Slow\] should test\.\*with a dot\+plus' ] && echo 1 || echo 0)"

# 2. The escaped string, anchored, must match ONLY the original literal text
#    -- this is the actual load-bearing property (see batch-focus.sh's file
#    header point 2: ginkgo's --focus matches "Kubernetes e2e suite " + the
#    joined spec text, so the round-trip must hold with that prefix too).
assert "escaped spec round-trips: anchored regex matches its own literal source text" \
  "$(printf '%s' "Kubernetes e2e suite $SPEC" | grep -qE "^Kubernetes e2e suite ${ESCAPED}\$" && echo 1 || echo 0)"

# 3. A second, unrelated spec must NOT match the first spec's anchored
#    regex -- proves the escaping+anchoring actually scopes a batch member
#    to itself, which is the whole point of exact per-spec anchoring
#    (without it, two specs differing only in "(block volmode)" vs
#    "(filesystem volmode)" could cross-match).
OTHER_SPEC='[sig-storage] CSI Volumes [Driver: csi-hostpath] [Testpattern: Dynamic PV (filesystem volmode)] multiVolume [Slow] should test.*with a dot+plus'
assert "escaped+anchored regex does NOT match a sibling spec differing only in one word" \
  "$(printf '%s' "Kubernetes e2e suite $OTHER_SPEC" | grep -qE "^Kubernetes e2e suite ${ESCAPED}\$" && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# -list-tests line-prefix strip -- mirrors the real sed invocation.
# ---------------------------------------------------------------------------
strip_prefix() {
  printf '%s\n' "$1" | sed -E 's/^[^:]+:[0-9]+: //'
}

# 4. Strips the "<file>:<line>: " prefix...
assert "line-prefix strip removes '<file>:<line>: '" \
  "$([ "$(strip_prefix 'k8s.io/kubernetes/test/e2e/foo.go:42: some spec text')" = 'some spec text' ] && echo 1 || echo 0)"

# 5. ...but does NOT truncate a colon that's part of the spec text itself
#    (e.g. "[Driver: csi-hostpath]") -- the class excludes ':' entirely, so
#    the FIRST colon in the line is always the file:line separator; a naive
#    greedy '.*:' here would eat straight through to the LAST colon instead.
assert "line-prefix strip preserves a colon inside the spec text (e.g. '[Driver: x]')" \
  "$([ "$(strip_prefix 'k8s.io/kubernetes/test/e2e/foo.go:42: [Driver: csi-hostpath] should work')" = '[Driver: csi-hostpath] should work' ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Batch-chunking arithmetic -- mirrors the real script's START/END loop.
# ---------------------------------------------------------------------------
count_batches() {
  local total="$1" batch_size="$2"
  echo $(( (total + batch_size - 1) / batch_size ))
}
last_batch_size() {
  local total="$1" batch_size="$2"
  local rem=$(( total % batch_size ))
  if [ "$rem" -eq 0 ]; then echo "$batch_size"; else echo "$rem"; fi
}

# 6. Evenly-divisible totals...
assert "24 specs / batch-size 12 -> 2 batches" "$([ "$(count_batches 24 12)" -eq 2 ] && echo 1 || echo 0)"
# 7. ...and remainders both partition with no spec left out or double-counted.
assert "7 specs / batch-size 4 -> 2 batches (4 + 3, matches the live validation run)" \
  "$([ "$(count_batches 7 4)" -eq 2 ] && [ "$(last_batch_size 7 4)" -eq 3 ] && echo 1 || echo 0)"
# 8. A single spec is its own one-spec batch, not rounded up or dropped.
assert "1 spec / batch-size 12 -> 1 batch of 1" \
  "$([ "$(count_batches 1 12)" -eq 1 ] && [ "$(last_batch_size 1 12)" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# ran_count_from_summary() -- mirrors batch-focus.sh's own function verbatim.
# ---------------------------------------------------------------------------
ran_count_from_summary() {
  printf '%s' "$1" | grep -oE '^Ran [0-9]+ of' | grep -oE '[0-9]+' || true
}

# 9. A real ginkgo summary line yields the actual ran count.
assert "ran_count_from_summary extracts 4 from a real 'Ran 4 of 7579 Specs' summary" \
  "$([ "$(ran_count_from_summary 'Ran 4 of 7579 Specs in 32.269 seconds SUCCESS! -- 4 Passed')" = "4" ] && echo 1 || echo 0)"
# 10. The exact regression this fix targets: a 0-match focus still reports
#     "Ran 0 of ... SUCCESS!" -- must extract 0, not treat it as "no line
#     found" (those two cases need different handling: an empty result means
#     the log had no summary at all, e.g. a crash; "0" means ginkgo ran and
#     legitimately matched nothing).
assert "ran_count_from_summary extracts 0 (not empty) from a genuine 0-match summary" \
  "$([ "$(ran_count_from_summary 'Ran 0 of 7579 Specs in 0.1 seconds SUCCESS! -- 0 Passed')" = "0" ] && echo 1 || echo 0)"
# 11. No "Ran ..." line at all (e.g. a crashed batch never reached ginkgo's
#     own summary printer) must yield empty, not a false "0" or a script
#     abort -- see the `|| true` comment in the real function: under
#     `set -e`, an unguarded failing pipeline here would abort every
#     remaining batch, not just flag this one.
assert "ran_count_from_summary returns empty (not aborting under set -e) when no Ran line exists" \
  "$([ -z "$(ran_count_from_summary 'panic: runtime error' || true)" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Count-mismatch-forces-failure -- mirrors the real script's BATCH_EXIT
# escalation. This is the actual regression target: a batch ginkgo reports
# as exit 0 must not stay "green" if it ran the wrong number of specs.
# ---------------------------------------------------------------------------
mismatch_forces_fail() {
  local batch_exit="$1" ran_count="$2" intended_count="$3"
  local count_mismatch=0
  if [ -z "$ran_count" ] || [ "$ran_count" -ne "$intended_count" ]; then
    count_mismatch=1
  fi
  if [ "$batch_exit" -eq 0 ] && [ "$count_mismatch" -eq 1 ]; then
    echo 1
  else
    echo 0
  fi
}

# 12. The exact bug report: exit 0 + 0-of-N ran -> must be forced to fail.
assert "exit=0 with ran=0 (intended=4) is forced to fail" \
  "$([ "$(mismatch_forces_fail 0 0 4)" = "1" ] && echo 1 || echo 0)"
# 13. exit=0 with an exact count match must NOT be touched -- a correct
#     batch must still report as a genuine pass.
assert "exit=0 with ran=4 (intended=4) is NOT forced to fail" \
  "$([ "$(mismatch_forces_fail 0 4 4)" = "0" ] && echo 1 || echo 0)"
# 14. An already-nonzero exit (real FAIL/CRASH) is already loud; the
#     mismatch check must not mask or double-escalate it differently.
assert "exit=2 (crash) with ran=0 is left alone (already loud, not re-flagged as 0/1)" \
  "$([ "$(mismatch_forces_fail 2 0 4)" = "0" ] && echo 1 || echo 0)"
# 15. Over-match (ran MORE than intended, e.g. an escaping bug causing a
#     sibling spec to also match) must be caught too, not just under-match.
assert "exit=0 with ran=5 (intended=4, over-match) is forced to fail" \
  "$([ "$(mismatch_forces_fail 0 5 4)" = "1" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Structural checks against the real script -- fail if the fix/design is
# reverted, unlike the mirrored functions above which pass regardless.
# ---------------------------------------------------------------------------
assert "batch-focus.sh anchors every batch focus with the 'Kubernetes e2e suite ' prefix" \
  "$(grep -qF -- '^Kubernetes e2e suite ' "$SCRIPT" && echo 1 || echo 0)"
# Matches the flag as an actual CLI argument (--json-report=... or
# --ginkgo.json-report=...), not the file header's prose explaining why it's
# absent -- a plain 'json-report' substring match would false-positive on
# that comment text itself.
assert "batch-focus.sh never passes --json-report / --ginkgo.json-report (spike gotcha #2)" \
  "$(grep -qE -- '(^|[^-])--(ginkgo\.)?json-report=' "$SCRIPT" && echo 0 || echo 1)"
# shellcheck disable=SC2016 # intentional: matching the literal, unexpanded source text, not expanding it ourselves.
assert "batch-focus.sh's watchdog uses the 600s (10m) Active threshold, unmodified" \
  "$(grep -qF -- '"$age_s" -ge 600' "$SCRIPT" && echo 1 || echo 0)"
# shellcheck disable=SC2016 # intentional: matching the literal, unexpanded source text, not expanding it ourselves.
assert "batch-focus.sh's watchdog uses the 900s (15m) any-phase threshold, unmodified" \
  "$(grep -qF -- '"$age_s" -ge 900' "$SCRIPT" && echo 1 || echo 0)"
assert "batch-focus.sh invokes e2e.test directly (no separate ginkgo CLI wrapper)" \
  "$(grep -qF -- '/usr/local/bin/e2e.test' "$SCRIPT" && ! grep -qE -- '(^|[^.])\bginkgo\s+--focus' "$SCRIPT" && echo 1 || echo 0)"
# 16. Fix: `trap cleanup EXIT` must be installed BEFORE the ConfigMap/Pod are
#     created, not after -- otherwise the zero-match-pool exit and
#     --list-only's own exit (both of which happen after pod creation, since
#     -list-tests only exists inside the conformance image) leak the debug
#     Pod + ConfigMap in `default`. Checked by line number, not just
#     presence, since both lines already existed before the fix.
TRAP_LINE=$(grep -n -- 'trap cleanup EXIT' "$SCRIPT" | head -1 | cut -d: -f1)
CONFIGMAP_LINE=$(grep -n -- 'create configmap' "$SCRIPT" | head -1 | cut -d: -f1)
assert "batch-focus.sh installs 'trap cleanup EXIT' before creating the ConfigMap" \
  "$([ -n "$TRAP_LINE" ] && [ -n "$CONFIGMAP_LINE" ] && [ "$TRAP_LINE" -lt "$CONFIGMAP_LINE" ] && echo 1 || echo 0)"
# shellcheck disable=SC2016 # intentional: matching the literal, unexpanded source text, not expanding it ourselves.
assert "batch-focus.sh's cleanup() deletes the Pod with --ignore-not-found (safe pre-creation)" \
  "$(grep -qF -- 'delete pod "$POD_NAME" -n default --ignore-not-found' "$SCRIPT" && echo 1 || echo 0)"
# shellcheck disable=SC2016 # intentional: matching the literal, unexpanded source text, not expanding it ourselves.
assert "batch-focus.sh's cleanup() deletes the ConfigMap with --ignore-not-found (safe pre-creation)" \
  "$(grep -qF -- 'delete configmap "${POD_NAME}-kubeconfig" -n default --ignore-not-found' "$SCRIPT" && echo 1 || echo 0)"
# 17. Fix: a per-batch ran-count assertion must exist and be wired to force
#     BATCH_EXIT nonzero -- guards against silently dropping the whole
#     mismatch-detection mechanism in a future edit.
assert "batch-focus.sh defines ran_count_from_summary" \
  "$(grep -qF -- 'ran_count_from_summary()' "$SCRIPT" && echo 1 || echo 0)"
assert "batch-focus.sh forces BATCH_EXIT nonzero on a count mismatch" \
  "$(grep -qF -- 'BATCH_EXIT=1' "$SCRIPT" && grep -qF -- 'COUNT_MISMATCH' "$SCRIPT" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Real end-to-end invocation: arg validation runs before any limactl/kubectl
# call, so a missing --focus or malformed --batch-size is fast and safe to
# exercise for real (mirrors run-all.sh's own --procs validation test).
# ---------------------------------------------------------------------------
set +e
NO_FOCUS_OUT="$(bash "$SCRIPT" 2>&1)"
NO_FOCUS_EXIT=$?
set -e
assert "batch-focus.sh exits non-zero with no --focus" \
  "$([ "$NO_FOCUS_EXIT" -ne 0 ] && echo 1 || echo 0)"
assert "batch-focus.sh's rejection message names --focus" \
  "$(printf '%s' "$NO_FOCUS_OUT" | grep -qF -- '--focus' && echo 1 || echo 0)"

set +e
BAD_BATCH_OUT="$(bash "$SCRIPT" --focus 'anything' --batch-size 0 2>&1)"
BAD_BATCH_EXIT=$?
set -e
assert "batch-focus.sh exits non-zero on --batch-size 0" \
  "$([ "$BAD_BATCH_EXIT" -ne 0 ] && echo 1 || echo 0)"
assert "batch-focus.sh's rejection message names --batch-size" \
  "$(printf '%s' "$BAD_BATCH_OUT" | grep -qF -- '--batch-size' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

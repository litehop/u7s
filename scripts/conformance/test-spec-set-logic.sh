#!/usr/bin/env bash
# spec-set.sh feeds the baseline-vs-trimmed comparison. If it counted skipped specs or suite nodes,
# or dropped a failure, two runs with different executed sets could compare equal and a trim that
# silently removed specs would look validated.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC_SET="$REPO/scripts/conformance/spec-set.sh"
PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mk() { # dir
  mkdir -p "$1/plugins/e2e/results/global"
  cat > "$1/plugins/e2e/results/global/junit_01.xml"
}
mk "$TMP/a" <<'EOF'
<testsuites>
  <testsuite name="Kubernetes e2e suite">
    <testcase name="[ReportBeforeSuite]" classname="Kubernetes e2e suite" status="passed" time="0.1"></testcase>
    <testcase name="[It] [sig-a] runs and passes [Conformance]" classname="Kubernetes e2e suite" status="passed" time="1"></testcase>
    <testcase name="[It] [sig-a] runs and fails [Conformance]" classname="Kubernetes e2e suite" status="failed" time="1">
      <failure message="">boom</failure>
    </testcase>
    <testcase name="[It] [sig-a] is skipped [Conformance]" classname="Kubernetes e2e suite" status="skipped" time="0">
      <skipped message="skipped"></skipped>
    </testcase>
    <testcase name="[ReportAfterSuite] x" classname="Kubernetes e2e suite" status="passed" time="0.1"></testcase>
  </testsuite>
</testsuites>
EOF
mk "$TMP/b" <<'EOF'
<testsuites>
  <testcase name="[It] [sig-b] disruptive [Conformance]" classname="Kubernetes e2e suite" status="passed" time="1"></testcase>
</testsuites>
EOF

got=$("$SPEC_SET" "$TMP/a" "$TMP/b" | cut -f2)
want=$'[It] [sig-a] runs and fails [Conformance]\n[It] [sig-a] runs and passes [Conformance]\n[It] [sig-b] disruptive [Conformance]'
[ "$got" = "$want" ] && ok "executed set is passed + failed specs across both archives, without skipped specs or suite nodes" \
  || bad "executed set wrong: $got"

got=$("$SPEC_SET" --failed "$TMP/a" "$TMP/b")
[ "$got" = "$(printf 'failed\t[It] [sig-a] runs and fails [Conformance]')" ] && ok "--failed lists exactly the failures" \
  || bad "--failed wrong: $got"

mk "$TMP/c" <<'EOF'
<testsuites>
  <testcase name="[It] [sig-a] runs and passes [Conformance]" classname="Kubernetes e2e suite" status="passed" time="1"></testcase>
  <testcase name="[It] [sig-architecture] Conformance Tests should have at least two untainted nodes [Conformance]" classname="Kubernetes e2e suite" status="failed" time="1"></testcase>
  <testcase name="[It] [sig-apps] Daemon set should rollback without unnecessary restarts [Conformance] [Serial]" classname="Kubernetes e2e suite" status="failed" time="1"></testcase>
</testsuites>
EOF
mk "$TMP/d" <<'EOF'
<testsuites>
  <testcase name="[It] [sig-a] runs and passes [Conformance]" classname="Kubernetes e2e suite" status="passed" time="1"></testcase>
  <testcase name="[It] [sig-architecture] Conformance Tests should have at least two untainted nodes [Conformance]" classname="Kubernetes e2e suite" status="passed" time="1"></testcase>
  <testcase name="[It] [sig-apps] Daemon set should rollback without unnecessary restarts [Conformance] [Serial]" classname="Kubernetes e2e suite" status="passed" time="1"></testcase>
</testsuites>
EOF
one=$("$SPEC_SET" --single-node "$TMP/c"); two=$("$SPEC_SET" --single-node "$TMP/d")
[ "$one" = "$two" ] && [ "$one" = "$(printf 'passed\t[It] [sig-a] runs and passes [Conformance]')" ] \
  && ok "--single-node makes a 1-node and a 2-node run compare equal (multi-node specs fail on 1 node, pass on 2)" \
  || bad "--single-node left topology-dependent specs in the set: [$one] vs [$two]"
[ -z "$("$SPEC_SET" --single-node --failed "$TMP/c")" ] \
  && ok "--single-node --failed is empty on a healthy 1-node run, matching the empty baseline failure set" \
  || bad "--single-node --failed still reports multi-node specs"
[ "$("$SPEC_SET" "$TMP/c" | wc -l)" -eq 3 ] && ok "without --single-node nothing is dropped" || bad "default output filtered specs"

"$SPEC_SET" "$TMP/missing" >/dev/null 2>&1 && bad "a missing archive did not fail; an empty set would compare equal to an empty set" \
  || ok "a missing archive fails loudly"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

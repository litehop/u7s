#!/usr/bin/env bash
# Logic test for scripts/e2e-install/cloud-two-node.sh against stub gcloud (ssh/scp included).
# The script creates and deletes billable VPSes in a shared project and handles a join token,
# so what matters is: it only ever deletes what it created, the token never reaches argv or a
# log, a reclaimed Spot VPS is not reported as a product failure, and the LoadBalancer check
# neither runs where beep is absent nor passes when the client IP is lost.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/cloud-two-node.sh"

PASS=0; FAIL=0
assert() {
  local label="$1" ok="$2"
  if [[ "$ok" =~ ^1+$ ]]; then echo "PASS: $label"; PASS=$((PASS + 1)); else echo "FAIL: $label"; FAIL=$((FAIL + 1)); fi
}
has() { grep -qF -- "$1" <<<"$2" && echo 1 || echo 0; }
hasnt() { grep -qF -- "$1" <<<"$2" && echo 0 || echo 1; }
rc_is() { [ "$RC" = "$1" ] && echo 1 || echo 0; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/bin"

TOKEN=abc123.0123456789abcdef
HASH="sha256:$(printf 'ab%.0s' $(seq 1 32))"

cat >"$TMP/bin/gcloud" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$STUB_LOG"
case "$*" in
  "config configurations describe "*) exit 0 ;;
  "config get-value project") echo fake-proj-123; exit 0 ;;
  "config get-value account") echo acct@example.com; exit 0 ;;
  "config get-value compute/zone") echo us-west1-b; exit 0 ;;
  "compute instances describe "*networkIP*)
    case "$*" in *-cp\ *) echo 10.80.0.2 ;; *-w1\ *) echo 10.80.0.3 ;; *) echo 10.80.0.4 ;; esac; exit 0 ;;
  "compute instances create "*)
    [ -z "${STUB_LEAK:-}" ] || echo "Created [https://compute.googleapis.com/projects/fake-proj-123/zones/z/instances/x]" >&2
    exit 0 ;;
  "compute instances describe "*) echo 1; exit 0 ;;
  "compute instances delete "*) [ -z "${STUB_DELETE_FAIL:-}" ] || exit 1; exit 0 ;;
  "compute operations list "*) [ -z "${STUB_OPS_FAIL:-}" ] || { echo "ERROR: denied" >&2; exit 1; }; echo "${STUB_OPS:-}"; exit 0 ;;
  "compute ssh "*)
    cat >>"$STUB_LOG.stdin"
    [ -z "${STUB_TERM_MATCH:-}" ] || case "$*" in *"$STUB_TERM_MATCH"*) kill -TERM "$(ps -axo pid=,command= | grep -F "bash $STUB_SCRIPT" | sort -n | awk 'NR==1{print $1}')" ;; esac
    [ -z "${STUB_FAIL_MATCH:-}" ] || case "$*" in
      *"$STUB_FAIL_MATCH"*)
        [ -z "${STUB_LEAK:-}" ] || echo "ERROR: https://compute.googleapis.com/projects/fake-proj-123/zones/z failed" >&2
        exit 1 ;;
    esac
    case "$*" in
      *--mint-join-token*)
        echo "Join token created in kube-system, expires 2026-10-20T00:00:00Z (single-use): $STUB_TOKEN"
        echo "  install.sh --join https://127.0.0.1:6443 \\"
        echo "    --ca-cert-hash $STUB_HASH --tarball <path> --node-name <name>" ;;
      *"get nodes -o wide"*)
        echo "u7s-e2e-t-w1.zone.internal Ready <none> 1m v1.37.1 10.80.0.3 <none> Ubuntu"
        case "${STUB_NODES:-one}" in
          one|dup) echo "u7s-e2e-t-cp.zone.internal Ready <none> 1m v1.37.1 10.80.0.2 <none> Ubuntu" ;;
        esac
        [ "${STUB_NODES:-one}" != dup ] || echo "u7s-e2e-t-cp2.zone.internal Ready <none> 1m v1.37.1 10.80.0.2 <none> Ubuntu" ;;
      *"get ds -o name"*)
        echo daemonset.apps/kube-proxy
        case "${STUB_BEEP:-0}" in
          1) echo daemonset.apps/servicelb-controller ;;
          decoy) echo daemonset.apps/beep-exporter ;;
        esac ;;
      *loadBalancer.ingress*) echo "${STUB_INGRESS-10.80.0.2 10.80.0.3}" ;;
      *"/clientip"*) echo "${STUB_SEEN-10.80.0.4}:41234" ;;
    esac
    exit 0 ;;
esac
exit 0
EOF
chmod +x "$TMP/bin/gcloud"

# run args... -> OUT, RC, LOG (gcloud argv), STDIN (everything piped into ssh), RES (results dir contents)
run() {
  : >"$TMP/log"; : >"$TMP/log.stdin"; rm -rf "$TMP/res"
  RC=0
  OUT="$(PATH="$TMP/bin:$PATH" STUB_LOG="$TMP/log" STUB_TOKEN="$TOKEN" STUB_HASH="$HASH" \
    STUB_SCRIPT="$SCRIPT" U7S_E2E_RUN_ID=t U7S_E2E_RESULTS_DIR="$TMP/res" U7S_E2E_POLL_SLEEP=0 \
    "$SCRIPT" "$@" 2>&1 </dev/null)" || RC=$?
  LOG="$(cat "$TMP/log")"
  STDIN="$(cat "$TMP/log.stdin")"
  RES="$(cat "$TMP"/res/* 2>/dev/null || true)"
}

# --- arg parsing
run
assert "no --release exits 2 before touching GCP (else a typo creates billable VPSes)" "$(rc_is 2)$([ -z "$LOG" ] && echo 1 || echo 0)"
run --release
assert "--release without a value exits 2" "$(rc_is 2)"
run --release latest
assert "a release that is not a vX.Y tag is rejected (the mirror path would be wrong)" "$(rc_is 2)$(hasnt 'instances create' "$LOG")"
run --release v0.4.0-snapshot.1 --bogus
assert "an unknown flag exits 2 without creating VPSes" "$(rc_is 2)$(hasnt 'instances create' "$LOG")"

# --- happy path without beep
unset STUB_BEEP
run --release v0.4.0-snapshot.1
assert "a release without beep passes the install+join asserts" "$(rc_is 0)$(has 'RESULT: PASS' "$OUT")"
assert "the LoadBalancer check reports SKIPPED when beep is absent (older releases cannot serve it)" \
  "$(has 'SKIPPED: loadbalancer' "$OUT")"
assert "no client VPS is created when the LB check is skipped" "$(hasnt 'u7s-e2e-t-client' "$LOG")"
assert "installs come from the mirror, never a local build" \
  "$(has 'https://u7s.dekiru.tech/v0.4.0-snapshot.1/install.sh' "$LOG")"
assert "w1 joins the control plane's internal IP, not a public one" \
  "$(has '--join https://10.80.0.2:6443' "$LOG")$(has '--ca-cert-hash '"$HASH" "$LOG")"
assert "the cp node is addressed by its registered FQDN, not the VPS name (a nodeName that matches no node gets the pod garbage-collected)" \
  "$(has 'node/u7s-e2e-t-cp.zone.internal' "$LOG")$(has 'nodeName: u7s-e2e-t-cp.zone.internal' "$STDIN")$(hasnt 'node/u7s-e2e-t-w1.zone.internal' "$LOG")"
assert "exec runs an agnhost subcommand that exists in 2.63 (there is no 'hostname'; a bad one fails logs-exec although exec works)" \
  "$(has 'exec pin -- /agnhost etc-hosts' "$LOG")$(hasnt '/agnhost hostname' "$LOG")"
assert "the join token reaches w1 on stdin (--token -)" "$(has "$TOKEN" "$STDIN")$(has '--token -' "$LOG")"
assert "the join token never appears in any gcloud argv (process lists and shell history would leak it)" \
  "$(hasnt "$TOKEN" "$LOG")"
assert "the join token is not written to the run log or results (artefacts get copied around)" \
  "$(hasnt "$TOKEN" "$RES")$(hasnt "$TOKEN" "$OUT")"
assert "the run creates exactly cp and w1 under its own prefix" \
  "$([ "$(grep -c 'instances create' <<<"$LOG")" = 2 ] && echo 1 || echo 0)$(has 'instances create u7s-e2e-t-cp' "$LOG")$(has 'instances create u7s-e2e-t-w1' "$LOG")"
assert "cleanup deletes only the VPSes this run created (a neighbour's VPS must survive)" \
  "$(has 'instances delete u7s-e2e-t-cp ' "$LOG")$(has 'instances delete u7s-e2e-t-w1 ' "$LOG")$([ "$(grep -c 'instances delete' <<<"$LOG")" = 2 ] && echo 1 || echo 0)"
assert "cleanup never uses gc (it sweeps every u7s-test=1 instance, including other people's)" \
  "$(hasnt 'instances list' "$LOG")"
assert "the results directory records PASS" "$(has PASS "$(cat "$TMP/res/result.txt")")"
assert "the target line is redacted (project/account must not reach logs)" \
  "$(has 'target: <redacted>' "$OUT")$(hasnt 'acct@example.com' "$OUT")$(hasnt 'project=fake-proj-123' "$OUT")"

# --- failure and preemption
STUB_FAIL_MATCH="wait --for=condition=Ready node" run --release v0.4.0-snapshot.1
assert "a failed assertion exits 1 and reports FAIL" "$(rc_is 1)$(has 'RESULT: FAIL' "$OUT")"
assert "a failed run still deletes its VPSes (they bill otherwise)" "$(has 'instances delete u7s-e2e-t-w1 ' "$LOG")"
STUB_OPS=op-1 STUB_FAIL_MATCH="wait --for=condition=Ready node" run --release v0.4.0-snapshot.1
assert "a failure on a preempted VPS is PREEMPTED (exit 3), not a product FAIL" \
  "$(rc_is 3)$(has 'RESULT: PREEMPTED' "$OUT")$(hasnt 'RESULT: FAIL' "$OUT")"
GCP_OPS_SLEEP=0 STUB_OPS_FAIL=1 STUB_FAIL_MATCH="wait --for=condition=Ready node" run --release v0.4.0-snapshot.1
assert "a failure whose preemption lookup keeps erroring is INVALID (exit 3, same code as burst-gate.sh), not a product FAIL: it may have been a reclaimed VPS" \
  "$(rc_is 3)$(has 'RESULT: INVALID' "$OUT")$(hasnt 'RESULT: FAIL' "$OUT")"
GCP_DELETE_SLEEP=0 GCP_DELETE_TRIES=2 STUB_DELETE_FAIL=1 run --release v0.4.0-snapshot.1
assert "a PASS whose VPS cannot be deleted exits 4 and lists it in leaked-vps.txt (a green run must not hide a billing VPS)" \
  "$(rc_is 4)$([ -s "$TMP/res/leaked-vps.txt" ] && echo 1 || echo 0)$(has 'LEAKED VPS' "$OUT")"
GCP_DELETE_SLEEP=0 GCP_DELETE_TRIES=2 STUB_DELETE_FAIL=1 STUB_FAIL_MATCH="wait --for=condition=Ready node" run --release v0.4.0-snapshot.1
assert "a FAIL with a leaked VPS keeps exit 1 (the leak never masks a product failure)" "$(rc_is 1)$([ -s "$TMP/res/leaked-vps.txt" ] && echo 1 || echo 0)"
STUB_OPS=op-1 run --release v0.4.0-snapshot.1
assert "a passing run is PASS even if an old preemption operation exists" "$(rc_is 0)$(has 'RESULT: PASS' "$OUT")"
STUB_FAIL_MATCH="--mint-join-token" run --release v0.4.0-snapshot.1
assert "a release without --mint-join-token fails loudly at the mint step" "$(rc_is 1)$(has 'mint-join-token' "$OUT")"

STUB_NODES=none run --release v0.4.0-snapshot.1
assert "no node with the cp InternalIP fails loudly instead of waiting on an empty node name" \
  "$(rc_is 1)$(has 'no node with InternalIP 10.80.0.2' "$OUT")"
STUB_NODES=dup run --release v0.4.0-snapshot.1
assert "two nodes sharing the cp InternalIP fail rather than feeding both names to kubectl wait" \
  "$(rc_is 1)$(has 'multiple nodes with InternalIP 10.80.0.2' "$OUT")"

# --- --keep
run --release v0.4.0-snapshot.1 --keep
assert "--keep deletes nothing" "$(rc_is 0)$(hasnt 'instances delete' "$LOG")"
assert "--keep prints how to reach each VPS and the kubeconfig path" \
  "$(has 'vps.sh ssh u7s-e2e-t-cp' "$OUT")$(has 'vps.sh ssh u7s-e2e-t-w1' "$OUT")$(has '/var/lib/u7s/kubeconfig' "$OUT")"

# --- LoadBalancer check (beep bundled)
STUB_BEEP=1 run --release v0.4.0-snapshot.1
assert "with beep a client VPS is created in the subnet and every ingress IP is curled from it" \
  "$(rc_is 0)$(has 'instances create u7s-e2e-t-client' "$LOG")$(has 'http://10.80.0.2/clientip' "$LOG")$(has 'http://10.80.0.3/clientip' "$LOG")"
assert "the client VPS is cleaned up too" "$(has 'instances delete u7s-e2e-t-client ' "$LOG")"
assert "SKIPPED is not printed when the LB check ran" "$(hasnt 'SKIPPED' "$OUT")"
STUB_BEEP=1 STUB_SEEN=10.80.0.3 run --release v0.4.0-snapshot.1
assert "an LB that SNATs the client (backend sees another IP) fails: client IP preservation is the point" \
  "$(rc_is 1)$(has 'backend saw client 10.80.0.3' "$OUT")"
STUB_BEEP=1 STUB_INGRESS="" run --release v0.4.0-snapshot.1
assert "a Service that never gets an ingress IP fails instead of passing vacuously" \
  "$(rc_is 1)$(has 'never got a LoadBalancer ingress IP' "$OUT")"

STUB_BEEP=1 STUB_INGRESS="10.80.0.2" run --release v0.4.0-snapshot.1
assert "an ingress list missing a node IP fails: the via-pod-less-node path would go unchecked" \
  "$(rc_is 1)$(has 'lacks node IP 10.80.0.3' "$OUT")"
STUB_BEEP=decoy run --release v0.4.0-snapshot.1
assert "only the real servicelb-controller DaemonSet counts as beep; a lookalike name is SKIPPED" \
  "$(rc_is 0)$(has 'SKIPPED: loadbalancer' "$OUT")"
STUB_BEEP=1 STUB_FAIL_MATCH="get ds -o name" run --release v0.4.0-snapshot.1
assert "a failed DaemonSet listing is FAIL, not a silent SKIPPED pass" \
  "$(rc_is 1)$(hasnt 'SKIPPED' "$OUT")$(has 'listing kube-system DaemonSets' "$OUT")"

# --- redaction and interrupts
STUB_LEAK=1 STUB_FAIL_MATCH="wait --for=condition=Ready node" run --release v0.4.0-snapshot.1
assert "the project id never reaches the run log, step logs or up logs (they get copied around)" \
  "$(hasnt 'fake-proj-123' "$OUT")$(hasnt 'fake-proj-123' "$RES")$(has 'projects/<project>/' "$RES")"
STUB_TERM_MATCH="wait --for=condition=Ready node" run --release v0.4.0-snapshot.1
assert "SIGTERM mid-run still deletes the VPSes (they bill otherwise)" \
  "$(rc_is 143)$(has 'instances delete u7s-e2e-t-cp ' "$LOG")$(has 'instances delete u7s-e2e-t-w1 ' "$LOG")"

echo "$PASS passed,$FAIL failed"
[ "$FAIL" = 0 ]

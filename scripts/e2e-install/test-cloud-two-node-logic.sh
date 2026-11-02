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
  "compute instances describe "*natIP*)
    case "$*" in *-cp\ *) echo 34.0.0.2 ;; *-w1\ *) echo 34.0.0.3 ;; *-probe\ *) echo "${STUB_PROBE_V4-203.0.113.9}" ;; *) echo 34.0.0.4 ;; esac; exit 0 ;;
  "compute instances describe "*ipv6Address*) echo "${STUB_PROBE_V6-2600:1900::4}"; exit 0 ;;
  "compute firewall-rules create "*) touch "$STUB_LOG.fw"; exit 0 ;;
  "compute firewall-rules describe "*) [ -z "${STUB_FW_LEAK:-}" ] || echo "$3"; [ -n "${STUB_FW_LEAK:-}" ]; exit $? ;;
  "compute firewall-rules delete "*) [ -z "${STUB_FW_LEAK:-}" ] || exit 1; rm -f "$STUB_LOG.fw"; exit 0 ;;
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
    # The probe is an outsider: it reaches the LB only while a firewall rule admits it, like GCE.
    admitted=0; { [ -e "$STUB_LOG.fw" ] || [ -n "${STUB_PROBE_OPEN:-}" ]; } && admitted=1
    case "$*" in
      *"ssh u7s-e2e-t-probe "*"curl-rc="*) [ "$admitted" = 1 ] && echo curl-rc=0 || echo "curl-rc=${STUB_PROBE_RC-28}" ;;
      *"ssh u7s-e2e-t-probe "*"curl -6"*) [ "$admitted" = 1 ] || exit 28; echo "${STUB_PROBE_SEEN6-[2600:1900::4]}:41234" ;;
      *"ssh u7s-e2e-t-probe "*"curl -4"*) [ "$admitted" = 1 ] || exit 28; echo "${STUB_PROBE_SEEN4-203.0.113.9}:41234" ;;
      *--mint-join-token*)
        echo "Join token created in kube-system, expires 2026-10-20T00:00:00Z (single-use): $STUB_TOKEN"
        echo "  install.sh --join https://127.0.0.1:6443 \\"
        echo "    --ca-cert-hash $STUB_HASH --tarball <path> --node-name <name>${STUB_MINT_FAMILIES:+ --cluster-ip-families $STUB_MINT_FAMILIES}" ;;
      *"get nodes -o wide"*)
        echo "u7s-e2e-t-w1.zone.internal Ready <none> 1m v1.37.1 10.80.0.3 <none> Ubuntu"
        case "${STUB_NODES:-one}" in
          one|dup) echo "u7s-e2e-t-cp.zone.internal Ready <none> 1m v1.37.1 10.80.0.2 <none> Ubuntu" ;;
        esac
        [ "${STUB_NODES:-one}" != dup ] || echo "u7s-e2e-t-cp2.zone.internal Ready <none> 1m v1.37.1 10.80.0.2 <none> Ubuntu" ;;
      *"status.addresses"*)
        case "$*" in *-cp.*) echo "10.80.0.2 ${STUB_NODE_V6-2600:1900::2}" ;; *) echo "10.80.0.3 ${STUB_NODE_V6-2600:1900::3}" ;; esac ;;
      *"spec.podCIDRs"*) echo "${STUB_PODCIDRS-10.244.0.0/24 fd00:244::/64}" ;;
      *"spec.clusterIPs"*) echo "${STUB_CLUSTERIPS-10.96.0.50 fd00:96::50}" ;;
      *"status.podIPs"*) echo "10.244.1.2 fd00:244:0:1::2" ;;
      *"dig +short"*)
        case "$*" in *" AAAA "*) echo "${STUB_AAAA-fd00:96::50}" ;; *) echo "${STUB_A-10.96.0.50}" ;; esac ;;
      *kubeletVersion*) echo v1.37.1 ;;
      *"sonobuoy --kubeconfig /var/lib/u7s/kubeconfig status"*) echo "PLUGIN  STATUS  RESULT  COUNT"; echo "e2e     ${STUB_SB_STATUS-complete}  failed  1" ;;
      *"sonobuoy --kubeconfig /var/lib/u7s/kubeconfig results"*)
        printf 'Plugin: e2e\nStatus: passed\nTotal: %s\nPassed: 9\nFailed: %s\nSkipped: 0\n' "${STUB_SB_TOTAL-9}" "${STUB_SB_FAILED-0}" ;;
      *"ip -6 -o addr"*) echo "2: ens4    inet6 2600:1900::4/128 scope global dynamic" ;;
      *"curl -6"*) echo "${STUB_SEEN6-[2600:1900::4]}:41234" ;;
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
  : >"$TMP/log"; : >"$TMP/log.stdin"; rm -rf "$TMP/res" "$TMP/log.fw"
  RC=0
  OUT="$(PATH="$TMP/bin:$PATH" STUB_LOG="$TMP/log" STUB_TOKEN="$TOKEN" STUB_HASH="$HASH" \
    STUB_SCRIPT="$SCRIPT" U7S_E2E_RUN_ID=t U7S_E2E_RESULTS_DIR="$TMP/res" U7S_E2E_POLL_SLEEP=0 U7S_E2E_SONOBUOY_POLLS=3 \
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

# --- --machine-type / default stays e2-micro with no IPv6 resources
unset STUB_BEEP
run --release v0.4.0-snapshot.1
assert "the default run keeps e2-micro, IPV4_ONLY VPSes and creates no firewall rule (the release gate must not change)" \
  "$(has 'machine-type=e2-micro' "$LOG")$(hasnt 'e2-standard' "$LOG")$(hasnt 'IPV4_IPV6' "$LOG")$(hasnt 'firewall-rules' "$LOG")$(hasnt 'cluster-cidr' "$LOG")"
run --release v0.4.0-snapshot.1 --machine-type e2-small
assert "--machine-type reaches every VPS create (a bigger node for a heavier suite)" \
  "$(rc_is 0)$([ "$(grep -c 'machine-type=e2-small' <<<"$LOG")" = 2 ] && echo 1 || echo 0)"
run --release v0.4.0-snapshot.1 --machine-type 'e2-micro;rm'
assert "a machine type that is not a plain name exits 2 before creating VPSes" "$(rc_is 2)$(hasnt 'instances create' "$LOG")"
run --release v0.4.0-snapshot.1 --machine-type
assert "--machine-type without a value exits 2" "$(rc_is 2)"

# --- --dual-stack
DS_INGRESS="10.80.0.2 10.80.0.3 2600:1900::2 2600:1900::3"
export STUB_BEEP=1 STUB_INGRESS="$DS_INGRESS"
run --release v0.4.0-snapshot.1 --dual-stack
dual_out="$OUT"; dual_log="$LOG"; dual_stdin="$STDIN"
fw="$(grep 'firewall-rules create' <<<"$dual_log" || true)"
assert "--dual-stack passes on a healthy dual-stack stub cluster" "$(rc_is 0)$(has 'RESULT: PASS' "$dual_out")"
assert "every VPS (cp, w1, client, probe) is IPV4_IPV6 with a premium external v6 address (a v4-only VPS cannot carry the v6 path)" \
  "$([ "$(grep -c 'stack-type=IPV4_IPV6' <<<"$dual_log")" = 4 ] && echo 1 || echo 0)$([ "$(grep -c 'ipv6-network-tier=PREMIUM' <<<"$dual_log")" = 4 ] && echo 1 || echo 0)"
assert "--dual-stack defaults the cluster VPSes to e2-standard-2 (the sonobuoy subset saturates e2-micro) while the curl-only probe stays e2-micro" \
  "$([ "$(grep -c 'machine-type=e2-standard-2' <<<"$dual_log")" = 3 ] && echo 1 || echo 0)$([ "$(grep -c 'machine-type=e2-micro' <<<"$dual_log")" = 1 ] && echo 1 || echo 0)$(has 'machine-type=e2-micro' "$(grep 'create u7s-e2e-t-probe' <<<"$dual_log")")"
assert "the probe is created in the u7s-probe VPC, the cluster VPSes in u7s-test (an in-VPC probe would prove nothing about external reachability)" \
  "$(has 'network=u7s-probe --subnet=u7s-probe' "$(grep 'create u7s-e2e-t-probe' <<<"$dual_log")")$([ "$(grep 'instances create' <<<"$dual_log" | grep -c 'network=u7s-test ')" = 3 ] && echo 1 || echo 0)"
run --release v0.4.0-snapshot.1 --dual-stack --machine-type e2-medium
assert "an explicit --machine-type wins over the --dual-stack default" "$(has 'machine-type=e2-medium' "$LOG")$(hasnt 'e2-standard-2' "$LOG")"
assert "install.sh gets both families for pods and Services (a single-stack install would pass the node asserts vacuously)" \
  "$(has 'install.sh --cluster-cidr 10.244.0.0/16,fd00:244::/56 --service-cidr 10.96.0.0/12,fd00:96::/108' "$dual_log")"
assert "--node-ip is not passed: install.sh derives both node addresses from --iface (GCE's NIC carries the v4 address plus the v6 /96 address on the one interface)" \
  "$(hasnt 'node-ip' "$dual_log")"
assert "the join does not repeat the CIDRs (w1 learns them from the cluster)" \
  "$(hasnt 'cidr' "$(grep -- '--join' <<<"$dual_log")")"
assert "the dual-stack join carries --cluster-ip-families 4,6 (a worker without it assumes IPv4 and drops its IPv6 address, so the cluster silently loses a family)" \
  "$(has '--node-name u7s-e2e-t-w1 --cluster-ip-families 4,6' "$(grep -- '--join' <<<"$dual_log")")"
fw4="$(grep 'firewall-rules create u7s-e2e-t-lb-v4' <<<"$dual_log" || true)"
fw6="$(grep 'firewall-rules create u7s-e2e-t-lb-v6' <<<"$dual_log" || true)"
assert "the v4 LB firewall rule opens only the LB port, to tagged VPSes, from the probe's external /32 alone (never the in-subnet client, 0.0.0.0/0 or all ports; GCE rules cannot mix families)" \
  "$(has 'rules=tcp:80' "$fw4")$(has 'target-tags=u7s-test-vps' "$fw4")$(has 'source-ranges=203.0.113.9/32 ' "$fw4 ")$(hasnt '0.0.0.0/0' "$fw4")$(hasnt '10.80.0.4' "$fw4")$(has 'direction=INGRESS' "$fw4")$(has 'network=u7s-test' "$fw4")"
assert "the v6 LB firewall rule opens only the LB port, to tagged VPSes, from the probe's own /96 alone (never the client's, ::/0 or all ports)" \
  "$(has 'rules=tcp:80' "$fw6")$(has 'target-tags=u7s-test-vps' "$fw6")$(has 'source-ranges=2600:1900::4/96 ' "$fw6 ")$(hasnt '::/0' "$fw6")$(has 'direction=INGRESS' "$fw6")"
assert "exactly the two LB firewall rules are created (nothing else is opened)" \
  "$([ "$(grep -c 'firewall-rules create' <<<"$dual_log")" = 2 ] && echo 1 || echo 0)"
assert "both LB firewall rules and the probe VM are deleted on a PASS (the rules admit a public address, the probe bills)" \
  "$(has 'firewall-rules delete u7s-e2e-t-lb-v6' "$dual_log")$(has 'firewall-rules delete u7s-e2e-t-lb-v4' "$dual_log")$(has 'instances delete u7s-e2e-t-probe ' "$dual_log")"
neg_first="$(grep -n 'curl-rc=' <<<"$dual_log" | head -1 | cut -d: -f1)"
neg_last="$(grep -n 'curl-rc=' <<<"$dual_log" | tail -1 | cut -d: -f1)"
fw_first="$(grep -n 'firewall-rules create' <<<"$dual_log" | head -1 | cut -d: -f1)"
pos_first="$(grep -n 'ssh u7s-e2e-t-probe .*-fsS' <<<"$dual_log" | head -1 | cut -d: -f1)"
assert "the probe is refused (negative) strictly before any LB rule exists and admitted only after both rules: otherwise the pass cannot show the rule is what admits outside traffic" \
  "$([ -n "$neg_first" ] && [ -n "$pos_first" ] && [ "$neg_last" -lt "$fw_first" ] && [ "$fw_first" -lt "$pos_first" ] && echo 1 || echo 0)"
probe_log="$(grep 'ssh u7s-e2e-t-probe' <<<"$dual_log")"
assert "the probe curls the nodes' external IPv4 and the v6 ingress with -4/-6, never the internal 10.80.x addresses another VPC cannot reach" \
  "$(has 'curl -4 -g -fsS --max-time 15 http://34.0.0.2/clientip' "$probe_log")$(has 'curl -4 -g -fsS --max-time 15 http://34.0.0.3/clientip' "$probe_log")$(has "curl -6 -g -fsS --max-time 15 'http://[2600:1900::2]/clientip'" "$probe_log")$(has "curl -6 -g -fsS --max-time 15 'http://[2600:1900::3]/clientip'" "$probe_log")$(hasnt 'http://10.80' "$probe_log")"
assert "the probe sends the negative curls over both families too (a v4-only refusal would not cover v6)" \
  "$(has 'curl -4 -g -sS --max-time 10 http://34.0.0.2/clientip' "$probe_log")$(has "curl -6 -g -sS --max-time 10 'http://[2600:1900::2]/clientip'" "$probe_log")"
assert "the probe results are reported" "$(has 'PASS: probe refused by 34.0.0.2 before the LB rule' "$(cat "$TMP"/res/probe-refused-without-rule.log)")$(has 'PASS: probe in u7s-probe reached 34.0.0.2 over IPv4' "$(cat "$TMP"/res/probe-reaches-lb.log)")"
assert "the in-subnet client checks still run alongside the probe" \
  "$(has 'ssh u7s-e2e-t-client' "$dual_log")$(has 'PASS: lb 10.80.0.2 answered over IPv4' "$dual_out")$(has 'PASS: lb 2600:1900::2 answered over IPv6' "$dual_out")"
assert "nodes carry both InternalIP families and two podCIDRs (checked per node)" \
  "$(has 'PASS: node u7s-e2e-t-cp.zone.internal InternalIP dual-stack' "$(cat "$TMP"/res/dual-nodes.log)")$(has 'PASS: node u7s-e2e-t-w1 podCIDRs dual-stack' "$(cat "$TMP"/res/dual-nodes.log)")"
assert "a PreferDualStack Service and a dnsutils pod are applied" \
  "$(has 'ipFamilyPolicy: PreferDualStack' "$dual_stdin")$(has 'jessie-dnsutils' "$dual_stdin")"
assert "the LoadBalancer Service is PreferDualStack too (else beep never sees a v6 family)" \
  "$([ "$(grep -c 'ipFamilyPolicy: PreferDualStack' <<<"$dual_stdin")" = 2 ] && echo 1 || echo 0)"
assert "CoreDNS is asked for A and AAAA from a pod" "$(has 'dig +short +time=5 A ds.default' "$dual_log")$(has 'dig +short +time=5 AAAA ds.default' "$dual_log")"
assert "pod-to-pod and pod-to-Service run per family, v6 in brackets" \
  "$(has "connect 10.244.1.2:8080" "$dual_log")$(has "connect '[fd00:244:0:1::2]:8080'" "$dual_log")$(has "connect 10.96.0.50:80" "$dual_log")$(has "connect '[fd00:96::50]:80'" "$dual_log")"
assert "the LB is curled from the client over IPv4 (-4) and IPv6 (-6) on every ingress address" \
  "$(has 'curl -4 -g -fsS --max-time 15 http://10.80.0.2/clientip' "$dual_log")$(has 'curl -4 -g -fsS --max-time 15 http://10.80.0.3/clientip' "$dual_log")$(has "curl -6 -g -fsS --max-time 15 'http://[2600:1900::2]/clientip'" "$dual_log")$(has "curl -6 -g -fsS --max-time 15 'http://[2600:1900::3]/clientip'" "$dual_log")"
assert "sonobuoy runs the upstream dual-stack focus with the node's own conformance image tag" \
  "$(has "--e2e-focus 'IPv6DualStack|dual-stack|DualStack|ipFamilyPolicy'" "$dual_log")$(has 'registry.k8s.io/conformance:v1.37.1' "$dual_log")"
assert "sonobuoy results are reported inline" "$(has 'Total: 9' "$dual_out")$(has 'Failed: 0' "$dual_out")"
assert "the default (single-stack) run never reaches the dual-stack assertions" \
  "$(hasnt 'dual-nodes' "$(STUB_BEEP=1 run --release v0.4.0-snapshot.1; echo "$OUT")")"

export STUB_BEEP=1 STUB_INGRESS="$DS_INGRESS"
STUB_NODE_V6= run --release v0.4.0-snapshot.1 --dual-stack
assert "a node with no IPv6 InternalIP fails (an IPv4-only node would otherwise pass)" "$(rc_is 1)$(has 'lacks an IPv4 or IPv6 entry' "$(cat "$TMP"/res/dual-nodes.log)")"
STUB_PODCIDRS=10.244.0.0/24 run --release v0.4.0-snapshot.1 --dual-stack
assert "a node with a single podCIDR fails (no IPv6 pod range allocated)" "$(rc_is 1)$(has 'podCIDRs' "$(cat "$TMP"/res/dual-nodes.log)")"
STUB_CLUSTERIPS=10.96.0.50 run --release v0.4.0-snapshot.1 --dual-stack
assert "a PreferDualStack Service with one clusterIP fails" "$(rc_is 1)$(has 'clusterIPs' "$(cat "$TMP"/res/dual-workload.log)")"
STUB_AAAA= run --release v0.4.0-snapshot.1 --dual-stack
assert "an empty AAAA answer from CoreDNS fails" "$(rc_is 1)$(has 'AAAA answer' "$(cat "$TMP"/res/dual-workload.log)")"
STUB_A=10.96.9.9 run --release v0.4.0-snapshot.1 --dual-stack
assert "a wrong A answer from CoreDNS fails" "$(rc_is 1)$(has 'A answer' "$(cat "$TMP"/res/dual-workload.log)")"
STUB_FAIL_MATCH="connect '[fd00:96::50]:80'" run --release v0.4.0-snapshot.1 --dual-stack
assert "a Service unreachable over IPv6 fails" "$(rc_is 1)$(has 'pod-to-Service over IPv6' "$(cat "$TMP"/res/dual-workload.log)")"
STUB_INGRESS="10.80.0.2 10.80.0.3" run --release v0.4.0-snapshot.1 --dual-stack
assert "a LoadBalancer with only IPv4 ingress fails (beep v6 not advertised)" "$(rc_is 1)$(has 'lacks an IPv4 or IPv6' "$OUT")"
STUB_INGRESS="10.80.0.2 10.80.0.3 2600:1900::2" run --release v0.4.0-snapshot.1 --dual-stack
assert "an ingress list missing a node's IPv6 fails" "$(rc_is 1)$(has 'lacks node IP 2600:1900::3' "$OUT")"
STUB_SEEN6="[2600:1900::99]" run --release v0.4.0-snapshot.1 --dual-stack
assert "an IPv6 LB that SNATs the client fails" "$(rc_is 1)$(has 'backend saw client 2600:1900::99' "$OUT")"
STUB_PROBE_V6= run --release v0.4.0-snapshot.1 --dual-stack
assert "a probe VPS without external IPv6 fails before any firewall rule is made (no source to scope it to)" \
  "$(rc_is 1)$(hasnt 'firewall-rules create' "$LOG")$(has 'instances delete u7s-e2e-t-probe ' "$LOG")"
STUB_PROBE_V4= run --release v0.4.0-snapshot.1 --dual-stack
assert "a probe VPS without external IPv4 fails before any firewall rule is made" \
  "$(rc_is 1)$(hasnt 'firewall-rules create' "$LOG")"
STUB_PROBE_OPEN=1 run --release v0.4.0-snapshot.1 --dual-stack
assert "a probe that reaches the LB with no rule fails (outside traffic admitted without the rule means the positive check proves nothing) and no rule is ever created" \
  "$(rc_is 1)$(has 'with no LB firewall rule' "$(cat "$TMP"/res/probe-refused-without-rule.log)")$(hasnt 'firewall-rules create' "$LOG")"
STUB_FAIL_MATCH="curl-rc=" run --release v0.4.0-snapshot.1 --dual-stack
assert "a dead IAP tunnel during the negative check is a FAIL, never read as the LB refusing the probe" \
  "$(rc_is 1)$(has 'tunnel failure' "$(cat "$TMP"/res/probe-refused-without-rule.log)")$(hasnt 'firewall-rules create' "$LOG")"
STUB_PROBE_RC= run --release v0.4.0-snapshot.1 --dual-stack
assert "a probe that returns no curl exit status fails rather than counting as refused" \
  "$(rc_is 1)$(has 'no curl exit status' "$(cat "$TMP"/res/probe-refused-without-rule.log)")"
STUB_PROBE_SEEN4=10.80.0.9 run --release v0.4.0-snapshot.1 --dual-stack
assert "an LB that SNATs the probe's IPv4 fails: the probe must be seen as its own external address" \
  "$(rc_is 1)$(has 'backend saw probe as 10.80.0.9' "$(cat "$TMP"/res/probe-reaches-lb.log)")"
STUB_PROBE_SEEN6="[2600:1900::99]" run --release v0.4.0-snapshot.1 --dual-stack
assert "an LB that SNATs the probe's IPv6 fails" "$(rc_is 1)$(has 'backend saw probe as 2600:1900::99' "$(cat "$TMP"/res/probe-reaches-lb.log)")"
STUB_FAIL_MATCH="ssh u7s-e2e-t-probe" run --release v0.4.0-snapshot.1 --dual-stack
assert "a probe whose ssh never comes up fails and still deletes the probe and creates no firewall rule" \
  "$(rc_is 1)$(has 'u7s-e2e-t-probe never became reachable' "$OUT")$(has 'instances delete u7s-e2e-t-probe ' "$LOG")$(hasnt 'firewall-rules create' "$LOG")"
STUB_FAIL_MATCH="--e2e-focus" run --release v0.4.0-snapshot.1 --dual-stack
assert "a FAIL after the probe check deletes the probe too" "$(rc_is 1)$(has 'instances delete u7s-e2e-t-probe ' "$LOG")"
STUB_TERM_MATCH="ssh u7s-e2e-t-probe --tunnel-through-iap -- curl -4 -g -fsS" run --release v0.4.0-snapshot.1 --dual-stack
assert "SIGTERM mid-probe still deletes the probe VM and both firewall rules" \
  "$(rc_is 143)$(has 'instances delete u7s-e2e-t-probe ' "$LOG")$(has 'firewall-rules delete u7s-e2e-t-lb-v4' "$LOG")$(has 'firewall-rules delete u7s-e2e-t-lb-v6' "$LOG")"
GCP_DELETE_SLEEP=0 GCP_DELETE_TRIES=2 STUB_DELETE_FAIL=1 run --release v0.4.0-snapshot.1 --dual-stack
assert "a probe VM that cannot be deleted is listed as leaked and turns a PASS into exit 4" \
  "$(rc_is 4)$(has 'u7s-e2e-t-probe' "$(cat "$TMP"/res/leaked-vps.txt)")"
STUB_BEEP=1 STUB_INGRESS="10.80.0.2 10.80.0.3" run --release v0.4.0-snapshot.1
assert "the single-stack run creates no probe and no firewall rule (the release gate must not change)" \
  "$(rc_is 0)$(hasnt 'probe' "$LOG")$(hasnt 'firewall-rules' "$LOG")"
STUB_SB_TOTAL=0 run --release v0.4.0-snapshot.1 --dual-stack
assert "a sonobuoy focus that ran zero specs fails (vacuous pass)" "$(rc_is 1)$(has 'ran no specs' "$(cat "$TMP"/res/sonobuoy-dual.log)")"
STUB_SB_FAILED=5 run --release v0.4.0-snapshot.1 --dual-stack
assert "failed upstream dual-stack specs fail the run" "$(rc_is 1)$(has 'has failed specs' "$(cat "$TMP"/res/sonobuoy-dual.log)")"
STUB_SB_STATUS=running run --release v0.4.0-snapshot.1 --dual-stack
assert "a sonobuoy run that never completes fails" "$(rc_is 1)$(has 'never completed' "$(cat "$TMP"/res/sonobuoy-dual.log)")"
STUB_BEEP=0 run --release v0.4.0-snapshot.1 --dual-stack
assert "--dual-stack on a release without beep fails instead of SKIPPED-passing the LB check" "$(rc_is 1)$(hasnt 'SKIPPED' "$OUT")"
STUB_FAIL_MATCH="--e2e-focus" run --release v0.4.0-snapshot.1 --dual-stack
assert "a failing run still deletes the firewall rule and all the VPSes (nothing may keep billing or stay open)" \
  "$(rc_is 1)$(has 'firewall-rules delete u7s-e2e-t-lb-v6' "$LOG")$(has 'instances delete u7s-e2e-t-client ' "$LOG")$(has 'instances delete u7s-e2e-t-cp ' "$LOG")"
STUB_FAIL_MATCH="--e2e-focus" STUB_TERM_MATCH="--e2e-focus" run --release v0.4.0-snapshot.1 --dual-stack
assert "SIGTERM mid-sonobuoy still deletes the firewall rule" "$(rc_is 143)$(has 'firewall-rules delete u7s-e2e-t-lb-v6' "$LOG")"
STUB_FW_LEAK=1 GCP_DELETE_SLEEP=0 run --release v0.4.0-snapshot.1 --dual-stack
assert "a firewall rule that cannot be deleted is reported as leaked and turns a PASS into exit 4" \
  "$(rc_is 4)$(has 'LEAKED FIREWALL RULE u7s-e2e-t-lb-v6' "$OUT")"
run --release v0.4.0-snapshot.1 --dual-stack --keep
assert "--keep leaves the firewall rules and the probe VM and says how to delete each" \
  "$(rc_is 0)$(hasnt 'firewall-rules delete' "$LOG")$(hasnt 'instances delete' "$LOG")$(has 'gcloud compute firewall-rules delete u7s-e2e-t-lb-v6' "$OUT")$(has 'gcloud compute firewall-rules delete u7s-e2e-t-lb-v4' "$OUT")$(has 'scripts/gcp/vps.sh down u7s-e2e-t-probe' "$OUT")"
STUB_MINT_FAMILIES=6,4 run --release v0.4.0-snapshot.1 --dual-stack
assert "the join uses the families the control plane printed rather than a guess (so ordering and future values follow the cluster)" \
  "$(rc_is 0)$(has '--cluster-ip-families 6,4' "$(grep -- '--join' <<<"$LOG")")$(hasnt '--cluster-ip-families 4,6' "$LOG")"
STUB_BEEP=0 run --release v0.4.0-snapshot.1
assert "single-stack joins are unchanged: no --cluster-ip-families flag" "$(hasnt 'cluster-ip-families' "$LOG")"
unset STUB_BEEP STUB_INGRESS

# --- redaction and interrupts
STUB_LEAK=1 STUB_FAIL_MATCH="wait --for=condition=Ready node" run --release v0.4.0-snapshot.1
assert "the project id never reaches the run log, step logs or up logs (they get copied around)" \
  "$(hasnt 'fake-proj-123' "$OUT")$(hasnt 'fake-proj-123' "$RES")$(has 'projects/<project>/' "$RES")"
STUB_TERM_MATCH="wait --for=condition=Ready node" run --release v0.4.0-snapshot.1
assert "SIGTERM mid-run still deletes the VPSes (they bill otherwise)" \
  "$(rc_is 143)$(has 'instances delete u7s-e2e-t-cp ' "$LOG")$(has 'instances delete u7s-e2e-t-w1 ' "$LOG")"

echo "$PASS passed,$FAIL failed"
[ "$FAIL" = 0 ]

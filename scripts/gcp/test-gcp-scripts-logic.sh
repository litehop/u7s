#!/usr/bin/env bash
# Logic test for scripts/gcp/{setup,vps}.sh against a stub gcloud on PATH. The scripts
# act on a real, shared GCP project, so what matters is: dry-run can never change it,
# a wrong/missing gcloud configuration never falls through to another project, VPSes
# are always cheap-and-self-limiting Spot VMs, and gc cannot touch unrelated instances.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

PASS=0; FAIL=0
assert() {
  local label="$1" ok="$2"
  if [[ "$ok" =~ ^1+$ ]]; then echo "PASS: $label"; PASS=$((PASS + 1)); else echo "FAIL: $label"; FAIL=$((FAIL + 1)); fi
}
has() { grep -qF -- "$1" <<<"$2" && echo 1 || echo 0; }
hasnt() { grep -qF -- "$1" <<<"$2" && echo 0 || echo 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/bin"
export GCP_DELETE_SLEEP=0 GCP_OPS_SLEEP=0

cat >"$TMP/bin/gcloud" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$STUB_LOG"
echo "${CLOUDSDK_ACTIVE_CONFIG_NAME-<unset>}" >>"$STUB_LOG.cfg"
env | grep '^CLOUDSDK_' >>"$STUB_LOG.env" || true
case "$*" in
  "config configurations describe "*) [ "${STUB_NO_CONFIG:-0}" = 1 ] && exit 1; exit 0 ;;
  "config get-value project") echo "${CLOUDSDK_CORE_PROJECT:-${STUB_PROJECT-proj}}"; exit 0 ;;
  "config get-value account") echo "${CLOUDSDK_CORE_ACCOUNT:-${STUB_ACCOUNT-acct@example.com}}"; exit 0 ;;
  "config get-value compute/zone") echo "${CLOUDSDK_COMPUTE_ZONE:-${STUB_ZONE-us-west1-b}}"; exit 0 ;;
  "services list "*) echo "${STUB_SERVICES:-}"; exit 0 ;;
  "compute networks subnets describe "*) case "$*" in *externalIpv6Prefix*) echo "${STUB_V6_PREFIX-2600:1900:4000:1::/64}" ;; *) echo "${STUB_STACK-IPV4_IPV6}" ;; esac; exit 0 ;;
  "compute instances list "*) echo "${STUB_INSTANCES:-}"; exit 0 ;;
  "compute instances describe "*) case "$* " in *" ${STUB_DESCRIBE_FAIL:-<none>} "*) exit 1 ;; *" ${STUB_NOTFOUND:-<none>} "*) echo "ERROR: (gcloud.compute.instances.describe) The resource was not found" >&2; exit 1 ;; esac; echo "${STUB_LABEL-1}"; exit 0 ;;
  "compute operations list "*) [ "${STUB_OPS_FAIL:-0}" = 1 ] && { echo "ERROR: denied on proj" >&2; exit 1; }; echo "${STUB_OPS:-}"; exit 0 ;;
  "compute "*" list "*)
    [ "${STUB_LIST_FAIL:-0}" = 1 ] && exit 1
    for w in ${STUB_EXISTING:-}; do case "$* " in *"name=$w "*) echo "$w" ;; esac; done
    exit 0 ;;
esac
exit 0
EOF
chmod +x "$TMP/bin/gcloud"

# run <script> args... -> sets OUT, RC, LOG (gcloud calls)
run() {
  : >"$TMP/log"; : >"$TMP/log.cfg"; : >"$TMP/log.env"
  RC=0
  OUT="$(PATH="$TMP/bin:$PATH" STUB_LOG="$TMP/log" "$@" 2>&1)" || RC=$?
  LOG="$(cat "$TMP/log")"
  CFG="$(sort -u "$TMP/log.cfg")"
  ENVS="$(sort -u "$TMP/log.env")"
}

SETUP="$HERE/setup.sh"
VPS="$HERE/vps.sh"

# --- setup.sh --dry-run
export STUB_SERVICES="compute.googleapis.com"
unset STUB_EXISTING || true
run "$SETUP" --dry-run
assert "dry-run exits 0 on an empty project" "$([ "$RC" = 0 ] && echo 1 || echo 0)"
READ_ONLY_RE='^(config get-value |config configurations describe |services list |compute [a-z-]+( subnets)? (list|describe) )'
admitted="$(grep -E "$READ_ONLY_RE" <<<$'compute instances delete list x\ncompute networks delete describe x\ncompute instances list x' || true)"
assert "the read-only allowlist admits only list/describe verbs, not a delete of a resource named list/describe (else a mutating dry run would pass the check)" \
  "$([ "$admitted" = 'compute instances list x' ] && echo 1 || echo 0)"
not_read_only="$(grep -vE "$READ_ONLY_RE" <<<"$LOG" || true)"
assert "dry-run issues only allowlisted read-only gcloud calls (a mutating dry run would change the operator's project without review); offender: '$not_read_only'" \
  "$([ -z "$not_read_only" ] && [ -n "$LOG" ] && echo 1 || echo 0)"
assert "dry-run prints its target first so the operator approves the real run against the right project" \
  "$([ "$(head -1 <<<"$OUT")" = "target: project=proj account=acct@example.com config=u7s-gcp" ] && echo 1 || echo 0)"
assert "every gcloud call runs under the u7s-gcp configuration (else it hits the operator's default project)" \
  "$([ "$CFG" = u7s-gcp ] && echo 1 || echo 0)"
CLOUDSDK_CORE_PROJECT=evil run "$SETUP" --dry-run
assert "a stray CLOUDSDK_CORE_PROJECT cannot retarget the scripts away from the named configuration" \
  "$(has 'project=proj ' "$OUT")$(hasnt 'evil' "$OUT")"
CLOUDSDK_CORE_ACCOUNT=evil@example.com run "$SETUP" --dry-run
assert "a stray CLOUDSDK_CORE_ACCOUNT cannot change the account" "$(hasnt 'evil@' "$OUT")"
U7S_GCP_CONFIG=other run "$SETUP" --dry-run
assert "U7S_GCP_CONFIG selects the configuration for every call and the target line" \
  "$([ "$CFG" = other ] && echo 1 || echo 0)$(has 'config=other' "$OUT")"
assert "dry-run still queried project state" "$(has 'services list' "$LOG")"
assert "dry-run prints the IAP enable it would run" "$(has 'WOULD RUN: gcloud services enable iap.googleapis.com' "$OUT")"
assert "dry-run does not re-enable compute when already on" "$(hasnt 'enable compute.googleapis.com' "$OUT")"
assert "dry-run prints VPC create (custom mode)" "$(has 'WOULD RUN: gcloud compute networks create u7s-test --subnet-mode=custom' "$OUT")"
assert "dry-run prints the 10.80.0.0/24 us-west1 subnet" "$(has '--range=10.80.0.0/24 --region=us-west1' "$OUT")"
assert "dry-run prints IAP-only ssh firewall" "$(has '--allow=tcp:22 --source-ranges=35.235.240.0/20' "$OUT")"
assert "dry-run prints intra-subnet firewall" "$(has '--allow=all --source-ranges=10.80.0.0/24' "$OUT")"

# structural: no mutating gcloud call outside mutate(), so --dry-run cannot reach one
bare="$(grep -nE 'gcloud[^"]* (create|enable|delete|update)( |$)' "$SETUP" | grep -v '^\s*[0-9]*:\s*#' | grep -v 'WOULD RUN' || true)"
assert "setup.sh has no mutating gcloud call except via mutate()" \
  "$([ -z "$bare" ] && [ -z "$(grep -E '&& exists |if \[ .* exists ' "$SETUP" | grep -v ' list')" ] && echo 1 || echo 0)"

# idempotent: everything exists -> nothing to do, in both modes
export STUB_SERVICES=$'compute.googleapis.com\niap.googleapis.com'
export STUB_EXISTING="u7s-test u7s-test-allow-iap-ssh u7s-test-allow-internal u7s-test-allow-internal-v6"
run "$SETUP" --dry-run
assert "a fully set-up project yields no planned changes (setup must be re-runnable)" "$(hasnt 'WOULD RUN' "$OUT")"
run "$SETUP"
assert "real mode on a fully set-up project makes no mutating call" \
  "$([ -z "$(grep -E ' (create|enable)( |$)' <<<"$LOG")" ] && [ "$RC" = 0 ] && echo 1 || echo 0)"

# partial state: only the missing pieces are planned
export STUB_EXISTING="u7s-test u7s-test-allow-iap-ssh"
run "$SETUP" --dry-run
assert "partial state plans only the missing internal firewall rule (existing ones must not be recreated)" \
  "$(has 'WOULD RUN: gcloud compute firewall-rules create u7s-test-allow-internal' "$OUT")$(hasnt 'networks create' "$OUT")$(hasnt 'allow-iap-ssh' "$(grep 'WOULD RUN' <<<"$OUT")")$(hasnt 'subnets create' "$OUT")"
export STUB_EXISTING="u7s-test"
run "$SETUP" --dry-run
assert "network without firewalls plans both firewall rules but no network" \
  "$(has 'create u7s-test-allow-iap-ssh' "$OUT")$(has 'create u7s-test-allow-internal' "$OUT")$(hasnt 'networks create' "$OUT")"
export STUB_EXISTING="u7s-test-allow-iap-ssh"
run "$SETUP" --dry-run
assert "a name that merely contains another resource's name does not count as existing" \
  "$(has 'networks create u7s-test --subnet-mode=custom' "$OUT")"
export STUB_EXISTING="u7s-test u7s-test-allow-iap-ssh u7s-test-allow-internal u7s-test-allow-internal-v6"
STUB_LIST_FAIL=1 run "$SETUP" --dry-run
assert "a failing gcloud list (e.g. permission denied) aborts instead of reading as 'not found'" \
  "$([ "$RC" != 0 ] && echo 1 || echo 0)$(hasnt 'WOULD RUN' "$OUT")"

# --- dual-stack subnet and IPv6 firewall
export STUB_EXISTING="u7s-test u7s-test-allow-iap-ssh u7s-test-allow-internal u7s-test-allow-internal-v6"
STUB_STACK=IPV4_ONLY run "$SETUP" --dry-run
assert "an IPV4_ONLY subnet is updated in place to external dual-stack (dual-stack VMs cannot get IPv6 otherwise) and not recreated" \
  "$(has 'WOULD RUN: gcloud compute networks subnets update u7s-test --region=us-west1 --stack-type=IPV4_IPV6 --ipv6-access-type=EXTERNAL' "$OUT")$(hasnt 'subnets create' "$OUT")"
STUB_STACK=IPV4_IPV6 run "$SETUP" --dry-run
assert "an already dual-stack subnet is left alone (setup must be re-runnable)" "$(hasnt 'subnets update' "$OUT")"
export STUB_EXISTING="u7s-test u7s-test-allow-iap-ssh u7s-test-allow-internal"
run "$SETUP" --dry-run
assert "the IPv6 internal rule mirrors the IPv4 one (allow all, source restricted to the subnet's own range) and never opens ::/0" \
  "$(has 'WOULD RUN: gcloud compute firewall-rules create u7s-test-allow-internal-v6 --network=u7s-test --direction=INGRESS --allow=all --source-ranges=<subnet-external-ipv6-prefix>' "$OUT")$(hasnt '::/0' "$OUT")$(hasnt '0.0.0.0/0' "$OUT")"
assert "there is no IPv6 ssh rule (IAP is IPv4-only, so ssh stays IAP-only)" "$(hasnt 'iap-ssh-v6' "$OUT")"
run "$SETUP"
assert "real mode feeds the subnet's actual external IPv6 /64 into the IPv6 rule" \
  "$(has 'firewall-rules create u7s-test-allow-internal-v6 --network=u7s-test --direction=INGRESS --allow=all --source-ranges=2600:1900:4000:1::/64' "$LOG")"
STUB_V6_PREFIX= run "$SETUP"
assert "real mode aborts rather than creating an IPv6 rule with an empty source range" \
  "$([ "$RC" != 0 ] && echo 1 || echo 0)$(hasnt 'internal-v6' "$LOG")"
unset STUB_EXISTING
run "$SETUP" --dry-run
assert "a missing subnet is created dual-stack from the start" \
  "$(has '--range=10.80.0.0/24 --region=us-west1 --stack-type=IPV4_IPV6 --ipv6-access-type=EXTERNAL' "$OUT")"

# real mode executes what dry-run would print
export STUB_SERVICES="compute.googleapis.com"
unset STUB_EXISTING
run "$SETUP"
assert "real mode runs the IAP enable" "$(has 'services enable iap.googleapis.com' "$LOG")"
assert "real mode runs the VPC create" "$(has 'compute networks create u7s-test --subnet-mode=custom' "$LOG")"

# --- fail loud on missing configuration / project, for every script
for args in "$SETUP --dry-run" "$SETUP" "$VPS list" "$VPS gc" "$VPS up t1" "$VPS down t1"; do
  # shellcheck disable=SC2086
  STUB_NO_CONFIG=1 run $args
  assert "'${args##*/} ' fails when the u7s-gcp configuration is missing (else gcloud would use the default project)" \
    "$([ "$RC" != 0 ] && [ -z "$(grep -E ' (create|delete|enable)( |$)' <<<"$LOG")" ] && echo 1 || echo 0)"
  # shellcheck disable=SC2086
  STUB_PROJECT= run $args
  assert "'${args##*/} ' fails when the configuration has no project" \
    "$([ "$RC" != 0 ] && [ -z "$(grep -E ' (create|delete|enable)( |$)' <<<"$LOG")" ] && echo 1 || echo 0)"
done

# --- vps.sh up
unset STUB_EXISTING
run "$VPS" up t1
assert "up succeeds" "$([ "$RC" = 0 ] && echo 1 || echo 0)"
create="$(grep 'compute instances create' <<<"$LOG" || true)"
assert "up uses SPOT (a standard VM would bill continuously)" "$(has '--provisioning-model=SPOT' "$create")"
assert "up stops, not deletes, on preemption (disk/logs survive for post-mortem)" "$(has '--instance-termination-action=STOP' "$create")"
assert "up caps lifetime at 16h (a forgotten VPS stops itself)" "$(has '--max-run-duration=16h' "$create")"
assert "up labels u7s-test=1 (gc and list find it by label)" "$(has '--labels=u7s-test=1' "$create")"
assert "up joins the u7s-test network/subnet (the IAP-only firewall applies there)" "$(has '--network=u7s-test --subnet=u7s-test' "$create")"
assert "up is e2-micro on the ubuntu-2604 family" "$(has '--machine-type=e2-micro' "$create")$(has '--image-family=ubuntu-2604-lts-amd64' "$create")"
assert "up pins the configured zone explicitly (else gcloud may prompt for one interactively)" "$(has '--zone=us-west1-b' "$create")"
STUB_ZONE= run "$VPS" up t1
assert "up without a configured zone fails instead of prompting or guessing" \
  "$([ "$RC" != 0 ] && echo 1 || echo 0)$(hasnt 'instances create' "$LOG")"
assert "up adds no firewall rules (ingress stays limited to the IAP and intra-subnet rules from setup)" "$(hasnt 'firewall' "$LOG")"

assert "up defaults to IPV4_ONLY with no IPv6 flags (existing gate/e2e VMs must not change when the subnet is dual-stack)" \
  "$(has '--stack-type=IPV4_ONLY' "$create")$(hasnt 'IPV6' "$(sed 's/IPV4_ONLY//' <<<"$create")")$(hasnt 'ipv6-network-tier' "$create")"
run "$VPS" up --stack-type IPV4_IPV6 t2
create="$(grep 'compute instances create' <<<"$LOG" || true)"
assert "up --stack-type IPV4_IPV6 requests a dual-stack NIC with external IPv6 (premium tier) while staying Spot on the same subnet" \
  "$(has 'instances create t2' "$create")$(has '--stack-type=IPV4_IPV6' "$create")$(has '--ipv6-network-tier=PREMIUM' "$create")$(has '--provisioning-model=SPOT' "$create")$(has '--subnet=u7s-test' "$create")"
run "$VPS" up --stack-type IPV6_ONLY t3
assert "an unsupported stack type is rejected before any instance is created" \
  "$([ "$RC" != 0 ] && echo 1 || echo 0)$(hasnt 'instances create' "$LOG")"

# --- ssh / scp go through IAP
run "$VPS" ssh t1 -- free -m
assert "ssh tunnels through IAP (port 22 is closed to the internet)" "$(has 'compute ssh t1 --tunnel-through-iap -- free -m' "$LOG")"
run "$VPS" scp a.txt t1:/tmp/
assert "scp tunnels through IAP" "$(has 'compute scp --tunnel-through-iap a.txt t1:/tmp/' "$LOG")"

# --- gc
export STUB_INSTANCES=$'a\tus-west1-b\nb\tus-east1-c'
run "$VPS" gc
assert "gc lists only labels.u7s-test=1 (other instances in the project must survive)" "$(has 'instances list --filter=labels.u7s-test=1' "$LOG")"
assert "gc deletes every listed instance in the zone it was listed in (a project-wide gc spans zones)" \
  "$(has 'instances delete a --zone=us-west1-b --quiet' "$LOG")$(has 'instances delete b --zone=us-east1-c --quiet' "$LOG")"
assert "gc deletes nothing it did not list" "$([ "$(grep -c 'instances delete' <<<"$LOG")" = 2 ] && echo 1 || echo 0)"
STUB_DESCRIBE_FAIL=a run "$VPS" gc
assert "gc continues past an instance it cannot describe (later instances must not be left running and billing)" \
  "$(has 'instances delete b --zone=us-east1-c --quiet' "$LOG")$(hasnt 'instances delete a ' "$LOG")"
assert "gc reports the failed instance and exits non-zero (a silent partial sweep looks like a clean one)" \
  "$([ "$RC" != 0 ] && echo 1 || echo 0)$(has 'failed to delete: a' "$OUT")$(hasnt 'failed to delete: a b' "$OUT")"
unset STUB_INSTANCES
run "$VPS" gc
assert "gc with no labelled instances deletes nothing" "$(hasnt 'delete' "$LOG")"

# --- down
run "$VPS" down t1
assert "down deletes a u7s-test=1 instance in the configured zone" "$(has 'instances delete t1 --zone=us-west1-b --quiet' "$LOG")"
CLOUDSDK_COMPUTE_ZONE=evil-zone run "$VPS" down t1
assert "a stray CLOUDSDK_COMPUTE_ZONE cannot redirect down to another zone" \
  "$(has 'instances delete t1 --zone=us-west1-b --quiet' "$LOG")$(hasnt 'evil-zone' "$LOG")"
CLOUDSDK_CONFIG=/nonexistent CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT=sa@example.com CLOUDSDK_CORE_PROJECT=evil run "$VPS" list
assert "only CLOUDSDK_ACTIVE_CONFIG_NAME survives into gcloud (config dir / impersonation vars would bypass the named configuration)" \
  "$([ "$ENVS" = 'CLOUDSDK_ACTIVE_CONFIG_NAME=u7s-gcp' ] && echo 1 || echo 0)"
STUB_LABEL= run "$VPS" down t1
assert "down refuses an unlabelled instance (it is not ours to delete)" \
  "$([ "$RC" != 0 ] && echo 1 || echo 0)$(hasnt 'instances delete' "$LOG")"
STUB_ZONE= run "$VPS" down t1
assert "down without a configured zone fails instead of guessing" \
  "$([ "$RC" != 0 ] && echo 1 || echo 0)$(hasnt 'instances delete' "$LOG")"
STUB_NOTFOUND=typo run "$VPS" down typo
assert "down of a nonexistent name fails (a typo must not report success while the real VPS keeps billing)" \
  "$([ "$RC" != 0 ] && echo 1 || echo 0)$(has 'does not exist' "$OUT")"

# --- list
run "$VPS" list
assert "list is restricted to the label and shows status (stopped VPSes still cost money)" \
  "$(has 'labels.u7s-test=1' "$LOG")$(has 'status' "$LOG")"

# --- preemption detection
# shellcheck source=lib.sh
. "$HERE/lib.sh"
export STUB_LOG="$TMP/log" PATH="$TMP/bin:$PATH"
STUB_OPS=op-1 gcp_vps_was_preempted t1 && p=1 || p=0
assert "a compute.instances.preempted operation reads as preempted (so gates report PREEMPTED, not FAIL)" "$p"
STUB_OPS= gcp_vps_was_preempted t1 && p=1 || p=0
assert "no preempted operation reads as not preempted" "$([ "$p" = 0 ] && echo 1 || echo 0)"
: >"$STUB_LOG"
STUB_OPS_FAIL=1 gcp_vps_was_preempted t1 && p=0 || p=$?
assert "a lookup that keeps failing is 'unknown' (2), not 'not preempted' (1): gates must not score a reclaimed VPS as a u7s FAIL" "$([ "$p" = 2 ] && echo 1 || echo 0)"
err="$(STUB_OPS_FAIL=1 gcp_vps_was_preempted t1 2>&1 >/dev/null || true)"
assert "a failing preemption lookup scrubs the project id from its stderr (console output gets pasted into PRs)" \
  "$(has 'denied on <project>' "$err")$(hasnt 'on proj' "$err")"
assert "the preemption lookup is retried before giving up" \
  "$([ "$(grep -c 'compute operations list' "$STUB_LOG")" -ge 3 ] && echo 1 || echo 0)"

# --- delete never exits its caller
: >"$STUB_LOG"
r=0; STUB_DESCRIBE_FAIL=t1 gcp_vps_delete t1 us-west1-b 2>/dev/null || r=$?
assert "a describe that keeps failing makes delete return non-zero, not exit the caller (an aborted gate skips later cleanup and leaks VPSes)" \
  "$([ "$r" = 1 ] && echo 1 || echo 0)"
assert "delete retries a failing describe (a transient API error must not leak a billing VPS)" \
  "$([ "$(grep -c 'instances describe' "$STUB_LOG")" = 4 ] && echo 1 || echo 0)"

r=0; STUB_NOTFOUND=t1 gcp_vps_delete t1 us-west1-b 2>/dev/null || r=$?
assert "a gate's delete of an already-gone VPS counts as deleted (a retried cleanup must not report a phantom leak)" \
  "$([ "$r" = 0 ] && echo 1 || echo 0)"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]

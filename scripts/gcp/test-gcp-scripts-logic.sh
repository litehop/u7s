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

cat >"$TMP/bin/gcloud" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$STUB_LOG"
case "$*" in
  "config configurations describe "*) [ "${STUB_NO_CONFIG:-0}" = 1 ] && exit 1; exit 0 ;;
  "config get-value project") echo "${STUB_PROJECT-proj}"; exit 0 ;;
  "services list "*) echo "${STUB_SERVICES:-}"; exit 0 ;;
  "compute instances list "*) echo "${STUB_INSTANCES:-}"; exit 0 ;;
  "compute operations list "*) echo "${STUB_OPS:-}"; exit 0 ;;
  "compute "*" list "*)
    for w in ${STUB_EXISTING:-}; do case "$*" in *"name=$w"*) echo "$w" ;; esac; done
    exit 0 ;;
esac
exit 0
EOF
chmod +x "$TMP/bin/gcloud"

# run <script> args... -> sets OUT, RC, LOG (gcloud calls)
run() {
  : >"$TMP/log"
  RC=0
  OUT="$(PATH="$TMP/bin:$PATH" STUB_LOG="$TMP/log" "$@" 2>&1)" || RC=$?
  LOG="$(cat "$TMP/log")"
}

SETUP="$HERE/setup.sh"
VPS="$HERE/vps.sh"

# --- setup.sh --dry-run
export STUB_SERVICES="compute.googleapis.com"
unset STUB_EXISTING || true
run "$SETUP" --dry-run
assert "dry-run exits 0 on an empty project" "$([ "$RC" = 0 ] && echo 1 || echo 0)"
mutating="$(grep -E ' (create|enable|delete|update|add-iam-policy-binding|ssh|scp)( |$)' <<<"$LOG" | grep -v 'config configurations describe' || true)"
assert "dry-run issues no mutating gcloud call (a mutating dry run would change the operator's project without review)" \
  "$([ -z "$mutating" ] && echo 1 || echo 0)"
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
  "$([ "$(grep -cE 'gcloud "\$@"' "$SETUP")" = 2 ] && [ -z "$bare" ] && [ -z "$(grep -E '&& exists |if \[ .* exists ' "$SETUP" | grep -v ' list')" ] && echo 1 || echo 0)"

# idempotent: everything exists -> nothing to do, in both modes
export STUB_SERVICES=$'compute.googleapis.com\niap.googleapis.com'
export STUB_EXISTING="u7s-test u7s-test-allow-iap-ssh u7s-test-allow-internal"
run "$SETUP" --dry-run
assert "a fully set-up project yields no planned changes (setup must be re-runnable)" "$(hasnt 'WOULD RUN' "$OUT")"
run "$SETUP"
assert "real mode on a fully set-up project makes no mutating call" \
  "$([ -z "$(grep -E ' (create|enable)( |$)' <<<"$LOG")" ] && [ "$RC" = 0 ] && echo 1 || echo 0)"

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
assert "up gives no public SSH path: no --no-address override needed, no firewall edits" "$(hasnt 'firewall' "$LOG")"

# --- ssh / scp go through IAP
run "$VPS" ssh t1 -- free -m
assert "ssh tunnels through IAP (port 22 is closed to the internet)" "$(has 'compute ssh t1 --tunnel-through-iap -- free -m' "$LOG")"
run "$VPS" scp a.txt t1:/tmp/
assert "scp tunnels through IAP" "$(has 'compute scp --tunnel-through-iap a.txt t1:/tmp/' "$LOG")"

# --- gc
export STUB_INSTANCES=$'a\nb'
run "$VPS" gc
assert "gc lists only labels.u7s-test=1 (other instances in the project must survive)" "$(has 'instances list --filter=labels.u7s-test=1' "$LOG")"
assert "gc deletes every listed instance" "$(has 'instances delete a --quiet' "$LOG")$(has 'instances delete b --quiet' "$LOG")"
assert "gc deletes nothing it did not list" "$([ "$(grep -c 'instances delete' <<<"$LOG")" = 2 ] && echo 1 || echo 0)"
unset STUB_INSTANCES
run "$VPS" gc
assert "gc with no labelled instances deletes nothing" "$(hasnt 'delete' "$LOG")"

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

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]

#!/usr/bin/env bash
# Real-binary proof that the signing intermediate CA is re-issued before it expires, with
# clients that pin only the ROOT riding through it: nothing a client holds or trusts changes.
#
# The apiserver must run a pki-test-knobs build with U7S_PKI_TEST_INTERMEDIATE_LIFETIME_SECS
# set (run-all.sh --pki-test-intermediate <secs>), at least 3x U7S_PKI_TEST_LIFETIME_SECS so the
# leaves it signs are not clamped. The intermediate is re-issued at 2/3 of its life, so the run
# takes up to that long.
#
#   scripts/e2e-pki-rotation/intermediate-rotation.sh --kubeconfig temp/u7s/kubeconfig \
#       --workdir temp/u7s --port <PORT> --intermediate-lifetime <secs> \
#       [--scheduler] [--vm <VM> --kubelet-port <KP>]
#
# Asserts, with polling and deadlines (never fixed sleeps):
#   1. the served chain is leaf + intermediate, verifies to the root, and the leaf alone does not
#      (the documented price of a distinct intermediate); the intermediate is a pathlen:0 CA;
#   2. a kubeconfig that pins only the root, with an admin cert+chain frozen before the rotation,
#      works before and after, and a watch opened through it keeps delivering events;
#   3. the intermediate's serial changes with no apiserver restart, and ca.crt, ca.key,
#      ca-bundle.pem and kube-root-ca.crt are byte-identical afterwards;
#   4. admin, kcm and (with --scheduler) scheduler cert files are re-issued under the new
#      intermediate, and the scheduler is not restarted;
#   5. with --vm (a live KCM and kubelet): a node client certificate signed by KCM before the
#      rotation carries the chain and authenticates; one signed after it is issued by the NEW
#      intermediate (KCM picked up the new signing files) and also carries the chain; the
#      kubelet's serving certificate carries the chain, the node stays Ready, and exec/logs
#      (apiserver -> kubelet) work after the rotation.
#
# On failure the script dumps the served chain, the rotation log lines and component logs.
set -euo pipefail

POLL_INTERVAL=1

poll() {
  local deadline="$1"; shift
  local end=$((SECONDS + deadline))
  while ! "$@"; do
    [ "$SECONDS" -lt "$end" ] || return 1
    sleep "$POLL_INTERVAL"
  done
}

# cert_count <pem-text-on-stdin>: number of CERTIFICATE blocks.
cert_count() { grep -c '^-----BEGIN CERTIFICATE-----$' || true; }

# nth_cert <n> <file>: the n-th (1-based) CERTIFICATE block of a PEM file.
nth_cert() {
  awk -v n="$1" '/^-----BEGIN CERTIFICATE-----$/ {c++} c == n {print} /^-----END CERTIFICATE-----$/ {if (c == n) exit}' "$2"
}

# chain_verifies <root.pem> <chain.pem>: the first cert verifies to the root through the rest.
chain_verifies() {
  local leaf rc=0
  leaf="$(mktemp)"
  nth_cert 1 "$2" >"$leaf"
  openssl verify -CAfile "$1" -untrusted "$2" "$leaf" >/dev/null 2>&1 || rc=$?
  rm -f "$leaf"
  return "$rc"
}

# leaf_alone_verifies <root.pem> <chain.pem>: the first cert verifies with no intermediate offered.
leaf_alone_verifies() {
  local leaf rc=0
  leaf="$(mktemp)"
  nth_cert 1 "$2" >"$leaf"
  openssl verify -CAfile "$1" "$leaf" >/dev/null 2>&1 || rc=$?
  rm -f "$leaf"
  return "$rc"
}

# cert_field <n> <file> <openssl x509 flag>: e.g. cert_field 2 chain.pem -serial.
cert_field() { nth_cert "$1" "$2" | openssl x509 -noout "$3"; }

sha() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }

[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

# shellcheck source=scripts/_kill-pattern.sh
source "$(dirname "${BASH_SOURCE[0]}")/../_kill-pattern.sh"

KC=""
WORKDIR=""
PORT=""
VM=""
KUBELET_PORT=""
WITH_SCHED=0
INTERMEDIATE_LIFETIME=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig) KC="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --vm) VM="$2"; shift 2 ;;
    --kubelet-port) KUBELET_PORT="$2"; shift 2 ;;
    --scheduler) WITH_SCHED=1; shift ;;
    --intermediate-lifetime) INTERMEDIATE_LIFETIME="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[ -n "$KC" ] && [ -n "$WORKDIR" ] && [ -n "$PORT" ] && [ -n "$INTERMEDIATE_LIFETIME" ] || {
  echo "usage: $0 --kubeconfig <path> --workdir <path> --port <N> --intermediate-lifetime <s> [--scheduler] [--vm <name> --kubelet-port <N>]" >&2
  exit 1
}
[ -z "$VM" ] || [ -n "$KUBELET_PORT" ] || {
  echo "error: --vm needs --kubelet-port (the kubelet serving cert is read through it)" >&2
  exit 1
}

ABS_WORKDIR="$(cd "$WORKDIR" && pwd)"
TMP="$(mktemp -d)"
NS=default
NAME="int-rot-$$"
IMAGE="registry.k8s.io/e2e-test-images/agnhost:2.63.0"
WATCH_PID=""
# Due at 2/3 of the life, counted from the backdated notBefore, plus slack for the 1s idle floor.
ROTATION_DEADLINE=$((INTERMEDIATE_LIFETIME * 2 / 3 + 60))

k() { kubectl --kubeconfig "$KC" --request-timeout=15s "$@"; }

served_chain() {
  { openssl s_client -connect "127.0.0.1:$PORT" -servername localhost -showcerts </dev/null 2>/dev/null || true; } |
    sed -n '/^-----BEGIN CERTIFICATE-----$/,/^-----END CERTIFICATE-----$/p'
}

kubelet_chain() {
  { openssl s_client -connect "127.0.0.1:$KUBELET_PORT" -showcerts </dev/null 2>/dev/null || true; } |
    sed -n '/^-----BEGIN CERTIFICATE-----$/,/^-----END CERTIFICATE-----$/p'
}

dump_diagnostics() {
  echo "=== diagnostics ===" >&2
  echo "--- served chain ---" >&2
  served_chain >"$TMP/diag.pem" 2>/dev/null || true
  for n in 1 2 3; do
    cert_field "$n" "$TMP/diag.pem" -subject >&2 2>/dev/null || true
    cert_field "$n" "$TMP/diag.pem" -issuer >&2 2>/dev/null || true
  done
  echo "--- apiserver rotation log ---" >&2
  grep -E "rotated |rotation failed|intermediate|pki-test-knobs" "$WORKDIR/apiserver.log" >&2 || true
  echo "--- apiserver log tail ---" >&2
  tail -40 "$WORKDIR/apiserver.log" >&2 || true
  if [ -n "$VM" ]; then
    echo "--- kcm log tail ---" >&2
    limactl shell "$VM" tail -30 /tmp/kcm.log >&2 || true
    echo "--- kubelet journal ---" >&2
    limactl shell "$VM" sudo journalctl -u kubelet --no-pager --utc -n 30 >&2 || true
  fi
}

fail() {
  echo "FAIL: $*" >&2
  dump_diagnostics
  exit 1
}

cleanup() {
  [ -z "$WATCH_PID" ] || kill "$WATCH_PID" 2>/dev/null || true
  k delete csr -l "app=$NAME" --ignore-not-found >/dev/null 2>&1 || true
  k -n "$NS" delete pod "$NAME" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  k -n "$NS" delete configmap -l "app=$NAME" --ignore-not-found >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'echo "FAIL: unexpected error at line $LINENO: $BASH_COMMAND" >&2; dump_diagnostics' ERR
set -E

grep -q "pki-test-knobs: intermediate CA lifetime" "$WORKDIR/apiserver.log" ||
  fail "apiserver.log has no intermediate-lifetime knob line: the binary was not built with --features pki-test-knobs or was started without U7S_PKI_TEST_INTERMEDIATE_LIFETIME_SECS"

poll 60 k get --raw /readyz >/dev/null 2>&1 || fail "apiserver not ready"

# The root, and a kubeconfig that pins only it, with the admin cert and chain as they are now.
openssl x509 -inform DER -in "$ABS_WORKDIR/ca.crt" -out "$TMP/root.pem"
cp "$ABS_WORKDIR/admin.pem" "$TMP/frozen-admin.pem"
cat >"$TMP/frozen-kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: c
  cluster:
    server: https://127.0.0.1:$PORT
    certificate-authority: $TMP/root.pem
users:
- name: u
  user:
    client-certificate: $TMP/frozen-admin.pem
    client-key: $TMP/frozen-admin.pem
contexts:
- name: x
  context: {cluster: c, user: u}
current-context: x
EOF
kf() { kubectl --kubeconfig "$TMP/frozen-kubeconfig" --request-timeout=15s "$@"; }

[ "$(cert_count <"$TMP/frozen-admin.pem")" = 2 ] ||
  fail "admin.pem must hold the leaf and its intermediate, found $(cert_count <"$TMP/frozen-admin.pem") certificate(s)"
kf get namespaces >/dev/null || fail "a root-only kubeconfig with the admin cert+chain does not authenticate"

served_chain >"$TMP/chain0.pem"
[ "$(cert_count <"$TMP/chain0.pem")" = 2 ] ||
  fail "the apiserver must present leaf + intermediate, presented $(cert_count <"$TMP/chain0.pem") certificate(s)"
chain_verifies "$TMP/root.pem" "$TMP/chain0.pem" || fail "the served chain does not verify to the root"
! leaf_alone_verifies "$TMP/root.pem" "$TMP/chain0.pem" ||
  fail "the served leaf verifies to the root without its intermediate: the root must not be signing leaves"
INTERMEDIATE_TEXT="$(nth_cert 2 "$TMP/chain0.pem" | openssl x509 -noout -text)"
[[ "$INTERMEDIATE_TEXT" == *"pathlen:0"* ]] ||
  fail "the intermediate is not constrained to pathlen:0"
I0="$(cert_field 2 "$TMP/chain0.pem" -serial)"
echo "PASS: served chain is leaf + intermediate $I0, verifies to the root, and the leaf alone does not; admin.pem carries the chain"

# A KCM-signed client cert: bare leaf out of KCM, chain appended by the apiserver.
kcm_client() { # kcm_client <tag> -> $TMP/<tag>.pem (chain) and $TMP/<tag>.key
  local tag="$1" csr="csr-$NAME-$1"
  openssl ecparam -genkey -name prime256v1 -noout -out "$TMP/$tag.key"
  openssl req -new -key "$TMP/$tag.key" -subj "/O=system:nodes/CN=system:node:$NAME-$tag" -out "$TMP/$tag.csr" 2>/dev/null
  k apply -f - >/dev/null <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: $csr
  labels: {app: $NAME}
spec:
  request: $(base64 <"$TMP/$tag.csr" | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client-kubelet
  usages: ["digital signature", "key encipherment", "client auth"]
EOF
  k certificate approve "$csr" >/dev/null
  csr_issued() { [ -n "$(k get csr "$csr" -o jsonpath='{.status.certificate}' 2>/dev/null)" ]; }
  poll 90 csr_issued || fail "KCM never signed CSR $csr"
  k get csr "$csr" -o jsonpath='{.status.certificate}' | base64 -d >"$TMP/$tag.pem"
}

whoami_with() { # whoami_with <tag>
  kubectl --kubeconfig /dev/null --server "https://127.0.0.1:$PORT" --certificate-authority "$TMP/root.pem" \
    --client-certificate "$TMP/$1.pem" --client-key "$TMP/$1.key" --request-timeout=15s \
    auth whoami -o jsonpath='{.status.userInfo.username}' 2>/dev/null
}

if [ -n "$VM" ]; then
  kcm_client before
  [ "$(cert_count <"$TMP/before.pem")" = 2 ] ||
    fail "the KCM-signed client cert carries $(cert_count <"$TMP/before.pem") certificate(s), expected leaf + intermediate"
  chain_verifies "$TMP/root.pem" "$TMP/before.pem" || fail "the KCM-signed client cert does not verify to the root"
  [ "$(whoami_with before)" = "system:node:$NAME-before" ] ||
    fail "the KCM-signed client cert does not authenticate against a root-only trust store"
  echo "PASS: KCM-signed node client cert carries the chain and authenticates (root-only trust)"
fi

SHA_CA="$(sha "$ABS_WORKDIR/ca.crt")"
SHA_KEY="$(sha "$ABS_WORKDIR/ca.key")"
SHA_BUNDLE="$(sha "$ABS_WORKDIR/ca-bundle.pem")"
ROOT_CM="$(k -n "$NS" get configmap kube-root-ca.crt -o 'jsonpath={.data.ca\.crt}' 2>/dev/null || true)"
APISERVER_PID="$(pgrep -f "$(workdir_kill_pattern apiserver "$ABS_WORKDIR")" | sed -n 1p || true)"

if [ "$WITH_SCHED" = 1 ] || [ -n "$VM" ]; then
  SCHED_PID="$(pgrep -f "$(workdir_kill_pattern scheduler "$ABS_WORKDIR")" | sed -n 1p || true)"
  [ -n "$SCHED_PID" ] || fail "no standalone u7s-scheduler process for $ABS_WORKDIR"
  RELOADS_PREV="$(grep -c "TLS material changed on disk" "$WORKDIR/scheduler.log" || true)"
fi

kubectl --kubeconfig "$TMP/frozen-kubeconfig" -n "$NS" get configmaps -w -o name >"$TMP/watch.out" 2>"$TMP/watch.err" &
WATCH_PID=$!
watch_saw() { grep -q "configmap/$1" "$TMP/watch.out"; }

if [ -n "$VM" ]; then
  k -n "$NS" run "$NAME" --image="$IMAGE" --restart=Never -- pause >/dev/null
fi

intermediate_changed() {
  served_chain >"$TMP/chain1.pem"
  [ "$(cert_count <"$TMP/chain1.pem")" = 2 ] && [ "$(cert_field 2 "$TMP/chain1.pem" -serial)" != "$I0" ]
}
poll "$ROTATION_DEADLINE" intermediate_changed ||
  fail "the intermediate $I0 was not replaced within ${ROTATION_DEADLINE}s of a ${INTERMEDIATE_LIFETIME}s lifetime"
I1="$(cert_field 2 "$TMP/chain1.pem" -serial)"
chain_verifies "$TMP/root.pem" "$TMP/chain1.pem" || fail "the chain served after the rotation does not verify to the root"
[ "$(cert_field 1 "$TMP/chain1.pem" -issuer)" = "$(cert_field 2 "$TMP/chain1.pem" -subject | sed 's/^subject=/issuer=/')" ] ||
  fail "the served leaf was not issued by the new intermediate"
grep -q "rotated intermediate CA" "$WORKDIR/apiserver.log" || fail "apiserver log never reports rotating the intermediate"
echo "PASS: intermediate $I0 -> $I1, serving chain re-issued and verifies to the root"

[ "$(pgrep -f "$(workdir_kill_pattern apiserver "$ABS_WORKDIR")" | sed -n 1p || true)" = "$APISERVER_PID" ] ||
  fail "the apiserver was restarted"
kf get namespaces >/dev/null ||
  fail "the root-only kubeconfig with the pre-rotation admin cert (chain: old intermediate) stopped authenticating"
kill -0 "$WATCH_PID" 2>/dev/null || fail "the watch opened before the rotation exited"
k -n "$NS" create configmap "$NAME-probe" >/dev/null
k -n "$NS" label configmap "$NAME-probe" "app=$NAME" >/dev/null
poll 20 watch_saw "$NAME-probe" || fail "the watch opened before the rotation delivered nothing after it"
[ "$(sha "$ABS_WORKDIR/ca.crt")" = "$SHA_CA" ] && [ "$(sha "$ABS_WORKDIR/ca.key")" = "$SHA_KEY" ] ||
  fail "the root was rewritten by an intermediate rotation"
[ "$(sha "$ABS_WORKDIR/ca-bundle.pem")" = "$SHA_BUNDLE" ] ||
  fail "ca-bundle.pem changed: an intermediate rotation must not touch what clients pin"
[ "$(k -n "$NS" get configmap kube-root-ca.crt -o 'jsonpath={.data.ca\.crt}' 2>/dev/null || true)" = "$ROOT_CM" ] ||
  fail "kube-root-ca.crt changed across the intermediate rotation"
echo "PASS: no restart; the pre-rotation admin cert and watch keep working through a root-only kubeconfig; root, ca-bundle.pem and kube-root-ca.crt untouched"

reissued_under_new() { [ "$(cert_field 2 "$ABS_WORKDIR/$1.pem" -serial)" = "$I1" ]; }
files="admin kcm"
{ [ "$WITH_SCHED" = 1 ] || [ -n "$VM" ]; } && files="$files scheduler"
for f in $files; do
  poll 60 reissued_under_new "$f" || fail "$f.pem was not re-issued under the new intermediate"
  [ "$(cert_count <"$ABS_WORKDIR/$f.pem")" = 2 ] || fail "$f.pem lost its chain"
done
k get namespaces >/dev/null || fail "the current admin kubeconfig fails after the rotation"
echo "PASS: $files re-issued under the new intermediate, each file carrying its chain"

if [ "$WITH_SCHED" = 1 ] || [ -n "$VM" ]; then
  [ "$(pgrep -f "$(workdir_kill_pattern scheduler "$ABS_WORKDIR")" | sed -n 1p)" = "$SCHED_PID" ] ||
    fail "the scheduler was restarted"
  reloaded() { [ "$(grep -c "TLS material changed on disk" "$WORKDIR/scheduler.log" || true)" -gt "$RELOADS_PREV" ]; }
  poll 60 reloaded || fail "the scheduler never reloaded its re-issued client cert chain"
  echo "PASS: scheduler reloaded the re-issued cert and chain without a restart"
fi

if [ -n "$VM" ]; then
  # KCM re-reads its signing files on file events, or at the latest on its one-minute resync
  # (a host-mounted workdir delivers no inotify events). Until then it signs with the previous
  # intermediate, and the chain the apiserver appends must name that one and still verify.
  attempt=0
  kcm_on_new_intermediate() {
    attempt=$((attempt + 1))
    kcm_client "after$attempt"
    [ "$(cert_count <"$TMP/after$attempt.pem")" = 2 ] ||
      fail "a KCM-signed cert carries $(cert_count <"$TMP/after$attempt.pem") certificate(s), expected leaf + intermediate"
    chain_verifies "$TMP/root.pem" "$TMP/after$attempt.pem" ||
      fail "a KCM-signed client cert issued across the rotation does not verify to the root"
    [ "$(cert_field 2 "$TMP/after$attempt.pem" -serial)" = "$I1" ]
  }
  poll 150 kcm_on_new_intermediate ||
    fail "KCM never switched to the new signing intermediate: its newest client cert chains to $(cert_field 2 "$TMP/after$attempt.pem" -serial), not $I1"
  mv "$TMP/after$attempt.pem" "$TMP/after.pem"
  mv "$TMP/after$attempt.key" "$TMP/after.key"
  [ "$(whoami_with after)" = "system:node:$NAME-after$attempt" ] ||
    fail "the post-rotation KCM-signed client cert does not authenticate against a root-only trust store"
  [ "$(whoami_with before)" = "system:node:$NAME-before" ] ||
    fail "the client cert KCM signed before the rotation stopped authenticating"
  echo "PASS: KCM signs with the new intermediate live; new and pre-rotation node client certs both authenticate (root-only trust)"

  node_ready() { [ "$(k get nodes -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}')" = "True" ]; }
  pod_running() { [ "$(k -n "$NS" get pod "$NAME" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ]; }
  poll 300 pod_running || fail "pod $NAME never became Running"
  poll 60 node_ready || fail "the node is not Ready after the intermediate rotation"
  kubelet_chain >"$TMP/kubelet.pem"
  [ "$(cert_count <"$TMP/kubelet.pem")" = 2 ] ||
    fail "the kubelet's serving cert carries $(cert_count <"$TMP/kubelet.pem") certificate(s), expected leaf + intermediate"
  chain_verifies "$TMP/root.pem" "$TMP/kubelet.pem" || fail "the kubelet's serving chain does not verify to the root"
  k -n "$NS" exec "$NAME" -- /agnhost help >/dev/null || fail "kubectl exec failed after the intermediate rotation"
  k -n "$NS" logs "$NAME" >/dev/null || fail "kubectl logs failed after the intermediate rotation"
  echo "PASS: node Ready; kubelet serving cert carries the chain; exec/logs work after the intermediate rotation"
fi

! grep -q "rotation failed" "$WORKDIR/apiserver.log" || fail "apiserver log reports a failed rotation"
echo "PASS: intermediate rotation $I0 -> $I1 complete"

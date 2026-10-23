#!/usr/bin/env bash
# Real-binary proof that every consumer of the cluster CA tolerates a bundle holding an extra
# (future) CA, picks it up with no restart, and drops it again when it is removed.
#
# Drops a self-made CA into <workdir>/ca-extra.pem next to ca.crt and asserts, with polling and
# deadlines (never fixed sleeps):
#   1. a client cert from that CA is rejected before it is listed and authenticates after (the
#      apiserver's client-CA store was swapped in place);
#   2. ca-bundle.pem (read by every kubeconfig, KCM and the kubelet), the kube-root-ca.crt of an
#      existing namespace, kube-public/cluster-info and extension-apiserver-authentication's
#      client-ca-file all carry both CAs;
#   3. the admin kubeconfig, and a watch opened before the change, keep working throughout;
#   4. with --vm: the node stays Ready and kubectl exec/logs (apiserver -> kubelet, which verifies
#      the kubelet serving cert against the bundle) work with the bundle in place;
#   5. removing the file shrinks every one of them back to a single CA and the extra CA's client
#      cert is rejected again.
# The bundle is picked up within ~5s, so the whole scenario takes well under a minute.
#
# Needs a running stack, like leaf-rotation.sh:
#   scripts/e2e-pki-rotation/ca-bundle.sh --kubeconfig temp/u7s/kubeconfig --workdir temp/u7s \
#       --port <PORT> [--vm <VM>]
set -euo pipefail

POLL_INTERVAL=1
DEADLINE=60

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

[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

KC=""
WORKDIR=""
PORT=""
VM=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig) KC="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --vm) VM="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[ -n "$KC" ] && [ -n "$WORKDIR" ] && [ -n "$PORT" ] || {
  echo "usage: $0 --kubeconfig <path> --workdir <path> --port <N> [--vm <name>]" >&2
  exit 1
}

ABS_WORKDIR="$(cd "$WORKDIR" && pwd)"
TMP="$(mktemp -d)"
NS=default
NAME="ca-bundle-$$"
IMAGE="registry.k8s.io/e2e-test-images/agnhost:2.63.0"
WATCH_PID=""

k() { kubectl --kubeconfig "$KC" --request-timeout=15s "$@"; }

dump_diagnostics() {
  echo "=== diagnostics ===" >&2
  echo "--- ca-bundle.pem ($(cert_count <"$ABS_WORKDIR/ca-bundle.pem") certs) ---" >&2
  grep -E "trust bundle|CA bundle" "$WORKDIR/apiserver.log" >&2 || true
  echo "--- apiserver log tail ---" >&2
  tail -40 "$WORKDIR/apiserver.log" >&2 || true
  echo "--- watch output ---" >&2
  cat "$TMP/watch.out" "$TMP/watch.err" >&2 2>/dev/null || true
  if [ -n "$VM" ]; then
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
  rm -f "$ABS_WORKDIR/ca-extra.pem"
  k -n "$NS" delete pod "$NAME" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  k -n "$NS" delete configmap -l "app=$NAME" --ignore-not-found >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'echo "FAIL: unexpected error at line $LINENO: $BASH_COMMAND" >&2; dump_diagnostics' ERR
set -E

poll 60 k get --raw /readyz >/dev/null 2>&1 || fail "apiserver not ready"
[ ! -e "$ABS_WORKDIR/ca-extra.pem" ] || fail "$ABS_WORKDIR/ca-extra.pem already exists: not a clean baseline"

# The "future" CA and an admin-equivalent client cert it signs.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
  -subj "/CN=u7s-future-ca" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$TMP/future-ca.key" -out "$TMP/future-ca.pem" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -subj "/CN=future-admin/O=system:masters" -keyout "$TMP/future-client.key" \
  -out "$TMP/future-client.csr" 2>/dev/null
printf 'extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n' >"$TMP/client.ext"
openssl x509 -req -in "$TMP/future-client.csr" -CA "$TMP/future-ca.pem" -CAkey "$TMP/future-ca.key" \
  -CAcreateserial -days 1 -extfile "$TMP/client.ext" -out "$TMP/future-client.pem" 2>/dev/null

future_client_ok() {
  curl -fsS --max-time 10 --cacert "$ABS_WORKDIR/ca-bundle.pem" \
    --cert "$TMP/future-client.pem" --key "$TMP/future-client.key" \
    "https://127.0.0.1:$PORT/api" >/dev/null 2>&1
}
future_client_rejected() { ! future_client_ok; }
bundle_has() { [ "$(cert_count <"$ABS_WORKDIR/ca-bundle.pem")" = "$1" ]; }
cm_cert_count() { k -n "$1" get configmap "$2" -o "jsonpath={.data.$3}" | cert_count; }
cm_has() { [ "$(cm_cert_count "$1" "$2" "$3")" = "$4" ]; }
cluster_info_has() {
  local data
  data="$(k -n kube-public get configmap cluster-info -o jsonpath='{.data.kubeconfig}')"
  [ "$(sed -n 's/^ *certificate-authority-data: *//p' <<<"$data" | head -n1 | base64 -d | cert_count)" = "$1" ]
}
node_ready() { [ "$(k get nodes -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}')" = "True" ]; }
pod_running() { [ "$(k -n "$NS" get pod "$NAME" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ]; }
watch_saw() { grep -q "configmap/$1" "$TMP/watch.out"; }

kubectl --kubeconfig "$KC" -n "$NS" get configmaps -w -o name >"$TMP/watch.out" 2>"$TMP/watch.err" &
WATCH_PID=$!

if [ -n "$VM" ]; then
  k -n "$NS" run "$NAME" --image="$IMAGE" --restart=Never -- pause >/dev/null
fi

bundle_has 1 || fail "baseline ca-bundle.pem does not hold exactly one CA"
future_client_rejected || fail "a client cert from a CA that is not in the bundle authenticated"
echo "PASS: baseline: one CA; a client cert from an unlisted CA is rejected"

cp "$TMP/future-ca.pem" "$ABS_WORKDIR/ca-extra.pem"
poll "$DEADLINE" bundle_has 2 || fail "ca-bundle.pem never grew to two CAs"
poll "$DEADLINE" future_client_ok ||
  fail "a client cert from the extra CA was not accepted after it joined the bundle"
echo "PASS: extra CA listed: ca-bundle.pem holds 2 CAs and its client cert authenticates"

# With --vm a rig KCM is running; its root-ca-cert-publisher owns kube-root-ca.crt and, unlike
# the systemd unit install.sh writes, the rig does not restart it when ca-bundle.pem changes
# (--root-ca-file is read once), so it would put its single-CA copy back.
[ -n "$VM" ] || poll "$DEADLINE" cm_has "$NS" kube-root-ca.crt 'ca\.crt' 2 ||
  fail "$NS/kube-root-ca.crt was not rewritten with both CAs"
poll "$DEADLINE" cluster_info_has 2 || fail "kube-public/cluster-info does not carry both CAs"
poll "$DEADLINE" cm_has kube-system extension-apiserver-authentication 'client-ca-file' 2 ||
  fail "extension-apiserver-authentication client-ca-file does not carry both CAs"
echo "PASS: kube-root-ca.crt, cluster-info and extension-apiserver-authentication carry both CAs"

k get namespaces >/dev/null || fail "the admin kubeconfig stopped working with two CAs in the bundle"
kill -0 "$WATCH_PID" 2>/dev/null || fail "the watch opened before the bundle changed exited"
k -n "$NS" create configmap "$NAME-probe" >/dev/null
k -n "$NS" label configmap "$NAME-probe" "app=$NAME" >/dev/null
poll 20 watch_saw "$NAME-probe" || fail "the long-lived watch delivered nothing after the bundle changed"
echo "PASS: admin kubectl and the pre-existing watch are unaffected"

if [ -n "$VM" ]; then
  poll 300 pod_running || fail "pod $NAME never became Running"
  poll 60 node_ready || fail "node is not Ready with two CAs in the bundle"
  k -n "$NS" exec "$NAME" -- /agnhost help >/dev/null || fail "kubectl exec failed with two CAs in the bundle"
  k -n "$NS" logs "$NAME" >/dev/null || fail "kubectl logs failed with two CAs in the bundle"
  echo "PASS: node Ready; kubectl exec/logs (apiserver -> kubelet) work with the two-CA bundle"
fi

rm -f "$ABS_WORKDIR/ca-extra.pem"
poll "$DEADLINE" bundle_has 1 || fail "ca-bundle.pem did not shrink back to one CA"
poll "$DEADLINE" future_client_rejected || fail "the extra CA's client cert still authenticates after it was removed"
[ -n "$VM" ] || poll "$DEADLINE" cm_has "$NS" kube-root-ca.crt 'ca\.crt' 1 ||
  fail "$NS/kube-root-ca.crt kept the removed CA"
k get namespaces >/dev/null || fail "the admin kubeconfig stopped working after the extra CA was removed"
echo "PASS: extra CA removed: bundle, kube-root-ca.crt and client trust shrink back to one CA"

#!/usr/bin/env bash
# Real-binary proof that the apiserver renews and hot-swaps its leaf certs before they
# expire, with live clients riding through it. Lifetimes are seconds (U7S_PKI_TEST_LIFETIME_SECS,
# honoured only by an apiserver built with --features pki-test-knobs): the serving cert and the
# apiserver-held kubelet-client and proxy-client identities live --lifetime seconds, so
# rotation (at 2/3 lifetime) happens in real time. admin, KCM, scheduler and
# bootstrap-installer certs stay at their long production lifetime.
#
# Bring the stack up first, e.g.
#   scripts/conformance/run-all.sh --pki-test-lifetime 60 --vm <VM> --port <PORT> \
#       --kubelet-port <KP> --stack-only
# then
#   scripts/e2e-pki-rotation/leaf-rotation.sh --kubeconfig temp/u7s/kubeconfig \
#       --workdir temp/u7s --port <PORT> --vm <VM> --iterations 10
# Without --vm only the apiserver is exercised (no kubelet, KCM or scheduler), which is the
# shape a plain CI runner can host.
#
# Each iteration waits for the currently served serving cert to expire, so it takes about
# --lifetime seconds; a whole run is ~(iterations x lifetime) plus the pod image pull.
# Asserts, with polling and deadlines (never fixed sleeps):
#   1. the served serving-cert serial changes while the old cert still has time left;
#   2. a `kubectl get -w` opened before any rotation is still delivering events after the
#      cert it connected under expired;
#   3. new kubectl requests succeed after the original serving cert expired (they would
#      fail x509 expired without the hot swap);
#   4. with --vm: `kubectl exec` into a pod works after the apiserver's original
#      kubelet-client cert expired, and a Deployment created then is made into a scheduled
#      pod (KCM and scheduler still reach the apiserver);
#   5. the apiserver log shows serving, kubelet-client and proxy-client rotated.
#
# Pending (need other beads, not asserted here): KCM and scheduler client-cert rotation
# and kubelet client-cert reload (file-path kubeconfigs and politeia file mode),
# intermediate rotation, root succession. proxy-client rotation is checked by log only:
# no aggregated backend in this harness verifies the identity.
#
# On failure the script dumps the served cert, the rotation log lines and component logs.
set -euo pipefail

POLL_INTERVAL=1

# poll <deadline-seconds> <cmd...>: run cmd every second until it succeeds or time runs out.
poll() {
  local deadline="$1"; shift
  local end=$((SECONDS + deadline))
  while ! "$@"; do
    [ "$SECONDS" -lt "$end" ] || return 1
    sleep "$POLL_INTERVAL"
  done
}

pem_serial() { openssl x509 -noout -serial; }

# cert_has_life <pem-file> <seconds>: true while the cert is valid for at least that long.
cert_has_life() { openssl x509 -checkend "$2" -noout -in "$1" >/dev/null; }

[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

KC=""
WORKDIR=""
PORT=""
VM=""
LIFETIME=60
ITERATIONS=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig) KC="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --vm) VM="$2"; shift 2 ;;
    --lifetime) LIFETIME="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[ -n "$KC" ] && [ -n "$WORKDIR" ] && [ -n "$PORT" ] || {
  echo "usage: $0 --kubeconfig <path> --workdir <path> --port <N> [--vm <name>] [--lifetime <s>] [--iterations <n>]" >&2
  exit 1
}

TMP="$(mktemp -d)"
NS=default
NAME="pki-rot-$$"
IMAGE="registry.k8s.io/e2e-test-images/agnhost:2.63.0"
WATCH_PID=""

k() { kubectl --kubeconfig "$KC" --request-timeout=15s "$@"; }

served_pem() {
  local out
  out="$(openssl s_client -connect "127.0.0.1:$PORT" -servername localhost </dev/null 2>/dev/null || true)"
  openssl x509 <<<"$out"
}

dump_diagnostics() {
  echo "=== diagnostics ===" >&2
  echo "--- served cert ---" >&2
  served_pem 2>&1 | openssl x509 -noout -serial -startdate -enddate >&2 2>&1 || true
  echo "--- apiserver rotation log ---" >&2
  grep -E "rotated |rotation failed|pki-test-knobs|loaded .* from" "$WORKDIR/apiserver.log" >&2 || true
  echo "--- apiserver log tail ---" >&2
  tail -40 "$WORKDIR/apiserver.log" >&2 || true
  echo "--- watch output ---" >&2
  cat "$TMP/watch.out" "$TMP/watch.err" >&2 2>/dev/null || true
  if [ -n "$VM" ]; then
    echo "--- scheduler log tail ---" >&2
    tail -20 "$WORKDIR/scheduler.log" >&2 || true
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
  k -n "$NS" delete pod "$NAME" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  k -n "$NS" delete deployment "$NAME" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  k -n "$NS" delete configmap -l "app=$NAME" --ignore-not-found >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'echo "FAIL: unexpected error at line $LINENO: $BASH_COMMAND" >&2; dump_diagnostics' ERR
set -E

grep -q "pki-test-knobs" "$WORKDIR/apiserver.log" ||
  fail "apiserver.log has no pki-test-knobs line: the binary was not built with --features pki-test-knobs or was started without U7S_PKI_TEST_LIFETIME_SECS"

poll 60 k get --raw /readyz >/dev/null 2>&1 || fail "apiserver not ready"

kubectl --kubeconfig "$KC" -n "$NS" get configmaps -w -o name >"$TMP/watch.out" 2>"$TMP/watch.err" &
WATCH_PID=$!

if [ -n "$VM" ]; then
  k -n "$NS" run "$NAME" --image="$IMAGE" --restart=Never -- pause >/dev/null
fi

pod_running() { [ "$(k -n "$NS" get pod "$NAME" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ]; }
serial_is() { [ "$(served_pem | pem_serial)" = "$1" ]; }
serial_differs() { ! serial_is "$1"; }
watch_saw() { grep -q "configmap/$1" "$TMP/watch.out"; }
cert_expired() { ! cert_has_life "$1" 0; }
scheduled() { [ -n "$(k -n "$NS" get pods -l "app=$NAME" -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null)" ]; }

START=$SECONDS
for i in $(seq 1 "$ITERATIONS"); do
  served_pem >"$TMP/old.pem"
  old_serial="$(pem_serial <"$TMP/old.pem")"
  t0=$SECONDS

  poll $((LIFETIME + 20)) serial_differs "$old_serial" ||
    fail "iteration $i: serving cert $old_serial was not replaced within $((LIFETIME + 20))s of a ${LIFETIME}s lifetime"
  renewed_after=$((SECONDS - t0))
  cert_has_life "$TMP/old.pem" 3 ||
    fail "iteration $i: serving cert was renewed only after it had (nearly) expired"
  new_serial="$(served_pem | pem_serial)"
  echo "PASS[$i]: serving cert $old_serial -> $new_serial, ${renewed_after}s after observing it, old cert still valid"

  poll $((LIFETIME + 10)) cert_expired "$TMP/old.pem" ||
    fail "iteration $i: old serving cert never expired"

  k get namespaces >/dev/null || fail "iteration $i: new kubectl request failed after the old serving cert expired"
  echo "PASS[$i]: new kubectl request succeeds after the old serving cert expired"

  kill -0 "$WATCH_PID" 2>/dev/null || fail "iteration $i: the watch opened before rotation exited"
  probe="$NAME-$i"
  k -n "$NS" create configmap "$probe" >/dev/null
  k -n "$NS" label configmap "$probe" "app=$NAME" >/dev/null
  poll 20 watch_saw "$probe" || fail "iteration $i: long-lived watch delivered no event after the serving cert it connected under expired"
  echo "PASS[$i]: long-lived watch still delivering events"

  if [ -n "$VM" ]; then
    poll 300 pod_running || fail "iteration $i: pod $NAME never became Running"
    k -n "$NS" exec "$NAME" -- /agnhost help >/dev/null ||
      fail "iteration $i: kubectl exec failed after the kubelet-client cert it started with expired"
    k -n "$NS" logs "$NAME" >/dev/null || fail "iteration $i: kubectl logs failed"
    echo "PASS[$i]: kubectl exec/logs through the rotated kubelet-client identity"

    k -n "$NS" delete deployment "$NAME" --ignore-not-found >/dev/null
    k -n "$NS" create deployment "$NAME" --image="$IMAGE" -- /agnhost pause >/dev/null
    poll 120 scheduled || fail "iteration $i: KCM did not create, or the scheduler did not place, a Deployment's pod"
    echo "PASS[$i]: KCM and scheduler still serve new work"
  fi
done

for leaf in apiserver-serving kubelet-client proxy-client; do
  grep -q "rotated $leaf" "$WORKDIR/apiserver.log" || fail "apiserver log never reports rotating $leaf"
done
! grep -q "rotation failed" "$WORKDIR/apiserver.log" || fail "apiserver log reports a failed rotation"
echo "PASS: serving, kubelet-client and proxy-client all rotated; $ITERATIONS iteration(s) in $((SECONDS - START))s"

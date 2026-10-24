#!/usr/bin/env bash
# Real-binary proof that the apiserver renews and hot-swaps its leaf certs before they
# expire, with live clients riding through it. Lifetimes are seconds (U7S_PKI_TEST_LIFETIME_SECS,
# honoured only by an apiserver built with --features pki-test-knobs): the serving cert and the
# apiserver-held kubelet-client and proxy-client identities live --lifetime seconds, so
# rotation (at 2/3 lifetime) happens in real time. So do the KCM and scheduler client certs.
# admin and bootstrap-installer certs stay at their long production lifetime.
#
# Bring the stack up first, e.g.
#   scripts/conformance/run-all.sh --pki-test-lifetime 60 --vm <VM> --port <PORT> \
#       --kubelet-port <KP> --stack-only
# then
#   scripts/e2e-pki-rotation/leaf-rotation.sh --kubeconfig temp/u7s/kubeconfig \
#       --workdir temp/u7s --port <PORT> --vm <VM> --kubelet-port <KP> --iterations 10
# Without --vm only the apiserver is exercised (no kubelet, KCM or scheduler), which is the
# shape a plain CI runner can host. --scheduler additionally watches a standalone u7s-scheduler
# running on this host against <workdir>/kubeconfig-scheduler (cert re-issue, no restart, TLS
# reload logged); --vm implies it. With either, --lifetime must be at least 120: the scheduler
# re-reads its cert files every 30s, and renewal at 2/3 lifetime leaves only lifetime/3 = 40s
# before the old cert expires, so the worst-case slack at 120 is about 10s (40s minus the 30s
# reload interval). A scheduler that misses that window fails the "new work" check, not this
# arithmetic: raise --lifetime on a slow host.
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
#      kubelet-client cert expired;
#   5. with --scheduler or --vm: the scheduler client cert is re-issued, the old one expires, and
#      the scheduler process is unchanged (same PID and kernel start tick -- no restart) while
#      its log gains at least one TLS-reload line per rotation window. With --vm also: the KCM
#      client cert is re-issued, KCM is unchanged, and a new Deployment is still made into a
#      scheduled pod;
#   6. the apiserver log shows serving, kubelet-client, proxy-client and, with --scheduler or
#      --vm, scheduler-client (plus kcm-client with --vm) rotated;
#   7. with --vm (needs --kubelet-port): the kubelet's serving cert, requested by the kubelet
#      through a kubelet-serving CSR and signed by KCM for --lifetime seconds, is re-issued
#      by the kubelet without a restart, chains to the cluster CA, and `kubectl exec/logs`
#      keep working after the original kubelet serving cert expired.
#
# Pending (need other beads, not asserted here): kubelet client-cert reload, root
# succession. Intermediate rotation is intermediate-rotation.sh. proxy-client rotation is
# checked by log only: no aggregated backend in this harness verifies the identity.
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

# pem_file_serial <file>: serial of the first certificate in a PEM file (a cert+key bundle is fine).
pem_file_serial() { openssl x509 -noout -serial -in "$1"; }

# cert_has_life <pem-file> <seconds>: true while the cert is valid for at least that long.
cert_has_life() { openssl x509 -checkend "$2" -noout -in "$1" >/dev/null; }

# stat_start_ticks <stat-line>: start time in clock ticks since boot (field 22 of /proc/PID/stat).
# comm (field 2) may contain spaces, so count fields after its closing paren (the last one).
stat_start_ticks() { local rest="${1##*) }"; cut -d" " -f20 <<<"$rest"; }

# reload_window_ok <before> <now>: at least one reload landed since <before>.
reload_window_ok() { [ "$(($2 - $1))" -ge 1 ]; }

[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

# shellcheck source=scripts/_kill-pattern.sh
source "$(dirname "${BASH_SOURCE[0]}")/../_kill-pattern.sh"

KC=""
WORKDIR=""
PORT=""
VM=""
KUBELET_PORT=""
WITH_SCHED=0
LIFETIME=60
ITERATIONS=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig) KC="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --vm) VM="$2"; shift 2 ;;
    --kubelet-port) KUBELET_PORT="$2"; shift 2 ;;
    --scheduler) WITH_SCHED=1; shift ;;
    --lifetime) LIFETIME="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[ -n "$KC" ] && [ -n "$WORKDIR" ] && [ -n "$PORT" ] || {
  echo "usage: $0 --kubeconfig <path> --workdir <path> --port <N> [--vm <name> --kubelet-port <N>] [--scheduler] [--lifetime <s>] [--iterations <n>]" >&2
  exit 1
}

[ -z "$VM" ] || [ -n "$KUBELET_PORT" ] || {
  echo "error: --vm needs --kubelet-port (the kubelet serving cert is read through it)" >&2
  exit 1
}

ABS_WORKDIR="$(cd "$WORKDIR" && pwd)"
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

kubelet_pem() {
  local out
  out="$(openssl s_client -connect "127.0.0.1:$KUBELET_PORT" </dev/null 2>/dev/null || true)"
  openssl x509 <<<"$out"
}

kubelet_chain() {
  { openssl s_client -connect "127.0.0.1:$KUBELET_PORT" -showcerts </dev/null 2>/dev/null || true; } |
    sed -n '/^-----BEGIN CERTIFICATE-----$/,/^-----END CERTIFICATE-----$/p'
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
    echo "--- kubelet serving cert and CSRs ---" >&2
    kubelet_pem 2>&1 | openssl x509 -noout -serial -issuer -startdate -enddate >&2 2>&1 || true
    k get csr >&2 || true
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

[ -z "$VM" ] || WITH_SCHED=1

if [ "$WITH_SCHED" = 1 ] && [ "$LIFETIME" -lt 120 ]; then
  echo "error: --lifetime must be at least 120 with --vm or --scheduler (the scheduler re-reads its certs every 30s)" >&2
  exit 1
fi

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

kcm_pid() { limactl shell "$VM" pgrep -x kube-controller 2>/dev/null | sed -n 1p; }
# Kernel start tick (field 22 of /proc/PID/stat): ps lstart is derived from boot time and drifts by a second between calls.
kcm_start() { stat_start_ticks "$(limactl shell "$VM" cat "/proc/$1/stat" 2>/dev/null)"; }
sched_pid() { pgrep -f "$(workdir_kill_pattern scheduler "$ABS_WORKDIR")" | sed -n 1p; }
# The scheduler runs on this host: /proc on Linux; a macOS host has no /proc, and its ps lstart is the stored start time (stable).
sched_start() {
  if [ -r "/proc/$1/stat" ]; then stat_start_ticks "$(cat "/proc/$1/stat")"; else ps -o lstart= -p "$1" 2>/dev/null | sed "s/^ *//"; fi
}
sched_reloads() { grep -c "TLS material changed on disk" "$WORKDIR/scheduler.log" || true; }
kubelet_cert_from_ca() {
  # The kubelet presents its leaf and the signing intermediate; ca.pem holds only roots.
  kubelet_chain >"$TMP/kubelet.chain.pem" && [ -s "$TMP/kubelet.chain.pem" ] &&
    awk '{print} /^-----END CERTIFICATE-----$/ {exit}' "$TMP/kubelet.chain.pem" >"$TMP/kubelet.cur.pem" &&
    openssl verify -CAfile "$ABS_WORKDIR/ca.pem" -untrusted "$TMP/kubelet.chain.pem" "$TMP/kubelet.cur.pem" >/dev/null 2>&1
}
kubelet_serial_differs() {
  kubelet_cert_from_ca && [ "$(pem_file_serial "$TMP/kubelet.cur.pem")" != "$1" ]
}
kubelet_start() { limactl shell "$VM" systemctl show kubelet -p ActiveEnterTimestampMonotonic --value; }
file_serial_differs() { [ "$(pem_file_serial "$1")" != "$2" ]; }

if [ "$WITH_SCHED" = 1 ]; then
  SCHED_PID="$(sched_pid)"
  [ -n "$SCHED_PID" ] || fail "no standalone u7s-scheduler process for $ABS_WORKDIR (rotation of its client cert cannot be observed with --embedded-scheduler)"
  SCHED_START="$(sched_start "$SCHED_PID")"
  RELOADS_PREV="$(sched_reloads)"
  echo "scheduler pid $SCHED_PID started $SCHED_START"
fi
if [ -n "$VM" ]; then
  KCM_PID="$(kcm_pid)"
  [ -n "$KCM_PID" ] || fail "no kube-controller-manager process in $VM"
  KCM_START="$(kcm_start "$KCM_PID")"
  echo "kcm pid $KCM_PID started $KCM_START"
  # Until its CSR is approved and signed the kubelet serves a self-signed cert.
  poll 180 kubelet_cert_from_ca ||
    fail "the kubelet's serving cert never chained to the cluster CA (still self-signed, or a static file?)"
  echo "kubelet serving cert $(pem_file_serial "$TMP/kubelet.cur.pem") chains to the cluster CA"
  KUBELET_START="$(kubelet_start)"
fi

WHO=""
[ "$WITH_SCHED" = 0 ] || WHO="scheduler"
[ -z "$VM" ] || WHO="$WHO kcm"

START=$SECONDS
for i in $(seq 1 "$ITERATIONS"); do
  served_pem >"$TMP/old.pem"
  old_serial="$(pem_serial <"$TMP/old.pem")"
  for who in $WHO; do
    cp "$ABS_WORKDIR/$who.pem" "$TMP/$who.old.pem"
  done
  if [ -n "$VM" ]; then
    kubelet_cert_from_ca || fail "iteration $i: the kubelet's serving cert does not chain to the cluster CA"
    cp "$TMP/kubelet.cur.pem" "$TMP/kubelet.old.pem"
    kubelet_old_serial="$(pem_file_serial "$TMP/kubelet.old.pem")"
  fi
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

    poll $((LIFETIME + 60)) kubelet_serial_differs "$kubelet_old_serial" ||
      fail "iteration $i: the kubelet never replaced its serving cert $kubelet_old_serial (CSR not approved or signed, or no reload)"
    poll $((LIFETIME + 10)) cert_expired "$TMP/kubelet.old.pem" ||
      fail "iteration $i: the old kubelet serving cert never expired"
    k -n "$NS" exec "$NAME" -- /agnhost help >/dev/null ||
      fail "iteration $i: kubectl exec failed after the kubelet re-issued its serving cert"
    k -n "$NS" logs "$NAME" >/dev/null || fail "iteration $i: kubectl logs failed after the kubelet re-issued its serving cert"
    [ "$(kubelet_start)" = "$KUBELET_START" ] || fail "iteration $i: the kubelet was restarted"
    echo "PASS[$i]: kubelet serving cert $kubelet_old_serial -> $(pem_file_serial "$TMP/kubelet.cur.pem") by CSR, no restart; exec/logs work after the old one expired"
  fi

  if [ "$WITH_SCHED" = 1 ]; then
    for who in $WHO; do
      old="$(pem_file_serial "$TMP/$who.old.pem")"
      poll $((LIFETIME + 20)) file_serial_differs "$ABS_WORKDIR/$who.pem" "$old" ||
        fail "iteration $i: $who client cert $old was never re-issued"
      poll $((LIFETIME + 10)) cert_expired "$TMP/$who.old.pem" || fail "iteration $i: old $who client cert never expired"
    done
    echo "PASS[$i]: $WHO client certs re-issued and the originals expired"

    if [ -n "$VM" ]; then
      k -n "$NS" delete deployment "$NAME" --ignore-not-found >/dev/null
      k -n "$NS" create deployment "$NAME" --image="$IMAGE" -- /agnhost pause >/dev/null
      poll 120 scheduled || fail "iteration $i: KCM did not create, or the scheduler did not place, a Deployment's pod"
      echo "PASS[$i]: KCM and scheduler still serve new work"
      [ "$(kcm_pid)" = "$KCM_PID" ] && [ "$(kcm_start "$KCM_PID")" = "$KCM_START" ] ||
        fail "iteration $i: KCM was restarted (pid $KCM_PID, started $KCM_START)"
    fi
    [ "$(sched_pid)" = "$SCHED_PID" ] && [ "$(sched_start "$SCHED_PID")" = "$SCHED_START" ] ||
      fail "iteration $i: the scheduler was restarted (pid $SCHED_PID, started $SCHED_START)"
    reloads="$(sched_reloads)"
    reload_window_ok "$RELOADS_PREV" "$reloads" ||
      fail "iteration $i: scheduler.log gained no TLS reload during this rotation window ($RELOADS_PREV -> $reloads)"
    RELOADS_PREV="$reloads"
    echo "PASS[$i]: no process restarted; scheduler reloaded TLS material ($reloads total)"
  fi
done

leaves="apiserver-serving kubelet-client proxy-client"
[ "$WITH_SCHED" = 0 ] || leaves="$leaves scheduler-client"
[ -z "$VM" ] || leaves="$leaves kcm-client"
for leaf in $leaves; do
  grep -q "rotated $leaf" "$WORKDIR/apiserver.log" || fail "apiserver log never reports rotating $leaf"
done
! grep -q "rotation failed" "$WORKDIR/apiserver.log" || fail "apiserver log reports a failed rotation"
if [ -n "$VM" ]; then
  issued="$(k get csr -o json | jq '[.items[] | select(.spec.signerName == "kubernetes.io/kubelet-serving" and (.status.certificate // "") != "" and any(.status.conditions[]?; .type == "Approved"))] | length')"
  [ "$issued" -gt "$ITERATIONS" ] ||
    fail "only $issued approved+issued kubelet-serving CSRs for $ITERATIONS rotation(s); the initial cert plus one per rotation are expected"
  echo "PASS: $issued kubelet-serving CSRs approved and issued"
fi
echo "PASS: $leaves all rotated; $ITERATIONS iteration(s) in $((SECONDS - START))s"

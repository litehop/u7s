#!/usr/bin/env bash
# Logic test for webhook-smoke.sh's retry decision. The smoke retries while the apiserver
# and kube-proxy converge; stopping on the first non-deny error turns a transient
# "failed to respond" into a false FAIL of release criterion (e). No cluster needed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=webhook-smoke.sh
. "$HERE/webhook-smoke.sh"

PASS=0; FAIL=0
check() {
  local label="$1" want="$2" text="$3" got=retry
  if smoke_should_stop "$text"; then got=stop; fi
  if [ "$got" = "$want" ]; then echo "PASS: $label"; PASS=$((PASS + 1)); else echo "FAIL: $label (got $got)"; FAIL=$((FAIL + 1)); fi
}

check "webhook denial -> stop: the deny landed, nothing more to wait for" stop \
  'Error from server (Forbidden): admission webhook "deny.u7s-smoke.example.com" denied the request: the configmap is denied'
check "'failed to respond' -> retry: kube-proxy has not programmed the Service yet" retry \
  'Error from server (InternalError): Internal error occurred: failed calling webhook "deny.u7s-smoke.example.com": failed to call webhook: Post "https://u7s-webhook-smoke.default.svc:443/always-deny?timeout=10s": dial tcp 10.0.0.5:443: failed to respond'
check "connection refused -> retry: backend pod not listening yet" retry \
  'failed calling webhook: dial tcp 10.0.0.5:443: connect: connection refused'
check "timeout -> retry: Service dial still blackholed" retry \
  'failed calling webhook: context deadline exceeded (Client.Timeout exceeded while awaiting headers)'
check "empty output -> retry: nothing observed is not a denial" retry ''

echo "---- $PASS passed, $FAIL failed ----"
[ "$FAIL" = 0 ]

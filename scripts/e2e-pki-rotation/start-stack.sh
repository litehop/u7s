#!/usr/bin/env bash
# Starts a standalone u7s-apiserver (pki-test-knobs build) and, with --scheduler, a standalone
# u7s-scheduler on its file-path kubeconfig, in <workdir>. The lifetimes come from the
# U7S_PKI_TEST_* environment, which the apiserver reads.
#
#   U7S_PKI_TEST_LIFETIME_SECS=30 scripts/e2e-pki-rotation/start-stack.sh --workdir temp/pki-e2e [--scheduler]
set -euo pipefail

WORKDIR=""
WITH_SCHED=0
BIN="${U7S_BIN_DIR:-target/release}"
while [ $# -gt 0 ]; do
  case "$1" in
    --workdir) WORKDIR="$2"; shift 2 ;;
    --scheduler) WITH_SCHED=1; shift ;;
    *) WORKDIR=""; break ;;
  esac
done
[ -n "$WORKDIR" ] || {
  echo "usage: $0 --workdir <path> [--scheduler]" >&2
  exit 1
}

W="$(mkdir -p "$WORKDIR/manifests" && cd "$WORKDIR" && pwd)"
"$BIN/u7s-apiserver" \
  --db "$W/state.db" --listen 127.0.0.1:6443 --kubeconfig "$W/kubeconfig" \
  --sa-key "$W/sa.key" --sa-pub "$W/sa.pub" \
  --ca-key "$W/ca.key" --ca-cert "$W/ca.crt" \
  --proxy-client-ca-key "$W/proxy-client-ca.key" --proxy-client-ca-cert "$W/proxy-client-ca.crt" \
  --advertise-address https://127.0.0.1:6443 \
  --manifest-dir "$W/manifests" >"$W/apiserver.log" 2>&1 &
for _ in $(seq 1 30); do
  nc -z 127.0.0.1 6443 2>/dev/null && break
  sleep 1
done
nc -z 127.0.0.1 6443 2>/dev/null || {
  cat "$W/apiserver.log"
  exit 1
}

if [ "$WITH_SCHED" = 1 ]; then
  "$BIN/u7s-scheduler" --kubeconfig "$W/kubeconfig-scheduler" >"$W/scheduler.log" 2>&1 &
  sleep 2
  pgrep -f "u7s-scheduler.*$W/kubeconfig" >/dev/null || {
    cat "$W/scheduler.log"
    exit 1
  }
fi

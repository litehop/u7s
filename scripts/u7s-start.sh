#!/usr/bin/env bash
# Start u7s-apiserver for local development against a lima-node kubelet.
#
# State persists in ./temp/u7s/ across restarts so the CA and kubelet trust
# relationship survive a server restart without re-provisioning the VM.
#
# Usage:
#   scripts/u7s-start.sh [--reset] [--background]
#
#   --reset       Wipe ./temp/u7s/ and start fresh (rotates CA — kubelet will need
#                 to be re-joined via scripts/conformance/lima-start.sh after this).
#   --background  Start backgrounded (logs to ./temp/u7s/apiserver.log). If port
#                 is already in use, warns and exits 0 (reuses existing instance).
#
# After starting (foreground mode):
#   export KUBECONFIG=./temp/u7s/kubeconfig
#   scripts/conformance/lima-start.sh  # join kubelet (first run or after --reset)
#   kubectl get nodes
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="$REPO/temp/u7s"
BINARY="$REPO/target/release/u7s-apiserver"
PORT=6443

RESET=0
BACKGROUND=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1; shift ;;
    --background) BACKGROUND=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ ! -f "$BINARY" ]; then
  echo "error: binary not found — run: cargo build --release -p u7s-apiserver" >&2
  exit 1
fi

KONNECTIVITY_OUT=$("$REPO/scripts/download-konnectivity.sh")
SERVER_BIN=$(echo "$KONNECTIVITY_OUT" | grep '^server=' | cut -d= -f2)

# Always kill any stale konnectivity-server so a --reset doesn't leave one
# running with cert paths that no longer exist in the wiped WORKDIR.
pkill -f konnectivity-server 2>/dev/null || true

APISERVER_RUNNING=0
if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
  if [ "$BACKGROUND" -eq 1 ]; then
    echo "WARNING: port $PORT already in use — reusing existing apiserver instance" >&2
    APISERVER_RUNNING=1
  else
    echo "error: port $PORT is already in use." >&2
    echo "If u7s is already running, set KUBECONFIG=$WORKDIR/kubeconfig and use it." >&2
    echo "To start fresh: scripts/u7s-start.sh --reset  (rotates CA, re-join kubelet needed)" >&2
    exit 1
  fi
fi

if [ "$RESET" -eq 1 ]; then
  echo "Resetting state in $WORKDIR ..."
  rm -rf "$WORKDIR"
fi

mkdir -p "$WORKDIR"

KONNECTIVITY_PROXY_PORT=8135

if [ -f "$WORKDIR/ca.crt" ]; then
  openssl x509 -inform DER -in "$WORKDIR/ca.crt" -out "$WORKDIR/ca.pem"

  if [ "$RESET" -eq 1 ] || [ ! -f "$WORKDIR/konnectivity-server.crt" ]; then
    openssl ecparam -genkey -name prime256v1 -noout -out "$WORKDIR/konnectivity-server.key"
    openssl req -new -key "$WORKDIR/konnectivity-server.key" \
      -subj "/CN=konnectivity-server" \
      -sha256 \
      -out "$WORKDIR/konnectivity-server.csr"
    cat > "$WORKDIR/konnectivity-server-ext.cnf" <<'EXTEOF'
[v3_req]
subjectAltName = IP:127.0.0.1,DNS:host.lima.internal,DNS:localhost
EXTEOF
    openssl x509 -req -in "$WORKDIR/konnectivity-server.csr" \
      -CA "$WORKDIR/ca.pem" -CAkey "$WORKDIR/ca.key" \
      -CAserial "$WORKDIR/ca.srl" \
      -days 365 -sha256 \
      -extfile "$WORKDIR/konnectivity-server-ext.cnf" \
      -extensions v3_req \
      -out "$WORKDIR/konnectivity-server.crt"
    rm -f "$WORKDIR/konnectivity-server.csr"
  fi

  pkill -f konnectivity-server || true

  "$SERVER_BIN" \
    --logtostderr=true \
    --log-file-max-size=0 \
    --cluster-cert="$WORKDIR/konnectivity-server.crt" \
    --cluster-key="$WORKDIR/konnectivity-server.key" \
    --server-ca-cert="$WORKDIR/ca.pem" \
    --server-cert="$WORKDIR/konnectivity-server.crt" \
    --server-key="$WORKDIR/konnectivity-server.key" \
    --mode=http-connect \
    --server-port=$KONNECTIVITY_PROXY_PORT \
    --agent-port=8132 \
    --admin-port=8133 \
    --health-port=8134 \
    >> "$WORKDIR/konnectivity-server.log" 2>&1 &
  disown $!

  for i in $(seq 1 10); do
    nc -z 127.0.0.1 $KONNECTIVITY_PROXY_PORT 2>/dev/null && break
    sleep 1
  done
  if ! nc -z 127.0.0.1 $KONNECTIVITY_PROXY_PORT 2>/dev/null; then
    echo "error: konnectivity-server did not open port $KONNECTIVITY_PROXY_PORT within 10s — see $WORKDIR/konnectivity-server.log" >&2
    exit 1
  fi
fi

PROXY_ARG=""
if [ -f "$WORKDIR/ca.crt" ]; then
  PROXY_ARG="--konnectivity-proxy-addr 127.0.0.1:$KONNECTIVITY_PROXY_PORT"
fi

ADVERTISE_ARG=""

if [ "$APISERVER_RUNNING" -eq 1 ]; then
  echo "KUBECONFIG=$WORKDIR/kubeconfig"
elif [ "$BACKGROUND" -eq 1 ]; then
  LOG="$WORKDIR/apiserver.log"
  echo "Starting u7s-apiserver (logs: $LOG) ..."
  "$BINARY" \
    --db         "$WORKDIR/state.db" \
    --kubeconfig "$WORKDIR/kubeconfig" \
    --sa-key     "$WORKDIR/sa.key" \
    --sa-pub     "$WORKDIR/sa.pub" \
    --ca-key     "$WORKDIR/ca.key" \
    --ca-cert    "$WORKDIR/ca.crt" \
    --kubelet-preferred-address "127.0.0.1" \
    --service-cluster-ip-range "10.96.0.0/12" \
    $PROXY_ARG \
    $ADVERTISE_ARG \
    > "$LOG" 2>&1 &
  SERVER_PID=$!
  disown "$SERVER_PID"
else
  echo "Starting u7s-apiserver (state: $WORKDIR) ..."
  "$BINARY" \
    --db         "$WORKDIR/state.db" \
    --kubeconfig "$WORKDIR/kubeconfig" \
    --sa-key     "$WORKDIR/sa.key" \
    --sa-pub     "$WORKDIR/sa.pub" \
    --ca-key     "$WORKDIR/ca.key" \
    --ca-cert    "$WORKDIR/ca.crt" \
    --kubelet-preferred-address "127.0.0.1" \
    --service-cluster-ip-range "10.96.0.0/12" \
    $PROXY_ARG \
    $ADVERTISE_ARG \
    &
  SERVER_PID=$!
fi

if [ "$APISERVER_RUNNING" -eq 0 ]; then
  echo "Waiting for server to accept connections ..."
  for i in $(seq 1 10); do
    if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
      break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      if [ "$BACKGROUND" -eq 1 ]; then
        echo "error: u7s-apiserver exited immediately — see $LOG" >&2
        tail -20 "$LOG" >&2
      else
        echo "error: u7s-apiserver exited immediately — check logs above" >&2
      fi
      exit 1
    fi
    sleep 1
  done

  if ! nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
    if [ "$BACKGROUND" -eq 1 ]; then
      echo "error: server did not open port $PORT within 10s — see $LOG" >&2
      tail -20 "$LOG" >&2
    else
      echo "error: server did not open port $PORT within 10s" >&2
    fi
    kill "$SERVER_PID" 2>/dev/null || true
    exit 1
  fi

  # Start konnectivity-server now that ca.crt exists (generated by the apiserver).
  # On first run ca.crt did not exist before the apiserver launched, so we deferred
  # konnectivity startup until after the apiserver is up.
  if [ -f "$WORKDIR/ca.crt" ] && ! nc -z 127.0.0.1 $KONNECTIVITY_PROXY_PORT 2>/dev/null; then
    openssl x509 -inform DER -in "$WORKDIR/ca.crt" -out "$WORKDIR/ca.pem"
    if [ ! -f "$WORKDIR/konnectivity-server.crt" ]; then
      openssl ecparam -genkey -name prime256v1 -noout -out "$WORKDIR/konnectivity-server.key"
      openssl req -new -key "$WORKDIR/konnectivity-server.key" \
        -subj "/CN=konnectivity-server" -sha256 \
        -out "$WORKDIR/konnectivity-server.csr"
      cat > "$WORKDIR/konnectivity-server-ext.cnf" <<'EXTEOF'
[v3_req]
subjectAltName = IP:127.0.0.1,DNS:host.lima.internal,DNS:localhost
EXTEOF
      openssl x509 -req -in "$WORKDIR/konnectivity-server.csr" \
        -CA "$WORKDIR/ca.pem" -CAkey "$WORKDIR/ca.key" \
        -CAcreateserial -CAserial "$WORKDIR/ca.srl" -days 365 -sha256 \
        -extfile "$WORKDIR/konnectivity-server-ext.cnf" -extensions v3_req \
        -out "$WORKDIR/konnectivity-server.crt"
      rm -f "$WORKDIR/konnectivity-server.csr"
    fi
    "$SERVER_BIN" \
      --logtostderr=true --log-file-max-size=0 \
      --cluster-cert="$WORKDIR/konnectivity-server.crt" \
      --cluster-key="$WORKDIR/konnectivity-server.key" \
      --server-ca-cert="$WORKDIR/ca.pem" \
      --server-cert="$WORKDIR/konnectivity-server.crt" \
      --server-key="$WORKDIR/konnectivity-server.key" \
      --mode=http-connect --server-port=$KONNECTIVITY_PROXY_PORT \
      --agent-port=8132 --admin-port=8133 --health-port=8134 \
      >> "$WORKDIR/konnectivity-server.log" 2>&1 &
    disown $!
    for i in $(seq 1 10); do
      nc -z 127.0.0.1 $KONNECTIVITY_PROXY_PORT 2>/dev/null && break; sleep 1
    done
    # Restart apiserver with proxy flag now that konnectivity is up.
    if nc -z 127.0.0.1 $KONNECTIVITY_PROXY_PORT 2>/dev/null && [ "$BACKGROUND" -eq 1 ]; then
      kill "$SERVER_PID" 2>/dev/null || true
      sleep 1
      "$BINARY" \
        --db         "$WORKDIR/state.db" \
        --kubeconfig "$WORKDIR/kubeconfig" \
        --sa-key     "$WORKDIR/sa.key" \
        --sa-pub     "$WORKDIR/sa.pub" \
        --ca-key     "$WORKDIR/ca.key" \
        --ca-cert    "$WORKDIR/ca.crt" \
        --kubelet-preferred-address "127.0.0.1" \
        --service-cluster-ip-range "10.96.0.0/12" \
        --konnectivity-proxy-addr "127.0.0.1:$KONNECTIVITY_PROXY_PORT" \
        > "$LOG" 2>&1 &
      SERVER_PID=$!
      disown "$SERVER_PID"
      sleep 2
    fi
  fi

  if [ "$BACKGROUND" -eq 1 ]; then
    echo "u7s-apiserver running (PID $SERVER_PID, logs: $LOG)"
    echo "KUBECONFIG=$WORKDIR/kubeconfig"
  else
    echo ""
    echo "u7s is running (PID $SERVER_PID)"
    echo ""
    echo "  export KUBECONFIG=$WORKDIR/kubeconfig"
    echo ""
    echo "Next steps:"
    echo "  First run (VM not provisioned): scripts/conformance/lima-start.sh"
    echo "  Subsequent runs (VM exists):    scripts/kubelet-reconnect.sh"
    echo "  kubectl get nodes"
    echo ""
    echo "u7s logs are going to stdout/stderr of this process."
    echo "Press Ctrl-C to stop."
    echo ""
    wait "$SERVER_PID"
  fi
fi

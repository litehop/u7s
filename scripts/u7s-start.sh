#!/usr/bin/env bash
# Start u7s-apiserver for local development against a lima-node kubelet.
#
# State persists in ./temp/u7s/ (relative to CWD — always the active worktree)
# across restarts so the CA and kubelet trust relationship survive a server
# restart without re-provisioning the VM.
#
# Usage:
#   scripts/u7s-start.sh [--reset] [--background] [--port <N>] [--kubelet-port <N>]
#                        [--konnectivity-server-port <N>]
#
#   --reset       Wipe ./temp/u7s/ and start fresh (rotates CA — kubelet will need
#                 to be re-joined via scripts/conformance/lima-start.sh after this).
#   --background  Start backgrounded (logs to ./temp/u7s/apiserver.log). Kills
#                 any existing apiserver on the port and starts the new binary.
#   --port        Port for the apiserver to listen on (default: 6443). Use a different
#                 port to run multiple workers in parallel without collisions.
#   --kubelet-port  Host-side port the kubelet is reachable on (default: 10250). Override
#                 when the lima port-forward maps guest 10250 to a different host port
#                 for per-worktree isolation.
#   --konnectivity-server-port  Server-facing port for konnectivity-server (default: 8135).
#                 The other three ports (agent, admin, health) are derived as
#                 server_port-3, server_port-2, server_port-1 respectively.
#                 Per-slot scheme: slot N uses 8135+N*100 (slot1→8235, slot2→8335, …)
#                 so slots never collide with each other or the mayor's 8135 default.
#
# Environment variables:
#   U7S_HOST_IP   IP to bind and advertise (default: 127.0.0.1).
#                 The apiserver, konnectivity-server, and readiness checks all use this address.
#
# After starting (foreground mode):
#   export KUBECONFIG=./temp/u7s/kubeconfig   (relative to CWD / active worktree)
#   scripts/conformance/lima-start.sh  # join kubelet (first run or after --reset)
#   kubectl get nodes
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"

RESET=0
BACKGROUND=0
_WORKDIR_OVERRIDE=""
_PORT_OVERRIDE=""
_KUBELET_PORT_OVERRIDE=""
_KONNECTIVITY_SERVER_PORT_OVERRIDE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1; shift ;;
    --background) BACKGROUND=1; shift ;;
    --vm) U7S_VM_NAME="$2"; shift 2 ;;
    --ip) U7S_HOST_IP="$2"; shift 2 ;;
    --binary) U7S_BINARY="$2"; shift 2 ;;
    --workdir) _WORKDIR_OVERRIDE="$2"; shift 2 ;;
    --port) _PORT_OVERRIDE="$2"; shift 2 ;;
    --kubelet-port) _KUBELET_PORT_OVERRIDE="$2"; shift 2 ;;
    --konnectivity-server-port) _KONNECTIVITY_SERVER_PORT_OVERRIDE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done
PORT="${_PORT_OVERRIDE:-6443}"
KUBELET_PORT="${_KUBELET_PORT_OVERRIDE:-10250}"

# Derive WORKDIR and runtime vars after arg parsing so flags override env.
_VM="${U7S_VM_NAME:-lima-node}"
if [ -n "$_WORKDIR_OVERRIDE" ]; then
  WORKDIR="$_WORKDIR_OVERRIDE"
else
  WORKDIR="$PWD/temp/u7s"
fi
BINARY="${U7S_BINARY:-$REPO/target/release/u7s-apiserver}"
HOST_IP="${U7S_HOST_IP:-127.0.0.1}"

if [ ! -f "$BINARY" ]; then
  echo "error: binary not found — run: cargo build --release -p u7s-apiserver" >&2
  exit 1
fi

KONNECTIVITY_OUT=$("$REPO/scripts/download-konnectivity.sh")
SERVER_BIN=$(echo "$KONNECTIVITY_OUT" | grep '^server=' | cut -d= -f2)

# Kill this worktree's konnectivity-server (scoped by cert path) so a --reset
# doesn't leave one running with cert paths that no longer exist in the wiped WORKDIR.
pkill -f "konnectivity-server.*${WORKDIR}" 2>/dev/null || true

if nc -z "$HOST_IP" "$PORT" 2>/dev/null; then
  if [ "$BACKGROUND" -eq 1 ]; then
    echo "Port $HOST_IP:$PORT in use — killing existing apiserver before restart ..." >&2
    API_PID=$(lsof -ti tcp:"$PORT" -sTCP:LISTEN 2>/dev/null || true)
    [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
    for i in $(seq 1 10); do
      nc -z "$HOST_IP" "$PORT" 2>/dev/null || break
      sleep 1
    done
  else
    echo "error: port $HOST_IP:$PORT is already in use." >&2
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

if [ -n "${_KONNECTIVITY_SERVER_PORT_OVERRIDE:-}" ]; then
  KONNECTIVITY_PROXY_PORT="$_KONNECTIVITY_SERVER_PORT_OVERRIDE"
else
  # Auto-derive: 6443→8135, 6444→8235, 6445→8335 (each port offset of 1 adds 100).
  KONNECTIVITY_PROXY_PORT=$(( 8135 + (PORT - 6443) * 100 ))
fi
# Derive agent/admin/health ports from the server port: server=N, agent=N-3, admin=N-2, health=N-1.
# This matches the mayor default layout (8135/8132/8133/8134) and lets each slot pick
# a unique base (slot1→8235, slot2→8335, …) without colliding with the mayor or each other.
KONNECTIVITY_AGENT_PORT=$(( KONNECTIVITY_PROXY_PORT - 3 ))
KONNECTIVITY_ADMIN_PORT=$(( KONNECTIVITY_PROXY_PORT - 2 ))
KONNECTIVITY_HEALTH_PORT=$(( KONNECTIVITY_PROXY_PORT - 1 ))

if [ -f "$WORKDIR/ca.crt" ]; then
  openssl x509 -inform DER -in "$WORKDIR/ca.crt" -out "$WORKDIR/ca.pem"

  if [ "$RESET" -eq 1 ] || [ ! -f "$WORKDIR/konnectivity-server.crt" ]; then
    openssl ecparam -genkey -name prime256v1 -noout -out "$WORKDIR/konnectivity-server.key"
    openssl req -new -key "$WORKDIR/konnectivity-server.key" \
      -subj "/CN=konnectivity-server" \
      -sha256 \
      -out "$WORKDIR/konnectivity-server.csr"
    cat > "$WORKDIR/konnectivity-server-ext.cnf" <<EXTEOF
[v3_req]
subjectAltName = IP:${HOST_IP},DNS:host.lima.internal,DNS:localhost
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

  pkill -f "konnectivity-server.*${WORKDIR}" || true

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
    --server-bind-address="$HOST_IP" \
    --agent-port=$KONNECTIVITY_AGENT_PORT \
    --agent-bind-address="$HOST_IP" \
    --admin-port=$KONNECTIVITY_ADMIN_PORT \
    --admin-bind-address="$HOST_IP" \
    --health-port=$KONNECTIVITY_HEALTH_PORT \
    --health-bind-address="$HOST_IP" \
    >> "$WORKDIR/konnectivity-server.log" 2>&1 &
  disown $!

  for i in $(seq 1 10); do
    nc -z "$HOST_IP" $KONNECTIVITY_PROXY_PORT 2>/dev/null && break
    sleep 1
  done
  if ! nc -z "$HOST_IP" $KONNECTIVITY_PROXY_PORT 2>/dev/null; then
    echo "error: konnectivity-server did not open port $HOST_IP:$KONNECTIVITY_PROXY_PORT within 10s — see $WORKDIR/konnectivity-server.log" >&2
    exit 1
  fi
fi

PROXY_ARG=""
if [ -f "$WORKDIR/ca.crt" ]; then
  PROXY_ARG="--konnectivity-proxy-addr $HOST_IP:$KONNECTIVITY_PROXY_PORT"
fi

ADVERTISE_ARG="--advertise-address https://$HOST_IP:$PORT"

if [ "$BACKGROUND" -eq 1 ]; then
  LOG="$WORKDIR/apiserver.log"
  echo "Starting u7s-apiserver (logs: $LOG) ..."
  "$BINARY" \
    --db         "$WORKDIR/state.db" \
    --listen     "$HOST_IP:$PORT" \
    --kubeconfig "$WORKDIR/kubeconfig" \
    --sa-key     "$WORKDIR/sa.key" \
    --sa-pub     "$WORKDIR/sa.pub" \
    --ca-key     "$WORKDIR/ca.key" \
    --ca-cert    "$WORKDIR/ca.crt" \
    --kubelet-preferred-address "$HOST_IP" \
    --kubelet-port "$KUBELET_PORT" \
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
    --listen     "$HOST_IP:$PORT" \
    --kubeconfig "$WORKDIR/kubeconfig" \
    --sa-key     "$WORKDIR/sa.key" \
    --sa-pub     "$WORKDIR/sa.pub" \
    --ca-key     "$WORKDIR/ca.key" \
    --ca-cert    "$WORKDIR/ca.crt" \
    --kubelet-preferred-address "$HOST_IP" \
    --kubelet-port "$KUBELET_PORT" \
    --service-cluster-ip-range "10.96.0.0/12" \
    $PROXY_ARG \
    $ADVERTISE_ARG \
    &
  SERVER_PID=$!
fi

echo "Waiting for server to accept connections ..."
for i in $(seq 1 10); do
  if nc -z "$HOST_IP" "$PORT" 2>/dev/null; then
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

if ! nc -z "$HOST_IP" "$PORT" 2>/dev/null; then
  if [ "$BACKGROUND" -eq 1 ]; then
    echo "error: server did not open port $HOST_IP:$PORT within 10s — see $LOG" >&2
    tail -20 "$LOG" >&2
  else
    echo "error: server did not open port $HOST_IP:$PORT within 10s" >&2
  fi
  kill "$SERVER_PID" 2>/dev/null || true
  exit 1
fi

# Start konnectivity-server now that ca.crt exists (generated by the apiserver).
# On first run ca.crt did not exist before the apiserver launched, so we deferred
# konnectivity startup until after the apiserver is up.
if [ -f "$WORKDIR/ca.crt" ] && ! nc -z "$HOST_IP" $KONNECTIVITY_PROXY_PORT 2>/dev/null; then
  openssl x509 -inform DER -in "$WORKDIR/ca.crt" -out "$WORKDIR/ca.pem"
  if [ ! -f "$WORKDIR/konnectivity-server.crt" ]; then
    openssl ecparam -genkey -name prime256v1 -noout -out "$WORKDIR/konnectivity-server.key"
    openssl req -new -key "$WORKDIR/konnectivity-server.key" \
      -subj "/CN=konnectivity-server" -sha256 \
      -out "$WORKDIR/konnectivity-server.csr"
    cat > "$WORKDIR/konnectivity-server-ext.cnf" <<EXTEOF
[v3_req]
subjectAltName = IP:${HOST_IP},DNS:host.lima.internal,DNS:localhost
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
    --server-bind-address="$HOST_IP" \
    --agent-port=$KONNECTIVITY_AGENT_PORT --agent-bind-address="$HOST_IP" \
    --admin-port=$KONNECTIVITY_ADMIN_PORT --admin-bind-address="$HOST_IP" \
    --health-port=$KONNECTIVITY_HEALTH_PORT --health-bind-address="$HOST_IP" \
    >> "$WORKDIR/konnectivity-server.log" 2>&1 &
  disown $!
  for i in $(seq 1 10); do
    nc -z "$HOST_IP" $KONNECTIVITY_PROXY_PORT 2>/dev/null && break; sleep 1
  done
  # Restart apiserver with proxy flag now that konnectivity is up.
  if nc -z "$HOST_IP" $KONNECTIVITY_PROXY_PORT 2>/dev/null && [ "$BACKGROUND" -eq 1 ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    sleep 1
    "$BINARY" \
      --db         "$WORKDIR/state.db" \
      --listen     "$HOST_IP:$PORT" \
      --kubeconfig "$WORKDIR/kubeconfig" \
      --sa-key     "$WORKDIR/sa.key" \
      --sa-pub     "$WORKDIR/sa.pub" \
      --ca-key     "$WORKDIR/ca.key" \
      --ca-cert    "$WORKDIR/ca.crt" \
      --kubelet-preferred-address "$HOST_IP" \
      --kubelet-port "$KUBELET_PORT" \
      --service-cluster-ip-range "10.96.0.0/12" \
      --konnectivity-proxy-addr "$HOST_IP:$KONNECTIVITY_PROXY_PORT" \
      $ADVERTISE_ARG \
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

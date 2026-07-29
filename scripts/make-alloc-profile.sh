#!/usr/bin/env bash
# make-alloc-profile.sh — Build u7s-apiserver with the dhat allocation
# profiler and run it long enough to capture a representative workload
# (e.g. a few kubectl/curl calls against it), then stop it so dhat's
# Drop-based profiler flushes dhat-heap.json for offline inspection.
#
# Open the resulting dhat-heap.json with dhat's viewer:
#   https://valgrind.org/docs/manual/dh-manual.html
# (dh_view.html from that page, or https://nnethercote.github.io/dh_view/dh_view.html)
#
# Usage:
#   scripts/make-alloc-profile.sh [duration_seconds]
#
#   duration_seconds  Optional. If given, the server is stopped automatically
#                      after this many seconds. If omitted, it runs until you
#                      press Ctrl-C.
#
# Environment variables:
#   U7S_ALLOC_PORT  Port for the apiserver to listen on (default: 18443).
set -euo pipefail

# Enables job control so the background apiserver gets its own process
# group — without this, a Ctrl-C at the terminal delivers SIGINT straight to
# the apiserver (default disposition: terminate, no destructors run) instead
# of only to this script, defeating the SIGTERM-triggered profile flush below.
set -m

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${U7S_ALLOC_PORT:-18443}"
DURATION="${1:-}"
SERVER_PID=""

PROFILE_DIR="$(mktemp -d /tmp/u7s-alloc-profile-XXXXXX)"
HEAP_FILE="$PROFILE_DIR/dhat-heap.json"

stop_server() {
    if [ -n "$SERVER_PID" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
}
trap stop_server EXIT
trap 'echo; echo "==> Ctrl-C received, stopping apiserver..."; stop_server' INT

echo "==> Building release binary with the dhat feature..."
cargo build --release -p u7s-apiserver --features dhat --manifest-path "$REPO/Cargo.toml"

echo "==> Starting apiserver on 127.0.0.1:$PORT (logs -> $PROFILE_DIR/server.log)..."
ALLOC_TOKEN="alloc-profile-token"
echo "$ALLOC_TOKEN,alloc-admin,uid0,system:masters" > "$PROFILE_DIR/token-auth.csv"

# dhat writes dhat-heap.json relative to the process's CWD by default, so run
# the binary from PROFILE_DIR — that's where the profile ends up. `exec`
# replaces the subshell with the binary so $! below is the apiserver's own
# PID, letting stop_server signal it directly.
(
    cd "$PROFILE_DIR"
    exec "$REPO/target/release/u7s-apiserver" \
        --db "$PROFILE_DIR/state.db" \
        --listen "127.0.0.1:$PORT" \
        --kubeconfig "$PROFILE_DIR/kubeconfig" \
        --sa-key "$PROFILE_DIR/sa.key" \
        --sa-pub "$PROFILE_DIR/sa.pub" \
        --ca-key "$PROFILE_DIR/ca.key" \
        --ca-cert "$PROFILE_DIR/ca.crt" \
        --token-auth-file "$PROFILE_DIR/token-auth.csv" \
        --advertise-address "https://127.0.0.1:$PORT" \
        --service-cluster-ip-range "10.96.0.0/12" \
        >"$PROFILE_DIR/server.log" 2>&1
) &
SERVER_PID=$!

echo "==> Waiting for server to accept connections (up to 10s)..."
for i in $(seq 1 10); do
    nc -z 127.0.0.1 "$PORT" 2>/dev/null && break
    sleep 1
done
if ! nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
    echo "ERROR: server did not start within 10s" >&2
    cat "$PROFILE_DIR/server.log" || true
    exit 1
fi

echo ""
echo "==> apiserver running under dhat (PID $SERVER_PID)."
echo "    kubeconfig: $PROFILE_DIR/kubeconfig"
echo "    Bearer token: $ALLOC_TOKEN (curl -k -H \"Authorization: Bearer $ALLOC_TOKEN\" https://127.0.0.1:$PORT/...)"
echo "    Run your representative workload now."
echo ""

if [ -n "$DURATION" ]; then
    echo "==> Running for ${DURATION}s..."
    sleep "$DURATION"
else
    echo "==> Press Ctrl-C when you're done to stop the server and flush the profile."
    wait "$SERVER_PID" 2>/dev/null || true
fi

echo "==> Stopping apiserver (SIGTERM) so dhat flushes its profile..."
stop_server

if [ -f "$HEAP_FILE" ]; then
    echo ""
    echo "==> Allocation profile written to: $HEAP_FILE ($(du -h "$HEAP_FILE" | awk '{print $1}'))"
    echo "    Open it with dhat's viewer: https://valgrind.org/docs/manual/dh-manual.html"
else
    echo "ERROR: expected $HEAP_FILE but it was not written — see $PROFILE_DIR/server.log" >&2
    exit 1
fi

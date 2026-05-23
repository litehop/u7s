#!/usr/bin/env bash
# Start u7s-scheduler for local development / conformance runs.
#
# Builds u7s-scheduler inside the Lima VM if cargo is available; installs
# rustup if not.  The repo is mounted read-only inside Lima at the same host
# path, so we build into a writable directory under /tmp.
#
# The scheduler connects to the apiserver on the host.  When running inside the
# Lima VM the apiserver is reachable via host.lima.internal rather than
# 127.0.0.1 — we rewrite the kubeconfig on the fly.
#
# NOTE: This script is intended to run INSIDE the Lima VM (Linux).
# On Mac: limactl shell lima-node bash "$REPO/scripts/scheduler-start.sh"
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="$REPO/temp/u7s"
BUILD_DIR="/tmp/u7s-scheduler-build"
SCHEDULER_LOG="/tmp/scheduler.log"

# Check required state files.
for f in "$WORKDIR/kubeconfig"; do
  if [ ! -f "$f" ]; then
    echo "error: missing required file: $f" >&2
    echo "Start u7s-start.sh first to generate state files." >&2
    exit 1
  fi
done

# Rewrite kubeconfig: 127.0.0.1 → host.lima.internal when running inside the VM.
TMPDIR_SCHED="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_SCHED"' EXIT

KUBECONFIG_FILE="$WORKDIR/kubeconfig"
if grep -q "127.0.0.1" "$KUBECONFIG_FILE" && \
   grep -q "host.lima.internal" /etc/hosts 2>/dev/null; then
  sed 's|https://127.0.0.1:6443|https://host.lima.internal:6443|g' \
    "$KUBECONFIG_FILE" > "$TMPDIR_SCHED/kubeconfig"
  KUBECONFIG_FILE="$TMPDIR_SCHED/kubeconfig"
fi

# Ensure cargo is available; install rustup if not.
if ! command -v cargo &>/dev/null; then
  if [ ! -f "$HOME/.cargo/bin/cargo" ]; then
    echo "cargo not found — installing rustup..."
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
  fi
  # shellcheck source=/dev/null
  source "$HOME/.cargo/env"
fi

if ! command -v cargo &>/dev/null; then
  echo "error: cargo still not available after rustup install" >&2
  exit 1
fi

# Build u7s-scheduler inside the VM.  The repo mount is read-only, so we
# redirect the Cargo target dir to a writable location under /tmp.
echo "Building u7s-scheduler (target dir: $BUILD_DIR) ..."
mkdir -p "$BUILD_DIR"
CARGO_TARGET_DIR="$BUILD_DIR" cargo build --release \
  --manifest-path="$REPO/Cargo.toml" \
  -p u7s-scheduler

SCHEDULER_BIN="$BUILD_DIR/release/u7s-scheduler"

echo "Starting u7s-scheduler ..."
exec "$SCHEDULER_BIN" \
  --kubeconfig="$KUBECONFIG_FILE" \
  --leader-elect=false

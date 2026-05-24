#!/usr/bin/env bash
# Start kube-controller-manager for local development.
#
# Downloads the kcm binary if not already cached in ~/.cache/u7s/kcm/
# (override with KCM_CACHE_DIR env var).
# Uses the cert-based kubeconfig at ./temp/u7s/kubeconfig (kcm requires
# x509 client cert auth — the token-based kubeconfig will NOT work).
#
# NOTE: kcm is a Linux binary. On a Mac host it must run inside the Lima VM.
# This script is intended to be called from inside the Lima VM or on Linux CI.
# On Mac: limactl shell lima-node bash -c "cd /path/to/repo && scripts/kcm-start.sh"
#
# Usage:
#   scripts/kcm-start.sh [--k8s-version <version>]
#
#   --k8s-version   Override the k8s version (default: match installed kubectl,
#                   fallback 1.34.8)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="$REPO/temp/u7s"
# The repo may be mounted read-only (e.g. inside Lima VM). Use a writable
# user-local cache dir for the downloaded binary.
CACHE_DIR="${KCM_CACHE_DIR:-${HOME}/.cache/u7s/kcm}"

# Determine default k8s version from installed kubectl; fallback to 1.34.8.
DEFAULT_VERSION="1.34.8"
if command -v kubectl &>/dev/null; then
  DETECTED=$(kubectl version --client -o json 2>/dev/null \
    | jq -r '.clientVersion.gitVersion' 2>/dev/null \
    | sed 's/^v//' || true)
  if [[ "$DETECTED" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    DEFAULT_VERSION="$DETECTED"
  fi
fi

K8S_VERSION="$DEFAULT_VERSION"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --k8s-version) K8S_VERSION="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# Detect platform for download URL.
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
  *)       echo "error: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

if [ "$OS" != "linux" ]; then
  echo "error: kcm is a Linux binary. On Mac, run this script inside the Lima VM:" >&2
  echo "  limactl shell lima-node bash -c \"cd /path/to/repo && scripts/kcm-start.sh\"" >&2
  exit 1
fi

KCM_BINARY="$CACHE_DIR/kube-controller-manager-${K8S_VERSION}-linux-${ARCH}"

# Check required state files exist.
for f in "$WORKDIR/kubeconfig" "$WORKDIR/ca.crt" "$WORKDIR/ca.key" "$WORKDIR/sa.key"; do
  if [ ! -f "$f" ]; then
    echo "error: missing required file: $f" >&2
    echo "Start u7s-start.sh first to generate state files." >&2
    exit 1
  fi
done

# Download kcm binary if not already cached.
if [ ! -f "$KCM_BINARY" ]; then
  mkdir -p "$CACHE_DIR"
  URL="https://dl.k8s.io/release/v${K8S_VERSION}/bin/linux/${ARCH}/kube-controller-manager"
  echo "Downloading kube-controller-manager v${K8S_VERSION} (linux/${ARCH}) ..."
  curl -fsSL "$URL" -o "$KCM_BINARY"
  chmod +x "$KCM_BINARY"
  echo "Cached at $KCM_BINARY"
fi

# ca.crt is written by u7s in DER format; KCM requires PEM. Convert on the fly.
# Also, when running inside a Lima VM the apiserver is on the host, reachable
# via host.lima.internal rather than 127.0.0.1 — rewrite the kubeconfig.
TMPDIR_KCM="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_KCM"' EXIT

openssl x509 -inform DER -in "$WORKDIR/ca.crt" -out "$TMPDIR_KCM/ca.pem"
CA_CERT="$TMPDIR_KCM/ca.pem"

KUBECONFIG_FILE="$WORKDIR/kubeconfig"
if grep -q "127.0.0.1" "$KUBECONFIG_FILE" && \
   grep -q "host.lima.internal" /etc/hosts 2>/dev/null; then
  sed 's|https://127.0.0.1:6443|https://host.lima.internal:6443|g' \
    "$KUBECONFIG_FILE" > "$TMPDIR_KCM/kubeconfig"
  KUBECONFIG_FILE="$TMPDIR_KCM/kubeconfig"
fi

echo "Starting kube-controller-manager v${K8S_VERSION} ..."
exec "$KCM_BINARY" \
  --kubeconfig="$KUBECONFIG_FILE" \
  --cluster-signing-cert-file="$CA_CERT" \
  --cluster-signing-key-file="$WORKDIR/ca.key" \
  --service-account-private-key-file="$WORKDIR/sa.key" \
  --root-ca-file="$CA_CERT" \
  --controllers=csrapproving,csrsigning,garbagecollector,deployment,replicaset,root-ca-cert-publisher \
  --use-service-account-credentials=false \
  --leader-elect=false \
  --bind-address=127.0.0.1 \
  --kube-api-content-type=application/json

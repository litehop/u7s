#!/usr/bin/env bash
set -euo pipefail

VERSION="v0.35.0"
CACHE_DIR="${HOME}/.cache/u7s/konnectivity"
BASE_URL="https://github.com/kubernetes-sigs/apiserver-network-proxy/releases/download/${VERSION}"

HOST_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
HOST_ARCH="$(uname -m)"
case "${HOST_ARCH}" in
  x86_64)       HOST_ARCH="amd64" ;;
  aarch64|arm64) HOST_ARCH="arm64" ;;
  *) echo "error: unsupported host architecture: ${HOST_ARCH}" >&2; exit 1 ;;
esac

SERVER_BINARY="${CACHE_DIR}/proxy-server-${HOST_OS}-${HOST_ARCH}"
AGENT_BINARY="${CACHE_DIR}/proxy-agent-linux-arm64"

mkdir -p "${CACHE_DIR}"

if [ ! -f "${SERVER_BINARY}" ]; then
  echo "Downloading konnectivity-server ${VERSION} (${HOST_OS}/${HOST_ARCH}) ..." >&2
  curl -fsSL "${BASE_URL}/proxy-server-${HOST_OS}-${HOST_ARCH}" -o "${SERVER_BINARY}"
  chmod +x "${SERVER_BINARY}"
fi

if [ ! -f "${AGENT_BINARY}" ]; then
  echo "Downloading konnectivity-agent ${VERSION} (linux/arm64) ..." >&2
  curl -fsSL "${BASE_URL}/proxy-agent-linux-arm64" -o "${AGENT_BINARY}"
  chmod +x "${AGENT_BINARY}"
fi

echo "server=${SERVER_BINARY}"
echo "agent=${AGENT_BINARY}"

#!/usr/bin/env bash
set -euo pipefail

VERSION="v0.35.0"
REPO="https://github.com/kubernetes-sigs/apiserver-network-proxy.git"
CACHE_DIR="${HOME}/.cache/u7s/konnectivity/${VERSION}"

HOST_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
HOST_ARCH="$(uname -m)"
case "${HOST_ARCH}" in
  x86_64)        HOST_ARCH="amd64" ;;
  aarch64|arm64) HOST_ARCH="arm64" ;;
  *) echo "error: unsupported host architecture: ${HOST_ARCH}" >&2; exit 1 ;;
esac

SERVER_BINARY="${CACHE_DIR}/proxy-server-${HOST_OS}-${HOST_ARCH}"
AGENT_BINARY="${CACHE_DIR}/proxy-agent-linux-arm64"

mkdir -p "${CACHE_DIR}"

if [ ! -f "${SERVER_BINARY}" ] || [ ! -f "${AGENT_BINARY}" ]; then
  SRC_DIR="${CACHE_DIR}/src"
  if [ ! -d "${SRC_DIR}" ]; then
    echo "Cloning apiserver-network-proxy ${VERSION} ..." >&2
    git clone --depth=1 --branch "${VERSION}" "${REPO}" "${SRC_DIR}" 2>&1 | tail -3 >&2
  fi

  if [ ! -f "${SERVER_BINARY}" ]; then
    echo "Building proxy-server (${HOST_OS}/${HOST_ARCH}) ..." >&2
    CGO_ENABLED=0 GOOS="${HOST_OS}" GOARCH="${HOST_ARCH}" \
      go build -C "${SRC_DIR}" -mod=vendor -o "${SERVER_BINARY}" ./cmd/server/
    chmod +x "${SERVER_BINARY}"
  fi

  if [ ! -f "${AGENT_BINARY}" ]; then
    echo "Building proxy-agent (linux/arm64) ..." >&2
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
      go build -C "${SRC_DIR}" -mod=vendor -o "${AGENT_BINARY}" ./cmd/agent/
    chmod +x "${AGENT_BINARY}"
  fi
fi

echo "server=${SERVER_BINARY}"
echo "agent=${AGENT_BINARY}"

#!/usr/bin/env bash
# Download and start kube-controller-manager inside the lima VM.
#
# Setup (download, cert conversion, kubeconfig rewrite) runs foreground so
# the script only returns after kcm is ready. Only the final binary launch
# is backgrounded.
#
# Part of the scripts/conformance/ orchestration sequence.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
KCM_LOG="/tmp/kcm.log"

_WORKDIR_OVERRIDE=""
_PORT_OVERRIDE=""
KCM_V=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm) U7S_VM_NAME="$2"; shift 2 ;;
    --workdir) _WORKDIR_OVERRIDE="$2"; shift 2 ;;
    --port) _PORT_OVERRIDE="$2"; shift 2 ;;
    --kcm-v) KCM_V="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done
PORT="${_PORT_OVERRIDE:-6443}"

_VM="${U7S_VM_NAME:-lima-node}"
VM_NAME="$_VM"
if [ -n "$_WORKDIR_OVERRIDE" ]; then
  WORKDIR="$_WORKDIR_OVERRIDE"
else
  WORKDIR="$PWD/temp/u7s"
fi

echo "=== [04] Start kube-controller-manager (inside $VM_NAME) ==="

if ! command -v limactl &>/dev/null; then
  echo "error: limactl not found — install with: brew install lima" >&2
  exit 1
fi

# Kill any stale kube-controller-manager from a previous run.
limactl shell "$VM_NAME" bash -c \
  "if pgrep -f '^kube-controller-manager' >/dev/null 2>&1; then echo 'WARNING: kube-controller-manager already running — killing and restarting' >&2; pkill -f '^kube-controller-manager' 2>/dev/null || true; sleep 1; fi"

# Run setup foreground (download, cert conversion, kubeconfig rewrite),
# then background only the final binary launch.
limactl shell "$VM_NAME" bash -s <<EOF
set -euo pipefail

WORKDIR="$WORKDIR"
# Verbosity flag: when run-all.sh is invoked with --verbose it passes --kcm-v <N>,
# which becomes "--v=<N>" here so the disruption controller's V(4) pod-list logs appear.
KCM_V_FLAG="$([ -n "$KCM_V" ] && echo "--v=$KCM_V" || echo "")"
CACHE_DIR="\${KCM_CACHE_DIR:-\${HOME}/.cache/u7s/kcm}"
KCM_LOG="$KCM_LOG"

# Determine k8s version from kubectl inside the VM; fallback to 1.36.1.
DEFAULT_VERSION="1.36.1"
if command -v kubectl &>/dev/null; then
  DETECTED=\$(kubectl version --client -o json 2>/dev/null \
    | jq -r '.clientVersion.gitVersion' 2>/dev/null \
    | sed 's/^v//' || true)
  if [[ "\$DETECTED" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    DEFAULT_VERSION="\$DETECTED"
  fi
fi
K8S_VERSION="\$DEFAULT_VERSION"

ARCH="\$(uname -m)"
case "\$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "error: unsupported architecture: \$ARCH" >&2; exit 1 ;;
esac

KCM_BINARY="\$CACHE_DIR/kube-controller-manager-\${K8S_VERSION}-linux-\${ARCH}"

for f in "\$WORKDIR/kubeconfig" "\$WORKDIR/ca.crt" "\$WORKDIR/ca.key" "\$WORKDIR/sa.key"; do
  if [ ! -f "\$f" ]; then
    echo "error: missing required file: \$f" >&2
    exit 1
  fi
done

if [ ! -f "\$KCM_BINARY" ]; then
  mkdir -p "\$CACHE_DIR"
  URL="https://dl.k8s.io/release/v\${K8S_VERSION}/bin/linux/\${ARCH}/kube-controller-manager"
  echo "Downloading kube-controller-manager v\${K8S_VERSION} (linux/\${ARCH}) ..."
  curl -fsSL "\$URL" -o "\$KCM_BINARY"
  chmod +x "\$KCM_BINARY"
  echo "Cached at \$KCM_BINARY"
fi

# ca.crt is written by u7s in DER format; KCM requires PEM.
TMPDIR_KCM="\$(mktemp -d)"
openssl x509 -inform DER -in "\$WORKDIR/ca.crt" -out "\$TMPDIR_KCM/ca.pem"
CA_CERT="\$TMPDIR_KCM/ca.pem"

KUBECONFIG_FILE="\$WORKDIR/kubeconfig"
if grep -qE "https://127\." "\$KUBECONFIG_FILE" && grep -q "host.lima.internal" /etc/hosts 2>/dev/null; then
  sed "s|https://127\.[0-9]*\.[0-9]*\.[0-9]*:[0-9]*|https://host.lima.internal:${PORT}|g" "\$KUBECONFIG_FILE" > "\$TMPDIR_KCM/kubeconfig"
  KUBECONFIG_FILE="\$TMPDIR_KCM/kubeconfig"
fi

echo "Starting kube-controller-manager v\${K8S_VERSION} ..."
setsid "\$KCM_BINARY" \\
  --kubeconfig="\$KUBECONFIG_FILE" \\
  --cluster-signing-cert-file="\$CA_CERT" \\
  --cluster-signing-key-file="\$WORKDIR/ca.key" \\
  --service-account-private-key-file="\$WORKDIR/sa.key" \\
  --root-ca-file="\$CA_CERT" \\
  --controllers='*,-cloud-node-lifecycle-controller,-node-ipam-controller,-node-lifecycle-controller,-node-route-controller,-service-lb-controller,-service-cidr-controller' \\
  --use-service-account-credentials=false \\
  --leader-elect=false \\
  --bind-address=127.0.0.1 \\
  --kube-api-content-type=application/json \\
  \$KCM_V_FLAG \\
  > "\$KCM_LOG" 2>&1 &

echo "kube-controller-manager running (PID \$!, log: \$KCM_LOG)"
EOF

echo "To tail: limactl shell $VM_NAME tail -f $KCM_LOG"

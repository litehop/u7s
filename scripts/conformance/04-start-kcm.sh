#!/usr/bin/env bash
# Download and start kube-controller-manager inside the lima VM.
#
# Setup (download, cert conversion, kubeconfig rewrite) runs foreground so
# the script only returns after kcm is ready. Only the final launch — now a
# crash supervisor (kcm-supervisor.sh) wrapping the binary — is backgrounded.
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

# Kill any stale kube-controller-manager from a previous run. The real process
# is launched via an absolute cached-binary path (e.g.
# /home/.../kube-controller-manager-1.36.4-linux-arm64), so an anchored
# '^kube-controller-manager' pattern never matches — match the versioned
# binary basename instead (the trailing [0-9] also keeps this guard's own
# quoted pattern text below from matching itself).
limactl shell "$VM_NAME" bash -c \
  "if pgrep -f 'kube-controller-manager-[0-9]' >/dev/null 2>&1; then echo 'WARNING: kube-controller-manager already running — killing and restarting' >&2; pkill -f 'kube-controller-manager-[0-9]' 2>/dev/null || true; sleep 1; fi"

# Copy the crash supervisor onto the VM — it wraps the final binary launch
# below so a kcm panic gets restarted (bounded exponential backoff) instead
# of silently blacking out the control plane for the rest of an unattended
# run. See kcm-supervisor.sh for the backoff/circuit-breaker logic.
limactl copy "$REPO/scripts/conformance/kcm-supervisor.sh" "${VM_NAME}:/tmp/kcm-supervisor.sh"

# Run setup foreground (download, cert conversion, kubeconfig rewrite),
# then background only the final binary launch.
limactl shell "$VM_NAME" bash -s <<EOF
set -euo pipefail

# Raise the FD limit before launching kube-controller-manager below — see
# u7s-start.sh (host side) for why: sustained load exceeds a low default
# RLIMIT_NOFILE trivially, and KCM holds a long-lived watch per controller.
ulimit -n 65536 2>/dev/null || ulimit -n "\$(ulimit -Hn)" 2>/dev/null || true

WORKDIR="$WORKDIR"
# klog has no --utc flag, so kube-controller-manager renders whatever local time
# it inherits; force UTC here so kcm.log matches apiserver.log/scheduler.log.
export TZ=UTC
# Go runtime tuning for smaller RSS -- same lever class as kubelet's proven
# GOMEMLIMIT/GOGC/GOMAXPROCS fix, measured independently for KCM rather than
# assumed to transfer (see PR description for before/after numbers). Exported
# here rather than via a systemd Environment= drop-in (KCM has none) so
# kcm-supervisor.sh and the kube-controller-manager binary it execs both
# inherit it as ordinary child processes. GOMEMLIMIT is a soft cap: GC works
# harder as it's approached, it never OOM-kills, so this is safe to trial and
# fully reversible.
# Round-2: 200MiB->128MiB. Two tuned full-conformance samples measured
# KCM peak at 109.2MB/112.8MB (transient 115.48MB) -- 128MiB still clears
# that by 19-25MB while giving GC less headroom to coast on.
export GOMEMLIMIT=128MiB
export GOGC=50
export GOMAXPROCS=2
# Verbosity flag: when run-all.sh is invoked with --verbose it passes --kcm-v <N>,
# which becomes "--v=<N>" here to surface controller-decision logs (see run-all.sh
# for the level chosen and why).
KCM_V_FLAG="$([ -n "$KCM_V" ] && echo "--v=$KCM_V" || echo "")"
CACHE_DIR="\${KCM_CACHE_DIR:-\${HOME}/.cache/u7s/kcm}"
KCM_LOG="$KCM_LOG"

# Determine k8s version from kubectl inside the VM; fallback to 1.37.0.
DEFAULT_VERSION="1.37.0"
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

for f in "\$WORKDIR/kcm-kubeconfig" "\$WORKDIR/ca.crt" "\$WORKDIR/ca.key" "\$WORKDIR/sa.key"; do
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

KUBECONFIG_FILE="\$WORKDIR/kcm-kubeconfig"
if grep -qE "https://127\." "\$KUBECONFIG_FILE" && grep -q "host.lima.internal" /etc/hosts 2>/dev/null; then
  sed "s|https://127\.[0-9]*\.[0-9]*\.[0-9]*:[0-9]*|https://host.lima.internal:${PORT}|g" "\$KUBECONFIG_FILE" > "\$TMPDIR_KCM/kubeconfig"
  KUBECONFIG_FILE="\$TMPDIR_KCM/kubeconfig"
fi

echo "Starting kube-controller-manager v\${K8S_VERSION} (under crash supervisor) ..."
SUPERVISOR_LOG="/tmp/kcm-supervisor.log"
chmod +x /tmp/kcm-supervisor.sh
# -clusterrole-aggregation-controller / -device-taint-eviction-controller:
# see scripts/install.sh's u7s-kcm.service for why -- mirrored here so the
# conformance run exercises what ships.
# --authorization-always-allow-paths below adds /metrics to the default
# /healthz,/readyz,/livez allow-list. Without it, sample-run-metrics.sh's
# unauthenticated curl to :10257/metrics gets a 403 -- confirmed: archived
# kcm-metrics-*.prom snapshots hold a JSON Forbidden body, not Prometheus
# text, so it's not just missing go_memstats, it's zero series of any kind.
setsid bash /tmp/kcm-supervisor.sh "\$KCM_BINARY" "\$KCM_LOG" \\
  --kubeconfig="\$KUBECONFIG_FILE" \\
  --cluster-signing-cert-file="\$CA_CERT" \\
  --cluster-signing-key-file="\$WORKDIR/ca.key" \\
  --service-account-private-key-file="\$WORKDIR/sa.key" \\
  --root-ca-file="\$CA_CERT" \\
  --controllers='*,-cloud-node-lifecycle-controller,-clusterrole-aggregation-controller,-device-taint-eviction-controller,-node-ipam-controller,-node-route-controller,-service-lb-controller,-service-cidr-controller' \\
  --concurrent-gc-syncs=5 \\
  --use-service-account-credentials=false \\
  --leader-elect=false \\
  --bind-address=127.0.0.1 \\
  --kube-api-content-type=application/json \\
  --authorization-always-allow-paths=/healthz,/readyz,/livez,/metrics \\
  \$KCM_V_FLAG \\
  > "\$SUPERVISOR_LOG" 2>&1 &

echo "kube-controller-manager supervisor running (PID \$!, kcm log: \$KCM_LOG, supervisor log: \$SUPERVISOR_LOG)"
EOF

echo "To tail: limactl shell $VM_NAME tail -f $KCM_LOG"
echo "Supervisor log (restarts/crashes): limactl shell $VM_NAME tail -f /tmp/kcm-supervisor.log"

#!/usr/bin/env bash
# Brings up a cluster on a Lima VM the way a user gets one: the checkout's real
# scripts/install.sh runs on the VM from a release-shaped tarball, then the VM's apiserver
# is made reachable from the host and the rig-only add-ons are applied on top.
# Used by run-all.sh --install; nothing here starts a host-side apiserver.
#
# Usage: scripts/conformance/install-bringup.sh --vm <name> --tarball <path under ~>
#          [--port <N>] [--kubelet-port <N>] [--workdir <path>] [--network <name>]
#          [--rust-log <filter>]
#
# Writes <workdir>/kubeconfig (127.0.0.1:<port>, an ssh tunnel to the VM's apiserver, pid in
# <workdir>/install-tunnel.pid) and <workdir>/e2e-ssh/ (key for [Disruptive] specs).
# --rust-log is written as a systemd drop-in for u7s-apiserver before install.sh runs, so
# install.sh itself stays free of any debug hook.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

VM_NAME="${U7S_VM_NAME:-lima-node}"
PORT=6443
KUBELET_PORT=10250
WORKDIR="$PWD/temp/u7s"
NETWORK=""
TARBALL=""
RUST_LOG_FILTER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm) VM_NAME="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --kubelet-port) KUBELET_PORT="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --network) NETWORK="$2"; shift 2 ;;
    --tarball) TARBALL="$2"; shift 2 ;;
    --rust-log) RUST_LOG_FILTER="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done
[ -n "$TARBALL" ] || { echo "error: --tarball is required" >&2; exit 1; }
[ -f "$TARBALL" ] || { echo "error: tarball not found: $TARBALL" >&2; exit 1; }

mkdir -p "$WORKDIR"
WORKDIR="$(cd "$WORKDIR" && pwd)"
KUBECONFIG_PATH="$WORKDIR/kubeconfig"
TUNNEL_PIDFILE="$WORKDIR/install-tunnel.pid"
VM_STATE_DIR=/var/lib/u7s

banner() { echo ""; echo "--- $* ---"; }

NETWORK="${NETWORK:-$(default_network_for_vm "$VM_NAME")}"

# ── VM ───────────────────────────────────────────────────────────────────────
banner "VM: provision or resume $VM_NAME"
VM_DIR="${HOME}/.lima/${VM_NAME}"
if [ -d "$VM_DIR" ]; then
  assert_kubelet_port_matches_vm "$VM_NAME" "$KUBELET_PORT" || exit 1
  if [ "$(limactl list --format '{{.Name}} {{.Status}}' | awk -v n="$VM_NAME" '$1 == n {print $2}')" != "Running" ]; then
    check_port_free "$KUBELET_PORT" "kubelet"
    lima_sync_provision "$VM_NAME" "$REPO/lima/kubelet.yaml"
    limactl start "$VM_NAME"
  fi
else
  check_port_free "$KUBELET_PORT" "kubelet"
  GOLDEN_STATUS=$(limactl list --format '{{.Name}} {{.Status}}' | awk '$1 == "lima-golden" {print $2}')
  if [ "$GOLDEN_STATUS" = "Stopped" ]; then
    limactl clone lima-golden "$VM_NAME" \
      --set ".networks[0].lima = \"${NETWORK}\"" \
      --set ".portForwards[0].hostPort = ${KUBELET_PORT}" \
      --tty=false
    lima_sync_provision "$VM_NAME" "$REPO/lima/kubelet.yaml"
    limactl start --tty=false "$VM_NAME"
  else
    sed -e "s/hostPort: 10250/hostPort: ${KUBELET_PORT}/" \
        -e "s/lima: user-v2/lima: ${NETWORK}/" \
        "$REPO/lima/kubelet.yaml" > "$WORKDIR/kubelet-patched.yaml"
    limactl start --tty=false --timeout 30m --name="$VM_NAME" "$WORKDIR/kubelet-patched.yaml"
  fi
fi

assert_vm_package_pins "$VM_NAME" "$REPO/lima/kubelet.yaml" "$REPO/scripts/lib/release-fetch.sh" || exit 1

if [ -n "$RUST_LOG_FILTER" ]; then
  banner "VM: u7s-apiserver RUST_LOG drop-in (harness-written, not install.sh)"
  limactl shell "$VM_NAME" sudo mkdir -p /etc/systemd/system/u7s-apiserver.service.d
  printf '[Service]\nEnvironment=RUST_LOG=%s\n' "$RUST_LOG_FILTER" \
    | limactl shell "$VM_NAME" sudo tee /etc/systemd/system/u7s-apiserver.service.d/10-conformance-debug.conf >/dev/null
fi

# ── install.sh ───────────────────────────────────────────────────────────────
banner "install.sh --tarball on $VM_NAME"
bash "$DIR/lima-install-test.sh" --vm "$VM_NAME" -- --tarball "$TARBALL" --node-name "$VM_NAME"

# ── kubeconfig + tunnel ──────────────────────────────────────────────────────
banner "Fetch kubeconfig and tunnel the VM apiserver to 127.0.0.1:$PORT"
limactl shell "$VM_NAME" sudo kubectl --kubeconfig="$VM_STATE_DIR/kubeconfig" config view --raw --flatten \
  > "$KUBECONFIG_PATH"
chmod 600 "$KUBECONFIG_PATH"
VM_SERVER=$(kubectl --kubeconfig="$KUBECONFIG_PATH" config view -o jsonpath='{.clusters[0].cluster.server}')
CLUSTER_NAME=$(kubectl --kubeconfig="$KUBECONFIG_PATH" config view -o jsonpath='{.clusters[0].name}')
TUNNEL_TARGET="${VM_SERVER#https://}"
kubectl --kubeconfig="$KUBECONFIG_PATH" config set-cluster "$CLUSTER_NAME" \
  --server="https://127.0.0.1:${PORT}" --tls-server-name=kubernetes >/dev/null

if [ -f "$TUNNEL_PIDFILE" ]; then
  read -r old_pid old_port < "$TUNNEL_PIDFILE" || true
  if is_install_tunnel_pid "$old_pid" "$old_port"; then kill "$old_pid" 2>/dev/null || true; sleep 1; fi
  rm -f "$TUNNEL_PIDFILE"
fi
check_port_free "$PORT" "apiserver"
# ControlPath=none: through Lima's shared mux master the forward would outlive this pid.
nohup ssh -F "$VM_DIR/ssh.config" -o ControlPath=none -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -N \
  -L "127.0.0.1:${PORT}:${TUNNEL_TARGET}" "lima-${VM_NAME}" >"$WORKDIR/install-tunnel.log" 2>&1 &
echo "$! $PORT" > "$TUNNEL_PIDFILE"
for _ in $(seq 1 30); do
  kubectl --kubeconfig="$KUBECONFIG_PATH" get --raw=/healthz >/dev/null 2>&1 && break
  sleep 1
done
kubectl --kubeconfig="$KUBECONFIG_PATH" get --raw=/healthz >/dev/null \
  || { echo "error: apiserver not reachable through the tunnel (see $WORKDIR/install-tunnel.log)" >&2; exit 1; }
kubectl --kubeconfig="$KUBECONFIG_PATH" wait --for=condition=Ready "node/$VM_NAME" --timeout=300s

# ── [Disruptive] ssh key (same credential the host rig provisions) ───────────
SSH_KEY="$(e2e_ssh_key_path "$KUBECONFIG_PATH")"
if [ ! -f "$SSH_KEY" ]; then
  mkdir -p "$(dirname "$SSH_KEY")"
  ssh-keygen -q -t ed25519 -N "" -C "$E2E_SSH_KEY_COMMENT" -f "$SSH_KEY"
fi
limactl shell "$VM_NAME" bash -c "$(authorized_keys_replace_cmd "$(cat "$SSH_KEY.pub")")"

# ── rig-only add-ons ─────────────────────────────────────────────────────────
banner "RIG-ONLY add-ons (NOT shipped by install.sh; labelled $RIG_ONLY_LABEL): $RIG_ONLY_ADDONS"
for addon in ${RIG_ONLY_ADDONS//,/ }; do
  manifest="$REPO/scripts/conformance/manifests/${addon}.yaml"
  kubectl --kubeconfig="$KUBECONFIG_PATH" apply --validate=false -f "$manifest"
  kubectl --kubeconfig="$KUBECONFIG_PATH" label --overwrite -f "$manifest" "$RIG_ONLY_LABEL" >/dev/null
done
kubectl --kubeconfig="$KUBECONFIG_PATH" -n kube-system rollout status ds/kube-network-policies --timeout=180s

banner "RIG-ONLY setup (NOT shipped by install.sh): $RIG_ONLY_SETUP"
rig_apply_apparmor_rig_setup "$VM_NAME"

echo ""
echo "Install-mode stack up: kubectl --kubeconfig $KUBECONFIG_PATH get pods -A"

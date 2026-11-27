#!/usr/bin/env bash
# Brings up a cluster on a Lima VM the way a user gets one: the checkout's real
# scripts/install.sh runs on the VM from a release-shaped tarball, then the VM's apiserver
# is made reachable from the host and the rig-only add-ons are applied on top.
# Used by run-all.sh --install; nothing here starts a host-side apiserver.
#
# Usage: scripts/conformance/install-bringup.sh --vm <name> --tarball <path under ~>
#          [--port <N>] [--kubelet-port <N>] [--workdir <path>] [--network <name>]
#          [--rust-log <filter>] [--extra-node <vm> --extra-kubelet-port <N>]
#          [--wipe-extra-node]
#
# --extra-node joins a 2nd VM through install.sh's own flow: --mint-join-token on the control
# plane, then --join on the extra VM (same network, same tarball). A VM that already joined
# is upgraded in place (install.sh with no --join); --wipe-extra-node instead deletes its
# Node and state and re-joins it, logging the wipe.
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
EXTRA_NODE=""
EXTRA_KUBELET_PORT=""
WIPE_EXTRA_NODE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm) VM_NAME="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --kubelet-port) KUBELET_PORT="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --network) NETWORK="$2"; shift 2 ;;
    --tarball) TARBALL="$2"; shift 2 ;;
    --rust-log) RUST_LOG_FILTER="$2"; shift 2 ;;
    --extra-node) EXTRA_NODE="$2"; shift 2 ;;
    --extra-kubelet-port) EXTRA_KUBELET_PORT="$2"; shift 2 ;;
    --wipe-extra-node) WIPE_EXTRA_NODE=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done
[ -n "$TARBALL" ] || { echo "error: --tarball is required" >&2; exit 1; }
[ -z "$EXTRA_NODE" ] || [ -n "$EXTRA_KUBELET_PORT" ] || { echo "error: --extra-node requires --extra-kubelet-port" >&2; exit 1; }
[ -n "$EXTRA_NODE" ] || [ -z "$EXTRA_KUBELET_PORT" ] || { echo "error: --extra-kubelet-port requires --extra-node" >&2; exit 1; }
[ -f "$TARBALL" ] || { echo "error: tarball not found: $TARBALL" >&2; exit 1; }

mkdir -p "$WORKDIR"
WORKDIR="$(cd "$WORKDIR" && pwd)"
KUBECONFIG_PATH="$WORKDIR/kubeconfig"
TUNNEL_PIDFILE="$WORKDIR/install-tunnel.pid"
VM_STATE_DIR=/var/lib/u7s

banner() { echo ""; echo "--- $* ---"; }

NETWORK="${NETWORK:-$(default_network_for_vm "$VM_NAME")}"

# ── VM ───────────────────────────────────────────────────────────────────────
VM_DIR="${HOME}/.lima/${VM_NAME}"

# Args: <vm> <kubelet host port>. Resumes an existing VM or provisions one on $NETWORK.
provision_vm() {
  local vm="$1" kubelet_port="$2" vm_dir="${HOME}/.lima/$1"
  banner "VM: provision or resume $vm"
  if [ -d "$vm_dir" ]; then
    assert_kubelet_port_matches_vm "$vm" "$kubelet_port" || exit 1
    if [ "$(limactl list --format '{{.Name}} {{.Status}}' | awk -v n="$vm" '$1 == n {print $2}')" != "Running" ]; then
      check_port_free "$kubelet_port" "kubelet"
      lima_sync_provision "$vm" "$REPO/lima/kubelet.yaml"
      limactl start "$vm"
    fi
  else
    check_port_free "$kubelet_port" "kubelet"
    local golden_status
    golden_status=$(limactl list --format '{{.Name}} {{.Status}}' | awk '$1 == "lima-golden" {print $2}')
    if [ "$golden_status" = "Stopped" ]; then
      limactl clone lima-golden "$vm" \
        --set ".networks[0].lima = \"${NETWORK}\"" \
        --set ".portForwards[0].hostPort = ${kubelet_port}" \
        --tty=false
      lima_sync_provision "$vm" "$REPO/lima/kubelet.yaml"
      limactl start --tty=false "$vm"
    else
      sed -e "s/hostPort: 10250/hostPort: ${kubelet_port}/" \
          -e "s/lima: user-v2/lima: ${NETWORK}/" \
          "$REPO/lima/kubelet.yaml" > "$WORKDIR/kubelet-patched-${vm}.yaml"
      limactl start --tty=false --timeout 30m --name="$vm" "$WORKDIR/kubelet-patched-${vm}.yaml"
    fi
  fi
  assert_vm_package_pins "$vm" "$REPO/lima/kubelet.yaml" "$REPO/scripts/lib/release-fetch.sh" || exit 1
}

provision_vm "$VM_NAME" "$KUBELET_PORT"
[ -z "$EXTRA_NODE" ] || provision_vm "$EXTRA_NODE" "$EXTRA_KUBELET_PORT"

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

# ── extra node: install.sh's own join flow ───────────────────────────────────
if [ -n "$EXTRA_NODE" ]; then
  if [ "$WIPE_EXTRA_NODE" = 1 ]; then
    banner "WIPING $EXTRA_NODE (--wipe-extra-node): deleting its Node and $VM_STATE_DIR; the upgrade-in-place path is NOT exercised"
    kubectl --kubeconfig="$KUBECONFIG_PATH" delete "node/$EXTRA_NODE" --ignore-not-found --wait=false
    limactl shell "$EXTRA_NODE" sudo bash -c "systemctl stop kubelet 2>/dev/null || true; rm -rf $VM_STATE_DIR"
  fi
  clear_stale_extra_node_state "$DIR" "$VM_NAME" "$EXTRA_NODE" || exit 1
  if limactl shell "$EXTRA_NODE" sudo test -s "$VM_STATE_DIR/kubeconfig"; then
    banner "install.sh upgrade in place on $EXTRA_NODE (already joined; no token)"
    bash "$DIR/lima-install-test.sh" --vm "$EXTRA_NODE" -- --tarball "$TARBALL" --node-name "$EXTRA_NODE"
    kubectl --kubeconfig="$KUBECONFIG_PATH" wait --for=condition=Ready "node/$EXTRA_NODE" --timeout=300s
  else
    banner "install.sh --mint-join-token on $VM_NAME, then --join on $EXTRA_NODE"
    mint="$(limactl shell "$VM_NAME" sudo bash "$REPO/scripts/install.sh" --mint-join-token)"
    { read -r join_url; read -r join_token; read -r ca_hash; } < <(join_fields_from_mint_output <<<"$mint") \
      || { echo "error: could not parse --mint-join-token output" >&2; exit 1; }
    unset mint
    # The token travels on stdin only, never argv.
    printf '%s\n' "$join_token" | bash "$DIR/lima-install-test.sh" --vm "$EXTRA_NODE" -- \
      --join "$join_url" --token - --ca-cert-hash "$ca_hash" --tarball "$TARBALL" --node-name "$EXTRA_NODE"
    unset join_token
    kubectl --kubeconfig="$KUBECONFIG_PATH" wait --for=condition=Ready "node/$EXTRA_NODE" --timeout=300s
  fi
fi

# ── [Disruptive] ssh key (same credential the host rig provisions) ───────────
SSH_KEY="$(e2e_ssh_key_path "$KUBECONFIG_PATH")"
if [ ! -f "$SSH_KEY" ]; then
  mkdir -p "$(dirname "$SSH_KEY")"
  ssh-keygen -q -t ed25519 -N "" -C "$E2E_SSH_KEY_COMMENT" -f "$SSH_KEY"
fi
for vm in "$VM_NAME" ${EXTRA_NODE:+"$EXTRA_NODE"}; do
  limactl shell "$vm" bash -c "$(authorized_keys_replace_cmd "$(cat "$SSH_KEY.pub")")"
done

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
rig_apply_vm_rig_setup "$VM_NAME"
if [ -n "$EXTRA_NODE" ]; then
  rig_apply_apparmor_rig_setup "$EXTRA_NODE"
  rig_apply_vm_rig_setup "$EXTRA_NODE"
fi

echo ""
echo "Install-mode stack up: kubectl --kubeconfig $KUBECONFIG_PATH get pods -A"

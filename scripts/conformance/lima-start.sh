#!/usr/bin/env bash
# Local E2E setup: u7s on Mac host + kubelet inside lima VM.
#
# Architecture:
#   - u7s runs natively on the Mac (fast cargo rebuild loop)
#   - kubelet + CRI-O run inside the lima VM (Linux kernel required)
#   - kubelet reaches u7s via host.lima.internal:6443
#   - kubectl runs on the Mac against 127.0.0.1:6443
#
# Quick start:
#   1. cargo build --release -p u7s-apiserver
#      scripts/u7s-start.sh       # starts server, prints export KUBECONFIG=...
#
#   2. export KUBECONFIG=./temp/u7s/kubeconfig
#      scripts/lima-start.sh
#
#   3. kubectl get nodes        # lima-node should appear within ~30s
#      kubectl get pods -A
#
# Re-running after u7s restart:
#   Just re-run this script — it rewrites the kubeconfig in the VM and
#   restarts kubelet, so the new TLS cert is picked up automatically.
#
# Troubleshooting:
#   kubelet not registering:
#     limactl shell lima-node sudo journalctl -u kubelet --no-pager -n 50
#   CRI-O issues:
#     limactl shell lima-node sudo journalctl -u crio --no-pager -n 30
#   Container sandbox failures ("unknown version specified"):
#     Two possible causes:
#     1. System crun used instead of CRI-O's bundled one (10-crun.conf drop-in):
#        Fix: limactl shell lima-node sudo rm /etc/crio/crio.conf.d/10-crun.conf
#             limactl shell lima-node sudo systemctl restart crio
#     2. Wrong CNI config format (10-crio-bridge.conf 0.4.0 instead of 1.0.0 conflist):
#        Fix: limactl shell lima-node sudo mv /etc/cni/net.d/10-crio-bridge.conf /etc/cni/net.d/10-crio-bridge.conf.disabled
#             limactl shell lima-node sudo mv /etc/cni/net.d/10-crio-bridge.conflist.disabled /etc/cni/net.d/10-crio-bridge.conflist
#             limactl shell lima-node sudo systemctl restart crio
#     (lima/kubelet.yaml provision now prevents both — delete+reprovision fixes them permanently)
set -euo pipefail

VM_NAME="lima-node"
LIMA_YAML="$(dirname "$0")/../../lima/kubelet.yaml"

check_deps() {
  local missing=0
  for cmd in limactl kubectl; do
    if ! command -v "$cmd" &>/dev/null; then
      echo "error: $cmd not found" >&2
      case "$cmd" in
        limactl) echo "  install: brew install lima" >&2 ;;
        kubectl)  echo "  install: aqua install" >&2 ;;
      esac
      missing=1
    fi
  done
  [ "$missing" -eq 0 ]
}

find_kubeconfig() {
  if [ -n "${KUBECONFIG:-}" ] && [ -f "$KUBECONFIG" ]; then
    echo "$KUBECONFIG"
    return
  fi
  echo "error: KUBECONFIG not set or file not found." >&2
  echo "Start u7s first, then export the path it prints:" >&2
  echo "  scripts/u7s-start.sh" >&2
  echo "  export KUBECONFIG=./temp/u7s/kubeconfig" >&2
  exit 1
}

check_deps

KUBECONFIG_PATH=$(find_kubeconfig)

# Verify u7s is reachable before touching the VM.
if ! kubectl --kubeconfig="$KUBECONFIG_PATH" get namespaces &>/dev/null; then
  echo "error: cannot reach u7s at the server in $KUBECONFIG_PATH" >&2
  echo "Make sure u7s is running on the host first." >&2
  exit 1
fi
echo "u7s is reachable."

# Start or resume the lima VM.
if limactl list --format '{{.Name}}' 2>/dev/null | grep -q "^${VM_NAME}$"; then
  STATUS=$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | awk "/^${VM_NAME} / {print \$2}")
  if [ "$STATUS" != "Running" ]; then
    echo "Starting stopped VM '$VM_NAME'..."
    limactl start "$VM_NAME"
  else
    echo "VM '$VM_NAME' already running."
  fi
else
  echo "Provisioning VM '$VM_NAME' (first run, takes ~5 min)..."
  limactl start --name="$VM_NAME" "$LIMA_YAML"
fi

# Rewrite server address from 127.0.0.1 to host.lima.internal for in-VM use.
echo "Copying kubeconfig into VM..."
REWRITTEN=$(mktemp)
sed 's|https://127.0.0.1:6443|https://host.lima.internal:6443|g' "$KUBECONFIG_PATH" > "$REWRITTEN"
limactl copy "$REWRITTEN" "${VM_NAME}:/tmp/kubelet-kubeconfig"
rm "$REWRITTEN"
limactl shell "$VM_NAME" sudo cp /tmp/kubelet-kubeconfig /etc/kubelet-kubeconfig
limactl shell "$VM_NAME" sudo chmod 600 /etc/kubelet-kubeconfig

# Restart kubelet so it picks up the new kubeconfig/cert.
echo "Starting kubelet inside VM..."
limactl shell "$VM_NAME" sudo systemctl restart kubelet

# Route kubernetes ClusterIP (10.96.0.1:443) to the host apiserver inside the VM.
# Pods use in-cluster config (KUBERNETES_SERVICE_HOST=10.96.0.1) to reach the apiserver.
# Without this rule, 10.96.0.1 traffic has no route in the VM and times out.
echo "Adding iptables DNAT for kubernetes ClusterIP → host apiserver..."
HOST_IP=$(limactl shell "$VM_NAME" getent hosts host.lima.internal 2>/dev/null | awk '{print $1}')
if [ -z "$HOST_IP" ]; then
  echo "WARNING: could not resolve host.lima.internal — skipping DNAT rule" >&2
else
  limactl shell "$VM_NAME" sudo iptables -t nat -D OUTPUT -d 10.96.0.1/32 -p tcp --dport 443 -j DNAT --to-destination "${HOST_IP}:6443" 2>/dev/null || true
  limactl shell "$VM_NAME" sudo iptables -t nat -A OUTPUT -d 10.96.0.1/32 -p tcp --dport 443 -j DNAT --to-destination "${HOST_IP}:6443"
  limactl shell "$VM_NAME" sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
  echo "DNAT rule added: 10.96.0.1:443 → ${HOST_IP}:6443"
fi

# Wait for the node to appear.
echo "Waiting for lima-node to register (up to 60s)..."
FOUND=0
for i in $(seq 1 60); do
  if kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes 2>/dev/null | grep -q "lima-node"; then
    FOUND=1
    break
  fi
  sleep 1
done

if [ "$FOUND" -eq 0 ]; then
  echo "ERROR: lima-node did not appear within 60s." >&2
  echo "--- kubelet log (last 30 lines) ---" >&2
  limactl shell "$VM_NAME" sudo journalctl -u kubelet --no-pager -n 30 >&2
  exit 1
fi

echo ""
echo "Success! Node registered:"
kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes
echo ""
echo "Run kubectl commands with:"
echo "  export KUBECONFIG=$KUBECONFIG_PATH"
echo "  kubectl get nodes"
echo "  kubectl run test --image=busybox:1.36 --restart=Never --overrides='{\"spec\":{\"nodeName\":\"lima-node\",\"hostNetwork\":true,\"dnsPolicy\":\"None\",\"dnsConfig\":{}}}' -- sh -c 'echo hello'"

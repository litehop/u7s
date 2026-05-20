#!/usr/bin/env bash
# Start the lima kubelet VM and join it to u7s running on the Mac host.
#
# Prerequisites:
#   brew install lima
#   u7s must already be running — start it manually first:
#     cargo run --release -p u7s-apiserver -- --db /tmp/u7s.db ...
#
# The script extracts the CA from u7s's kubeconfig, copies it into the VM,
# and starts kubelet. kubectl get nodes should show lima-node within ~90s.
set -euo pipefail

VM_NAME="lima-node"
LIMA_YAML="$(dirname "$0")/../lima/kubelet.yaml"

check_deps() {
  if ! command -v limactl &>/dev/null; then
    echo "error: limactl not found — install with: brew install lima" >&2
    exit 1
  fi
  if ! command -v kubectl &>/dev/null; then
    echo "error: kubectl not found — run: aqua install" >&2
    exit 1
  fi
}

find_kubeconfig() {
  # u7s prints: kubeconfig written to <path>
  # Try common locations the operator might use.
  if [ -n "${KUBECONFIG:-}" ] && [ -f "$KUBECONFIG" ]; then
    echo "$KUBECONFIG"
    return
  fi
  echo "error: KUBECONFIG env var not set or file not found." >&2
  echo "Start u7s and export KUBECONFIG to the path it printed." >&2
  exit 1
}

check_deps

KUBECONFIG_PATH=$(find_kubeconfig)

# Verify u7s is reachable
if ! kubectl --kubeconfig="$KUBECONFIG_PATH" get namespaces &>/dev/null; then
  echo "error: cannot reach u7s at the server in $KUBECONFIG_PATH" >&2
  echo "Make sure u7s is running on the host." >&2
  exit 1
fi

echo "u7s is reachable. Starting lima VM '$VM_NAME'..."

limactl start --name="$VM_NAME" "$LIMA_YAML" || true

echo "Copying kubeconfig into VM (u7s address will be rewritten to host.lima.internal)..."

# Rewrite the server address from 127.0.0.1 to host.lima.internal for in-VM use
REWRITTEN=$(mktemp)
sed 's|https://127.0.0.1:6443|https://host.lima.internal:6443|g' "$KUBECONFIG_PATH" > "$REWRITTEN"
limactl copy "$REWRITTEN" "${VM_NAME}:/tmp/kubelet-kubeconfig"
rm "$REWRITTEN"

limactl shell "$VM_NAME" sudo cp /tmp/kubelet-kubeconfig /etc/kubelet-kubeconfig
limactl shell "$VM_NAME" sudo chmod 600 /etc/kubelet-kubeconfig

echo "Starting kubelet inside VM..."
limactl shell "$VM_NAME" sudo systemctl start kubelet

echo "Waiting for lima-node to register with u7s (up to 90s)..."
FOUND=0
for i in $(seq 1 90); do
  if kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes 2>/dev/null | grep -q "lima-node"; then
    FOUND=1
    break
  fi
  sleep 1
done

if [ "$FOUND" -eq 0 ]; then
  echo "ERROR: lima-node did not appear within 90s." >&2
  echo "--- kubelet log ---" >&2
  limactl shell "$VM_NAME" sudo journalctl -u kubelet --no-pager -n 50 >&2
  exit 1
fi

echo "Success! Node registered:"
kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes

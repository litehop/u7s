#!/usr/bin/env bash
# Reconnect the lima-node kubelet to a (re)started u7s apiserver.
#
# Use this after: cargo build --release && scripts/u7s-start.sh [--reset]
# The VM must already be provisioned. For first-time setup: scripts/conformance/lima-start.sh
#
# What this does (idempotent, safe to re-run):
#   - Copies the new kubeconfig and CA cert into the VM
#   - Rewrites the kubelet drop-in and restarts kubelet
#   - Re-applies the iptables DNAT rule for in-cluster API access
#   - Waits for the node to re-register
#
# Usage:
#   export KUBECONFIG=./temp/u7s/kubeconfig   # set by u7s-start.sh
#   scripts/kubelet-reconnect.sh
set -euo pipefail

VM_NAME="lima-node"

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

# Fail fast if the VM is not already running.
STATUS=$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | awk "/^${VM_NAME} / {print \$2}")
if [ -z "$STATUS" ]; then
  echo "error: VM '$VM_NAME' does not exist." >&2
  echo "Run scripts/conformance/lima-start.sh first to provision the VM." >&2
  exit 1
fi
if [ "$STATUS" != "Running" ]; then
  echo "error: VM '$VM_NAME' is not running (status: $STATUS)." >&2
  echo "Run scripts/conformance/lima-start.sh to start and reconnect it." >&2
  exit 1
fi
echo "VM '$VM_NAME' is running."

# Rewrite server address from 127.0.0.1 to host.lima.internal for in-VM use.
echo "Copying kubeconfig into VM..."
REWRITTEN=$(mktemp)
sed 's|https://127.0.0.1:6443|https://host.lima.internal:6443|g' "$KUBECONFIG_PATH" > "$REWRITTEN"
limactl copy "$REWRITTEN" "${VM_NAME}:/tmp/kubelet-kubeconfig"
rm "$REWRITTEN"
limactl shell "$VM_NAME" sudo cp /tmp/kubelet-kubeconfig /etc/kubelet-kubeconfig
limactl shell "$VM_NAME" sudo chmod 600 /etc/kubelet-kubeconfig

# Copy CA cert (DER→PEM) so kubelet can authenticate the apiserver's mTLS client cert.
CA_CERT="$(dirname "$KUBECONFIG_PATH")/ca.crt"
CA_PEM=$(mktemp)
trap 'rm -f "$CA_PEM"' EXIT
if [ -f "$CA_CERT" ]; then
  openssl x509 -in "$CA_CERT" -inform DER -out "$CA_PEM" -outform PEM
  limactl copy "$CA_PEM" "${VM_NAME}:/tmp/kubelet-ca.crt"
  limactl shell "$VM_NAME" sudo cp /tmp/kubelet-ca.crt /etc/kubelet-ca.crt
  limactl shell "$VM_NAME" sudo chmod 644 /etc/kubelet-ca.crt
  limactl shell "$VM_NAME" sudo bash -c 'mkdir -p /etc/systemd/system/kubelet.service.d && cat > /etc/systemd/system/kubelet.service.d/u7s.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/bin/kubelet \
  --config=/etc/kubelet-config.yaml \
  --kubeconfig=/etc/kubelet-kubeconfig \
  --client-ca-file=/etc/kubelet-ca.crt \
  --hostname-override=lima-node \
  --v=2
EOF'
  limactl shell "$VM_NAME" sudo systemctl daemon-reload
  echo "Kubelet client-ca-file configured."
else
  echo "WARNING: $CA_CERT not found — kubelet client auth will not work (logs/exec will return 401)" >&2
fi

# Restart kubelet so it picks up the new kubeconfig/cert/CA.
echo "Restarting kubelet..."
limactl shell "$VM_NAME" sudo systemctl restart kubelet

# Re-apply iptables DNAT: 10.96.0.1:443 → host apiserver (idempotent delete+add).
echo "Re-applying iptables DNAT for kubernetes ClusterIP → host apiserver..."
HOST_IP=$(limactl shell "$VM_NAME" getent hosts host.lima.internal 2>/dev/null | awk '{print $1}')
if [ -z "$HOST_IP" ]; then
  echo "WARNING: could not resolve host.lima.internal — skipping DNAT rule" >&2
else
  limactl shell "$VM_NAME" sudo iptables -t nat -D OUTPUT -d 10.96.0.1/32 -p tcp --dport 443 -j DNAT --to-destination "${HOST_IP}:6443" 2>/dev/null || true
  limactl shell "$VM_NAME" sudo iptables -t nat -A OUTPUT -d 10.96.0.1/32 -p tcp --dport 443 -j DNAT --to-destination "${HOST_IP}:6443"
  limactl shell "$VM_NAME" sudo iptables -t nat -D PREROUTING -d 10.96.0.1/32 -p tcp --dport 443 -j DNAT --to-destination "${HOST_IP}:6443" 2>/dev/null || true
  limactl shell "$VM_NAME" sudo iptables -t nat -A PREROUTING -d 10.96.0.1/32 -p tcp --dport 443 -j DNAT --to-destination "${HOST_IP}:6443"
  limactl shell "$VM_NAME" sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
  echo "DNAT rule added: 10.96.0.1:443 → ${HOST_IP}:6443 (OUTPUT + PREROUTING)"
fi

# Refresh cert Secret and restart the konnectivity-agent pod so it reconnects with
# new certs to the (re)started server.  The pod runs in kube-system with CoreDNS
# access; deleting it causes Kubernetes to restart it with the updated Secret.
WORKDIR="$(dirname "$KUBECONFIG_PATH")"
if [ -f "$WORKDIR/konnectivity-agent.crt" ] && [ -f "$WORKDIR/ca.pem" ]; then
  kubectl --kubeconfig="$KUBECONFIG_PATH" create secret generic konnectivity-agent-certs \
    --from-file=ca.crt="$WORKDIR/ca.pem" \
    --from-file=tls.crt="$WORKDIR/konnectivity-agent.crt" \
    --from-file=tls.key="$WORKDIR/konnectivity-agent.key" \
    -n kube-system \
    --dry-run=client -o yaml | \
    kubectl --kubeconfig="$KUBECONFIG_PATH" apply --validate=false -f -
  kubectl --kubeconfig="$KUBECONFIG_PATH" delete pod konnectivity-agent -n kube-system --ignore-not-found
  echo "konnectivity-agent pod will restart with fresh certs"
fi

# Restart kube-proxy systemd service with a fresh token so it reconnects to the new apiserver.
WORKDIR="$(dirname "$KUBECONFIG_PATH")"
if [ -f "$WORKDIR/ca.pem" ]; then
  KUBE_PROXY_TOKEN=$(kubectl --kubeconfig="$KUBECONFIG_PATH" create token kube-proxy \
    -n kube-system --duration=8760h 2>/dev/null || echo "")
  if [ -n "$KUBE_PROXY_TOKEN" ]; then
    limactl shell "$VM_NAME" sudo bash -c "cat > /etc/kube-proxy/kubeconfig.conf" <<KUBEEOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://host.lima.internal:6443
    certificate-authority-data: $(base64 < "$WORKDIR/ca.pem" | tr -d '\n')
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
current-context: default
users:
- name: default
  user:
    token: ${KUBE_PROXY_TOKEN}
KUBEEOF
    limactl shell "$VM_NAME" sudo systemctl restart kube-proxy 2>/dev/null || true
    echo "kube-proxy restarted with fresh token"
  else
    echo "WARNING: could not generate kube-proxy token; service not restarted" >&2
  fi
fi

# Wait for the node to re-register.
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

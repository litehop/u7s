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

# For day-to-day iteration after initial VM provisioning, use scripts/kubelet-reconnect.sh
# instead — it skips VM provisioning and just reconnects the kubelet.
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
  limactl start --tty=false --name="$VM_NAME" "$LIMA_YAML"
fi

# Rewrite server address from 127.0.0.1 to host.lima.internal for in-VM use.
echo "Copying kubeconfig into VM..."
REWRITTEN=$(mktemp)
sed 's|https://127.0.0.1:6443|https://host.lima.internal:6443|g' "$KUBECONFIG_PATH" > "$REWRITTEN"
limactl copy "$REWRITTEN" "${VM_NAME}:/tmp/kubelet-kubeconfig"
rm "$REWRITTEN"
limactl shell "$VM_NAME" sudo cp /tmp/kubelet-kubeconfig /etc/kubelet-kubeconfig
limactl shell "$VM_NAME" sudo chmod 600 /etc/kubelet-kubeconfig

# Copy cluster CA so the kubelet can authenticate the apiserver's mTLS client cert
# when proxying log/exec/attach requests. Without --client-ca-file the kubelet falls
# back to webhook auth and rejects the apiserver's cert with 401.
# ca.crt is DER-encoded; kubelet requires PEM.
CA_CERT="$(dirname "$KUBECONFIG_PATH")/ca.crt"
CA_PEM=$(mktemp)
trap 'rm -f "$CA_PEM"' EXIT
if [ -f "$CA_CERT" ]; then
  openssl x509 -in "$CA_CERT" -inform DER -out "$CA_PEM" -outform PEM
  limactl copy "$CA_PEM" "${VM_NAME}:/tmp/kubelet-ca.crt"
  limactl shell "$VM_NAME" sudo cp /tmp/kubelet-ca.crt /etc/kubelet-ca.crt
  limactl shell "$VM_NAME" sudo chmod 644 /etc/kubelet-ca.crt
  # Write --client-ca-file into the kubelet drop-in (idempotent: overwrite each run).
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
echo "Starting kubelet inside VM..."
limactl shell "$VM_NAME" sudo systemctl restart kubelet

# Generate a dedicated client cert for the konnectivity-agent (mTLS with server).
# The server trusts certs signed by the cluster CA; the CA key is only on the Mac host.
WORKDIR="$(dirname "$KUBECONFIG_PATH")"
AGENT_CERT_KEY="$WORKDIR/konnectivity-agent.key"
AGENT_CERT_CRT="$WORKDIR/konnectivity-agent.crt"
AGENT_CERT_CSR="$WORKDIR/konnectivity-agent.csr"
if [ ! -f "$WORKDIR/ca.pem" ]; then
  openssl x509 -in "$WORKDIR/ca.crt" -inform DER -out "$WORKDIR/ca.pem" -outform PEM
fi
if [ ! -f "$AGENT_CERT_KEY" ] || [ ! -f "$AGENT_CERT_CRT" ]; then
  openssl ecparam -genkey -name prime256v1 -noout -out "$AGENT_CERT_KEY"
  openssl req -new -key "$AGENT_CERT_KEY" \
    -subj "/CN=konnectivity-agent" -sha256 \
    -out "$AGENT_CERT_CSR"
  openssl x509 -req -in "$AGENT_CERT_CSR" \
    -CA "$WORKDIR/ca.pem" -CAkey "$WORKDIR/ca.key" \
    -CAcreateserial -CAserial "$WORKDIR/ca.srl" \
    -days 365 -sha256 \
    -out "$AGENT_CERT_CRT"
  rm -f "$AGENT_CERT_CSR"
fi

# Create cert Secret for konnectivity-agent pod so the pod can mount the mTLS certs
# without copying binaries or tokens into the VM host filesystem.
kubectl --kubeconfig="$KUBECONFIG_PATH" create secret generic konnectivity-agent-certs \
  --from-file=ca.crt="$WORKDIR/ca.pem" \
  --from-file=tls.crt="$WORKDIR/konnectivity-agent.crt" \
  --from-file=tls.key="$WORKDIR/konnectivity-agent.key" \
  -n kube-system \
  --dry-run=client -o yaml | \
  kubectl --kubeconfig="$KUBECONFIG_PATH" apply --validate=false -f -

# Resolve the Mac host IP so the agent pod can reach the konnectivity-server.
# CoreDNS inside the pod does not know host.lima.internal; inject it as a hostAlias.
LIMA_HOST_IP=$(limactl shell "$VM_NAME" getent hosts host.lima.internal 2>/dev/null | awk '{print $1}')
LIMA_HOST_IP="${LIMA_HOST_IP:-192.168.5.2}"

# Run the agent as a Pod in kube-system so it uses CoreDNS: service DNS names like
# e2e-test-webhook.webhook-N.svc resolve correctly inside the pod network.
# hostAliases injects host.lima.internal so the pod can dial the Mac-side server.
kubectl --kubeconfig="$KUBECONFIG_PATH" apply --validate=false -f - <<PODEOF
apiVersion: v1
kind: Pod
metadata:
  name: konnectivity-agent
  namespace: kube-system
  labels:
    app: konnectivity-agent
spec:
  nodeName: lima-node
  hostNetwork: false
  restartPolicy: Always
  hostAliases:
  - ip: "$LIMA_HOST_IP"
    hostnames:
    - host.lima.internal
  tolerations:
  - operator: Exists
  containers:
  - name: konnectivity-agent
    image: registry.k8s.io/kas-network-proxy/proxy-agent:v0.35.0
    args:
    - --logtostderr=true
    - --proxy-server-host=host.lima.internal
    - --proxy-server-port=8132
    - --ca-cert=/certs/ca.crt
    - --agent-cert=/certs/tls.crt
    - --agent-key=/certs/tls.key
    - --agent-identifiers=default-route=true
    - --sync-interval=5s
    - --sync-interval-cap=30s
    volumeMounts:
    - name: certs
      mountPath: /certs
      readOnly: true
  volumes:
  - name: certs
    secret:
      secretName: konnectivity-agent-certs
PODEOF

echo "konnectivity-agent pod applied (logs: kubectl logs -n kube-system konnectivity-agent)"

# kube-proxy runs as a systemd service inside the VM using the kube-proxy binary from the
# official container image. This avoids the pod sandbox loop that occurs with hostNetwork
# pods in u7s (strategic-merge-patch accumulation in podIPs causes the kubelet to
# continuously recreate the sandbox). The binary uses IPVS mode because the Lima VM's
# iptables uses nf_tables which lacks the userspace extension library for protocol matching.

# Detect kubelet version to pull the matching kube-proxy binary.
KUBELET_VERSION=$(limactl shell "$VM_NAME" kubelet --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
KUBELET_VERSION="${KUBELET_VERSION:-1.36.1}"

# Create kube-proxy ServiceAccount and RBAC (needed for the kubeconfig token).
kubectl --kubeconfig="$KUBECONFIG_PATH" create serviceaccount kube-proxy -n kube-system \
  --dry-run=client -o yaml | \
  kubectl --kubeconfig="$KUBECONFIG_PATH" apply --validate=false -f -

kubectl --kubeconfig="$KUBECONFIG_PATH" apply --validate=false -f - <<RBACEOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kube-proxy
rules:
- apiGroups: [""]
  resources: [nodes, services, endpoints]
  verbs: [get, list, watch]
- apiGroups: [""]
  resources: [events]
  verbs: [create, patch, update]
- apiGroups: [discovery.k8s.io]
  resources: [endpointslices]
  verbs: [get, list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kube-proxy
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kube-proxy
subjects:
- kind: ServiceAccount
  name: kube-proxy
  namespace: kube-system
RBACEOF

# Generate a long-lived token for kube-proxy to authenticate with u7s.
KUBE_PROXY_TOKEN=$(kubectl --kubeconfig="$KUBECONFIG_PATH" create token kube-proxy \
  -n kube-system --duration=8760h 2>/dev/null || echo "")

# Write config files to the VM filesystem.
limactl shell "$VM_NAME" sudo mkdir -p /etc/kube-proxy
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

limactl shell "$VM_NAME" sudo bash -c 'cat > /etc/kube-proxy/config.conf' <<'CONFEOF'
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs
clusterCIDR: 10.85.0.0/16
clientConnection:
  kubeconfig: /etc/kube-proxy/kubeconfig.conf
CONFEOF

# Extract the kube-proxy binary from the container image if not already present.
# The image is pulled by CRI-O when applying the static pod; we reuse it from the overlay.
if ! limactl shell "$VM_NAME" test -x /usr/local/bin/kube-proxy 2>/dev/null; then
  limactl shell "$VM_NAME" sudo bash -c "
    # Pull image via static pod to populate overlay storage, then copy binary out.
    OVERLAY=\$(find /var/lib/containers/storage/overlay -name 'kube-proxy' -path '*/usr/local/bin/*' 2>/dev/null | head -1)
    if [ -n \"\$OVERLAY\" ]; then
      cp \"\$OVERLAY\" /usr/local/bin/kube-proxy
      chmod +x /usr/local/bin/kube-proxy
      echo 'kube-proxy binary installed from overlay'
    else
      echo 'WARNING: kube-proxy binary not found in overlay; pull the image first' >&2
    fi
  " 2>/dev/null
fi

# If binary is still missing, write a static pod manifest to force CRI-O to pull the image,
# wait for the pull, then extract the binary.
if ! limactl shell "$VM_NAME" test -x /usr/local/bin/kube-proxy 2>/dev/null; then
  echo "Pulling kube-proxy image via static pod (first run)..."
  limactl shell "$VM_NAME" sudo bash -c "cat > /tmp/kubelet-pods/kube-proxy-pull.yaml" <<PULLEOF
apiVersion: v1
kind: Pod
metadata:
  name: kube-proxy-pull
  namespace: kube-system
spec:
  nodeName: lima-node
  hostNetwork: true
  containers:
  - name: kube-proxy
    image: registry.k8s.io/kube-proxy:v${KUBELET_VERSION}
    command: ["/usr/local/bin/kube-proxy", "--version"]
PULLEOF
  # Wait for image pull (up to 120s)
  for i in $(seq 1 24); do
    OVERLAY=$(limactl shell "$VM_NAME" sudo bash -c "find /var/lib/containers/storage/overlay -name 'kube-proxy' -path '*/usr/local/bin/*' 2>/dev/null | head -1" 2>/dev/null)
    if [ -n "$OVERLAY" ]; then
      limactl shell "$VM_NAME" sudo cp "$OVERLAY" /usr/local/bin/kube-proxy
      limactl shell "$VM_NAME" sudo chmod +x /usr/local/bin/kube-proxy
      echo "kube-proxy binary installed"
      break
    fi
    sleep 5
  done
  limactl shell "$VM_NAME" sudo rm -f /tmp/kubelet-pods/kube-proxy-pull.yaml
fi

# Install ipset (required by kube-proxy IPVS mode).
limactl shell "$VM_NAME" sudo apt-get install -y ipset 2>/dev/null | tail -1 || true

# Load IPVS kernel modules.
limactl shell "$VM_NAME" sudo bash -c '
  modprobe ip_vs ip_vs_rr ip_vs_wrr ip_vs_sh 2>/dev/null || true
' 2>/dev/null

# Write the systemd service unit.
limactl shell "$VM_NAME" sudo bash -c 'cat > /etc/systemd/system/kube-proxy.service' <<'SVCEOF'
[Unit]
Description=Kubernetes Kube Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/kube-proxy \
  --config=/etc/kube-proxy/config.conf \
  --hostname-override=lima-node
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SVCEOF

limactl shell "$VM_NAME" sudo systemctl daemon-reload
limactl shell "$VM_NAME" sudo systemctl enable kube-proxy 2>/dev/null
limactl shell "$VM_NAME" sudo systemctl restart kube-proxy

echo "kube-proxy systemd service started (logs: limactl shell lima-node sudo journalctl -u kube-proxy -n 20)"

# Route kubernetes ClusterIP (10.96.0.1:443) to the host apiserver inside the VM.
# Pods use in-cluster config (KUBERNETES_SERVICE_HOST=10.96.0.1) to reach the apiserver.
# Without this rule, 10.96.0.1 traffic has no route in the VM and times out.
echo "Adding iptables DNAT for kubernetes ClusterIP → host apiserver..."
HOST_IP=$(limactl shell "$VM_NAME" getent hosts host.lima.internal 2>/dev/null | awk '{print $1}')
if [ -z "$HOST_IP" ]; then
  echo "WARNING: could not resolve host.lima.internal — skipping DNAT rule" >&2
else
  # OUTPUT: catches traffic from processes on the VM host itself.
  # PREROUTING: catches traffic from containers/pods (their own network namespaces).
  # Both chains are needed so that both kubelet and in-pod API calls are routed correctly.
  limactl shell "$VM_NAME" sudo iptables -t nat -D OUTPUT -d 10.96.0.1/32 -p tcp --dport 443 -j DNAT --to-destination "${HOST_IP}:6443" 2>/dev/null || true
  limactl shell "$VM_NAME" sudo iptables -t nat -A OUTPUT -d 10.96.0.1/32 -p tcp --dport 443 -j DNAT --to-destination "${HOST_IP}:6443"
  limactl shell "$VM_NAME" sudo iptables -t nat -D PREROUTING -d 10.96.0.1/32 -p tcp --dport 443 -j DNAT --to-destination "${HOST_IP}:6443" 2>/dev/null || true
  limactl shell "$VM_NAME" sudo iptables -t nat -A PREROUTING -d 10.96.0.1/32 -p tcp --dport 443 -j DNAT --to-destination "${HOST_IP}:6443"
  limactl shell "$VM_NAME" sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
  echo "DNAT rule added: 10.96.0.1:443 → ${HOST_IP}:6443 (OUTPUT + PREROUTING)"
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

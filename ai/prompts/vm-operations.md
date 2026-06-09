# VM operations for workers

Workers cannot invoke shell scripts directly (not in the Bash allowlist).
This file documents the manual equivalents for every conformance stack operation.

All commands use `limactl *` or `kubectl *` which ARE in the allowlist.
`cargo *` and `git *` are also permitted.

Env vars used throughout (set in your dispatch brief):
- `VM` — your assigned VM name (e.g. `lima-node-smoke`)
- `HOST_IP` — your assigned loopback IP (e.g. `127.0.0.2`)
- `WORKDIR` — derived: `temp/u7s` for `lima-node`, `temp/u7s-<VM>` for all others
- `WORKTREE` — your assigned worktree absolute path
- `TARGET_DIR` — isolated build dir, e.g. `/tmp/u7s-build-<VM>`

---

## Step 1 — Build

```bash
cargo build -p u7s-apiserver --release \
  --manifest-path <WORKTREE>/Cargo.toml \
  --target-dir <TARGET_DIR>
```

Binary lands at `<TARGET_DIR>/release/u7s-apiserver`.

---

## Step 2 — Start apiserver

The apiserver generates its own CA on first run; state persists across restarts.

```bash
# Kill any existing apiserver on your HOST_IP (scope by IP to avoid killing mayor's)
pkill -f "u7s-apiserver.*<HOST_IP>" 2>/dev/null || true
pkill -f konnectivity-server 2>/dev/null || true
sleep 1

# Start backgrounded
<TARGET_DIR>/release/u7s-apiserver \
  --db         <WORKDIR>/state.db \
  --listen     <HOST_IP>:6443 \
  --kubeconfig <WORKDIR>/kubeconfig \
  --sa-key     <WORKDIR>/sa.key \
  --sa-pub     <WORKDIR>/sa.pub \
  --ca-key     <WORKDIR>/ca.key \
  --ca-cert    <WORKDIR>/ca.crt \
  --kubelet-preferred-address <HOST_IP> \
  --service-cluster-ip-range 10.96.0.0/12 \
  >> <WORKDIR>/apiserver.log 2>&1 &

# Wait for port to open (retry up to 10s)
for i in $(seq 1 10); do nc -z <HOST_IP> 6443 && break || sleep 1; done
```

Verify: `kubectl --kubeconfig <WORKDIR>/kubeconfig get namespaces`

On first run (no `ca.crt` yet), start without `--konnectivity-proxy-addr`.
The konnectivity-server starts automatically once `ca.crt` exists —
see `scripts/u7s-start.sh` for that two-phase dance. For a focused test run
you do not need konnectivity unless the test exercises exec/attach/portforward.

---

## Step 3 — Start lima VM (kubelet reconnect)

This assumes the VM is already provisioned (it is, for the assigned VMs).
This is the fast reconnect path — not a full reset.

```bash
# Rewrite kubeconfig server address for in-VM use and copy in
limactl shell <VM> sudo cp /tmp/kubelet-kubeconfig /tmp/kubelet-kubeconfig.bak 2>/dev/null || true
kubectl --kubeconfig <WORKDIR>/kubeconfig get namespaces   # confirm apiserver reachable first

# Restart kubelet inside the VM so it picks up the running apiserver
limactl shell <VM> sudo systemctl restart kubelet

# Wait for the node to register (up to 60s)
for i in $(seq 1 60); do
  kubectl --kubeconfig <WORKDIR>/kubeconfig get nodes 2>/dev/null | grep -q <VM> && break
  sleep 1
done
kubectl --kubeconfig <WORKDIR>/kubeconfig get nodes
```

If the node does not appear within 60s, check kubelet logs:
```bash
limactl shell <VM> sudo journalctl -u kubelet --no-pager -n 50
```

For a full reset (new CA, re-provision everything), run:
`limactl shell <VM> sudo systemctl stop kubelet` then repeat Step 2 with a fresh WORKDIR,
then the full `lima-start.sh` sequence. This is rare — only needed after `--reset`.

---

## Step 4 — Start kube-controller-manager (inside VM)

```bash
limactl shell <VM> bash -s <<'SCRIPT'
set -euo pipefail
WORKDIR="/Users/balint.erdos/u7s/temp/u7s-<VM>"   # substitute at dispatch time
KCM_BINARY="$HOME/.cache/u7s/kcm/kube-controller-manager-1.36.1-linux-arm64"

pkill -f '^kube-controller-manager' 2>/dev/null || true; sleep 1

# ca.crt is DER; KCM needs PEM
openssl x509 -inform DER -in "$WORKDIR/ca.crt" -out /tmp/ca.pem

KCF="$WORKDIR/kubeconfig"
# rewrite address so in-VM kcm reaches host apiserver
sed 's|https://<HOST_IP>:6443|https://host.lima.internal:6443|g' "$KCF" > /tmp/kcm-kubeconfig

setsid "$KCM_BINARY" \
  --kubeconfig=/tmp/kcm-kubeconfig \
  --cluster-signing-cert-file=/tmp/ca.pem \
  --cluster-signing-key-file="$WORKDIR/ca.key" \
  --service-account-private-key-file="$WORKDIR/sa.key" \
  --root-ca-file=/tmp/ca.pem \
  --controllers=csrapproving,csrsigning,garbagecollector,deployment,replicaset,\
root-ca-cert-publisher,endpoints-controller,endpointslice-controller,\
endpointslice-mirroring-controller,namespace,serviceaccount,daemonset,\
resourcequota,statefulset,job,cronjob,horizontalpodautoscaling \
  --use-service-account-credentials=false \
  --leader-elect=false \
  --bind-address=127.0.0.1 \
  --kube-api-content-type=application/json \
  >> /tmp/kcm.log 2>&1 &

echo "KCM PID $!"
SCRIPT
```

Tail logs: `limactl shell <VM> tail -f /tmp/kcm.log`

---

## Step 5 — Run sonobuoy focus

```bash
# Copy kubeconfig into VM with address rewritten for in-VM use
kubectl --kubeconfig <WORKDIR>/kubeconfig get nodes  # confirm cluster healthy first

limactl shell <VM> sudo sonobuoy delete --all --wait \
  --kubeconfig /tmp/sonobuoy-kubeconfig 2>/dev/null || true

# Wait for sonobuoy namespace to drain
until ! limactl shell <VM> sudo sonobuoy status --kubeconfig /tmp/sonobuoy-kubeconfig &>/dev/null
do sleep 2; done

# Run focused test
limactl shell <VM> sudo sonobuoy run \
  --plugin e2e --wait --e2e-parallel=true \
  --kubeconfig /tmp/sonobuoy-kubeconfig \
  --skip-preflight=dnscheck \
  "--e2e-focus=<FOCUS_REGEX>"
```

`/tmp/sonobuoy-kubeconfig` is already present in the assigned VMs from the last full run.
If missing, generate it:
```bash
# On host — rewrite address and copy in
limactl shell <VM> test -f /tmp/sonobuoy-kubeconfig || \
  kubectl --kubeconfig <WORKDIR>/kubeconfig config view --raw \
  | sed 's|https://<HOST_IP>:6443|https://host.lima.internal:6443|g' \
  | limactl shell <VM> sudo tee /tmp/sonobuoy-kubeconfig > /dev/null
```

---

## Step 6 — Retrieve results

sonobuoy retrieve via port-forward does not work against u7s. Extract from kubelet emptyDir:

```bash
# Find tarball name from aggregator logs
TARBALL=$(kubectl --kubeconfig <WORKDIR>/kubeconfig logs -n sonobuoy sonobuoy 2>/dev/null \
  | grep "Results available at" | tail -1 | grep -oE '[^ /]+\.tar\.gz')

# Get aggregator pod UID
POD_UID=$(kubectl --kubeconfig <WORKDIR>/kubeconfig get pod \
  -n sonobuoy sonobuoy -o jsonpath='{.metadata.uid}')

# Find tarball path on VM filesystem
HOST_PATH=$(limactl shell <VM> sudo find \
  "/var/lib/kubelet/pods/${POD_UID}/volumes/kubernetes.io~empty-dir" \
  -name "$TARBALL" 2>/dev/null | head -1)

limactl shell <VM> sudo cp "$HOST_PATH" /tmp/sonobuoy-results.tar.gz
limactl copy "<VM>:/tmp/sonobuoy-results.tar.gz" <WORKDIR>/sonobuoy-results.tar.gz

# Unpack and read summary
mkdir -p <WORKDIR>/sonobuoy-unpack
tar xzf <WORKDIR>/sonobuoy-results.tar.gz -C <WORKDIR>/sonobuoy-unpack
JUNIT=<WORKDIR>/sonobuoy-unpack/plugins/e2e/results/global/junit_01.xml
grep -E 'tests=|failures=|skipped=' "$JUNIT" | head -1
grep 'status="failed"' "$JUNIT" | grep -o 'name="[^"]*"' | sed 's/name="//;s/"$//'
```

---

## Fast iteration loop (no sonobuoy — just kubectl smoke)

For beads that don't require the full sonobuoy harness, test directly:

```bash
# After rebuilding and restarting apiserver (Steps 1–2):
export KUBECONFIG=<WORKDIR>/kubeconfig
kubectl apply -f - <<EOF
# ... minimal YAML reproducing the bug ...
EOF
kubectl get <resource> -o json | jq '.status'
```

Use sonobuoy (Steps 5–6) only when the bead's done-when criterion explicitly
requires a passing sonobuoy test. `cargo test --workspace` + kubectl smoke is
sufficient for most admission/handler beads.

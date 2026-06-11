# VM operations for workers

Workers run the conformance scripts directly — do NOT manually replicate what the
scripts do. The scripts are the source of truth; manual equivalents drift.

Workers are launched with the **repo root as CWD** (`/Users/balint.erdos/u7s`).
The worktree is a separate directory. All state (kubeconfig, CA, DB) goes under
the worktree's own `temp/` so parallel workers never collide.

## Variables to substitute (per dispatch brief)

- `<WORKTREE>` — your assigned worktree absolute path, e.g.
  `/Users/balint.erdos/u7s/ai/worktrees/w5fd-scale-diag`
- `<VM>` — your assigned Lima VM name, e.g. `lima-node-2`
- `<IP>` — your assigned loopback IP, e.g. `127.0.0.2`
- `<WORKDIR>` — `<WORKTREE>/temp/u7s` (create with `mkdir -p <WORKTREE>/temp/u7s`)

**Networking note**: your apiserver binds to `<IP>:6443` (host loopback). Inside
the Lima VM the host is reachable at `host.lima.internal` (QEMU NAT gateway) — NOT
`<IP>`. The scripts handle this rewrite automatically.

---

## Step 1 — Build

Build from the worktree's `Cargo.toml` into the worktree's own `target/`:

```bash
cargo build -p u7s-apiserver --release \
  --manifest-path <WORKTREE>/Cargo.toml \
  --target-dir    <WORKTREE>/target
```

Binary: `<WORKTREE>/target/release/u7s-apiserver`. The worktree `target/` is gitignored.

---

## Step 2 — Start apiserver

```bash
mkdir -p <WORKTREE>/temp/u7s

scripts/u7s-start.sh \
  --vm      <VM> \
  --ip      <IP> \
  --binary  <WORKTREE>/target/release/u7s-apiserver \
  --workdir <WORKTREE>/temp/u7s \
  --background

# Kubeconfig written to --workdir:
kubectl --kubeconfig <WORKTREE>/temp/u7s/kubeconfig get namespaces
```

`u7s-start.sh` generates the CA, writes kubeconfig (with `<IP>` as the server
address), and starts konnectivity-server. To start fully fresh:
```bash
rm -rf <WORKTREE>/temp/u7s && mkdir -p <WORKTREE>/temp/u7s
```

---

## Step 3 — Connect kubelet

```bash
scripts/conformance/lima-start.sh \
  --vm      <VM> \
  --workdir <WORKTREE>/temp/u7s
```

This provisions the VM (if needed) or reconnects the kubelet. Handles:
- Rewriting `<IP>` → `host.lima.internal` in the kubelet kubeconfig
- Kubelet serving cert signed by the cluster CA
- konnectivity-agent pod (mTLS)
- kube-proxy systemd service (IPVS)
- iptables DNAT for ClusterIP `10.96.0.1:443` → host apiserver

Wait for node Ready (up to 60s):
```bash
kubectl --kubeconfig <WORKTREE>/temp/u7s/kubeconfig get nodes
# <VM> should appear as Ready
```

If the node does not register:
```bash
limactl shell <VM> sudo journalctl -u kubelet --no-pager -n 30
```

---

## Step 4 — Start KCM

```bash
scripts/conformance/04-start-kcm.sh \
  --vm      <VM> \
  --workdir <WORKTREE>/temp/u7s
```

Downloads KCM binary if needed (cached at `~/.cache/u7s/kcm/`).

Verify:
```bash
limactl shell <VM> pgrep -a kube-controller-manager
limactl shell <VM> tail -5 /tmp/kcm.log
```

---

## Step 5 — Verify cluster health

```bash
KCF=<WORKTREE>/temp/u7s/kubeconfig
kubectl --kubeconfig "$KCF" get nodes          # <VM> Ready
kubectl --kubeconfig "$KCF" get pods -A        # konnectivity-agent Running
limactl shell <VM> pgrep -a kube-controller    # KCM alive
```

---

## Step 6 — Fast kubectl iteration (no sonobuoy)

```bash
KCF=<WORKTREE>/temp/u7s/kubeconfig

kubectl --kubeconfig "$KCF" apply -f - <<'EOF'
# ... minimal YAML reproducing the bug ...
EOF

kubectl --kubeconfig "$KCF" get pods -w --request-timeout=60s
```

Use sonobuoy only when the bead's done-when criterion explicitly requires it.

---

## Logs

| Component           | Where                                                          |
|---------------------|----------------------------------------------------------------|
| apiserver           | `<WORKTREE>/temp/u7s/apiserver.log`                           |
| konnectivity-server | `<WORKTREE>/temp/u7s/konnectivity-server.log`                 |
| KCM                 | `limactl shell <VM> tail -f /tmp/kcm.log`                     |
| kubelet             | `limactl shell <VM> sudo journalctl -u kubelet -n 50`         |
| konnectivity-agent  | `kubectl --kubeconfig <WORKTREE>/temp/u7s/kubeconfig logs -n kube-system konnectivity-agent` |

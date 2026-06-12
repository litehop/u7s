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
- `<PORT>` — your assigned host port, e.g. `6444` (mayor owns `6443`)
- `<WORKDIR>` — `<WORKTREE>/temp/u7s` (create with `mkdir -p <WORKTREE>/temp/u7s`)

**Networking note**: all apiservers bind to `127.0.0.1:<PORT>` (host loopback). Port
is the isolation boundary between parallel workers — different loopback IPs are NOT
reliably reachable from inside Lima VMs via `host.lima.internal`. Inside the Lima VM
the host is reachable at `host.lima.internal` (QEMU NAT gateway). The scripts handle
the address rewrite automatically when given `--port <PORT>`.

---

## Primary path — use run-all.sh

For full stack bringup (build + apiserver + kubelet + KCM + sonobuoy), use `run-all.sh`.

**First run in a fresh worktree — always pass `--reset`.**
The VM may have stale state from its previous owner (old certs, stale processes, leftover kubeconfig). `--reset` wipes the worktree's `temp/u7s/`, kills any process on `<PORT>`, kills in-VM processes, and deletes+reprovisions the VM.

```bash
scripts/conformance/run-all.sh \
  --vm      <VM> \
  --port    <PORT> \
  --workdir <WORKTREE>/temp/u7s \
  --reset \
  --focus   "<regex>"
```

**Subsequent runs in the same worktree — omit `--reset`.**
The CA, kubeconfig, and VM are already set up. Omitting `--reset` reuses them, which is faster and avoids unnecessary re-provisioning.

```bash
scripts/conformance/run-all.sh \
  --vm      <VM> \
  --port    <PORT> \
  --workdir <WORKTREE>/temp/u7s \
  --focus   "<regex>"
```

`run-all.sh` handles build, CA generation, kubeconfig, all component starts, and sonobuoy in one invocation. It is whitelisted. Do NOT replicate its steps manually unless you need a partial restart (see individual steps below).

To build first from the worktree and then run:
```bash
cargo build -p u7s-apiserver --release \
  --manifest-path <WORKTREE>/Cargo.toml \
  --target-dir    <WORKTREE>/target

scripts/conformance/run-all.sh \
  --vm      <VM> \
  --port    <PORT> \
  --binary  <WORKTREE>/target/release/u7s-apiserver \
  --workdir <WORKTREE>/temp/u7s \
  --reset \
  --focus   "<regex>"
```

---

## Step 1 — Build (individual, for partial restarts only)

Build from the worktree's `Cargo.toml` into the worktree's own `target/`:

```bash
cargo build -p u7s-apiserver --release \
  --manifest-path <WORKTREE>/Cargo.toml \
  --target-dir    <WORKTREE>/target
```

Binary: `<WORKTREE>/target/release/u7s-apiserver`. The worktree `target/` is gitignored.

---

## Step 2 — Start apiserver (individual, for partial restarts only)

```bash
mkdir -p <WORKTREE>/temp/u7s

scripts/u7s-start.sh \
  --vm      <VM> \
  --port    <PORT> \
  --binary  <WORKTREE>/target/release/u7s-apiserver \
  --workdir <WORKTREE>/temp/u7s \
  --background

# Kubeconfig written to --workdir:
kubectl --kubeconfig <WORKTREE>/temp/u7s/kubeconfig get namespaces
```

`u7s-start.sh` generates the CA, writes kubeconfig (with `127.0.0.1:<PORT>` as the
server address), and starts konnectivity-server. To start fully fresh:
```bash
rm -rf <WORKTREE>/temp/u7s && mkdir -p <WORKTREE>/temp/u7s
```

---

## Step 3 — Connect kubelet

```bash
scripts/conformance/lima-start.sh \
  --vm      <VM> \
  --port    <PORT> \
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
  --port    <PORT> \
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

# VM operations for workers

Workers run the conformance scripts directly — do NOT manually replicate what the
scripts do. The scripts are the source of truth; manual equivalents drift.

Workers are launched with the **worktree root as CWD** (set automatically by
`isolation="worktree"` in the Agent call). All state (kubeconfig, CA, DB) goes under
the worktree's own `temp/` so parallel workers never collide. Scripts
(`scripts/conformance/run-all.sh` etc.) are present in every worktree — always invoke
them with relative paths (e.g. `scripts/conformance/run-all.sh`) from the worktree CWD.
Never use absolute paths; they break the permission allowlist and are not portable across machines.

## Variables to substitute (per dispatch brief)

- `<VM>` — your assigned Lima VM name, e.g. `lima-node-2`
- `<PORT>` — your assigned host port, e.g. `6444` (mayor owns `6443`)
- `<FOCUS>` — sonobuoy test filter regex, e.g. `AdmissionWebhook`

**Networking note**: all apiservers bind to `127.0.0.1:<PORT>` (host loopback). Port
is the isolation boundary between parallel workers — different loopback IPs are NOT
reliably reachable from inside Lima VMs via `host.lima.internal`. Inside the Lima VM
the host is reachable at `host.lima.internal` (QEMU NAT gateway). The scripts handle
the address rewrite automatically when given `--port <PORT>`.

---

## Primary path — use run-all.sh

For full stack bringup (build + apiserver + kubelet + KCM + sonobuoy), use `run-all.sh`.
Your CWD is the worktree root. `--workdir` defaults to `$PWD/temp/u7s` — omit it entirely.

**First run — pass `--reset`.**
`--reset` wipes `temp/u7s/`, kills any process on `<PORT>`, kills in-VM processes, and
deletes+reprovisions the VM. Required when the VM may have stale state from a previous
owner. Takes longer due to VM reprovisioning.

```bash
scripts/conformance/run-all.sh \
  --vm    <VM> \
  --port  <PORT> \
  --reset \
  --focus "<FOCUS>"
```

**Subsequent runs — omit `--reset`.**
Reuses the existing CA, kubeconfig, and VM — significantly faster.

```bash
scripts/conformance/run-all.sh \
  --vm    <VM> \
  --port  <PORT> \
  --focus "<FOCUS>"
```

`run-all.sh` handles build, CA generation, kubeconfig, all component starts, and sonobuoy
in one invocation. It is allowlisted. Do NOT replicate its steps manually unless you need
a partial restart (see individual steps below).

To build first from the worktree and then run:
```bash
cargo build -p u7s-apiserver --release \
  --manifest-path Cargo.toml \
  --target-dir    target

scripts/conformance/run-all.sh \
  --vm     <VM> \
  --port   <PORT> \
  --binary target/release/u7s-apiserver \
  --reset \
  --focus  "<FOCUS>"
```

---

## Step 1 — Build (individual, for partial restarts only)

Build from the worktree's `Cargo.toml` into the worktree's own `target/`:

```bash
cargo build -p u7s-apiserver --release \
  --manifest-path Cargo.toml \
  --target-dir    target
```

Binary: `target/release/u7s-apiserver`. The worktree `target/` is gitignored.

---

## Step 2 — Start apiserver (individual, for partial restarts only)

```bash
scripts/u7s-start.sh \
  --vm     <VM> \
  --port   <PORT> \
  --binary target/release/u7s-apiserver \
  --background

# Kubeconfig written to temp/u7s/ (default):
kubectl --kubeconfig temp/u7s/kubeconfig get namespaces
```

`u7s-start.sh` generates the CA, writes kubeconfig (with `127.0.0.1:<PORT>` as the
server address), and starts konnectivity-server. To start fully fresh, delete `temp/u7s/`.

---

## Step 3 — Connect kubelet

```bash
scripts/conformance/lima-start.sh \
  --vm   <VM> \
  --port <PORT>
```

This provisions the VM (if needed) or reconnects the kubelet. Handles:
- Rewriting `<IP>` → `host.lima.internal` in the kubelet kubeconfig
- Kubelet serving cert signed by the cluster CA
- konnectivity-agent pod (mTLS)
- kube-proxy systemd service (IPVS)
- iptables DNAT for ClusterIP `10.96.0.1:443` → host apiserver

Wait for node Ready (up to 60s):
```bash
kubectl --kubeconfig temp/u7s/kubeconfig get nodes
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
  --vm   <VM> \
  --port <PORT>
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
KCF=temp/u7s/kubeconfig
kubectl --kubeconfig "$KCF" get nodes          # <VM> Ready
kubectl --kubeconfig "$KCF" get pods -A        # konnectivity-agent Running
limactl shell <VM> pgrep -a kube-controller    # KCM alive
```

---

## Step 6 — Fast kubectl iteration (no sonobuoy)

```bash
KCF=temp/u7s/kubeconfig

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
| apiserver           | `temp/u7s/apiserver.log`                           |
| konnectivity-server | `temp/u7s/konnectivity-server.log`                 |
| KCM                 | `limactl shell <VM> tail -f /tmp/kcm.log`                     |
| kubelet             | `limactl shell <VM> sudo journalctl -u kubelet -n 50`         |
| konnectivity-agent  | `kubectl --kubeconfig temp/u7s/kubeconfig logs -n kube-system konnectivity-agent` |

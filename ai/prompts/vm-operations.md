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
- `<KUBELET_PORT>` — your assigned kubelet host port, e.g. `10251` (mayor owns `10250`)
- `<FOCUS>` — sonobuoy test filter regex, e.g. `AdmissionWebhook`

**Networking note**: all apiservers bind to `127.0.0.1:<PORT>` (host loopback). Port
is the isolation boundary between parallel workers — different loopback IPs are NOT
reliably reachable from inside Lima VMs via `host.lima.internal`. Inside the Lima VM
the host is reachable at `host.lima.internal` (QEMU NAT gateway). The scripts handle
the address rewrite automatically when given `--port <PORT>`.

`<KUBELET_PORT>` is the host-side port-forward for the kubelet's guest port 10250.
Each worker VM forwards to a different host port so parallel log/exec/attach requests
don't collide. Always pass `--kubelet-port <KUBELET_PORT>` to `run-all.sh` and
`u7s-start.sh`. Provision the VM with its kubelet port before the first run:
```bash
scripts/worker-vm.sh start <VM> 127.0.0.1 <KUBELET_PORT>
```

---

## Primary path — use run-all.sh

For full stack bringup (build + apiserver + kubelet + KCM + sonobuoy), use `run-all.sh`.
Your CWD is the worktree root. `--workdir` defaults to `$PWD/temp/u7s` — omit it entirely.

**WARNING: bare `run-all.sh` (no `--focus`, no `--stack-only`) runs the FULL conformance
suite, which takes ~6h at current state. Always use `--focus` or `--stack-only` unless
you intend a full run.**

**First run — pass `--reset`.**
`--reset` wipes `temp/u7s/`, kills any process on `<PORT>`, kills in-VM processes, and
deletes+reprovisions the VM. Required when the VM may have stale state from a previous
owner. Takes longer due to VM reprovisioning.

```bash
scripts/conformance/run-all.sh \
  --vm           <VM> \
  --port         <PORT> \
  --kubelet-port <KUBELET_PORT> \
  --reset \
  --focus "<FOCUS>"
```

**Subsequent runs — omit `--reset`.**
Reuses the existing CA, kubeconfig, and VM — significantly faster.

```bash
scripts/conformance/run-all.sh \
  --vm           <VM> \
  --port         <PORT> \
  --kubelet-port <KUBELET_PORT> \
  --focus "<FOCUS>"
```

`run-all.sh` handles build, CA generation, kubeconfig, all component starts, and sonobuoy
in one invocation. It is allowlisted. Do NOT replicate its steps manually unless you need
a partial restart (see individual steps below).

**Omit `--binary` and run-all.sh builds your worktree for you** — you do NOT need a
separate `cargo build`. Add `--verbose` when you need debug-level apiserver logs
(it sets `RUST_LOG=debug` correctly inside the script — never `export RUST_LOG=`
or prefix it inline). Other flags as needed: `--reset`, `--focus "<FOCUS>"`.

Common command forms (copy the EXACT relative form — the allowlist is
`Bash(scripts/conformance/run-all.sh *)`; never prefix with `bash`, never with a
`VAR=...` assignment, never an absolute path):
```bash
# first run (builds worktree, resets stale VM state, debug logs):
scripts/conformance/run-all.sh --reset --verbose --vm <VM> --port <PORT> --kubelet-port <KUBELET_PORT> --focus "<FOCUS>"

# subsequent runs (reuse VM/CA/kubeconfig — faster):
scripts/conformance/run-all.sh --vm <VM> --port <PORT> --kubelet-port <KUBELET_PORT> --focus "<FOCUS>"
```

Only pass `--binary <path>` if you deliberately want to skip the build and run a
pre-built binary; for normal worktree iteration, omit it.

---

## Stack-only mode — live stack without sonobuoy

Use `--stack-only` to bring up steps 1–5 (build, apiserver, kubelet, KCM, scheduler)
and then stop, leaving the stack running for kubectl or direct-DB investigation. Step 6
(sonobuoy) is skipped entirely — no sonobuoy pod is launched.

This is the correct tool when you want to inspect cluster state, run kubectl commands
manually, or debug the API surface without waiting for sonobuoy. It avoids accidentally
triggering the full ~6h suite.

```bash
# first time (reset + stack-only):
scripts/conformance/run-all.sh \
  --vm           <VM> \
  --port         <PORT> \
  --kubelet-port <KUBELET_PORT> \
  --reset \
  --stack-only

# subsequent (reuse stack):
scripts/conformance/run-all.sh \
  --vm           <VM> \
  --port         <PORT> \
  --kubelet-port <KUBELET_PORT> \
  --stack-only
```

After the run completes, the stack is accessible:
```bash
kubectl --kubeconfig temp/u7s/kubeconfig get nodes
kubectl --kubeconfig temp/u7s/kubeconfig get pods -A
```

If `--focus` and `--stack-only` are both passed, `--focus` is ignored (warning printed to
stderr) and the stack is brought up without sonobuoy.

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
  --vm           <VM> \
  --port         <PORT> \
  --kubelet-port <KUBELET_PORT> \
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
  --vm           <VM> \
  --port         <PORT> \
  --kubelet-port <KUBELET_PORT>
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

## Step 6 — Fast kubectl iteration (DIAGNOSE HERE, not on sonobuoy)

This is where you spend almost all diagnostic time. A `sonobuoy --focus` run is
5+ min and can hang to 20 (watchdog reaps the test namespace at 5 min, ginkgo
then flails against the dead namespace). kubectl answers the same question in
seconds. Read the failing test's source (`test/e2e/...`) to learn its exact API
sequence, then reproduce it here.

```bash
kubectl --kubeconfig temp/u7s/kubeconfig apply -f - <<'EOF'
# ... minimal YAML reproducing what the test does ...
EOF

kubectl --kubeconfig temp/u7s/kubeconfig get pods -w --request-timeout=60s
# inspect exact state: get -o yaml / -o jsonpath; check GC by deleting and watching
# check controller behaviour (Job/GC/SA/endpoint controllers live in KCM):
limactl shell <VM> sudo tail -50 /tmp/kcm.log     # rv mismatch, nil panics, sync errors
```

Run sonobuoy ONLY as the final pass/fail gate, after kubectl confirms the fix.
When you do, read the result from
`temp/e2e/<run>/podlogs/sonobuoy/<...>/logs/e2e.txt` (the full test timeline) —
NOT `plugins/e2e/results/global/e2e.log`, which omits the test body.

---

## Logs

| Component           | Where                                                          |
|---------------------|----------------------------------------------------------------|
| apiserver           | `temp/u7s/apiserver.log`                           |
| konnectivity-server | `temp/u7s/konnectivity-server.log`                 |
| KCM                 | `limactl shell <VM> tail -f /tmp/kcm.log`                     |
| kubelet             | `limactl shell <VM> sudo journalctl -u kubelet -n 50`         |
| konnectivity-agent  | `kubectl --kubeconfig temp/u7s/kubeconfig logs -n kube-system konnectivity-agent` |

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
seconds. Read the failing test's source to learn its exact API sequence, then
reproduce it here.

### Upstream source — three rules

Upstream Kubernetes source (e2e test bodies, controllers, API types) is NOT in
this repo. When you need it:

1. **Stay inside the repo.** Never `find /`, never read or write outside the
   worktree, never stash upstream source in `/tmp`. The only place upstream
   source belongs is `temp/research/` (see rule 2).
2. **`temp/research/` is the upstream cache** (gitignored). Read from it, and
   write any upstream file you fetch INTO it — never elsewhere. It is not
   present in fresh worker worktrees (gitignored → not checked out); if you are
   a worker and need a file that lives in the mayor's `temp/research/`, ask the
   mayor to copy it into your worktree rather than fetching your own divergent
   copy or reaching into the mayor checkout.
3. **Pin to the latest Kubernetes version: `1.36.2`** (as of 2026-07). Use
   branch `release-1.36` for raw GitHub fetches and reference 1.36.2 API/test
   semantics — not an older minor. Only deviate if a run's `serverversion.json`
   explicitly shows a different client version for that specific run.

### Locating the failing test's source (do NOT hunt for it)

Do NOT search the sonobuoy archive, `temp/e2e/`, or the workspace for the test
body — the e2e test source is upstream Go, not in this repo or the run archive.
Two places only, in this order:

1. **`temp/research/` first** (gitignored; already holds curated upstream k8s
   source — test bodies like `statefulset_e2e.go` / `webhook-test.go`, plus
   controllers like `kcm_job_controller.go`). `ls temp/research/` and grep it for
   the test name or a distinctive assertion string. If the file is there, Read it.
2. **Otherwise fetch it from GitHub** with the `WebFetch` tool against the raw
   URL, and save it into `temp/research/`. The failure line in `e2e.txt` names
   the file+line, e.g. `k8s.io/kubernetes/test/e2e/node/pods.go:530` →
   `https://raw.githubusercontent.com/kubernetes/kubernetes/release-1.36/test/e2e/node/pods.go`
   (pin the branch to `release-1.36` per the version rule above; check
   `serverversion.json` in the run dir only if you suspect that run used a
   different client). Read the function around the cited line to get the exact
   create→update→assert sequence.

Never reconstruct the test from the failure message alone — the assertion text
(`Expected 2 to be equivalent to 1`) is meaningless without the surrounding
sequence (e.g. that the `2` came from a no-op update that must not have bumped).

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

### The `--focus` gate BLOCKS — scope it slim, or background it (do NOT busy-poll)

`run-all.sh --focus` runs `sonobuoy run --wait` (`06-run-sonobuoy.sh`), so the
command **blocks until the e2e binary exits and returns the result then** — you
do NOT need to poll for completion. Two ways to run it, by expected duration:

- **Slim focus (finishes < 10 min) → run it foreground, bare.** Scope the regex
  to the SPECIFIC failing test(s), e.g. `--focus "Guestbook application should
  create and stop"`, NOT a whole area like `--focus "Kubectl client"` (that
  matches dozens of tests, ~15 min). A slim focus keeps iteration fast and
  finishes inside the foreground timeout. To pin to exactly ONE test, use its
  FULL name as the focus, e.g.
  `--focus "[sig-node] Pods Extended (pod generation) Pod Generation pod generation should start at 1 and increment per update"`
  (the full test name from `e2e.txt` / the JUnit XML; ginkgo focus is a regex, so
  a complete name matches that one test).

  **But the ACCEPTANCE GATE is the focus you were DISPATCHED with, not the one you
  narrowed to.** Zooming into one test is for fast ITERATION only. A bead that
  covers a cluster (e.g. all `Kubectl client` create/replace tests, or all
  `pod generation` tests) is NOT discharged by one narrowed test going green —
  the other tests in the cluster may still fail. Before you close the bead / claim
  success, re-run the FINAL gate against the ORIGINAL dispatch focus and confirm
  the whole set passes (read `e2e.txt`). Report the pass line for the dispatch
  focus, not just your zoomed-in one.
- **A run that will exceed ~10 min → launch it as a BACKGROUND job**
  (`run_in_background: true` on the bare `scripts/conformance/run-all.sh …`
  command — the background flag is a tool parameter, not a command suffix, so it
  stays allowlist-safe). The foreground Bash timeout is capped at **10 min
  (600000 ms) and cannot be raised** — a longer run will time out mid-flight and
  return nothing. A background job detaches, survives past 10 min, and notifies
  you when it exits; then read `e2e.txt`.

**Never** hand-roll a `kubectl get pods -n sonobuoy` wait loop to watch a run
finish, and never launch a second `--focus` run while one is going. If a
foreground `--focus` call returns without a result, it TIMED OUT (run too long) —
re-run it in the background or narrow the focus; do not start polling.

**Cancelling the Bash call does NOT cancel the sonobuoy run.** sonobuoy runs
inside the VM; killing/timing-out the host-side `run-all.sh` command (or a Ctrl-C
equivalent) leaves the e2e job still executing in the VM — which is why polling
still shows live pods, and why a second `--focus` then collides with the first.
To actually stop a run (before re-running, or to abort), delete it IN THE VM
against the in-VM kubeconfig (the same command the script uses for pre-run
cleanup):

```bash
limactl shell <VM> sudo sonobuoy delete --all --wait --kubeconfig /tmp/sonobuoy-kubeconfig
```

Note `/tmp/sonobuoy-kubeconfig` is the VM-side kubeconfig the script copies in —
NOT the host's `temp/u7s/kubeconfig`. A fresh `run-all.sh --focus` (or `--reset`)
runs this delete automatically before starting, so you only need it by hand when
you interrupted a run and want to re-issue one, or to abort without re-running.

---

## Logs

| Component           | Where                                                          |
|---------------------|----------------------------------------------------------------|
| apiserver           | `temp/u7s/apiserver.log`                           |
| konnectivity-server | `temp/u7s/konnectivity-server.log`                 |
| KCM                 | `limactl shell <VM> tail -f /tmp/kcm.log`                     |
| kubelet             | `limactl shell <VM> sudo journalctl -u kubelet -n 50`         |
| konnectivity-agent  | `kubectl --kubeconfig temp/u7s/kubeconfig logs -n kube-system konnectivity-agent` |

After a sonobuoy run completes, `06-run-sonobuoy.sh` automatically collects all logs into
`temp/e2e/<TIMESTAMP>-<FOCUS>/host-logs/`: `apiserver.log`, `scheduler.log`,
`konnectivity-server.log`, `kcm.log` (from in-VM `/tmp/kcm.log`), and `kubelet.log`
(from `journalctl -u kubelet --no-pager` — captures the full boot history, including any
crash-loops). To collect manually (e.g. after a `--stack-only` run):
```bash
limactl shell <VM> sudo journalctl -u kubelet --no-pager > kubelet.log
```

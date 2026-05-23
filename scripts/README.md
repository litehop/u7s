# scripts/

Development, testing, and CI tooling for u7s. Requires a working Rust toolchain, `curl`, and (for lima scripts) `limactl`.

## Local kubelet workflow

Full end-to-end: u7s on the Mac host, kubelet inside a lima VM.

```bash
# 1. Build
cargo build --release -p u7s-apiserver

# 2. Start apiserver (state persists in ./temp/u7s/ across restarts)
scripts/u7s-start.sh
# → prints: export KUBECONFIG=./temp/u7s/kubeconfig

# 3. In a second terminal — join the kubelet
export KUBECONFIG=./temp/u7s/kubeconfig
scripts/lima-start.sh
# → waits for lima-node to appear in kubectl get nodes

# 4. Verify
kubectl get nodes
kubectl get pods -A
```

**Re-joining after a server restart:** Just re-run `scripts/lima-start.sh` — it rewrites the kubeconfig in the VM and restarts kubelet. The CA is stable across restarts so no re-provisioning is needed.

**Full reset** (rotates CA — kubelet must re-join):
```bash
scripts/u7s-start.sh --reset
export KUBECONFIG=./temp/u7s/kubeconfig
scripts/lima-start.sh
```

**VM re-provisioning** (slow, ~5 min — only needed once or if VM is broken):
```bash
limactl delete lima-node
scripts/lima-start.sh   # provisions fresh VM then joins
```

---

## u7s-start.sh — Start the apiserver for local development

Builds are handled by the caller (`cargo build --release`). This script only starts the server, waits for the port to open, and prints the `KUBECONFIG` export line.

State lives in `./temp/u7s/` (gitignored). The CA and SA keys persist across restarts so kubelets stay joined without re-provisioning.

```bash
scripts/u7s-start.sh           # start (errors if port 6443 already in use)
scripts/u7s-start.sh --reset   # wipe state and start fresh
```

## lima-start.sh — Start lima-node and join it to u7s

Starts the lima VM (`lima-node`), copies the kubeconfig into it (rewriting `127.0.0.1` → `host.lima.internal`), starts kubelet inside the VM, and polls until the node appears in `kubectl get nodes`.

```bash
export KUBECONFIG=/path/to/kubeconfig   # printed by u7s at startup
scripts/lima-start.sh
```

**Prerequisites:** `limactl` (`brew install lima`), `kubectl`, and u7s running on the host.

## sonobuoy-run.sh — Run Kubernetes conformance tests

Runs sonobuoy inside the lima VM in `non-disruptive-conformance` mode and retrieves results. Use `--focus` to narrow to a specific test area.

```bash
scripts/sonobuoy-run.sh
scripts/sonobuoy-run.sh --focus "ConfigMap"
```

**Prerequisites:** u7s running, lima-node registered (`scripts/lima-start.sh` first).

## assert-worktree-boundary.sh — Worktree boundary guard (PreToolUse hook)

Blocks Edit/Write calls targeting files outside the current git worktree root. Registered as a `PreToolUse` hook in `.claude/settings.json` — not intended for direct invocation.

## create-worktree.sh — Worker worktree setup (WorktreeCreate hook)

Creates worker worktrees at `ai/worktrees/` instead of the default `.claude/worktrees/`, and copies gitignored config files (`.beads-credential-key`, `.claude/settings.json`) into the new worktree. Registered as a `WorktreeCreate` hook — not intended for direct invocation.

## bench-rss.sh — Idle RSS gate

Builds the release binary, starts the apiserver, waits for memory to stabilize, samples RSS, then asserts the threshold.

```bash
bash scripts/bench-rss.sh
```

**What it does:**
1. `cargo build --release -p u7s-apiserver`
2. Starts the server in a temp directory with a static token-auth file
3. Waits up to 10s for the TCP port (6443) to be ready
4. Waits 3s for memory to stabilize
5. Samples RSS via `ps -o rss=` (works on macOS and Linux; returns kilobytes)
6. Prints `RSS: <N> kB (threshold: 65536 kB)`
7. Exits 0 if RSS <= 65536 kB (64 MB), exits 1 with server log on failure

**Threshold:** 64 MB for the apiserver alone. The combined control-plane target is 128 MB on a 1 vCPU / 1 GB VPS. This is a hard correctness gate in CI, not an aspirational goal.

## bench-latency.sh — Request latency report

Starts the server and fires 100 sequential GET /api requests, reporting p50 and p99 wall-clock latency. Results are saved to `ai/perf/` as a timestamped text file.

```bash
bash scripts/bench-latency.sh
```

**What it does:**
1. Builds and starts the server (same as bench-rss.sh)
2. Fires 100 sequential `curl` requests to `https://127.0.0.1:6443/api`
3. Computes p50 and p99 from `curl --write-out '%{time_total}'` output using `sort` + `awk`
4. Prints `p50: Xms  p99: Yms`
5. Saves the full results to `ai/perf/latency-YYYYMMDD-HHMMSS.txt`

**No CI threshold:** latency varies too much between environments (CI runners vs. local dev). Results are saved as artifacts for trend tracking but do not gate CI.

## bench-rss-load.sh — RSS delta under saturated load

Saturates the server with 50 concurrent GET requests and 20 concurrent mutating POST requests for 30 seconds, then measures the RSS delta. Fails if the delta exceeds 20 MB.

```bash
bash scripts/bench-rss-load.sh
```

**Threshold:** 20 MB RSS delta. Guards against memory leaks under concurrent load.

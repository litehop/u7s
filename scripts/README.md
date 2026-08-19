# scripts/

Development, testing, and CI tooling for u7s. Requires a working Rust toolchain, `curl`, and (for lima scripts) `limactl`.

## Local kubelet workflow

Full end-to-end: u7s on the Mac host, kubelet inside a lima VM.

```bash
# 1. Build
cargo build --release -p u7s-apiserver

# 2. Start apiserver (state persists in ./temp/u7s/ relative to CWD)
scripts/u7s-start.sh
# → prints: export KUBECONFIG=./temp/u7s/kubeconfig

# 3. In a second terminal — join the kubelet
export KUBECONFIG=./temp/u7s/kubeconfig
scripts/conformance/lima-start.sh
# → waits for lima-node to appear in kubectl get nodes

# 4. Start kcm (runs inside the Lima VM — kcm is a Linux binary)
scripts/conformance/04-start-kcm.sh
# Downloads kcm binary on first run, caches in ~/.cache/u7s/kcm/ inside the VM

# 5. Verify
kubectl get nodes
kubectl get pods -A
```

**Re-joining after a server restart:** Just re-run `scripts/conformance/lima-start.sh` — it rewrites the kubeconfig in the VM and restarts kubelet. The CA is stable across restarts so no re-provisioning is needed.

**Full reset** (rotates CA — kubelet must re-join; wipes `./temp/u7s/` in CWD):
```bash
scripts/u7s-start.sh --reset
export KUBECONFIG=./temp/u7s/kubeconfig
scripts/conformance/lima-start.sh
```

**VM re-provisioning** (slow, ~5 min — only needed once or if VM is broken):
```bash
limactl delete lima-node
scripts/conformance/lima-start.sh   # provisions fresh VM then joins
```

---

## u7s-start.sh — Start the apiserver for local development

Builds are handled by the caller (`cargo build --release`). This script only starts the server, waits for the port to open, and prints the `KUBECONFIG` export line.

State lives in `./temp/u7s/` relative to CWD (gitignored). The CA and SA keys persist across restarts so kubelets stay joined without re-provisioning.

```bash
scripts/u7s-start.sh             # start (errors if port 6443 already in use)
scripts/u7s-start.sh --reset     # wipe state and start fresh
scripts/u7s-start.sh --background  # start backgrounded (logs to file; reuses if port in use)
```

## scripts/conformance/ — Automated sonobuoy conformance orchestration

Numbered scripts that run the full conformance sequence end-to-end. Each step
can be run individually or via the top-level `run-all.sh` orchestrator.

```bash
# Full run (all 6 steps):
scripts/conformance/run-all.sh

# Narrow to a specific test area:
scripts/conformance/run-all.sh --focus "ConfigMap"

# Or run steps individually:
scripts/conformance/01-build.sh
scripts/conformance/02-start-apiserver.sh   # starts apiserver backgrounded; logs to ./temp/u7s/apiserver.log (relative to CWD)
export KUBECONFIG=./temp/u7s/kubeconfig
scripts/conformance/lima-start.sh
scripts/conformance/04-start-kcm.sh
scripts/conformance/05-start-scheduler.sh
scripts/conformance/06-run-sonobuoy.sh [--focus <regex>]
```

| Script | What it does |
|---|---|
| `01-build.sh` | `cargo build --release -p u7s-apiserver -p u7s-scheduler` |
| `02-start-apiserver.sh` | Delegates to `scripts/u7s-start.sh --background`; exports KUBECONFIG |
| `lima-start.sh` | Provisions/starts the lima VM and joins its kubelet to u7s |
| `04-start-kcm.sh` | Downloads (if needed) and starts kube-controller-manager inside the lima VM |
| `05-start-scheduler.sh` | Starts u7s-scheduler on the host (backgrounded) |
| `06-run-sonobuoy.sh` | Runs sonobuoy conformance tests inside the lima VM; supports `--focus` |
| `run-all.sh` | Top-level orchestrator: sources step 02 so KUBECONFIG propagates, runs all steps |

**KUBECONFIG propagation:** `run-all.sh` sources `02-start-apiserver.sh` so the
`KUBECONFIG` export is visible to subsequent steps. When running steps individually,
export it manually after step 02.

---

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

**`SKIP_BUILD=1`:** skips step 1 and reuses whatever binaries already exist in `target/release/`. Used by CI (`perf.yaml`) so the three `bench-rss*` jobs share one upstream build instead of each rebuilding from scratch.

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

**`SKIP_BUILD=1`:** skips the build step and reuses whatever binaries already exist in `target/release/` (same rationale as `bench-rss.sh` above).

---

## Troubleshooting

### `openssl s_client` prints "certificate signature failure" — false alarm

**Symptom:** Running `openssl s_client -connect 127.0.0.1:6443` (or `host.lima.internal:6443`) from inside the Lima VM prints an error like:

```
verify error:num=1:X509_V_ERR_UNSPECIFIED:unspecified certificate verification error
...
certificate signature failure
```

**This is a false alarm.** The certificate and server are fine.

**Root cause:** Ubuntu 22.04 ships OpenSSL 3.0.x, which does not support the `X25519MLKEM768` post-quantum key-exchange extension used by u7s's `rustls-post-quantum` TLS stack. OpenSSL 3.0.x cannot complete the handshake and misreports this as a certificate error.

**Verification:** Go clients (kubelet, kcm, kubectl) use a modern TLS implementation and connect successfully. Use these instead:

```bash
# Correct diagnostic — if this works, the server and cert are fine:
kubectl get namespaces
curl --cacert ./temp/u7s/ca.crt https://127.0.0.1:6443/api   # ./temp/u7s/ relative to CWD
```

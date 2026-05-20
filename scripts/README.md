# scripts/

Development, testing, and CI tooling for u7s. Requires a working Rust toolchain, `curl`, and (for lima scripts) `limactl`.

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

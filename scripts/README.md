# scripts/

Benchmarking scripts for u7s-apiserver. Requires a working Rust toolchain and `curl`.

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

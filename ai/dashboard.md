# Dashboard
2026-08-15T00:36Z — Mayor session on CLI. **2 workers active, 0 open PRs.** Resume: `bd prime` → this file.

Stance: resource-optimized k8s, correctness → obs → perf, pre-alpha, merge-on-green.

## ▶ IN PROGRESS (2 workers, both VM-heavy, dispatched pre-agent-md-fix)
- **mayor-pxae4** — RuntimeClass e2e coverage scout under cri-o. VM `lima-node-2` / port 6444 / kubelet 10251.
- **mayor-lry4o** — PodDisruptionBudget e2e coverage scout. VM `lima-node-4` / port 6446 / kubelet 10253. Also a datapoint for mayor-3g1ft (lima-node-4 network-loss watch) if it hits.

Also a low-concurrency stress test of the just-recreated shared `usernet` daemon (mayor-o61zz P1 workaround verification).

## 👀 Watch — agent-md MCP fix (operator-applied, needs verification)
Operator added MCP tools to `worker.md` + `researcher.md` line 6 (`mcp__mcpls,mcp__lima-node*`). **Two caveats surfaced:**
1. `researcher.md` has a single-underscore typo: `mcp_lima-node*` (should be `mcp__lima-node*` like `worker.md`). Won't match anything — trivial one-char fix pending.
2. Worker toolsets are sealed from Agent-launch time, so the two in-flight workers above do NOT retroactively gain MCP. Next dispatch will be the verification — and only then if agent md hot-reloads without a session restart (unverified; operator flagged).

## 🧠 Memories this session
- `mcpls-lsp-unavailable-in-worker-worktrees-project-trust-not-warmup` — updated in place: RESOLVED, actual root cause was worker.md allowlist (not project-trust). Verification pending on next dispatch.
- `e2e-test-has-no-kube-api-qps-flag` — hardcoded 20/50 QPS in conformance image.
- `crd-delete-watch-teardown-not-urgent-timeoutseconds-is-the-recovery-path` — `timeoutSeconds` drives Reflector relist to the existing 410 tombstone path.

## ✅ merged this session
- **#1189 → `4194974f`** (renovate: uuid → v1.24.1).
- **#1188 → `b38bacf0`** (mayor-9n1s7-side-fix: NetworkPolicy endPort validation).

## Recently closed
- **mayor-0g968** (mcpls scout) — verdict superseded; real cause was worker.md allowlist.
- **mayor-qlnxh** (e2e QPS scout) — deferred.
- **mayor-m5gjv** (CRD-delete watch-teardown scout) — deferred.

## Queued (not dispatched)
- **mayor-fgh2b** (P1, blocked-by o61zz cleared) — dstIP NetworkPolicy bisect.
- **mayor-bfq6l / ejm5s / 5v9gl / w44wg** — P2 heavy scouts (VM).
- **mayor-53fir / w6oeb / ud31w / moejy / j0g9u / 8n64y** — P3 e2e-coverage scouts (VM).
- **mayor-n62ww / gnf1o** — codegen Phases 3/4 (large, split-or-hold pending).

## Repo state
Main at `4194974f`. Worktrees: 3 (mayor + 2 workers). Open PRs: 0. VMs: 2 provisioning (lima-node-2, lima-node-4). Uncommitted: `.claude/agents/worker.md`, `.claude/agents/researcher.md` (operator's MCP fix, not committed yet).

## Live docs
- ADRs: [`network-policy-engine`](docs/decisions/network-policy-engine.md) · [`proto-adapter-codegen`](docs/decisions/proto-adapter-codegen.md)
- Findings: [`t6mh5`](ai/findings/t6mh5-e2e-suite-taxonomy-2026-08-14.md) · [`9n1s7`](ai/findings/9n1s7-netpol-enforcement-bisect-2026-08-14.md)

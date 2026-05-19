# Dashboard

2026-05-19T13:15 UTC+9
Session: mayor-phase3-dispatch — resume by opening Claude Code at /Users/balint.erdos/u7s
Open beads: 3 (+ 1 in-progress: mayor-n9a)

## What needs the operator now

### 1. Security review — mayor-n9a (SA JWT validation)
A PR will open shortly for SA JWT inbound verification. This touches the auth path — please review before merging. The PR description is flagged `⚠️ SECURITY REVIEW REQUESTED`.

### 2. Restart environment
Operator requested restart to pick up config changes (settings.json allow-list, .mcp.json, worker.md tool restrictions).

## Remaining open beads

| Priority | Bead | Title | Notes |
|----------|------|-------|-------|
| P2 | mayor-d01 | Scale subresource (Deployments/ReplicaSets/StatefulSets) | Ready — dispatch next session |
| P2 | mayor-u9f | CRD support | Large/architectural — third wave |
| P3 | mayor-2hu | Controller manager SA token provisioning | Depends on mayor-n9a merge |

## What changed this session

**Infra fixes:**
- `.claude/settings.json`: Bash allow-list added (cargo/bd/git/gh + cd-prefixed variants) — workers no longer blocked on permissions
- `.claude/agents/worker.md`: `permissionMode: auto`, explicit tool allowlist, `disallowedTools: WebSearch,WebFetch,Agent`, no-Python rule
- `CLAUDE.md`: Rule 13 added — prefer Bash/Rust over Python
- `crates/mcp-server/`: MCP server with `get_diagnostics`, `bd_ready`, `bd_show` tools
- `.mcp.json`: wires MCP server into Claude Code for project scope

**Phase 3 beads closed this session (12):**
- mayor-srk (permissions fix), mayor-j55, mayor-weh, mayor-8sb, mayor-6wk (discovery surface)
- mayor-0fb, mayor-bfu, mayor-aqv, mayor-2ae (cleanup)
- mayor-vgr (RBAC startup scan), mayor-f28 (RBAC live updates)
- mayor-5nv (cross-namespace pods), mayor-4z5 (generic watch), mayor-3w7 (scheduler scaffold)
- mayor-35k (MCP server)

**PRs merged: #18, #19, #20, #21** (+ changes committed directly to main)

## Stance (reasserted each session)

Pre-alpha/greenfield: break freely, no backward compat, delete dead code. Correctness first, then performance. kubectl-compatible API surface. Minimal dependencies. **Merge on green CI automatically**; flag security/API surface/architecture PRs for operator review first.

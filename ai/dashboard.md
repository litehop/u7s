# Dashboard
2026-05-22T22:00 UTC
Session: a2079177-fb10-4b26-8356-4640391653f9 (`I am the Mayor now` at /Users/balint.erdos/u7s)
Open beads: 11

## What needs the operator now

**Networking discussion (pre-requisite for two beads):**
- mayor-2d7p (portforward) and mayor-l7a9 (attach) are both deferred pending your decision on SPDY vs WebSocket. The transport audit (mayor-5ob2) confirmed upstream kubectl 1.34–1.36 uses SPDY for exec/attach/portforward — so we need a SPDY library to implement these correctly. The audit found `hyper` already in use; a SPDY crate (`async-h1`/`h2` won't help — it would be `tokio-tungstenite` + SPDY framing or the `spdylay` bindings). Worth a separate conversation.

**No other decisions blocking dispatch.**

## Dispatch-ready (no blockers, no decisions needed)

| ID | P | Summary |
|----|---|---------|
| mayor-xas3 | P2 | Admission webhook invocation — full pipeline decision resolved |
| mayor-rvkq | P3 | CRD CEL validation — minimal inline evaluator |
| mayor-u7ij | P3 | ResourceQuota enforcement (count-based) |
| mayor-x9b5 | P3 | LimitRange enforcement |
| mayor-knyy | P3 | Switch reqwest native-tls → rustls-tls + fix danger_accept_invalid_certs |
| mayor-15hu | P3 | Deduplicate send_request/stream_watch_events into client-util |
| mayor-2ni  | P3 | Sonobuoy conformance audit (hold lifted — needs lima VM running) |

**Dependency chain:** mayor-knyy → mayor-lghq (PQC). mayor-15hu is prereq for transport abstraction trait.

## Open beads

| ID | P | Summary |
|----|---|---------|
| mayor-xas3 | P2 | Admission webhook invocation |
| mayor-2d7p | P2 | Pod /portforward (SPDY — awaiting networking discussion) |
| mayor-knyy | P3 | reqwest native-tls → rustls-tls + cert verification fix |
| mayor-15hu | P3 | Deduplicate HTTP client into client-util |
| mayor-lghq | P3 | rustls-post-quantum ML-KEM (depends mayor-knyy) |
| mayor-rvkq | P3 | CRD CEL validation |
| mayor-u7ij | P3 | ResourceQuota enforcement |
| mayor-x9b5 | P3 | LimitRange enforcement |
| mayor-pva9 | P3 | CRD conversion webhooks (depends mayor-xas3) |
| mayor-l7a9 | P3 | Pod /attach (SPDY — awaiting networking discussion) |
| mayor-2ni  | P3 | Sonobuoy audit |

## In-flight work

None. All workers completed or stale. Stale worktrees to clean up:
- `ai/worktrees/cel-rvkq` (worker/cel-rvkq — no commits, stranded)
- `ai/worktrees/quota-u7ij` (worker/quota-u7ij — no commits, stranded)
- `ai/worktrees/transport-audit-5ob2` (worker/transport-audit-5ob2 — audit complete, no commits to push)

## Session findings — transport & crypto audit (mayor-5ob2)

Completed this session. Key results:
- **Security gap**: `proxy.rs:168` has `danger_accept_invalid_certs(true)` on kubelet proxy — fixed by mayor-knyy
- **OpenSSL removed**: switching reqwest to `rustls-tls` drops 5 C crates (mayor-knyy)
- **PQC near-drop-in**: `rustls-post-quantum 0.2` swaps in as CryptoProvider after knyy lands (mayor-lghq)
- **QUIC**: viable only for internal scheduler/kcm traffic; kubelet path blocked until we build our own kubelet
- **Findings doc**: `ai/findings/transport-crypto-audit-2026-05-22.md` (gitignored, local only)

## Session findings — dispatch mechanics

Resolved a persistent worker dispatch failure. Root cause: subagents launched via `Agent()` don't load `worker.md` before their first tool call — they prompt for permission. Fix: mayor pre-creates worktree + copies `settings.json` before dispatch; prompt includes "You have full permission... do not ask, just act." Both conditions required. Updated `dispatch-prompt-template.md` and three bd memories. Confirmed working on mayor-5ob2 (34 tool uses, no prompts).

## Recent progress

**This session:**
- Resolved worker dispatch mechanics (multiple failed attempts → confirmed fix)
- Completed transport & crypto audit (mayor-5ob2) → 3 follow-on beads filed
- Updated dispatch-prompt-template.md with correct worktree pattern and mayor pre-checklist
- Filed and discussed QUIC/HTTP3 and PQC directions with operator
- Set up loops (currently stopped — operator winding down session)

**Previous session metrics:** 5 PRs merged, 15 beads closed.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI automatically; flag security/API/architecture PRs for operator review first.

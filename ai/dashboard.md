# Dashboard
2026-05-22T23:15 UTC
Session: bb35dc0d-a124-4aa4-99c9-70752a592c8b (`I am the Mayor now` at /Users/balint.erdos/u7s)
Open beads: 10 (mayor-knyy closed this session)

## What the operator needs to do now

**One open decision — exec/attach/portforward proxy-through approach:**

mayor-2d7p (portforward) and mayor-l7a9 (attach) are unblocked on transport (WebSocket confirmed, no SPDY). One question remains before dispatch:

> When kubectl exec hits our apiserver, we must forward the WebSocket session to the kubelet. Do you want:
> - **(A) Full proxy-through now** — WebSocket inbound from kubectl, WebSocket outbound to kubelet. Correct end-to-end, ~300-400 LoC.
> - **(B) Stub-first** — implement the inbound WebSocket upgrade (kubectl gets 101 + upgrade), but the kubelet forward returns a clean 501. Unblocks conformance tests that check upgrade negotiation. Forward wired in a follow-on bead.

**Worker dispatch is broken for this session** — background workers block on Bash permissions. mayor-knyy succeeded once (unknown why); admission and client-util fail repeatedly. Worktrees exist and are clean; work can resume next session when the permission issue is resolved. See bd memory `worker-dispatch-permission-failure-root-cause` for full analysis.

## In-flight work

| Bead | Worktree | Status |
|------|----------|--------|
| mayor-xas3 P2 | ai/worktrees/admission-xas3 | Worktree clean, ready to re-dispatch next session |
| mayor-15hu P3 | ai/worktrees/client-util-15hu | Worktree clean, ready to re-dispatch next session |

No open PRs.

## Dispatch-ready (next session)

| ID | P | Summary |
|----|---|---------|
| mayor-xas3 | P2 | Admission webhook invocation — worktree exists |
| mayor-15hu | P3 | Deduplicate HyperApiClient — worktree exists |
| mayor-2d7p | P2 | Pod /portforward (pending proxy-through decision above) |
| mayor-l7a9 | P3 | Pod /attach (same) |
| mayor-pva9 | P3 | CRD conversion webhooks (depends mayor-xas3) |
| mayor-lghq | P3 | rustls-post-quantum ML-KEM (depends mayor-knyy ✓ — now unblocked) |
| mayor-rvkq | P3 | CRD CEL validation — needs scope definition |
| mayor-u7ij | P3 | ResourceQuota — needs scope definition |
| mayor-x9b5 | P3 | LimitRange — needs scope definition |

## Recent progress

**This session (2026-05-22):**
- PR #174 merged: reqwest native-tls → rustls, danger_accept_invalid_certs fixed (mayor-knyy ✓)
- WebSocket transport decision made: WebSocket only, no SPDY, both layers (kubectl→apiserver and apiserver→kubelet)
- Proxy-through approach decision pending (see above)
- Diagnosed worker dispatch permission failure — root cause unknown, memorialized
- Cleaned stale worktrees from prior session (cel-rvkq, quota-u7ij, transport-audit-5ob2)

**Unresolved infra issue:** Worker dispatch blocks on Bash for mayor-xas3 and mayor-15hu (but not mayor-knyy, once). Likely requires global `~/.claude/settings.json` to have `defaultMode: auto` or `Bash(*)` added.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI automatically; flag security/API/architecture PRs for operator review first.

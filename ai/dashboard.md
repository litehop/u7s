# Dashboard
2026-05-23 02:15 UTC — session winding down
Resume: open Claude Code in /Users/balint.erdos/u7s and say "I am the Mayor now"
Open beads: 3 (1 P1 blocked on local debug, 2 P3 deferred)

## What the operator needs to do now

**Nothing urgent.** The blocking issue (mayor-ve5z) needs more local iteration next session. The kcm connection from Lima VM is TLS-blocked — likely the ML-KEM post-quantum extension isn't understood by the OpenSSL/LibreSSL clients used in the test. Next session should try connecting with a Rust/Go client instead.

## Unresolved: mayor-ve5z (P1)

kcm still can't create ReplicaSets from Deployments. Root cause chain:
1. CSR watch fix (#192) landed — CSR informer no longer loops.
2. But metadatainformer still never gets its initial-events-end BOOKMARK.
3. Local debugging revealed TLS connection from Lima VM fails with "certificate signature failure" — suspected to be the ML-KEM-768 hybrid TLS extension not understood by OpenSSL.
4. Next step: bypass PQ crypto interference to get a clean kcm connection, then observe the actual watch stream.

## In-flight PRs

| PR | Title | Status |
|----|-------|--------|
| #179 | test(ci): Deployment + ConfigMap smoke test (mayor-9o59) | kcm failing — blocked on mayor-ve5z |

## Active worktrees

| Worktree | Branch | Status |
|----------|--------|--------|
| ai/worktrees/kcm-metadata-fix-ve5z | worker/kcm-metadata-fix-ve5z | awaiting diagnosis |
| ai/worktrees/smoke-fix-9o59 | worker/deployment-smoke-9o59 | #179 open |

## Mayor's next focus (next session)

1. Reproduce kcm connection without PQ TLS interference — try Go/Rust client or disable PQ for local debug
2. Observe actual metadatainformer watch requests, identify the stalling resource type
3. Spec a bounded fix → dispatch worker → rebase #179 → merge → close mayor-9o59
4. Dispatch mayor-h2fk once #179 merges
5. mayor-2ni (sonobuoy) deferred — operator decision

## Recent progress (this session)

- **#192 merged**: CSR watch fix — `list_csr` now streams watch events properly
- **9 worktrees cleaned up** this session (hygiene sweep)
- **5 cron loops** cancelled at session wind-down
- **Local kcm debugging started**: TLS handshake blocked by ML-KEM extension incompatibility with OpenSSL — not yet at the application layer

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, performance-critical (RSS/latency hard targets), kubectl-compatible API surface, minimal crate deps. Mayor merges on green CI automatically; flags security/API/architecture PRs for operator review first.

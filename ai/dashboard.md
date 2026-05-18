# Dashboard

2026-05-19 01:10 UTC+2
Resume: open Claude Code at /Users/balint.erdos/u7s (mayor session e87d5896)
Open beads: 0 open (14 closed) — Phase 2 bead filing blocked on 5 decisions

## What needs the operator now

**5 architectural decisions needed before Phase 2 beads can be filed.** Mayor asked them in chat — please answer each:

1. **DB-01** `resourceVersion=0` on LIST — treat as "current snapshot" (recommended) or implement read cache?
2. **DB-02** ADDED vs MODIFIED in watch events — encode in `InternalEvent.is_create` during `put_sync` (recommended) or detect in consumer?
3. **DB-03** Finalizer/graceful deletion — soft-delete only for ArgoCD Application objects (recommended), hard-delete all (simplest), or full two-phase for all resources?
4. **DB-04** Scheduler binary — leave `crates/scheduler` for Phase 3 (recommended) or add skeleton now?
5. **DB-05** Controller manager auth — use existing admin client cert / `system:masters` bypass (recommended) or implement SA token flow now?

Answering these unlocks filing ~14 Phase 2 beads and dispatching 3 parallel clusters (A: store watch, B: generic router, D: pods extensions).

## In-flight

Nothing. All worktrees clean. Phase 2 spec audit complete (findings in mayor session context).

## Forward-looking

Once decisions land, dispatch order:
- **Parallel:** Cluster A (store watch), Cluster B (generic router + discovery + namespaces), Cluster D (watch HTTP handler + SMP + binding subresource)
- **After A+B:** Cluster C (RBAC + auth middleware), Cluster E (core resources + field selector index)

## Recent progress

- **PR #1** — Phase 1: u7s-store + u7s-apiserver
- **PR #2** — GH Actions CI, git hooks, Claude Code push gate
- **PR #3** — Typed API models, Namespace newtype, kubeconfig cleanup (CI green)
- 14 beads closed, 0 open, 3 PRs merged

## Active loops

| Job ID   | Cadence | Purpose                         |
|----------|---------|---------------------------------|
| 79fd6852 | 60m     | Re-read bootstrap + stance      |
| a9e40a02 | 15m     | Dispatch ready beads            |
| 91601c59 | 30m     | Cluster same-surface beads      |
| a89b03d9 | 60m     | Worktree hygiene sweep          |
| 031ac23c | 30m     | Merge green PRs                 |
| d3785920 | 10m     | Update this dashboard           |

# Dashboard

2026-05-19 01:30 UTC+2
Resume: open Claude Code at /Users/balint.erdos/u7s (mayor session e87d5896)
Open beads: 15 open, 4 in-flight with workers

## What needs the operator now

Nothing urgent. 4 workers running. Mayor will review PRs as they land.
PRs touching API surface will be flagged for your review before merge.

## In-flight workers (4 parallel, disjoint surfaces)

| Worker | Bead(s) | Surface |
|--------|---------|---------|
| `worker/p2-store-watch` | mayor-lzc | `crates/store/src/lib.rs` — broadcast, ring buffer, WatchEvent stream |
| `worker/p2-generic-handler` | mayor-cgy, mayor-ihi | `main.rs`, `keys.rs`, `types.rs`, new `handlers/generic.rs` — generic CRUD + non-core discovery |
| `worker/p2-smp` | mayor-qu2 | `handlers/pods.rs`, new `patch.rs` — strategic merge patch |
| `worker/p2-rbac-index` | mayor-q3h | new `rbac.rs` — RBAC index, wildcard matching, system:masters bypass |

## Forward-looking

After these 4 land (in merge order to avoid main.rs conflicts):
1. Merge store watch (no conflicts) → unblocks P2-02 watch HTTP handler, P2-12 field selector
2. Merge generic handler → unblocks P2-09 namespaces, P2-10 core resources, P2-11 status subresource, P2-13 binding, P2-15 soft-delete
3. Merge RBAC index → dispatch P2-06 RBAC middleware (touches main.rs — after generic handler lands)
4. Merge SMP (no ordering constraint with others)

## Recent progress

- **PR #1–#3 merged** — Phase 1, CI/hooks, apiserver cleanup
- 14 beads closed before Phase 2; 15 new Phase 2 beads filed
- All 5 architectural decisions recorded (DB-01 through DB-05)

## Active loops

| Job ID   | Cadence | Purpose                         |
|----------|---------|---------------------------------|
| 79fd6852 | 60m     | Re-read bootstrap + stance      |
| a9e40a02 | 15m     | Dispatch ready beads            |
| 91601c59 | 30m     | Cluster same-surface beads      |
| a89b03d9 | 60m     | Worktree hygiene sweep          |
| 031ac23c | 30m     | Merge green PRs                 |
| d3785920 | 10m     | Update this dashboard           |

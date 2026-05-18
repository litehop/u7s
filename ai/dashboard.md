# Dashboard

2026-05-19 UTC+2
Resume: open Claude Code at /Users/balint.erdos/u7s (mayor session e87d5896)
Open beads: 10 open, 5 in-flight with workers

## What needs the operator now

**Question**: The `rbac-middleware` worker changed `build_router(Arc<SqliteStore>)` → `build_router(AppState)` to expose `rbac_index` to the tower layer. This is a reasonable refactor but touches the main function signature. Flagging per API-surface policy — no action needed, just awareness.

PRs #8–#12 are in CI. Mayor will merge in safe order (#8 field-selector → #9 watch → #10 namespaces → #11 generic-cluster → #12 rbac-middleware) rebasing as needed for conflicts.

## In-flight workers (5 parallel, PRs open)

| PR | Branch | Beads | Surface |
|----|--------|-------|---------|
| #8 | `worker/p2-field-selector` | mayor-0on | `crates/store/src/lib.rs` — field selector index |
| #9 | `worker/p2-watch` | mayor-hoo | `handlers/pods.rs` — chunked watch streaming |
| #10 | `worker/p2-namespaces` | mayor-tgg | `handlers/namespaces.rs` (new), `main.rs` (ns routes), `pods.rs` |
| #11 | `worker/p2-generic-cluster` | mayor-8pq, mayor-cbj, mayor-13x | `handlers/generic.rs`, `pods.rs`, `main.rs` (status/binding routes) |
| #12 | `worker/p2-rbac-middleware` | mayor-kmo | `auth.rs` (new), `main.rs` (tower layer), `state.rs` |

## Forward-looking

Merge order (safe): #8 → #9 → #10 → #11 → #12 (rebase each on updated main)

After these 5 land:
- Unblocked: mayor-4mi (P2-10 core resources: Nodes/Services/etc) — blocked on namespaces (#10)
- Unblocked: mayor-b12 (P2-14 SelfSubjectAccessReview) — blocked on rbac-middleware (#12)
- Unblocked: mayor-e51 (P2-07 SA JWT minting) — blocked on rbac-middleware (#12)

## Recent progress

- **PR #4 merged** — store watch infrastructure (P2-01)
- **PR #5 merged** — generic resource handler + non-core discovery (P2-03, P2-08)
- **PR #6 merged** — strategic merge patch (P2-04)
- **PR #7 merged** — RBAC index (P2-05)
- Phase 2 beads mayor-lzc, mayor-cgy, mayor-ihi, mayor-qu2, mayor-q3h all closed

## Active loops

| Job ID   | Cadence | Purpose                         |
|----------|---------|---------------------------------|
| 79fd6852 | 60m     | Re-read bootstrap + stance      |
| a9e40a02 | 15m     | Dispatch ready beads            |
| 91601c59 | 30m     | Cluster same-surface beads      |
| a89b03d9 | 60m     | Worktree hygiene sweep          |
| 031ac23c | 30m     | Merge green PRs                 |
| d3785920 | 10m     | Update this dashboard           |

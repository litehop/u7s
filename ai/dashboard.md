# Dashboard

2026-05-19 00:20 UTC+2
Resume: open Claude Code at /Users/balint.erdos/u7s (mayor session e87d5896)
Open beads: 3 open (mayor-vvs, mayor-h6n, mayor-s6z — all in-flight with worker)

## What needs the operator now

**Nothing urgent.** Worker running on `worker/apiserver-cleanup`. Await PR then review.

Note: PRs touching API types/handlers are flagged for operator review per merge policy.

## In-flight

- **worker/apiserver-cleanup** — cluster of 3 P2 beads, all `crates/apiserver/`:
  - `mayor-vvs`: typed API models + Into/From (replaces raw json!() in discovery.rs)
  - `mayor-h6n`: Namespace newtype with validation (replaces raw String in pods.rs)
  - `mayor-s6z`: kubeconfig path default + typed serialisation

## Forward-looking

1. Worker returns → mayor reviews PR (API surface change, needs operator eye)
2. After merge: file Phase 2 beads (watch, ring buffer, controllers, scheduler)
3. Consider CI badge in README once GH Actions first run completes

## Recent progress

- **PR #1 merged** — Phase 1: u7s-store + u7s-apiserver
- **PR #2 merged** — GH Actions CI, git pre-push hook, Claude Code push gate
- 11 beads closed total
- Memory profiling findings in ai/findings/rust-memory-profiling.md

## Active loops

| Job ID   | Cadence | Purpose                         |
|----------|---------|---------------------------------|
| 79fd6852 | 60m     | Re-read bootstrap + stance      |
| a9e40a02 | 15m     | Dispatch ready beads            |
| 91601c59 | 30m     | Cluster same-surface beads      |
| a89b03d9 | 60m     | Worktree hygiene sweep          |
| 031ac23c | 30m     | Merge green PRs                 |
| d3785920 | 10m     | Update this dashboard           |

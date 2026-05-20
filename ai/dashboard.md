# Dashboard

2026-05-20T13:12 UTC
`bd prime` in a fresh Claude Code session
Open beads: 1 (mayor-xy2 P3 deferred)

## What needs the operator now

**PR #73 — RBAC security surface, CI green, awaiting your review:**
- Evicts RBAC index immediately on soft-delete; test proves alice loses access on DELETE before finalizers drain
- Also: json-patch `add` on missing path, watch 410 uses compaction horizon, field-selector dedup
- 226 tests. Do not merge without your review.

**PR #74 — regression tests only, CI green, safe to merge:**
- Pure-function extractions (`accepts_patch_content_type`, `build_server_sans`) with unit tests
- No logic changes. Optional review.

## Forward-looking

1. Merge PR #73 (after your review) + PR #74 (CI green)
2. Post-merge: verify pod reaches Succeeded on lima-node; add CI smoke job
3. mayor-xy2 (CR schema validation, P3) — deferred until Argo CD milestone

## Recent progress

- Backlog cold: all P1/P2 beads closed this sprint (mayor-oyn, mayor-ofi, mayor-iek, mayor-lyc, mayor-adg)
- 14 new regression tests added across PRs #73–74 (Rule 14 compliance)
- Rule 14 codified in CLAUDE.md and worker preamble

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first. Every bug fix ships with a regression test (Rule 14).

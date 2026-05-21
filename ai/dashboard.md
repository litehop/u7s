# Dashboard

2026-05-21 04:02 UTC
`bd prime` in a fresh Claude Code session
Open beads: 20

## What needs the operator now

Nothing blocking — no decisions queued, no PRs pending review.

All open beads are unassigned and ready to dispatch:
- **4 P1 security** (`mayor-5vlg`, `mayor-dx5m`, `mayor-huwm`, `mayor-woob`) — weak RNG for UIDs, unbounded watch DoS, request body OOM, timing oracle on token compare
- **1 P1 feat** (`mayor-v43`) — pod lifecycle smoke test (create pod → assert Succeeded)

## Forward-looking

**Security sprint is the natural next focus** — 4 P1 security beads are cold and ready:
1. `mayor-woob` — fix non-constant-time static token comparison (easy, 1-liner)
2. `mayor-huwm` — add request body size limit (axum layer, ~20 LoC)
3. `mayor-5vlg` — replace weak UID RNG with CSPRNG (`uuid::v4` already used for CRs — apply to all paths)
4. `mayor-dx5m` — per-client watch stream concurrency cap

Then:
5. `mayor-v43` (P1) — pod lifecycle CI smoke test
6. `mayor-2ni` (P3) — sonobuoy non-disruptive conformance gap audit
7. `mayor-zcur` (P2) — CRD status subresource for custom resources

## Recent progress

**This session (2026-05-21):**
- **SA token projection** (`mayor-vacv`) — tokens now correctly projected into pods; default ServiceAccounts seeded in all four namespaces. Correctness fixes over two rounds of commits.
- **kubectl version matrix** (`mayor-jyt3`) — CI now smoke-tests against kubectl 1.34, 1.35, and 1.36 in parallel.
- **watch quality** (`mayor-1hc`, `mayor-e8fx`, `mayor-5kzn`) — 410 Gone on expired resourceVersion, bookmark suppression, watch event dedup.
- **CoreDNS seeding** (`mayor-6m3`) — minimal CoreDNS Deployment seeded in `kube-system` at startup.
- **Path traversal fix** — `validate_cli_path` added to block path injection from CLI-supplied paths.
- **ApiSerializer trait** (`mayor-oayj`) — JSON/proto wire format abstraction.
- **labelSelector/fieldSelector** propagated into live watch streams (`mayor-6zbc`).
- **Coverage CI** auto-updates baseline daily; fails if coverage drops >5% below baseline.
- ~96+ PRs merged total since project start.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.

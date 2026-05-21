# Dashboard
2026-05-21 08:35 UTC
Resume: open Claude Code in /Users/balint.erdos/u7s, say "I am the Mayor now"
Open beads: 2 (both P3, no blockers)

## What needs the operator now
- **PR #125** (CNI smoke fix) — re-queued after fixing `--allow-overwrite` → `-o Dpkg::Options::="--force-overwrite"`. CI running. Merge when green.
- **PR #127** (proto decoders) — Lease/CSINode/Event proto body decoding. CI running. Merge when green.
- **Renovate PRs #109 (rcgen) and #110 (rusqlite)** — still failing, not yet dispatched.
- **lima-node** — still NotReady; will reach Ready once PR #127 merges and server restarts with proto decode support.
- **Nested worktree bug** — workers keep spawning inside each other's worktrees. Root cause: worker isolation spawns relative to CWD, not repo root. No operator action needed; mayor cleans up after each dispatch.

## Forward-looking
- Merge PRs #125 and #127 when CI goes green (no operator review needed — correctness fix + new feature below security/API surface threshold)
- After #127 merges: restart lima-node u7s server → kubelet should reach Ready → sonobuoy audit (mayor-2ni) becomes unblocked
- Dispatch Renovate PR fixes (#109 rcgen, #110 rusqlite)
- CSR bootstrap flow (mayor-z1bu) — P3, scoped bead exists, awaiting operator decision on priority

## Recent progress
- **PR #123** (CodeQL dismissals) merged ✓ — 14 path-injection alerts cleared
- **PR #124** (jsonwebtoken v10) merged ✓ — rust_crypto feature, tests no longer panic
- **PR #126** (system:nodes RBAC test) merged ✓
- **PR #125** (CNI + pod lifecycle smoke) — open, CI re-running after dpkg flag fix
- **PR #127** (Lease/CSINode/Event proto decoders) — open, CI running (547 additions, 6 new tests)
- Closed beads: mayor-47hf, mayor-zxu4, mayor-66s8, mayor-pgdr (work done, PR open)

## Stance
Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.

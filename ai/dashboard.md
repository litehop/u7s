# Dashboard
2026-05-23 (session closed)
Resume: open Claude Code in /Users/balint.erdos/u7s and say "I am the Mayor now"
Open beads: 1 (1×P3)

## What needs the operator now

Nothing urgent. One deferred bead:
- `mayor-6w76` (P3) — Pod proto decoder. Defer until decode failure observed.

Good candidate for next session: checkpoint review of recent commits (PRs #206–#213) — spawn independent reviewers for correctness, coverage, performance hotspots; cluster resulting beads.

## In-flight / open PRs

None. All loops cancelled. Worktrees clean.

## Recent progress (this session)

- **PR #206**: `scripts/conformance/` — numbered orchestration scripts for sonobuoy
- **PR #207**: `/openapi/v2` and `/openapi/v3` stub endpoints
- **PR #208**: SMP nested list merge fix — path-reset bug + 3 regression tests (mayor-p4br, mayor-4c81)
- **PR #209**: CSR typed fields — `CertificateSigningRequestSpec/Status/CsrCondition`, 6 map lookups replaced (mayor-h7rl)
- **PR #210**: Pod typed fields — `PodSpec/PodStatus/Volume/VolumeProjection`, 3 map lookups replaced (mayor-51an)
- **PR #211**: SMP Service ports merge key — `spec.ports` → `port` key (mayor-pt54)
- **PR #212**: Namespace status.phase typed enum — `NamespacePhase/NamespaceStatus` (mayor-veja)
- **PR #213**: boon replaces hand-rolled CRD validator — full enum/pattern/min/max enforcement (mayor-rlfe)
- **Decision doc**: `docs/decisions/boon-for-crd-schema-validation.md` — benchmark + Viotti et al. VLDB rationale
- **Typed fields policy established**: type what apiserver reasons about; Value for pass-through; schemars derives on all new structs; k8s-openapi as dev-dep only

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, performance-critical (RSS/latency hard targets), kubectl-compatible API surface, minimal crate deps. Mayor merges on green CI automatically. Flags security/API/architecture PRs for operator review first.

# Dashboard

2026-05-21 05:55 UTC
`bd prime` in a fresh Claude Code session
Open beads: 2 (+ 2 in-flight with workers)

## What needs the operator now

**Renovate PRs #109 (rcgen 0.14) and #110 (rusqlite 0.39)** — both break the build. `rcgen 0.14` changed `signed_by()` API from 3-arg to 2-arg. Need your call: accept the upgrades (dispatch a worker to fix the call site in `tls.rs`)? Or close/ignore the Renovate PRs for now?

**PRs #97 and #103** (node Ready, pod lifecycle) — you rebased these onto main; CI reruns in progress. Should go green with wireType 7 fix now merged.

**`system:masters` bypass** — flagged as architecturally fishy, tracked in bd memory. No action needed now.

**`mayor-2ni`** (sonobuoy audit) and **`mayor-pgdr`** (typed proto bindings) — both held. 2ni needs Lima VM (can't run in CI worker). pgdr needs approach decision (Option A prost vs Option C Unknown-envelope — see bead description). No action needed unless you want to prioritise.

## Forward-looking

2 workers in flight:
- **solo-vxo9** — GET collection → list verb fix (auth.rs), kubeconfig 0o600 perms (tls.rs), store error message sanitisation
- **solo-xy2** — openAPIV3Schema validation for CR instances (422 on type/required violations)

After those land, the bead backlog will be cold (2ni and pgdr held). Natural pause — good time for the sonobuoy run locally, or to decide on the Renovate upgrades.

## Recent progress (this session)

Security sprint (all P1s closed): constant-time token compare, CSPRNG UIDs, body size limit, SA key 0o600, path traversal, CRD group shadowing, RBAC escalation (logic + wiring), SAR privilege gate, per-client watch limit.

CI hardening: gpg --batch fix, permissions blocks, SHA pinning, wireType 7 proto fix (Node/NodeList).

Feature work: CRD status subresource (#114), watch_pods dedup (#113), client-util crate (#112), RBAC dead code cleanup (#115).

**PRs merged this session: ~115 total since project start. Session merges: #103/#97 pending + #104, #106–#108, #111–#115.**

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.

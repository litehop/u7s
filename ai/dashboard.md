# Dashboard

2026-05-21 06:35 UTC
`bd prime` in a fresh Claude Code session
Open beads: 2 (both held)

## What needs the operator now

**PRs #97 and #103** (node Ready, pod lifecycle) — CI running after root-cause fix. Watch stream fix landed on main (see below); both PRs rebased and fmt-fixed. Should go green.

**Renovate PRs #109/#110** (rcgen 0.14, rusqlite 0.39) — both break the build (rcgen API change). Ignored per operator policy until backlog empty.

**Renovate PR #117** (jsonwebtoken v10) — breaks JWT auth tests. Same policy: ignore.

**`system:masters` bypass** — flagged as architecturally fishy, tracked in bd memory. No action needed now.

**`mayor-2ni`** (sonobuoy audit) and **`mayor-pgdr`** (typed proto bindings) — both held. 2ni needs Lima VM. pgdr needs approach decision. No action unless you want to prioritise.

## Root cause found and fixed: pod lifecycle smoke test

**Bug:** `ContentTypeLayer` was intercepting watch stream responses (kubelet's node watch, pod watch) and calling `to_bytes()` on the infinite streaming body. This deadlocked all watch responses — the kubelet never received node/pod watch events, its local cache stayed empty, and it never ran any pods.

**Fix:** detect `Transfer-Encoding: chunked` before buffering; skip re-encoding for streaming responses. Watch responses are already JSON; `application/json` fallback in Accept is always valid. Regression test added (`watch_stream_not_buffered_or_re_encoded`). Committed to main as `fix(content_type)`, PRs #97/#103 rebased.

**PRs merged this round:** #118 (openAPIV3Schema validation, xy2 worker), #119 (list verb/kubeconfig perms/error sanitisation, vxo9 worker, merged --admin for CodeQL false positive in tests).

## Backlog status

Bead backlog is cold (2ni, pgdr both held). After #97 and #103 merge, the only open work is held beads and Renovate PRs.

## Recent progress (this session)

Security sprint (all P1s closed): constant-time token compare, CSPRNG UIDs, body size limit, SA key 0o600, path traversal, CRD group shadowing, RBAC escalation (logic + wiring), SAR privilege gate, per-client watch limit.

CI hardening: gpg --batch fix, permissions blocks, SHA pinning, wireType 7 proto fix (Node/NodeList GET), watch stream deadlock fix.

Feature work: CRD status subresource (#114), watch_pods dedup (#113), client-util crate (#112), RBAC dead code cleanup (#115), openAPIV3Schema validation (#118), list-verb/kubeconfig/error-sanitisation (#119).

**PRs merged total: ~120. This round: #118, #119 (+ #97/#103 pending).**

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.

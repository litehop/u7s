# Dashboard

2026-05-21 05:15 UTC
`bd prime` in a fresh Claude Code session
Open beads: 9 (was 20 at session start)

## What needs the operator now

**Stance check:** Current stance is pre-alpha/greenfield — break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; security/API/architecture PRs flagged for review first. Does this still match your intent?

**Renovate PRs #109, #110** (rcgen 0.14, rusqlite 0.39) are failing — both break the build because `rcgen 0.14` changed `signed_by()` from 3-arg to 2-arg API. These need code adaptation before they can merge. A worker can handle this if you want to accept the upgrades.

**`system:masters` hardcoded bypass** — flagged earlier as architecturally fishy. Noted in bd memory for revisit. No action needed now.

**PRs #97 and #103** (node Ready assertion, pod lifecycle) — kubelet CI reruns triggered after wireType 7 fix (#111) landed. Should go green shortly; merge loop will catch them.

## Forward-looking

4 workers in flight (dispatched this loop):
- **cluster-5vyz-vm3l** — wire RBAC escalation check into CRB handler + remove dead_code suppressions
- **solo-rph** — deduplicate watch_pods into thin wrapper
- **solo-zcur** — CRD status subresource (Argo CD compatibility)
- **solo-3lv** — extract shared HTTP client stack into client-util crate

After those land, remaining open beads are all P3: sonobuoy audit, proto bindings, schema validation, security MED/LOW audit. Natural pause point to check in with you on priorities.

## Recent progress (this session)

- **gpg smoke fix** — kubectl install step was failing with `cannot open /dev/tty`; added `--batch --yes` (direct mayor edit)
- **Security sprint** — 12 beads closed: constant-time token compare, body size limit, CSPRNG UIDs, SA key 0o600 permissions, path traversal validation, CRD group shadowing, RBAC escalation prevention, SAR privilege gate, per-client watch limit
- **CI hardening** — permissions blocks on all workflow jobs, all Actions pinned to commit SHAs
- **Proto fix** — wireType 7 in Node watch stream; Node/NodeList excluded from proto re-encoding (returns JSON, which kubelet accepts)
- **PRs merged this session:** #104, #106, #107, #108, #111 (+ #103/#97 reruns pending)
- ~111+ PRs merged total since project start

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.

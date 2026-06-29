# Dashboard
2026-06-29T01:42Z — **PR #617 MERGED (cascade-delete + propagationPolicy=Orphan, GC correctness). Mayor on main `8b399974`, 0 workers, 0 open PRs. Branch protection ON. Loops CANCELLED.**

Resume: `bd prime`

## What just landed: #617 (mayor-3dnc cascade + mayor-5rkt Orphan)
The 0627-1541 saturation root cause + the GC orphan bug, both fixed in one merged PR.
- **Cascade:** owner hard-delete now cascades to owned pods (RS→pods, RC→pods, StatefulSet→pods). Stops the 110-pod node saturation (`OutOfpods` ×224 in 0627-1541 → ~24 fake failures + the 6h truncation).
- **Orphan (the real root cause):** DELETE bodies are proto-encoded (`application/vnd.kubernetes.protobuf`); old code JSON-decoded them and ALWAYS got Background, silently ignoring `propagationPolicy`. Added a `DeleteOptionsProto` decoder; Orphan now strips ownerReferences + skips cascade; cascade gated on `policy != Orphan`. (Same proto-decode-drop family we've hit repeatedly.)
- **Verified:** GC `--focus` on lima-node-smoke (run `temp/e2e/0629-1021-garbage-collector`): **7 passed / 4 failed (was 5/6)** — no regression, +2 specs. CI fully green (17/17). Fixed specs: orphan-RS-from-deployment, orphan-pods-rc [Serial], delete-RS-when-not-orphaning.

## Follow-ups filed from #617's 4 remaining GC failures (all pre-existing, none a regression)
- **mayor-wo9t (P3)** — legacy `orphanDependents=nil` orphan default still cascades (partial gap in #617's own Orphan fix; small extension).
- **mayor-kxsk (P3, feature)** — Foreground propagation unimplemented (deferred by design; needs finalizer machinery).
- **mayor-2f5a (P3)** — cronjob→jobs→pods + CR cascading deletion TIME OUT (`context deadline exceeded`). INVESTIGATE-FIRST: saturation/throughput vs. a real CronJob/CR cascade gap — re-run isolated on a clean node before assuming code gap.

## Infra fix — mayor-evnb CONFIRMED + FIX DISPATCHED (agent ab80163e on lima-node-2)
Scout (adcdeab4, CLOSED-by-mayor) + mayor-verified-in-source root cause of the 7h "aggregator Pending" hang. NOT "non-default VMs broken" — two bugs that only bite non-default workdir/port runs (workers used default temp/u7s → unaffected):
- **BUG 1 (the hang):** `run-all.sh:137` invokes the scheduler with NO `${_WORKDIR_ARG}` (every sibling step passes it). Scheduler defaulted to `temp/u7s/kubeconfig` → connected to the WRONG cluster → never scheduled the lima-node-2 aggregator. (My konnectivity hypothesis was a red herring for the hang.) Side-effect: a non-default-workdir scheduler-start would pkill the MAYOR's scheduler (default-workdir pkill scope) — my baseline likely disrupted the mayor stack.
- **BUG 2 (independent, breaks exec/logs not scheduling):** `u7s-start.sh:108` + `lima-start.sh:60` hardcode konnectivity port default 8135 → non-default run collides with mayor's 8135 → the `nc -z 8135` guard skips the konnectivity block → stack runs with no proxy.
- **FIX (ab80163e):** (1) pass `${_WORKDIR_ARG}` to scheduler; (2) auto-derive konnectivity port = 8135+(PORT-6443)×100 in both scripts; (3) add konnectivity column to the VM-slots tables. Verifying on lima-node-2 with a NON-default workdir (closes the scout's no-live-repro gap). Findings: `ai/findings/0629-lima-node-2-konnectivity-hang.md`.
- ⚠️ Worker is editing the VM-slots table in BOTH dispatch-prompt-template.md AND ai/dashboard.md — mayor must NOT touch those tables until its PR merges (collision avoidance).

## 0627-1541 discrete-bug backlog (FILED, HELD — operator: dispatch none until priority decided)
- **mayor-6fej (P2)** — kubectl OpenAPI `proto: cannot parse invalid wire-format data` (3 specs, one root cause; may relate to deferred mayor-52wo). Scout-first.
- **mayor-bg9m (P2)** — 6 discrete wrong-value bugs (Lease times nil, PVC status, ExternalName→ClusterIP, GC orphan [now likely fixed by #617 — re-verify], PDB, Secret immutability). Split per-bug at dispatch.
- **mayor-xe19 (P3)** — default ServiceCIDR not created (service-cidr-controller disabled) + RS GC timing.

## Pre-existing held beads
- mayor-wjon (P2) in-place pod resize — SPIKE-FIRST.
- mayor-9xb5 (P3) remove dead default_pod — trivial cargo-only chore.
- mayor-gobh (P3) OIDC residual after #606 — INVESTIGATE-FIRST.
- mayor-trb0 (P3) parameterize scale handlers by group — cleanup from #615.

## Deferred (3)
mayor-52wo (embed upstream OpenAPI v2) · mayor-j7to (Argo CD RBAC seed) · mayor-rvkq (CRD CEL validation).

## TODO (mayor, trivial)
- Fix the ` ```bash ` fence at `dispatch-prompt-template.md:375` → plain ``` (the source of workers copying `bash` into the allowlisted `run-all.sh` command). One-line doc edit; operator-approved.

## Lessons this wave (candidates for bd memory)
- **Mayor checkout drift:** dispatching a worker WITHOUT `isolation="worktree"` (to build on an existing PR branch) makes it operate in the mayor's checkout and leaves it on the feature branch. Twice this session. If a worker must extend an existing branch, either give it a worktree off that branch or expect to restore main afterward (stash beads/dashboard → checkout main → pull → re-export beads).
- **`bash`/`cd` prefix breaks the allowlist:** `Bash(scripts/conformance/run-all.sh *)` matches commands STARTING WITH `scripts/...`. Any `bash `/`sh `/`cd ... &&` prefix → denied. Workers must invoke bare; a denial means adapt, not abort.

## Stance
Pre-alpha Kubernetes apiserver in Rust. Correctness > conformance breadth. Workers in isolated worktrees; mayor orchestrates, doesn't code (except trivial 4-condition externally-verified edits). Merge-on-green WITH verification. No back-compat shims. Never `--admin`.

## VM slots
| Slot | VM | Port | Kubelet | Konnectivity | Status |
|---|---|---|---|---|---|
| mayor | lima-node | 6443 | 10250 | 8135 | operator stack |
| worker-1 | lima-node-smoke | 6444 | 10251 | 8235 | free (known-good for GC focus) |
| worker-2 | lima-node-2 | 6445 | 10252 | 8335 | free (mayor-evnb fix verified) |
Konnectivity auto-derives from port: 8135 + (port − 6443) × 100. No need to pass --konnectivity-server-port for standard slots.

## Session loops
CANCELLED. Re-create on resume: :07 posture · :11 worktree hygiene · :17/2h cluster · :23/2h merge · :43 dispatch · :53 dashboard

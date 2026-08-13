# Dashboard
2026-08-13T06:07Z — Mayor at `d5a5e007` (docs-roadmap-rewrite-vy44t, PR #1138). Resume: `bd prime` → this file.

Stance: resource-optimized k8s, correctness → obs → perf, pre-alpha, merge-on-green.

## ▶ IN PROGRESS
None. `mayor-vy44t` roadmap rewrite complete this session; about to push and merge PR #1138.

## ✅ this session (mayor-vy44t, via direct operator interview)
- Closed `mayor-vy44t` via direct operator interview, not delegated — the
  original `8137c129` rewrite had skipped the discussion step its own bead
  description called for.
- Split roadmap.md into two files: **north-star.md** (new — durable north
  star, decision metric, guiding principles; operator sign-off required to
  change) and **roadmap.md** (rewritten — current-state/priorities only,
  links back to north-star.md rather than duplicating it).
- Key corrections from the interview: k3s 430/60 MiB figures demoted to
  illustrative-only (excludes containerd/CoreDNS, unverified against k3s
  source); decision metric made explicitly memory-primary; component
  evaluation replaced a fixed "apiserver → scheduler → eventually
  kubelet/KCM" order with necessity-then-measurement-then-config-tuning-
  then-rewrite, no fixed order; Argo CD reframed from milestone to
  correctness-probe; new Gate 5 (correctness baseline beyond Conformance)
  added after a real gap surfaced (scheduler shipped with zero
  taint/toleration handling, undetected by Conformance's single-node bias,
  since fixed).
- `mayor-52wo` closed (superseded — its diagnosis was wrong even at the
  time; the real fixes were PRs #575/#621).
- `mayor-rvkq` corrected (a CEL evaluator exists for
  ValidatingAdmissionPolicy, not for CRD-schema `x-kubernetes-validations`
  — bead was conflating the two).
- `mayor-u6ju`'s SSA trigger made concrete (tied to Gate 5's probes);
  standalone-crate shape preference recorded on the bead.
- `mayor-sks59` filed: `project-context.md` has its own stale north-star
  ("run Argo CD" framing) and phase-status ("Phase 3, ready for first
  sonobuoy run") claims, found during this review, deferred as a separate
  follow-on.
- Near-miss: `project-stance.md` was briefly overwritten on a wrong
  filename assumption mid-session — caught before commit, restored with
  zero diff.

## Known loose ends (not resolved this session)
- A stash (`stash@{0}: On main`) predates this session — touches
  `.beads/*.jsonl` and this file, looks like leftover sync state from
  earlier on 2026-08-12, likely superseded by everything since. Not
  touched; worth a look before deciding whether to drop it.
- `lima-node-4` is running (8 CPU / 4 GiB) but wasn't tracked as active in
  the prior dashboard snapshot — likely a leftover from the `mayor-jnk90`
  measurement session. Not stopped; worth confirming nothing still depends
  on it before reclaiming it.

## Ready queue (top-5)
1. `mayor-sks59` — project-context.md refresh (north star, phase status,
   reconcile "Design decisions" duplication with roadmap.md's Architecture
   summary)
2. `mayor-t1h49` — ai/prompts refresh (stale `controller-manager` references)
3. `mayor-jtlnx` — opportunistic verify of #1134 on next conformance run
4. `mayor-bfq6l` — mount-race repro under `--procs=4+` (VM-heavy)
5. `mayor-9xsn3` — DRA v1alpha3 (deferred to 1.37 bump)

## Repo state
- Branch: `docs-roadmap-rewrite-vy44t`, PR #1138 — pushing this session's
  2 commits (`c8ad55ce`, `d5a5e007`), merge once CI passes.
- Worktrees: 1 (this one). Local branches: `docs-roadmap-rewrite-vy44t`,
  `main`. Stashes: 1 (see Known loose ends).
- VMs: `lima-node`, `lima-node-3`, `lima-node-4` all Running —
  `lima-node-4`'s assignment unconfirmed, see Known loose ends.

## Live docs
- [`ai/extended-context/north-star.md`](ai/extended-context/north-star.md) — new, durable north star + decision framework
- [`ai/extended-context/roadmap.md`](ai/extended-context/roadmap.md) — rewritten, current-state/priorities
- [`ai/findings/roadmap-audit-2026-08-12.md`](ai/findings/roadmap-audit-2026-08-12.md) — the audit that triggered this session
- [`ai/findings/upstream-component-rss-cpu-baseline-2026-08-12.md`](ai/findings/upstream-component-rss-cpu-baseline-2026-08-12.md) — mayor-jnk90 measurement data referenced throughout the rewrite

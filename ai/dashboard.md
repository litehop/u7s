---
updated: 2026-11-26T07:32Z
---
# Dashboard — session 2026-11-26 closed (main `79d9b9ae`)
**Stance:** alpha (no compat promise); correctness > security > perf > features; upstream **1.37.3** except secure crypto; queue merge on green, never `--admin`; security PRs drafted for operator; every release gated (agent runs burst + upgrade gates, operator pushes tags + approves publish).
**Resume:** paste `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register crons; `bd show mayor-rh8y3.3`; `bd show mayor-46dmq`.

## 🎯 Waiting on you
- **#2281 guard.sha256 pin change** (topology-aware KCM baseline: `kcm-multinode-specs.txt` added to PINNED) — review when the PR comes out of draft.

## ⏭ Next session — start here
- **#2281** `rh8y3.3` KCM trim (DRAFT): 10-controller trim full run = identical spec set, +1 failure `Probing container should *not* be restarted with a tcp:8080 liveness probe` (not reproduced idle; suspected load flake, unconfirmed). Decide flake vs trim effect → re-review. Steps in bead notes.
- If #2280 didn't land: it was in the merge queue at close (APPROVE, operator OK'd).
- P2 `46dmq` scheduler: in_flight keyed ns/name + Binding without UID precondition → stale bind on same-name recreate.
- P2 `0h9um` debug apiserver 512 KiB stack overflow (labeled pod create / PATCH).
- P3: `amw4o` Binding annotations merge · `4mh3f` golden VM version stamp · `rh8y3.6` kcm Pss_Anon/pod (needs runnable binary).
- Stale pre-11-20 in_progress claims untriaged (`lwwze` `b6c59` `rdy7h` `83irk` `qap3i.35` `1xpj7` `xdw6u.11` `p3ktl` `l2imr` `ynfzk`).

## Decided this session (detail in bead notes / PR bodies)
- Session focus: k8s version currency + KCM.
- k8s target **1.37.3**, CI matrix 1.36.7/1.37.3; CRI-O pin unchanged; ruleset checks renamed by operator.
- Watch resume after unwatched gap: **seeded backfill**, not 410 (`39isy`).
- Header limits: **keep hyper defaults** (HTTP/1 100, h2 16 KiB); upstream 16384 is a documented divergence — no e2e/Conformance covers it (`p2v2g`).
- CODEOWNERS on guard-pinned files is **documentation only**; guard.sha256 is the gate (`rh8y3.3`).

## ✅ merged this session (9 + 1 no-PR)
#2280 parity: scheduler/Binding pins, header-limit divergence documented (`vhms7` `new3g` `p2v2g`; queued at close) · #2279 KCM informer backoff reset on clean close, politeia 410 pin (`rh8y3.5`) · #2278 store rv=0 full replay + deterministic seeding-race test (`nz8gs`) · #2276 `crates/kcm` hardened informer + **P1** watch-gap event-loss fix (`rh8y3.4` `39isy`) · #2277 k8s 1.37.3 bump (`47br9`) · #2275 PQ TLS builder tests (`0slxf`) · #2273/#2274 renovate · (no PR) `jwnsx` lima-golden re-baked on 1.37.3.

<!-- BEGIN AUTO: open-prs -->
- #2281 feat(kcm): Phase 0c trim validation, leave-one-out memory table, guard pin (mayor-rh8y3.3) (DRAFT)
- #2280 fix(parity): k8s 1.37.2/1.37.3 changelog parity (in merge queue)
<!-- END AUTO: open-prs -->
<!-- BEGIN AUTO: worktrees -->
<!-- END AUTO: worktrees -->
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->
<!-- BEGIN AUTO: repo-state -->
As of 2026-11-26T07:32Z (session close) — Branch `main` @ `79d9b9ae`.
<!-- END AUTO: repo-state -->
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->

---
updated: 2026-11-25T16:14Z
---
# Dashboard — session 2026-11-25 closing (main `1e43f3f3`)
**Stance:** alpha (no compat promise); correctness > security > perf > features; upstream 1.37.3 except secure crypto; queue merge on green, never `--admin`; security PRs drafted for operator; every release gated (agent runs burst + upgrade gates, operator pushes tags + approves publish).
**Resume:** paste `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register crons; `bd show mayor-rh8y3`; `bd recall listagents-completed-may-still-be-live-pass-to-live-agents`; `bd recall gcp-project-lives-in-u7s-gcp-gcloud-config`.

## 🎯 Waiting on you
- **#2270 (KCM harness):** verdict APPROVE (at `50b1d27a`; head `a1ee4090` = empty resync commit) but bot review POST returns HTTP 500 every try. Next session reposts via `scripts/gh-app-review.sh`, or you merge by hand.
- **Stale stashes** (shared stack): `stash@{0}` dvv9w-fix cr.rs (fix merged #2229) · `stash@{1}` 2026-10-30 dashboard auto-stash. Drop if you agree.

## ⏭ Next session — start here
- Land #2269 (KCM spike, APPROVE, CI pending) + #2270 (above). Close `rh8y3.1`/`.2` on merge.
- **KCM Phase 0 next:** P2 `rh8y3.4` informer hardening for stack C (RV resume, 410 relist, backoff, fault-injection) — prerequisite for Phase 1 · P3 `rh8y3.3` trim validation + leave-one-out + guard pin (unblocked once #2270 merges).
- P3: `4cgjg` bound kcm-mode revert trap · `xpwbn` `as=Table` on status/scale + route-text coverage test · `8og76` meminfo test flake · `roqm0` node release() test · `omxmp` kubelet reduced-gate conformance · `7s8gr` apiserver RSS · `ynnoq` protobuf POM (deferred) · P4 `th29y` renovate ignorePaths.
- Stale pre-11-20 in_progress claims untriaged (`lwwze` `b6c59` `rdy7h` `83irk` `qap3i.35` `1xpj7` `xdw6u.11` `p3ktl` `l2imr` `ynfzk`).

## Decided this session (detail in bead notes / PR bodies)
- **KCM:** design approved; local/dev-only — no install.sh/release until measured perf benefit + conformance parity; start with well-e2e-covered controllers; shipped Go KCM untouched. ADR `kcm-rust-port-local-first-separate-process`. Phase 0 PASS (R−T 9.3/11.7 MiB). **Client stack C** (own hyper informer: 33.8 MiB idle, 3508 B/pod, 0 crates), harden first.
- **CEL:** cel 0.16.1, single depth limit 96 (documented divergence; new ADR supersedes 128).
- **Capacity artefacts** on GCP (`u7s-gcp` config), not Lima. Metadata-only watch: implement for parity (JSON done; protobuf deferred).

## ✅ merged this session (16)
#2268 upgrade-gate deletes VM on TERM/INT · #2267 burst-gate deletes VM on TERM/INT (2 bugs) · #2266 all 31 handlers via POM negotiator · #2265 hygiene reaps closed-PR worktrees · #2264 watch-channel reclaim tests · #2263 guard blocks HEAD-moving `gh` · #2262 POM on every watch event + 406 · #2261 watch fan-out lazy channels · #2260 cel 0.16.1 / depth 96 · #2259 first GCP capacity artefact (v0.4.7) · #2258 KCM ADR + state doc · #2257 watch defaulting parity · #2256 proxy test flake · #2255 hygiene STEP G reap · #2253 clap · #2239 KCM design. Closed unmerged: #2254, #2252.

<!-- BEGIN AUTO: open-prs -->
- #2271 chore(deps): update rust crate sha2 to v0.11.2 (`renovate/sha2-0.x-lockfile`, BLOCKED)
- #2270 feat(bench): local KCM memory harness — R/T A/B with Pss_Anon sampler (mayor-rh8y3.1) (`worker/agent-aab4e0dd4d3168700`, CLEAN)
- #2269 docs(findings): KCM client-stack spike — hyper client + narrow informer (mayor-rh8y3.2) (`worker/agent-a146bbe688b2eae08`, UNSTABLE)
<!-- END AUTO: open-prs -->
<!-- BEGIN AUTO: worktrees -->
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a08a831449e1e39da` (`pr2269b`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a146bbe688b2eae08` (`worker/agent-a146bbe688b2eae08`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a15675d8cb036dfe3` (`pr2270`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a4298aa82d379f76e` (`pr2269`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-aab4e0dd4d3168700` (`worker/agent-aab4e0dd4d3168700`)
<!-- END AUTO: worktrees -->
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->
<!-- BEGIN AUTO: repo-state -->
As of 2026-11-25T16:08:12Z (last tick) — Branch `main` @ `1e43f3f3`, dirty, up to date with origin/main.
<!-- END AUTO: repo-state -->
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->

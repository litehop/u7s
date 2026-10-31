# CI wall-clock audit

Bead: mayor-b6c59
Date: 2026-10-31
Scope: Phase 1 audit only; no workflow changes.

The merge-queue long pole is the cold fat-LTO release build of the single
`u7s-apiserver` crate (about 7 min) in the `e2e-focus` workflow's `build` job,
so the cheapest route toward ~5 min is a cheaper CI-only binary profile for the
e2e and PKI builds, followed by removing duplicate runs (main push, release
invariants) and parallelising `script-tests`.

## 1. Workflow inventory

| Workflow | Triggers | Jobs | Required in ruleset 18156794 |
|---|---|---|---|
| Test (`test.yaml`) | push (all branches except `gh-readonly-queue/**`), merge_group | lint, fmt, script-tests, test-coverage, release-invariants (+ `feature-tests` in PR #2053) | lint, fmt, script-tests, test-coverage. release-invariants and feature-tests are not required |
| E2E focus (`e2e-focus.yaml`) | pull_request, push main, merge_group | build -> e2e-focus x3 (1.35.9/1.36.5/1.37.1), sensitive-e2e-guard x3 | `e2e-focus 1.37.1`, `sensitive-e2e-guard 1.37.1` |
| PKI rotation e2e (`pki-rotation-e2e.yaml`) | push (all branches except queue), merge_group | build -> intermediate, leaf, leaf-scheduler, sa-key-and-ca-bundle | none |
| Audit (`audit.yaml`) | push main, daily cron, dispatch | audit | none |
| Release (`release-tarball.yaml`) | tag `v*`, dispatch | build, publish | none; deliberately no rust-cache |

Ruleset confirmed with `gh api repos/litehop/u7s/rulesets/18156794`: required
contexts are exactly `lint`, `test-coverage`, `fmt`, `script-tests`,
`e2e-focus 1.37.1`, `sensitive-e2e-guard 1.37.1`.

Trigger consequences per landed PR (one branch push assumed):

- `test.yaml` and `pki-rotation-e2e.yaml` run on every worker-branch push, again
  in the queue, and a third time on the push to main.
- `e2e-focus.yaml` runs on PR sync, in the queue, and on the push to main.
- The push-to-main run tests the same SHA the queue already tested. Verified
  with `gh run list --json headSha`: main push runs 41042499173 / 41039737106
  / 41039119811 have the same `headSha` as merge_group runs 41041728460 /
  41038453524 / 41038333966 (366e6dbc, 5553cf03, c9f830bb). The main run is a
  pure duplicate except for cache priming (section 3).
- The queue runs the whole set, so every required job runs at least twice per
  landing by design (PR head must be green to enqueue; queue re-tests the
  synthetic merge commit). Unverified: whether dropping the PR-level run of a
  required check is allowed by the ruleset; not tested.
- Queue regrouping reruns whole workflows: PRs 2046/2047 each got 2-3
  merge_group runs on 2026-10-30 (runs 41034720625, 41036596034, 41036597614,
  41036597590 ...) after a failure ahead of them.

## 2. Measured per-job timings

Sources: merge_group runs 41041728460, 41038453524, 41037089123, 41029322376,
41025682233 and main-push runs 41042499173, 41039737106 (Test); merge_group
runs 41041728451, 41038453499, 41037089105, 41029322365, 41025682257 plus 7
more merge_group runs for wall-clock, and PR runs (E2E focus); merge_group /
main runs 41038453512, 41041728555, 41042499134, 41039737263, 41037186215
(PKI). Seconds, from `gh run view --json jobs`; step splits from the same job
step records and, where steps are composite, from `gh run view --log` timestamps.

### Test workflow (n=7: 5 merge_group + 2 main push)

| Job | Range | Median | Critical path split (typical run) |
|---|---|---|---|
| lint | 85-115 | ~100 | setup 4, toolchain 9, rust-cache restore 4, clippy 87 (compile only, ~0 test), bead-id 1 |
| fmt | 19-24 | ~20 | toolchain 9-10, restore ~4, `cargo fmt` <2. The cache restore is wasted (119 MB) |
| script-tests | 189-218 | ~205 | toolchain 9, restore 3, **195 s running 84 bash scripts serially**; no cargo compile happens (log has no `Compiling`/`Finished`) |
| test-coverage | 226-352 | ~296 | toolchain 9, restore 9 (471 MB), llvm-cov install 1 (rust-cache `cache-bin`), compile 2m47 (apiserver ~2 min of it), test exec + report ~2m30, save 0 |
| release-invariants | 313-421 | ~405 | toolchain 9, restore 7, release compile 6m08 (apiserver crate alone 5m50), test exec 16 s |

Slowest script-tests entries (log timestamps, run 41041728460): kcm-supervisor
57 s, burst-gate 26 s, install-logic 12.7 s, sample-run-metrics 12.5 s,
mayor-tick 9.7 s, disruptive-pass 6.5 s. The rest are under 5 s. Serial run
floor if parallelised is therefore ~60 s.

Workflow wall-clock: 6m48 (the non-required release-invariants is the tail);
the required `test-coverage` finishes 5m41 after enqueue in that run.

### E2E focus workflow

| Stage | Range | Notes |
|---|---|---|
| `build` job, release-bin cache hit | 25-33 | hit only when the hash of all `crates/**` sources equals an entry saved by main; docs-only PRs |
| `build` job, miss | 397-471 (n=7) | toolchain 9, rust-cache restore 8 (465 MB, hit), **`cargo build --release` 7m10** (`lto="fat"`, `codegen-units=1`; `u7s-apiserver` compiles alone from 10:08:28 to 10:15:23), upload 7, bin-cache save 3 |
| `e2e-focus <k8s>` | 115-145 | per run 1.37.1 (run 41038453499): checkout 3, download binaries 4, kubelet/kubectl cache hit 2, cri-o/CNI/skopeo/conformance image installs and loads ~28, stack bring-up ~27, sonobuoy ~61 |
| `sensitive-e2e-guard <k8s>` | 7-10 | quick-succeeds; still `needs: build`, so it reports only after the build |

merge_group wall-clock of the whole workflow (12 runs, createdAt -> updatedAt):
171, 172, 241, 259, 490, 506, 571, 588, 614, 620, 620, 641 s. Median ~9m40.
4 of 12 were release-bin cache hits (<=4m19); 8 of 12 were cold builds
(8m10-10m41).

Merge-queue latency evidence: PR 2047 enqueued 10:07:46, merged 10:18:07 (10m21;
its e2e-focus run finished 10:18:06, build 7m48 cold). PR 2050 enqueued
10:06:49, merged 10:13:11 (6m22; e2e-focus hit, finished 2m52, `test-coverage`
was the binding check). PR 2051 enqueued 10:34:25, merged 10:40:42 (6m17;
`test-coverage` 5m41).

### PKI rotation workflow (not required; n=5)

| Job | Range | Notes |
|---|---|---|
| build | 390-536 | one step: `cargo build --release -p u7s-apiserver --features pki-test-knobs && ... -p u7s-scheduler` = 500 s; no release-bin cache; apiserver is built with fat LTO a second time (different feature set from the e2e-focus build) |
| suites | intermediate 85-90, leaf 69-72, leaf-scheduler 118-120, sa-key-and-ca-bundle 163-167 | scripts with real-time sleeps; floor is the longest suite |

Workflow wall-clock 9m22-11m47 (5 runs). Not on the queue path, but its
runners and cache traffic compete with the required jobs.

### Baseline in the bead (run 41203375594, PR #2053 round 1)

lint 1m50, fmt 20 s, script-tests 3m24, release-invariants 5m27, test-coverage
5m33, feature-tests 8m47 (clippy 146 s + tests 366 s; rust-cache step 0 s =
cold miss). PR #2053's later run 41204474289 shows feature-tests at 241 s
(13:11:56 -> 13:15:57) after its branch-scoped save-if saved a cache at
13:15:55, which is the expected cold-then-warm behaviour, not a like-for-like
comparison.

## 3. Cache behaviour

- rust-cache v2.9.3, `save-if: github.ref == 'refs/heads/main'` in every job.
  Key = `v0-rust-<job-id>-Linux-x64-<hash1>-<hash2>`; the job id is part of
  the key, so each job owns a separate cache (not shared). Example key from a
  test-coverage log: `v0-rust-test-coverage-Linux-x64-770ca156-342fe122`.
- Every sampled job reported "Cache hit ... full match: true" (test-coverage,
  script-tests, release-invariants, build); the third hash segment changes with
  `Cargo.lock`. Main re-saves only when that key is new (post-step cache save
  was 0 s on main run 41042499173), so the cached content is dependencies only;
  all 8 workspace crates recompile every time (visible as `Compiling u7s-*`
  in every log).
- Cache sizes (`gh api .../actions/caches`): build 465 MB, release-invariants
  473 MB, test-coverage 471 MB, lint 316 MB, fmt 119 MB, script-tests 119 MB.
  Each `Cargo.lock` change writes a new generation of all of them (seen:
  `...-ce245686`, `-a4faef5d`, `-b0e877d8`, `-b013126a`, `-342fe122` within
  ~10 h on 2026-10-30/31).
- Cache quota is exhausted: `actions/cache/usage` reports 10.67 GB active
  (89 entries) against the 10 GB repository limit, so GitHub evicts
  least-recently-used entries. Of that, 62 `release-bin-*` entries (46 MB
  each, one per source hash per ref scope) total 2.85 GB. Eviction of a
  `v0-rust-*` entry would cost a full dependency rebuild (not measured).
- `release-bin` cache (e2e-focus build only): key hashes all of `crates/**`
  `*.rs`/`Cargo.toml`/`*.proto`; the entry saved on a PR or queue ref is not
  readable from other refs, so a hit needs an entry written by a main push for
  an identical source tree. In practice only docs-only or non-crate PRs hit.
- A job added in a PR (e.g. `feature-tests`) starts cold and stays cold for
  every other branch until main saves its cache, because only main writes.
- Per-job fixed overhead on a warm cache: checkout 2-3 s, rustup toolchain
  install 9 s, rust-cache restore 3-9 s. About 15-20 s per job, negligible
  against compile except for fmt (20 s total) and script-tests.

## 4. Duplicate builds

Same crates compiled in different jobs/workflows (each warm-dependency
compile still rebuilds the workspace crates):

| Workload | Where | apiserver compile |
|---|---|---|
| dev check profile | lint | ~85 s (clippy) |
| dev test profile + coverage instrumentation | test-coverage | ~2 min of the 2m47 |
| release, fat LTO, cgu 1 | e2e-focus build | ~6m50 |
| release, fat LTO, cgu 1, `pki-test-knobs` | pki build | ~7-8 min (500 s total step) |
| release test binary, lto off, cgu 16 | release-invariants | ~5m50 |
| dev test profile, `rig-test-knobs,pki-test-knobs` (PR #2053) | feature-tests, plus a second clippy pass in lint | 146 s clippy cold in round 1 |

Profiles differ (opt level, LTO, instrumentation, features), so no artifact is
reusable across rows as-is. Two release-profile fat-LTO builds of the same
~330k-line crate (e2e-focus and pki-rotation) run on every PR/queue/main
trigger. `crates/apiserver` is one crate: its single compile unit sets the
floor of every job above, regardless of dependency caching.

## 5. Queue critical path

Required-check wall-clock after enqueue today:

- lint ~1m40, fmt ~20 s, script-tests ~3m25, test-coverage ~5m (4-6m).
- `e2e-focus 1.37.1` / `sensitive-e2e-guard 1.37.1`: build (7m50 cold, 35 s
  hit) + ~2m10 = ~10m cold, ~2m50 hit.
- Cold release build is on the critical path in ~2/3 of sampled runs; when it
  hits, `test-coverage` is the bound (5-6 min).

Long pole: `e2e-focus` `build` (cold fat-LTO apiserver). Second: `test-coverage`
(compile 2m47 + test/report 2m30). `script-tests` (3m25) is third but trivially
parallelisable. `release-invariants` (6m45) and PKI (9-12 min) are off the
required path but extend workflow wall-clock and consume runner capacity.

PR #2053 interaction: it adds a clippy pass with test-knob features to `lint`
(extra apiserver check compile; lint is ~1m40 against test-coverage ~5m, so no
queue latency change) and a non-required `feature-tests` job (cold 8m47, 241 s
once its branch cache exists). Under the ratchet, its steady-state cost is one
more cache key (~350 MB) against a cache that is already over quota.

## 6. Ranked options

Savings are estimates, not measurements, unless stated. "Queue" = effect on
merge-queue latency; "Minutes" = runner minutes per trigger.

| # | Option | Est. saving | Risk | Notes |
|---|---|---|---|---|
| 1 | CI-only build profile for the e2e-focus and PKI binaries (no fat LTO, cgu 16, opt-level 1-2, `debug=0`) | Queue -3 to -5 min on cold builds (7m to ~2.5-4m); Minutes -8 per trigger across both builds | Low-medium: the e2e binary no longer equals the shipped one; mitigate because release-invariants covers optimised frames and release-tarball builds the shipped binary. Unmeasured: needs `--timings` run in Phase 2 | Existing precedent: release-invariants already uses `lto=off`, `cgu=16` |
| 2 | Drop the push-to-main run of Test and PKI (and e2e-focus except the cache-priming build); keep `Cargo.lock`/toolchain-triggered cache priming | Queue 0; Minutes -40 to -45 per landed PR; frees runner concurrency; fewer cache writes | Low: verified identical SHA to the queue run. Loses release-bin hits for docs-only PRs unless the build is kept on main | Keep a main-only `build` (and `rust-cache` save) so the 33% docs-only hit path survives |
| 3 | Parallelise `script-tests` (`xargs -P4` over the discovered list) and drop toolchain + rust-cache from `fmt` and `script-tests` | script-tests 205 s -> ~65 s (floor kcm-supervisor 57 s); fmt/script-tests -12 s each; frees ~240 MB cache | Low-medium: scripts may share ports/temp dirs (port-squatter, kill-scope tests); needs a flake check | Not on the queue critical path today but is the third-slowest required job and becomes the bound once options 1 and 4 land |
| 4 | Trim `test-coverage`: `CARGO_PROFILE_DEV_DEBUG=0` (as PR #2053 does for feature-tests), measure the effect; consider 2-way nextest partition with merged llvm-cov profraw only if still the long pole | debug=0: unmeasured, expected tens of seconds of the 2m47 compile; partition: ~1-1.5 min but high complexity | debug=0: low. nextest partition + coverage merge: high | `cargo llvm-cov nextest --partition` needs per-shard `--no-report` + a merge job |
| 5 | Move `release-invariants` and (new) `feature-tests` out of the per-push path: run on merge_group only, or path-filter to `crates/apiserver/**`, `Cargo.*`, `profile` changes | Minutes -6.7 per PR-level run; workflow wall-clock tail 6m48 -> 5m41; one fewer ~470 MB cache | Low: non-required; regressions then surface at queue time (they still gate nothing) so decide whether they should become required | |
| 6 | Share one build for e2e-focus and PKI (single `build` job / one binary with `pki-test-knobs` env-gated, consumed by both) | Minutes -7 per trigger; queue 0 (jobs already parallel) | Medium: e2e-focus then tests a binary with test-only code compiled in; cross-workflow artifact reuse needs the workflows merged | Largely moot if option 1 lands (second build becomes ~3 min) |
| 7 | Shared rust-cache keys (`shared-key`) | Time ~0; cache footprint only | Low | Profiles differ across jobs (check / test+llvm-cov / release fat LTO / release lto-off), so deps are not shareable; the real fix is trimming (cache footprint section below) |
| 8 | Prune/trim caches: drop `fmt`/`script-tests` rust-cache, stop writing 46 MB `release-bin` entries from PR and queue refs (save only on main) | Avoids LRU eviction of the 470 MB dependency caches (a cold dep rebuild costs several minutes, unmeasured); -2.8 GB of the 10.67 GB | Low | `release-bin` save step is `if: cache-hit != 'true' && success()` on all refs today |
| 9 | sccache with the GHA backend | Expected ~0-20 s | Low-medium: new moving part, extra cache traffic against a full quota | Not recommended: the only expensive unit is the single apiserver crate, which changes in nearly every PR (sccache misses it), while dependencies are already restored by rust-cache; sccache cannot cache incremental compilation |
| 10 | cargo-nextest archive (build once, run elsewhere) | ~0 to -30 s on the queue path | Medium | The only jobs sharing a profile are test-coverage and (PR #2053) feature-tests, and they differ in features and instrumentation, so there is no common build to archive; nextest per-process overhead can slow the 5011 apiserver tests |
| 11 | Path filters (docs-only PRs skip Test/PKI/e2e builds) | Large for docs-only PRs (today ~1/3 of landings are docs/bookkeeping) | Medium: required checks must still report (use the sensitive-e2e-guard pattern: always run, quick-succeed); a plain `paths:` filter would deadlock the queue | Cheap variant: keep jobs but gate the heavy steps on a changed-files probe |
| 12 | Larger runners (4 -> 8/16 vCPU) | The apiserver crate compile is largely single-codegen-unit and fat-LTO serial, so expect little for option-1-style builds; dependency-heavy cold builds scale better | Cost: public repo has free standard runners, larger runners are billed | Do after 1-4; not the first lever |
| 13 | Make `sensitive-e2e-guard` not `needs: build` when no sensitive file changed | Queue 0 today (e2e-focus needs build anyway); saves ~7 min of idle wait | Low | Only matters once e2e-focus stops depending on build or the guard is read alone |

Expected combined queue effect of 1 + 3 + 4 (all estimates): e2e-focus workflow
~9m40 median -> ~5 min; required test jobs ~5 min -> ~4m30. The ~5 min target
is reachable only with option 1; without it the e2e build alone is above target.

## 7. Proposed follow-on beads (not filed)

In suggested order:

1. ci: add a CI-only cargo profile (no fat LTO, cgu 16, reduced opt, debug 0)
   and use it for the e2e-focus and PKI-rotation builds; record `--timings` and
   per-job deltas in the PR; confirm e2e-focus and PKI suites still pass.
2. ci: drop the push-to-main re-run of Test and PKI (keep a main-only e2e
   `build` + rust-cache priming) and confirm identical-SHA reasoning holds; also
   restrict `release-bin` cache writes to main.
3. ci: parallelise `script-tests` with `xargs -P` and remove toolchain and
   rust-cache from `fmt`/`script-tests` unless a test needs cargo; run a
   30-run flake check.
4. ci: `CARGO_PROFILE_DEV_DEBUG=0` for test-coverage (measure), then decide on
   a nextest + llvm-cov partition only if it remains the long pole.
5. ci: move `release-invariants` (and `feature-tests` after #2053) to
   merge_group-only or path-filtered runs.
6. ci: cache hygiene — quota is over 10 GB; set a retention approach for
   `release-bin` entries and revisit rust-cache keys/footprint per job.
7. ci: evaluate sharing one build between e2e-focus and PKI if #1 leaves the
   second build above ~3 min.
8. ci: docs-only fast path (always-report, quick-succeed) for required checks.
9. ci (investigate, larger): split `u7s-apiserver` (~330k lines, one compile
   unit) into crates to cut the per-job compile floor; high effort, high risk;
   measure only after the cheaper options land.
10. ci: price larger runners for the build jobs only if 1-4 leave the queue
    above target.

## 8. Not measured

- Actual compile time of the proposed CI profile; no experiment was run
  (CI-only changes, no workflow edits in this phase).
- Eviction frequency for `v0-rust-*` caches under the exceeded quota.
- Whether the ruleset allows dropping PR-level runs of required checks.
- Runner queue/provisioning delay (job `startedAt` is after provisioning).
- Per-step timing for the six uncited e2e-focus merge_group runs beyond job
  totals (counted for wall-clock only).
- Cost figures for larger runners.

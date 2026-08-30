# Dashboard
2026-08-29T14:55Z — Resume: `bd prime` → this file. **Session wrapped after 32 PRs merged (#1443 → #1474).**

**Stance:** pre-alpha/greenfield, break freely, merge-on-green via native queue, Rule 17 answer-first, `--admin` never. Discipline banked this session: dashboard non-auto sections update on every signal.

## 🏁 What this session accomplished

- **Wordpress-workload validation chain complete end-to-end** on `v0.2.1-snapshot.2` — fresh Ubuntu Lima QEMU-x86_64 VM → u7s install → csi-hostpath → MariaDB → WordPress + nginx sidecar → `curl` returns rendered HTML with DB write→read round-trip proven. 7m11s wall-clock.
- **11 code fixes shipped** across auth, RBAC, install path, and API-contract handling. `4ggk0`(SA-JWT-cache P0), `vamg1`+`nly97`(kubelet certDir), `u1g6k`(system:node PVC/PV/VolumeAttachment P0), `ilu9b`(test-only, main already fixed), `e78se`(SSA-create rbac_index P0), `l9oo0`(Secret stringData), `m7fxk`(system:node delete pods), `324jm`(SSA escalation + bootstrap-installer escalate).
- **Fix-and-reverify loop proven end-to-end.** mayor-nly97 catch (Phase 3 caught vamg1's silent no-op → filed → fixed → Phase 4 reverified with the identical repro recipe) — strongest evidence the process actually works.
- **Red-team + workload validation = complementary bug-finding.** Audit produced 2 P0s + 9 surface deep-dives; workload validation surfaced 5 more u7s bugs live that no test caught.

## 🎯 Next session — top of queue

1. **`mayor-tkv6j`** (P0, deferred all session) — `system:node` bound cluster-wide with no Node authorizer. Needs architectural approach (NodeRestriction admission / per-node subjects / doc-only). Related: shared admission bypass for bootstrap-labeled RBAC vs per-identity `escalate` grants (3 recurrences in `seed_rbac`). Both threads best solved together.
2. **`mayor-m6daz`** — release-tarball CI cache-restore fix. Root cause investigated + docs-verified this session: cache key includes `github.job`; no other workflow uses `build-and-publish`, so no main-branch cache exists under that key. Fix: `push: branches: [main]` trigger with `paths:` filter.
3. **RBAC-hardening follow-ons:** `x1x2u` (audit 4 unverified "Matches upstream" claims), `8tcqr` (SSA race-fallback tests), `gq4ip` (SSA ClusterRole/RoleBinding escalation tests), `5y8iz` (system:node create pods for mirror pods).
4. **`mayor-khb1z`** (P3) — kubectl get pvc/pv missing standard printer columns. Cosmetic.
5. **9 security-audit surface deep-dives** from mayor-s851y: livvs / ergg5 / qlgws / usjqk / zdaw8 / 0qjgc / vtq5n / lzd66 / c6njm.
6. **Wordpress untested territory** (Phase 4 flag): pod restart/rescheduling, node loss, multi-node Service routing.

## 📌 Standing decisions
- 9bwrc: `strict_required_status_checks_policy=false` deliberate.
- pwwql: reviewers answer "does this test the behaviour" by READING.
- v9jk0: tuning-first, Round-2 done — likely ceiling for this lever generation.

## 🧊 Longer queue (deferred, no-active-driver)
Legacy triage: 44jyu, xiovg (173 files). DEFER-with-trigger: sm91b.6, 1y0h6, 90qvg, ujqtt, tnzdi, t8ucq, 9xsn3, hm02b, bqncp, dry3v, nj2it, 2z1no, 8368x, c6njm. Golden-clone: gfcz9 (unblocked, not-this-focus).

## 🧠 Fresh bd memories from this session
- `snapshot-release-tarball-for-linux-testing-not-local-cross-compile` — use CI tarball, not local cross-compile.
- `macos-bash-3-2-case-inside-command-substitution-silent-truncation` — parameter expansion instead of case-in-substitution in shell test scripts.
- `mayor-discipline-update-dashboard-non-auto-sections-on-every-signal` — dashboard is source-of-truth; if not there, operator misses it.
- `kubelet-configuration-yaml-not-superset-of-cli-flags-silent-noop` — kubelet ignores unknown yaml keys silently; some settings are CLI-flag-only.
- `gh-app-review-payload-must-pipe-jq-directly-not-echo` — reviewer scripting pattern.

## 🔎 Open PRs
<!-- BEGIN AUTO: open-prs -->
None open.
<!-- END AUTO: open-prs -->
## 🌲 Worktrees
<!-- BEGIN AUTO: worktrees -->
None (no active worker worktrees).
<!-- END AUTO: worktrees -->
## 🔁 Cron loops
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->
## Repo state
<!-- BEGIN AUTO: repo-state -->
Branch `main` @ `29d78205`, dirty, up to date with origin/main.
<!-- END AUTO: repo-state -->

## 📋 Review queue
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->

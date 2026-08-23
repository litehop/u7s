# Dashboard
2026-08-23T15:56Z — `mayor-te5y0` in flight; `mayor-xm2zp` blocked (see decision point); queue idle. Resume: `bd prime` → this file.

Stance: pre-alpha/greenfield, no backward compatibility, break freely, merge-on-green.

## 🆕 Session-scope change (2026-08-23)
Repo moved from `valerauko/u7s` → **`litehop/u7s`** (organization). Main-branch ruleset ACTIVE (18156794) with strict status checks + Merge Queue (MERGE method, all-green grouping, min 1 / max 5). `allow_auto_merge=true` confirmed working end-to-end — all 4 PRs this session merged cleanly via `gh pr merge <N>` (bare, no flags) → queue.

## ▶ In-flight workers (0)
None. `mayor-xm2zp` still blocked (see decision point) — worktree left as-is, may resume once direction is picked.

## 🌊 Open PRs (1)
- **#1356** — `mayor-te5y0` checksum verification. Rigorous test verification: extracts real `install.sh` function at test time (not a reimplemented copy), bit-flip corruption test + a mutation test proving the test suite itself catches a broken implementation. Reviewed (not modified) `deploy/get-u7s/`'s routes, claims `.sha256` passes through unmodified. Critical-reviewer dispatched; CI running.

## 🎯 DECISION POINT
- **`mayor-xm2zp` BLOCKED — floating `dev` release tag is impossible as designed.** GitHub's immutable-release policy applies repo-wide (confirmed even on the real `v0.2.0-alpha.1`) — published release assets can never be overwritten, and deleting a release doesn't free its tag name (permanently burned). Worker's live testing confirmed this and, as an unavoidable side effect of testing, permanently burned the `dev` tag name on `litehop/u7s` (disclosed, test artifacts cleaned up). This retroactively affects `mayor-7kkhi`'s merged proxy (#1353), which assumes `releases/download/dev/<asset>` is a stable URL — it is not, and can't be recreated under that name. 3 options: (1) check if an org owner can disable immutable releases via GitHub's web UI — cheapest if it exists, unverified; (2) revert to live Releases-API querying for dev (mayor's original pre-simplification design, sidesteps immutability entirely, costs re-adding njs logic to the already-merged #1353); (3) host the rolling dev artifact outside GitHub Releases (proxy caches from a direct CI push instead) — cleanest long-term, biggest lift. Awaiting operator call.

## 📥 Handoff queue
- **mayor-ua9gg** (P2) — multi-node pod network has no CIDR coordination; needs a design decision (CIDR-coordination fix vs. CNI overlay) before dispatch.
- **mayor-72kil / mayor-lrpi2 / mayor-gkgg9 / mayor-po8qf / mayor-0fdes / mayor-tnzdi** — held pending operator nod.
- **mayor-fbxcy** (P3, CEL admission gap) — deferred by context; safe to dispatch as audit later.
- **mayor-o61zz** (P1, Lima ARP) — upstream-blocked; Phase A+B mitigations live.
- **Operator-held**: `mayor-u6ju` (EPIC), `mayor-t8ucq` (P4).
- **Not yet a bead**: tiny #1349 follow-on cleanup (bead-ID-in-comment + fail-loud-on-corrupt-token, both MED); #1354's 2 bead-ID-in-comment leaks (LOW) — worth batching into one small cleanup bead.

## ✅ Merged this session (9 PRs)
#1347 (portability), #1348 (CI release-tarball, x86_64), #1349 (kubeconfig-survives-restart fix), #1350 (real front-proxy headers, removed `admin_bearer_token`), #1351 (CSR spec-stamping security fix + RBAC seed), #1352 (front-proxy headers for discovery), #1353 (distribution reverse-proxy), #1354 (install.sh CSR-based join/rotation — Gate 6 multi-node milestone), #1355 (distribution-hosting ADR).

## 🔁 Cron loops (6, durable)
5m merge · 10m dashboard · 15m dispatch · 30m cluster-review · 60m hygiene · 60m reread. Persisted to `.claude/scheduled_tasks.json`.

## Repo state
Main @ `a0187adb`. Ruleset 18156794 ACTIVE, merge queue live and proven across 9 merges.

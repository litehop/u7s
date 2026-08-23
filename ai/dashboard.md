# Dashboard
2026-08-23T15:36Z — #1355 (ADR) QUEUED; `mayor-xm2zp` in flight. Resume: `bd prime` → this file.

Stance: pre-alpha/greenfield, no backward compatibility, break freely, merge-on-green.

## 🆕 Session-scope change (2026-08-23)
Repo moved from `valerauko/u7s` → **`litehop/u7s`** (organization). Main-branch ruleset ACTIVE (18156794) with strict status checks + Merge Queue (MERGE method, all-green grouping, min 1 / max 5). `allow_auto_merge=true` confirmed working end-to-end — all 4 PRs this session merged cleanly via `gh pr merge <N>` (bare, no flags) → queue.

## ▶ In-flight workers (1)
- **agent-te5y0** — `mayor-te5y0`: checksum verification for tarball downloads (sha256 sidecar + install.sh hard-fail on mismatch). Scoped strictly to the existing `v*`-tag path, explicitly avoiding the unresolved dev-channel question. Surface: `.github/workflows/release-tarball.yaml`, `scripts/install.sh`. `mayor-xm2zp` still blocked (see decision point) — worktree left as-is, may resume once direction is picked.

## 🌊 Open PRs (1)
- **#1355** — mayor-authored ADR PR (`operator/distribution-hosting-adr`, exempt from review queue). **QUEUED**.

## 🎯 DECISION POINT
- **`mayor-xm2zp` BLOCKED — floating `dev` release tag is impossible as designed.** GitHub's immutable-release policy applies repo-wide (confirmed even on the real `v0.2.0-alpha.1`) — published release assets can never be overwritten, and deleting a release doesn't free its tag name (permanently burned). Worker's live testing confirmed this and, as an unavoidable side effect of testing, permanently burned the `dev` tag name on `litehop/u7s` (disclosed, test artifacts cleaned up). This retroactively affects `mayor-7kkhi`'s merged proxy (#1353), which assumes `releases/download/dev/<asset>` is a stable URL — it is not, and can't be recreated under that name. 3 options: (1) check if an org owner can disable immutable releases via GitHub's web UI — cheapest if it exists, unverified; (2) revert to live Releases-API querying for dev (mayor's original pre-simplification design, sidesteps immutability entirely, costs re-adding njs logic to the already-merged #1353); (3) host the rolling dev artifact outside GitHub Releases (proxy caches from a direct CI push instead) — cleanest long-term, biggest lift. Awaiting operator call.

## 📥 Handoff queue
- **mayor-xm2zp** (P3, NEW) — extend release-tarball workflow to publish/overwrite a floating `dev`-tagged release on main-branch pushes (feeds `mayor-7kkhi`'s dev channel). **Critical detail**: must set `prerelease: true` on that release — GitHub's own `/latest/download/` resolution ignores tag names entirely and would silently start serving dev builds as "stable" if that flag is ever missing, regardless of what the tag is called.
- **mayor-72kil / mayor-lrpi2 / mayor-gkgg9 / mayor-po8qf / mayor-0fdes / mayor-tnzdi** — held pending operator nod.
- **mayor-fbxcy** (P3, CEL admission gap) — deferred by context; safe to dispatch as audit later.
- **mayor-o61zz** (P1, Lima ARP) — upstream-blocked; Phase A+B mitigations live.
- **Operator-held**: `mayor-u6ju` (EPIC), `mayor-t8ucq` (P4).
- **Not yet a bead**: tiny #1349 follow-on cleanup (bead-ID-in-comment + fail-loud-on-corrupt-token, both MED); #1354's 2 bead-ID-in-comment leaks (LOW) — worth batching into one small cleanup bead.

## ✅ Merged this session (8 PRs)
#1347 (portability), #1348 (CI release-tarball, x86_64), #1349 (kubeconfig-survives-restart fix), #1350 (real front-proxy headers, removed `admin_bearer_token`), #1351 (CSR spec-stamping security fix + RBAC seed), #1352 (front-proxy headers for discovery), #1353 (distribution reverse-proxy), #1354 (install.sh CSR-based join/rotation — Gate 6 multi-node milestone).

## 🔁 Cron loops (6, durable)
5m merge · 10m dashboard · 15m dispatch · 30m cluster-review · 60m hygiene · 60m reread. Persisted to `.claude/scheduled_tasks.json`.

## Repo state
Main @ `694d1a42`. Ruleset 18156794 ACTIVE, merge queue live and proven across 8 merges.

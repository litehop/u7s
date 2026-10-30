---
updated: 2026-10-30T10:25Z
---
# Dashboard — session 2026-10-30 WRAPPED (main `5553cf03`)
**Stance:** pre-alpha, no existing users; Conformance correctness > security > perf > features; match upstream 1.37.1 except secure defaults for weak crypto (never hand-roll it); queue merge on green, never `--admin`.
**Resume:** `claude --settings .claude/settings.json`; paste `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register crons. Read `ai/extended-context/` (release-gate, dual-stack, L7). No workers, VMs or GCP VMs running.

## 🎯 Waiting on you
- **`yfca9` MariaDB first init on cold GCP disk** — gate still FAILs (d): entrypoint's temp-server wait expires on pd-standard. A config only: lift CPU limit + small-node InnoDB init settings (mayor rec) / B marker-gated init recovery / C both. Blocks `vw7jc` and the `i4bvb` burst A/B.

## 📝 Decided 2026-10-30
- Gate: no pre-pull/sequencing; pd-standard stays; snapshot cuts and publish approval are operator-only.
- Memory: protect control-plane units (`i4bvb`, #2039 draft); size ~160Mi/~136Mi pending burst A/B.
- Crypto: aws-lc-rs only, RSA ≥ 2048. L7: Traefik; TLS later via cert-manager. CSR chain kept (ADR).
- Dual-stack epic `8w6at`: GCP subnet `u7s-test` now IPV4_IPV6 (one-way); beep work in beep tracker.

## ⏭ First dispatches
1. `yfca9` once decided → GCP gate run → `i4bvb` A/B with bursts (alternate arms, experiment mode).
2. Dual-stack: `8w6at.7` manifests · `8w6at.13` worker v6 forwarding · `rv1aw` · #2045 verify on a workers-a pair (not lima-node-5: `0k4i8`).
3. P2 follow-ons: `jb3ly` PriorityClass parity · `8atzp` CI feature tests · `okr7g` node CSR without openssl.

## 🔎 Open PRs
#2039 (draft, `i4bvb`) · #2045 (draft, `8w6at.11`) · #2030 Renovate.

## ✅ Merged 2026-10-30
25 PRs, #2023–#2050 (`git log --merges 0bf3bb79..5553cf03`).

<!-- BEGIN AUTO: open-prs -->
#2039 · #2045 · #2030
<!-- END AUTO: open-prs -->
<!-- BEGIN AUTO: worktrees -->
Two kept for draft PRs (#2039, #2045).
<!-- END AUTO: worktrees -->
<!-- BEGIN AUTO: cron-loops -->
Stopped at wrap.
<!-- END AUTO: cron-loops -->
<!-- BEGIN AUTO: repo-state -->
`main` @ `5553cf03`.
<!-- END AUTO: repo-state -->
<!-- BEGIN AUTO: review-queue -->
0 pending.
<!-- END AUTO: review-queue -->

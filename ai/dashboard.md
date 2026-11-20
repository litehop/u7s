---
updated: 2026-11-20T13:32Z
---
# Dashboard — session 2026-11-20 closed (main `9115c5b7`) — v0.4.7 released
**Stance:** alpha (no compat promise); correctness > security > perf > features; upstream 1.37.1 except secure crypto; queue merge on green, never `--admin`; security PRs drafted for operator; every release gated (agent runs burst + upgrade gates, operator pushes tags + approves publish).
**Resume:** paste `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register crons; `bd recall rig-install-tested-setup-must-be-identical`; `bd show mayor-qqy20`.

## 🎯 Waiting on you
Nothing blocking.

## ⏭ Next session — start here
- **Epic `qqy20` (P1): rig ≡ install tested setup** (operator 2026-11-20: scripts may differ, configs identical; only userspace additions). First: re-audit divergences vs main, file one child each. Children: `r2omk` derive flags/units from install.sh · `3myx0` CI e2e-focus parity · `azbbb` SIGHUP apply + per-node NIC · `06ha8` 2-node `--install` via `install.sh --join`.
- Conformance open: `odx0m` DNS ExternalName (dig `file_inherit`) · `1f8g4` GRPC liveness flake · `neeru` webhook flake.
- Ready backlog: `hjwdo.2` `hjwdo.3` `0slxf` `ge3we` `n0k1e` `73u2w` `500n2` `ub445` `qwf1z` (note: run-all.sh:672 desired=0 blocker).
- 10 beads were already in_progress before this session (`lwwze` `b6c59` `rdy7h` `83irk` `qap3i.35` `1xpj7` `xdw6u.11` `p3ktl` `l2imr` `ynfzk`) — triage stale claims.

## Conformance (final, 2026-11-20)
`--install` (real install.sh, kernel 7.0.0-43) **458/462** (453 at start of day); host rig 459/462. Failing: `06ha8` ×2 (needs 2 nodes), `odx0m`, `1f8g4` flake. Archives `temp/e2e/{o5frl-full-host-rig,h2fqc-full-install,final-install}-20261120/`.

## Decided today (detail in bead notes / PR bodies)
- Upgrade: step-through policy documented; untested rollback cut, then re-added verified (archive 0600). Node names >63 breaking (CHANGELOG only).
- PQ TLS: keep classical clients; fail startup if default provider not PQ-first.
- Rig-only add-ons + AppArmor dig/nslookup setup (u7s-default rule + host overrides) applied in both rig modes; install.sh unchanged. Kubelet gates are GA in 1.37 (not rig-only).
- CRI-O AppArmor stacked-peer issue posted upstream (kernel 7.0.0-43/-44 stack; -34 doesn't).

## ✅ merged this session (27)
#2216 rig AppArmor both modes · #2215 DeleteOptions.preconditions · #2214 rig flag parity + leftover units · #2213 flannel hash by key · #2212 renovate · #2211 JSON-Patch RV pin + pinned deletes · #2210 rig full manifests + kube-proxy DS · #2209 per-slot tunnel kill · #2208 rig-only add-on docs · #2207 status/scale template parity · #2206 `run-all.sh --install` · #2205 node-name ≤63 · #2204 one GuaranteedUpdate write path · #2203/#2199/#2194/#2193 upgrade guide · #2202 PQ TLS · #2201/#2197 label + webhook validation · #2200 flannel MTU roll · #2198/#2195 Service reservations · #2196 SIGPIPE · #2192/#2191 renovate.

<!-- BEGIN AUTO: open-prs -->
None open.
<!-- END AUTO: open-prs -->
<!-- BEGIN AUTO: worktrees -->
None (no active worker worktrees).
<!-- END AUTO: worktrees -->
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->
<!-- BEGIN AUTO: repo-state -->
As of 2026-11-20T13:31:39Z (last tick) — Branch `main` @ `9115c5b7`, dirty, up to date with origin/main.
<!-- END AUTO: repo-state -->
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->

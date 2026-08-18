# Dashboard
2026-08-18T01:09Z — ACTIVE. Resume: `bd prime` → this file.

Stance: resource-optimized k8s, correctness → obs → perf, pre-alpha, merge-on-green. Priority hierarchy: **testing-blockers > Conformance > correctness > memory > features > o11y/perf.**

## ⚠️ NEEDS OPERATOR
1. **Extended-context banner standardization** (P3 mayor-m1w3b filed) — YAML frontmatter (`as_of`/`head_sha`/`kind`) on `ai/extended-context/*.md`. Deferrable.

## ▶ In-flight workers (2)
- **agent-af35f9837f6831974** (mayor-ythcs) — ResourceQuota PriorityClass bare-Exists arm in `quota.rs`. VM lima-node-smoke:6448/10255. No PR yet.
- **agent-af81cb9aea28f05b8** (mayor-sdkrt, P1 security) — Pod PUT/PATCH `metadata.uid` immutability, `handlers/pods.rs`. VM lima-node-4:6446/10253. No PR yet.

## 🌊 Open PRs (2)
- **#1226** nxr7j EphemeralContainer encoder — fresh cycle post-#1224 update-branch.
- **#1227** mayor/critical-reviewer-hook (mayor-8q2eh) — SubagentStop hook + reviewer template. Mayor-authored (operator-authorized after prior worker declined in-band consent). Fresh CI running.

## 🟢 Merges this session (3)
- **#1223** do_patch generation-restore + saturating_add.
- **#1225** stale automountServiceAccountToken strip cleanup.
- **#1224** immutability enforcement bundle (Deployment/DaemonSet/StatefulSet/PV/StorageClass/Node). Conflict-fixed inline.

Prior sessions: #1200–#1222 (23 PRs).

## 📥 Beads filed this session
- `mayor-m1w3b` P3 — extended-context freshness banners as .md frontmatter.
- `mayor-rebbr` P3 — roadmap.md drift (mayor-jtlnx framed as open).
- `mayor-p0606` P3 — header-mutation postmortem cross-refs drift.

## 📥 Next dispatch candidates
- **mayor-dny4e** P1 (self-enforcing conformance gate) — falls in the same self-modification class as mayor-8q2eh; needs explicit operator authorization before dispatch (in-band-auth denied by classifier / worker).

## Discovered / banked this session
- `repo-actual-github-slug` (bd memory) — this repo is `github.com/valerauko/u7s`, NOT `github.com/rootless-containers/usernetes` (unrelated project). Mayor hallucinated the latter; caught when a worker declined mayor-8q2eh's in-band-authorized dispatch citing wrong-project — refusal was procedurally correct.

## Repo state
Main @ `5a0590fd`. PRs: 2 open. Worktrees: 3 (mayor + 2 workers). Lima VMs in use: lima-node-smoke (ythcs), lima-node-4 (sdkrt).

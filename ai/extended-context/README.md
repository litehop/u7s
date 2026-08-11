# Extended Context

Durable project knowledge that a fresh mayor would not infer from the code alone.

Each file should be structured like an AI Skill: front matter describing scope, then a body with the insight.

| File | Contents |
|------|----------|
| [project-stance.md](project-stance.md) | Project posture, constraints, merge policy, and worker preamble to inject in every dispatch |
| [project-context.md](project-context.md) | u7s technical context: goals, target environment, settled decisions, current phase |
| [roadmap.md](roadmap.md) | Phase roadmap — goals, milestones, exit criteria, deferred items per phase |
| [apiserver-code-gotchas.md](apiserver-code-gotchas.md) | Non-obvious apiserver correctness constraints that have bitten conformance (KCM panic propagation, read-time defaults on watch init, exec param translation, CSINode gap) |
| [memory-management-state.md](memory-management-state.md) | Snapshot of memory-management state: allocation hotspots, known issues, low-hanging fruit, highest-leverage changes, diagnostic playbook. AS-OF dated, refreshed weekly by mayor-rr177's cron |
| [mayor-handoff-2026-08-11-close.md](mayor-handoff-2026-08-11-close.md) | Session handoff — 2026-08-11. Proto-descriptor oracle initiative completed; KCM-protobuf-flip investigation arc closed. 18 PRs merged, 35 beads closed. |

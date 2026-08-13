# Extended Context

Durable project knowledge that a fresh mayor would not infer from the code alone.

Each file should be structured like an AI Skill: front matter describing scope, then a body with the insight.

| File | Contents |
|------|----------|
| [project-context.md](project-context.md) | u7s technical context: goals, target environment, settled decisions, current phase |
| [north-star.md](north-star.md) | u7s's durable north star, decision framework, and guiding principles for component build-vs-delegate decisions — operator sign-off required to change |
| [roadmap.md](roadmap.md) | Current state and priorities: component matrix, gates, standing initiatives — changes often, links back to north-star.md rather than restating it |
| [apiserver-code-gotchas.md](apiserver-code-gotchas.md) | Non-obvious apiserver correctness constraints that have bitten conformance (KCM panic propagation, read-time defaults on watch init, exec param translation, CSINode gap) |
| [memory-management-state.md](memory-management-state.md) | Snapshot of memory-management state: allocation hotspots, known issues, low-hanging fruit, highest-leverage changes, diagnostic playbook. AS-OF dated, refreshed weekly by mayor-rr177's cron |
| [mayor-handoff-2026-08-11-close.md](mayor-handoff-2026-08-11-close.md) | Session handoff — 2026-08-11. Proto-descriptor oracle initiative completed; KCM-protobuf-flip investigation arc closed. 18 PRs merged, 35 beads closed. |

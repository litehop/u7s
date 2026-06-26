# Extended Context

Durable project knowledge that a fresh mayor would not infer from the code alone.

Each file should be structured like an AI Skill: front matter describing scope, then a body with the insight.

| File | Contents |
|------|----------|
| [project-stance.md](project-stance.md) | Project posture, constraints, merge policy, and worker preamble to inject in every dispatch |
| [project-context.md](project-context.md) | u7s technical context: goals, target environment, settled decisions, current phase |
| [roadmap.md](roadmap.md) | Phase roadmap — goals, milestones, exit criteria, deferred items per phase |
| [apiserver-code-gotchas.md](apiserver-code-gotchas.md) | Non-obvious apiserver correctness constraints that have bitten conformance (KCM panic propagation, read-time defaults on watch init, exec param translation, CSINode gap) |

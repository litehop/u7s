---
as_of: 2026-08-18
kind: index
---

# Extended Context

Durable project knowledge that a fresh mayor would not infer from the code alone.

Each file should be structured like an AI Skill: front matter describing scope, then a body with the insight.

| File | Contents |
|------|----------|
| [project-context.md](project-context.md) | u7s technical context: goals, target environment, settled decisions, current phase |
| [north-star.md](north-star.md) | u7s's durable north star, decision framework, and guiding principles for component build-vs-delegate decisions — operator sign-off required to change |
| [roadmap.md](roadmap.md) | Current state and priorities: component matrix, gates, standing initiatives — changes often, links back to north-star.md rather than restating it |
| [apiserver-code-gotchas.md](apiserver-code-gotchas.md) | Non-obvious apiserver correctness constraints that have bitten conformance (KCM panic propagation, read-time defaults on watch init, exec param translation, CSINode gap) |
| [memory-management-state.md](memory-management-state.md) | Snapshot of memory-management state: allocation hotspots, known issues, low-hanging fruit, highest-leverage changes, diagnostic playbook. AS-OF dated; audited weekly by mayor-rr177's cron (audit-only — files drift beads, never edits the doc's content) — actual refreshes are manual or by a dispatched worker |
| [project-priority-hierarchy.md](project-priority-hierarchy.md) | Operator's bucket-ordered priority framework for bead triage and dispatch order (testing-blockers > conformance > other correctness > memory-usage > new features > o11y/perf polish) |
| [e2e-focus-conformance-image-pull-postmortem-2026-08-25.md](e2e-focus-conformance-image-pull-postmortem-2026-08-25.md) | Postmortem: `e2e-focus.yaml` CI timeouts caused by CDN edge-cache misses on infrequently-pulled conformance-image tags, not a code regression |

## Frontmatter convention

Every file in this directory carries YAML frontmatter with two required fields:

```yaml
---
as_of: 2026-08-18
kind: gotchas
---
```

- **`as_of`** — the date the doc's content was last verified accurate, not
  necessarily the date of the file's last edit. This is the single field
  the weekly freshness audit (`mayor-rr177`) reads, instead of scanning
  free-text dates scattered through the body.
- **`kind`** — one of:
  - `index` — a table-of-contents doc (this file).
  - `principles` — durable decision framework / north star; changes
    rarely, needs explicit operator sign-off (`north-star.md`).
  - `roadmap` — current state and priorities; changes often, treat numeric
    claims as dated (`roadmap.md`).
  - `project-state` — founding technical context: goals, constraints,
    settled decisions (`project-context.md`).
  - `initiative-state` — a snapshot of an in-flight initiative's state
    (hotspots, known issues, diagnostic playbook), refreshed periodically
    as the initiative progresses (`memory-management-state.md`).
  - `gotchas` — non-obvious code-level correctness constraints; individual
    entries may be marked historical/fixed, but the doc as a whole has no
    single freshness moment (`apiserver-code-gotchas.md`).
  - `postmortem` — an incident writeup. **`as_of` here is the incident
    date, not a freshness claim** — the audit workflow excludes
    `kind: postmortem` docs from ongoing drift checks, and only re-audits
    one if its own "Cross-references" section is edited (e.g. a follow-on
    bead cited there closes).

**Audit workflow:** read `as_of`, then `git log --since=<as_of> -- <doc-relevant-paths>`
to surface landings that could have obsoleted a claim in the doc. `head_sha`
is deliberately NOT part of this frontmatter — it would duplicate
`git log -1 --format="%H" -- <file>`, which already gives the authoritative
last-modified SHA with no maintenance overhead and no risk of drifting out
of sync with the file it describes.

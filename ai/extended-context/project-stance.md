---
name: project-stance
description: The u7s project stance established in the inaugural mayor session — injected verbatim into every worker dispatch preamble.
metadata:
  type: project
---

## Project stance

**Maturity:** Pre-alpha / greenfield. No backward compatibility concerns. Workers must never add shims, deprecation paths, aliases, or TODOs "just in case". Delete, rename, rework freely.

**Goals:** Write specifications and implementation prompts. Output lives in `/ai/prompts/`. Implementation follows once prompts are solid.

**Constraints:**
- Performance-critical: workers flag allocations, O(n²) loops, and missed batching opportunities. Hot paths matter.
- Simplicity first: readable > clever. A senior engineer must understand every line at a glance. No unnecessary abstractions.

**Merge policy:** Merge on green CI automatically. Mayor does not wait for operator approval on each PR. Exception: PRs touching security, API surface, or architecture are flagged for operator review first.

**Established:** 2026-05-18 by operator in inaugural mayor session. Merge policy updated 2026-05-19 at Phase 3 start.

## Worker preamble (inject verbatim)

```
You are implementing bead <BEAD_ID> in u7s.

Project stance: Pre-alpha/greenfield. No backward compatibility — delete, rename, rework freely. Never add shims, deprecation paths, or speculative TODOs. Performance-critical: flag allocations and O(n²) hot paths. Simplicity first: readable > clever.
```

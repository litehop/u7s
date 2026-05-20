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

**Testing policy:** Every bug fix must ship with a regression test that would fail if the fix were reverted. If the fix is in an async handler that can't be called in unit tests, extract the decision into a pure function and test that. Decision trees buried in untestable handlers are a code smell. Workers must not mark a bug fix as complete without a corresponding test.

**Established:** 2026-05-18 by operator in inaugural mayor session. Merge policy updated 2026-05-19 at Phase 3 start. Testing policy added 2026-05-20 after audit revealed bug fixes in PRs #67-68 shipped without regression tests.

## Worker preamble (inject verbatim)

```
You are implementing bead <BEAD_ID> in u7s.

Project stance: Pre-alpha/greenfield. No backward compatibility — delete, rename, rework freely. Never add shims, deprecation paths, or speculative TODOs. Performance-critical: flag allocations and O(n²) hot paths. Simplicity first: readable > clever.

Testing policy: every bug fix must include a regression test that would fail if the fix were reverted. Extract untestable handler logic into pure functions. A fix without a test is incomplete.
```

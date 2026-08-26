---
as_of: 2026-08-17
kind: principles
---

# Project priority hierarchy

Operator direction (2026-08-17) for triaging beads, choosing dispatch order, and
framing decision points. Complements `north-star.md` (the underlying
memory-primary, correctness-first philosophy) and `roadmap.md` (the gate-by-gate
framework this integrates with) rather than restating either.

## The buckets, in order

1. **Issues blocking testing** — anything that prevents conformance/test runs
   from happening at all: Lima/VM infra defects, CI infra breakage, VM sizing,
   sandbox/tooling regressions. Rationale: without a working test harness nothing
   below can be verified. These are unblockers.
2. **Conformance** — fixes that keep the sonobuoy Conformance suite passing,
   including both regressions and known-open gaps. Rationale: "a clear
   conformance result is the solid footing we can work from."
3. **Correctness not covered by Conformance** — bugs found via audits,
   representative workloads, non-Conformance-tagged upstream e2e subsets, or
   independent reasoning. Conformance has known blind spots (single-node bias);
   these still count as correctness.
4. **Major memory-usage improvements** — substantive perf wins that meaningfully
   move the founding <128 MiB idle control-plane goal (see `north-star.md` and
   `project-context.md`).
5. **New features** — adding API surface u7s doesn't yet implement. Should be
   evidence-driven (e.g. a representative-workload gap), not speculative.
6. **o11y / profiling / other performance improvements** — dashboards, metrics
   wiring, minor perf tuning, build-perf work. Improves developer/operator
   experience but doesn't move core project targets directly.

## Application

- Dispatch triage: within the ready queue, sort by which bucket a bead falls
  into. A P3 in bucket 1 outranks a P1 in bucket 6.
- Decision-point framing: when surfacing a decision to the operator, note which
  bucket the item falls into.
- New bead priority (P1-P4) should reflect the bucket's importance AND the
  bead's magnitude within it — a tiny bucket-1 fix might be P2; a huge bucket-6
  rewrite might be P3.
- Tie-break within the same bucket: (a) blocking status of other work, (b)
  recent operator focus / stated goals, (c) size (small-and-obvious first for
  velocity).

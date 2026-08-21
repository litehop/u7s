# <The thing chosen, stated plainly — not "ADR-013" or "a decision about X">

**Status:** Accepted
**Date:** YYYY-MM-DD

## Context

What forced a choice. Two or three sentences. State the constraint that
exists now, not how the project arrived at it — git already records that.

## Decision

What was chosen, present tense, specific enough to act on. If several
components each got a different answer, one bullet each.

## Rationale

The evidence that decided it: numbers, measurements, file references.
`crio-over-containerd.md` is the model — "containerd spawns a persistent
shim per pod sandbox, 5–10 MB RSS each; on a 20-pod node that is 100–200 MB."
**If a sentence argues rather than measures, cut it.** An ADR records what
was decided and what settled it, not a debate with an imagined objector.
Where nothing was measured, say the decision was a judgment call and name
the principle it applied — that is shorter and more honest than manufacturing
justification.

## Consequences

What is true now that was not before, and what this forecloses. Three or
four bullets. A bullet that restates the Decision in other words is not a
consequence.

---

**Budget: 400 words**, enforced by `scripts/check-doc-budget.sh` (words, not
lines — reflowing does nothing). The ADRs worth copying sit well under it:
`crio-over-containerd.md` 225, `webhook-tls-via-konnectivity.md` 235,
`sqlite-over-lmdb.md` 263. Replace this footer along with the guidance above.

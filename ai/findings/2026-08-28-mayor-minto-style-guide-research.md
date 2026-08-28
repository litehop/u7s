Bead: mayor-r4mza

# Minto Pyramid Principle — Style Guide Recommendations for the Mayor Method

## Recommendation

Add one rule: every artefact written for another agent to read cold — bead
note, PR body, dashboard entry, findings doc, worker brief — must open with a
single-sentence answer or decision (Minto's governing thought / BLUF) before
any evidence, mechanism, or chronology. This is the single highest-leverage
Minto import for this project.

## Why

Our artefacts already lead with evidence, out of Rule 12's fail-loud
instinct — but evidence-first is not answer-first. `mayor-9bwrc`'s bug
description opens "VERIFIED 2026-08-28T05:00Z via gh api…" and states the
doc's false claim; the actual resolution ("fix the DOC, not the ruleset")
doesn't appear until a `## RESOLVED` note roughly 30 lines later. A future
agent reopening that bead, or a mayor skimming it mid-tick, has to read the
full evidentiary trail before learning what was decided. Minto's core
discipline is exactly this failure mode's fix: discover bottom-up, present
top-down.

## Concrete adoptions (by leverage)

1. **Answer-first opening line.** The first line of any bead note, PR body,
   finding, or dashboard entry states the verdict/decision; evidence
   follows. From: Answer-first / governing thought. Lives in: CLAUDE.md, new
   clause on Rule 16 ("Prose Is Code") — a paragraph that doesn't state its
   own conclusion first is unfinished, same as an unstated WHY today.
   Example: `mayor-9bwrc`'s RESOLVED note would open "Fix bootstrap.md, not
   the ruleset — `strict_required_status_checks_policy=false` is
   deliberate," before the operator-observation evidence that currently
   opens it.

2. **Reorder bug/audit descriptions: Answer, then S-C-Q.** Bug bead
   descriptions and Shape-3 audit docs already show clean
   Situation-Complication-Question structure (see `mayor-3ic7d`: "MEASURED…"
   / "The gap" / "Why this matters") but never promote the Answer above it.
   From: SCQ(A), reordered per Minto's top-down presentation rule. Lives in:
   `dispatch-prompt-template.md`, Shape 3. Example: prefix `mayor-3ic7d`'s
   description with "Extend `reconcile_missing_queue_entries` to also queue
   a re-review when a blocking verdict is followed by a later commit"
   before the MEASURED evidence.

3. **MECE gate on severity tags.** An audit's HIGH/MED/LOW/DEFER tagging
   must be mutually exclusive and collectively exhaustive — a finding
   needing two tags gets split into two findings, not double-tagged. From:
   MECE grouping test. Lives in: `dispatch-prompt-template.md` Shape 3, the
   "Severity tags" bullet under "Critical learnings."

4. **Name vertical logic explicitly in Shape 1/6.** Each brief section
   (context → steps → quality gate → push) must answer the question the
   prior section provokes in the worker's head; name this explicitly so
   future edits to the Shapes preserve the ordering instead of reshuffling
   for narrative flow. From: vertical logic (Q&A dialogue between pyramid
   levels). Lives in: `dispatch-prompt-template.md`, Shape 1 preamble.

## What NOT to adopt

- **SCQA's civility framing.** Minto's Situation is scene-setting to earn a
  skeptical executive's attention; our readers are agents that already have
  repo context. Codifying "establish uncontroversial context first" would
  fight Rule 16's ban on restating what a linked doc already says.
- **Rule-of-three grouping.** Minto favors 2-3 supporting groups per level.
  Our findings and steps vary in count (1 to 7+); forcing artificial 2-3
  buckets would misrepresent audits that don't cluster that way.
- **Full-sentence pyramid headings everywhere.** Minto insists every heading
  is a complete sentence, not a noun label. Applying that below the top
  BLUF line would collide with our compact severity tags, emoji dashboard
  markers, and `file:line` citations — keep the sentence discipline at the
  top line only.

## Alternatives considered

Considered mandating full SCQA section labels (Situation/Complication/
Question/Answer headers) in every artefact — rejected as too heavy a
structural tax on artefacts that are already dense and technical; a single
answer-first sentence captures most of the benefit (immediate visibility of
the governing thought) without four new mandatory headers per bead note.

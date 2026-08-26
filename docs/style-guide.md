# Docs Style Guide

Governs future user-facing docs — README, install guides, and other docs
written for people setting up or operating u7s. It does not require
rewriting docs that already exist; apply it going forward and whenever an
existing doc is next substantially edited.

Base: [Google's developer documentation style guide](https://developers.google.com/style).
This distills the subset that matters for a small infra project into
u7s's own voice.

Agents read and maintain these docs at least as much as humans do.
Machine-parseable structure — fenced code blocks, numbered steps,
consistent headings — is load-bearing here, not a nicety: it is what
lets an agent parse and safely edit a doc without misreading its
structure.

## Rules

1. **Second person.** Write "you configure the node agent," not "the
   operator configures the node agent" or "developers can configure."
2. **Active voice.** "The scheduler binds the pod," not "the pod is
   bound by the scheduler."
3. **Present tense.** Describe what the system does now, not what it
   will or would do. Reserve "will" for ADR consequences, not
   how-to docs.
4. **Short, single-purpose sentences.** One claim per sentence. Split
   compound sentences joined by "and" or "which" when each half stands
   alone.
5. **One term per concept, everywhere.** Pick a single name for each
   thing — e.g. "state store," not "etcd," "database," and "backing
   store" interchangeably — and use it in every doc.
6. **Fence every code and CLI example, with a language tag.** Never
   inline a command or config snippet in prose; use ` ```bash `,
   ` ```yaml `, or ` ```rust ` as appropriate.
7. **Numbered lists for procedures.** Any sequence a reader executes
   step by step is a numbered list, never narrative prose.
8. **Consistent heading hierarchy.** Do not skip levels (no `####`
   directly under `##`). A heading's children sit exactly one level
   down.
9. **Prescriptive phrasing.** "Create the namespace before deploying,"
   not "some operators create the namespace first."
10. **Depart from any rule above when it makes a doc clearer.** These
    are defaults, not a lint gate — judgment beats mechanical
    compliance.

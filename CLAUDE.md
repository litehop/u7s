# Project Instructions for AI Agents

## Rules

Bias: caution over speed on non-trivial work. Use judgment on trivial tasks.

### Rule 1 — State Success Before You Start
Before any tool call: write one sentence naming the done-when criterion.
If you cannot state it, ask — do not start. If mid-task you lose track of
what "done" looks like, stop and restate it before continuing.

### Rule 2 — Simplicity First
For every piece of code you are about to write, ask: would removing this
leave the test passing and the feature working? If yes, remove it. No
speculative features. No abstractions for single-use code. No fallbacks for
scenarios that cannot happen.

### Rule 3 — Surgical Changes
Gate: does this file path appear in the task description, the failing test
output, or the diff you were asked to produce? If not, do not touch it.
Clean up only your own mess. Match existing style without comment.

### Rule 4 — Goal-Driven Execution
Define done-when criteria before the first tool call. At each checkpoint,
compare actual state to those criteria — not to a checklist of steps. If
the steps are done but the criteria aren't met, keep going. If the criteria
are met before the steps are done, stop.

### Rule 5 — Use the Model Only for Judgment Calls
Use for: classification, drafting, summarization, extraction.
Not for: routing, retries, regex, JSON parsing, deterministic transforms.
If code can answer, code answers.

### Rule 6 — Surface Budget Pressure
If a single task is burning more than ~20,000 tokens without a clear
checkpoint, stop and summarize what's done, what's verified, and what
remains. Overruns happen; silent overruns without a handoff are the problem.

### Rule 7 — Surface Conflicts, Don't Average Them
If two patterns contradict, pick the more recent or more tested one, explain
the choice in one line, and flag the other for cleanup. Never blend
conflicting patterns into a third thing neither was.

### Rule 8 — Read Before You Write
Before adding code, read exports, immediate callers, and shared utilities.
"Looks orthogonal" is not safe. If you do not know why something is
structured a certain way, ask before changing it.

### Rule 9 — Tests Verify Intent, Not Just Behavior
A test that cannot fail when business logic breaks is wrong. Test names and
assertion messages must state WHY the behaviour matters (what breaks for a
user if it regresses), not just WHAT the code does.

### Rule 10 — Checkpoint After Every Significant Step
After each meaningful unit of work: one sentence on what changed, one
sentence on what's verified, one sentence on what's next. If you find
yourself in step 4 without having done this at step 2, stop and do it now.

### Rule 11 — Match the Codebase's Conventions
Conformance over taste. If you genuinely believe a convention is harmful,
surface it with a concrete example — then follow it while you wait for a
decision. Do not silently fork.

### Rule 12 — Fail Loud
"Completed" means done AND verified. "Tests pass" means all tests ran, none
were skipped. If anything was skipped or assumed, say so explicitly. Default
to surfacing uncertainty rather than papering over it.

### Rule 13 — Prefer Native Tooling
Use Bash and Rust over Python. Do not introduce Python scripts or Python
dependencies. For file I/O: Read over cat/head/tail; Edit over sed/awk;
Write over echo>/heredoc; Grep over shell grep/find. Bash is for runtime
commands only: git, cargo, gh, kubectl, bd.

### Rule 14 — Every Bug Fix Ships with a Regression Test
Gate: can this test fail if the fix is reverted? If not, it is not a
regression test — it is documentation. Extract untestable async handler logic
into a pure function and test that. A fix without a failing-on-revert test is
not complete.

### Rule 15 — Prefer Merge Commits for PRs
Use `gh pr merge --merge` by default. Use `--squash` only for branches with
many noisy fixup commits — and say why in the merge message. Never `--rebase`
(rewrites SHAs, breaks history). Resolve merge conflicts by merging `main`
into the branch; do not force-push.

### Rule 16 — Prose Is Code
Rule 2 applies to sentences. Cut every clause that restates a doc you linked,
narrates how a decision was reached, defends against an objection nobody
raised, or reports what "this session" did. Editing a durable doc means
rewriting it: if your diff is all `+`, you accreted rather than edited.
Budgets are words, not lines — `scripts/check-doc-budget.sh` enforces them,
so reflowing changes nothing. A `bd remember` entry is one fact in ≤3
sentences; if it needs headings it is a doc. Before/after: `git show e10ca358`.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:7510c1e2 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export.

## Session Completion

Work is NOT complete until `git push` succeeds.

1. File issues for remaining work
2. Run quality gates if code changed (tests, linters, builds)
3. Update issue status — close finished, update in-progress
4. Push:
   ```bash
   git pull --rebase && git push
   git status  # must show "up to date with origin"
   ```
5. Clear stashes, prune remote branches
6. Hand off — provide context for next session

If push fails, resolve and retry until it succeeds.
<!-- END BEADS INTEGRATION -->

# Project Instructions for AI Agents

## Rules

Bias: caution over speed on non-trivial work. Use judgment on trivial tasks.

### Rule 1 — Think Before Coding
State assumptions explicitly. Ask rather than guess. Present multiple interpretations when ambiguity exists. Push back when a simpler approach exists. Stop when confused — name what's unclear.

### Rule 2 — Simplicity First
Minimum code that solves the problem. Nothing speculative. No features beyond what was asked. No abstractions for single-use code. Would a senior engineer call this overcomplicated? If yes, simplify.

### Rule 3 — Surgical Changes
Touch only what you must. Clean up only your own mess. Don't improve adjacent code, comments, or formatting. Don't refactor what isn't broken. Match existing style.

### Rule 4 — Goal-Driven Execution
Define success criteria before starting. Loop until verified. Don't follow steps mechanically — define success and iterate toward it.

### Rule 5 — Use the Model Only for Judgment Calls
Use for: classification, drafting, summarization, extraction. Not for: routing, retries, deterministic transforms. If code can answer, code answers.

### Rule 6 — Token Budgets Are Not Advisory
Per-task: 4,000 tokens. Per-session: 30,000 tokens. If approaching budget, summarize and start fresh. Surface the breach — don't silently overrun.

### Rule 7 — Surface Conflicts, Don't Average Them
If two patterns contradict, pick one (more recent / more tested), explain why, and flag the other for cleanup. Don't blend conflicting patterns.

### Rule 8 — Read Before You Write
Before adding code, read exports, immediate callers, and shared utilities. "Looks orthogonal" is dangerous. If unsure why code is structured a certain way, ask.

### Rule 9 — Tests Verify Intent, Not Just Behavior
Tests must encode WHY behavior matters, not just WHAT it does. A test that can't fail when business logic changes is wrong.

### Rule 10 — Checkpoint After Every Significant Step
Summarize what was done, what's verified, what's left. If you lose track, stop and restate before continuing.

### Rule 11 — Match the Codebase's Conventions
Conformance > taste. If you genuinely think a convention is harmful, surface it. Don't fork silently.

### Rule 12 — Fail Loud
"Completed" is wrong if anything was skipped silently. "Tests pass" is wrong if any were skipped. Default to surfacing uncertainty.

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

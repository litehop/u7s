Bead: mayor-zagsa

# Deferral gate audit: mayor-zagsa (Workflow-tool for backlog drains)

## Verdict: (A) Gate has NOT fired — recommend closing mayor-zagsa as verified-out-of-scope

## Method

Compared token-growth curves between:
- **534747a7** (16MB, 11,522 lines, 3,303 assistant turns, 2026-08-25T22:51:19Z → 2026-08-26T14:44:05Z, ~15h53m) — the bead's cited "Phase 1 at 316 turns/hr" reference session.
- **e9556130** (current session, 2.6MB→growing, 381 assistant turns as of 2026-08-27T06:26:58Z, started 2026-08-27T02:39:59Z, ~3h47m elapsed at measurement time) — the session in which all three prerequisite PRs (#1412 mayor-zhwjg 04:36:45Z, #1413 mayor-u2zs0 Track A 05:33:46Z, #1414 mayor-wem1t Phase 2 06:09:01Z, #1415 mayor-u2zs0 Track B 06:16:19Z) merged live, mid-session.

Both sessions run `claude-opus-4-7` (same context-window class), so cache_read_input_tokens is a valid apples-to-apples proxy for "distance to compaction."

## Compaction timing (ground truth, not inferred from cache resets)

Searched both transcripts for the literal auto-compact marker `"This session is being continued from a previous conversation that ran out of context"`.

- 534747a7: first compaction at **2026-08-26T03:53:20Z = 5h02m** into session, with `cache_read_input_tokens=932,446` immediately prior (line 5030-5043). Second (and only other) compaction at 14h19m. This matches the bead's cited "compaction-in-5h" claim exactly.
- e9556130: **zero compaction markers found** through 3h47m elapsed, max observed `cache_read_input_tokens=348,492` at the last sampled turn (06:26:58Z).

Note: cache_read drops to 0 mid-session (turns 68, 79, 116, 166, 175, 180, 241, 252, 267, 273, 301, 311, 329, 359 in e9556130) are **not** true compactions — they correlate with >5min gaps (subagent dispatch waits) that expire the prompt cache TTL, forcing a full cache_creation rewrite. This is a distinct, cheaper phenomenon than conversation summarization; conflating the two would have overstated the "bad" pattern.

## Growth-rate comparison

- 534747a7 Phase 1: 0 → 932,446 cache_read tokens in 302 min ≈ **3,086 tokens/min**.
- e9556130: 0 → 348,492 cache_read tokens in 227 min ≈ **1,535 tokens/min** — **~50% of the reference bad-session rate.**

This is a conservative estimate: e9556130's SessionStart hook fired at 393KB (pre-bd-prime-slim baseline — the fix hadn't landed yet), and only the last ~1h45m of the session ran with all four fixes live. The mature post-fix rate is likely better than this session-average 2x figure.

## Was this a real drain-shape test?

Yes. e9556130 dispatched **20 Agent calls** (worker + critical-reviewer subagent types) across the mayor-wem1t / mayor-zhwjg / mayor-u2zs0 (Track A+B) / mayor-aruza cluster — a genuine 5-bead-at-once drain with multiple review cycles, matching the ≥5-dispatchable-beads trigger condition in zagsa's own description. Each Agent dispatch still embeds its full prompt (500-2000+ words) directly into the mayor's own context — the exact mechanism zagsa's Path A/B target was never touched by the three prerequisite beads. Despite that, the session's overall growth rate still improved ~2x and avoided the 5h compaction, because bd-prime-slim (394KB→35KB per-turn floor) and loop consolidation (mayor-tick.sh) reduced the baseline overhead enough to swamp the untouched dispatch-fan-out cost.

## Fleet/tooling check (for completeness, low weight given verdict A)

- `docs/the-mayor-method/bootstrap.md:125` — mayor already runs `scripts/mayor-tick.sh` (540 lines) for deterministic queue-drain/gate/merge/cleanup/dashboard; `bootstrap.md:102` already documents "hot-zone parallelism" as the binding dispatch rule for drains, not strict same-surface sequencing.
- `.claude/agents/` now has `bead-triager.md`, `dashboard-differ.md`, `diff-summarizer.md` (Haiku, from mayor-u2zs0) alongside `worker.md`, `critical-reviewer.md`, `researcher.md`.
- The mayor still does the actual `Agent`-tool fan-out itself (Sonnet judgment call on cluster shape, per mayor-zhwjg's design), so Path A/B's "move fan-out state off the mayor's context" premise is technically still available as a future win — just not currently justified by the compaction symptom.

## Cost/benefit re-estimate

Original bead estimate: ~$30-40/day when drains fire, ~$500-1000/month, "cost/benefit not clearly favorable for a single script." Given the ~2x baseline-overhead reduction just measured, and that the specific compaction-in-5h symptom used to justify the $30-40/day estimate no longer reproduces, the realistic marginal savings from Path A or Path B today is smaller than the original estimate — likely well under $500/month, insufficient to justify introducing a new language surface (Path A) or a queue-based bash extension (Path B) against Rule 2 (Simplicity First) and Rule 13 (Prefer Native Tooling / no speculative scope).

## Recommendation

Close mayor-zagsa as **verified-out-of-scope**: the deferral gate's own condition ("still shows Phase-1-style compaction-in-5h behavior during backlog drains") is empirically false on the first available post-merge drain trace. No follow-on implementation bead is needed. Optional (not required): a lightweight reminder to spot-check the first *organic* 10+ bead drain (larger than the 5-bead cluster observed here) once one occurs, since this trace, while real, was on the smaller end of the "5+" trigger range.

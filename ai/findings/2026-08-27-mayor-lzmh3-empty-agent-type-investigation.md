Bead: mayor-lzmh3
Date: 2026-08-27
Author: researcher subagent (findings written by mayor per researcher's Write-tool absence)

# Empty-agent_type SubagentStop fires — investigation

## Root cause (confidence: medium-high)

Spurious SubagentStop hook invocations from the Claude Code harness, not real subagent completions. Matches upstream **anthropics/claude-code#27755** (closed "not planned").

Evidence:
- **No backing transcript.** None of the empty-agent_type `agent_id`s have a corresponding `~/.claude/projects/-Users-balint-erdos-u7s/*/subagents/agent-<id>.jsonl` file. Real events do (e.g. `agent-a9c8f6037f3ef3cf4.jsonl` for critical-reviewer, `agent-add435465debf10d7.jsonl` for worker).
- **Invisible in the mayor's own transcript.** The main mayor session (`05bde2a4-8b5b-45a3-b4fd-eda1b65cf27f.jsonl`) shows zero `SubagentStop` tool_use/tool_result entries during the 04:06–04:19 window where 13 empty fires occurred — they're out-of-band harness events, not turns in the visible loop.
- **`jq -r '.agent_type // "unknown"'` returned `""`, not `"unknown"`.** Since `//` only triggers on `null`/`false`, the payload literally contains `"agent_type": ""` — exact match to #27755's documented symptom.
- The hook's own header already references #27755 as a known unreliability source.

## Cadence: regular, ~32–33s period (median 33s)

Delta samples from 04:06–04:28 (33 events):
```
33s, 32s, 33s, 92s(≈3×31), 33s, 33s, 34s, 33s, 33s, 33s, 35s, 33s, 32s, 33s,
34s, 33s, 32s, 33s, 32s, 33s, 33s, 77s(≈2×33+11), 32s, 69s(≈2×33+3), 23s,
32s, 34s, 32s, 32s, 33s, 32s, 31s, 33s, 31s, 33s, 35s, 11s
```

Outlier gaps (69s, 77s, 92s) are near-exact multiples of the base period, occurring exactly when a genuine hook event landed. Consistent with a single dispatch slot per tick where a real event displaces the phantom one — not two independent processes.

## Correlation table

| Event class | Matches empty-agent_type fires? |
|---|---|
| Registered cron loops (5/10/15/30/60m) | No — period is ~30s, an order of magnitude faster |
| Real subagent completions (worker/critical-reviewer, backed by transcript files) | No — distinct agent_ids, always have transcripts, occasionally displace a tick |
| Background subagents in flight | Correlated in time but continues after their completion — points to "harness polling while anything is backgrounded," not one specific subagent |
| Session forks (`agent_type=fork`) | Partial (early logs showed adjacent empty+fork pairs; not observed in current sample) |
| Upstream issue #27755 documented symptom | **Yes — exact match** |

## Recommendation: early filter in the hook

Do NOT file a fresh upstream bug — #27755 already documents this and Anthropic closed "not planned."

Add one line after `AGENT_TYPE`/`AGENT_ID` parse (right after line 28 in `scripts/critical-reviewer-dispatch.sh`, before the `mkdir -p`/timestamp/log-write block):

```sh
[ -z "$AGENT_TYPE" ] && exit 0
```

Rationale: every genuine deliverable-bearing payload observed populates `agent_type`; an empty-string `agent_type` never carries a reviewable message per the queued-payload schema. This stops the `decisions.tsv` bloat and wasted `jq`/exec cycles without risking dropped real signals.

## Blast radius
- `decisions.tsv` currently 8856 lines and growing unbounded — the empty fires are the majority contributor. Separate follow-on to prune/rotate.

## What this does NOT cover
mayor-ks2z2 (hook branch-lookup fallback) and mayor-9syl7 (mayor-tick self-heal) address a DIFFERENT problem: real `agent_type=worker` completions where the PR URL regex misses non-URL phrasing. Do not conflate.

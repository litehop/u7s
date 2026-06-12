# Dashboard
2026-06-12T11:48Z — 1 worker in-flight (yno6, BLOCKED on startup). No open PRs.

Resume: `bd prime`

## Operator attention needed

**yno6 worker is stuck** using inline-env / individual-script invocation instead of `run-all.sh --flags`. Mayor drafted a correction message but operator paused it. Decide: send the run-all.sh correction to unblock it?

**Doc root cause:** dispatch-prompt-template.md §351 + project-stance.md §40 still show the broken `U7S_VM_NAME=... ./run-all.sh` inline-env pattern (+ stale U7S_HOST_IP). vm-operations.md is correct (flags). This conflict keeps misleading workers — needs a small doc-fix worker.

**GitHub branch protection still off.** Recommend enabling.

**mayor-91p3 (P1 admission enforcement)** — still needs audit-first decision.

## In-flight workers
| Worker | Bead | Surface | VM | State |
|---|---|---|---|---|
| adbbbdacf00490f89 | mayor-yno6 (P1) | apiserver pod PATCH path | lima-node-smoke:6444 | blocked on stack startup |

## Open PRs
None.

## Recent merges
- #533 fix(apiserver): validate matchConditions CEL on MutatingWebhookConfiguration (mayor-b69i) — additive test only
- #535 fix(apiserver): AND-evaluate involvedObject field selectors for Events (mayor-giem)
- #534 fix(apiserver): accept application/json-patch+json on custom resources (mayor-1mp5)
- #532 fix(scripts): stall-watchdog keys on progress.completed/msg (mayor-f73c) — partial; see yno6
- #531 fix(apiserver): seed CoreDNS Corefile w/ kubernetes plugin (mayor-mm5q)

## VM port assignment
| Slot | VM | Port | Who |
|---|---|---|---|
| mayor | lima-node | 6443 | operator (live conformance run) |
| worker-1 | lima-node-smoke | 6444 | yno6 |
| worker-2 | lima-node-2 | 6445 | free |
| worker-3 | — | 6446 | free |

## Queued beads
- mayor-91p3 (P1) — admission webhook enforcement (DECISION: audit first?)
- mayor-y4ll (P2) — RuntimeClass .overhead not injected into pod.spec.overhead
- mayor-5asj (P2) — pod contradictory scheduling state / phase unset (investigate)
- mayor-yno6 (P1) — IN FLIGHT — aggregator annotation PATCH 200s but doesn't persist (frozen progress)
- mayor-7jli (P3) — Event timestamps zero (0001-01-01); breaks kubectl LAST SEEN

## Key learnings this session
- ROOT CAUSE of frozen sonobuoy progress + watchdog false-kills: aggregator PATCHes pod annotation, apiserver 200s, but value doesn't persist (kubectl annotate of OTHER keys works → specific to aggregator's patch shape). yno6 investigating with debug logging.
- Conflict-status & existing-key-overwrite hypotheses both FALSIFIED by live probing — capture the actual request body, don't infer.
- kubelet heartbeat = PATCH /pods/<n>/status (subresource); aggregator = PATCH /pods/<n> (main). Log has no client id/body → must add debug logging.
- run-all.sh: use FLAGS (--vm --port --workdir --binary), never inline env vars, never individual numbered scripts.

## Loops (session-only)
- :07 posture · :11 worktree hygiene · :17/2h cluster · :23/2h merge · :43 dispatch · :53 dashboard

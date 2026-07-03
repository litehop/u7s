# Dashboard
2026-07-03T03:16Z — **Non-proto-drop batch COMPLETE (4 fixes merged + 1 reclassified). 18 PRs merged this session. Mayor on main `4f41f2de` = origin. 0 open PRs, 0 workers. Board: 13 ready + EPIC. STOPPED for backlog re-evaluation (operator).**

Resume: `bd prime`

## What needs the operator now — RE-EVALUATION DECISIONS
The non-proto-drop batch is done. Threads awaiting your call:
1. **Proto-typing EPIC (mayor-xmu4)** — decided (Direction A). P1 gate mayor-dqwf is READY. Start now (~3-5d) or defer? Highest-leverage — kills the recurring bug class.
2. **7lrp (P1)** — watch/informer-consistency latency (design decision; maybe-unfixable-without-forking-KCM per audit). Re-measure on a fresh full run first, then decide.
3. **rsei preemption (P1)** — SCOUTED = missing FEATURE (~6-9d EPIC), not a bug; blocked-by osuq (priority proto-drop). Build or defer?
Also: a fresh FULL conformance run to re-baseline (18 fixes landed) — re-ranks everything + confirms dfly PATCH-TypeMeta blast radius (mayor-f172).

## ✅ Non-proto-drop batch results
| Bead | Outcome |
|---|---|
| 2av8 | ✅ #659 — create_pod honors dryRun=All + 403 missing RuntimeClass. VM-verified, --focus PASS. |
| f60a | ✅ #660 — webhook timeout error includes URL+timeout. Mayor caught+fixed a double-`?` URL-collision bug. |
| frxo | ✅ #661 — SA token credential-id (JTI). Added UserInfo.extra (~90 mechanical sites, verified uniform). |
| n124 | ✅ #662 — pod proxy via manual CONNECT tunnel (reqwest only tunnels https). VM-verified 200/zero-405. |
| rsei | RECLASSIFIED → missing feature (~6-9d EPIC). Escape-hatch caught proto-drop osuq. |

Escape-hatch + verify-the-diff paid off 3×: rsei's hidden proto-drop, f60a's URL-collision, n124's asymmetry. All fixes have fails-on-revert tests.

## PROTO-TYPING EPIC (mayor-xmu4) — decided (Direction A: prost-build codegen)
Kills silent-field-drop structurally. Record: ai/extended-context/proto-typing-decision.md (on main). Phases: P1 mayor-dqwf (GATE — prove decode+JSON-emission adapter; hard part = proto.rs combines decode+emit in ~200 fns), P2 tkyb, P3 0vl5, P4 2bfd. New instance this session: mayor-osuq (PodSpec priority/priorityClassName).

## Board — 13 ready (+ EPIC)
- **P1:** 7lrp (design decision), osuq (priority proto-drop — EPIC scope), dqwf (EPIC P1 gate).
- **Still-open conformance (root-cause-verify via --stack-only before fixing — half checked this session were mis-framed):** qrip (STS rolling update — MAY be spec.template proto/patch drop, scout first), kxht (VAP outcomes+panic — CEL context, likely not proto), uam0 (CRD schema in /openapi/v2 — OpenAPI gen, downstream of typing EPIC), pu5i (pod log 500 — proxy/streaming), y832 (sonobuoy progress annotation not persisting — WRITE-path silent-loss, sibling of proto-drop).
- **Chores:** zc9l (smoke coverage), vehd (k8s patch pins). **P3:** f172 (verify dfly PATCH-TypeMeta blast radius next run), cef5 (deferred audit perf/LOW: admission-config-cache, delete_collection error-swallow).

## Shipped this session (18 PRs)
Proto-drops: #645 Deploy/RS status · #650 Job spec · #654 Volume defaultMode+Lease MicroTime+generic PATCH TypeMeta · #656 ResourceQuota terminating (activeDeadlineSeconds+scopeSelector). Consistency: #653 u3fa batch-delete watch-event-loss. Conformance: #647 PATCH CAS+/status isolation · #646 CEL checked-arith+matches_rule scope · #659 dryRun+RuntimeClass · #660 webhook timeout · #661 SA token JTI · #662 pod proxy CONNECT. Infra/docs: #648 rmcp2.1 · #651 --stack-only · #652/#657 dispatch-template · #649/#658 bookkeeping. Plus 3 audits.

## Key lessons banked
proto-decode-drop is THE bug class → EPIC mayor-xmu4. Root-cause-first + escape-hatch + read-the-e2e.txt-yourself repeatedly caught mis-framed beads + would-be-regressions. Worker discipline: FOREGROUND run-all.sh, check branch-base before merge, never bare run-all.sh (=6h). mcpls grep-then-LSP in dispatch template.

## Tooling
`run-all.sh --stack-only` (stack up, no sonobuoy) · `--focus <regex>` (targeted gate) · NEVER bare (=6h full suite).

## Stance (unchanged)
Pre-alpha k8s apiserver in Rust. Correctness > breadth. Workers in isolated worktrees (ALWAYS isolation="worktree"); mayor orchestrates (4-condition gate). Merge-on-green WITH verification (read the e2e.txt). No back-compat. Never --admin. Flag security/API/architecture PRs. Confirm branch=main + pwd before bead/dashboard ops.

## VM slots (6: mayor + slots 1-5)
| Slot | VM | Port | Kubelet |
|---|---|---|---|
| mayor | lima-node | 6443 | 10250 |
| 1 | lima-node-smoke | 6444 | 10251 |
| 2 | lima-node-2 | 6445 | 10252 |
| 3-5 | lima-node-3/4/5 | 6446-8 | 10253-5 |
Slots 3-5 provision on first `run-all.sh --reset`. Konnectivity auto-derives: 8135 + (port−6443)×100.

## Session loops (session-only, auto-expire 7d)
:07 posture · :11 worktree hygiene · :17/2h cluster · :23/2h merge · :43 dispatch · :53 dashboard

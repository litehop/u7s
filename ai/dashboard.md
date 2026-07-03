# Dashboard
2026-07-03T04:28Z — **CLEAN STATE. 23 PRs merged this session; #666 admission-cache landed. Mayor on main `87ae7cc7` = origin. 0 workers, 0 open PRs. Board ~11 ready + EPIC. Awaiting operator on the big open calls.**

Resume: `bd prime`

## What needs the operator now — pick the next thread (all your call)
1. **Proto-typing EPIC P1 (mayor-dqwf)** — ready to dispatch. ~3-5d initiative that structurally kills the proto-drop bug class (this session's dominant bug). Highest leverage. Decision record: ai/extended-context/proto-typing-decision.md.
2. **A-vs-B re-baseline** — a fresh FULL conformance run (23 fixes landed) re-ranks the board + confirms dfly PATCH-TypeMeta blast radius (f172). Cheap insight; my earlier lean was "A then B" (baseline, then EPIC).
3. **7lrp (P1)** — watch/informer-consistency latency; design decision (maybe-unfixable-without-forking-KCM per audit). Re-measure on a fresh run first.
4. **rsei (P1)** — scheduler preemption is a missing FEATURE (~6-9d EPIC), blocked by osuq. Build or defer?

## ✅ Smoke-test catch RESOLVED (operator diagnosis) — was CI config, NOT a u7s bug
zc9l's pod-log smoke check failed on all 3 kubelet cells (apiserver→kubelet containerLogs rejected). Operator pinned it: inbound apiserver→kubelet path lacked the client-ca/TLS auth lima-start.sh:217-283 sets up. Fixed in #664 (mirror lima: client-ca-file + serving cert signed by cluster CA + authorization.mode:AlwaysAllow). All 10 smoke cells GREEN; check NOT weakened. Permanent CI hardening — inbound kubelet path now exercised every PR. (Distinct from mayor-pu5i, the real log-500 code bug — still open.)

## In-flight
0 workers, 0 open PRs. Clean.

## Shipped this session (23 PRs)
Perf/correctness: #665 delete_collection error propagation (8a7b). Non-proto-drop batch: #659 dryRun+RuntimeClass, #660 webhook timeout, #661 SA token JTI, #662 pod proxy CONNECT. Proto-drops: #645/#650/#654/#656. Consistency: #653 u3fa batch-delete. Earlier conformance: #646/#647. Infra/docs: #648/#651/#652/#657/#663 + #649/#658 bookkeeping. Plus 3 audits.

## Board (post-batch): ~11 ready + EPIC
P1: 7lrp (design), osuq (priority proto-drop, EPIC scope), dqwf (EPIC P1 gate). Conformance (root-cause-verify first): qrip, kxht, uam0, pu5i (the real log-500 bug — smoke catch is CI-config, separate), y832. Chores: (vehd/zc9l in #664). P3: f172 (needs a run), cef5 (remaining audit items after F1/F-05 promoted).

## Key lessons banked
proto-decode-drop = THE bug class → EPIC mayor-xmu4. Root-cause-first + escape-hatch + read-the-e2e.txt/CI-log-yourself repeatedly caught mis-framed beads + would-be-regressions (this turn: operator caught me about to mis-route a CI-config failure to pu5i). Worker discipline: FOREGROUND run-all.sh, check branch-base before merge, never bare run-all.sh (=6h). A good test that FAILS is signal — fix the cause, don't weaken the test.

## Tooling
`run-all.sh --stack-only` (stack, no sonobuoy) · `--focus <regex>` (gate) · NEVER bare (=6h). Smoke/CI matrix is the real gate for CI-config PRs.

## Stance (unchanged)
Pre-alpha k8s apiserver in Rust. Correctness > breadth. Workers in isolated worktrees (ALWAYS isolation="worktree"); mayor orchestrates (4-condition gate). Merge-on-green WITH verification (read the e2e.txt / CI log). No back-compat. Never --admin. Flag security/API/architecture PRs. Confirm branch=main + pwd before bead/dashboard ops.

## VM slots (6: mayor lima-node + 1-5)
lima-node(6443/10250) · smoke(6444/10251) · 2(6445/10252) · 3-5(6446-8/10253-5). Slots 3-5 provision on first --reset. Konnectivity: 8135+(port−6443)×100.

## Session loops (session-only, auto-expire 7d)
:07 posture · :11 worktree hygiene · :17/2h cluster · :23/2h merge · :43 dispatch · :53 dashboard

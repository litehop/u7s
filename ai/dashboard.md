# Dashboard
2026-07-03T02:15Z — **Long session, lots shipped. 12 PRs merged (audits→fixes, proto-drops, u3fa consistency, tooling). PROTO-TYPING EPIC decided + filed. Mayor on main `3e423de3` = origin. 0 open PRs. 0 workers. Board: 15 ready + EPIC.**

Resume: `bd prime`

## What needs the operator now
- **Nothing blocking.** Clean slate — pick the next thread.
- **Two P1s teed up, both need an operator call before dispatch:**
  1. **mayor-dqwf** — Phase-1 GATE of the proto-typing EPIC (mayor-xmu4). Ready to dispatch when you want to start the ~3-5 day migration. It's a spike→real (prove the prost-build decode+JSON-emission adapter on one group), cargo-verifiable, gates the rest.
  2. **mayor-7lrp** — the residual watch/informer-consistency latency ("EndpointSlice informer cache out of date" — bookmark-delivery lag, distinct from the u3fa batch-delete bug now fixed). NEEDS A DESIGN DECISION, not a blind fix — the 0702-watch-consistency-audit flags it as maybe-not-fixable without forking KCM. Recommend: re-measure on a fresh full run first, then decide.
- **Also available:** a fresh FULL conformance run to re-baseline (12 fixes landed since the last one) — would re-rank the 15 symptom beads and confirm the dfly generic-PATCH-TypeMeta fix's blast radius.

## ✅ PROTO-TYPING EPIC — DECIDED (Direction A: prost-build codegen)
The week's dominant bug class = proto.rs hand-written PARTIAL prost structs (224 of 643 msgs) silently dropping fields. Decision (operator): generate complete structs FROM upstream .proto → omission becomes STRUCTURALLY impossible. Rejected Direction B (types-as-source-of-truth): no Rust types→proto tool exists (spike surveyed 7 crates); B's checker catches wrong tags but NOT omissions, ~2x cost. Full record: **ai/extended-context/proto-typing-decision.md** + bd memory `proto-typing-direction-a-decision`. Research: ai/findings/{k8s-proto-schema-churn-1.34-1.36, proto-source-of-truth-spike}-2026-07-03.md + PoC.
- **EPIC mayor-xmu4** → P1 mayor-dqwf (GATE), P2 mayor-tkyb (existing groups), P3 mayor-0vl5 (10 missing groups), P4 mayor-2bfd (delete dead structs+gate). OpenAPI mayor-52wo relates-to. Hard part: proto.rs combines decode+JSON-emit in ~200 fns → must split into generated-decode + adapter (Phase 1 proves the pattern).

## Uncommitted (fold into next push)
.beads/ (EPIC + phase beads, 7lrp re-scope), ai/dashboard.md, ai/extended-context/proto-typing-decision.md (new). No code.

## Board — 15 ready (+ EPIC mayor-xmu4)
- **mayor-7lrp (P1)** — watch/informer-consistency latency (design decision; see above).
- **mayor-cef5 (P3)** — deferred audit findings (perf F1 admission-config-cache = biggest write-latency lever; quality F-05 delete_collection error-swallow).
- **~13 symptom-framed P2 conformance beads** (root-cause-verify each via --stack-only kubectl BEFORE a fix — half of the ones checked this session were mis-framed): qrip (STS rolling update), frxo (SA token credential-id), kxht (VAP outcomes+panic — distinct from wucf's arithmetic fix), rsei (scheduler preemption), uam0 (CRD /openapi/v2), pu5i (pod log 500), n124 (pod proxy CONNECT tunnel), 2av8 (dryRun+RuntimeClass), y832 (sonobuoy progress dropped), f60a (webhook timeout type). Infra/chore: zc9l (smoke coverage), vehd (k8s patch-version check). Plus a filed follow-up: verify which PATCH tests the dfly generic-TypeMeta fix now passes.

## Shipped this session (all merged, mayor-verified)
#657 mcpls dispatch guidance · #656 f5p5 ResourceQuota terminating-scope (+2 proto-drops: activeDeadlineSeconds, scopeSelector) · #655 GET /pods/resize (lp6i) · #654 proto cluster (on07 Volume defaultMode, a83z Lease MicroTime nanos, dfly GENERIC PATCH-TypeMeta) · #653 u3fa batch-delete watch-event-loss (distinct-rv-per-object) · #652 --stack-only mandate docs · #651 --stack-only flag · #650 Job proto decode (2w29) · #649 beads-sync · #648 rmcp 2.1.0 · #647 PATCH CAS + JSON-Patch /status isolation · #646 CEL checked-arith + matches_rule scope · #645 Deployment/RS status proto decode. Plus 3 audits (perf/quality/security) closed.

## Key lessons banked this session
- **proto-decode-drop is THE bug class** → the mayor-xmu4 EPIC exists to kill it structurally. Every `// skipped` in proto.rs is a latent bug.
- Root-cause-first pays: several symptom beads were mis-framed (lp6i "route missing"=missing GET method; f5p5 "404"=scope bug; #646 suspected then refuted for EndpointSlice). Scouts avoided ≥2 bad fixes (one would've regressed conformance).
- Worker discipline: check branch-base vs origin/main before merging (stale forks silently revert merges); mandate FOREGROUND run-all.sh (backgrounded runs stall workers); ALWAYS read the e2e.txt PASS line yourself (workers claim progress the test doesn't confirm); NEVER bare run-all.sh (=6h full suite — see --stack-only).
- mcpls LSP is useful (grep-then-LSP-at-position) but underused → now in dispatch template + memory.

## Tooling
`run-all.sh --stack-only` (stack up, no sonobuoy — for kubectl/DB investigation). `--focus <regex>` for targeted gate. NEVER bare (=full ~6h suite). Dispatch template + bd memory carry the discipline.

## Stance (unchanged)
Pre-alpha Kubernetes apiserver in Rust. Correctness > conformance breadth. Workers in isolated worktrees (ALWAYS isolation="worktree"); mayor orchestrates, doesn't code (4-condition gate). Merge-on-green WITH verification (read the e2e.txt). No back-compat. Never --admin. Flag security/API/architecture PRs. Confirm branch=main + pwd before bead/dashboard ops.

## VM slots
| Slot | VM | Port | Kubelet | Konnectivity | Status |
|---|---|---|---|---|---|
| mayor | lima-node | 6443 | 10250 | 8135 | operator stack |
| worker-1 | lima-node-smoke | 6444 | 10251 | 8235 | free |
| worker-2 | lima-node-2 | 6445 | 10252 | 8335 | free |
Konnectivity auto-derives from port: 8135 + (port − 6443) × 100.

## Session loops (session-only, auto-expire 7d)
:07 posture · :11 worktree hygiene · :17/2h cluster · :23/2h merge · :43 dispatch · :53 dashboard

# Dashboard
2026-07-03T11:20Z — **First full conformance run (0703-1822) → first fix MERGED. #668 MIME/Content-Type (13 tests) landed on main `7a57604b`. 1 fix worker still in-flight (pod-gen-17). Facts-before-beads keeps paying: caught the categorization scout fabricating ALL file paths + 2 wrong root-cause sketches; caught the MIME worker's soft "grep-for-zero-errors" evidence and verified via the green CI kubectl smoke matrix instead. Mayor on `7a57604b` = origin.**

Resume: `bd prime`

## ✅ Shipped this session
- **#668 (mayor-tt5h)** MIME/Content-Type — /openapi/v2 proto response now uses the non-deprecated dot form (@v1.0→.v1.0). Upstream-verified (kube-openapi responds dot-form for both Accept variants); 17/17 CI green incl. kubectl smoke cells; API-surface change flagged in PR body. Unblocks 13 kubectl-validation conformance tests.

## 🔧 1 fix worker in-flight
- **mayor-h4xw** pod-generation no-op bump (17 tests) → worker a54f02c9, pods.rs, VM 2/6445, branch based on pre-merge c6dda7b6 (DISJOINT from #668's discovery.rs — no conflict when it merges, no rebase needed). Fix (Option A, operator-approved): extract pure apply_pod_spec_defaults (NO status side effects) so create+update share spec-defaulting; compare spec-defaulted at 5 update call sites. ⚠️ scout's apply_pod_create_defaults fix REJECTED — it stomps status→Pending. Awaiting PR.

## 📝 Staged (uncommitted, fold into next PR) — NOT pushed
- ai/prompts/vm-operations.md + docs/the-mayor-method/dispatch-prompt-template.md: "locate the e2e test source" protocol (check temp/research/ first, else WebFetch raw GitHub pinned to client version). Memory: locate-e2e-test-source-research-then-github.
- ai/prompts/vm-operations.md: "--focus gate BLOCKS — scope slim or background it, never busy-poll" + "cancelling run-all.sh does NOT cancel sonobuoy" + "narrow --focus to ONE test (full name) for iteration, but the ACCEPTANCE GATE is the DISPATCH focus (whole cluster), not the narrowed one" (Step 6). Mayor return-review must confirm e2e.txt PASS is for the dispatch-level focus/count, not a zoomed-in subset. Memory: focus-acceptance-is-dispatch-focus-not-narrowed. Root-caused the MIME worker's 62-min run: --focus "Kubectl client" (~15 min, sonobuoy run --wait) hit the 10-min FOREGROUND Bash timeout ceiling → returned no result → worker busy-polled kubectl ~40 min (the run kept executing IN THE VM, orphaned; delete needs `limactl shell <VM> sudo sonobuoy delete --all --wait --kubeconfig /tmp/sonobuoy-kubeconfig`) → then double-launched into a VM with the first run still alive. Fix: slim --focus (foreground <10min) OR run_in_background:true (survives >10min, pings; allowlist-safe); cancel via in-VM sonobuoy delete. NOT port isolation, NOT a u7s bug. Memories: worker-run-all-verbatim (corrected) + worker-run-all-cancel-gotcha.
- ai/dashboard.md (this file).

## ⚠️ Triage doc caveat (READ before trusting it)
ai/findings/conformance-full-run-triage-2026-07-03.md (Haiku scout) has TRUSTWORTHY cluster counts/symptoms/test-lists from the logs, but its root-cause hypotheses + ALL source-file pointers are FABRICATED (cold-workspace guessing — every path I checked was wrong; real layout is flat crates/apiserver/src/, no crates/controllers/). Use it for the failure MAP only. Each cluster needs real root-causing (kubectl repro + verified file:line) before it becomes a fix bead.

## What needs the operator now
1. **✅ 2 clusters ROOT-CAUSED (CONFIRMED, verified vs real source):**
   - **MIME/Content-Type (13 tests)** — /openapi/v2 returns `Content-Type: application/com.github.proto-openapi.spec.v2@v1.0+protobuf`; the `@v1.0` breaks Go mime.ParseMediaType in kubectl validation. discovery.rs:1379. TENSION: existing test (discovery.rs:3245) asserts current behavior is "correct" (it fixed the opposite proto-decode bug). Operator chose: **verify upstream exactly THEN fix** → ⏳ upstream-verification scout in-flight (ad802787). Doc: ai/findings/rc-mime-content-type-2026-07-03.md.
   - **observedGeneration (17 tests)** — top-level status.observedGeneration never initialized on create (pods.rs:3103 apply_pod_create_defaults). Generation defaulting/increment WORK. SECONDARY: Pod status dropped on proto decode (proto.rs:1000, "not decoded on input") — proto-drop class, likely folds into EPIC. Doc: ai/findings/rc-observed-generation-2026-07-03.md. Decomposes into Bead A (observedGen init, small) + Bead B (proto status-drop, → EPIC). **Awaiting operator go to file + fix.**
2. **~28 of 141 already have beads** (uam0 CRD-openapi ×10, kxht VAP-panic ×7, rsei preempt ×7, pu5i pod-log ×4-cascade, 7lrp WAL ×3, f172 PATCH-TypeMeta ×2, qrip ×1). **4 are pure INFRA** (need 2 nodes; kubelet /etc/hosts). Real NEW surface ≈ 21 clusters.
3. **Proto-typing EPIC (mayor-dqwf)** — triage confirms proto-drop is live (Pod status, plus Lease defaults/status fields/security-context/image spec smell the same). Sizes the EPIC's payoff. Ready when you are.
4. **Next RC-scout candidates** (your call): admission-webhook-deny (8), CRD-watch-never-converges (5) + watch-order (5), the 4 apiserver PANICS (VAP index-oob + 3 controller nil-derefs — crashes = high value), status-fields-missing (4).

## Board bugs likely CONFIRMED-real by this run (were symptom-beads)
kxht (VAP `index out of range [-1]` panic — CONFIRMED in logs), uam0 (CRD schema timeout — CONFIRMED), f172 (PATCH missing Kind — CONFIRMED). rsei/pu5i/7lrp/qrip corroborated by matching failures.

## ⚠️ Scout-isolation lesson (banked: scout-isolation-use-worker-not-researcher)
researcher-type scouts do NOT get a pinned worktree CWD — their file writes hit the mayor checkout (path-resolution leak) or get permission-blocked. VM/--stack-only isolation DID work for them. RULE: researcher = read-only analysis, NO file writes to repo; use subagent_type=worker for anything needing isolation="worktree" + file output. (No harm this session: findings docs are gitignored + verified correct.)

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

# Dashboard
2026-07-16T08:39Z — **WRAPPING UP.** 11 fix PRs merged; docs PR #838 in CI (last merge). Operator chose "bank and wrap up."

Resume: `bd prime` · Mayor at `0c0fcd5b` (origin/main), clean, 0 worker worktrees, orphan host procs swept.

## This session — conformance 0715-2142 drain
Baseline: **434 passed / 17 failed / 451 ran**. Analyzed → reconciled the board (3 scouts, 17→~9 root causes) → fixed. Reconciliation writeup: `ai/extended-context/conformance-0715-2142-reconciliation.md` (PR #838).

**11 fix PRs merged (all mayor-reviewed PASS, fail-on-revert tests, sonobuoy/live evidence):**
#828 GC co-ownership · #829 conversion caBundle+decode-drop · #830 conversion no-op self-call · #831 Sentinel rollout (all 10 adapters, +17 dropped fields) · #832 preemption 409 · #833 watch idle-timeout + request timeout · #834 pick_node NodeTally · #835 typed pick_node err · #836 CR LIST field-selectors · #837 proxy scheme:name:port.

## Conformance state (per-bead focus PASSes — NOT a full re-run)
FULLY GREEN (9 tests): GC, 2 conversion, 4 preemption, 2 scheduler-predicates.
PARTIAL (fix landed, test still red — needs more beads): CustomResourceFieldSelectors (LIST done, watch=tv4ob) · Proxy (parsing done, +rmqrl HTML-rewrite +vkkma https-TLS).
NOT STARTED: g40rz (field-val SSA wording), bpmz9 (OrderedNamespaceDeletion), e788i (attach-deny, needs real-backend scout).
INFRA WONTFIX: 2 two-node-precondition tests (wz5s7 — single-node lima).

## 🎯 NEXT SESSION — remaining queue to reach the ~2-failure floor
Fixable, disjoint, mostly small — dispatch when ready:
- **P2:** g40rz (cr.rs field-val wording, Rule-7: branch on SSA vs Create — do NOT revert w1p59), bpmz9 (namespaces.rs — emit NamespaceDeletionContentFailure or hand off to KCM).
- **P2 scout-first:** e788i (attach-deny reachable backend — needs a real agnhost webhook pod deployed; repro recipe in the bead).
- **P3 tails (discovered mid-fix):** tv4ob (CR watch field-selector, needs cross-version conversion in watch path), rmqrl (proxy HTML link rewrite), vkkma (proxy https→TLS backend), 7xr09 (find_preemption_plan typed err), allowWatchBookmarks (scheduler watch), shared Sentinel test-util.
**After draining all of the above: expected ~2 remaining (infra only).** Then run a FRESH FULL conformance suite to confirm the real aggregate — per-bead focus gates don't prove interactions.

## Key lessons banked this session
- Several conformance tests are HYDRA-HEADED: one test, multiple independent gaps (Proxy=3 beads, FieldSelectors=2). A per-bead focus PASS ≠ the ginkgo spec green. Count tests, not beads.
- Audit-first paid off: the scheduler→apiserver glue audit found a P1 (watch_stream total-outage hang) that bead-by-bead fixing would have missed.
- Sentinel rollout complete (all 10 adapters) — closes the recurring protobuf decode-drop class; #829's caBundle drop was concrete evidence it was worth it.
- bd descriptions via Bash: NO backticks / no `(...)` — shell interprets them and silently drops tokens (banked: `bd-create-description-zsh-glob`).
- Orphan host processes survive worktree prune — sweep on session close (banked: `orphaned-u7s-processes-survive-worktree-prune`).

## Housekeeping
Uncommitted (intentional, local session state, not for git): `ai/dashboard.md`, `.beads/*.jsonl` exports. Docs PR #838 (reconciliation doc) merges then session is fully closed.

## Stance (durable)
Pre-alpha k8s apiserver in Rust. Correctness > breadth. Workers always `isolation="worktree"`; mayor orchestrates. Merge-on-green WITH verification; API/security/architecture PRs get dedicated review + operator signoff. No back-compat. Never `--admin`.

## VM slots — all idle
lima-node/6443 mayor · 2-5 + smoke idle. All 6 VMs running, no stacks up (orphans swept at wrap-up).

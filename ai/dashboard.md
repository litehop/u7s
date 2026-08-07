# Dashboard
2026-08-07T06:59Z — **SESSION CLOSED.** Mayor at HEAD `90295185` (main).
Resume: `bd prime` → this file → `ai/extended-context/mayor-handoff-2026-08-07-close.md`.

**7 PRs merged this session** (`855f628c → 90295185`).
**Zero workers, zero scouts, zero worktrees, zero loops at close.**

## Full handoff → `ai/extended-context/mayor-handoff-2026-08-07-close.md`

Contains:
- What each of the 7 merged PRs did
- Data-locked measurements (Conformance/csi-hostpath memory profiles at various --procs)
- Full 49-failure triage breakdown (5 clusters filed as beads, 3 existing beads updated)
- All 10+ new memories banked (mayor discipline, upstream framing, VM operations, port-collision diagnosis)
- What each in-flight investigation concluded (bounded-cap discarded; cv3jo is upstream kubelet; ag0e5 is port-collision, not code)
- What needs operator attention next session (mayor-dda10 fix option A vs B; cv3jo upstream-file decision)
- Ready-to-dispatch queue (all P1s unblocked)

## Stance (unchanged from session close)
Resource-optimized k8s. Correctness → observability → perf. Merge-on-green (never `--admin`). Pre-alpha, no back-compat.

## Session lessons banked (short list — full context in memories)
- Mayor dispatches ready P1s + merges on green without per-item approval.
- Mayor does not do scout work in-band (grepping certs, etc.).
- Verify scout "100%" claims with TIGHT grep patterns + live probes, not broad substring matches.
- Upstream tests passing = bug is ours (default suspicion order).
- Timeouts are ceilings, not targets.
- Scouts on shared VMs must NOT `sudo rm -rf` sibling-scout artifacts.
- Concurrent VM scouts MUST pass explicit `--port` + `--kubelet-port` from the slot table.
- u7s kubelet is stock upstream Go (only apiserver/scheduler/KCM/store are Rust).

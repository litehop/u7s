# Mayor session handoff — 2026-08-07 close

Session ran ~2026-08-06 22:40 UTC through 2026-08-07 06:47+ UTC (~8 hours).

**Session shape**: heavy csi-hostpath investigation + code fixes on top of a small backlog drain. Merged 6 PRs, split some large P1s into concrete follow-ons, banked 8 mayor-discipline memories.

## What each merged PR did

- **PR #1044** (`chore(misc)`) — 3-bead P3 drain: `mayor-dvvaw` (inflight.rs cap comments), `mayor-ipyp1` (shellcheck SC2086 disable), `mayor-a9rs3` (scheduler `.with_ansi(false)`).
- **PR #1045** (`mayor-ppcwt`) — `u7s_discovery_build_total` IntCounterVec + APIService cache-safety doc on `build_aggregated_discovery`. Unblocks a future `mayor-k3pxp` cache implementation.
- **PR #1046** (`mayor-ds8hb`) — typed-struct EPIC child 1: migrated 17 `default_X` functions in `handlers/defaults.rs` from `serde_json::Value` wrangling to typed structs in `types.rs`. +400 LoC, 19 new typed structs.
- **PR #1048** (`mayor-65e5w`) — apiserver rejects PVC size UPDATE when StorageClass.allowVolumeExpansion=false. Upstream `PersistentVolumeClaimResize` admission plugin mirrored. +383 LoC in `handlers/resource.rs`.
- **PR #1050** (`mayor-l8g29`) — apiserver adds `csi` match arm to `core_gen_adapter.rs::gen_pod_spec_to_json`. Fixes silent-drop of inline CSI volume source on protobuf-decoded pod CREATE. Closes 4 CSI-Ephemeral test failures.
- **PR #1051** (`mayor-s0wa3`) — scheduler stamps `volume.kubernetes.io/selected-node` on unbound WaitForFirstConsumer PVCs (direct + ephemeral-derived) at bind time. New `stamp_selected_node_for_pvcs` in scheduler. Closes 9 Generic-Ephemeral test failures.

## What was closed as NOT-a-u7s-bug

- **`mayor-cv3jo`** — scout v2 root-caused the pod-termination-hang as an UPSTREAM KUBELET block-device bind-mount cleanup race (`k8s.io/kubernetes/pkg/volume/util/volume_path_handler_linux.go:60`). CSI driver's NodeUnpublishVolume never called; kubelet stuck in pre-CSI cleanup retrying `remove()` with EBUSY. Every apiserver call for the pod during the hang was latency 0-4ms — u7s confirmed not at fault.

## What was closed as strategy-shift

- **`mayor-o4fmo` PR #1047** — bounded-container-cap route (1Gi limit on e2e-job) closed unmerged per operator direction. Cap size insufficient for memory-heavy suites; strategy pivoted to "provision higher-power VMs for intensive suites" (proven by mp7z1 scout: 30-parallel + 6Gi req/limit on 12GiB VM works cleanly).
- **`mayor-4dtlb`** (Phase-3 --procs override) — closed as superseded; its sizing rationale was pinned to the 1Gi cap that got discarded.

## Data-locked measurements banked this session

- **Conformance --procs=16 on 2-VM 4GiB stack**: 446/446 tests, 30m11s wall-clock. e2e-job anon peak **150 MiB total across 17 workers**. Per-worker anon steady-state ~9 MiB.
- **csi-hostpath --focus --procs=16 on same 4GiB stack**: OOM at 42s. Kernel dmesg shows 19 processes killed, summed anon-rss **2780 MiB (2.71 GiB)**. `constraint=CONSTRAINT_NONE, global_oom` — luck-picked e2e-job as victim.
- **csi-hostpath --focus --procs=4 on same stack**: steady-state cgroup anon ~440 MiB, `memory.peak` 707 MiB (ramp), NO OOM. Per-worker ~100 MiB steady.
- **csi-hostpath --focus --procs=30 6Gi/6Gi req/limit on 12GiB VM (mp7z1)**: runner survives full 11-min observation window, e2e cgroup peak 5729 MiB (93% of 6Gi cap) at startup burst then falls to ~198 MiB steady. **Upstream's 6Gi/30-parallel shape works on u7s.**

## Triage banked (49 csi-hostpath failures → 8 mechanism clusters)

The `--procs=4` csi-hostpath run at `temp/e2e/0807-0450--driver-csi-hostpath/` was fully triaged by scout `mayor-6q2v2`:

- **`mayor-rcujn` P1 (14 failures)** — pod-exec can't see mounted volume content after (re)mount. Race hypothesis unproven. **Blocked by `mayor-ag0e5`** (exec-proxy TLS BadSignature).
- **`mayor-suf4l` P1 (14 failures) — SPLIT + CLOSED**. Root-caused to two bugs, both now merged: PR #1050 (csi arm, 4 failures) + PR #1051 (scheduler selected-node, 9 failures). 1 residual RWOP failure unclassified.
- **`mayor-cv3jo` P1 (7 failures) — CLOSED as UPSTREAM KUBELET BUG** (see above).
- **`mayor-65e5w` P1 (2 failures) — CLOSED**, PR #1048 merged.
- **`mayor-xbfm0` P2 (2 failures)** — VAC missing vac-protection finalizer. Confirmed VAC IS registered (`state.rs:1324-1325`), narrow finalizer-only gap. Not yet dispatched.
- **`mayor-cst7t`** — updated with 7 snapshot-family test names. Operator has said this is low-prio (not in `[Conformance]`).
- **`mayor-51z5g`** — updated with 15 additional "still exists within 20m0s" cross-refs. Watchdog theory would only resolve 2 of 15; others are compound with rcujn/cv3jo/65e5w.
- **`mayor-w44wg`** — added 1 DiskPressure test.

## Resolved during wrap-up

- **PR #1049** (`mayor-pzize`) — rename worker completed the operator-requested `reject_disallowed_pvc_expansion → reject_disallowed_pvc_resize` update. Push landed at commit `d874509`. Awaiting CI re-run + merge (should complete cleanly per pre-push hook run).
- **`mayor-ag0e5` CLOSED as NOT-A-U7S-CODE-BUG.** Scout v2 (aa82864c86ab81711) found the root cause: **host-port collision in the conformance harness**, not a rustls/webpki/cert bug. Two concurrent scouts both defaulted to `--kubelet-port 10250`; whichever hostagent booted first won the `127.0.0.1:10250` bind; the second scout's apiserver tried to reach its own kubelet but connected to the FIRST scout's kubelet instead. Since every u7s CA uses hardcoded `CN=u7s-ca` (`crates/apiserver/src/tls.rs:179`), rustls's WebPkiServerVerifier found a name-matching trust anchor and legitimately rejected the misrouted leaf with `BadSignature`. **Rustls was validating correctly.** The confusion cost roughly 3 mayor cycles + 3 scout dispatches.
  - **Follow-on filed**: `mayor-dda10` P1 (harness auto-allocate or hard-fail on port collision), `mayor-2tc20` P2 (unique CA CN per stack for legible failure mode).
  - **Memory banked**: `host-port-collision-manifests-as-tls-badsignature` — how to diagnose this class in the future (`lsof -n -i :10250` + `openssl s_client -connect ... </dev/null`).

## Operator directions banked this session

Read these before starting the next session:

- **`mayor-dispatch-autonomy-default`** — mayor dispatches ready P1s + merges on-green without per-item approval. Only decisions/risky-ops need explicit go-ahead.
- **`mayor-does-not-do-scout-work-in-band`** — mayor is orchestration, not investigation. Grepping cert bytes, cross-comparing timestamps, running openssl verify pairs = scout work. Dispatch a scout with the methodology even for "quick" checks.
- **`mayor-broad-grep-patterns-produce-false-successes`** — when grep-verifying scout claims about counts, use TIGHT regexes anchored on subresource path (e.g. `uri=[^ ]*/(exec|log|attach)\?[^ ]*`), not broad substring matches. False-positive scale can be 10x-100x.
- **`mayor-must-grep-verify-scout-blast-radius-claims`** — "100% X" / "blocks ALL Y" scout claims require independent grep-verification before elevating priority or reprioritizing session direction. And when the operator pushes back on a scout claim, verify — do NOT defend the scout without evidence.
- **`upstream-tests-passing-means-bug-is-ours`** — default suspicion order: our code / our harness / our setup. Not "the upstream test is wrong."
- **`upstream-test-timeouts-are-ceilings-not-targets`** — upstream 20m timeouts are safety ceilings, not what tests are expected to take. Don't propose bumping our own thresholds to accommodate slowness; find why it's slow.
- **`u7s-kubelet-is-stock-upstream-not-u7s-code`** — u7s reimplements only apiserver/scheduler/KCM/store. Kubelet is stock Go. Bugs that live in kubelet-side code are upstream; u7s can only cause them via signals from apiserver/KCM.
- **`scouts-must-not-delete-shared-vm-state-without-authorization`** — scouts sharing a VM must NOT `sudo rm -rf` sibling-scout artifacts to free disk. STOP and report.
- **`sonobuoy-junit-missing-when-e2e-container-exits-abnormally`** — when e2e-job pod ends in Error status, sonobuoy tarball won't have junit_01.xml. Use `plugins/e2e/results/global/e2e.log` grep `\[FAILED\]` for triage.
- **`vm-memory-edit-requires-kubelet-reconnect-not-just-kcm-restart`** — `limactl edit --memory` procedure needs `run-all.sh --stack-only` to reconnect kubelet (its systemd unit is disabled by base image, only started imperatively).
- **`host-port-collision-manifests-as-tls-badsignature`** — when dispatching multiple concurrent VM-using scouts, ALWAYS pass explicit non-default `--port` and `--kubelet-port` from the standard slot table in `ai/prompts/vm-operations.md`. Silent bind race → cross-stack cert misroute → rustls `BadSignature`. Diagnose with `lsof -n -i :10250` + `openssl s_client -connect 127.0.0.1:10250 </dev/null`.
- **`mayor-does-not-do-scout-work-in-band`** — grepping cert bytes, comparing cert pairs, running openssl verify comparisons = scout work. Even for "quick" checks, dispatch a scout with the methodology.
- **`mayor-broad-grep-patterns-produce-false-successes`** — verify scout claims with TIGHT regexes anchored on the specific field (`uri=[^ ]*/(exec|log|attach)\?[^ ]*`), not broad substring matches. Same class of trap: `status`, `system`, `watch` all appear in unrelated URL substrings.

## Fresh-mayor onramp for next session

1. `bd prime` — restore session cron loops (none currently registered; the standard bootstrap set should be re-created).
2. Read `ai/dashboard.md` — the SNAPSHOT of state at handoff.
3. Read this handoff doc for the context of decisions made.
4. Skim the 10 memories banked this session (search `bd memories 2026-08-07`).
5. Check `mayor-ag0e5` bead notes for the cert-investigation status. If scout v2 finished mid-handoff-write, its findings memo at `temp/e2e-memory-samples/scout-ag0e5-v2/findings.md` may exist.

## Ready to dispatch next session (all queued, none blocked)

- **`mayor-xbfm0`** — VAC finalizer, narrow gap
- **`mayor-drs2a`** — SqliteStore shard (structural P1, will need its own dedicated attention)
- **`mayor-qq14v`** — pod_log silent-fail diagnostic warn (~5-10 LoC)
- **`mayor-l3kch`** — vm-operations.md doc update
- **`mayor-6ii27`** — kubectl describe node returns unfiltered pod list

## What needs YOUR attention next session

- **`mayor-dda10` (P1)** — the port-collision fix in `scripts/conformance/lima-start.sh`. This is a real dispatch decision: Option A (auto-allocate a free port when default collides) vs Option B (hard-fail with a clear error). B is simpler and matches the "operator explicitly chooses" convention; A is more scout-friendly. Small worker either way (~20 LoC).
- **`mayor-cv3jo` outcome** — the pod-termination-hang is confirmed UPSTREAM KUBELET, NOT u7s. Options: (a) file upstream, (b) treat as known-flaky and document, or (c) reduce reproducibility via u7s-side apiserver-latency-injection (explicit hack). Recommended (b) for now.
- **`mayor-cst7t`** — VolumeSnapshot API still low-prio per your direction. If HPA becomes a session goal, `mayor-vjnqa` (CRD-backed resources have no scale subresource) is the higher-leverage HPA blocker.
- **PR #1049 rename** — merges automatically after the rename push's CI goes green. No decision needed.

**Nothing else is genuinely blocking — full P1/P2 backlog is now dispatchable.** The 3 in-flight items at the START of this session's wrap-up all completed cleanly: 3 PRs merged (1048, 1050, 1051), 2 scout memos with root causes.

## Repo state at close

- Main at HEAD `901a1120` (post-#1051 merge). Will advance to include PR #1049 after its CI passes and mayor merges.
- Worktrees at close: 0 (all pruned).
- VMs at close: lima-node/-3 up (operator), lima-node-2 available (rcujn/cv3jo v2 leftover safe to lose), lima-node-4 up (was ag0e5 evidence — root cause is now known as scout-environment host-port collision, safe to reset), lima-node-5 DiskPressure-degraded (safe to delete or reprovision).
- Uncommitted operator edits: `M scripts/conformance/06-run-sonobuoy.sh` (temp `--procs=4` for this session's runs).

Bead: mayor-c8wfg

# bd memory audit (working draft; summary sections are added at the end)

## Batch rows (raw; regrouped in the final tables)

| key | class | evidence | action |
|---|---|---|---|
| adrs-are-immutable-supersede-never-rewrite-operator-rule | KEEP | operator rule 2026-11-02; docs/decisions/ exists | - |
| all-e2e-intentionally-maximally-inclusive | KEEP | operator stance 2026-08-14; run-all.sh still has --all-e2e | - |
| all-lima-vms-share-vsock-fallback-limitation | STALE | lima/kubelet.yaml:58,60 now points at ubuntu 26.04 cloud images (the "fix in scope" bump landed); the 24.04/systemd 255 premise is gone | forget all-lima-vms-share-vsock-fallback-limitation |
| allocatedresourcesstatus-orphaned-mergekey-upstream-and-u7s | KEEP | crates/apiserver/src/patch.rs:3518 test and known_ambiguous allowlist exist | - |
| allow-dead-code-review-heuristic-adjacent-comment-required | KEEP | sa_sig_cache.rs still exists; heuristic is generic | - |
| apiserver-dev-loop | KEEP | scripts/conformance/run-all.sh, ai/prompts/vm-operations.md exist | - |
| architectural-decisions-phase-2-db-01-resourceversion-0 | STALE | Phase-2 design snapshot; DB-04 "No scheduler skeleton in Phase 2" is moot, crates/scheduler exists; nothing actionable, state-store design lives in ai/prompts/state-store.md | forget architectural-decisions-phase-2-db-01-resourceversion-0 |
| architectural-reasoning-is-not-verification | KEEP | quotes operator "Any change must be verified locally before merging code"; generic lesson | - |
| archive-unmerged-findings-as-tag-not-branch | KEEP | scripts/worktree-hygiene.sh exists; archive/* tags exist in git tag | - |
| auth-middleware-check-is-exempt-list-when-fixing-request-pipeline | PARTIALLY-STALE | rg is_exempt crates: no match; AuthLayer::is_exempt is gone | rewrite auth-middleware-check-is-exempt-list-when-fixing-request-pipeline: DISCOVERY 2026-08-15 (mayor-ymvrw PR #1199): when adding request-pipeline middleware (APF classification, admission hooks, metrics), first check whether the target endpoint bypasses AuthLayer entirely; a bypassed endpoint never sees middleware wired into that chain. Example: the APF conformance test targets /version, which used to bypass AuthLayer, so APF classification never ran for it; the fix routed /version through AuthLayer and kept anonymous access via the system:public-info-viewer RBAC grant. A bypass is not a no-auth-required flag; grant anonymous access through RBAC instead. Reverse: if a test on one endpoint shows the middleware never ran, check for a bypass before assuming the middleware is buggy. |
| authlayer-must-skip-watch-verb-for-request-total-double-count | KEEP | auth.rs:6244 test auth_layer_records_request_total_but_does_not_mutate_response_headers_on_chunked_watch still encodes the invariant | - |
| auto-close-needs-worker-pr-note | PARTIALLY-STALE | mayor-fzgx8 status is closed, so "Until fzgx8 merges, keep the tick cron off" is obsolete | rewrite auto-close-needs-worker-pr-note: mayor-tick's merged-PR scan (PR #1887) must not close a bead just because a merged PR's title names it: partial PRs, epics, umbrella beads and pending-measurement beads were wrongly closed on its first run (2026-10-17) and reopened. The fix (mayor-fzgx8, merged) closes only beads carrying the worker note "PR #N opened" for that PR and not "(partial". When a PR does only part of a bead, the worker notes "(partial: ...)". |
| bd-create-shell-metachars-use-body-file | KEEP | bd create --help confirms --body-file, --stdin, --design-file | - |
| bd-dep-add-direction-epic-child | KEEP | generic bd semantics, 2026-11-04 | - |
| bd-update-notes-replaces-use-bd-note | KEEP | generic bd semantics | - |
| bead-snapshot-pr-at-session-close | KEEP | operator decision 2026-10-09; nothing later supersedes it (see note in conflicts table: bookkeeping-prs-use-haiku-reviewer refines the review step only) | - |
| beads-close-on-merge-not-pr-open | KEEP | operator decision 2026-10-17; matches worker.md step 8 | - |
| beep-u7s-kube-proxy-ipvs-vip-hijack-conflict-and-dataplane-blocked | SUPERSEDED | self-labelled SUPERSEDED 2026-10-13 (mayor-re973 round 5); only the lesson survives | rewrite beep-u7s-kube-proxy-ipvs-vip-hijack-conflict-and-dataplane-blocked: beep v0.4.0 on SHIPPED u7s (flannel VXLAN + iptables kube-proxy, 2 nodes + foreign client) passes the happy-path gate (mayor-re973 round 5, 2026-10-13). Rounds 2-3 (2026-09-15) "data plane blocked" was measured on the NON-shipped cri-o bridge CNI under IPVS kube-proxy, where IPVS binds LB ingress IPs onto kube-ipvs0 and hijacks the VIP. Lesson: never judge beep on an IPVS or bridge-CNI rig; test on shipped flannel+iptables. Trail: bd show mayor-re973. |
| beep-u7s-wg-transport-does-not-fix-dataplane-0-response | DUPLICATE | same mayor-re973 round-3 retraction as the entry above; adds no lesson | merge beep-u7s-wg-transport-does-not-fix-dataplane-0-response into beep-u7s-kube-proxy-ipvs-vip-hijack-conflict-and-dataplane-blocked: (use the rewrite text above; additionally: the round-3 "WireGuard transport does not fix the 0-response data plane" result was on the bridge-CNI rig, do not cite it as a beep data-plane bug) |
| bisection-incremental-cherry-pick-technique | KEEP | generic technique; cross-ref content-type-header-mutation-breaks-watch-streams exists | - |
| bookkeeping-prs-use-haiku-reviewer | KEEP | operator 2026-10-19 | - |
| boon-1024-byte-pattern-empirical-657ms | PARTIALLY-STALE | PoC test poc_timing_boon_ecma_compat_shim_is_quadratic exists at cr.rs:28189 but the cap/timing are a 2026-07-28 point-in-time measurement; PR #924 is merged | rewrite boon-1024-byte-pattern-empirical-657ms: Empirical boon::Compiler::compile cost on d-repeated patterns (2026-07-28, mayor-cmtwm): 1 byte 18ms, 1024 bytes 657ms, 4096 bytes 9400ms (x14.3 per x4 size, close to quadratic), 16384 bytes over 60s. The 1024-byte pattern cap bounds one compile at about 657ms. Opt-in PoC: crates/apiserver/src/handlers/cr.rs poc_timing_boon_ecma_compat_shim_is_quadratic (cargo test -- --ignored). Lesson: audit cost estimates extrapolated linearly across 3 decades of input are unreliable for quadratic algorithms; require an empirical timing PoC at the proposed cap before locking it. |
| bpf-linker-miscompiles-noninlined-call-returning-option | STALE | crates/servicelb removed (commit 4cab7346, "migrated to litehop/beep"); no aya/eBPF code remains in this repo | forget bpf-linker-miscompiles-noninlined-call-returning-option |
| bsd-sed-i-leaves-dash-e-backup-files | KEEP | generic macOS gotcha | - |
| burst-gate-install-only-needs-tarball-scripts-release | KEEP | burst-gate.sh header: --install-only is experiment-only, with --tarball | - |
| burst-gate-runs-must-be-time-boxed-operator | KEEP | operator 2026-11-05 | - |
| burst-gate-workers-must-term-their-own-gate | KEEP | scripts/release-gate/burst-gate.sh exists with trap | - |
| ca-cn-load-path-must-read-from-cert-not-hardcode | KEEP | tls.rs:96 load_or_generate_ca exists; CLAUDE.md cites this memory as the example | - |
| changelog-wanted-later-not-for-first-release | KEEP | operator 2026-11-16; v0.4.5 is already tagged, so "first non-snapshot release (v0.4.4-ish)" is outdated wording: ask operator whether the changelog bead should now be scheduled | - |
| check-non-conformance-e2e-before-manual-wire-test | KEEP | operator guidance 2026-08-20; also present in ai/prompts/mayor-dispatch-template.md:396-403 (doc duplicate, not forgettable without operator) | - |

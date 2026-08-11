---
name: mayor-handoff-2026-08-11-close
description: Session handoff — 2026-08-11. Proto-descriptor oracle initiative completed end-to-end (matcher strict, ~14 zero-KNOWN_GAPS sentinels landed). KCM-protobuf-flip investigation arc closed (root-caused as EndpointPort.name empty-string decode drop; fix landed). 18 PRs merged, 35 beads closed, 13 memories banked.
metadata:
  type: session-handoff
  date: 2026-08-11
---

# Session handoff — 2026-08-11 close

Session ran ~2026-08-11 01:46Z through ~11:19Z (~9.5 hours). Mayor: Opus 4.7 (1M) at
xhigh effort. Dispatched via `The Mayor Method`. Base HEAD at session-open: `d7ca8255`.
Close HEAD: `57481c85`.

## Session shape

Heavy correctness cadence (18 PRs, 6 direct decoder fixes, 4 refactor/infra PRs, 4
audit scouts producing actionable follow-ups). Two multi-hop investigation arcs closed
that had been open across multiple prior sessions. One folklore-worker-cap
discipline correction from operator that saved probable future drift.

## What landed (18 PRs, chronological)

- **#1104** mayor-j430l — schema-derived completeness oracle. `build.rs` emits
  FileDescriptorSet into `OUT_DIR`; `crates/apiserver/src/proto_descriptor.rs` walks
  it to derive expected JSON keys from schema (not from human recollection). Four
  exception tables (`OPAQUE_MESSAGES`, `RENAMES`, `DELIBERATE_OMISSIONS`,
  `KNOWN_GAPS`).
- **#1105** mayor-y0pcm — **P0** pod-status wipe sealed. Protobuf PUT
  `/pods/{name}/status` was returning 200 while destroying `containerStatuses` +
  49 other PodStatus fields. 6 top-level PodStatus arrays now decoded end-to-end
  with zero KNOWN_GAPS. Also unblocked the KCM-protobuf-flip investigation
  (KCM pod-GC calls PUT `/status`).
- **#1106** cluster (bzft0 + 174wl + 7ze14 + h9gv7) — 4 decode gaps + 1 pre-existing
  casing bug (`daemonEndpoints.kubeletEndpoint` was emitted as `"Port"` instead
  of `"port"`, caught for free by the sentinel).
- **#1107** cluster (hfoid + p0dyr) — foundational oracle tables.
  `DELIBERATE_OMISSIONS` for 37 legacy in-tree volume plugins (CSI migration).
  `INLINE_EMBEDS` for 7 Go `json:",inline"` false positives.
- **#1108** mayor-ie8d8 — DRA sentinel coverage (test-only). Worker discovered via
  empirical probing that the bead's "3 real drops" premise was actually a survey
  harness limitation, not decoder bugs. Rule 7 in action.
- **#1109** mayor-n0ahk — SecurityContext hardening (7 named fields + 1 bonus
  `PodSecurityContext.appArmorProfile` the worker found). User-visible seal:
  protobuf clients now correctly persist SecurityContext hardening controls.
- **#1110** mayor-9jtjp — DELIBERATE_OMISSIONS reason strings in evidence-citing
  format. Fixed 4 false-deprecation claims (`fc`/`iscsi` were NOT actually
  upstream-deprecated despite prior reason string claiming so).
- **#1111** mayor-onb44 — VolumeSource.nfs decode gap sealed (Pod-level NFS
  volumes silently dropped on protobuf writes).
- **#1112** mayor-9qrhc — Secret* INLINE_EMBEDS follow-on.
- **#1113** cluster (aj53s + xn6ou + 3yjyx + a8v1w) — 4-bead P2 decode-gap
  cluster. Aggregate survey delta 76 → 14 missing keys across 21 decoders.
  Rule-7 finding: worker refused to fabricate a deprecation citation for
  `Probe.handler` (bead premise wrong).
- **#1114** mayor-jhuw2 — sentinel_completeness tests for HPA v1 + v2.
- **#1115** mayor-66qj6 — **CAPSTONE** of the oracle initiative. Strict-migrate
  matcher from any-segment to exact leaf path; walk emits dotted paths; 61
  consumer sites migrated across 12 files in one PR. Worker survived 2 API-side
  stream timeouts via SendMessage resume. Found + fixed 2 real drops in-band
  (SA.secrets ObjectReference fields + Container/PodSpec resources.claims DRA
  refs).
- **#1116** mayor-a9kc1 — bytes-cache for `build_aggregated_discovery`. 3-order
  wall-clock speedup + ~half memory footprint on the discovery hot path per
  k3pxp measurement. Worker deviated sensibly from brief (cached plain-data
  snapshot not raw Bytes since `types.rs` was off-limits + `mayor-ohh8o`
  test forbids `serde_json::Value`/`json!` in that function).
- **#1117** mayor-77b49 — HashMap dispatch for `decode_proto_by_kind_and_version`.
  62 of 64 arms migrated to `OnceLock<HashMap<&str, DecoderFn>>`. 2 kept as
  pre-hook (Event/HPA versioned fallback).
- **#1118** mayor-u6rec — dhat max backtrace depth bumped to 50. Worker read the
  actual dhat crate source rather than guessing the API — real method is
  `trim_backtraces(Option<usize>)` not `.max_backtrace_frames()`.
- **#1119** mayor-vjnqa — CRD scale subresource. HPA-targeting-CRD unblocks.
  Hand-rolled 30-line JSONPath walker after verifying no in-tree parser fit
  (no new dep). Sonobuoy PASS 7/7 CustomResourceDefinition. Bonus follow-on
  filed (mayor-hl7py).
- **#1120** mayor-hl7py — CRD subresources now advertised in classic + aggregated
  discovery. Fixes client-go ScaleKindResolver failing before making any
  network call.
- **#1121** mayor-mb9ed — **KCM-protobuf-flip arc closed**. 1-line fix:
  `.filter(|s| !s.is_empty())` removed from `EndpointPort.name` decode.
  Sonobuoy PASS on the exact failing spec verified live.

## Beads closed without a PR

- **mayor-jrf8x** (P4) — closed as trigger-only marker (revisit-if-X-Y-Z bead
  didn't belong in ready queue).
- **mayor-noub6** (P2) — closed as upstream-kubelet, not u7s. Memory banked
  (`kubelet-eviction-manager-cannot-preempt-sub-60s-bursts-upstream-limitation`).
- **mayor-ecs8b** (P0) — closed as premise-falsified (scout ran single-node
  Conformance despite well-known 2-node requirement, OOM was topology
  mismatch not regression). Replaced by fresh `mayor-cy4ci` (P2, sonobuoy
  QoS improvement — deferred).
- **mayor-5xgtm** (P3) — rescoped to live-verification scout (was speculative
  "likely working via KCM" bead, not a fix bead).
- **mayor-8qcaw** (EPIC, DRA) — deferred with note. Un-defer when backlog
  clears.
- **mayor-u6ju** (EPIC, SSA) — deferred with un-defer trigger (research
  showing Helm/Argo/Flux require SSA).
- **mayor-cst7t** (P2, VolumeSnapshot API) — scoped-and-deferred. Scout
  measured all 3 options concretely; operator deferred implementation.
  Findings preserved.
- **mayor-jw8wf** (P3, Serial specs interleaving) — closed as premise-false
  (operator verified e2e-skip is only [Flaky]; no evidence Serial specs ever
  parallelized causing failure).
- **mayor-z1p1u** (P3, mutating-webhook namespaceSelector) — narrowed. Prior
  worker sessions attempted extensive live-repro without reproducing;
  scout found the archived failing run has aged out, but 4 fresh full-suite
  runs since have all passed. Filed follow-on `mayor-odsv6` for
  observability improvement in `admission.rs:1230`.
- **mayor-zp7jj / mayor-edqgg** — parts of the KCM-protobuf-flip arc, closed
  after `mb9ed` root-caused it.
- **mayor-k3pxp** (P2, discovery cache) — closed after scout picked winner
  (bytes-cache), implementer bead filed as `mayor-a9kc1` (landed as #1116).
- **mayor-9jlei** (P2, protobuf response scoping) — closed with operator
  picking Option A (proper protobuf response encoder for hot-path types).
  Implementer bead filed as `mayor-re0a5`.

## Memories banked (13)

New / substantially-revised:
- `mayor-worker-cap-is-folklore-not-policy` — the "2-worker soft cap" is
  self-invented folklore, not documented policy. Correction after operator
  pointed out prior mayors independently invented the same rule.
- `operator-companion-vm-reservation-lifted-2026-08-11` — `lima-node-3` is a
  normal pool VM, not reserved.
- `filter-is-empty-idiom-drops-semantically-meaningful-empty-strings` — the
  Rust idiom `Option::filter(|s| !s.is_empty())` collapses present-but-empty
  strings into absent JSON keys; wrong when empty-string has distinct
  semantic meaning (EndpointPort.name being the load-bearing case).
- `bead-premise-verify-against-source-before-writing-fix` — workers should
  probe bead premises against source before implementing. Twice this session
  workers refused to fabricate fixes for bead premises that turned out
  wrong (ie8d8 RawExtension "drops" that weren't; a8v1w Container.handler
  that isn't actually a field).
- `oracle-any-segment-matcher-caveat-live-example` — live evidence from PR
  #1106 (bzft0) that the pre-66qj6 matcher missed real drops.
- `proto-schema-walk-container-fields-are-not-leaves` — design insight from
  mayor-66qj6 worker's expansion beyond the mayor's brief.
- `seed-metrics-server-makes-has-apiservice-always-true` — structural fact
  overturning the discovery-cache design.
- `oracle-survey-sentinel-vs-real-rawextension-drop` — survey harness limit.
- `daemonendpoints-port-casing-bug-fixed-h9gv7` — port-casing bug class.
- `kubelet-eviction-manager-cannot-preempt-sub-60s-bursts-upstream-limitation`
  — from noub6 close.
- `kcm-protobuf-flip-partial-2026-08-11` — progress state (superseded by
  mb9ed's landing, but the "endpoints-correct-but-connection-refused is
  NOT a data-plane bug" rule is still relevant for future decoder-bug
  investigations).

## The two multi-session investigation arcs closed

### Arc 1 — Proto-descriptor oracle initiative (mayor-j430l → mayor-66qj6)

Started as a prototype on branch `proto-descriptor-oracle` at session-open.
Ended as: matcher strict + walk emits dotted leaf paths + 61 consumer sites
migrated + 14 zero-KNOWN_GAPS sentinels landed across the adapter surface.
Aggregate survey went from 442/1781 missing keys → 14/1523 → ~2 after
mb9ed's fix.

**Consequence for the "silent decode-drop bug class"**: future decode drops
of this shape are now caught by `cargo test` instead of reaching production
behind a falsely-green sentinel. This closes a bug class that had produced
~10 fresh silent-drop bugs in the month before this session.

### Arc 2 — KCM-protobuf-flip investigation (mayor-zp7jj → mb9ed)

Cross-session arc that had been open for ~2 weeks. Root cause was NOT
what any of the prior 3 scouts had inferred:
- Original hypothesis (Endpoints/EndpointSlice decode drop) — refuted by
  source audit (round-1 scout).
- Post-y0pcm+h9gv7 hypothesis (kube-proxy data-plane) — under-supported.
  Operator pushback + corrected framing led to a `--focus` reproduction
  that isolated the trigger to the flip itself, then live kube-proxy log
  correlation identified `.filter(|s| !s.is_empty())` on EndpointPort.name
  as the true root cause. Fix landed in mb9ed.

**KCM protobuf-flip is now ship-safe** pending operator decision to permanentize
the 1-line flag change (diff preserved at
`ai/findings/zp7jj-kcm-protobuf-flip.diff`).

## What needs operator attention next session

### High-priority ready-for-dispatch (clean solo/scout shape)

1. **mayor-re0a5** (P2, filed this session) — implement protobuf response
   encoder for hot-path types (Pod, EndpointSlice, Endpoints, Event, Service,
   Node). Option A picked by operator on mayor-9jlei scout's cost data.
   ~500-800 LoC (JSON→typed-struct conversion is the mirror of decode
   direction; prost handles encode natively). Wire-perf win: ~1.8-1.9x on
   hot paths. Real spec compliance. Findings doc:
   `ai/findings/protobuf-response-scoping-2026-08-11.md`.

2. **mayor-5di71** (P3) — DRA v1alpha3 resourcepoolstatusrequests (9
   conformance failures). Small `state.rs` edit. Verify upstream 1.36 has
   this resource first (may be an upstream-not-required situation).

3. **mayor-i2068** (P2 audit, filed this session) — systemic scan of 671
   `.filter(|s| !s.is_empty())` sites in `_gen_adapter.rs` for
   silent-drop-on-empty-string bugs of the same class as mb9ed. Read-only
   scout shape, produces per-site triage.

4. **mayor-cy4ci** (P2) — sonobuoy e2e-job pod QoS to Burstable/Guaranteed
   for test reliability. Needs 2-node conformance verification.

5. **mayor-9r0oa** (P3) — metagen consolidation across `_gen_adapter.rs`.
   Broad blast radius; serialize behind other adapter-touching work.

### Operator-attention scheduling (not solo-dispatchable)

- **mayor-eegsu** (P3, filed this session by u6rec worker) — dhat recapture
  run + re-triage scout. Operator schedules the run (now that
  `run-all.sh --profile` handles SIGTERM automatically per PR #1041).

- **mayor-edqgg / mayor-zp7jj follow-up** — permanentize the KCM
  protobuf-flip flag if you want the wire-perf win from KCM's side (u7s side
  is separate = mayor-re0a5).

### Deferred with explicit un-defer triggers

- `mayor-u6ju` (SSA EPIC) — un-defer trigger is "research shows Helm/
  Argo/Flux requires SSA."
- `mayor-8qcaw` (DRA EPIC) — un-defer when backlog otherwise clears OR
  specific conformance failure traces back to DRA claim allocation.

## Follow-on beads filed this session (bd IDs, for grep)

`mayor-9r0oa`, `mayor-77b49` (from #1106 scope-flags), `mayor-eo6ll` (from
#1117 completeness-test deferral), `mayor-eegsu` (from #1118 recapture),
`mayor-hl7py` (from #1119 vjnqa live-verify — landed as #1120),
`mayor-9qrhc` (from #1107 Secret family — landed as #1112),
`mayor-cy4ci` (from ecs8b close), `mayor-onb44` (from ukpnw audit —
landed as #1111), `mayor-a9kc1` (from k3pxp scout — landed as #1116),
`mayor-mb9ed` (from edqgg scout — landed as #1121),
`mayor-odsv6` (from z1p1u scout), `mayor-i2068` (from mb9ed's follow-on
audit), `mayor-re0a5` (from 9jlei scout, operator picked Option A),
`mayor-ukpnw` (deprecation audit, closed with 1 follow-on `mayor-9jtjp` —
landed as #1110). Not counting the 3tu3t audit's 9 follow-ons already
landed as parts of #1107/1108/1109/1113/1114.

## Repo state at close

- Main at HEAD `57481c85` (after 18 PRs merged this session).
- Local worktrees: 0 (all cleaned).
- Local worker branches: 0.
- Local remote-tracking origin/worker/*: 0 (all pruned).
- Open PRs: 0.
- VMs: `lima-node`, `lima-node-2`, `lima-node-3`, `lima-node-4`,
  `lima-node-5` all Running (all idle). `lima-node-smoke` unprovisioned.
- Cron loops: 0 session-only (all cancelled at close). Durable
  `c6250b1c` (Sunday 19:37 UTC extended-context freshness) still registered.
- Stashes: 0.

## Fresh-mayor onramp for next session

1. `bd prime` — restore beads workflow context.
2. Read `ai/dashboard.md` — CLOSED snapshot.
3. Read this handoff doc for context.
4. `bd memories 2026-08-11` — 13 memories banked this session.
5. Findings docs preserved for future work:
   - `ai/findings/proto-decode-oracle-rollout-survey-2026-08-11.md` (mayor-3tu3t)
   - `ai/findings/deprecation-consistency-audit-2026-08-11.md` (mayor-ukpnw)
   - `ai/findings/discovery-cache-value-vs-bytes-measurement-2026-08-11.md` (mayor-k3pxp)
   - `ai/findings/snapshot-api-scoping-2026-08-11.md` (mayor-cst7t)
   - `ai/findings/z1p1u-tracing-scout-2026-08-11.md`
   - `ai/findings/zp7jj-endpoints-decoder-audit-2026-08-11.md` (round 1)
   - `ai/findings/zp7jj-rerun-2026-08-11.md` (round 2)
   - `ai/findings/zp7jj-kcm-protobuf-flip.diff` (1-line diff, ready-to-apply)
   - `ai/findings/edqgg-scout-2026-08-11.md` (root cause)
   - `ai/findings/protobuf-response-scoping-2026-08-11.md` (option A picked)
   - `ai/findings/mayor-k3pxp-bench-harness/` (reusable perf benches)

## Lessons for future mayors

- **Do not invent numeric worker caps out of caution.** File-surface collisions
  + VM availability + host resources + attention are the real constraints.
  Prior mayors have independently invented a "2-worker soft cap" out of
  caution multiple times; write the true constraints into the dispatch-loop
  cron body, not a made-up number.
- **Push back on scout inferences that skip evidence.** Twice this session
  scouts inferred plausible-sounding root causes that were under-supported
  by evidence (ie8d8 RawExtension, edqgg kube-proxy data-plane). The correct
  pattern is: acknowledge the scout's observations as evidence, then push
  back on their inference-to-cause. Root-causing bugs correctly matters
  more than clearing a scout task.
- **`--focus` reproduction is cheaper signal than full conformance re-runs.**
  When investigating a specific conformance failure, prefer
  `sonobuoy --focus <regex>` on the specific spec. ~2-3 min per invocation
  vs ~25 min for full suite. Only use full-suite as a final gate.
- **The Rust idiom `Option::filter(|s| !s.is_empty())` is a smell in decoders.**
  It collapses present-but-empty into absent, which is wrong for fields
  where empty-string has distinct semantic meaning. `mayor-i2068` filed
  the systemic audit.
- **Worker resume via SendMessage works excellently across API-side stream
  timeouts.** The mayor-66qj6 worker survived 2 stream timeouts + 2 resumes
  with worktree state preserved and picked up cleanly both times. Do not
  re-dispatch a fresh Agent on stream-timeout completion notifications —
  SendMessage the original agentId.
- **Write bd memory / bd note content with single-quotes in zsh.** Backticks
  in memory bodies get interpreted as command substitution and silently
  drop tokens. Also parens (per the pre-existing memory
  `bd-create-description-zsh-glob`). Two incidents this session.

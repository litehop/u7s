# KCM Rust port, Phase 2 design

Bead: mayor-w9xt5
Date: 2026-11-24 (main a1b0a1e0)

Sources: Phase 1 audit (`2026-09-16-mayor-vc844-...`), mayor-w898x memory decomposition (branch `871d58e7`), roadmap Gate 4, `scripts/install.sh:2712`, `scripts/conformance/*`, `.github/workflows/e2e-focus.yaml`, upstream v1.35.0 `test/e2e/apps` and `test/integration` listings (`gh api`, `temp/research/`).

**Recommendation:** port KCM as a separate Rust process that runs alongside upstream KCM, one controller group at a time, where every phase must clear a total-KCM-side memory ceiling (hybrid phases included, no higher than today's shipped Go KCM, and cumulatively no higher than the trimmed-Go baseline) and a sonobuoy gate (identical executed spec-name set, no new failures, zero KCM restarts) before it merges. The Rust process talks to the apiserver over loopback HTTP with per-controller identities, and each phase has an `--controllers` kill switch back to Go. Phase 0 is the measurement harness plus a validated Go trim, which funds the Rust process's fixed memory cost.

**Tags and units.** Every number is MEASURED (source named) or TARGET (proposed, not yet measured). All sizes are MiB; w898x and the Phase 1 audit print "MB", and those figures are read as MiB (the difference is under 5% and below the noise band).

## 1. Memory: the first-class constraint

### Baseline (what a port must beat)

| Quantity | Value | Tag, source |
|---|---|---|
| KCM peak PSS, release-gate run | 76-81 MiB | MEASURED, roadmap 2026-10-15 |
| KCM anon, shipped config (idle / WordPress / 50-pod burst) | 40.2 / 41.9 / 45.2 MiB | MEASURED, w898x |
| KCM anon, trimmed `--controllers` (stock env, idle / WordPress) | 31.7 / 33.4 MiB | MEASURED, w898x |
| KCM file-backed PSS (73 MiB binary) | 9 MiB loaded, 50 MiB idle | MEASURED, w898x |
| Rewrite-only residual after flags | 10-22 MiB | MEASURED, w898x |
| u7s-apiserver PSS | 27-31 MiB | MEASURED, w898x run tables; Phase 0 re-measures it as `Pss_Anon` |
| Rust KCM fixed cost (runtime, TLS, binary data) | at most 8 MiB | TARGET; no measurement exists, Phase 0 spike measures it |
| Single-run variation | about 3 MiB | MEASURED, w898x |

Two consequences. (1) Anon is the comparable number, because file-backed pages are reclaimable. (2) At this object count the Go cost is runtime, type registration and goroutines (1469 goroutines, 7 MiB of stacks; MEASURED, w898x), not caches. Cache design matters for scale, not for today's small clusters.

The bar is the **trimmed** Go KCM (33.4 MiB at WordPress), not the shipped 41.9, because the trim is nearly free. It drops 11 controllers, including HPA and TTL, and no conformance run has confirmed it; Phase 0 validates it first (invariant 3).

### Cache and informer strategy

- One Rust process with one shared informer per type for all ported controllers (one Pod cache, not one per controller). **Required.**
- Narrow own structs, so serde drops unread fields at parse time (keeps labels, ownerRefs, selector, phase, the few spec fields read). **Default.** Full typed objects (k8s-openapi style) retain `managedFields` and every optional field; reject for Pod and Node.
- Metadata-only watch (`as=PartialObjectMetadata`) where only owner/labels are read (GC, podgc): smallest, but needs apiserver support. Open check.
- Each extra watcher costs apiserver buffering, so apiserver anon is in the gate total.

The hybrid problem is structural. Go KCM's informer factory only starts informers some enabled controller needs, and the Pod informer is shared by GC, podgc, disruption, HPA, attach-detach and others. Porting ReplicaSet therefore frees almost nothing in Go while adding a second Pod cache plus a second apiserver watch. The Pod duplication ends only when the last Pod consumer leaves Go, so order the port to make that happen late and keep the Rust Pod cache a narrow projection.

### Per-phase budget and measurement

Metric: `Pss_Anon` from `/proc/<pid>/smaps_rollup` for KCM-Go, KCM-Rust and u7s-apiserver. Today's `sample-run-metrics.sh` records `ps` RSS for the busiest processes, so a PSS-anon column and a `kcm-mem.json` output are new Phase 0 work. Protocol is the w898x one: gate template (`scripts/release-gate/u7s-vps-1g.yaml`, 1 vCPU, 1 GiB, no swap), `--install` mode, three stages (idle, WordPress+MariaDB, 50-pod burst).

**The one memory rule (gate on total per phase, not per controller).** Per-controller leave-one-out savings are not gateable: the hybrid Go side frees almost nothing per port and the 3 MiB run-to-run variation exceeds most of them. So the gate is the total `anon(KCM-Go) + anon(KCM-Rust) + anon(apiserver)` per stage, and the Phase 0 leave-one-out table is used only to order ports. Procedure: on one VM, same day, run the shipped Go-only config (R) and the phase build (H) three times each, interleaved; take medians per stage. Noise band: 3 MiB. An INCONCLUSIVE 3-run result extends the same series to 5 runs each. The verdict is terminal per commit SHA: the 5-run result is final, neither the memory gate nor the sonobuoy gate is re-run on the same SHA, and all runs (the first 3 included) are kept in the committed result record. A new attempt needs a code change, so a new SHA, except under the infra-abort exception below.

> Infra-abort exception: a run is void only if it ended before the stage metrics and spec report were produced, with a harness or VM log naming a cause external to the build (VM or provider failure, harness script error, network loss to the VM). A run that completed, produced any stage metric or report, OOM-killed a unit, restarted a KCM unit, or failed a spec is never void. Void status is decided from the log by the operator or a required reviewer, not the PR author, and declared before the replacement run starts. A void run is replaced by one more run in the same interleaved series, is kept in the record with its log, and counts toward a cap of 2 voids per SHA; a third void is a FAIL for that SHA. A spec failure, timeout or flake is never an infra abort.

| Outcome | Arithmetic (per stage, all three stages) |
|---|---|
| PASS | `median(H) - median(R) <= 0` |
| INCONCLUSIVE | `0 < median(H) - median(R) <= 3` on 3 runs: extend to 5 runs each; PASS only if the 5-run median difference is `<= 0` |
| FAIL | difference `> 3` on 3 runs, or `> 0` on 5 runs |

**Cumulative cap.** The per-phase gate alone lets small passing regressions accumulate, so at each phase end also measure 5 runs each of the phase build H_k and the Phase 0 trimmed Go (T), interleaved on one VM. Let `K(x)` = `anon(KCM-Go) + anon(KCM-Rust)` (apiserver excluded) per stage. Require `median5(K(H_k)) - median5(K(T)) <= 0` at every stage. The cap is the same at every phase and never rises, so total KCM-side memory across all phases so far cannot exceed the trimmed-Go baseline. Same terminal-per-SHA rule.

Headroom comes from Phase 0: the trim is TARGET -8 (w898x measured 41.9 -> 33.4 at WordPress), so T sits about 8 MiB below R. The cumulative cap requires `median5(K(H_k)) - median5(K(T)) <= 0`, so `H = R` fails it. The Rust fixed cost (TARGET at most 8) must come out of the trim headroom: a Phase 1 build is the trimmed Go plus Rust, so it passes only if the Go side shrinks below T by at least the Rust cost. If Go saves nothing, Phase 1 fails the cap. Phase 0 itself passes if `median(R) - median(T) >= 5` (the -8 target minus the 3 band).

| Phase | Gate | TARGET budget |
|---|---|---|
| 0 | `median(R) - median(T) >= 5`, T = trimmed Go | none |
| 1-5 | hybrid total rule above, plus the cumulative cap vs T | Rust fixed cost at most 8; Pod cache at most N bytes/pod |
| 6 (Go KCM removed) | `median(total KCM anon, WordPress) <= 25`, at least 8 under trimmed Go (33.4 MEASURED); 50 MiB file-backed Go binary gone | whole Rust process at most 25 |

**N (bytes/pod).** The Phase 0 spike builds the Pod informer three ways (section 5) at 10k synthetic pods under a counting allocator and records bytes/pod B for each. `N = ceil(1.25 x B_chosen)`, rounded up to 64, and the Phase 0 PR commits N in `scripts/conformance/kcm-pod-bytes.txt`, which the CI test reads (under the invariant 1 pin). Until then the provisional TARGET is 1024 bytes/pod.

**Go/no-go after each phase.** Continue only if (a) the memory rule PASSes, (b) apiserver anon grew at most 2 MiB (median, same procedure), and (c) the projection holds. Projection, computed by a Phase 0 script (`scripts/conformance/kcm-memory-projection.sh`) from the phase's `kcm-mem.json`: `P = F + sum(m_c)` over all controllers, where F is Rust anon at WordPress with no controllers enabled, `m_c` for ported controllers is `(Rust anon - F) / ported count` split per controller, and for unported ones is the mean of the ported `m_c`. Require `P <= 33.4` (trimmed Go, MEASURED); the 25 TARGET is reported, not gated. Any miss stops the port and the operator decides.

**Regression catching (memory).** Add a deterministic CI test: load 10k synthetic pods into the Rust cache under a counting allocator (dhat tooling already exists in the rig) and assert bytes/pod against the budget. Wall-clock RSS gating stays local on Lima and in the existing release gate (`burst-gate.sh`), because the CI runner is not a 1 GiB VM.

## 2. Verification architecture

### Invariants that keep sonobuoy authoritative

1. **Config pin, independent of any port PR.** A committed `scripts/conformance/guard.sha256` holds the hashes of these pinned files plus the e2e binary version/digest. A CI job recomputes them on every PR and fails on any mismatch; the check is unconditional.
   - Pinned files: the e2e binary pin, the plugin config (`sonobuoy-plugin-e2e.yaml`) and every skip/focus list, the focus registry, the memory-projection script, `kcm-mem.json`, and the file holding N (`scripts/conformance/kcm-pod-bytes.txt`, committed by the Phase 0 PR; the CI test reads N from that file).
   - Changing the pin is a REQUIREMENT of its own PR: a pin-change PR may touch no `crates/kcm/` file, so a port PR cannot weaken the skip/focus logic.
   - Sign-off goes through CODEOWNERS entries naming the operator with required code-owner review (or a required-reviewer rule), not a label any collaborator can add.
2. **Spec-name set equality.** Every gated run extracts the executed spec names (ginkgo JSON/junit report, one line per spec, sorted) and requires them to be exactly equal to the committed baseline list, generated from the pinned untrimmed Go run. A swapped, renamed, added or skipped spec fails even at the same `Ran N`; the count is printed but not trusted. Environment-conditional specs (run only on some node, CRI or cloud conditions) are handled by recording that set explicitly in the baseline: the baseline run is repeated 3 times on the gate environment, and specs that differ between those runs are listed in a committed, pinned conditional set that each gated run must reproduce exactly. The match is never loosened. The baseline list is under the invariant 1 pin.
3. **Failure-set containment against untrimmed Go.** The baseline is a full 2-node run at a commit before the port started with the **untrimmed** shipped Go KCM, so the Phase 0 trim cannot hide trim-caused failures. Phase 0 runs the trimmed Go on the same suite and requires identical executed-spec and failure sets to the untrimmed run; any difference restores the responsible controller (this settles the HPA/TTL question by evidence). Afterwards, failures in a port run must be a subset of the untrimmed baseline's failures (known set: multi-node specs on single-node, etc.), compared by script, not by eye.
4. **Zero KCM restarts.** `kcm-supervisor.sh` restarts crashes under a circuit breaker, which can absorb a Rust crash while a short run still passes. A gate run fails if either unit's supervisor log records any restart or if either unit is not `active` at the end. Production keeps the supervision; the gate does not tolerate it. Open risk: a controller wedged but alive (deadlock, stuck watch) is not a restart. The failure-set and spec-set checks and the corpus diff are the only catch, and a liveness metric per controller is not designed here.
5. Run-meta records `kcm_mode` and the ported-controller list (run-meta already records topology). A "PASS" claim without it is rejected.
6. The standing merge rule applies: a sonobuoy PASS line quoted from `e2e.txt`, or operator signoff. Gated runs use `--install` mode, which runs the real `install.sh`, so the tested unit files are the shipped ones.

### Per-phase layers

- L0, `cargo test` in CI: pure reconcile functions with tables derived from upstream `pkg/controller/*_test.go` cases.
- L1, CI single-node: registered focus entries per controller in the sensitive-conformance focus registry, run by `sensitive-e2e-guard` on any diff under that controller's path.
- L2, local pre-merge: full suite on 2-node Lima, `run-all.sh --install`, 20-25 min. Authoritative for what single-node CI cannot gate (DaemonSet, multi-node specs); stays mandatory.
- L3, local: differential corpus (below). L4, local: memory gate (section 1). L5, per minor release: release-gate burst test.


### A/B, shadow and differential modes

All are feasible because KCM controllers hold no state: all state lives in the apiserver, and `--controllers` partitions work cleanly.

- **A/B suite** (every phase, two full runs, about 50 min): same suite with controller X on Go, then Rust, via a rig knob rendering both `--controllers` lists (does not exist yet). Diff pass/fail sets.
- **Shadow (read-only)**: Rust controller computes the writes it would make against a Go-managed cluster and logs a diff after convergence. For deterministic outputs (EndpointSlice, `kube-root-ca.crt`, default ServiceAccount); needs a dry-run flag; not for race-sensitive controllers (GC, node lifecycle).
- **Sequential corpus diff** (one VM): apply a fixed manifest corpus plus the objects a sonobuoy run creates; dump normalised state (strip uid, resourceVersion, timestamps, generated suffixes); `reset.sh`; repeat on the other mode; diff.
- **Simultaneous dual-run**: never; two ReplicaSet controllers over-create pods.

### Which upstream suites cover what

KCM has no standalone upstream conformance suite. In v1.35.0, `test/e2e/apps` covers the workload controllers and `ttl_after_finished`; `test/integration` has about 22 per-controller directories; networking, API-machinery, auth and storage e2e specs cover Services, namespaces, GC, quota, ServiceAccounts and PV/PVC indirectly.

**Largest gap: the integration suites cannot be pointed at a Rust KCM.** They build controllers in-process from Go packages. Many behaviours (GC with cluster-scoped owners, Job pod-failure policy, podgc orphan handling) are asserted mostly or only there. Whether the framework can target an external apiserver is unverified; expect not. Mitigation: port each ported controller's integration scenarios as black-box Rust tests against a real u7s apiserver, citing the upstream test name.

**Measuring gaps instead of guessing.** KCM runs with `--use-service-account-credentials=true`, so each controller writes as its own identity (`system:serviceaccount:kube-system:<name>-controller`). Count writes per identity across the baseline run; an identity with few or no writes has no real e2e coverage and needs ported scenarios or the corpus diff. Whether audit or metrics expose user identity today is unverified. The port must preserve these identities and the `system:controller:*` RBAC.

## 3. Phasing

Order is by risk (stateless, small, deterministic) and coverage (breakage is loud), with the heavy shared-Pod consumers last so the duplicate Go Pod cache lives as short a time as possible.

| Phase | Controllers | Why here | Main coverage |
|---|---|---|---|
| 0 | none. Harness, PSS-anon sampler, leave-one-out table, trim validation, client spike | Funds later phases; no port risk | n/a |
| 1 | root-ca-cert-publisher, serviceaccount (default SA), ttl-after-finished, pod-gc | Small; failures are loud; measures Rust fixed cost | SA/`kube-root-ca.crt` e2e, `ttl_after_finished`, integration `podgc`/`serviceaccount`/`ttlcontroller` |
| 2 | endpoint, endpointslice, endpointslice-mirroring | Output is a pure function of Service+Pod; shadow mode applies; heavy Services conformance | sig-network e2e, integration `endpoints*` |
| 3 | replicaset, replicationcontroller, deployment, then statefulset, daemonset, job, cronjob | Core workload; RC/Job already in the sensitive registry; owns the Pod cache decision | `apps` e2e, integration per controller |
| 4 | namespace, garbage-collector, resourcequota, disruption, node-lifecycle, node-ipam | High blast radius; race-sensitive; mostly integration-only coverage | namespace/GC/quota e2e, integration |
| 5 | PV binder, attach-detach, expand, protection controllers, ephemeral-volume, CSR approving/signing, bootstrap-signer, token-cleaner, resource-claim, HPA (if kept) | Storage and security-sensitive, thin e2e coverage in single-node; CSR signing is on the join path | sig-storage, `certificates`, `dra` |
| 6 | Remove Go KCM | The 50 MiB file-backed binary and runtime go | full suite |

Memory win per phase, from the numbers we have: Phase 0 about 8 MiB (TARGET; w898x trim, unvalidated). Phases 1-5 are expected neutral to slightly negative in the hybrid (Rust fixed cost against small Go savings), which is what the ceiling polices. Phase 6 realises the main win (w898x bounds the total rewrite saving at 22-34 MiB anon, MEASURED).

## 4. Rollback

One source of truth renders both unit files: an env file (for example `/etc/u7s/kcm-ported`) listing ported controllers. `install.sh` expands it into Go's `--controllers=*,...,-<ported>` and Rust's `--controllers=<ported>`; `04-start-kcm.sh` does the same for the rig. The current Go list at `install.sh:2712` is the template. Rolling back one controller means removing its name and restarting both units. A global fallback is an empty file, which gives pure Go. A logic test in the style of `test-install-flag-parity-logic.sh` asserts the two sets are **disjoint and their union is the full set**, since KCM runs with `--leader-elect=false` and a double-owned controller would fight silently. The Rust unit gets the same `kcm-supervisor.sh` supervision as Go in production; gate runs forbid restarts (invariant 4).

## 5. Rust building blocks

Loopback HTTP, separate process, own identities is **recommended**: RBAC, admission, validation and audit see controller traffic, as with Go KCM, at the cost of a cache copy and JSON parse. In-process store access (like an embedded controller in the apiserver) has the lowest memory but the worst verification: writes bypass authn, RBAC, admission and audit, an apiserver bug can be masked, hybrid phases (Go over HTTP) differ from the final shape, and restarts couple. Rejected for now. Client candidates: kube-rs full, kube-rs runtime plus narrow own types, or the scheduler's hyper client plus a small own informer (decision 2).

Precedent: the scheduler went embedded but still dials the apiserver over loopback TLS with its own `system:kube-scheduler` kubeconfig (`crates/apiserver/src/lib.rs`, step 10h). It uses plain hyper with its own caches and has no kube-rs dependency.

Phase 0 spike: build the same Pod+ReplicaSet informer three ways and record idle anon and bytes/pod at 10k pods. That choice follows from the numbers.

## 6. Decisions for the operator

1. **Funding the Rust fixed cost (TARGET at most 8 MiB) under the hybrid ceiling.** (a) Adopt the Phase 0 trim (TARGET -8 MiB): cheapest, but drops HPA and TTL unless invariant 3 restores them. (b) Allow a bounded overshoot (for example +6 MiB) until Phase 3: weakens the memory-first requirement for the longest hybrid stretch. (c) Batch Phases 1-2 into one merge: amortises the fixed cost, but a bigger blast radius per gate run. Recommend (a), with HPA restored if metrics-server rig use requires it.
2. **Client stack.** (A) kube-rs full: least code, but full objects retained and a large new dependency tree. (B) kube-rs runtime plus narrow own types: low retained size, moderate code, still a big dependency. (C) The scheduler's hyper client plus a small own informer: smallest retained size, no new crates, but we own watch/relist/backoff code. Proposed rule: lowest idle anon at 10k pods from the spike; within 10%, fewer new crates. Operator confirms the rule, not the winner.
3. **Final memory target.** Proposed TARGET: at most 25 MiB total KCM anon at WordPress (-17 vs shipped, -8 vs trimmed Go), no-go if the projection exceeds trimmed Go (33.4). Confirm or set another number.
4. **Integration-test gap.** Accept porting upstream integration scenarios as black-box Rust tests (cost grows with controller complexity), or restrict the port to controllers with strong e2e coverage and leave GC/namespace/node-lifecycle on Go indefinitely. Recommend the latter as the default exit if scenario porting stalls; it keeps the hybrid as an end state but forfeits removing the 50 MiB Go binary.
5. **Metadata-only watch support.** If the u7s apiserver lacks it, the Pod cache cost for GC rises. Implement it in the apiserver, or accept narrow-struct projection only?
6. **Trim failures.** If invariant 3 shows a trim-removed controller (HPA, TTL) matters to the suite, restore it (costs memory, keeps parity) or drop the affected specs from the baseline (saves memory, weakens the guardrail and needs the invariant 1 signoff). Recommend restore.
7. **Multi-node coverage.** (A) Lima-only for multi-node specs: free, manual, relies on operator discipline. (B) Fund multi-node CI first: automates the gate but delays Phase 1 by an unestimated infra effort. (C) Nightly multi-node job on a self-hosted runner: catches regressions within a day, needs a runner and does not block merges. Recommend A for Phases 1-2, C before Phase 3 (workload controllers, where DaemonSet and multi-node specs matter).
8. **Per-phase merge cadence.** (A) Full 2-node suite on every phase: strongest guardrail, about 25 min per run and two runs for A/B. (B) Full suite only at Phases 3, 5 and 6, `--focus` plus L1 elsewhere: cheaper but lets Phases 1, 2 and 4 merge on partial evidence, against the standing merge rule. (C) Full suite on every phase, A/B only at 3, 5 and 6: middle cost. Recommend A for Phases 3-5 and C elsewhere.

### Decided 2026-11-24 (operator)

- **Terminal verdict per SHA.** The 5-run result is final for a commit SHA; all runs are retained in the committed result record; a retry needs a new SHA, except for a run void under the infra-abort exception (section 1), capped at 2 voids per SHA.
- **Cumulative cap.** Total KCM-side memory at every phase end stays at or below the Phase 0 trimmed-Go baseline, 5 runs each (section 1 arithmetic).
- **Pin scope.** The projection script, `kcm-mem.json` and N sit under `guard.sha256`; sign-off via CODEOWNERS or a required-reviewer rule, not a label.

## Open risks and not verified

Open: a wedged but alive Rust controller escapes the restart check (invariant 4). Not measured: Go leave-one-out savings, Rust fixed cost, bytes/pod (all TARGET). The trim has never passed conformance. Spec-to-controller mapping is from directory listings. Integration-framework retargetability, audit user visibility and metadata-only watch support were not checked.

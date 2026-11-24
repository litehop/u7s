# KCM Rust port, Phase 2 design

Bead: mayor-w9xt5
Date: 2026-11-24 (main a1b0a1e0)

**Recommendation:** port KCM as a separate Rust process that runs alongside upstream KCM, one controller group at a time, where every phase must clear a memory ceiling (total KCM-side anon memory, hybrid phases included, no higher than today's shipped Go KCM) and a sonobuoy gate (same spec count, no new failures) before it merges. The Rust process talks to the apiserver over loopback HTTP with per-controller identities, and each phase has an `--controllers` kill switch back to Go. Phase 0 is the measurement harness plus a validated Go trim. It funds the Rust process's fixed memory cost, which would otherwise breach the hybrid ceiling.

Sources: Phase 1 audit (`2026-09-16-mayor-vc844-...`), mayor-w898x memory decomposition (branch `871d58e7`), roadmap Gate 4, `scripts/install.sh:2712`, `scripts/conformance/*`, `.github/workflows/e2e-focus.yaml`, upstream v1.35.0 `test/e2e/apps` and `test/integration` listings (`gh api`, `temp/research/`). Memory numbers below are measured unless marked *budget* (a proposed target) or *unmeasured*.

## 1. Memory: the first-class constraint

### Baseline (what a port must beat)

| Quantity | Value | Source |
|---|---|---|
| KCM peak PSS, release-gate run | 76-81 MiB | roadmap, 2026-10-15 |
| KCM anon, shipped config (idle / WordPress / 50-pod burst) | 40.2 / 41.9 / 45.2 MB | w898x |
| KCM anon, trimmed `--controllers` (stock env, idle / WordPress) | 31.7 / 33.4 MB | w898x |
| KCM file-backed PSS (73 MB binary) | 9 MB loaded, 50 MB idle | w898x |
| Live informer caches + workqueues at ~170 objects | 0.3 MB | w898x |
| Rewrite-only residual after flags | 10-22 MB | w898x |
| Phase 1 modelled Rust KCM | 12-45 MB | Phase 1 audit |

Two consequences. (1) Anon is the comparable number, because file-backed pages are reclaimable. (2) At this object count the Go cost is runtime, type registration and goroutines (1469 goroutines, 7 MB of stacks), not caches. A Rust port saves by dropping the runtime and the per-controller baggage. Cache design matters for scale, not for today's small clusters.

The bar is the **trimmed** Go KCM (about 33 MB at WordPress), not the shipped 42 MB, because the trim is nearly free. It is also unvalidated: it drops 11 controllers, including HPA and TTL, and no conformance run has confirmed it.

### Cache and informer strategy, with cost

| Choice | Memory cost | Verdict |
|---|---|---|
| One Rust process, one shared informer per type for all ported controllers | One Pod cache, not one per controller | **Required** |
| Full typed objects (k8s-openapi style) | Retains `managedFields`, status, every optional field. Scales with objects x object size. | Reject for Pod, Node, Event-like types |
| Narrow own structs, so serde drops unread fields at parse time | Retains labels, ownerRefs, selector, phase, the few spec fields read. The best case short of metadata-only. | **Default** |
| Metadata-only watch where only owner/labels are read (GC, podgc) | Smallest. Needs u7s apiserver support for `as=PartialObjectMetadata`. | Open check |
| Go KCM keeps its own caches in hybrid phases | Duplicate Pod/Node/Service cache for the whole middle of the port | Dominant hybrid cost; see section 2 |
| Watch fan-out | Each extra watcher costs apiserver buffering (apiserver is 27-31 MiB PSS) | Include apiserver PSS in the gate |

The hybrid problem is structural. Go KCM's informer factory only starts informers some enabled controller needs, and the Pod informer is shared by GC, podgc, disruption, HPA, attach-detach and others. Porting ReplicaSet therefore frees almost nothing in Go while adding a second Pod cache plus a second apiserver watch. The Pod duplication ends only when the last Pod consumer leaves Go, so order the port to make that happen late and keep the Rust Pod cache a narrow projection.

### Per-phase budget and measurement

Measured: PSS `Pss_Anon` from `/proc/<pid>/smaps_rollup` for KCM-Go, KCM-Rust and u7s-apiserver. Today's `sample-run-metrics.sh` records `ps` RSS for the busiest processes, so a PSS-anon column is new work. Protocol is the w898x one: gate template (`scripts/release-gate/u7s-vps-1g.yaml`, 1 vCPU, 1 GiB, no swap), `--install` mode, idle, WordPress+MariaDB, 50-pod burst, 3 runs, median. Single runs differ by up to about 3 MB, so anything under 3 MB is noise.

Gate metric per stage: `total = anon(KCM-Go) + anon(KCM-Rust) + anon(apiserver)`. Reference is the same-day Go-only shipped run on the same VM.

| Phase | Hybrid total ceiling vs same-day shipped Go-only | Rust-side budget (*budget*) |
|---|---|---|
| 0 | Go trimmed: at least -8 MB (w898x: 41.9 -> 33.4) | none |
| 1 | no more than 0 MB | fixed cost (runtime, TLS, binary data) at most 8 MB; each controller at most its measured Go leave-one-out saving |
| 2-4 | no more than 0 MB and no more than the previous phase +3 MB | Pod cache at most N bytes/pod (set from the Phase 1 spike) |
| 5 (Go KCM removed) | at least -8 MB vs trimmed Go (about 25 MB total KCM anon at WordPress) | whole process at most 25 MB; Go binary's 50 MB file-backed PSS gone |

Per-controller budget: in Phase 0, run Go with each candidate controller disabled in turn ("leave-one-out") to get its real Go-side saving. A controller may port in only if its Rust marginal anon is at or below that saving. This guards the case where tiny controllers cost more in Rust than they free in Go.

**Go/no-go after each phase.** Continue only if (a) the hybrid ceiling holds on all three stages at median of 3, (b) apiserver anon did not grow more than 2 MB, and (c) a linear projection of Rust fixed cost plus per-controller marginals across the remaining controllers lands below the trimmed-Go figure (about 33 MB at WordPress). Any miss stops the port, and the operator decides.

**Regression catching (memory).** Add a deterministic CI test: load 10k synthetic pods into the Rust cache under a counting allocator (dhat tooling already exists in the rig) and assert bytes/pod against the budget. Wall-clock RSS gating stays local on Lima and in the existing release gate (`burst-gate.sh`), because the CI runner is not a 1 GiB VM.

## 2. Verification architecture

### Invariants that keep sonobuoy authoritative

1. The upstream `e2e.test` binary, the plugin config (`sonobuoy-plugin-e2e.yaml`) and the skip/focus logic are untouched by port PRs. A CI path check fails any PR that touches `crates/kcm/` and those files together.
2. Spec-count equality: every gated run asserts ginkgo's `Ran N of M` equals the Go-KCM baseline. A port may not reduce N. The sensitive-focus registry already asserts an exact `specs:` count for the same reason.
3. Failure-set containment: failures in a port run must be a subset of the failures in the most recent Go-only run at the same commit (the known set today: multi-node specs on single-node, etc.). Comparison is automated, not eyeballed.
4. Run-meta records `kcm_mode` and the ported-controller list (run-meta already records topology). A "PASS" claim without it is rejected.
5. The standing merge rule applies: a sonobuoy PASS line quoted from `e2e.txt`, or operator signoff. Gated runs use `--install` mode, which runs the real `install.sh`, so the tested unit files are the shipped ones.

### Per-phase layers

| Layer | What | Where | Catches |
|---|---|---|---|
| L0 | Pure reconcile functions, tables derived from upstream `pkg/controller/*_test.go` cases | `cargo test`, CI | logic errors |
| L1 | Registered focus entries per controller in `.githooks/sensitive-conformance-focus.yaml`, run by `sensitive-e2e-guard` on any diff under that controller's path | CI, single-node only | regressions in single-node-verifiable specs |
| L2 | Full suite, 2-node Lima, `run-all.sh --install`, 20-25 min | local, pre-merge | everything single-node CI cannot (DaemonSet, multi-node specs) |
| L3 | Differential corpus (below) | local | semantic drift not covered by any spec |
| L4 | Memory gate (section 1) | local | memory regressions |
| L5 | Release gate burst test | per minor release | scale and burst behaviour |

CI cannot gate multi-node specs, so L2 on Lima is the authoritative layer for those and stays mandatory.

### A/B, shadow and differential modes

All are feasible because KCM controllers hold no state: all state lives in the apiserver, and `--controllers` partitions work cleanly.

| Mode | How | Suits | Cost |
|---|---|---|---|
| A/B suite | Run the same sonobuoy suite with controller X on Go, then on Rust, via a rig knob that renders both `--controllers` lists (does not exist yet, analogous to `--embedded-scheduler`). Diff pass/fail sets. | Every phase | Two full runs, about 50 min |
| Shadow (read-only) | Rust controller runs against a live Go-managed cluster, computes the writes it would make, and logs a diff against the actual objects after convergence | Deterministic outputs: EndpointSlice, `kube-root-ca.crt`, default ServiceAccount, ReplicaSet/Deployment status | A dry-run flag in each controller. Not for race-sensitive ones (GC, node lifecycle). |
| Sequential corpus diff | Apply a fixed manifest corpus plus the objects a sonobuoy run creates; dump normalised state (strip uid, resourceVersion, timestamps, generated suffixes); `reset.sh`; repeat on the other mode; diff | Everything with observable output | One VM, sequential, so no extra RAM |
| Simultaneous dual-run | Both KCMs active for the same controller | **Never**; two actors fight (two ReplicaSet controllers over-create pods) | n/a |

### Which upstream suites cover what

KCM has no standalone upstream conformance suite. From the v1.35.0 listings: `test/e2e/apps` has `controller_revision`, `cronjob`, `daemon_set`, `deployment`, `disruption`, `job`, `rc`, `replica_set`, `statefulset`, `ttl_after_finished`. `test/integration` has `cronjob`, `daemonset`, `deployment`, `disruption`, `endpoints`, `endpointslice`, `garbagecollector`, `job`, `namespace`, `podgc`, `pvc`, `quota`, `replicaset`, `replicationcontroller`, `serviceaccount`, `statefulset`, `ttlcontroller`, `volume`, `certificates`, `dra`, `servicecidr`, `storageversionmigrator`. Networking, API-machinery, auth and storage e2e specs cover Services, namespaces, GC, quota, ServiceAccounts, PV/PVC indirectly.

**Largest gap: the integration suites cannot be pointed at a Rust KCM.** They build controllers in-process from Go packages. Many behaviours (GC with cluster-scoped owners, Job pod-failure policy, podgc orphan handling) are asserted mostly or only there. Whether the integration framework can target an external apiserver with the controller disabled is unverified; I expect not. Mitigation: for each ported controller, port the integration scenarios as black-box Rust tests against a real u7s apiserver (the existing crate tests spawn the server), and cite the upstream test name per scenario.

**Measuring gaps instead of guessing.** KCM runs with `--use-service-account-credentials=true`, so each controller writes as its own identity (`system:serviceaccount:kube-system:<name>-controller`). Count writes per identity across a full Go-baseline sonobuoy run, and `ginkgo --dry-run` the spec list. A controller identity with few or no writes has no real e2e coverage and needs ported integration scenarios or the corpus diff. Whether apiserver audit or request metrics expose user identity today is unverified. The Rust port must preserve these identities and the `system:controller:*` RBAC, otherwise RBAC bootstrap parity breaks silently.

## 3. Phasing

Order is by risk (stateless, small, deterministic) and coverage (breakage is loud), with the heavy shared-Pod consumers last so the duplicate Go Pod cache lives as short a time as possible.

| Phase | Controllers | Why here | Main coverage |
|---|---|---|---|
| 0 | none. Harness, PSS-anon sampler, leave-one-out table, trim validation, client spike | Funds later phases; no port risk | n/a |
| 1 | root-ca-cert-publisher, serviceaccount (default SA), ttl-after-finished, pod-gc | Small; failure of the first two breaks every namespace immediately; smallest Rust fixed-cost test | SA/`kube-root-ca.crt` e2e, `ttl_after_finished`, integration `podgc`/`serviceaccount`/`ttlcontroller` |
| 2 | endpoint, endpointslice, endpointslice-mirroring | Output is a pure function of Service+Pod; shadow mode applies; heavy Services conformance | sig-network e2e, integration `endpoints*` |
| 3 | replicaset, replicationcontroller, deployment, then statefulset, daemonset, job, cronjob | Core workload; RC/Job already in the sensitive registry; owns the Pod cache decision | `apps` e2e, integration per controller |
| 4 | namespace, garbage-collector, resourcequota, disruption, node-lifecycle, node-ipam | High blast radius; race-sensitive; mostly integration-only coverage | namespace/GC/quota e2e, integration |
| 5 | PV binder, attach-detach, expand, protection controllers, ephemeral-volume, CSR approving/signing, bootstrap-signer, token-cleaner, resource-claim, HPA (if kept) | Storage and security-sensitive, thin e2e coverage in single-node; CSR signing is on the join path | sig-storage, `certificates`, `dra` |
| 6 | Remove Go KCM | The 50 MB file-backed binary and runtime go | full suite |

Memory win per phase, from the numbers we have: Phase 0 about 8 MB (w898x trim, unvalidated). Phases 1-4 are expected neutral to slightly negative in the hybrid (Rust fixed cost against small Go savings), which is exactly what the ceiling polices. Phase 6 realises the main win: w898x bounds the total rewrite saving at 22-34 MB anon, of which 10-22 MB beyond flags.

## 4. Rollback

One source of truth renders both unit files: an env file (for example `/etc/u7s/kcm-ported`) listing ported controllers. `install.sh` expands it into Go's `--controllers=*,...,-<ported>` and Rust's `--controllers=<ported>`; `04-start-kcm.sh` does the same for the rig. The current Go list at `install.sh:2712` is the template. Rolling one controller back is: remove its name from the file and restart both units. No data migration is needed, because controllers hold no state. A logic test in the style of `test-install-flag-parity-logic.sh` asserts the two sets are **disjoint and their union is the full set**, since KCM runs with `--leader-elect=false` and a double-owned controller would fight silently. A global fallback is an empty file, which gives pure Go. Because `kcm-supervisor.sh` already restarts crashes with a circuit breaker, the Rust unit needs the same supervision.

## 5. Rust building blocks

| Option | Memory | Verification | Verdict |
|---|---|---|---|
| In-process store access (like an embedded controller in the apiserver) | Lowest: no duplicate cache, no serialization | **Worst.** Writes bypass authn, RBAC, admission, validation and audit, so sonobuoy no longer exercises the real write path for controller traffic, and an apiserver bug can be masked. Hybrid phases (Go over HTTP) differ from the final shape. Couples restarts. | Reject for now |
| Loopback HTTP, separate process, own identities | Pays a cache copy and JSON parse | Same path as Go KCM; RBAC, admission and audit exercised | **Recommended** |
| kube-rs full (k8s-openapi types) | Full objects retained; large binary (reclaimable); not in the lockfile today | Same as above | Candidate |
| kube-rs runtime plus narrow own types, or the scheduler's hyper client plus a small own informer | Smallest retained size | Same as above | Candidate; spike picks |

Precedent: the scheduler went embedded but still dials the apiserver over loopback TLS with its own `system:kube-scheduler` kubeconfig (`crates/apiserver/src/lib.rs`, step 10h), explicitly rejecting an in-process client. It uses plain hyper with its own node/CSI caches and has no kube-rs dependency. In-process access can be revisited after parity, as a separately measured step, because it changes the verification story.

Phase 0 spike: build the same Pod+ReplicaSet informer three ways and record idle anon and bytes/pod at 10k pods. That choice follows from the numbers.

## 6. Decisions for the operator

1. **Hybrid memory ceiling vs Rust fixed cost.** Early phases likely add 6-10 MB of Rust runtime while Go frees little. Options: (a) adopt the Phase 0 trim (about -8 MB) to fund them, which also drops HPA and TTL; (b) allow a bounded overshoot (for example up to +6 MB) until Phase 3; (c) batch Phases 1-2 into one merge; (d) host early controllers inside the apiserver process, which saves the runtime but weakens isolation and the verification path. Recommend (a), with HPA kept if metrics-server rig use requires it.
2. **Client stack.** kube-rs full, kube-rs runtime plus narrow types, or the scheduler's hyper client. Recommend deciding on spike numbers, defaulting to narrow types.
3. **Final memory target.** Proposed: at most 25 MB total KCM anon at WordPress (about -17 vs shipped, -8 vs trimmed Go), no-go if the projection exceeds trimmed Go. Confirm or set another number.
4. **Integration-test gap.** Accept porting scenarios as black-box Rust tests (cost grows with controller complexity), or restrict the port to controllers with strong e2e coverage and leave GC/namespace/node-lifecycle on Go indefinitely. Recommend the latter as the default exit if scenario porting stalls; it keeps the hybrid as a legitimate end state, but it forfeits the 50 MB Go binary removal.
5. **Metadata-only watch support.** If the u7s apiserver lacks it, the Pod cache cost for GC rises; implement it in the apiserver, or accept narrow-struct projection only?
6. **Trim validation scope.** Validate the 11-controller trim via a full sonobuoy run, or drop individual entries (HPA, TTL)? A mid-state needs the operator to say which controllers are product features rather than dead weight.
7. **Single-node CI limits.** Multi-node specs gate only on local Lima. Accept that, or fund multi-node CI first? Recommend accept; it matches the existing stance.
8. **Per-phase merge cadence.** Require full 2-node suite per phase (about 25 min per run, two runs for A/B), or only at phases 3, 5 and 6, with `--focus` plus L1 for the rest? Recommend the former for Phases 3-5 given the standing merge rule.

## Not verified

Per-controller Go leave-one-out savings, Rust fixed cost and bytes/pod are unmeasured; the budgets are targets. The Phase 0 trim list has never passed conformance. Spec-to-controller mapping is from directory listings, not a spec dry-run. Integration-framework retargetability, audit user visibility and metadata-only watch support in the u7s apiserver were not checked.

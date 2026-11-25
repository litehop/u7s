---
as_of: 2026-11-25
kind: initiative-state
---

# KCM Rust port state

**AS OF 2026-11-25.** Decision record:
`docs/decisions/kcm-rust-port-separate-process-memory-gated.md`. The operator
approved the design on 2026-11-25. No port code exists; Phase 0 is not
started. Full original design: `git show 900097c6:ai/findings/2026-11-24-mayor-w9xt5-kcm-port-phase2-design.md`.

## Numbers (MiB; all measured by the memory decomposition, branch `871d58e7`)

| Quantity | Value |
|---|---|
| KCM anon, shipped (idle / WordPress / 50-pod burst) | 40.2 / 41.9 / 45.2 |
| KCM anon, trimmed `--controllers` (idle / WordPress) | 31.7 / 33.4 |
| KCM file-backed PSS (73 MiB binary) | 9 loaded, 50 idle |
| Run-to-run noise | about 3 |
| Rewrite-only residual after flags | 10-22 |

Unmeasured targets: Rust fixed cost at most 8; Phase 6 total KCM anon at
most 25 at WordPress; Pod cache at most N bytes/pod (provisionally 1024).
The trim has never passed conformance.

## Phase plan

Order is by risk (stateless, small, deterministic) and coverage (breakage is
loud), with the heavy shared-Pod consumers last so the duplicate Go Pod cache
lives as short a time as possible. Go KCM starts only informers an enabled
controller needs, so porting ReplicaSet alone frees almost nothing in Go while
adding a second Pod cache and watch.

| Phase | Controllers | Why here |
|---|---|---|
| 0 | none: harness, trim validation, client spike | funds later phases |
| 1 | root-ca-cert-publisher, default serviceaccount, ttl-after-finished, pod-gc | small, loud failures, measures Rust fixed cost |
| 2 | endpoint, endpointslice, endpointslice-mirroring | pure function of Service+Pod; shadow mode applies |
| 3 | replicaset, replicationcontroller, deployment, then statefulset, daemonset, job, cronjob | core workload; owns the Pod cache decision |
| 4 | namespace, garbage-collector, resourcequota, disruption, node-lifecycle, node-ipam | high blast radius, race-sensitive, mostly integration-only coverage |
| 5 | PV binder, attach-detach, expand, protection, ephemeral-volume, CSR approving/signing, bootstrap-signer, token-cleaner, resource-claim, HPA if kept | storage and security, thin single-node e2e; CSR signing is on the join path |
| 6 | remove Go KCM | the 50 MiB binary and Go runtime go; main memory win |

Phases 1-5 are expected memory-neutral to slightly negative in the hybrid;
the gates police that. If porting upstream integration scenarios stalls, the
default exit is to keep GC, namespace and node-lifecycle on Go indefinitely,
forfeiting removal of the Go binary.

## Memory gate (per phase)

Metric: `Pss_Anon` from `smaps_rollup` for KCM-Go, KCM-Rust and the apiserver,
on the release-gate VM template in `--install` mode, three stages (idle,
WordPress+MariaDB, 50-pod burst). The sampler records `ps` RSS today, so
the PSS-anon column and `kcm-mem.json` are Phase 0 work.

- Gate on the total per stage, not per controller: Go-side savings per port
  are below the noise.
- R = shipped Go-only, H = phase build. Three interleaved runs each, same VM,
  same day, medians. PASS if `median(H) - median(R) <= 0`; INCONCLUSIVE if
  0 to 3, extend to 5 runs and pass only if `<= 0`; FAIL if above 3 on 3 runs
  or above 0 on 5.
- Cumulative cap: at each phase end, 5 interleaved runs of H_k and trimmed Go
  (T); KCM-side anon (Go + Rust, apiserver excluded) of H_k must be at most T
  at every stage. So the Rust fixed cost must come out of the trim headroom.
- Phase 0 passes if `median(R) - median(T) >= 5`.
- Continue only if the total gate passes, apiserver anon grew at most 2, and
  the projection `P = F + sum(m_c)` is at most 33.4 (script
  `scripts/conformance/kcm-memory-projection.sh`, not yet written).
- Verdicts are terminal per commit SHA; all runs are retained. A run is void
  only if it ended before any stage metric or spec report with a harness or VM
  log naming an external cause; the operator or a required reviewer decides,
  before the replacement run. At most 2 voids per SHA, a third is FAIL.
  Failures, flakes, OOM kills and KCM restarts are never void.
- N = ceil(1.25 x B_chosen) rounded up to 64, from a 10k-pod counting-allocator
  spike, committed in `scripts/conformance/kcm-pod-bytes.txt`.

## Verification protocol

Sonobuoy stays authoritative through these invariants:

1. `scripts/conformance/guard.sha256` pins the e2e binary, plugin config,
   skip/focus lists, focus registry, projection script, `kcm-mem.json` and N.
   CI recomputes it on every PR. A pin-change PR may touch no `crates/kcm/`
   file. Sign-off is CODEOWNERS naming the operator.
2. Executed spec-name set equals the committed baseline exactly. Conditional
   specs are recorded by repeating the baseline 3 times and pinning the
   differing set.
3. Baseline is a full 2-node run of untrimmed Go before the port. Trimmed Go
   must match its spec and failure sets. Port-run failures must be a subset
   of the baseline's.
4. Zero KCM restarts: any supervisor restart or non-active unit fails the run.
5. Run-meta records `kcm_mode` and the ported-controller list.
6. A PASS is a sonobuoy line quoted from `e2e.txt`, or operator sign-off.

Layers: L0 `cargo test` reconcile tables from upstream unit cases; L1 CI
single-node focus entries; L2 local 2-node full suite (`run-all.sh --install`,
20-25 min, mandatory); L3 differential corpus; L4 memory gate; L5 release-gate
burst per minor release. Modes: A/B (X on Go, then Rust; needs a rig knob that
does not exist), read-only shadow for deterministic controllers (EndpointSlice,
`kube-root-ca.crt`, default SA), sequential corpus diff. Never run Go and Rust
copies of the same controller simultaneously.

Rollback: one env file (for example `/etc/u7s/kcm-ported`) renders Go's
`--controllers=*,-<ported>` and Rust's `--controllers=<ported>`; an empty
file is pure Go. A logic test must assert the two sets are disjoint and
their union is the full set. The Rust unit gets the same supervision as Go.

Adopted cadence and fallbacks (approved with the design): trim funds the Rust
fixed cost and HPA/TTL are restored if the trim breaks the suite; client
stack chosen by lowest idle anon at 10k pods, fewer new crates within 10%;
multi-node specs by manual 2-node Lima runs for Phases 1-2 and a nightly job
before Phase 3; full suite every phase, A/B only at Phases 3, 5 and 6.

## Open and needs-data

- Rust fixed cost, bytes/pod, Go leave-one-out savings: all unmeasured. Bead
  `mayor-rh8y3` (Phase 0).
- Trim validity (HPA, TTL): unproven. `mayor-rh8y3`.
- Embedded-in-apiserver alternative: re-measure at Phase 0 and every phase
  end; raise for an operator decision if the estimated saving is at least
  4 MiB. No bead; part of each phase's gate record.
- Metadata-only WATCH support in the apiserver: `mayor-jbqti`.
- Whether upstream integration tests can target an external apiserver, and
  whether audit shows per-controller identity: `mayor-anvu2`.
- Wedged-but-alive controller detection: `mayor-n6njd`.
- Nightly multi-node job: `mayor-iv2yg`.
- Spec-to-controller mapping is from directory listings only; re-derive from
  release-1.37 in Phase 0 (`mayor-rh8y3`).

## Kubelet

Not decided. The Phase 1 audit judged a Rust kubelet not viable absent new
evidence: about 139k non-test LOC, no Rust prior art for the real CRI path,
and it would forfeit the unmodified-kubelet conformance-oracle role and
node-rejoin story. Revisit after the capacity benchmark data (`mayor-jedol`).
Cheap prerequisite, unverified and unfiled until the revisit: does the
already-reduced kubelet feature-gate set pass conformance with in-tree volume
plugins beyond CSI and topology-manager cut. Full audit:
`git show 900097c6:ai/findings/2026-09-16-mayor-vc844-kubelet-kcm-rust-eval.md`.

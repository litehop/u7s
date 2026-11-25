---
as_of: 2026-11-25
kind: initiative-state
---

# KCM Rust port state

**AS OF 2026-11-25.** Decision record:
`docs/decisions/kcm-rust-port-local-first-separate-process.md`. No port code
exists; Phase 0 is not started. Original design: `git show 900097c6:ai/findings/2026-11-24-mayor-w9xt5-kcm-port-phase2-design.md`.

## Operator decision (2026-11-25) and what follows

Operator: no high-risk KCM operations; start small with a scalable design;
verify locally; deliver to releases or `install.sh` only once verification
shows a performance benefit and conformance parity, and not soon. The mapping below is the mayor's reading of it (the operator may correct it). The gates and phases
below are the local verification regime, not a shipping plan.

| # | Question | Status |
|---|---|---|
| D1 | Trim shipped Go KCM `--controllers` | Moot until ship time; shipped Go KCM unchanged |
| D2 | Client-stack rule (lowest idle anon at 10k pods, fewer crates within 10%) | Adopted |
| D3 | Phase 6 total KCM anon target (25 MiB) | Ship-time check; number set then |
| D4 | Order | Start with controllers having strong e2e coverage; GC, namespace, node-lifecycle stay Go until evidence |
| D5 | Metadata-only WATCH | Resolved by evidence: JSON PartialObjectMetadata works; gaps in `mayor-ju5k1`, `mayor-ynnoq` |
| D6 | Drop specs the trim breaks | Moot until ship time |
| D7 | Multi-node specs | Lima, locally; no CI investment yet |
| D8 | Cadence | Local phases merge on `--focus` plus unit gates; full 2-node suite before shipping |

Ship gate: measured benefit versus the shipped Go KCM and full 2-node
conformance. Until then nothing ships in `install.sh` or releases.

## Numbers (MiB; all measured by the memory decomposition, branch `871d58e7`)

| Quantity | Value |
|---|---|
| KCM anon, shipped (idle / WordPress / 50-pod burst) | 40.2 / 41.9 / 45.2 |
| KCM anon, trimmed `--controllers` (idle / WordPress) | 31.7 / 33.4 |
| KCM file-backed PSS (73 MiB binary) | 9 loaded, 50 idle |
| Run-to-run noise | about 3 |
| Rewrite-only residual after flags | 10-22 |

Unmeasured targets: Rust fixed cost at most 8; Pod cache at most N
bytes/pod (provisionally 1024). The trim has never passed conformance.

## Phase plan

Order is by coverage (breakage is loud) and risk (stateless, small,
deterministic), with the heavy shared-Pod consumers last so the duplicate Go
Pod cache lives as short a time as possible. Porting ReplicaSet alone frees
almost nothing in Go while adding a second Pod cache and watch.

| Phase | Controllers | Why here |
|---|---|---|
| 0 | none: harness, trim validation, client spike | funds later phases |
| 1 | root-ca-cert-publisher, default serviceaccount, ttl-after-finished, pod-gc | small, loud failures, measures Rust fixed cost |
| 2 | endpoint, endpointslice, endpointslice-mirroring | pure function of Service+Pod; shadow mode applies |
| 3 | replicaset, replicationcontroller, deployment, then statefulset, daemonset, job, cronjob | core workload; owns the Pod cache decision |
| 4 | resourcequota, disruption, node-ipam; namespace, garbage-collector, node-lifecycle stay Go until evidence | race-sensitive, mostly integration-only coverage |
| 5 | PV binder, attach-detach, expand, protection, ephemeral-volume, CSR approving/signing, bootstrap-signer, token-cleaner, resource-claim, HPA if kept | storage and security, thin single-node e2e; CSR signing is on the join path |
| 6 | remove Go KCM (ship-time only) | the 50 MiB binary and Go runtime go |

Phases 1-5: expected memory-neutral or slightly negative.

## Memory gate (per phase)

Metric: `Pss_Anon` from `smaps_rollup` for KCM-Go, KCM-Rust and the apiserver,
in `--install` mode on a Lima VM, three stages (idle, WordPress+MariaDB,
50-pod burst). The sampler records `ps` RSS today; PSS-anon and
`kcm-mem.json` are Phase 0 work, and run-meta must record `kcm_mode` and the ported-controller list (`mayor-rh8y3`).

- Gate on the per-stage total, not per controller (per-port savings are
  noise).
- R = shipped Go-only, H = phase build. Three interleaved runs each, same VM,
  same day, medians. PASS if `median(H) - median(R) <= 0`; INCONCLUSIVE if
  0 to 3, extend to 5 runs and pass only if `<= 0`; FAIL if above 3 on 3 runs
  or above 0 on 5.
- Cumulative cap: at each phase end, 5 interleaved runs of H_k and trimmed Go
  (T); KCM-side anon (Go + Rust, apiserver excluded) of H_k must be at most T
  at every stage. So Rust fixed cost must come out of trim headroom.
- Phase 0 passes if `median(R) - median(T) >= 5`.
- Continue only if the total gate passes, apiserver anon grew at most 2, and
  the projection `P = F + sum(m_c)` is at most 33.4 (script
  `scripts/conformance/kcm-memory-projection.sh`, not yet written).
- Verdicts are terminal per commit SHA; all runs are retained. A run is void
  only if it ended before any stage metric or spec report, with a harness or
  VM log naming an external cause, ruled before the replacement run. At most
  2 voids per SHA. Failures, flakes, OOM kills and restarts are never void.
- N = ceil(1.25 x B_chosen) rounded up to 64, from 10k-pod spike Pss_Anon delta,
  in `scripts/conformance/kcm-pod-bytes.txt`.

## Verification protocol

Sonobuoy stays authoritative via these invariants:

1. `scripts/conformance/guard.sha256` pins the e2e binary, plugin config,
   skip/focus lists, focus registry, projection script, `kcm-mem.json` and N.
   CI recomputes it on every PR. A pin-change PR may touch no `crates/kcm/`
   file. Sign-off is CODEOWNERS naming the operator.
2. Executed spec-name set equals the committed baseline exactly; conditional
   specs are pinned by repeating the baseline 3 times.
3. Baseline is a full 2-node run of untrimmed Go before the port. Trimmed Go
   must match its spec and failure sets. Port-run failures must be a subset
   of the baseline's.
4. Zero KCM restarts: any supervisor restart or non-active unit fails the run.
5. A PASS is a sonobuoy line quoted from `e2e.txt`, or operator sign-off.

Layers: L0 `cargo test` reconcile tables from upstream unit cases; L1 local
`--focus` entries; L2 local 2-node full suite (`run-all.sh --install`, 20-25
min, needed to ship); L3 differential corpus; L4 memory gate.
Modes: A/B (needs a nonexistent rig knob), read-only shadow for
deterministic controllers, sequential corpus diff. Never run Go and Rust
copies of one controller simultaneously.

Rollback: one env file renders Go's `--controllers=*,-<ported>` and Rust's
`--controllers=<ported>`; an empty file is pure Go. A logic test asserts the
two sets are disjoint and their union is the full set.

## Open and needs-data

- Rust fixed cost, bytes/pod, Go leave-one-out savings: all unmeasured. Bead
  `mayor-rh8y3` (Phase 0).
- Trim validity (HPA, TTL): unproven. `mayor-rh8y3`.
- Embedded-in-apiserver alternative: re-measure each phase end; raise to the
  operator if the estimated saving is at least 4 MiB.
- Can upstream integration tests target an external apiserver; does audit
  show per-controller identity: `mayor-anvu2`.
- Wedged-but-alive controller detection: `mayor-n6njd`.
- Nightly multi-node job: `mayor-iv2yg`, deferred until the ship gate.
- Spec-to-controller mapping is from directory listings only; re-derive from
  release-1.37 in Phase 0 (`mayor-rh8y3`).

## Kubelet

Not decided. The Phase 1 audit judged a Rust kubelet not viable absent new evidence: about 139k non-test LOC, no Rust prior art for the real CRI path,
and it would forfeit the unmodified-kubelet conformance-oracle role. Revisit
after the capacity benchmark data (`mayor-jedol`). The eval also cites the unmodified-kubelet node-rejoin story; the reduced-gate conformance prerequisite is tracked in `mayor-omxmp`. Audit:
`git show 900097c6:ai/findings/2026-09-16-mayor-vc844-kubelet-kcm-rust-eval.md`.

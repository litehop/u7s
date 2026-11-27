---
as_of: 2026-11-26
kind: initiative-state
---

# KCM Rust port state

**AS OF 2026-11-26.** Decision record:
`docs/decisions/kcm-rust-port-local-first-separate-process.md`. Phase 0 harness
and trim validation are done. Original design:
`git show 900097c6:ai/findings/2026-11-24-mayor-w9xt5-kcm-port-phase2-design.md`.
Decision table D1-D8, memory gate, verification protocol and trim validation:
`kcm-rust-port-gates.md`.

## Operator decision (2026-11-25) and what follows

Operator: no high-risk KCM operations; start small with a scalable design;
verify locally; deliver to releases or `install.sh` only once verification
shows a performance benefit and conformance parity, and not soon. The mapping
below is the mayor's reading of it. The gates and phases below are the local
verification regime, not a shipping plan.

Ship gate: measured benefit versus the shipped Go KCM and full 2-node
conformance. Until then nothing ships in `install.sh` or releases.

## Numbers (MiB; memory decomposition, branch `871d58e7`)

| Quantity | Value |
|---|---|
| KCM anon, shipped (idle / WordPress / 50-pod burst) | 40.2 / 41.9 / 45.2 |
| KCM anon, trimmed `--controllers` (idle / WordPress) | 31.7 / 33.4 |
| KCM file-backed PSS (73 MiB binary) | 9 loaded, 50 idle |
| Run-to-run noise | about 3 |
| Rewrite-only residual after flags | 10-22 |

Unmeasured targets: Rust fixed cost at most 8; Pod cache at most N
bytes/pod (provisionally 1024).

## Phase plan

Order is by coverage (breakage is loud) and risk (stateless, small,
deterministic), with the heavy shared-Pod consumers last so the duplicate Go
Pod cache lives as short a time as possible.

| Phase | Controllers | Why here |
|---|---|---|
| 0 | none: harness, trim validation, client spike | funds later phases |
| 1 | root-ca-cert-publisher, default serviceaccount, ttl-after-finished, pod-gc | small, loud failures, measures Rust fixed cost |
| 2 | endpoint, endpointslice, endpointslice-mirroring | pure function of Service+Pod; shadow mode applies |
| 3 | replicaset, replicationcontroller, deployment, then statefulset, daemonset, job, cronjob | core workload; owns the Pod cache decision |
| 4 | resourcequota, disruption, node-ipam; namespace, garbage-collector, node-lifecycle stay Go | race-sensitive, mostly integration-only coverage |
| 5 | PV binder, attach-detach, expand, protection, ephemeral-volume, CSR approving/signing, bootstrap-signer, token-cleaner, resource-claim, HPA if kept | storage and security, thin single-node e2e; CSR signing is on the join path |
| 6 | remove Go KCM (ship-time only) | the 50 MiB binary and Go runtime go |
## Phase 0 re-measure (2026-11-27)

- PASS on idle and WordPress: R−T 8.12 / 9.14 MiB, R 42.99 / 45.13 vs T 34.87 / 35.99.
- SHA 474d89af, lima-node-4, 3 interleaved runs, 0 voids.
- The burst stage is not implemented (`mayor-84rmv`); the operator accepted the two-stage pass on 2026-11-27.
- Client stack: C (hardened).
- #2284 adds seat pools.


## Open and needs-data

- Rust fixed cost and bytes/pod: unmeasured.
- Embedded-in-apiserver alternative: re-measure each phase end; raise to the
  operator if the estimated saving is at least 4 MiB.
- Wedged-but-alive controller detection: `mayor-n6njd`.
- Nightly multi-node job: `mayor-iv2yg`, deferred until the ship gate.

## Kubelet

Not decided. The Phase 1 audit judged a Rust kubelet not viable absent new
evidence: about 139k non-test LOC, no Rust prior art for the real CRI path,
and it would forfeit the unmodified-kubelet conformance-oracle role. Revisit
after the capacity benchmark data (`mayor-jedol`); the reduced-gate
conformance prerequisite is `mayor-omxmp`. Audit:
`git show 900097c6:ai/findings/2026-09-16-mayor-vc844-kubelet-kcm-rust-eval.md`.

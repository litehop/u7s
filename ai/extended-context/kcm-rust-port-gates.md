---
as_of: 2026-11-26
kind: initiative-state
---

# KCM Rust port gates

Initiative state, numbers, phase plan and open items: `kcm-rust-port-state.md`.

## Operator decision (2026-11-25) and what follows

Operator: no high-risk KCM operations; start small with a scalable design;
verify locally; deliver to releases or `install.sh` only once verification
shows a performance benefit and conformance parity, and not soon. The mapping
below is the mayor's reading of it. The gates and phases below are the local
verification regime, not a shipping plan.

| # | Question | Status |
|---|---|---|
| D1 | Trim shipped Go KCM `--controllers` | Moot until ship time; shipped Go KCM unchanged |
| D2 | Client-stack rule (lowest idle anon at 10k pods, fewer crates within 10%) | Adopted |
| D3 | Phase 6 total KCM anon target (25 MiB) | Ship-time check; number set then |
| D4 | Order | Controllers with strong e2e coverage first; GC, namespace, node-lifecycle stay Go until evidence |
| D5 | Metadata-only WATCH | Resolved: JSON PartialObjectMetadata works; gaps in `mayor-ju5k1`, `mayor-ynnoq` |
| D6 | Drop specs the trim breaks | Moot until ship time |
| D7 | Multi-node specs | Lima, locally; no CI investment yet |
| D8 | Cadence | Local phases merge on `--focus` plus unit gates; full 2-node suite before shipping |

## Memory gate (per phase)

Metric: `Pss_Anon` from `smaps_rollup` for KCM-Go, KCM-Rust and the apiserver,
in `--install` mode on a Lima VM, three stages (idle, WordPress+MariaDB,
50-pod burst). Run-meta records `kcm_mode`; the ported-controller list and
`scripts/conformance/kcm-memory-projection.sh` are not yet written.

- Gate on the per-stage total, not per controller.
- R = shipped Go-only, H = phase build. Three interleaved runs each, same VM,
  same day, medians. PASS if `median(H) - median(R) <= 0`; INCONCLUSIVE if
  0 to 3, extend to 5 runs and pass only if `<= 0`; FAIL if above 3 on 3 runs
  or above 0 on 5.
- Cumulative cap: at each phase end, 5 interleaved runs of H_k and trimmed Go
  (T); KCM-side anon (Go + Rust, apiserver excluded) of H_k must be at most T
  at every stage.
- Phase 0 passes if `median(R) - median(T) >= 5`.
- Continue only if the total gate passes, apiserver anon grew at most 2, and
- Continue only if the total gate passes, apiserver anon grew at most 2, and
  the projection `P = F + sum(m_c)` is at most 33.4 MiB (T WordPress KCM anon, 11-controller trim; the 10-controller trim measures 35.99, #2300 — re-baselining is an operator decision).
- Verdicts are terminal per commit SHA; all runs are retained. A run is void
  only if it ended before any stage metric or spec report, with a harness or
  VM log naming an external cause, ruled before the replacement run. At most
  2 voids per SHA. Failures, flakes, OOM kills and restarts are never void.
- N = ceil(1.25 x B_chosen) rounded up to 64, from 10k-pod spike Pss_Anon delta,
  in `scripts/conformance/kcm-pod-bytes.txt`.

## Verification protocol

Sonobuoy stays authoritative via these invariants:

1. `scripts/conformance/guard.sha256` pins the e2e binary, plugin config,
   skip/focus lists, focus registry, baselines and N. `guard-check.sh`
   recomputes it in CI. A pin-change PR may touch no `crates/kcm/` file.
   Operator decision 2026-11-26: CODEOWNERS is documentation only
   (`require_code_owner_review` stays false); `guard.sha256` +
   `guard-check.sh` is the gate, and the mayor flags pin-changing PRs to
   the operator.
2. Executed spec-name set equals the committed baseline exactly; conditional
   specs are pinned by repeating the baseline 3 times.
3. Trimmed Go must match the baseline's spec and failure sets; port-run
   failures must be a subset of the baseline's. Baseline and comparison runs
   are 2-node (`run-all.sh --extra-node`); compare with `spec-set.sh`.
4. Zero KCM restarts: any supervisor restart or non-active unit fails the run.
5. A PASS is a sonobuoy line quoted from `e2e.txt`, or operator sign-off.

Layers: L0 `cargo test` reconcile tables from upstream unit cases; L1 local
`--focus` entries; L2 local 2-node full suite (`run-all.sh --extra-node`,
25-30 min, needed to ship); L3 differential corpus; L4 memory gate.
Never run Go and Rust copies of a controller together.
Upstream `test/integration` runs its own in-process apiserver and Go
controllers, so each ported controller needs black-box L1 scenarios
(`mayor-anvu2`). Per-controller write attribution: the bounded `user` label on `apiserver_request_total` (controller-SA allowlist, else `other` or `unauthenticated`, #2301).

Rollback: one env file renders Go's `--controllers=*,-<ported>` and Rust's
`--controllers=<ported>`; an empty file is pure Go. A logic test asserts the
two sets are disjoint and their union is the full set.

## Trim validation (release-1.37 sources)

Baseline: untrimmed Go KCM, 2 nodes (lima-node-2 + lima-node-3, kubelet 1.37.3), host rig
`run-all.sh --extra-node --kcm-mode R`, two runs: 462 executed and passed, spec sets identical.
The 11-controller trim failed the VAC lifecycle spec (the apiserver adds
`kubernetes.io/vac-protection`; only `volumeattributesclass-protection-controller` removes it), so
it stays; the trim is 10 controllers. Two 2-node 10-controller trim runs
(`--kcm-mode T`): spec and failure sets (empty) equal baseline. The tcp:8080 liveness-probe
failure seen once on a single-node run did not reproduce in 4 two-node runs (R 2/2, T 2/2); cause
unestablished.

Spec-to-controller map: `scripts/conformance/kcm-trim-spec-map.txt`.

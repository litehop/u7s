# Port KCM to Rust as a separate, memory-gated process alongside upstream KCM

**Status:** Accepted
**Date:** 2026-11-25

## Context

KCM is the second-largest u7s component: 41.9 MiB anon at WordPress, 76-81 MiB
peak PSS in the release gate. The port exists to cut memory, and sonobuoy
Conformance is the parity oracle.

## Decision

- **KCM first.** The kubelet port is undecided and is revisited after the
  capacity benchmark data exists.
- **Separate process, loopback HTTP, own identities.** The Rust KCM dials the
  apiserver like upstream KCM, so RBAC, admission and audit see its traffic.
  Embedding it in the apiserver (as the scheduler is) stays a measured
  alternative; revisit if the estimated saving is at least 4 MiB of total
  KCM-side plus apiserver anon on a production-like install.
- **Memory gates every phase.** Total KCM-Go + KCM-Rust + apiserver anon
  must not exceed the shipped Go-only config, and KCM-side memory must not
  exceed the validated trimmed-Go baseline at any phase end. Each commit SHA
  gets one terminal verdict.
- **Upstream KCM is the fallback.** Controllers are split between the two
  processes by a single `--controllers` source of truth; removing a name
  reverts that controller to Go.
- **Sonobuoy Conformance is the guardrail.** Each phase must reproduce the
  baseline executed-spec set exactly, add no failures beyond the untrimmed
  baseline, and record zero KCM restarts. The pinned configuration cannot
  change in the same PR as a port.

## Rationale

Judgment call, not measured. The principles applied were memory-first (the
operator's stated reason for porting) and never weaken the oracle. The KCM
audit found a bounded rewrite surface and a shipped Rust scheduler as
precedent; its 12-45 MB estimate is modelled, not measured.

Separate process was chosen for fault isolation, independent restarts and
clean memory attribution, and costs a Rust fixed cost not yet measured
(target at most 8 MiB). The 4 MiB trigger is the 3 MiB run-to-run noise band
plus 1 MiB.

## Consequences

- Hybrid phases carry two KCMs and a second Pod cache, so early phases are
  expected to be memory-neutral at best; the main saving arrives only when
  Go KCM is removed.
- This ADR does not reverse `upstream-component-shipping-shape.md`. Removing
  Go KCM at the last phase will, and needs its own superseding ADR then.
- Phase plan, ordering and open items live in
  `ai/extended-context/kcm-rust-port-state.md`.

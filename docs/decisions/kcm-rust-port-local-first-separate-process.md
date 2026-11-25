# Port KCM to Rust as a local-first separate process, shipped only after a gate

**Status:** Accepted
**Date:** 2026-11-25

## Context

KCM is the second-largest u7s component: 41.9 MiB anon at WordPress. On
2026-11-24 the operator directed that the KCM port come first, be
memory-driven, and keep sonobuoy Conformance as the parity guardrail. On
2026-11-25 the operator
directed: no high-risk KCM operations; start small with a solid, scalable
design; verify locally; deliver to releases or `install.sh` only once
verification shows a performance benefit and conformance parity, and not soon.

## Decision

- **Local/dev track.** The Rust KCM is not wired into `install.sh` or
  releases. The shipped Go KCM is unchanged (no trim, no dropped specs).
- **Ship gate.** Shipping requires a measured memory benefit versus the
  shipped Go KCM, and full conformance including the 2-node suite. The
  memory threshold is set at that time.
- **KCM first, small start.** Begin with controllers that have strong e2e
  coverage; GC, namespace and node-lifecycle stay Go until evidence says
  otherwise. The kubelet port stays undecided, pending the capacity data.
- **Separate process, loopback HTTP, own identities.** The Rust KCM dials the
  apiserver like upstream KCM, so RBAC, admission and audit see its traffic.
  Embedding in the apiserver (as the scheduler is) remains a measured
  alternative; revisit if the estimated saving is at least 4 MiB.
- **Upstream KCM is the fallback.** Controllers split between the two
  processes through one `--controllers` source of truth; removing a name
  reverts that controller to Go.
- **Sonobuoy is the guardrail** (operator, 2026-11-24). The phase gates in
  the state doc follow from it: the executed-spec set must match the
  baseline, no new failures, zero KCM restarts, and the pinned configuration
  cannot change in the same PR as a port.

## Rationale

Judgment call, not measured. Shipping nothing until proven removes risk to
the shipped control plane. The audit's 12-45 MB saving is modelled, not
measured. Separate process gives fault isolation and clean memory
attribution, at an unmeasured Rust fixed cost.

## Consequences

- Hybrid phases carry two KCMs and a second Pod cache, so early phases are
  memory-neutral at best; the main saving arrives only if Go KCM is removed.
- This ADR does not reverse `upstream-component-shipping-shape.md`. Shipping
  the port, or removing Go KCM, needs its own superseding ADR then.
- Phase plan and open items live in
  `ai/extended-context/kcm-rust-port-state.md`.

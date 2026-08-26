# Well-known folder, applied at config-load time, for vendored manifests

**Status:** Accepted
**Date:** 2026-08-25

## Context

u7s has three inconsistent mechanisms for bundled in-cluster resources:
CoreDNS compiled into the apiserver binary (`include_bytes!`) and
self-applied every restart; kube-proxy applied inline by `install.sh`;
Flannel (PR #1365) adding a heredoc variant. Full Server-Side Apply would
answer upgrade-time drift fully, but it's a deferred, multi-week epic
(`mayor-u6ju`) with no existing Rust crate — not built speculatively.

## Decision

`/etc/u7s/manifests` holds vendored manifest files, matching kubelet's
`/etc/kubernetes/manifests/` static-pod convention. An installer flag
controls where they land — default this folder (auto-applied), or
elsewhere for the operator to manage (GitOps; the apiserver checks the
default folder either way, finds it empty). Source-of-truth for these files
is `manifests/` at the repo root (real, standalone `.yaml`, scannable by
Renovate/Dependabot for image-tag bumps) — `scripts/build-release-tarball.sh`
bundles it into the release tarball, and `install.sh` copies from there at
install time rather than fetching over the network, since some target nodes
have no GitHub connectivity at all. The apiserver unconditionally
re-applies every manifest at boot via its existing SSA-shaped
`?fieldManager=` path; a bad manifest is a fatal startup error naming the
offending file. SIGHUP reload is a follow-on, not required here. No
continuous watching, no checksum/diff skip-if-unchanged logic. CoreDNS
moves out of `include_bytes!` as part of adopting this.

## Rationale

k3s and k0s are the closest precedents; neither uses real SSA. Both rely on
homegrown checksums to skip no-op reapplies (k3s: SHA-256 on a custom CR;
k0s: a config annotation + MD5), with no field-level ownership or conflict
detection — and their real, still-open bugs (`k3s-io/k3s#1317`,
`k0sproject/k0s#4021`) trace to that cleverness. Not attempting it
sidesteps their failure mode.

Continuous watching (k0s: fsnotify plus a fallback poll; k3s: 15s polling,
with a documented staleness bug, `#3711`) buys immediate pickup of
dropped-in files — not needed at u7s's manifest count, and skipping it
avoids a watch-loop, debounce logic, and partial-write races.

u7s's apiserver already accepts `?fieldManager=` on apply-shaped PATCH
requests, doing a correct one-shot merge per request
(`bootstrap_apply.rs:229-234`) — it just doesn't persist `managedFields` for
conflict detection across requests (`resource.rs:850-877`). Only one
applier touches these objects, so there's no conflict to detect, and this
gap doesn't block the decision. Full SSA isn't safer either — a
from-scratch reimplementation of structured-merge-diff, no existing crate,
carries its own bug risk.

## Consequences

- A manual edit to a well-known-folder resource is overwritten wholesale on
  next restart — deliberate, not an oversight. Durable customization uses
  the installer's alternate-output flag instead.
- Flannel's heredoc-in-`install.sh` (PR #1365) should migrate here, not
  stay install.sh-embedded.
- Non-destructive, drift-aware upgrades remain unsolved and out of scope.
  Full SSA is the leading candidate if a real need is later demonstrated,
  per `mayor-u6ju`'s trigger.

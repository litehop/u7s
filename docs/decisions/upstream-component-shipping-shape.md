# How upstream components ship

**Status:** Accepted  
**Date:** 2026-08-21

## Context

u7s's control plane is native Rust, but a working cluster also needs kubelet,
KCM, kube-proxy, a container runtime, CoreDNS, and optionally metrics-server.
Each has a different natural shipping shape; packaging needs one settled
answer per component rather than resolving it ad hoc at install time.

## Decision

- **kubelet**, **KCM** — pre-built binaries bundled in the install tarball,
  the same way u7s's own binaries ship.
- **kube-proxy** — not vendored as a host binary. Ships as an in-cluster
  DaemonSet manifest; its pods pull the upstream image at runtime.
- **CRI-O + crun** — host dependency, installed by the install script via
  `apt`. Ubuntu only for now.
- **CoreDNS** — in-cluster manifest, applied through the existing
  manifest-bootstrap path (`bootstrap_apply.rs`).
- **metrics-server** — not installed by default. Users wanting HPA apply the
  manifest themselves; documented, not hidden.

## Rationale

**kubelet/KCM** are static Go binaries with no OS-integration burden. Pinned
pre-built copies alongside u7s's release give every install the same tested
combination and no fetch step at daemon start.

**kube-proxy** has no bootstrap circularity — unlike kubelet, it is needed
only for Service and pod-to-pod networking, not for the control plane to
exist. A live 2-node measurement found RSS a wash between host-systemd and
DaemonSet placement (its footprint is dominated by fixed Go-runtime and
informer-cache overhead, not by where it runs), with inter-node Service and
pod-to-pod correctness passing identically either way. Both dimensions equal,
maintenance cost decided it: the DaemonSet reuses the mechanism CoreDNS
already needs, while host placement would require bespoke binary extraction,
systemd-unit authoring, and node-token minting in u7s's install/join tooling.

**CRI-O** via `apt` collapses cross-distro package fragmentation into one
testable sequence by targeting a single Ubuntu LTS — and it is a near-direct
lift of the sequence already proven in this project's dev/test node
provisioning, so it is not new engineering.

**CoreDNS** needs no new code path: `bootstrap_apply.rs` already exists and
is tested.

**metrics-server** is excluded because a full Conformance run confirmed it is
not required for certification, and shipping it anyway is the k3s/k0s
default-bloat failure mode the packaging philosophy exists to avoid.

## Consequences

- CRI-O beyond Ubuntu is unaddressed until there is demand.
- HPA requires a user-applied manifest.
- A future native kube-proxy folds into u7s's own binary; this ADR governs
  only the upstream-binary path.

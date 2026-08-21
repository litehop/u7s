# How upstream components ship: bundled binaries, in-cluster manifests, and package-manager delegation

**Status:** Accepted  
**Date:** 2026-08-21

## Context

u7s's control plane is native Rust (apiserver, scheduler), but a working
cluster also needs several non-Rust upstream components: kubelet,
kube-controller-manager (KCM), kube-proxy, a container runtime (CRI-O +
crun), CoreDNS, and optionally metrics-server. Each has a different natural
shipping shape, and the packaging story needs one settled answer per
component instead of resolving this ad hoc at install time.

## Decision

Each upstream component ships as follows:

- **kubelet** and **KCM**: bundled as pre-built binaries inside the install
  tarball, the same way u7s's own binaries ship.
- **kube-proxy**: **not** vendored as a host binary at all. It ships as an
  in-cluster DaemonSet manifest, applied by the control plane like any other
  workload, with the DaemonSet's pods pulling the upstream `kube-proxy`
  image at runtime.
- **CRI-O + crun**: a host-level dependency, installed via the OS package
  manager (`apt`) as a step the install script runs itself rather than
  something the user is asked to pre-install. Initial scope targets Ubuntu
  only.
- **CoreDNS**: an in-cluster manifest, applied via the control plane's
  existing manifest-bootstrap mechanism (`bootstrap_apply.rs`).
- **metrics-server**: **not** installed by default as part of the
  distributed bundle at all. Users who want HPA support apply the manifest
  themselves; it is documented, not hidden.

## Rationale

kubelet and KCM are plain static Go binaries with no OS-specific integration
burden beyond running them — vendoring pinned, pre-built copies alongside
u7s's own release gives every install the same tested combination and
requires no separate fetch step at daemon start.

kube-proxy differs because it has no bootstrap circularity: unlike kubelet
(which must be running before any pod can schedule) or KCM, kube-proxy is
only needed for pod-to-pod/Service networking, not for the control plane
itself to exist. A live 2-node measurement comparing host-systemd placement
against in-cluster DaemonSet placement found RSS a wash between the two
(kube-proxy's footprint is dominated by fixed Go-runtime and informer-cache
overhead, not by where it runs) and inter-node Service/pod-to-pod
correctness passing identically either way. With those two dimensions equal,
maintenance cost decided it: the DaemonSet placement reuses the same
kubelet-plus-DaemonSet-controller mechanism the control plane already needs
for CoreDNS and other in-cluster workloads, while host placement would
require u7s's own install/join tooling to invent and maintain kube-proxy-
specific binary extraction, systemd-unit authoring, and node-token minting —
a whole category of bespoke logic the DaemonSet shape avoids entirely.

CRI-O is installed via the package manager rather than left to the user
because targeting a single Ubuntu LTS version up front turns what would
otherwise be cross-distro package-name/repository fragmentation into one
well-defined, testable apt sequence — friendlier than a "go install this
yourself" failure message, and not new engineering effort: it is a
near-direct lift of an apt sequence already proven in this project's own
dev/test node provisioning.

CoreDNS ships as an in-cluster manifest because the mechanism to apply it
(`bootstrap_apply.rs`) already exists and is already tested — no new code
path is needed.

metrics-server is excluded from the default bundle because a real, full
Conformance run confirmed it is not required for Conformance certification,
and shipping components nobody asked for by default is precisely one of the
k3s/k0s failure modes the packaging philosophy exists to avoid. Keeping the
surface minimal applies to *what ships by default*, not only to what stays
configurable.

## Consequences

- If kube-proxy is ever natively rewritten, it folds into u7s's own binary
  and stops being an "upstream component to ship" entirely; this decision
  only governs the upstream-binary path.
- The install tarball's vendored binary set is kubelet and KCM plus
  CoreDNS/kube-proxy manifests, not kube-proxy as a binary — narrower than a
  naive "vendor every upstream piece" approach.
- CRI-O support beyond Ubuntu remains unaddressed until real demand for
  another distro exists.
- Users needing HPA/metrics-server must apply it themselves; this is a
  deliberate default-off choice, not an oversight, and is documented as
  such.

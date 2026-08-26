# Flannel as the default CNI

**Status:** Accepted
**Date:** 2026-08-25

## Context

u7s's KCM disabled `node-ipam-controller`, so `Node.spec.podCIDR` was never
coordinated across nodes, and CRI-O's stock `bridge` CNI plugin gave every
node the same default subnet — cross-node pod and Service traffic was
unreachable (`mayor-ua9gg`). Closing this gap needs a CNI that actually
consumes `podCIDR` for cross-node routing; the stock bridge plugin does not.
Target deployment is memory-constrained: 1GB RAM / 1VCPU nodes.

## Decision

Bundle Flannel (vxlan backend) as u7s's default CNI, deployed alongside
re-enabling KCM's `node-ipam-controller`. Operators may substitute another
CNI; bundling a lightweight default costs nothing beyond the IPAM fix every
CNI choice needs anyway.

## Rationale

Candidates compared: Flannel, Calico (VXLAN-only, BGP disabled), Cilium,
kube-router, Patu. Flannel
measured ~50–80MB per node, the lightest of any viable candidate, with no
forced kube-proxy replacement. Calico runs ~120–220MB with no supported way
to shed its NetworkPolicy engine's overhead even when unwanted. Cilium's
~180–250MB baseline is beside the point — its memory behavior is
unpredictable at scale, with real production reports of step-growth to
multi-GB and OOM-killing kubelet (`cilium/cilium#37935`, `#37629`,
`#44310`) — a worse risk on a node with zero OOM headroom than a static
number. kube-router carries an unresolved multi-GB memory-leak report
(`cloudnativelabs/kube-router#795`) with no fix in current releases. Patu is
single-node only, disqualifying for any multi-node cluster.

NetworkPolicy support did not factor into the ranking: `kube-network-policies`
already runs as a separate layer regardless of CNI choice
(`network-policy-engine.md`), so a candidate's own NetPol depth only matters
if it makes that redundant at zero marginal cost — none do.

Verified live: PR #1365 confirmed Flannel + `node-ipam-controller` on a
2-node Lima cluster — distinct auto-allocated `podCIDR`s, cross-node Service
and direct pod-to-pod reachability in both directions, no regression on
single-node installs.

## Consequences

- Every u7s cluster now needs `node-ipam-controller` enabled with a real
  `--cluster-cidr`; deployments needing a different pod-CIDR range must
  override it.
- Flannel's manifest ships as a heredoc inside `install.sh`, not a separate
  vendored file, since `install.sh` is distributed as a standalone
  curl-pipeable script with no sibling files. This should migrate to a
  proper installer-managed-manifest mechanism once that exists, rather than
  staying embedded in `install.sh` indefinitely.
- Kilo (`squat/kilo`) remains a flagged, unranked experiment — its
  WireGuard-mesh-plus-Flannel-add-on mode could additionally replace
  Tailscale, but its footprint has never been measured.
- Calico is the fallback if Flannel proves insufficient in practice; no
  other candidate is under consideration.

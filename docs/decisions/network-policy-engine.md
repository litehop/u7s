# kube-network-policies for NetworkPolicy enforcement

**Status:** Accepted
**Date:** 2026-08-14

## Context

u7s runs upstream kube-proxy in IPVS mode and uses CRI-O's stock `bridge` CNI plugin. Neither implements NetworkPolicy enforcement. An August 2026 audit (`ai/findings/oqr64-networkpolicy-current-state-2026-08-14.md`) confirmed the apiserver stored, listed, and watched NetworkPolicy objects correctly but nothing acted on them — a `default-deny-all-ingress` policy in place, a probe from `eve` to `bob` succeeded. Every deny rule was silently unenforced.

## Decision

Install `kubernetes-sigs/kube-network-policies` as a DaemonSet alongside kubelet/CRI-O/kube-proxy. Keep IPVS kube-proxy and the CRI-O bridge CNI unchanged.

## Rationale

The candidates compared (`ai/findings/jj1vz-cni-comparison-2026-08-14.md`): Calico, Flannel, Cilium, kube-network-policies, Antrea, kube-router. Calico and Antrea replace the CNI outright; Cilium's own recommended request is 512Mi RSS (5–10× the top pick); Flannel does not implement NetworkPolicy at all.

kube-network-policies is a NetworkPolicy-only enforcer designed to layer onto any CNI. It hooks the data path via NFQUEUE + nftables + NRI — no CNI swap, no BGP or overlay, no CRDs, no write-RBAC for the standard flavor. Its published request is 50Mi/100m. It supports both ingress and egress natively. The same engine is embedded in `kindnet` (KIND's default CNI), so the code path has broad production-adjacent exposure.

The integration proved trivial: 134 total lines of change (28 to `scripts/conformance/lima-start.sh` + a 106-line vendored `install.yaml`). A six-scenario empirical PoC on `lima-node-2` replayed the exact audit failures and confirmed all denies now enforce, with matching `verdict="drop"` entries in the DaemonSet log.

## Consequences

- CRI-O must have NRI enabled. Verified on-by-default in CRI-O 1.36.3 (August 2026); a `crio.conf.d` drop-in is the fallback if a future upstream default flips it off.
- The manifest is vendored at `scripts/conformance/manifests/kube-network-policies.yaml`, pinned to a release tag. A version bump requires a manual re-vendor.
- Native egress support means the originally-planned separate egress bead becomes redundant with the standard-flavor install.
- Follow-on impl beads originally scoped for a from-scratch enforcer are superseded — vendor + DaemonSet is the implementation.
- `[sig-network] Netpol` conformance coverage becomes measurable (was zero-coverage before). Upstream renamed the Ginkgo describe block from `NetworkPolicy` to `Netpol` in `release-1.36`; focus regex is `\[sig-network\] Netpol`.
- Continuously evaluated as another vendored component. If measured runtime footprint proves excessive relative to the value delivered, the fallback options are: disable the DaemonSet and revert to the pre-2026-08-14 accept-but-noop behaviour (accepting the correctness cost), or replace with an in-house enforcer targeting only the sub-features u7s actually exercises. Neither is committed to today; the trigger is measurement.

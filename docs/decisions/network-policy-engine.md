# kube-network-policies for NetworkPolicy enforcement

**Status:** Accepted
**Date:** 2026-08-14

## Context

u7s runs upstream kube-proxy in IPVS mode and uses CRI-O's stock `bridge` CNI plugin. Neither implements NetworkPolicy enforcement. An August 2026 audit — a full-crate grep for NetworkPolicy-consulting code cross-referenced with a live empirical test — confirmed the apiserver stored, listed, and watched NetworkPolicy objects correctly but nothing acted on them: zero code paths anywhere in u7s's own Rust codebase, in upstream kube-proxy, or in the bridge CNI plugin ever read a stored NetworkPolicy to permit or deny a connection. Empirically, with a `default-deny-all-ingress` policy in place, a probe from `eve` to `bob` succeeded. Every deny rule was silently unenforced. This is a data-path/CNI-plugin-choice gap — the same behavior a vanilla `kubeadm` cluster shows with only the bridge CNI installed — not a missing `if` check in u7s's own code.

## Decision

Use `kubernetes-sigs/kube-network-policies` as u7s's tested and recommended NetworkPolicy engine, wired into the conformance/dev-loop test harness — but **do not bundle it as a production default**. Document it as the recommended engine for operators who want NetworkPolicy enforcement, so they don't have to re-run the CNI comparison from scratch. Keep IPVS kube-proxy and the CRI-O bridge CNI unchanged either way.

**Amendment (2026-08-25):** confirmed via upstream `test/e2e/network/netpol/network_policy.go` (release-1.36) that NetworkPolicy tests carry zero `framework.ConformanceIt` markers — enforcement was never a certification requirement. Combined with a separate memory-first CNI/LB investigation demoting NetworkPolicy to near-zero priority for resource-constrained deployments, this supersedes the original "install as a production DaemonSet" decision below in favor of test-only-plus-documented-recommendation.

## Rationale

The candidates compared: Calico, Flannel, Cilium, kube-network-policies, Antrea, kube-router. Calico and Antrea replace the CNI outright; Cilium's own recommended request is 512Mi RSS (5–10× the top pick); Flannel does not implement NetworkPolicy at all. kube-router (firewall-only mode) was the closest second choice — same iptables/ipset shape, coexists with kube-proxy — but its only published number (250Mi) covers the heavier all-features (router+proxy+firewall) mode; the firewall-only manifest ships no resource request at all.

kube-network-policies is a NetworkPolicy-only enforcer designed to layer onto any CNI. It hooks the data path via NFQUEUE + nftables + NRI — no CNI swap, no BGP or overlay, no CRDs, no write-RBAC for the standard flavor. Its published request is 50Mi/100m. It supports both ingress and egress natively. The same engine is embedded in `kindnet` (KIND's default CNI), so the code path has broad production-adjacent exposure. Integration into the test harness was trivial (134 lines total) and a six-scenario empirical PoC confirmed all denies enforce correctly.

## Consequences

- CRI-O must have NRI enabled for this engine to work at all — verified on-by-default in CRI-O 1.36.3; relevant to any operator who deploys it, not just the test harness.
- The test-harness manifest is vendored at `scripts/conformance/manifests/kube-network-policies.yaml`, pinned to a release tag; a version bump requires manual re-vendor.
- `[sig-network] Netpol` (Ginkgo describe block renamed from `NetworkPolicy` in `release-1.36`; focus regex `\[sig-network\] Netpol`) is exercised by the test harness but is not part of `[Conformance]` — u7s ships correctly whether or not NetworkPolicy is enforced.
- If a future revisit compares this engine against alternatives, `[sig-network] Netpol` pass-count under a fixed test harness (measured in the `mayor-et3sl` scout) is the accepted benchmark — published per-engine resource claims are themselves rarely measured (jj1vz found zero of six candidates publish an actual RSS number) and are not a valid comparison basis alone.

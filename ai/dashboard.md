# Dashboard

2026-05-21T16:35 UTC
`bd prime` in a fresh Claude Code session
Open beads: 2 (mayor-1di P1, mayor-xy2 P3 deferred)

## What needs the operator now

**Root cause identified for all kubelet "invalid JSON" failures** — mayor-1di P1. Kubelet 1.36 sends `Accept: application/vnd.kubernetes.protobuf` on every request (CSINode, Lease, Events, Node). Our server always returns `content-type: application/json`. The Go client-go library fails to decode the response and emits "invalid JSON: expected value at line 1 column 1". Fix: detect the `Accept` header and encode responses as protobuf using the existing `proto.rs` infrastructure when protobuf is preferred. This is the only remaining blocker to node Ready and pod scheduling.

**CNI gap fixed** — bridge CNI config written to `/etc/cni/net.d/` in the lima VM during this session; NetworkReady is no longer in the error message.

**Next dispatch:** mayor-1di (protobuf response negotiation). Ready to dispatch on your signal.

**CoreDNS / sonobuoy:** Agreed — seed a default DNS service (Deployment + ConfigMap + ClusterIP Service at `10.96.0.10`) in `kube-system` at startup. Operator can replace it with any DNS server; it doesn't have to be CoreDNS specifically. File as a separate bead once the kubelet e2e is unblocked.

## Forward-looking

1. **mayor-1di** — protobuf response negotiation → node reaches Ready → pod lifecycle test can proceed
2. After node Ready: seed default DNS service (coredns or generic) for sonobuoy milestone
3. CI smoke job: create pod, assert Succeeded within 60s
4. mayor-xy2 (CR schema validation, P3) — deferred until Argo CD milestone

## Recent progress

- **PR #83 merged**: `storage.k8s.io/csinodes` and `csidrivers` added to seeded `system:node` ClusterRole — RBAC was correct but underlying issue is protobuf response negotiation
- Live e2e test run: node registers, CNI gap fixed, two blockers remain (protobuf responses, CSINode init)
- Root cause of all "invalid JSON" errors traced and filed as mayor-1di
- Test count: 260 (unchanged this round)

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI with `--merge`; flag security/API/architecture PRs for operator review first. Every bug fix ships with a regression test (Rule 14).

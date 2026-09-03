# Geneve wire-format decision brief (mayor-gjbov)

Bead: mayor-gjbov (decision-prep for mayor-aie31 Phase 3 / mayor-pa0ze)

## Recommendations

1. Option encoding: raw pod IP for the pod identifier; raw `VIP_IP:VIP_PORT` for the VIP echo. Compact alternatives (backend-index, flow-id) save a handful of bytes the mechanism doc's own sizing treats as noise (`ebpf-lb-dataplane.md:98-107`) while each adds a cross-node coordination or id-collision surface. The raw VIP echo is load-bearing, not a debugging nicety: the un-DNAT node must recover a VIP the reply never carries, so a reliable forward-leg VIP channel is required (decision 3). No ADR touches wire encoding.
2. NAT placement: DNAT on the backend, un-DNAT on the ingress node. This is the mechanism doc's packet-flow narrative and what mayor-g7jh2 (Phase 2) is written against, so it gates Phase 2, not Phase 3. kube-proxy likewise places un-DNAT at the node that owns the VIP's conntrack, never at the backend. The symmetric-return ADR fixes the return route, not the rewrite node.
3. Backend reverse-flow key uniqueness: accept overlapping LoadBalancers. Do NOT reject at admission (upstream permits the overlap) and do NOT fold the VIP into the key (unrecoverable on return). The reverse key can genuinely alias; the real decision is per-flow SNAT vs. real-client-IP (below), settled in Phase 3/4.

## Decision 1 — Geneve option wire encoding

Two sub-choices (`ebpf-lb-dataplane.md:136-140`): (a) pod identifier — raw pod IP vs. compact backend-index; (b) VIP echo — raw `VIP_IP:VIP_PORT` vs. compact flow-id.

Raw wins both. A compact backend-index needs an ordered table kept in lockstep across every node (the `vni_to_pod` map, `ebpf-lb-dataplane.md:106`); EndpointSlice churn can then point an ingress-stamped index at a pod a backend has not rebound, sending traffic to the wrong pod. A compact flow-id adds a second id-allocation/collision surface on top of decision 3's. Both compact forms save only a few bytes the mechanism doc's sizing already treats as noise (`ebpf-lb-dataplane.md:98-107`), and both are opaque to `tcpdump` exactly when a not-yet-proven dataplane is being debugged. Raw pod IP lets the backend rewrite the destination directly; raw `VIP_IP:VIP_PORT` is the value the un-DNAT node needs in decision 3 and matches Cilium's own return option (`geneve_dsr_opt4/6`, raw service address+port).

Gates Phase 3 (mayor-pa0ze). Locked into the wire format once ingress-encap and backend-decap programs compile against a chosen layout — cheap to change now, a flag-day after Phase 3 ships.

## Decision 2 — VIP<->PodIP NAT placement

DNAT on the backend (step 4), un-DNAT on the ingress node (step 7), per the mechanism doc's packet-flow (`ebpf-lb-dataplane.md:42-60`) and mayor-g7jh2's bead text. The alternative (both on the backend) is a wash on what data exists — both nodes already hold the VIP — and would only move which classifier does the rewrite, at the cost of rewriting Phase 2's approved plan. kube-proxy performs un-DNAT at the VIP-owning node via conntrack, reinforcing this placement. The symmetric-return ADR settles the route (reply always transits the ingress), not the rewrite node.

Gates Phase 2 (mayor-g7jh2), not Phase 3 — settle it before Phase 2 starts.

## Decision 3 — Backend reverse-flow key uniqueness

The backend keys its reverse-flow map on `(CLIENT_IP, SRC_PORT, PodIP, TargetPort, proto)` with the VIP as the stored value, captured on the forward leg. The key is NOT unique. A client may open two connections from one ephemeral source port to two different VIPs — the kernel enforces outbound-connection uniqueness on the full 4-tuple including destination, so identical `(CLIENT_IP, SRC_PORT)` to different VIPs is legal — and when both VIPs route to the same `Pod:TargetPort`, both DNAT to the same inner 4-tuple and the reverse keys collide.

The VIP cannot be recovered from the reply: the pod's reply carries `(PodIP, TargetPort, CLIENT_IP, SRC_PORT)` and never the VIP (`ebpf-lb-dataplane.md:54-56`). Folding the VIP into the key is therefore a dead end — a VIP-bearing key cannot be rebuilt on the return path. The VIP must be captured on the forward leg and re-applied on return from stored state.

Severity: for TCP the collision is largely self-limiting — a pod's kernel will not host two connections on one post-DNAT 4-tuple, so two such flows cannot both be live at once. The residual risk is stale-entry misattribution: a sequential reuse of the same client port to a different VIP reads a not-yet-evicted prior entry and gets the wrong VIP on return. UDP has no such protection; QUIC sidesteps it via DCID-keyed matching (`ebpf-lb-dataplane.md:90-96`).

Upstream permits the overlap: Kubernetes has no cross-Service selector validation — `ValidateServiceCreate` in `pkg/apis/core/validation/validation.go` validates a Service only against itself/its prior version, and the endpoints controller lists each Service's selector in isolation. Multiple `type=LoadBalancer` Services targeting the same `Pod:TargetPort` are legal, so admission-time rejection is non-conformant and is not an option.

The design decision, for Phase 3/4:
- Per-flow SNAT at the ingress: rewrite the client source to an ingress-owned unique IP:port, making the reverse key unique by construction, at the cost of the real client IP. (kube-proxy takes this trade in some modes; it relies on Linux conntrack's conflict resolution, which may SNAT or reject rather than making the bare tuple unique.)
- Preserve the real client IP: keep the client 5-tuple key and accept the stale-misattribution window, mitigated by evicting the reverse entry on connection teardown (FIN/RST) plus a metric for the residual window.

Real-client-IP is a stated gjbov goal, which favors the second option plus mitigation; the first is correct-by-construction if client-IP visibility is expendable. Gates Phase 3 (mayor-pa0ze); admission policy or SNAT choice is pure control-plane/dataplane policy, changeable without touching the wire format.

## Precedent

- Cilium's Geneve return option (`DSR_GENEVE_OPT_CLASS`, `struct geneve_dsr_opt4/6`, `cilium/cilium:bpf/lib/tunnel.h`) carries the raw service address and port, not a compact id.
- kube-proxy performs un-DNAT at the VIP-owning node via conntrack and handles shared-backend aliasing through conntrack conflict resolution (SNAT or reject), not a naturally-unique tuple.

## Open Phase-3 verification items

- Quantify the TCP stale-misattribution window and confirm evict-on-teardown closes it acceptably; quantify the UDP exposure.
- The reverse-recovery scheme assumes symmetric return (the reply transits the state-holding node) and, for the real-client-IP option, that no hop SNATs the client before the un-DNAT. Verify both in the prototype.

## References

`ai/extended-context/ebpf-lb-dataplane.md`; `docs/decisions/servicelb-ebpf-geneve-dataplane.md`; `docs/decisions/servicelb-symmetric-geneve-return.md`; `docs/decisions/ebpf-toolchain-aya.md`; `bd show mayor-aie31/g6u8s/g7jh2/pa0ze`; Cilium `bpf/lib/tunnel.h`.

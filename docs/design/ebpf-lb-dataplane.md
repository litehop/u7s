# u7s eBPF LB dataplane

**Status:** Living design doc — datapath mechanism, Phase 1
**Date:** 2026-09-01
**Bead:** mayor-2et9d (supersedes mayor-fhfro, mayor-mma08)

This doc covers the datapath mechanism only. The decision that this
dataplane IS u7s's `type=LoadBalancer` ServiceLB, the symmetric (not DSR)
return path, and the `aya` toolchain choice are recorded in
`docs/decisions/servicelb-ebpf-geneve-dataplane.md`,
`docs/decisions/servicelb-symmetric-geneve-return.md`, and
`docs/decisions/ebpf-toolchain-aya.md` — this doc builds on them, not
re-argues them. Service-level semantics settled before this dataplane
existed (`bd show mayor-0gpqp`) — the node's-own-address VIP model,
`externalTrafficPolicy` semantics, IPv6/dual-stack as a MUST, opt-in
node-selector scoping — carry over unchanged.

## Datapath & hooks

Four attachment points, two per direction, mapped to the mechanism required
at each rather than one hook type doing everything:

| Hook | Where | Why this hook, not another |
|---|---|---|
| tc-bpf ingress classifier | Physical uplink, every node (forward path) | VIP match, backend hash, flow-affinity write, Geneve dispatch via `bpf_skb_set_tunnel_key` + redirect to a `geneve0 external` tunnel device. Needs skb context (not an XDP helper) so the kernel's own geneve driver resolves the real egress path over whatever underlay reaches the backend node — a Tailscale mesh, plain routed L3, or no overlay. Raw XDP redirect has no notion of "route through a mesh peer that also does NAT traversal"; it redirects to a fixed ifindex with a hand-built L2 header, which does not work against a NAT'd peer. |
| XDP or TC ingress on `geneve0`, backend-node decap | Backend node (forward path) | Decap, then a local `vni_to_pod` lookup (this node's own scheduled pods only, <20 entries) rewrites dst from `VIP:port` to `PodIP:TargetPort` — the DNAT step. Records the reverse-flow entry (see Conntrack) so the reply can find its way back. The rewritten packet is now an ordinary pod-CIDR-destined packet, handed to normal forwarding — flannel's existing pod-CIDR route delivers the last hop to the veth, no new delivery mechanism. |
| tc-bpf egress classifier, backend-node capture | Physical uplink, backend node (return path) | Intercepts the pod's raw reply (`src=PodIP:TargetPort, dst=CLIENT_IP:SRC_PORT` — the pod has no notion a VIP exists) before normal routing sends it anywhere, looks up the reverse-flow entry, stamps Geneve tunnel metadata back toward the ingress node, redirects to `geneve0`. The backend node never emits a packet toward the client directly, so it never has to source one as an address it doesn't own. XDP has no egress hook at all. |
| XDP or TC ingress on `geneve0`, ingress-node decap | Ingress node (return path) | Decaps the returned reply, looks up the flow-affinity entry this same node wrote on the forward pass (see Conntrack), rewrites `src` from `PodIP:TargetPort` back to `VIP:PORT`, hands the packet to normal routing. It leaves sourced as the VIP — an address this node actually owns — so no anti-spoof/uRPF concern exists anywhere. |

## Packet flow

**Forward** (external client → backend Pod on another node):

1. Client sends `CLIENT_IP:SRC_PORT → VIP:PORT`. Routing delivers it to
   whichever node holds the VIP (the "ingress node" — may or may not also
   host a ready backend).
2. Ingress node's tc-bpf ingress program matches dst against the VIP map,
   consistent-hashes the flow to a ready backend `(node, pod IP, port)`
   triple, and writes a flow-affinity entry keyed on the client's own
   `(CLIENT_IP, SRC_PORT, proto)` — value = chosen backend + the `VIP:PORT`
   being answered (see Conntrack for why this key, not a 4-tuple).
3. It stamps tunnel metadata (remote = backend node's address, VNI = a fixed
   u7s-LB constant, one Geneve option carrying the chosen pod's identifier)
   and redirects to `geneve0`. The inner packet is untouched:
   `src=CLIENT_IP:SRC_PORT, dst=VIP:PORT`. No service IP/port needs encoding
   in the tunnel metadata — the backend node's decap step already has the
   real `VIP:PORT` from the inner header.
4. Backend node's `geneve0`-ingress program decapsulates, reads the pod
   identifier, rewrites dst to `PodIP:TargetPort` (`src` stays
   `CLIENT_IP:SRC_PORT` — the real-client-IP guarantee), records a
   reverse-flow entry keyed the same way, hands the packet to normal
   forwarding. **The Pod sees the real external client IP at L3**,
   unmodified end to end.

**Return:**

5. The Pod replies ordinarily: `src=PodIP:TargetPort, dst=CLIENT_IP:SRC_PORT`.
6. The backend node's tc-bpf egress classifier intercepts the reply, looks up
   the reverse-flow entry from step 4 (same client triple, now read from the
   packet's `dst` field), stamps Geneve tunnel metadata back toward the
   ingress node, redirects to `geneve0`. The inner packet is still untouched.
7. The ingress node's `geneve0`-ingress program decaps, looks up its own
   flow-affinity entry from step 2 (same client triple, again read from
   `dst`), rewrites `src` from `PodIP:TargetPort` to the stored `VIP:PORT`,
   and hands the packet to normal routing — leaving sourced as the VIP, an
   address this node owns.

## Conntrack & affinity

Both nodes in a flow hold per-connection state: the **ingress node** keeps a
flow-affinity entry (chosen backend, for the forward hash decision; the
`VIP:PORT` to restore, for the return leg) and the **backend node** keeps a
reverse-flow entry (which node to tunnel the reply back to, learned from the
forward packet's own tunnel source). A node acting as ingress for one flow
and backend for another uses the same map shape either way.

**The key is the client's own `(CLIENT_IP, SRC_PORT, proto)` triple —
nothing else.** This is the one field in every packet of the flow that no
hook anywhere ever rewrites, in either direction — it *is* the
real-client-IP guarantee this design exists to deliver. Every hook derives
it the same way: read from whichever field currently carries it — `src` on
the forward leg, `dst` on the return leg. A full 4-tuple key (or a src/dst
swap of one) cannot work here, because the packet's *other* side changes
identity mid-flight — `VIP:PORT` on the way in, `PodIP:TargetPort` on the
way back, since the backend node's DNAT sits between the two legs — so
nothing about that side is stable enough to match against. One key
derivation rule, one map per protocol, no separate reverse-NAT map: it
follows directly from the client triple being the only invariant, not from
an assumed swap.

Two flow-affinity maps, both `BPF_MAP_TYPE_LRU_PERCPU_HASH`, both custom (not
Linux's `nf_conntrack` — TC/skb-only and heavier than this needs;
`kubernetes-retired/blixt`'s own `LB_CONNECTIONS` map is likewise a
hand-rolled hash map). Per-CPU replication cost is bounded by the node's
actual vCPU count — u7s's target hardware is 1 vCPU/1GB per node
(`docs/design/cni-svclb-landscape-2026-08-25.md`), so it's nearly free
there; size for the highest vCPU count actually in the fleet.

- **TCP**: key = `(CLIENT_IP, SRC_PORT, proto)`. The fleet is IPv6-primary
  (3 of 5 nodes are IPv6-only —
  `docs/design/cni-svclb-landscape-2026-08-25.md`), so the key is **19
  bytes** (16 + 2 + 1), not the 13-byte IPv4-only figure an earlier draft
  used. Value = chosen backend (node + Pod IP + port, ~34 bytes) plus, on
  the ingress role, `VIP:PORT` (~18 bytes) — ~50 bytes, sized for the
  larger of the two roles since both share one map shape. 8192-entry
  ceiling.
- **QUIC**: key = a *fixed-length* prefix of the Destination Connection ID.
  RFC 9000 §17.2 gives the Initial packet's DCID an explicit,
  self-describing length byte, but §17.3.1's 1-RTT short header carries no
  length field at all — length is known only to whoever chose the CID. DCID
  matching on post-handshake traffic is only reliable if the whole cluster
  mints **one fixed CID length** (Traefik's QUIC stack must be configured
  for this — open question below). v1 design: learn the mapping when the
  Initial packet's self-describing DCID is seen, key subsequent
  short-header lookups on the first N bytes of DCID at that fixed length.
  Simpler than `draft-ietf-quic-load-balancers`'s self-encoding scheme —
  worth adopting only if u7s ever runs more than one ingress point per
  Service. 4096-entry ceiling (half of TCP's).

Sizing table, bottom-up:

| Component | Estimate | Basis |
|---|---|---|
| Userspace control-plane process | 3–5 MiB RSS | Rust async binary reusing `u7s_kubeconfig::HyperApiClient::watch_stream`/`drain_watch_buffer` (already used by `crates/scheduler`) — no new HTTP client. Idle after initial reconcile. |
| eBPF programs (tc ×3, XDP/TC decap ×2) | ~0 MiB (kernel-resident) | JIT'd native code, 5–50 KiB each; does not count against process RSS. |
| VIP map (<100 Services × ≤2 protocols) | ~25 KiB | <200 entries, small fixed struct. |
| Endpoint map (<1000 endpoints) | ~128 KiB | Backend triple per entry. Every node carries the full map — any node can become an accidental ingress node for any VIP. |
| TCP flow-affinity map, per-CPU | ~0.5–1 MiB **at 1 vCPU** | 8192 entries × ~90 B/entry (19 B IPv6-sized key + ~50 B value + ~20 B hash-bucket overhead) × vCPU count. The client-only key is narrower than a full 4-tuple would be even at IPv6 width, which offsets IPv6's larger addresses — the total is essentially unchanged from an (incorrectly) IPv4-sized 4-tuple estimate. |
| QUIC CID flow-affinity map, per-CPU | ~0.25–0.5 MiB **at 1 vCPU** | 4096 entries, same overhead model. |
| `vni_to_pod` map (backend node, local only) | <5 KiB | <20 entries — this node's own scheduled pods. |
| **Total** | **~4–7 MiB at 1 vCPU** | Sum of the rows above. The corrected IPv6-sized key changes the TCP/QUIC rows' internal math but not the headline total — a client-only key is narrower than the four-tuple it replaces even measured in IPv6-width bytes. Scales roughly linearly with vCPU count for the two per-CPU rows on any node with more than 1 core. |

All four hash maps pre-allocate their full `max_entries` ceiling at
creation — this is exactly the mechanism behind loxilb's "cannot start on
1GB node" failure (`docs/design/cni-svclb-landscape-2026-08-25.md`: measured
directly on a real 1 CPU/1GiB Lima VM, `bpf_create_map_xattr` failing with
`ENOMEM` before the process could reach a running state). The ceilings above
are chosen deliberately small for u7s's stated envelope (<10 nodes/<100
Services/<1000 endpoints); this is not a number to grow casually.

## Userspace control plane

Runs **per node**, not centrally: eBPF maps are local kernel memory with no
remote-write API, so a single centralized controller cannot populate
another node's maps. One DaemonSet replica per node, `hostNetwork` +
`CAP_BPF`/`CAP_NET_ADMIN` (no `hostPID`/`hostIPC`, no CRI socket — this
dataplane never enters a pod's network namespace): load the tc-bpf/XDP
programs once at start, watch `Service`(`type=LoadBalancer`) and
`EndpointSlice` via the existing `watch_stream`/`drain_watch_buffer`
machinery, write the VIP/endpoint maps on change, then idle. Pin
programs/maps under `/sys/fs/bpf` so a watcher-process restart does not drop
in-flight flow-affinity state; a full node reboot still cold-starts.

## Prototype gates — go/no-go before Phase 3

1. **Return path works cross-node on real disjoint subnets.** A pure Geneve
   round trip — forward encap ingress→backend, decap+DNAT at the backend,
   reply capture+encap backend→ingress, decap+un-DNAT at ingress, delivery
   to the client sourced as the VIP — with no address-forging anywhere.
   Lima cannot validate this alone; it needs the real multi-provider
   topology (or at minimum two disjoint subnets with no shared default
   route).
2. **Measured RSS footprint on a real 1GB/1vCPU node**, not the ~4–7 MiB
   estimate above. loxilb's "cannot start on 1GB" is the standing reminder
   that map pre-allocation can hide a floor invisible until actually run.
3. **Both userspace RSS and kernel eBPF-map memory must be independently
   and continuously monitorable**, not measured once and assumed stable
   (`docs/decisions/ebpf-toolchain-aya.md`) — `bpftool map dump`/`show` or
   equivalent wired into the same observability path as the userspace
   process's RSS.

Any of these gates failing forecloses this design as built; it does not
automatically resurrect the klipper-lb-alike, since that path already loses
real client IP on cross-node delivery — a third option would need fresh
evaluation.

## Open questions to resolve before the Phase-3 prototype

- **Traefik fixed-length QUIC CID support**: does Traefik's QUIC stack
  support configuring a fixed connection-ID length? A hard precondition for
  the CID flow-affinity design above, not yet verified against Traefik
  specifically.
- **Geneve option encoding for the backend-pod identifier**: a raw pod IP
  (4/16 bytes) is simplest; a compact backend-index (matching the endpoint
  map's own ordering) is smaller but adds a dependency on map-ordering
  staying consistent between the ingress and backend node's view — pick one
  before implementation.
- **VIP↔PodIP NAT placement**: this doc proposes DNAT on the backend node
  (step 4) and un-DNAT on the ingress node (step 7), since the ingress node
  already holds everything it needs for the un-DNAT from its own step-2
  write — no new cross-node coordination. The alternative, both rewrites on
  the backend node, would require the backend node to learn the ingress
  node's VIP, state this design otherwise avoids entirely. Not yet settled.

## References

- `bd show mayor-0gpqp`, `bd show mayor-fhfro`, `bd show mayor-mma08` —
  prior ServiceLB and dataplane work this doc supersedes/builds on.
- `docs/design/cni-svclb-landscape-2026-08-25.md` — CNI/ServiceLB landscape
  research (target hardware, IP allocation model, loxilb disqualification).
- `docs/decisions/servicelb-ebpf-geneve-dataplane.md`,
  `docs/decisions/servicelb-symmetric-geneve-return.md`,
  `docs/decisions/ebpf-toolchain-aya.md` — the decisions behind this
  mechanism.
- `docs/decisions/flannel-for-cni.md` — the CNI whose pod-CIDR routing the
  backend-node last hop reuses.
- `kubernetes-retired/blixt`, `dataplane/ebpf/src/{ingress,egress}/*.rs` —
  closest architectural analog for the conntrack/hash-map shape.
- RFC 9000 §17.2 (Long Header Packets), §17.3.1 (1-RTT Packet) — QUIC
  Connection-ID framing this design's CID conntrack depends on.
- `draft-ietf-quic-load-balancers-21` — the future-upgrade CID-encoding
  scheme, not adopted for v1.
- `crates/scheduler/src/lib.rs`, `crates/kubeconfig` — existing
  `watch_stream`/`drain_watch_buffer` machinery this design's userspace
  control plane reuses.

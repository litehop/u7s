# u7s eBPF LB dataplane

**Status:** Draft — Phase 1 design, for operator refinement
**Date:** 2026-09-01 (return-path model revised same day, see Notes on
`bd show mayor-2et9d`)
**Bead:** mayor-2et9d (supersedes mayor-fhfro, mayor-mma08)

This dataplane IS u7s's `type=LoadBalancer` ServiceLB — there is no separate
klipper-lb-alike. A per-node eBPF pipeline matches VIP traffic and
Geneve-encaps it to whichever node holds a ready backend, giving cross-node
delivery, real client IP at L3, and disjoint subnets with no shared L2 or
BGP. **The return path is symmetric, not DSR (Direct Server Return):** the
backend node never sources a packet as the VIP. It Geneve-encaps the pod's
reply back to the ingress node, which decaps it and sends it to the client
sourced as the VIP — an address that node actually owns. No node ever
forges an address it doesn't own. This was an explicit operator decision
(2026-09-01) reversing an earlier DSR-based draft of this doc: DSR's
return-offload benefit (skipping the extra hop back through the ingress
node) is nil at u7s's scale, since there is no video/download-heavy
workload to justify it, while symmetric return deletes an entire
complexity/risk layer DSR required — see "The return-path crux" below.
**Recommend `aya`** as the toolchain: pure Rust, no libbpf C dependency,
matches the all-Rust workspace. The forward path's cross-node hop is
**tc-bpf + a real `geneve0 external` tunnel device**, not raw XDP redirect:
Geneve encapsulation plus normal kernel routing works over whatever
underlay connects two nodes — a Tailscale/WireGuard mesh (u7s's actual
fleet today, including one node behind NAT), plain routed L3, or no overlay
at all — where XDP's redirect model assumes flat L2/L3 fabric reachability
this topology does not always have. Bottom-up footprint estimate:
**~4–7 MiB RSS at 1 vCPU** (the primary target hardware) — the symmetric
return path's extra per-flow state fits inside the same map ceilings this
estimate already budgeted, not a new map, so the number is unchanged from
the DSR draft — still unverified on real hardware, which is why footprint
measurement is a named go/no-go gate below, not a settled number.

## Scope carried over from prior work

`docs/design/cni-svclb-landscape-2026-08-25.md` and mayor-0gpqp's ServiceLB
design proposal (`bd show mayor-0gpqp`, closed/superseded once this eBPF
pipeline replaced it) already settled: IP allocation is the node's-own-address
model (no VIP pool — the VIP is always an address the node hosting it
actually owns, whether a provider-pinned public IPv6 prefix, a LAN address,
or a Tailscale address); `externalTrafficPolicy` semantics; IPv6/dual stack
as a MUST; opt-in node-selector scoping. Those hold. What changes: 0gpqp's
per-Service DaemonSet fan-out and iptables DNAT dataplane are replaced
entirely by this eBPF pipeline for the cross-node+real-IP path. 0gpqp's
controller-placement analysis (embed vs. standalone) does not transfer:
this dataplane's state is per-node kernel memory (eBPF maps), which a
centralized apiserver-embedded controller cannot write into remotely — the
control plane here must run per node (see below), not centrally.

## Datapath & hooks

The pipeline has four attachment points — two per direction — mapped to the
mechanism required at each rather than one hook type doing everything:

| Hook | Where | Why this hook, not another |
|---|---|---|
| tc-bpf ingress classifier | Physical uplink, every node (forward path) | VIP match, backend hash, flow-affinity map, Geneve dispatch via `bpf_skb_set_tunnel_key` + redirect to a `geneve0 external` tunnel device. Needs skb context (`bpf_skb_set_tunnel_key` is not an XDP helper) so the kernel's own geneve driver — not our code — resolves the real egress path over whatever underlay reaches the backend node: today that's transparently riding the existing Tailscale WireGuard tunnel, but the mechanism is the same over plain routed L3 or no overlay. Raw XDP redirect has no notion of "route through a mesh peer that also does NAT traversal"; it redirects a frame to a fixed ifindex with an L2 header we would have to construct ourselves, which does not work against a NAT'd peer. |
| XDP or TC ingress on `geneve0`, backend-node decap | Backend node (forward path) | Decap, then a tiny local `vni_to_pod` lookup (this node's own scheduled pods only, <20 entries) rewrites dst from `VIP:port` to `PodIP:targetPort` — the actual DNAT step. Also records a reverse-flow entry (this node's own return map — see Conntrack below) so the reply can find its way back. The rewritten packet is now an ordinary pod-CIDR-destined packet, handed to normal forwarding, riding flannel's existing pod-CIDR route for the last hop to the veth — no new last-hop delivery mechanism. |
| tc-bpf egress classifier, backend-node capture | Physical uplink, backend node (return path) | Intercepts the pod's raw reply (`src=PodIP:targetPort, dst=CLIENT_IP:SRC_PORT` — the pod is unaware a VIP exists) before normal routing would send it anywhere, looks up the reverse-flow entry the decap step populated, stamps Geneve tunnel metadata back toward the ingress node, and redirects to `geneve0`. This is the crux of the symmetric model: the backend node never emits a packet toward the client directly, so it never has to source one as an address it doesn't own. Egress rewrite/redirect of a locally-originated packet has no XDP equivalent; XDP has no egress hook at all. |
| XDP or TC ingress on `geneve0`, ingress-node decap | Ingress node (return path) | Decaps the returned reply, looks up the flow-affinity entry this same node wrote on the forward pass (keyed by the client's own 4-tuple/CID, carried unchanged in the inner packet through both tunnel hops), rewrites `src` from `PodIP:targetPort` back to `VIP:port`, and hands the packet to normal routing. It leaves this node sourced as the VIP — an address this node actually owns — so no anti-spoof/uRPF concern exists anywhere in this design. |

Packet flow, external client to backend Pod on a different node:

**Forward:**

1. Client sends `CLIENT_IP:SRC_PORT → VIP:PORT`. Routing (provider-level for
   a public address, or just normal L3 for a LAN/mesh address) delivers it
   to whichever node actually holds the VIP (the "ingress node" — may or may
   not host a ready backend itself).
2. Ingress node's tc-bpf ingress program matches dst against the VIP map,
   consistent-hashes the flow to a ready backend `(node, pod IP, port)`
   triple, and records the choice plus the client's own 4-tuple in this
   node's own flow-affinity map (see Conntrack below) — used both to avoid
   re-hashing an established flow on endpoint churn, and later to un-DNAT
   the reply.
3. It stamps tunnel metadata (remote = backend node's address on whatever
   underlay reaches it, VNI = a fixed u7s-LB constant, one Geneve option
   carrying the chosen pod's identifier) and redirects to `geneve0`. The
   kernel's geneve driver encapsulates and normal routing carries it over
   the mesh — **the inner packet is untouched**: `src=CLIENT_IP:SRC_PORT,
   dst=VIP:PORT`. No service IP/port needs encoding in the tunnel metadata,
   because the inner packet is never modified — the backend node's decap
   step already has the real VIP:port from the inner header.
4. Backend node's `geneve0`-ingress program decapsulates, reads the pod
   identifier option, rewrites dst to `PodIP:TargetPort` (src stays
   `CLIENT_IP:SRC_PORT` — this is the real-client-IP guarantee), records the
   reverse-flow entry, hands the packet to normal forwarding. Flannel's
   pod-CIDR route delivers it to the pod's veth. **The Pod sees the real
   external client IP at L3**, unmodified end to end.

**Return:**

5. The Pod replies ordinarily: `src=PodIP:TargetPort, dst=CLIENT_IP:SRC_PORT`
   — it has no notion a VIP exists.
6. The backend node's tc-bpf egress classifier intercepts the reply, looks up
   the reverse-flow entry from step 4, stamps Geneve tunnel metadata back
   toward the ingress node, and redirects to `geneve0`. **The inner packet is
   still untouched** — the backend node has rewritten nothing about the
   packet's addressing, only tunneled it.
7. The ingress node's `geneve0`-ingress program decaps, looks up its own
   flow-affinity entry from step 2 (keyed by the client 4-tuple carried
   unchanged in the inner packet), rewrites `src` from `PodIP:TargetPort` to
   `VIP:port`, and hands the packet to normal routing. It leaves sourced as
   the VIP — an address this node owns — reaching the client as an ordinary
   reply from `VIP:PORT`.

## The return-path crux

**Mechanism (operator decision, 2026-09-01): symmetric return through the
ingress node, not DSR.** The backend node never sources a packet as the
VIP; it tunnels the pod's raw reply back to whichever node actually owns
the VIP (steps 5–7 above), and that node sends it to the client under its
own address. This replaces an earlier draft of this doc that chose
DSR-style return (either a VIP-on-loopback alias entered via the pod's own
netns, or an eBPF egress rewrite that sourced the reply as the VIP directly
from the backend node). DSR's only real advantage over symmetric return is
skipping the extra Geneve hop back through the ingress node on the
high-throughput leg (server → client, typically the larger of the two for
video/downloads) — worth nothing at u7s's scale, since no workload here is
throughput-heavy enough for that hop to matter. In exchange, symmetric
return deletes an entire complexity and risk layer DSR required, none of
which apply to this design:

- **No source-spoofing / cloud anti-spoof (uRPF) risk.** DSR's backend node
  had to emit a packet sourced as an address it was never assigned — a
  cloud's own anti-spoof filtering could silently drop that, and this doc's
  DSR draft could not verify Linode's or Scaleway's behavior either way.
  Under symmetric return no node ever sources a packet as an address it
  doesn't own, so this risk, and its prototype gate, do not exist.
- **No home-NAT-node backend-scheduling exclusion.** DSR would have required
  excluding the home-NAT node from hosting any backend for an externally-facing
  Service, because its own router would re-mangle a reply forged as the VIP
  before it reached the internet. Symmetric return never asks the home node
  to source anything but its own already-NAT'd traffic, so this exclusion is
  unnecessary — the home node is schedulable like any other node.
- **No public-VIP requirement.** DSR implicitly needed the VIP to be a
  provider-pinned public address reachable independent of which node actually
  answers for it. Symmetric return has no such constraint — see VIP model
  below.

Revisit DSR only if a genuinely download-heavy, high-throughput workload
appears **and** the provider in use allows cross-node egress source-forging;
neither holds today.

### VIP model

The VIP is simply an address the ingress node itself owns and the client
can reach it on — no requirement that it be public. The operator's actual
fleet gives every node a public IPv6 `/64` pool, which makes node-owned
public VIPs abundant and clean and is the expected common case, but this
design does not require public addressing: a LAN address or a Tailscale
address works identically, since the mechanism only needs the node to own
the address it sources replies from, never that the address be globally
routable.

### Underlay-agnostic transport

Geneve encapsulation plus normal kernel routing carries both the forward and
return legs over whatever underlay exists between two nodes: a
Tailscale/WireGuard mesh, plain L3 routing with no overlay at all, or any
other transport the kernel can route through. Tailscale is today's example
underlay for the operator's real fleet, not a premise this design depends
on — a future non-Tailscale fleet works unchanged as long as the two nodes
can route to each other's `geneve0` endpoint.

### VIP↔PodIP NAT placement — a refinement point, still open

Two NAT rewrites now exist: forward DNAT (`VIP:port → PodIP:targetPort`,
step 4) and return un-DNAT (`PodIP:targetPort → VIP:port`, step 7).
**Proposed split: DNAT stays on the backend node (unchanged from the
forward-only draft), un-DNAT runs on the ingress node.** The ingress node
already holds everything it needs for the un-DNAT from its own step-2 write
— no new cross-node coordination. The alternative, doing both rewrites on
the backend node (so the ingress node's decap step forwards an
already-rewritten packet untouched), would require the backend node to
learn the ingress node's VIP, a piece of state this design otherwise avoids
entirely. The proposed split needs the backend node to know only "which
node to tunnel the reply back to" (learned trivially from the forward
packet's own outer Geneve source at decap time, step 4) — no VIP knowledge
on the backend node at all. Flagged as an open question below, not settled
by this doc.

## Conntrack & affinity

Both nodes in a flow now hold per-connection state, not just the ingress
node: the **ingress node** keeps a flow-affinity entry (chosen backend, for
the forward hash decision; enough to un-DNAT, for the return leg) and the
**backend node** keeps a reverse-flow entry (which node to tunnel the reply
back to, learned from the forward packet's own tunnel source) alongside the
existing static `vni_to_pod` lookup. A node acting as ingress for one flow
and backend for another (or occasionally both, for a flow that routes to
itself) uses the same map shape either way — the entry's fields are just
populated by whichever hook wrote them first.

Two flow-affinity maps, both `BPF_MAP_TYPE_LRU_PERCPU_HASH`, both custom
(not Linux's `nf_conntrack` — that subsystem is TC/skb-only and heavier than
this needs; blixt's own `LB_CONNECTIONS` map is likewise a hand-rolled hash
map, not `nf_conntrack`, despite prior notes describing its XDP→TC switch as
"for conntrack access" — the actual TC-only dependency in blixt's source is
`bpf_redirect_neigh`, an skb-context L2-neighbor-resolution helper, a
different mechanism than what this design needs). Per-CPU is the correct
map type for lock-free concurrent updates, but its cost multiplier is
**bounded by the node's actual vCPU count** — u7s's stated target hardware is
1 vCPU/1GB per node (`docs/design/cni-svclb-landscape-2026-08-25.md`), so
per-CPU replication is nearly free there; size for the highest vCPU count
actually in the fleet, not a generic multi-core assumption.

- **TCP**: key = 4-tuple (13 bytes, `src_ip, dst_ip, src_port, dst_port,
  proto`), value = chosen backend/return-remote + last-seen. 8192-entry
  ceiling. The same entry serves the forward lookup (ingress role) and the
  reverse lookup (backend role) — the reply's own 4-tuple is the forward
  4-tuple with `src`/`dst` swapped, so one map, two lookup directions, no
  duplicate state.
- **QUIC**: key = a *fixed-length* prefix of the Destination Connection ID.
  RFC 9000 §17.2 gives the Initial packet's DCID an explicit, self-describing
  length byte — easy to parse on the first packet of a new connection. But
  §17.3.1's 1-RTT short header carries **no length field at all**: "The
  header form bit and the Destination Connection ID field of a short header
  packet are version independent" — length is known only to whoever chose
  the CID. This means DCID-prefix matching on ongoing (post-handshake)
  traffic is only reliable if the whole cluster uses **one fixed CID length**,
  a real operational precondition (Traefik's QUIC stack must be configured
  to mint fixed-length CIDs) — flagged as an open question below, not solved
  here. v1 design: learn the mapping when the Initial packet's self-describing
  DCID is seen, key subsequent short-header lookups on the first N bytes of
  DCID at that fixed length. This is deliberately simpler than the IETF
  `draft-ietf-quic-load-balancers` scheme (self-encoding server ID +
  encrypted config rotation in the CID's first octet, for multi-LB /
  address-migration correctness) — worth adopting later if u7s ever runs more
  than one ingress point per Service; not needed at today's single-Traefik
  scale. 4096-entry ceiling (half of TCP's, since fewer Services are expected
  to front QUIC at this scale).

Sizing table, bottom-up (fixes mayor-fhfro's non-summing total and its
under-cited maps-row):

| Component | Estimate | Basis |
|---|---|---|
| Userspace control-plane process | 3–5 MiB RSS | Rust async binary, reusing `u7s_kubeconfig::HyperApiClient::watch_stream`/`drain_watch_buffer` (already used by `crates/scheduler`) — no new HTTP client, no generic k8s client crate. Idle after initial reconcile; no per-connection proxy state. |
| eBPF programs (tc ×3, XDP/TC decap ×2) | ~0 MiB (kernel-resident) | JIT'd native code, 5–50 KiB each; does not count against process RSS. One extra tc-bpf (backend-node egress capture) and one extra decap program (ingress-node return) versus a forward-only pipeline, both negligible at this size. |
| VIP map (<100 Services × ≤2 protocols) | ~25 KiB | <200 entries, small fixed struct. |
| Endpoint map (<1000 endpoints) | ~128 KiB | Backend triple per entry, hash overhead included. Every node carries the full map — any node can become an accidental ingress node for any VIP. |
| TCP flow-affinity map, per-CPU | ~0.5–1 MiB **at 1 vCPU** | 8192 entries × ~64B/entry-with-bucket-overhead × vCPU count. One entry now serves both the forward hash decision and the return un-DNAT/reverse-tunnel lookup — no separate reverse-NAT map. |
| QUIC CID flow-affinity map, per-CPU | ~0.25–0.5 MiB **at 1 vCPU** | 4096 entries, same overhead model. |
| `vni_to_pod` map (backend node, local only) | <5 KiB | <20 entries — this node's own scheduled pods. |
| **Total** | **~4–7 MiB at 1 vCPU** | Sum of the rows above — unchanged from a forward-only estimate, since the return path's extra state reuses the same map ceilings rather than adding new ones. Scales roughly linearly with vCPU count for the two per-CPU rows on any node with more than 1 core. |

All four hash maps pre-allocate their full `max_entries` ceiling at creation
— this is exactly the mechanism behind loxilb's "cannot start on 1GB node"
failure (`docs/design/cni-svclb-landscape-2026-08-25.md`, Service
LoadBalancer section: measured directly on a real 1 CPU/1GiB Lima VM,
`bpf_create_map_xattr` failing with `ENOMEM` before the process could even
reach a running state). The ceilings above are chosen deliberately small for
u7s's stated envelope (<10 nodes/<100 Services/<1000 endpoints); this is not
a number to grow casually.

## Userspace control plane

Must run **per node**, not centrally: eBPF maps are local kernel memory with
no remote-write API, so a single apiserver-embedded controller (the shape
0gpqp recommended for DaemonSet lifecycle, a genuinely different problem)
cannot populate another node's maps. One DaemonSet replica per node,
`hostNetwork` + `CAP_BPF`/`CAP_NET_ADMIN` (no `hostPID`/`hostIPC`, no CRI
socket — this dataplane never enters a pod's network namespace, unlike
kube-router's DSR mode): load the tc-bpf/XDP programs once at start, watch
`Service`(`type=LoadBalancer`) and `EndpointSlice` via the existing
`watch_stream`/`drain_watch_buffer` machinery, write the VIP/endpoint maps on
change, then idle — load-once-then-watch, no persistent proxy loop, matching
the memory discipline klipper-lb's shell script already demonstrated. Pin
programs/maps under `/sys/fs/bpf` so a watcher-process restart does not drop
in-flight flow-affinity state; a full node reboot still cold-starts.

## Toolchain recommendation

| | aya | libbpf-rs | C + libbpf |
|---|---|---|---|
| Rust-fit | Pure Rust, no C dependency, no C toolchain in the build (`aya-rs/aya` README: "does not rely on libbpf... built from the ground up purely in Rust") | Rust wrapper *around* the real libbpf C library — adds a C dependency and toolchain to an all-Rust workspace | None — a second language in a project with zero C today |
| CO-RE | Own BTF-based CO-RE, musl-linkable single binary ("compile once, run everywhere") — already matches the multi-kernel matrix confirmed live (Lima 7.0.0-30 arm64 vs. 7.0.0-28 x86_64) | Relies on libbpf's CO-RE, mature and field-proven | Same libbpf CO-RE, most mature but manual |
| Verifier/compiler maturity | Uses `bpf-linker`, an LLVM-based Rust→BPF backend with materially less production mileage than clang's decades-old BPF backend — the real, non-marketing trade-off against aya, since the kernel verifier itself is identical regardless of toolchain | Compiles via clang, the same mature backend as C | Most mature: clang's original target |
| QUIC parsing feasibility | Bounded, byte-at-a-time varint parsing (verifier requires provably-bounded access; blixt's own `ptr_at` + explicit `ctx.data_end()` checks show the idiom) — **no easier or harder than C**, this constraint is inherent to the verifier, not the source language | Same constraint | Same constraint |
| Reuse precedent at this problem class | `kubernetes-retired/blixt` — Rust+aya k8s L4 LB, TC classifiers, custom hash-map conntrack, DNAT+redirect — closest architectural analog, confirms aya is viable for this exact shape (archived for scope/maintenance reasons, not a technical dead end) | None found at this problem class | Katran (C++/heavy, general-purpose) |
| Dependency footprint | One crate family, no vendored C library | Vendors/links libbpf | N/A — different build system entirely |

**Recommend `aya`.** It is the only option with no C toolchain or C
dependency in a project whose entire stance is minimal-deps and all-Rust; the
`bpf-linker` maturity gap is real but narrower than the cost of introducing
C to the workspace, and blixt already proved the toolchain viable for a
directly comparable dataplane. Operator call to confirm, since the task
scope explicitly leaves this open.

## Coexistence

**kube-proxy**: this dataplane owns north-south `LoadBalancer` external-IP:port
traffic only, end to end (including the backend-node last hop, which reuses
flannel's pod-CIDR routing directly rather than kube-proxy). Everything else
— `ClusterIP`/`NodePort` traffic, including **east-west** traffic (one Pod
calling another Service's `ClusterIP` in-cluster) — stays entirely
kube-proxy's, unmodified. The VIP map matches only `LoadBalancer`-Service
external IP:port pairs, never `ClusterIP`/`NodePort` ranges, so non-matching
traffic falls through unmodified to kube-proxy's existing IPVS rules by
construction — no double-processing, no overlap. The backend-node last hop
reusing flannel's routing is plain pod-to-pod delivery of a north-south flow
already resolved to a specific pod, not a `ClusterIP` lookup — it does not
compete with or duplicate kube-proxy's east-west responsibility.

**flannel** (`docs/decisions/flannel-for-cni.md`): the VIP address space is a
real externally-routable (or Tailscale-mesh, or LAN) address, categorically
outside flannel's pod-CIDR and the cluster's Service-CIDR — no address-space
collision by construction. This dataplane's Geneve tunnel (forward and
return) and flannel's own vxlan overlay are separate encapsulations for
separate traffic classes (external ingress vs. pod-to-pod); a
dataplane-forwarded packet's outer header targets the peer node's real
address directly, never traversing flannel's vxlan device. The only point of
contact is the deliberate one named above: the backend-node decap step hands
its DNAT'd packet to flannel's existing pod-CIDR routing for the last hop,
reusing it rather than duplicating it.

## Prototype gates — go/no-go before Phase 3

1. **Return path works cross-node on real disjoint subnets.** Under the
   symmetric model this is a pure Geneve round trip — forward encap
   ingress→backend, decap+DNAT at the backend, reply capture+encap
   backend→ingress, decap+un-DNAT at ingress, delivery to the client sourced
   as the VIP — with no address-forging anywhere. This is materially simpler
   than the DSR draft's version of the same gate, which also had to verify
   cloud anti-spoof behavior; that verification is no longer needed. Lima
   cannot validate this on its own — it needs the real multi-provider
   topology (or at minimum two disjoint subnets with no shared default
   route).
2. **Measured RSS footprint on a real 1GB/1vCPU node**, not the ~4–7 MiB
   estimate above. loxilb's "cannot start on 1GB" is the standing reminder
   that map pre-allocation can hide a floor invisible until actually run.

Either gate failing forecloses this design as built; it does not
automatically resurrect the fixed klipper-lb-alike, since that path was
already found to lose real client IP on cross-node delivery — a third option
would need fresh evaluation.

## Open questions for the operator

- **Toolchain**: confirm `aya` over libbpf-rs/C (recommended above).
- **QUIC CID length**: does Traefik's QUIC stack support configuring a fixed
  connection-ID length? This is a hard precondition for the CID
  flow-affinity design above, not yet verified against Traefik specifically.
- **Geneve option encoding for the backend-pod identifier**: a raw pod IP
  (4/16 bytes) is simplest; a compact backend-index (matching the endpoint
  map's own ordering) is smaller but adds a dependency on map-ordering
  staying consistent between the ingress and backend node's view — pick one
  before implementation.
- **VIP↔PodIP NAT placement**: confirm the proposed split (DNAT on the
  backend node, un-DNAT on the ingress node — see "The return-path crux"
  above) versus doing both rewrites on the backend node at the cost of new
  cross-node VIP-knowledge coordination.

## References

- `bd show mayor-fhfro`, `bd show mayor-mma08` — prior work (datapath
  sketch, critical-review notes, live Lima kernel-7.0 eBPF-helper evidence)
  this doc supersedes for the dataplane mechanism, builds on for Service
  semantics.
- `docs/design/cni-svclb-landscape-2026-08-25.md` — CNI/ServiceLB landscape
  research this design builds on (target hardware, IP allocation model,
  loxilb disqualification).
- `bd show mayor-0gpqp` — the shell-script ServiceLB design this eBPF
  pipeline supersedes; closed as superseded 2026-09-01.
- `docs/decisions/flannel-for-cni.md`.
- `kubernetes-retired/blixt`, `dataplane/ebpf/src/{ingress,egress}/*.rs`,
  `dataplane/ebpf/src/main.rs` — fetched 2026-09-01, cached in
  `temp/research/blixt-*.rs` (not committed).
- `cilium/cilium`, `Documentation/network/kubernetes/kubeproxy-free.rst`
  (DSR, DSR-with-Geneve, DSR-with-IPIP sections) — fetched 2026-09-01,
  cached in `temp/research/cilium-kubeproxy-free.rst`; cited for the
  rejected DSR mechanism this doc no longer uses, not for the symmetric
  return path.
- `cloudnativelabs/kube-router`, `docs/dsr.md` — fetched 2026-09-01, cached
  in `temp/research/kube-router-dsr.md`; cited for the rejected
  VIP-on-loopback DSR mechanism.
- RFC 9000 §17.2 (Long Header Packets), §17.3.1 (1-RTT Packet) — fetched
  2026-09-01, cached in `temp/research/rfc9000.txt`.
- `draft-ietf-quic-load-balancers-21` — fetched 2026-09-01, cached in
  `temp/research/quic-lb-draft.txt`; cited as the future-upgrade path for
  CID encoding, not adopted for v1.
- `aya-rs/aya` README — fetched 2026-09-01, cached in
  `temp/research/aya-README.md`.
- `crates/scheduler/src/lib.rs`, `crates/kubeconfig` — existing
  `watch_stream`/`drain_watch_buffer` machinery this design reuses.

# u7s eBPF DSR dataplane

**Status:** Draft — Phase 1 design, for operator refinement
**Date:** 2026-09-01
**Bead:** mayor-2et9d (supersedes mayor-fhfro, mayor-mma08)

This dataplane IS u7s's `type=LoadBalancer` ServiceLB — there is no separate
klipper-lb-alike. A per-node eBPF pipeline matches VIP traffic, Geneve-encaps
it to whichever node holds a ready backend, and lets that backend node's own
kernel source the reply directly to the client as the VIP — satisfying
cross-node delivery, real client IP at L3, and disjoint subnets with no
shared L2 or BGP. **Recommend `aya`** as the toolchain: pure Rust, no libbpf
C dependency, matches the all-Rust workspace. The return-path crux is solved
by **eBPF egress-rewrite at the backend node**, not a VIP-on-loopback alias in
the pod netns — cheaper, and requires no CRI/netns privilege. The forward
path's cross-node hop is **tc-bpf + a real `geneve0 external` tunnel device**,
not raw XDP redirect, because u7s's actual nodes sit on a Tailscale WireGuard
mesh with one node behind NAT — XDP's redirect model assumes flat L2/L3
fabric reachability, which this topology does not have. Bottom-up footprint
estimate: **~4–7 MiB RSS at 1 vCPU** (the primary target hardware), corrected
from mayor-fhfro's non-summing table — still unverified on real hardware,
which is why footprint measurement is a named go/no-go gate below, not a
settled number.

## Scope carried over from prior work

`ai/findings/legacy/cni-svclb-landscape-2026-08-25.md` and
`ai/findings/2026-08-31-mayor-0gpqp-servicelb-design.md` already settled:
IP allocation is the node's-own-address model (no VIP pool — providers pin
one IPv6 prefix per instance); `externalTrafficPolicy` semantics; IPv6/dual
stack as a MUST; opt-in node-selector scoping. Those hold. What changes:
0gpqp's per-Service DaemonSet fan-out and iptables DNAT dataplane are
replaced entirely by this eBPF pipeline for the cross-node+real-IP path.
0gpqp's controller-placement analysis (embed vs. standalone) does not
transfer: this dataplane's state is per-node kernel memory (eBPF maps), which
a centralized apiserver-embedded controller cannot write into remotely — the
control plane here must run per node (see below), not centrally.

## Datapath & hooks

The pipeline has three attachment points, mapped to the mechanism required at
each rather than one hook type doing everything:

| Hook | Where | Why this hook, not another |
|---|---|---|
| tc-bpf ingress classifier | Physical uplink, every node | VIP match, backend hash, flow-affinity map, Geneve dispatch via `bpf_skb_set_tunnel_key` + redirect to a `geneve0 external` tunnel device. Needs skb context (`bpf_skb_set_tunnel_key` is not an XDP helper) so the kernel's own geneve driver — not our code — resolves the real egress path, which for a Tailscale-addressed backend node means transparently riding the existing WireGuard tunnel. Raw XDP redirect has no notion of "route through a WireGuard peer that also does NAT traversal"; it redirects a frame to a fixed ifindex with an L2 header we would have to construct ourselves, which does not work against a NAT'd peer. |
| XDP or TC ingress on `geneve0` | Backend node only | Decap, then a tiny local `vni_to_pod` lookup (this node's own scheduled pods only, <20 entries) rewrites dst from `VIP:port` to `PodIP:targetPort` — the actual DNAT step. The rewritten packet is now an ordinary pod-CIDR-destined packet, so it is handed to normal forwarding and rides flannel's existing pod-CIDR route for the last hop to the veth. No new last-hop delivery mechanism is built; flannel's is reused unmodified. |
| tc-bpf egress classifier | Physical uplink, every node that hosts DSR backends | Reply-as-VIP source rewrite — see Return path below. Egress rewrite of a locally-originated packet has no XDP equivalent; XDP has no egress hook at all. |

Packet flow, external client to backend Pod on a different node:

1. Client sends `CLIENT_IP:SRC_PORT → VIP:PORT`. Provider routing delivers it
   to whichever node the provider pins that address to (the "ingress node" —
   may or may not host a ready backend).
2. Ingress node's tc-bpf ingress program matches dst against the VIP map,
   consistent-hashes the flow to a ready backend `(node, pod IP, port)`
   triple, and records the choice in this node's own flow-affinity map (see
   Conntrack below) so re-hash on endpoint churn does not move an
   established flow.
3. It stamps tunnel metadata (remote = backend node's Tailscale IP, VNI = a
   fixed u7s-DSR constant, one Geneve option carrying the chosen pod's
   identifier) and redirects to `geneve0`. The kernel's geneve driver
   encapsulates and normal routing carries it over the mesh — **the inner
   packet is untouched**: `src=CLIENT_IP:SRC_PORT, dst=VIP:PORT`. Unlike
   Cilium's own DSR-Geneve mode, no service IP/port needs encoding in the
   tunnel metadata, because we never modify the inner packet — the backend
   node's decap step already has the real VIP:port from the inner header.
4. Backend node's `geneve0`-ingress program decapsulates, reads the pod
   identifier option, rewrites dst to `PodIP:TargetPort` (src stays
   `CLIENT_IP:SRC_PORT` — this is the real-client-IP guarantee), hands the
   packet to normal forwarding. Flannel's pod-CIDR route delivers it to the
   pod's veth. **The Pod sees the real external client IP at L3**, unmodified
   end to end.

## The return-path crux

**Mechanism: eBPF egress-rewrite at the backend node, not VIP-on-loopback.**
Two real designs exist:

- **VIP bound to a dummy/loopback interface inside the pod's own netns**
  (classic IPVS DSR; this is literally what kube-router's DSR mode does —
  it enters the pod's network namespace via the CRI socket and configures a
  `kube-dummy-if` carrying the external IP, per
  `kube-router/docs/dsr.md`). The app's own socket binds to the VIP, so the
  kernel sources replies as the VIP with no per-packet rewrite needed.
  **Rejected**: requires `hostPID`/`hostIPC`, a CRI socket mount, and
  entering every backend pod's netns on every scheduling change — an
  operational surface disproportionate to u7s's target scale and outside
  the CNI/CRI boundary this project otherwise respects.
- **eBPF rewrite of the reply's source address at the backend node's
  egress**, leaving the pod itself unaware of the VIP entirely. This is
  confirmed as Cilium's actual DSR mechanism, not a hand-wave: "the backend
  node is itself part of the service handling: it terminates the inbound
  [tunnel] traffic and rewrites the reply so that it is sourced from the
  service address and returned directly to the client"
  (`cilium/kubeproxy-free.rst`). **Recommended.** A tc-bpf egress classifier
  on the physical uplink matches the reply against the same
  flow-affinity/reverse-NAT entry the decap step populated
  (`PodIP:targetPort → VIP:port`, keyed by the client's 4-tuple), rewrites
  `src` from `PodIP:targetPort` to `VIP:port`, and lets normal routing send
  it to the client directly — no re-encap on the return leg.

**The load-bearing open risk this mechanism has**, which mayor-fhfro's
sketch never named: a node emitting a packet whose source address is *not*
one it was actually assigned (the VIP belongs to whichever node the provider
pins it to, not necessarily the backend node) can be silently dropped by the
emitting network's own anti-spoofing / uRPF filtering. Cilium's own docs
concede exactly this for DSR generally: "In some public cloud provider
environments that implement source/destination IP address checking (e.g.
AWS), the checking has to be disabled." Whether Linode's and Scaleway's
networks apply this to instance egress is **unverified** — this doc found no
citation either way. This is prototype gate (a) below, not an assumption.

**A second, harder constraint this design surfaces: the home-NAT node
cannot be a DSR backend for public VIPs at all.** Its own router performs
stateful NAT on all outbound traffic; a reply we've sourced as the VIP (an
address that is not the home connection's own WAN IP) would be re-mangled by
the home router before it ever reaches the internet, silently breaking the
rewrite regardless of anything done in-kernel on the node itself. Recommend
treating this as a hard **scheduling exclusion** — the home node must not be
selected as a DSR-backend-eligible node for externally-facing Services — not
just a caveat to test. This reuses the node-selector opt-in mechanism
`ai/findings/2026-08-31-mayor-0gpqp-servicelb-design.md` already proposed for
a different reason (unreachable-address filtering); the same knob now also
gates DSR-backend eligibility.

## Conntrack & affinity

Two flow-affinity maps, both `BPF_MAP_TYPE_LRU_PERCPU_HASH`, both custom
(not Linux's `nf_conntrack` — that subsystem is TC/skb-only and heavier than
this needs; blixt's own `LB_CONNECTIONS` map is likewise a hand-rolled hash
map, not `nf_conntrack`, despite prior notes describing its XDP→TC switch as
"for conntrack access" — the actual TC-only dependency in blixt's source is
`bpf_redirect_neigh`, an skb-context L2-neighbor-resolution helper, a
different mechanism than what this design needs). Per-CPU is the correct
map type for lock-free concurrent updates, but its cost multiplier is
**bounded by the node's actual vCPU count** — u7s's stated target hardware is
1 vCPU/1GB per node (`cni-svclb-landscape-2026-08-25.md`), so per-CPU
replication is nearly free there; size for the highest vCPU count actually
in the fleet, not a generic multi-core assumption.

- **TCP**: key = 4-tuple (13 bytes, `src_ip, dst_ip, src_port, dst_port,
  proto`), value = chosen backend + last-seen. 8192-entry ceiling.
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
| eBPF programs (tc ×2, XDP/TC decap ×1) | ~0 MiB (kernel-resident) | JIT'd native code, 5–50 KiB each; does not count against process RSS. |
| VIP map (<100 Services × ≤2 protocols) | ~25 KiB | <200 entries, small fixed struct. |
| Endpoint map (<1000 endpoints) | ~128 KiB | Backend triple per entry, hash overhead included. Every node carries the full map — any node can become an accidental ingress node for any VIP. |
| TCP flow-affinity map, per-CPU | ~0.5–1 MiB **at 1 vCPU** | 8192 entries × ~64B/entry-with-bucket-overhead × vCPU count. |
| QUIC CID flow-affinity map, per-CPU | ~0.25–0.5 MiB **at 1 vCPU** | 4096 entries, same overhead model. |
| `vni_to_pod` map (backend node, local only) | <5 KiB | <20 entries — this node's own scheduled pods. |
| **Total** | **~4–7 MiB at 1 vCPU** | Sum of the rows above. Scales roughly linearly with vCPU count for the two per-CPU rows on any node with more than 1 core. |

All four hash maps pre-allocate their full `max_entries` ceiling at creation
— this is exactly the mechanism behind loxilb's "cannot start on 1GB node"
failure. The ceilings above are chosen deliberately small for u7s's stated
envelope (<10 nodes/<100 Services/<1000 endpoints); this is not a number to
grow casually.

## Userspace control plane

Must run **per node**, not centrally: eBPF maps are local kernel memory with
no remote-write API, so a single apiserver-embedded controller (the shape
0gpqp recommended for DaemonSet lifecycle, a genuinely different problem)
cannot populate another node's maps. One DaemonSet replica per node,
`hostNetwork` + `CAP_BPF`/`CAP_NET_ADMIN` (no `hostPID`/`hostIPC`, no CRI
socket — an advantage of the egress-rewrite return path over kube-router's
netns-entry approach): load the tc-bpf/XDP programs once at start, watch
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

**kube-proxy**: XDP/tc-bpf on the physical NIC runs before netfilter/IPVS in
the RX path. The VIP map matches only `LoadBalancer`-Service external
IP:port pairs, never `ClusterIP`/`NodePort` ranges — non-matching traffic
falls through unmodified to kube-proxy's existing IPVS rules. DSR fully owns
the external-LB path end to end (including the backend-node last hop, which
bypasses kube-proxy via flannel's pod-CIDR route directly); kube-proxy
continues to own `ClusterIP`/`NodePort`, including in-cluster access to the
same Service's `ClusterIP` — no double-processing, no overlap.

**flannel** (`docs/decisions/flannel-for-cni.md`): the VIP address space is a
real externally-routable (or Tailscale-mesh) address, categorically outside
flannel's pod-CIDR and the cluster's Service-CIDR — no address-space
collision by construction. The DSR forward-path Geneve tunnel and flannel's
own vxlan overlay are separate encapsulations for separate traffic classes
(external ingress vs. pod-to-pod); a DSR-forwarded packet's outer header
targets the backend node's real address directly, never traversing
flannel's vxlan device. The only point of contact is the deliberate one
named above: DSR's decap step hands its DNAT'd packet to flannel's existing
pod-CIDR routing for the last hop, reusing it rather than duplicating it.

## Prototype gates — go/no-go before Phase 3

1. **Return-path works across real disjoint subnets.** Specifically: (a)
   Linode's and Scaleway's networks do not drop egress packets sourced as an
   address the emitting instance was not assigned (uRPF/anti-spoof —
   unverified in this doc); (b) the home-NAT node is excluded from
   DSR-backend eligibility per the constraint above, not relied on to work.
   Lima cannot validate this — it needs the real multi-provider topology.
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
- **Home-NAT node exclusion**: confirm excluding it from DSR-backend
  eligibility (not just ingress-list exposure, which 0gpqp already proposed
  for a different reason) is acceptable, given it removes that node as a
  valid scheduling target for any Pod backing an externally-facing Service.
- **uRPF/anti-spoof verification plan**: how to test gate 1(a) against real
  Linode/Scaleway instances before committing further build time — this
  needs an answer before a bounded prototype is worth starting.
- **Geneve option encoding for the backend-pod identifier**: a raw pod IP
  (4/16 bytes) is simplest; a compact backend-index (matching the endpoint
  map's own ordering) is smaller but adds a dependency on map-ordering
  staying consistent between the ingress and backend node's view — pick one
  before implementation.

## References

- `ai/findings/legacy/cni-svclb-landscape-2026-08-25.md`,
  `ai/findings/2026-08-31-mayor-0gpqp-servicelb-design.md`,
  `ai/findings/2026-09-01-mayor-fhfro-ebpf-dsr-feasibility.md` and its
  critical-review notes (`bd show mayor-fhfro`) — prior work this doc
  supersedes for the dataplane mechanism, builds on for Service semantics.
- `docs/decisions/flannel-for-cni.md`.
- `kubernetes-retired/blixt`, `dataplane/ebpf/src/{ingress,egress}/*.rs`,
  `dataplane/ebpf/src/main.rs` — fetched 2026-09-01, cached in
  `temp/research/blixt-*.rs` (not committed).
- `cilium/cilium`, `Documentation/network/kubernetes/kubeproxy-free.rst`
  (DSR, DSR-with-Geneve, DSR-with-IPIP sections) — fetched 2026-09-01,
  cached in `temp/research/cilium-kubeproxy-free.rst`.
- `cloudnativelabs/kube-router`, `docs/dsr.md` — fetched 2026-09-01, cached
  in `temp/research/kube-router-dsr.md`.
- RFC 9000 §17.2 (Long Header Packets), §17.3.1 (1-RTT Packet) — fetched
  2026-09-01, cached in `temp/research/rfc9000.txt`.
- `draft-ietf-quic-load-balancers-21` — fetched 2026-09-01, cached in
  `temp/research/quic-lb-draft.txt`; cited as the future-upgrade path for
  CID encoding, not adopted for v1.
- `aya-rs/aya` README — fetched 2026-09-01, cached in
  `temp/research/aya-README.md`.
- `crates/scheduler/src/lib.rs`, `crates/kubeconfig` — existing
  `watch_stream`/`drain_watch_buffer` machinery this design reuses.

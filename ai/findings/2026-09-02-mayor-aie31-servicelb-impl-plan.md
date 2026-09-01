Bead: mayor-aie31

# ServiceLB eBPF dataplane — implementation plan

Seven ordered phases, each a filed child bead of `mayor-aie31`, chained
linearly (each phase blocks the next): `mayor-g6u8s` (1) → `mayor-g7jh2`
(2) → `mayor-pa0ze` (3) → `mayor-lrbvo` (4) → `mayor-9gr0n` (5) →
`mayor-waqhd` (6) → `mayor-g9l0f` (7). Design is settled
(`docs/decisions/servicelb-ebpf-geneve-dataplane.md`,
`servicelb-symmetric-geneve-return.md`, `ebpf-toolchain-aya.md`, PR
#1502) and mechanism detail lives in
`ai/extended-context/ebpf-lb-dataplane.md`; this doc sequences
implementation, it does not re-argue the design.

Linear chaining, not a DAG with parallel branches, because each phase's
mechanism is a genuine prerequisite for the next: no packets to conntrack
before Geneve encap/decap exists, no controller worth building before the
go/no-go gate clears, no coexistence to verify before a controller-driven
system exists, no conformance run to gate before coexistence is proven.

## Phase 1 — aya skeleton + build/load wiring (`mayor-g6u8s`)

**Delivers**: the aya toolchain stood up in this workspace per
`ebpf-toolchain-aya.md` (bpf-linker, the standard aya two-crate split — a
`no_std` eBPF-program crate plus a userspace loader crate/binary), with
CI wiring so the eBPF object builds reproducibly. Four no-op tc-bpf
(clsact) programs attach at the hook points `ebpf-lb-dataplane.md` names
(physical-uplink ingress; `geneve0` ingress on the backend leg;
physical-uplink egress on the backend leg; `geneve0` ingress on the
ingress-node return leg), pinned under `/sys/fs/bpf`. Also lands the
memory-observability tooling `ebpf-toolchain-aya.md` calls out as
mandatory groundwork, not optional instrumentation added later:
userspace RSS via normal OS tooling, and a documented `bpftool map
dump`/`show` path for real (not ceiling) map memory.

**Depends on**: nothing (first phase). **Blocks**: Phase 2.

**Risk/size**: MEDIUM risk, SMALL-MEDIUM size. The real risk is
`ebpf-toolchain-aya.md`'s own named trade-off — `bpf-linker`'s relative
immaturity against clang's. If even a no-op program shape is rejected by
the linker or verifier, that is a toolchain-level blocker for the whole
epic, not a Phase-1-only problem.

**Verification**: `cargo build` for the eBPF target in CI. Manual
load/attach/pin on a single-node Lima VM confirming all four hooks attach
and pinned programs survive a userspace process restart.

## Phase 2 — Geneve encap/decap, single-flow happy path (`mayor-g7jh2`)

**Delivers**: the full packet-flow mechanism in `ebpf-lb-dataplane.md`'s
"Packet flow" section, for one static VIP-to-backend mapping (test
fixture, not real Service/EndpointSlice data — that is Phase 5).
Forward: ingress classifier matches VIP:PORT, stamps Geneve metadata via
`bpf_skb_set_tunnel_key`, redirects to `geneve0`; backend decaps, reads
`VIP_IP:VIP_PORT` off the untouched inner dst *before* rewriting
anything, DNATs to `PodIP:TargetPort`, forwards via flannel's routing —
the Pod sees the real client IP at L3. Return (symmetric, per
`servicelb-symmetric-geneve-return.md`, explicitly not DSR): backend's
egress classifier Geneve-encaps the reply back to the ingress node,
echoing the captured VIP; ingress decaps, un-DNATs, routes to the client
sourced as an address it actually owns. Naive single-entry flow state is
acceptable here; collision-proofing is Phase 3's job.

**Depends on**: Phase 1 (needs the loadable skeleton to attach packet
mutation to). **Blocks**: Phase 3 (conntrack keying only matters once
real packets flow this path).

**Risk/size**: HIGH risk, LARGE size. This is the core novel mechanism
the epic exists to prove — Geneve option stamping and the
capture-before-rewrite decap/DNAT ordering are both unproven in this
codebase.

**Verification**: 2-node Lima VM topology (enough to prove a real
cross-node hop; the real disjoint-subnet/NAT gate is Phase 4, not here).
`tcpdump` on `geneve0` on both nodes confirming inner-packet integrity
and correct rewrite ordering across one full request/reply round trip.

## Phase 3 — conntrack full-tuple keying + open-question resolution (`mayor-pa0ze`)

**Delivers**: hardens Phase 2 into the real conntrack model —
`BPF_MAP_TYPE_LRU_PERCPU_HASH`, one map per protocol, forward key
`(CLIENT_IP, SRC_PORT, VIP_IP, VIP_PORT, proto)` (a client-only key
collides across two concurrent connections from the same local port to
different VIPs on the same ingress node), sized per
`ebpf-lb-dataplane.md`'s table (TCP: 37-byte IPv6-primary key, 8192-entry
ceiling; QUIC: fixed-length DCID-prefix key, 4096-entry ceiling). The
key-encode/decode logic is extracted into plain Rust functions, not left
embedded only in the eBPF program, so it is unit-testable outside a
kernel. This phase also **resolves** three mechanism-doc open questions
before it closes (documented in the bead's close note, not left
implicit): the Geneve option wire encoding (pod-identifier and VIP-echo
format), VIP↔PodIP NAT placement (backend-DNAT/ingress-un-DNAT vs
both-on-backend), and the backend reverse-flow key's cross-flow
uniqueness gap.

**Depends on**: Phase 2. **Blocks**: Phase 4 (the go/no-go RSS
measurement needs real, not single-entry, map sizing).

**Risk/size**: MEDIUM-HIGH risk, MEDIUM size. Collision-proofing and
per-CPU LRU eviction under churn is exactly the failure class
`ebpf-toolchain-aya.md`'s verifier-maturity caveat points at.

**Verification**: unit tests for the extracted key functions, including
the two-Services-sharing-one-backend-Pod collision case as an explicit
test. 2-node Lima load test with concurrent/churning connections
checking for verifier rejection and flow-affinity survival under LRU
eviction pressure.

## Phase 4 — prototype go/no-go gates (`mayor-lrbvo`)

**Delivers**: no new mechanism — runs the three go/no-go checks
`ebpf-lb-dataplane.md` names explicitly: (1) the return path works
cross-node on **real** disjoint subnets (Linode + Scaleway + a home-NAT
node over Tailscale/WireGuard) — Lima alone cannot validate this, since
none of the disjoint-subnet/NAT conditions the design exists to handle
occur on a single-VM L2; (2) measured RSS on a real 1GB/1vCPU node, not
the ~4–7 MiB estimate — pre-allocated maps can hide a floor until run
(the loxilb precedent in `cni-svclb-landscape.md`); (3) userspace RSS and
kernel map memory both continuously monitorable in practice, using
Phase 1's tooling.

**Depends on**: Phase 3. **Blocks**: Phase 5 — do not invest in the full
controller ahead of this gate; a failure here can send the design back to
Phase 2 or 3.

**Risk/size**: HIGH risk (this is the actual go/no-go point for the
epic), SMALL size (measurement, not new code) — but see the open
question below on real-fleet access, which is an operational dependency
this bead cannot resolve on its own.

**Verification**: live measurement only — `bpftool map dump`/`show` and
OS-level RSS on each real node class, and an actual
client→VIP→cross-node-backend→client round trip captured end to end.

## Phase 5 — userspace controller (`mayor-9gr0n`)

**Delivers**: the per-node control plane from `ebpf-lb-dataplane.md`'s
"Userspace control plane" section — one DaemonSet per node, `hostNetwork`
+ `CAP_BPF`/`CAP_NET_ADMIN`, no CRI socket. Loads and pins the Phase 1–3
programs once, watches `Service` (`type=LoadBalancer`) and
`EndpointSlice` via u7s's existing watch machinery (reused, not
reimplemented), writes the VIP map / endpoint map / backend-local
`vni_to_pod` map on change, then idles — no persistent proxy loop, kernel
does the forwarding (mirrors klipper-lb's memory discipline). The
Service/EndpointSlice-diff-to-map-entries logic is extracted as a pure
function, separate from the async watch plumbing, so it is directly
unit-testable.

**Depends on**: Phase 4 passing. **Blocks**: Phase 6 (coexistence needs a
controller-driven system with real Service objects, not Phase 2's static
fixture).

**Risk/size**: MEDIUM risk, MEDIUM-LARGE size. Lower mechanism risk than
Phases 2–3 (reuses existing watch code), but wrong map population is a
silent-wrong-routing failure mode, not a crash.

**Verification**: unit tests for the pure reconcile function (fixture
Service/EndpointSlice diffs in, expected map-entry diffs out, including
multi-EndpointSlice-per-Service). Lima integration test: create/update/
delete a real `type=LoadBalancer` Service, confirm map contents via
`bpftool map dump`.

## Phase 6 — kube-proxy/flannel coexistence verification (`mayor-waqhd`)

**Delivers**: live proof of the consequence
`servicelb-ebpf-geneve-dataplane.md` states but does not itself verify —
kube-proxy stays untouched for east-west ClusterIP/NodePort traffic, this
dataplane owns north-south LoadBalancer traffic only, no double
processing, no flannel address-space collision (VIP range outside
pod-CIDR/Service-CIDR, `geneve0` never touching flannel's vxlan device
except at the one legitimate decap-then-flannel-routes-last-hop contact
point).

**Depends on**: Phase 5. **Blocks**: Phase 7.

**Risk/size**: MEDIUM risk, SMALL-MEDIUM size — an integration-
verification phase; its failure mode is a regression in *existing*
east-west behavior the conformance suite already gates, raising the cost
of a miss.

**Verification**: Lima cluster running flannel + kube-proxy + this
dataplane together; existing ClusterIP/NodePort e2e-focus coverage
unaffected while a `type=LoadBalancer` Service concurrently exercises the
new path.

## Phase 7 — e2e/conformance gating (`mayor-g9l0f`)

**Delivers**: picks and wires the sonobuoy specs that actually prove
north-south LB + real-client-IP for u7s's own ServiceLB. Not a resolved
question going in — many upstream `sig-network` LoadBalancer specs
(e.g. the ESIPP external-source-IP-preservation family) are
cloud-provider-gated/skipped by default without a recognized `--provider`
signal, since upstream assumes a real cloud LB controller; picking which
specs apply and what (if anything) needs to change to un-skip them is
this phase's first task.

**Depends on**: Phase 6. **Blocks**: nothing (last phase).

**Risk/size**: MEDIUM risk, SMALL-MEDIUM size — mostly test wiring/
focus-list curation once spec selection is decided, not new dataplane
code. Priority: P3, lower than Phases 1–6 (P2) — verification/gating
polish once the mechanism is proven live in Phases 4 and 6, not
correctness-critical dataplane work itself.

**Verification**: the chosen specs pass against a real (or Lima, if
sufficient) cluster running the full stack from Phases 1–6, added to the
tracked e2e-focus list so regressions are caught going forward.

## Open questions the ADRs leave unresolved

These are for operator/mayor review — not resolved in this plan or by
this pass:

- **Real-fleet access for Phase 4's gate 1.** `ebpf-lb-dataplane.md` is
  explicit that Lima cannot substitute for a real disjoint-subnet +
  NAT'd-node topology. Who provisions time on the operator's actual
  Linode/Scaleway/home-NAT fleet for this gate, and on what timeline, is
  an operational open question, not a design one — and Phase 5 is
  explicitly blocked on this gate clearing.
- **Which sonobuoy/conformance specs actually gate Phase 7.** Not
  enumerated by any of the three ADRs or the mechanism doc; deferred to
  Phase 7 itself by design, flagged here so it is not silently decided
  mid-implementation without visibility.
- **Traefik's fixed-length QUIC CID support** — a hard precondition for
  the Phase 3 QUIC conntrack design (`ebpf-lb-dataplane.md`'s "Open
  questions"), not yet verified against real Traefik behavior.
- **Node-selection scoping, IPv6/dual-stack timing, and SCTP for v1** —
  all flagged as open by the Service-level semantics bead (`mayor-0gpqp`)
  that these ADRs explicitly carry over unchanged; none of the three
  settled ADRs revisit them, so they remain open regardless of this
  epic's dataplane work.

## References

`docs/decisions/servicelb-ebpf-geneve-dataplane.md`,
`servicelb-symmetric-geneve-return.md`, `ebpf-toolchain-aya.md`;
`ai/extended-context/ebpf-lb-dataplane.md`,
`ai/extended-context/cni-svclb-landscape.md`; `bd show mayor-aie31`
(epic), `mayor-0gpqp`/`mayor-2et9d`/`mayor-fhfro`/`mayor-mma08` (closed
design-phase predecessors).

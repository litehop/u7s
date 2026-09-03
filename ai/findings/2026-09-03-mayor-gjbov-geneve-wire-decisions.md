# Geneve wire-format decision brief (mayor-gjbov)

Date: 2026-09-03
Bead: mayor-gjbov (decision-prep for `mayor-aie31` Phase 3, `mayor-pa0ze`)

**Correction (2026-09-03):** decisions 1 and 3 below were revised after
verifying upstream Kubernetes source directly — see "Research addendum"
near the end. Decision 2 was checked against real-dataplane precedent and
stands unchanged.

## Recommendation summary

1. **Option encoding**: raw pod IP for the pod identifier. Raw
   `VIP_IP:VIP_PORT` for the VIP echo is **mandatory**, not optional —
   decision 3 depends on it being correct and unambiguous, not merely on
   it being debuggable. Compact alternatives for either sub-choice buy a
   few bytes at the cost of new cross-node state or a second collision
   surface; neither is worth it. Not settled by any ADR.
2. **NAT placement**: keep DNAT-on-backend + un-DNAT-on-ingress — it is
   already the mechanism doc's literal Packet-flow narrative and what
   `mayor-g7jh2` (Phase 2) is written against, so this decision actually
   gates Phase 2, not Phase 3 as currently framed. Not settled by the
   symmetric-return ADR (that ADR fixes the *route*, not which node does
   the rewrite). Unchanged by this correction.
3. **Backend key uniqueness — CORRECTED.** Upstream Kubernetes places no
   restriction on two `type=LoadBalancer` Services routing to the same
   backend Pod + targetPort (`ValidateServiceCreate`,
   `validation.go:7033-7045`, verified against `release-1.36` — see
   addendum). The prior recommendation — reject this at admission — would
   have made u7s non-conformant. Corrected recommendation: **accept the
   overlap; keep the map's key/value split as already designed.** The
   backend's reverse-flow key, `(CLIENT_IP, SRC_PORT, PodIP, TargetPort,
   proto)`, already contains no VIP — it's symmetric, buildable from
   either the forward packet or the reply's own reverse tuple — and the
   VIP is the stored *value* under it, captured once at write time (step
   4, off the still-untouched forward-leg inner destination, before any
   rewrite). The Pod's raw reply never carries the VIP (unchanged from the
   original brief); on return the backend rebuilds the same key from the
   reply's own tuple, reads the VIP back out of the *value*, and stamps it
   into the **outer** Geneve header for the hop to the ingress node (step
   6) — the VIP re-enters the wire from stored state, never from the Pod.
   Per decision 2, un-DNAT itself happens at the **ingress** node, not the
   backend — gjbov is not Cilium-style DSR. The doc's own proposed
   variant — folding the VIP *into* the key — is what's rejected: a
   VIP-bearing key can't be rebuilt from a reply that carries no VIP. Left
   **open** (Rule 12, not asserted either way): whether the existing
   VIP-less key can actually collide under multi-LB-same-Pod at all — see
   addendum. Gates Phase 3 (`mayor-pa0ze`) as intended.

Decision 3 is genuinely locked into Phase 3's scope as framed. Decision 2
needs settling before Phase 2 starts, not before Phase 3 closes. Decision
1's VIP-echo sub-choice is now load-bearing for decision 3's correctness,
not an independent debuggability call.

---

## Decision 1 — Geneve option wire encoding

**Question** (`ai/extended-context/ebpf-lb-dataplane.md:136-140`): two
independent sub-choices — (a) pod identifier: raw pod IP vs. a compact
backend-index; (b) VIP echo: raw `VIP_IP:VIP_PORT` vs. a compact flow-id
minted by the ingress.

**Options — (a) pod identifier**

| | Raw pod IP | Compact backend-index |
|---|---|---|
| Wire size | 4B (v4) / 16B (v6) | 1-2B |
| Map/parse complexity | None — backend rewrites dst directly from the option | Requires an *ordered* table shared in meaning between the ingress that picks the index and every backend node's local table (the doc's own `vni_to_pod` map, `ebpf-lb-dataplane.md:106`) |
| Correctness/collision risk | Self-describing, no synchronization needed | Real risk: EndpointSlice churn must update every node's ordered table in lockstep, or ingress can stamp an index a backend hasn't rebound yet → traffic to the wrong/stale pod |
| Debuggability | `tcpdump` shows the literal pod IP | Opaque integer; needs a live control-plane table to resolve, at the exact moment you're debugging a possibly-broken control plane |
| Perf/memory | Negligible either way (`<5 KiB`/`<20 entries`, `ebpf-lb-dataplane.md:106`) | same |

**Options — (b) VIP echo**

| | Raw `VIP_IP:VIP_PORT` | Compact flow-id |
|---|---|---|
| Wire size | 6B (v4) / 18B (v6, `geneve_dsr_opt6`-shaped) | ~4B |
| Map/parse complexity | None new — backend already captures+stores this exact value in its reverse-flow entry (`ebpf-lb-dataplane.md:48-50`) before DNATing; echoing it back is a copy | New id-allocation space on the ingress, looked up by id on both ends — a second collision surface layered on top of decision 3's |
| Correctness | Ingress already keys its own forward-flow map on `VIP_IP:VIP_PORT` (`ebpf-lb-dataplane.md:44-45,69`), so no new state is introduced | id reuse across churn is the same failure class as decision 3, just relocated |
| Debuggability | VIP is readable straight off a captured packet | Opaque id; unrecoverable post-hoc once the minting table entry is gone |
| Perf/memory | Negligible (`Total ~4-7 MiB`, `ebpf-lb-dataplane.md:107`, treats byte-level option cost as noise) | same |

**Precedent.** Cilium's own Geneve return-path option (`DSR_GENEVE_OPT_CLASS
0x014B`, `struct geneve_dsr_opt4/6` — fetched to
`temp/research/cilium-tunnel.h:56-78`, upstream
`cilium/cilium:bpf/lib/tunnel.h`) carries the raw service address and port,
not a compact id, for exactly this use case (Geneve-borne LB return
metadata). Cilium *does* overload its VNI field to carry a compact 24-bit
security identity elsewhere (`tunnel_vni_to_sec_identity`,
`cilium-tunnel.h:109-117`), but that is a different problem (security
identity of the source endpoint for policy), not backend selection, so it
is not precedent for the backend-index sub-choice.

**What the docs lean toward.** Mechanism doc frames both as genuinely
undecided, listing compact-as-desirable-if-cheap ("smaller, couples nodes'
map-ordering" / "smaller, format-agnostic",
`ebpf-lb-dataplane.md:137-139`) but does not pick. No ADR touches wire
encoding at all.

**Recommendation.** Raw encoding for both (a) and (b) — and for (b), this
is now a **correctness requirement, not a preference.** Decision 3
(corrected below) depends on the ingress node being able to recover the
right VIP for a reply that itself carries no VIP; some reliable channel
from decision 3's per-flow capture back to the ingress node's un-DNAT step
is load-bearing, and raw `VIP_IP:VIP_PORT` is the only one of the two
options that doesn't introduce its own id-collision surface on top of the
one decision 3 is already managing. Beyond that, the project's own memory
table already treats sub-20-byte option overhead as noise against total
packet cost (`ebpf-lb-dataplane.md:98-107`), so the compact options' only
real benefit evaporates, while their cost — new cross-node ordering
coordination for (a), a second id-collision surface for (b) — is exactly
the class of correctness risk this brief exists to avoid building into an
unproven mechanism (Phase 2 is flagged HIGH risk, "unproven in this
codebase", `bd show mayor-g7jh2`). Debuggability matters disproportionately
right now because the mechanism itself is unproven.

**Open item (not settled here):** whether an explicit backend→ingress
Geneve echo is even the right mechanism, versus the ingress node
recovering the VIP purely from its own step-2 flow-affinity state keyed
against the reply's natural reverse tuple, is a Phase-3 design question —
see "Open verification items" below. This recommendation covers the
*encoding* if a wire echo is used; it does not settle whether one is
strictly necessary.

**Gates:** Phase 3 (`mayor-pa0ze`) as framed by the epic.

**Reversibility:** Locked into the wire format once both an ingress node's
encap program and a backend node's decap program are compiled against a
chosen option layout — every node must agree simultaneously (no rolling
mixed-version tolerance is described anywhere in the mechanism doc).
Cheap to change today, a flag-day after Phase 3 ships.

## Decision 2 — VIP↔PodIP NAT placement

**Question** (`ebpf-lb-dataplane.md:141-144`): DNAT-on-backend (step 4) +
un-DNAT-on-ingress (step 7) — the mechanism doc's own Packet-flow
narrative — vs. both-on-backend, where the backend also performs the
un-DNAT before Geneve-encapping the reply, requiring it to know the
ingress's owned VIP.

**Options**

| | DNAT-backend + un-DNAT-ingress (current narrative) | Both-on-backend |
|---|---|---|
| Wire/map complexity | Needs decision 1(b)'s VIP-echo option so the ingress can recover the VIP at step 7 | Needs *no* VIP-echo option at all — the backend already stores the captured VIP in its own reverse-flow entry (`ebpf-lb-dataplane.md:49-50`), so it can un-DNAT locally before encapping; ingress return-leg becomes a bare decap-and-route with no lookup |
| Correctness | Both nodes already independently hold the VIP value (ingress from its own step-2 write, backend from its step-4 capture) — no new data needed either way | same — the two options are a wash on *what data exists*, they only move *which classifier program does the rewrite* |
| ADR interaction | Matches `servicelb-symmetric-geneve-return.md` literally as narrated | Does **not** violate that ADR — the ADR fixes the *route* (reply always transits the ingress node) and forbids the backend from *sourcing* a packet as the VIP at the outer/underlay hop; it says nothing about which node performs the inner-packet NAT rewrite before the (backend-owned) Geneve outer header carries it to the ingress. Easy to conflate; worth calling out so the operator doesn't assume this ADR already settles it. |
| Blast radius if chosen | None — already what Phase 2's bead text describes step-by-step (`bd show mayor-g7jh2`: "Ingress decaps... rewrites src to the recovered VIP") | Requires rewriting Phase 2's already-approved plan text and mechanism doc's Packet-flow section, not just Phase 3's |

**What the docs lean toward.** The mechanism doc's Packet-flow section
(`ebpf-lb-dataplane.md:42-60`) already narrates DNAT-on-backend +
un-DNAT-on-ingress as *the* mechanism, not one of two options — the "open
question" framing at line 141-144 undersells how committed this already
is in practice.

**Recommendation.** Keep the current placement (DNAT-backend +
un-DNAT-ingress). Rationale: it is what `mayor-g7jh2` is already written
to implement; switching now means rewriting Phase 2's plan before Phase 2
even starts, for a change that (per the trade-off table) is a wash on
correctness and only trades one wire option for one map lookup. Revisit
only if Phase 3/4 prototype data shows the VIP-echo option (decision 1b)
is itself a problem — record that as a documented revisit trigger, mirroring
the pattern `ebpf-toolchain-aya.md:38-41` already uses for the toolchain
choice. **Unchanged by this doc's research addendum** — kube-proxy's
un-DNAT likewise happens at the node that owns the VIP's conntrack (never
at the backend), so real precedent reinforces this placement rather than
challenging it; see addendum.

**Gates:** Phase 2 (`mayor-g7jh2`), **not** Phase 3 as the epic currently
frames it — flag this explicitly to the operator, since `mayor-pa0ze`'s
bead text lists it as a Phase-3 gate but Phase 2's own bead text already
bakes in the answer.

**Reversibility:** Locked once Phase 2's two classifier programs
(backend egress, ingress return-decap) are deployed with mirror-image
responsibilities — changing placement afterward is a coordinated
redeploy of both nodes' program logic. Cheap now (a plan-text edit only).

## Decision 3 — Backend reverse-flow key uniqueness

**Question** (`ebpf-lb-dataplane.md:145-149`): is `(CLIENT_IP, SRC_PORT,
PodIP, TargetPort, proto)` unique across concurrent flows sharing one
backend Pod at the same targetPort? Two LB Services (different VIPs)
routing to the same Pod:TargetPort, hit by a client that reuses one
ephemeral src port for both, produce an identical backend key.

**Key vs. value — the distinction the original framing blurred.** The
backend's reverse-flow key, `(CLIENT_IP, SRC_PORT, PodIP, TargetPort,
proto)`, already contains no VIP. It's symmetric: the forward packet
carries `src=CLIENT_IP:SRC_PORT, dst=PodIP:TargetPort` and the reply
carries the same pair swapped, so the identical key is buildable from
either direction without ever touching the VIP. The VIP is the *value*
stored under that key, captured once at write time (step 4, off the
still-untouched forward-leg inner destination, before any rewrite) — this
is the same key/value split kube-proxy's own conntrack-based un-DNAT
relies on. On return, the backend rebuilds the key from the reply's own
tuple, reads the VIP back out of the value, and stamps it into the
**outer** Geneve header for the hop to the ingress node (step 6): the VIP
re-enters the wire from stored state, never from the Pod, whose raw reply
carries no VIP either way. Per decision 2, actual un-DNAT happens at the
**ingress** node using that value once echoed (step 6-7) — not at the
backend; gjbov is not Cilium-style DSR, where the backend sources its own
reply directly to the client.

**Why the doc's own proposed variant doesn't hold up.** The mechanism
doc's open question (`ebpf-lb-dataplane.md:148-149`, restated in `bd show
mayor-pa0ze`) proposes folding the VIP *into* the key too. That's the one
part of this design that's a genuine dead end: a VIP-bearing key can't be
rebuilt from a reply that carries no VIP at all
(`ebpf-lb-dataplane.md:54-56`: "same pair, read in reverse — nothing
rewrote either side here"). Widening the *write* key doesn't help the
*read* side; it only stops one connection's value from silently
overwriting another's in a shared slot, which presupposes the collision
this brief has not established is real (see open item below). Worth
flagging so Phase 3 doesn't spend effort implementing it before hitting
this wall itself.

**Open question the mechanism doc's proposal implies but never states
(Rule 12 — flagged, not resolved here):** does the existing VIP-less key
actually collide under multi-LB-same-Pod? One client socket is one
connection to one remote VIP; two different VIPs from the same client
reaching the same backend Pod:TargetPort would need the client to reuse
one local port across both — allowed by the client's own kernel (remotes
differ), but then, for TCP, the Pod's own kernel TCP stack already
forbids two *live* connections at an identical `(local=PodIP:TargetPort,
remote=CLIENT_IP:SRC_PORT)` 4-tuple, rejecting the second SYN outright.
Whether a narrower window remains — e.g. a stale, not-yet-evicted entry
from a torn-down connection being misattributed to a later, sequential
reuse of the same client port against a different VIP — is not
established either way in this pass; it may be a real residual risk, or
the mechanism doc's key-folding instinct may have been over-cautious
about a collision that cannot actually occur. See research addendum;
resolve in Phase 3, not by assumption here. UDP/QUIC sidesteps this
question by construction — QUIC already uses DCID-keyed matching
(`ebpf-lb-dataplane.md:90-96`), not a client-tuple key.

**Options — CORRECTED.** Admission-time prevention is no longer a valid
option regardless of how the open question above resolves: upstream
Kubernetes allows two `type=LoadBalancer` Services to route to the same
backend Pod + targetPort with no cross-Service selector check
(`ValidateServiceCreate`, `validation.go:7033-7045`, `release-1.36` — see
research addendum), so rejecting it would make u7s non-conformant.

| | Fold VIP into key | Admission-time prevention (REJECTED — non-conformant) | Accept overlap; keep the existing VIP-less key / VIP-value split |
|---|---|---|---|
| Wire/map complexity | Dead end (see above) | None, but not viable | None new — already the mechanism doc's step-4 capture + step-6 echo; decision 1 only makes the echo's encoding mandatory-raw |
| Conformance | N/A | Blocks a legal upstream configuration | Conformant — no restriction added |
| Correctness | Does not fix the read side | Would be correct by construction, but for a scenario u7s has no right to forbid | Depends on the open question above — not yet established either way |
| Debuggability | N/A (doesn't work) | N/A | If a residual window is confirmed in Phase 3, straightforward to add a metric for it; nothing to build until confirmed |
| User-facing cost | — | Breaks a legal pattern (different Services, same Pod) | None — no new restriction on Service authors |
| Reversibility | — | — | Pure dataplane/observability detail; tightenable later without an API change |

**What the docs lean toward.** Mechanism doc proposes the key-folding
variant as the presumed answer (`ebpf-lb-dataplane.md:148-149`) without
checking it against what the return packet actually carries, and without
stating what collision it's guarding against; `mayor-pa0ze`'s bead text
repeats it verbatim as "likely fix." Neither the mechanism doc nor either
ADR checked the scenario against upstream's own validation code.

**Recommendation — FLIPPED.** Accept the overlap; do not add
admission-time rejection; keep the reverse-flow map's existing key/value
split as designed — it needs no eBPF-side change for this decision.
Decision 1 making the VIP-echo encoding mandatory-raw (not compact) is
what keeps the value's round trip reliable. Do not spend Phase 3 effort
on the key-fold, which the reply's own contents make structurally
unworkable regardless of whether a real collision exists. Before closing
this out, Phase 3 should resolve the open question above — whether the
existing key can collide at all — rather than carrying it forward
unresolved into implementation.

**Gates:** Phase 3 (`mayor-pa0ze`) — this is exactly the decision that
bead was filed to resolve, with the corrected verdict plus one item still
open (see addendum).

**Reversibility:** This is now a dataplane-behavior commitment, not a
control-plane admission policy — it locks in once Phase 3 ships decision
1's mandatory raw echo and the existing reverse-flow capture. Whatever the
open question resolves to, any resulting mitigation (e.g. a metric or TTL
tuning) remains freely adjustable afterward without a wire change.

## Already-settled question, for the record

None of the three decisions is fully settled by an existing ADR. The
closest near-miss is decision 2: `servicelb-symmetric-geneve-return.md`
settles the *return route* (always via the ingress node, never DSR) but
explicitly does not decide which node performs the NAT rewrite — flagged
above so it isn't mistaken for already-closed.

## Open follow-on for the operator

Decision 2's framing correction (it gates Phase 2, not Phase 3) means the
operator should settle it *before* `mayor-g7jh2` starts, not batch it with
the other two at Phase 3's gate — otherwise Phase 2 risks shipping against
an assumption Phase 3 later reopens.

## Research addendum — correction to decisions 1 and 3 (2026-09-03)

**Load-bearing fact, verified against upstream source.** Kubernetes places
no restriction on multiple `type=LoadBalancer` Services selecting the same
backend Pod, including at the identical `targetPort`.
`ValidateServiceCreate` (`pkg/apis/core/validation/validation.go:7033-7045`
in `release-1.36`, confirmed by direct fetch) calls
`validateService(service, nil)` — a function whose signature
(`validateService(service, oldService *core.Service)`) only ever compares
a Service to itself or its own prior version, never to any other Service
in the cluster; there is no lister/indexer of other Services anywhere in
the path. The endpoints controller confirms the same absence at the
control loop: `Controller.syncService`
(`pkg/controller/endpoint/endpoints_controller.go:348`) lists Pods per
Service via `labels.Set(service.Spec.Selector).AsSelectorPreValidated()`
(line 392), independently for each Service key, with no cross-Service
selector-overlap check anywhere in the sync path. This is why decision 3's
prior "reject at admission" recommendation was wrong: it would have
rejected a configuration upstream explicitly permits.

**Real-dataplane precedent.** Cited only for how each system carries the
VIP across the round trip — not as precedent for *where* the un-DNAT
happens. Cilium's Direct Server Return (backend replies straight to the
client) is a different topology from gjbov's decision 2 (reply always
transits the ingress node); it is not evidence for or against decision 2.

| Implementation | VIP-carry mechanism | Where the reply is re-sourced as the VIP |
|---|---|---|
| Cilium (eBPF + Geneve DSR) | Raw service address+port in a Geneve option (`geneve_dsr_opt4`/`geneve_dsr_opt6`, `bpf/lib/tunnel.h`) — precedent for decision 1's raw-not-compact encoding | The **backend**, directly to the client (DSR) — not gjbov's model; decision 2 keeps this at the ingress node instead |
| kube-proxy (iptables/IPVS) | Per-Service conntrack entry, created on the node that performs the DNAT | The **same node that DNAT'd**, via conntrack un-DNAT on the return leg — the precedent decision 2 actually matches |
| MetalLB | Announces the VIP (BGP/ARP); delegates all Service NAT to kube-proxy | Inherits kube-proxy's placement; adds nothing at the NAT layer |

Sources: kubernetes.io/docs/reference/networking/virtual-ips/;
blog.stonegarden.dev/articles/2026/02/cilium-dsr/;
cilium.io/use-cases/load-balancer/; Kubernetes `release-1.36`
`pkg/apis/core/validation/validation.go` and
`pkg/controller/endpoint/endpoints_controller.go`;
metallb.universe.tf/usage/. All five URLs verified resolving (HTTP 200) on
2026-09-03.

**Open verification items for Phase 3 — not settled by this brief:**

- Whether the existing VIP-less reverse-flow key `(CLIENT_IP, SRC_PORT,
  PodIP, TargetPort, proto)` can actually collide under multi-LB-same-Pod
  at all (see Decision 3 above for the reasoning either way). The
  mechanism doc's "fold VIP into key" proposal implies it believed a
  collision exists; this brief could not construct one that survives the
  Pod's own TCP-4-tuple uniqueness, but also cannot rule one out. Confirm
  before Phase 3 implementation, rather than building a mitigation for an
  unconfirmed risk or skipping one that's needed.
- Whether decision 1's backend→ingress Geneve VIP echo is strictly
  necessary at all, given the ingress node already writes its own
  flow-affinity entry at step 2 (keyed on `CLIENT_IP, SRC_PORT, VIP_IP,
  VIP_PORT`). If that entry were also indexed by the chosen backend's
  `PodIP:TargetPort`, the ingress could in principle recover the VIP
  purely from the reply's own natural reverse tuple, with no wire signal
  from the backend at all. Whether the echo is instead needed for
  backend→ingress-node attribution or return-tunnel routing (e.g. in a
  multi-ingress topology) is unresolved here — the load-bearing
  requirement (VIP recoverable on return, never derived from the raw
  reply) holds regardless of how this resolves, but the exact mechanism
  and wire necessity is a Phase-3 design question, not a settled claim.
- Cilium's exact reverse-lookup code path for Geneve-DSR when one backend
  Pod serves multiple VIPs was not fully traced in this pass —
  `ct_lazy_lookup4(SCOPE_REVERSE)` / `lb4_lookup_rev_nat_entry` were the
  entry points found, but map population for the Geneve-DSR case
  specifically was not confirmed. Lower priority given Cilium's DSR
  topology differs from gjbov's (see table above).
- Whether the reverse-flow map structure already sketched in
  `ai/extended-context/ebpf-lb-dataplane.md` actually satisfies the
  now-load-bearing VIP-capture requirement (captures the correct VIP at
  write time, per flow, before any possible key collision) needs to be
  checked as part of Phase 3 design, not assumed from this brief.

## References

`ai/extended-context/ebpf-lb-dataplane.md`;
`docs/decisions/servicelb-ebpf-geneve-dataplane.md`;
`docs/decisions/servicelb-symmetric-geneve-return.md`;
`docs/decisions/ebpf-toolchain-aya.md`; `bd show mayor-aie31/g6u8s/g7jh2/pa0ze`;
Cilium `bpf/lib/tunnel.h` (cached `temp/research/cilium-tunnel.h`, not
committed — untracked research scratch); Kubernetes `release-1.36`
`pkg/apis/core/validation/validation.go` and
`pkg/controller/endpoint/endpoints_controller.go` (cached
`temp/research/k8s-validation.go`,
`temp/research/k8s-endpoints_controller.go`, not committed — untracked
research scratch); kubernetes.io/docs/reference/networking/virtual-ips/;
blog.stonegarden.dev/articles/2026/02/cilium-dsr/;
cilium.io/use-cases/load-balancer/; metallb.universe.tf/usage/.

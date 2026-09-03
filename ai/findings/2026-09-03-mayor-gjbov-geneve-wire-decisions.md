# Geneve wire-format decision brief (mayor-gjbov)

Date: 2026-09-03
Bead: mayor-gjbov (decision-prep for `mayor-aie31` Phase 3, `mayor-pa0ze`)

## Recommendation summary

1. **Option encoding**: raw pod IP for the pod identifier, raw
   `VIP_IP:VIP_PORT` for the echo — both compact-encoding alternatives buy
   a few bytes at the cost of new cross-node state or opaque debugging;
   neither is worth it here. Not settled by any ADR.
2. **NAT placement**: keep DNAT-on-backend + un-DNAT-on-ingress — it is
   already the mechanism doc's literal Packet-flow narrative and what
   `mayor-g7jh2` (Phase 2) is written against, so this decision actually
   gates Phase 2, not Phase 3 as currently framed. Not settled by the
   symmetric-return ADR (that ADR fixes the *route*, not which node does
   the rewrite).
3. **Backend key uniqueness**: the doc's own proposed fix ("fold VIP into
   the backend key") is not viable as stated — the return packet never
   carries the VIP, so a wider key has nothing to look itself up by.
   Recommend admission-time prevention (reject two LB Services sharing a
   backend Pod + targetPort) instead of an eBPF-side fix. Not settled by
   any ADR; gates Phase 3 (`mayor-pa0ze`) as intended.

Only decision 3 is genuinely locked-into-Phase-3's scope as framed;
decision 2 needs settling before Phase 2 starts, not before Phase 3 closes.

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

**Recommendation.** Raw encoding for both (a) and (b). Rationale: the
project's own memory table already treats sub-20-byte option overhead as
noise against total packet cost (`ebpf-lb-dataplane.md:98-107`), so the
compact options' only real benefit evaporates, while their cost — new
cross-node ordering coordination for (a), a second id-collision surface for
(b) — is exactly the class of correctness risk this brief exists to avoid
building into an unproven mechanism (Phase 2 is flagged HIGH risk,
"unproven in this codebase", `bd show mayor-g7jh2`). Debuggability matters
disproportionately right now because the mechanism itself is unproven.

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
choice.

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

**Why the doc's own proposed fix doesn't hold up.** The suggested fix
(`ebpf-lb-dataplane.md:148-149`, restated in `bd show mayor-pa0ze`)
is "fold the captured VIP into the backend key too." But the raw pod
reply the backend intercepts at step 6 carries only `(PodIP, TargetPort,
CLIENT_IP, SRC_PORT)` — the VIP is never present in that packet
(`ebpf-lb-dataplane.md:54-56`: "same pair, read in reverse — nothing
rewrote either side here"). A wider *write* key doesn't help a *lookup*
that has nothing to key by; it only stops one connection's stored VIP
from silently overwriting another's in a shared map slot, it does not let
step 6 pick the right one. This is a map-design dead end, not a fix — worth
flagging so Phase 3 doesn't spend effort implementing it before hitting
this wall itself.

**A second, separate observation on severity.** For TCP, two connections
cannot both stay alive at the destination Pod on one literal 4-tuple —
the Pod's own kernel TCP stack, not the LB, already collapses/rejects a
second SYN to an already-established 4-tuple. The genuinely live risk
window is narrower than "concurrent collision": it's a *stale-entry
misattribution* after LRU eviction or connection teardown, where a later,
sequential reuse of the same client port to a *different* VIP reads back
a not-yet-evicted prior entry and gets the wrong VIP echoed on return.
UDP/QUIC has no such protocol-level self-protection — but QUIC already
uses DCID-keyed matching (`ebpf-lb-dataplane.md:90-96`), which sidesteps
the 4-tuple-reuse problem entirely by construction.

**Options**

| | Fold VIP into key | Admission-time prevention | Accept + document as known limitation |
|---|---|---|---|
| Wire/map complexity | Dead end (see above) | None — app-layer validation, zero eBPF/wire change | None |
| Correctness | Does not fix the lookup side | Correct by construction — collision becomes structurally impossible | Probabilistic; residual risk remains indefinitely |
| Debuggability | N/A (doesn't work) | Trivial — rejected at admission time with a clear reason | A misattributed reply is silent unless instrumented |
| User-facing cost | — | Blocks a rare pattern: two LB Services sharing one Pod at the identical targetPort (common case — different targetPorts per Service — is unaffected) | None |
| Reversibility | — | Fully reversible later (app-layer policy, no wire/eBPF coupling) | Can be tightened later without wire changes |

**What the docs lean toward.** Mechanism doc proposes the key-folding fix
as the presumed answer (`ebpf-lb-dataplane.md:148-149`) without checking
it against what the return packet actually carries; `mayor-pa0ze`'s bead
text repeats it verbatim as "likely fix." Neither ADR discusses backend
port-sharing across Services at all.

**Recommendation.** Admission-time prevention (reject/flag two
`type=LoadBalancer` Services that would route to the same backend
Pod + targetPort) over any eBPF-side key change. Rationale: it is the only
option that is actually correct rather than probabilistic, costs nothing
in the dataplane, and avoids sinking Phase 3 effort into a key-widening
approach that the return packet's own contents make unworkable. If
admission-time validation is judged too much scope for Phase 3, fall back
to "accept + document + add a metric for the stale-misattribution window"
rather than attempting the key fold.

**Gates:** Phase 3 (`mayor-pa0ze`) — this is exactly the decision that
bead was filed to resolve.

**Reversibility:** Least wire-locked of the three. Admission-time
validation is pure control-plane policy; it can be added, loosened, or
removed at any time without touching the eBPF programs or wire format.

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

## References

`ai/extended-context/ebpf-lb-dataplane.md`;
`docs/decisions/servicelb-ebpf-geneve-dataplane.md`;
`docs/decisions/servicelb-symmetric-geneve-return.md`;
`docs/decisions/ebpf-toolchain-aya.md`; `bd show mayor-aie31/g6u8s/g7jh2/pa0ze`;
Cilium `bpf/lib/tunnel.h` (cached `temp/research/cilium-tunnel.h`, not
committed — untracked research scratch).

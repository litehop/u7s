# CNI + Service LoadBalancer landscape for u7s

Pre-decision research for a real target cluster: 5 nodes, 1GB RAM / 1VCPU each — 2 on
Linode (control plane + worker), 1 behind a home NAT router, 3 on Scaleway STARDUST
(IPv6-only, no IPv4 at all). Currently mesh-connected via Tailscale. Priorities, in
order: **memory footprint** (hard ceiling, not a soft preference), then correctness
(cross-node pod routing, source-IP preservation, IPv4-less egress), then
NetworkPolicy depth (near-zero weight — `kube-network-policies`, ~50Mi/100m, is
already adopted per `docs/decisions/network-policy-engine.md` and stays regardless of
CNI choice).

Memory figures are labeled **[official]** (a documented resource request in the
project's own manifest), **[vendor]** (a vendor/blog claim, not independently
reproduced), or **[bench]** (an outside benchmark — mostly sanj.dev's CNI comparison
posts, a personal blog that republishes near-identical templated content year over
year; treated as directionally indicative only, not authoritative). Anything with no
label was measured directly on real hardware for this document.

## Recommendation

| Layer | Pick | Why |
|---|---|---|
| CNI | **Flannel, bundled as u7s's default** | Lightest verified footprint (~50–80MB [bench]) of any viable candidate; no forced kube-proxy replacement. Bundling it (rather than leaving CNI choice entirely to the operator) costs nothing extra: the real fix needed either way is `mayor-ua9gg`'s cross-node routing gap (KCM disables `node-ipam-controller`, so no per-node podCIDR is ever coordinated) — fixing that properly benefits any CNI, bundled or not (see CNI section). Multi-cloud/VPN-mesh topologies like this one are natively supported today via the existing `--iface` flag, no new code needed (see "u7s core vs. operator-deployed" below). |
| Egress (Scaleway IPv4-less nodes) | **Jool + CoreDNS `dns64`**, host-level systemd on the Linode node(s) only | Empirically measured negligible footprint (see NAT64/DNS64 section). No CNI cooperation needed — pure static routing. |
| Mesh | **Tailscale** (stays) | Nothing surveyed beats it on all three criteria (no exposed home IP, low footprint, carries pod-CIDR routes) at zero added infrastructure. |
| Ingress/L7 | **Traefik** (stays) | ~45MiB observed in your own production, not replaced by any surveyed alternative (see Ingress section). |
| Service LB | **Bundled as u7s's default: klipper-lb, forked/reimplemented and owned outright** (fixing the one known MASQUERADE bug — not "hope Rancher fixes it upstream") | loxilb, the prior leading candidate, is **disqualified** — it cannot start at all on a 1GB node (see LB section). klipper-lb's own baseline footprint is confirmed (~92KB RSS per DaemonSet instance, operator-measured), with no comparable BPF-map-style hidden-floor risk. At sub-100 lines of shell script with one well-understood bug, owning a fix outright costs less than waiting on a third party who has no obligation to prioritize it — a fundamentally different calculus than forking a real CNI or ingress controller. |

**Rough per-node total** (Flannel + Tailscale + `kube-network-policies` + Traefik,
before kubelet/CRI-O overhead): **~155–375MB** on the 3 Scaleway + 1 home-NAT nodes;
same plus Jool's now-measured negligible cost on the Linode gateway node(s). This is
an additive stack of individually-uncertain numbers, not an independently verified
end-to-end total — treat it as a shape, not a precise figure.

**Rejected alternative**: Cilium as the CNI (with its built-in Egress Gateway,
replacing the separate Jool step). It would work, but its footprint is both higher
and *unpredictable* — see the CNI section — and its two selling points (deep
NetworkPolicy, bundled egress-gateway) are worth little under this project's
priorities. Not reconsidered unless Flannel/Calico prove insufficient in practice.

**Bundling doesn't lower the bar.** Once Flannel and the svclb fix are actually
shipped as u7s defaults, they're subject to the same ongoing resource scrutiny as any
other component u7s carries — self-built (the apiserver) or vendored unmodified
(kubelet). If either ever proves prohibitively heavy in practice, the response is the
same swap-evaluation process that would apply to kubelet: is there a lighter vendor
alternative, or does it need a self-built replacement — not grandfathering it in
because it was already chosen. This measurement shouldn't be one-time either; the
natural home for ongoing tracking is the same kind of periodic audit discipline
`ai/extended-context/memory-management-state.md` already applies to the apiserver's
own memory hotspots.

## Provider IPv6 pools are statically routed, not BGP-gated

**Both Linode and Scaleway statically route an IPv6 prefix to a single instance at
the network layer. No customer-run BGP session is required or offered for the
standard product.** This means "no BGP peer available anywhere" is a red herring for
basic external reachability — the real unsolved problem is entirely intra-cluster
(node → pod, source-IP preservation), not getting traffic to a node in the first
place.

- **Linode**: "An IPv6 routed range is assigned to a single Linode. Addresses from
  that range can only be configured on that Linode." — [Akamai TechDocs: IPv6 on
  Linodes](https://techdocs.akamai.com/cloud-computing/docs/an-overview-of-ipv6-on-linode).
  Linode staff, directly: "All traffic coming in for those addresses is routed to one
  Linode... you just need to bring them up on the Linode the route points to." —
  [Linode Community
  thread](https://www.linode.com/community/questions/8978/setting-up-ipv6-addresses-from-pool).
  An optional BGP-based failover path (FRR) exists for HA but is opt-in, not the
  default/required path.
- **Scaleway**: "Routed IPs" deliver "public IPv6 prefixes routed directly to your
  Instance... without going through a NAT gateway" — [Scaleway: Routed IPs are coming
  to all Scaleway
  Products](https://www.scaleway.com/en/news/routed-ips-are-coming-to-all-scaleway-products/).
  Typically a /64 used with SLAAC on the instance's own interface — [Scaleway: IPv6
  and the Scaleway ecosystem](https://www.scaleway.com/en/docs/ipam/reference-content/ipv6/)
  (page body only partially retrievable — verify directly, including whether it
  applies identically to STARDUST specifically, before final commitment).

**Implication**: an LB only needs to (a) bind/respond on the provider-assigned
address on the one node it's already routed to — an OS-level SLAAC/static-config
problem, not an announcement protocol — and (b) get the packet to the right pod
without losing source IP. This is a materially lower bar than MetalLB's L2 or BGP
modes.

**Checked and ruled out: a real shared (multi-instance) IPv6 pool that could unlock
MetalLB's L2 mode.** Linode did offer a shareable /116 pool, confirmed by their own
support — but it's **deprecated, no longer available for new Linodes**, and even when
live, "sharing" meant Linode's own fabric moving statically-assigned /128s between
instances for failover, not a real broadcast domain — it wouldn't have enabled L2
mode regardless. Scaleway has no equivalent product found; their only shared-L2 IPv6
mechanism is a private VPC's ULA range (`fc00::/7`), not publicly routable.

## CNI

| Candidate | Memory | kube-proxy | Cross-node routing (mayor-ua9gg) | NetworkPolicy |
|---|---|---|---|---|
| **Flannel** — recommended | **~50–80MB [bench] is the number to plan against.** A lower "~30MB k3s-embedded" figure exists but is not applicable to u7s: confirmed via k3s source (`pkg/agent/flannel/flannel.go` imports Flannel's own Go packages directly; `pkg/agent/flannel/setup.go:117-118` launches it via `go func()` as a goroutine sharing k3s's own process/heap — categorically different from how k3s deploys Traefik/CoreDNS as normal containerized manifests) that k3s runs Flannel **in-process**, amortizing its cost against a Go runtime k3s's other components already pay for. u7s's apiserver is Rust with no cgo/FFI infrastructure and already runs KCM as a separate OS process — replicating k3s's Go-to-Go embedding trick isn't a realistic option, so u7s will run Flannel as its own separate process/container regardless, making the standalone ~50-80MB figure the correct comparison point. (The ~30MB figure also has no evidence of rigorous measurement behind it — no goroutine-level `pprof` attribution was found, consistent with treating it as uncited.) Matches the operator's own live "<100MB" k3s experience either way. No official floor. | Coexists (no built-in proxy) | **Fixed in PR #1365** by re-enabling KCM's `node-ipam-controller` (`--allocate-node-cidrs=true --cluster-cidr=10.244.0.0/16 --node-cidr-mask-size=24`) — the proper fix, not the manual-patch workaround this row previously (incorrectly) recommended. Flannel's own troubleshooting doc actually calls the manual `kubectl patch node ... podCIDR` route "not generally recommended" and lists `--allocate-node-cidrs` as the primary fix — [flannel-io/flannel troubleshooting.md](https://github.com/flannel-io/flannel/blob/master/Documentation/troubleshooting.md); this doc's earlier citation omitted that. Verified live on a 2-node Lima repro/fix: distinct auto-allocated podCIDRs, no manual patching involved, cross-node Service and pod-to-pod reachability confirmed both directions. | None built-in — no penalty, `kube-network-policies` already fills this at fixed cost. |
| **Calico** (VXLAN-only, BGP disabled) — second choice | ~120–150MB low density, up to ~220MB high density [bench]. No supported "policy-disabled minimal mode" exists — an open feature request for Felix to skip routing-table interaction entirely is still unresolved ([projectcalico/calico#5247](https://github.com/projectcalico/calico/issues/5247)) — so its footprint doesn't shrink even with NetPol unwanted. | Coexists in default iptables dataplane | **Yes** — `calico-ipam` is independent of KCM's `node-ipam-controller` by default, no manual patching needed ([docs.tigera.io](https://docs.tigera.io/calico/latest/networking/ipam/get-started-ip-addresses)). | Real L3/L4 policy included, but not worth anything extra under near-zero NetPol weighting. |
| **Kilo** (`squat/kilo`) — flagged experiment, not yet ranked | **Not found anywhere** — no official/vendor/bench number. Confirmed actively maintained into 2026 (`pkg.go.dev` publish 2026-06-10; `kgctl connect`, Peer CRD webhook, MTU config work). Needs direct empirical measurement before ranking. | Delegates to whatever base CNI it layers onto | In "add-on mode," layers a WireGuard mesh onto an existing Flannel install — could **replace Tailscale AND be the CNI mesh simultaneously**, collapsing two components into one ([kilo.squat.ai](https://kilo.squat.ai/)). The most structurally interesting option if its footprint proves low. | Not a policy engine — no change to the existing `kube-network-policies` plan. |
| **Cilium** — not recommended | No independent benchmark exists beyond sanj.dev-family blogs (~180–250MB baseline, up to ~450MB at 500+ pods/node [bench] — actively re-searched, nothing better found). More importantly, its memory behavior is **unpredictable, not just high**: real production reports of step-growth to ~8GB on node churn ([cilium/cilium#37935](https://github.com/cilium/cilium/issues/37935)), 75/181 nodes exceeding 100GB agent memory on v1.16.1 ([cilium/cilium#37629](https://github.com/cilium/cilium/issues/37629)), v1.19.0 memory usage bad enough to OOM-kill kubelet itself ([cilium/cilium#44310](https://github.com/cilium/cilium/issues/44310)). A proposed "High-Scale Configuration Profile" for reduced footprint was closed as not-planned, never shipped ([cilium/cilium#37510](https://github.com/cilium/cilium/issues/37510)). | Egress Gateway mandates full `kubeProxyReplacement: true`, growing BPF map allocations on **every node**, including ones that never originate egress traffic. | Yes, via `cluster-pool` IPAM — but no longer enough to justify the cost given the two points at right. | Deepest native NetworkPolicy of any candidate (L3/L4/L7, FQDN/DNS) — worth ~zero under this project's priorities. |
| **kube-router** — disqualified | Real multi-GB memory-growth reports ("3.868GB after 10 days," traced to `NodeSpec` deep-copies) with no fix in 2026 releases checked (v2.7.0, v2.8.0 changelogs contain no memory-leak remediation) — [cloudnativelabs/kube-router#795](https://github.com/cloudnativelabs/kube-router/issues/795). | Optional | No — default host-local IPAM still depends on KCM's `--allocate-node-cidrs`, no manual-patch equivalent. | Yes (iptables-based), moot given the memory risk. |
| **Patu CNI** (`redhat-et/patu`) — disqualified | Unverified, moot given the disqualifier at right. | N/A | **Confirmed single-node only** as of this check — no cross-node pod routing/IPAM exists at all. | N/A |

No new mainstream CNI project beyond Kilo and Patu was found targeting
resource-constrained clusters.

## u7s core vs. operator-deployed, and the multi-cloud/VPN-mesh story

u7s should bundle a lightweight default (Flannel for CNI, and eventually the fixed
klipper-lb-alike for Service LB) rather than leave those entirely to the operator —
matching k3s's "batteries included, swappable" philosophy rather than kubeadm's
"bring everything." This costs nothing extra: bundling Flannel doesn't add complexity
beyond what `mayor-ua9gg`'s fix already requires regardless of who provides the CNI,
and it doesn't conflict with the existing `docs/decisions/network-policy-engine.md`
decision — that decision was specifically about layering `kube-network-policies` onto
any CNI for NetworkPolicy enforcement, orthogonal to which CNI provides base pod
routing. Genuinely topology-specific pieces (the NAT64/DNS64 gateway, the mesh, the
choice of ingress controller) stay operator-deployed, since not every u7s cluster
needs them.

**Multi-cloud/VPN-mesh clusters (this topology) are already supported today, with no
new code.** k3s has a purpose-built solution for this — a real `pkg/vpn` package
(not just documentation) that parses a `--vpn-auth` flag (`name=tailscale,joinKey=...`,
marked **experimental**), shells out to `tailscale up`, parses `tailscale status
--json` for the assigned IP, and sequences this *before* the kubelet serving cert is
issued (the VPN IP must be in the cert's SAN) — see k3s's own ADR
([github.com/k3s-io/k3s/blob/main/docs/adrs/integrate-vpns.md](https://github.com/k3s-io/k3s/blob/main/docs/adrs/integrate-vpns.md))
and [docs.k3s.io/networking/distributed-multicloud](https://docs.k3s.io/networking/distributed-multicloud).
Flannel's own CIDR/IPAM logic is confirmed unchanged underneath this — the VPN mesh
only swaps the transport layer that carries pod traffic between nodes; cross-node CIDR
coordination and NAT-traversed reachability stay architecturally separate concerns.

u7s already has the underlying capability k3s's VPN package provides, via a much
simpler path: `scripts/install.sh`'s existing `--iface`/`U7S_IFACE` flag already
resolves an interface's IP (`install.sh:466`) and feeds it into both kubelet's
`--node-ip` (`install.sh:579,694`) and the apiserver's `--listen`/`--advertise-address`
(`install.sh:623`) — including cert generation, which happens after this resolution in
the same sequential script, naturally satisfying the ordering constraint k3s needs
dedicated code for. **Pointing `--iface tailscale0` today already makes u7s advertise
its Tailscale IP correctly.** The only new work if Flannel is bundled as default is
templating Flannel's own native interface-selection flag from the already-existing
`$IFACE` value — a few lines, since Flannel supports this natively too.

**Do not replicate k3s's deeper VPN-lifecycle code** (auth-key-based join, automated
`tailscale up`, VPN client lifecycle management). That solves a zero-touch-provisioning
UX problem — joining the VPN and the cluster in one command — which isn't a need here,
since the mesh is deployed independently regardless (see Mesh section). It would be
convenience sugar over a capability u7s already has, not a missing capability. The
practical action: document `--iface <vpn-interface>` (with the mesh already configured
and up before running `install.sh`) as the supported pattern for multi-cloud/VPN-mesh
clusters.

**Versioning: bundled add-ons must not be compiled into the u7s binary.** u7s's
current CoreDNS deployment is a real, pre-existing example of the anti-pattern to
avoid: `crates/apiserver/src/bootstrap_apply.rs:22` does
`include_bytes!("../manifests/coredns.yaml")`, and that manifest hardcodes
`image: registry.k8s.io/coredns/coredns:v1.11.1` — already stale against upstream's
v1.14.2 per the manifest's own comment. A CoreDNS CVE patch today genuinely requires
rebuilding and releasing the apiserver binary. Compare kube-proxy, handled correctly:
deployed as a live container-image reference in an applied manifest
(`install.sh:796`, `image: registry.k8s.io/kube-proxy:v${KUBE_VERSION}`) — not baked
into any binary, independently bumpable. kubelet/kube-controller-manager ARE bundled
into the release tarball (`install.sh:530`), but that coupling is technically
defensible — kubelet has a real version-skew compatibility requirement against the
apiserver it talks to, unlike CoreDNS, which is k8s-API-version-agnostic and has no
technical reason to move in lockstep with a u7s release.

**The distinguishing test for any future bundled add-on**: does it have a genuine
version-skew dependency on u7s's own API version, or not? If not (Flannel and the LB
fix both fall here — neither has any coupling to u7s's own API surface version),
ship it the way kube-proxy is shipped: a plain manifest file applied via `kubectl
apply` at install/upgrade time, with the image tag as an externally-editable value —
never `include_bytes!`'d into the binary. This keeps a future CVE patch a manifest
edit + re-apply, not a full u7s rebuild. Separately, CoreDNS's own existing
compile-time-embedding should be fixed on the same principle — not blocking for the
CNI/LB decision, but a real, already-present maintenance-overhead gap.

## Standalone NAT64/DNS64 gateway (Scaleway egress)

Solves the 3 IPv4-less Scaleway nodes' outbound traffic (e.g. pulling images from
GitHub, which has no IPv6 infrastructure) entirely outside the CNI, on the Linode
nodes only — an alternative to Cilium's built-in Egress Gateway that avoids paying
its cluster-wide kube-proxy-replacement tax.

**Jool** (kernel-module NAT64/SIIT, stateful) — recommended. **Empirically measured**
on a fresh 1 CPU/1GiB-RAM Lima VM (Ubuntu 24.04): idle footprint (module loaded, NAT64
instance configured, no traffic) was unmeasurable above `free -m` noise — the only
Jool-specific slab cache held 11 objects × 728B ≈ 8KB. Load-tested with a synthetic
IPv6→IPv4 path (network namespaces + veth pairs, since Lima has no real IPv6 host
path) up to 500 concurrent TCP flows with zero failures and a flat slab count — well
under 1MB at that scale (a 1000-flow attempt was capped by the test harness's own fork
budget, not by Jool; true per-session cost above ~1000 sessions remains unmeasured but
isn't expected to matter at this cluster's realistic scale). Active project: latest
release v4.1.15 (2026-01-27), latest commit 2026-05-24
([github.com/NICMx/Jool](https://github.com/NICMx/Jool/releases)). No official
Kubernetes manifest exists — runs as a systemd service on a dedicated gateway
host/VM, not a per-node DaemonSet, doing full stateful NAT64/PAT (many IPv6 clients
share one IPv4 address).

**CoreDNS `dns64` plugin** — recommended pairing. **Empirically confirmed**: ~0MB
delta measured directly (plain Corefile RSS 48.4MB vs. dns64-enabled RSS 48.1–49.1MB
on CoreDNS 1.14.7) — compiled into the binary every vanilla k8s cluster already runs,
config-only change. **Resolution correctness verified live with zero real IPv6
connectivity**: `github.com` (no native AAAA) synthesized `64:ff9b::141b:b171`, which
hex-decodes exactly to the real A record `20.27.177.113` (RFC 6052-correct);
`cloudflare.com` (has native AAAA) passed through unmodified. Real limitation: no
per-client-subnet scoping — cluster-wide `allow_ipv4` is correctness-preserving but
routes even Linode-native pods' AAAA-less lookups through the NAT64 path (an
efficiency, not correctness, concern). If subnet-scoped synthesis is ever needed,
**BIND9's `dns64` clause** supports an explicit `clients { }` ACL that CoreDNS and
Unbound cannot do ([BIND9 Configuration
Reference](https://bind9.readthedocs.io/en/v9.16.26/reference.html);
[NLnetLabs/unbound#462](https://github.com/NLnetLabs/unbound/issues/462) confirms
Unbound's incapability).

**Not recommended**: TAYGA (stateless — needs a second NAT44/MASQUERADE hop to share
one IPv4 among many nodes, which Jool avoids natively; also less actively maintained
by commit recency). 464XLAT (solves translating *private* IPv4 over an IPv6-only
path — mobile/CPE tethering; u7s's nodes have no private IPv4 to translate, so this
doesn't apply).

**Routing**: NAT64 traffic steering is a plain L3 static-route concern, fully
independent of the CNI. The existing Tailscale mesh already supports this —
`tailscale set --advertise-routes=64:ff9b::/96` from a Linode gateway node, accepted
on the Scaleway nodes, is standard subnet-router functionality ([Tailscale subnet
routers docs](https://tailscale.com/docs/features/subnet-routers)). No CNI change, no
dataplane-mode switch — this can be prototyped independently of the CNI decision.

## Mesh (Tailscale alternatives)

Constraint: 3 Scaleway nodes are IPv6-only, 1 node sits behind home NAT and must not
expose its own public IPv4. Any replacement must do real NAT traversal/relay.

**Tailscale's own footprint**: no official minimum-RAM spec exists. On a 128MB-RAM
router (OpenWrt), `tailscaled` used 72.3MB RSS (56% of total device RAM) —
[tailscale/tailscale#18013](https://github.com/tailscale/tailscale/issues/18013). A
competitor benchmark (Defined Networking, Nebula's commercial backer — treat the
specific multiple as directional) measured Tailscale at ~60MB idle up to 220–250MB
under sustained transfer, vs. Nebula's flat ~27MB and ZeroTier's flat ~10MB in the
same test ([defined.net](https://www.defined.net/blog/nebula-is-not-the-fastest-mesh-vpn/)).
The 72MB figure from Tailscale's own bug tracker anchors this comparison.

**Recommendation: keep Tailscale.** Nothing surveyed beats it on all three criteria
(no exposed IP, low footprint, carries pod-CIDR routes) simultaneously at zero added
infrastructure. Two real alternatives depending on what problem you're actually
solving:

- **headscale** (self-hosted Tailscale-protocol control server) — the move if the
  goal is decoupling from Tailscale Inc.'s *hosted control plane*. Identical client,
  NAT-traversal behavior, and route-carrying mechanism; only the control plane
  (~50–100MB [vendor], centrally run, not per-node) needs self-hosting. Zero
  capability regression.
- **Nebula** — the only candidate with a plausible *lower* per-node footprint
  (~27MB vendor-claimed vs. Tailscale's 60–250MB), and NAT traversal costs nothing
  extra since an existing Linode node can serve as lighthouse. Tradeoffs: its
  subnet-routing story (`unsafe_routes`) is explicitly a discouraged/secondary
  feature, not a first-class primitive like Tailscale's, and automatic
  fallback-to-relay has an open, unresolved gap
  ([slackhq/nebula#204](https://github.com/slackhq/nebula/issues/204)). Worth a
  real trial if footprint reduction specifically is the goal.

**Not recommended**: plain WireGuard (no built-in signaling/relay — breaks on
symmetric NAT/CGNAT without hand-building a relay, reinventing DERP). Netmaker and
netbird (both require self-hosting a control/relay stack with a documented minimum
of 1–2GB RAM — exceeds this project's entire per-node budget by itself). ZeroTier
(lowest claimed footprint and zero-cost default relay, but isn't WireGuard-based so
can't piggyback on any CNI's native WireGuard support, and doesn't reduce
third-party dependency any more than Tailscale does). Kilo remains the most
structurally interesting "mesh + CNI in one" option (see CNI section) but is
unverified and untested for this specific angle.

## Service LoadBalancer

**loxilb is disqualified.** Empirically measured: on a real 1 CPU/1GiB Lima VM
(kernel 6.17, well above loxilb's stated 5.8 floor), the container crash-loops
indefinitely — `bpf_create_map_xattr(fc_v4_map): Cannot allocate memory(-12)` →
assertion failure → SIGABRT, every 2–3s, never reaching a running state. Confirmed as
a genuine memory floor, not an ARM64/kernel artifact: the identical VM/kernel/image
starts immediately and stably at 2GiB (loxilb's own "starting point" guidance) and at
4GiB; only 1GiB fails. At 2GiB, idle RSS was ~75–82MB and RSS under 500 concurrent
flows was ~42–47MB — genuinely lightweight once running, which is irrelevant on the
actual target hardware. Every other property checked out live before the
disqualification: source-IP preservation confirmed (backend logs recorded the real
client address through the VIP, validating the default DNAT-only "mode 0"), no BGP
required, and the only candidate surveyed with real end-to-end PROXY protocol v2
support ([LoxiLB PROXY protocol
docs](https://docs.loxilb.io/main/proxy-protocol-v2/)) — none of it matters if the
process cannot start.

**Also ruled out — loxilb's Gateway API mode as a Traefik replacement.** It needs
three separate components (base loxilb, the `kube-loxilb` operator, a distinct
`loxilb-ingress` pod) — architecturally more, not fewer, than "loxilb + Traefik."
Real functional gaps: no rewrite/redirect support (confirmed open bug,
[loxilb-io/loxilb-ingress#19](https://github.com/loxilb-io/loxilb-ingress/issues/19)),
no traffic splitting or middleware, manual TLS with no cert-manager automation.
loxilb/kube-loxilb is absent from the official [Kubernetes Gateway API
implementations list](https://gateway-api.sigs.k8s.io/implementations/). `loxilb-ingress`
has 21 stars / 6 forks / 55 commits. Traefik stays.

**Leading candidate: a purpose-built minimal LB fixing klipper-lb's one known bug.**
klipper-lb (k3s's built-in ServiceLB) is a shell script installing iptables DNAT
rules with no persistent proxy loop — architecturally trivial, negligible memory by
construction. **Confirmed directly by the operator on a real running instance**:
`ps -o rss=`/`top` on the `entry` process reports **~92KB RSS** — matches the
architecture exactly, since the foreground process only installs iptables rules once
then idles; all actual packet forwarding happens in-kernel via those rules, with zero
per-packet userspace involvement. Unlike loxilb, there's no comparable hidden-floor
risk behind this number: iptables/conntrack kernel state is allocated incrementally
as connections are actually seen, not pre-sized for worst-case capacity the way
eBPF maps are — so a small RSS here isn't hiding an invisible allocation that could
fail under load, the way it was for loxilb. Caveat: this is a per-instance figure —
klipper-lb runs as a DaemonSet **per exposed `LoadBalancer` Service, per protocol**
(a Service exposing both TCP and UDP gets two separate DaemonSets), each replicated
one-pod-per-node, so the right mental model is "~92KB × Services × protocols ×
nodes," not a flat total. **The transferable lesson, worth deliberately preserving
in the fix**: this fan-out stays essentially free precisely *because* of the
install-rules-once-then-idle design — marginal cost per instance doesn't grow with
scale the way a persistent-proxy-loop architecture's would, so multiplying instances
(more Services, more protocols, more nodes) multiplies a near-zero number, not a
meaningful one. This is a design property to keep, not just an incidental
measurement — the fixed-klipper-lb-alike should preserve the same "kernel does all
subsequent work" shape, not reintroduce a persistent per-instance process that would
make the same fan-out costly. Its only defect: an
unconditional `POSTROUTING ... -j MASQUERADE` in the `entry` script SNATs every
packet regardless of `externalTrafficPolicy` — this is the exact mechanism behind
the original observed source-IP loss, not a topology limitation
([k3s-io/klipper-lb source](https://github.com/k3s-io/klipper-lb)). The fix is
straightforward in principle: omit the MASQUERADE step when the destination is
local. **This does not exist as a real, tested artifact yet** — it needs to be built,
then verified end-to-end (source-IP preservation against a real backend, actual
measured footprint under real connection churn rather than assumed from the idle
number alone, and correctness against this
cluster's specific provider-routed-IPv6 topology) before it's a real recommendation
rather than a design sketch.

**Second concrete failure mode this same fix would resolve, from the operator's own
prior attempt**: running a split-horizon DNS server in-cluster (local network queries
resolve a cluster domain to the home-LAN node's address, avoiding an external round
trip; public queries resolve to the public address) failed because the DNS server,
reached through klipper-lb + Traefik in UDP mode, only ever saw the in-cluster virtual
IP as the query's source — never the real client's origin IP. This is the exact same
MASQUERADE mechanism, confirmed to affect UDP traffic as well as TCP/HTTP, not just an
HTTP-layer concern. A fixed LB would need to preserve source IP for UDP Services too,
not just TCP — worth an explicit test case when the new LB is built.

**Separate, non-infrastructure limitation observed in the same attempt (do not chase
this as a bug)**: Android's Secure DNS ("Private DNS") setting can disregard the local
network's DHCP-provided DNS server entirely and query a hardcoded public DoH/DoT
provider instead — this is client-side OS behavior, not something any server-side
source-IP fix, CNI change, or LB change can address. Any split-horizon DNS design
needs to treat "some clients will bypass local resolution regardless of network
configuration" as a fixed constraint, not a solvable problem.

**Hard requirement: QUIC/HTTP3 support.** Traefik already supports this at the L7
layer — no work needed there. The requirement this pushes down to the LB layer is
more specific than "UDP works": QUIC connections are long-lived and stateful, so the
LB needs to keep routing the *same* UDP flow to the *same* backend pod for the
connection's lifetime, not just deliver individual packets to whatever pod is
available. iptables DNAT (the fixed-klipper-lb-alike's mechanism) provides this
naturally via Linux's conntrack subsystem — a UDP 4-tuple pins to one destination
once conntrack sees it — so this should already be covered by the planned fix, but
verify it explicitly rather than assume (see open questions). Independent corroboration: `kubernetes-retired/blixt` (an experimental eBPF-native
Gateway API L4 LB, archived 2025-09-08 — retired for scope/maintenance reasons, not
a technical dead-end; its TCPRoute/UDPRoute mission was substantially absorbed by
their GA graduation in Gateway API v1.6) deliberately switched from XDP to TC hooks
specifically to gain conntrack access for stateful NAT, even though eBPF's own
design could have avoided conntrack entirely — independent validation, from a
completely different implementation stack, that conntrack is the *right* mechanism
for this, not a fallback compromise. This only gets materially harder with multiple load-balanced
Traefik replicas needing QUIC connection-migration/Connection-ID-aware routing
across them — not a concern at this
cluster's scale with a single Traefik instance.

**Not recommended, none clear this cluster's topology bar**: MetalLB (L2 mode needs
shared L2/ARP visibility, ruled out for a WAN/Tailscale topology; BGP mode needs a
real peer, no side-channel; PROXY protocol feature request closed unimplemented —
[metallb/metallb#797](https://github.com/metallb/metallb/issues/797)). kube-vip
(same L2/BGP split as MetalLB, no third mode; PROXY protocol is an open,
unresolved issue — [kube-vip/kube-vip#1027](https://github.com/kube-vip/kube-vip/issues/1027)).
purelb (same topology limitation, delegates to your own routing daemon). OpenELB
(CNCF-archived 2025-05-22, dead).

## Open questions before committing

- **The fixed-klipper-lb-alike doesn't exist yet.** Build it, verify source-IP
  preservation against a real backend for **both TCP and UDP** (the operator's own
  prior split-horizon DNS attempt confirmed the MASQUERADE bug affects UDP Services
  too, not just HTTP/TCP), verify **UDP flow affinity for QUIC/HTTP3** specifically
  (the same 4-tuple must keep routing to the same backend pod for a connection's
  lifetime — expected to work via conntrack, but confirm rather than assume, same
  discipline as everything else in this doc), measure its actual footprint (don't
  assume negligible — loxilb's disqualification is a reminder that architectural
  expectations about footprint can be wrong until tested), and confirm it works
  against this cluster's specific provider-routed-IPv6 topology.
- **RESOLVED — Flannel + `node-ipam-controller`, not the manual-podCIDR-patch
  workaround this doc originally (incorrectly) recommended.** PR #1365 fixed
  `mayor-ua9gg` by re-enabling KCM's `node-ipam-controller`
  (`--cluster-cidr=10.244.0.0/16`), verified live on a 2-node Lima setup: distinct
  auto-allocated podCIDRs, no manual patching, cross-node Service and pod-to-pod
  reachability confirmed both directions, single-node regression clean. Residual
  item: confirm the `10.244.0.0/16` range doesn't collide with Tailscale's routes or
  Jool's `64:ff9b::/96` advertised route in the actual 5-node deployment (only
  checked against the apiserver's own service CIDR so far).
- **Kilo's actual per-node footprint has never been measured.** Confirmed alive and
  maintained into 2026, but needs a real measurement (ideally on a Scaleway STARDUST
  or Linode nanode) before it can move from "flagged experiment" to a ranked
  recommendation — especially given its potential to replace Tailscale and the CNI
  overlay simultaneously.
- **Nebula's ~27MB and ZeroTier's ~10MB figures come from one vendor-authored
  benchmark** on desktop-class hardware, not this cluster's actual 1GB/1VCPU nodes —
  needs reproduction on target hardware before justifying a mesh switch.
- **Confirmed: cone NAT, not symmetric** (`tailscale netcheck` on the home node:
  `MappingVariesByDestIP: false`). This meaningfully de-risks **Nebula** specifically —
  its documented relay-fallback gap
  ([slackhq/nebula#204](https://github.com/slackhq/nebula/issues/204)) only matters
  when hole-punching fails, and a cone NAT makes that far less likely. Nebula moves
  from "worth a trial, with a real caveat" to a solid option if footprint reduction
  is still a goal. Does not change plain WireGuard's disqualification — that's a
  signaling/rendezvous gap (no mechanism to discover/exchange a changing external
  mapping), not a NAT-friendliness problem.
- **Scaleway's IPv6 doc page could only be partially fetched, even on a second
  attempt** — verify directly, including whether it applies identically to the
  STARDUST instance type.
- **NEW — the home node may not need NAT-traversal mesh tooling for IPv6 traffic at
  all**, if the ISP's delegated /64 is stable. IPv6 generally isn't NAT'd (RIPE-690)
  and the actual blocker would just be the router's default-deny IPv6 firewall — a
  pinhole rule, not hole-punching. **Real gotcha confirmed**: prefix stability isn't
  guaranteed — many ISPs rotate the delegated /64 unless the router maintains a
  stable DUID ("sticky" PD) or a static add-on is purchased. Confirm this specific
  ISP's behavior before relying on it; if stable, the home node could be treated like
  the Linode/Scaleway nodes above (statically addressed) for IPv6-based traffic
  specifically. Doesn't reduce the case for keeping Tailscale, though — its value is
  uniform route-carrying across all 5 nodes, not just NAT traversal for this one.
- **Cilium's 180–450MB figure remains single-sourced** from a low-credibility blog
  after two research passes actively searching for alternatives. Doesn't change the
  recommendation (Cilium's unpredictable large-cluster memory-growth history matters
  more than the exact baseline) but shouldn't be treated as settled if it resurfaces.
- **Lima can measure memory footprint without real IPv6 connectivity** — proven by
  the Jool measurement above (synthetic namespaces + veth pairs, no real external
  IPv6 needed) and reused for the loxilb measurement. What Lima genuinely can't
  validate is true end-to-end reachability from a real external IPv6-only caller —
  for that specific question, a real cloud node or Scaleway STARDUST node is needed.

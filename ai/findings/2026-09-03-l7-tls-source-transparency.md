# L7 TLS termination and source-IP transparency (exploratory, verified)

Bead: mayor-98i0y (verify + refine this prelim doc)

Status: exploratory research, not a decision. No ADR or wire-format
impact; revisit only if/when a Gateway API `HTTPRoute` requirement is
actually scoped for u7s (no such bead exists today). Relates to the
ServiceLB initiative (`mayor-aie31`), which owns the eBPF/Geneve L3
dataplane this doc treats as a given and does not change.

## Answer

The core idea survives verification: an L7 TLS terminator can preserve
real-client-IP-at-L3 via Linux TPROXY, and Envoy/nginx are shipped,
verifiable proxy choices for it. But the original doc's central
integration claim — reusing the existing symmetric-Geneve-return path is
"not a new subsystem" — is **overstated**: the mechanism doc's forward
hook is physical-uplink-only, and neither of the proxy's two plausible
backend-dial paths obviously traverses it (see Refuted, `mayor-bguco`).
Two other factual claims were wrong and are corrected below (HAProxy does
have a native Gateway API controller; the Traefik-correction instruction
pointed at the wrong document). Nothing here changes `mayor-aie31`'s
current L3-only scope.

## Mechanism (corrected)

A naive terminating proxy opens a fresh backend connection and the Pod
sees the proxy's IP. Linux TPROXY (`IP_TRANSPARENT` +
`iptables -j TPROXY`, `Documentation/networking/tproxy.txt`) lets the
proxy bind that backend socket to the client's own address instead. The
backend then replies to the client IP, so the reply must be steered back
to the proxy holding the connection state. The original doc claimed this
steering is free — the fabric's existing return path. It is not
obviously free: see Refuted below.

## Verified

- **ADR invariant, correctly quoted.**
  `docs/decisions/servicelb-ebpf-geneve-dataplane.md:14`: "...that Pod
  must see the real client IP at L3." Confirmed by direct read.
- **Proxy feature claims**, confirmed in each project's own source/docs
  via GitHub code search:
  - Envoy: `original_src` listener+HTTP filter exists
    (`envoyproxy/envoy`, `source/extensions/filters/listener/original_src/`);
    Envoy Gateway is a real, maintained Gateway API implementation
    (`envoyproxy/gateway`).
  - nginx: `proxy_bind ... transparent` exists in both
    `src/http/modules/ngx_http_proxy_module.c` and
    `src/stream/ngx_stream_proxy_module.c`. NGINX Gateway Fabric
    (`nginx/nginx-gateway-fabric`, Apache-2.0) runs on OSS nginx by
    default — `Dockerfile.nginxplus` is a separate, opt-in build. "OSS —
    verify vs NGINX Plus" resolves to: OSS works, Plus is optional.
  - HAProxy: `usesrc clientip` documented (`haproxy/haproxy`,
    `doc/network-namespaces.txt`, `doc/design-thoughts/binding-possibilities.txt`).
  - Traefik: zero `IP_TRANSPARENT` hits across `traefik/traefik`;
    PROXY-protocol support is extensive (`pkg/tcp/dialer.go`,
    `pkg/provider/kubernetes/crd/kubernetes_tcp.go`, 40+ hits). "Ruled
    out, no IP_TRANSPARENT" is correct.
- **Gateway API is CRD-based, not core k8s.** k8s `release-1.36`'s
  `staging/src/k8s.io/api` has no `gateway` group (`gh api
  repos/kubernetes/kubernetes/contents/staging/src/k8s.io/api?ref=release-1.36`,
  no `gateway` entry). It ships from `kubernetes-sigs/gateway-api`
  (latest tag `v1.6.1`, published 2026-07-16 — actively maintained; core
  resources GA since v1.0.0, 2023). u7s has zero Gateway API/HTTPRoute
  code today (`grep -rl HTTPRoute crates/` — no hits): this whole doc is
  prework, not integration with anything that exists yet.
- **HTTP-path-routing XOR end-to-end-encryption tradeoff** is a
  tautology (path lives inside the encrypted record; routing on it
  requires holding the key) — true by definition, not further
  verifiable.
- **u7s already has the pieces to hand-roll a minimal TPROXY proxy**,
  which the original doc didn't consider: `crates/apiserver/Cargo.toml`
  already carries `hyper` (http1+http2), `rustls`/`tokio-rustls`, and
  `socket2 = "0.6"` — and `socket2`'s own `src/socket.rs` exposes
  `set_ip_transparent`. This doesn't overturn "build-from-scratch is not
  warranted" (Envoy/nginx still win on HTTP compliance and Gateway API
  controller maturity), but the build option is more tractable than
  implied, worth naming given the project's minimal-deps bias.

## Refuted / corrected

- **"HAProxy: Gateway API only via its Ingress controller (no native
  HTTPRoute)" is wrong.** `haproxytech/haproxy-unified-gateway` is a
  real, active native Gateway API controller (created 2025-11-11, last
  push 2026-08-31, 87 stars) — young and unproven relative to Envoy
  Gateway/NGINX Gateway Fabric, but it exists. Corrected: HAProxy's
  Gateway API story is "young native controller," not "none."
- **"(Correct the Traefik assumption in `ebpf-lb-dataplane.md`.)" points
  at the wrong document.** That doc's only Traefik mention
  (`ebpf-lb-dataplane.md:101` and `:141`) is about fixed-length QUIC
  Connection-ID matching for the *L3 DCID-routing* dataplane — an
  unrelated capability question, not a claim about Traefik's
  source-transparency support. There is nothing to correct there on this
  axis; the instruction conflated two unrelated "Traefik" mentions across
  two different docs. No edit made to that file (also out of scope: a
  concurrent worker owns it).
- **"...exactly the symmetric-Geneve-return machinery we already have" /
  "not a new subsystem" is overstated.** The mechanism doc's
  forward-ingress tc-bpf hook is *physical-uplink only*
  (`ai/extended-context/ebpf-lb-dataplane.md:28`, "Physical uplink, every
  node (forward leg)"). The proxy P's TPROXY'd backend connection has two
  plausible paths, neither obviously covered:
  - P dials the backend Pod IP directly — the normal ingress-controller
    pattern, load-balancing over EndpointSlice IPs and bypassing the
    Service VIP. That traffic is flannel vxlan pod-to-pod routing and
    never touches the Geneve tunnel at all (the ServiceLB ADR's own
    consequence: "the Geneve tunnel never touches flannel's vxlan
    device," `servicelb-ebpf-geneve-dataplane.md:51`).
  - P instead dials the VIP, deliberately re-entering the ServiceLB path
    so the existing return machinery has a forward-flow entry to steer
    against. That is a locally-originated packet to a local/owned
    address; Linux delivers such packets without transiting the
    *physical* NIC's tc ingress qdisc, which is the only attachment
    point the forward classifier has.
  - Filed `mayor-bguco` to resolve which of the two (if either) actually
    works before any L7 prototype assumes free reuse of the L3 return
    path.

## Uncertain

- **RAM baselines** ("Envoy ~150MB", "nginx ~50–100MB", "HAProxy
  lightest") are uncited operational estimates, not measurements. The
  ServiceLB ADR's own loxilb precedent — a vendor/folklore RAM
  expectation wrong by enough margin to crash-loop on a real 1GB/1vCPU
  node — is a direct warning against trusting these unmeasured. Filed
  `mayor-88n36`.
- **HAProxy H3 "experimental"** is weakly supported (docs mention QUIC
  near "experimental" in adjacent files, not a clean maturity statement)
  and, per the doc's own reframe below, non-decision-relevant anyway.
  Left as noted, not chased further.
- **Fallback SNAT idea** (eBPF-provided transparency for a
  non-transparent proxy) is undesigned, correctly hedged already as "a
  known fallback, not the plan." No new evidence changes that; the
  cross-reference to Decision 3's conntrack-key uniqueness
  (`2026-09-03-mayor-gjbov-geneve-wire-decisions.md`) is a sound
  consistency check, not a resolved design.

## Reframes and topology (unchanged, sound)

Two reframes collapse the original "no proxy wins all four axes" problem:
H3 stays passthrough-by-DCID (Decision 4, gjbov finding) — L7 only ever
terminates TCP TLS (H1/H2), so a proxy's H3 maturity is irrelevant; and
the L7 tier is a separately-scaled node pool, not the eBPF fabric's
per-node DaemonSet, so a heavy proxy's RAM is confined to a small pool.
Both hold given the ADRs as read.

Topology: publishing only L7 nodes' addresses in DNS makes the proxy node
*the* ingress node for its own client-facing leg, needing no new
mechanism for that hop. The unresolved part is P's *backend*-facing leg
(Refuted, above) — that is where any real integration cost lives, not the
client-facing leg the original doc focused its "P = ingress" framing on.

## Gating criteria — what would need to be true before building this

1. `mayor-bguco` is answered: the return-path reuse either works as
   claimed, or a small, named extension closes the gap. If it needs real
   new dataplane work, this stops being "adjunct integration" and needs
   its own cost/benefit case as a mini-epic.
2. A concrete Gateway API `HTTPRoute` requirement exists for u7s — none
   does today; no bead scopes it, no code references it.
3. `mayor-88n36`'s measured RSS lands in a range compatible with the
   "confined to a small L7 node pool" framing this doc's viability rests
   on, not folklore numbers.

## References

`ai/extended-context/ebpf-lb-dataplane.md`;
`2026-09-03-mayor-gjbov-geneve-wire-decisions.md`;
`docs/decisions/servicelb-ebpf-geneve-dataplane.md`;
`servicelb-symmetric-geneve-return.md`; `bd show mayor-aie31`; `bd show
mayor-bguco`; `bd show mayor-88n36`; `kubernetes/kubernetes@release-1.36`;
`kubernetes-sigs/gateway-api`; `envoyproxy/envoy`; `envoyproxy/gateway`;
`nginx/nginx`; `nginx/nginx-gateway-fabric`; `haproxy/haproxy`;
`haproxytech/haproxy-unified-gateway`; `traefik/traefik`;
`rust-lang/socket2`.

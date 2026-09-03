# L7 TLS termination and source-IP transparency (exploratory)

Bead: mayor-98i0y (verify + refine this prelim doc)

Status: exploratory, not a decision. Revisit if/when an L7 (TLS-terminating,
path-routing) tier is added alongside the eBPF/Geneve L3 dataplane. Relates to
the ServiceLB initiative (`mayor-aie31`). No wire-format or ADR impact yet.

## Idea to persist

If we ever terminate TLS at an L7 tier (for Gateway API `HTTPRoute` path/header
routing), **real-client-IP-at-L3 — an ADR invariant
(`servicelb-ebpf-geneve-dataplane.md:14`) — survives termination only via
original-source transparent proxying (Linux TPROXY / `IP_TRANSPARENT`).** A
naive terminating proxy opens a fresh backend connection and the Pod sees the
proxy's IP; TPROXY makes the proxy bind its backend socket to the client's IP.
The catch: the backend then replies to the client IP, so the reply must be
steered back to the proxy that holds the connection state — which is exactly
the symmetric-Geneve-return machinery we already have. So preserving the
invariant across an L7 hop is an integration of our existing return path, not a
new subsystem. The one irreducible tradeoff is **HTTP-path-routing XOR
end-to-end-encryption-to-the-Pod** — path lives inside the encrypted stream, so
routing on it requires termination.

## Options outlined

**Proxy choice.** Build-from-scratch is not warranted; original-source
transparency is a shipped feature in several proxies. Verified 2026:

- **Envoy** — `original_src` filter (reference impl), Gateway API GA (Envoy
  Gateway), native SPIFFE/SDS. Heavy (~150 MB baseline).
- **nginx** — `proxy_bind $remote_addr transparent`; H3 GA; Gateway API via
  NGINX Gateway Fabric (OSS — verify vs NGINX Plus). Light (~50–100 MB).
- **HAProxy** — `source … usesrc clientip`; lightest; H3 experimental; Gateway
  API only via its Ingress controller (no native HTTPRoute).
- **Traefik — ruled out for this role**: PROXY-protocol / `X-Forwarded-For`
  only, no `IP_TRANSPARENT`. Cannot preserve the L3 invariant through
  termination. (Correct the Traefik assumption in `ebpf-lb-dataplane.md`.)

**Two reframes that collapse the "no single proxy wins all four axes"
problem:**
1. *H3 stays passthrough-by-DCID* (Decision 4) — we only ever terminate TCP
   TLS (H1/H2) at L7, so a proxy's H3-termination maturity is irrelevant.
   HAProxy's weak H3 stops mattering.
2. *The L7 tier is not fleet-wide* — the eBPF fabric is the per-node DaemonSet;
   the L7 proxy is a separately-scaled tier. Envoy's RAM is then confined to a
   small L7 node pool, not every 1 GB node.

**Topology.** L7 need not be a DaemonSet. Cross-node source transparency is
what frees the proxy from running per-node: its client-src egress is traffic
the fabric already carries and returns anywhere. Publish only the L7 nodes'
addresses in DNS for L7 Services so the proxy node *is* the ingress node
(P = ingress) — then the existing symmetric-return-to-ingress works unchanged.
Do NOT forward client→ingress-N→proxy-P across nodes (that needs new
return-steering to target P≠N). Cost of centralizing: fewer ingress IPs for
L7 Services (smaller edge spread) vs. not running a heavy proxy fleet-wide.

**Fallback.** The eBPF fabric could provide source transparency *for* a
non-transparent proxy (SNAT the proxy egress → client IP, un-SNAT on return),
reopening Traefik — at the cost of more eBPF conntrack (re-raises Decision-3
uniqueness) and a synthetic client source port. File as a known fallback, not
the plan.

## References

`ebpf-lb-dataplane.md`; `2026-09-03-mayor-gjbov-geneve-wire-decisions.md`;
`docs/decisions/servicelb-ebpf-geneve-dataplane.md`;
`servicelb-symmetric-geneve-return.md`; `bd show mayor-aie31`.

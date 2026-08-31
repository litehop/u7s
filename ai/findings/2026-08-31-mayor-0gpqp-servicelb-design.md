Bead: mayor-0gpqp

# u7s ServiceLB: feature set and architecture design proposal

## Verdict

Build a fixed klipper-lb-alike: same shell dataplane script (install DNAT
rules once, idle forever, kernel forwards), same per-Service DaemonSet
fan-out model, one bug fixed (conditional MASQUERADE instead of
unconditional). The controller that watches Services and manages
DaemonSets/IP-status should be a new embedded task inside `u7s-apiserver`
(same shape as the existing `--embedded-scheduler`), not a KCM patch (KCM is
vendored unmodified upstream and already has `-service-lb-controller`
disabled in `install.sh` as a breadcrumb for this) and not shell (a
long-lived watch+reconcile loop is a poor fit for shell; the dataplane's
one-shot install script is fine as shell precisely because it has no watch
loop). IP allocation model: the node's-own-address model (klipper/k3s
default), not a MetalLB-style pool — u7s's target topology has no L2/ARP
domain and no BGP peer, and provider IPv6 prefixes are already statically
pinned to one node each, so a floating-VIP pool has nothing to allocate
*from*. The two things that don't exist in klipper-lb today and must be
added: (1) omit `MASQUERADE` when it isn't needed, verified for both TCP and
UDP; (2) an opt-in node-selector default (reuse k3s's `enablelb`-label
mechanism) so a Service's ingress-IP list doesn't include unreachable
addresses from this cluster's genuinely heterogeneous per-node reachability
domains (public Linode IPv4/IPv6, IPv6-only Scaleway, Tailscale-only home
node).

This elaborates `ai/findings/legacy/cni-svclb-landscape-2026-08-25.md`'s
Service LoadBalancer section, which already made the loxilb/MetalLB/kube-vip
rejection calls — not relitigated here.

## Layering: where ServiceLB sits relative to kube-proxy

u7s runs real upstream kube-proxy in IPVS mode (`bd recall
u7s-runs-upstream-kube-proxy-ipvs-and-crio-bridge-cni`). ServiceLB does not
replace or duplicate kube-proxy's Service-routing logic; it sits **in front
of** it, solving the one problem kube-proxy cannot: kube-proxy has no
mechanism to bind a `LoadBalancer` Service's externally-facing IP:port at
all — it only programs `ClusterIP`/`NodePort` rules. ServiceLB's DNAT rule
does exactly one thing: redirect the external-facing hostPort to a target
that kube-proxy already knows how to handle correctly:

- **`externalTrafficPolicy: Cluster`** → DNAT to the Service's `ClusterIP`.
  kube-proxy's existing IPVS rules then load-balance across every ready
  endpoint cluster-wide. Source IP is not preserved here — that's upstream
  Kubernetes semantics for `Cluster` policy, not a defect to fix.
- **`externalTrafficPolicy: Local`** → DNAT to the *same node's own*
  `NodeIP:NodePort`. kube-proxy's own Local-policy NodePort rules already
  restrict forwarding to that node's local ready endpoints only and already
  preserve source IP correctly (this is a real, already-tested kube-proxy
  guarantee) — ServiceLB doesn't need to reimplement Local-policy semantics,
  only route to a node kube-proxy has confirmed has a ready local endpoint
  (see "Backend/endpoint readiness" below).

ServiceLB owns zero backend-selection logic. Confirmed directly in k3s's
`newDaemonSet` (`k3s-io/k3s pkg/cloudprovider/servicelb.go`, fetched
2026-08-31): `Cluster`-policy containers get `DEST_IPS=<ClusterIPs>`,
`Local`-policy containers get `DEST_IPS=$(status.hostIPs)` (the pod's own
downward-API host IP, i.e. hairpin to this same node) with `DEST_PORT` set
to the Service's `NodePort`, not its target port.

## Feature set

| Feature | Required? | Rationale |
|---|---|---|
| `type=LoadBalancer` external-IP assignment + `status.loadBalancer.ingress` | **MUST** | Headline function; `kubectl get svc` EXTERNAL-IP and LB-status-gated conformance tests depend on it. |
| Source-IP preservation, `externalTrafficPolicy: Local`, **TCP** | **MUST** | The one known klipper-lb defect this bead exists to fix. |
| Source-IP preservation, `externalTrafficPolicy: Local`, **UDP** | **MUST** | Operator's own split-horizon-DNS incident proved the MASQUERADE bug is not TCP/HTTP-specific — a fix that only tests TCP doesn't verify the actual regression. |
| QUIC/HTTP3 UDP flow affinity (same 4-tuple → same backend for connection lifetime) | **MUST verify**, no new mechanism | Falls out of conntrack once DNAT dataplane is in place (a UDP 4-tuple pins to one DNAT target on first packet, for the conntrack entry's lifetime) — independently corroborated by `kubernetes-retired/blixt` switching XDP→TC specifically for conntrack access. Confirm empirically per project discipline ("confirm, don't assume"); do not add bespoke flow-pinning logic if conntrack already provides it. |
| `externalTrafficPolicy: Cluster` | **MUST** | Default policy; already the trivial DNAT-to-ClusterIP path, source-IP loss here is upstream-correct behavior, not a bug. |
| `externalTrafficPolicy: Local` | **MUST** | Correctness-load-bearing — see MASQUERADE fix above. |
| Protocol: TCP | **MUST** | Baseline. |
| Protocol: UDP | **MUST** | Baseline; also the QUIC/DNS use cases above depend on it. |
| Protocol: SCTP | **Open question, leaning WON'T for v1** | `iptables -p sctp` mechanically works if `nf_conntrack_proto_sctp` is loaded, so it's cheap to wire through the same `DEST_PROTO` templating — but no cited operator use case, and this doc found no confirmation of how much conformance weight it carries at u7s's certification target. Don't decide silently — see Open Questions. |
| IP allocation: node's-own-address model (klipper/k3s default) | **MUST**, recommended default | See dedicated section below — the only model that fits a no-L2/no-BGP, provider-pinned-IP topology without new infrastructure. |
| IP allocation: pool-based VIP (MetalLB-alike) | **WON'T** | Already ruled out by the landscape doc for this topology (no shared L2 domain, no BGP peer) — not relitigated. |
| Opt-in node selection for which nodes host a Service's DaemonSet pod (k3s's `enablelb` node-label pattern) | **SHOULD, likely promotes to MUST** | Without it, every LB Service's ingress list includes every node running a pod — including nodes whose address is meaningless to an external client (e.g. the home node's private LAN IP, or a Scaleway node's IPv6 when a client only wants the Linode IPv4 front door). Needs testing against the real 5-node topology to confirm it's load-bearing rather than cosmetic. |
| IPv6 support | **MUST** | 3 of 5 target nodes are IPv6-only. Already present in klipper-lb's `entry` script unmodified (mirrored `ip6tables` rules, per-family sysctl toggling, `IPFamilies`-ordered address selection in `filterByIPFamily`) — this is verification work, not new engineering. |
| Dual-stack Services | **SHOULD** | Same mechanism as IPv6 above; needs explicit test on a real dual-stack Service, not assumed from IPv6-only coverage. |
| Multi-node fan-out (DaemonSet-based) | **MUST**, preserve install-once-then-idle | See footprint correction below — this is the property that keeps fan-out near-free; do not reintroduce a persistent per-instance proxy loop. |
| Backend/endpoint readiness tracking | **MUST delegate to kube-proxy/EndpointSlice**, not reimplement | ServiceLB's only readiness-sensitive decision is *which nodes* qualify as `Local`-policy ingress-IP candidates (has this node got a ready local endpoint, per EndpointSlice) — it does not itself select which pod receives a given connection; that's kube-proxy's job end to end (see Layering section). |
| Bundling: manifest + externally-editable image tag, not `include_bytes!` | **MUST** | Matches the already-Accepted `docs/decisions/upstream-component-shipping-shape.md` (kube-proxy: "not vendored as a host binary… ships as an in-cluster DaemonSet manifest") and `docs/decisions/well-known-manifest-folder.md`. See Architecture section for the two-layer nuance this component needs beyond a flat static manifest. |
| `loadBalancerSourceRanges` (client-IP allow-list) | **SHOULD** | klipper-lb's `entry` script already implements this (`SRC_RANGES` → `iptables -I FORWARD -s <range> ... -j ACCEPT`); free to keep. |
| PROXY protocol v2 | **WON'T (v1)** | Already flagged as an open MetalLB/kube-vip gap in the landscape doc; klipper-lb has no support either. No cited need yet. |
| BGP / L2 (ARP) announcement modes | **WON'T** | Landscape doc already disqualified both for this topology (no shared L2, no BGP peer offered on the standard product tier). |
| Gateway API surface | **WON'T (v1)** | Traefik already serves L7; a dedicated Gateway API LB (e.g. loxilb's mode) was already ruled out on functional-gap and component-count grounds in the landscape doc. |

## Architecture proposal

### Dataplane: shell script, install-once-then-idle (unchanged shape)

Fork `k3s-io/klipper-lb`'s `entry` script (fetched 2026-08-31,
`k3s-io/klipper-lb@master`, sub-100 lines). Confirmed mechanism:

1. Detect `iptables` nft vs. legacy mode (`lsmod | grep nf_tables`), symlink
   the right backend.
2. For each `SRC_RANGES` entry, insert a `FORWARD` `ACCEPT` rule scoped to
   `DEST_PROTO`/`DEST_PORT` (the `loadBalancerSourceRanges` allow-list).
3. For each `DEST_IPS` entry (comma-separated, one per address family):
   `FORWARD ... -j DROP` (default-deny past this point), `PREROUTING -j DNAT
   --to <dest_ip>:<dest_port>`, then **unconditionally**
   `POSTROUTING -d <dest_ip> -j MASQUERADE`.
4. `mkfifo /pause` and block forever — no persistent proxy loop; the kernel
   does all subsequent packet forwarding via the installed rules and
   conntrack. This is the ~92KB-RSS, install-once-then-idle property
   confirmed by the operator on a live instance and explicitly the design
   property to preserve, not an incidental measurement.

**The one bug, confirmed unfixed upstream** (checked commit history on
`entry` back to its initial commit — the closest related fix,
`63942dfa "Fix iptables filtering rules when externalTrafficPolicy is
Local"`, only touched the FORWARD/ACCEPT rules, not the MASQUERADE line):
step 3's `MASQUERADE` runs for every `DEST_IPS` target regardless of
`externalTrafficPolicy`, unconditionally rewriting the packet's source
address to the ServiceLB pod's own (overlay) IP before the packet reaches
either the `ClusterIP` (Cluster policy) or the local `NodePort` (Local
policy) — the backend never sees the real client address.

**The fix**: MASQUERADE exists to keep the return path symmetric when the
post-DNAT destination isn't reachable via a route that would naturally
retrace through this same interface. For both DNAT targets ServiceLB
actually uses — the Service's own `ClusterIP` (return traffic already
retraces via conntrack's automatic un-DNAT, since the ClusterIP is a
virtual address kube-proxy already handles symmetrically) and the local
node's own `NodeIP:NodePort` (a same-host hairpin) — MASQUERADE is not
needed for correctness, only for the (already narrow) case it was
presumably copied in for defensively. Omit the `POSTROUTING ... -j
MASQUERADE` line for these two DNAT targets; conntrack's own state handles
the return path. This needs to be verified live against a real backend for
both TCP and UDP before being treated as done — this doc is not claiming
that verification, only the mechanism.

**Footprint correction versus the landscape doc's rough phrasing.**
Re-reading the primary source (current k3s `main`) rather than paraphrasing:
it is **not** "one DaemonSet per Service per protocol" — it's **one
DaemonSet per Service**, with **one container per declared port** inside
that DaemonSet's pod spec (a Service exposing TCP/80 and UDP/53 gets one pod
with two sibling containers, each running its own `entry` instance). The
"kernel does all subsequent work, marginal cost stays near-zero" conclusion
is unaffected — footprint is still ~92KB RSS × (ports across all
`LoadBalancer` Services, TCP and UDP counted separately) × nodes hosting a
pod — but the accounting unit is per-port-container, not per-protocol-
DaemonSet. Flagging per Rule 7 (surface conflicts, don't blend them): the
landscape doc's phrasing should be treated as superseded by this fetched
source, not averaged with it.

### Controller: embedded task in `u7s-apiserver`, not KCM, not shell

Something has to: watch `Services`/`Nodes`/`EndpointSlices`/`Pods`, create
one DaemonSet per `LoadBalancer` Service (with the containers/env described
above), and patch `status.loadBalancer.ingress` when the set of qualifying
node addresses changes. Three real candidates, in the order the code
already points to:

1. **KCM (upstream Go, unmodified)** — ruled out structurally, not by
   preference. `scripts/install.sh`'s `u7s-kcm.service` already passes
   `--controllers=*,...,-service-lb-controller,...` — **the in-tree
   controller is already disabled**, a breadcrumb that this integration
   point was deliberately left for something else. `install.sh` states
   explicitly (line 26): "u7s's kube-controller-manager is unmodified
   upstream" — u7s does not carry KCM source to patch, and upstream's
   in-tree cloud-provider interface this controller depended on was removed
   from core components in favor of an out-of-tree cloud-controller-manager
   pattern years before 1.36.4 regardless.
2. **A standalone shell component** — ruled out for the controller
   specifically (the dataplane script stays shell). A correct controller
   needs list+watch semantics, resourceVersion tracking, and a
   deduplicating work queue (k3s's own comment on this: "we don't need the
   full overhead of a wrangler service controller… but we do want to run
   changes through a keyed queue to reduce thrashing") — the dataplane
   script's shell-appropriateness comes specifically from having *none* of
   that: it installs rules once and never touches the API again. The
   controller's job is categorically continuous reconciliation against a
   live API, a poor fit for shell.
3. **A new embedded task inside `u7s-apiserver`** — recommended. u7s
   already has the precedent: `u7s-apiserver --embedded-scheduler true`
   runs the scheduler's own watch/schedule loop in-process
   (`crates/scheduler/src/lib.rs`: `run_scheduler` is "callable directly"
   specifically so `u7s-apiserver`'s `--embedded-scheduler` task can call it
   without a second process). The same shape — `run_servicelb_controller` as
   a library function, gated by a new `--embedded-servicelb` flag — avoids
   a fourth long-running component (no new systemd unit, no new binary in
   the release tarball), and keeps "Rust-owned control-plane logic that
   isn't upstream Go" in one place rather than two. This is a recommendation,
   not a foreclosed decision — flagged again in Open Questions since the
   task specifically calls for the trade-off to reach the operator.

### Bundling: two layers, not one flat manifest

The existing well-known-folder mechanism
(`docs/decisions/well-known-manifest-folder.md`) unconditionally re-applies
every file in `manifests/` at every apiserver boot — correct for *static*
resources (CoreDNS, Flannel, kube-proxy), but a `LoadBalancer` Service's
DaemonSet is inherently dynamic: one is created/updated/deleted per Service,
not known at manifest-authoring time. Two layers follow from that:

- **Static layer** (well-known-folder, `manifests/servicelb.yaml`): the
  `svclb` `Namespace`, `ServiceAccount`, minimal RBAC for the controller,
  and a `ConfigMap` holding the dataplane image reference (e.g.
  `ghcr.io/<org>/u7s-svclb:v__SVCLB_VERSION__`, install-time-templated the
  same way `kube-proxy.yaml`'s `__KUBE_VERSION__` is). This is what makes a
  CVE patch a `ConfigMap` edit + reconcile, not a controller rebuild —
  matching the landscape doc's stated bar ("does it have a genuine
  version-skew dependency on u7s's own API version? If not, ship it the way
  kube-proxy is shipped"). The image tag must live here, in the
  externally-editable `ConfigMap`, **not** as a string literal in the
  controller's Rust source — hardcoding it there would just relocate the
  same `include_bytes!`-style CVE-patch-requires-rebuild problem from a YAML
  blob into a Rust constant.
- **Dynamic layer** (the embedded controller, at runtime): reads that
  `ConfigMap` for the current image tag, then creates/updates/deletes the
  per-Service `DaemonSet` objects live via the apiserver's own in-process
  client — mirroring exactly what k3s's `deployDaemonSet`/`deleteDaemonSet`
  do today, just in Rust instead of Go.

## Open questions for the operator

- **IP allocation model, sub-decision: default node-selection scope.**
  Node's-own-address (klipper/k3s model, recommended) is the only viable
  top-level model for this topology — but *which* nodes host a given
  Service's DaemonSet pod by default is a real choice: fan out to every
  node (simplest, but reports unreachable addresses for nodes outside a
  given client's reachability domain — e.g. the home node's LAN-only IP),
  vs. opt-in only via a node label (k3s's `enablelb`, safer default for this
  specific 5-node heterogeneous topology, more setup). Recommend opt-in as
  the default; needs operator sign-off since it changes out-of-box UX.
- **Controller placement: embed in `u7s-apiserver` (recommended above) vs. a
  standalone Rust binary/systemd unit.** Embedding reuses the
  `--embedded-scheduler` precedent and avoids a fourth component; a
  standalone binary would isolate a controller crash/panic from the
  apiserver's own request-serving path, at the cost of a new
  binary+systemd-unit+RBAC-identity to provision (the `--join`/CSR path
  every other node-side component already goes through). Trade-off is
  blast-radius isolation vs. component count — pick one before
  implementation starts.
- **Protocol scope: is SCTP in scope for v1?** Mechanically cheap
  (`DEST_PROTO=SCTP` through the same iptables templating) but has zero
  cited operator use case and unconfirmed weight in u7s's actual conformance
  target. Leaning WON'T; confirm rather than silently drop it.
- **Fork-klipper-shell-verbatim vs. reimplement the dataplane script from
  scratch.** Forking preserves a script that's already field-tested at
  scale (real k3s/RKE2 installs) with only one known, well-understood
  defect; reimplementing from scratch risks reintroducing subtler bugs the
  original already worked through (nft-vs-legacy detection, IPv6 sysctl
  gating, comma-separated multi-`DEST_IPS` support). Recommend forking, not
  rewriting — but this determines licensing/attribution handling
  (klipper-lb is Apache-2.0) and is worth an explicit operator call before
  work starts.
- **IPv6/dual-stack: v1 scope or a fast-follow?** The mechanism already
  exists unmodified in the fork target and needs verification effort, not
  new engineering — but "verification effort" still has to be scheduled
  against the 3 IPv6-only Scaleway nodes specifically, which this doc has
  not measured.
- **Opt-in node-selector labeling scheme: reuse k3s's exact label names
  (`svccontroller.k3s.cattle.io/enablelb` etc.) or mint u7s-native
  equivalents?** Reusing k3s's names costs nothing extra and is a smaller
  diff against the forked script/controller; minting u7s-native names avoids
  a stray `k3s`-branded label surviving in a project with no other k3s
  dependency. Low-stakes but visible in `kubectl get nodes --show-labels`
  output, worth a deliberate pick rather than an accidental one.

## Non-goals / v1 cuts

- **BGP announcement mode** — no BGP peer available on the standard product
  tier for either target cloud provider (landscape doc, "Provider IPv6 pools
  are statically routed, not BGP-gated" section); nothing to peer with.
- **L2/ARP announcement mode** — this topology has no shared broadcast
  domain across nodes (WAN + Tailscale mesh, not a LAN); MetalLB/kube-vip
  were already ruled out on exactly this ground.
- **PROXY protocol v2** — no cited need; both MetalLB and kube-vip have
  open/closed-unimplemented issues for it, and klipper-lb has never had it.
  loxilb was the only surveyed candidate with real support, and loxilb is
  disqualified outright (can't start on a 1GB node).
- **Gateway API surface at the LB layer** — Traefik already owns L7; a
  dedicated Gateway API implementation at the L4 LB layer was evaluated via
  loxilb's Gateway-API mode and rejected on functional-gap and
  component-count grounds in the landscape doc, not revisited here.
- **A real cloud-provider IP pool / floating VIP mechanism** — nothing to
  build against; both target providers pin an IPv6 prefix to exactly one
  instance at the network layer, with no shared/poolable multi-instance
  product currently available (Linode's former shareable /116 pool is
  deprecated).
- **Multi-replica QUIC connection-migration/Connection-ID-aware routing
  across multiple Traefik replicas** — not a concern at this cluster's
  scale (single Traefik instance); conntrack-based 4-tuple pinning is
  sufficient for the actual topology.

## References

- `ai/findings/legacy/cni-svclb-landscape-2026-08-25.md` — prior research;
  this doc elaborates its Service LoadBalancer, "u7s core vs
  operator-deployed", and bundling sections, does not relitigate them.
- `k3s-io/klipper-lb@master`, `entry` — fetched 2026-08-31 via `gh api`,
  saved to `temp/research/klipper-lb-entry.sh` (not committed; scratch
  research only).
- `k3s-io/k3s@main`, `pkg/cloudprovider/servicelb.go` — fetched 2026-08-31,
  saved to `temp/research/k3s-servicelb.go` (not committed; scratch research
  only).
- `docs/decisions/well-known-manifest-folder.md`,
  `docs/decisions/upstream-component-shipping-shape.md` — existing Accepted
  ADRs this proposal builds on rather than reopens.
- `crates/scheduler/src/lib.rs`, `scripts/install.sh` (`u7s-apiserver`'s
  `--embedded-scheduler` flag; `u7s-kcm.service`'s `--controllers=` flag) —
  grounding for the controller-placement recommendation.
- `bd recall u7s-runs-upstream-kube-proxy-ipvs-and-crio-bridge-cni`.

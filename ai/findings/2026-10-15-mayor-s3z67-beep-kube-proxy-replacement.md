# beep as u7s's kube-proxy replacement

Bead: mayor-s3z67 (research, read-only; no code changed)
Date: 2026-10-15

**Answer: feasible but not close — beep today covers none of the east-west
contract (it only owns north-south LoadBalancer fronts on the uplink NIC), so
replacing kube-proxy means building a second dataplane mode (pod-originated
ClusterIP/NodePort), worth roughly 9-12 MB PSS per node versus
kube-proxy-only and 20-23 MB versus kube-proxy+beep; recommend a gated spike
(Phases 0-1) and no commitment to the default flip until Conformance parity is
measured with kube-proxy absent, including the host-apiserver -> webhook /
aggregated-Service path (~25 specs), which today rides kube-proxy via the
konnectivity agent pod.**

Stale premises in the bead (checked, not assumed):

- "beep programs exactly ONE endpoint per front (reconcile.rs:471)" is true of
  the v0.4.0 tag (`1a71f52`) only. `main` (2026-10-14) already has multi-endpoint
  selection: `controller/src/reconcile.rs` slots N endpoints with
  `local_count`, tests assert "FRONT_META must publish count 4 / local_count 2",
  and beep epic `beep-5lw` closed 2026-10-14 (commit `#261`). It is in
  CHANGELOG `[Unreleased]`, untagged.
- `bd recall kube-proxy-mode-rig-ipvs-vs-shipped-iptables` is stale: the rig now
  runs iptables (`scripts/conformance/lima-start.sh:694,784` `mode: iptables`),
  matching `manifests/kube-proxy.yaml:54`. Corrected statement for the memory:
rig and shipped are both iptables; IPVS was rig-only and has been removed; the
nf_tables-lacks-extensions belief was refuted by mayor-8g7f6.
- beep's own doc states IPVS mode is unsupported (`docs/design/kube-proxy-coexistence.md`)
  because beep publishes every node's IP into `status.loadBalancer.ingress[]`
  and IPVS binds them to `kube-ipvs0`. Moot once kube-proxy is gone.

## 1. Contract x coverage

Sources: kubernetes `release-1.37` `test/e2e/network/*.go` and
`test/conformance/testdata/conformance.yaml` (cached in `temp/research/k8s/`),
beep `main` docs/code (cached in `temp/research/beep/`). "C" = Conformance-tagged
(`framework.ConformanceIt`). Line numbers are release-1.37 `service.go` unless
stated. beep status = `main`, not v0.4.0. Gap: S (days), M (1-2 weeks), L (new
subsystem).

| Feature | Upstream specs | C? | beep today | Gap |
|---|---|---|---|---|
| ClusterIP east-west (pod->svc, node->svc, hairpin-free) | `networking.go` "pod-Service/node-Service/endpoint-Service http/udp" (147-263); DNS conformance specs (all pods dial CoreDNS ClusterIP 10.96.0.10); in-cluster clients use `kubernetes.default` 10.96.0.1 | DNS and any pod using in-cluster config: yes (indirectly); the pod-Service specs: no | None. Fronts are node-IP:port on the uplink tc hook; ClusterIP "never written to beep's front map" (`kube-proxy-coexistence.md`). No hook sees pod-originated traffic | **L** |
| `kubernetes` Service -> host apiserver (u7s-specific) | no upstream spec; every e2e pod and sonobuoy depend on it | implicitly | None. Backend is a host address (patched EndpointSlice), not a pod. beep admits host IPs only via `ep.node_addrs.contains(pod_ip)` (`reconcile.rs` `is_admitted`); beep's own kubeconfig must use the real host IP (same bootstrap deadlock `manifests/kube-proxy.yaml:14-20` describes) | M |
| NodePort | 1287 "functioning NodePort service"; 1462/1540 type changes; 2266/2288 NodePort affinity; `networking.go` 360-391; `conntrack.go` NodePort UDP | yes (4+) | None. Front model is node address + service port, not nodePort range on all node IPs | M |
| sessionAffinity ClientIP (+timeout) | 2229, 2251 (ClusterIP), 2266, 2288 (NodePort); timeout variants 2235, 2272 | yes (4); timeout variants no | Not read: `reconcile.rs` has no `sessionAffinity`. beep's pin is per-flow 5-tuple (LRU), "held vacuously" in re973. ClientIP affinity with a 10800s default timeout is a different table | M |
| externalIPs | 1313 "connect via ExternalIP not assigned to a node" | no | Not read (no `externalIPs` in `reconcile.rs`) | S-M |
| externalTrafficPolicy Local/Cluster | 2778, 2830, 3080, 3156, 3840; `loadbalancer.go` 1016-1221 | no | Implemented for LB fronts (local-only slots, serving-terminating fallback, matches `CategorizeEndpoints`). Preserves client IP, kube-proxy SNATs on Cluster | S (NodePort variant rides on NodePort work) |
| healthCheckNodePort | 2830, 3840; `loadbalancer.go` 1081-1174 | no | "not served by beep" (`ebpf-lb-dataplane.md`) | M (small HTTP listener) |
| internalTrafficPolicy Local | 2529, 2598, 2669, 3001 | no | None (nearest analogue: `trafficDistribution: PreferSameNode`) | S once ClusterIP exists |
| trafficDistribution / topology hints | `traffic_distribution.go` (6 specs), `topology_hints.go` | no (feature-gated) | `trafficDistribution` handled for LB; EndpointSlice hints deliberately ignored | S |
| Terminating/serving fallback | 2927, 3001, 3080, 3156 | no | Handled for eTP Local; Cluster fallback to terminating-when-no-ready not implemented (ready+non-terminating only) | S |
| publishNotReadyAddresses | 1792, 1948, 2068 | no | Not read | S |
| No-endpoint REJECT | 2419, 2464 ("rejected when no endpoints exist") | no | Silent drop (count 0); beep roadmap has RST/ICMP in flight (`beep-5lw.5`) | S |
| Same port, different protocols | 3586 (C), 3708 | yes (1) | Key includes proto | S |
| Hairpin / src pod IP preserved via ClusterIP | 1095, 1020; `no_snat.go` | no | None | M (trivial with socket-LB, hard with per-packet DNAT) |
| UDP conntrack hygiene on endpoint churn | `conntrack.go` (7 specs), `loadbalancer.go` 707, 841 | no | Own LRU `FLOW_TABLE` with eviction on endpoint removal; remote-backend sweep (`beep-eto0`, `beep-b6qw`) fixed by beep PR #200 (merged 2026-10-09T06:18Z, in v0.4.0); restart-orphan sweep `beep-e28g` fixed by PR #209 (merged 2026-10-09T08:05Z, in v0.4.0; follow-ups `beep-tlbt` on main). Residual unverified: whether any new beep bead is open for a remote pod reusing an IP while the controller is down (beep's tracker was not read) | S (verify) |
| Dual-stack | `dual_stack.go` (~30 specs) | no | Dual-stack LB fronts, IPv6-only nodes validated on Lima k3s; real-fleet pending (`beep-7qm`) | S (LB), M (ClusterIP) |
| service-proxy-name / headless labels | 2294, 2345 | no | Not read | S |
| kube-proxy healthz/metrics | `networking.go` 132 "should check kube-proxy urls" (healthz :10256, `/proxyMode` :10249) | no | None | S (serve, or skip-list) |
| Restart resilience | 1207 "after restarting kube-proxy", 1240 apiserver (Disruptive) | no | Pinned maps survive restart (advantage) | S |
| SCTP | `networking.go` SCTP specs | no (feature) | TCP/UDP/QUIC only | Out of scope (Cilium also only partial) |
| loadBalancerSourceRanges | `loadbalancer.go` 422 | no (cloud) | n/a | Out of scope |
| localhost NodePort | `localhost_nodeports.go` | no (feature) | None | Out of scope |
| NodePort allocation/collision/range | 1575, 1629, 1696 | no | n/a: apiserver-side | none |
| hostPort | `hostport.go` (C) | yes | n/a: CNI portmap, not kube-proxy | none |

Reading the table: Conformance's dependence on the proxy is not narrow.
Counted from release-1.37 `conformance.yaml` (`temp/research/conformance.yaml`):
47 `[sig-network]` Conformance specs, of which Services 15, DNS 8, Proxy 3,
Networking Granular 4 (30 in those families) and the rest EndpointSlice 5,
EndpointsController 2, API-only specs. By reading the spec names:

- **Send traffic through a ClusterIP/NodePort/CoreDNS ClusterIP: ~16.**
  Services 9 (4 type changes, functioning NodePort, 4 sessionAffinity), DNS 7
  (every pod's resolv.conf nameserver is the CoreDNS ClusterIP; "/etc/hosts"
  does not query).
- **Need pod/host routing but not the Service proxy: 7.** Networking Granular
  4 (pod IPs directly) and Proxy 3 (the apiserver proxies to the resolved pod
  IP). They still need a working CNI and the host->pod path.
- **Control-plane-only (no dataplane): the remaining 24** (6 Services, 1 DNS,
  EndpointSlice, EndpointsController, Ingress/IngressClass, ServiceCIDR, etc.).
- **Host-apiserver -> webhook/aggregated Service: 25 specs**
  (22 AdmissionWebhook, 2 CustomResourceConversionWebhook, 1 Aggregator) in
  `[sig-api-machinery]`; see "Host apiserver -> ClusterIP path" below.

So ~16 + 25 = ~41 Conformance specs depend on the proxy dataplane (the
sig-network share alone is a third of the 47), plus every pod's path to
`10.96.0.1`. The non-Conformance sig-network set (which u7s's CI focus,
`460/460 + 2/2 disruptive`, partly exercises) is far wider. Parity on the
Conformance subset is achievable; correctness on the rest is what makes this
"a kube-proxy".

### Host apiserver -> ClusterIP path

Verdict: the apiserver never dials a ClusterIP itself. It is a host process
with no route to the service CIDR, so every Service-backed webhook and
aggregated APIService call goes out through the konnectivity HTTP CONNECT
proxy (`crates/apiserver/src/state.rs:1088` `reqwest::Proxy::all`, fed by
`konnectivity_proxy_addr`, `args.rs:100`). The URL is the Service DNS name
`https://{svc}.{ns}.svc:{svcPort}{path}` (`admission.rs:763-775`
`webhook_url`; `handlers/aggregation.rs:33`, `:110` for APIServices). The
konnectivity-agent runs as a non-hostNetwork Pod in kube-system
(`scripts/conformance/lima-start.sh:640-666`, `hostNetwork: false`), resolves
the name via CoreDNS (ClusterIP), and dials the ClusterIP; kube-proxy NATs
`ClusterIP:svcPort -> PodIP:targetPort` (`admission.rs:578-580`, `:749-751`).
u7s deliberately sends the Service port, not the target port, so that NAT is
required: it does not resolve EndpointSlices itself
(`handlers/aggregation.rs:33-40`). The 300 ms connect-retry budget
(`admission.rs:25-35`) exists to absorb kube-proxy's NAT-programming race.

What a kube-proxy-free node changes:
- The agent pod's DNS query (to the CoreDNS ClusterIP) and its connect to the
  webhook ClusterIP are both pod-originated, so both need the new east-west
  hook (socket-LB covers it; tc on the uplink does not). This is the same
  requirement as pod->`10.96.0.1`, but with the apiserver-visible failure mode
  of 25 specs failing with webhook/aggregator timeouts.
- The retry budget was tuned to iptables sync lag; beep's programming latency
  for a new ClusterIP front is unmeasured and must be checked against it
  (`WEBHOOK_CONNECT_RETRY_BACKOFFS_MS`, `admission.rs:35`), and the error
  matcher assumes kube-proxy-specific connection-refused semantics.
- The comments at `admission.rs:578`, `:749`, `:768` and `aggregation.rs:33`
  assert "kube-proxy NATs ClusterIP" and would need rewording when beep owns
  that translation.
- An alternative that removes the dependence: resolve Service -> EndpointSlice
  pod IPs inside the apiserver and dial them through konnectivity. That
  duplicates a proxy function in the apiserver and hits the target-port
  simplification noted in `aggregation.rs:35-40`; not recommended unless the
  socket-LB path fails G1.

**Core architectural gap.** beep's hooks are tc-bpf on the uplink NIC and
`geneve0` (4 attach points; `ebpf-lb-dataplane.md` "Hooks"). Pod->ClusterIP
leaves a pod veth and is DNATed pre-uplink; host processes reach ClusterIP via
the OUTPUT path. Neither crosses an uplink ingress hook. East-west therefore
needs a new attach point: cgroup `connect4/sendmsg4/recvmsg4/getpeername4`
(socket-LB) or tc on the CNI bridge/veths. Geneve is unnecessary for
east-west (flannel already routes pod CIDRs); the packet only needs DNAT
and a conntrack for replies.

## 2. Memory math

Inputs (measured): idle PSS per node, 947 MiB `MemTotal` VM
(`ai/extended-context/memory-management-state.md`, mayor-g0qp7): kube-proxy
23 MB, flanneld 21, stack 240; idle `MemAvailable` 462 MiB, thrash below
~150-200 MiB. Conformance RSS
(`temp/e2e/1014-1518-conformance/monitoring/rss.csv`, 2026-10-14T14:50Z-15:18Z,
mayor checkout): kube-proxy avg 46.2 MB (min 44.6, max 47.9) on lima-node-2
and 45.7 MB (43.8-46.4) on lima-node-3. beep v0.4.0: ~10-11 MiB RSS per node
(re973 round 5); beep design table: 6.9 MiB userspace + ~2.7 MiB kernel maps
= ~9.6 MiB (`ebpf-lb-dataplane.md`).

| Scenario | Per-node idle | Per-node under conformance |
|---|---|---|
| A. kube-proxy only (shipped today) | 23 MB PSS | ~46 MB RSS |
| B. kube-proxy + beep (LB shipped, no replacement) | ~33-34 MB | ~57 MB |
| C. beep-only, east-west added (estimate) | ~11-14 MB | ~15-20 MB (estimate) |

C is an estimate, not a measurement: it assumes ClusterIP fronts add rows to
the no-prealloc front maps (floor ~17 KiB + ~129 KiB, ~96-128 B/row) and the
controller already watches Services/EndpointSlices, so deltas are small; socket-LB
reverse maps add kernel memory (Cilium's `reverse_sk` maps are LRU and exhaust
under unconnected-UDP patterns, see section 3). Allow +2-4 MB headroom.

Net: C vs A saves ~9-12 MB PSS (1.0-1.3% of 947 MiB; ~2% of idle MemAvailable).
C vs B saves ~20-23 MB (2.1-2.4% of MemTotal, ~5% of idle MemAvailable). The
relevant baseline is B, since the operator decided beep ships as the service LB
regardless (mayor-da224 note, 2026-10-13). Caveat: PSS vs RSS are not
comparable (kube-proxy RSS is ~2x PSS because of shared text); only the idle
PSS row is apples-to-apples with beep's RSS (RSS >= PSS, so beep's figure is, if
anything, pessimistic).

Guardrails (north-star: CPU/disk must not be disproportionate):
- CPU: kube-proxy's measured cost is `syncProxyRules` 45-70 ms/event, ~1100
  events per conformance run, one vCPU. The `cpu_seconds_cumulative` column in
  rss.csv reads 2.00 s over 27 min for kube-proxy, but its resolution looks
  coarse (0.00 -> 2.00); not reliable. eBPF removes O(rules) iptables rewrites
  but beep's per-event reconcile CPU for ClusterIP is unmeasured. Unmeasured.
- Disk: dropping the kube-proxy image/binary offsets beep's image; sizes not
  measured. Unmeasured.
- Data-path CPU: socket-LB translates once per connect(), cheaper than per-packet
  conntrack/DNAT; per-packet tc DNAT is comparable to netfilter.

Verdict under the decision metric: saving ~2% of RAM per node is "meaningful"
only against B (a whole Go process removed), not against A. It is not a case
for a 1 GiB node surviving where it otherwise would not (the 80-pod burst
failure mode is ~1.7 MB/pod slab; 20 MB is ~12 pods).

## 3. Prior-art lessons

Fetched: Cilium `Documentation/network/kubernetes/kubeproxy-free.rst`
(`temp/research/cilium-kubeproxy-free.rst`). Not fetched (no usable doc path
via `gh api` for Calico's mdx tree): Calico eBPF and kube-router claims below
are from beep's own landscape doc or from memory and are marked.

- **Cilium: replacement = socket-LB first.** "Cilium's kube-proxy replacement
  depends on the socket-LB feature" (cgroup connect hooks). Per-connection
  translation covers pod and host clients, hairpin, and preserves source IP.
  Costs it documents: connected UDP/TCP sockets keep targeting deleted
  backends, so it force-terminates sockets (`CONFIG_INET_DIAG_DESTROY`
  kernel options); `reverse_sk` LRU maps fill on unconnected UDP and make
  termination unreliable until reboot; NFS/SMB mounts to ClusterIPs broke
  without specific kernel patches; Istio/KubeVirt/Kata need
  `socketLB.hostNamespaceOnly`; SCTP only basic; hostPort and NodePort-range
  overlaps unsupported.
- **Cilium: per-packet shared-backend collisions.** Two VIPs/NodePorts to the
  same backend from the same client source port collide in conntrack ("highly
  recommended not to expose a backend via multiple VIPs", issues 11810/18632).
  beep's own design hit the same class (cross-Service reverse-key collision,
  `ebpf-lb-dataplane.md` "Backend reverse-flow key uniqueness").
- **Cilium: SNAT/masquerade port collisions** between BPF NodePort and
  iptables SNAT (issue 23604) — relevant because u7s runs flannel, which
  installs iptables masquerade rules.
- **Cilium: termination race.** Kubelet SIGTERM and EndpointSlice
  `Terminating` fire simultaneously; docs recommend `preStop` sleeps. Applies
  to any proxy, kube-proxy included; beep already excludes terminating from
  new flows.
- **Footprint reality check.** beep's landscape doc rejects Cilium as CNI
  (~180-450 MB, multi-GB step-growth reports `cilium/cilium#37935`, `#37629`,
  `#44310`) and kube-router (unresolved multi-GB leak, `#795`), and
  disqualified loxilb (ENOMEM on 1 GiB). The lesson for beep: preallocated
  map ceilings are the failure mode on a 1 GiB node; keep front maps
  no-prealloc and cap flow tables.
- **Calico eBPF (from memory, unverified here):** requires its own dataplane
  mode with kube-proxy disabled or `kubeProxyHealthzPort`-compatible
  coexistence, and a connect-time load balancer for host-originated traffic.
  Same two-path shape as Cilium (socket-LB for local, tc for external).

Common design: a connect-time hook for local clients plus a packet-time hook
for external NodePort. beep has only the second.

## 4. Integration shape

- **Shipping.** beep stays a separate DaemonSet (`deploy/daemonset.yaml`,
  `CAP_BPF`/`CAP_NET_ADMIN`, hostNetwork, pinned maps under `/sys/fs/bpf`),
  built from the beep repo and consumed by u7s as an owned dependency (policy:
  re-evaluate on each release). This **conflicts** with the one-line
  consequence in `docs/decisions/upstream-component-shipping-shape.md`
  ("A future native kube-proxy folds into u7s's own binary") and with the
  2026-09-08 split into `litehop/beep`. Decision 5 below.
- **Install flag.** `scripts/install.sh` gains a proxy selector
  (`kube-proxy|beep`); `manifests/kube-proxy.yaml` stays, a beep manifest
  joins it in the well-known manifest folder, with the same `__IFACE_IP__`
  trick (beep's kubeconfig must target the host apiserver, not 10.96.0.1).
- **Open prerequisite to verify.** `lima-start.sh:691-694` documents that
  hostNetwork pods in u7s hit a podIPs patch-accumulation sandbox loop, which
  is why the rig runs kube-proxy as a systemd unit. beep ran as a real
  DaemonSet on u7s in re973 round 5, so it works at least on that rig, but the
  kube-proxy-vs-DaemonSet split in the rig has not been reconciled.
- **Kernel floor.** beep needs Linux >= 6.6 (TCX); the README says so. Ubuntu
  24.04 (6.8) is fine; older kernels cannot run beep-only mode.
- **Interactions to test:** flannel iptables masquerade rules, kube-network-policies
  (NFQUEUE; `netpol` appears in rss.csv) seeing pre- or post-DNAT addresses,
  CRI-O/crun cgroup attach point for socket-LB (root cgroup v2 hook covers
  descendants).
- **Rig with kube-proxy removed.** Add a lane that skips the kube-proxy
  systemd unit (`lima-start.sh` ~line 691-905) and asserts absence of the
  process and `KUBE-SERVICES` chain; run full certified-conformance, the CI
  e2e-focus set and the disruptive pair on it. Add an informational
  non-Conformance `[sig-network]` lane with an explicit expected-skip list
  (SCTP, localhost NodePort, cloud-LB specs, kube-proxy URL spec unless served).

## 5. Phased plan with gates

| Phase | Work | Lands in | Go/no-go gate |
|---|---|---|---|
| 0 | Re-evaluate beep on its next release (mayor-da224): tag a release containing multi-endpoint, multi-endpoint affinity test, churn round (scale/rolling/drain), image built from tag. `beep-eto0`/`beep-b6qw`/`beep-e28g` already shipped in v0.4.0: verify-only (re-run the churn round; check beep's tracker for any open remote-IP-reuse-while-controller-down bead). | beep (release), u7s (rig run, existing bead) | G0: happy-path plus N-endpoint affinity plus churn green on shipped flannel+iptables; image digest verified |
| 1 | East-west spike: ADR choosing socket-LB vs veth-tc; prototype ClusterIP DNAT for pod and host clients on Lima; measure RSS and reconcile CPU | beep | G1: pod->ClusterIP works incl. 10.96.0.1->host apiserver; beep total <= ~15 MiB RSS+maps with ClusterIP fronts for 100 Services; no kube-proxy needed for CoreDNS lookups; a Service-backed webhook and an aggregated APIService (sample-apiserver) are reachable from the host apiserver via konnectivity-agent with kube-proxy absent, within the apiserver's connect-retry budget |
| 2 | Contract build-out behind a flag: ClusterIP, NodePort, sessionAffinity ClientIP+timeout, internalTrafficPolicy, publishNotReady, REJECT on no-endpoints, service-proxy-name, healthz/proxyMode, UDP stale-flow hygiene | beep | G2: beep-side smoke covers each table row marked S/M; no open P1 dataplane bugs in beep's tracker (checked at G2, not assumed) |
| 3 | u7s integration: install flag, beep manifest, rig lane with kube-proxy absent, memory harness comparison | u7s | G3: full sonobuoy Conformance + e2e-focus + disruptive green on kube-proxy-less lane, repeated (3 consecutive runs), measured memory delta >= ~15 MB vs B on the rss.csv harness, no CPU regression. A Conformance regression stops the phase |
| 4 | Default flip; keep kube-proxy path one release, then delete it | u7s | G4: no operator-reported regressions over a release; kernel floor documented |

Total honest effort: Phases 1-2 are weeks of beep work; Phase 0 is already
queued and, with the beep P1s shipped, is now a release plus verification. The memory case is decided at G1, before the large spend.

## 6. Operator decisions

1. **Pursue replacement at all?** (a) Stop at LB-only: beep north-south,
   kube-proxy stays (zero Conformance risk, no savings). (b) Pursue phased.
   Recommend (b), but commit only to Phases 0-1; decide on Phase 2 at G1 with
   measured numbers, since the win (~20-23 MB vs B) is real but ~2% of RAM, while ~41 Conformance
   specs (~16 sig-network plus ~25 webhook/aggregator) ride the proxy dataplane.
2. **East-west hook.** (a) cgroup socket-LB: no per-packet conntrack, hairpin
   and source IP free, matches Cilium; cost is stale-socket handling and
   INET_DIAG kernel config. (b) tc on veth/cni0: reuses beep's tc code, but
   needs reverse conntrack and hairpin handling. Recommend (a) for
   pod/host-originated traffic plus the existing uplink tc path for external
   NodePort.
3. **Client-IP semantics for NodePort/Cluster.** beep preserves the client IP;
   kube-proxy SNATs on Cluster policy. Recommend keeping preservation (it is
   beep's differentiator) and treating `source pod IP preserved` non-Conformance
   specs as expected-pass.
4. **Documented unsupported list.** SCTP, loadBalancerSourceRanges, localhost
   NodePort, IPVS coexistence; healthCheckNodePort and `/healthz`/`/proxyMode`
   either served (small) or on the lane's skip-list. Recommend skip-list first,
   serve only if a test or user needs it.
5. **Where it lives.** Keep beep a separate repo and DaemonSet (matches the
   2026-09-08 split) and amend the shipping-shape ADR, versus folding it into
   the u7s binary as that ADR anticipated. Recommend separate: eBPF maps are
   node-local, needs CAP_BPF, and the apiserver is a host systemd unit.
6. **Fallback policy.** Keep `kube-proxy` selectable through Phases 3-4, then
   delete (greenfield stance). Recommend yes, time-boxed to one release.
7. **Kernel floor.** Accept Linux >= 6.6 plus cgroup v2 for beep-only mode, or
   keep kube-proxy as the supported path on older kernels. Recommend accept
   and enforce at install with a clear error.
8. **Host-apiserver -> Service path.** Keep konnectivity-agent + Service DNS
   (needs the east-west hook for the agent pod), versus resolving EndpointSlices
   in the apiserver. Recommend keep, gated at G1 (see section 1); re-word the
   "kube-proxy NATs" comments and re-check the connect-retry budget at G3.
9. **Image provenance.** Build beep from the tag in u7s's release pipeline (or
   verify digest) instead of consuming `docker.io/valerauko/beep-lb`. Recommend
   build from tag (open item from mayor-da224).

## Evidence not collected

- Calico eBPF docs were not fetched; claims are marked.
- No live measurement of beep with ClusterIP fronts exists; scenario C memory is
  an estimate.
- kube-proxy CPU from rss.csv is too coarse to use.
- `main`'s multi-endpoint behaviour is read from code and tests, not run on u7s.

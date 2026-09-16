# Kubelet/KCM Rust-reimplementation: Phase-1 research

Bead: mayor-vc844

Status: Phase-1 research/audit only. No code changed, no implementation beads
filed. This is input to an operator Phase-2 decision, not a decision itself.

## Verdict

**KCM is a plausible, bounded rewrite target; kubelet is not, absent new
evidence.** A prior internal audit (2026-08-28, `mayor-p4buc`, recovered
below — see Sources) already modeled this: a standalone Rust KCM was
estimated at **12–45 MB** against today's ~90–109 MB baseline, using
Kubernetes-shaped primitives (informers, workqueues, leader-election) that
`kube-rs` already provides production-grade, and u7s's own scheduler rewrite
is a direct, already-shipped proof point (~7–14 MB Rust vs. a comparable Go
footprint). A standalone Rust kubelet was modeled in the same audit and
**could not clear the then-active 128 MiB Gate-4 budget even optimistically**
— KCM + CRI-O alone already exceeded it — and no Rust prior art actually
implements kubelet's real-container (CRI/OCI) path: krustlet, the one Rust
kubelet that shipped, deliberately built for WASM instead and skipped CRI
entirely. kubelet is also ~139k non-test LOC dominated by cgroup/QoS/topology
managers, and rewriting it forfeits two standing project guarantees: the
conformance-oracle role of an unmodified upstream kubelet, and Gate 7's
unmodified-kubelet node-rejoin story. Verification tooling is good news on
*how* a rewrite would be gated (the CRI, kubelet↔apiserver, CSI, and
device-plugin seams are all versioned, documented, behavior-based contracts,
not Go-internals-coupled), but does not reduce the size of what would need
to be built. **Net: if Phase 2 greenlights anything, KCM-first is the
substantially better-supported starting point; a kubelet rewrite should stay
parked pending the specific new evidence in "What would flip the calculus"
below.**

One load-bearing gap this research could not close within budget: no
existing bd memory or findings doc gives a single measured number for
"does the full u7s control plane + OS baseline actually fit in 1 GiB on a
real VPS, with workload headroom to spare." The operator's stated goal is
that absolute number, not the old 128 MiB Gate-4 target or the k3s-relative
comparison — and it appears genuinely unmeasured (see Risks).

---

## 1. Responsibilities — sized to what u7s actually needs

### Kubelet

Upstream kubelet (`kubernetes/kubernetes` `release-1.36`, `pkg/kubelet/`) is
~139k non-test LOC. Its subpackages (confirmed via `gh api` against
`release-1.36`): `pod/`, `kuberuntime/` (CRI client), `cm/` (cgroup/QoS/CPU/
memory/topology managers — the single largest subpackage at ~24.8k lines per
the prior audit), `eviction/`, `volumemanager/`, `pluginmanager/` (CSI +
device-plugin socket discovery), `prober/`, `status/`, `nodestatus/`,
`stats/`, `server/` (the :10250 HTTPS API: logs/exec/attach/port-forward,
`/stats/summary`), `pleg/`, `checkpointmanager/`, `clustertrustbundle/`,
`podcertificate/`, `runtimeclass/`, `userns/`, `nodeshutdown/`, `watchdog/`.

What u7s's own source and config already prove it needs, vs. what it can
drop:

| Responsibility | u7s needs it? | Evidence |
|---|---|---|
| Pod syncLoop / lifecycle | Yes, core | every conformance run |
| CRI integration (kuberuntime) | Yes, core | cri-o is the only supported runtime (ADR) |
| Node status/heartbeat/Lease | Yes, core | KCM's node-lifecycle-controller depends on it |
| Probes (liveness/readiness/startup) | Yes, core | conformance-tested |
| Static pods | Supported, **not used by u7s's own control plane** | `staticPodPath` set in `kubelet-config.yaml` (`scripts/install.sh:292`), but apiserver/scheduler ship as systemd units, not static pods — this responsibility exists only for *operator* use |
| log/exec/attach/port-forward server | Yes, core, **load-bearing for u7s itself** | `crates/apiserver/src/handlers/proxy.rs` proxies `kubectl logs/exec` straight to this kubelet server; a Rust kubelet must reproduce this exactly or u7s's own apiserver breaks |
| CSI volume management | Yes, exercised | `lima/kubelet.yaml` pre-pulls the full CSI-hostpath sidecar set (attacher/provisioner/resizer/snapshotter/node-driver-registrar) and u7s runs a dedicated csi-hostpath conformance focus |
| Device plugins | Needed for GPU workloads | roadmap.md Gate 5 names a "GPU-request workload" correctness probe; core `Allocate`/`ListAndWatch` stays in scope even though the newer `ResourceHealthStatus[Message]` reporting gates are explicitly disabled (see below) |
| CNI coordination | **Largely not kubelet's job any more** | since dockershim's removal (kubelet 1.24), CRI implementations (cri-o) invoke the CNI plugin chain directly for sandbox networking — kubelet's own network-plugin manager was removed with dockershim. (High-confidence from general k8s architecture knowledge; not independently re-verified against `release-1.36` source in this pass — flag before relying on it for scoping.) |
| cgroup/QoS/eviction | Needed, but bounded | u7s already disables `PodLevelResources`, `InPlacePodLevelResourcesVerticalScaling`, `InPlacePodVerticalScalingInitContainers`, `RestartAllContainersOnContainerExits` via `KUBELET_ROUND2_FLAGS` (`scripts/install.sh:798`) — these are real scope cuts already in production, not hypothetical ones |
| Image mgmt / checkpoint | Bounded | `ContainerCheckpoint`, `ContainerRestartRules`, `KubeletSeparateDiskGC`, `KubeletEnsureSecretPulledImages` all disabled in the same flag set |
| Cert rotation surface | Bounded | `RotateKubeletServerCertificate`, `ReloadKubeletClientCAFile`, `ReloadKubeletServerCertificateFile` disabled; u7s mints kubelet's serving cert itself at install time (`scripts/install.sh:1046`) instead |
| Stats/summary API | Low priority | feeds `metrics-server`, which u7s does **not** ship by default (ADR) — inert until a user opts in |

**Net kubelet scope for u7s** is meaningfully smaller than upstream's full
surface — CNI is someone else's problem now, several beta features are
already turned off in production, and static-pod support is a
pass-through, not a self-dependency — but the *remaining* core (CRI client,
volume/CSI, device plugins, probes, eviction, the :10250 streaming server,
node status/Lease) is still the bulk of that ~139k LOC and is exactly the
part upstream's own architecture keeps most tightly coupled to Go's
`client-go`/cAdvisor ecosystem.

### KCM

u7s runs KCM with `--controllers=*,-cloud-node-lifecycle-controller,
-clusterrole-aggregation-controller,-device-taint-eviction-controller,
-node-route-controller,-service-lb-controller,-service-cidr-controller`
(`scripts/install.sh:1010`; the conformance dev-loop script,
`scripts/conformance/04-start-kcm.sh:158`, matches minus
`node-route-controller` — a minor, apparently-inert residual drift between
the two scripts, both cloud-only controllers). Upstream registers 52
controller descriptors total, 3 of which (`bootstrap-signer`,
`token-cleaner`, `selinux-warning`) are disabled-by-default and **stay off**
under a `*` glob unless named explicitly — u7s does not name them. So u7s's
real enabled set is roughly 52 − 3 − 6 ≈ **43 controllers**, not upstream's
full 52 (counts as of the 2026-08-28 audit below were 52/3/4→45; the
explicit-exclusion list has grown by two since — `node-route-controller` and
`service-cidr-controller` — so ~43 is the current estimate, not
independently re-derived from `controller_descriptor.go` in this pass).

Why each exclusion holds, per the exclusion comments already in
`scripts/install.sh`:
- `cloud-node-lifecycle-controller`, `node-route-controller`,
  `service-lb-controller` — **no cloud provider** (ADR: u7s never sets
  `--cloud-provider`); these exist only to glue KCM to a cloud API u7s
  doesn't have.
- `device-taint-eviction-controller` — acts on `DeviceTaintRule`, which
  lives at `resource.k8s.io/v1beta2`; u7s serves `resource.k8s.io/v1` only,
  so this object can never exist — structurally unreachable, not a policy
  choice.
- `clusterrole-aggregation-controller` — acts on
  `ClusterRole.aggregationRule`, which no shipped u7s ClusterRole sets and
  no code reads.
- `service-cidr-controller` — dynamic multi-CIDR `ServiceCIDR` allocation;
  u7s uses the classic static `--cluster-cidr`/`--service-cluster-ip-range`
  allocator instead.

The **real, remaining surface** (~43 controllers) still includes all the
"hard" reconciliation logic: GC (owner-reference graph), PV/PVC
binding+protection+expansion, HPA's scaling algorithm, PodDisruptionBudget
math, `resource-claim-controller` (DRA), `node-ipam-controller` (needed —
recently re-enabled for flannel podCIDR leasing, per `b465b1e7`), and the
workload controllers (ReplicaSet/Deployment/StatefulSet/DaemonSet/Job/
CronJob/Namespace/ServiceAccount/Endpoint(Slice)). This is the part a Rust
KCM would actually need to reimplement — cloud glue and a few
structurally-unreachable object types are the only responsibilities u7s's
no-cloud-provider, small-cluster stance genuinely lets it drop.

---

## 2. Verification — what could gate a Rust reimplementation

Researched in depth by a delegated subagent against `kubernetes/kubernetes`
`release-1.36` and `kubernetes-sigs/cri-tools`; summarized and cross-checked
here.

**test/e2e_node** (github.com/kubernetes/kubernetes/tree/release-1.36/test/e2e_node):
exercises pod lifecycle, probes, eviction, cgroups, device plugins,
DRA, security contexts, node shutdown, GC, mirror pods. Runs as Ginkgo v2
against a real kubelet + a real or minimal apiserver (`test/e2e_node/services/
kubelet.go` configures kubelet startup; remote mode deploys via SSH).
**Not implementation-language-agnostic as a test *harness*** (it's compiled
Go, invoked as a binary) **but behaviorally so as a test *contract*** — it
asserts on pod status, probe outcomes, events, and CRI-visible effects, not
on kubelet's Go internals. A Rust kubelet that satisfies the same
CRI/apiserver contract should pass the same specs unmodified.

**Node Conformance Test** — a standalone subset, distinct from full
cluster conformance, distributed as a container
(`registry.k8s.io/node-test:0.2`, built from `test/conformance/image`) that
starts a local control plane and runs against just the node under test
(kubelet + CRI runtime), no full cluster needed. Documented at
kubernetes.io/docs/setup/best-practices/node-conformance/, `FOCUS`/`SKIP`
env vars select subsets. This is the most direct existing tool for gating a
standalone Rust kubelet without u7s's own apiserver in the loop.

**critest / cri-tools** (kubernetes-sigs/cri-tools) validates the CRI gRPC
*server* — i.e. the container runtime (cri-o), not kubelet. The distinction
matters: a Rust kubelet is a CRI *client*; critest doesn't test it directly,
but the CRI protobuf schema it validates against
(`kubernetes/cri-api/pkg/apis/runtime/v1/api.proto`) is the exact contract a
Rust kubelet's CRI client must implement correctly. `test/e2e_node` is what
actually verifies kubelet used that contract correctly (via observed pod
behavior), not critest.

**kubelet component/integration tests** (`pkg/kubelet/**/*_test.go`) are
Go-internals-coupled (mocks, struct mutation) and not reusable against a
different-language reimplementation. `test/integration/...` tests that spin
up a real apiserver+etcd+kubelet and assert on the REST/watch contract
(Node status, Lease renewal, pod binding, exec/log tunneling) *are*
behavioral and language-agnostic in the same way `test/e2e_node` is.

**Contract seams** (why a drop-in reimplementation is verifiable by
behavior, not by code review):
- **CRI gRPC** (kubelet→cri-o): stable, versioned protobuf
  (`cri-api/pkg/apis/runtime/v1/api.proto`), v1 required since 1.26.
- **kubelet↔apiserver**: REST/watch on Node objects, Lease heartbeats
  (`kube-node-lease` namespace), pod binding, plus kubelet's own HTTPS
  server for exec/log/attach/port-forward (documented, stable).
- **CSI gRPC** (kubelet→CSI driver socket) and **device-plugin gRPC**
  (`ListAndWatch`/`Allocate` over a Unix socket): both documented, stable,
  versioned specs, kubelet is the client in both.

All four seams are documented HTTP/gRPC contracts with no required
Go-specific coupling — the good-news finding of this section. The bad news
is unchanged from Section 1: passing the contract doesn't shrink the amount
of logic that has to sit behind it.

**KCM has no standalone conformance suite upstream** — controllers are
tested via full `test/e2e` (indirectly, e.g. node-lifecycle via Node tests,
job-controller via Job tests) and `test/integration` (real apiserver+etcd,
no full cluster). u7s's existing sonobuoy-based full-conformance runs
already exercise this path for every controller it enables; a Rust KCM
would be graded by the same suite u7s already runs, with no new
verification infrastructure needed.

---

## 3. Rust prior art

Researched by a delegated subagent against GitHub/crates.io; all projects
below are Apache-2.0 or MIT (no licensing blocker).

**krustlet** (github.com/krustlet/krustlet, archived by CNCF 2024-09-30) —
a Rust kubelet, but built specifically to run WASM/WASI workloads, not OCI
containers. It genuinely implemented the kubelet↔apiserver contract in Rust:
node registration, a reflector-based pod-watch informer, and status/
condition reporting. Archived because the WASM-on-k8s niche it served moved
to other projects (wasmCloud, SpinKube), not because the Rust approach
failed. **What it proves**: the non-CRI half of kubelet (node lifecycle,
lease, status heartbeats, pod-assignment watching) is Rust-tractable with
no language-specific blocker. **What it omits**: the entire CRI/OCI path —
volumes, CSI, device plugins, probes, lifecycle hooks, and any real
container runtime integration. Directly reusable: its node-registration/
status-update pattern and provider abstraction shape.

**kube-rs** (github.com/kube-rs/kube, CNCF Sandbox, actively maintained,
pushed 2026-09-14) — Rust's client-go + controller-runtime equivalent:
informers/reflectors, workqueue-equivalent reconciliation, CRD derive
macros, and a `kube-leader-election` crate implementing Lease-based leader
election. Used in production by CNCF Sandbox projects (Kubewarden — policy
engine, v1.0+; Akri — edge device interface) and others. **This is the
strongest single prior-art finding**: it supplies almost exactly the
primitives a Rust KCM's controllers need, already proven at production
scale, and directly supports the "KCM-first" recommendation above.

**youki** (github.com/containers/youki, active, pushed 2026-09-14) — a Rust
OCI runtime (runc alternative), cgroups v1/v2, namespaces, seccomp,
production-tested, passes OCI conformance. Not a kubelet building block —
kubelet still needs a CRI-compliant runtime underneath regardless of
language — but evidence that the lowest-level container-execution surface
is Rust-tractable if u7s ever wanted to own that layer too (out of scope
here; u7s uses cri-o unmodified).

**CRI protobuf/gRPC bindings in Rust**: `containerd-client` (async gRPC to
containerd) and `k8s-cri` (github.com/kflansburg/k8s-cri, tonic-generated
from the CRI protobuf spec, small — 8 stars, last active mid-2026) show the
CRI client contract is fully expressible in Rust via existing crates, though
`k8s-cri` specifically is niche/unproven at scale — a Rust kubelet would
likely need to harden or fork it rather than depend on it as-is.

**aya** (github.com/aya-rs/aya) — Rust eBPF, tangential; relevant to
kube-proxy/CNI-adjacent work (and already u7s's own choice for the
ServiceLB eBPF dataplane, `litehop/beep`), not to kubelet/KCM directly.

---

## What would flip the memory-reduction calculus

The two governing bd memories
(`kubelet-kcm-memory-normal-for-go-lever-left-is-rust`,
`memory-reduction-scope-1gib-vps-what-u7s-controls`) frame today's ~104 MB
(kubelet) + ~106 MB (KCM) combined RSS as normal, already-tuned Go-runtime
behavior, with the rewrite lever reopened only because the non-rewrite
levers are near-exhausted. What would specifically change the ~100 MB-for-
huge-surface tradeoff:

1. **A real, measured KCM prototype number below today's ~106 MB, passing
   u7s's own conformance suite unmodified** — not another estimate. The
   Aug-28 audit's 12–45 MB S1 figure is a model, not a measurement; kube-rs
   and the scheduler precedent make building the prototype cheap enough to
   be the actual next step rather than more estimation.
2. **For kubelet specifically**: either (a) proof that a reduced-scope
   kubelet (dropping the already-disabled features permanently, and
   further dropping in-tree volume plugins beyond CSI, most of `cm/`'s
   topology-manager machinery, etc.) still passes full sonobuoy conformance
   — flagged as unverified by the Aug-28 audit and still unverified here —
   or (b) a real measured "u7s control plane + OS baseline vs. 1 GiB VPS"
   number showing the *absolute* budget, not the old 128 MiB Gate-4 number
   or the k3s-relative comparison, is actually tight even after KCM is
   addressed and all non-rewrite kubelet levers are exhausted. Neither
   exists yet.
3. **Willingness to spend the non-monetary cost**, independent of any
   number: forfeiting the conformance-oracle role of an unmodified upstream
   kubelet, and Gate 7's unmodified-kubelet node-rejoin story. These are
   policy trade-offs the operator has to accept, not something more
   measurement resolves.

---

## Proposed phased approach (Phase 3, if approved — proposal only)

**Phase 3a — KCM (recommended entry point if anything proceeds):**
1. Spike a minimal Rust KCM on `kube-rs` covering a first slice of u7s's
   ~43 enabled controllers (node-lifecycle, node-ipam, endpoint(slice),
   the core workload controllers, GC, namespace/serviceaccount) as a
   standalone process — not folded into apiserver, to preserve restart
   isolation.
2. Gate it on u7s's existing sonobuoy conformance suite unmodified — no new
   verification infrastructure needed (Section 2's finding).
3. Measure real RSS against the current ~106 MB baseline before deciding
   whether to expand coverage. Stop here if the number doesn't beat the
   modeled range meaningfully.
4. Expand toward full parity (HPA, PodDisruptionBudget, DRA resource-claim
   — the most complex reconciliation logic) only if Step 3 holds.
5. Folding into the apiserver+scheduler binary (best-case but highest-risk
   ordering) stays parked until standalone-process parity is proven.

**Phase 3b — kubelet (gated behind 3a's outcome, plus its own prerequisite):**
0. Prerequisite, cheap and independent of any Rust work: verify whether
   u7s's already-reduced kubelet feature-gate set still passes full
   conformance with further scope cut (in-tree volume plugins beyond CSI,
   topology-manager). Answers exactly how much surface a Rust kubelet would
   need to cover before committing to build it.
1. If pursued: standalone Rust kubelet prototype (not folded into
   apiserver) covering node status/Lease, static-pod pass-through, CRI
   client (via existing Rust CRI bindings, hardened as needed), probes, and
   the :10250 streaming server that u7s's own apiserver already depends on.
2. CSI + device-plugin gRPC client support next (needed for the
   csi-hostpath focus u7s already runs).
3. cgroup/QoS/eviction manager last — the highest upstream-behavior-coupled
   piece.
4. Gate each step on the relevant `test/e2e_node`/Node Conformance Test
   focuses, then u7s's full sonobuoy run.

---

## Risks and biggest unknowns

- **The actual gating number is missing.** No memory or findings doc found
  in this research gives a measured "full u7s control plane + OS baseline
  vs. 1 GiB VPS" figure. Everything cited here is either per-component RSS
  or relative-to-k3s/relative-to-Gate-4 — neither is the operator's stated
  absolute target.
- **Reduced-scope-kubelet-still-passes-conformance is unverified** — flagged
  by the 2026-08-28 audit, still open.
- **CNI-not-kubelet's-job claim** (Section 1) is stated from general k8s
  architecture knowledge, not re-verified against `release-1.36` source in
  this pass — worth an independent check before it's used to scope a
  kubelet rewrite.
- **Blast radius asymmetry**: a bug in a Rust kubelet reimplementation
  affects every node it runs on; a bug in apiserver/scheduler affects one
  control-plane instance. cgroup/eviction logic in particular carries real
  correctness risk disproportionate to its RSS payoff.
- **Rust CRI-client prior art is niche** (`k8s-cri`: 8 stars) — kube-rs's
  production maturity does not transfer to the CRI-client side; that half
  would need u7s's own hardening and conformance runs, not borrowed
  confidence.
- **Folding either component into the apiserver process** (the best-case
  numbers in the Aug-28 model) trades away per-process restart isolation —
  a real availability cost the model's optimistic scenarios note but do not
  price in.
- The ADR `docs/decisions/upstream-component-shipping-shape.md` (governs how
  upstream binaries ship) is **not reversed** by this research — a Rust
  reimplementation would make kubelet/KCM u7s-owned binaries (like the
  scheduler already is), which is a shipping-shape change the ADR's own
  "Consequences" section already anticipates for kube-proxy but not yet for
  kubelet/KCM.

---

## Sources

- `scripts/install.sh` (KCM `--controllers`, kubelet feature-gates,
  `kubelet-config.yaml` generation), `scripts/conformance/04-start-kcm.sh`,
  `lima/kubelet.yaml`, `docs/decisions/upstream-component-shipping-shape.md`,
  `ai/extended-context/roadmap.md` (component matrix, Gate 4) — read
  directly in this session.
- `kubernetes/kubernetes` `release-1.36`: `pkg/kubelet/` and
  `cmd/kube-controller-manager/app/` directory listings via `gh api`.
- `ai/findings/2026-08-28-mayor-p4buc-go-components-consolidation.md` — a
  prior internal audit deleted same-day, 2026-08-28, as one of "6 stale
  findings for closed beads" (commit `1a1df0bb`, cleanup bead
  `mayor-l5hk8`); recovered via
  `git show 3ce069f7:ai/findings/2026-08-28-mayor-p4buc-go-components-consolidation.md`
  for this research since its technical content (kubelet ~139k LOC
  breakdown, KCM 52/3/45 controller count, S0–S3 rewrite scenarios) remains
  the deepest existing analysis on this exact question.
- bd beads/memories: `mayor-v9jk0` (the tuning-ceiling-then-rewrite trigger
  rule this bead is executing), `mayor-9dk3n`/`mayor-xpxj5` (round-2 tuning,
  closed), `mayor-5x0kh` (k3s matched comparison, PR #1295), `bd recall
  kubelet-kcm-memory-normal-for-go-lever-left-is-rust`, `bd recall
  memory-reduction-scope-1gib-vps-what-u7s-controls`.
- Delegated subagent research (this session) against
  `kubernetes/kubernetes`, `kubernetes-sigs/cri-tools`, `kube-rs/kube`,
  `krustlet/krustlet`, `containers/youki`, `aya-rs/aya`, and related
  crates.io/GitHub sources for Sections 2 and 3.

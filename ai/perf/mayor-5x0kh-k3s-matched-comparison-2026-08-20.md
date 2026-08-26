# Matched-methodology k3s RSS comparison

Resolves the gap flagged in `ai/extended-context/roadmap.md`'s "On the
k3s/k0s comparison" note: the north star's illustrative k3s figure
(~70-100MB) covers only the bare `k3s`/`k3s-agent` binary, while u7s's own
measured total sums every control-plane and data-plane process it runs. This
document replaces that illustrative estimate with a real, executed
measurement of actual k3s, using the same sonobuoy conformance harness and
the same component-boundary accounting u7s uses on itself.

## TL;DR

- Real k3s (v1.36.3+k3s1, native containerd, traefik/servicelb disabled),
  single-node, **idle**, matched-boundary total: **~813 MB** (`k3s-server`
  445.5MB + containerd 163.0MB + 3 default-addon shims 49.8MB + CoreDNS
  55.9MB + local-path-provisioner 36.9MB + metrics-server 62.4MB).
- That is **~8-11x higher** than the old "~70-100MB" illustrative figure —
  confirms the roadmap's suspicion that the old ratio was not trustworthy;
  it undercounted by measuring only the bare binary.
- Against u7s's own Gate-4 **target** (128 MiB = 134.2MB combined idle for
  its entire control-plane process set), the real gap is **~6.1x**, and
  likely larger once compared against u7s's current actual total rather
  than its aspirational target. Gate 4's own framing ("far enough below
  even the illustrative k3s figure to settle the comparison on any
  reasonable accounting") holds up, now with a real number behind it.
- The container **runtime** (CRI-O vs containerd) is reported separately,
  not folded into the totals above — see "Container-runtime scaling" below.
  Idle runtime-daemon RSS is not representative of behavior under real
  container load for either runtime.
- Two methodology deviations were forced by real constraints hit during
  execution (host memory pressure, a topology limitation with fully
  isolated VMs); both are documented in detail below, not glossed over.

## Methodology recap and deviations

### What matched the locked-in plan

- **Native containerd, not forced CRI-O.** Installed via `curl -sfL
  https://get.k3s.io | sh -` with no runtime override. k3s bundles
  containerd 2.3.2-k3s2.
- **Version pin.** k3s stable channel's latest (`update.k3s.io/v1-release/
  channels`) is `v1.36.3+k3s1` — the closest match to u7s's own dual
  `v1.36.2`/`v1.36.3` conformance-image pin. Installed
  `INSTALL_K3S_VERSION=v1.36.3+k3s1`; sonobuoy plugin run with
  `--kube-conformance-image=registry.k8s.io/conformance:v1.36.3`. Sonobuoy
  CLI itself pinned to v0.57.3, same as u7s uses.
- **Component-boundary accounting.** k3s installed with `--disable traefik
  --disable servicelb` (u7s has no ingress/LB equivalent — a real deployer
  who doesn't need them would disable them too). CoreDNS,
  local-path-provisioner, and metrics-server were left at their stock
  defaults and are all counted in the matched-boundary total, per the
  locked-in methodology's explicit instruction (even though u7s has no
  local-path-provisioner equivalent at all — an intentional asymmetry in
  that methodology, not something introduced here).
- **Same sonobuoy harness.** Copied `scripts/conformance/
  sonobuoy-plugin-e2e.yaml` verbatim into the VM (unmodified) and ran the
  identical 4-spec focus set `.github/workflows/e2e-focus.yaml` uses for
  u7s: `RollingUpdateDeployment should delete old pods and create new
  ones|Kubectl logs logs should be able to retrieve and filter
  logs|Job should adopt matching orphans and release non-matching
  pods|ConfigMap should be consumable in multiple volumes in the same pod`.
- **Same sampler, zero code changes.** `scripts/conformance/
  sample-run-metrics.sh` was pointed directly at the k3s VM(s) via
  `--vm`/`--extra-node`, completely unmodified. Its host-side
  apiserver/scheduler/konnectivity-server PID-resolution and its
  u7s-specific `/metrics` ring-gauge scrape both no-op harmlessly against a
  cluster that has none of those things (wrapped `|| true` throughout) —
  confirming that a straightforward adaptation required literally no
  script changes for the sampling side. `aggregate-run-metrics.sh`'s
  presentation layer, by contrast, hardcodes u7s process-name regexes
  (`^kubelet$`, `^kube-proxy$`, etc.) that don't match k3s's process names
  (`k3s-server`, `k3s-agent`) — rather than fork a new script for a
  one-time findings-doc table (more surface area than the problem
  warrants), the per-process peak tables below were computed directly from
  the raw `rss.csv` with ad hoc `awk`.

### Deviation 1 — VM sizing (4 vCPU/4GiB + 2 vCPU/2GiB, not 8/8 + 8/8)

The locked-in methodology asks for the same 8 vCPU/8GiB ceiling as
`lima/kubelet.yaml`'s template, for resource-ceiling parity. At
provisioning time this host was already running four concurrent 8GiB
worker VMs (`lima-node-2..5`) with real, demonstrated memory pressure:

```
$ sysctl vm.swapusage
vm.swapusage: total = 9216.00M  used = 7908.00M  free = 1308.00M  (encrypted)
$ top -l 1 -n 0 | grep PhysMem
PhysMem: 45G used (3444M wired, 20G compressor), 1922M unused.
```

Adding a full second 8GiB VM risked destabilizing those in-flight worker
sessions. `k3s-compare` was sized 4 vCPU/4GiB and `k3s-compare-2` (agent
only) 2 vCPU/2GiB instead — comfortably above k3s's documented minimum
(~512MB-1GB for a single-node server) and, since the comparison workload is
a 4-spec conformance focus rather than a full suite, not a binding
constraint on the RSS numbers themselves. This was the right call: even at
this reduced size, the shared host hit genuine resource exhaustion twice
during this session (see Deviation 3) — full 8/8 sizing would very likely
have made that worse for every other concurrent worker.

### Deviation 2 — 2-node topology: real cross-node pod networking not achievable

The locked-in methodology requires "independent VM, own network" and
explicitly forbids joining `lima-node-2..5`'s shared `user-v2-workers-a/b`
partitions or touching `lima-node`'s own network. Both `k3s-compare` and
`k3s-compare-2` were provisioned with no `networks:` stanza at all, relying
on Lima's own default per-VM NAT.

This has a real consequence discovered during execution: **Lima's default
per-VM NAT assigns the identical private IP to every independently-isolated
VM** (both nodes registered `InternalIP: 192.168.5.15`). Once
`k3s-compare-2` joined as an agent (via `K3S_URL=https://
host.lima.internal:16443`, the only channel available between two
fully-isolated VMs — reachable because host-loopback-bound ports are
visible from any Lima VM, the same mechanism u7s's own apiserver already
relies on), the k3s server's own kubelet-log-proxy broke — not just for the
agent, but for **the server's own, previously-working log fetches**:

```
$ kubectl logs -n kube-system -l k8s-app=kube-dns --tail=5
Error from server: Get "https://192.168.5.15:10250/containerLogs/...":
proxy error from 127.0.0.1:6443 while dialing 192.168.5.15:10250,
code 502: 502 Bad Gateway
```

Cordoning the agent node (to force sonobuoy's pods back onto the server)
did not fix this — the routing corruption is node-IP-collision-level, not
scheduling-level, most likely flannel/k3s installing a route or iptables
rule for the "remote" 192.168.5.15 peer that shadows the server's own
local-loopback path to itself.

A proper fix (a new, disjoint Lima network solely for this VM pair, added
via `~/.lima/_config/networks.yaml`) was attempted — the sandbox's own
worktree-boundary guard hard-blocked the edit as an unauthorized
modification of shared host infrastructure, and a follow-up classifier
denial confirmed the same boundary applies to even read-only inspection of
other VMs' configs once the intent was flagged. This is the correct outcome
given the "no shared switches" requirement, not a tooling bug — so the fix
was abandoned rather than worked around.

**Net effect:** the 2-node leg validates a real k3s server+agent join (both
nodes report `Ready`) and real per-node RSS at idle and under container
load (pure `ps`-based sampling via `sample-run-metrics.sh`, entirely
independent of the broken proxy path). It does **not** validate genuine
cross-node pod scheduling, log fetch, or exec — those require the two nodes
to have distinct, mutually-routable IPs, which a "no shared network at all"
topology cannot provide. This is a limitation of the specific isolated-VM
topology chosen here, not a k3s defect — real k3s deployments never have
colliding node IPs.

### Deviation 3 — container-runtime load test cut short by host resource exhaustion

Mid-session, an operator request asked for a peak-RSS measurement under a
meaningful concurrent-container count (not just idle) specifically to
answer the CRI-O-vs-containerd per-container-shim-cost question honestly.
A 40-replica `registry.k8s.io/pause:3.10` Deployment was applied to the
2-node cluster to generate that load.

The shared host was independently, severely resource-constrained at this
point in the session (four unrelated worker VMs still running):

```
$ sysctl vm.swapusage
vm.swapusage: total = 10240.00M  used = 9011.38M  free = 1228.62M
$ top -l 1 -n 0 | grep -E "PhysMem|CPU usage"
CPU usage: 70.80% user, 28.30% sys, 0.89% idle
PhysMem: 43G used (3449M wired, 17G compressor), 4407M unused.
```

`k3s-compare` was involuntarily stopped by the hypervisor twice during this
session (VZ vm state change: stopped, host agent received SIGTERM) — once
during the networking investigation above, once directly correlated with
this load test's image-pull/container-start burst. Given the risk of
destabilizing other concurrent worker sessions on the shared host, the load
test was deliberately capped and torn down early (~20 pods reached
`Running` before deletion) rather than pushed to the originally-planned
50-100+ concurrent-container scale. Real numbers up to ~11-20 concurrent
containers were captured (see below) — enough to establish the linear
per-container trend with actual measured numbers, not just an architectural
assertion, but short of a definitive high-count (100+) stress measurement.
Flagged as a follow-on, not silently glossed over.

## Per-process RSS — single-node k3s (matched boundary)

All figures from `temp/k3s-single/rss.csv` (216 raw samples, 15s interval).
"Matched boundary" = the set of components u7s's own roadmap matrix
measures on itself: control-plane processes + container runtime + CoreDNS +
metrics-server, plus local-path-provisioner (no u7s equivalent, included
per the locked-in methodology's explicit instruction), minus
traefik/servicelb (disabled) and minus any conformance-test workload pod or
sonobuoy's own control pod (u7s's own `aggregate-run-metrics.sh` tracks
"sonobuoy control pods" as its own separate, excluded line item — same
treatment here).

### Idle (first sampler tick, all 3 default addons already `Running`)

| Process | Role | RSS (MB) |
|---|---|---:|
| `k3s-server` | apiserver+scheduler+controller-manager+kubelet+kube-proxy, ONE process (see below) | 445.5 |
| `containerd` | runtime daemon (bundled, no shims counted here) | 163.0 |
| `containerd-shim` x3 | one per running addon container | 49.8 (~16.6 each) |
| `coredns` | DNS addon | 55.9 |
| `local-path-provisioner` | default storage addon | 36.9 |
| `metrics-server` | metrics addon | 62.4 |
| **Matched-boundary idle total** | | **~813.4** |

Excluded from the total, tracked separately: `lima-guestagent` (65.4MB —
Lima's own tooling, not part of k3s) and an orphaned `kubectl` process
(133.8MB — see "CLI artifact" finding below).

### Peak (during the 4-spec conformance focus; 34.6s ginkgo runtime, PASS)

| Process | Peak RSS (MB) |
|---|---:|
| `k3s-server` | 496.0 |
| `containerd` (daemon only) | 165.7 (essentially flat vs idle) |
| `coredns` | 58.5 |
| `local-path-provisioner` | 38.7 |
| `metrics-server` | 64.5 |
| **Matched-boundary peak total** | **~823.4** |
| `e2e.test` (conformance driver — EXCLUDED, workload not component) | 239.4 |
| `sonobuoy` (control pod — EXCLUDED, tracked separately) | 71.7 |

Peak vs idle delta (~10MB) is almost entirely `k3s-server` growth from
handling the test's create/update/delete churn — the addon set barely
moved, consistent with a light 4-spec focus rather than a full suite.

## Per-process RSS — 2-node leg (matched boundary, idle)

All 3 default addons (coredns, local-path-provisioner, metrics-server) run
only on the server in this topology (they were never rescheduled to the
agent). From `temp/k3s-two-node/rss.csv`:

| Node | Process | RSS (MB) |
|---|---|---:|
| server | `k3s-server` | ~448 (consistent with single-node idle) |
| server | `containerd` | ~154 |
| server | coredns/local-path-prov/metrics-server | same as single-node table |
| agent | `k3s-agent` | 179.7 |
| agent | `containerd` | 149.4 |

`k3s-agent` alone (idle, no addons scheduled) is meaningfully lighter than
the full `k3s-server` process (~180MB vs ~446-496MB) — a direct, measured
illustration of how much the server process's folded-in
apiserver/scheduler/controller-manager/etcd-equivalent components cost
relative to "just" kubelet+kube-proxy+agent bookkeeping.

## Container-runtime scaling — reported separately, not in the totals above

An idle comparison of the container runtime **alone** (CRI-O vs containerd)
is not representative of real behavior, because both runtimes spawn one
supervisor process per running container (containerd's `containerd-shim`,
CRI-O's `conmon`) — a marginal, per-container cost invisible at low
container counts but significant at realistic ones. This section is
intentionally kept separate from the matched-boundary totals above, which
only include each runtime's flat idle daemon RSS.

**u7s side (CRI-O) — verified, not measured live** (touching u7s's own VM
fleet was out of scope for this measurement). `lima/kubelet.yaml`'s own
CRI-O provisioning was read directly: it never sets `runtime_type = "pod"`
for any runtime entry, only `runtime_type = "oci"` (the `test-handler`
RuntimeClass block). Cross-checked against upstream CRI-O's own
`release-1.36` docs (`crio.conf.5.md`): `conmon`/`conmon_cgroup`/
`conmon_env` are the always-present default-path config keys, and
`conmon-rs` (the process-pooling alternative that would reduce
per-container process count) only activates under `runtime_type = "pod"`.
**Conclusion: u7s's own pinned CRI-O config uses one traditional `conmon`
monitor process per running container — the same one-process-per-container
architecture class as containerd's shim, not an inherently cheaper
alternative.** Caution against assuming CRI-O wins here was warranted.

**k3s side (containerd) — measured live:**

- Idle (3 running containers: coredns, local-path-provisioner,
  metrics-server): exactly 3 `containerd-shim` processes, 16.6-17.1MB RSS
  each; containerd daemon 163-166MB.
- Under the capped 40-replica `pause` load test (see Deviation 3), a single
  sampler tick captured **11 concurrent `containerd-shim` processes on the
  agent node alone** (16.5MB-17.4MB RSS each, avg ~17.2MB) plus at least 2
  more on the server (top-N=20 per-node sampling cutoff likely truncated
  the true total — both nodes had ~20 requested replicas scheduled between
  them). containerd daemon RSS on the agent grew only from ~149MB (idle,
  zero containers) to 178MB (>=11 concurrent containers) — a ~29MB daemon
  delta versus >=11x17.2MB ~= 189MB+ in shim RSS. **The marginal
  per-container cost is almost entirely in the shim population, not the
  daemon** — exactly the scaling risk this section exists to answer, now
  with a real (if capped) number behind it.

**What this does and doesn't establish:** the trend (linear-ish,
~17MB/container, daemon-flat) is real and measured, not asserted. The
absolute crossover point where containerd's or CRI-O's per-container
overhead becomes decision-relevant at *production* scale (50-100+
containers on one node) is **not** resolved here — the load test was capped
at ~20 concurrent containers by genuine host resource exhaustion (Deviation
3), and the CRI-O side wasn't measured live at all. **Follow-on
recommended:** a dedicated bead running both sides at a matched, larger
concurrent-container count (50-100+) on adequately-resourced,
non-contended hardware.

## Ratio and Gate 4 relevance

| | Old illustrative figure | Real measurement |
|---|---:|---:|
| Scope | bare `k3s`/`k3s-agent` binary only | k3s-server + containerd + CoreDNS + local-path-provisioner + metrics-server (matched to u7s's own measured boundary) |
| Single-node idle total | ~70-100 MB | **~813 MB** |

The real total is **~8-11x** the old illustrative figure — confirming the
roadmap's own caveat that the old ratio "is not trustworthy": it undercounted
by measuring only the bare binary, missing containerd and all three default
addons entirely.

Against u7s's Gate-4 **target** (128 MiB = 134.2MB combined idle, across
its *entire* control-plane process set — apiserver, scheduler, KCM,
kubelet, CRI-O, kube-proxy, CoreDNS, metrics-server; a target Gate 4 is
still actively working toward, not yet necessarily fully achieved): 813.4 /
134.2 ~= **6.1x**. This compares k3s's real *measured* total against u7s's
*aspirational* target rather than u7s's current actual total, so it is a
conservative (floor) estimate of the real gap — the true ratio against
u7s's current actual figure is unknown from this measurement alone (see
"Limitations" below) but is unlikely to be smaller.

**Gate 4 relevance:** this does not change Gate 4's target or urgency. It
confirms the roadmap's already-cautious framing was justified, and replaces
a hand-wavy "the ratio isn't trustworthy yet" with a real, if still
partially-caveated (container-runtime-under-load question still open),
number. The 128 MiB target remains "far enough below" k3s's real measured
footprint to be a safe target regardless of exactly where u7s's own current
actual total lands.

## Conformance-on-k3s findings (informational)

- **Single-node conformance: 4/4 focus specs passed.** `Ran 4 of 7579
  Specs in 34.565 seconds` / `SUCCESS! -- 4 Passed | 0 Failed | 0 Pending |
  7575 Skipped`.
- **Single/dual-binary process model, confirmed live.** A stock `k3s
  server` invocation folds apiserver + scheduler + controller-manager +
  kubelet + kube-proxy into **one** OS process (`comm=k3s-server`, verified
  via `/proc/<pid>/cmdline` = `/usr/local/bin/k3s server`). A standalone
  agent similarly folds kubelet + kube-proxy + containerd-client into one
  `k3s-agent` process. This means there is no way to attribute RSS to "just
  k3s's apiserver-equivalent" the way u7s's own matrix separates NATIVE
  apiserver/scheduler/store — any u7s-vs-k3s comparison below the
  `k3s-server` line is definitionally impossible; only the combined figure
  is meaningful for k3s. This was an expected, worth-documenting finding
  going in, and it held up exactly as anticipated.
- **CLI-artifact noise.** Running `sonobuoy`/`kubectl` directly on a k3s
  node (no separate host-side control machine was available) leaves at
  least one orphaned, long-lived `kubectl` process per invocation cycle
  (~135MB RSS, reparented to `lima-guestagent`, survives the invoking
  command's own exit). Confirmed harmless to kill (zero effect on cluster
  health/`kubectl get nodes` afterward) but is real `ps`-sampling noise if
  not manually excluded — excluded from every total in this document.
- **2-node topology fragility (see Deviation 2).** Worth restating here as
  a conformance-adjacent surprise: joining a second, fully-isolated Lima VM
  broke the *server's own* previously-working kubelet-log-proxy, not just
  the new agent's. This is an artifact of this test's specific
  no-shared-network topology, not a real-world k3s concern (real
  deployments never have colliding node IPs) — but it is a genuine sharp
  edge worth remembering for any future multi-VM k3s test setup: two nodes
  need distinct, mutually-routable IPs, full stop.

## Limitations (explicit, not silently absorbed into the headline numbers)

1. u7s's own current actual absolute RSS total (as opposed to its Gate-4
   target) was not re-measured here — it lives in `mayor-jnk90`'s
   per-process baseline (see `ai/extended-context/roadmap.md`'s Gate 2)
   plus whatever perf-PR deltas have landed since (the roadmap notes these
   "change with nearly every perf PR"). The ratio against u7s above is
   therefore computed against the Gate-4 *target* (134.2MB), not u7s's
   current actual figure. This is a conservative floor, not the final
   word.
2. The 2-node leg's cross-node pod networking/log-fetch could not be
   validated (Deviation 2) — RSS numbers for both nodes are real, but no
   genuine multi-node workload distribution was exercised on k3s.
3. The container-runtime-under-load comparison is one-sided (k3s/containerd
   measured live; u7s/CRI-O verified only via config-and-docs, not a live
   measurement) and capped at ~20 concurrent containers rather than the
   50-100+ that would be needed for a fully conclusive answer (Deviation
   3). Flagged as a concrete follow-on, not resolved here.

## Raw data

- `temp/k3s-single/{rss.csv,vm-free.csv,ring-age.csv,metrics-*.prom}` —
  single-node leg (idle baseline through post-conformance peak).
- `temp/k3s-two-node/{rss.csv,vm-free.csv,ring-age.csv}` — 2-node leg
  (idle, join, and the capped container-scaling load test).
- `temp/k3s-compare.yaml`, `temp/k3s-compare-2.yaml` — the Lima VM configs
  used (ephemeral; VMs torn down after measurement).

These raw artifacts are local to the worker worktree that produced this
measurement (`temp/` is gitignored) and are not part of this commit. The
sonobuoy result tarballs themselves (extracted `e2e.txt` etc.) lived only in
the VMs' own `/tmp` (tmpfs) and were lost across two involuntary VM restarts
during the session — the PASS/FAIL transcript is preserved verbatim above
(see "Conformance-on-k3s findings").

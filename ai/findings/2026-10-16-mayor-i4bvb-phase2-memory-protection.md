# Phase 2: memory protection for the 1 GiB burst gate

Bead: mayor-i4bvb

Answer: systemd MemoryLow/MemoryMin protection of the control-plane units does
not fix the 80-pod burst (3 gate/screening measurements, node still goes
NotReady or API-unreachable); a zram swap device does (80 pods Ready in 21 s,
refault rate down ~15x). Shipping swap is an operator decision, so install.sh
is unchanged and the gate gains an opt-in `--zram-mib` experiment knob.

## Why protection cannot work here

The node is capacity-bound, not mis-prioritised. At burst80 (snap.txt, run 1,
MemTotal 947 MiB): AnonPages 531 MB, Slab 149 MB (SUnreclaim 116), PageTables
15, KernelStack 6, leaving ~200 MB of page cache (Active(file) 24 MB,
Inactive(file) 135 MB) for the text of kubelet/KCM/crio/apiserver/flannel/
kube-proxy/coredns/mariadb/php plus every crun/conmon exec. Anon is pinned (no
swap), so reclaim can only evict file pages, and the hot file set is larger
than what is left: protecting one consumer's file pages only moves the
refaults to another.

Per-pod overhead (pause Deployment, snapshots while the pods run):

| | pre-burst (1 pod) | 20 pods | 80 pods |
|---|---|---|---|
| MemAvailable MB | 321 | 308 | 151 |
| AnonPages MB | 450 | 442 | 531 |
| SUnreclaim MB | 53 | 66 | 116 |
| PageTables MB | 7.0 | 8.9 | 14.6 |
| Cached MB | 347 | 328 | 200 |
| conmon PSS MB | 1.9 | 3.9 | 9.1 |
| kubelet PSS MB | 61 | 52 | 98 |

About 2 MB per extra pod (kernel slab ~0.8, kubelet heap ~0.5, page tables
~0.1, conmon+pause ~0.15 plus file cache displaced): 80 pods cost ~170 MB of
MemAvailable out of ~320. conmon/pause themselves are small; the cost is kernel
cgroup/netns slab and kubelet/crio heap growth, not a tunable.

## Protection experiments

- `system.slice` `MemoryLow=infinity` as an install.sh drop-in, full gate (runs 2 and
  3): memory.low=max confirmed in the VM; 80-pod burst still times out, refault
  ~1.1M/s, node NotReady (41 / 15 observations). Per-cgroup refaults in run 3
  (burst80 window, per second): system.slice 580k (kubelet 193k, kcm 200k,
  crio 88k, apiserver 38k), kubepods 230k, user.slice 272k.
- The cgroup2 mount lacks `memory_recursiveprot` (`rw,nosuid,nodev,noexec,
  relatime`), so a unit with memory.low=0 inherits no protection from a
  protected parent; slice-level settings alone are inert. Per-unit settings
  (screening, kubelet/crio/kcm/apiserver and system.slice all `MemoryLow=infinity`):
  worse, API unreachable at 106-230 s. `MemoryMin=infinity` on system.slice:
  node stayed Ready but 27/80 pods Ready after 245 s, refault 1.07M/s.
  Protection moves the damage; it does not remove it.

## Observer effect in the harness

Screening on one VM (reboot between tests, no lever, 80 pause pods):
without the gate's background kubectl loops 80/80 Ready in 22 s; with
vm-capture + vm-sampler + a 10 s pod-list loop running the same burst reached
61 pods and flapped the node NotReady. At 1 GiB the harness's own polling
(~3 kubectl/s, ~50 MB RSS each, user.slice refaults 190-270k/s) is a
measurable part of the pressure. The node verdict is still real (the Lease
froze), but the margin is thin.

## What works: zram swap

Screening (same VM, harness loops running, no systemd protection, 512 MiB
zstd zram, page-cluster 0): 80/80 Ready in 21 s, node Ready throughout,
refault 61k/s (vs 0.9-1.1M/s), MemAvailable min 322 MB (vs 91-143). See the gate-run
table below. kubelet already runs with `failSwapOn: false`, and its
default NoSwap behaviour keeps pod cgroups at swap.max=0, so only host daemons
(kubelet/KCM/crio heaps) swap out; that freed anon is what lets the page cache
hold the working set.

## Gate runs

All with the harness at its current polling rate, arm64 1 GiB / 1 vCPU VM.
Host state is from `limactl list` at run start/end (`host.txt`).

| run | lever | host | (a) | (b) | (c) | (d) | (e) | MemAvail min | refault/s | PSI full | 80-pod |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | none | quiet start; own VM only at end | P | F (43) | F | P | P | 103 MiB | 1.21M | 44% | timeout |
| 2 | system.slice MemoryLow=inf | quiet start; beep VMs at end | P | F (41) | F | F | P | 108 MiB | 1.12M | 44% | timeout |
| 3 | same + CG capture | quiet start/end | F (coredns OOM) | F (15) | F | P | F | 91 MiB | 1.08M | 44% | timeout |
| 4 | zram 512 MiB | quiet start; beep-node-a/b at end | P | P (0) | P | P | F | 345 MiB | 87k | 17% | 15 s |
| 5 | zram 512 MiB | CONTENDED (beep-client/a/b) | P | P (0) | P | P | F | 337 MiB | 83k | 15% | 17 s |
| 6 | zram 512 MiB | CONTENDED (beep-client/a/b) | P | P (0) | P | P | P | 325 MiB | 64k | 13% | 17 s |
| 7 | zram 512 MiB + smoke retry fix | quiet start; own VM only at end | P | P (0) | P | P | P | 348 MiB | 70k | 14% | 17 s |

PSI/refault are over the whole burst80 phase window (so the failing runs
include the 600 s hard-kill and cleanup). Run 1's `burst-gate.sh` ran while the
host was at loadavg 25 from the preceding cross-build.

Run 4-6 (e) failures: `webhook-smoke.sh` stopped retrying on the first
non-deny error ("failed to respond", i.e. kube-proxy had not programmed the
smoke Service yet) because it `break`s on any create failure. A healthy node
reaches that step faster than a thrashing one, which is why it only showed
up now. The loop now only stops on "denied the request"; run 7 passes (e).

## Upstream comparison

kubeadm and k3s ship no memory.low/min on control-plane units. kubelet's
systemReserved + enforceNodeAllocatable only sets Allocatable and a
kubepods memory.max; here kubepods is not the consumer being starved
(kubepods.slice memory.max is already ~MemTotal) so it cannot help. kubeadm
requires swap off by default; Kubernetes NodeSwap (beta, LimitedSwap) is the
supported route to swap on a node.

## Decisions for the operator

1. Allow install.sh to provision zram swap (e.g. systemd-zram-generator)? The
   gate template currently states "no swap unless the operator's lever decision
   adds one".
2. Reduce harness polling (vm-capture NODE kubectl every 2 s is the heaviest
   loop) so the gate measures the node, not itself.

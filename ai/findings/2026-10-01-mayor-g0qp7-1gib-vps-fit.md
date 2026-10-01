# u7s on a real 1 GiB / 1 vCPU VM: it fits idle and with one small app, but not with pod bursts

Bead: mayor-g0qp7

The shipped single-node install (`scripts/install.sh`) boots to Ready in 57 s on a
real 1 GiB / 1 vCPU Ubuntu 26.04 VM and leaves 462 MiB `MemAvailable` (49%) idle and
319 MiB (34%) with WordPress + MariaDB running -- but a burst of 20 new pods on top
of that workload triggered kernel OOM kills twice, and an 80-pod burst thrashed the
1 vCPU for 4.5 minutes. A KCM and/or kubelet rewrite is not needed to fit; it would
buy 17-50 MB (KCM) / similar (kubelet) of headroom, less than the non-Go
"shipped extras" (flannel + kube-proxy + CoreDNS = 65 MB PSS) and the OS baseline
(163 MB PSS + 76 MB slab) already cost.

## Environment (real VM, not a simulation)

- Dedicated Lima VM `u7s-vps-1g` (created and deleted by this bead): vz, aarch64,
  **1 vCPU, 1 GiB** (guest `MemTotal` 970136 kB = 947 MiB), no swap, Ubuntu 26.04.1
  (kernel 7.0.0-34), 12 GiB disk, no host mounts.
- Installed with the unmodified `scripts/install.sh --tarball`, tarball built by hand
  in the layout of `scripts/build-release-tarball.sh` but for arm64 (that script is
  x86_64 only): `u7s-apiserver`/`u7s-scheduler` via `cargo zigbuild --release
  --target aarch64-unknown-linux-gnu.2.35`, kubelet + kube-controller-manager
  v1.36.4 arm64 from dl.k8s.io (sha256-verified), `manifests/*.yaml`. cri-o 1.36.6
  from the apt repo as install.sh does.
- Shipped topology: `u7s-apiserver` (embedded scheduler), `u7s-kcm`, `kubelet`,
  `crio` as systemd units; kube-proxy, CoreDNS and flannel as pods applied from
  `/etc/u7s/manifests`. No konnectivity.
- Timeline (UTC, 2026-10-01): install start 04:06:38; node Ready 04:07:35 (57 s);
  CoreDNS Running ~04:08:00. 10-minute settle snapshot 04:18:24 (10 m 49 s after
  Ready).
- Fresh VM before install (`free -m`): total 947, used 305, available 642 MiB.

## Per-component memory (kB converted to MB; PSS from `/proc/<pid>/smaps_rollup`)

PSS is used for all totals (it apportions shared library pages). `Peak` is max RSS
from a 10 s `ps` sampler over the whole run (04:18:53-04:40), so it includes the
churn bursts.

| Component | Idle RSS | Idle PSS | +WordPress PSS (04:23:03) | 80-pod burst PSS (04:24:46) | Peak RSS |
|---|---|---|---|---|---|
| kube-controller-manager | 62.2 | 62.2 | 46.2 | 48.5 | 62.2 |
| kubelet | 62.4 | 60.9 | 57.6 | 79.6 | 108.3 |
| cri-o (+ 3 conmon ~0.4) | 34.4 | 34.4 | 35.5 | 44.4 | 66.5 |
| kube-proxy (pod) | 22.9 | 22.9 | 14.2 | n/a | 23.0 |
| CoreDNS (pod) | 21.8 | 21.8 | 18.4 | n/a | 28.4 |
| flanneld (pod) | 20.5 | 20.5 | 13.2 | n/a | 22.9 |
| u7s-apiserver (+ embedded scheduler) | 18.2 | 16.6 | 13.2 | 14.5 | 43.7 |
| **u7s stack subtotal** | 242.8 | **239.6** | ~198 | | |
| MariaDB (workload) | | | 106.4 | 100.3 | 118.2 |
| php-fpm x4 + nginx (workload) | | | 57.0 | | 130.0 (php-fpm) |
| OS userspace (non-stack, see below) | | ~163 | ~163 | | |

Notes on the table:

- Idle = `snap-idle10b` (04:18:24). The first snapshot 38 s after Ready showed
  cri-o at 53.9 and KCM at 50.5, i.e. KCM grows ~12 MB over the first ten minutes
  while cri-o falls ~20.
- "+WordPress" is `examples/e2e/wordpress` with the MariaDB PVC swapped
  for an emptyDir (no csi-hostpath), plus 100 GETs and a completed WordPress install
  through the ClusterIP. Workload PSS ~163 MB (MariaDB 106 + php-fpm 54 + nginx 3).
- Idle OS userspace: total userspace PSS 449.7 MB minus stack 239.6 = 210.1; of that
  29.0 is `lima-guestagent` (not present on a real VPS) and ~18 is my own probe
  processes (`sort`, `sudo`, `bash`, `awk`, `sleep`), leaving ~163 MB: udisksd 17.8,
  unattended-upgrades 18.6, networkd-dispatcher 18.0, multipathd 14.5, systemd (2)
  15.4, ModemManager 13.0, polkitd 10.0, rsyslogd 9.2, chronyd 7.0, ssh 8.2,
  journald 6.6, udevd 6.2, others.

## Kernel and `/proc/meminfo`

| Snapshot (UTC) | MemAvailable | MemFree | Cached | AnonPages | Slab (SUnreclaim) | KernelStack | PageTables | Shmem |
|---|---|---|---|---|---|---|---|---|
| idle10b 04:18 | 472900 kB (462 MiB) | 115912 | 410748 | 312716 | 76000 (49796) | 3104 | 5088 | 1656 |
| + WordPress 04:23:03 | 326204 (319 MiB) | 41720 | 365292 | 445116 | 77396 (52148) | 3520 | 6912 | 28532 |
| 80-pod burst 04:24:46 | 191360 (187 MiB) | 49632 | 225240 | 497004 | 144516 (114708) | 6656 | 13884 | 32668 |
| post-churn steady 04:25:45 | 267924 (262 MiB) | 46628 | 296076 | 471100 | 111380 (84448) | 4192 | 6908 | 24352 |

The first idle snapshot (04:18:24) read 414940 kB because my own 80 MB tarball sat
in `/tmp` (tmpfs, counted as Shmem); it was deleted and the figures above are
post-removal. Honest headroom figure is `MemAvailable`: page cache (410 MB idle) is
mostly reclaimable, but see thrashing below -- reclaimable is not free.

Per-pod kernel+runtime cost: 5 -> 84 pods moved MemAvailable 326 -> 191 MiB while
summed userspace PSS barely changed (569 -> 577 MB), so roughly 1.6-1.7 MB per pause
pod lands in slab / page tables / kernel stacks / cgroups, plus +22 MB kubelet and
+9 MB cri-o.

## Behaviour on the 1 GiB / 1 vCPU box

- **Install and bring-up:** CPU saturated (us+sy ~95%) for ~25 s during apt/cri-o
  unpack and first starts (04:06:48-04:07:13, `vmstat`), idle 98% from 04:07:38 on.
  No OOM during install or bring-up. Steady idle 04:10-04:18 averaged 1.1% us, 1.1%
  sy, 98.0% idle (n=102 samples).
- **WordPress load:** MariaDB + php-fpm/nginx ready 50 s after apply; 100 sequential
  GETs via ClusterIP returned 100x HTTP 200 in 4 s. No restarts, no OOM at this stage.
- **API churn** (3 rounds of 100 ConfigMaps create/delete + 20 pause pods
  create/delete, each ~20 s, 04:23:16-04:24:16): fine. apiserver peaked at 43.7 MB RSS.
- **First OOM storm, 04:24:12:** kernel `oom-killer` invoked by crun, the apiserver
  (`tokio-rt-worker`) and kubelet; victims php-fpm x5, nginx and CoreDNS (all
  BestEffort, `oom_score_adj` 1000). CoreDNS restarted (Error/137 at 04:24:12); WP
  containers also restarted. Control-plane units (apiserver, KCM, kubelet, cri-o)
  were not killed. The sampler's last `MemAvailable` before the kill was 274768 kB
  (10 s granularity), so the estimate overstated usable memory.
- **80-pause-pod deployment:** run 1 (04:24:22) reached 80 Ready in 21 s; run 2
  (04:26:38) took 4 m 31 s, with `vmstat` showing 12-22 runnable tasks, **sy 93-97%,
  `bi` 2.5-5.5 M blocks/s** and MemFree pinned at 20-45 MB: the 1 vCPU spent its time
  re-faulting executable pages (page-cache thrash), not on user work. 20-pod burst on
  an otherwise idle cluster (04:26:05) was clean: 7 s to Ready, min `MemAvailable`
  239868 kB.
- **Second OOM storm, 04:34:22** during a repeat of the churn script (round 1 pods
  not Ready within 120 s; round took 6 min): php-fpm killed again. By 04:40 the
  WordPress and CoreDNS pods had new names / ages of 3-4 min; the cause of the
  recreation was not investigated.
- No swap exists (`failSwapOn: false` is set by install.sh, so a swapfile is a valid
  lever); kubelet default `evictionHard memory.available<100Mi` was active.
  Sampler min `MemAvailable` over the run: 105512 kB.

## Verdict

- **Fits idle:** 240 MB PSS stack + 163 MB OS userspace + ~84 MB kernel
  (slab 76 + stacks/page tables 8) leaves 462 MiB MemAvailable, 49% of 947 MiB.
- **Fits one small app:** with WordPress + MariaDB (~163 MB PSS) headroom is
  319 MiB (34%) at steady state; 262 MiB after churn.
- **Does not fit pod churn at headroom:** the binding limit is not steady-state RSS
  but transient demand (new pods ~1.7 MB kernel each, kubelet to 108 MB, cri-o to
  67 MB, apiserver to 44 MB) landing on a box whose page cache is also its code
  working set. Below ~150-200 MiB `MemAvailable` the 1 vCPU thrashes, and BestEffort
  workloads (and CoreDNS, which ships BestEffort) get OOM-killed.
- **Is a KCM/kubelet rewrite needed?** Not to fit. Ranked by idle PSS: KCM 62,
  kubelet 61, cri-o 34, kube-proxy 23, CoreDNS 22, flanneld 21, apiserver+scheduler
  17. A Rust KCM at the modelled 12-45 MB saves 17-50 MB (5-15% more of the 319 MiB
  headroom); a kubelet rewrite is a comparable single-digit-percent gain with a far
  larger surface. Neither removes the transient/thrash failure mode. Cheaper levers
  of the same order, all stock Go components u7s only configures: flannel +
  kube-proxy + CoreDNS (65 MB), the Ubuntu cloud-image services above (~100 MB PSS
  of udisksd/multipathd/ModemManager/unattended-upgrades/networkd-dispatcher/
  polkitd/rsyslogd, if the OS baseline were in scope), a swapfile, and a
  non-BestEffort / `system-cluster-critical` CoreDNS so it is not first to die.

## Caveats and unknowns

- aarch64 Lima/vz guest, not an x86_64 VPS (bead mayor-ed4dv covers x86_64);
  binary sizes and some RSS will differ. Kubernetes 1.36.4 (the version
  `build-release-tarball.sh` pins), not the rig's 1.37.1.
- Single run, single VM; OOM reproduced twice, thrash once. Not a statistical bound.
- Snapshot probes (`snap.sh`) add ~18 MB transient and CPU on a 1 vCPU box and
  coincided with the first OOM; the second OOM storm (04:34:22) ran the same churn
  script (which also invokes `snap.sh` once per round), so probe interference is not
  excluded. The clean 20-pod burst (no probes) did not OOM when the system was idle
  of WordPress.
- Lima guest agent (29 MB PSS) is in the OS number only as removable; a real VPS has
  its own agents.
- `scripts/install.sh` prints `line 996: --controllers: command not found` during
  the unit-file heredoc (a backticked word in a comment inside an unquoted heredoc is
  command-substituted). Harmless to the unit; noise only.
- CoreDNS is the current main (self-forward loop fixed): 21.8 MB PSS idle, 28.4 MB
  peak RSS. That is process memory only; it is well under the ~58 MiB cited for the
  fixed CoreDNS, which presumably counts cgroup memory (page cache included).

## Raw data

`/Users/balint.erdos/litehop/u7s/temp/e2e/g0qp7-1341/` (snap-*.txt per-process smaps and
meminfo, vmstat.log, meminfo.log, sampler.log, fine-*.log, kernel-journal.txt,
install.log, scripts). Worktree copy: `temp/g0qp7/`.

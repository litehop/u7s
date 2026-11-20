# Idle memory attribution on a 1 GiB / 1 vCPU node

Bead: mayor-hjwdo.1
Date: 2026-11-20
Base: main 1d100b63 (baselines: tags v0.4.0-snapshot.1, v0.4.3-snapshot.4)

**Answer: idle headroom did not regress. On the gate-shape node (WordPress + MariaDB + warm pod
resident, trimmed Lima, observer-light) MemAvailable is 413 MiB (404.7-417.6, 3 fresh VMs x 2
snapshots), against 407 on v0.4.0-snapshot.1 and 400 on v0.4.3-snapshot.4 measured the same
way; main is 6-13 MiB better, all of it CRI-O (22.6 MiB anon on main, pinned 1.37.3, vs 36-37
on the two older tags, which installed an unpinned CRI-O that is 1.37.4 today). kutwm's ~210-260
MiB differs from this by its ~79 MiB of streaming observers and ~75-85 MiB of untrimmed Lima
guest daemons, not by u7s growth. The attributable, undisputed savings left are small: 35 MiB of
Ubuntu guest daemons (unattended-upgrades, networkd-dispatcher) and keeping the CRI-O pin
(13-20 MiB).**

## Method

- VM: `scripts/release-gate/u7s-vps-1g.yaml` (vz, 1 vCPU, 1 GiB, MemTotal 947.4 MiB, no swap,
  bare Ubuntu 26.04 arm64 cloud image, kernel 7.0.0-34), `vm_trim` applied (masks udisks2,
  ModemManager, multipathd, polkit, lima-guestagent; kubelet MALLOC_ARENA_MAX=1). This is what
  `burst-gate.sh --backend lima` builds. The assigned `lima-node-5` was deleted and recreated
  from that template (same name, same 1 vCPU / 1 GiB shape).
- Not `run-all.sh --stack-only`, as the brief prescribed: that rig keeps u7s-apiserver, the
  scheduler and konnectivity-server on the Mac host and the guest is a golden-image clone with
  rig drop-ins, so the dominant u7s processes would be missing from the guest.
- Install: `install.sh --tarball` from an arm64 tarball built from main
  (`build-arm64-tarball.sh`; the baked zero-arg path needs a signature the local tarball lacks).
  Scheduler is embedded in u7s-apiserver (no u7s-scheduler process); no konnectivity in a
  default single-node install.
- Settle: node Ready, 180 s sleep (post-install startup, image pulls, GC of install-time
  garbage), WordPress + MariaDB (emptyDir, as the gate rewrites it) to Ready, 100 warm-up GETs,
  60 s, 1-replica pause Deployment (the gate's `warmup` phase), then snapshots at +5 and +10
  min. MemAvailable differed by <= 5 MiB between the two snapshots per VM, so the node is at
  rest by then. No bursts were run; this is idle only.
- Snapshot (`snap.sh`, one pass of /proc and cgroupfs, ~0.6-0.9 s): /proc/meminfo, vmstat,
  zoneinfo, memory PSI, `smaps_rollup` of every process (Rss, Pss, Pss_Anon, Pss_File,
  Pss_Shmem), per-cgroup `memory.current` + `memory.stat`, slabinfo top, `fincore` of the
  control-plane binaries.
- 3 fresh VMs of main (6 snapshots), 1 fresh VM each of the two baseline tags (2 snapshots
  each; tarballs built at the tag with that tag's `build-arm64-tarball.sh`, same method).
- Observer overhead: the only observer is one `limactl shell` ssh session, held open for the
  snapshot and visible in the table (sshd-session + sudo + bash + the user systemd manager =
  11.3 MiB anon + 6.4 MiB file PSS). The snapshot script itself peaks at 11.3 MiB RSS for
  0.6-0.9 s (5 repeats). Consecutive MemAvailable reads on the idle node drift by up to +-8 MiB,
  which is the noise floor. No sampler, journal streams, or kubectl loops ran during
  measurement. So MemAvailable here is ~11 MiB below an unobserved node (anon part only), versus
  kutwm's ~79 MiB.
- Raw data: `temp/e2e/hjwdo.1/` (raw archive, if still present): per-run `snap*.txt`,
  `summary-*.txt`, probe outputs.

## Results (main 1d100b63, median of 6 snapshots on 3 fresh VMs)

### Kernel counters (MiB)

| counter | median [min-max] |
|---|---|
| MemTotal | 947.4 |
| MemAvailable | 413.5 [404.7-417.6] |
| MemFree | 51.0 [43.8-72.7] |
| Cached | 422.2 [405.1-430.2] |
| Buffers | 4.0 |
| Active(file) / Inactive(file) | 119 / 277 |
| Mapped (file pages in use by processes) | 183.7 [159.9-190.8] |
| AnonPages | 336.7 [332.1-340.0] |
| Shmem | 27.3 (php-fpm opcache 25.4) |
| Slab (SReclaimable / SUnreclaim) | 95.0 (41.0 / 54.0) |
| PageTables / KernelStack / Percpu | 5.6 / 2.8 / 0.5 |
| VmallocUsed | 17.2 |

Memory PSI was 0 (some and full avg10/60/300) at every snapshot. `vm.min_free_kbytes` is 22528 on
this image, so the high watermark is 33 MiB (zoneinfo: low 7040, high 8448 pages).

### Per-process / per-component (MiB, PSS split)

| component | Pss_Anon | Pss_File | note |
|---|---|---|---|
| mariadbd | 91.7 | 5.8 | workload |
| kube-controller-manager | 44.6 | 26.4 | GOMEMLIMIT=128MiB GOGC=50 in the unit |
| kubelet | 26.1 | 23.1 | |
| crio | 22.6 | 16.8 | pinned 1.37.3 |
| php-fpm + nginx (WordPress) | 15.8 | 10.8 | + Pss_Shmem 25.4 (opcache) |
| u7s-apiserver (+ embedded scheduler) | 13.4 | 9.7 | |
| coredns | 11.9 | 14.3 | pod |
| kube-proxy | 10.8 | 13.6 | pod |
| flanneld | 9.5 | 12.1 | pod |
| conmon (8 processes) | 0.9 | 1.1 | |
| servicelb (beep-controller) | 0.8 | 2.1 | pod |
| unattended-upgrades | 18.6 | 0.1 | Ubuntu |
| networkd-dispatcher | 16.7 | 3.3 | Ubuntu |
| systemd + journald | 8.1 | 4.8 | |
| other OS daemons (udevd, resolved, networkd, rsyslog, chrony, sshd, logind, cron, dbus, agetty) | 32.5 | 4.2 | |
| observer (ssh session + user manager) | 11.3 | 6.4 | measurement artefact |
| sum of per-process anon | 335.3 | | meminfo AnonPages 336.7 |

Per-cgroup (memory.current, MiB, run 1 snapshot 1): system.slice 370 (u7s-kcm 92, crio 67,
kubelet 74, u7s-apiserver 36), kubepods.slice 356 (burstable 294 incl. mariadb pod 114, coredns
72, kube-proxy 48, flannel 51; besteffort 62 = WordPress + pause), user.slice 75 (observer
ssh session; mostly file cache). These include file cache charged to the cgroup, so they exceed
the anon figures above.

### File-backed working set of the control plane

- Pss_File (mapped file pages, resident): kcm 26.4, kubelet 23.1, crio 16.8, apiserver 9.7 =
  76 MiB for the four host processes; with coredns 14.3, kube-proxy 13.6, flanneld 12.1,
  servicelb 2.1 the control plane maps ~118 MiB of file pages. System-wide `Mapped` is 160-191
  MiB (it counts shared pages once per mapping process; the workload adds mariadb 5.8 and
  WordPress 10.8).
- `fincore` (page cache holding the binary, run 3): kube-controller-manager 66 of 70 MiB,
  kubelet 38 of 54 MiB, crio 32 of 49 MiB, u7s-apiserver 19 of 147 MiB: 155 MiB of the 405 MiB
  `Cached` is control-plane binary pages, of which only the ~76 MiB mapped set is hot. The rest
  is startup readahead and is reclaimed first.
- After `drop_caches` Cached refilled 177 -> 395 MiB in 120 s with no workingset refault and no
  change in Mapped (161 -> 171 MiB), so the hot mapped set is ~160-170 MiB at idle.

### Attribution of used memory (MemTotal - MemAvailable = 533.9 MiB)

| item | MiB | % | how known |
|---|---|---|---|
| mariadbd anon | 91.7 | 17.2 | measured, PSS |
| u7s host control plane: kcm 44.6, kubelet 26.1, crio 22.6, apiserver 13.4, conmon 0.9 | 107.6 | 20.2 | measured, PSS |
| cluster pods: coredns 11.9, kube-proxy 10.8, flanneld 9.5, servicelb 0.8 | 33.0 | 6.2 | measured, PSS |
| WordPress: php-fpm/nginx anon 15.8 + opcache shmem 25.4 | 41.2 | 7.7 | measured, PSS |
| OS daemons: unattended-upgrades 18.6, networkd-dispatcher 16.7, systemd+journald 8.1, other 32.5 | 75.9 | 14.2 | measured, PSS |
| observer (ssh session) | 11.3 | 2.1 | measured, PSS |
| unreclaimable slab | 54.0 | 10.1 | meminfo SUnreclaim |
| PageTables + KernelStack + Percpu | 8.9 | 1.7 | meminfo |
| other kernel allocations (vmalloc 17.2 + direct page allocations) | 29.6 | 5.5 | derived: Total - Free - Buffers - Cached - Slab - Anon - PT - KS - Percpu |
| MemAvailable's own discount: totalreserve (high wm 33) + min(pagecache/2, low wm 27.5) + min(SReclaimable/2, 27.5) | 77.4 | 14.5 | derived residual; formula predicts ~81 |
| anon/shmem not matched to a process | 3.3 | 0.6 | residual |
| total | 533.9 | 100 | |

Directly measured rows (process PSS, SUnreclaim, PT/KS/Percpu, Shmem) are 427 MiB = 80%.
Adding VmallocUsed (17.2) gives 83%. The two derived rows (other kernel 12.4 beyond vmalloc,
and the 77.4 MiB MemAvailable heuristic, which I verified against zoneinfo but did not
measure as allocated memory) complete the rest; ">= 90%" holds only with those. 14.5% of
"used" is the kernel's own watermark/reserve discount, not memory any process holds.

## Comparison with kutwm and older releases

| node | MemAvailable at idle (WordPress + MariaDB) | AnonPages | crio anon | kcm / kubelet / apiserver anon |
|---|---|---|---|---|
| v0.4.0-snapshot.1 (this method, 1 VM x 2) | 406.8 [405.4-408.3] | 344.9 | 35.9 | 43.7 / 26.3 / 12.3 |
| v0.4.3-snapshot.4 (this method, 1 VM x 2) | 400.2 [396.7-403.8] | 350.8 | 36.7 | 45.1 / 26.3 / 14.2 |
| main 1d100b63 (this method, 3 VMs x 2) | 413.5 [404.7-417.6] | 336.7 | 22.6 | 44.6 / 26.1 / 13.4 |
| kutwm, main 2b8dc2ab (untrimmed Lima, observers streaming) | 231-260 after WordPress, 203-225 after the first burst | 510-536 | n/a | n/a |

- The older releases are not published for arm64 (release tarballs are x86_64); both were
  built at their tag with that tag's own `build-arm64-tarball.sh` and installed with
  `install.sh --tarball`. Both tags' `install.sh` install CRI-O unpinned (1.37.4 at install
  time today); main pins 1.37.3.
- Component growth between the Oct tag and main: none above 1.3 MiB for kcm, kubelet,
  apiserver. CRI-O is the only mover (-13 to -14 MiB).
- CRI-O attribution: on the 0.4.3 VM (1.37.4, anon 37.0 MiB) I downgraded to 1.37.3-1.1 and
  restarted crio: anon 16.3 MiB after 240 s, MemAvailable 385.2 -> 413.9 MiB. This A/B is
  confounded by the restart (a fresh process), but it agrees with the fresh-install
  comparison (1.37.3 on main: 22.6, n=3; 1.37.4 on both tags: 36-37, n=2).
- kutwm's ~100 MiB "lost headroom" (305-320 in October vs 203-225 on 2b8dc2ab at the same
  point) is mostly its own observers (~79 MiB, measured by kutwm); the remaining ~20 MiB is
  inside the 13 MiB snapshot spread plus untested drift. Under identical method the Oct tag and
  main differ by +7 MiB in main's favour, so no u7s component grew.
- kutwm's absolute idle (231-260) vs the 413 here differs by ~150-180 MiB: its observers
  (~79 MiB) plus its untrimmed Lima guest (~75-85 MiB: lima-guestagent, udisks2, ModemManager,
  multipathd, polkit, 8 kubelet arenas; the gate trims these since). Headroom here is ~180 MiB
  above kutwm's ~230 MiB thrash threshold, and the 20-pod burst cost kutwm measured
  (MemAvailable 253 -> 181, ~72 MiB) would not reach it from here. Inference only; no burst
  was run in this bead.

## Reclaimable items (ranked)

| # | item | est. MiB | confidence | note |
|---|---|---|---|---|
| 1 | Stop/mask `unattended-upgrades` (18.6) and `networkd-dispatcher` (16.7) | 35 anon; MemAvailable +40.3 (399.4 -> 439.7) | high that it frees this on this image; medium that the GCP gate image has them | measured live (`systemctl stop`, run 3). Both are Ubuntu server defaults, not u7s processes |
| 2 | Keep CRI-O pinned at 1.37.3; do not bump the pin to 1.37.4 without re-measuring | 13-20 anon already banked on main | high | 1.37.4 = 36-37 MiB anon idle, 1.37.3 = 16-23 |
| 3 | kcm `GOMEMLIMIT` 128 -> 48 MiB | ~6 anon (43.6 -> 37.8 after a 180 s control restart) | medium; more GC CPU on a 1 vCPU box | kcm heap is mostly live (informer caches), not garbage |
| 4 | WordPress opcache (25.4 shmem) / MariaDB 91.7 anon | up to ~25 + (innodb buffer pool) | high that it is tunable | the gate workload's own config, not u7s; changes what the gate measures |
| 5 | Kernel `vm.min_free_kbytes` 22528 (high wm 33 MiB) | ~18 of MemAvailable accounting | low | accounting only; a lower watermark makes direct-reclaim stalls more likely, not recommended |

Items that are not reclaimable without code work: kubelet 26.1, apiserver 13.4, kcm's live heap
~38. Nothing else above 5 MiB is a u7s component.

## Caveats

- Idle only; no burst was run, so the claim that the current headroom clears the 20-pod
  threshold is inference from kutwm's costs.
- Gate-trimmed Lima guest (arm64, Ubuntu 26.04, kernel 7.0). The GCP x86_64 node was not
  measured here; `unattended-upgrades` / `networkd-dispatcher` presence there is unverified.
- One VM per baseline tag; main n=3. Spread on main (13 MiB) is as large as main-vs-0.4.3.
  The 6-13 MiB gap rests on the CRI-O version, which the downgrade A/B supports.
- The 3 main VMs were created sequentially on a host shared with other workers (host load
  average 9-10); memory results do not depend on host CPU, install/settle times do and are not
  reported.
- The CRI-O A/B and the kcm GOMEMLIMIT probe were run once on a live VM, not repeated.
- The MemAvailable "discount" row and the "other kernel" row are derived, not measured.

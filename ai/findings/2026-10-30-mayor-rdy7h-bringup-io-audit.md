# Bring-up and example I/O audit on a 1 GiB node (2026-10-30)

Bead: mayor-rdy7h (discovered from mayor-uaasp)

**About 95% of the disk reads (about 100 of 106 GB on Lima) are
page-cache refault thrash that starts the moment the Traefik + WordPress +
MariaDB example lands on the 947 MiB node, not image data; the other two
sources are install.sh's apt + tarball writes (1.8 GB, about 0.35 GB avoidable)
and crio's image unpack (1.6 GB written for 1.3 GB of images, about 0.15 GB
avoidable by dropping beep and Traefik from the default path).** Enabling a
512 MiB zram swap device on the same VM cut idle reads from 70-300 MB/s to
under 10 MB/s (measured below), so the thrash is avoidable with a memory
change, not an image or storage-driver change. Image pull is not duplicated,
the storage driver is overlay, and nothing is fsync-heavy.

## Method

One fresh Lima VM (`lima-node-5`, deleted and recreated from
`scripts/release-gate/u7s-vps-1g.yaml`: vz, aarch64, 1 vCPU, 1 GiB, 12 GiB
virtio disk, Ubuntu 26.04 cloud image, no mounts, no swap, MemTotal 947 MiB).
aarch64 tarball from `scripts/release-gate/build-arm64-tarball.sh`,
`install.sh --tarball <local path>` (the baked `file://` URL path fails the
signature fetch on a local tarball, so the gate's zero-arg path was not
used). Then `kubectl apply` of `examples/e2e/traefik` + `examples/e2e/wordpress`
(MariaDB `volumeClaimTemplates` replaced with `emptyDir`, as in the uaasp
run, so csi-hostpath's images are out of scope), then 5 min idle.

A sampler (systemd transient unit) recorded every 5 s: `/proc/diskstats`
for `vda`, every cgroup's `io.stat` (cumulative, so exited processes stay
counted until their cgroup is removed), `/proc/pressure/io`, and a
`du -sx /var/lib/containers/storage` (the sampler's own reads are about
2.2 GB of the 106 GB: 2%). Timestamps (epoch, VM clock): install
1793333034-1793333085, kube-system Ready 1793333106, example applied
1793333157, all pods Ready 1793333210, sampling ended 1793333526. Raw samples:
`temp/e2e/rdy7h-20261030/raw/` in the mayor checkout, if still present.

## Results (whole run, `vda` totals from `/proc/diskstats`)

| Window | Duration | Read | Written | Read ops |
|---|---|---|---|---|
| install.sh | 51 s | 1195 MB | 1813 MB | 11.4k |
| install end to kube-system Ready | 21 s | 1030 MB | 563 MB | 13.7k |
| kube-system settle (idle, 4 pods) | 50 s | about 0.4 GB (about 5 MB / 5 s once settled) | 0.2 GB | - |
| example apply to all Ready | 57 s | 17.0 GB | 1.1 GB | 159.8k |
| 5 min idle with the example running | 312 s | 83.5 GB | 17 MB | 803k |

Reads in the last two rows ran at 300-500 MB/s on a node whose entire image
store is 1.3 GB. They are file-page refaults: `/proc/vmstat`
`workingset_refault_file` = 30.5 M pages (about 125 GB) against `pgpgin`
125.7 M KiB at the end of the run, i.e. essentially all page-ins were
refaults of pages evicted moments earlier. Per cgroup (idle 5 min, `io.stat`
rbytes): traefik 17.1 GB, coredns 11.5 GB, kubelet 14.3 GB,
u7s-kcm 10.2 GB, crio 7.7 GB, flannel 4.9 GB, kube-proxy 3.6 GB,
lima-guestagent 3.6 GB, u7s-apiserver 3.0 GB, mariadb 2.4 GB, WordPress pod
1.4 GB. These are mostly mapped executable text of Go binaries being
evicted and re-read. The kube-system-only node was quiet (about 1 MB/s) until
the example was applied, then never recovered.

### Experiments on the same VM (all after the main run)

| Change | Idle read rate (diskstats, 5 s samples) |
|---|---|
| none | 350-830 MB / 5 s |
| Traefik scaled to 0 (180 s) | 350-830 MB / 5 s: not Traefik |
| plus 512 MiB zram swap, zstd (210 s) | 180 MB / 5 s in the first 25 s, under 30 MB / 5 s after 100 s, near 0 by 190 s; 3.2 GB read in 210 s total; zram held 148 MB at the end |

This matches the earlier decision to leave swap to the operator (docs suggest
zram) but shows the cost of not having it: with no swap the kernel cannot
evict cold anonymous pages (MariaDB, php-fpm, kubelet heap), so it evicts the
hot file-backed text of every other process.

## Ranked sources

| # | Source | Read | Written | Avoidable? | How | Est. saving |
|---|---|---|---|---|---|---|
| 1 | Page-cache refault thrash once the example runs (Lima) | about 100 GB | about 0 | Yes | zram swap on by default or in docs for 1 GiB, and/or shrink resident memory so the file working set fits; also bound `crio` pull bursts | about 97% of reads in the measured 5 min (83.5 GB to about 3 GB with zram) |
| 2 | install.sh: tarball stage + `install` copy | 0.1 GB | about 0.68 GB (85 MB tarball + 299 MB extract + 299 MB copy to `/opt/u7s`) | Partly | move or extract straight to `$BIN_DIR` (same filesystem under `/var/tmp`) instead of `install -m` from the stage | about 0.3 GB written |
| 3 | install.sh: apt (cri-o, crun, conmon, criu, kubectl, kubernetes-cni, curl deps) | about 0.2 GB | about 0.5 GB (72 MB debs, about 293 MB unpacked, 154 MB lists) | Mostly not | lists: skip `Translation-en` (33 MB), dep11 (6 MB) with `Acquire::Languages=none` and `-o Acquire::IndexTargets...`; four `apt-get update` call sites could be one | about 0.04-0.1 GB |
| 4 | crio image pull + unpack, kube-system (flannel, flannel-cni-plugin, kube-proxy, coredns, beep-lb, pause) | small | about 0.6 GB (crio.service: 635 MB) for 385 MB unpacked / 122 MB compressed | Partly | do not deploy beep (117 MB unpacked, 35 MB compressed) unless a `LoadBalancer` Service exists | about 0.15 GB written, 1 pod of memory |
| 5 | crio image pull + unpack, example (traefik, mariadb, nginx, wordpress) | small | about 1.0 GB (crio.service: 980 MB) for 892 MB unpacked / 278 MB compressed | Example only | not part of u7s; Traefik alone is 178 MB unpacked / 50 MB compressed; the example's nginx sidecar + php-fpm-alpine could be one image | up to 0.2 GB if Traefik is not default |
| 6 | Everything else (apiserver sqlite, journald, kubelet, container logs, ext4 journal) | n/a | about 0.4 GB incl. install-time journal | No | apiserver wrote 6 MB over bring-up and 2 MB over the example; idle writes were 17 MB in 5 min | none |

Not duplicated or heavy: each image was pulled exactly once (crio journal:
9 `Pulling image` lines, 9 distinct images; flannel's init container reuses
the flannel image); crio writes (1.6 GB) equal unpacked bytes (1.28 GB, from
`layers.json` `diff-size`) plus one compressed temp copy (0.40 GB), so unpack
is not amplified; pulls were serial and took 2-6 s each on Lima.

## Runtime configuration (verified on the VM)

- Storage driver: `storage_driver = "overlay"` (crio's logged config);
  `/etc/containers/storage.conf` does not exist, so these are defaults.
  Overlay mounts show `fsync=volatile`, so container layer writes do not
  fsync.
- Signature policy: `/etc/crio/policy.json` from the package; no signature
  verification cost was visible (no network or CPU bursts beyond pulls).
- `crio.service` CPU: 15.8 CPU-s cumulative over about 20 min on this
  vCPU (`cpu.stat`, `usage_usec`); uaasp saw 127 CPU-s in 4 min on e2-micro.
  CPU was not sampled per phase here, so the decompression share is not
  attributed.
- `10-memory.conf` sets only `stream_idle_timeout`; no pull-concurrency
  option is set (not tested whether crio exposes one).
- Image sizes (compressed layers from registry manifests via `curl`; unpacked
  from `diff-size` in containers storage on the VM, arm64): kube-system:
  coredns v1.14.7 21.7 MB / 74 MB, kube-proxy v1.37.1 26.5 / 84, flannel
  v0.28.9 31.9 / 99, flannel-cni-plugin 5.4 / 11, beep-lb 35.6 / 117, pause
  3.10.2 0.3 MB. Example: traefik v3.7.16 50.2 / 178, mariadb 11.8.6-noble
  104.2 / 365, nginx:alpine 26.3 / 64, wordpress 6.7.0-php8.3-fpm-alpine
  98.5 / 285. amd64 compressed sizes differ by -3% to +10% (traefik 55.4,
  kube-proxy 30.2, coredns 24.3, mariadb 106.3 MB; wordpress 97.0); unpacked
  sizes were not measured on amd64. Three layer digests are shared between
  images; the saving is negligible.

## Lima versus GCP e2-micro

- Disk: Lima virtio sustains 300-500 MB/s, so thrash completes as fast
  reads and shows as read volume; a pd-standard disk saturates near 9 MB/s
  (uaasp), so the same thrash would appear as io PSI and a long wall time,
  not a large byte count. uaasp's 3.8 GiB read in 10 min with 80.5k ops
  (about 50 KB/op) cannot be explained by pulls: the WordPress-only images
  are about 0.23 GB compressed. That fits refault thrash during pulls and
  MariaDB start, but it is inference: refault counters were not captured on
  GCP.
- uaasp found GCP quiet at minutes 55-56 (22-32 MB/min) after WordPress was
  ready, whereas Lima never recovered. Differences not isolated: Traefik
  was not part of uaasp's run (removing it here changed nothing),
  lima-guestagent (27 MB RSS, 89 MB cgroup), aarch64 binaries and a different
  kernel.
- Install is network-fast here (51 s, apt `Fetched` 24 MB in 2 s) so
  install wall time is not comparable; its byte counts (1.2 GB read / 1.8 GB
  written vs uaasp 1.1 GB / 1.9 GB on GCP) match, which supports the install
  rows. The install read volume was not decomposed.
- Install writes are an estimate from file sizes (tarball, extract, copy,
  debs, lists); individual processes exited before sampling so per-process
  attribution is not measured.
- The tarball here is the gate arm64 build (84.5 MB, four binaries),
  comparable in structure to the release tarball (93 MB per uaasp).

## Follow-ups

See the bead notes on mayor-rdy7h for the filed beads.

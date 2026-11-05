# Lima vs GCP idle anon memory, same u7s release

Bead: mayor-18a8g
Date: 2026-11-05

**Answer: with no observers Lima carries 72-80 MiB more anon than GCP (not 120-170), and it is
guest-OS and harness, not u7s: ~70 MiB of Lima-only or oversized Ubuntu daemons plus the Lima guest
agent, plus 16 MiB of glibc arenas in the arm64 kubelet, partly offset by ~30 MiB of GCP-only
agents. Lima needs trimming rather than a correction factor: stopping `lima-guestagent`, `udisks2`,
`ModemManager`, `multipathd`, `polkit` and setting `MALLOC_ARENA_MAX=1` on kubelet took Lima's
WordPress-state AnonPages from 422 to 338 MiB on a live VM, 12 MiB below GCP (whose own
snapd/osconfig/guest-agent are real production cost).**

## Method

- `v0.4.3-snapshot.4` on both, n=1 per side, one-shot snapshots only (no observers); collector is
  the adwea `collect.sh` plus pagesize/THP/arch/cgls. Lima: `u7s-vps-1g.yaml` (vz, aarch64, 1 vCPU,
  MemTotal 947 MiB), arm64 tarball built at the tag with `build-arm64-tarball.sh`,
  `install.sh --tarball` (the baked zero-arg path needs `.sig` files the local build lacks; the
  first attempt also hit the first-boot unattended-upgrades dpkg lock and was retried). GCP:
  `n1-custom-1-1024` Spot, Ubuntu 26.04 amd64, release tarball from the GitHub release,
  `install.sh --tarball` (sha256 not re-verified). `burst-gate.sh --install-only` was not used (it
  only accepts an unpublished `--tarball` experiment); the VMs came from `vps.sh` / `limactl`.
- States: `bare` = install done + settle (GCP ~7 min, Lima 6 min); `wp` = WordPress + MariaDB
  (emptyDir) applied as the gate does, 31 GETs, +5 min.
- Same on both: PAGESIZE 4096, THP `madvise`, 1 vCPU, no swap. Different: kernel 7.0.0-1014-gcp
  (x86_64) vs 7.0.0-34-generic (aarch64); MemTotal 975860 vs 970140 kB.
- Snapshot times (UTC, 2026-11-05): GCP wp 02:07:29, Lima bare 02:10:06, Lima wp 02:16:28, Lima
  trimmed 02:22:10.

## Totals (MiB)

| | GCP bare | Lima bare | GCP wp | Lima wp | Lima wp trimmed |
|---|---|---|---|---|---|
| AnonPages (meminfo) | 233.7 | 309.3 | 349.8 | 422.1 | 337.7 |
| sum of per-process Pss_Anon | 234.0 | 313.6 | 348.7 | 426.4 | 340.1 |
| Slab / SUnreclaim | 86.5 / 52.8 | 86.9 / 51.9 | 83.9 / 54.7 | 79.4 / 53.1 | 80.0 / 53.8 |
| PageTables | 6.0 | 5.1 | 7.6 | 6.4 | |
| KernelStack | 3.3 | 3.0 | 3.8 | 3.3 | |

Lima minus GCP in AnonPages: bare +75.6, wp +72.3. Slab, kernel stacks and page tables match within
noise, so arch, kernel and page size are not the cause. MemAvailable is not comparable in this
run (GCP wp 229 vs Lima 327 MiB): the GCP VM holds the 100 MB release tarball in a tmpfs `/tmp`
(Shmem 117 vs 27 MiB), which is page-cache side, not anon.

## Attribution (wp state, per-process Pss_Anon, MiB; the bare state differs by at most a few MiB per row)

| category / process | Lima | GCP | delta |
|---|---|---|---|
| lima-guestagent (Lima-only) | 21.8 | 0 | +21.8 |
| udisksd (Ubuntu cloud image, not on the GCP image) | 17.5 | 0 | +17.5 |
| kubelet (glibc malloc arenas, below) | 41.4 | 25.6 | +15.8 |
| ModemManager | 12.1 | 0 | +12.1 |
| multipathd | 11.2 | 2.1 | +9.1 |
| polkitd | 8.7 | 1.3 | +7.4 |
| snapd (GCP-only) | 0 | 14.0 | -14.0 |
| google_osconfig_agent (GCP-only) | 0 | 9.2 | -9.2 |
| google_guest_agent (GCP-only) | 0 | 6.6 | -6.6 |
| remainder (listed below) | | | +23.8 |
| **total (process sum)** | 426.4 | 348.7 | **+77.7** |

Remainder: chrony +4.9, unattended-upgrades +4.4, rsyslog +4.3, systemd/init +3.4, udevd +2.7,
logind +2.1, agetty +1.9, dbus + networkd-dispatcher +2.7, collector `sort` +5.3 (Lima only; the
collector's own pipeline), ssh/sshd-session -9.0, php-fpm -2.9, crio -2.7, kcm -1.4, small others.

u7s is the same size on both sides: u7s-kcm 45.1 vs 46.5, u7s-apiserver 13.1 vs 12.7, crio 22.6
vs 25.3, mariadbd 91.8 vs 91.1, coredns 12.2 vs 11.6, kube-proxy 11.1 vs 10.9, flanneld 9.5 vs 9.7;
kubepods.slice process anon 141.0 vs 142.9. By cgroup (bare, anon): system.slice 261.4 vs 186.8
(+74.6), kubepods 31.8 vs 32.3, user.slice 8.0 vs 8.4, init.scope 7.3 vs 3.8. So +75 of the +75.6 is
system.slice.

Running services only on Lima: ModemManager, lima-guestagent, udisks2. Only on GCP:
google-guest-agent, google-osconfig-agent, snapd. fwupd was not running on either at idle.

## kubelet +15.8 MiB: glibc arenas

kubelet is dynamically linked to glibc on both (cgo). Lima's has exactly 8 anonymous 2048 kB
mappings at 64 MiB-aligned addresses (glibc per-thread arenas, the 8-per-core cap) = 16 MiB; GCP's
has none. It is systematic, not first-start: after `systemctl restart kubelet` the 8 arenas
reappeared (Pss_Anon 40.1 MiB). With a drop-in `Environment=MALLOC_ARENA_MAX=1` on the same VM,
Pss_Anon was 24.1 MiB (GCP 25.6-26.2). Why arm64/Lima grows arenas and x86/GCP does not was not
determined.

## Trim experiment (Lima, same VM, wp state, no reinstall)

`systemctl stop udisks2 ModemManager multipathd multipathd.socket polkit lima-guestagent` plus the
kubelet drop-in: AnonPages 422.1 -> 337.7 MiB (-84.4: kubelet -17, daemons -67), MemAvailable
327 -> 413 MiB. `limactl shell` kept working with the guest agent stopped (it uses ssh). This was a
single live-VM measurement, not a gate run. Trimmed Lima is 12 MiB below GCP because GCP carries
~30 MiB of snapd/osconfig/guest-agent, which a production 1 GiB GCP node also pays.

## Verdict

- The earlier "~120-170 MiB" included observer sessions (adwea measured +62 MiB anon for ten on
  GCP). The observer-free delta is ~75 MiB, at both bare and WordPress states.
- Burst knees measured on stock Lima are pessimistic for GCP by about 75 MiB (8% of the node,
  roughly a quarter of the ~300 MiB burst headroom). Trim Lima instead of applying a factor: the
  five daemons (-67) and kubelet arenas (-17) leave Lima ~12 MiB lighter than GCP; treat "GCP is
  ~12 MiB heavier than trimmed Lima" as the residual.
- GCP's snapd/osconfig/guest-agent are production reality and are not to be trimmed from the model.
- Limits: n=1 per side; ssh sessions differ (IAP vs `limactl shell`, a few MiB); the trim was
  measured once; the arm64 arena cause is unexplained; production x86 kubelet has no arenas, so
  `MALLOC_ARENA_MAX=1` is a Lima/arm64 trim only. The earlier Oct-vs-Nov Lima drop (kutwm) is not
  addressed here.

## Raw data

Per-process, cgroup, meminfo and kubelet-mapping archives (hostnames embed the operator project,
not committed): mayor checkout `temp/e2e/18a8g/` if still present.

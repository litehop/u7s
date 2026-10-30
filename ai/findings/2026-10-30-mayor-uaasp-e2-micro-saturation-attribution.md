# e2-micro CPU/IO saturation: attribution (2026-10-30)

Bead: mayor-uaasp (feeds mayor-vw7jc)

**Disk I/O saturation is attributable to our install, image pull and
MariaDB/WordPress bring-up; CPU saturation is not attributed: the harness
cgroup alone used 20-23 CPU-s/min (~0.33-0.38 vCPU) under load and the whole
node 30-100 CPU-s/min (0.5-1.7 vCPU) in min 46-54, against a documented
e2-micro sustained share of 0.25 vCPU (2 vCPUs at 12.5% each; 100% burst
for ~30 s, token bucket), with mariadb CFS-throttled for 78.5 s, so a
platform CPU cap may be part of it and was not excluded.** Evidence for the
I/O half: on a pd-standard e2-micro the u7s install, then container image
pull + unpack plus MariaDB/WordPress start-up, drive the boot disk to 85-93%
busy and PSI to cpu ~57% / io ~73%; a VM with no u7s is quiet after its
first ~1 minute, and the same saturation reproduces on a 55-minute-old VM, so
"a fresh VM is saturated for ~20 min" is wrong. Burst-credit exhaustion was
not observed via steal (<= 1.8 s in any minute), but steal does not reliably
expose shared-core capping, so it is not excluded. No single VM did the
first-boot install and WordPress back to back: gate2's install phase ran on a
fresh VM and its bring-up on a 47-minute-old one with cached packages.

Source for the e2-micro figures: Google Cloud docs, "General-purpose machine
family", E2 shared-core machine types and CPU bursting
(docs.cloud.google.com/compute/docs/general-purpose-machines, read 2026-10-30).

## Method

Three Spot e2-micro VMs, us-west1-b, `ubuntu-2604-lts-amd64`, 10 GB
`pd-standard` (identical to `gcp_vps_create`), sampled every 5 s by the
extended `scripts/release-gate/vm-sampler.sh` (`attrib.tsv`: PSI totals,
`/proc/stat`, boot-disk `/proc/diskstats`, per-cgroup `cpu.stat`/`io.stat`,
per-pid CPU/IO). Counters are cumulative, so nothing before the sampler
started (~45 s after boot) is lost, only its time resolution.

| VM | Purpose | Outcome |
|---|---|---|
| ctl | no u7s, 26 min | valid |
| gate-dup | gate-like | discarded: my manual start duplicated the boot-time startup script, two installers ran concurrently |
| gate2 | gate-like: v0.4.2-snapshot.1 `install.sh`, 180 s settle, `examples/e2e/wordpress` (emptyDir MariaDB) | first install aborted (my VM name made the node cert CN > 64 chars); re-run 47 min after boot with `--node-name`, packages cached |

Total VM wall-clock about 103 min; all deleted. gate2 therefore has a real
first-boot install phase (min 1-3) and a bring-up + WordPress phase measured
on an aged VM (min 45-56). The numbers quoted here are the evidence; the
raw samples are not kept.

## Control VM (no u7s), minutes since sampler start

| Window | cpu PSI some | io PSI some / full | CPU-s (cgroup) | disk read / write | ops r / w |
|---|---|---|---|---|---|
| boot to sampler start (~45 s) | 3.8 s | 14.6 s / 10.5 s | 18.3 (udevd 2.2, cloud-init 1.7, snapd 1.6, guest-agent 0.6) | 383 / 203 MB | 7.7k / 2.0k |
| min 0-4 | 0% | 0% | 10 | 40 / 25 MB | 470 / 352 |
| min 5-24 (per 5 min) | <= 0.1% | <= 0.1% | 8 (all of it is the two samplers, 0.84 CPU-s/min each) | <= 15 / <= 8 MB | <= 654 / <= 204 |

OS first-boot jobs (b): `systemd-analyze blame` top: snapd.seeded 11.6 s,
snapd 9.5 s, cloud-config 7.1 s, grub2-common 6.9 s, google-guest-agent
6.2 s. Their whole footprint is the first row: about 45 s of io stall, then
nothing. No unattended-upgrades/apt-daily CPU appears in the 26-min cgroup
data.

## gate2 timeline (minutes since sampler start; sampler start = boot + ~45 s)

CPU-s are cgroup `usage_usec` (system.slice + kubepods.slice + user.slice;
`/proc/stat` jiffies undercount it about 3x here). "harness" is the
google-startup-scripts / rerun cgroup: install.sh, `kubectl wait`, and the
sampler itself.

| Min | Phase | cpu PSI | io PSI some / full | CPU-s | harness | crio | kubepods | disk busy | read / write MB | ops r / w |
|---|---|---|---|---|---|---|---|---|---|---|
| boot | firmware, systemd | 3.8 s | 14.8 s / 9.8 s | 17 | 0 | 0 | 0 | 15 s | 382 / 89 | 7.8k / 2.1k |
| 0 | wait 60 s | 0% | 0% | 2 | 2 | 0 | 0 | 0% | 0 / 119 | 24 / 166 |
| 1 | install: download, extract, apt (cri-o, kubectl) | 2% | 25% / 23% | 28 | 26 | 0 | 0 | 40% | 679 / 1427 | 8.8k / 7.7k |
| 2 | install | 13% | 20% / 15% | 51 | 47 | 1 | 0 | 40% | 411 / 448 | 3.8k / 2.5k |
| 3 | install ends (aborted at CSR) | 7% | 2% / 0% | 22 | 15 | 0 | 0 | 5% | 11 / 8 | 224 / 258 |
| 4-44 | apiserver + kcm only, no kubelet | 0-1% | <= 1% | 3-5 | 2-4 | 0 | 0 | <= 1% | <= 19 / <= 5 | <= 260 / <= 220 |
| 45 | install re-run, packages cached | 2% | 19% / 17% | 16 | 12 | 0 | 0 | 29% | 848 / 854 | 5.7k / 4.0k |
| 46 | kubelet + crio start, kube-system image pulls | 24% | 46% / 21% | 53 | 10 | 30 | 3 | 60% | 615 / 969 | 12.4k / 9.3k |
| 47 | pulls + unpack | 57% | 73% / 9% | 100 | 16 | 62 | 13 | 80% | 308 / 369 | 7.6k / 3.3k |
| 48 | settle (180 s) | 50% | 68% / 18% | 82 | 20 | 35 | 16 | 85% | 366 / 424 | 7.7k / 4.8k |
| 49 | WordPress+MariaDB applied at 49.5 | 60% | 49% / 11% | 61 | 23 | 3 | 17 | 64% | 517 / 41 | 12.5k / 1.4k |
| 50 | mariadb init, wordpress pull | 39% | 78% / 27% | 71 | 23 | 4 | 22 | 93% | 550 / 73 | 15.0k / 1.7k |
| 51 | | 57% | 35% / 11% | 51 | 23 | 1 | 21 | 52% | 258 / 60 | 6.2k / 3.1k |
| 52 | | 53% | 15% / 5% | 46 | 22 | 0 | 19 | 27% | 92 / 15 | 2.9k / 0.7k |
| 53 | | 37% | 30% / 13% | 40 | 20 | 0 | 13 | 45% | 199 / 7 | 5.6k / 0.5k |
| 54 | mariadb Ready (min 53.1), WordPress Available (54.2) | 10% | 19% / 10% | 30 | 13 | 0 | 11 | 31% | 145 / 3 | 4.9k / 0.2k |
| 55-56 | quiet | 1-2% | 2% | 7-8 | 3 | 0 | 2 | 3% | 22-32 / 4 | 570-700 / 140-215 |

Per-source totals:

- **Install phase (min 1-3):** 1101 MB read, 1883 MB written, device busy
  50 s of 180 s; system.slice 101 CPU-s, of which install.sh's tree 88.
  `apt-get`/`dpkg` account for about 0.76 GB of the writes (cri-o + kubectl
  packages unpack ~280 MB; the rest is the 93 MB tarball, its extraction to
  `/opt/u7s` (314 MB), journald, apt-check (8 CPU-s, 106 MB, triggered by
  our apt invocations)). The remaining writes are short-lived children that
  exited between samples and are not individually attributable.
- **Bring-up + WordPress (min 45-54):** 3.8 GiB read (80.5k ops), 2.7 GiB
  written (28.8k ops) in 10 min; device busy 340 s of 600 s, peak 93%;
  `/var/lib/containers/storage` ends at 2.05 GB. crio.service 127 CPU-s in
  min 45-48 (1.2 GB written). The MariaDB pod used 41 CPU-s and was CFS
  throttled for 78.5 s (limit 375m); another burstable pod 36 s throttled.
  Steal over the whole run: <= 1.8 s in any minute (0.0-0.1 s in min 45-56).
- Sustained disk plateau while pulling: about 250 read IOPS at ~37 KB/op
  (~9 MB/s) at 85-93% busy; peak 35 MB/s read+write during install. These
  are measured throughput at saturation of this 10 GB pd-standard, not a
  quoted GCP limit.

MariaDB on the aged node (not a boot effect): applied 03:26:52, entrypoint
started 03:28:05 (73 s: image pull), datadir init 21 s, temporary server
42 s to start (03:28:44-03:29:26), real server ready 03:30:20, then the
liveness probe (`initialDelaySeconds: 120`, `timeoutSeconds: 1`,
`failureThreshold: 3`) killed it at 03:30:28 (restart count 1) because the
container had not answered within ~135 s. WordPress Available at 03:31:30.

## Archive mining (existing gate run, v0.4.2-snapshot.1)

`vw7jc-run2/run-1`: VM created 05:40:56, install 05:42:11-05:47:03 (4 m 52 s),
idle to 05:50:05, WordPress applied 05:50:05. `psi-cpu.log` holds only cpu
PSI: total 3.87 s at install start and 70.7 s at the end of idle (67 s of
stall, ~14% of the 475 s window, avg300 10.4%), but **avg10 was 0.4-0.5% at
the end of idle, 9 minutes after create**: the node was already quiet before
WordPress. The 72% io / 61% cpu readings were taken during the WordPress
phase (05:50-06:00). The archive has no io PSI, no disk counters and no
per-cgroup data (the old sampler records only MemAvailable and RSS), so
nothing in it separates install from workload I/O. The "~20 min" is the
length of the whole run, not a boot property.

## Verdict

- **(a) ours: dominant.** Install.sh (about 3 GB of disk traffic in 3 min on
  first boot) and, more so, first-time image pull and unpack (crio) plus
  MariaDB/WordPress start-up. Reproduced at VM age 55 min, so not a
  fresh-VM or credit effect.
- **(b) OS first-boot: ~1 min, negligible.** 14.6 s io stall and 18 CPU-s,
  then 1.5 CPU-s in 25 min; no apt-daily/unattended-upgrades work seen.
- **(c) platform: the disk is the saturated resource (85-93% busy at
  ~250 read IOPS), which turns our I/O burst into PSI.** Not tested against
  a faster disk (the pd-standard choice is deliberate), so how much a
  pd-balanced disk would shorten it is unmeasured. **CPU: not established.**
  Node CPU use (0.5-1.7 vCPU for 9 min) exceeds the 0.25 vCPU sustained
  share, so burst budget was being spent; exhaustion is not visible in steal
  and is not excluded. mariadb's throttling is its own 375m limit.

## Recommendation for vw7jc

The mariadb start-up window overlaps the heaviest I/O we generate, so
sequencing is the first lever, ahead of changing the disk:

1. Gate and `examples/e2e/wordpress`: pre-pull the mariadb and wordpress
   images (or apply mariadb, wait Ready, then WordPress) so datadir init does
   not compete with ~2 GB of layer unpack; wait for io PSI some avg10 < 5%
   instead of a fixed 180 s settle (on a fast re-install the settle ended
   mid-pull, cpu PSI 50% / io 68% in its last minute).
2. `install.sh` (not edited here; the cert-generation worker owns it):
   return only after kube-system pods are Ready, so users and the gate start
   workloads on a quiet node.
3. The MariaDB manifest still needs a `startupProbe` (or a larger liveness
   delay / `timeoutSeconds`): it was liveness-killed at 135 s even on a warm
   node. This is a separate failure from the entrypoint's own temporary-server
   exit recorded in vw7jc, but the same slow-start root cause.
4. A real user hits this: `kubectl apply` of a workload right after install
   on a 10 GB pd-standard sees the same disk-bound pull.

## Caveats

- The harness cgroup used 20-23 CPU-s/min during the WordPress phase vs
  0.84 CPU-s/min per sampler at idle (control). The cgroup holds only the
  sampler and `kubectl wait`; per-pid CPU of its short-lived forks is not
  attributable. The sampler's own cost under load is therefore an unresolved
  confound (a re-run with per-pid sampling off would settle it; the VM cap
  was reached). The sampler now walks per-pid files only every 30 s; on a
  synthetic 500-pid fixture (macOS, not a VM) a sample cost 0.145 s CPU with
  the walk vs 0.064 s without.
- Per-pid I/O folds reaped children into the parent; use cgroup numbers.
- Side finding: `install.sh` fails with `string too long` when
  `system:node:<fqdn>` exceeds 64 characters (GCE FQDN is
  `<name>.c.<project>.internal`, so the limit depends on the project id
  length); gate names (`u7s-rg-MMDDHHMMSS-N`) fit.

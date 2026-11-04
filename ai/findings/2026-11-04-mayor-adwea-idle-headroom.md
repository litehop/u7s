# Where did the ~100 MiB of idle headroom go?

Bead: mayor-adwea
Date: 2026-11-04

**Answer: no u7s release step lost it: on identical fresh GCP `n1-custom-1-1024` VMs MemAvailable
is flat from v0.3.0-snapshot.1 to v0.4.3-snapshot.4 (idle 483-506 MiB, with WordPress+MariaDB
337-356 MiB, at the gate's "end of settle20" point 306-330 MiB, matching October's 305-320), and the
Lima 219 MiB was a degraded, observer-laden measurement: attaching kutwm's 10 streaming ssh
sessions to the same GCP VM costs 79 MiB of MemAvailable (323 -> 244), the same size and shape
(anon up, page cache down) as the Lima Oct -> Nov drop (321 -> 250 pre-burst).** The Lima side
of that attribution is circumstantial (no Lima VM was run, by instruction); mayor-9ygmh's A/B ramp
is the direct test.

## 1. Premise check: Oct 305-320 vs Nov 219 is not like-for-like

| | Oct (i4bvb) | Nov (kutwm) |
|---|---|---|
| platform | Lima vz aarch64, 1 vCPU, 1 GiB (MemTotal ~947 MiB), `u7s-vps-1g.yaml` | same template and pinned image (release-20260927) |
| u7s | main b3a14d06 (10-15) | main 2b8dc2ab (11-04) |
| install | zero-arg install.sh (arm64 tarball, baked URL) | `install.sh --tarball` (harness fix) |
| point | gate "end of settle20": WordPress+MariaDB, warm-up pod, 20-pod burst scaled to 1, 60 s settle | 10:24:00 UTC, same gate point, ~3 min after burst 20 |
| observers | gate harness only | gate harness + ~10 extra streaming `limactl shell` sessions (1 s sampler, 2 `journalctl -f`, 7 curl\|jq/curl loops), kutwm's own caveat |
| prior state | first burst | after one 20-pod burst, thrash, ~2.5 min of 93% sys |

The same-workload "pre-burst, 1 pod" snapshots exist on both sides (Oct: `ai/findings/2026-10-16-mayor-i4bvb-phase2-memory-protection.md`; Nov:
`temp/e2e/kutwm/gate2/run-1/out/snap.txt`, kutwm's own raw data, units as printed):

| Lima, WP+MariaDB, 1 burst pod | Oct 16 | Nov 4 | delta |
|---|---|---|---|
| MemAvailable | 321 | 249.6 MiB (255556 kB) | -71 |
| AnonPages | 450 | 493.5 MiB | +43 |
| Cached | 347 | 293.9 MiB | -53 |
| user.slice (Nov only) | n/a | 146.7 MiB (user-502.slice 132 MiB) | |

(Oct numbers are quoted as "MB" in the old doc; a 5% unit ambiguity does not change the picture.)
So the comparison is like-for-like in workload and gate point, but not in observer load, and the
loss shows up as extra anon + less cache, which is the signature of extra resident processes,
not of a larger kernel/slab footprint (Nov Lima Slab 81-87 MiB vs GCP 91-95).

Also noted: Lima idle (no WordPress) in kutwm's stream is MemAvailable 373 MiB, AnonPages 391 MiB
(10:14:30), vs GCP idle 483-506 MiB / anon 215-231 MiB. Lima carries ~170 MiB more anon than
GCP at idle in November; i4bvb's Oct "idle ~430" and its Oct pre-burst anon 450 (vs 331 on GCP
with WordPress) show the Lima-vs-GCP gap existed in October too. Its composition (harness
processes, lima guest agent, arm64 builds, different cloud-init/services) was not measured here.

## 2. Method

- 8 fresh `n1-custom-1-1024` Spot VMs in series (max 3 in parallel), Ubuntu 26.04
  (`ubuntu-2604-lts-amd64`), kernel 7.0.0-1014-gcp, MemTotal 975860 kB, no swap, 1 dedicated
  vCPU. Bare image before install: MemAvailable 618 MiB.
- Per release `driver.sh <tag>`: fetch `install.sh`, tarball and `.sha256` from the GitHub release,
  verify sha256 (all OK), `install.sh --tarball <local file>` (the signed zero-arg path needs
  `.sig` files; v0.3.0 has none). v0.3.0 and v0.4.0's first install exited non-zero with
  "u7s-kcm.service failed" on a slow first start while the unit came up a minute later; re-running
  install.sh once (idempotent upgrade path) completed both; their data is from the re-run
  installs. The other releases installed in one pass (~2 min).
- Phases: `idle` = node Ready + 10 min; `wp` = WordPress+MariaDB applied
  (`examples/e2e/wordpress/*.yaml` from current main, MariaDB on emptyDir exactly as the gate
  does), both Ready, 30 GETs, +5 min; `s20` = the gate's settle20 point (warm-up pod, 20-pod
  `registry.k8s.io/pause:3.10` burst, scale to 1, wait, +60 s). Snapshots by `collect.sh`:
  full meminfo and vmstat, per-process smaps_rollup (PSS/RSS/USS, anon/file split), per-cgroup
  memory.stat, slabtop, fincore on `/opt/u7s/bin/*`, `/opt/cni/bin/*`, crio/crun/conmon, pods,
  images, dmesg memory lines. Collected over IAP ssh, so the snapshot itself adds one sshd
  session (a few MiB, equal for all).
- v0.4.3-snapshot.4 and v0.4.0-snapshot.1 were measured twice (an early manual run without
  `s20`, then the scripted run); the scripted run is the table. v0.3.0 `wp`/`s20` was attempted
  twice and the VM became unreachable both times (below).
- One VM per release, one run each: differences under ~15 MiB are noise. The two runs of
  v0.4.3-snapshot.4 differ by 12 MiB (idle 483 vs 495) and v0.4.0-snapshot.1 by 15 MiB (484 vs
  499); scripted vs manual runs differ by the extra interactive ssh sessions (+13 MiB anon in
  the manual idle snapshots).
- Observer experiment: on a fresh v0.4.3-snapshot.4 VM at the `s20` state, started kutwm's stream
  set from the workstation (10 long-lived ssh sessions: 1 s `kut-sample.sh`, `journalctl -f` on
  the control-plane units, `journalctl -k -f`, 7 `kut-api.sh` curl|jq streams), snapshot 100 s
  later. Scripts: `ai/findings/2026-11-04-mayor-adwea-{observers,obs-sample,obs-api}.sh`.
- Not measured: Lima (the Lima host belongs to mayor-9ygmh), arm64, any kernel other than 7.0.0-1014-gcp.
- Raw data (contains the GCP project id in hostnames; not committed): mayor checkout
  `temp/e2e/adwea/raw/` if still present. Scripts in this directory: `*-collect.sh`, `*-install.sh`,
  `*-driver.sh`, `*-s20.sh`, `*-summarize.sh`, `*-compare.sh`, `*-compare2.sh`, `adwea-wp/`.

## 3. Results

MemAvailable and the kernel-side floor (MiB), one VM per row:

| release | date | idle avail | wp avail | s20 avail | idle anon | wp anon | s20 anon | idle/wp Slab | s20 SUnreclaim |
|---|---|---|---|---|---|---|---|---|---|
| v0.3.0-snapshot.1 | 09-16 | 506 | VM unreachable | n/a | 220 | | | 81 | |
| v0.4.0-snapshot.1 | 10-19 | 499 | 354 | 330 | 215 | 330 | 345 | 94 / 100 | 65 |
| v0.4.1-snapshot.1 | 10-21 | 499 | 355 | n/a | 217 | 330 | | 91 / 92 | |
| v0.4.2-snapshot.1 | 10-25 | 498 | 354 | n/a | 218 | 332 | | 90 / 95 | |
| v0.4.2-snapshot.2 | 10-30 | 486 | 355 | 306 | 226 | 332 | 368 | 91 / 92 | 67 |
| v0.4.3-snapshot.1 | 11-02 | 492 | 353 | 308 | 217 | 332 | 367 | 91 / 96 | 68 |
| v0.4.3-snapshot.2 | 11-02 | 498 | 337 | 322 | 219 | 332 | 352 | 88 / 94 | 66 |
| v0.4.3-snapshot.4 | 11-04 | 495 | 356 | 325 | 218 | 331 | 350 | 93 / 93 | 67 |

(`s20` was added after the first four VMs were done; v0.4.1/v0.4.2-snapshot.1 have no s20.
v0.3.0 idle row is the manually collected first VM.) Page cache is the compressible part of
MemAvailable and swings 440-485 MiB at idle; the non-reclaimable floor
(AnonPages + SUnreclaim + KernelStack + PageTables) is the stable measure:

| release | idle floor | wp floor | s20 floor |
|---|---|---|---|
| v0.3.0-snapshot.1 | 278 | | |
| v0.4.0-snapshot.1 | 276 | 394 | 420 |
| v0.4.1-snapshot.1 | 278 | 393 | |
| v0.4.2-snapshot.1 | 278 | 395 | |
| v0.4.2-snapshot.2 | 286 | 395 | 447 |
| v0.4.3-snapshot.1 | 277 | 396 | 446 |
| v0.4.3-snapshot.2 | 279 | 395 | 429 |
| v0.4.3-snapshot.4 | 279 | 394 | 428 |

Idle floor +1 MiB v0.3.0 -> v0.4.3-snapshot.4. WordPress adds ~116 MiB (mariadbd 90 MiB anon,
php-fpm x3-4 ~13 MiB anon, plus pod slab), every release. The 20-pod burst leaves +25-50 MiB
behind at settle20 (SUnreclaim 53 -> 65-68, anon +20-37); v0.4.0 is the low end (420), the later
four are 428-447, i.e. at most +27 MiB with one VM each, within the run-to-run spread seen
elsewhere (+-15) plus a mild trend; it is the only candidate for a real, small growth.

Per-process PSS at idle (MiB, includes file pages so it fluctuates with cache; anon in brackets
for v0.3.0 / v0.4.0 / v0.4.3-snapshot.4):

| release | kcm | kubelet | crio | apiserver | coredns | flannel | kube-proxy | beep (servicelb) |
|---|---|---|---|---|---|---|---|---|
| v0.3.0-snapshot.1 | 94 (40) | 73 (24) | 55 (20) | 25 (7) | 55 | 41 | 40 | absent |
| v0.4.0-snapshot.1 | 77 | 72 | 47 | 19 | 52 | 41 | 33 | 6.5 |
| v0.4.3-snapshot.4 | 73 (44) | 68 (24) | 51 (21) | 21 (11) | 51 | 36 | 28 | 5.8 |

anon: KCM +4, apiserver +4, kubelet/crio unchanged; the `servicelb-controller` pod (process
`beep-controller`) appears in v0.4.0 and costs ~6 MiB PSS plus its pod's cgroup slab; kubepods.slice
at idle goes 58 -> 74-98 MiB (cache-inflated). Total anon change v0.3.0 -> v0.4.3-snapshot.4:
+0 to +11 MiB idle (220 -> 218 in the scripted v0.4.3-snapshot.4 run, 231 in the manual one: the difference is the
interactive sessions).

Binary sizes (MiB) grow but resident text does not: apiserver 133.0 -> 144.5 (v0.4.0) -> 152.4,
KCM 71.0 -> 75.7, crio 55.6 -> 58.2, kubelet 57.4 -> 58.4, scheduler 29.4 -> 30.8 (not running:
embedded scheduler, 0 pages resident). fincore resident at idle: kubelet 43-47, crio 44-51, KCM
36-41, apiserver 11-15 of 133-152 MiB, unchanged across releases. Pods at idle: flannel, CoreDNS,
kube-proxy (+ servicelb from v0.4.0), no other images. Running services identical apart from
that. No swap, boot reservation identical (`Memory: 589984K/1044788K available ... 445952K
reserved` at early boot on every VM, MemTotal 975860 kB).

Slab top at idle on every release: ext4_inode_cache 13-19 MiB, radix_tree_node 5-7, kernfs_node_cache
4.5, dentry 4-5, buffer_head 3-5, trace_event_file 3. Nothing release-specific.

v0.3.0 + WordPress: both v0.3.0 VMs (first applied 13:38 UTC, second ~14:20 UTC) went unreachable over
IAP ssh within minutes of applying the example and stayed so for 20+ min (RUNNING, serial log
shows 1-3 minute gaps, apiserver `u7s_scheduler::run: resync ... failed`, no OOM-kill lines). Not
investigated; v0.3.0 is not the regression direction (it is the best idle), and v0.4.0 on the same
manifest and VM shape is fine.

### Observer cost (GCP, v0.4.3-snapshot.4, s20 state)

| | s20, no observers | + 10 ssh stream sessions | delta |
|---|---|---|---|
| MemAvailable | 323 | 244 | -79 |
| AnonPages | 351 | 413 | +62 |
| Cached | 312 | 236 | -76 |
| PageTables | 7 | 12 | +5 |
| user.slice anon / current | n/a | 38 / 94 | |
| sshd-session / sudo / bash / journalctl procs | 0 | 24 / 11 / 10 / 2 | ~61 MiB PSS |
| apiserver/kubelet/kcm page cache (fincore) | 14 / 30 / 34 | 9 / 27 / 21 | evicted |

Same direction and magnitude as Lima Oct -> Nov (-71 MemAvailable, +43 anon, -53 cached). The
control-plane text pages evicted by it (KCM 34 -> 21 MiB resident, apiserver 14 -> 9) are the pages
the thrash in kutwm refaults. One run, so +-15 MiB.

## 4. Attribution

- Release-to-release: none. v0.3.0 -> v0.4.3-snapshot.4 idle floor +1 MiB, with-WordPress floor
  flat at 393-396 (v0.4.0 onward), idle MemAvailable within a 23 MiB band that is page-cache
  noise. The product adds one pod (servicelb/beep, ~6 MiB) and grows the on-disk binaries by
  ~35 MiB total without raising resident memory. Hence step 5 of the brief (commit list between
  two tags) does not apply: no tag step holds a loss to bisect.
- Settle20 (the exact point of the 305-320 vs 219 claim): GCP 306-330 across v0.4.0 ... .4, i.e.
  the October value on the October workload shape, for every release. The 219 is therefore not
  reproducible on a clean VM; it is specific to the Lima Nov run.
- What differs in the Lima Nov run, in order of measured weight: (1) the kutwm observer set, 79 MiB
  on GCP, anon +62; (2) post-thrash residue (kutwm: slab 133-141 MiB after the 80-pod burst vs 102
  before; at 10:24:00 only one 20-pod burst had run, so this is a minor share); (3) a persistent
  Lima-vs-GCP offset of ~120-170 MiB anon present already in October. (1) alone accounts for most
  of the Oct -> Nov pre-burst drop (-71 Lima vs -79 GCP-observed), but the Lima/arm64 observer
  cost was not measured on Lima.
- Not ruled out for Lima (untestable here): apt drift in unpinned CRI-O/crun/Ubuntu packages
  between Oct and Nov (my GCP VMs all installed on 11-04, so they cannot show it; the crio
  binary is 58.2 MiB on all x86 tarballs, but install.sh pulls CRI-O from the apt repo at install
  time), host/Lima version, arm64-specific growth.

## 5. Suggested follow-ups (not filed, operator decides)

- Measure the Lima settle20 point twice without the stream observers (mayor-9ygmh's ramp, or one
  quiet run), and once with: that is the direct test of attribution (1).
- Treat the "305-320 MiB" gate expectation as observer-free on Lima; capture gate memory via the
  in-VM sampler only.
- v0.3.0 + WordPress node wedge is a separate oddity if anyone cares about that release.

## 6. GCP hygiene

All VMs deleted right after their snapshot (adwea-v043s4, adwea-v030s1, adwea-v040s1, adwea-v041s1,
adwea-v042s1, adwea-v043s1, adwea-v042s2, adwea-v030s1b, adwea-v043s4b, adwea-v043s2,
adwea-v040s1b, adwea-obs); `scripts/gcp/vps.sh list` and `gcloud compute instances list`
empty at the end. No firewall rules or disks were created.

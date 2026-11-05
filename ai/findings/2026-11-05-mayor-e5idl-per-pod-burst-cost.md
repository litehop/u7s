# Per-pod memory cost of a pause-pod burst on 1 GiB

Bead: mayor-e5idl
Date: 2026-11-05

**Answer: the steady per-pod cost is under 1 MiB on both GCP and Lima (kernel+slab ~0.2-0.3, conmon 0.13, pause 0.04, cgroup anon ~0.05), so crio/conmon tuning can recover at most ~0.2 MiB/pod; what wedges a node is transient (GCP post-burst 10 -> 20 ramp: 207 s, ~4 GiB page-cache refaults, inferred MariaDB restart; Lima: 1 s, no restarts), so the lever is limiting parallel sandbox creation and protecting hot pages.**

Method: release v0.4.3-snapshot.4, `burst-gate.sh --backend gcp --release v0.4.3-snapshot.4 --ramp 20 --keep`
(WordPress+MariaDB, one gate 20-pod burst), so the baseline is POST-BURST, not fresh. Then the 20 gate pods
are deleted, the node settles ~5 min, and one-shot snapshots (`2026-11-05-mayor-e5idl-snap.sh`) are taken at
0, 10 and 20 pause pods plus during the 0 -> 20 transition. No streaming observers. n=1 per platform.

## GCP n1-custom-1-1024

### GCP raw (run 2026-11-05 02:24-02:42 UTC; VM deleted afterwards; baseline = post gate 20-pod burst, 20 pods deleted, 5 min settle)

Full snapshot text: `/Users/balint.erdos/litehop/u7s/temp/e2e/e5idl/gcp-snaps.txt` if still present. Timeline: scale 0->10 pods ready in 109 s
(02:34:19 -> 02:36:08), then 10->20 took 207 s (02:37:20 -> 02:40:50). Gate itself did 20 pods in 26 s from a fresh node.

| snapshot | MemAvail MiB | Anon MiB | Cached MiB | Slab MiB | besteffort pods cg kernel/slab/anon/file MiB | refault_file (cum) | majfault (cum) | netns/veth/conmon |
|---|---|---|---|---|---|---|---|---|
| 0 pods settled | 243.6 | 417.8 | 266.4 | 102.8 | 4.2/3.1/18.5/31.0 | 1631638 | 29643 | 6/3/7 |
| 10 ready | 261.2 | 413.9 | 258.4 | 103.2 | 5.9/3.7/21.6/31.9 | 2149084 | 39971 | 16/13/19 |
| 10 +60 s | 255.6 | 409.5 | 293.6 | 102.8 | 5.7/4.0/18.9/49.3 | 2283021 | 42618 | 16/13/17 |
| 20 ready | 376.6 | 299.4 | 382.0 | 106.0 | 7.1/4.6/9.7/55.1 | 3295553 | 61305 | 26/23/27 |
| 20 +60 s | 272.9 | 401.2 | 313.9 | 106.4 | 7.0/4.6/19.2/39.2 | 3386650 | 63153 | 26/23/27 |

(MemAvail/Anon/Cached/Slab converted from kB in the raw snapshot; the 0 pods row baseline has 1 leftover besteffort pod cgroup.)

Steady (0 -> 20 pods settled), MiB per pod:

| category | MiB/pod |
|---|---|
| besteffort pod cgroups kernel (includes slab) | 0.14 (4.2 -> 7.0 MiB) |
| global slab | 0.19 (102.8 -> 106.4 MiB; kernfs_node_cache +1.6 MiB, inode_cache +0.5) |
| pod cgroup anon (pause) | 0.04 |
| crio process PSS | 0.11 (37.0 -> 39.3 MiB, noisy: 35-48 between snapshots) |
| kubelet process PSS | 0.41 (49.4 -> 57.7 MiB, noisy) |
| conmon (27 procs) | not measured (outside the top-14 PSS list; 27 procs, none of them in the list) |
| pod cgroup file (pause image/layers, shared, reclaimable) | 0.4 total, shared |
| pause process PSS | n/a (not in top 14) |
| sum of attributable steady cost | about 0.7-0.9 MiB/pod |

Host-wide MemAvailable went UP (243.6 -> 272.9) and AnonPages DOWN over the same interval (sshd-session procs 40 -> 18 from ssh sessions closing, so no
meaningful node-level steady delta is visible above ~10 MiB noise; at most ~1 MiB/pod).

Transient: no snapshot caught a peak above settled by more than noise on MemAvailable. What the transients did show:
- `workingset_refault_file` grew 0.65 M pages (about 2.5 GiB) over the 10-pod step and 1.0 M pages (about 4 GiB) over the 10 -> 20 step, and
  `pgmajfault` +13k / +20k: the node was refaulting page cache (binaries/libs of crio, kubelet, mariadb) through the whole 2-3.5 min ramp.
  The gate's fresh-node 20-pod burst took 26 s; the same 20 pods after a prior burst took ~5 min.
- At "20 ready" AnonPages was 299 MiB (vs ~410) and burstable anon 31 MiB (vs 124): mariadbd was missing from the PSS list and php-fpm halved,
  i.e. the MariaDB (and WordPress) container was restarted during the 10 -> 20 step. This is inferred from the cgroup/PSS data; I did not capture
  `kubectl get pods` restart counts or the OOM log before deleting the VM.
- Page cache attributed to pod cgroups swings 27-56 MiB between snapshots (shared pause image layers + churn), well above any per-pod anon.


## Lima u7s-vps-1g (arm64, 1 vCPU, 1 GiB)

Build: scratch worktree at tag v0.4.3-snapshot.4, `build-arm64-tarball.sh` (4m27s; main's version needs cosign, the tag's does not),
then `burst-gate.sh --backend lima --tarball-dir <out> --ramp 20 --keep`. Same baseline as GCP (post gate 20-pod burst, deleted, 5 min
settle) and the same driver; the snapshot now also has conmon/pause PSS, pod restarts and kernel OOM lines.
**Validity: the gate marked the run INVALID** (host contention: "other Lima VMs running (1)" and host idle CPU 42-60% < 70% while the gate ran), and
attempts 2 and 3 were INVALID before starting; the data below is from attempt 1's kept VM, so it is not gate-valid.
Snapshot text: `/Users/balint.erdos/litehop/u7s/temp/e2e/e5idl/lima-snaps.txt` if still present.

Timeline: 10 pods Ready in ~1 s, 20 pods Ready in ~1 s (03:39:16-17, 03:40:21-22), versus 109 s / 207 s on GCP. No pod restarts other than
`servicelb-controller` (1, pre-existing); mariadb-0 and WordPress 0 restarts through the 20-pod point; no kernel OOM lines at any snapshot.

| snapshot | MemAvail MiB | Anon MiB | Cached MiB | Slab MiB | besteffort pods cg kernel/slab/anon/file MiB | conmon / pause PSS MiB (procs) | refault_file (cum) |
|---|---|---|---|---|---|---|---|
| 0 pods settled | 293.0 | 445.4 | 337.0 | 90.0 | 2.7/1.9/15.8/30.0 | 1.05 (7) / 0 | 38429353 |
| 10 ready | 291.6 | 443.2 | 324.1 | 90.8 | 3.7/2.2/16.2/33.8 | 2.32 (17) / 0.70 (10) | 40118827 |
| 10 +60 s | 285.2 | 449.7 | 327.7 | 90.8 | 4.1/2.7/16.2/37.1 | 2.30 (17) / 0.40 (10) | 41959203 |
| 20 ready | 281.9 | 447.5 | 310.2 | 94.1 | 5.1/3.1/16.6/26.3 | 3.52 (27) / 1.07 (20) | 43212885 |
| 20 +60 s | 277.5 | 452.5 | 316.8 | 94.2 | 5.6/3.6/16.6/25.9 | 3.57 (27) / 0.77 (20) | 45373208 |

Steady (0 -> 20 pods +60 s), MiB per pod, Lima vs GCP:

| category | Lima | GCP |
|---|---|---|
| global slab | 0.21 (90.0 -> 94.2) | 0.19 |
| pod cgroup kernel (incl. slab) | 0.15 (2.7 -> 5.6) | 0.14 |
| pod cgroup anon | 0.06 | 0.04 |
| conmon PSS | 0.13 (1.05 -> 3.57 MiB, 7 -> 27 procs) | not captured |
| pause PSS | 0.04 | not captured |
| crio / kubelet PSS | no signal (crio 41 -> 34, kubelet 65 -> 62 MiB; noise exceeds any per-pod delta) | 0.11 / 0.41 (noisy) |
| MemAvailable, node level | -0.8 (293 -> 278 MiB, -15 MiB total) | rose 244 -> 273 (noise) |
| AnonPages, node level | +0.4 (445 -> 452 MiB) | fell (ssh sessions closed) |

Lima's attributable steady cost is about 0.4-0.5 MiB/pod (slab 0.21, conmon 0.13, pause 0.04, cgroup anon 0.06); node-level MemAvailable fell
0.8 MiB/pod, so up to ~0.3 MiB/pod is unattributed.

## Conclusion

1. The ~5 MiB/pod figure is not steady per-pod runtime overhead on either platform: attributable steady cost is under 1 MiB/pod
   (kernel/slab ~0.2-0.3, conmon 0.13, pause 0.04, pod cgroup anon 0.04-0.06; crio/kubelet growth is below snapshot noise on Lima, ~0.5 on GCP).
   crio/conmon tuning can recover at most ~0.2 MiB/pod (conmon + pause), about 4 MiB for 20 pods.
2. The cost that wedges the node is transient and platform-dependent: on GCP after a prior burst the 10 -> 20 ramp took 207 s, refaulted ~4 GiB of
   page cache and (inferred from anon 410 -> 299 MiB, mariadbd absent) restarted MariaDB; on Lima the same ramp took ~1 s with no restarts and no OOM.
   The GCP restart stays inferred; Lima's absence of restarts is observed directly (`kubectl get pods`, `journalctl -k`).
3. Lever: limit parallel sandbox creation and protect hot pages (MemoryLow on crio, kubelet, mariadb), not per-pod crio/conmon trimming.
4. Limits: n=1 per platform; Lima run flagged INVALID for host contention; post-burst baseline; no sampling between 3 s and ready, so the true
   peak (peak minus settled) was not caught on either platform; MemAvailable noise is about ±10 MiB.

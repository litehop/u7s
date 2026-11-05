# Per-pod memory cost of a pause-pod burst on 1 GiB

Bead: mayor-e5idl
Date: 2026-11-05

**Answer: PENDING (measurement in progress; numbers are appended per snapshot below).**

Method: release v0.4.3-snapshot.4, `burst-gate.sh --backend gcp --release v0.4.3-snapshot.4 --ramp 20 --keep`
(WordPress+MariaDB, one gate 20-pod burst), so the baseline is POST-BURST, not fresh. Then the 20 gate pods
are deleted, the node settles ~5 min, and one-shot snapshots (`2026-11-05-mayor-e5idl-snap.sh`) are taken at
0, 10 and 20 pause pods plus during the 0 -> 20 transition. No streaming observers. n=1 per platform.

## GCP n1-custom-1-1024

## Lima u7s-vps-1g

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

## Lima u7s-vps-1g
(pending)

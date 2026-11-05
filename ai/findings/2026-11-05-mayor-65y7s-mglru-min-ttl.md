# MGLRU min_ttl_ms vs the 1 GiB burst wedge

Bead: mayor-65y7s

Answer: no. MGLRU `min_ttl_ms=1000` is available on the Lima gate kernel but
does not turn the wedge into a recoverable kill: it made the node strictly
worse (333 kernel OOM invocations, apiserver and kcm killed repeatedly, no pod
ever Ready), and the premise "the OOM killer never fires" is false on Lima,
where it already fires in the control run.

## Step 1 - feasibility (Lima gate VM, bare template boot)

- Kernel `7.0.0-34-generic` (Ubuntu 26.04 arm64 cloud image).
- `CONFIG_LRU_GEN=y`, `CONFIG_LRU_GEN_ENABLED=y`, `CONFIG_LRU_GEN_WALKS_MMU=y`,
  `CONFIG_LRU_GEN_STATS` not set.
- `/sys/kernel/mm/lru_gen/enabled` = `0x0001` (base on; mm-walk and non-leaf
  PMD bits off). Left as is in arm B.
- `/sys/kernel/mm/lru_gen/min_ttl_ms` exists, default `0`.
- No swap; swappiness 60.
- No existing reference to `lru_gen` / `min_ttl` in `scripts/`, `install.sh`,
  `crates/`.
- `oom_score_adj` on the installed VM: kubelet -999, crio -999, conmon -1000,
  flanneld -997, kube-proxy -999, u7s-apiserver 0 (the single binary also
  hosts kcm and scheduler; kcm 0), mariadbd 730, coredns 927, WordPress
  php-fpm / nginx / pause 1000 (BestEffort). The control-plane binary is at 0,
  so it is a victim as soon as pods are exhausted.

## Step 2 - A/B

Both arms: trimmed Lima VM (1 GiB, 1 vCPU, no swap), same arm64 tarball, WordPress+MariaDB
resident, `--burst-pods 50 --runs 1 --mem-hog-mib 350 --keep`. Experiment patch
adds `--min-ttl-ms N` (written to `/sys/kernel/mm/lru_gen/min_ttl_ms` in
`vm_trim`, before install). Both attempts were marked INVALID by the harness
(host idle CPU 46-57% < 62%, another worker's GCP gate and background work on
the host); not retried. The effect sizes below dwarf plausible host noise, but
n=1 per arm.

The harness wedge signal fires at the 20-pod step and aborts the burst, so
the 50-pod burst was never reached in either arm. Recovery was observed by
probing the kept VM after the abort; "time to node Ready + API + WordPress 200"
is therefore not reached in either arm (WordPress never returned 200).

| | Arm A (min_ttl 0) | Arm B (min_ttl 1000) |
|---|---|---|
| Burst start | 05:38:47Z | 06:00:07Z |
| Outcome | 20-pod step stalled at 1 pod Ready; wedge abort at +306 s | 0 pods Ready; wedge abort at +~330 s |
| Kernel OOM invocations | 5 (05:40:39-05:41:00, +112..133 s, then none) | 333 (06:00:06-06:08:59, continuous) |
| Victims (oom_score_adj) | php-fpm/nginx/pause 1000, coredns 927, mariadbd 730; no control plane | same pods many times over, plus kube-controller x70 (0), u7s-apiserver x35 (0), kubectl, sleep, systemd-resolved |
| Node Ready | True -> Unknown at +136 s, False at +243 s; Ready again by ~+9 min (after abort scale-down) | API unreachable from burst start; apiserver restarted 38 times; Ready by +9 min only after the abort |
| MemAvailable during burst | ~50 MiB, ~100 MiB at stall | 270-340 MiB (the kills keep freeing memory) |
| WordPress after burst | 000 at +10 and +11 min; php pod 1/2, 2 restarts | 000 at +10 min; mariadb CrashLoopBackOff (58 restarts), WordPress 101 restarts, coredns OOMKilled (52), burst pod Error (51) |
| Recovered + stays recovered 2 min | node Ready and stable; WordPress not back | no: workload pods in permanent crash/OOM loop |

Arm A at rest: node Ready, 7 pods Running, WordPress pod 1/2.
Arm B at +10 min: node Ready only, MemAvailable ~300 MiB, yet pods still
OOM-killed.

## Interpretation

- Premise corrected: on Lima (kernel 7.0, cgroup v2, `memory.oom.group`) the
  kernel OOM killer does fire during the wedge, killing BestEffort pods first
  by oom_score_adj as designed. The livelock is what remains after it stops
  firing: the 350 MiB hog is tmpfs (shmem, not killable), the remaining
  working set is above what the node can hold, and reclaim thrashes.
- `min_ttl_ms=1000` makes the kernel OOM-kill whenever the youngest generation
  lives less than 1 s. On a 1 GiB node whose pods and control plane all need
  more than the resident set, that is permanently true, so it kills every
  process that restarts, including the control-plane binary at
  oom_score_adj 0, and keeps killing at 300 MiB MemAvailable. A kill loop,
  not a recovery.
- A smaller `min_ttl_ms` (e.g. 100-300) was not tried; it would only shift
  the threshold, not change that the control-plane binary at score 0 is the
  next victim after pods.

## Caveats

- n=1 per arm; both INVALID on host contention; the hog is a Lima-only
  harness artefact (350 MiB tmpfs).
- Wedge abort stops the burst, so recovery was measured on the aborted state,
  not an unattended burst.
- Only `min_ttl_ms=1000` and `enabled=0x0001` tested.
- GCP (x86_64, pd-standard) not tested.

Raw archives, if still present: `/Users/balint.erdos/litehop/u7s/temp/e2e/65y7s/{armA,armB}`.

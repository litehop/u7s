# Experiment E: kubepods.slice cap vs control under the killable overload

Bead: mayor-pzhtd

**Verdict:** the #2039 cap (kubepods `memory.max` 657 MiB) did not contain the overload
and the node was worse off than control (n=1 per arm). The cap never engaged: pod anon
read at 414 MiB, `memory.events` shows `max 0` and `oom 0` on kubepods, and every
OOM kill was a global OOM (`CONSTRAINT_NONE`), the same as control. The node froze with
no OOM kill for ~15 min, and its API was still unreachable ~40 min after the scale-up.

## Method

- GCP spot `n1-custom-1-1024` (1 vCPU, 1 GiB, no swap, Ubuntu 26.04, kernel 7.0 gcp),
  one fresh VM per arm, via `scripts/release-gate/burst-gate.sh --backend gcp --tarball
  ... --keep --overload-pods 30 --overload-mib 25 --overload-window-secs 600`.
- Both arms install the published v0.4.7 x86_64 tarball (sha256 verified). Control uses
  the v0.4.7 `install.sh` unmodified. Treatment uses a local copy with the
  `scripts/install.sh` hunks of PR #2039 applied (clean `patch`, never committed). #2039
  is a bundle: `u7s.slice` + per-unit `MemoryLow` (kubelet 96, crio 80, apiserver 48,
  KCM 96 MiB) AND kubelet `systemReserved` 160 Mi / `kubeReserved` 136 Mi with
  `enforceNodeAllocatable: [pods]`. The arm tests the bundle, not the cap alone.
- Workload: WordPress + MariaDB resident, then 30 BestEffort pods holding 25 MiB each
  (oom_score_adj 1000), 600 s window.
- Post-run cgroup counters read over ssh from the kept VM (control ~22 min and
  treatment ~40 min after the scale-up, so cumulative counters are NOT comparable
  between arms). The treatment harness collect phase never returned (VM unreachable
  for 45 min), so the treatment has no `probes.log`, `recovery.log`, OOM-victim file
  or pod table; its kernel facts come from the GCE serial console (last ~4900 lines,
  from 03:36 UTC, i.e. +15 min).
- Deviation: `build-experiment-tarball.sh` output lacks `kubectl` and the CNI plugins
  that current `install.sh` requires (two aborted installs, VMs deleted), so the
  release tarball was used instead.

## Results

| metric | control | #2039 treatment |
|---|---|---|
| kubepods `memory.max` | 953 MiB | 657 MiB |
| allocatable memory | 853 MiB | not read (API unreachable) |
| recovery_secs (Ready + /readyz + WordPress, 120 s hold) | none in 600 s | none (loop ended at +16 min, node unknown) |
| availability, recovery cycles OK | 3/71 (4%); last OK +12 s, first fail +21 s | not measured |
| node Ready timeline | Unknown +141 s, True +199 s, Unknown +305 s, False +609 s; True again by +22 min | PLEG unhealthy 6.5 min by +16 min, `Node became not ready` +16.5 min; API unreachable ssh/kubectl at +40 min |
| first OOM kill | +108 s | +15 min (frozen with no kill before) |
| OOM kills (cumulative `oom_kill`) | 116 at +22 min | 218 at +40 min (kubepods counter) |
| OOM constraint | all `CONSTRAINT_NONE` (global) | all `CONSTRAINT_NONE` (global), 17/17 logged |
| OOM victims | all oom_score_adj 1000 overload-pod processes (`sh`/`head`/`tr`) | same (58 of 58 in the serial window) |
| control-plane OOM kills | 0 | 0 |
| overload pod restarts | 19 OOMKilled pods at +22 min (harness: restarts=0 in its pod snapshot at +10 min) | not measured |
| WordPress | `pehelypress` pod OOMKilled at +22 min, mariadb Running | not measured |
| kubepods `memory.events` | max 0, oom 0, oom_kill 116, oom_group_kill 29 | max 0, oom 0, oom_kill 218, oom_group_kill 54 |
| kubepods anon / current at read | 403 / 430 MiB | 414 / 438 MiB (cap 657) |
| MemAvailable at read | 53 MiB | 33 MiB |

Control-plane cgroups at read time (control: `system.slice/*`, no low; treatment:
`u7s.slice/*`, with MemoryLow). Memory PSI `full avg300` (%), cumulative `full` seconds,
`memory.events` low/max/oom, and anon/file at read:

| cgroup | control | treatment |
|---|---|---|
| kubelet | 10.0 %, 97 s, low 0 / max 0 / oom 0, anon 42 MiB file 15 MiB | 6.1 %, 252 s, low 317,856 / max 0 / oom 0, anon 44 MiB file 2.3 MiB |
| crio | 3.8 %, 48 s, 0/0/0, anon 31 MiB file 10 MiB | 4.8 %, 183 s, low 4.6 M / 0 / 0, anon 32 MiB file 4.9 MiB |
| u7s-apiserver | 6.4 %, 66 s, 0/0/0, anon 23 MiB file 6 MiB | 7.2 %, 325 s, low 2.0 M / 0 / 0, anon 21 MiB file 2.6 MiB |

Reading, with the caveat of different read times:

- The control-plane cgroups never hit `max` or `oom`; they lost file pages (kubelet file
  15 MiB control vs 2.3 MiB treatment at read) and stalled in reclaim. PSI `full` of
  5-10 % per unit and kubepods `full` 11-15 % mean tasks were stalled in direct reclaim
  for a tenth of wall time, consistent with kubelet starving by waiting, not by being
  killed.
- In the treatment the `low` counters (`u7s.slice` 11.0 M) show reclaim pushed through
  the protection, and kubelet's file pages are still gone: `MemoryLow` is best-effort and
  was exhausted.
- Why the cap did not engage: 1 GiB node, 975 MiB total. Everything outside kubepods
  (u7s.slice ~187 MiB, system.slice, kernel, page cache) plus pod anon of ~430 MiB
  already exhausts RAM, so global reclaim/OOM happens before kubepods reaches 657 MiB.
  A cap only contains the overload if it is below total RAM minus everything else that
  must stay resident, here below roughly 430 MiB; allocatable 564 MiB leaves no room.
- MemoryPressure taint and eviction: not observed in either arm. Control read at
  +22 min showed `MemoryPressure=False`, no eviction events, 19 OOMKilled pods (container
  OOM kills, not kubelet evictions). Treatment: kubelet was starved (PLEG unhealthy
  6+ min) and no `eviction_manager` / `Evicted` line appears in the serial window
  (0 matches); the node condition could not be read.

## Caveats

n=1 per arm; spot VMs; the treatment is the #2039 bundle (MemoryLow plus reservations),
so it cannot isolate the cap; the treatment was observed longer than control and its
harness data is missing; arms were not run in the same instance (different VMs, 20-min
cap exceeded by the unresponsive treatment). Whether a tighter cap (~400 MiB) would
contain it is untested.

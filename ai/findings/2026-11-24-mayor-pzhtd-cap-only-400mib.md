# Experiment E rerun: kubepods cap-only (~400 MiB) vs control

Bead: mayor-pzhtd

**Verdict:** a 400 MiB kubepods cap engages (cgroup-local OOMs, `memory.events` max/oom far above 0) but does not keep a 1 GiB node's control plane responsive: kubelet stopped heartbeating, the node went NotReady/Unknown, the API answered 9 of 48 probes, and nothing recovered in the 20-minute cap (n=1 per arm). The cap is also too tight to hold the resident workload: 300 MiB allocatable cannot schedule MariaDB, so the specified "WordPress resident" setup cannot exist under it. The control froze outright (ssh dead for 20 min), so neither arm recovered.

## Method

- GCP spot `n1-custom-1-1024` (1 vCPU, 1 GiB, no swap), one fresh VM per arm, `scripts/release-gate/burst-gate.sh --backend gcp --tarball <v0.4.7 release tarball> --keep --overload-pods 30 --overload-mib 25 --overload-window-secs 600`.
- Both arms install the published v0.4.7 x86_64 tarball (sha256 `b6a371a4...3441` matches the release `.sha256`). Control: v0.4.7 `install.sh` unmodified.
- Cap-only: the same `install.sh` with only this appended to the kubelet config heredoc (no `MemoryLow`, no `u7s.slice`): `enforceNodeAllocatable: [pods]`, `systemReserved.memory: 300Mi`, `kubeReserved.memory: 253Mi`. The first run's kubepods `memory.max` was 953 MiB minus reservations, so 553 MiB of reservations targets 400 MiB.
- Cap verified before the overload: kubepods `memory.max` = 419401728 bytes (400.0 MiB); node allocatable memory 307172Ki (300 MiB).
- 20-minute cap per arm, measured from the overload start. Cgroup counters were pulled over ssh during the run and from the GCE serial console, not at the end.

## Deviation: the cap arm ran without WordPress's database

With 300 MiB allocatable and 200 MiB already requested by kube-system/flannel/servicelb/pehelypress, `mariadb-0` (request 256 Mi) stayed `Pending` (`NodeResourcesFit`, no node with free capacity). The harness aborted at its marker write (`marker write failed`, 07:27:35) before the overload phase. On the same VM I created the identical `rg-overload` deployment (nginx:alpine, 25 MiB held per pod, BestEffort) and scaled it to 30 by hand at 07:28:31, with an in-VM probe loop (`/readyz` plus node conditions via kubectl, 10 s timeouts per call). So the cap arm's overload ran with `pehelypress` (WordPress) up but MariaDB never scheduled, and its numbers come from my snapshots and the in-VM probe log, not the harness (`recovery_secs`/availability are not harness-measured).

## Results

| metric | control (stock v0.4.7) | cap-only (kubepods 400 MiB) |
|---|---|---|
| overload start (scale-up) | 06:50:19 | 07:28:31 (manual) |
| kubepods `memory.max` | not read (node unreachable; first run: 953 MiB) | 400 MiB (verified) |
| recovery within 20 min | none | none |
| API reachability during overload | ssh and kubectl dead for the whole window; kernel `task blocked for more than 122 seconds` x20 on the serial console from +~10 min; serial output stops at 06:57 | in-VM probe: `/readyz` ok 9 of 48 probes (19%), 7 of them in the first ~3 min; a probe cycle took ~22 s once the API stalled; ssh usable (slowly) throughout |
| node condition | not readable | kubelet `Node became not ready` at 07:35:12 (+6m41); conditions all `Unknown` at +15 min; `MemoryPressure=True` seen once (probe line 40) |
| OOM scope | no OOM kill in the readable serial window (06:44-06:57); harness collect never ran | cgroup-local: 20 `CONSTRAINT_MEMCG` (`oom_memcg=/kubepods.slice`) vs 1-2 global `CONSTRAINT_NONE` in the dmesg/serial windows |
| kubepods `memory.events` | not read | at +20:23: `max 1,193,293`, `oom 66`, `oom_kill 110`, `oom_group_kill 31` |
| victims | not observed | overload pod processes (`sh`, `head`, `tr`, `sleep`, oom_score_adj 1000) plus 4 `php-fpm` kills (WordPress) early in the window; no control-plane process killed |
| kubelet shedding | not observed | kubelet's eviction manager ran: "attempting to reclaim memory" at 07:36:38, 07:38:34, 07:39:30; it ranked overload pods but logged `pod failed to evict: timeout waiting to kill pod` and `timed out waiting for pods to be cleaned up`; 34 eviction-manager/Evicted journal lines by the end |
| overload pods at +20 min | not read | OOMKilled 10, Running 12, CreateContainerError 8, Pending 3; 9 restarts |
| WordPress | not read | `mariadb-0` Pending the whole run (unschedulable); `pehelypress` 1/2 Running, 1 restart |

Cgroups at the final read (+20:23, cap arm; pre-overload values in parentheses), `memory.events` `max`/`oom` all 0 for each, PSI `full avg300`:

| cgroup | `max`/`oom` | PSI full avg300 | anon / file |
|---|---|---|---|
| kubelet | 0 / 0 (0 / 0) | 8.1 % (0.0 %) | 45 MiB / 14 MiB (25 / 14) |
| crio | 0 / 0 (0 / 0) | 4.0 % (0.0 %) | 28 MiB / 10 MiB (28 / 60) |
| u7s-apiserver | 0 / 0 (0 / 0) | 4.8 % (0.0 %) | 22 MiB / 11 MiB (12 / 11) |
| kubepods | max 1.19 M / oom 66 | 53.6 % (0.0 %) | 345 MiB / 32 MiB (44 / 100) |

The control-plane cgroups never hit their own limits and kept their anon pages, but crio lost ~50 MiB of file pages and all three spent 4-8 % of wall time in reclaim stalls. kubepods itself sat at `memory.max` with 50-80 % full PSI for 20 minutes, so any control-plane task that touched kubepods memory (kubelet's pod-managed work, crio exec/stat paths) stalled behind it.

## Reading

- The cap does what #2039's bundle did not: because 400 MiB is below RAM minus everything else, the overload OOMs inside kubepods and `memory.events` max/oom move. Global OOM was rare (1-2 of ~21 kills).
- Containing the kills is not the same as staying responsive. kubepods held at `memory.max` and reclaimed continuously (1.19 M `max` events), the CPU (1 vCPU) went to that reclaim, and kubelet/apiserver latency rose until kubelet status updates stopped (NotReady at +6m41) and `/readyz` mostly timed out. No recovery in 20 minutes, even as the OOM killer kept removing overload pods, because the Deployment recreates them as fast as they die.
- kubelet shedding was attempted (MemoryPressure was set at least once and the eviction manager ranked BestEffort overload pods) but the evictions timed out ("timeout waiting to kill pod"): the kill path sat behind the same reclaim stall.
- The cap cost: 300 MiB allocatable on a 1 GiB node is below the resident workload (MariaDB 256 Mi request plus system pods). A cap tight enough to engage under this overload is too tight to schedule the workload the gate runs, so a fixed `systemReserved`+`kubeReserved` of this size is not a viable default for a 1 GiB node.

## Caveats

- n=1 per arm; spot VMs; arms not on the same instance; clocks are UTC.
- Cap arm is a deviation: overload scaled by hand, MariaDB never scheduled, so the node carried less resident memory than in the control/first-run setup. The control's resident WordPress was up.
- The control read is thin: no cgroup counters (ssh never answered), only the serial console (window ends 06:57) and the harness log. Its absence of OOM kills in the serial window differs from the first run's control (first kill at +108 s) and may be a serial-window artefact.
- Probe numbers (9/48) come from an in-VM kubectl loop with 10 s timeouts and no timestamps in the saved log; they are not the harness's 5 s probes and not comparable to its availability %.
- dmesg `Killed process` counts include duplicate lines per kill; `oom_kill 110` (cgroup counter) is the authoritative total.

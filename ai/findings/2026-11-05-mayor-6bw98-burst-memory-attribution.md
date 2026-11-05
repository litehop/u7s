# Burst memory attribution on the 1 GiB / 1 vCPU gate node

Bead: mayor-6bw98 (sampler), mayor-36soz (killable overload repro)

Answer: in every overload run the MemAvailable loss is anonymous memory of the overload pods
(kubepods-besteffort), balanced by file-cache eviction; control-plane anon, slab (~+10-25 MiB) and
page tables (<20 MiB) are not the consumers, and the node (Lima and GCP) does not recover within
300 s even when the kernel OOM killer fires on the killable pods (n=1 per run).

## Method

- Sampler (`scripts/release-gate/vm-sampler.sh`): `/proc/meminfo` split every 2 s during
  burst/overload phases (MEMI rows), per-component `Pss_Anon`/`Pss_File`, per-cgroup
  `memory.stat` (anon, file, slab, workingset_refault_file) and `memory.pressure`, kernel
  `oom_kill` counter; OOM victims with `oom_score_adj` from the kernel log (`oom-events.txt`).
- `u7s-apiserver` runs apiserver and scheduler in one process (`--embedded-scheduler true`),
  so there is no separate scheduler row.
- Overload: `--overload-pods N --overload-mib M`: BestEffort pods (`nginx:alpine`, busybox ash
  holds M MiB in a shell variable), killable at oom_score_adj 1000. Recovery = node Ready +
  `/readyz` + WordPress 200 held 120 s.

## Runs

All Lima runs: trimmed 1 GiB / 1 vCPU VM, branch merged with main incl. `OOMScoreAdjust=-997`
on u7s-apiserver/u7s-kcm (mayor-5ljmf), 30 pods x 25 MiB BestEffort overload, 300 s window, n=1.
Both runs are flagged INVALID by the harness (host idle CPU 57-59% < 62% floor at 1-2 probes), so
treat the numbers as indicative, not authoritative; no retry (time-box).

### L1: Lima, WordPress+MariaDB resident

Overload NOT recovered (recovery_secs=none; API unreachable at the end, node Unknown).

| t after scale | AnonPages | file (Act+Inact) | Slab | PageTables | MemAvailable |
|---|---|---|---|---|---|
| +1 s | 393 MiB | 334 MiB | 93 | 6 | 355 MiB |
| +7 s | 629 MiB | 85 MiB | 110 | 13 | 84 MiB |
| +388 s | 645 MiB | 94 MiB | 108 | 16 | 92 MiB |
| +449 s | 650 MiB | 79 MiB | 119 | 25 | 68 MiB |

- Drop of ~270 MiB in 7 s is anon (+236) plus slab/pagetables (+24); the file cache lost
  ~250 MiB, i.e. the kernel traded page cache for the overload's anon pages.
- By cgroup: kubepods-besteffort anon 38 -> 293 MiB (the overload pods); burstable (WordPress +
  MariaDB) anon flat at 124 MiB; system.slice units flat (crio 28->31, kcm 45->49, kubelet 29->32,
  apiserver 16).
- By component Pss_File: every component's file PSS fell to 0 (kcm 15, crio 18, kubelet 25,
  apiserver 9 MiB before): control-plane code/data pages are evicted and refault. kubepods
  workingset_refault_file reached 45 M pages, system.slice/kubelet 22.7 M.
- The guest froze for ~380 s (no sampler row between +7 s and +388 s), so no OOM kill happened
  in that interval; 4 oom_kill by the end, victims php-fpm x4 (oom_score_adj 1000), none of the
  overload pods, none of the control plane.
- Memory PSI full at +440..456 s: ~437-455 s of cumulative full stall.

### L2: Lima, WordPress+MariaDB OFF (headroom +~130 MiB)

Overload NOT recovered (2 OK probes then node Unknown at +35 s, API unreachable).

| t after scale | AnonPages | file | Slab | PageTables | MemAvailable |
|---|---|---|---|---|---|
| 0 s | 266 MiB | 481 MiB | 97 | 5 | 508 MiB |
| +51 s | 660 MiB | 99 MiB | 105 | 15 | 79 MiB |
| +209 s | 698 MiB | 54 MiB | 104 | 13 | 45 MiB |
| +364 s | 709 MiB | 44 MiB | 104 | 13 | 39 MiB |

- Same thrash signature as L1: file cache collapses to <100 MiB, MemAvailable < 80 MiB, node
  Unknown, API unreachable. Removing ~130 MiB of workload did not move the knee because 750 MiB
  of overload exceeds both headrooms; this was not a dose-response (that needs several overload
  sizes, not run).
- besteffort anon 406 MiB at +51 s (about 16 of 30 pods resident, the rest OOM-killed and
  restarting).
- Kernel OOM killer fired 26 times (L1: 4): every victim a pod process at oom_score_adj 1000
  (`sh` holding 18-25 MiB anon-rss, plus head/tr/sleep children); no control-plane victim.
  The killer works here, but the pods restart (restart loop) and the node does not leave the
  thrash within 300 s.

### G1: GCP n1-custom-1-1024 Spot, WordPress+MariaDB resident

Release v0.4.3-snapshot.4 (newest; it predates `OOMScoreAdjust=-997`), this branch's gate scripts,
same 30 x 25 MiB overload. Harness status FAIL (valid, not INVALID). NOT recovered (1 OK probe of
6; node-ready log ends True, API then unreachable). The guest froze for 173 s mid-window (largest
sampler gap), the collect phase never completed (no kernel log / OOM victims file; the
`oom_kill` counter read 16 at +390 s, victims unknown).

| t after scale | AnonPages | file | MemAvailable | besteffort anon |
|---|---|---|---|---|
| +1 s | 391 MiB | 280 MiB | 292 MiB | 40 MiB |
| +142 s | 398 | 268 | 271 | 34 |
| +181 s | 325 | 322 | 342 | - |
| +194 s | 479 | 225 | 185 | - |
| +390 s | 480 | 211 | 185 | 211 |

- Overload pods are slow to start on GCP (besteffort anon 35-40 MiB for ~170 s, then 211 MiB at
  +390 s); the control plane's anon is flat (kcm 48, crio 33, kubelet 35, apiserver 15 MiB) and
  its Pss_File fell to 3-6 MiB per component.
- Mem PSI full +236 s of 390 s (61%), CPU iowait 54% and system 37% of the window: the same
  thrash signature as Lima (file refault, ~0 free), but at a higher MemAvailable (185 vs 40-90 MiB).
  Refault counters are not comparable across platforms.
- GCP cleanup: `gcloud compute instances list` after the run: `Listed 0 items.`

## Verdict and caveats

- Consumer: overload-pod anon (Lima +236-400 MiB within 7-50 s). Components, slab and page tables
  do not grow materially, so the earlier "unattributed 70-160 MiB" in burst runs is most plausibly
  file-cache loss plus per-pod sandbox anon, to be re-checked with a pause-burst run (this work ran
  only the overload mode).
- Recovery: 0 of 3 runs recovered in 300 s. L2 shows the OOM killer works on killable pods
  (26 kills, all adj 1000, no control-plane victim) but the restart loop keeps the node thrashing.
- Not tested: dose-response at several sizes, a pause-pod burst, recovery windows beyond 300 s.
- L1/L2 are flagged INVALID by the harness (host idle 57-59% vs 62% floor).
- The sampler costs 0.6% of a core at idle but 8-9% during a Lima thrash and 1.8% on GCP.

### Sampler cost

The sampler's own CPU (SELF row): 0.6% of one core at idle and during the WordPress phase,
7.8-8.7% of one core during the overload thrash (the sampler is itself starved and refaulting).

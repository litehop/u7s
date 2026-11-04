# Burst cliff on 1 GiB / 1 vCPU (Lima arm64)

Bead: mayor-kutwm
Date: 2026-11-04
Base: main 2b8dc2ab (+ one harness fix, see Method)

**Answer: on the gate shape (WordPress + MariaDB resident, MemAvailable ~210 MiB) the cliff is
at or below 20 pods; it is a page-cache thrash, not CPU or I/O: once MemAvailable falls under
~230 MiB the control-plane processes (kubelet, KCM, CRI-O, apiserver, CoreDNS, flannel) evict
and refault their own code pages at 1.2-1.4 M pages/s, 93-95% of the CPU goes to kernel
reclaim, and kubelet's sync loop stalls for 16-86 s per pass. The thrash outlives the burst
(2-10 min), and the kubelet failures it causes (NotReady, then immediate taint eviction of
every pod) make the next burst slower (500 s vs 170 s for the same 20 pods). Freeing ~130 MiB
(scaling WordPress/MariaDB to 0) moved the cliff from <=20 to between 50 and 60 pods.**

## Method

- Lima `u7s-vps-1g.yaml` (1 vCPU, 1 GiB, MemTotal 970140 kB, no swap), arm64 tarball built from
  main 2b8dc2ab, `burst-gate.sh --backend lima --ramp 20,30,40,50,60,80 --probe-kill 240
  --keep`. Quiet host (gate's own quiet check passed, steal 0.0%, no other Lima VM).
- Harness fix needed first (separate branch `worker/kutwm-lima-unsigned-tarball`): main's
  install.sh now fetches `.sig` files for the baked URL, so every Lima gate run died at
  install ("Could not open file ...tar.gz.sig"). The Lima run therefore installs with
  `install.sh --tarball` (not the zero-argument path). install took 78 s.
- Streamed off the VM continuously (limactl shell into host files, survive the VM): 1 s
  sampler (PSI cpu/mem/io, /proc/stat, meminfo, vmstat refault/majfault/pgscan, per-comm
  utime/stime/majflt, per-cgroup workingset_refault_file from 10:38Z), journalctl -f of
  kubelet/crio/kcm/apiserver/scheduler, kernel log, API watches via curl (node, lease, events,
  rg-burst deployment), a 1 Hz API probe (GET namespace, curl total time) and apiserver
  /metrics every 5 s. The apiserver exposes no request-duration histogram or inflight gauge
  (only apiserver_request_total, longrunning_requests, watch_*), so the probe is the latency
  measure.
- Caveat (observer effect): the streams run ~10 extra processes (journalctl, 7 curl+jq pairs,
  sampler). In the 20-pod window user.slice (my observers) caused 164k of 1.43M refaults/s
  and journalctl used 6.7-14.7% CPU, comparable to kubelet's 13%. October runs without
  these tools show the same 1.2 M/s signature, so the thrash is real, but the exact knee may
  sit slightly lower than an un-observed run. `--capture` was not used (its per-2 s kubectl
  forks cost more than the curl streams).
- All times UTC. Single VM, state carries over between bursts. Raw archive, if still present:
  `/Users/balint.erdos/litehop/u7s/temp/e2e/kutwm/` (`stream/`, `gate2/`, `tools/`).

## Experiment 1: knee

Gate run (WordPress + MariaDB resident), `ramp` stops at first failure:

| pods | seconds to all Ready | MemAvailable min | notes |
|---|---|---|---|
| 20 | 170 (10:17:48 -> 10:20:38) | 181 MiB | Oct Lima: 4-5 s |
| 30 | timeout at 240 s (4/30 Ready at 10:27:38) | 148 MiB | (c),(d) FAIL, WordPress 0 |
| 40-80 | not run | | |

Burst 20 detail: 1 pod Ready at 10:18:16, still 1 at 10:20:00, then 4->20 in 41 s. Pod startup
(kubelet "Observed pod startup duration") ranged 5.1 s (first pod) to 165 s (last).

Controlled variation (chosen to test whether the cliff is a pod count or a memory-headroom
effect): same VM, WordPress/MariaDB scaled to 0 at 10:58 (MemAvailable 210 -> 335 MiB, refault
~12-14k/s at rest), bursts from 1 replica, waiting for refault < 15k/s between sizes:

| pods | seconds | note |
|---|---|---|
| 30 | 13 | timed out (>240 s) with WordPress |
| 50 | 9 | |
| 60 | 324 | MemAvailable ~206-164 M; thrash |
| 80 | 227 | non-monotone vs 60: both are inside the thrash regime, timing is chaotic |

So the cliff is a function of memory headroom, not of pod count: ~130 MiB freed moved it from
<=20 to 50-60 pods. Per-pod cost measured at the 80-pod burst: Slab +40 MiB (102 -> 142 M),
AnonPages +60 M, MemAvailable 318 -> 164-206 M.

## Experiment 2: recovery

The node does not recover on a minutes timescale, and it is never fully idle again.

- After burst 20 (10:20:41, scaled to 1): sys 93% (refault 1.2-1.3 M/s) until 10:22:58, 17% at
  10:23:18, i.e. ~2.5 min. Resting refault with 1 burst pod + WordPress stays 105-135k/s
  (10:39-10:48) vs 1-2.6k/s at fresh idle (10:13:44-10:15:06, MemAvailable 375 M) and 75k/s
  before the first burst (10:16:49).
- After burst 30 failed (scale to 1 at ~10:28:40): 1.3-1.4 M refaults/s, 94-95% sys with a single
  burst pod until 10:37:49 (9 min), then 120k/s. The gate itself logged "burst pods not scaled
  down within 300s" (10:35:01).
- Repeat of the 20-pod burst at 10:49:14, 11 min after the failure and after the 10-min watch:
  500 s (all Ready 10:57:34) vs 170 s the first time. During it the kubelet reported
  `Node became not ready ... container runtime is down` at 10:53:44 (Ready again 10:54:25),
  and within 1 min node-lifecycle taint eviction (TaintManagerEviction events, first seen
  10:54-10:55) removed CoreDNS, WordPress, MariaDB and all 20 burst pods. u7s has no default
  not-ready/unreachable tolerations, so eviction is immediate; the replacements are more
  kubelet work in the same thrash.
- Later (11:00:57 node Unknown/`unreachable` taint, back 11:01:16; 11:10:07 NotReady
  `container runtime is down`, 11:11:48 NotReady `PLEG is not healthy: pleg was last seen active
  3m6s ago; threshold is 3m0s`; 79 burst pods taint-evicted 11:10-11:11).
- After the 80-pod burst scaled to 1 (~11:08:40) with WordPress already gone: 1.3 M refaults/s
  and 95% sys continued until ~11:18:45, 10 min, with a single pod and node Ready/NotReady
  flapping; slab stayed 133-141 M (vs 102 before) and fell to 107 M when it ended.
- The API itself stayed answerable: probe max latency 0.5-1.4 s per 2 min window during
  thrash, 2.5-2.9 s at worst, one 10 s timeout at 11:00:57 (the Unknown flip).
  `kubectl scale` calls always returned. The kubelet side failed first (see below).

Not "wedged": no component stayed dead, no OOM kill (`oom_kill` 0, gate (a) PASS), node returns
Ready each time. What persists is the degraded state: a resident set that does not fit, so
reclaim never lets up until the pending pod create/delete work drains.

## Experiment 3: attribution

Resource: memory (file-cache capacity), appearing as CPU. Evidence, 20-pod repeat window
10:49:14-10:57:34 (498 s, per cgroup workingset_refault_file, per comm CPU/majflt):

- Total refault 1.43 M pages/s (~5.6 GiB/s of re-read file pages, 0% iowait: served from the
  host page cache). `/proc/stat`: user 4-6%, sys 93-95%, idle 0%, iowait 0. Memory PSI some
  ~70%, full ~40%, cpu PSI some ~99%, io some ~18-22%, full 0%.
- Who refaults: system.slice 888k/s (kubelet.service 269k, u7s-kcm 290k, crio 123k, apiserver
  59k), kubepods burstable 366k/s (CoreDNS, flannel, WordPress), user.slice 164k/s (my
  observers). Majflt over the window: kube-controller 138.5k, kubelet 150.8k, crio 89.6k,
  coredns 67.6k, apiserver 59.7k, flanneld 55.9k.
- CPU by process (% of the single vCPU): kswapd0 28.1, kubelet 12.7, KCM 12.6, apiserver 4.0,
  crio 5.7, coredns 6.7, flanneld 5.4, kube-proxy 1.7; these sum to ~75%, the rest of the 93%
  sys is direct reclaim (pgscan_direct 120-260k/s). User-space demand is small; CPU is
  saturated by reclaim.
- Not the pods: during bursts AnonPages moved 510 -> 536 M and MemAvailable 253 -> 181 M. The
  pods cost ~100 MiB total (slab + anon), which is what pushes the resident hot set of the
  control plane (Active(file) 28-80 M, Inactive(file) 130-190 M) past the cache.

Timeline of the first burst (10:17:47):
1. 10:15:47-10:17:09 WordPress/MariaDB up: refault 75-143k/s, MemAvailable 260 -> 231 M, no
   user impact.
2. 10:17:30 warm-up pod, refault 219k/s, sys 29%; 10:17:50 burst 20 starts: refault 1.28 M/s,
   sys 93%, idle 0, kswapd0 29%.
3. 10:17:49 first kubelet "Housekeeping took longer than expected" (1.3 s), 10:18:07 9.5 s,
   10:18:54 18 s, 10:19:34 39.5 s (kubelet's syncLoop is stalled, so pods are not started).
4. 10:18:16-10:20:00 readyReplicas stays 1 (pods created 10:17:48).
5. 10:20:00-10:20:41 pods finally start in bursts (4 -> 20) as the kubelet gets scheduled.
6. 10:21:13 `Failed to update lease ... context deadline exceeded` (10 s timeout), 10:21:50
   housekeeping 1m0.5 s.

Which component fails first: kubelet. Lease PUT (10 s timeout) fails in 13 log lines over the run,
housekeeping exceeded 1 s in 199 log lines (max 1m26 s at 11:01:22), kubelet declared the runtime
down/PLEG unhealthy. The apiserver served probes throughout. KCM is itself thrashing (refault
290k/s) and does the NotReady -> taint eviction step.

## Experiment 4

Done: the memory-headroom variation above (WordPress/MariaDB off). Not done (time): steps of
10 and host-network pods.

## Ruled out

- OOM kill / eviction by kubelet memory pressure: `oom_kill` 0, gate (a) PASS, no kubelet
  eviction.
- Disk/I/O: iowait 0, io PSI full 0.
- Image pulls: pause pre-pulled; the Pulling events at 10:43 and 11:13 are watch-replay
  artefacts of my events stream (not new pulls); none in burst windows.
- CPU starvation by a single user-space component: no process above 13% (aside from kswapd0).
- Host contention: steal 0.0%, quiet host, calibration 451 vs 454 ms.
- CNI/CRI latency as root cause: crio/CNI are as thrashed as everything else; no
  `FailedCreatePodSandBox`, no DeadlineExceeded in CRI-O before the node flips.
- Apiserver saturation: probe latency stays sub-second to ~3 s, no non-200 except one 10 s
  timeout.

## Open

- Why the kubelet housekeeping pass takes 16-86 s once refaulting (single-threaded loop
  doing page-faulting work vs lock waits): not profiled.
- Oct runs had 20 pods in 4-5 s and MemAvailable ~305-320 M at the end of settle20; now
  ~203-225 M at the same point (10:24:00: 219 M). The ~100 MiB of lost headroom between then
  and main 2b8dc2ab is not bisected.
- GCP n1-custom-1-1024 (mayor-ltido) not compared here; Lima is vz with the host's page cache
  behind it (0 iowait), refaults on GCP (<=800/s before bursts per mayor-i4bvb) differ.

# MemoryMin + early kubelet eviction vs the killable overload (n=1 per arm)

Bead: mayor-j1ao0

Answer: no. MemoryMin on the control-plane units plus earlier kubelet eviction did not recover the node, API or WordPress within 600 s (n=1 per arm, both INVALID for host contention), and the API was less available in arm D than in control.

Setup: trimmed Lima VM (1 GiB, 1 vCPU), WordPress+MariaDB resident, 30 BestEffort pods x 25 MiB
scaled at once, 600 s window, 120 s hold, reused arm64 tarball from the #2117 branch (includes
OOMScoreAdjust=-997). Control = no changes; D = `scripts/release-gate/exp-j1ao0-arm-d.sh`
after install. Harness patch (experiment only): `--exp-hook`, per-probe `probes.log` with each
probe's own duration.

MemoryMin values (MiB), last pre-overload WordPress-resident sample of #2117 L1b (Pss_Anon+Pss_File)
x 1.25: apiserver 23.1 -> 29, kcm 70.4 -> 88, kubelet 50.5 -> 62, crio 54.5 -> 67; system.slice
= sum + 20 = 266.

## Arm C (control)

Not recovered in 600 s (`recovery_secs=none`). Run flagged INVALID for host contention (idle CPU
48-61% < 62%); attempt 1 was a pre-flight refusal with no VM; no second valid retry (time box).
- /readyz OK in 17 of 21 probe cycles (81% by count; the 4 failures were the 121 s first cycle
  and the last three 60 s cycles, i.e. ~40% of the window by time). WordPress was never 200/302
  after overload start (000/502 in all 20 post-first probes), so no cycle had ok=1.
- Probe-gap check: 10 of 21 cycles exceeded 15 s while the node was alive (node/readyz answering
  slowly): max 121.5 s (node get 75.5 s, readyz 33.9 s, wp 12.1 s), then 33.5, 29.4, 21.8, 19.0.
  `k()` has a 30 s timeout per kubectl, so one cycle can be ~70-120 s. With ok=1 never occurring,
  widening the gap does not change this arm's "none", but a real recovery with a slow probe cycle
  could be missed by the 15 s rule; the gap must exceed the worst cycle or probes must be time-boxed.
- OOM victims: php-fpm x1, sh x6 (all adj 1000); no control-plane victim, no kubelet evictions
  (no `Evicted` events), `oom_kubesystem=0`.
- Node: Ready True -> Unknown (taint node.kubernetes.io/unreachable) -> True -> False
  (not-ready taint) -> Unknown -> API unreachable at the end. MemoryPressure stayed False;
  no memory-pressure taint (kubelet default evictionHard 100Mi never fired).
- Restart counts at end: not collectable (API unreachable at collect).

## Arm D (A+B)

Not recovered in 600 s; no better than control, API availability worse. INVALID for host
contention (idle CPU 28-58% < 62%; a pre-push test run on the host overlapped the window).
- memory.min took effect without further changes (systemd drop-in + `set-property --runtime`;
  MemoryAccounting default on, memory controller already in root subtree_control):
  kcm 92274688 B (88 MiB), apiserver 30408704 (29), kubelet 65011712 (62), crio 70254592 (67),
  system.slice 278921216 (266). system.slice was given the sum + 20 MiB so ancestor
  protection does not cap the children.
- kernelMemcgNotification: true was accepted on cgroup v2: no parse error, kubelet logged
  "created memoryThresholdNotifier" for the hard, soft and hard-allocatable thresholds. Whether
  the notifier fired is unknown: kubelet logged no eviction activity at all after the overload.
- /readyz OK in 2 of 6 probe cycles (33%); only 6 cycles fit in 600 s because 5 of them took
  52-134 s (max 134.5 s: node get 30.9 s timeout, readyz 79.0 s, wp 24.7 s), vs 10 of 21 in C.
  Only the first cycle (overload start) had ok=1; no recovery under any gap setting.
- OOM victims: php-fpm x1, sh x4 (adj 1000); no control-plane victim; zero `Evicted` events,
  no MemoryPressure=True, no memory-pressure taint (node went Unknown/unreachable at +181 s,
  before kubelet could act). Restart counts not collectable (API unreachable at collect).

## Verdict

Neither protection nor earlier eviction restored the API or WordPress inside 600 s. Evidence
(n=1 each, both INVALID for contention): the node still wedged within ~3 min; the control plane
was not OOM-killed in either arm (kubelet adj -999, apiserver/kcm -997), so the failure is
reclaim thrash/starvation, not kills; kubelet is starved too and never reached its eviction
loop, so evictionSoft/Hard at 300/200 Mi cannot act as back-pressure here. MemoryMin totalling
~246 MiB of a ~900 MiB VM did not keep the control plane responsive, and left less for
everything else (D had fewer completed probe cycles than C). Not tested: larger MemoryLow,
protecting WordPress/mariadb, a lower overload (dose-response), kubepods memory.max / pod limits
on the overload pods.

Harness finding: probe cycles of 50-135 s occur while the node is alive-but-starved, so the 15 s
max-gap rule cannot be satisfied by a starved node and a recovery could be read as `none`. A
probe should have a per-call timeout well under the gap (e.g. 5 s each) so cycle <= gap.

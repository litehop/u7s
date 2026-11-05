# MemoryMin + early kubelet eviction vs the killable overload (n=1 per arm)

Bead: mayor-j1ao0

Answer: (filled in after both arms; see sections below).

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

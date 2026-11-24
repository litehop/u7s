# Capacity

What a u7s node is expected to carry, and what it is not. The numbers come from
stamped benchmarks (date, git SHA, VM shape) under `docs/benchmarks/`, one per
minor release, cited from the [CHANGELOG](../CHANGELOG.md). u7s is alpha: the
envelope below is what is measured, not a promise beyond it.

**Latest stamped benchmark:** none committed yet. The first one is produced by
`scripts/release-gate/capacity-benchmark.sh` ([how to run it](#running-the-benchmark)).
Until a release cites one, treat every figure here as indicative.

## The envelope

| Shape | Status | What to expect |
|---|---|---|
| 1 vCPU / 1 GiB, no swap, SSD-class disk | **Gated.** Every release must pass 3 of 3 runs of the 20-pod burst with WordPress and MariaDB resident ([release gate](dev-setup.md#release-gate-1-gib-burst-survival)). | Boots to Ready in about a minute with roughly 450 MiB of `MemAvailable` idle and about 320 MiB with a small app running ([install.md](install.md#running-on-a-1-gib-host)). Comfortable: a small app plus tens of pods that are already running. A burst of about 20 pods becoming Ready together is the gated ceiling. |
| 1 vCPU / 1 GiB, with swap you provide | Not gated. | Larger bursts become survivable (an 80-pod burst timed out without swap and completed with 512 MiB zram, an indicative 2026-10 A/B). u7s never configures swap itself. |
| 2 GiB | Not gated, not yet measured. | Expected to carry larger bursts and steadier headroom; no figure is claimed until a stamped benchmark (`--memory 2`) records one. |
| Under 1 GiB, or HDD-class disk | Out of scope. | HDD-class disks (GCP pd-standard) wedge a 1 GiB node under bursts. |

## What degrades

Past the envelope the node degrades in the order the kernel decides, not the
order you would pick: page cache is reclaimed first, so every process (kubelet,
CRI-O, the apiserver) slows as it re-reads its own code from disk. Bursts take
longer, probes time out, and the node can flap NotReady.

## What is out of scope

Surviving memory overload. On 1 GiB / 1 vCPU without swap, an overload (30
BestEffort pods holding 25 MiB each on top of WordPress and MariaDB) did not
recover within 20 minutes on any arm of the experiments in bead `mayor-pzhtd`
(GCP n1-custom-1-1024, n=1 per arm). Capping kubepods at 657 MiB (closed PR
#2039) never engaged; capping at 400 MiB engaged but kubelet still stopped
heartbeating, and 300 MiB allocatable cannot schedule MariaDB. So u7s does not
aim to survive extreme overload (operator decision 2026-11-24): size the node
so the workload stays inside the envelope. The same data points are embedded in
every artefact (`docs/benchmarks/past-envelope.json`).

## Running the benchmark

```bash
scripts/release-gate/capacity-benchmark.sh --backend gcp --release <tag>      # authoritative
scripts/release-gate/capacity-benchmark.sh --backend lima --allow-contended    # local, non-authoritative
```

One install on a 1 vCPU / 1 GiB VM, WordPress and MariaDB resident, then
Ready-bursts of 20, 30, 40, 50 and 60 pods (the ramp stops at the first size
that fails the gate criteria). It writes `docs/benchmarks/<date>-<sha>/` with
`benchmark.json` and `benchmark.md`: version, git SHA, date, provider and VM
shape, idle PSS/RSS per component, time-to-Ready per burst, MemAvailable
headroom and the largest passing burst. Only the 20-pod burst gates a release;
the rest is documentation. A Lima artefact is labelled
`provider=lima (non-authoritative)`. `--memory 2` (Lima) measures the 2 GiB row.
Release timing: [releasing.md](releasing.md).

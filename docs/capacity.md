# Capacity

What a u7s node is expected to carry, and what it is not. The numbers come from
stamped benchmarks (date, git SHA, VM shape) under `docs/benchmarks/`, one per
minor release, cited from the [CHANGELOG](../CHANGELOG.md). u7s is alpha: the
envelope below is what is measured, not a promise beyond it.

**Latest stamped benchmark:**
[2026-11-25 @ d9e45502 (v0.4.7), GCP n1-custom-1-1024, Spot](benchmarks/2026-11-25-d9e45502-gcp/benchmark.md):
idle PSS 361 MiB, 445 MiB `MemAvailable` idle, and bursts of 20 to 60 pods
all Ready within 6 to 20 s with WordPress and MariaDB resident (largest pass
60, the top of the ramp; the lowest `MemAvailable` was 107 MiB at 60 pods).
It is a single run (n=1) of the published v0.4.7 release, not of current main.
These numbers do not gate a release; only the 20-pod burst gate does.
Produced by `scripts/release-gate/capacity-benchmark.sh`
([how to run it](#running-the-benchmark)).

## The envelope

| Shape | Status | What to expect |
|---|---|---|
| 1 vCPU / 1 GiB, no swap, SSD-class disk | **Gated.** Every release must pass 3 of 3 runs of the 20-pod burst with WordPress and MariaDB resident ([release gate](dev-setup.md#release-gate-1-gib-burst-survival)). | Boots to Ready in about a minute with roughly 450 MiB of `MemAvailable` idle and about 320 MiB with a small app running ([install.md](install.md#running-on-a-1-gib-host)). A burst of about 20 pods becoming Ready together is the gated ceiling. |
| 1 vCPU / 1 GiB, with swap you provide | Not gated. | **Not measured on a stamped run.** The only evidence is a historical 2026-10 A/B (an 80-pod burst timed out without swap and completed with 512 MiB zram) that predates #2115 and #2116, so it may no longer hold. u7s never configures swap itself. |
| 2 GiB | Not gated, not yet measured. | Expected to carry larger bursts and steadier headroom; no figure is claimed until a stamped benchmark (`--memory 2`) records one. |
| Under 1 GiB, or HDD-class disk | Out of scope. | HDD-class disks (GCP pd-standard) wedge a 1 GiB node under bursts. |

## What degrades

Past the envelope the node degrades in the order the kernel decides, not the
order you would pick. The working explanation is that page cache is reclaimed
first, so processes (kubelet, CRI-O, the apiserver) re-read their own code from
disk and slow down. It comes from beads `mayor-i4bvb` (80-pod burst: page-cache
refault thrash, lease and CRI timeouts, NotReady) and `mayor-hjwdo` (40-50 pod
burst: 94% iowait, API unreachable). The per-cgroup file-versus-anon split that
`mayor-pzhtd` asked for was not recorded in a committed artefact, so the
mechanism is not measured on this page. Observed symptoms: longer bursts, probe
timeouts, NotReady flapping.

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
that fails the gate criteria). It writes `docs/benchmarks/<date>-<sha8>-<provider>[-contended]/` with
`benchmark.json` and `benchmark.md`: version, git SHA, date, provider and VM
shape, idle PSS/RSS per component, time-to-Ready per burst, MemAvailable
headroom and the largest passing burst. Only the 20-pod burst gates a release;
the rest is documentation. A Lima artefact is labelled
`provider=lima (non-authoritative)`. `--memory 2` (Lima) measures the 2 GiB row.
Release timing: [releasing.md](releasing.md).

### KCM memory A/B (local)

```bash
scripts/bench/kcm-mem-ab.sh --vm <vm> --port <port> --kubelet-port <port>
```

Compares the shipped Go KCM (R) with the same KCM minus 10 candidate controllers (T, applied by
`scripts/conformance/kcm-mode.sh` as a systemd drop-in; install.sh is untouched). Runs R, T, R, T, R, T on
one VM, each from a fresh `install.sh`, and records `Pss_Anon` of the KCM and apiserver processes at an idle
and a WordPress + MariaDB stage. Writes `docs/benchmarks/<date>-<sha8>-lima-kcm-mem/` with one `kcm-mem.json`
per run plus `summary.json` and `summary.md` (medians, and the Phase 0 verdict `median(R) - median(T) >= 5` MiB
on the KCM process at every stage). Lima only, non-authoritative, not part of any release gate. The driver
restores mode R on exit (including INT/TERM), and install teardown removes `u7s-kcm.service.d`.

The checked-in run `2026-11-25-64b81227-lima-kcm-mem` is **exploratory and non-authoritative** (local Lima,
n=3 per mode). T was the 11-controller trim, which failed the VolumeAttributesClass lifecycle spec; the trim is now 10 controllers (volumeattributesclass-protection kept) and its full conformance run is owed. The
tree was dirty (`git_dirty=1`) and the stamped SHA differs from the code that ran: two fixes were made after
the run, a lint fix (`head -1` to `sed -n 1p`) and diff rounding.

### KCM leave-one-out (local)

```bash
scripts/bench/kcm-mem-loo.sh --vm <vm> --port <port> --kubelet-port <port>
```

One install, WordPress + MariaDB deployed once, then the shipped KCM restarted with a single controller
excluded (`--controllers=<installed>,-<name>`) and `Pss_Anon` sampled after a settle. An untrimmed
baseline is re-measured every 8 controllers. Writes `docs/benchmarks/<date>-<sha8>-lima-kcm-loo/`
(`rows.jsonl`, `table.json`, `table.md`). One sample set per controller, so a saving below the baseline
spread (reported in the table) is noise. The checked-in run `2026-11-26-bde957a6-lima-kcm-loo` covers the
46 controllers install.sh does not already exclude; only validatingadmissionpolicy-status (7.1 MiB) and
garbage-collector (4.1 MiB) stand clear of the 1.2 MiB spread.

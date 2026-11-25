# Capacity benchmark 2026-11-25 @ d9e45502

**provider=gcp (n1-custom-1-1024 disk=pd-balanced, authoritative)**

| | |
|---|---|
| u7s version | v0.4.7 |
| git SHA | `d9e45502ef2d23958a6e9d0bb142595ef5435038` |
| date (UTC) | 2026-11-25 |
| provider | provider=gcp (n1-custom-1-1024 disk=pd-balanced, authoritative) |
| vCPU | 1 |
| RAM (MemTotal) | 952 MiB |
| swap | 0 MiB |
| kernel / OS / arch | 7.0.0-1017-gcp / Ubuntu 26.04.1 LTS / x86_64 |

## Idle footprint (WordPress + MariaDB not yet deployed)

| component | PSS (MiB) | RSS (MiB) |
|---|---|---|
| coredns | 48.6 | 48.6 |
| flanneld | 40.6 | 40.6 |
| kube-proxy | 25.9 | 25.9 |
| kcm | 89.3 | 89.3 |
| crio | 69.0 | 69.0 |
| apiserver | 21.7 | 23.9 |
| conmon | 1.6 | 5.2 |
| kubelet | 64.5 | 66.6 |

Total idle PSS: 361.2 MiB. MemAvailable at idle: 445 MiB; minimum over the whole run after install: 107 MiB.

## Bursts to Ready

The 20-pod burst is the release gate. Larger bursts are documented, not gated. The ramp stops at the first failing size.

| pods | Ready after (s) | passed (a-d) | MemAvailable min (MiB) |
|---|---|---|---|
| 20 | 6 | yes | 258 |
| 30 | 8 | yes | 240 |
| 40 | 13 | yes | 216 |
| 50 | 16 | yes | 193 |
| 60 | 20 | yes | 107 |

Criteria: (a) no OOM kill of a control-plane process or kube-system pod, (b) node Ready throughout, (c) Ready within 300 s, (d) WordPress still answers and the MariaDB marker row survives.

Largest passing burst: 60 pods, all Ready at once on this shape, with WordPress and MariaDB resident.

## Past the envelope

- On 1 GiB / 1 vCPU with no swap, a memory overload (30 BestEffort pods holding 25 MiB each on top of WordPress and MariaDB) does not recover: the node went NotReady or froze and the API stayed unreachable for 20+ minutes on every arm (bead mayor-pzhtd, GCP n1-custom-1-1024, n=1 per arm, findings commits ff2f35cc and e7866fdf on the bead's worker branches).
- Capping kubepods at 657 MiB (the kubelet reservations and MemoryLow bundle of closed PR #2039) never engaged: every OOM kill was global and the node did worse than the uncapped control (bead mayor-pzhtd, findings commit ff2f35cc).
- Capping kubepods at 400 MiB engaged (cgroup-local OOM kills) but kubelet stopped heartbeating and nothing recovered in 20 minutes; 300 MiB allocatable could not even schedule MariaDB (bead mayor-pzhtd, findings commit e7866fdf).
- Overload survival is not a goal (operator decision 2026-11-24, bead mayor-jedol): size the node so the workload stays inside the envelope above.

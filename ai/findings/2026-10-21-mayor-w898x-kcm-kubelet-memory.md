# KCM and kubelet Go memory: what a Rust rewrite could save, and what flags save today

Bead: mayor-w898x
Date: 2026-10-21, main 360b9750, k8s 1.37.1 stock arm64 binaries, flags only.

**Answer:** on the WordPress-loaded 1 GiB node a Rust rewrite could save at
most about 22-34 MB (anon) for KCM and 27-32 MB for kubelet versus the
shipped config, and flags already reclaim about 12 MB of that for KCM
(trimmed `--controllers` plus `GOMEMLIMIT=40MiB`) and about 8 MB for kubelet
(`GOMEMLIMIT=60MiB`, noisy); the residual only a rewrite can remove is
~10-22 MB (KCM) and ~19-24 MB (kubelet). A KCM `GOMEMLIMIT` of 40 MiB is
**not** free with the shipped controller set: it pins ~22% of the 1 vCPU
in GC; it is free only together with the trimmed set.

## Method and limits

- VM: gate template (`scripts/release-gate/u7s-vps-1g.yaml`, 1 vCPU, 1 GiB,
  no swap), zero-arg `install.sh` from the main tarball, host 83% idle, no
  other VM, no cargo.
- Each variant = systemd drop-in + service restart, 45 s warm-up, then
  8 PSS samples at 5 s (idle, WordPress) or 20 samples (burst). One
  process instance per cell: no variance estimate; differences under
  ~3 MB are noise.
- Stages on one cluster, in order: A idle; B + WordPress/MariaDB (emptyDir);
  C + a 50-pod pause burst (the gate size). 20-pod and 80-pod bursts were
  not run (50 replaces the gate's pair; 80 thrashes without swap per
  `mayor-f2gfd`). A GOGC-only variant was not run: the shipped
  `GOGC=50, GOMEMLIMIT=128MiB` is GOGC-only in effect (heap never nears
  128 MiB).
- KCM `/metrics` scraped with `kubectl create token monitoring`; KCM
  `/debug/pprof` is 403 for that SA, so heap profiles used the admin client
  cert. Kubelet via `nodes/proxy`.
- **Anon is the comparable number.** File-backed PSS (binary text mapped
  from page cache) is 50 MB for KCM when the VM is idle and drops to 5-10
  MB once WordPress creates memory pressure; it is reclaimable and varies
  with cache state, so it is reported but not used for conclusions.
- "Trimmed" set (candidate, NOT derived from a conformance run, so it is
  unvalidated): shipped set plus `-ttl-controller`,
  `-legacy-serviceaccount-token-cleaner-controller`,
  `-validatingadmissionpolicy-status-controller`,
  `-storage-version-migrator-controller`,
  `-storageversion-garbage-collector-controller`,
  `-kube-apiserver-serving-clustertrustbundle-publisher-controller`,
  `-podcertificaterequest-cleaner-controller`,
  `-podgroup-protection-controller`,
  `-resourcepoolstatusrequest-controller`,
  `-volumeattributesclass-protection-controller`,
  `-horizontal-pod-autoscaler-controller`. The shipped unit already drops
  clusterrole-aggregation, device-taint-eviction, service-cidr.
- Skipped, not approximated: bytes-per-cached-object cross-check against
  u7s-apiserver (needs a large-object-count cluster; this one has ~170
  non-event objects), and a conformance-derived controller set.

Variants: **stock** = no `GOGC`/`GOMEMLIMIT`/`GOMAXPROCS`, `--controllers=*`;
**shipped** = installed unit (`GOGC=50`, KCM `GOMEMLIMIT=128MiB`, kubelet
`200MiB`, `GOMAXPROCS=2`, shipped controllers); **tuned** = shipped with
KCM `40MiB` / kubelet `60MiB`; **trim** = stock env + trimmed controllers;
**trimtuned** = tuned + trimmed controllers.

## KCM (anon MB / PSS MB incl. file / CPU of one vCPU)

| variant | idle | WordPress | 50-pod burst | burst time |
|---|---|---|---|---|
| stock | 43.0 / 97.2 / 0.4% | 43.6 / 52.1 / 0.9% | 53.2 / 57.9 / 3.5% | 29 s |
| shipped | 40.2 / 92.0 / 0.5% | 41.9 / 51.2 / 0.9% | 45.2 / 51.6 / 2.0% | 17 s |
| tuned (40 MiB) | 34.0 / 88.4 / **21.9%** | 34.0 / 45.4 / **24.4%** | 35.6 / 43.0 / **21.3%** | 32 s |
| trim | 31.7 / 83.4 / 0.3% | 33.4 / 42.0 / 0.7% | not run | n/a |
| trimtuned | 28.9 / 80.6 / 0.5% | 29.7 / 39.9 / 0.7% | 30.9 / 35.9 / 2.9% | 20 s |

Peak PSS in the burst window: stock 68.6, shipped 64.0, tuned 58.8,
trimtuned 52.3. Burst times are single runs; do not read 17 vs 29 s as an
effect of the variant.

GC thrash evidence (`go_gc_duration_seconds_count` at scrape): tuned
1220 / 1313 / 2027 GCs at idle / WordPress / burst vs shipped 16 / 16 / 19
and trimtuned 17 / 17 / 34. Live heap with the shipped controllers does not
fit under 40 MiB total runtime memory; with the trimmed set it does.

### KCM Go runtime breakdown (`/metrics`, MB, stock vs shipped, WordPress)

| bucket | stock | shipped | removable by rewrite | removable by flag |
|---|---|---|---|---|
| `go_memstats_sys_bytes` total | 54.7 | 55.0 | | |
| heap in use | 37.8 | 31.2 | partly (see live) | yes (GOGC) |
| heap idle (of which released) | 2.0 (2.0) | 9.7 (4.4) | yes | yes |
| goroutine stacks (1469 goroutines) | 8.2 | 7.1 | mostly | no |
| GC metadata + mspan + bucket hash + other | ~6.7 | ~6.9 | yes | no |
| anon minus `sys` (binary .data/.bss COW, thread stacks, malloc) | ~-11 | ~-13 | yes | no |
| file-backed PSS (73 MB binary) | 8.6 (50+ at idle) | 9.3 | yes (reclaimable) | no |

`anon - sys` is negative because `sys` counts address space the runtime has
mapped but not touched or has released. Live heap after GC (heap profile,
inuse_space): 7.6 MB at `memprofilerate=4096`, 19.3 MB at the default
512 KB rate (coarse; quanta are 0.5 MB). Largest live buckets, fine
profile: k8s api/apimachinery type registration and init 2.2 MB, go stdlib
1.2, generated openapi 0.9 (8.2 MB in the coarse profile, a sampling
artefact), component-base/prometheus metrics 0.9, client-go rest 0.5,
protobuf 0.5, logging 0.4, informer caches and workqueues 0.3.

## Kubelet (anon MB / PSS MB incl. file / CPU)

| variant | idle | WordPress | 50-pod burst | burst time |
|---|---|---|---|---|
| stock | 41.2 / 81.1 / 0.9% | 41.0 / 56.9 / 1.2% | 49.6 / 64.1 / 6.1% | 26 s |
| shipped | 37.0 / 65.8 / 1.1% | 38.5 / 54.3 / 1.5% | 47.1 / 61.3 / 6.5% | 23 s |
| tuned (60 MiB) | 37.2 / 82.5 / 0.5% | 30.4 / 46.1 / 1.5% | 46.0 / 60.1 / 7.2% | 27 s |

Peak PSS in the burst window: stock 77.7, shipped 70.7, tuned 70.1. The
60 MiB limit costs no measurable CPU, saves ~8 MB at WordPress, and ~1 MB
at the burst (live heap plus per-pod state exceeds the limit headroom
there). The idle-stage tuned figure equals shipped, so treat the 8 MB as
suggestive, not established.

### Kubelet Go runtime breakdown (MB, stock vs shipped, WordPress)

| bucket | stock | shipped | removable by rewrite | removable by flag |
|---|---|---|---|---|
| `sys` total | 34.4 | 30.4 | | |
| heap in use | 16.7 | 14.8 | partly | yes |
| heap idle | 8.5 | 6.5 | yes | yes |
| stacks (243 goroutines) | 2.8 | 2.7 | mostly | no |
| GC metadata + other | ~6.4 | ~6.4 | yes | no |
| anon minus `sys` (binary .data/.bss, threads) | +6.6 | +8.1 | yes | no |

Heap profile attribution (inuse_space, fine rate, total 6.8 MB live):
go stdlib 2.2, protobuf (CRI/CSI/api) 1.2, k8s api/apimachinery
registration 0.9, **cadvisor 0.6**, logging 0.4, sigs.k8s.io/json type
cache 0.4, CEL libs 0.2, kubelet's own packages 0.03. No informer caches
appear: the kubelet's pod/node watches are tiny on a one-node cluster
(no `client-go/tools/cache` frames above the sampling floor). Cadvisor is
~9% of live heap, ~0.6 MB; it is not a lever worth a flag.

## Rewrite upper bound, free levers, residual (WordPress, anon MB)

| | KCM | kubelet |
|---|---|---|
| shipped today | 41.9 | 38.5 |
| live heap floor (profile range) | 7.6-19.3 | 6.8-11.7 |
| rewrite upper bound (shipped - floor) | 22-34 | 27-32 |
| free lever measured | 12.2 (trimtuned 29.7) | 8.1 (tuned 30.4, noisy) |
| residual only a rewrite removes | 10-22 | 19-24 |

The "floor" is the live Go heap after GC; a Rust rewrite still needs its
own TLS/HTTP/serde state and would not reach it, so these are upper
bounds. Idle node-wide, KCM + kubelet together are ~80 MB anon today; the
upper bound for both is ~50-65 MB, of which flags already take ~20 MB.

## Recommendations

1. Do not ship `GOMEMLIMIT=40MiB` for KCM on the shipped controller set:
   22% of the single vCPU goes to GC for 6 MB.
2. KCM controller trimming is the biggest free KCM lever (trim vs stock:
   -11 MB anon at idle, -10 at WordPress, no CPU cost) but needs the candidate list validated
   against a conformance run before shipping; HPA and the clusterrole /
   TTL / VAP-status entries are the likely contributors and the ones most
   likely to break a conformance spec. Follow-up bead recommended.
3. Kubelet `GOMEMLIMIT=200MiB` -> 60MiB looks free but needs a repeat run
   (idle-stage result did not reproduce the WordPress-stage saving).
4. The Rust-rewrite case for KCM + kubelet is bounded at roughly
   30-46 MB combined beyond what flags can still reclaim.

Raw captures, if still present: `temp/e2e/w898x-20261021/` (mayor checkout).

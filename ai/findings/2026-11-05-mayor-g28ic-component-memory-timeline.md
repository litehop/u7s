# Per-component memory timeline through bursts (existing release-gate data)

Bead: mayor-g28ic

**Answer: no — concurrent transient growth of the sampled control-plane/node components does not explain the squeeze.**
Their summed PSS is flat through a burst (mean +27 MiB, max +65 MiB over 41 bursts of >= 30 s), the refault storm starts at burst start while summed PSS is 20-46 MiB *below* its pre-burst level, component peaks are staggered across the whole burst rather than concurrent, and the "+46 kcm / +44 crio" numbers in the GCP gate summary are install/idle-phase peaks, not burst growth.

## Method and data

Scripts (bash+awk, no VMs, read-only on `temp/e2e/`), all in this directory as `2026-11-05-mayor-g28ic-*.sh`:
`peaks.sh` (per phase/component start, peak, offset), `timeline.sh` (aligned burst timeline), `agg.sh` / `all.sh` (per-burst rows over all runs), `onset.sh` / `onset-all.sh` (cause-vs-effect), `comptable.sh`, `cgmem.sh`.

- 64 `samples.tsv` files; 32 contain a `burst*` phase (71 burst phases incl. the 80-pod and ramp steps).
  `attrib.tsv` (PSI, refaults) exists only for 11 of them (9ygmh x9, kutwm gate2, e5idl); the older Lima runs (hg1xx, i4bvb, od9qh, zjnon, confirm-2, jlm8z) have component PSS and MemAvailable only.
- Platform: 31 of the 32 burst runs are Lima (MemTotal ~970 MB); the only GCP run with a burst phase is `e5idl/gcp-gate/run-1` (20 pods, PASS). The other GCP runs (p3ktl, vw7jc, i4bvb-gcp-ab, kbpw7, vnmcw) stop after `wordpress` and have no burst.
  The failing GCP runs (ltido, 0/3 at 40/50) are not in this data.
- Observers: 9ygmh A1/A3/Bp* and kutwm streamed (~79 MiB); 9ygmh A0/A2 and e5idl did not; observer state of the legacy runs is not recorded here (`?`).
- Sample interval (MEM rows): 5-6 s on Lima at rest and in bursts, 6-10 s in GCP bursts (e5idl: 7 samples in the 64 s burst). Components are sampled in the same tick as MEM.
  Passing 20-pod Lima bursts finish in 5-11 s (1-3 samples): they cannot resolve peak timing and are excluded from the timing aggregates (`dur >= 30 s`).
  Counters are cumulative; rates are deltas over the previous attrib row (5-10 s windows).
- Outcome: ramp-table runs = (a)-(d) all PASS; legacy runs only record "burst finished < 300 s" (`c-ok`).
- One artefact: `hg1xx gate3 burst80` has a duplicated epoch row (sum 750 MiB); excluded from aggregates.

## 1. Per-component peak timing, five representative bursts (MiB PSS; start = first sample of the burst phase, off = peak offset / phase length in s)

| component | GCP pass, no obs, 20 pods (e5idl) | Lima pass, obs, 20 pods (A1, 156 s) | Lima pass, no obs, 40 pods (A2-2, 149 s) | Lima fail, no obs, 50 pods (A2-2, 508 s) | Lima fail, obs, 30 pods (A3, 627 s) |
|---|---|---|---|---|---|
| kubelet | 53 -> 60 (+7) 32/64 | 47 -> 59 (+12) 55/156 | 49 -> 70 (+21) 71/149 | 52 -> 76 (+24) 356/508 | 53 -> 67 (+14) 416/627 |
| crio | 56 -> 56 (0) 0/64 | 32 -> 35 (+3) 134/156 | 31 -> 41 (+10) 71/149 | 33 -> 45 (+13) 406/508 | 27 -> 35 (+8) 264/627 |
| kcm | 60 -> 67 (+7) 25/64 | 57 -> 57 (0) | 50 -> 59 (+8) 127/149 | 61 -> 71 (+10) 491/508 | 53 -> 62 (+9) 427/627 |
| apiserver | 23 -> 24 (+1) | 21 -> 25 (+4) 128/156 | 25 -> 29 (+4) 149/149 | 34 -> 34 (0) | 23 -> 28 (+5) 213/627 |
| flanneld | 13 -> 44 (+31) 25/64 | 11 -> 12 (+1) | 14 -> 14 (0) | 12 -> 24 (+13) 139/508 | 11 -> 25 (+14) 461/627 |
| kube-proxy | 14 -> 21 (+7) 17/64 | 12 -> 13 (0) | 12 -> 17 (+5) 144/149 | 12 -> 16 (+4) 27/508 | 12 -> 15 (+2) 359/627 |
| mariadb | 97 -> 97 (0) | 94 -> 99 (+5) 145/156 | 94 -> 98 (+4) 149/149 | 94 -> 102 (+8) 508/508 | 94 -> 101 (+7) 359/627 |
| php-fpm | 44 -> 48 (+4) | 41 -> 44 (+4) | 39 -> 44 (+5) | 38 -> 48 (+10) | 37 -> 40 (+3) |
| **sum of 10 comps** | 381 -> 404 (+23) @25 s | 332 -> 338 (+6) @77 s | 332 -> 369 (+37) @149 s | 355 -> 383 (+28) @508 s | 326 -> 344 (+18) @416 s |
| MemAvailable start -> min | 312 -> 242 @41 s | 216 -> 196 @100 s | 244 -> 188 @66 s | 246 -> 168 @173 s | 219 -> 62 @164 s |
| mem PSI full max (%) | 79 | 39 | 42 | 46 | 67 |

The GCP flanneld +31 is a single-sample spike (18 MiB again by the next sample).
The Lima per-component peaks are late and spread out (kubelet at 48-67 % of the burst, apiserver/mariadb/php-fpm at the very end).
In every column the summed PSS grows by <= 37 MiB while MemAvailable falls 20-157 MiB.

### Where the gate summary's "+46 kcm, +44 crio ..." comes from (e5idl, whole-run peak per component)

| component | peak PSS (MiB) | phase / offset |
|---|---|---|
| kcm | 102.7 | **install** @48/81 s |
| kubelet | 69.5 | **install** @48 s |
| kube-proxy | 44.7 | **install** @48 s |
| apiserver | 32.6 | **install** @48 s |
| crio | 84.5 | **idle** @84/179 s |
| coredns | 50.8 | **idle** @11 s |
| mariadb | 131.5 | wordpress @24/143 s |
| php-fpm / nginx | 53.2 / 6.7 | wordpress |
| flanneld | 43.7 | burst20 @25/64 s (one-sample spike) |

The same install tick (t+48 s) sets the peak of four components at once: that is the installer's page-cache residency (file-backed PSS is not anon), and the "wordpress -> peak" delta is therefore install/idle PSS minus a later, smaller wordpress-phase value.
PSS falls (crio 68 -> 40, kcm 65 -> 57, flanneld 40 -> 20, coredns 49 -> 26 idle -> wordpress) as file pages are reclaimed, i.e. PSS follows resident file cache and is not an anon-growth measure.

## 2. Aggregate over all usable runs

Bursts >= 30 s (41 phases, all Lima; gate3-burst80 duplicate-epoch row excluded):

| group | n | mean dur (s) | summed-PSS growth in burst, mean / max (MiB) | MemAvailable min, mean (MiB) | mem PSI full max, mean (%) |
|---|---|---|---|---|---|
| PASS (ramp table) | 12 | 205 | +20.6 / +40 | 186 | 44 |
| FAIL (ramp table) | 11 | 604 | +20.9 / +49 | 148 | 49 |
| legacy 80-pod / `c-ok` | 18 | 676 | +35.1 / +65 | 134 | n/a (no attrib) |

Per-component growth within a burst (peak minus first sample, only bursts where the component grew >= 3 MiB; offset = peak position as a fraction of the burst):

| component | bursts | mean +MiB | max +MiB | mean peak position | peak in last 20 % | peak in first 20 % |
|---|---|---|---|---|---|---|
| kubelet | 41 | 21.2 | 51 | 0.67 | 12 | 2 |
| crio | 35 | 14.0 | 43 | 0.40 | 6 | 15 |
| flanneld | 27 | 11.8 | 31 | 0.44 | 6 | 7 |
| kcm | 33 | 8.9 | 17 | 0.71 | 16 | 3 |
| apiserver | 32 | 6.5 | 13 | 0.80 | 18 | 0 |
| php-fpm | 29 | 6.4 | 13 | 0.28 | 3 | 18 |
| coredns | 25 | 5.8 | 11 | 0.42 | 8 | 12 |
| mariadb | 31 | 5.3 | 9 | 0.47 | 9 | 11 |
| kube-proxy | 12 | 5.2 | 8 | 0.56 | 5 | 3 |

Findings:

- **Staggered, not concurrent.** Within one burst the component peaks are spread over most of the burst (e.g. A2-2 burst50: kube-proxy @27 s, flanneld @139 s, kubelet @356 s, crio @406 s, kcm @491 s, mariadb/php-fpm @508 s). Only php-fpm/mariadb/crio cluster early (the first seconds after warmup); apiserver/kcm/kubelet grow slowly and peak late, i.e. they track burst *duration* (a stuck burst keeps creating/updating objects), not burst start.
- **Passing vs failing:** the summed growth is the same (+20.6 vs +20.9 MiB); what differs is duration (205 vs 604 s) and MemAvailable min (186 vs 148 MiB). Component growth is a symptom of a long burst, not a discriminator.
- **Lima vs GCP:** Lima pre-burst refault is already 33k-110k pages/s and 1.0-2.0 M pages/s in the storm (pgscan ~ refault: pure file-cache thrash); GCP e5idl is 0.3-1.8k/s at rest and 3.4-6.3k/s in the burst with mem PSI full up to 79 %. Refault count is therefore not comparable across the two (Lima refaults appear cheap, host-backed); use PSI full. Only one GCP burst (passing) exists, so no GCP fail/pass contrast is possible from this data.
- 20-pod bursts that pass in 5-11 s on Lima (17 runs) have 1-3 samples; summed PSS +0..+23 there.

## 3. Aligned burst timeline (t=0 = first `burst*` sample; refault in pages/s, PSI in %)

GCP, passing, no observers (e5idl burst20, 64 s; sample every 5-10 s):

| t (s) | phase | sum PSS (MiB) | MemAvail (MiB) | refault/s | mem PSI full | mem PSI some |
|---|---|---|---|---|---|---|
| -60 | wordpress | 392 | 300 | 1818 | 1.6 | 1.8 |
| -28 | wordpress | 373 | 299 | 408 | 0.1 | 0.1 |
| -12 | warmup | 375 | 320 | 667 | 0.1 | 0.2 |
| -6 | warmup | 376 | 320 | 6063 | 13.3 | 16.0 |
| 0 | burst20 | 381 | 312 | 5124 | 18.1 | 27.3 |
| 7 | burst20 | 362 | 296 | 6329 | 25.6 | 44.0 |
| 17 | burst20 | 366 | 279 | 3692 | 23.2 | 36.5 |
| 25 | burst20 | 404 | 288 | 3600 | 8.0 | 11.9 |
| 32 | burst20 | 381 | 295 | 5272 | 56.9 | 68.7 |
| 41 | burst20 | 351 | 242 | 5133 | 51.1 | 72.3 |
| 64 | burst20 | 336 | 308 | 5498 | 79.4 | 90.7 |
| 80 | settle20 | 355 | 309 | 3442 | 28.2 | 34.2 |
| 101 | settle20 | 302 | 335 | 5121 | 45.1 | 61.5 |
| 111 | settle20 | 289 | 402 | 1781 | 6.7 | 9.5 |
| 130 | settle20 | 399 | 309 | 1408 | 3.5 | 9.0 |
| 168 | settle20 | 398 | 300 | 459 | 0.0 | 0.0 |

Reading: PSI full rises at t=-6 (warmup, before the burst phase) with summed PSS at its baseline; the sum peaks (404) at t=25 s when PSI full is *low* (8 %); the worst PSI (79 %) is at t=64 where the sum is down to 336. The PSS sum moves inversely to pressure.

Lima, failing, no observers (A2 run-2 burst50, 50 pods; every 5-6 s for the first 105 s, then sparse):

| t (s) | sum PSS | MemAvail | refault/s | PSI full | PSI some |
|---|---|---|---|---|---|
| -20 | 374 | 245 | 47907 | 1.9 | 2.2 |
| -5 | 362 | 246 | 46324 | 2.5 | 3.1 |
| 0 | 355 | 246 | 95778 | 4.5 | 5.4 |
| 6 | 340 | 218 | 887510 | 28.2 | 48.1 |
| 17 | 343 | 225 | 1314287 | 37.6 | 61.8 |
| 33 | 342 | 214 | 868340 | 25.2 | 40.4 |
| 60 | 352 | 208 | 1624754 | 41.4 | 71.3 |
| 82 | 349 | 181 | 1569319 | 42.8 | 89.0 |
| 105 | 355 | 175 | 1386443 | 37.5 | 64.7 |
| 173 | 354 | 168 | 1342491 | 38.2 | 79.1 |
| 311 | 344 | 195 | 1346891 | 38.6 | 65.1 |
| 508 | 383 | 231 | 951756 | 29.4 | 55.0 |

Summed PSS stays 340-365 for the whole 500 s while the refault rate is 1.0-1.6 M/s and MemAvailable slides 246 -> 168 MiB (-78 MiB) within ~170 s. The ~78 MiB goes somewhere the sampler does not see.

### Cause vs effect (`onset-all.sh`; 11 runs with attrib, first burst20; thresholds: refault > 5x pre-burst mean, PSI full > 10 %, summed PSS > baseline + 15 MiB)

| run | refault onset (s) | PSI full > 10 % (s) | PSS sum at refault onset vs baseline | PSS sum > baseline+15 |
|---|---|---|---|---|
| Lima 9ygmh A0 | +5 | +5 | -36 | -5 (single sample) |
| Lima A1 | -5 | -5 | -30 | never in 120 s |
| Lima A2-1 | +6 | +6 | -37 | never |
| Lima A2-2 | +5 | +5 | -46 | never |
| Lima A3 | +5 | +5 | -46 | never |
| Lima Bp1-1 | +6 | +6 | -30 | never |
| Lima Bp1-2 | +6 | +6 | -20 | +368 s |
| Lima Bp2 | +6 | +6 | -44 | never |
| Lima Bp3 | +6 | +6 | -33 | +237 s |
| Lima kutwm | +7 | +7 | -37 | never |
| GCP e5idl | none (5x of a low base) | +7 (-6 in the table above) | 0 | +25 s |

In all 10 Lima runs the storm begins in the first 5-7 s of the burst (pods are being sandboxed/started) while the component sum is 20-46 MiB under baseline: growth does not precede the refaults; the sum falls with them.
Resolution caveat: 5-6 s sampling cannot order events within one interval, but a 5 s lead of the storm over a PSS drop and the absence of any rise in 120 s rules out growth-as-cause at that resolution.

## Verdict

1. Concurrent transient growth of kubelet/crio/kcm/apiserver/flanneld/kube-proxy/mariadb (the sampled set) is not what squeezes the ~260 MiB of reclaimable cache. Total growth is <= 65 MiB (mean 27) even summing non-simultaneous peaks, equal in passing and failing bursts, and absent at the refault onset. Kubelet is the one real grower (+21 mean, +51 max, slow, late) and scales with burst duration/pod count; crio +14 early.
2. The gate summary's "+46 kcm +44 crio" reading is an artefact of comparing install/idle peaks (page-cache-inflated file PSS) with the post-reclaim wordpress-phase value.
3. MemAvailable falls 70-160 MiB in failing bursts while sampled-component PSS is flat, so the squeeze lives in memory the sampler does not attribute: new pod sandboxes/containers (pause + app processes, conmon), unsampled processes (u7s-scheduler, conmon, containerd-shim-like helpers), kernel memory (slab, pagetables, netns/cgroup structures), and the page-cache composition itself (Active(file) vs Inactive(file) protecting hot pages). `kubepods.slice` memory.current is flat ~240-255 MiB (it includes cache), so it does not discriminate either.

## Next measurement

Replace PSS-of-named-components by a whole-system split, sampled at <= 2 s through a burst (5 s cannot order the first 10 s, which is where the storm starts):

1. `/proc/meminfo` in the sampler: AnonPages, Active(file), Inactive(file), Slab/SReclaimable/SUnreclaim, PageTables, KernelStack, Shmem, Mapped. The question is how fast Active(file)+Inactive(file) shrink and whether anon+slab+pagetables absorb the loss.
2. Per-process `Pss_Anon`/`Pss_File` (smaps_rollup) for the same components plus conmon, pause, u7s-scheduler, and every pod process aggregated, so anon growth is separated from file residency (PSS conflates them, shown above).
3. If anon is flat and file shrinks: the squeeze is file cache being displaced by pod/kernel memory, so test which file set is being refaulted (`workingset_refault_file` per cgroup via `memory.stat` in `u7s.slice` vs `kubepods.slice`), and the mem PSI per cgroup, rather than component heap snapshots. KCM/apiserver `/metrics` heap snapshots are low value now: their burst growth is <= 17 MiB.
4. For Lima vs GCP comparability, record PSI full and `pgscan`/`pgsteal` rather than refaults (refault counts differ by 200x between platforms).
5. Add a GCP failing burst (n >= 1; this data only has a passing GCP 20-pod burst) with the same sampler at <= 2 s.

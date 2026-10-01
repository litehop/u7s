# CoreDNS memory: root cause is a DNS forwarding loop, not query volume or MADV_FREE

Bead: mayor-rtx3q (follow-on of mayor-60vz3)

**Answer:** CoreDNS's `forward . /etc/resolv.conf` resolves to CoreDNS itself
(`nameserver 127.0.0.1` / `::1`, because kubelet is configured with
`resolvConf: ""`), so a single query that falls through to `forward` spawns a
self-amplifying storm of ~24,000 blocked handler goroutines whose stacks take
the pod from 58 MiB to ~600+ MiB RSS within seconds; the post-burst ~141-145
MiB plateau is hard-consumed Go runtime memory (not reclaimable by the
kernel), and the fix is to remove the loop, not to tune GOMEMLIMIT.

All measurements: lima-node-5, single node, CoreDNS v1.14.7 (go1.26.6, arm64),
2026-10-01 UTC, pprof plugin live-patched on that disposable stack only.
Raw data: `/Users/balint.erdos/litehop/u7s/temp/e2e/rtx3q-0255/` (cited per
claim below). No tracked manifest was changed.

## 1. Is the plateau real? Yes: hard-consumed, not reclaimable

- Go 1.26 on Linux does not use MADV_FREE by default. `smaps_rollup` shows
  `LazyFree: 0 kB` in every sample (all CSVs, column `lazyfree_kb`). The
  MADV_FREE hypothesis is refuted.
- Post-burst floor (GOMEMLIMIT=128MiB, 02:39:17Z, `E2_128.csv`):
  `VmRSS 146,880 kB = RssAnon 98,932 + RssFile 47,948`. Runtime view
  (`E2_heap_floor.txt`): HeapInuse 57.6 MiB (HeapAlloc 33.5 MiB), HeapReleased
  483 MiB of HeapSys 551 MiB, OtherSys 17.5 MiB, GCSys 5 MiB, Stack 5.4 MiB.
  So anon retained ~99 MiB = heap spans still in use after the storm
  (fragmentation plus garbage up to NextGC) plus runtime overhead.
- Reclaim test: with no swap, cgroup `memory.high=70M` set on the container
  scope (anon 101,339,136 B): after 20 s anon was 101,343,232 B, `memory.events`
  `high 320`, `oom 0`. The kernel tried 320 times and reclaimed nothing. The
  plateau would not shrink under node pressure; it only shrinks when the Go
  scavenger returns pages.
- Idle fresh process: 56-58 MiB RSS, of which RssAnon 10 MiB and RssFile 47
  MiB (the mapped coredns binary). So the true working set above the
  mapped binary is ~10 MiB; the "30 MiB in prod" figure is consistent.
- Return is slow and staircase-shaped, driven by the 2-minute forced GC plus
  background scavenger (GOMEMLIMIT=512MiB, `E1_512.csv`):
  02:28:06 529 MiB, 02:30:06 243 MiB, 02:32:07 141 MiB, flat afterwards.
  The earlier Sept run shows the same: 535 MiB at 15:57:55, 160 MiB 16:01,
  145 MiB from 16:03 (`0910-1621-conformance/monitoring/rss.csv`, same
  `cpu_seconds` jump 1 -> 19 in the first minute, i.e. a real CPU storm,
  not an idle anomaly).

## 2. What triggers the burst: any query that falls through to `forward`

Mechanism evidence:

- The CoreDNS pod's resolv.conf (read via `/proc/<pid>/root/etc/resolv.conf`):
  `search .`, `nameserver 127.0.0.1`, `nameserver ::1`. Source:
  `lima/kubelet.yaml:300` and `scripts/install.sh:264-291` set
  `resolvConf: ""`, so kubelet gives `dnsPolicy: Default` pods a loopback
  resolver. `forward . /etc/resolv.conf` therefore forwards to itself.
- Amplification: one `nslookup example.com` (02:27:58Z) left CoreDNS
  `coredns_dns_request_duration_seconds_count` at ~64,500 requests from
  127.0.0.1/::1 (A/AAAA/NS). Errors log `dial udp 127.0.0.1:53: connect:
  resource temporarily unavailable` (socket exhaustion ends the storm).
- Goroutine profile at the peak (`A2_goroutine_peak_24112.txt`, polled every
  0.2 s): count 41 -> 544 -> 2,669 -> 5,180 -> ... -> 24,112 over ~10 s, in
  waves, back to 41 after ~15 s. 23,792 of them share one stack:

  ```
  proxy.(*Proxy).lookupDNS (connect.go:187) -> dns.(*Conn).ReadMsg -> net.(*conn).Read -> poll.runtime_pollWait
  <- proxy.(*Proxy).Connect <- forward.(*Forward).ServeDNS (forward.go:191)
  <- kubernetes.Kubernetes.ServeDNS <- cache.(*Cache).doRefresh <- cache.(*Cache).ServeDNS
  <- loadbalance <- errors
  ```
- Memory goes to goroutine stacks, not the heap: at 02:25:03Z MemStats showed
  `Stack = 363,134,976` (346 MiB) vs HeapInuse 101 MiB, Sys 595 MiB
  (`A_heap_t10.txt`). Allocator sites in the allocs profile (`A_allocs_t10.txt`)
  are `net.(*conn).SetReadDeadline` / `context.WithDeadline` called from
  `proxy.(*Proxy).lookupDNS`/`Connect` and `runtime.newproc1`/`allgadd`
  (goroutine creation) - the forward plugin's per-hop work, not cache,
  prometheus or the kubernetes informers.
- One query, timeline (`A2.csv`, 1 s sampling): 02:26:33 60 MiB -> 02:26:34 290
  -> 02:26:36 546 -> 02:26:39 620 MiB; 66 GCs in the first 6 s.

Query load itself is not the trigger (sonobuoy `--procs=16` mimic: 16 parallel
workers per pod, distinct one-off qnames, via the busybox `nslookup` search-list
path, scripts `load.sh`/`load_local.sh`):

| scenario | requests to CoreDNS | RSS |
|---|---|---|
| broken forward (loop), cluster.local NXDOMAIN only, 1 pod x 16 workers, 40 s (`G1_local_broken.csv`) | 520,950 (~13k qps) | 57 -> 74 MiB, flat (peak 76 MiB) |
| fixed upstream (`forward . 192.168.109.2`), 4 pods x 16 workers, cluster.local + external NXDOMAIN, 80 s (`F1_fixed.csv`) | 199,560 | 59 -> 85 MiB, flat (peak 87 MiB); cache filled to its cap (9,984 denial + 9,984 success entries) |
| broken forward, one external query (`A_oneq.csv`/`A2.csv`/`E1_512.csv`) | ~64,500 | 58 -> 600-640 MiB |

Cache plugin growth is bounded (+~25 MiB at cap) and prometheus per-request
metrics did not show up in any profile. The cluster.local zone is answered
authoritatively by the kubernetes plugin and never reaches `forward`; the
conformance suite's 15:57 and 16:17 bursts are explained by tests that resolve
a name outside cluster.local (the `fallthrough` is only for in-addr.arpa, but
anything else, e.g. external names, goes to `forward`). I did not identify which
specific e2e test issued it (not verified).

## 3. Fix recommendation, with measurements

Ranked:

1. **Break the loop (root cause).** Give CoreDNS a real upstream. Verified
   equivalent: with the upstream pointed at the VM's real resolver the same
   `nslookup example.com` returns an answer and the 80 s heavy mixed load
   stayed at 85 MiB (peak 87). Concretely, for the Lima rig and
   `scripts/install.sh`, set kubelet `resolvConf` to the systemd-resolved
   non-stub file (`/run/systemd/resolve/resolv.conf`, which on lima-node-5 holds
   `nameserver 192.168.109.2`) instead of `""`; the install.sh comment
   ("127.0.0.53 stub unreachable from a pod netns") is correct but the `""`
   workaround produces a loopback resolver, which is worse. This also affects
   real installs (`scripts/install.sh`), not only the test rig.
2. **Cap forward concurrency.** `forward . /etc/resolv.conf { max_concurrent
   1000 }` is what upstream kubeadm's Corefile ships; u7s dropped it. Measured
   with the loop still present (`H1_maxconc.csv`): the same single external
   query peaks at 79.6 MiB (02:51:37Z) and settles at 62-63 MiB, versus
   600-640 MiB without it. Defence in depth: bounds any future runaway.
3. **Do not retune GOMEMLIMIT as the fix.** Same single query, loop present:

   | GOMEMLIMIT | peak RSS | floor after ~3-5 min | note |
   |---|---|---|---|
   | 512MiB (current) | ~618-640 MiB | 141 MiB (02:33:08Z) | |
   | 128MiB | 467 MiB | 143 MiB (02:39:17Z) | 3 recurring spikes to 456 MiB |
   | 64MiB | 610 MiB | 133 MiB (02:44:54Z) | 1,204 GCs by 02:44 (GC thrash: stacks alone exceed the limit) |

   The floor is ~133-143 MiB for all three values and the peak is unchanged
   because stacks, not heap, dominate. Once the loop is gone GOMEMLIMIT matters
   little (working set 59-87 MiB).
4. `loop` plugin (kubeadm default) would detect the loop but CoreDNS exits
   fatally on detection, so on the current rig it would crash-loop; use it
   only after fix 1. Not tested.
5. Permanent `pprof` hook in `manifests/coredns.yaml`: **recommend not adding
   it.** It was needed only to confirm the mechanism (it bound
   `0.0.0.0:6060` here; the default `localhost:6060` is unreachable from the
   VM and the image has no shell/curl, so a standing hook is not even
   convenient). Operator decision per brief; no manifest change made.

Remaining real cost once fixed: RSS 57 MiB idle (47 MiB is the mapped binary),
75-87 MiB under 2.5k qps mixed load with a full cache. That is ~2-3x the "<30
MiB" quoted for prod, almost all RssFile plus bounded cache.

## Risks / unknowns

- The `. NS` requests in the storm come from forward's health check as well as
  the client queries; I did not separate them. The loop terminates on fd
  exhaustion, so storm size depends on ulimits and may differ on other hosts.
- Peak numbers for E1 and the A2 run overlap in time (two samplers briefly
  ran, A2's tail rows belong to the E1 pod); E1 peak is quoted as ~618-640 MiB.
- Which e2e test issued the fall-through query in the Sept runs is unverified.
- `max_concurrent`, `loop` and the kubelet `resolvConf` change were not run
  through a full sonobuoy pass (out of scope for this bead; `--stack-only`).
- Setup note: first `--reset` on this VM failed at
  `/tmp/kubelet-pods/kube-proxy-pull.yaml: No such file or directory` (the
  directory was missing after the reprovision); `mkdir -p /tmp/kubelet-pods`
  in the VM, then two reruns (one hit a dpkg lock held by unattended-upgrades)
  got the stack up.

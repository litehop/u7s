# Where did the ~100 MiB of idle headroom go?

Bead: mayor-adwea
Date: 2026-11-04

**Answer: (in progress, see Results.)**

## Premise check: is 219 vs 305-320 MiB like-for-like?

Not exactly. Sources:

- October 305-320 MiB: mayor-i4bvb Phase 1 (2026-10-15, base b3a14d06, quiet Lima host): "MemAvailable
  end of settle20 ~305-320 MB", i.e. WordPress + MariaDB resident, after the first 20-pod burst
  settled. The same bead's description gives "idle ~430" (no workload).
- November 219 MiB: mayor-kutwm, main 2b8dc2ab, Lima arm64 `u7s-vps-1g.yaml`, installed with
  `install.sh --tarball`, sampled at 10:24:00 after WordPress + MariaDB, one 20-pod burst and its
  scale-down, plus ~10 observer processes (journalctl -f, 7 curl/jq pairs, a 1 s sampler) in
  user.slice, and after a thrash episode that left slab at 133-141 MiB vs 102 before. The same
  run's fresh idle (no workload) was 375 MiB (10:13:44-10:15:06) and 260 -> 231 MiB right after
  WordPress came up (10:15:47-10:17:09).
- So the 100 MiB gap compares a post-burst, observer-laden, post-thrash point (Nov) with a
  post-burst point of a different arm/harness (Oct). It overstates a pure idle regression.
  Like-for-like numbers below come from identical fresh GCP `n1-custom-1-1024` VMs (kernel
  7.0.0-1014-gcp, Ubuntu 26.04, MemTotal 975860 kB, no swap), bare install + 10 min settle, then
  + WordPress/MariaDB (same manifest from main, MariaDB on emptyDir as the gate does).

## Method

(to be filled)

## Results

(to be filled)

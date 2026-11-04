# MariaDB 11.8 first init on GCP e2-micro

Bead: mayor-w5xs5

**Cause (measured): the e2-micro gives 25% sustained CPU, so once its 30 s burst allowance is spent every CPU-bound step runs 6-10x slower; the image's temp server (started with `--skip-ssl --ssl-cert='' --ssl-key='' --ssl-ca=''`) still generates an RSA key at startup, which costs 18-30 s on a drained e2-micro versus ~1 s on a normal core and pushes "Waiting for server startup" past the entrypoint's ~35 s limit; under u7s the 375m CPU limit adds ~80-110 s of CFS throttling on top. It is not disk, not probe connections, and not a u7s/k8s bug.**

The previous "28 CPU-s in BN_mod_exp_mont_consttime" claim was wrong in form: guest CPU-s are inflated by hypervisor throttling (see 1 and 2), and the crypto in the stack is RSA key *generation* from `new_VioSSLAcceptorFd`.

Evidence level: n=2 to 6 per cell, single GCP zone (us-west1-b), one image digest. The mechanism is supported by three independent controls; exact percentages are not.

## Hypotheses

| Hypothesis | Verdict | Evidence |
|---|---|---|
| e2-micro is much slower than a "real" 1 vCPU | Confirmed | 1, 2, 3 |
| u7s/k8s causes it (probes, TLS healthchecks, concurrent unpack) | Ruled out as the cause; CPU limit and control-plane load amplify it | 3, 5 |
| Disk (pd-standard) | Ruled out | strace: `fdatasync` 1208 calls 0.30 s total; 49% of perf samples are idle (swapper) |
| libcrypto is slow / TLS keygen takes minutes | Keygen is real and is the largest single mariadbd phase, but takes seconds per key on a normal core; minutes only under the throttle | 4, 6 |
| The temp server skips SSL because the entrypoint passes `--skip-ssl` | Not true in 11.8.6 | 4 (entry flags 18-30 s vs plain `--skip-ssl` 6-9 s) |
| Image problem | Partly: the entrypoint's empty `--ssl-*=` flags keep keygen on, and its wait is a fixed ~35 s | 4 |

## 1. The machine

GCP docs (https://cloud.google.com/compute/docs/general-purpose-machines, fetched 2026-11-04): "e2-micro sustains 2 vCPUs, each for 12.5% of CPU time, totaling 25% CPU time. e2-small ... 50% ... e2-medium sustains 2 vCPUs, each at 50% of CPU time, totaling 100% CPU time." Burst when at 100% CPU: e2-micro 30 s, e2-small 60 s, e2-medium 120 s.

| Machine | nproc | CPU | Condition | openssl genrsa 2048 x5 | rsa2048 sign/s | steal |
|---|---|---|---|---|---|---|
| e2-medium | 2 | AMD EPYC 7B12 | idle | 0.37 s | 1492 | 2 ticks of 10246 |
| e2-micro | 2 | AMD EPYC 7B12 | after apt install + 41 s image pull | 2.24 s | 180 | 1 of 7150 |
| e2-micro | 2 | AMD EPYC 7B12 | after 150 s of 2x `yes` (drained) | 2.26, 2.27 s | not measured | n/a |

e2-micro is 6x (keygen) to 8x (RSA sign) slower than e2-medium once drained, and the guest reports steal of about 0.02% throughout: the throttle is invisible in `/proc/stat` steal (and guest CPU-s are inflated, see 2).

## 2. Control A (plain podman, e2-micro) and Control B (e2-medium)

Setup: Ubuntu 26.04 VM (vps.sh flags: Spot, pd-standard 10 GB, label `u7s-test=1`, tag `u7s-test-vps`), root podman, image `docker.io/mariadb:11.8.6-noble` pre-pulled (id `93ce7a24...`), env as in `examples/e2e/wordpress/mariadb.yaml`, fresh empty bind-mounted datadir per run, no CPU limit. "Seconds" = `podman run` to the second "ready for connections" (the real server). CPU-s = container cgroup `cpu.stat` usage_usec delta (guest-accounted). Throttled = 0 (no limit; `nr_throttled 0`).

Pull time: e2-medium 6.0 s; e2-micro 41.3 s (excluded below).

| Machine | Condition | Run | Seconds to ready | CPU-s | Steal |
|---|---|---|---|---|---|
| e2-medium | idle | 1 | 10.96 | 3.93 | 1 tick of 2172 |
| e2-medium | idle | 2 | 6.87 | 4.37 | 0 of 1359 |
| e2-medium | idle | 3 | 6.88 | 7.67 | 1 of 1366 |
| e2-micro | after apt + pull | 1 | 64.3 | 47.9 | 1 of 5360 |
| e2-micro | same | 2 | 45.3 | 61.9 | 1 of 3502 |
| e2-micro | same | 3 | 70.3 | 35.5 | 1 of 5296 |
| e2-micro | ~2 min after the runs above (bucket partly refilled, not verified) | perf run `prof` | init-start to ready ~7-10 s | 4.43 | n/a |
| e2-micro | drained (150 s 2x yes) | perf run | ~42 | 40.7 | n/a |
| e2-micro | drained | `default1` (`ssl.sh`, first attempt, killed) | entrypoint "Unable to start server." 34 s after the temp server's wsrep line | n/a | n/a |

Reading: the same container does 4-8 CPU-s of work on e2-medium (7-11 s) and on a full-burst e2-micro (4.4 CPU-s), but reports 35-62 "CPU-s" and takes 45-70 s on a drained e2-micro. Guest-accounted CPU-s grow 10x while the work is constant, which is the hypervisor freezing the vCPU while the guest clock keeps running (no steal reported). This is why a CPU-s figure taken inside an e2-micro cannot be used as a cost of the workload.

The failure reproduces without Kubernetes: drained e2-micro, plain podman, `default1` hit `[ERROR] [Entrypoint]: Unable to start server.` (log: temp server started 01:08:45.9, wsrep line 01:08:47.0, error 01:09:20.96).

## 3. u7s v0.4.3-snapshot.4 on e2-micro (MariaDB only)

Install: `https://u7s.dekiru.tech/v0.4.3-snapshot.4/install.sh`; its sha256 `c7bb8d9c...760fcd` equals the GitHub release asset's (`gh release download`); the installer itself checks the tarball sha256 (release `.sha256`: `194a8300...19314`). Manifest = `examples/e2e/wordpress/mariadb.yaml` with the gate's emptyDir rewrite (no csi-hostpath on the VM), applied alone (no WordPress). Image pre-pulled by the first run's kubelet pull (the `crictl pull` step failed, `crictl` not in PATH; the first run includes the pull, runs 2-3 do not). Container cgroup `cpu.max` = `38000 100000` (the manifest's 375m limit; request 250m). "Seconds" = `kubectl apply` to second "ready for connections"; "failed" = container exited with `Unable to start server.` and was restarted (the restart skips init, healthcheck gets Access denied, never Ready; wall = until restart observed).

| Run | Condition | Outcome | Seconds | CPU-s (guest) | Throttled s (of nr_throttled) | Steal ticks |
|---|---|---|---|---|---|---|
| mdb-1 | right after install, limit 375m | ready | 227 | 32.3 | 108.6 (930) | 10 of 24344 |
| mdb-2 | limit 375m | failed | 137 | 22.1 | 99.3 (760) | 3 of 12709 |
| mdb-3 | limit 375m | ready | 205 | 34.1 | 98.5 (929) | 6 of 18283 |
| wp-1 | limit 375m, WordPress applied too | failed | 220 | 19.2 | 97.5 (761) | 11 of 24842 |
| nolimit-1 | limit removed, idle first | ready | 16.3 | 5.7 | 0 | 1 of 3184 |
| nolimit-2 | limit removed | ready | 40.5 | 26.9 | 0 | 1 of 2848 |

Alternating A/B, each preceded by an identical 150 s CPU drain (`alt.sh`):

| Pair | Limit 375m | No limit |
|---|---|---|
| 1 | ready 174 s, throttled 78.6 s | failed 81 s (CPU-s 39.4) |
| 2 | failed 147 s, throttled 109.7 s | ready 98 s (CPU-s 52.8) |
| 3 | failed 130 s, throttled 89.6 s | ready 101 s (CPU-s 58.7) |

Reading: with the limit, 1/3 pass and 80-110 s of each run is CFS throttling; without it, 2/3 pass and take 98-101 s on a drained VM, 16-40 s on a rested one. WordPress concurrent unpack: one run, failed, but the limit-375m runs without WordPress also fail 2/4 (mdb-2, alt limit-2/-3), so one run cannot separate its effect; I did not measure it further. Even without the limit, u7s on a drained e2-micro (98-101 s) is slower than plain podman (45-70 s) because the kubelet, apiserver and crio share the same 25%.

Probe connections: `SHOW GLOBAL STATUS` after a ready run (uptime 51 s): `Connections 7, Ssl_accepts 1, Aborted_connects 0, Threads_connected 1`. During the temp server `--skip-networking` means healthcheck.sh can only use the socket; after a failed init the logs show 3 Access-denied attempts per 10 s probe (`mysql@localhost`, `mysql@::1`, `mysql@localhost`, no password). That is a handful of cheap connections, not a CPU factor.

Timestamps (mdb-3, from `kubectl logs --timestamps`): entrypoint start 01:32:41.6; "Initializing database files" 01:33:04 (+23 s); "Database files initialized" 01:33:32 (28 s); wsrep line 01:33:35.9; Event Scheduler 01:33:50.7 (15 s); "Temporary server started" 01:33:52.6; "Stopping temporary server" 01:34:33 (40 s of init SQL); final server wsrep line 01:34:39.9; "Server socket created" 01:35:53.7 (74 s, the final server's own keygen, not subject to the entrypoint wait).

## 4. Does the temp server really still generate keys?

Direct `mariadbd --skip-networking` on a finished datadir (copy), drained e2-micro before each start, container started with `--entrypoint mariadbd`:

| Flags | Run 1 | Run 2 |
|---|---|---|
| none (default SSL auto-generation) | 36.0 s | 23.9 s |
| `--skip-ssl` | 6.3 s | 8.7 s |
| the entrypoint's: `--skip-ssl --ssl-cert= --ssl-key= --ssl-ca=` + tz/wsrep/slave flags | 30.3 s | 18.0 s |
| entrypoint's without the three empty `--ssl-*=` | 9.1 s | 5.7 s |

The entrypoint source (`/usr/local/bin/docker-entrypoint.sh` lines 121-127 in the image) passes `--skip-ssl --ssl-cert='' --ssl-key='' --ssl-ca=''` to the temp server. The only difference between rows 3 and 4 is the empty `--ssl-*=` options. So in 11.8.6 an explicit empty `ssl-cert` re-enables auto-generation despite `--skip-ssl`.

Full first init with plain podman `--skip-ssl` as CMD (the entrypoint still adds its own flags), drained, `ssl.sh` 3 pairs:

| | default | `--skip-ssl` as CMD |
|---|---|---|
| 1 | 61.7 s ok | 55.5 s, entrypoint failed |
| 2 | 46.1 s ok | 44.3 s ok |
| 3 | 76.5 s ok | 47.5 s ok |

Not a fix: CMD `--skip-ssl` only removes the *final* server's keygen (final server gap 0.04 s in the profiled run), not the temp server's, which is the one under the entrypoint's wait.

Isolated RSA keygen on the drained e2-micro (`openssl genpkey`, 6 each): 4096-bit 10.7, 3.0, 3.3, 1.0, 4.8, 3.5 s (median 3.4 s); 2048-bit 1.0, 0.75, 0.25, 0.26, 0.49, 0.51 s. Which key size and how many keys MariaDB generates was not measured; the observed 18-30 s versus 6-9 s difference implies more than one 4096-bit generation or a larger tail than these six samples (keygen time is a random-prime search with a long tail).

## 5. Profile (perf -a -g -F 99, e2-micro, drained, plain podman, full init)

Symbols: `mariadbd` has a symbol table (names below resolve); libcrypto resolves only exported names (inner frames shown as addresses); no dbgsym installed. The image's apt source (`deb http://archive.mariadb.org/mariadb-11.8.6/repo/ubuntu/ noble main main/debug`) offers a debug component; not needed to name the phases. Kernel frames did not symbolise.

Caveat: samples are tick-based, so time the hypervisor froze the vCPU is under-counted (1522 samples at 99 Hz x 2 CPUs for a ~42 s run); 49% of samples are `swapper` (idle/frozen). Percentages are of all samples; mariadbd = 25.2%.

Top inclusive paths in `mariadbd` (default flags, run `prof2`):

| Inclusive | Self | Symbol (caller chain) |
|---|---|---|
| 17.2% | 0 | `_start` > `__libc_start_main` > `mysqld_main` |
| 9.7% | 0 | `new_VioSSLAcceptorFd` (called from `mysqld_main`) |
| 9.2% | 0 | `EVP_PKEY_generate` (called from `new_VioSSLAcceptorFd`) |
| 5.6% | 5.35% | `BN_consttime_swap` (from EVP_PKEY_generate via unnamed libcrypto frames) |
| 3.3% | 0.3% | `BN_gcd` |
| 2.0% | 0 | `bootstrap` > `mysql_parse` (install-db SQL) |

`new_VioSSLAcceptorFd` is 38% of mariadbd's samples. Same profile with `--skip-ssl` as CMD (`prof3`): `new_VioSSLAcceptorFd` 12.4%, `EVP_PKEY_generate` 12.2%, `BN_consttime_swap` 6.8% self, of mariadbd 25.7% (48%): the temp server's keygen remains. No `BN_mod_exp_mont_consttime` is in the top paths; the crypto is key generation, not modular exponentiation for handshakes.

Other mariadbd time: libcrypto 16.4%/19.9% of all samples (so about two thirds of mariadbd), kernel 5.5%, mariadbd itself 2.2%.

`strace -f -c` (whole init, default flags, drained, 94 s wall under strace; and `--skip-ssl`, 54 s): futex 41.7%/41.2% of syscall time (threads waiting on the CPU-bound thread), wait4 37.4%/35.3% (entrypoint waiting on children), `io_getevents` 6%/7%, `fdatasync` 1208 calls 0.30 s total. No disk-bound syscall pattern.

cgroup `cpu.stat` for the perf runs: warm run usage 4.4 s, drained run 40.7 s (same work, differing bucket state), see section 2.

## 6. u7s-specific suspects

| Suspect | Result |
|---|---|
| Startup/health probe connections | negligible: 7 connections total in a ready run, 3 cheap socket attempts per 10 s probe; the temp server has no network listener |
| CPU request/limit | manifest 250m/375m; cgroup `cpu.max 38000 100000`; throttled 78-110 s per run; removing the limit lifted pass rate from 1/3 to 2/3 and cut wall by 30-40% but did not make it reliable |
| SSL auto-generation in the temp server | yes, despite `--skip-ssl` (section 4); costs ~12-24 s extra on a drained e2-micro, ~1 s normally (temp gap on e2-medium 1.6 s) |
| Concurrent unpack | not separable from one WordPress run (section 3) |

## Not measured

- gdb stack samples (perf was usable); libssl3 debug symbols (inner libcrypto frames unnamed).
- Number of keys and key size MariaDB generates in the temp server.
- A drained e2-medium; e2-small.
- More than one WordPress-concurrent run; n is 2-6 per cell and burst-bucket state before each run is known only for runs preceded by the explicit drain.
- First-attempt `default1` in section 2 has no CPU/steal numbers (killed by the harness's wait loop that did not detect container exit; replaced by `ssl.sh`).

## Raw data

Raw archive, if still present: `/Users/balint.erdos/litehop/u7s/temp/e2e/w5xs5/` (`micro-ctlA`, `medium-ctlB`, `micro-prof`, `micro-prof2`, `micro-prof3`, `micro-ssl`, `u7s-mdb`, `u7s-wp`, `u7s-alt`, scripts `ctl.sh prof*.sh ssl.sh u7s.sh alt.sh direct*.sh kg.sh rep.sh`). The `direct*` and `kg.sh` outputs were deleted with the VM; their numbers are inline in section 4 and the keygen table.

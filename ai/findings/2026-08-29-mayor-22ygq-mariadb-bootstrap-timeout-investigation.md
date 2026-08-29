# MariaDB temp-server bootstrap timeout investigation

Bead: mayor-22ygq
Date: 2026-08-29
Shape: investigation, no code fix

## Verdict

Environmental (hypothesis a): the ~13-28s gap between MariaDB's InnoDB init
finishing and its server socket opening is caused by `lima-workload` being a
fully software-emulated (QEMU TCG) x86_64 VM on arm64 host hardware, not by
a u7s bug, a MariaDB config gap, or CoreDNS breakage — no dependency on
mayor-e78se or any other in-flight fix landing.

## Evidence

- `lima-workload` is `qemu`/`x86_64` (`limactl list`); host is `arm64`
  (Apple Silicon) — no HVF acceleration for cross-arch, unlike
  `lima-node-2..5` (`vz`/`aarch64`, native).
- The InnoDB-complete → socket-open gap reproduced consistently across four
  independent restarts, regardless of CPU quota or storage backend:
  - Restart @09:18 UTC (original 250m/375m limits, CSI-hostpath PVC):
    buffer pool load complete 09:18:18 → `Server socket created` 09:18:46
    (28s).
  - Restart @09:59 UTC (same limits, same PVC): 09:59:29 → 09:59:46 (17s).
  - Restart @10:05 UTC after patching CPU to 2000m/3000m (8x): 10:05:03 →
    10:05:16 (13s) — an 8x CPU bump did **not** close the gap, ruling out
    "CPU limit too tight" (hypothesis c).
  - Fresh init on a throwaway pod using `emptyDir` (no CSI, original
    250m/375m limits): entrypoint's "Waiting for server startup" loop
    started 10:07:35, temp server confirmed ready only at 10:07:59 (24s) —
    same order of magnitude as CSI-hostpath, ruling out CSI-driver-specific
    I/O overhead.
  - `getent hosts mariadb-0.mariadb...` resolved instantly (exit 0, no
    delay) — rules out DNS/CoreDNS (hypothesis b).
- The entrypoint's own detection loop is hardcoded and not configurable:
  `docker-entrypoint.sh`'s `docker_temp_server_start` caller runs
  `for i in {30..0}; do ...; sleep 1; done` — a fixed ~31s budget, no env
  var or manifest setting can extend it.
- Confirmed live (mayor-itt0e): once the race is lost, the entrypoint
  skips the bootstrap SQL on all subsequent restarts (non-empty data dir),
  so root's password never gets set; K8s probes (which use the intended
  password) fail forever — `2026-08-29 09:18:53 ... [Warning] Access
  denied for user 'root'@'localhost' (using password: YES)`, repeating on
  the liveness/readiness probe's 10s period.

## Root cause

MariaDB's own startup latency between InnoDB init completing and the
server becoming connectable is inflated by QEMU TCG's x86_64-on-arm64
instruction emulation to 13-28s, consistently consuming most or all of the
image's hardcoded ~31s temp-server-detection budget — independent of
cgroup CPU quota and storage backend. The outcome is a genuine race whose
result depends on host-level emulation load at that instant, which
explains the original bug's intermittent (not deterministic) crash loop.

## Recommendation

No u7s fix and no MariaDB manifest fix are possible — the entrypoint's
retry budget is hardcoded in the upstream image, not tunable. Do not use
QEMU-TCG cross-arch VMs (like `lima-workload`) to validate
temp-server-bootstrap workloads (the mysql/mariadb/postgres pattern);
prefer native-arch (`vz`/`aarch64`) VMs, matching `lima-node-2..5`. If
x86_64-under-QEMU testing continues, treat this crash-loop symptom as a
known, already-diagnosed environmental limitation, not a fresh bug.

## Follow-on beads

None for mayor-22ygq itself (closing as environmental, no fix). Filed
**mayor-m7fxk** (P1) for an unrelated bug hit while forcing pod restarts
during this investigation: kubelet's `system:node` identity lacks RBAC
`delete` on `pods` (`status_manager.go:1219`: "not allowed to delete
pods"), wedging terminated pods in `Terminating` forever until a
privileged client force-deletes them — distinct from mayor-u1g6k's
PVC/PV/VolumeAttachment scope, same seeded ClusterRole.

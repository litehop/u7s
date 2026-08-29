# MariaDB init: vz vs QEMU-TCG A/B test

Bead: mayor-1uc1r
Date: 2026-08-29
Shape: A/B verification, no code fix

## Verdict

Confirmed: mayor-22ygq's "environmental — QEMU-TCG x86_64-on-arm64 emulation
overhead" verdict holds. On a native vz-aarch64 VM (`lima-node-5`), the same
InnoDB-init-to-socket-open gap that took 13-28s under QEMU-TCG
(`lima-workload`) took **1-2s** — over 6x faster, well under the <5s
confirmation threshold this bead set out to test.

## Timing table

| Measurement | QEMU-TCG (mayor-22ygq) | vz (this test) |
|---|---|---|
| InnoDB buffer-pool-load-complete → Server socket created | 13-28s (4 runs: 28s, 17s, 13s, 24s) | **1-2s** (2 runs: 2s, 1s) |
| Pod restarts / crash loops | Permanent crash loop after first race loss | 0 restarts, both runs |
| Readiness | Never durably Ready (probe auth failed forever) | 1/1 Ready in both runs (~30-50s pod age, gated by `initialDelaySeconds: 30`) |
| `SELECT 1` via root creds | N/A (credentials never set) | Succeeds |

Phase-by-phase (vz, run 1): Scheduled 13:12:08 → image pull 13:12:08-13:12:14
(5.6s, 366MB `mariadb:11.8.6-noble` arm64) → container started 13:12:14 →
temp-server InnoDB init + bootstrap SQL 13:12:15-13:12:17 → permanent
mysqld InnoDB buffer-pool-load-complete 13:12:17 → socket open 13:12:19
(**2s gap**). Run 2 (fresh pod, fresh `emptyDir`, same StatefulSet):
buffer-pool-load-complete 13:13:30 → socket open 13:13:31 (**1s gap**).

## Confidence check

One unexpected environmental issue, unrelated to MariaDB or u7s: `lima-node-5`'s
kubelet had zero IPv4 connectivity to `host.lima.internal` (guest NIC had no
DHCPv4 lease, IPv6-only) — a stale condition present since its prior boot,
also reproduced on the idle sibling `lima-node-2`, so it's a Lima-fleet
network-race issue (documented in `lima-node-5/lima.yaml`'s own
first-boot-DHCP-race comment), not caused by this session. Fixed with a
plain `limactl stop`/`start` (not a reprovision) before any workload ran;
had no bearing on the timing measurements themselves, which only started
after the node registered `Ready` and both apiserver/kubelet were
confirmed reachable. No other anomalies: image pull was fast (arm64 variant
pulled automatically, no manifest changes needed), CPU/memory limits were
identical to Phase 2/QEMU-TCG (250m/375m, 256Mi/384Mi).

## Verdict-driven next step

Confirmed — no follow-on bead. mayor-22ygq's root cause and recommendation
stand: MariaDB's own temp-server-bootstrap timing is fine on native-arch
hardware; only QEMU-TCG cross-arch emulation (`lima-workload`) inflates it
past the entrypoint's hardcoded ~31s detection budget. Continue treating
QEMU-TCG cross-arch VMs as unsuitable for validating temp-server-bootstrap
workloads (mysql/mariadb/postgres pattern); prefer vz/aarch64 slots.

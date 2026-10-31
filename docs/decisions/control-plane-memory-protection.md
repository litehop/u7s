# Control-plane memory is protected with a systemd slice and kubelet reservations

**Status:** Accepted
**Date:** 2026-10-30

## Context

On a 1 GiB / 1 vCPU node with no swap, a workload (WordPress + MariaDB +
Traefik) makes the kernel reclaim file pages, including the mapped text of
the control-plane binaries, then re-read them: 64 M `workingset_refault_file`
and 270 GB of disk reads in 510 s. Upstream kubeadm, k3s and k0s reserve
nothing by default.

## Decision

- `apiserver`, `kcm`, `kubelet` and `crio` run in `u7s.slice`
  (`MemoryAccounting=yes`). Each unit sets `MemoryLow=`: 48, 96, 96, 80 MiB;
  the slice's `MemoryLow=` is their sum (320 MiB; 176 MiB on an agent, which
  runs kubelet and crio only). `crio.service` joins via a drop-in; the vendor
  unit is untouched.
- `MemoryLow`, not `MemoryMin`: it is best-effort, so an oversized value
  degrades to normal reclaim instead of OOM-killing everything unprotected.
- `kubelet-config.yaml`: `systemReserved.memory` 256 Mi (128 Mi on an agent),
  `kubeReserved.memory` 160 Mi, `enforceNodeAllocatable: [pods]`. System and
  kube cgroups are not enforced; a cap would starve the daemons. The
  eviction threshold stays kubelet's default `memory.available<100Mi`.

## Rationale

Idle cgroup `memory.current` (anon + page cache) on the 1 GiB Lima node:
apiserver 34 MiB, KCM 84, kubelet 73, crio 63; PSS 20/53/62/54. Lows are
that plus 15-45% headroom. `systemReserved` is apiserver + KCM (118) plus
OS share; `kubeReserved` is kubelet + crio (136) plus headroom.

The slice is required: the cgroup2 mount here lacks `memory_recursiveprot`,
and `system.slice` has no low, so a per-unit low under it is inert.

Same VM, fresh install, WordPress apply + 5 min idle: refaults 64.4 M ->
25.7 M, disk reads 270 -> 110 GB, memory PSI full 22 s -> 14 s, MemAvailable
minimum 187 -> 288 MiB. Allocatable memory is 431 MiB; `kubepods.slice`
is capped at 531 MiB.

## Consequences

- Thrash is reduced about 2.5x, not removed: unprotected kube-system pods and
  OS daemons still refault. Swap or smaller footprints remain the lever.
- Pods are capped in `kubepods.slice` and are OOM-killed there first, never
  the control plane.
- Allocatable shrinks by about 416 MiB on 1 GiB; requests above 431 MiB
  stay Pending.

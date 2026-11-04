# Burst cliff on 1 GiB / 1 vCPU (Lima arm64)

Bead: mayor-kutwm
Date: 2026-11-04
Base: main 2b8dc2ab

**Answer: not yet measured (experiment 1 in progress).**

## Method

- Lima `u7s-vps-1g.yaml` (1 vCPU, 1 GiB, no swap), arm64 tarball from main 2b8dc2ab,
  `burst-gate.sh --backend lima --ramp ... --keep`.
- Host-side streams (limactl shell into host files) so evidence survives a dead node.

## Results

(pending)

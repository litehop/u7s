# Idle memory attribution on a 1 GiB / 1 vCPU node

Bead: mayor-hjwdo.1
Date: 2026-11-20
Base: main 1d100b63

**Answer: (in progress)**

## Method

- Gate-shape VM: `scripts/release-gate/u7s-vps-1g.yaml` (1 vCPU, 1 GiB, bare Ubuntu 26.04 arm64
  cloud image), `vm_trim` applied, zero-argument `install.sh` from an arm64 tarball built from
  this checkout (`build-arm64-tarball.sh`), then the gate's WordPress + MariaDB (emptyDir) and the
  1-replica warm-up pause Deployment. This is what `burst-gate.sh --backend lima` builds.
- `run-all.sh --stack-only` was NOT used for the measurement: it runs the apiserver, scheduler
  and konnectivity-server on the Mac host, so the dominant u7s processes would not be in the
  guest.
- (to be filled)

## Results

(to be filled)

## Reclaimable items

(to be filled)

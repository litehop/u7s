# Changelog

User-visible changes to u7s releases. Pre-releases (snapshots) are not listed
individually; their changes land in the next release's section.

## [Unreleased]

### Fixed

- An unreadable or non-numeric NIC MTU now fails the pod-MTU derivation with a
  clear error instead of a bash arithmetic error.

## [0.4.6] - 2026-11-18

### Added

- Pod MTU is now derived from the NIC MTU minus the Geneve overhead of the
  bundled beep load balancer (74 bytes on an IPv4 underlay, 94 on IPv6 or
  dual-stack; 1460 gives 1386, 1500 gives 1426). Without this, full-size pod
  packets through the load balancer depended on IP fragmentation.
  `--pod-mtu <N>` or `U7S_POD_MTU` overrides it (minimum 1280, not above the
  NIC MTU; refused with `--join`). An explicit value is saved and reused on
  later `install.sh` re-runs. The MTU is cluster-wide: a worker with a smaller
  NIC than the control plane needs the control plane installed with a fitting
  `--pod-mtu`. Changing it on an existing install takes effect only after
  restarting flannel (`kubectl -n kube-flannel delete pod -l app=flannel`),
  and then only for pods created afterwards. (#2177)

### Changed

- flannel images are pulled from docker.io (pinned by digest) instead of
  ghcr.io, so IPv6-only nodes can pull them. (#2177)
- `install.sh` downloads now share one overall deadline. Slow links that keep
  making progress are no longer aborted, and a dead mirror fails in about 90 s
  instead of about 210 s. (#2175)

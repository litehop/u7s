# Changelog

User-visible changes to u7s releases. Pre-releases (snapshots) are not listed
individually; their changes land in the next release's section.

## [Unreleased]

### Changed

- **Breaking:** node names longer than 63 characters, accepted by
  v0.4.5 through v0.4.7, are no longer supported, matching upstream's
  hostname-label limit. `install.sh` refuses them and such Nodes fail
  apiserver label validation. Re-join affected nodes with a `--node-name` of
  63 characters or fewer before upgrading.

## [0.4.7] - 2026-11-18

### Changed

- The apiserver records the store's on-disk format and refuses to start on a
  store written by a newer u7s. Downgrades are not supported. (#2182)

### Fixed

- StatefulSet pods were deleted and recreated every ~30 s (`collisionCount`
  climbing without bound) when the pod template contained `<`, `>` or `&`,
  for example a shell command with a redirect. ControllerRevisions are now
  served with the same JSON escaping the controllers compare against.
  `kubectl api-resources` and `kubectl get controllerrevisions` now list
  `controllerrevisions`, which were previously reported as not served.
  (#2184)

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

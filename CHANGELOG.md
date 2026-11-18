# Changelog

User-visible changes to u7s releases. Pre-releases (snapshots) are not listed
individually; their changes land in the next release's section.

## [Unreleased]

### Added

- Pod MTU is now derived from the node's NIC MTU minus the Geneve overhead of
  the bundled beep load balancer (74 bytes for an IPv4 underlay, 94 for IPv6
  or dual-stack), and a flag overrides it. Without this, full-size pod packets
  through the load balancer depended on IP fragmentation.

### Changed

- flannel images are pulled from docker.io, pinned by digest, so IPv6-only
  nodes can pull them.
- `install.sh` downloads now share one overall deadline. Slow links that keep
  making progress are no longer aborted, and a dead mirror fails in about 90 s
  instead of about 210 s. (#2175)

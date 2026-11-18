# Shipped container images come from registries with AAAA records, pinned by digest

**Status:** Accepted
**Date:** 2026-11-18

Extends [distribution-hosting-shape.md](distribution-hosting-shape.md), which
solved IPv6-only reachability for `install.sh` and the tarball but not for
container images. That ADR stays as written.

## Context

`ghcr.io` has no AAAA record (`dig`, 2026-11-17). Flannel was the one shipped
image served from it, so an IPv6-only node without NAT64 could not pull flannel
and never got pod networking. `docker.io` (registry-1.docker.io) and
`registry.k8s.io` both resolve over IPv6.

## Decision

- Every image in `manifests/*.yaml` comes from a registry with AAAA records.
- Flannel is pulled from `docker.io/flannel/flannel` and
  `docker.io/flannel/flannel-cni-plugin` (the project's Docker-sponsored
  mirror), pinned by index digest like `beep-lb`. Version stays v0.28.9.

## Rationale

The Docker Hub and ghcr per-arch manifests for v0.28.9 differ (amd64 config
`c7a75e0c...` vs `1644118e...`, different layers beyond the base): they are
separate builds of the same release, so the digests were verified against the
Docker Hub copy itself, not carried over. Anonymous Docker Hub pulls are
limited to 100 per hour per IPv4 address (per /64 for IPv6); a node pulls
about four manifest GETs for flannel, so one NAT address supports roughly twenty
fresh node installs per hour.

## Consequences

- IPv6-only nodes get flannel without a proxy; `ghcr.io` is no longer a
  prerequisite.
- Docker Hub tags are inconsistent (`0.28.9` has no `v`, `v0.28.10` does);
  bumps are deliberate and re-verify the digest.
- Many nodes or CI jobs behind one NAT address can hit the anonymous limit;
  mirror the images if that happens.

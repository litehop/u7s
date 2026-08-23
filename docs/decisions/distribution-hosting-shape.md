# Distribution hosting: self-hosted reverse-proxy, not a GitHub-fronted redirect

**Status:** Accepted
**Date:** 2026-08-23

## Context

The release tarball already ships as a GitHub Release artifact (interim, settled
separately). What remained open was how an admin invokes the install flow, and
whether that works on IPv6-only nodes — a real production constraint, not a
hypothetical: `dig` confirms `github.com` and `ghcr.io` have no AAAA record; only
`raw.githubusercontent.com` does. k3s/k0s both solve the "friendly install URL"
problem with a domain that redirects to GitHub Releases, because neither project
runs its own infrastructure. That constraint does not apply here — a dual-stack
Kubernetes cluster and domain are available.

## Decision

Serve the install script and release tarball through a small reverse-proxy
Deployment on that cluster, exposed via a dual-stack Service/Ingress. The proxy
fetches from GitHub Releases server-side and streams the bytes to the client —
it does not redirect. Caching or mirroring (object storage, a CDN) is deferred
until network cost or GitHub outages actually justify the added complexity.

## Rationale

A redirecting front door does not fix IPv6 reachability: the client still opens
a fresh connection to wherever it's redirected, and that target's IPv6 support
is exactly as unverified as `github.com`'s own. Streaming through a
self-controlled proxy removes GitHub reachability from the client's dependency
chain entirely — the client only ever talks to infrastructure whose dual-stack
support is known, not assumed. This is a judgment call enabled by having
controllable infrastructure at all, which is the one input k3s/k0s's designs
don't have and u7s does.

## Consequences

- Install-time IPv6 reachability no longer depends on GitHub's own IPv6 rollout
  status, confirmed or not.
- A small piece of real infrastructure (proxy Deployment + dual-stack
  Service/Ingress) now needs to be built and kept running — more than a static
  file, still well within a small project's means.
- Caching/mirroring is out of scope for the initial build; this ADR governs the
  live-proxy shape only, revisit once traffic data exists.
- Client-side checksum verification (independent of hosting choice) is still
  needed and is tracked separately.

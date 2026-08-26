# Install script UX: zero-argument default, three configurable knobs

**Status:** Accepted  
**Date:** 2026-08-21

## Context

u7s needs a first-run install experience for a new node. The north star
already settles the philosophy — default everything, keep the configurable
surface small — motivated by k3s's and k0s's large, under-documented,
drift-prone YAML surfaces, and it names node identity and networking as the
only settings that legitimately stay configurable. What stayed open was the
concrete shape of the script's own interface.

## Decision

The install script is invoked as a single `curl | bash`-style command
(`curl -sfL <install-script-url> | bash`). With zero arguments it bootstraps
a single-node cluster: node name defaults to the hostname, and the cluster
network interface defaults to the first non-loopback interface.

Node identity, interface selection, and manifest output location are the
**only** three knobs beyond that default path — a `--node-name` and an
`--iface` flag, each with an env-var equivalent, for cases where cluster
traffic must route over something like a WireGuard mesh, and a
`--manifest-output-dir` / `U7S_MANIFEST_OUTPUT_DIR` flag for redirecting
vendored manifests away from the well-known auto-applied folder (see
`docs/decisions/well-known-manifest-folder.md`). A version-pin flag (default:
latest stable) exists but is not part of the zero-argument path. No other
configuration surface exists.

## Rationale

No measurement decided this; it applies the north star's packaging
philosophy. The `curl | bash` shape reuses a convention users already recognize
from k3s — the north star's objection to k3s is its configuration surface and
defaults, not its invocation shape. Restricting the knobs to node identity
and interface is that philosophy applied directly rather than a fresh
judgment call.

The third knob, `--manifest-output-dir`, is a narrower case decided
separately in `docs/decisions/well-known-manifest-folder.md`: the apiserver
auto-applies whatever lands in the well-known `/etc/u7s/manifests` folder, so
an installer-level override is how an operator opts into GitOps management
instead — an explicit escape hatch for that folder, not a config surface
added for its own sake.

## Consequences

- Join mode (first node's address plus a shared token) is an additive surface
  on the multi-node path only, never part of the zero-argument install.
- Any further configuration need must justify itself against the
  default-everything baseline.
- The install-script domain and release-artifact hosting are not decided
  here; both remain open.

# Install script UX: zero-argument default, two configurable knobs

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

Node identity and interface selection are the **only** two knobs beyond that
default path — a `--node-name` and an `--iface` flag, each with an env-var
equivalent, for cases where cluster traffic must route over something like a
WireGuard mesh. A version-pin flag (default: latest stable) exists but is not
part of the zero-argument path. No other configuration surface exists.

## Rationale

No measurement decided this; it applies the north star's packaging
philosophy. The `curl | sh` shape reuses a convention users already recognize
from k3s — the north star's objection to k3s is its configuration surface and
defaults, not its invocation shape. Restricting the knobs to node identity
and interface is that philosophy applied directly rather than a fresh
judgment call.

## Consequences

- Join mode (first node's address plus a shared token) is an additive surface
  on the multi-node path only, never part of the zero-argument install.
- Any further configuration need must justify itself against the
  default-everything baseline.
- The install-script domain and release-artifact hosting are not decided
  here; both remain open.

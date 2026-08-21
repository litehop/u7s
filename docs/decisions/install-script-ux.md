# Install script UX: zero-argument default, two configurable knobs

**Status:** Accepted  
**Date:** 2026-08-21

## Context

u7s needs a first-run installation experience for a new cluster node. The
project's north star already settles the general packaging philosophy
(default everything, keep the configurable surface deliberately small),
motivated by direct negative experience with both k3s and k0s: both expose
large, under-documented, drift-prone YAML configuration surfaces, and node
identity plus networking are the only settings the north star names as
legitimately needing to stay configurable. What remained open was the
concrete shape of the install script's own user-facing interface — this ADR
settles that shape, not the underlying philosophy.

## Decision

The install script is invoked as a single `curl | sh`-style command, matching
the ecosystem-standard shape (e.g. `curl -sfL <install-script-url> | sh -`).
With zero arguments, it bootstraps a new single-node cluster: node name
defaults to the host's hostname, and the network interface used for cluster
traffic defaults to the first non-loopback interface. Node identity and
network interface selection are the **only** two knobs the install script
exposes beyond that default path (e.g. a `--node-name`/env-var pair and an
`--iface`/env-var pair for the case where cluster traffic needs to route over
something like a WireGuard mesh instead). A version-pin option (defaulting to
latest stable) is also available as a flag, but is not part of the
zero-argument default path. No other configuration surface exists in the
install script itself.

## Rationale

Matching k3s's own `curl | sh` invocation shape, rather than inventing new
syntax, uses a working ecosystem convention users already recognize: the
north star's negative comparison with k3s targets the resulting
*configuration surface and defaults*, not this UX shape itself, so there is
no reason to diverge here just to be different. Restricting the configurable
surface to exactly node identity and network interface is a direct
application of the already-settled packaging philosophy rather than a new
judgment call — any additional knob, however small it looks in isolation, is
exactly the kind of creeping configuration surface that philosophy exists to
prevent.

## Consequences

- A join-mode variant (first node's address plus a shared join token) is a
  separate, additive input surface that exists only on the multi-node join
  path, never as part of the zero-argument install.
- Any future configuration need beyond node identity and network interface
  must justify itself against this default-everything baseline rather than
  being added ad hoc.
- The literal install-script hostname/domain and the release-artifact
  hosting mechanism are not decided by this ADR; they are tracked
  separately as still open.

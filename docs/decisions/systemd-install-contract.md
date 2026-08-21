# Fresh-node install contract: systemd units per host binary, Ubuntu-only

**Status:** Accepted  
**Date:** 2026-08-21

## Context

Once binaries are on a fresh node, something must keep them running across
reboots and crashes without a human intervening. u7s's Lima dev/conformance
environment runs bare backgrounded shell processes, which suits ephemeral
single-session VMs but is not a model for a VPS or bare-metal deployment.

## Decision

Each host-level binary gets its own systemd unit, written and enabled by the
u7s install script: `u7s-apiserver.service` (absorbing the scheduler if the
two native binaries are ever merged, otherwise a separate
`u7s-scheduler.service`), `u7s-kcm.service`, and `kubelet.service`. Every
u7s-authored unit sets `Restart=always` and is enabled at boot.
`crio.service` comes from the CRI-O apt package, not from u7s.

If systemd is absent the install fails loudly rather than falling back to an
unsupervised process. Initial scope is Ubuntu LTS, which always ships
systemd, so no OpenRC path is designed yet.

kube-proxy, CoreDNS, and metrics-server get no systemd unit — they are
in-cluster pods, scheduled by kubelet once the control plane is reachable,
and rely on DaemonSet rolling-update and kubelet-restart mechanics.

## Rationale

No measurement decided this; it applies the packaging philosophy's
default-everything principle. A real deployment target needs boot-time start
and restart-on-crash, and systemd provides both on Ubuntu at zero engineering
cost. A bespoke supervisor was rejected because it is itself a new component
to build and maintain — the opposite of defaulting to what the host provides.

The same reasoning puts kube-proxy and CoreDNS on DaemonSets: the control
plane already needs kubelet-plus-DaemonSet for in-cluster workloads, so
reusing it avoids maintaining a second, host-level supervision path.

Failing loud on a systemd-less host keeps the contract honest instead of
producing a fragile install on an unsupported target.

## Consequences

- Alpine/OpenRC and other non-systemd targets are unsupported until demand
  exists.
- In-cluster component liveness stays entirely within the existing manifest
  and DaemonSet mechanism; no new host-level tooling.

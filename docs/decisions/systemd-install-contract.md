# Fresh-node install contract: systemd units per host binary, Ubuntu-only

**Status:** Accepted  
**Date:** 2026-08-21

## Context

Once binaries are on a fresh node, something has to actually run them
persistently: survive reboots and restart automatically after a crash,
without a human noticing and intervening. u7s's own Lima-based dev/
conformance environment runs its processes as bare backgrounded shell
processes, which is correct for that context (ephemeral, single-session VMs
where the dev workflow re-runs the start script every session) but is not an
adequate model for a real deployment target such as a VPS or bare-metal box.

## Decision

Each host-level u7s/upstream binary gets its own systemd unit:
`u7s-apiserver.service` (absorbing the scheduler as an in-process task if the
two native binaries are ever merged into one, otherwise a separate
`u7s-scheduler.service`), `u7s-kcm.service`, and `kubelet.service`, all
written and enabled by the u7s install script. `crio.service` is installed
and enabled by the CRI-O apt package itself, not authored by u7s's install
script. Every u7s-authored unit uses `Restart=always` and is enabled for
boot-time start. If systemd is not present, the install fails loudly rather
than silently falling back to an unsupervised bare process. Initial release
scope targets Ubuntu LTS only, which always ships systemd, so no
non-systemd (e.g. OpenRC) supervisor path is designed for yet.

kube-proxy, CoreDNS, and metrics-server (if applied at all) get no systemd
unit: they are in-cluster pods, scheduled by kubelet once the control plane
is reachable, and rely on standard DaemonSet rolling-update/kubelet-restart
mechanics for their own liveness rather than host-level process supervision.

## Rationale

A real deployment target needs both boot-time start and restart-on-crash;
systemd already provides both correctly on Ubuntu at zero additional
engineering cost. A bespoke custom process supervisor was explicitly
rejected: it would reinvent what systemd already does, adds a new component
u7s would have to build and maintain indefinitely, and directly contradicts
the packaging philosophy's preference for an opinionated default over a new
knob — a custom supervisor is itself a new component, not a default use of
something the host already provides. Failing loud when systemd is absent,
rather than degrading to a bare process, keeps this contract honest rather
than silently producing a fragile install on an unsupported host. The same
"let the platform already provide this" reasoning is why kube-proxy and
CoreDNS are DaemonSets rather than systemd units: the control plane already
needs the kubelet-plus-DaemonSet mechanism for in-cluster workloads
generally, so reusing it for these components avoids a second, host-level
restart/supervision mechanism that would otherwise have to be built and kept
correct in parallel.

## Consequences

- Non-Ubuntu, non-systemd targets (Alpine/OpenRC, etc.) are unsupported
  until there is real demand, not designed around speculatively.
- A crash in any u7s-authored host binary restarts automatically via
  systemd, with no custom supervisor logic to maintain or debug.
- kube-proxy, CoreDNS, and metrics-server liveness is governed entirely by
  the existing in-cluster manifest-and-DaemonSet mechanism, not by any new
  host-level tooling.

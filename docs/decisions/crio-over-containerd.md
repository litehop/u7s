# CRI-O + crun as the container runtime

**Status:** Accepted  
**Date:** 2026-05-18

## Context

u7s data plane nodes need a CRI-compatible container runtime. The `ContainerRuntime` trait in the node agent abstracts over the choice.

## Decision

Target CRI-O + crun as the primary runtime. containerd remains a supported alternative (socket path is the only code difference).

## Rationale

containerd spawns a persistent `containerd-shim-runc-v2` process per pod sandbox. This process lives for the pod's lifetime and consumes 5–10 MB RSS. On a node running 20 pods that is 100–200 MB of additional overhead — invisible in idle benchmarks but material in practice. RSS grows linearly with pod count.

CRI-O does not use persistent shim processes. It execs `crun` directly; the runtime process exits after container start. RSS is flat with pod count. `crun` is written in C with no Go runtime overhead and starts containers faster than `runc`.

The integration code is identical: same CRI gRPC protocol, same `tonic` stubs, same `ContainerRuntime` trait implementation. The socket path (`/run/crio/crio.sock` vs `/run/containerd/containerd.sock`) is the only difference.

## Consequences

- CRI-O must be installed on data plane nodes (available in standard Linux package repos).
- The `ContainerRuntime` trait makes switching to containerd a one-line config change if a registry compatibility issue arises.
- Direct OCI (no daemon) remains an option if node RSS budget proves critical; see `container-runtime.md` §3.3.

# Custom bin-spread scheduler with kube-scheduler escape hatch

**Status:** Accepted  
**Date:** 2026-05-18

## Context

u7s needs a pod scheduler. The options are a custom Rust implementation or delegating to the upstream `kube-scheduler` binary.

## Decision

Implement a custom bin-spread scheduler in ~200 lines of Rust. Document and preserve a clean escape hatch to upstream `kube-scheduler`.

## Rationale

The scheduling requirements for the target workload are simple: place pods on nodes that have capacity, respect `nodeSelector` and taints. The upstream `kube-scheduler` brings the full scheduling framework (plugins, priorities, preemption, topology spread) at the cost of a Go binary dependency (~30–50 MB RSS) and operational complexity.

A custom implementation covers the needed surface in ~200 lines:
- **Filter:** NodeReady, ResourceFit, NodeSelector, TaintToleration
- **Score:** LeastAllocated — `(remaining_cpu_fraction + remaining_memory_fraction) / 2`

**Bin-spread over bin-pack:** LeastAllocated distributes load across nodes. For a small cluster this reduces blast radius from a single node failure. Bin-packing concentrates risk with no benefit at this scale.

**`kube` crate (client-side):** Used for the scheduler's API client. Handles 410 Gone watch reconnect and relist correctly out of the box. No server-side overhead.

## Escape hatch

Upstream `kube-scheduler` is available from Phase 3 onward: point it at the u7s API server, set `spec.schedulerName: default-scheduler` on pods, disable the built-in scheduler. Requires only a working watch endpoint plus `coordination.k8s.io/v1` Lease objects for leader election.

Trigger: operator needs pod affinity/anti-affinity, topology spread, or preemption.

## Key implementation risk

Pod allocation accounting on MODIFIED and terminal-state events. A `pod_allocations: HashMap<PodUID, (NodeName, Resources)>` side-map is required to correctly subtract allocations when a pod transitions to Succeeded/Failed or is deleted. Missing this causes nodes to appear more full than they are.

## Consequences

- No support for pod affinity, anti-affinity, topology spread, or preemption in the built-in scheduler.
- Escape hatch to `kube-scheduler` is cheap: watch endpoint is the only prerequisite.

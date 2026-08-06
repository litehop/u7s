# Container Runtime Interface — Trade-off Analysis and Integration Spec

**Status:** RFC-grade implementation prompt. Last updated: 2026-05-18.
**Scope:** Data plane nodes only. Control plane node does not run a container runtime.

---

## 1. Decision Summary

**Recommendation: CRI-O + crun.**

CRI-O is purpose-built for CRI with no bundled extras (no snapshotter plugin system, no image build support, no containerd-shim model). The decisive practical factor: containerd spawns a `containerd-shim-runc-v2` process per pod sandbox that persists for the pod's lifetime. On a node running 20 pods that is 20 additional processes, each consuming 5–10 MB RSS — 100–200 MB of overhead that accumulates invisibly and is absent from idle benchmarks. CRI-O does not use persistent shims: it execs `crun` directly and the runtime process exits after container start. This makes CRI-O's RSS profile flat with pod count, not linear.

`crun` (written in C, not Go) adds no Go runtime overhead and starts containers faster than `runc`. The combination of CRI-O + crun is the default in OpenShift/OKD and is well-tested in production.

Whatever CRI-compliant runtime is chosen, the client speaking to it is unaffected — only the socket path differs (`/run/crio/crio.sock` vs. `/run/containerd/containerd.sock`). In practice the client is the real upstream kubelet (see §5), not u7s code, so swapping runtimes is a kubelet config change, not a code change.

**What would cause this recommendation to change:**
- A specific image format or registry authentication edge case proves incompatible with CRI-O (rare, but CRI-O has less ecosystem testing than containerd for exotic registries).
- The target deployment environment ships containerd by default and installing CRI-O is operationally impractical.

---

## 2. CRI Protocol Overview

The Container Runtime Interface (CRI) is a gRPC protocol defined in the `k8s.io/cri-api` repository. It consists of two gRPC services:

- **RuntimeService** — sandbox and container lifecycle
- **ImageService** — image pull, list, remove

The proto definitions live at:
`https://github.com/kubernetes/cri-api/blob/main/pkg/apis/runtime/v1/api.proto`

### Key RPCs

**RuntimeService:**

| RPC | Purpose |
|---|---|
| `RunPodSandbox(PodSandboxConfig) → RunPodSandboxResponse` | Creates the sandbox (network namespace, pause container) |
| `StopPodSandbox(sandbox_id)` | Signals sandbox shutdown; containers inside are stopped |
| `RemovePodSandbox(sandbox_id)` | Destroys sandbox and all containers within it |
| `CreateContainer(sandbox_id, ContainerConfig, PodSandboxConfig) → CreateContainerResponse` | Creates a container inside an existing sandbox |
| `StartContainer(container_id)` | Starts a created container |
| `StopContainer(container_id, timeout)` | Sends SIGTERM then SIGKILL after timeout |
| `RemoveContainer(container_id)` | Destroys a stopped container |
| `ListContainers(ContainerFilter) → ListContainersResponse` | Lists containers matching a filter |
| `ContainerStatus(container_id, verbose) → ContainerStatusResponse` | State, exit code, start/finish times, log path |
| `ExecSync(container_id, cmd, timeout) → ExecSyncResponse` | Run a command and capture output |

**ImageService:**

| RPC | Purpose |
|---|---|
| `PullImage(ImageSpec, auth, sandbox_config) → PullImageResponse` | Pulls an image to local storage |
| `ListImages(ImageFilter) → ListImagesResponse` | Lists locally available images |
| `RemoveImage(ImageSpec)` | Removes an image |

### Pod Lifecycle — CRI Call Sequence

A Kubernetes Pod maps to one sandbox plus N containers:

```
PullImage(image)              ← for each container image not already present
RunPodSandbox(sandbox_config) → sandbox_id
  CreateContainer(sandbox_id, container_config_1) → container_id_1
  StartContainer(container_id_1)
  CreateContainer(sandbox_id, container_config_2) → container_id_2
  StartContainer(container_id_2)
  ...
```

Teardown:
```
StopContainer(container_id_1, grace_period)
RemoveContainer(container_id_1)
StopPodSandbox(sandbox_id)
RemovePodSandbox(sandbox_id)
```

The sandbox isolates the network namespace. All containers in a pod share the sandbox's network namespace. CNI is called on the sandbox's netns, not on individual containers.

### CRI API Version

As of Kubernetes 1.26+, v1 CRI API (`runtime.v1`) is the stable interface. The older `runtime.v1alpha2` is removed. Use `runtime.v1` exclusively.

---

## 3. Candidate Runtimes

### 3.1 containerd

**Socket:** `/run/containerd/containerd.sock`

**Idle RSS:** In practice, containerd idles at approximately 30–50 MB RSS on a minimal Linux system (no workloads running). Numbers vary by configuration:
- Fresh installation with no plugins loaded: ~25–35 MB.
- With the default CRI plugin, snapshotter, and metrics endpoint active: ~40–55 MB.
- Published k3s teardown benchmarks (2023) show containerd at ~35 MB idle on their minimal node image.

These figures come from community benchmarks and k3s/RKE2 operator reports. No official containerd documentation publishes idle RSS targets.

**Architecture:**
- Single daemon binary (`containerd`) with pluggable snapshotters (overlayfs default on Linux)
- CRI plugin is built-in since containerd 1.1; no separate shim for basic use
- Image storage under `/var/lib/containerd`; layer deduplication across containers is handled by the snapshotter

**Rust gRPC integration:**
- `tonic` crate for gRPC transport
- `prost` for protobuf codegen
- CRI proto files compiled via `tonic-build` in `build.rs`
- Socket connection via `tonic`'s UDS transport endpoint

**Pros:**
- Most widely deployed CRI runtime; extremely well-tested image and runtime compatibility
- Overlayfs snapshotter handles layer deduplication correctly across all standard images
- Multi-arch image support (OCI image index / manifest list) is built-in
- Registry auth via `~/.config/containerd/config.toml` or per-pull `AuthConfig`
- Active maintenance; CRI API conformance tests pass against it

**Cons:**
- Daemon adds 35–50 MB to every data plane node's RSS baseline
- An additional process to monitor, configure, and upgrade

---

### 3.2 CRI-O

**Socket:** `/run/crio/crio.sock`

**Idle RSS:** CRI-O idles at approximately 20–35 MB RSS. Being purpose-built for CRI with no bundled image-build or snapshotter plugin system, it runs leaner. Community measurements from OpenShift/OKD deployments suggest 15–25 MB lighter than containerd in comparable configurations, though this gap narrows on small nodes where both are dominated by the same kernel subsystems.

**Architecture:**
- Implements only the CRI gRPC service; delegates to OCI runtimes (`runc`, `crun`) directly
- Uses the containers/storage library for image layer management (overlayfs)
- No containerd-style plugin model; simpler configuration surface

**CRI protocol:** Identical to containerd path; only the socket path differs. Whichever CRI client is on the other end (kubelet, in u7s's actual arrangement — see §5) needs no code change to target CRI-O instead of containerd.

**Pros:**
- Purpose-built for CRI: fewer moving parts, no image-build subsystem
- Slightly lower idle RSS than containerd
- Red Hat-backed; well-maintained for OpenShift use cases

**Cons:**
- Less common in edge/embedded deployments than containerd
- Smaller community; fewer third-party integrations
- Some image registries or authentication edge cases are better tested against containerd
- `crun` (the Go-free OCI runtime CRI-O prefers) adds a dependency

---

### 3.3 Direct OCI (No CRI Daemon)

The node agent manages the full container lifecycle without an intermediary daemon:

1. **Image pull:** HTTP client (`reqwest`) against OCI Distribution Spec v1 endpoints. Must handle: registry authentication (Bearer token exchange), multi-arch manifest lists (OCI image index), layer streaming and decompression (gzip/zstd tar), layer deduplication across containers on the same node.
2. **Layer unpacking:** Write layers to disk (e.g., under `/var/lib/u7s/layers/<digest>`), construct overlayfs mounts with lower dirs = layer chain, upper dir = container-writable layer.
3. **OCI bundle prep:** Generate `config.json` from the pod container spec using the `oci-spec` crate (`oci-spec = "0.6"`).
4. **Runtime exec:** `std::process::Command` to exec `runc` or `crun` with the bundle path. Process supervision: the node agent must track PIDs and reap zombies or use a subreaper.

**Memory savings:** No daemon process. The ~35–50 MB containerd RSS is reclaimed. The node agent itself uses that headroom instead.

**Rust ecosystem:**
- `oci-spec` crate: OCI image and runtime spec types, bundle generation
- `reqwest` + `serde_json`: registry API calls and manifest parsing
- Direct `overlayfs` mount via `nix::mount::mount` (requires `CAP_SYS_ADMIN`)
- `runc`/`crun` exec via `std::process::Command`

**Cons (significant):**
- Registry auth is non-trivial: Bearer token exchange, credential helpers, private registries
- Multi-arch manifest handling requires parsing OCI image index and selecting the correct platform manifest
- Layer deduplication across containers on the same node requires a content-addressed layer store with reference counting
- Zombie reaping and PID namespace management with no intermediate subreaper
- No existing conformance test suite for this implementation path; CRI conformance tests cannot be run against it
- Estimated implementation effort: 4–8x the CRI gRPC path

**When this wins:** Node RSS budget is so tight that 35 MB for containerd is genuinely unacceptable — i.e., the target node has less than ~150 MB total RAM for workloads + agent + runtime. On a 1 GB VPS, this is not the current constraint.

---

## 4. Head-to-Head Comparison Table

| Criterion | containerd | CRI-O | Direct OCI |
|---|---|---|---|
| **Idle RSS on node (daemon)** | ~35–50 MB | ~20–35 MB | 0 MB (no daemon) |
| **Implementation complexity for u7s node agent** | Low: generate CRI stubs, implement trait | Low: identical to containerd path | High: image pull, layer store, overlayfs, exec model |
| **Image pull support** | Full (multi-arch, OCI, Docker V2, private registries) | Full (same underlying library) | Must implement from scratch |
| **OCI compliance** | Full; passes OCI runtime conformance | Full; passes OCI runtime conformance | Implementation-defined; no conformance testing |
| **Rust ecosystem for integration** | tonic + prost + generated stubs; mature | Same as containerd path | oci-spec crate + reqwest; less proven end-to-end |
| **Operational maturity** | Production grade; used by k3s, RKE2, EKS, GKE | Production grade; used by OpenShift | u7s-specific; no external validation |
| **Node agent lines of code** | ~300–500 for CRI integration | ~300–500 (same) | ~2000–4000 (image store + bundle + exec) |
| **CRI conformance tests** | Pass (containerd passes upstream CRI conformance) | Pass | Not applicable |

---

## 5. Actual Integration: Vendored kubelet + CRI-O

Sections 5–9 of this document originally specified a u7s-authored Rust node agent
(`ContainerRuntime` trait, `tonic`/`prost` CRI gRPC stubs, a phased Phase 1/2 delivery
plan) that was **never built**. There is no node-agent crate in the workspace
(`Cargo.toml`'s `[workspace] members` lists only `store`, `apiserver`, `scheduler`,
`mcp-server`, `controller-manager`, `kubeconfig`, `sentinel`, `sentinel-derive`), and no
`ContainerRuntime` trait or CRI client code anywhere in `crates/`.

The actual arrangement: u7s runs the real upstream **kubelet** binary directly, unmodified,
against the u7s API server. Kubelet already speaks CRI to CRI-O itself, so u7s does not
need to reimplement any of the CRI gRPC lifecycle (`RunPodSandbox`, `CreateContainer`,
image pull, log paths, resource-limit mapping) described in the old §5–9 — that logic
lives in kubelet and CRI-O, both of which are mature, already-shipped binaries. Kubelet,
CRI-O, and kube-proxy all run as systemd units on the data plane node (see
`scripts/conformance/06-run-sonobuoy.sh` and `scripts/conformance/add-node.sh` for the
Lima VM provisioning and log-collection arrangement); `roadmap.md`'s "Phase 2 —
Controller manager + kubelet hardening" entry documents this as the shipped decision.

The CRI-O vs. containerd vs. direct-OCI trade-off analysis in §§1–4 above remains valid
input to that decision (CRI-O is what kubelet is configured to talk to) — only the
delivery mechanism changed: no Rust node agent was built or is needed.

# Container Runtime Interface — Trade-off Analysis and Integration Spec

**Status:** RFC-grade implementation prompt. Last updated: 2026-05-18.
**Scope:** Data plane nodes only. Control plane node does not run a container runtime.

---

## 1. Decision Summary

**Recommendation: containerd via CRI gRPC.**

containerd is battle-tested, has the widest image compatibility, and is implemented by the same CRI gRPC protocol that upstream Kubernetes uses. The node agent's integration cost is bounded: generate Rust gRPC stubs from the CRI proto files, implement the `ContainerRuntime` trait, done. Direct OCI is substantially more implementation surface for a saving of ~35 MB RSS per node — a worthwhile trade only if node RSS proves to be the active constraint.

**What would cause this recommendation to change:**
- Node RSS budget collapses to the point where 35–50 MB for containerd is genuinely unacceptable (i.e., workload containers plus node agent plus containerd exceed available memory on the target node class).
- A benchmark shows that containerd's gRPC overhead introduces unacceptable pod-start latency on 1-shared-vCPU nodes.
- CRI-O's resource numbers are validated lower than containerd's by more than ~10 MB idle; at that point CRI-O is a drop-in (same gRPC protocol, no agent code changes).

The `ContainerRuntime` trait defined in §6 makes the swap cheap regardless.

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

**CRI protocol:** Identical to containerd path. The `ContainerRuntime` trait implementation is byte-for-byte the same; only the socket path differs.

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

## 5. Integration Design — containerd via CRI gRPC

### 5.1 Rust Crate Selection

```toml
# Cargo.toml [dependencies]
tonic = { version = "0.12", features = ["transport"] }
prost = "0.13"
tokio = { version = "1", features = ["full"] }

# Cargo.toml [build-dependencies]
tonic-build = "0.12"
```

### 5.2 Proto Code Generation

In `build.rs` at the node agent crate root:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CRI proto files vendored under cri-api/
    // Clone: https://github.com/kubernetes/cri-api
    // File: pkg/apis/runtime/v1/api.proto
    tonic_build::configure()
        .build_server(false)   // node agent is a client only
        .build_client(true)
        .compile(
            &["cri-api/pkg/apis/runtime/v1/api.proto"],
            &["cri-api/pkg/apis/runtime/v1"],
        )?;
    Ok(())
}
```

Vendor the proto file into the repo under `cri-api/`. Do not fetch at build time. Pin to the CRI API version matching the minimum Kubernetes version u7s targets (currently: v1.29+ → use `runtime.v1`).

The generated code appears under `OUT_DIR`; include it:

```rust
pub mod cri {
    tonic::include_proto!("runtime.v1");
}
```

This gives you `cri::runtime_service_client::RuntimeServiceClient` and `cri::image_service_client::ImageServiceClient`.

### 5.3 Connecting to the containerd Socket

tonic's `Endpoint` accepts a UDS path via a custom connector:

```rust
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

async fn connect_cri(socket_path: &str) -> Result<Channel> {
    let path = socket_path.to_string();
    let channel = Endpoint::try_from("http://[::]:0")?   // URI is ignored for UDS
        .connect_with_connector(service_fn(move |_: Uri| {
            UnixStream::connect(path.clone())
        }))
        .await?;
    Ok(channel)
}
```

Default socket path: `/run/containerd/containerd.sock`. Make this configurable in the node agent config (support CRI-O's `/run/crio/crio.sock` with no code change).

### 5.4 The ContainerRuntime Trait

See §6 for the full definition. The node agent programs against this trait exclusively; the concrete `ContainerdRuntime` struct is the only implementation in Phase 1.

### 5.5 Pod Lifecycle — Mapping K8s PodSpec to CRI Calls

Given a `v1::Pod` object received from the API server watch:

**Step 1: Pre-pull images**

For each `container` in `pod.spec.containers` (and `init_containers`):
- Check `ListImages` for the image ref. If absent or `imagePullPolicy == Always`, call `PullImage`.
- `PullImage` blocks until the image is locally available.
- Call order: init containers first, then regular containers.

**Step 2: Build `PodSandboxConfig`**

```
PodSandboxConfig {
    metadata: PodSandboxMetadata {
        name: pod.metadata.name,
        namespace: pod.metadata.namespace,
        uid: pod.metadata.uid,
        attempt: 0,
    },
    hostname: pod.spec.hostname or pod.metadata.name,
    log_directory: format!("/var/log/pods/{}_{}_{}/",
        pod.metadata.namespace, pod.metadata.name, pod.metadata.uid),
    dns_config: map from pod.spec.dns_config,
    linux: LinuxPodSandboxConfig {
        cgroup_parent: format!("/kubepods/pod{}/", pod.metadata.uid),
        security_context: LinuxSandboxSecurityContext { ... },
        resources: map resource limits if set,
    },
}
```

**Step 3: RunPodSandbox**

```rust
let resp = runtime_client.run_pod_sandbox(RunPodSandboxRequest {
    config: Some(sandbox_config),
    runtime_handler: String::new(),  // use default runtime
}).await?;
let sandbox_id = resp.into_inner().pod_sandbox_id;
```

After this call returns, invoke the CNI plugin to configure the network namespace (see architecture §3.7). The netns path is obtained from the sandbox status if needed.

**Step 4: CreateContainer + StartContainer (per container)**

```
ContainerConfig {
    metadata: ContainerMetadata { name: container.name, attempt: 0 },
    image: ImageSpec { image: container.image },
    command: container.command,
    args: container.args,
    working_dir: container.working_dir,
    envs: container.env → Vec<KeyValue>,
    mounts: container.volume_mounts → Vec<Mount>,
    log_path: format!("{}/0.log", container.name),  // relative to sandbox log_directory
    linux: LinuxContainerConfig {
        resources: map_resources(container.resources),
        security_context: ...,
    },
}
```

Call `CreateContainer`, then immediately `StartContainer`. Do this for init containers in order first (wait for each to complete before starting the next), then regular containers in parallel.

**Step 5: Update Pod Status**

After all containers start:
- Set `status.phase = "Running"`
- Populate `status.containerStatuses` from `ContainerStatus` RPC results
- Set `status.podIP` from CNI result
- PATCH to API server

### 5.6 Container Status Polling

The node agent's status loop (runs every 10 s per architecture §7):

```rust
async fn poll_pod_statuses(&self, pods: &[ActivePod]) {
    for pod in pods {
        for (container_id, name) in &pod.container_ids {
            let resp = self.runtime.container_status(container_id).await?;
            let status = resp.status.unwrap();
            // status.state: CONTAINER_RUNNING, CONTAINER_EXITED, etc.
            // status.exit_code, status.reason, status.finished_at
            self.reconcile_pod_status(pod, name, &status).await;
        }
    }
}
```

On `CONTAINER_EXITED`: set `pod.status.phase = Succeeded` (exit 0) or `Failed` (exit != 0), set `containerStatuses[i].state.terminated`, PATCH to API server immediately (do not wait for next poll cycle).

### 5.7 Image Pre-Pull

Pre-pull is called before `RunPodSandbox`. The node agent must not start the sandbox if any required image fails to pull.

```rust
async fn ensure_images(&self, pod: &v1::Pod) -> Result<()> {
    for container in &pod.spec.init_containers {
        self.pull_if_needed(&container.image, &pod.spec.image_pull_secrets).await?;
    }
    for container in &pod.spec.containers {
        self.pull_if_needed(&container.image, &pod.spec.image_pull_secrets).await?;
    }
    Ok(())
}

async fn pull_if_needed(&self, image: &str, pull_secrets: &[LocalObjectReference]) -> Result<()> {
    // 1. ListImages to check local cache
    // 2. If not present (or Always policy), call PullImage
    // 3. Auth: construct AuthConfig from pull_secrets (read Secret from API server)
    let auth = self.resolve_auth(image, pull_secrets).await?;
    self.runtime.pull_image(image, auth).await
}
```

Registry credentials come from `pod.spec.imagePullSecrets` → look up each `v1::Secret` of type `kubernetes.io/dockerconfigjson` via the API server, parse the `.dockerconfigjson` field, find the entry matching the image registry host, and pass `AuthConfig { username, password, ... }` to `PullImage`.

### 5.8 Resource Limits — Mapping to CRI LinuxContainerResources

```rust
fn map_resources(r: &v1::ResourceRequirements) -> LinuxContainerResources {
    let cpu_limit = r.limits.get("cpu").map(|q| parse_cpu_millis(q));
    let mem_limit = r.limits.get("memory").map(|q| parse_bytes(q));
    let cpu_request = r.requests.get("cpu").map(|q| parse_cpu_millis(q));

    LinuxContainerResources {
        // CPU shares: 1024 * cpu_request_millis / 1000 (minimum 2)
        cpu_shares: cpu_request.map(|m| (1024 * m / 1000).max(2) as i64).unwrap_or(0),
        // CFS quota/period for CPU limit
        cpu_quota: cpu_limit.map(|m| m * 100_000 / 1000).unwrap_or(-1),  // microseconds per period
        cpu_period: 100_000,  // 100ms
        // Memory limit in bytes
        memory_limit_in_bytes: mem_limit.map(|b| b as i64).unwrap_or(0),
        // OOM score: do not set (runtime default)
        oom_score_adj: 0,
        ..Default::default()
    }
}
```

`parse_cpu_millis("500m")` → 500; `parse_cpu_millis("2")` → 2000.
`parse_bytes("128Mi")` → 134217728.

Phase 1 can log a warning and use zeros (unlimited) for missing limits. Phase 2 should enforce limits.

### 5.9 Log Collection

containerd writes container logs to the path specified in `ContainerConfig.log_path` (relative to the sandbox's `log_directory`). With the paths above:

```
/var/log/pods/<namespace>_<name>_<uid>/<container_name>/0.log
```

Log format: one JSON line per log entry:
```json
{"time":"2026-05-18T12:00:00.000000000Z","stream":"stdout","log":"hello\n"}
```

For `kubectl logs` (`GET /api/v1/namespaces/{ns}/pods/{name}/log`):
- The API server delegates to the node agent via a node proxy (or the node agent hosts a local HTTP endpoint).
- Phase 1 simplification: the API server can read the log file directly via a node-local endpoint that the node agent serves on a local port.
- The node agent opens the log file, streams lines, optionally tailing (`?follow=true`) using `inotify` or polling.
- Filter by `?sinceTime` or `?tailLines` parameters.

**Phase 1:** Serve logs from the file path above via a simple HTTP endpoint on the node agent. No streaming required for Phase 1.

---

## 6. CRI Trait Definition

This is the boundary the node agent programs against. Implementing a `CriORuntime` or `DirectOciRuntime` requires only implementing this trait.

```rust
use std::collections::HashMap;

/// Opaque ID returned by the runtime for a sandbox or container.
pub type SandboxId = String;
pub type ContainerId = String;

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub name: String,
    pub namespace: String,
    pub uid: String,          // Pod UID
    pub hostname: String,
    pub log_directory: String,
    pub dns_servers: Vec<String>,
    pub dns_search: Vec<String>,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub linux: LinuxSandboxConfig,
}

#[derive(Debug, Clone, Default)]
pub struct LinuxSandboxConfig {
    pub cgroup_parent: String,
    pub sysctls: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ContainerConfig {
    pub name: String,
    pub image: String,
    pub command: Vec<String>,
    pub args: Vec<String>,
    pub working_dir: String,
    pub env: Vec<(String, String)>,
    pub mounts: Vec<Mount>,
    pub log_path: String,     // relative to sandbox log_directory
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub linux: LinuxContainerConfig,
}

#[derive(Debug, Clone, Default)]
pub struct LinuxContainerConfig {
    pub cpu_shares: i64,
    pub cpu_quota: i64,
    pub cpu_period: i64,
    pub memory_limit_in_bytes: i64,
    pub oom_score_adj: i32,
}

#[derive(Debug, Clone)]
pub struct Mount {
    pub host_path: String,
    pub container_path: String,
    pub readonly: bool,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
    pub server_address: String,
}

#[derive(Debug, Clone)]
pub struct ContainerStatus {
    pub id: ContainerId,
    pub name: String,
    pub state: ContainerState,
    pub created_at: i64,   // unix ns
    pub started_at: i64,   // unix ns
    pub finished_at: i64,  // unix ns
    pub exit_code: i32,
    pub reason: String,    // e.g. "Completed", "OOMKilled", "Error"
    pub log_path: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContainerState {
    Created,
    Running,
    Exited,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ImageStatus {
    pub id: String,
    pub repo_tags: Vec<String>,
    pub size_bytes: i64,
}

/// The boundary the node agent programs against for all container lifecycle operations.
/// All methods are async. Errors are opaque `anyhow::Error`; callers match on
/// well-known error kinds (ImageNotFound, SandboxNotFound) via downcasting if needed.
#[trait_variant::make(ContainerRuntime: Send)]
pub trait LocalContainerRuntime {
    /// Create a pod sandbox (network namespace + pause container).
    /// Returns the opaque sandbox ID.
    async fn run_pod_sandbox(&self, config: SandboxConfig) -> anyhow::Result<SandboxId>;

    /// Stop a running sandbox. Stops all containers within it.
    async fn stop_pod_sandbox(&self, sandbox_id: &str) -> anyhow::Result<()>;

    /// Remove a stopped sandbox and all its containers.
    async fn remove_pod_sandbox(&self, sandbox_id: &str) -> anyhow::Result<()>;

    /// Create a container inside an existing sandbox. Does not start it.
    async fn create_container(
        &self,
        sandbox_id: &str,
        config: ContainerConfig,
    ) -> anyhow::Result<ContainerId>;

    /// Start a created container.
    async fn start_container(&self, container_id: &str) -> anyhow::Result<()>;

    /// Stop a running container. Sends SIGTERM, then SIGKILL after `timeout_secs`.
    async fn stop_container(&self, container_id: &str, timeout_secs: i64) -> anyhow::Result<()>;

    /// Remove a stopped container.
    async fn remove_container(&self, container_id: &str) -> anyhow::Result<()>;

    /// Get the current status of a container.
    async fn container_status(&self, container_id: &str) -> anyhow::Result<ContainerStatus>;

    /// List all containers matching the given sandbox ID (pass empty string for all).
    async fn list_containers(&self, sandbox_id: &str) -> anyhow::Result<Vec<ContainerStatus>>;

    /// Pull an image. No-op if already present and auth is the same.
    async fn pull_image(&self, image: &str, auth: Option<AuthConfig>) -> anyhow::Result<()>;

    /// Check if an image is present locally.
    async fn image_status(&self, image: &str) -> anyhow::Result<Option<ImageStatus>>;

    /// Remove a locally cached image.
    async fn remove_image(&self, image: &str) -> anyhow::Result<()>;
}
```

**Note on `trait_variant`:** `trait_variant::make` (from the `trait-variant` crate) generates the `Send`-bound version needed for use with `tokio::spawn`. Alternatively, use `async_trait::async_trait` macro if `trait-variant` is not already a dependency. Both approaches produce equivalent code; pick one and be consistent.

The concrete `ContainerdRuntime` struct holds a `RuntimeServiceClient<Channel>` and an `ImageServiceClient<Channel>`. Each trait method translates to a single CRI gRPC call.

---

## 7. Node Agent RSS Budget

**Node agent binary (idle estimate):**

| Component | RSS estimate |
|---|---|
| Tokio runtime (2 worker threads, 512 KB stack each) | 1–2 MB |
| axum or bare hyper for local HTTP (log endpoint) | 3–5 MB |
| tonic gRPC channel to containerd socket | ~1 MB |
| HTTP/2 watch connection to API server | ~1 MB |
| In-memory pod state (100 pods × ~10 KB) | ~1 MB |
| Binary text + rodata + heap baseline | 5–10 MB |
| **Total node agent idle** | **~12–20 MB** |

**Per-node footprint with containerd:**

| Process | Idle RSS |
|---|---|
| Node agent | ~12–20 MB |
| containerd | ~35–50 MB |
| **Total** | **~47–70 MB** |

On a 1 GB VPS used as a data plane node, this leaves ~930–953 MB for workloads after the kernel (~50 MB) and other system processes. That is a comfortable budget. Even with containerd at the high end (50 MB) and the node agent at 20 MB, workloads get >880 MB.

**Comparison if direct OCI were used:**
- Node agent grows to ~30–50 MB (image store, layer cache, registry client)
- No containerd process
- Net change: roughly break-even on RSS, but much higher implementation cost

The RSS argument for direct OCI is weak at the 1 GB scale. It becomes relevant only at <256 MB total node RAM.

---

## 8. Phased Delivery

### Phase 1 — Run One Pod (Manually Specified)

Minimum viable integration:

1. Generate CRI gRPC stubs from vendored `api.proto`.
2. Implement `ContainerdRuntime` with all methods in the `ContainerRuntime` trait.
3. Node agent startup: connect to `/run/containerd/containerd.sock`, fail fast with a clear error if unavailable.
4. Pod watch: receive ADDED event for a pod with `spec.nodeName = <self>`.
5. Pre-pull images (`pull_if_needed`): no registry auth for Phase 1 (public images only, no `imagePullSecrets`).
6. `RunPodSandbox` → CNI exec → `CreateContainer` + `StartContainer` for each container.
7. Patch `pod.status.phase = Running` and `containerStatuses` to API server.
8. Status poll loop: every 10 s, `ContainerStatus` for all running containers; patch status on exit.
9. Termination: on `deletionTimestamp` set, `StopContainer` → `RemoveContainer` → `StopPodSandbox` → `RemovePodSandbox` → CNI DEL.

**Not in Phase 1:**
- Registry auth / `imagePullSecrets`
- Resource limits mapping (log a warning; pass zeros)
- Log streaming (log file exists; no HTTP endpoint yet)
- Liveness/readiness probes

### Phase 2 — Controller-Driven Pod Lifecycle

Adds to Phase 1:

1. **Registry auth:** Parse `kubernetes.io/dockerconfigjson` secrets, pass `AuthConfig` to `PullImage`.
2. **Resource limits:** Map `resources.requests/limits` to `LinuxContainerResources` (CPU shares, quota, memory limit).
3. **Log streaming:** Node agent serves `GET /logs?pod=<uid>&container=<name>&follow=<bool>` on a local HTTP endpoint. API server proxies `pods/log` requests to the node agent.
4. **Liveness probes:** HTTP GET or exec probes, implemented as a periodic tokio task per container. On failure, call `StopContainer` and let the restart policy trigger.
5. **Readiness probes:** Same mechanism; on failure, patch `containerStatuses[i].ready = false` rather than stopping.
6. **`imagePullPolicy` enforcement:** `Always`, `IfNotPresent`, `Never`.
7. **Init containers:** Run init containers in order, wait for exit code 0, proceed to regular containers.

---

## 9. Implementation Risks

**Risk 1 — CRI gRPC proto drift.**

The CRI API proto file must match the containerd version deployed on nodes. If the proto is compiled against `runtime.v1` from cri-api v0.29 and the deployed containerd speaks a slightly different field set, serialization breaks silently or calls fail. Mitigation: vendor the proto file alongside the Cargo workspace; document the minimum containerd version (1.7+ for `runtime.v1`); add a startup handshake (`Version` RPC) that logs the runtime version and fails if the major CRI version does not match.

**Risk 2 — Sandbox network namespace timing.**

`RunPodSandbox` returns before the sandbox's network namespace is fully configured by the container runtime's internal pause-container startup. If CNI `ADD` is called immediately, it may race against the netns existing on the filesystem. Mitigation: after `RunPodSandbox`, call `PodSandboxStatus` to retrieve the netns path and confirm it is non-empty before invoking CNI. Add a short retry loop (3 × 100 ms) if the netns path is empty.

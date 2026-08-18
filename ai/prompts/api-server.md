# u7s API Server — Implementation Spec

**Status:** RFC-grade. Last updated: 2026-05-18. The non-goals list below is
substantially superseded by shipped code (see the note after it) — treat
`roadmap.md`'s phase status as the current source of truth for scope.
**Audience:** A senior Rust engineer building this component from scratch.
**Read first:** `architecture.md` — this document assumes familiarity with §§3.1, 4, 5, 6, 8.

---

## 1. Scope and Non-Goals

### In scope

- HTTPS server on port 6443, serving the Kubernetes REST API
- All API groups listed in architecture.md §5 (core, apps/v1, rbac.authorization.k8s.io/v1, apiextensions.k8s.io/v1)
- Watch protocol (chunked streaming, BOOKMARK events, 410 Gone)
- RBAC enforcement (in-memory index, evaluated per request)
- Strategic merge patch for built-in types
- Server-side apply (SSA) with `managedFields` tracking
- CRD registration and dynamic route generation
- Discovery endpoints (`/api`, `/apis`, `/apis/{group}/{version}`)
- Error responses as Kubernetes `Status` objects
- Subresources: `pods/log`, `*/status`, `deployments/scale`, `statefulsets/scale`
- ServiceAccount JWT token authentication; client cert authentication
- Self-signed TLS using a generated cluster CA

### Explicit non-goals (do not implement)

- **etcd:** Never. The storage backend is SQLite or LMDB via the `Store` trait (architecture.md §6).
- **Audit logging:** Deferred to Phase 5+.
- **Control plane HA:** Single process, no leader election.
- **Priority and Fairness (APF):** No request priority queuing. Add a simple concurrency limit (tower middleware) to prevent unbounded connection storms.

The following were originally listed here as non-goals but are now implemented —
see `roadmap.md` for the shipped decision in each case:

- **Aggregation layer / API aggregation:** `APIService` routing to remote servers is implemented (`crates/apiserver/src/handlers/aggregation.rs`); CRDs are no longer the only extension mechanism.
- **Admission webhooks:** `MutatingWebhookConfiguration`/`ValidatingWebhookConfiguration` infrastructure is implemented (`crates/apiserver/src/admission.rs`), invoked from the resource handlers in addition to built-in validation.
- **OpenAPI v2/v3 schema endpoint (`/openapi/v2`, `/openapi/v3`):** Implemented (`crates/apiserver/src/handlers/discovery.rs`: `openapi_v2`, `openapi_v3`, `openapi_v3_group`), validated against the `CustomResourcePublishOpenAPI` conformance test.
- **Conversion webhooks:** Cross-version CRD conversion is implemented (`call_conversion_webhook` in `crates/apiserver/src/handlers/cr.rs`, dispatched from `admission.rs`/`handlers/watch.rs`); a CRD is no longer limited to exactly one stored version.
- **Metrics endpoint:** `/metrics` is implemented (`crates/apiserver/src/lib.rs`), separate from the metrics-server addon workload the API server deploys for HPA.
- **Pod exec/attach/port-forward:** Implemented as WebSocket-proxied calls to kubelet (`crates/apiserver/src/handlers/proxy.rs`: `pod_exec`, `pod_attach`, `pod_portforward`).

---

## 2. HTTP Framework and TLS

### Crates

```toml
[dependencies]
axum             = "0.8"          # HTTP framework; native tower integration
tower            = "0.5"          # Middleware composability
tower-http       = "0.6"          # Tracing, compression layers
hyper            = { version = "1", features = ["http1", "http2"] }
hyper-util       = "0.1"
tokio            = { version = "1", features = ["full"] }
rustls           = "0.23"         # TLS — prefer over openssl; no C deps
tokio-rustls     = "0.26"         # Async TLS stream wrapper for tokio
rcgen            = "0.13"         # Pure-Rust X.509 cert generation
rustls-pemfile   = "2"            # PEM parsing
```

**Why rustls over openssl:** No C build dependency, smaller binary, smaller RSS. Footprint matters: the control plane budget is 128 MB total.

### TLS bootstrap (like k3s)

On first startup, the API server generates all TLS material if not present on disk. Paths are relative to a configurable data directory (default `/var/lib/u7s`):

```
/var/lib/u7s/tls/
  ca.crt          # Cluster CA certificate (PEM)
  ca.key          # Cluster CA private key (PEM, EC P-256)
  server.crt      # API server TLS cert (SAN: localhost, 127.0.0.1, cluster IP)
  server.key      # API server TLS private key
  sa.pub          # ServiceAccount token signing public key
  sa.key          # ServiceAccount token signing private key
```

Generation procedure (run at startup if any file is missing):

```rust
use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType};

fn generate_cluster_ca() -> (CertifiedKey, CertifiedKey) {
    // 1. Generate CA key pair (ECDSA P-256)
    // 2. Generate CA cert with is_ca = IsCa::Ca(BasicConstraints::Unconstrained)
    // 3. Generate server key pair
    // 4. Generate server cert signed by CA, with SANs: localhost, 127.0.0.1, <node-ip>
    // 5. Generate separate key pair for ServiceAccount tokens (used for JWT signing)
    // 6. Write all to disk atomically (write to .tmp then rename)
}
```

**Rotation:** Not automated in Phase 1–4. Rotation requires restarting the API server with a new cert. In Phase 5, add a watch on cert file mtime and hot-reload via `arc-swap` or a shared `Arc<RwLock<ServerConfig>>`.

**Kubeconfig discovery:** After cert generation, write `/var/lib/u7s/kubeconfig`:

```yaml
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
    certificate-authority-data: <base64(ca.crt)>
  name: u7s
contexts:
- context:
    cluster: u7s
    user: admin
  name: u7s
current-context: u7s
users:
- name: admin
  user:
    client-certificate-data: <base64(admin.crt)>  # signed by CA
    client-key-data: <base64(admin.key)>
```

Generate an `admin` client cert at cluster init for bootstrapping. This is the only static admin credential; subsequently, RBAC controls access.

### Binding

```rust
// In main():
let tls_config = load_server_tls_config()?;  // rustls::ServerConfig
let listener = TcpListener::bind("0.0.0.0:6443").await?;
// Wrap with TLS acceptor
let acceptor = TlsAcceptor::from(Arc::new(tls_config));
// Feed into axum via hyper-util's accept loop
```

Use HTTP/1.1. HTTP/2 is not required by kubectl or Argo CD for the REST API (watch uses chunked HTTP/1.1). Enable HTTP/2 only if benchmarks show a benefit; it adds complexity to the TLS config.

---

## 3. Request Routing

### Kubernetes REST path structure

```
/api/v1/{resource}                                 # core, cluster-scoped list
/api/v1/{resource}/{name}                          # core, cluster-scoped named
/api/v1/namespaces/{ns}/{resource}                 # core, namespace-scoped list
/api/v1/namespaces/{ns}/{resource}/{name}          # core, namespace-scoped named
/api/v1/namespaces/{ns}/{resource}/{name}/{sub}    # core, subresource

/apis/{group}/{version}/{resource}                 # non-core, cluster-scoped list
/apis/{group}/{version}/{resource}/{name}          # non-core, cluster-scoped named
/apis/{group}/{version}/namespaces/{ns}/{resource}
/apis/{group}/{version}/namespaces/{ns}/{resource}/{name}
/apis/{group}/{version}/namespaces/{ns}/{resource}/{name}/{sub}
```

### Axum router structure

Do not register one route per resource. Use parameterized catch-all routes dispatched to a central handler. This makes CRD support tractable (no router modification per CRD beyond registering the group/version).

```rust
use axum::{Router, routing::get};

fn build_router(state: AppState) -> Router {
    Router::new()
        // Health/liveness (unauthenticated)
        .route("/healthz", get(healthz))
        .route("/readyz",  get(readyz))
        .route("/livez",   get(livez))

        // Discovery
        .route("/api",                          get(discovery::api_versions))
        .route("/api/v1",                       get(discovery::api_v1_resources))
        .route("/apis",                         get(discovery::api_groups))
        .route("/apis/:group/:version",         get(discovery::api_group_resources))

        // Core group — cluster-scoped resources (Namespaces, Nodes, PVs)
        .route("/api/v1/:resource",
            get(core::list_or_watch).post(core::create))
        .route("/api/v1/:resource/:name",
            get(core::get).put(core::update).patch(core::patch).delete(core::delete))
        .route("/api/v1/:resource/:name/:subresource",
            get(core::get_sub).put(core::update_sub).patch(core::patch_sub))

        // Core group — namespace-scoped resources
        .route("/api/v1/namespaces/:ns/:resource",
            get(core::list_or_watch).post(core::create))
        .route("/api/v1/namespaces/:ns/:resource/:name",
            get(core::get).put(core::update).patch(core::patch).delete(core::delete))
        .route("/api/v1/namespaces/:ns/:resource/:name/:subresource",
            get(core::get_sub).put(core::update_sub).patch(core::patch_sub))

        // Non-core groups (apps, rbac, apiextensions, and CRDs)
        .route("/apis/:group/:version/:resource",
            get(api::list_or_watch).post(api::create))
        .route("/apis/:group/:version/:resource/:name",
            get(api::get).put(api::update).patch(api::patch).delete(api::delete))
        .route("/apis/:group/:version/:resource/:name/:subresource",
            get(api::get_sub).put(api::update_sub).patch(api::patch_sub))
        .route("/apis/:group/:version/namespaces/:ns/:resource",
            get(api::list_or_watch).post(api::create))
        .route("/apis/:group/:version/namespaces/:ns/:resource/:name",
            get(api::get).put(api::update).patch(api::patch).delete(api::delete))
        .route("/apis/:group/:version/namespaces/:ns/:resource/:name/:subresource",
            get(api::get_sub).put(api::update_sub).patch(api::patch_sub))

        .layer(AuthLayer::new(state.auth.clone()))  // RBAC middleware (§7)
        .with_state(state)
}
```

**Routing note:** axum resolves routes in registration order. The namespaced namespace (`/api/v1/namespaces/:ns/:resource`) must be registered before the cluster-scoped catch-all (`/api/v1/:resource`); axum handles this by specificity — literal segments beat path params. But with the namespace segment as `:ns`, axum will not auto-disambiguate. Use a single handler for `/api/v1/:resource` and `/api/v1/namespaces/:ns/:resource` and detect the pattern in the handler via path params presence.

Simpler approach: register `/api/v1/namespaces` as a separate concrete route (for the Namespaces resource itself), and rely on the `:resource` catch-all for everything else. Inside the handler, check if the resource key is namespace-scoped or cluster-scoped by consulting the resource registry.

**The resource registry** is a compile-time-initialized `HashMap<ResourceKey, ResourceMeta>` for built-ins, extended at runtime for CRDs:

```rust
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct ResourceKey {
    pub group:   String,   // "" for core
    pub version: String,
    pub plural:  String,   // e.g. "pods"
}

pub struct ResourceMeta {
    pub kind:          String,       // e.g. "Pod"
    pub namespaced:    bool,
    pub verbs:         &'static [&'static str],
    pub subresources:  &'static [&'static str],
}
```

### Query parameters

Handlers inspect these on every request:

| Parameter | Used by |
|---|---|
| `watch=true` | Switch GET from list to watch stream |
| `resourceVersion=<rv>` | List at revision / watch from revision |
| `resourceVersionMatch=NotOlderThan\|Exact` | List semantics |
| `labelSelector=k=v,k2=v2` | Filter list/watch results |
| `fieldSelector=key=val` | Filter (only a subset of fields are indexable) |
| `limit=N` | Pagination page size |
| `continue=<token>` | Pagination cursor |
| `allowWatchBookmarks=true` | Enable BOOKMARK events on watch |
| `fieldManager=<name>` | SSA field manager name |
| `force=true` | SSA force-apply |

---

## 4. Type System

### Recommendation: `serde_json::Value` body + strongly-typed metadata

**Do not use kube-rs types as the primary representation.** Rationale:

- `kube` + `k8s-openapi` adds ~8 MB to the binary and pulls in a large dependency graph. Given the 128 MB RSS budget, binary size matters.
- k8s-openapi types encode every Kubernetes field — they are accurate but inflexible. CRD support requires dynamic types anyway; you end up with two parallel type universes.
- The API server does not need to understand most field semantics. It stores JSON, applies patches, validates against schemas. Only a handful of fields require structured access: `metadata`, `status`, and merge keys for SMP.

**The hybrid approach:**

```rust
/// Every Kubernetes object in memory is this.
/// The full JSON is kept as a serde_json::Value for cheap pass-through.
/// Metadata fields are parsed on demand, not always.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object {
    /// Deserialized object body. Must contain at minimum "kind", "apiVersion", "metadata".
    #[serde(flatten)]
    pub body: serde_json::Value,
}

impl Object {
    pub fn metadata(&self) -> Result<ObjectMeta, serde_json::Error> {
        serde_json::from_value(self.body["metadata"].clone())
    }
    pub fn name(&self) -> Option<&str> {
        self.body["metadata"]["name"].as_str()
    }
    pub fn namespace(&self) -> Option<&str> {
        self.body["metadata"]["namespace"].as_str()
    }
    pub fn resource_version(&self) -> Option<&str> {
        self.body["metadata"]["resourceVersion"].as_str()
    }
    pub fn kind(&self) -> Option<&str> {
        self.body["kind"].as_str()
    }
    /// Set metadata.resourceVersion in the body.
    pub fn set_resource_version(&mut self, rv: u64) {
        self.body["metadata"]["resourceVersion"] = rv.to_string().into();
    }
}

/// Strongly typed metadata — only parse when needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    pub name:              String,
    pub namespace:         Option<String>,
    pub uid:               Option<String>,
    pub resource_version:  Option<String>,
    pub generation:        Option<i64>,
    pub labels:            Option<HashMap<String, String>>,
    pub annotations:       Option<HashMap<String, String>>,
    pub managed_fields:    Option<Vec<ManagedFieldsEntry>>,
    pub deletion_timestamp: Option<String>,
    pub finalizers:        Option<Vec<String>>,
    pub owner_references:  Option<Vec<OwnerReference>>,
}
```

**Strongly typed structs for logic-heavy resources:** For resources that the API server manipulates structurally (not just stores), define typed structs:

```rust
// Needed for SMP merge key resolution:
pub struct PodSpec { pub containers: Vec<Container>, pub init_containers: Vec<Container>, pub volumes: Vec<Volume>, /* ... */ }
pub struct Container { pub name: String, /* merge key */ /* ... */ }

// Needed for CRD validation:
pub struct CustomResourceDefinition { pub spec: CrdSpec, /* ... */ }

// Needed for RBAC:
pub struct ClusterRole { pub rules: Vec<PolicyRule>, /* ... */ }
pub struct RoleBinding { pub subjects: Vec<Subject>, pub role_ref: RoleRef, /* ... */ }
```

These typed structs are used internally for logic; the stored and served form is always the raw `serde_json::Value` from `Object.body`.

**CRD implication:** Custom resources are pure `Object` / `serde_json::Value`. Schema validation uses the stored OpenAPI v3 schema (§8). No generated structs.

**Performance note (hot path):** For GET and list responses, avoid re-serializing: store bytes from the state store (`StoreObject.value: Bytes`) and write them directly to the response body using `axum::body::Body::from(bytes)`. Only deserialize when the handler needs to inspect or modify fields.

---

## 5. Storage Interface

The full trait is defined in architecture.md §6. This section specifies the types and semantics the API server layer imposes on top.

### Key schema

All objects are stored under deterministic string keys:

```
# Core group, namespace-scoped:
/registry/pods/<namespace>/<name>
/registry/configmaps/<namespace>/<name>
/registry/secrets/<namespace>/<name>
/registry/serviceaccounts/<namespace>/<name>
/registry/services/<namespace>/<name>
/registry/events/<namespace>/<name>

# Core group, cluster-scoped:
/registry/namespaces/<name>
/registry/nodes/<name>
/registry/persistentvolumes/<name>

# Non-core groups:
/registry/apps/deployments/<namespace>/<name>
/registry/apps/replicasets/<namespace>/<name>
/registry/apps/statefulsets/<namespace>/<name>
/registry/rbac.authorization.k8s.io/clusterroles/<name>
/registry/rbac.authorization.k8s.io/clusterrolebindings/<name>
/registry/rbac.authorization.k8s.io/roles/<namespace>/<name>
/registry/rbac.authorization.k8s.io/rolebindings/<namespace>/<name>
/registry/apiextensions.k8s.io/customresourcedefinitions/<name>

# Custom resources (populated dynamically from CRD spec):
/registry/<group>/<plural>/<namespace>/<name>      # namespaced
/registry/<group>/<plural>/<name>                  # cluster-scoped
```

**Key derivation function:**

```rust
pub fn object_key(group: &str, plural: &str, namespace: Option<&str>, name: &str) -> String {
    let g = if group.is_empty() { String::new() } else { format!("{}/", group) };
    match namespace {
        Some(ns) => format!("/registry/{}{}/{}/{}", g, plural, ns, name),
        None     => format!("/registry/{}{}/{}", g, plural, name),
    }
}

pub fn list_prefix(group: &str, plural: &str, namespace: Option<&str>) -> String {
    let g = if group.is_empty() { String::new() } else { format!("{}/", group) };
    match namespace {
        Some(ns) => format!("/registry/{}{}/{}/", g, plural, ns),
        None     => format!("/registry/{}{}/", g, plural),
    }
}
```

### ResourceVersion semantics

- `metadata.resourceVersion` is the decimal string of the `u64` global revision from the store.
- On GET/list response, `metadata.resourceVersion` reflects the revision when that object was last written.
- On list response, `metadata.resourceVersion` at the list level reflects the store snapshot revision (from `revision_out` in `Store::list`).
- On create/update, the caller submits `metadata.resourceVersion` (or omits it for create). The handler extracts it and passes as `expected_revision` to `Store::put`:
  - Omitted → `None` (unconditional, typically for create when `generateName` is used)
  - `"0"` or absent on create → `Some(0)` (must-not-exist)
  - Non-zero string → `Some(rv)` (optimistic concurrency)

### The `ObjectKey` helper

```rust
#[derive(Debug, Clone)]
pub struct ObjectRef {
    pub group:     String,
    pub version:   String,
    pub plural:    String,
    pub namespace: Option<String>,
    pub name:      String,
}

impl ObjectRef {
    pub fn store_key(&self) -> String {
        object_key(&self.group, &self.plural, self.namespace.as_deref(), &self.name)
    }
    pub fn list_prefix(&self) -> String {
        list_prefix(&self.group, &self.plural, self.namespace.as_deref())
    }
}
```

### List options

```rust
pub struct ListOptions {
    pub label_selector:  Option<LabelSelector>,
    pub field_selector:  Option<FieldSelector>,
    pub limit:           Option<u64>,
    pub continue_token:  Option<ContinueToken>,
    pub resource_version: Option<u64>,
}

pub struct ListResponse {
    pub items:    Vec<StoreObject>,
    pub revision: u64,
    pub continue_token: Option<ContinueToken>,
}

/// Opaque pagination cursor — base64(json({prefix, last_key, revision}))
pub struct ContinueToken(pub String);
```

**Label selector filtering is done in the handler, not the store.** The store does prefix scans; the handler iterates results and filters by label. Flag as a hot path (§14).

**Field selector filtering** is also handler-side for most fields. The one exception is `spec.nodeName` for Pods, which is critical for the node agent watch. Consider adding a field index for `spec.nodeName` in the store (a secondary key table in SQLite).

---

## 6. Watch Protocol

### Overview

A watch request is a GET with `?watch=true`. The response is an HTTP/1.1 chunked transfer encoding stream. Each chunk is a JSON object followed by `\n`. The connection stays open until the client closes it or the server decides to close it (e.g., too-old resource version).

Content-Type: `application/json;stream=watch`

Event format:

```json
{"type":"ADDED","object":{"kind":"Pod","apiVersion":"v1","metadata":{"name":"foo","resourceVersion":"42"},...}}
{"type":"MODIFIED","object":{...}}
{"type":"DELETED","object":{...}}
{"type":"BOOKMARK","object":{"kind":"Pod","apiVersion":"v1","metadata":{"resourceVersion":"99"}}}
{"type":"ERROR","object":{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Gone","code":410}}
```

### Handler structure

```rust
async fn list_or_watch(
    State(app): State<AppState>,
    Path(params): Path<RouteParams>,
    Query(query): Query<WatchQuery>,
    auth: AuthInfo,
    headers: HeaderMap,
) -> Response {
    if query.watch == Some(true) {
        watch_handler(app, params, query, auth).await
    } else {
        list_handler(app, params, query, auth).await
    }
}

async fn watch_handler(app: AppState, params: RouteParams, query: WatchQuery, auth: AuthInfo) -> Response {
    let from_rv = query.resource_version.unwrap_or(0);
    let prefix = list_prefix_from_params(&params);

    // Open a watch stream from the store.
    let mut store_stream = app.store.watch(&prefix, from_rv).await?;

    // Build a channel for the HTTP body.
    let (tx, body) = axum::body::Body::channel();

    tokio::spawn(async move {
        let mut last_rv = from_rv;
        let mut bookmark_interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                event = store_stream.next() => {
                    match event {
                        None => break,  // store closed the stream
                        Some(WatchEvent::Put(obj)) => {
                            let filtered = apply_selectors(&obj, &query);
                            if !filtered { continue; }
                            last_rv = obj.revision;
                            let ev_type = if_first_see_added_else_modified(&obj);
                            let line = serialize_watch_event(ev_type, &obj.value);
                            if tx.send_data(line).await.is_err() { break; }
                        }
                        Some(WatchEvent::Delete { key, revision }) => {
                            last_rv = revision;
                            // Reconstruct a minimal tombstone object for the DELETED event.
                            let tombstone = make_tombstone(&key, revision);
                            let line = serialize_watch_event("DELETED", &tombstone);
                            if tx.send_data(line).await.is_err() { break; }
                        }
                        Some(WatchEvent::Bookmark { revision }) => {
                            last_rv = revision;
                            // The store signals a compaction boundary — send 410.
                            let gone = status_gone(revision);
                            let _ = tx.send_data(serialize_watch_event("ERROR", &gone)).await;
                            break;
                        }
                    }
                }
                _ = bookmark_interval.tick() => {
                    let bk = serialize_bookmark(last_rv, &params);
                    if tx.send_data(bk).await.is_err() { break; }
                }
            }
        }
    });

    Response::builder()
        .status(200)
        .header("Content-Type", "application/json;stream=watch")
        .header("Transfer-Encoding", "chunked")
        .body(body)
        .unwrap()
}
```

### In-memory watch registry and fan-out

The `Store` trait handles fan-out internally (architecture.md §6). The store's `watch()` method returns a `Stream` per caller. For LMDB, this is a `tokio::sync::broadcast` channel; for SQLite, it is a broadcast channel driven by the write path.

**Critical implementation detail for the store layer:** After each successful `put` or `delete`, the store MUST:

1. Increment and persist the global revision atomically with the write.
2. Serialize the changed object (or a tombstone) to `Bytes` once.
3. Send `WatchEvent::Put(StoreObject { value: bytes.clone(), ... })` to a `tokio::sync::broadcast::Sender<WatchEvent>`.
4. Each active watch stream is a `tokio::sync::broadcast::Receiver<WatchEvent>` filtered by prefix.

**Pre-serialize once, then clone `Bytes` (reference-counted).** Do not serialize per-watcher. This is the critical hot path (architecture.md §4.2).

### Watch ring buffer (for resumption)

The store maintains a bounded ring buffer of recent events per resource type prefix. Size: last 1000 events or 10 minutes, whichever is smaller. When a `watch(prefix, from_rv)` call arrives:

- If `from_rv` is within the ring buffer range: replay buffered events, then live-feed from the broadcast channel.
- If `from_rv` is before the ring buffer range: the `watch()` call returns a stream whose first event is `WatchEvent::Bookmark { revision: current }`. The API server handler detects this and sends an `ERROR` event with reason `Gone`, status 410. The client must re-list.
- If `from_rv` is 0: start from the current state (the client should have done a list first; for a fresh watch, send current objects as ADDED events before switching to live).

**410 Gone response** (when `from_rv` is compacted):

```json
{"type":"ERROR","object":{"kind":"Status","apiVersion":"v1","status":"Failure","message":"too old resource version: 5 (current: 100)","reason":"Gone","code":410}}
```

### BOOKMARK events

`BOOKMARK` events are sent:
1. Every 60 seconds on idle watches (keep-alive + resume point).
2. Immediately after the ring buffer replay completes (to signal the client where live events begin).

BOOKMARK object shape:

```json
{"type":"BOOKMARK","object":{"kind":"Pod","apiVersion":"v1","metadata":{"resourceVersion":"<current-rv>","annotations":{"k8s.io/initial-events-end":"true"}}}}
```

The `annotations["k8s.io/initial-events-end"]` is included only on the bookmark that marks the end of initial event replay.

### Client disconnect detection

The `tokio::select!` on `tx.send_data(...)` failing is the disconnect signal. `axum::body::Body::channel()` returns a `Sender` whose `send_data` returns an error when the receiver (client) is gone. Break the loop immediately on send error; do not leak the background task.

---

## 7. RBAC Enforcement

### Middleware position

RBAC runs as a `tower::Layer` applied to the entire router. It runs after TLS but before any handler. The `/healthz`, `/readyz`, `/livez` routes are registered before the auth layer (or explicitly excluded).

```rust
// Layer order (innermost = first to run on request):
Router::new()
    .route("/healthz", ...)       // No auth
    // ... all API routes ...
    .layer(RbacLayer::new(state.rbac.clone()))   // Auth + authz
    .layer(RequestIdLayer::new())
    .layer(TraceLayer::new_for_http())
```

The `RbacLayer` extracts the request, authenticates, authorizes, and either passes the request to the inner handler (with auth info attached via request extensions) or returns a `Status` error response.

### Authentication

**Phase 1:** Static bearer token file (map of `token → UserInfo`). Loaded at startup.

**Phase 2+:** ServiceAccount JWT tokens.

JWT validation:

```rust
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

#[derive(Debug, Deserialize)]
struct SaClaims {
    sub: String,                          // "system:serviceaccount:<ns>/<name>"
    iss: String,                          // must be cluster issuer URL
    exp: u64,
    #[serde(rename = "kubernetes.io")]
    k8s: Option<K8sClaims>,
}

fn validate_sa_token(token: &str, pubkey: &DecodingKey) -> Result<UserInfo> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[CLUSTER_ISSUER]);
    let data = decode::<SaClaims>(token, pubkey, &validation)?;
    let sub = data.claims.sub;
    // sub format: "system:serviceaccount:<namespace>/<name>"
    Ok(UserInfo { username: sub, groups: vec!["system:serviceaccounts".into()] })
}
```

**Client certificates:** Extract `CN` as username, `O` fields as groups from the mTLS peer certificate. axum does not expose the peer cert directly; read it from the `tokio-rustls` `TlsStream` before handing to axum, attach to request extensions.

```rust
#[derive(Clone, Debug)]
pub struct AuthInfo {
    pub username: String,
    pub groups:   Vec<String>,
    pub uid:      Option<String>,
}
```

Anonymous access returns `system:anonymous` / `system:unauthenticated` group (for `/healthz` etc). Reject unauthenticated requests to API paths with 401.

### Authorization (RBAC index)

```rust
#[derive(Clone)]
pub struct RbacIndex {
    /// All rules keyed by (subject_type, subject_name) → Vec<ResolvedRule>
    /// ResolvedRule = (namespace_scope, apiGroups, resources, verbs, resourceNames)
    inner: Arc<RwLock<RbacInner>>,
}

pub struct AuthzRequest {
    pub user:      UserInfo,
    pub verb:      String,       // "get", "list", "watch", "create", "update", "patch", "delete"
    pub group:     String,       // API group, "" for core
    pub resource:  String,       // plural resource name
    pub subresource: Option<String>,
    pub namespace: Option<String>,
    pub name:      Option<String>,
}

impl RbacIndex {
    /// Returns true if the request is allowed. Hot path — must not block.
    pub fn is_allowed(&self, req: &AuthzRequest) -> bool {
        let inner = self.inner.read();
        for subject_key in subject_keys(&req.user) {
            if let Some(rules) = inner.rules.get(&subject_key) {
                for rule in rules {
                    if rule.matches(req) { return true; }
                }
            }
        }
        false  // Default deny
    }

    /// Called on watch events for Role/ClusterRole/Binding resources.
    pub fn apply_event(&self, event: &WatchEvent) {
        let mut inner = self.inner.write();
        inner.rebuild_from_event(event);
    }
}
```

**Index structure:** Map from `SubjectKey` (user or group name) to a `Vec<ResolvedRule>`. A `ResolvedRule` is the cartesian product of a binding → role → rule, with the namespace scope from the binding embedded. This avoids any joins on the hot path.

**Rebuild:** On startup, list all ClusterRoles, ClusterRoleBindings, Roles, RoleBindings from the store and build the index. Then watch them for changes and call `apply_event`. The write lock is held only for the duration of `rebuild_from_event`, which processes one watch event at a time. Reads are concurrent via `RwLock`.

**Bootstrap problem:** On a fresh cluster, no RBAC objects exist, so no one can do anything. Solve with a built-in `system:masters` group that is hardcoded to allow all operations (similar to upstream). The admin client cert in the kubeconfig has `O=system:masters`. A user in `system:masters` bypasses the RBAC check entirely.

---

## 8. CRD Support

### Storage

CRD objects themselves are stored under:

```
/registry/apiextensions.k8s.io/customresourcedefinitions/<name>
```

Where `<name>` is `<plural>.<group>`, e.g., `applications.argoproj.io`.

Custom resource instances are stored under:

```
/registry/<group>/<plural>/<namespace>/<name>   # namespaced
/registry/<group>/<plural>/<name>               # cluster-scoped
```

### Dynamic route registration

The API server maintains a `CrdRegistry`:

```rust
pub struct CrdRegistry {
    inner: Arc<RwLock<HashMap<ResourceKey, CrdMeta>>>,
}

pub struct CrdMeta {
    pub group:    String,
    pub version:  String,
    pub plural:   String,
    pub kind:     String,
    pub namespaced: bool,
    pub schema:   Option<serde_json::Value>,  // OpenAPI v3 schema from CRD spec
    pub status_subresource: bool,
}
```

When a CRD is written (via the `apiextensions.k8s.io/v1/customresourcedefinitions` handler), the handler:

1. Validates the CRD spec (valid group, version, plural, kind, names).
2. Writes it to the store.
3. Calls `CrdRegistry::register(meta)` under write lock.
4. Updates the discovery cache (§10).

**No router modification is required.** The catch-all routes `/apis/:group/:version/:resource` already handle any group/version/plural. Each handler checks the `CrdRegistry` to determine if the resource is a known CRD. If not found in built-ins or CRDs, return 404 with a `Status{reason: "NotFound"}`.

**CRD watch:** Works identically to built-in resources via the same `Store::watch` mechanism. No special path.

**Established condition:** After writing the CRD to the store, update its `status.conditions` with `type: Established, status: True`. This is what clients poll for before trying to create custom resources.

### Schema validation

```rust
fn validate_custom_resource(obj: &serde_json::Value, schema: &serde_json::Value) -> Result<(), ValidationError> {
    // Use jsonschema crate for OpenAPI v3 structural schema validation.
    // The CRD spec.versions[*].schema.openAPIV3Schema is a JSONSchema object.
    // Validate obj["spec"] (and other fields) against it.
    // Do NOT validate metadata — it is validated by the API server itself.
}
```

Crate: `jsonschema = "0.29"` (pure Rust, no C deps).

CEL validation rules (`x-kubernetes-validations`) are deferred to Phase 5. In Phase 4, structural schema validation is sufficient for Argo CD.

### Status subresource

If the CRD has `spec.subresources.status: {}`, then:

- `PUT /apis/<group>/<version>/namespaces/<ns>/<plural>/<name>` ignores changes to `status`.
- `PUT /apis/<group>/<version>/namespaces/<ns>/<plural>/<name>/status` ignores changes to `spec`.
- `PATCH` on the main resource endpoint similarly ignores the `status` field.

Implement by stripping the `status` field from the incoming body before merging (for main resource), or by merging only the `status` field (for the `/status` subresource).

---

## 9. Strategic Merge Patch and Server-Side Apply

### 9.1 JSON Merge Patch (RFC 7396)

Used for: custom resources, and any `PATCH` with `Content-Type: application/merge-patch+json`.

Algorithm: recursively merge patch object into target. If patch field is `null`, delete it. If patch field is an object, recurse. Otherwise, overwrite.

```rust
fn json_merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    if let (Some(target_obj), Some(patch_obj)) = (target.as_object_mut(), patch.as_object()) {
        for (key, val) in patch_obj {
            if val.is_null() {
                target_obj.remove(key);
            } else if val.is_object() {
                let entry = target_obj.entry(key).or_insert(serde_json::Value::Object(Default::default()));
                json_merge_patch(entry, val);
            } else {
                target_obj.insert(key.clone(), val.clone());
            }
        }
    } else {
        *target = patch.clone();
    }
}
```

### 9.2 Strategic Merge Patch (SMP)

Used for built-in types when `Content-Type: application/strategic-merge-patch+json`.

SMP extends JSON merge patch with **merge keys** for arrays. Without merge keys, array fields are replaced wholesale. With merge keys, array elements are matched by a key field and merged individually.

**Merge key table for u7s (must cover Argo CD use cases):**

| Field path | Merge key | Strategy |
|---|---|---|
| `spec.containers` | `name` | merge |
| `spec.initContainers` | `name` | merge |
| `spec.volumes` | `name` | merge |
| `spec.template.spec.containers` | `name` | merge |
| `spec.template.spec.initContainers` | `name` | merge |
| `spec.template.spec.volumes` | `name` | merge |
| `spec.ports` | `containerPort` | merge |
| `spec.env` | `name` | merge |
| `spec.volumeMounts` | `mountPath` | merge |
| `rules` (RBAC) | (no key) | replace |
| `subjects` (RoleBinding) | (no key) | replace |

Fields not in this table: arrays are replaced (standard JSON merge patch behavior).

**SMP algorithm:**

```rust
fn strategic_merge_patch(
    target: &mut serde_json::Value,
    patch: &serde_json::Value,
    path: &str,                    // e.g. "spec.containers" for merge key lookup
) {
    match (target, patch) {
        (Value::Object(t), Value::Object(p)) => {
            for (key, pval) in p {
                let child_path = format!("{}.{}", path, key);
                if pval.is_null() {
                    t.remove(key);
                } else if let Some(tval) = t.get_mut(key) {
                    if tval.is_array() && pval.is_array() {
                        if let Some(merge_key) = MERGE_KEYS.get(child_path.as_str()) {
                            strategic_merge_array(tval, pval, merge_key);
                        } else {
                            *tval = pval.clone();  // replace
                        }
                    } else {
                        strategic_merge_patch(tval, pval, &child_path);
                    }
                } else {
                    t.insert(key.clone(), pval.clone());
                }
            }
        }
        (t, p) => *t = p.clone(),
    }
}

fn strategic_merge_array(target: &mut Value, patch: &Value, merge_key: &str) {
    let t_arr = target.as_array_mut().unwrap();
    let p_arr = patch.as_array().unwrap();
    for p_elem in p_arr {
        let p_key = &p_elem[merge_key];
        if let Some(t_elem) = t_arr.iter_mut().find(|e| &e[merge_key] == p_key) {
            // Merge the patch element into the matching target element
            json_merge_patch(t_elem, p_elem);
        } else {
            t_arr.push(p_elem.clone());
        }
    }
    // Handle $patch: delete directive
    // If p_elem has "$patch": "delete", remove the matching element from target.
}
```

`MERGE_KEYS` is a static `phf::Map<&'static str, &'static str>` compiled at build time.

### 9.3 Server-Side Apply (SSA)

**This is the hardest part of the API server.** SSA is invoked by `PATCH` with `Content-Type: application/apply-patch+yaml` and `?fieldManager=<name>`.

SSA tracks which fields are owned by which field manager in `metadata.managedFields`. On apply, the server must detect conflicts (a field the requester is trying to set is already owned by a different manager), and either reject (default) or overwrite (if `?force=true`).

#### What gets stored

`metadata.managedFields` is an array of entries:

```json
[
  {
    "manager": "argocd-controller",
    "operation": "Apply",
    "apiVersion": "apps/v1",
    "time": "2026-05-18T00:00:00Z",
    "fieldsType": "FieldsV1",
    "fieldsV1": {
      "f:spec": {
        "f:replicas": {},
        "f:template": {
          "f:spec": {
            "f:containers": {
              "k:{\"name\":\"app\"}": {
                "f:image": {}
              }
            }
          }
        }
      }
    }
  }
]
```

**FieldsV1 encoding:** A JSON object where keys are either:
- `f:<fieldName>` — a field in the object.
- `k:<JSON key object>` — an element in a merge-key array, keyed by the merge key value.
- `i:<index>` — an element in an atomic list by index (not used for SSA merge lists).
- `v:<value>` — a set element.

Empty value (`{}`) means "this manager owns this leaf field."

#### SSA apply algorithm

Given: `live` (current stored object), `config` (the apply patch from the client), `manager` (fieldManager), `force` (bool).

```
1. Parse `config` into a typed field set: fields_in_config = extract_field_set(config)

2. Load live.metadata.managedFields → Vec<ManagedFieldsEntry>

3. Compute the entry for this manager: old_entry = entries.find(manager == manager && operation == "Apply")

4. Detect conflicts:
   For each field in fields_in_config:
     For each other_entry in entries where manager != this_manager AND operation == "Apply":
       If field in other_entry.fields:
         → CONFLICT
   If conflicts exist AND NOT force:
     Return 409 Conflict with Status listing conflicting fields and owning managers.
   If force: remove conflicting fields from other managers' entries.

5. Compute the new managed fields entry for this manager:
   new_entry = ManagedFieldsEntry { manager, operation: "Apply", fields: fields_in_config }

6. Compute the new live object:
   - Start from live.
   - For fields that old_entry owned but new_entry does NOT: clear those fields (the manager dropped ownership).
   - For fields in fields_in_config: set them from config.
   - For fields owned by OTHER managers: leave them unchanged.
   - For fields owned by NO manager (unmanaged): leave them unchanged (SSA does not touch unmanaged fields).

7. Replace this manager's entry in managedFields (or add if new).

8. Write new live to store with optimistic concurrency.
```

**Implementation notes:**

- The field set extraction (`extract_field_set`) traverses the JSON object recursively, producing a `FieldsV1` tree. Arrays with merge keys produce `k:{...}` children; atomic arrays produce a single owned entry.
- The "clear owned fields" step (step 6) is the inverse of the field set: for each field path in `old_entry` that is not in `new_entry`, delete that path from the live object. This is a recursive JSON path deletion.
- Conflicts on scalar fields are simple (two managers setting the same field). Conflicts on array elements are keyed by the merge key.
- SSA does not merge metadata fields (labels, annotations have their own management). Labels and annotations merge by key (each label key is separately owned).

**Testing SSA:** The upstream Kubernetes conformance suite has SSA tests. Run `kubectl apply` with `--server-side` twice from different field managers and verify conflict detection. This is a known hard problem; budget significant implementation time.

**Known hard edge cases:**
- Atomic structs (structs with `x-kubernetes-map-type: atomic` in the schema) are owned as a unit.
- Default values: fields not in the config but defaulted by the server are owned by the server manager (`"manager": "apiserver"`, operation `"Update"`).
- The "manager/Update" vs "manager/Apply" distinction: Update operations (PUT/PATCH non-SSA) create/update an entry with `operation: "Update"`. Apply operations create/update with `operation: "Apply"`. They have different conflict semantics.

---

## 10. Discovery Endpoints

Discovery is served from a cache rebuilt on startup and on CRD changes.

### `GET /api` → APIVersions

```json
{
  "kind": "APIVersions",
  "apiVersion": "v1",
  "versions": ["v1"],
  "serverAddressByClientCIDRs": [{"clientCIDR": "0.0.0.0/0", "serverAddress": "https://127.0.0.1:6443"}]
}
```

### `GET /api/v1` → APIResourceList

```json
{
  "kind": "APIResourceList",
  "apiVersion": "v1",
  "groupVersion": "v1",
  "resources": [
    {"name": "pods",           "singularName": "", "namespaced": true,  "kind": "Pod",       "verbs": ["create","delete","deletecollection","get","list","patch","update","watch"], "shortNames": ["po"]},
    {"name": "pods/log",       "singularName": "", "namespaced": true,  "kind": "Pod",       "verbs": ["get"]},
    {"name": "pods/status",    "singularName": "", "namespaced": true,  "kind": "Pod",       "verbs": ["get","patch","update"]},
    {"name": "namespaces",     "singularName": "", "namespaced": false, "kind": "Namespace", "verbs": ["create","delete","get","list","patch","update","watch"]},
    // ... all core resources
  ]
}
```

### `GET /apis` → APIGroupList

```json
{
  "kind": "APIGroupList",
  "apiVersion": "v1",
  "groups": [
    {"name": "apps",                              "versions": [{"groupVersion": "apps/v1",                              "version": "v1"}], "preferredVersion": {"groupVersion": "apps/v1",                              "version": "v1"}},
    {"name": "rbac.authorization.k8s.io",         "versions": [{"groupVersion": "rbac.authorization.k8s.io/v1",         "version": "v1"}], "preferredVersion": {"groupVersion": "rbac.authorization.k8s.io/v1",         "version": "v1"}},
    {"name": "apiextensions.k8s.io",              "versions": [{"groupVersion": "apiextensions.k8s.io/v1",              "version": "v1"}], "preferredVersion": {"groupVersion": "apiextensions.k8s.io/v1",              "version": "v1"}},
    // CRD groups added dynamically:
    {"name": "argoproj.io",                       "versions": [{"groupVersion": "argoproj.io/v1alpha1",                 "version": "v1alpha1"}], "preferredVersion": {"groupVersion": "argoproj.io/v1alpha1", "version": "v1alpha1"}}
  ]
}
```

### `GET /apis/{group}/{version}` → APIResourceList

Same shape as `/api/v1` but for the specified group/version. For CRD-registered groups, this list is built from `CrdRegistry`.

### Discovery cache

```rust
pub struct DiscoveryCache {
    inner: Arc<RwLock<DiscoveryCacheInner>>,
}

struct DiscoveryCacheInner {
    api_versions:   serde_json::Value,           // GET /api
    api_v1:         serde_json::Value,           // GET /api/v1
    api_groups:     serde_json::Value,           // GET /apis
    group_versions: HashMap<String, serde_json::Value>,  // GET /apis/{group}/{version}
}

impl DiscoveryCache {
    pub fn rebuild(&self, builtins: &[ResourceMeta], crds: &[CrdMeta]) {
        // Reconstruct all four responses. Hold write lock only for the swap.
        let new_inner = build_inner(builtins, crds);
        *self.inner.write() = new_inner;
    }
    pub fn get_api_groups(&self) -> serde_json::Value {
        self.inner.read().api_groups.clone()
    }
    // ...
}
```

Call `DiscoveryCache::rebuild` on startup and whenever a CRD is created, updated, or deleted.

---

## 11. Error Responses

Every error response body is a Kubernetes `Status` object. Never return a bare HTTP error body.

```rust
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub kind:        &'static str,   // "Status"
    pub api_version: &'static str,   // "v1"
    pub status:      &'static str,   // "Failure" or "Success"
    pub message:     String,
    pub reason:      StatusReason,
    pub details:     Option<StatusDetails>,
    pub code:        u16,
}

#[derive(Serialize)]
pub enum StatusReason {
    NotFound,          // 404
    AlreadyExists,     // 409
    Conflict,          // 409 (resourceVersion mismatch, or SSA conflict)
    Invalid,           // 422
    Forbidden,         // 403
    Unauthorized,      // 401
    Gone,              // 410 (watch resource version compacted)
    Timeout,           // 504
    TooManyRequests,   // 429
    InternalError,     // 500
    BadRequest,        // 400
    MethodNotAllowed,  // 405
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusDetails {
    pub name:   Option<String>,
    pub group:  Option<String>,
    pub kind:   Option<String>,
    pub uid:    Option<String>,
    pub causes: Option<Vec<StatusCause>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusCause {
    pub r#type:  String,   // e.g. "FieldValueRequired", "FieldValueInvalid"
    pub message: String,
    pub field:   String,
}
```

**Serialization note:** `StatusReason` serializes as a string (`"NotFound"`, `"AlreadyExists"`, etc.) using a custom `Serialize` impl or `#[serde(rename = "...")]` on each variant.

**Standard error constructor helpers:**

```rust
impl Status {
    pub fn not_found(name: &str, kind: &str) -> (StatusCode, Self) { ... }
    pub fn already_exists(name: &str, kind: &str) -> (StatusCode, Self) { ... }
    pub fn conflict(message: &str) -> (StatusCode, Self) { ... }
    pub fn invalid(causes: Vec<StatusCause>) -> (StatusCode, Self) { ... }
    pub fn forbidden(user: &str, verb: &str, resource: &str) -> (StatusCode, Self) { ... }
    pub fn unauthorized(message: &str) -> (StatusCode, Self) { ... }
    pub fn gone(message: &str) -> (StatusCode, Self) { ... }
    pub fn internal(message: &str) -> (StatusCode, Self) { ... }
}
```

axum handlers return `Result<impl IntoResponse, StatusError>` where `StatusError` wraps a `(StatusCode, Status)` and implements `IntoResponse`:

```rust
impl IntoResponse for StatusError {
    fn into_response(self) -> Response {
        let (code, status) = self.0;
        (code, axum::Json(status)).into_response()
    }
}
```

---

## 12. Phased Implementation

### Phase 1: Minimum viable API server

**Goal:** `kubectl get pods` works. A pod with `spec.nodeName` set runs via the node agent.

Implement:
- TLS bootstrap (rcgen, rustls)
- Axum router with core group only: `pods`, `namespaces`, `nodes`
- `Store` trait + SQLite implementation
- GET, LIST, CREATE, UPDATE, PATCH (JSON merge patch only), DELETE handlers
- Watch protocol (ADDED/MODIFIED/DELETED events; BOOKMARK after 60 s)
- Static bearer token authentication; no RBAC (allow all requests)
- Discovery endpoints for `/api` and `/api/v1` only
- Status error responses
- `pods/log` subresource (basic: read from store, not live stream)

Skip: SSA, SMP, CRDs, RBAC enforcement, non-core groups.

Acceptance: `kubectl get pods -n default` returns an empty list without error. `kubectl apply` of a Pod with `spec.nodeName` set creates it. The node agent picks it up.

### Phase 2: RBAC + apps/v1 + SMP

**Goal:** `kubectl apply -f deployment.yaml` creates a running Deployment.

Add:
- `apps/v1` API group: Deployments, ReplicaSets, StatefulSets
- `rbac.authorization.k8s.io/v1` API group
- RBAC enforcement middleware (in-memory index, bearer token + SA JWT auth)
- Strategic merge patch for built-in types (merge key table above)
- ServiceAccount JWT token minting (for controller manager service accounts)
- `system:masters` bypass
- Discovery for `/apis` and `/apis/apps/v1`, `/apis/rbac.authorization.k8s.io/v1`
- Pagination foundation (`continue` token; at least parse it, even if implementation is full-scan with offset)

Acceptance: `kubectl apply` of a Deployment creates pods. The controller manager (Deployment + ReplicaSet controllers) can authenticate and operate.

### Phase 3: Scheduler + StatefulSets + hardening

- StatefulSet status subresource
- `PersistentVolumeClaims`, `PersistentVolumes` in the API
- Field selector indexing for `spec.nodeName` (node agent watch performance)
- Watch bookmark on reconnect (ring buffer replay)
- 410 Gone handling end-to-end
- Pagination implementation (cursor-based)
- Node status subresource

Acceptance: Pods are placed automatically. StatefulSets with PVCs work.

### Phase 4: CRD + Server-Side Apply + Argo CD

This is the hardest phase. Do not start it until Phase 3 is solid.

- `apiextensions.k8s.io/v1` CRD CRUD + watch
- Dynamic resource registration (CrdRegistry)
- JSON schema validation for custom resources (jsonschema crate)
- Server-side apply (full FieldsV1 tracking, conflict detection, force-apply)
- Discovery cache rebuild on CRD change
- `argoproj.io/v1alpha1` custom resources servable
- Argo CD ApplicationSet support (additional CRD)

Acceptance: `kubectl apply -f argocd-install.yaml` installs Argo CD. Argo CD can create Application objects and sync a simple Deployment.

### Phase 5: Hardening

- LMDB storage backend (benchmark, decide)
- TLS cert rotation (hot-reload)
- CEL validation for CRDs (`x-kubernetes-validations`)
- Pod log streaming (live, via CRI API on node agent, relayed through the API server)
- Watch history compaction tuning
- Request concurrency limit (tower middleware)

---

## 13. Crate Selection

```toml
[dependencies]
# HTTP
axum         = "0.8"        # Routing, middleware, request extractors
tower        = "0.5"        # Layer/Service trait; compose middleware
tower-http   = "0.6"        # TraceLayer, ConcurrencyLimitLayer, CompressionLayer
hyper        = { version = "1", features = ["http1"] }
hyper-util   = "0.1"

# Async runtime
tokio        = { version = "1", features = ["full"] }
tokio-util   = "0.7"        # Streams, codec

# TLS
rustls       = "0.23"
tokio-rustls = "0.26"
rcgen        = "0.13"       # Self-signed cert generation
rustls-pemfile = "2"

# Serialization
serde        = { version = "1", features = ["derive"] }
serde_json   = "1"
serde_yaml   = "0.9"        # For apply-patch+yaml content type
bytes        = "1"          # Bytes type for zero-copy

# Storage
rusqlite     = { version = "0.32", features = ["bundled"] }  # Phase 1; bundled avoids system sqlite dep
# lmdb-rkv   = "0.14"      # Phase 5 alternative; evaluate after benchmarks

# JWT / auth
jsonwebtoken = "9"
base64       = "0.22"

# Schema validation (CRDs)
jsonschema   = "0.29"       # OpenAPI v3 structural schema validation; no C deps

# gRPC (for CRI shim in node agent; API server does not use gRPC)
tonic        = "0.12"
prost        = "0.13"

# Compile-time maps
phf          = { version = "0.11", features = ["macros"] }  # Merge key table

# Observability
tracing      = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Allocator (production builds)
jemallocator = "0.5"        # Reduces RSS vs system allocator; enabled via feature flag
```

### kube-rs vs roll your own types

| Dimension | kube-rs (kube + k8s-openapi) | Roll your own |
|---|---|---|
| Completeness | Every upstream field | Only what you implement |
| Binary size | +5–8 MB (k8s-openapi codegen) | Minimal |
| CRD support | Awkward — requires generic `DynamicObject` | Natural — everything is `serde_json::Value` |
| SSA field set extraction | Not provided; must implement | Must implement |
| Maintenance | Tracks upstream K8s releases | Self-contained |
| Risk | Upstream churn; version mismatches | You own every bug |

**Decision: roll your own with the `Object` / hybrid approach from §4.** The kube-rs types are valuable for *client* code (controller manager, node agent) where you need to manipulate typed resources. For the *API server*, which is primarily storing and routing JSON, the overhead is not justified. If the controller manager is written later and uses kube-rs types, ensure the stored JSON format is byte-for-byte compatible with what kube-rs would serialize — it is, because both use standard Kubernetes JSON field names.

**Exception:** The controller manager and node agent may use `kube` as a client library. That does not affect the API server's internal type representation.

---

## 14. Performance Considerations

All hot paths are flagged below. "Hot path" = called on every API request or every watch event.

### Watch fan-out (HOT PATH: O(watchers) per write)

- Pre-serialize the watch event once to `Bytes` before broadcasting.
- Use `tokio::sync::broadcast::channel` for fan-out. Each watch stream holds a `Receiver`.
- Broadcast channel capacity: 1000 events. On overflow, slow receivers get `RecvError::Lagged` — send them a 410 Gone and close the connection.
- Do NOT clone the serialized `Value` per watcher. Clone only the `Bytes` (reference-counted, O(1)).
- Measure: with 10 active watches on Pods and 100 Pod mutations/second, fan-out must complete in < 1 ms total.

```rust
// In the store write path (LMDB or SQLite):
let event_bytes: Bytes = serialize_watch_event("MODIFIED", &obj_bytes).into();
let _ = self.broadcast_tx.send(InternalEvent { prefix: key_prefix, bytes: event_bytes, revision });
// Each watch receiver filters by prefix before forwarding to HTTP.
```

### List with label selectors (HOT PATH: O(objects) per list)

- Label selector filtering is O(objects) — no index. For small clusters (< 1000 objects per resource), this is acceptable.
- **In Phase 2+:** Add an in-memory label index for frequently listed resources (Pods, Deployments). The index is a `HashMap<LabelKey, HashMap<LabelValue, HashSet<ObjectKey>>>`. Update on every write event. Protected by a `RwLock`; reads are concurrent.
- For Argo CD: it lists all resources it cares about once at startup, then watches. The label-selector scan hits at startup; subsequent watches use the event stream. Acceptable.
- **Field selector for `spec.nodeName`:** Critical for node agent scaling. Add a secondary key in SQLite: `CREATE INDEX IF NOT EXISTS pods_nodename ON objects (json_extract(value, '$.spec.nodeName')) WHERE key LIKE '/registry/pods/%'`. This makes `fieldSelector=spec.nodeName=<node>` a single indexed query instead of a full scan.

### RBAC evaluation (HOT PATH: every request)

- The RBAC index is an in-memory `HashMap`. Lookup is O(rules for this subject) ≈ O(1) for small RBAC policies.
- `RwLock` for the index: reads are concurrent (no blocking). Writes only on RBAC object changes (rare).
- Do NOT cache authorization decisions in Phase 1–3. If the policy changes, the cache is stale. The in-memory index is already fast enough.
- If RBAC evaluation is measured to be slow (> 1 μs per request), consider a pre-computed allow-set per (subject, resource, verb) tuple. Invalidate on any RBAC write.

### JSON serialization (HOT PATH: every GET, LIST, watch event)

- For GET responses: store objects as JSON `Bytes` in the store. Serve them directly without deserialization + re-serialization. The handler only needs to inspect `metadata.resourceVersion` (a string parse) and set it on the response. Use `simd-json` or `serde_json` with string manipulation to patch the `resourceVersion` field in the bytes without full parse, or deserialize only `metadata` and reconstruct.
- For LIST responses: the list wrapper (`{"kind":"List","items":[...]}`) must be constructed. Stream the items directly: `{"kind":"PodList",...,"items":[` + join items with `,` + `]}`. Avoid holding all items in memory as `serde_json::Value`; write them incrementally.
- For watch events: pre-serialize once (see above).

### Pagination (Phase 2+)

Without pagination, a `list` of 10,000 Pods serializes all 10,000 objects into a single response. This breaks the RSS budget. Implement cursor-based pagination from Phase 2:

- `limit=500&continue=<token>` returns 500 objects and a `continue` token.
- The token encodes `{prefix, last_key, snapshot_revision}` as base64 JSON.
- Subsequent pages use the same snapshot revision for consistency (the list must be consistent at a single point in time).
- Argo CD uses pagination; client-go's `ListWatch` respects `continue` tokens.

### Connection and task limits

- Cap concurrent watch connections with a semaphore. Default: 1000. Each watch holds a tokio task (~400 bytes) and a broadcast receiver (negligible). At 1000 watches, overhead is ~400 KB — acceptable.
- Cap list response size. If `limit` is not set by the client, apply a server-side default of 500. Return a `continue` token even if unasked.
- Use `tower::limit::ConcurrencyLimitLayer` to cap total in-flight requests to prevent thread pool exhaustion.

### Tokio worker threads

Do not hardcode `worker_threads(2)` unconditionally: a static value tuned for the
control plane's 1-shared-vCPU footprint target becomes a self-imposed bottleneck the
moment the same binary runs on a many-core host (e.g. local dev / conformance
testing), starving the TCP accept loop and TLS handshakes behind other scheduled work
under sustained concurrent load even while idle CPU cores sit unused. Scale to
`std::thread::available_parallelism()`, floored at `2` to preserve the footprint
target on a genuinely single/few-core host:

```rust
fn runtime_worker_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).max(2)
}

tokio::runtime::Builder::new_multi_thread()
    .worker_threads(runtime_worker_threads())
    .thread_stack_size(512 * 1024)
    .enable_all()
    .build()
    .unwrap()
    .block_on(async_main());
```

Still use `thread_stack_size(512 * 1024)` to reduce stack RSS per thread (512 KB vs
tokio's 8 MB default) — that reduction scales with thread count regardless of how
many threads are provisioned.

### Memory allocator

Enable jemalloc in production builds:

```rust
#[cfg(not(test))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;
```

jemalloc typically reduces RSS by 10–20% for server workloads due to better size-class fitting and reduced fragmentation. At a 20–30 MB idle budget for the API server, 5 MB savings is meaningful.

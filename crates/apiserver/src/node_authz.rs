//! Node authorization mode.
//!
//! Scopes a `system:node:<name>` identity (group `system:nodes`) to objects related to its
//! OWN node, modeled on upstream's `plugin/pkg/auth/authorizer/node`. Consulted alongside
//! RBAC (see `AuthService::call` in `auth.rs`): a request is allowed if EITHER this authorizer
//! or RBAC allows it. Since the `system:node` ClusterRoleBinding is now seeded with no
//! subjects (matching upstream bootstrappolicy), RBAC alone grants a kubelet identity nothing
//! — this module is the only thing standing between a compromised node and every other node's
//! secrets, ServiceAccount tokens, and pod statuses.
//!
//! # Graph model
//!
//! A pod's `spec.nodeName` is set exactly once — at creation (a pre-scheduled/static pod) or
//! via the `pods/binding` subresource (`bind_pod`) — and is immutable afterward
//! (`validate_pod_spec_immutable` rejects any PATCH/PUT that touches it). Every other field
//! this module cares about (volumes, env, imagePullSecrets, serviceAccountName) is likewise
//! immutable post-creation. So the graph only needs to be told about a pod ONCE it has a
//! node assignment (`NodeGraph::apply_pod`, called from `create_pod` and `bind_pod`) and told
//! when a pod is gone (`NodeGraph::remove_pod`, called from every hard-delete site in
//! `handlers/pods.rs` and the owner-cascade delete paths in `handlers/resource.rs`) — there is
//! no periodic refresh or reconciliation loop, and none is needed. `AppState::init_node_graph`
//! backfills the graph from already-persisted pods on apiserver restart, mirroring
//! `AppState::init`'s RBAC-index bootstrap.
//!
//! Secret/ConfigMap/PersistentVolumeClaim/ServiceAccount objects themselves are never
//! observed — only pods, and only their reference fields (this is why deleting or mutating a
//! referenced Secret needs no graph update: whether the *edge* exists depends solely on the
//! pod's own (immutable) spec, not on the referenced object's lifecycle).
//!
//! # Scope cuts (documented, not silent)
//!
//! Upstream's graph additionally threads Secret access through a bound PersistentVolume
//! (`pod -> pvc -> pv -> secret`, for CSI drivers that store credentials in a PV's
//! `secretRef`) and subdivides `persistentvolumes`, `volumeattachments`, `csidrivers`, and
//! `resourceslices` individually. u7s doesn't model PV objects at that granularity; those
//! resources fall through to the same static, un-scoped rule match every other unsubdivided
//! `system:node` permission gets (see the `_ =>` arm of `authorize`) — identical to today's
//! behavior, not a regression. Mirror-pod create is authorized by the separate
//! `authorize_pod_create` (it needs the request body, unavailable where `authorize()` runs);
//! it isn't yet called from the pod-create handler, so the `system:node` ClusterRole's
//! `create` grant on pods stays inert until that wiring lands. The SelfSubjectAccessReview/
//! SubjectAccessReview/LocalSubjectAccessReview endpoints (`handlers/authorization.rs`) DO
//! consult this authorizer, via the `authorized()` helper defined there.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::rbac::{self, AuthzRequest, RbacIndex};

const NODE_USERNAME_PREFIX: &str = "system:node:";
const NODES_GROUP: &str = "system:nodes";
const NODE_LEASE_NAMESPACE: &str = "kube-node-lease";
const NODE_CLUSTER_ROLE: &str = "system:node";
const MIRROR_POD_ANNOTATION: &str = "kubernetes.io/config.mirror";

/// Reference edges extracted from a single pod's (immutable, post-creation) spec.
#[derive(Debug, Default, Clone)]
struct PodEdges {
    secrets: HashSet<String>,
    configmaps: HashSet<String>,
    pvcs: HashSet<String>,
    service_account: Option<String>,
}

type PodKey = (String, String); // (namespace, name)

#[derive(Default)]
struct NodeGraphInner {
    pods: HashMap<PodKey, (String /* node_name */, PodEdges)>,
    by_node: HashMap<String, HashSet<PodKey>>,
}

/// The node -> {pods, and what those pods reference} graph. See module docs for the
/// freshness model.
pub struct NodeGraph {
    inner: RwLock<NodeGraphInner>,
}

impl NodeGraph {
    pub fn new() -> Self {
        NodeGraph {
            inner: RwLock::new(NodeGraphInner::default()),
        }
    }

    /// Register a pod's node assignment and reference edges. A no-op when
    /// `spec.nodeName` is empty (not yet scheduled) — there is nothing to record until a
    /// node owns the pod, and `bind_pod`/a later `apply_pod` call will register it once one
    /// does. Safe to call more than once for the same pod (e.g. once at create, once at
    /// bind) since nodeName/edges never change after being set.
    pub fn apply_pod(&self, namespace: &str, name: &str, body: &serde_json::Value) {
        let node_name = body["spec"]["nodeName"].as_str().unwrap_or("");
        if node_name.is_empty() {
            return;
        }
        let edges = extract_pod_edges(body);
        let key: PodKey = (namespace.to_owned(), name.to_owned());
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        inner
            .by_node
            .entry(node_name.to_owned())
            .or_default()
            .insert(key.clone());
        inner.pods.insert(key, (node_name.to_owned(), edges));
    }

    /// Deregister a pod on hard delete. A no-op if the pod was never registered (deleted
    /// before ever being scheduled, or never referenced anything worth tracking).
    pub fn remove_pod(&self, namespace: &str, name: &str) {
        let key: PodKey = (namespace.to_owned(), name.to_owned());
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if let Some((node_name, _)) = inner.pods.remove(&key) {
            if let Some(set) = inner.by_node.get_mut(&node_name) {
                set.remove(&key);
            }
        }
    }

    fn any_pod_edge(
        &self,
        node_name: &str,
        namespace: &str,
        pred: impl Fn(&PodEdges) -> bool,
    ) -> bool {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let Some(keys) = inner.by_node.get(node_name) else {
            return false;
        };
        keys.iter()
            .filter(|(ns, _)| ns == namespace)
            .filter_map(|k| inner.pods.get(k))
            .any(|(_, edges)| pred(edges))
    }

    /// True if a pod named `pod_name` in `namespace` is scheduled on `node_name`.
    pub fn pod_on_node(&self, node_name: &str, namespace: &str, pod_name: &str) -> bool {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner
            .by_node
            .get(node_name)
            .is_some_and(|set| set.contains(&(namespace.to_owned(), pod_name.to_owned())))
    }

    /// True if some pod scheduled on `node_name` references Secret `secret_name`.
    pub fn secret_referenced(&self, node_name: &str, namespace: &str, secret_name: &str) -> bool {
        self.any_pod_edge(node_name, namespace, |e| e.secrets.contains(secret_name))
    }

    /// True if some pod scheduled on `node_name` references ConfigMap `configmap_name`.
    pub fn configmap_referenced(
        &self,
        node_name: &str,
        namespace: &str,
        configmap_name: &str,
    ) -> bool {
        self.any_pod_edge(node_name, namespace, |e| {
            e.configmaps.contains(configmap_name)
        })
    }

    /// True if some pod scheduled on `node_name` references PersistentVolumeClaim `pvc_name`.
    pub fn pvc_referenced(&self, node_name: &str, namespace: &str, pvc_name: &str) -> bool {
        self.any_pod_edge(node_name, namespace, |e| e.pvcs.contains(pvc_name))
    }

    /// True if some pod scheduled on `node_name` runs as ServiceAccount `sa_name`.
    pub fn service_account_used(&self, node_name: &str, namespace: &str, sa_name: &str) -> bool {
        self.any_pod_edge(node_name, namespace, |e| {
            e.service_account.as_deref() == Some(sa_name)
        })
    }
}

impl Default for NodeGraph {
    fn default() -> Self {
        Self::new()
    }
}

fn push_ref(set: &mut HashSet<String>, v: &serde_json::Value) {
    if let Some(s) = v.as_str() {
        if !s.is_empty() {
            set.insert(s.to_owned());
        }
    }
}

/// Pure extraction of a pod's Secret/ConfigMap/PVC/ServiceAccount references from its spec —
/// the same fields kubelet itself must resolve to actually run the pod, listed in the bead:
/// volumes, envFrom, env valueFrom, imagePullSecrets, and projected volume sources.
fn extract_pod_edges(body: &serde_json::Value) -> PodEdges {
    let mut edges = PodEdges::default();
    let spec = &body["spec"];

    if let Some(volumes) = spec["volumes"].as_array() {
        for vol in volumes {
            push_ref(&mut edges.secrets, &vol["secret"]["secretName"]);
            push_ref(&mut edges.configmaps, &vol["configMap"]["name"]);
            push_ref(&mut edges.pvcs, &vol["persistentVolumeClaim"]["claimName"]);
            if let Some(sources) = vol["projected"]["sources"].as_array() {
                for src in sources {
                    push_ref(&mut edges.secrets, &src["secret"]["name"]);
                    push_ref(&mut edges.configmaps, &src["configMap"]["name"]);
                }
            }
        }
    }

    if let Some(pull_secrets) = spec["imagePullSecrets"].as_array() {
        for ps in pull_secrets {
            push_ref(&mut edges.secrets, &ps["name"]);
        }
    }

    for container_field in ["containers", "initContainers", "ephemeralContainers"] {
        let Some(containers) = spec[container_field].as_array() else {
            continue;
        };
        for c in containers {
            if let Some(env_from) = c["envFrom"].as_array() {
                for ef in env_from {
                    push_ref(&mut edges.secrets, &ef["secretRef"]["name"]);
                    push_ref(&mut edges.configmaps, &ef["configMapRef"]["name"]);
                }
            }
            if let Some(env) = c["env"].as_array() {
                for e in env {
                    push_ref(&mut edges.secrets, &e["valueFrom"]["secretKeyRef"]["name"]);
                    push_ref(
                        &mut edges.configmaps,
                        &e["valueFrom"]["configMapKeyRef"]["name"],
                    );
                }
            }
        }
    }

    edges.service_account = spec["serviceAccountName"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    edges
}

/// Parses `username`/`groups` into a node name, matching upstream's
/// `nodeidentifier.NodeIdentifier`: the username must be `system:node:<name>` AND the caller
/// must actually carry the `system:nodes` group — a CN alone (without the matching
/// Organization) is not enough, since x509 CN is client-chosen but O is what the issuing CA
/// controls.
pub(crate) fn node_identity<'a>(username: &'a str, groups: &[String]) -> Option<&'a str> {
    let name = username.strip_prefix(NODE_USERNAME_PREFIX)?;
    if name.is_empty() || !groups.iter().any(|g| g == NODES_GROUP) {
        return None;
    }
    Some(name)
}

/// True if the request's `fieldSelector` query param contains an exact-match
/// `spec.nodeName=<node_name>` term (possibly combined with other terms via `,`, as kubelet's
/// real pod-list/watch query does: `spec.nodeName=<node>,status.phase!=Succeeded,...`).
/// Mirrors upstream's `attrs.GetFieldSelector()` scoped-list check, needed because a bare
/// LIST/WATCH pods request has no `name` for the graph to key off.
fn field_selector_selects_node(query: Option<&str>, node_name: &str) -> bool {
    let Some(query) = query else {
        return false;
    };
    let Some(raw) = query
        .split('&')
        .find_map(|p| p.strip_prefix("fieldSelector="))
    else {
        return false;
    };
    let decoded = crate::auth::percent_decode(raw);
    decoded.split(',').any(|term| {
        let parsed = term.split_once("==").or_else(|| term.split_once('='));
        matches!(parsed, Some(("spec.nodeName", v)) if v == node_name)
    })
}

fn authorize_referenced_object(
    req: &AuthzRequest<'_>,
    check: impl FnOnce(&str, &str) -> bool,
) -> bool {
    if !matches!(req.verb, "get" | "list" | "watch") || !req.subresource.is_empty() {
        return false;
    }
    let (Some(ns), Some(name)) = (req.namespace, req.name) else {
        return false;
    };
    check(ns, name)
}

fn authorize_pvc(node_name: &str, req: &AuthzRequest<'_>, graph: &NodeGraph) -> bool {
    let (Some(ns), Some(name)) = (req.namespace, req.name) else {
        return false;
    };
    match (req.subresource, req.verb) {
        ("", "get") => graph.pvc_referenced(node_name, ns, name),
        ("status", "update") | ("status", "patch") => graph.pvc_referenced(node_name, ns, name),
        _ => false,
    }
}

fn authorize_sa_token(node_name: &str, req: &AuthzRequest<'_>, graph: &NodeGraph) -> bool {
    if req.verb != "create" {
        return false;
    }
    let (Some(ns), Some(name)) = (req.namespace, req.name) else {
        return false;
    };
    graph.service_account_used(node_name, ns, name)
}

fn authorize_lease(node_name: &str, req: &AuthzRequest<'_>) -> bool {
    if !matches!(req.verb, "get" | "create" | "update" | "patch" | "delete") {
        return false;
    }
    if req.namespace != Some(NODE_LEASE_NAMESPACE) {
        return false;
    }
    if req.verb == "create" {
        // The authorizer can't know the target name on create (no name in the URL); the
        // request body's name is checked by admission upstream. u7s has no such admission
        // plugin — this is a narrow, documented gap identical to upstream's own posture.
        return true;
    }
    req.name == Some(node_name)
}

fn authorize_node(node_name: &str, req: &AuthzRequest<'_>) -> bool {
    match req.subresource {
        "" => match req.verb {
            // Self-registration: no name in the URL for a plain POST, so this can't be
            // scoped to "own node only" at this layer (same gap as leases' create, above).
            "create" => true,
            "get" | "list" | "watch" | "update" | "patch" => req.name == Some(node_name),
            _ => false,
        },
        "status" => matches!(req.verb, "update" | "patch") && req.name == Some(node_name),
        _ => false,
    }
}

fn authorize_pod(
    node_name: &str,
    req: &AuthzRequest<'_>,
    raw_query: Option<&str>,
    graph: &NodeGraph,
) -> bool {
    // A named single-pod check (get/delete/status/log, or the name-fallback branch of
    // list/watch below) always needs a namespace+name pair against the graph. The
    // fieldSelector=spec.nodeName=<node> list/watch path does NOT — a real kubelet's pod
    // informer lists ALL namespaces (`GET /api/v1/pods?fieldSelector=...`), matching
    // upstream's own `authorizePod`, which never calls `attrs.GetNamespace()` on that path
    // either. Requiring a namespace here would 403 every real kubelet's pod informer.
    let owns = |n: &str| {
        req.namespace
            .is_some_and(|ns| graph.pod_on_node(node_name, ns, n))
    };
    match req.subresource {
        "" => match req.verb {
            "get" | "delete" => req.name.is_some_and(owns),
            "list" | "watch" => {
                field_selector_selects_node(raw_query, node_name) || req.name.is_some_and(owns)
            }
            // Deliberately denied, not an oversight: telling a mirror pod (bound to this
            // node) apart from any other pod needs the request body (the
            // `kubernetes.io/config.mirror` annotation and `spec.nodeName`), which isn't
            // available here — `authorize()` runs in `AuthService::call` before the body is
            // read (see module doc). See `authorize_pod_create`, called directly by the
            // create handler once the body is parsed.
            "create" => false,
            _ => false,
        },
        "status" => matches!(req.verb, "get" | "update" | "patch") && req.name.is_some_and(owns),
        "log" => req.verb == "get" && req.name.is_some_and(owns),
        _ => false,
    }
}

/// Authorizes a pod CREATE for a `system:node:<name>` identity, mirroring upstream's
/// NodeRestriction admission-plugin semantics (`plugin/pkg/admission/noderestriction`): only
/// a mirror pod (carries the `kubernetes.io/config.mirror` annotation) bound to the
/// requesting node's own `spec.nodeName` may be created this way — kubelet's mechanism for
/// registering one of its own locally-run static pods. Anything else (a non-mirror pod, or a
/// mirror pod claiming a different node) is denied.
///
/// Not reachable from `authorize()`/`authorize_pod` above — see the `"create" => false` arm's
/// comment for why the pod body can't reach that layer. Call this directly wherever the
/// create request's body has already been parsed (e.g. the pod-create handler); not wired up
/// yet (`handlers/pods.rs` is a separate, concurrently-owned change), hence `dead_code`
/// outside test builds.
#[cfg_attr(not(test), allow(dead_code))]
pub fn authorize_pod_create(
    username: &str,
    groups: &[String],
    pod_body: &serde_json::Value,
) -> bool {
    let Some(node_name) = node_identity(username, groups) else {
        return false;
    };
    let is_mirror_pod = pod_body["metadata"]["annotations"]
        .get(MIRROR_POD_ANNOTATION)
        .is_some();
    is_mirror_pod && pod_body["spec"]["nodeName"].as_str() == Some(node_name)
}

const NODE_RESTRICTION_LABEL_NAMESPACE: &str = "node-restriction.kubernetes.io";

/// Labels kubelet itself is known to set on its own Node object at registration, taken from
/// upstream's `k8s.io/kubelet/pkg/apis.KubeletLabels()` (release-1.36) — anything else in the
/// `kubernetes.io`/`k8s.io` namespace family is reserved for controllers/humans, not a node.
const KUBELET_LABELS: &[&str] = &[
    "kubernetes.io/hostname",
    "topology.kubernetes.io/zone",
    "topology.kubernetes.io/region",
    "failure-domain.beta.kubernetes.io/zone",
    "failure-domain.beta.kubernetes.io/region",
    "beta.kubernetes.io/instance-type",
    "node.kubernetes.io/instance-type",
    "kubernetes.io/os",
    "kubernetes.io/arch",
    "beta.kubernetes.io/os",
    "beta.kubernetes.io/arch",
];

/// Label namespaces kubelet may freely set under, per upstream's `KubeletLabelNamespaces()`.
const KUBELET_LABEL_NAMESPACES: &[&str] = &["kubelet.kubernetes.io", "node.kubernetes.io"];

fn label_namespace(key: &str) -> &str {
    key.split_once('/').map_or("", |(ns, _)| ns)
}

fn namespace_is_or_ends_with(namespace: &str, suffix: &str) -> bool {
    namespace == suffix || namespace.ends_with(&format!(".{suffix}"))
}

fn is_kubelet_label(key: &str) -> bool {
    KUBELET_LABELS.contains(&key)
        || KUBELET_LABEL_NAMESPACES
            .iter()
            .any(|ns| namespace_is_or_ends_with(label_namespace(key), ns))
}

fn is_kubernetes_label(key: &str) -> bool {
    let ns = label_namespace(key);
    namespace_is_or_ends_with(ns, "kubernetes.io") || namespace_is_or_ends_with(ns, "k8s.io")
}

/// Mirrors upstream's `getForbiddenLabels` (NodeRestriction admission,
/// `plugin/pkg/admission/noderestriction/admission.go`, release-1.36): a node may never
/// set/change a `node-restriction.kubernetes.io/*` label — that namespace exists precisely so
/// an RBAC-holding human/controller can place a trust marker a compromised kubelet cannot forge
/// for itself — nor any other `kubernetes.io`/`k8s.io` label outside the fixed set kubelet is
/// actually known to set (`is_kubelet_label`).
fn is_forbidden_node_label(key: &str) -> bool {
    namespace_is_or_ends_with(label_namespace(key), NODE_RESTRICTION_LABEL_NAMESPACE)
        || (is_kubernetes_label(key) && !is_kubelet_label(key))
}

/// First label key that changed value between `old`/`new` (mirrors upstream's
/// `getModifiedLabels`, which diffs both directions) AND is forbidden for a node to touch.
fn first_forbidden_modified_label(
    old: Option<&serde_json::Map<String, serde_json::Value>>,
    new: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Option<String> {
    let empty = serde_json::Map::new();
    let old = old.unwrap_or(&empty);
    let new = new.unwrap_or(&empty);
    old.keys()
        .chain(new.keys())
        .find(|k| old.get(k.as_str()) != new.get(k.as_str()) && is_forbidden_node_label(k))
        .cloned()
}

/// `true` for anything JSON would consider "actually set" — a bare absent/null field and an
/// explicit empty string/array both count as unset, matching how a real kubelet's client-go
/// struct marshals a zero-value field (it doesn't emit a literal `""`/`[]`, but some client
/// bodies do, and either must be treated as "no opinion", not as an assignment attempt).
fn field_is_set(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        _ => true,
    }
}

/// `true` if two possibly-array-or-null JSON values are the same once "absent" and "present but
/// empty" are treated as equivalent — needed for `spec.taints`/`metadata.ownerReferences` below,
/// since a client that never touches an empty array field commonly round-trips it as JSON
/// `null` instead of `[]`, which a plain `!=` would wrongly flag as "the node changed this".
fn array_or_null_eq(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    let is_empty = |v: &serde_json::Value| {
        matches!(v, serde_json::Value::Null)
            || matches!(v, serde_json::Value::Array(a) if a.is_empty())
    };
    if is_empty(a) && is_empty(b) {
        true
    } else {
        a == b
    }
}

/// NodeRestriction-equivalent admission for a `system:node:<name>` identity's own Node
/// create/update, mirroring upstream's `admitNode`
/// (`plugin/pkg/admission/noderestriction/admission.go`, release-1.36). `authorize_node` above
/// grants such an identity the same *broad* verb access upstream's own Node authorizer does
/// (full-object create/update/patch, not just `nodes/status`) and — like upstream — relies on
/// this check, not a narrower RBAC/authorizer grant, to restrict which fields that access can
/// actually touch. `old_node` is `None` on create.
///
/// `spec.podCIDR`/`spec.podCIDRs`/`spec.providerID` additionally get a from-empty-once-only
/// immutability check regardless of caller identity (`validate_node_spec_immutable`,
/// handlers/resource.rs) — upstream doesn't need an equivalent rule here because its
/// `system:node` ClusterRole never grants a plain (non-`status`) node update/patch at all, so a
/// kubelet can't reach `spec.podCIDR` in the first place. u7s's Node authorizer, by design,
/// grants that broader access instead (matching upstream's *newer*, admission-gated
/// `AuthorizeNodeWithSelectors` posture) — which makes this the ONLY thing stopping a
/// compromised kubelet from self-assigning its own pod CIDR / cloud-provider ID, so it is
/// forbidden unconditionally rather than only "once already set".
pub fn restrict_node_self_write(
    username: &str,
    groups: &[String],
    requested_name: &str,
    old_node: Option<&serde_json::Value>,
    new_node: &serde_json::Value,
) -> Result<(), String> {
    let Some(node_name) = node_identity(username, groups) else {
        return Ok(());
    };
    if requested_name != node_name {
        return Err(format!(
            "node {node_name:?} is not allowed to modify node {requested_name:?}"
        ));
    }

    let no_spec = serde_json::Value::Null;
    let old_spec = old_node.map_or(&no_spec, |n| &n["spec"]);
    let new_spec = &new_node["spec"];

    for field in ["podCIDR", "podCIDRs", "providerID", "configSource"] {
        if field_is_set(&new_spec[field]) && new_spec[field] != old_spec[field] {
            return Err(format!(
                "node {node_name:?} is not allowed to set spec.{field} — only a controller \
                 may assign it"
            ));
        }
    }

    // Taints/ownerReferences steer which workloads land on this node and who owns it; upstream
    // only checks these on UPDATE (a fresh registration's taints come from kubelet's own
    // `--register-with-taints` flag and are legitimate), hence the `old_node.is_some()` guard.
    if let Some(old) = old_node {
        if !array_or_null_eq(&new_spec["taints"], &old["spec"]["taints"]) {
            return Err(format!(
                "node {node_name:?} is not allowed to modify spec.taints"
            ));
        }
        if !array_or_null_eq(
            &new_node["metadata"]["ownerReferences"],
            &old["metadata"]["ownerReferences"],
        ) {
            return Err(format!(
                "node {node_name:?} is not allowed to modify metadata.ownerReferences"
            ));
        }
    }

    let old_labels = old_node.and_then(|n| n["metadata"]["labels"].as_object());
    let new_labels = new_node["metadata"]["labels"].as_object();
    if let Some(label) = first_forbidden_modified_label(old_labels, new_labels) {
        return Err(format!(
            "node {node_name:?} is not allowed to set label {label:?}"
        ));
    }

    Ok(())
}

/// Node authorization entry point. Returns `true` only for a genuine `system:node:<name>`
/// identity whose request targets something related to `<name>`'s own node; `false`
/// otherwise (including for every non-node caller), so callers must OR this with a normal
/// RBAC check rather than treat `false` as an explicit deny — matching upstream's
/// `DecisionNoOpinion` semantics, and how `AuthService::call` actually wires this in.
///
/// `raw_query` is the incoming request's raw HTTP query string (`req.uri().query()`), used
/// only to recognize kubelet's `fieldSelector=spec.nodeName=<node>` pod-list/watch pattern.
pub fn authorize(
    req: &AuthzRequest<'_>,
    raw_query: Option<&str>,
    graph: &NodeGraph,
    rbac_index: &RbacIndex,
) -> bool {
    let Some(node_name) = node_identity(req.username, req.groups) else {
        return false;
    };

    match (req.api_group, req.resource) {
        ("", "secrets") => authorize_referenced_object(req, |ns, name| {
            graph.secret_referenced(node_name, ns, name)
        }),
        ("", "configmaps") => authorize_referenced_object(req, |ns, name| {
            graph.configmap_referenced(node_name, ns, name)
        }),
        ("", "persistentvolumeclaims") => authorize_pvc(node_name, req, graph),
        ("", "serviceaccounts") if req.subresource == "token" => {
            authorize_sa_token(node_name, req, graph)
        }
        ("coordination.k8s.io", "leases") => authorize_lease(node_name, req),
        ("", "nodes") => authorize_node(node_name, req),
        ("", "pods") => authorize_pod(node_name, req, raw_query, graph),
        // Not subdivided by node: fall back to the same plain rule match RBAC would do
        // against the `system:node` ClusterRole's own rules (services, events, csinodes,
        // csidrivers, persistentvolumes, volumeattachments, SAR/TokenReview/CSR creation,
        // ...). Reusing `cluster_role_rules` (rather than a hand-copied rule list) means this
        // stays correct if the seeded ClusterRole is ever edited.
        _ => rbac::rules_allow(&rbac_index.cluster_role_rules(NODE_CLUSTER_ROLE), req),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod_body(node_name: &str, sa: &str) -> serde_json::Value {
        serde_json::json!({
            "spec": {
                "nodeName": node_name,
                "serviceAccountName": sa,
                "volumes": [
                    {"name": "v1", "secret": {"secretName": "vol-secret"}},
                    {"name": "v2", "configMap": {"name": "vol-cm"}},
                    {"name": "v3", "persistentVolumeClaim": {"claimName": "vol-pvc"}},
                    {"name": "v4", "projected": {"sources": [
                        {"secret": {"name": "proj-secret"}},
                        {"configMap": {"name": "proj-cm"}},
                    ]}},
                ],
                "imagePullSecrets": [{"name": "pull-secret"}],
                "containers": [{
                    "name": "c",
                    "envFrom": [
                        {"secretRef": {"name": "envfrom-secret"}},
                        {"configMapRef": {"name": "envfrom-cm"}},
                    ],
                    "env": [
                        {"name": "A", "valueFrom": {"secretKeyRef": {"name": "envval-secret", "key": "k"}}},
                        {"name": "B", "valueFrom": {"configMapKeyRef": {"name": "envval-cm", "key": "k"}}},
                    ],
                }],
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn node_req<'a>(
        node: &'a str,
        groups: &'a [String],
        verb: &'a str,
        api_group: &'a str,
        resource: &'a str,
        subresource: &'a str,
        namespace: Option<&'a str>,
        name: Option<&'a str>,
    ) -> AuthzRequest<'a> {
        AuthzRequest {
            username: node,
            groups,
            verb,
            api_group,
            resource,
            subresource,
            namespace,
            name,
            non_resource_url: None,
        }
    }

    // -----------------------------------------------------------------------
    // extract_pod_edges: every reference kind the bead calls out must be found, and only
    // those — a missed one silently reopens the exact secret-exfiltration path this
    // authorizer exists to close; an over-eager one would falsely grant access.
    // -----------------------------------------------------------------------

    #[test]
    fn extract_pod_edges_finds_every_reference_kind() {
        let body = pod_body("node-a", "sa-a");
        let edges = extract_pod_edges(&body);
        for expect in [
            "vol-secret",
            "proj-secret",
            "pull-secret",
            "envfrom-secret",
            "envval-secret",
        ] {
            assert!(
                edges.secrets.contains(expect),
                "must extract secret ref '{expect}' — a missed one lets a real kubelet's own \
                 mounted secret 403, breaking the pod it's supposed to run"
            );
        }
        for expect in ["vol-cm", "proj-cm", "envfrom-cm", "envval-cm"] {
            assert!(
                edges.configmaps.contains(expect),
                "must extract configmap ref '{expect}'"
            );
        }
        assert!(edges.pvcs.contains("vol-pvc"));
        assert_eq!(edges.service_account.as_deref(), Some("sa-a"));
        assert_eq!(edges.secrets.len(), 5, "must not invent extra secret refs");
    }

    #[test]
    fn extract_pod_edges_unscheduled_pod_has_no_node_name_and_is_never_registered() {
        // apply_pod must no-op for a pod with no nodeName — asserted via the graph, since
        // extract_pod_edges itself doesn't look at nodeName at all.
        let graph = NodeGraph::new();
        let body = serde_json::json!({"spec": {"serviceAccountName": "sa-a"}});
        graph.apply_pod("default", "pending-pod", &body);
        assert!(
            !graph.pod_on_node("", "default", "pending-pod"),
            "a pod with no nodeName must not be attributed to any node"
        );
    }

    // -----------------------------------------------------------------------
    // The bead's core invariant: node A's identity must reach only node A's own objects.
    // Each test below fails on a revert to a subject-full `system:node` binding (the bug),
    // because that binding path is gone — only this authorizer's graph check stands between
    // node A and node B's secrets/tokens/pods.
    // -----------------------------------------------------------------------

    /// A minimal pod body referencing exactly one Secret, distinct per pod — unlike
    /// `pod_body` above (which hardcodes the same reference names for every pod, fine for
    /// exercising extraction logic once but WRONG for a two-node fixture: if pod-a and pod-b
    /// referenced the same secret name, "node-a can read its own secret" and "node-a can
    /// read node-b's secret" would be indistinguishable).
    fn scoped_pod_body(node_name: &str, sa: &str, secret: &str) -> serde_json::Value {
        serde_json::json!({
            "spec": {
                "nodeName": node_name,
                "serviceAccountName": sa,
                "containers": [{"name": "c", "envFrom": [{"secretRef": {"name": secret}}]}],
            }
        })
    }

    fn seeded_graph() -> NodeGraph {
        let graph = NodeGraph::new();
        graph.apply_pod(
            "default",
            "pod-a",
            &scoped_pod_body("node-a", "sa-a", "secret-a"),
        );
        graph.apply_pod(
            "default",
            "pod-b",
            &scoped_pod_body("node-b", "sa-b", "secret-b"),
        );
        graph
    }

    #[test]
    fn node_cannot_read_secret_referenced_only_by_another_nodes_pod() {
        let graph = seeded_graph();
        let idx = RbacIndex::new();
        let groups = vec![NODES_GROUP.to_owned()];
        // node-a's identity asking for a secret only pod-b (on node-b) references.
        let req = node_req(
            "system:node:node-a",
            &groups,
            "get",
            "",
            "secrets",
            "",
            Some("default"),
            Some("secret-b"),
        );
        assert!(
            !authorize(&req, None, &graph, &idx),
            "a compromised node-a must NOT be able to read a secret mounted only by a pod on \
             node-b — that is exactly the cross-node secret exfiltration this authorizer exists \
             to stop"
        );
    }

    #[test]
    fn node_can_read_secret_referenced_by_its_own_pod() {
        let graph = seeded_graph();
        let idx = RbacIndex::new();
        let groups = vec![NODES_GROUP.to_owned()];
        let req = node_req(
            "system:node:node-a",
            &groups,
            "get",
            "",
            "secrets",
            "",
            Some("default"),
            Some("secret-a"),
        );
        assert!(
            authorize(&req, None, &graph, &idx),
            "node-a must still be able to read a secret its own pod actually mounts, or every \
             real pod on that node fails to start"
        );
    }

    #[test]
    fn node_cannot_mint_token_for_service_account_not_used_by_its_own_pods() {
        let graph = seeded_graph();
        let idx = RbacIndex::new();
        let groups = vec![NODES_GROUP.to_owned()];
        // node-a asking to mint a token for sa-b, which only runs on node-b.
        let req = node_req(
            "system:node:node-a",
            &groups,
            "create",
            "",
            "serviceaccounts",
            "token",
            Some("default"),
            Some("sa-b"),
        );
        assert!(
            !authorize(&req, None, &graph, &idx),
            "node-a must NOT be able to mint a bound token for sa-b — sa-b belongs to a pod on \
             node-b, and a forged token is a direct escalation to whatever RBAC sa-b holds"
        );
    }

    #[test]
    fn node_can_mint_token_for_its_own_pods_service_account() {
        let graph = seeded_graph();
        let idx = RbacIndex::new();
        let groups = vec![NODES_GROUP.to_owned()];
        let req = node_req(
            "system:node:node-a",
            &groups,
            "create",
            "",
            "serviceaccounts",
            "token",
            Some("default"),
            Some("sa-a"),
        );
        assert!(
            authorize(&req, None, &graph, &idx),
            "node-a must be able to mint a projected token for sa-a, the ServiceAccount its \
             own pod actually runs as, or every in-cluster API call from that pod breaks"
        );
    }

    #[test]
    fn node_cannot_patch_status_of_a_pod_scheduled_on_another_node() {
        let graph = seeded_graph();
        let idx = RbacIndex::new();
        let groups = vec![NODES_GROUP.to_owned()];
        let req = node_req(
            "system:node:node-a",
            &groups,
            "patch",
            "",
            "pods",
            "status",
            Some("default"),
            Some("pod-b"),
        );
        assert!(
            !authorize(&req, None, &graph, &idx),
            "node-a must NOT be able to patch pod-b's status — pod-b runs on node-b; allowing \
             this lets one compromised kubelet forge status (podIP, phase) for pods everywhere, \
             feeding the pod-proxy SSRF surface"
        );
    }

    #[test]
    fn node_can_patch_status_of_its_own_pod() {
        let graph = seeded_graph();
        let idx = RbacIndex::new();
        let groups = vec![NODES_GROUP.to_owned()];
        let req = node_req(
            "system:node:node-a",
            &groups,
            "patch",
            "",
            "pods",
            "status",
            Some("default"),
            Some("pod-a"),
        );
        assert!(
            authorize(&req, None, &graph, &idx),
            "node-a must still be able to patch pod-a's own status — this is the routine \
             kubelet status-report path every running pod depends on"
        );
    }

    // -----------------------------------------------------------------------
    // authorize_pod_create: kubelet's mirror-pod registration path. A body-blind pass here
    // would let a compromised kubelet directly schedule arbitrary pods (bypassing the
    // scheduler) or forge another node's static-pod mirror — these tests fail if either gap
    // reopens.
    // -----------------------------------------------------------------------

    fn mirror_pod_body(node_name: &str) -> serde_json::Value {
        serde_json::json!({
            "metadata": { "annotations": { "kubernetes.io/config.mirror": "abc123" } },
            "spec": { "nodeName": node_name },
        })
    }

    #[test]
    fn node_can_create_a_mirror_pod_bound_to_itself() {
        let groups = vec![NODES_GROUP.to_owned()];
        assert!(
            authorize_pod_create("system:node:node-a", &groups, &mirror_pod_body("node-a")),
            "a kubelet registering its own static pod as a mirror pod must be allowed to \
             create it — denying this breaks static pod support entirely"
        );
    }

    #[test]
    fn node_cannot_create_a_non_mirror_pod() {
        let groups = vec![NODES_GROUP.to_owned()];
        let body = serde_json::json!({"spec": {"nodeName": "node-a"}});
        assert!(
            !authorize_pod_create("system:node:node-a", &groups, &body),
            "a node must NOT be able to create an ordinary (non-mirror) pod — that would let \
             a compromised kubelet directly schedule arbitrary pods onto itself, bypassing \
             the scheduler entirely"
        );
    }

    #[test]
    fn node_cannot_create_a_mirror_pod_bound_to_a_different_node() {
        let groups = vec![NODES_GROUP.to_owned()];
        assert!(
            !authorize_pod_create("system:node:node-a", &groups, &mirror_pod_body("node-b")),
            "node-a must NOT be able to register a mirror pod claiming node-b — that would \
             let one compromised kubelet forge another node's static-pod mirror"
        );
    }

    #[test]
    fn node_can_list_pods_scoped_to_its_own_node_via_field_selector() {
        // Regression test: a real kubelet's pod informer lists ALL namespaces
        // (`GET /api/v1/pods?fieldSelector=spec.nodeName=<node>,...`, matching u7s's own
        // core.rs cluster-wide-pod-watch path and upstream's authorizePod, which never
        // checks GetNamespace() on this branch) — namespace is None here, not "default".
        // An earlier version of authorize_pod required a namespace unconditionally and
        // 403'd this exact request; caught live against a real apiserver, not by a unit
        // test with a namespace-carrying fixture that happened to sidestep the bug.
        let graph = seeded_graph();
        let idx = RbacIndex::new();
        let groups = vec![NODES_GROUP.to_owned()];
        let req = node_req(
            "system:node:node-a",
            &groups,
            "list",
            "",
            "pods",
            "",
            None,
            None,
        );
        assert!(
            authorize(
                &req,
                Some("fieldSelector=spec.nodeName%3Dnode-a%2Cstatus.phase!%3DSucceeded"),
                &graph,
                &idx
            ),
            "node-a's own pod informer (fieldSelector=spec.nodeName=node-a,...) must still be \
             authorized even as a cluster-wide (no-namespace) list — this is how a real \
             kubelet builds its whole view of cluster state"
        );
    }

    #[test]
    fn node_cannot_list_all_pods_with_another_nodes_field_selector() {
        let graph = seeded_graph();
        let idx = RbacIndex::new();
        let groups = vec![NODES_GROUP.to_owned()];
        let req = node_req(
            "system:node:node-a",
            &groups,
            "list",
            "",
            "pods",
            "",
            Some("default"),
            None,
        );
        assert!(
            !authorize(
                &req,
                Some("fieldSelector=spec.nodeName%3Dnode-b"),
                &graph,
                &idx
            ),
            "node-a must not be able to list node-b's pods by simply spoofing the \
             fieldSelector — the selector's node must match the caller's own identity"
        );
    }

    #[test]
    fn node_cannot_get_or_patch_another_nodes_node_object() {
        let idx = RbacIndex::new();
        let graph = NodeGraph::new();
        let groups = vec![NODES_GROUP.to_owned()];
        let get_req = node_req(
            "system:node:node-a",
            &groups,
            "get",
            "",
            "nodes",
            "",
            None,
            Some("node-b"),
        );
        assert!(
            !authorize(&get_req, None, &graph, &idx),
            "node-a must not be able to read node-b's Node object"
        );
        let patch_req = node_req(
            "system:node:node-a",
            &groups,
            "patch",
            "",
            "nodes",
            "status",
            None,
            Some("node-b"),
        );
        assert!(
            !authorize(&patch_req, None, &graph, &idx),
            "node-a must not be able to patch node-b's Node status"
        );
    }

    #[test]
    fn node_can_get_and_patch_its_own_node_object() {
        let idx = RbacIndex::new();
        let graph = NodeGraph::new();
        let groups = vec![NODES_GROUP.to_owned()];
        let get_req = node_req(
            "system:node:node-a",
            &groups,
            "get",
            "",
            "nodes",
            "",
            None,
            Some("node-a"),
        );
        assert!(authorize(&get_req, None, &graph, &idx));
        let patch_req = node_req(
            "system:node:node-a",
            &groups,
            "patch",
            "",
            "nodes",
            "status",
            None,
            Some("node-a"),
        );
        assert!(authorize(&patch_req, None, &graph, &idx));
    }

    #[test]
    fn node_can_only_touch_its_own_named_lease() {
        let idx = RbacIndex::new();
        let graph = NodeGraph::new();
        let groups = vec![NODES_GROUP.to_owned()];
        let own = node_req(
            "system:node:node-a",
            &groups,
            "update",
            "coordination.k8s.io",
            "leases",
            "",
            Some("kube-node-lease"),
            Some("node-a"),
        );
        assert!(authorize(&own, None, &graph, &idx));
        let other = node_req(
            "system:node:node-a",
            &groups,
            "update",
            "coordination.k8s.io",
            "leases",
            "",
            Some("kube-node-lease"),
            Some("node-b"),
        );
        assert!(
            !authorize(&other, None, &graph, &idx),
            "node-a must not be able to update node-b's heartbeat Lease"
        );
    }

    #[test]
    fn non_node_identity_gets_no_opinion_regardless_of_graph_state() {
        // A plain authenticated user (not system:node:*) must never be granted anything by
        // this authorizer — it must fall straight through to RBAC, unaffected.
        let graph = seeded_graph();
        let idx = RbacIndex::new();
        let groups = vec!["system:authenticated".to_owned()];
        let req = node_req(
            "alice",
            &groups,
            "get",
            "",
            "secrets",
            "",
            Some("default"),
            Some("secret-a"),
        );
        assert!(!authorize(&req, None, &graph, &idx));
    }

    #[test]
    fn cn_without_the_system_nodes_group_is_not_treated_as_a_node() {
        // The CN half of an x509 subject is client-chosen; only the issuing CA controls O.
        // Trusting CN alone would let anyone self-sign a "system:node:victim" CN and inherit
        // victim's scoped access without ever being a real node.
        let graph = seeded_graph();
        let idx = RbacIndex::new();
        let groups = vec!["system:authenticated".to_owned()];
        let req = node_req(
            "system:node:node-a",
            &groups,
            "get",
            "",
            "secrets",
            "",
            Some("default"),
            Some("secret-a"),
        );
        assert!(!authorize(&req, None, &graph, &idx));
    }

    #[test]
    fn unsubdivided_resource_falls_back_to_the_system_node_cluster_role_rules() {
        // "services" isn't graph-scoped (matches upstream); a node must still get it from the
        // ClusterRole's own (unbound) rules, not from the emptied ClusterRoleBinding.
        let idx = RbacIndex::new();
        idx.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/system:node",
            &serde_json::json!({"rules": [
                {"apiGroups": [""], "resources": ["services"], "verbs": ["get", "list", "watch"]}
            ]}),
        );
        let graph = NodeGraph::new();
        let groups = vec![NODES_GROUP.to_owned()];
        let req = node_req(
            "system:node:node-a",
            &groups,
            "list",
            "",
            "services",
            "",
            None,
            None,
        );
        assert!(
            authorize(&req, None, &graph, &idx),
            "a resource the Node authorizer doesn't subdivide must still fall back to the \
             system:node ClusterRole's rules, or kubelet's service-discovery informer breaks \
             even though the ClusterRole itself was never touched by this fix"
        );
    }

    #[test]
    fn removed_pod_no_longer_authorizes_access_to_what_it_referenced() {
        let graph = seeded_graph();
        let idx = RbacIndex::new();
        let groups = vec![NODES_GROUP.to_owned()];
        graph.remove_pod("default", "pod-a");
        let req = node_req(
            "system:node:node-a",
            &groups,
            "get",
            "",
            "secrets",
            "",
            Some("default"),
            Some("secret-a"),
        );
        assert!(
            !authorize(&req, None, &graph, &idx),
            "once pod-a is hard-deleted, node-a must lose access to what only pod-a \
             referenced — permissions must not outlive the object that granted them"
        );
    }

    // -----------------------------------------------------------------------
    // restrict_node_self_write: node_authz's own-node "" subresource grant above hands a
    // system:node identity update/patch on the FULL Node object, not just status — this is the
    // NodeRestriction-equivalent admission that must narrow it back down, or a single
    // compromised kubelet can rewrite its own Node's networking/scheduling fields (SSRF via a
    // forged podCIDR, workload steering via forged taints/labels) with nothing else in u7s
    // standing in the way.
    // -----------------------------------------------------------------------

    fn own_node(fields: serde_json::Value) -> serde_json::Value {
        let mut body = serde_json::json!({"metadata": {"name": "node-a"}, "spec": {}});
        if let Some(spec) = fields.get("spec") {
            body["spec"] = spec.clone();
        }
        if let Some(metadata) = fields.get("metadata") {
            for (k, v) in metadata.as_object().unwrap() {
                body["metadata"][k] = v.clone();
            }
        }
        body
    }

    #[test]
    fn node_cannot_set_its_own_pod_cidr_from_empty() {
        let groups = vec![NODES_GROUP.to_owned()];
        let old = own_node(serde_json::json!({}));
        let new = own_node(serde_json::json!({"spec": {"podCIDR": "10.244.99.0/24"}}));
        assert!(
            restrict_node_self_write("system:node:node-a", &groups, "node-a", Some(&old), &new)
                .is_err(),
            "a compromised kubelet must not be able to self-assign spec.podCIDR — this is the \
             live-confirmed PATCH (empty -> attacker value, 200 OK) this admission check exists \
             to close, since only kube-controller-manager's node-ipam-controller may assign it"
        );
    }

    #[test]
    fn node_cannot_set_its_own_taints() {
        let groups = vec![NODES_GROUP.to_owned()];
        let old = own_node(serde_json::json!({}));
        let new = own_node(serde_json::json!({"spec": {"taints": [
            {"key": "evil", "effect": "NoSchedule"}
        ]}}));
        assert!(
            restrict_node_self_write("system:node:node-a", &groups, "node-a", Some(&old), &new)
                .is_err(),
            "a compromised kubelet must not be able to add/remove its own taints — that would \
             let it steer disallowed workloads onto (or away from) itself"
        );
    }

    #[test]
    fn node_cannot_set_provider_id_or_config_source() {
        let groups = vec![NODES_GROUP.to_owned()];
        let old = own_node(serde_json::json!({}));
        for (field, value) in [
            (
                "providerID",
                serde_json::json!("aws:///us-east-1a/i-abc123"),
            ),
            (
                "configSource",
                serde_json::json!({"configMap": {"name": "evil"}}),
            ),
        ] {
            let mut new = own_node(serde_json::json!({}));
            new["spec"][field] = value;
            assert!(
                restrict_node_self_write("system:node:node-a", &groups, "node-a", Some(&old), &new)
                    .is_err(),
                "a compromised kubelet must not be able to set spec.{field} — configSource is a \
                 documented view-escalation vector upstream forbids for the same reason"
            );
        }
    }

    #[test]
    fn node_cannot_set_a_node_restriction_label_on_itself() {
        let groups = vec![NODES_GROUP.to_owned()];
        let old = own_node(serde_json::json!({}));
        let new = own_node(serde_json::json!({"metadata": {"labels": {
            "node-restriction.kubernetes.io/trusted": "true"
        }}}));
        assert!(
            restrict_node_self_write("system:node:node-a", &groups, "node-a", Some(&old), &new)
                .is_err(),
            "a compromised kubelet must not be able to forge a node-restriction.kubernetes.io/* \
             label on itself — that namespace exists so only RBAC-holding humans/controllers, \
             never a node, can place a trust marker workloads are scheduled against"
        );
    }

    #[test]
    fn node_can_still_register_itself_with_ordinary_kubelet_labels_and_taints() {
        // The kubelet registration flow this fix must not break: a fresh node's CREATE body
        // legitimately carries standard kubernetes.io labels and --register-with-taints.
        let groups = vec![NODES_GROUP.to_owned()];
        let new = own_node(serde_json::json!({
            "metadata": {"labels": {
                "kubernetes.io/hostname": "node-a",
                "kubernetes.io/os": "linux",
                "kubernetes.io/arch": "amd64",
            }},
            "spec": {"taints": [{"key": "node.kubernetes.io/not-ready", "effect": "NoSchedule"}]},
        }));
        assert!(
            restrict_node_self_write("system:node:node-a", &groups, "node-a", None, &new).is_ok(),
            "kubelet's own node registration (standard labels + --register-with-taints) must \
             still succeed, or every real node in the cluster fails to join"
        );
    }

    #[test]
    fn node_cannot_register_itself_with_a_pod_cidr_already_set() {
        // Unlike taints/labels, a FRESH node must never carry podCIDR/providerID either — only
        // a controller assigns those, never kubelet itself, even at first registration.
        let groups = vec![NODES_GROUP.to_owned()];
        let new = own_node(serde_json::json!({"spec": {"podCIDR": "10.244.5.0/24"}}));
        assert!(
            restrict_node_self_write("system:node:node-a", &groups, "node-a", None, &new).is_err(),
            "a node registering itself must not be able to walk in already claiming a \
             podCIDR — that value is controller-assigned, never kubelet-chosen"
        );
    }

    #[test]
    fn node_can_still_patch_its_own_unrelated_spec_fields() {
        // A narrow-but-real allowance: unschedulable is a legitimate field kubelet's own
        // drain/cordon-adjacent logic can toggle on itself, and isn't in any forbidden set
        // above — this must stay Ok or the fix has silently become "node can never PATCH
        // itself at all", failing every real heartbeat-adjacent path in a different way.
        let groups = vec![NODES_GROUP.to_owned()];
        let old = own_node(serde_json::json!({}));
        let new = own_node(serde_json::json!({"spec": {"unschedulable": true}}));
        assert!(
            restrict_node_self_write("system:node:node-a", &groups, "node-a", Some(&old), &new)
                .is_ok(),
            "fields outside the upstream-mirrored forbidden set must remain writable, or this \
             fix over-restricts far beyond what NodeRestriction actually blocks"
        );
    }

    #[test]
    fn node_cannot_modify_a_different_nodes_object() {
        let groups = vec![NODES_GROUP.to_owned()];
        let old = serde_json::json!({"metadata": {"name": "node-b"}, "spec": {}});
        let new =
            serde_json::json!({"metadata": {"name": "node-b"}, "spec": {"unschedulable": true}});
        assert!(
            restrict_node_self_write("system:node:node-a", &groups, "node-b", Some(&old), &new)
                .is_err(),
            "node-a's identity must not be able to touch node-b's Node object at all, \
             regardless of which field — own-node scoping must hold even if some other bug \
             ever let the request reach this admission check"
        );
    }

    #[test]
    fn non_node_identity_is_never_restricted_by_this_check() {
        // kube-controller-manager's node-ipam-controller (a controller/SA identity, never
        // system:node) must retain its empty -> valid podCIDR assignment path untouched, or
        // this fix breaks every real cluster's node bring-up.
        let old = serde_json::json!({"metadata": {"name": "node-a"}, "spec": {}});
        let new = serde_json::json!({
            "metadata": {"name": "node-a"},
            "spec": {"podCIDR": "10.244.7.0/24", "taints": [{"key": "x", "effect": "NoSchedule"}]},
        });
        assert!(
            restrict_node_self_write("kube-controller-manager", &[], "node-a", Some(&old), &new)
                .is_ok(),
            "a non-system:node caller (KCM, an admin) must be completely unaffected by this \
             check — it exists only to narrow what a NODE's own identity can write"
        );
    }
}

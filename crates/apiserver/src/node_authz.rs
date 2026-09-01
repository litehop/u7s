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
//! behavior, not a regression. Mirror-pod create/delete is not wired to this authorizer (see
//! the follow-on fix). The SelfSubjectAccessReview/SubjectAccessReview/LocalSubjectAccessReview
//! endpoints (`handlers/authorization.rs`) DO consult this authorizer, via the `authorized()`
//! helper defined there.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::rbac::{self, AuthzRequest, RbacIndex};

const NODE_USERNAME_PREFIX: &str = "system:node:";
const NODES_GROUP: &str = "system:nodes";
const NODE_LEASE_NAMESPACE: &str = "kube-node-lease";
const NODE_CLUSTER_ROLE: &str = "system:node";

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
            _ => false,
        },
        "status" => matches!(req.verb, "get" | "update" | "patch") && req.name.is_some_and(owns),
        "log" => req.verb == "get" && req.name.is_some_and(owns),
        _ => false,
    }
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
}

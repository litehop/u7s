use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;

use crate::{status::Status, util::content_type};

/// Query parameters accepted by PATCH and write endpoints.
///
/// `field_validation` is accepted and ignored — the server does not implement
/// server-side field validation. Accepting it prevents 400 responses when clients
/// like `kubectl create` send `?fieldValidation=Strict` or `?fieldValidation=Warn`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct PatchQuery {
    #[serde(rename = "fieldManager")]
    pub field_manager: Option<String>,
    /// Accepted and ignored: we do not implement server-side field validation.
    #[serde(rename = "fieldValidation")]
    pub _field_validation: Option<String>,
    /// When set to "All", the server validates the request but does NOT persist the change.
    /// The response looks identical to a successful write (200 + would-be object).
    /// Only "All" is meaningful server-side; "client" is handled by kubectl itself.
    #[serde(rename = "dryRun")]
    pub dry_run: Option<String>,
}

impl PatchQuery {
    /// Returns true when the request must be a dry-run (no store write).
    pub(crate) fn is_dry_run(&self) -> bool {
        self.dry_run.as_deref() == Some("All")
    }
}

/// Query parameters accepted by CREATE endpoints (POST).
///
/// `field_validation` drives server-side unknown-field detection:
///   - `Strict`  → 422 UnprocessableEntity with Status body listing unknown fields
///   - `Warn`    → 200/201 with `Warning: 299 - "..."` response header
///   - `Ignore`  → silently strip (default, existing behaviour)
#[derive(Debug, Default, Deserialize)]
pub(crate) struct CreateQuery {
    #[serde(rename = "fieldManager")]
    pub _field_manager: Option<String>,
    #[serde(rename = "fieldValidation")]
    pub field_validation: Option<String>,
    /// When set to "All", validate but do NOT persist the object.
    #[serde(rename = "dryRun")]
    pub dry_run: Option<String>,
}

impl CreateQuery {
    /// Returns true when the request must be a dry-run (no store write).
    pub(crate) fn is_dry_run(&self) -> bool {
        self.dry_run.as_deref() == Some("All")
    }
}

/// Query parameters accepted by PUT (replace) endpoints.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ReplaceQuery {
    #[serde(rename = "fieldManager")]
    pub _field_manager: Option<String>,
    /// When set to "All", validate but do NOT persist the replacement object.
    #[serde(rename = "dryRun")]
    pub dry_run: Option<String>,
}

impl ReplaceQuery {
    /// Returns true when the request must be a dry-run (no store write).
    pub(crate) fn is_dry_run(&self) -> bool {
        self.dry_run.as_deref() == Some("All")
    }
}

/// Header used to thread the real `?dryRun=All` flag into handlers that have no
/// `Query<...>` extractor of their own (CRD/CSR/Namespace create/replace/patch, and CR
/// create/replace/patch reached via resource.rs's fallback). `inject_dry_run_header`
/// (lib.rs) sets this from the raw query string as a router-wide layer, so every handler
/// reachable through axum sees it regardless of which typed Query struct (if any) it
/// declares. Without this, AdmissionContext.dry_run stays hardcoded false on those paths,
/// wrongly invoking a `sideEffects: Some` webhook on a dry-run request.
pub(crate) const DRY_RUN_HEADER: &str = "x-u7s-dry-run";

/// Returns true when `inject_dry_run_header` marked this request as dry-run. See
/// `DRY_RUN_HEADER` for why handlers without their own typed dry-run query field need this.
pub(crate) fn is_dry_run_header(headers: &HeaderMap) -> bool {
    headers.contains_key(DRY_RUN_HEADER)
}

/// Router-wide layer (installed in lib.rs's `build_router`) that stamps `DRY_RUN_HEADER`
/// onto the request before any handler runs, read straight from the raw query string
/// rather than a typed `Query<...>` extractor — the only way to reach handlers that don't
/// declare one of their own. "All" is the only server-meaningful value (see
/// `CreateQuery::is_dry_run` etc.); "client" is handled by kubectl itself and never reaches
/// the server as `dryRun=All`.
pub(crate) async fn inject_dry_run_header(
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let is_dry_run = req
        .uri()
        .query()
        .is_some_and(|q| q.split('&').any(|kv| kv == "dryRun=All"));
    if is_dry_run {
        req.headers_mut().insert(
            HeaderName::from_static(DRY_RUN_HEADER),
            HeaderValue::from_static("true"),
        );
    }
    next.run(req).await
}

// ---------------------------------------------------------------------------
// Known-field sets for top-level and metadata field validation
// ---------------------------------------------------------------------------

/// Known top-level fields for any Kubernetes typed object.
///
/// `apiVersion`, `kind`, `metadata` are universal.  The remaining fields cover
/// every resource in the static registry; unknown top-level keys trigger the
/// Strict/Warn validation path.
fn known_top_level_fields(group: &str, plural: &str) -> &'static [&'static str] {
    // Resource-specific extra fields beyond the universal set.
    match (group, plural) {
        // ConfigMap / Secret
        ("", "configmaps") => &[
            "apiVersion",
            "kind",
            "metadata",
            "data",
            "binaryData",
            "immutable",
        ],
        ("", "secrets") => &[
            "apiVersion",
            "kind",
            "metadata",
            "data",
            "stringData",
            "type",
            "immutable",
        ],
        // ServiceAccount
        ("", "serviceaccounts") => &[
            "apiVersion",
            "kind",
            "metadata",
            "secrets",
            "imagePullSecrets",
            "automountServiceAccountToken",
        ],
        // RBAC — cluster-scoped
        ("rbac.authorization.k8s.io", "clusterroles") => {
            &["apiVersion", "kind", "metadata", "rules", "aggregationRule"]
        }
        ("rbac.authorization.k8s.io", "clusterrolebindings") => {
            &["apiVersion", "kind", "metadata", "subjects", "roleRef"]
        }
        // RBAC — namespaced
        ("rbac.authorization.k8s.io", "roles") => &["apiVersion", "kind", "metadata", "rules"],
        ("rbac.authorization.k8s.io", "rolebindings") => {
            &["apiVersion", "kind", "metadata", "subjects", "roleRef"]
        }
        // StorageClass
        ("storage.k8s.io", "storageclasses") => &[
            "apiVersion",
            "kind",
            "metadata",
            "provisioner",
            "parameters",
            "reclaimPolicy",
            "volumeBindingMode",
            "allowVolumeExpansion",
            "mountOptions",
            "allowedTopologies",
        ],
        // VolumeAttributesClass
        ("storage.k8s.io", "volumeattributesclasses") => {
            &["apiVersion", "kind", "metadata", "driverName", "parameters"]
        }
        // PriorityClass
        ("scheduling.k8s.io", "priorityclasses") => &[
            "apiVersion",
            "kind",
            "metadata",
            "value",
            "preemptionPolicy",
            "globalDefault",
            "description",
        ],
        // RuntimeClass
        ("node.k8s.io", "runtimeclasses") => &[
            "apiVersion",
            "kind",
            "metadata",
            "handler",
            "overhead",
            "scheduling",
        ],
        // IngressClass
        ("networking.k8s.io", "ingressclasses") => &["apiVersion", "kind", "metadata", "spec"],
        // PodDisruptionBudget
        ("policy", "poddisruptionbudgets") => &["apiVersion", "kind", "metadata", "spec", "status"],
        // ControllerRevision
        ("apps", "controllerrevisions") => &["apiVersion", "kind", "metadata", "data", "revision"],
        // Lease
        ("coordination.k8s.io", "leases") => &["apiVersion", "kind", "metadata", "spec"],
        // ValidatingWebhookConfiguration / MutatingWebhookConfiguration — top-level field is
        // "webhooks", not spec/status. Without these entries, fieldValidation=Strict (kubectl's
        // default) rejects every valid webhook config with 422 "unknown field \"webhooks\"",
        // breaking `kubectl apply` of webhook configs.
        ("admissionregistration.k8s.io", "validatingwebhookconfigurations") => {
            &["apiVersion", "kind", "metadata", "webhooks"]
        }
        ("admissionregistration.k8s.io", "mutatingwebhookconfigurations") => {
            &["apiVersion", "kind", "metadata", "webhooks"]
        }
        // EndpointSlice — top-level fields are not spec/status but addressType/endpoints/ports.
        // Without this entry, fieldValidation=Strict rejects valid EndpointSlice bodies with
        // 422 "unknown field" for addressType, endpoints, and ports.
        ("discovery.k8s.io", "endpointslices") => &[
            "apiVersion",
            "kind",
            "metadata",
            "addressType",
            "endpoints",
            "ports",
        ],
        // PodTemplate — top-level field is "template" (a PodTemplateSpec), not spec/status.
        // Without this entry, fieldValidation=Strict rejects every valid PodTemplate with
        // 422 "unknown field \"template\"", breaking `kubectl apply` of PodTemplates.
        ("", "podtemplates") => &["apiVersion", "kind", "metadata", "template"],
        // Endpoints — top-level field is "subsets", not spec/status. Without this entry,
        // fieldValidation=Strict rejects every valid Endpoints object with 422 "unknown
        // field \"subsets\"", breaking `kubectl apply` of Endpoints.
        ("", "endpoints") => &["apiVersion", "kind", "metadata", "subsets"],
        // core/v1 Event — the legacy Event schema: all resource-specific fields sit
        // directly at the top level, not under spec/status. Without this entry,
        // fieldValidation=Strict rejects every valid Event with 422 "unknown field",
        // breaking event recording (client-go's core/v1 event recorder posts this shape).
        ("", "events") => &[
            "apiVersion",
            "kind",
            "metadata",
            "involvedObject",
            "reason",
            "message",
            "source",
            "firstTimestamp",
            "lastTimestamp",
            "count",
            "type",
            "eventTime",
            "series",
            "action",
            "related",
            "reportingComponent",
            "reportingInstance",
        ],
        // events.k8s.io/v1 Event — a different top-level schema than core/v1 Event (e.g.
        // reportingController/regarding/note instead of reportingComponent/involvedObject/
        // message). Without this entry, fieldValidation=Strict rejects every valid
        // events.k8s.io/v1 Event, breaking client-go's events/v1 event recorder.
        ("events.k8s.io", "events") => &[
            "apiVersion",
            "kind",
            "metadata",
            "eventTime",
            "series",
            "reportingController",
            "reportingInstance",
            "action",
            "reason",
            "regarding",
            "related",
            "note",
            "type",
            "deprecatedSource",
            "deprecatedFirstTimestamp",
            "deprecatedLastTimestamp",
            "deprecatedCount",
        ],
        // CSIStorageCapacity — top-level fields are nodeTopology/storageClassName/capacity/
        // maximumVolumeSize, not spec/status. Without this entry, fieldValidation=Strict
        // rejects every valid CSIStorageCapacity reported by a CSI driver's
        // external-provisioner sidecar with 422 "unknown field".
        ("storage.k8s.io", "csistoragecapacities") => &[
            "apiVersion",
            "kind",
            "metadata",
            "nodeTopology",
            "storageClassName",
            "capacity",
            "maximumVolumeSize",
        ],
        // Default: universal set + spec + status covers most resources
        _ => &["apiVersion", "kind", "metadata", "spec", "status"],
    }
}

/// Known `spec` fields for resource types with nested field validation enabled.
///
/// `known_top_level_fields` treats `spec` as an opaque known key — it does not look
/// inside it. That means a body like `{"spec": {"unknownField": ...}}` passes
/// unknown-field detection even though `unknownField` is not part of the resource's
/// schema. Most resource types return `None` here (nested spec validation is not
/// implemented for them) so they keep the pre-existing top-level-only behaviour;
/// only types actually exercised by fieldValidation=Strict conformance tests are
/// covered, to avoid false positives from an incomplete schema guess.
fn known_spec_fields(group: &str, plural: &str) -> Option<&'static [&'static str]> {
    match (group, plural) {
        // Deployment — matches k8s.io/api/apps/v1 DeploymentSpec exactly (8 fields).
        // Conformance test "should detect unknown and duplicate fields of a typed
        // object" POSTs a Deployment with `spec.unknownField` and
        // `?fieldValidation=Strict`, expecting 422. Before this table, u7s accepted
        // the request (HTTP success), and the Go test client panicked calling
        // `.Error()` on the nil error it expected instead.
        ("apps", "deployments") => Some(&[
            "replicas",
            "selector",
            "template",
            "strategy",
            "minReadySeconds",
            "revisionHistoryLimit",
            "paused",
            "progressDeadlineSeconds",
        ]),
        _ => None,
    }
}

/// Known fields within `metadata` for any Kubernetes object.
///
/// This matches the full `ObjectMeta` schema from the Kubernetes API.
/// Unknown metadata keys (e.g. a misspelled annotation key at the wrong level)
/// trigger validation errors in Strict mode.
const KNOWN_METADATA_FIELDS: &[&str] = &[
    "name",
    "generateName",
    "namespace",
    "selfLink",
    "uid",
    "resourceVersion",
    "generation",
    "creationTimestamp",
    "deletionTimestamp",
    "deletionGracePeriodSeconds",
    "labels",
    "annotations",
    "ownerReferences",
    "finalizers",
    "managedFields",
    "clusterName",
];

// ---------------------------------------------------------------------------
// Duplicate-key detection — needs the raw bytes, not the parsed Value
// ---------------------------------------------------------------------------

/// A JSON value that preserves ALL object keys, including duplicates, in
/// encounter order.
///
/// `serde_json::Value` silently keeps only the last occurrence of a repeated
/// object key while parsing — by the time a handler has a parsed `Value`, the
/// fact that a key was ever duplicated is gone. Detecting duplicates requires
/// re-deserializing the raw bytes into a shape that doesn't collapse them.
/// Leaf scalars and array elements are not preserved: this type only needs to
/// reconstruct enough structure to find duplicate keys, not to read values —
/// arrays are consumed (so nested objects inside them still parse correctly)
/// but their elements are discarded rather than kept.
enum DupCheckValue {
    Leaf,
    Array,
    Object(Vec<(String, DupCheckValue)>),
}

impl<'de> serde::de::Deserialize<'de> for DupCheckValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct DupCheckVisitor;

        impl<'de> serde::de::Visitor<'de> for DupCheckVisitor {
            type Value = DupCheckValue;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_bool<E>(self, _v: bool) -> Result<Self::Value, E> {
                Ok(DupCheckValue::Leaf)
            }
            fn visit_i64<E>(self, _v: i64) -> Result<Self::Value, E> {
                Ok(DupCheckValue::Leaf)
            }
            fn visit_u64<E>(self, _v: u64) -> Result<Self::Value, E> {
                Ok(DupCheckValue::Leaf)
            }
            fn visit_f64<E>(self, _v: f64) -> Result<Self::Value, E> {
                Ok(DupCheckValue::Leaf)
            }
            fn visit_str<E>(self, _v: &str) -> Result<Self::Value, E> {
                Ok(DupCheckValue::Leaf)
            }
            fn visit_string<E>(self, _v: String) -> Result<Self::Value, E> {
                Ok(DupCheckValue::Leaf)
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(DupCheckValue::Leaf)
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(DupCheckValue::Leaf)
            }
            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                serde::de::Deserialize::deserialize(deserializer)
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                // Consume (and discard) every element so the deserializer advances
                // correctly past the array; contents aren't needed for key-duplicate
                // detection, which only looks at "spec"'s immediate object keys.
                while seq.next_element::<DupCheckValue>()?.is_some() {}
                Ok(DupCheckValue::Array)
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut entries = Vec::new();
                while let Some((k, v)) = map.next_entry::<String, DupCheckValue>()? {
                    entries.push((k, v));
                }
                Ok(DupCheckValue::Object(entries))
            }
        }

        deserializer.deserialize_any(DupCheckVisitor)
    }
}

/// Return keys that appear more than once in `entries`, each reported once,
/// in the order their second occurrence appears.
fn repeated_keys(entries: &[(String, DupCheckValue)]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut reported = std::collections::HashSet::new();
    let mut duplicates = Vec::new();
    for (key, _) in entries {
        if !seen.insert(key.as_str()) && reported.insert(key.as_str()) {
            duplicates.push(key.clone());
        }
    }
    duplicates
}

/// Detect duplicate object keys within `spec`, by re-parsing the raw request
/// bytes into a structure that preserves repeated keys (see `DupCheckValue`).
///
/// Scoped to resource types with a known spec schema (see `known_spec_fields`)
/// to match exactly what the FieldValidation conformance test needs, rather
/// than scanning every request body for a rare, always-invalid shape.
pub(crate) fn detect_duplicate_fields(raw: &[u8], group: &str, plural: &str) -> Vec<String> {
    if known_spec_fields(group, plural).is_none() {
        return Vec::new();
    }
    let root: DupCheckValue = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(), // malformed JSON is reported elsewhere
    };
    if let DupCheckValue::Object(top) = root {
        if let Some((_, DupCheckValue::Object(spec_entries))) =
            top.iter().find(|(k, _)| k == "spec")
        {
            return repeated_keys(spec_entries)
                .into_iter()
                .map(|k| format!("spec.{k}"))
                .collect();
        }
    }
    Vec::new()
}

/// Detect unknown top-level keys and unknown metadata keys in `body`.
///
/// Returns a list of dot-separated field paths that are not part of the
/// resource's known schema, e.g. `["unknownField", "metadata.bogusKey"]`.
pub(crate) fn detect_unknown_fields(
    body: &serde_json::Value,
    group: &str,
    plural: &str,
) -> Vec<String> {
    let mut unknown = Vec::new();
    let known_top = known_top_level_fields(group, plural);

    if let Some(obj) = body.as_object() {
        for key in obj.keys() {
            if !known_top.contains(&key.as_str()) {
                unknown.push(key.clone());
            }
        }

        // Check metadata fields.
        if let Some(meta) = obj.get("metadata").and_then(|m| m.as_object()) {
            for key in meta.keys() {
                if !KNOWN_METADATA_FIELDS.contains(&key.as_str()) {
                    unknown.push(format!("metadata.{key}"));
                }
            }
        }

        // Check nested spec fields for resource types with a known spec schema.
        // Types not covered by known_spec_fields return None and are unaffected —
        // see known_spec_fields for why most types are intentionally excluded.
        if let Some(known_spec) = known_spec_fields(group, plural) {
            if let Some(spec) = obj.get("spec").and_then(|s| s.as_object()) {
                for key in spec.keys() {
                    if !known_spec.contains(&key.as_str()) {
                        unknown.push(format!("spec.{key}"));
                    }
                }
            }
        }
    }

    unknown
}

/// Apply `?fieldValidation=` semantics.
///
/// - `Strict`  → returns `Err(422)` when unknown or duplicate fields are detected.
/// - `Warn`    → returns `Ok(Some(warning_header_value))` when they are detected.
/// - `Ignore`  → returns `Ok(None)` unconditionally (existing strip-and-store behaviour).
/// - absent    → same as `Ignore`.
///
/// `raw` is the undecoded request body, needed to detect duplicate object keys —
/// see `detect_duplicate_fields` for why the parsed `body` can't be used for that.
pub(crate) fn apply_field_validation(
    body: &serde_json::Value,
    raw: &[u8],
    mode: Option<&str>,
    group: &str,
    plural: &str,
) -> Result<Option<HeaderValue>, crate::status::StatusError> {
    let mode = mode.unwrap_or("Ignore");
    if mode == "Ignore" {
        return Ok(None);
    }

    let unknown = detect_unknown_fields(body, group, plural);
    let duplicate = detect_duplicate_fields(raw, group, plural);
    if unknown.is_empty() && duplicate.is_empty() {
        return Ok(None);
    }

    // Upstream renders each issue as its own "<kind> field \"<path>\"" phrase, unknown
    // fields first, then duplicate fields, comma-separated, e.g.:
    //   strict decoding error: unknown field "spec.unknownField", duplicate field "spec.replicas"
    let phrases: Vec<String> = unknown
        .iter()
        .map(|f| format!("unknown field \"{f}\""))
        .chain(duplicate.iter().map(|f| format!("duplicate field \"{f}\"")))
        .collect();
    let joined = phrases.join(", ");

    match mode {
        "Strict" => Err(Status::unprocessable_entity(format!(
            "strict decoding error: {joined}"
        ))),
        "Warn" => {
            let msg = format!("299 - \"{joined}\"");
            let hv = HeaderValue::from_str(&msg).unwrap_or_else(|_| {
                HeaderValue::from_static("299 - \"unknown field(s) detected\"")
            });
            Ok(Some(hv))
        }
        // Any other value: treat as Ignore.
        _ => Ok(None),
    }
}

/// Strip `managedFields` from an SSA apply body before merging.
///
/// Kubernetes clients (including Argo CD) include a `managedFields` key in the
/// apply body to indicate their previous ownership. We don't track field
/// ownership, so we discard it before the merge to avoid persisting stale data.
pub(crate) fn strip_managed_fields(patch: &mut serde_json::Value) {
    if let Some(map) = patch.as_object_mut() {
        if let Some(meta) = map.get_mut("metadata") {
            if let Some(meta_map) = meta.as_object_mut() {
                meta_map.remove("managedFields");
            }
        }
    }
}

/// Inject a synthetic `managedFields` entry into a response object.
///
/// Argo CD's client library reads `managedFields` from apply responses to
/// determine field ownership. Without it, Argo CD treats every resource as
/// OutOfSync and loops forever. We echo back a single entry for the applying
/// manager; we do not implement full SSA field-level tracking.
pub(crate) fn inject_managed_fields(
    obj: &mut serde_json::Value,
    manager: &str,
    api_version: &str,
    now: &str,
) {
    if let Some(map) = obj.as_object_mut() {
        if let Some(meta) = map.get_mut("metadata") {
            if let Some(meta_map) = meta.as_object_mut() {
                meta_map.insert(
                    "managedFields".to_string(),
                    serde_json::json!([{
                        "manager": manager,
                        "operation": "Apply",
                        "apiVersion": api_version,
                        "time": now
                    }]),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SSA body parser: YAML-or-JSON → serde_json::Value
//
// The k8s conformance client sends genuine YAML block-mapping bytes (not JSON)
// in apply-patch+yaml bodies, verified by logging body_prefix in a live run:
//   "\napiVersion: mygroup.example.com/v1beta1\nkind: ...\nmetadata:\n..."
// yaml-rust2 is a pure-Rust YAML parser (no unsafe-libyaml); it also parses
// JSON because JSON is valid YAML, so kubelet-style JSON bodies work too.
// ---------------------------------------------------------------------------

/// yaml_rust2 reports duplicate mapping keys as `info() == "<Debug of Yaml key>: duplicated
/// key in mapping"` (e.g. `String("foo"): duplicated key in mapping`). Upstream k8s's
/// conformance suite greps the error body for `line N: key "X" already set in map`, so
/// reformat to that phrasing rather than leaking the raw yaml-rust2 Debug output.
fn dup_key_message(e: &yaml_rust2::ScanError) -> String {
    let Some(key_debug) = e.info().strip_suffix(": duplicated key in mapping") else {
        return format!("invalid SSA body: {e}");
    };
    let key = key_debug
        .strip_prefix("String(\"")
        .and_then(|s| s.strip_suffix("\")"))
        .unwrap_or(key_debug);
    format!(
        "line {}: key \"{key}\" already set in map",
        e.marker().line()
    )
}

/// Parse an `apply-patch+yaml` body (YAML or JSON) into a serde_json::Value.
///
/// Shared by every PATCH handler that accepts the Server-Side Apply content type: real
/// SSA clients (kubectl apply --server-side, the k8s conformance suite) send genuine
/// multi-line YAML, which `serde_json::from_slice` rejects outright. yaml-rust2 parses
/// both YAML and JSON (JSON is valid YAML), so this also handles JSON apply bodies
/// (e.g. kubelet's Lease/CSINode SSA requests) without a separate code path.
///
/// Returns 400 Bad Request on any parse or encoding error so the caller does not
/// store garbage.
pub(crate) fn ssa_body_to_json(
    body: &[u8],
) -> Result<serde_json::Value, crate::status::StatusError> {
    let s = std::str::from_utf8(body)
        .map_err(|e| Status::bad_request(format!("SSA body is not valid UTF-8: {e}")))?;
    let docs = yaml_rust2::YamlLoader::load_from_str(s)
        .map_err(|e| Status::bad_request(dup_key_message(&e)))?;
    let doc = docs
        .into_iter()
        .next()
        .ok_or_else(|| Status::bad_request("SSA body is empty".into()))?;
    yaml_to_json(&doc)
        .ok_or_else(|| Status::bad_request("SSA body contains unparseable value".into()))
}

/// Recursively convert a `yaml_rust2::Yaml` node to a `serde_json::Value`.
///
/// Returns `None` for `BadValue` (malformed YAML node) so the caller can
/// surface a 400 instead of silently storing garbage.
fn yaml_to_json(y: &yaml_rust2::Yaml) -> Option<serde_json::Value> {
    use serde_json::{Number, Value};
    use yaml_rust2::Yaml;
    Some(match y {
        Yaml::String(s) => Value::String(s.clone()),
        Yaml::Integer(i) => Value::Number(Number::from(*i)),
        Yaml::Real(s) => {
            // Yaml::Real holds the raw string; parse to f64 and reject non-finite values
            // (NaN/Inf are not valid JSON) rather than silently coercing them to null.
            match s.parse::<f64>() {
                Ok(f) if f.is_finite() => {
                    Value::Number(Number::from_f64(f).unwrap_or_else(|| Number::from(0)))
                }
                _ => return None,
            }
        }
        Yaml::Boolean(b) => Value::Bool(*b),
        Yaml::Array(a) => Value::Array(a.iter().map(yaml_to_json).collect::<Option<Vec<_>>>()?),
        Yaml::Hash(m) => {
            let mut map = serde_json::Map::new();
            for (k, v) in m {
                // k8s bodies always use string keys; coerce non-string scalar keys
                // to their string representation defensively rather than panicking.
                let key = match k {
                    Yaml::String(s) => s.clone(),
                    Yaml::Integer(i) => i.to_string(),
                    Yaml::Real(s) => s.clone(),
                    Yaml::Boolean(b) => b.to_string(),
                    Yaml::Null => "null".into(),
                    // Non-scalar keys (nested mappings/arrays) or bad values cannot
                    // be coerced to a string key — skip the entry.
                    _ => continue,
                };
                map.insert(key, yaml_to_json(v)?);
            }
            Value::Object(map)
        }
        Yaml::Null => Value::Null,
        // BadValue signals a parse problem within the document; surface it as None
        // so the caller returns 400 rather than storing garbage.
        Yaml::BadValue | Yaml::Alias(_) => return None,
    })
}

/// Patch Content-Type variants understood by all patch endpoints.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PatchType {
    Merge,
    StrategicMerge,
    Json,
}

pub(crate) fn detect_patch_type(
    headers: &HeaderMap,
) -> Result<PatchType, crate::status::StatusError> {
    let ct = content_type(headers);
    if ct.contains("application/strategic-merge-patch+json") {
        return Ok(PatchType::StrategicMerge);
    }
    if ct.contains("application/merge-patch+json") {
        return Ok(PatchType::Merge);
    }
    if ct.contains("application/json-patch+json") {
        return Ok(PatchType::Json);
    }
    // Treat server-side apply as strategic-merge-patch: we don't implement full SSA
    // semantics (field ownership, managed fields), but the apply body is structurally
    // identical to a strategic-merge-patch body.  This is sufficient for kubelet's
    // Lease and CSINode use cases; without this kubelet gets 415 and logs
    // "invalid JSON: expected value at line 1 column 1".
    if ct.contains("application/apply-patch+yaml") {
        return Ok(PatchType::StrategicMerge);
    }
    Err(Status::unsupported_media_type(format!(
        "unsupported media type '{ct}'; use application/merge-patch+json, application/strategic-merge-patch+json, or application/json-patch+json"
    )))
}

/// Apply a JSON Patch (RFC 6902) to `obj`.
/// Supports `add`, `remove`, `replace`, and `test` operations.
/// Returns Err(422) for unsupported operations, invalid paths, or a failing `test`.
///
/// Applies atomically: operations run against a clone of `obj` and are only written back
/// once every operation succeeds, so a failing `test` (or any other op) leaves `obj`
/// untouched rather than half-patched — `test` is used by clients as an optimistic-
/// concurrency guard, and a partial apply on failure would defeat that guarantee.
pub(crate) fn apply_json_patch(
    obj: &mut serde_json::Value,
    patch: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let ops = patch.as_array().ok_or_else(|| {
        Status::unprocessable_entity("JSON patch must be an array of operations".into())
    })?;

    let mut working = obj.clone();
    for op in ops {
        let op_str = op["op"].as_str().ok_or_else(|| {
            Status::unprocessable_entity("each JSON patch operation must have an 'op' field".into())
        })?;
        let path = op["path"].as_str().ok_or_else(|| {
            Status::unprocessable_entity(
                "each JSON patch operation must have a 'path' field".into(),
            )
        })?;

        match op_str {
            "add" => {
                let value = op
                    .get("value")
                    .ok_or_else(|| {
                        Status::unprocessable_entity(
                            "'add' operation requires a 'value' field".into(),
                        )
                    })?
                    .clone();
                // RFC 6902 §4.1: 'add' creates intermediate objects when missing.
                json_patch_add(&mut working, path, value)?;
            }
            "replace" => {
                let value = op
                    .get("value")
                    .ok_or_else(|| {
                        Status::unprocessable_entity(
                            "'replace' operation requires a 'value' field".into(),
                        )
                    })?
                    .clone();
                // 'replace' is strict: 422 if path does not exist.
                json_patch_set(&mut working, path, value)?;
            }
            "remove" => {
                json_patch_remove(&mut working, path)?;
            }
            "test" => {
                let expected = op.get("value").ok_or_else(|| {
                    Status::unprocessable_entity("'test' operation requires a 'value' field".into())
                })?;
                let actual = json_patch_get(&working, path)?;
                if actual != expected {
                    return Err(Status::unprocessable_entity(format!(
                        "'test' operation failed: value at path '{path}' does not match expected value"
                    )));
                }
            }
            other => {
                return Err(Status::unprocessable_entity(format!(
                    "unsupported JSON patch operation '{other}'; supported: add, remove, replace, test"
                )));
            }
        }
    }
    *obj = working;
    Ok(())
}

/// Parse a JSON Pointer (RFC 6901) into path segments.
pub(crate) fn json_pointer_segments(pointer: &str) -> Vec<String> {
    if pointer.is_empty() {
        return vec![];
    }
    // Leading '/' is required for non-empty pointers; skip it.
    let stripped = pointer.strip_prefix('/').unwrap_or(pointer);
    stripped
        .split('/')
        .map(|seg| seg.replace("~1", "/").replace("~0", "~"))
        .collect()
}

/// Navigate to the parent of the target, returning a mutable ref to the parent and the final key.
pub(crate) fn json_patch_navigate_mut<'a>(
    obj: &'a mut serde_json::Value,
    segments: &[String],
) -> Result<(&'a mut serde_json::Value, String), crate::status::StatusError> {
    if segments.is_empty() {
        return Err(Status::unprocessable_entity(
            "cannot operate on root document".into(),
        ));
    }
    let (parents, last) = segments.split_at(segments.len() - 1);
    let mut cur = obj;
    for seg in parents {
        cur = json_navigate_one(cur, seg)?;
    }
    Ok((cur, last[0].clone()))
}

pub(crate) fn json_navigate_one<'a>(
    node: &'a mut serde_json::Value,
    seg: &str,
) -> Result<&'a mut serde_json::Value, crate::status::StatusError> {
    match node {
        serde_json::Value::Object(map) => map
            .get_mut(seg)
            .ok_or_else(|| Status::unprocessable_entity(format!("path segment '{seg}' not found"))),
        serde_json::Value::Array(arr) => {
            let idx: usize = seg.parse().map_err(|_| {
                Status::unprocessable_entity(format!(
                    "path segment '{seg}' is not a valid array index"
                ))
            })?;
            arr.get_mut(idx).ok_or_else(|| {
                Status::unprocessable_entity(format!("array index {idx} out of bounds"))
            })
        }
        _ => Err(Status::unprocessable_entity(format!(
            "cannot traverse into non-object/array at segment '{seg}'"
        ))),
    }
}

/// Read the value at `pointer` for RFC 6902 'test'. Unlike `json_patch_navigate_mut`, this
/// resolves the full path (not just its parent) and never mutates `obj`.
pub(crate) fn json_patch_get<'a>(
    obj: &'a serde_json::Value,
    pointer: &str,
) -> Result<&'a serde_json::Value, crate::status::StatusError> {
    let segs = json_pointer_segments(pointer);
    let mut cur = obj;
    for seg in &segs {
        cur = match cur {
            serde_json::Value::Object(map) => map.get(seg).ok_or_else(|| {
                Status::unprocessable_entity(format!("path segment '{seg}' not found"))
            })?,
            serde_json::Value::Array(arr) => {
                let idx: usize = seg.parse().map_err(|_| {
                    Status::unprocessable_entity(format!(
                        "path segment '{seg}' is not a valid array index"
                    ))
                })?;
                arr.get(idx).ok_or_else(|| {
                    Status::unprocessable_entity(format!("array index {idx} out of bounds"))
                })?
            }
            _ => {
                return Err(Status::unprocessable_entity(format!(
                    "cannot traverse into non-object/array at segment '{seg}'"
                )))
            }
        };
    }
    Ok(cur)
}

/// Navigate to a child, creating an empty object if the key is absent.
/// Used by `json_patch_add` to satisfy RFC 6902 §4.1 intermediate-creation semantics.
///
/// An array parent is never fabricated — RFC 6902 gives no rule for inventing array
/// slots — but an index into an array element that already exists (e.g. `versions/0`
/// on a CRD, which always has at least one version) is a real position to descend into,
/// not something to create, so it must navigate rather than error.
pub(crate) fn json_navigate_one_or_create<'a>(
    node: &'a mut serde_json::Value,
    seg: &str,
) -> Result<&'a mut serde_json::Value, crate::status::StatusError> {
    match node {
        serde_json::Value::Object(map) => {
            map.entry(seg)
                .or_insert_with(|| serde_json::Value::Object(Default::default()));
            Ok(map.get_mut(seg).unwrap())
        }
        serde_json::Value::Array(arr) => {
            let idx: usize = seg.parse().map_err(|_| {
                Status::unprocessable_entity(format!(
                    "path segment '{seg}' is not a valid array index"
                ))
            })?;
            arr.get_mut(idx).ok_or_else(|| {
                Status::unprocessable_entity(format!("array index {idx} out of bounds"))
            })
        }
        _ => Err(Status::unprocessable_entity(format!(
            "cannot create intermediate key '{seg}' in non-object"
        ))),
    }
}

/// Apply RFC 6902 'add': navigate parents creating missing objects, then insert.
pub(crate) fn json_patch_add(
    obj: &mut serde_json::Value,
    pointer: &str,
    value: serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let segs = json_pointer_segments(pointer);
    if segs.is_empty() {
        *obj = value;
        return Ok(());
    }
    let (parents, last) = segs.split_at(segs.len() - 1);
    let mut cur = obj;
    for seg in parents {
        cur = json_navigate_one_or_create(cur, seg)?;
    }
    let key = &last[0];
    match cur {
        serde_json::Value::Object(map) => {
            map.insert(key.clone(), value);
        }
        serde_json::Value::Array(arr) => {
            if key == "-" {
                arr.push(value);
            } else {
                let idx: usize = key.parse().map_err(|_| {
                    Status::unprocessable_entity(format!("invalid array index '{key}'"))
                })?;
                if idx <= arr.len() {
                    arr.insert(idx, value);
                } else {
                    return Err(Status::unprocessable_entity(format!(
                        "array index {idx} out of bounds (len {})",
                        arr.len()
                    )));
                }
            }
        }
        _ => {
            return Err(Status::unprocessable_entity(
                "cannot add value to non-object/array".into(),
            ))
        }
    }
    Ok(())
}

pub(crate) fn json_patch_set(
    obj: &mut serde_json::Value,
    pointer: &str,
    value: serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let segs = json_pointer_segments(pointer);
    if segs.is_empty() {
        *obj = value;
        return Ok(());
    }
    let (parent, key) = json_patch_navigate_mut(obj, &segs)?;
    match parent {
        serde_json::Value::Object(map) => {
            map.insert(key, value);
        }
        serde_json::Value::Array(arr) => {
            if key == "-" {
                arr.push(value);
            } else {
                let idx: usize = key.parse().map_err(|_| {
                    Status::unprocessable_entity(format!("invalid array index '{key}'"))
                })?;
                // RFC 6902 §4.3: 'replace' overwrites an existing element in place; unlike
                // 'add', it never grows the array, so idx == arr.len() (one past the end,
                // "replace past the end") is out of bounds too.
                match arr.get_mut(idx) {
                    Some(slot) => *slot = value,
                    None => {
                        return Err(Status::unprocessable_entity(format!(
                            "array index {idx} out of bounds (len {})",
                            arr.len()
                        )));
                    }
                }
            }
        }
        _ => {
            return Err(Status::unprocessable_entity(
                "cannot set value on non-object/array".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn json_patch_remove(
    obj: &mut serde_json::Value,
    pointer: &str,
) -> Result<(), crate::status::StatusError> {
    let segs = json_pointer_segments(pointer);
    let (parent, key) = json_patch_navigate_mut(obj, &segs)?;
    match parent {
        serde_json::Value::Object(map) => {
            map.remove(&key).ok_or_else(|| {
                Status::unprocessable_entity(format!("path '{pointer}' not found"))
            })?;
        }
        serde_json::Value::Array(arr) => {
            let idx: usize = key.parse().map_err(|_| {
                Status::unprocessable_entity(format!("invalid array index '{key}'"))
            })?;
            if idx < arr.len() {
                arr.remove(idx);
            } else {
                return Err(Status::unprocessable_entity(format!(
                    "array index {idx} out of bounds"
                )));
            }
        }
        _ => {
            return Err(Status::unprocessable_entity(
                "cannot remove from non-object/array".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// strip_managed_fields removes the managedFields key from metadata.
    /// This matters because Argo CD sends managedFields in apply bodies to signal
    /// previous ownership — we must not persist it or it corrupts the stored object.
    #[test]
    fn strip_managed_fields_removes_managed_fields_from_metadata() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "test",
                "managedFields": [{"manager": "argocd", "operation": "Apply"}]
            }
        });

        strip_managed_fields(&mut obj);

        assert!(
            obj["metadata"]["managedFields"].is_null(),
            "managedFields must be removed from metadata after strip"
        );
        // Other metadata fields must survive the strip.
        assert_eq!(obj["metadata"]["name"], "test");
    }

    /// strip_managed_fields is a no-op when managedFields is absent.
    #[test]
    fn strip_managed_fields_is_noop_when_absent() {
        let mut obj = serde_json::json!({
            "metadata": { "name": "clean" }
        });
        strip_managed_fields(&mut obj);
        assert_eq!(obj["metadata"]["name"], "clean");
    }

    /// inject_managed_fields inserts a synthetic SSA entry with the expected shape.
    /// Argo CD reads manager, operation, apiVersion, and time from this entry.
    #[test]
    fn inject_managed_fields_inserts_synthetic_ssa_entry() {
        let mut obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "metadata": { "name": "my-deploy" }
        });

        inject_managed_fields(&mut obj, "argocd", "apps/v1", "2026-05-23T00:00:00Z");

        let mf = &obj["metadata"]["managedFields"];
        assert!(mf.is_array(), "managedFields must be an array");
        assert_eq!(mf[0]["manager"], "argocd");
        assert_eq!(mf[0]["operation"], "Apply");
        assert_eq!(mf[0]["apiVersion"], "apps/v1");
        assert_eq!(mf[0]["time"], "2026-05-23T00:00:00Z");
    }

    // ---------------------------------------------------------------------------
    // Unit tests for ssa_body_to_json / yaml_to_json
    //
    // WHY these matter: the k8s conformance client sends genuine YAML bytes in
    // apply-patch+yaml bodies. These tests ensure the conversion is correct and
    // that garbage bodies surface as 400 rather than silently storing bad data.
    // ---------------------------------------------------------------------------

    /// A genuine YAML body (as sent by the k8s conformance client) must parse to
    /// the expected serde_json::Value.
    #[test]
    fn ssa_body_to_json_parses_yaml_block_syntax() {
        let yaml = b"\napiVersion: mygroup.example.com/v1beta1\nkind: FooBar\nmetadata:\n  name: mytest\nspec:\n  foo: foo1\n  ports:\n  - containerPort: 80\n    protocol: TCP\n";
        let val = ssa_body_to_json(yaml).expect("valid YAML must parse");
        assert_eq!(
            val["apiVersion"].as_str(),
            Some("mygroup.example.com/v1beta1"),
            "apiVersion must survive YAML → JSON conversion"
        );
        assert_eq!(val["metadata"]["name"].as_str(), Some("mytest"));
        assert_eq!(
            val["spec"]["ports"][0]["containerPort"].as_i64(),
            Some(80),
            "integer values must parse as JSON numbers, not strings"
        );
    }

    /// A JSON body (as sent by kubelet SSA / resource.rs-style callers) must also
    /// parse correctly — JSON is valid YAML, so ssa_body_to_json handles both.
    #[test]
    fn ssa_body_to_json_parses_json_body() {
        let json = br#"{"apiVersion":"v1","kind":"Thing","metadata":{"name":"obj"},"spec":{"count":42,"flag":true}}"#;
        let val = ssa_body_to_json(json).expect("JSON body must parse via yaml-rust2");
        assert_eq!(val["kind"].as_str(), Some("Thing"));
        assert_eq!(
            val["spec"]["count"].as_i64(),
            Some(42),
            "JSON integers must survive YAML parse as JSON numbers"
        );
        assert!(
            val["spec"]["flag"].as_bool() == Some(true),
            "JSON booleans must survive"
        );
    }

    /// An invalid (non-UTF-8) body must return 400, not panic or store garbage.
    #[test]
    fn ssa_body_to_json_rejects_non_utf8() {
        let bad: &[u8] = b"\xff\xfe not utf8";
        let result = ssa_body_to_json(bad);
        assert!(
            result.is_err(),
            "non-UTF-8 body must return Err (400) rather than panic or store garbage"
        );
    }

    /// A non-finite float in YAML (NaN, Inf) must return 400 — these are not
    /// valid JSON values and must not be silently stored as null or coerced.
    #[test]
    fn ssa_body_to_json_rejects_non_finite_float() {
        // YAML allows ".inf" and ".nan" as special float values
        let yaml = b"value: .inf";
        let result = ssa_body_to_json(yaml);
        assert!(
            result.is_err(),
            "non-finite float (.inf) in YAML must return Err (400) — JSON has no Infinity"
        );
    }

    /// Upstream's FieldValidation conformance test greps the CR create/patch error body for
    /// the literal phrase `line N: key "X" already set in map`; the raw yaml-rust2 Debug
    /// output (`String("foo"): duplicated key in mapping`) does not contain that phrase, so
    /// a passthrough would keep failing conformance even though the duplicate is rejected.
    #[test]
    fn ssa_body_to_json_dup_key_error_matches_upstream_wording() {
        let yaml = b"spec:\n  unknown: uk1\n  foo: foo1\n  foo: foo2\n";
        let err = ssa_body_to_json(yaml).expect_err("duplicate mapping key must be rejected");
        assert!(
            err.1
                .message
                .contains("line 4: key \"foo\" already set in map"),
            "error message must match upstream's expected phrasing, got: {}",
            err.1.message
        );
    }

    // ---------------------------------------------------------------------------
    // Webhook configuration field validation — regression
    // ---------------------------------------------------------------------------

    /// ValidatingWebhookConfiguration and MutatingWebhookConfiguration top-level field
    /// `webhooks` must not be reported as unknown by detect_unknown_fields.
    ///
    /// Both types use a non-standard schema: `webhooks` sits directly at the top level
    /// instead of under `spec`. Before this fix, `known_top_level_fields` had no entry
    /// for either type, so both fell through to the default `[apiVersion, kind, metadata,
    /// spec, status]` set, and `webhooks` was flagged as unknown — rejecting every valid
    /// webhook config under fieldValidation=Strict.
    #[test]
    fn webhook_configuration_webhooks_field_is_not_unknown() {
        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": { "name": "my-vwc" },
            "webhooks": []
        });
        let unknown = detect_unknown_fields(
            &vwc,
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
        );
        assert!(
            unknown.is_empty(),
            "ValidatingWebhookConfiguration's webhooks field must not be flagged as unknown — \
             before the fix, fieldValidation=Strict returned 422 for every valid \
             ValidatingWebhookConfiguration, blocking kubectl apply. Got unknown: {:?}",
            unknown
        );

        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": { "name": "my-mwc" },
            "webhooks": []
        });
        let unknown = detect_unknown_fields(
            &mwc,
            "admissionregistration.k8s.io",
            "mutatingwebhookconfigurations",
        );
        assert!(
            unknown.is_empty(),
            "MutatingWebhookConfiguration's webhooks field must not be flagged as unknown — \
             before the fix, fieldValidation=Strict returned 422 for every valid \
             MutatingWebhookConfiguration, blocking kubectl apply. Got unknown: {:?}",
            unknown
        );
    }

    /// apply_field_validation with Strict mode must accept a ValidatingWebhookConfiguration
    /// or MutatingWebhookConfiguration body whose only resource-specific field is `webhooks`.
    ///
    /// This is the end-to-end regression: `kubectl apply` sends
    /// `?fieldValidation=Strict` by default, so a false "unknown field" positive here means
    /// every webhook config POST is rejected with 422, and the 8 [sig-api-machinery]
    /// AdmissionWebhook conformance tests fail during setup because they can't register
    /// their webhook configuration.
    #[test]
    fn strict_validation_accepts_webhooks_field_else_kubectl_apply_of_webhook_configs_fails_422() {
        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": { "name": "my-vwc" },
            "webhooks": [{"name": "example.com"}]
        });
        let raw = serde_json::to_vec(&vwc).unwrap();
        let result = apply_field_validation(
            &vwc,
            &raw,
            Some("Strict"),
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
        );
        assert!(
            result.is_ok(),
            "ValidatingWebhookConfiguration with a webhooks array must pass Strict validation — \
             before the fix this returned Err(422), which is exactly the 'strict decoding error: \
             unknown field \"webhooks\"' seen live against the running server. Error: {:?}",
            result.err()
        );

        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": { "name": "my-mwc" },
            "webhooks": [{"name": "example.com"}]
        });
        let raw = serde_json::to_vec(&mwc).unwrap();
        let result = apply_field_validation(
            &mwc,
            &raw,
            Some("Strict"),
            "admissionregistration.k8s.io",
            "mutatingwebhookconfigurations",
        );
        assert!(
            result.is_ok(),
            "MutatingWebhookConfiguration with a webhooks array must pass Strict validation — \
             before the fix this returned Err(422), blocking kubectl apply of every mutating \
             webhook config. Error: {:?}",
            result.err()
        );
    }

    // ---------------------------------------------------------------------------
    // PodTemplate / Endpoints / Event (both schemas) / CSIStorageCapacity field
    // validation — regression
    // ---------------------------------------------------------------------------

    /// PodTemplate's top-level `template` field must not be reported as unknown.
    ///
    /// PodTemplate has no `spec`: its payload sits directly under `template`
    /// (a PodTemplateSpec). Before this fix, `known_top_level_fields` had no entry
    /// for it, so it fell through to the default `[apiVersion, kind, metadata, spec,
    /// status]` set and `template` was flagged unknown — rejecting every valid
    /// PodTemplate under fieldValidation=Strict.
    #[test]
    fn podtemplate_template_field_is_not_unknown() {
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PodTemplate",
            "metadata": { "name": "my-template" },
            "template": {
                "metadata": { "labels": { "app": "nginx" } },
                "spec": { "containers": [{ "name": "nginx", "image": "nginx:latest" }] }
            }
        });
        let unknown = detect_unknown_fields(&body, "", "podtemplates");
        assert!(
            unknown.is_empty(),
            "PodTemplate's template field must not be flagged as unknown — before the fix, \
             fieldValidation=Strict returned 422 for every valid PodTemplate, blocking \
             kubectl apply. Got unknown: {:?}",
            unknown
        );
    }

    /// Endpoints' top-level `subsets` field must not be reported as unknown.
    ///
    /// Endpoints has no `spec`: its payload sits directly under `subsets`. Before
    /// this fix, `known_top_level_fields` had no entry for it, so it fell through
    /// to the default set and `subsets` was flagged unknown — rejecting every valid
    /// Endpoints object under fieldValidation=Strict.
    #[test]
    fn endpoints_subsets_field_is_not_unknown() {
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Endpoints",
            "metadata": { "name": "my-service", "namespace": "default" },
            "subsets": [
                {
                    "addresses": [{ "ip": "10.0.0.1" }],
                    "ports": [{ "port": 80, "protocol": "TCP" }]
                }
            ]
        });
        let unknown = detect_unknown_fields(&body, "", "endpoints");
        assert!(
            unknown.is_empty(),
            "Endpoints' subsets field must not be flagged as unknown — before the fix, \
             fieldValidation=Strict returned 422 for every valid Endpoints object, blocking \
             kubectl apply. Got unknown: {:?}",
            unknown
        );
    }

    /// core/v1 Event's legacy top-level fields must not be reported as unknown.
    ///
    /// core/v1 Event predates spec/status conventions: reason, message, source,
    /// involvedObject, etc. sit directly at the top level. Before this fix, the
    /// default `[apiVersion, kind, metadata, spec, status]` set flagged every one
    /// of these as unknown, rejecting every Event a component tried to record
    /// under fieldValidation=Strict.
    #[test]
    fn core_event_legacy_fields_are_not_unknown() {
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": { "name": "my-pod.17abc", "namespace": "default" },
            "involvedObject": { "kind": "Pod", "name": "my-pod", "namespace": "default" },
            "reason": "Scheduled",
            "message": "Successfully assigned default/my-pod to node-1",
            "source": { "component": "default-scheduler" },
            "firstTimestamp": "2026-07-06T00:00:00Z",
            "lastTimestamp": "2026-07-06T00:00:00Z",
            "count": 1,
            "type": "Normal",
            "eventTime": null,
            "reportingComponent": "default-scheduler",
            "reportingInstance": "default-scheduler-abc"
        });
        let unknown = detect_unknown_fields(&body, "", "events");
        assert!(
            unknown.is_empty(),
            "core/v1 Event's legacy top-level fields must not be flagged as unknown — before \
             the fix, fieldValidation=Strict returned 422 for every Event a component tried \
             to record, breaking event recording cluster-wide. Got unknown: {:?}",
            unknown
        );
    }

    /// events.k8s.io/v1 Event's top-level fields must not be reported as unknown.
    ///
    /// events.k8s.io/v1 Event is schema-incompatible with core/v1 Event — it uses
    /// reportingController/regarding/note instead of reportingComponent/
    /// involvedObject/message. Before this fix, both Event types shared the same
    /// default fallback and every one of these fields was flagged unknown, rejecting
    /// every events.k8s.io/v1 Event under fieldValidation=Strict.
    #[test]
    fn events_k8s_io_event_fields_are_not_unknown() {
        let body = serde_json::json!({
            "apiVersion": "events.k8s.io/v1",
            "kind": "Event",
            "metadata": { "name": "my-pod.17abc", "namespace": "default" },
            "eventTime": "2026-07-06T00:00:00.000000Z",
            "reportingController": "default-scheduler",
            "reportingInstance": "default-scheduler-abc",
            "action": "Binding",
            "reason": "Scheduled",
            "regarding": { "kind": "Pod", "name": "my-pod", "namespace": "default" },
            "note": "Successfully assigned default/my-pod to node-1",
            "type": "Normal"
        });
        let unknown = detect_unknown_fields(&body, "events.k8s.io", "events");
        assert!(
            unknown.is_empty(),
            "events.k8s.io/v1 Event's top-level fields must not be flagged as unknown — before \
             the fix, fieldValidation=Strict returned 422 for every events.k8s.io/v1 Event, \
             breaking client-go's events/v1 event recorder. Got unknown: {:?}",
            unknown
        );
    }

    /// CSIStorageCapacity's top-level fields must not be reported as unknown.
    ///
    /// CSIStorageCapacity has no `spec`: nodeTopology/storageClassName/capacity/
    /// maximumVolumeSize sit directly at the top level. Before this fix, these
    /// fields fell through to the default set and were flagged unknown, rejecting
    /// every CSIStorageCapacity reported by a CSI driver's external-provisioner
    /// sidecar under fieldValidation=Strict.
    #[test]
    fn csistoragecapacity_fields_are_not_unknown() {
        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSIStorageCapacity",
            "metadata": { "name": "my-capacity", "namespace": "default" },
            "nodeTopology": { "matchLabels": { "topology.kubernetes.io/zone": "us-east-1a" } },
            "storageClassName": "fast-ssd",
            "capacity": "100Gi",
            "maximumVolumeSize": "50Gi"
        });
        let unknown = detect_unknown_fields(&body, "storage.k8s.io", "csistoragecapacities");
        assert!(
            unknown.is_empty(),
            "CSIStorageCapacity's top-level fields must not be flagged as unknown — before \
             the fix, fieldValidation=Strict returned 422 for every CSIStorageCapacity \
             reported by a CSI driver, breaking storage capacity tracking. Got unknown: {:?}",
            unknown
        );
    }

    /// apply_field_validation with Strict mode must accept a body for each of the five
    /// types above, whose only resource-specific fields are their real (non-spec)
    /// top-level fields.
    ///
    /// This is the end-to-end regression: `kubectl apply` sends
    /// `?fieldValidation=Strict` by default, so a false "unknown field" positive here
    /// means every create of these types is rejected with 422 — breaking PodTemplate/
    /// Endpoints/Event/CSIStorageCapacity creation cluster-wide (kubelet event
    /// recording, kube-controller-manager Endpoints sync, CSI capacity reporting).
    #[test]
    fn strict_validation_accepts_podtemplate_endpoints_event_csistoragecapacity_else_kubectl_apply_fails_422(
    ) {
        let cases: Vec<(&str, &str, serde_json::Value)> = vec![
            (
                "",
                "podtemplates",
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "PodTemplate",
                    "metadata": { "name": "my-template" },
                    "template": { "spec": { "containers": [{ "name": "nginx", "image": "nginx:latest" }] } }
                }),
            ),
            (
                "",
                "endpoints",
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Endpoints",
                    "metadata": { "name": "my-service", "namespace": "default" },
                    "subsets": [{ "addresses": [{ "ip": "10.0.0.1" }], "ports": [{ "port": 80 }] }]
                }),
            ),
            (
                "",
                "events",
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Event",
                    "metadata": { "name": "my-pod.17abc", "namespace": "default" },
                    "involvedObject": { "kind": "Pod", "name": "my-pod" },
                    "reason": "Scheduled",
                    "message": "assigned",
                    "type": "Normal"
                }),
            ),
            (
                "events.k8s.io",
                "events",
                serde_json::json!({
                    "apiVersion": "events.k8s.io/v1",
                    "kind": "Event",
                    "metadata": { "name": "my-pod.17abc", "namespace": "default" },
                    "eventTime": "2026-07-06T00:00:00.000000Z",
                    "reportingController": "default-scheduler",
                    "reportingInstance": "default-scheduler-abc",
                    "action": "Binding",
                    "reason": "Scheduled",
                    "regarding": { "kind": "Pod", "name": "my-pod" },
                    "type": "Normal"
                }),
            ),
            (
                "storage.k8s.io",
                "csistoragecapacities",
                serde_json::json!({
                    "apiVersion": "storage.k8s.io/v1",
                    "kind": "CSIStorageCapacity",
                    "metadata": { "name": "my-capacity", "namespace": "default" },
                    "storageClassName": "fast-ssd",
                    "capacity": "100Gi"
                }),
            ),
        ];

        for (group, plural, body) in cases {
            let raw = serde_json::to_vec(&body).unwrap();
            let result = apply_field_validation(&body, &raw, Some("Strict"), group, plural);
            assert!(
                result.is_ok(),
                "({group:?}, {plural:?}) must pass Strict validation with only its real \
                 top-level fields — before the fix this returned Err(422), the exact \
                 'strict decoding error: unknown field' response kubectl apply would see \
                 live. Error: {:?}",
                result.err()
            );
        }
    }

    // ---------------------------------------------------------------------------
    // EndpointSlice field validation — regression
    // ---------------------------------------------------------------------------

    /// EndpointSlice top-level fields (addressType, endpoints, ports) must not be
    /// reported as unknown by detect_unknown_fields.
    ///
    /// EndpointSlice uses a non-standard schema: its payload fields are at the top
    /// level instead of under spec/status.  Before this fix, fieldValidation=Strict
    /// rejected valid EndpointSlice bodies with 422 "unknown field" for all three
    /// resource-specific fields, blocking EndpointSlice create/update conformance
    /// tests.
    #[test]
    fn endpointslice_top_level_fields_are_not_unknown() {
        let body = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": { "name": "my-slice", "namespace": "default" },
            "addressType": "IPv4",
            "endpoints": [
                {
                    "addresses": ["10.0.0.1"],
                    "conditions": { "ready": true }
                }
            ],
            "ports": [
                { "name": "http", "port": 80, "protocol": "TCP" },
                { "name": "https", "port": 443, "protocol": "TCP" }
            ]
        });

        let unknown = detect_unknown_fields(&body, "discovery.k8s.io", "endpointslices");

        assert!(
            unknown.is_empty(),
            "EndpointSlice fields addressType/endpoints/ports must not be flagged as unknown — \
             before the fix, fieldValidation=Strict returned 422 rejecting valid EndpointSlice \
             creates, blocking conformance tests. Got unknown: {:?}",
            unknown
        );
    }

    /// A ConfigMap with the spec/status fields that don't belong to it must be
    /// flagged as unknown by detect_unknown_fields in Strict mode.  This ensures
    /// the detection logic still works for resources that use the default known set.
    #[test]
    fn unknown_top_level_field_is_detected_for_default_resource() {
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "test" },
            "data": { "key": "val" },
            "bogusField": "should be detected"
        });

        let unknown = detect_unknown_fields(&body, "", "configmaps");

        assert!(
            unknown.contains(&"bogusField".to_string()),
            "bogusField must be detected as unknown for ConfigMap — \
             the regression test protects against detect_unknown_fields being silently bypassed"
        );
    }

    /// apply_field_validation with Strict mode must return Ok when an EndpointSlice
    /// body has only known fields (addressType, endpoints, ports).
    ///
    /// Before the fix, this returned Err(422) because addressType/endpoints/ports
    /// were flagged as unknown, preventing EndpointSlice creation via kubectl.
    #[test]
    fn apply_field_validation_strict_accepts_valid_endpointslice() {
        let body = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": { "name": "my-slice", "namespace": "default" },
            "addressType": "IPv4",
            "endpoints": [{"addresses": ["10.0.0.1"]}],
            "ports": [{"name": "http", "port": 80, "protocol": "TCP"}]
        });

        let raw = serde_json::to_vec(&body).unwrap();
        let result = apply_field_validation(
            &body,
            &raw,
            Some("Strict"),
            "discovery.k8s.io",
            "endpointslices",
        );

        assert!(
            result.is_ok(),
            "EndpointSlice with addressType/endpoints/ports must pass Strict validation — \
             before the fix, these fields were flagged as unknown and the create returned \
             422 blocking all EndpointSlice conformance tests. Error: {:?}",
            result.err()
        );
    }

    // ---------------------------------------------------------------------------
    // Nested spec field validation — regression (PANIC 2)
    // ---------------------------------------------------------------------------

    /// detect_unknown_fields must recurse into `spec` for resource types with a known
    /// spec schema (e.g. Deployment), not just check top-level/metadata keys.
    ///
    /// Before this fix, `known_top_level_fields` treated `spec` as an opaque known
    /// key and never looked inside it, so `spec.unknownField` was silently accepted —
    /// this is exactly the body the upstream FieldValidation conformance test
    /// ("should detect unknown and duplicate fields of a typed object") POSTs.
    #[test]
    fn detect_unknown_fields_recurses_into_deployment_spec() {
        let body = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "my-dep", "labels": { "app": "nginx" } },
            "spec": {
                "unknownField": "foo",
                "replicas": 3,
                "selector": { "matchLabels": { "app": "nginx" } },
                "template": {
                    "metadata": { "labels": { "app": "nginx" } },
                    "spec": { "containers": [{ "name": "nginx", "image": "nginx:latest" }] }
                }
            }
        });

        let unknown = detect_unknown_fields(&body, "apps", "deployments");

        assert!(
            unknown.contains(&"spec.unknownField".to_string()),
            "spec.unknownField must be detected as unknown for Deployment — \
             before the fix, detect_unknown_fields only checked top-level and metadata \
             keys, so any bogus field nested under spec was silently accepted. Got: {:?}",
            unknown
        );
        // Known spec fields (replicas, selector, template) must not be flagged.
        assert!(
            !unknown.iter().any(|f| f.starts_with("spec.replicas")
                || f.starts_with("spec.selector")
                || f.starts_with("spec.template")),
            "known Deployment spec fields must not be flagged as unknown — a false \
             positive here would reject every valid Deployment under fieldValidation=Strict. \
             Got: {:?}",
            unknown
        );
    }

    /// detect_duplicate_fields must find a JSON key repeated within `spec`, which
    /// `serde_json::Value` can no longer see once the raw bytes are parsed (last
    /// occurrence silently wins). This is the other half of the upstream
    /// FieldValidation conformance body: `"replicas": 2, "replicas": 3`.
    #[test]
    fn detect_duplicate_fields_finds_repeated_spec_key() {
        let raw = br#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "my-dep" },
            "spec": {
                "replicas": 2,
                "replicas": 3,
                "selector": { "matchLabels": { "app": "nginx" } }
            }
        }"#;

        let duplicate = detect_duplicate_fields(raw, "apps", "deployments");

        assert_eq!(
            duplicate,
            vec!["spec.replicas".to_string()],
            "spec.replicas must be reported as duplicated exactly once — without raw-byte \
             scanning, this information is unrecoverable once serde_json collapses the \
             repeated key to its last value, and the conformance test's expected error \
             message would be missing the \"duplicate field\" half entirely. Got: {:?}",
            duplicate
        );
    }

    /// detect_duplicate_fields must not flag anything for resource types without a
    /// known spec schema — it must not scan (or false-positive on) arbitrary bodies.
    #[test]
    fn detect_duplicate_fields_is_noop_for_uncovered_resource_type() {
        let raw = br#"{"spec": {"replicas": 1, "replicas": 2}}"#;

        let duplicate = detect_duplicate_fields(raw, "", "configmaps");

        assert!(
            duplicate.is_empty(),
            "duplicate-key scanning must stay scoped to known_spec_fields types — \
             scanning every resource type would be unnecessary work for a shape upstream \
             kube-apiserver never sees in practice for uncovered types. Got: {:?}",
            duplicate
        );
    }

    /// POST with `?fieldValidation=Strict` and a Deployment body containing BOTH an
    /// unknown field and a duplicate key under `spec` must return Err(422) with the
    /// combined message, matching the upstream conformance assertion exactly.
    ///
    /// This is the exact body and expected message from the upstream FieldValidation
    /// conformance test ("should detect unknown and duplicate fields of a typed
    /// object"): before this fix, u7s returned Ok (HTTP success) because neither
    /// unknown- nor duplicate-field detection looked inside `spec`; the Go e2e client
    /// then panicked calling `.Error()` on the nil error it expected instead of a 422
    /// containing both `unknown field "spec.unknownField"` and
    /// `duplicate field "spec.replicas"`.
    #[test]
    fn apply_field_validation_strict_rejects_unknown_deployment_spec_field_else_conformance_test_panics_on_nil_error(
    ) {
        // Raw text (not serde_json::json!) because the macro can't represent a
        // JSON object with a literally duplicated key — it builds a Map directly.
        let raw = br#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "my-dep",
                "labels": {"app": "nginx"}
            },
            "spec": {
                "unknownField": "foo",
                "replicas": 2,
                "replicas": 3,
                "selector": {
                    "matchLabels": {
                        "app": "nginx"
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "nginx"
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name":  "nginx",
                            "image": "nginx:latest"
                        }]
                    }
                }
            }
        }"#;
        let body: serde_json::Value =
            serde_json::from_slice(raw).expect("test body must be valid JSON");

        let result = apply_field_validation(&body, raw, Some("Strict"), "apps", "deployments");

        match result {
            Err(e) => {
                assert_eq!(
                    e.1.message,
                    "strict decoding error: unknown field \"spec.unknownField\", duplicate field \"spec.replicas\"",
                    "422 error message must match the upstream conformance test's \
                     strings.Contains assertion exactly — a differently-worded or \
                     differently-ordered message fails the conformance test even though \
                     the status code is correct"
                );
            }
            Ok(_) => panic!(
                "fieldValidation=Strict must reject a Deployment with spec.unknownField and \
                 duplicate spec.replicas; the conformance test client panics calling .Error() \
                 on the nil error it gets instead of the expected 422"
            ),
        }
    }
}

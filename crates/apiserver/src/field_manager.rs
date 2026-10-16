//! Server-side-apply field ownership: the `metadata.managedFields` bookkeeping that lets an
//! apply detect conflicts, take ownership with `force`, and remove fields it stopped
//! applying. Field identity follows structured-merge-diff's path elements (`f:` field, `k:`
//! keyed list item, `v:` set member); list merge keys come from the same tables
//! strategic-merge-patch uses, so ownership and merge agree on what an item is.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use crate::patch::{ssa_merge_key_for_path, MergeKeyKind};

/// One structured-merge-diff path: `["f:spec", "f:containers", "k:{\"name\":\"c\"}", "f:image"]`.
pub(crate) type Path = Vec<String>;
type PathSet = BTreeSet<Path>;

const OPERATION_APPLY: &str = "Apply";
const OPERATION_UPDATE: &str = "Update";

/// Server-managed identity fields no manager owns (structured-merge-diff's `stripMeta`).
const UNOWNED: &[&str] = &[
    "apiVersion",
    "kind",
    "metadata.name",
    "metadata.namespace",
    "metadata.creationTimestamp",
    "metadata.selfLink",
    "metadata.uid",
    "metadata.clusterName",
    "metadata.generation",
    "metadata.managedFields",
    "metadata.resourceVersion",
];

/// String maps the schema marks granular: the map itself is a member alongside its keys.
const MAP_FIELDS: &[&str] = &["metadata.labels", "metadata.annotations"];

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Manager {
    name: String,
    operation: &'static str,
    api_version: String,
    subresource: Option<String>,
    time: Option<String>,
    set: PathSet,
}

impl Manager {
    fn is(&self, name: &str, operation: &str, subresource: Option<&str>) -> bool {
        self.name == name
            && self.operation == operation
            && self.subresource.as_deref() == subresource
    }
}

#[derive(Debug)]
pub(crate) struct Conflict {
    manager: String,
    api_version: String,
    field: String,
}

pub(crate) struct Request<'a> {
    pub manager: &'a str,
    pub api_version: &'a str,
    pub subresource: Option<&'a str>,
    /// CRD `openAPIV3Schema` for custom resources, `None` for built-ins.
    pub schema: Option<&'a Value>,
    pub now: &'a str,
}

pub(crate) struct ApplyPlan {
    /// Fields the manager applied before, no longer applies, and nobody else owns.
    removals: Vec<Path>,
    managers: Vec<Manager>,
}

#[derive(Default)]
struct Extracted {
    set: PathSet,
    /// Members that carry a comparable value: scalars and atomic lists.
    values: BTreeMap<Path, Value>,
}

fn join(dotted: &str, key: &str) -> String {
    if dotted.is_empty() {
        key.to_string()
    } else {
        format!("{dotted}.{key}")
    }
}

fn extract(obj: &Value, schema: Option<&Value>) -> Extracted {
    let mut out = Extracted::default();
    if let Some(m) = obj.as_object() {
        walk_children(m, "", &mut Vec::new(), schema, &mut out);
    }
    out
}

fn walk_children(
    m: &Map<String, Value>,
    dotted: &str,
    path: &mut Path,
    schema: Option<&Value>,
    out: &mut Extracted,
) {
    for (k, child) in m {
        let d = join(dotted, k);
        if UNOWNED.contains(&d.as_str()) {
            continue;
        }
        path.push(format!("f:{k}"));
        walk_field(child, &d, path, schema, out);
        path.pop();
    }
}

fn walk_field(
    v: &Value,
    dotted: &str,
    path: &mut Path,
    schema: Option<&Value>,
    out: &mut Extracted,
) {
    match v {
        Value::Null => {}
        Value::Object(m) if !m.is_empty() => {
            if MAP_FIELDS.contains(&dotted) {
                out.set.insert(path.clone());
            }
            walk_children(m, dotted, path, schema, out);
        }
        Value::Array(items) => walk_list(items, v, dotted, path, schema, out),
        _ => {
            out.set.insert(path.clone());
            out.values.insert(path.clone(), v.clone());
        }
    }
}

fn walk_list(
    items: &[Value],
    list: &Value,
    dotted: &str,
    path: &mut Path,
    schema: Option<&Value>,
    out: &mut Extracted,
) {
    match ssa_merge_key_for_path(dotted, schema) {
        MergeKeyKind::Key(keys) => {
            if let Some(ids) = item_ids(items, &keys) {
                for (item, id) in items.iter().zip(ids) {
                    path.push(id);
                    out.set.insert(path.clone());
                    if let Some(m) = item.as_object() {
                        walk_children(m, dotted, path, schema, out);
                    }
                    path.pop();
                }
                return;
            }
        }
        MergeKeyKind::Set => {
            if items
                .iter()
                .all(|i| !i.is_object() && !i.is_array() && !i.is_null())
            {
                for item in items {
                    path.push(format!("v:{item}"));
                    out.set.insert(path.clone());
                    out.values.insert(path.clone(), item.clone());
                    path.pop();
                }
                return;
            }
        }
        MergeKeyKind::Replace | MergeKeyKind::Unknown => {}
    }
    out.set.insert(path.clone());
    out.values.insert(path.clone(), list.clone());
}

/// A port's `protocol` is part of its identity and defaults to TCP, so an item that omits it
/// is the same item as one that spells it out.
fn key_value(v: Option<&Value>, key: &str) -> Option<Value> {
    match v {
        Some(v) => Some(v.clone()),
        None if key == "protocol" => Some(Value::String("TCP".into())),
        None => None,
    }
}

/// `k:{...}` identity per item, or `None` when any item lacks every key field or two items
/// collide — the list is then treated as atomic, as upstream does for an unkeyable list.
fn item_ids(items: &[Value], keys: &[String]) -> Option<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut ids = Vec::with_capacity(items.len());
    for item in items {
        let obj = item.as_object()?;
        let mut key = Map::new();
        for k in keys {
            if let Some(v) = key_value(obj.get(k), k) {
                key.insert(k.clone(), v);
            }
        }
        if !keys.iter().any(|k| k != "protocol" && obj.contains_key(k)) {
            return None;
        }
        let id = format!("k:{}", Value::Object(key));
        if !seen.insert(id.clone()) {
            return None;
        }
        ids.push(id);
    }
    Some(ids)
}

fn parse_fields_v1(node: &Value) -> PathSet {
    fn go(node: &Value, path: &mut Path, out: &mut PathSet) {
        let Some(m) = node.as_object() else { return };
        if m.is_empty() {
            if !path.is_empty() {
                out.insert(path.clone());
            }
            return;
        }
        for (k, child) in m {
            if k == "." {
                out.insert(path.clone());
            } else {
                path.push(k.clone());
                go(child, path, out);
                path.pop();
            }
        }
    }
    let mut out = PathSet::new();
    go(node, &mut Vec::new(), &mut out);
    out
}

fn to_fields_v1(set: &PathSet) -> Value {
    #[derive(Default)]
    struct Node {
        member: bool,
        children: BTreeMap<String, Node>,
    }
    fn render(n: &Node) -> Value {
        let mut m = Map::new();
        if n.member && !n.children.is_empty() {
            m.insert(".".into(), json!({}));
        }
        for (k, c) in &n.children {
            m.insert(k.clone(), render(c));
        }
        Value::Object(m)
    }
    let mut root = Node::default();
    for path in set {
        let mut n = &mut root;
        for e in path {
            n = n.children.entry(e.clone()).or_default();
        }
        n.member = true;
    }
    render(&root)
}

fn read_managers(obj: &Value) -> Vec<Manager> {
    obj["metadata"]["managedFields"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| {
            Some(Manager {
                name: e.get("manager")?.as_str()?.to_string(),
                operation: match e.get("operation")?.as_str()? {
                    OPERATION_APPLY => OPERATION_APPLY,
                    OPERATION_UPDATE => OPERATION_UPDATE,
                    _ => return None,
                },
                api_version: e.get("apiVersion")?.as_str()?.to_string(),
                subresource: e
                    .get("subresource")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                time: e.get("time").and_then(|v| v.as_str()).map(String::from),
                set: parse_fields_v1(e.get("fieldsV1")?),
            })
        })
        .collect()
}

fn write_managers(obj: &mut Value, managers: &[Manager]) {
    let Some(meta) = obj.get_mut("metadata").and_then(|m| m.as_object_mut()) else {
        return;
    };
    if managers.is_empty() {
        meta.remove("managedFields");
        return;
    }
    let entries: Vec<Value> = managers
        .iter()
        .map(|m| {
            let mut e = json!({
                "manager": m.name,
                "operation": m.operation,
                "apiVersion": m.api_version,
                "fieldsType": "FieldsV1",
                "fieldsV1": to_fields_v1(&m.set),
            });
            if let Some(t) = &m.time {
                e["time"] = json!(t);
            }
            if let Some(s) = &m.subresource {
                e["subresource"] = json!(s);
            }
            e
        })
        .collect();
    meta.insert("managedFields".into(), Value::Array(entries));
}

fn elem_matches(item: &Value, elem: &str) -> bool {
    if let Some(k) = elem.strip_prefix("k:") {
        let Ok(Value::Object(key)) = serde_json::from_str::<Value>(k) else {
            return false;
        };
        key.iter()
            .all(|(kk, vv)| key_value(item.get(kk), kk).as_ref() == Some(vv))
    } else if let Some(v) = elem.strip_prefix("v:") {
        serde_json::from_str::<Value>(v).is_ok_and(|v| *item == v)
    } else {
        false
    }
}

fn get_at<'a>(mut v: &'a Value, path: &[String]) -> Option<&'a Value> {
    for e in path {
        v = match e.strip_prefix("f:") {
            Some(f) => v.as_object()?.get(f)?,
            None => v.as_array()?.iter().find(|i| elem_matches(i, e))?,
        };
    }
    Some(v)
}

fn get_at_mut<'a>(mut v: &'a mut Value, path: &[String]) -> Option<&'a mut Value> {
    for e in path {
        v = match e.strip_prefix("f:") {
            Some(f) => v.as_object_mut()?.get_mut(f)?,
            None => v.as_array_mut()?.iter_mut().find(|i| elem_matches(i, e))?,
        };
    }
    Some(v)
}

fn is_item(elem: &str) -> bool {
    elem.starts_with("k:") || elem.starts_with("v:")
}

fn owns(set: &PathSet, p: &Path) -> bool {
    if p.last().is_some_and(|e| is_item(e)) {
        set.range(p.clone()..)
            .next()
            .is_some_and(|q| q.starts_with(p))
    } else {
        set.contains(p)
    }
}

fn display_path(path: &[String]) -> String {
    let mut s = String::new();
    for e in path {
        if let Some(f) = e.strip_prefix("f:") {
            s.push('.');
            s.push_str(f);
        } else if let Some(k) = e.strip_prefix("k:") {
            if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(k) {
                let parts: Vec<String> = m.iter().map(|(k, v)| format!("{k}={v}")).collect();
                s.push_str(&format!("[{}]", parts.join(",")));
            }
        } else if let Some(v) = e.strip_prefix("v:") {
            s.push_str(&format!("[={v}]"));
        }
    }
    s
}

/// The part of an apply body the apply actually manages: a kind with a status subresource
/// never takes `status` from a main-resource write, so it owns nothing there.
pub(crate) fn applied_fields(body: &Value, has_status_subresource: bool) -> Value {
    let mut applied = body.clone();
    if has_status_subresource {
        if let Some(o) = applied.as_object_mut() {
            o.remove("status");
        }
    }
    applied
}

const FIELD_MANAGER_HEADER: &str = "x-u7s-field-manager";
const FORCE_HEADER: &str = "x-u7s-force";

/// Forward `?fieldManager=`/`?force=` to a handler that has no query extractor of its own
/// (custom-resource patch, reached through the generic handler's fallback).
pub(crate) fn forward_query(
    headers: &mut axum::http::HeaderMap,
    manager: Option<&str>,
    force: bool,
) {
    if let Some(Ok(v)) = manager.map(axum::http::HeaderValue::from_str) {
        headers.insert(FIELD_MANAGER_HEADER, v);
    }
    if force {
        headers.insert(FORCE_HEADER, axum::http::HeaderValue::from_static("true"));
    }
}

/// The manager and `force` flag of a request whose query was forwarded by [`forward_query`].
pub(crate) fn forwarded_query(headers: &axum::http::HeaderMap) -> (String, bool) {
    let get = |h: &str| headers.get(h).and_then(|v| v.to_str().ok());
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    (
        request_manager(get(FIELD_MANAGER_HEADER), user_agent),
        get(FORCE_HEADER) == Some("true"),
    )
}

/// Who is writing, for handlers that record ownership of a non-apply write.
pub(crate) struct WriteIdentity {
    manager: String,
    now: String,
}

impl WriteIdentity {
    pub(crate) fn new(query_manager: Option<&str>, headers: &axum::http::HeaderMap) -> Self {
        let forwarded = headers
            .get(FIELD_MANAGER_HEADER)
            .and_then(|v| v.to_str().ok());
        let user_agent = headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok());
        Self {
            manager: request_manager(query_manager.or(forwarded), user_agent),
            now: crate::util::utc_now_rfc3339(),
        }
    }

    /// Record `after` as an Update by this writer of `before` (`Value::Null` for a create).
    pub(crate) fn record(
        &self,
        before: &Value,
        after: &mut Value,
        api_version: &str,
        subresource: Option<&str>,
        schema: Option<&Value>,
    ) {
        record_update(
            before,
            after,
            &Request {
                manager: &self.manager,
                api_version,
                subresource,
                schema,
                now: &self.now,
            },
        );
    }
}

/// The manager name upstream records for a request without `?fieldManager=`: the user agent's
/// product token.
pub(crate) fn request_manager(query: Option<&str>, user_agent: Option<&str>) -> String {
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        return q.to_string();
    }
    user_agent
        .and_then(|ua| ua.split('/').next())
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

/// Decide what an apply of `applied` onto `live` owns, conflicts with, and removes. `live`
/// is `Value::Null` for an apply that creates the object.
pub(crate) fn plan_apply(
    live: &Value,
    applied: &Value,
    force: bool,
    req: &Request<'_>,
) -> Result<ApplyPlan, Vec<Conflict>> {
    let ext = extract(applied, req.schema);
    let mut managers = read_managers(live);
    let me = managers
        .iter()
        .position(|m| m.is(req.manager, OPERATION_APPLY, req.subresource));
    let previous = me.map(|i| managers[i].set.clone()).unwrap_or_default();

    let mut conflicts = Vec::new();
    let mut taken = PathSet::new();
    for (path, value) in &ext.values {
        let Some(current) = get_at(live, path) else {
            continue;
        };
        if current == value {
            continue;
        }
        for (i, m) in managers.iter().enumerate() {
            if Some(i) != me && m.set.contains(path) {
                conflicts.push(Conflict {
                    manager: m.name.clone(),
                    api_version: m.api_version.clone(),
                    field: display_path(path),
                });
                taken.insert(path.clone());
            }
        }
    }
    if !conflicts.is_empty() && !force {
        return Err(conflicts);
    }
    for (i, m) in managers.iter_mut().enumerate() {
        if Some(i) != me {
            m.set.retain(|p| !taken.contains(p));
        }
    }

    let mut removals: Vec<Path> = previous
        .difference(&ext.set)
        .filter(|p| {
            // Still applied, just with a different shape (atomic list <-> keyed items): the
            // field is not dropped, so neither it nor its items may be deleted.
            let covered_by_atomic = ext.values.keys().any(|q| p.starts_with(q));
            let still_applied_below = ext
                .set
                .range((*p).clone()..)
                .next()
                .is_some_and(|q| q.starts_with(p));
            !covered_by_atomic && !still_applied_below
        })
        .filter(|p| {
            !managers
                .iter()
                .enumerate()
                .any(|(i, m)| Some(i) != me && owns(&m.set, p))
        })
        .cloned()
        .collect();
    // Items first, so an item is matched by its key fields before its own children (which
    // include those key fields) are removed; then deepest-first so a map is only emptied
    // after its entries.
    removals.sort_by_key(|p| {
        (
            !p.last().is_some_and(|e| is_item(e)),
            std::cmp::Reverse(p.len()),
        )
    });

    let unchanged = me
        .is_some_and(|i| managers[i].set == ext.set && managers[i].api_version == req.api_version);
    let time = match me {
        Some(i) if unchanged => managers[i].time.clone(),
        _ => Some(req.now.to_string()),
    };
    let mine = Manager {
        name: req.manager.to_string(),
        operation: OPERATION_APPLY,
        api_version: req.api_version.to_string(),
        subresource: req.subresource.map(String::from),
        time,
        set: ext.set,
    };
    match me {
        Some(i) => managers[i] = mine,
        None => managers.push(mine),
    }
    managers.retain(|m| !m.set.is_empty() || m.is(req.manager, OPERATION_APPLY, req.subresource));
    Ok(ApplyPlan { removals, managers })
}

impl ApplyPlan {
    /// Delete the fields this apply dropped, then record the new ownership on `obj`.
    pub(crate) fn remove_dropped_fields(&self, obj: &mut Value) {
        for path in &self.removals {
            remove_member(obj, path);
        }
    }

    pub(crate) fn record(&self, obj: &mut Value) {
        write_managers(obj, &self.managers);
    }
}

fn remove_member(obj: &mut Value, path: &Path) {
    let Some((last, parent_path)) = path.split_last() else {
        return;
    };
    let Some(parent) = get_at_mut(obj, parent_path) else {
        return;
    };
    if let Some(f) = last.strip_prefix("f:") {
        let Some(map) = parent.as_object_mut() else {
            return;
        };
        let removable = match map.get(f) {
            Some(Value::Object(o)) => o.is_empty(),
            Some(_) => true,
            None => false,
        };
        if removable {
            map.remove(f);
        }
        return;
    }
    let emptied = match parent.as_array_mut() {
        Some(arr) => {
            arr.retain(|i| !elem_matches(i, last));
            arr.is_empty()
        }
        None => return,
    };
    if emptied {
        if let Some((field, grandparent)) = parent_path.split_last() {
            if let (Some(f), Some(gp)) = (
                field.strip_prefix("f:"),
                get_at_mut(obj, grandparent).and_then(|g| g.as_object_mut()),
            ) {
                gp.remove(f);
            }
        }
    }
}

/// Upstream's rule for the managedFields a non-apply write carries (fieldmanager.go
/// `decodeLiveOrNew`): `[]` or `[{}]` resets ownership, a decodable non-empty list is the
/// base the write's changes are layered on, anything else falls back to the live object's.
/// A subresource write never takes ownership from the request object.
fn base_managers(live: &[Manager], after: &Value, subresource: bool) -> Vec<Manager> {
    if subresource {
        return live.to_vec();
    }
    if let Some(entries) = after["metadata"]["managedFields"].as_array() {
        let reset = entries.is_empty()
            || (entries.len() == 1 && entries[0].as_object().is_some_and(|o| o.is_empty()));
        if reset {
            return Vec::new();
        }
    }
    let supplied = read_managers(after);
    if supplied.is_empty() {
        live.to_vec()
    } else {
        supplied
    }
}

/// Record on `after` that `manager` changed every field that differs from `before`, taking
/// those fields (and dropping fields that disappeared) from every other manager. Runs for
/// every non-apply write, including ones whose body carries no managedFields (PUT, POST),
/// so ownership is never lost by a write that did not mention it.
pub(crate) fn record_update(before: &Value, after: &mut Value, req: &Request<'_>) {
    let old = extract(before, req.schema);
    let new = extract(after, req.schema);
    let mut changed: PathSet = new.set.difference(&old.set).cloned().collect();
    for (path, value) in &new.values {
        if old.values.get(path).is_some_and(|v| v != value) {
            changed.insert(path.clone());
        }
    }
    let removed: PathSet = old.set.difference(&new.set).cloned().collect();

    let live = read_managers(before);
    let mut managers = base_managers(&live, after, req.subresource.is_some());
    for m in &mut managers {
        m.set
            .retain(|p| !changed.contains(p) && !removed.contains(p));
    }
    if !changed.is_empty() {
        let idx = managers
            .iter()
            .position(|m| m.is(req.manager, OPERATION_UPDATE, req.subresource));
        match idx {
            Some(i) => {
                managers[i].set.extend(changed);
                managers[i].api_version = req.api_version.to_string();
                managers[i].time = Some(req.now.to_string());
            }
            None => managers.push(Manager {
                name: req.manager.to_string(),
                operation: OPERATION_UPDATE,
                api_version: req.api_version.to_string(),
                subresource: req.subresource.map(String::from),
                time: Some(req.now.to_string()),
                set: changed,
            }),
        }
    }
    managers.retain(|m| !m.set.is_empty());
    write_managers(after, &managers);
}

impl Conflict {
    /// Upstream's 409: one `FieldManagerConflict` cause per conflicting field.
    pub(crate) fn into_status(conflicts: Vec<Conflict>) -> crate::status::StatusError {
        let n = conflicts.len();
        let lines: Vec<String> = conflicts
            .iter()
            .map(|c| {
                format!(
                    "conflict with \"{}\" using {}: {}",
                    c.manager, c.api_version, c.field
                )
            })
            .collect();
        let causes: Vec<Value> = conflicts
            .iter()
            .map(|c| {
                json!({
                    "reason": "FieldManagerConflict",
                    "message": format!("conflict with \"{}\" using {}", c.manager, c.api_version),
                    "field": c.field,
                })
            })
            .collect();
        let message = format!(
            "Apply failed with {n} conflict{}: {}",
            if n == 1 { "" } else { "s" },
            lines.join("\n")
        );
        crate::status::Status::conflict_with_causes(message, causes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(manager: &'a str) -> Request<'a> {
        Request {
            manager,
            api_version: "apps/v1",
            subresource: None,
            schema: None,
            now: "2026-01-01T00:00:00Z",
        }
    }

    fn deployment(replicas: Option<i64>, port: bool) -> Value {
        let mut container = json!({"name": "nginx", "image": "img"});
        if port {
            container["ports"] = json!([{"containerPort": 80, "protocol": "TCP"}]);
        }
        let mut d = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "d", "labels": {"app": "nginx"}},
            "spec": {"template": {"spec": {"containers": [container]}}}
        });
        if let Some(r) = replicas {
            d["spec"]["replicas"] = json!(r);
        }
        d
    }

    fn apply(
        live: &mut Value,
        applied: &Value,
        manager: &str,
        force: bool,
    ) -> Result<(), Vec<Conflict>> {
        let plan = plan_apply(live, applied, force, &req(manager))?;
        let mut merged = live.clone();
        crate::patch::strategic_merge_patch_ssa(&mut merged, applied).unwrap();
        plan.remove_dropped_fields(&mut merged);
        plan.record(&mut merged);
        *live = merged;
        Ok(())
    }

    /// kubectl and every GitOps tool read ownership back from managedFields; the encoding
    /// must match upstream byte-for-byte or they see phantom diffs.
    #[test]
    fn applied_fields_serialize_to_upstream_fields_v1() {
        let pod = json!({
            "apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "test-container", "image": "test-image"}]}
        });
        let fv1 = to_fields_v1(&extract(&pod, None).set);
        assert_eq!(
            fv1.to_string(),
            r#"{"f:spec":{"f:containers":{"k:{\"name\":\"test-container\"}":{".":{},"f:image":{},"f:name":{}}}}}"#
        );
        let svc = json!({
            "apiVersion": "v1", "kind": "Service", "metadata": {"name": "s"},
            "spec": {"ports": [{"port": 8080, "protocol": "UDP"}]}
        });
        assert_eq!(
            to_fields_v1(&extract(&svc, None).set).to_string(),
            r#"{"f:spec":{"f:ports":{"k:{\"port\":8080,\"protocol\":\"UDP\"}":{".":{},"f:port":{},"f:protocol":{}}}}}"#
        );
    }

    #[test]
    fn fields_v1_round_trips() {
        let set = extract(&deployment(Some(3), true), None).set;
        assert_eq!(parse_fields_v1(&to_fields_v1(&set)), set);
    }

    /// A manager that stops applying a field it owns must lose that field, or removed
    /// config lingers on the object forever.
    #[test]
    fn dropping_an_owned_field_removes_it() {
        let mut live = json!({});
        apply(&mut live, &deployment(Some(3), true), "a", false).unwrap();
        assert!(get_at(&live, &["f:spec".into(), "f:replicas".into()]).is_some());

        apply(&mut live, &deployment(None, false), "a", false).unwrap();
        assert!(
            live["spec"].get("replicas").is_none(),
            "owned replicas must be removed"
        );
        let ctr = &live["spec"]["template"]["spec"]["containers"][0];
        assert!(
            ctr.get("ports").is_none(),
            "owned port list entry must be removed: {ctr}"
        );
    }

    /// Fields another manager also owns are shared, so one manager dropping them must not
    /// delete them out from under the other.
    #[test]
    fn dropping_a_co_owned_field_keeps_it() {
        let mut live = json!({});
        apply(&mut live, &deployment(Some(3), false), "a", false).unwrap();
        apply(&mut live, &deployment(Some(3), false), "b", false).unwrap();
        apply(&mut live, &deployment(None, false), "a", false).unwrap();
        assert_eq!(live["spec"]["replicas"], 3);
    }

    /// Applying a different value for a field someone else owns must be refused, or two
    /// tools silently overwrite each other's config.
    #[test]
    fn applying_over_another_managers_value_conflicts_until_forced() {
        let mut live = json!({});
        apply(&mut live, &deployment(Some(3), false), "a", false).unwrap();
        let conflicts = apply(&mut live, &deployment(Some(5), false), "b", false).unwrap_err();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].field, ".spec.replicas");
        assert_eq!(conflicts[0].manager, "a");
        assert_eq!(
            live["spec"]["replicas"], 3,
            "a refused apply must not change the object"
        );

        apply(&mut live, &deployment(Some(5), false), "b", true).unwrap();
        assert_eq!(live["spec"]["replicas"], 5);
        let owners: Vec<_> = read_managers(&live)
            .into_iter()
            .filter(|m| {
                m.set
                    .contains(&vec!["f:spec".to_string(), "f:replicas".to_string()])
            })
            .map(|m| m.name)
            .collect();
        assert_eq!(owners, ["b"], "force must move ownership, not share it");
    }

    /// A non-apply write that changes a field takes it from the applier, so the applier's
    /// next apply of the old value conflicts instead of silently reverting the write.
    #[test]
    fn an_update_takes_ownership_and_conflicts_with_the_next_apply() {
        let mut live = json!({});
        apply(&mut live, &deployment(Some(3), false), "a", false).unwrap();
        let before = live.clone();
        live["spec"]["replicas"] = json!(5);
        record_update(&before, &mut live, &req("kubectl-patch"));

        let conflicts = apply(&mut live, &deployment(Some(3), false), "a", false).unwrap_err();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].manager, "kubectl-patch");
    }

    /// Re-applying an identical manifest must not touch managedFields: a changing timestamp
    /// would bump resourceVersion and wake every watcher on a no-op apply.
    #[test]
    fn identical_reapply_leaves_managed_fields_untouched() {
        let mut live = json!({});
        apply(&mut live, &deployment(Some(3), false), "a", false).unwrap();
        let first = live["metadata"]["managedFields"].clone();
        let plan = plan_apply(
            &live,
            &deployment(Some(3), false),
            false,
            &Request {
                now: "2030-01-01T00:00:00Z",
                ..req("a")
            },
        )
        .unwrap();
        plan.record(&mut live);
        assert_eq!(live["metadata"]["managedFields"], first);
    }

    fn with_ports(ports: Value) -> Value {
        let mut d = deployment(Some(1), false);
        d["spec"]["template"]["spec"]["containers"][0]["ports"] = ports;
        d
    }

    fn ports_of(live: &Value) -> Value {
        live["spec"]["template"]["spec"]["containers"][0]["ports"].clone()
    }

    fn dns_ports() -> Value {
        json!([
            {"containerPort": 53, "protocol": "TCP"},
            {"containerPort": 53, "protocol": "UDP"}
        ])
    }

    /// A DNS pod serves 53/TCP and 53/UDP. Keying ports on containerPort alone collapsed them
    /// into one item and a re-apply deleted the whole list; both protocols must be items.
    #[test]
    fn same_port_number_on_two_protocols_is_two_items_and_survives_reapply() {
        let mut live = json!({});
        apply(&mut live, &with_ports(dns_ports()), "a", false).unwrap();
        assert_eq!(ports_of(&live), dns_ports());
        apply(&mut live, &with_ports(dns_ports()), "a", false).unwrap();
        assert_eq!(ports_of(&live), dns_ports(), "DNS shape must round-trip");
    }

    /// Dropping one of two ports removes that item only; it must never delete the list.
    #[test]
    fn dropping_one_port_removes_only_that_item_in_both_orders() {
        let tcp = json!([{"containerPort": 53, "protocol": "TCP"}]);
        let mut live = json!({});
        apply(&mut live, &with_ports(dns_ports()), "a", false).unwrap();
        apply(&mut live, &with_ports(tcp.clone()), "a", false).unwrap();
        assert_eq!(ports_of(&live), tcp, "only the UDP item may be removed");

        let mut live = json!({});
        apply(&mut live, &with_ports(tcp.clone()), "a", false).unwrap();
        apply(&mut live, &with_ports(dns_ports()), "a", false).unwrap();
        assert_eq!(ports_of(&live), dns_ports());
    }

    /// A port without `protocol` is the TCP port: spelling the default out must not look like
    /// a different item (which would delete and re-add it).
    #[test]
    fn omitted_protocol_is_the_same_item_as_tcp() {
        let implicit = json!([{"containerPort": 80}]);
        let explicit = json!([{"containerPort": 80, "protocol": "TCP"}]);
        let mut live = json!({});
        apply(&mut live, &with_ports(implicit), "a", false).unwrap();
        apply(&mut live, &with_ports(explicit.clone()), "a", false).unwrap();
        assert_eq!(ports_of(&live).as_array().unwrap().len(), 1);
    }

    /// A list recorded as one atomic field (older ownership) that is now applied as keyed
    /// items is still applied: the transition must not delete it.
    #[test]
    fn atomic_to_keyed_ownership_transition_does_not_delete_the_list() {
        let mut live = json!({});
        apply(&mut live, &with_ports(dns_ports()), "a", false).unwrap();
        let mut managers = read_managers(&live);
        let ports_field: Path = ["f:spec", "f:template", "f:spec", "f:containers"]
            .iter()
            .map(|s| s.to_string())
            .chain([r#"k:{"name":"nginx"}"#.to_string(), "f:ports".to_string()])
            .collect();
        managers[0].set.retain(|p| !p.starts_with(&ports_field));
        managers[0].set.insert(ports_field);
        write_managers(&mut live, &managers);

        apply(&mut live, &with_ports(dns_ports()), "a", false).unwrap();
        assert_eq!(ports_of(&live), dns_ports());
    }

    /// The reverse: items previously owned individually, the list now applied as one atomic
    /// field (a CRD that changed its list type). The new list is the applied state; pruning
    /// the old items out of it would wipe the list.
    #[test]
    fn keyed_to_atomic_ownership_transition_does_not_delete_the_list() {
        let schema = |list_type: &str| {
            json!({"properties": {"spec": {"properties": {"items": {
                "type": "array",
                "x-kubernetes-list-type": list_type,
                "x-kubernetes-list-map-keys": ["name"]
            }}}}})
        };
        let body = json!({"apiVersion": "x/v1", "kind": "X", "metadata": {"name": "o"},
            "spec": {"items": [{"name": "a"}, {"name": "b"}]}});
        let keyed = schema("map");
        let atomic = schema("atomic");
        let request = |s: &'static Value| Request {
            schema: Some(s),
            ..req("a")
        };
        let keyed: &'static Value = Box::leak(Box::new(keyed));
        let atomic: &'static Value = Box::leak(Box::new(atomic));

        let mut live = body.clone();
        plan_apply(&Value::Null, &body, false, &request(keyed))
            .unwrap()
            .record(&mut live);
        let plan = plan_apply(&live, &body, false, &request(atomic)).unwrap();
        assert!(
            plan.removals.is_empty(),
            "nothing is dropped: {:?}",
            plan.removals
        );
    }

    /// A scale-subresource (or any subresource) write is attributed to its writer, so an
    /// applier that later drops the field does not delete a value another actor set.
    #[test]
    fn subresource_write_co_owns_so_a_later_apply_that_drops_the_field_keeps_it() {
        let mut live = json!({});
        apply(&mut live, &deployment(Some(3), false), "applier", false).unwrap();
        let before = live.clone();
        live["spec"]["replicas"] = json!(5);
        let scale = Request {
            subresource: Some("scale"),
            ..req("hpa")
        };
        record_update(&before, &mut live, &scale);

        apply(&mut live, &deployment(None, false), "applier", false).unwrap();
        assert_eq!(live["spec"]["replicas"], 5);
    }

    /// A PUT body carries no managedFields; recording it must keep existing ownership rather
    /// than wiping it, and attribute only what the PUT changed.
    #[test]
    fn put_without_managed_fields_keeps_ownership_and_attributes_its_changes() {
        let mut live = json!({});
        apply(&mut live, &deployment(Some(3), false), "applier", false).unwrap();
        let before = live.clone();
        let mut put = before.clone();
        put["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("managedFields");
        put["spec"]["replicas"] = json!(7);
        record_update(&before, &mut put, &req("kubectl-edit"));

        let managers = read_managers(&put);
        assert!(
            managers.iter().any(|m| m.name == "applier"),
            "applier ownership kept"
        );
        let editor = managers.iter().find(|m| m.name == "kubectl-edit").unwrap();
        assert!(editor
            .set
            .contains(&vec!["f:spec".to_string(), "f:replicas".to_string()]));
    }

    /// Client-supplied managedFields: `[{}]` resets ownership (upstream's documented way to
    /// clear it), and a patch that carries managedFields is still attributed to its manager.
    #[test]
    fn managed_fields_reset_clears_other_managers_and_changes_are_still_recorded() {
        let mut live = json!({});
        apply(&mut live, &deployment(Some(3), false), "applier", false).unwrap();
        let before = live.clone();
        live["metadata"]["managedFields"] = json!([{}]);
        live["spec"]["replicas"] = json!(9);
        record_update(&before, &mut live, &req("resetter"));

        let managers = read_managers(&live);
        assert_eq!(
            managers.len(),
            1,
            "reset drops every previous manager: {managers:?}"
        );
        assert_eq!(managers[0].name, "resetter");
    }

    /// A subresource write must ignore managedFields in its body (upstream decodeLiveOrNew):
    /// otherwise a status/scale writer could forge ownership of arbitrary fields.
    #[test]
    fn subresource_write_ignores_client_supplied_managed_fields() {
        let mut live = json!({});
        apply(&mut live, &deployment(Some(3), false), "applier", false).unwrap();
        let before = live.clone();
        live["metadata"]["managedFields"] = json!([]);
        record_update(
            &before,
            &mut live,
            &Request {
                subresource: Some("status"),
                ..req("kubelet")
            },
        );
        assert!(read_managers(&live).iter().any(|m| m.name == "applier"));
    }

    #[test]
    fn manager_defaults_to_user_agent_product() {
        assert_eq!(request_manager(Some("m"), Some("kubectl/v1")), "m");
        assert_eq!(
            request_manager(None, Some("e2e.test/v1.37 (linux)")),
            "e2e.test"
        );
        assert_eq!(request_manager(Some(""), None), "unknown");
    }
}

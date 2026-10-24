//! Server-side-apply field ownership: the `metadata.managedFields` bookkeeping that lets an
//! apply detect conflicts, take ownership with `force`, and remove fields it stopped
//! applying. Field identity follows structured-merge-diff's path elements (`f:` field, `k:`
//! keyed list item, `v:` set member); list merge keys come from the same tables
//! strategic-merge-patch uses, so ownership and merge agree on what an item is.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use crate::patch::{ssa_merge_key_for_path, MergeKeyKind};
use crate::types::DeleteOptions;

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
    force: bool,
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
            force: headers.get(FORCE_HEADER).and_then(|v| v.to_str().ok()) == Some("true"),
        }
    }

    /// Plan an apply of `patch` to a subresource of `live`. Only the top-level members in
    /// `fields` are applied: the others belong to the main resource (or are reset by the
    /// subresource's strategy), so this manager must not come to own them.
    pub(crate) fn plan_subresource_apply(
        &self,
        live: &Value,
        patch: &Value,
        fields: &[&str],
        api_version: &str,
        subresource: &str,
        schema: Option<&Value>,
    ) -> Result<ApplyPlan, crate::status::StatusError> {
        let mut applied = Value::Object(
            fields
                .iter()
                .filter_map(|f| patch.get(*f).map(|v| (f.to_string(), v.clone())))
                .collect(),
        );
        crate::handlers::json_patch::strip_managed_fields(&mut applied);
        plan_apply(
            live,
            &applied,
            self.force,
            &Request {
                manager: &self.manager,
                api_version,
                subresource: Some(subresource),
                schema,
                now: &self.now,
            },
        )
        .map_err(Conflict::into_status)
    }

    /// Record a subresource write: an apply owns exactly what its plan names, anything
    /// else is an Update of the fields that changed.
    pub(crate) fn record_subresource_write(
        &self,
        plan: Option<&ApplyPlan>,
        before: &Value,
        after: &mut Value,
        api_version: &str,
        subresource: &str,
        schema: Option<&Value>,
    ) {
        match plan {
            Some(plan) => plan.record(after),
            None => self.record(before, after, api_version, Some(subresource), schema),
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

const FIELD_MANAGER_MAX_LENGTH: usize = 128;

fn go_printable(c: char) -> bool {
    crate::go_unicode::is_print(c)
}

/// Go's `strconv.Quote`, which upstream's error messages use for string values.
pub(crate) fn go_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if go_printable(c) => out.push(c),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push('"');
    out
}

type FieldError = (String, &'static str, String);

/// Upstream's `ValidatePatchOptions` over the raw query pairs of a patch request whose
/// media type is already known to be supported.
fn validate_patch_options(is_apply: bool, query: &[(String, String)]) -> Vec<FieldError> {
    let first = |k: &str| query.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let mut errs: Vec<FieldError> = Vec::new();
    if is_apply {
        if first("fieldManager").unwrap_or_default().is_empty() {
            errs.push((
                "fieldManager".into(),
                "FieldValueRequired",
                "Required value: is required for apply patch".into(),
            ));
        }
    } else if first("force").is_some() {
        errs.push((
            "force".into(),
            "FieldValueForbidden",
            "Forbidden: may not be specified for non-apply patch".into(),
        ));
    }
    errs.extend(validate_common_options(query));
    errs
}

/// Upstream's `ValidateDryRun`.
fn validate_dry_run(dry_run: &[&str]) -> Option<FieldError> {
    dry_run.iter().any(|v| *v != "All").then(|| {
        (
            "dryRun".into(),
            "FieldValueNotSupported",
            format!(
                "Unsupported value: {}: supported values: \"All\"",
                serde_json::to_string(&dry_run).unwrap_or_default()
            ),
        )
    })
}

fn query_dry_run(query: &[(String, String)]) -> Vec<&str> {
    query
        .iter()
        .filter(|(n, _)| n == "dryRun")
        .map(|(_, v)| v.as_str())
        .collect()
}

/// Upstream's `ValidateDeleteOptions` over the effective options of a DELETE.
fn validate_delete_options(opts: &DeleteOptions) -> Vec<FieldError> {
    let mut errs: Vec<FieldError> = Vec::new();
    let policy = opts.propagation_policy.as_deref();
    if let (Some(p), Some(_)) = (policy, opts.orphan_dependents) {
        errs.push((
            "propagationPolicy".into(),
            "FieldValueInvalid",
            format!(
                "Invalid value: {}: orphanDependents and deletionPropagation cannot be both set",
                go_quote(p)
            ),
        ));
    }
    if let Some(p) = policy {
        if !["Foreground", "Background", "Orphan"].contains(&p) {
            errs.push((
                "propagationPolicy".into(),
                "FieldValueNotSupported",
                format!(
                    "Unsupported value: {}: supported values: \"Foreground\", \"Background\", \"Orphan\", \"nil\"",
                    go_quote(p)
                ),
            ));
        }
    }
    let dry_run: Vec<&str> = opts.dry_run.iter().flatten().map(String::as_str).collect();
    errs.extend(validate_dry_run(&dry_run));
    errs
}

/// Upstream's `ParameterCodec.DecodeParameters` into `DeleteOptions`, used only when the
/// request has no body. `orphanDependents` follows apimachinery's bool conversion: "0" and
/// any case of "false" are false, every other value (including empty) is true.
fn delete_options_from_query(query: &[(String, String)]) -> DeleteOptions {
    let first = |k: &str| query.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let dry_run = query_dry_run(query);
    DeleteOptions {
        propagation_policy: first("propagationPolicy").map(String::from),
        orphan_dependents: first("orphanDependents")
            .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false"))),
        grace_period_seconds: None,
        dry_run: (!dry_run.is_empty()).then(|| dry_run.into_iter().map(String::from).collect()),
    }
}

/// The JSON body handlers decode `DeleteOptions` from, carrying the query-supplied options.
fn delete_options_body(opts: &DeleteOptions) -> Vec<u8> {
    let mut body = json!({"apiVersion": "v1", "kind": "DeleteOptions"});
    if let Some(p) = &opts.propagation_policy {
        body["propagationPolicy"] = json!(p);
    }
    if let Some(o) = opts.orphan_dependents {
        body["orphanDependents"] = json!(o);
    }
    if let Some(d) = &opts.dry_run {
        body["dryRun"] = json!(d);
    }
    body.to_string().into_bytes()
}

/// The pod, service and node proxy routes: their DELETE body and query belong to the
/// backend, not to `DeleteOptions`.
fn is_proxy_path(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    matches!(
        segs.as_slice(),
        [
            "api",
            "v1",
            "namespaces",
            _,
            "pods" | "services",
            _,
            "proxy",
            ..
        ] | ["api", "v1", "nodes", _, "proxy", ..]
    )
}

/// Resolves a DELETE's effective `DeleteOptions` as upstream's delete handler does: a
/// non-empty body is the options (the query is ignored), an empty body takes them from the
/// query. The result is validated (422 `DeleteOptions`) before any handler runs; options
/// that came from the query are handed on as a JSON body, the one place every delete and
/// deletecollection handler reads them from. An undecodable body is left to the handlers'
/// lenient parse. A non-empty body also makes its `dryRun` authoritative: the query-derived
/// dry-run header is dropped, as upstream never reads the query then.
async fn resolve_delete_options(
    req: axum::http::Request<axum::body::Body>,
    query: &[(String, String)],
) -> Result<axum::http::Request<axum::body::Body>, Box<axum::response::Response>> {
    use axum::response::IntoResponse;
    let (mut parts, body) = req.into_parts();
    let raw = axum::body::to_bytes(body, crate::MAX_BODY_BYTES)
        .await
        .map_err(|e| {
            let over_cap = std::error::Error::source(&e)
                .is_some_and(|s| s.is::<http_body_util::LengthLimitError>());
            Box::new(if over_cap {
                axum::http::StatusCode::PAYLOAD_TOO_LARGE.into_response()
            } else {
                crate::status::Status::bad_request(format!("unable to read the request body: {e}"))
                    .into_response()
            })
        })?;
    let from_query = raw.is_empty();
    if !from_query {
        parts
            .headers
            .remove(crate::handlers::json_patch::DRY_RUN_HEADER);
    }
    let opts = if from_query {
        Some(delete_options_from_query(query))
    } else {
        crate::util::extract_body_quiet(&raw, crate::util::content_type(&parts.headers))
            .ok()
            .and_then(|b| serde_json::from_slice::<DeleteOptions>(&b).ok())
    };
    let mut out = raw;
    if let Some(opts) = opts {
        let errs = validate_delete_options(&opts);
        if !errs.is_empty() {
            return Err(Box::new(
                crate::status::Status::invalid_options("DeleteOptions", &errs).into_response(),
            ));
        }
        if from_query
            && (opts.propagation_policy.is_some()
                || opts.orphan_dependents.is_some()
                || opts.dry_run.is_some())
        {
            out = delete_options_body(&opts).into();
            parts.headers.remove(axum::http::header::CONTENT_LENGTH);
            parts.headers.insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json"),
            );
        }
    }
    Ok(axum::http::Request::from_parts(
        parts,
        axum::body::Body::from(out),
    ))
}

/// The fieldManager, dryRun and fieldValidation checks shared by upstream's
/// `ValidateCreateOptions`, `ValidateUpdateOptions` and `ValidatePatchOptions`.
fn validate_common_options(query: &[(String, String)]) -> Vec<FieldError> {
    let first = |k: &str| query.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let manager = first("fieldManager").unwrap_or_default();
    let mut errs: Vec<FieldError> = Vec::new();
    if manager.len() > FIELD_MANAGER_MAX_LENGTH {
        errs.push((
            "fieldManager".into(),
            "FieldValueTooLong",
            format!("Too long: may not be more than {FIELD_MANAGER_MAX_LENGTH} bytes"),
        ));
    }
    for (i, c) in manager.char_indices() {
        if !go_printable(c) {
            errs.push((
                "fieldManager".into(),
                "FieldValueInvalid",
                format!(
                    "Invalid value: {}: invalid character U+{:04X} (at position {i})",
                    go_quote(manager),
                    c as u32
                ),
            ));
        }
    }
    errs.extend(validate_dry_run(&query_dry_run(query)));
    if let Some(fv) = first("fieldValidation") {
        if !["", "Ignore", "Warn", "Strict"].contains(&fv) {
            errs.push((
                "fieldValidation".into(),
                "FieldValueNotSupported",
                format!(
                    "Unsupported value: {}: supported values: \"\", \"Ignore\", \"Strict\", \"Warn\"",
                    go_quote(fv)
                ),
            ));
        }
    }
    errs
}

/// Resolves `?fieldManager=` once for every kind's write route: validates a patch's options
/// as upstream's `ValidatePatchOptions` does before any handler runs (an unsupported media
/// type is left for the handler's 415, as upstream rejects it first), and forwards the
/// manager as the internal header [`WriteIdentity`] reads, so handlers without a query
/// extractor still record the caller-chosen manager. A client-supplied copy of the header is
/// always discarded.
pub(crate) async fn resolve_field_manager(
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    req.headers_mut().remove(FIELD_MANAGER_HEADER);
    let query = axum::extract::Query::<Vec<(String, String)>>::try_from_uri(req.uri())
        .map(|q| q.0)
        .unwrap_or_default();
    if *req.method() == axum::http::Method::DELETE && !is_proxy_path(req.uri().path()) {
        req = match resolve_delete_options(req, &query).await {
            Ok(req) => req,
            Err(resp) => return *resp,
        };
    }
    let validated = match *req.method() {
        axum::http::Method::PATCH
            if crate::handlers::json_patch::detect_patch_type(req.headers()).is_ok() =>
        {
            let is_apply = req
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ct| ct.contains("apply-patch+yaml"));
            Some(("PatchOptions", validate_patch_options(is_apply, &query)))
        }
        axum::http::Method::POST => Some(("CreateOptions", validate_common_options(&query))),
        axum::http::Method::PUT => Some(("UpdateOptions", validate_common_options(&query))),
        _ => None,
    };
    if let Some((kind, errs)) = validated {
        if !errs.is_empty() {
            return crate::status::Status::invalid_options(kind, &errs).into_response();
        }
    }
    let manager = query
        .iter()
        .find(|(n, _)| n == "fieldManager")
        .map(|(_, v)| v.as_str())
        .filter(|m| !m.is_empty());
    if let Some(Ok(v)) = manager.map(axum::http::HeaderValue::from_str) {
        req.headers_mut().insert(FIELD_MANAGER_HEADER, v);
    }
    req.headers_mut().remove(FORCE_HEADER);
    if query.iter().any(|(n, v)| n == "force" && v == "true") {
        req.headers_mut()
            .insert(FORCE_HEADER, axum::http::HeaderValue::from_static("true"));
    }
    next.run(req).await
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

    mod routed {
        use super::*;
        use axum::{body::Body, http::Request};
        use tower::ServiceExt as _;

        async fn patch(
            content_type: &str,
            uri: &str,
            forged_header: bool,
        ) -> (axum::http::StatusCode, Value, Option<String>) {
            let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
            let seen2 = seen.clone();
            let app = axum::Router::new()
                .route(
                    "/x",
                    axum::routing::patch(move |h: axum::http::HeaderMap| async move {
                        *seen2.lock().unwrap() = h
                            .get(FIELD_MANAGER_HEADER)
                            .and_then(|v| v.to_str().ok())
                            .map(String::from);
                        "ok"
                    }),
                )
                .layer(axum::middleware::from_fn(resolve_field_manager));
            let mut b = Request::builder()
                .method("PATCH")
                .uri(uri)
                .header("content-type", content_type);
            if forged_header {
                b = b.header(FIELD_MANAGER_HEADER, "forged");
            }
            let resp = app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let seen = seen.lock().unwrap().clone();
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or_default(),
                seen,
            )
        }

        const APPLY: &str = "application/apply-patch+yaml";

        /// A controller that forgets `?fieldManager=` on an apply must be told so, with
        /// upstream's exact status, instead of silently becoming the "unknown" manager.
        #[tokio::test]
        async fn apply_without_field_manager_is_rejected_like_upstream() {
            for uri in ["/x", "/x?fieldManager=", "/x?force=true"] {
                let (status, body, _) = patch(APPLY, uri, false).await;
                assert_eq!(status, 422, "{uri}: {body}");
                assert_eq!(body["reason"], "Invalid", "{uri}");
                assert_eq!(
                    body["message"],
                    "PatchOptions.meta.k8s.io \"\" is invalid: fieldManager: Required value: \
                     is required for apply patch",
                    "{uri}"
                );
                assert_eq!(body["details"]["causes"][0]["field"], "fieldManager");
                assert_eq!(body["details"]["causes"][0]["reason"], "FieldValueRequired");
            }
        }

        const MERGE: &str = "application/merge-patch+json";

        /// `?force` on a merge patch is a client bug upstream refuses; accepting it hides
        /// that a controller believes a non-apply patch can take field ownership.
        #[tokio::test]
        async fn force_on_non_apply_patch_is_rejected_like_upstream() {
            for ct in [
                MERGE,
                "application/strategic-merge-patch+json",
                "application/json-patch+json",
            ] {
                for q in ["force=true", "force=false"] {
                    let (status, body, _) = patch(ct, &format!("/x?{q}"), false).await;
                    assert_eq!(status, 422, "{ct} ?{q}: {body}");
                    assert_eq!(
                        body["message"],
                        "PatchOptions.meta.k8s.io \"\" is invalid: force: Forbidden: may not \
                         be specified for non-apply patch"
                    );
                    assert_eq!(body["details"]["group"], "meta.k8s.io");
                    assert_eq!(body["details"]["kind"], "PatchOptions");
                    assert!(body["details"].get("name").is_none());
                    assert_eq!(
                        body["details"]["causes"][0]["reason"],
                        "FieldValueForbidden"
                    );
                    assert_eq!(body["details"]["causes"][0]["field"], "force");
                }
            }
            let (status, _, _) = patch(APPLY, "/x?fieldManager=m&force=true", false).await;
            assert_eq!(status, 200, "force is valid for apply");
        }

        /// u7s serves no CBOR apply; it must reach the handler's 415 rather than be
        /// mistaken for apply or masked as a 422 by `force`.
        #[tokio::test]
        async fn unsupported_media_type_is_left_to_the_handler() {
            let (status, _, _) =
                patch("application/apply-patch+cbor", "/x?force=true", false).await;
            assert_eq!(
                status, 200,
                "validation must not pre-empt the handler's 415"
            );
            let mut h = axum::http::HeaderMap::new();
            h.insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/apply-patch+cbor"),
            );
            assert_eq!(
                crate::handlers::json_patch::detect_patch_type(&h)
                    .unwrap_err()
                    .0,
                axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE
            );
        }

        /// A manager over 128 bytes would bloat every managedFields entry it owns.
        #[tokio::test]
        async fn overlong_field_manager_is_rejected_like_upstream() {
            let uri = format!("/x?fieldManager={}", "a".repeat(129));
            let (status, body, _) = patch(MERGE, &uri, false).await;
            assert_eq!(status, 422);
            assert_eq!(
                body["message"],
                "PatchOptions.meta.k8s.io \"\" is invalid: fieldManager: Too long: may not be \
                 more than 128 bytes"
            );
            assert_eq!(body["details"]["causes"][0]["reason"], "FieldValueTooLong");
            let uri = format!("/x?fieldManager={}", "a".repeat(128));
            assert_eq!(patch(MERGE, &uri, false).await.0, 200);
        }

        /// A control character in the manager would corrupt logs and managedFields output.
        #[tokio::test]
        async fn unprintable_field_manager_is_rejected_like_upstream() {
            let (status, body, _) = patch(MERGE, "/x?fieldManager=a%07b", false).await;
            assert_eq!(status, 422);
            assert_eq!(
                body["message"],
                "PatchOptions.meta.k8s.io \"\" is invalid: fieldManager: Invalid value: \
                 \"a\\ab\": invalid character U+0007 (at position 1)"
            );
            assert_eq!(body["details"]["causes"][0]["reason"], "FieldValueInvalid");
            assert_eq!(body["details"]["causes"][0]["field"], "fieldManager");
        }

        /// Only `All` is a real dry run; any other value must not silently become a write.
        #[tokio::test]
        async fn unsupported_dry_run_value_is_rejected_like_upstream() {
            let (status, body, _) = patch(MERGE, "/x?dryRun=All&dryRun=None", false).await;
            assert_eq!(status, 422);
            assert_eq!(
                body["message"],
                "PatchOptions.meta.k8s.io \"\" is invalid: dryRun: Unsupported value: \
                 [\"All\",\"None\"]: supported values: \"All\""
            );
            assert_eq!(
                body["details"]["causes"][0]["reason"],
                "FieldValueNotSupported"
            );
            assert_eq!(patch(MERGE, "/x?dryRun=All", false).await.0, 200);
        }

        /// A typo such as `fieldValidation=strict` must fail loudly, not skip validation.
        #[tokio::test]
        async fn unsupported_field_validation_value_is_rejected_like_upstream() {
            let (status, body, _) = patch(MERGE, "/x?fieldValidation=strict", false).await;
            assert_eq!(status, 422);
            assert_eq!(
                body["message"],
                "PatchOptions.meta.k8s.io \"\" is invalid: fieldValidation: Unsupported value: \
                 \"strict\": supported values: \"\", \"Ignore\", \"Strict\", \"Warn\""
            );
            assert_eq!(body["details"]["causes"][0]["field"], "fieldValidation");
            for ok in ["", "Ignore", "Warn", "Strict"] {
                let uri = format!("/x?fieldValidation={ok}");
                assert_eq!(patch(MERGE, &uri, false).await.0, 200, "{ok}");
            }
        }

        /// Several bad options are reported together, as upstream's aggregate does.
        #[tokio::test]
        async fn several_bad_options_are_aggregated() {
            let (status, body, _) = patch(MERGE, "/x?force=true&dryRun=x", false).await;
            assert_eq!(status, 422);
            assert_eq!(body["details"]["causes"].as_array().unwrap().len(), 2);
            assert!(body["message"]
                .as_str()
                .unwrap()
                .contains("is invalid: [force: Forbidden"));
        }

        /// Only PATCH carries PatchOptions.
        #[tokio::test]
        async fn non_patch_requests_are_not_validated() {
            let app = axum::Router::new()
                .route("/x", axum::routing::put(|| async { "ok" }))
                .layer(axum::middleware::from_fn(resolve_field_manager));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri("/x?force=true")
                        .header("content-type", "application/json")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
        }

        async fn send(method: &str, uri: &str) -> (axum::http::StatusCode, Value) {
            let app = axum::Router::new()
                .route(
                    "/x",
                    axum::routing::post(|| async { "ok" })
                        .put(|| async { "ok" })
                        .delete(|| async { "ok" }),
                )
                .layer(axum::middleware::from_fn(resolve_field_manager));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, serde_json::from_slice(&bytes).unwrap_or_default())
        }

        const CREATE_UPDATE: [(&str, &str); 2] =
            [("POST", "CreateOptions"), ("PUT", "UpdateOptions")];

        /// A bad fieldManager/dryRun/fieldValidation on a create or update must be refused
        /// with the kind-specific upstream Status, not silently written with a corrupt
        /// manager or as a real write instead of a dry run.
        #[tokio::test]
        async fn create_and_update_options_are_validated_like_upstream() {
            let long = format!("/x?fieldManager={}", "a".repeat(129));
            let cases = [
                (
                    long.as_str(),
                    "fieldManager: Too long: may not be more than 128 bytes".to_string(),
                    "FieldValueTooLong",
                ),
                (
                    "/x?fieldManager=a%07b",
                    "fieldManager: Invalid value: \"a\\ab\": invalid character U+0007 (at position 1)"
                        .to_string(),
                    "FieldValueInvalid",
                ),
                (
                    "/x?dryRun=None",
                    "dryRun: Unsupported value: [\"None\"]: supported values: \"All\"".to_string(),
                    "FieldValueNotSupported",
                ),
                (
                    "/x?fieldValidation=strict",
                    "fieldValidation: Unsupported value: \"strict\": supported values: \"\", \
                     \"Ignore\", \"Strict\", \"Warn\""
                        .to_string(),
                    "FieldValueNotSupported",
                ),
            ];
            for (method, kind) in CREATE_UPDATE {
                for (uri, tail, reason) in &cases {
                    let (status, body) = send(method, uri).await;
                    assert_eq!(status, 422, "{method} {uri}: {body}");
                    assert_eq!(
                        body["message"],
                        format!("{kind}.meta.k8s.io \"\" is invalid: {tail}"),
                        "{method} {uri}"
                    );
                    assert_eq!(body["details"]["kind"], kind);
                    assert_eq!(body["details"]["causes"][0]["reason"], *reason);
                }
            }
        }

        /// Create/update have no apply semantics: an empty manager is defaulted from the
        /// user agent, `force` is ignored, and valid options reach the handler untouched.
        #[tokio::test]
        async fn valid_create_and_update_options_are_unaffected() {
            for (method, _) in CREATE_UPDATE {
                for uri in [
                    "/x",
                    "/x?fieldManager=",
                    "/x?force=true",
                    "/x?dryRun=All&fieldValidation=Strict&fieldManager=kubectl-edit",
                    "/x?fieldManager=%E2%82%AC%20caf%C3%A9",
                ] {
                    assert_eq!(send(method, uri).await.0, 200, "{method} {uri}");
                }
            }
            let at_limit = format!("/x?fieldManager={}", "a".repeat(128));
            assert_eq!(send("POST", &at_limit).await.0, 200);
        }

        /// Go's `unicode.IsPrint` rejects format characters; a zero-width space or soft
        /// hyphen would make two visually identical managers distinct owners.
        #[tokio::test]
        async fn format_characters_in_field_manager_are_rejected_like_go() {
            for (method, kind) in CREATE_UPDATE {
                for (q, cp) in [("a%E2%80%8Bb", "U+200B"), ("a%C2%ADb", "U+00AD")] {
                    let (status, body) = send(method, &format!("/x?fieldManager={q}")).await;
                    assert_eq!(status, 422, "{method} {cp}");
                    assert!(
                        body["message"]
                            .as_str()
                            .unwrap()
                            .contains(&format!("invalid character {cp} (at position 1)")),
                        "{kind}: {body}"
                    );
                }
            }
            let (status, _, _) = patch(MERGE, "/x?fieldManager=a%E2%80%8Bb", false).await;
            assert_eq!(status, 422, "PATCH shares the check");
        }

        #[test]
        fn go_printable_matches_go_unicode_is_print() {
            for c in [
                'a',
                'Z',
                '0',
                ' ',
                '~',
                '€',
                'é',
                '中',
                '\u{1F600}',
                '\u{301}',
            ] {
                assert!(go_printable(c), "{c:?} is printable in Go");
            }
            for c in [
                '\u{0}',
                '\u{7}',
                '\u{7f}',
                '\u{85}',
                '\u{A0}',
                '\u{AD}',
                '\u{200B}',
                '\u{2028}',
                '\u{3000}',
                '\u{E000}',
                '\u{378}',
                '\u{FFFF}',
                '\u{10FFFF}',
            ] {
                assert!(!go_printable(c), "{c:?} is not printable in Go");
            }
        }

        /// `kubectl delete --dry-run` typos and bogus propagation policies must fail loudly
        /// on DELETE as they do on every other write, not silently become a real delete.
        #[tokio::test]
        async fn delete_options_are_validated_like_upstream() {
            let (status, body) = send("DELETE", "/x?dryRun=None").await;
            assert_eq!(status, 422, "{body}");
            assert_eq!(
                body["message"],
                "DeleteOptions.meta.k8s.io \"\" is invalid: dryRun: Unsupported value: \
                 [\"None\"]: supported values: \"All\""
            );
            assert_eq!(body["details"]["kind"], "DeleteOptions");

            let (status, body) = send("DELETE", "/x?propagationPolicy=Bogus").await;
            assert_eq!(status, 422, "{body}");
            assert_eq!(
                body["message"],
                "DeleteOptions.meta.k8s.io \"\" is invalid: propagationPolicy: Unsupported \
                 value: \"Bogus\": supported values: \"Foreground\", \"Background\", \
                 \"Orphan\", \"nil\""
            );

            let (status, body) = send(
                "DELETE",
                "/x?propagationPolicy=Orphan&orphanDependents=true",
            )
            .await;
            assert_eq!(status, 422, "{body}");
            assert_eq!(
                body["message"],
                "DeleteOptions.meta.k8s.io \"\" is invalid: propagationPolicy: Invalid value: \
                 \"Orphan\": orphanDependents and deletionPropagation cannot be both set"
            );
            assert_eq!(body["details"]["causes"][0]["reason"], "FieldValueInvalid");

            for ok in [
                "/x",
                "/x?dryRun=All",
                "/x?propagationPolicy=Foreground",
                "/x?propagationPolicy=Background&gracePeriodSeconds=0",
                "/x?orphanDependents=false",
            ] {
                assert_eq!(send("DELETE", ok).await.0, 200, "{ok}");
            }
        }

        /// Sends a DELETE through the middleware to a handler that echoes the body and
        /// content type it receives, as every delete handler would see them.
        async fn delete_echo(
            uri: &str,
            content_type: Option<&str>,
            body: Vec<u8>,
        ) -> (axum::http::StatusCode, Value, Option<String>) {
            let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
            let seen2 = seen.clone();
            let app = axum::Router::new()
                .route(
                    "/x",
                    axum::routing::delete(
                        move |h: axum::http::HeaderMap, b: axum::body::Bytes| async move {
                            *seen2.lock().unwrap() = h
                                .get("content-type")
                                .and_then(|v| v.to_str().ok())
                                .map(String::from);
                            b
                        },
                    ),
                )
                .layer(axum::middleware::from_fn(resolve_field_manager));
            let mut b = Request::builder().method("DELETE").uri(uri);
            if let Some(ct) = content_type {
                b = b.header("content-type", ct);
            }
            let resp = app
                .oneshot(b.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let ct = seen.lock().unwrap().clone();
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or_default(),
                ct,
            )
        }

        /// An invalid DeleteOptions body must be refused like the query form: kubectl and
        /// client-go send options in the body, so a bad dryRun or policy there would
        /// otherwise run a real (or cascading) delete the caller did not ask for.
        #[tokio::test]
        async fn delete_options_body_is_validated_like_upstream() {
            let cases = [
                (
                    json!({"dryRun": ["None"]}),
                    "dryRun: Unsupported value: [\"None\"]: supported values: \"All\"",
                ),
                (
                    json!({"propagationPolicy": "Bogus"}),
                    "propagationPolicy: Unsupported value: \"Bogus\": supported values: \
                     \"Foreground\", \"Background\", \"Orphan\", \"nil\"",
                ),
                (
                    json!({"propagationPolicy": "Orphan", "orphanDependents": false}),
                    "propagationPolicy: Invalid value: \"Orphan\": orphanDependents and \
                     deletionPropagation cannot be both set",
                ),
            ];
            for (opts, cause) in cases {
                let (status, body, _) = delete_echo(
                    "/x",
                    Some("application/json"),
                    opts.to_string().into_bytes(),
                )
                .await;
                assert_eq!(status, 422, "{opts}: {body}");
                assert_eq!(
                    body["message"],
                    format!("DeleteOptions.meta.k8s.io \"\" is invalid: {cause}"),
                    "{opts}"
                );
                assert_eq!(body["details"]["kind"], "DeleteOptions");
            }
        }

        /// Validation must also see protobuf bodies, which is what kubectl and client-go
        /// actually send; a JSON-only check would pass every real client through.
        #[tokio::test]
        async fn protobuf_delete_options_body_is_validated() {
            // Payloads here are all under 128 bytes, so every length is a one-byte varint.
            fn ld(field: u8, payload: &[u8]) -> Vec<u8> {
                let mut out = vec![(field << 3) | 2, payload.len() as u8];
                out.extend_from_slice(payload);
                out
            }
            let delete_options = ld(5, b"None"); // DeleteOptions.dryRun
            let mut type_meta = ld(1, b"v1");
            type_meta.extend(ld(2, b"DeleteOptions"));
            let mut unknown = ld(1, &type_meta);
            unknown.extend(ld(2, &delete_options));
            let mut envelope = vec![0x6b, 0x38, 0x73, 0x00];
            envelope.extend(unknown);
            let (status, body, _) =
                delete_echo("/x", Some("application/vnd.kubernetes.protobuf"), envelope).await;
            assert_eq!(status, 422, "{body}");
            assert_eq!(body["details"]["kind"], "DeleteOptions");
        }

        /// Upstream decodes the query only when the body is empty: a body (even `{}`) wins
        /// outright, so a bad query beside it is ignored and a good query cannot override it.
        #[tokio::test]
        async fn delete_options_body_takes_precedence_over_query_like_upstream() {
            let (status, _, ct) = delete_echo(
                "/x?propagationPolicy=Bogus&dryRun=None",
                Some("application/json"),
                b"{}".to_vec(),
            )
            .await;
            assert_eq!(status, 200, "a non-empty body makes the query irrelevant");
            assert_eq!(ct.as_deref(), Some("application/json"));

            let (status, echoed, _) = delete_echo(
                "/x?propagationPolicy=Orphan",
                Some("application/json"),
                br#"{"propagationPolicy":"Background"}"#.to_vec(),
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(
                echoed,
                json!({"propagationPolicy": "Background"}),
                "the body must reach the handler untouched, not merged with the query"
            );
        }

        /// A `?propagationPolicy=` / `?orphanDependents=` / `?dryRun=All` on a bodyless
        /// DELETE must reach the handlers (which only read the body), or `kubectl delete
        /// --cascade=orphan`-style raw requests silently cascade or really delete.
        #[tokio::test]
        async fn delete_query_options_reach_handlers_as_a_json_body() {
            let (status, echoed, ct) =
                delete_echo("/x?propagationPolicy=Orphan&dryRun=All", None, Vec::new()).await;
            assert_eq!(status, 200);
            assert_eq!(ct.as_deref(), Some("application/json"));
            assert_eq!(echoed["propagationPolicy"], "Orphan");
            assert_eq!(echoed["dryRun"], json!(["All"]));
            assert!(echoed.get("orphanDependents").is_none());

            for (value, want) in [
                ("false", false),
                ("0", false),
                ("FALSE", false),
                ("true", true),
                ("", true),
            ] {
                let (_, echoed, _) =
                    delete_echo(&format!("/x?orphanDependents={value}"), None, Vec::new()).await;
                assert_eq!(
                    echoed["orphanDependents"], want,
                    "orphanDependents={value:?}"
                );
            }
        }

        /// A plain delete without options must not grow a synthetic body, or handlers that
        /// treat "no body" as "no explicit propagation intent" would see one.
        #[tokio::test]
        async fn delete_without_options_is_passed_through_unchanged() {
            for uri in ["/x", "/x?gracePeriodSeconds=0", "/x?unrelated=1"] {
                let (status, echoed, ct) = delete_echo(uri, None, Vec::new()).await;
                assert_eq!(status, 200, "{uri}");
                assert_eq!(echoed, Value::Null, "{uri}: body must stay empty");
                assert_eq!(ct, None, "{uri}");
            }
        }

        /// Mirrors the delete handlers' dry-run decision (`body.is_dry_run() || header`)
        /// behind the same layer order as the real router.
        async fn handler_dry_runs(uri: &str, body: &str) -> bool {
            let app = axum::Router::new()
                .route(
                    "/x",
                    axum::routing::delete(
                        |h: axum::http::HeaderMap, b: axum::body::Bytes| async move {
                            let opts: DeleteOptions =
                                serde_json::from_slice(&b).unwrap_or_default();
                            let dry = opts.is_dry_run()
                                || crate::handlers::json_patch::is_dry_run_header(&h);
                            dry.to_string()
                        },
                    ),
                )
                .layer(axum::middleware::from_fn(resolve_field_manager))
                .layer(axum::middleware::from_fn(
                    crate::handlers::json_patch::inject_dry_run_header,
                ));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(uri)
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_owned()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            bytes.as_ref() == b"true"
        }

        /// Upstream ignores the query once a body is present, so a body that says "really
        /// delete" must not be turned into a dry run by `?dryRun=All` (the caller would
        /// believe the object is gone), and a body dryRun must still dry-run.
        #[tokio::test]
        async fn body_dry_run_is_authoritative_over_query_dry_run() {
            assert!(
                !handler_dry_runs("/x?dryRun=All", r#"{"dryRun":[]}"#).await,
                "body without dryRun must really delete despite ?dryRun=All"
            );
            assert!(handler_dry_runs("/x", r#"{"dryRun":["All"]}"#).await);
            assert!(
                handler_dry_runs("/x?dryRun=All", "").await,
                "a bodyless ?dryRun=All must still dry-run"
            );
        }

        /// Proxied DELETEs carry the backend's own body and query: decoding them as
        /// DeleteOptions would 422 a valid backend request or inject a JSON body into it.
        #[tokio::test]
        async fn proxied_delete_reaches_the_backend_unchanged() {
            let app =
                axum::Router::new()
                    .route(
                        "/api/v1/namespaces/{ns}/services/{name}/proxy/{*p}",
                        axum::routing::delete(
                            |h: axum::http::HeaderMap,
                             uri: axum::http::Uri,
                             b: axum::body::Bytes| async move {
                                format!(
                                    "{}|{}|{}",
                                    uri.query().unwrap_or_default(),
                                    h.get("content-type")
                                        .and_then(|v| v.to_str().ok())
                                        .unwrap_or(""),
                                    String::from_utf8_lossy(&b)
                                )
                            },
                        ),
                    )
                    .layer(axum::middleware::from_fn(resolve_field_manager));
            for (uri, ct, body) in [
                (
                    "/api/v1/namespaces/d/services/s/proxy/a?propagationPolicy=Bogus&dryRun=None",
                    "text/plain",
                    r#"{"dryRun":["None"]}"#,
                ),
                (
                    "/api/v1/namespaces/d/services/s/proxy/a?propagationPolicy=Orphan",
                    "",
                    "",
                ),
            ] {
                let mut b = Request::builder().method("DELETE").uri(uri);
                if !ct.is_empty() {
                    b = b.header("content-type", ct);
                }
                let resp = app
                    .clone()
                    .oneshot(b.body(Body::from(body)).unwrap())
                    .await
                    .unwrap();
                assert_eq!(resp.status(), 200, "{uri}");
                let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let query = uri.split_once('?').unwrap().1;
                assert_eq!(
                    String::from_utf8_lossy(&bytes),
                    format!("{query}|{ct}|{body}")
                );
            }
        }

        /// An oversized DELETE body is the client's size error (413), distinct from a
        /// failed read (400), so callers know whether to shrink the body or retry.
        #[tokio::test]
        async fn oversized_delete_body_is_413() {
            let (status, _, _) = delete_echo(
                "/x",
                Some("application/json"),
                vec![b' '; crate::MAX_BODY_BYTES + 1],
            )
            .await;
            assert_eq!(status, 413);
        }

        #[test]
        fn proxy_paths_are_recognised_exactly() {
            for p in [
                "/api/v1/namespaces/d/pods/p/proxy",
                "/api/v1/namespaces/d/pods/p/proxy/x/y",
                "/api/v1/namespaces/d/services/s/proxy/",
                "/api/v1/nodes/n/proxy/metrics",
            ] {
                assert!(is_proxy_path(p), "{p}");
            }
            for p in [
                "/api/v1/namespaces/d/configmaps/proxy",
                "/api/v1/namespaces/d/pods/proxy",
                "/api/v1/namespaces/d/pods",
            ] {
                assert!(!is_proxy_path(p), "{p}");
            }
        }

        /// Upstream's `req.URL.Query()` drops malformed pairs and the option types have no
        /// field whose conversion can fail, so odd query strings are not an error there;
        /// they must not become one here.
        #[tokio::test]
        async fn malformed_query_pairs_are_tolerated_like_upstream() {
            for method in ["POST", "PUT"] {
                for uri in ["/x?%FF&&=&a", "/x?fieldManager=%FF", "/x?=x&;"] {
                    assert_eq!(send(method, uri).await.0, 200, "{method} {uri}");
                }
            }
        }

        /// Only apply requires it: merge patches fall back to the user agent, as upstream.
        #[tokio::test]
        async fn non_apply_patch_and_named_apply_pass_through_with_the_manager_forwarded() {
            let (status, _, seen) = patch(APPLY, "/x?fieldManager=gitops", false).await;
            assert_eq!(status, 200);
            assert_eq!(seen.as_deref(), Some("gitops"));
            let (status, _, seen) = patch("application/merge-patch+json", "/x", false).await;
            assert_eq!(status, 200);
            assert_eq!(seen, None);
        }

        /// The forwarding header is internal: a client-sent copy would let it name any
        /// manager regardless of `?fieldManager=`.
        #[tokio::test]
        async fn client_supplied_forwarding_header_is_discarded() {
            let (_, _, seen) = patch("application/merge-patch+json", "/x", true).await;
            assert_eq!(seen, None);
            let (_, _, seen) = patch(APPLY, "/x?fieldManager=real", true).await;
            assert_eq!(seen.as_deref(), Some("real"));
        }

        /// A client that forges `x-u7s-force` must not be able to take fields from other
        /// managers without `?force=true`; only the query string may set it.
        #[tokio::test]
        async fn client_supplied_force_header_is_discarded() {
            async fn force_seen(uri: &str, forged: bool) -> Option<String> {
                let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
                let seen2 = seen.clone();
                let app = axum::Router::new()
                    .route(
                        "/x",
                        axum::routing::patch(move |h: axum::http::HeaderMap| async move {
                            *seen2.lock().unwrap() = h
                                .get(FORCE_HEADER)
                                .and_then(|v| v.to_str().ok())
                                .map(String::from);
                            "ok"
                        }),
                    )
                    .layer(axum::middleware::from_fn(resolve_field_manager));
                let mut b = Request::builder()
                    .method("PATCH")
                    .uri(uri)
                    .header("content-type", APPLY);
                if forged {
                    b = b.header(FORCE_HEADER, "true");
                }
                app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
                let v = seen.lock().unwrap().clone();
                v
            }
            assert_eq!(force_seen("/x?fieldManager=m", true).await, None);
            assert_eq!(
                force_seen("/x?fieldManager=m&force=true", false)
                    .await
                    .as_deref(),
                Some("true")
            );
        }

        /// The layer is installed on the real router, so every kind's apply route is covered.
        #[tokio::test]
        async fn real_router_rejects_apply_without_field_manager() {
            let state = crate::handlers::test_support::make_state();
            let app = crate::build_router(state).layer(axum::Extension(crate::auth::UserInfo {
                username: "admin".into(),
                ..Default::default()
            }));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("PATCH")
                        .uri("/api/v1/namespaces/default")
                        .header("content-type", APPLY)
                        .body(Body::from("metadata: {}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), 422);
        }
    }
}

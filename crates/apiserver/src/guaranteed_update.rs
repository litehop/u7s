//! Read-modify-write with compare-and-swap on the revision read, as upstream's
//! `GuaranteedUpdate` (apiserver/pkg/storage/etcd3/store.go).
//!
//! Every update-class write goes through [`GuaranteedUpdate`]: the object is only obtainable
//! from [`GuaranteedUpdate::read`], and the only way to persist is
//! [`GuaranteedUpdate::commit`] (or [`GuaranteedUpdate::pending`] for writes that must run on
//! their own task), which is conditional on the revision that read returned. A write can
//! therefore neither resurrect an object deleted after the read nor overwrite a concurrent
//! write it never saw.
//!
//! Call sites loop, so everything between read and commit (validation, defaulting, admission
//! webhooks) is re-run on the fresh object after a lost race, as upstream re-runs its
//! `tryUpdate` function:
//!
//! ```ignore
//! let mut gu = GuaranteedUpdate::new(state.store.clone(), &key, client_rv, (group, plural, name, kind));
//! let rv = loop {
//!     let stored = gu.read_existing().await?;
//!     /* build `obj` from `stored`; `return` early for dry-run */
//!     if let Some(rv) = gu.commit(obj.to_bytes()).await? { break rv; }
//! };
//! ```

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use u7s_store::{CreateNamespacedError, Store, StoreError, StoreObject};

use crate::status::{Status, StatusError};

/// Upstream's default `--request-timeout`. The handlers have no request deadline of their
/// own, so the conflict loop gives up with a 409 after this long.
const CONFLICT_RETRY_DEADLINE: Duration = Duration::from_secs(60);

/// Why a write did not land.
pub(crate) enum WriteFailure {
    /// A concurrent writer won and the client did not pin a revision: re-read and redo.
    Retry,
    Fail(StatusError),
}

pub(crate) struct GuaranteedUpdate<S> {
    store: Arc<S>,
    key: String,
    client_rv: Option<u64>,
    group: String,
    resource: String,
    name: String,
    kind: String,
    /// `(namespace, namespace key)`: creates (key absent at read) are refused in a terminating
    /// or missing namespace.
    ns: Option<(String, String)>,
    deadline: tokio::time::Instant,
    expected: Option<u64>,
}

impl<S: Store> GuaranteedUpdate<S> {
    /// `client_rv`: a resourceVersion the client pinned. The write is then conditional on exactly
    /// that revision and a lost race is a 409 without retrying. `None` makes a lost race re-read
    /// and re-run the caller's loop body against the fresh object.
    ///
    /// `ctx` is `(group, resource, name, kind)`, used for error messages.
    pub(crate) fn new(
        store: Arc<S>,
        key: &str,
        client_rv: Option<u64>,
        (group, resource, name, kind): (&str, &str, &str, &str),
    ) -> Self {
        Self {
            store,
            key: key.to_string(),
            client_rv,
            group: group.to_string(),
            resource: resource.to_string(),
            name: name.to_string(),
            kind: kind.to_string(),
            ns: None,
            deadline: tokio::time::Instant::now() + CONFLICT_RETRY_DEADLINE,
            expected: None,
        }
    }

    /// Route creates through the namespace-phase gate for namespace `ns`.
    pub(crate) fn in_namespace(mut self, ns: &str) -> Self {
        self.ns = Some((
            ns.to_string(),
            crate::keys::cluster_object_key("namespaces", ns),
        ));
        self
    }

    /// Reads the key. `None` means it is absent and the following write creates it, which
    /// only kinds with upstream `AllowCreateOnUpdate` may do.
    pub(crate) async fn read(&mut self) -> Result<Option<StoreObject>, StatusError> {
        let current = self
            .store
            .get(self.key.clone())
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        self.expected = Some(match (&current, self.client_rv) {
            (_, Some(rv)) => rv,
            (Some(c), None) => c.revision,
            (None, None) => 0,
        });
        Ok(current)
    }

    /// Reads the key; an absent key is NotFound.
    pub(crate) async fn read_existing(&mut self) -> Result<StoreObject, StatusError> {
        self.read()
            .await?
            .ok_or_else(|| Status::not_found(&self.group, &self.resource, &self.name))
    }

    /// A `metadata.resourceVersion` that a patch set on the object is a precondition on the
    /// revision `read` returned, as upstream checks it on the patched object, so every patch
    /// type (a JSON Patch op included) pins alike. `rv_before_patch` is the stored body's own
    /// value, which is not a client pin. A stale pin is a 409 without retrying.
    pub(crate) fn check_patched_pin(
        &self,
        rv_before_patch: Option<&str>,
        patched: &serde_json::Value,
    ) -> Result<(), StatusError> {
        let patched_rv = patched["metadata"]["resourceVersion"].as_str();
        if patched_rv == rv_before_patch {
            return Ok(());
        }
        let (Some(pinned), Some(read)) = (
            crate::util::parse_resource_version(patched_rv)?,
            self.expected,
        ) else {
            return Ok(());
        };
        if pinned == read {
            return Ok(());
        }
        Err(crate::handlers::generic::store_err(
            StoreError::RevisionMismatch {
                expected: pinned,
                current: read,
            },
            &self.group,
            &self.resource,
            &self.name,
            &self.kind,
        ))
    }

    /// Writes `bytes` iff the key is still at the revision `read` returned. `Ok(None)` means a
    /// concurrent writer won and the caller must `continue` its loop; a client-pinned revision
    /// never yields `None` but a 409.
    pub(crate) async fn commit(&mut self, bytes: Bytes) -> Result<Option<u64>, StatusError> {
        match self.pending(bytes).await {
            Ok(rv) => Ok(Some(rv)),
            Err(WriteFailure::Retry) => Ok(None),
            Err(WriteFailure::Fail(e)) => Err(e),
        }
    }

    /// The write of [`Self::commit`] as a `'static` future, for callers that run it on its
    /// own task (e.g. under a Service's reservations).
    pub(crate) fn pending(
        &mut self,
        bytes: Bytes,
    ) -> impl std::future::Future<Output = Result<u64, WriteFailure>> + Send + 'static {
        let expected = self
            .expected
            .take()
            .expect("write without a preceding read");
        let store = self.store.clone();
        let key = self.key.clone();
        let retry = self.client_rv.is_none() && tokio::time::Instant::now() < self.deadline;
        let ns = self.ns.clone();
        let (group, resource, name, kind) = (
            self.group.clone(),
            self.resource.clone(),
            self.name.clone(),
            self.kind.clone(),
        );
        async move {
            let fail = |e: StoreError| {
                WriteFailure::Fail(crate::handlers::generic::store_err(
                    e, &group, &resource, &name, &kind,
                ))
            };
            let lost = |e: StoreError| if retry { WriteFailure::Retry } else { fail(e) };
            if let (0, Some((ns, ns_key))) = (expected, &ns) {
                return match store
                    .create_if_namespace_active(Some(ns_key), &key, bytes)
                    .await
                {
                    Ok(rv) => Ok(rv),
                    Err(
                        e @ (CreateNamespacedError::NamespaceTerminating
                        | CreateNamespacedError::NamespaceNotFound),
                    ) => Err(WriteFailure::Fail(Status::namespace_create_rejected(
                        ns, &e,
                    ))),
                    Err(CreateNamespacedError::Store(e @ StoreError::AlreadyExists { .. })) => {
                        Err(lost(e))
                    }
                    Err(CreateNamespacedError::Store(e)) => Err(fail(e)),
                };
            }
            match store.put(&key, bytes, Some(expected)).await {
                Ok(rv) => Ok(rv),
                // The store reports a missing key as a mismatch against revision 0.
                Err(StoreError::RevisionMismatch { current: 0, .. }) if expected != 0 => Err(
                    WriteFailure::Fail(Status::not_found(&group, &resource, &name)),
                ),
                Err(
                    e @ (StoreError::RevisionMismatch { .. } | StoreError::AlreadyExists { .. }),
                ) => Err(lost(e)),
                Err(StoreError::NotFound { .. }) => Err(WriteFailure::Fail(Status::not_found(
                    &group, &resource, &name,
                ))),
                Err(e) => Err(fail(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use u7s_store::SqliteStore;

    const KEY: &str = "/registry/configmaps/default/c";
    const CTX: (&str, &str, &str, &str) = ("", "configmaps", "c", "ConfigMap");

    /// How a direct `.put(` constrains the stored revision, read off its third argument.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Put {
        /// `None`: an unconditional upsert.
        Blind,
        /// `Some(0)`: fails if the key exists.
        CreateOnly,
        /// `Some(rv)` or a caller-supplied expectation.
        Conditional,
    }

    /// Every production `.put(` call site: `(file, fn, argument class)` and how many there are.
    /// A new site, or a site whose class changes (a pinned write turned into a blind one),
    /// fails until it is listed here with why it cannot resurrect a deleted object or clobber a
    /// write it did not see. An update-class write belongs on `GuaranteedUpdate` instead.
    ///
    /// Blind is only for a record nothing else updates (new record, or a seed of a
    /// server-owned constant). Conditional is a revision read in the same function (a lost
    /// race is a 409 or the caller's own loop re-reads), the client's required resourceVersion
    /// (422 without it), or the caller's argument.
    const AUDITED: &[(&str, &str, Put, usize)] = &[
        ("bootstrap_rbac.rs", "reconcile_object", Put::CreateOnly, 2),
        ("bootstrap_rbac.rs", "reconcile_object", Put::Conditional, 1),
        ("cert_expiry.rs", "upsert_event", Put::Blind, 1),
        (
            "csr_approver.rs",
            "approve_kubelet_serving_csrs",
            Put::Conditional,
            1,
        ),
        ("guaranteed_update.rs", "pending", Put::Conditional, 1),
        (
            "handlers/aggregation.rs",
            "check_and_persist_availability",
            Put::Conditional,
            1,
        ),
        ("handlers/cr.rs", "create_cr", Put::CreateOnly, 1),
        ("handlers/cr.rs", "delete_cr", Put::Conditional, 1),
        (
            "handlers/cr.rs",
            "delete_cr_namespaced",
            Put::Conditional,
            1,
        ),
        ("handlers/cr.rs", "patch_cr", Put::CreateOnly, 1),
        ("handlers/cr.rs", "patch_cr", Put::Conditional, 1),
        ("handlers/cr.rs", "patch_cr_namespaced", Put::Conditional, 1),
        ("handlers/cr.rs", "replace_cr", Put::Conditional, 1),
        (
            "handlers/cr.rs",
            "replace_cr_namespaced",
            Put::Conditional,
            1,
        ),
        ("handlers/crd.rs", "create_crd", Put::CreateOnly, 1),
        ("handlers/crd.rs", "delete_instances", Put::Conditional, 1),
        ("handlers/crd.rs", "finalize_crd", Put::Conditional, 4),
        ("handlers/crd.rs", "patch_crd", Put::CreateOnly, 1),
        ("handlers/crd.rs", "patch_crd_status", Put::Conditional, 1),
        ("handlers/crd.rs", "purge_crd", Put::Blind, 1),
        ("handlers/crd.rs", "put_crd_status", Put::Conditional, 1),
        ("handlers/crd.rs", "replace_crd", Put::Conditional, 1),
        ("handlers/crd.rs", "soft_delete_crd", Put::Conditional, 1),
        ("handlers/csr.rs", "create_csr", Put::CreateOnly, 1),
        (
            "handlers/namespaces.rs",
            "create_namespace",
            Put::CreateOnly,
            1,
        ),
        (
            "handlers/namespaces.rs",
            "delete_namespace",
            Put::Conditional,
            1,
        ),
        (
            "handlers/namespaces.rs",
            "patch_namespace",
            Put::Conditional,
            1,
        ),
        (
            "handlers/namespaces.rs",
            "patch_namespace_status",
            Put::Conditional,
            1,
        ),
        (
            "handlers/namespaces.rs",
            "seed_root_ca_configmap",
            Put::CreateOnly,
            1,
        ),
        ("handlers/pods.rs", "bind_pod", Put::Conditional, 1),
        (
            "handlers/pods.rs",
            "check_pdb_allows_eviction",
            Put::Conditional,
            1,
        ),
        ("handlers/pods.rs", "delete_pod", Put::Conditional, 1),
        ("handlers/pods.rs", "evict_pod", Put::Conditional, 1),
        (
            "handlers/resource.rs",
            "create_resource",
            Put::CreateOnly,
            1,
        ),
        (
            "handlers/resource.rs",
            "delete_namespaced_resource",
            Put::Conditional,
            1,
        ),
        (
            "handlers/resource.rs",
            "delete_resource",
            Put::Conditional,
            1,
        ),
        (
            "handlers/resource.rs",
            "propagate_rs_revision_to_deployment",
            Put::Conditional,
            1,
        ),
        (
            "handlers/resource.rs",
            "write_flowcontrol_status",
            Put::Conditional,
            1,
        ),
        (
            "handlers/resource.rs",
            "write_vap_status",
            Put::Conditional,
            1,
        ),
        (
            "lib.rs",
            "reconcile_extension_apiserver_authentication",
            Put::Conditional,
            1,
        ),
        (
            "lib.rs",
            "reconcile_kubernetes_endpointslice",
            Put::Conditional,
            1,
        ),
        ("lib.rs", "reconcile_quota_status", Put::Conditional, 1),
        (
            "lib.rs",
            "reconcile_system_node_binding_subjects",
            Put::Conditional,
            1,
        ),
        ("lib.rs", "seed_cluster_config", Put::CreateOnly, 1),
        ("lib.rs", "seed_cluster_config", Put::Conditional, 1),
        ("lib.rs", "seed_cluster_info", Put::CreateOnly, 1),
        ("lib.rs", "seed_cluster_info", Put::Conditional, 1),
        ("lib.rs", "seed_flowcontrol", Put::Blind, 21),
        ("lib.rs", "seed_kube_root_ca", Put::CreateOnly, 1),
        ("lib.rs", "seed_kube_root_ca", Put::Conditional, 1),
        ("lib.rs", "seed_namespaces", Put::CreateOnly, 1),
        ("lib.rs", "seed_priorityclasses", Put::CreateOnly, 1),
        ("lib.rs", "seed_serviceaccounts", Put::CreateOnly, 1),
        ("lib.rs", "seed_servicecidrs", Put::CreateOnly, 1),
        ("lib.rs", "seed_services", Put::CreateOnly, 4),
        (
            "lib.rs",
            "upgrade_default_servicecidr_to_dual_stack",
            Put::Conditional,
            1,
        ),
        ("service_alloc.rs", "put_committing", Put::Conditional, 1),
        ("service_alloc.rs", "repair", Put::CreateOnly, 1),
        ("service_alloc.rs", "reserve", Put::CreateOnly, 1),
        ("service_resolver.rs", "put_loopback_service", Put::Blind, 1),
        ("state.rs", "allocate_service_ip", Put::CreateOnly, 1),
        ("state.rs", "seed_immortal_namespaces", Put::CreateOnly, 1),
    ];

    /// The text of the third top-level argument of the call whose `(` is at `open`.
    fn third_arg(text: &str, open: usize) -> Option<String> {
        let (mut depth, mut in_str, mut esc) = (0usize, false, false);
        let mut args = vec![String::new()];
        for c in text[open..].chars() {
            if in_str {
                args.last_mut().unwrap().push(c);
                match (esc, c) {
                    (true, _) => esc = false,
                    (false, '\\') => esc = true,
                    (false, '"') => in_str = false,
                    _ => {}
                }
                continue;
            }
            match c {
                '"' => {
                    in_str = true;
                    args.last_mut().unwrap().push(c);
                }
                '(' | '[' | '{' => {
                    depth += 1;
                    if depth > 1 {
                        args.last_mut().unwrap().push(c);
                    }
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    args.last_mut().unwrap().push(c);
                }
                ',' if depth == 1 => args.push(String::new()),
                _ => args.last_mut().unwrap().push(c),
            }
        }
        args.get(2)
            .map(|a| a.split_whitespace().collect::<String>())
    }

    fn classify(arg: &str) -> Put {
        match arg {
            "None" => Put::Blind,
            "Some(0)" => Put::CreateOnly,
            _ => Put::Conditional,
        }
    }

    /// `(file, fn, class) -> count` of every store `.put(` outside test code under `src/`.
    fn production_put_sites() -> std::collections::BTreeMap<(String, String, Put), usize> {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                let name = p.file_name().unwrap().to_string_lossy().to_string();
                if p.is_dir() {
                    if !matches!(name.as_str(), "tests" | "test_utils" | "testdata") {
                        walk(&p, out);
                    }
                } else if name.ends_with(".rs")
                    && name != "tests.rs"
                    && name != "test_support.rs"
                    && !name.ends_with("_tests.rs")
                {
                    out.push(p);
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&src, &mut files);
        let mut sites = std::collections::BTreeMap::new();
        for f in files {
            let rel = f.strip_prefix(&src).unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(&f).unwrap();
            let mut in_test_mod = false;
            let mut prev_cfg_test = false;
            let mut current_fn = String::new();
            let mut offset = 0;
            for line in text.split_inclusive('\n') {
                let line_start = offset;
                offset += line.len();
                let line = line.trim_end_matches('\n');
                if in_test_mod {
                    in_test_mod = line != "}";
                    continue;
                }
                if prev_cfg_test && line.starts_with("mod ") && line.ends_with('{') {
                    in_test_mod = true;
                }
                prev_cfg_test = line == "#[cfg(test)]";
                let t = line.trim_start();
                if let Some(i) = t.find("fn ") {
                    let head = &t[..i];
                    if head.is_empty()
                        || head.ends_with("async ")
                        || head.ends_with("pub ")
                        || head.ends_with(") ")
                    {
                        current_fn = t[i + 3..]
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect();
                    }
                }
                if t.starts_with("//") {
                    continue;
                }
                let mut from = 0;
                while let Some(i) = line[from..].find(".put(") {
                    let open = line_start + from + i + ".put".len();
                    from += i + ".put(".len();
                    // A router's `.put(handler)` has one argument; a store put has three.
                    if let Some(arg) = third_arg(&text, open) {
                        *sites
                            .entry((rel.clone(), current_fn.clone(), classify(&arg)))
                            .or_insert(0) += 1;
                    }
                }
            }
        }
        sites
    }

    /// An update-class write that calls `store.put` directly is the bug class this module
    /// removes: it either overwrites a write it never saw or resurrects a deleted object.
    /// Fails when a call site appears, disappears or changes its argument class unaudited.
    #[test]
    fn every_direct_store_put_is_audited() {
        let found = production_put_sites();
        let audited: std::collections::BTreeMap<_, _> = AUDITED
            .iter()
            .map(|(f, n, c, k)| ((f.to_string(), n.to_string(), *c), *k))
            .collect();
        let keys: std::collections::BTreeSet<_> = found.keys().chain(audited.keys()).collect();
        let diff: Vec<String> = keys
            .into_iter()
            .filter_map(|key| {
                let (have, want) = (found.get(key).unwrap_or(&0), audited.get(key).unwrap_or(&0));
                (have != want).then(|| format!("{key:?}: found {have}, audited {want}"))
            })
            .collect();
        assert!(
            diff.is_empty(),
            "direct `.put(` sites differ from the audit:\n{}\nfound:\n{}",
            diff.join("\n"),
            found
                .iter()
                .map(|((f, n, c), k)| format!("        (\"{f}\", \"{n}\", Put::{c:?}, {k}),"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    fn with_n(n: i64) -> Bytes {
        Bytes::from(format!(r#"{{"metadata":{{"name":"c"}},"n":{n}}}"#))
    }

    fn n_of(o: &StoreObject) -> i64 {
        serde_json::from_slice::<serde_json::Value>(&o.value).unwrap()["n"]
            .as_i64()
            .unwrap()
    }

    async fn seeded() -> Arc<SqliteStore> {
        let s = Arc::new(SqliteStore::new(":memory:").unwrap());
        s.put(KEY, with_n(1), None).await.unwrap();
        s
    }

    /// A writer that loses the race must redo its update on the winner's object; applying the
    /// stale computation would silently drop the winner's change.
    #[tokio::test]
    async fn conflict_rereads_and_applies_update_to_the_fresh_object() {
        let s = seeded().await;
        let mut gu = GuaranteedUpdate::new(s.clone(), KEY, None, CTX);
        let mut attempts = 0;
        let rv = loop {
            let cur = gu.read_existing().await.unwrap();
            attempts += 1;
            if attempts == 1 {
                s.put(KEY, with_n(10), None).await.unwrap();
            }
            if let Some(rv) = gu.commit(with_n(n_of(&cur) + 1)).await.unwrap() {
                break rv;
            }
        };
        assert_eq!(attempts, 2);
        let stored = s.get(KEY).await.unwrap().unwrap();
        assert_eq!(stored.revision, rv);
        assert_eq!(n_of(&stored), 11, "must build on the concurrent write");
    }

    /// An update that raced a delete must report NotFound; an unconditional put would
    /// resurrect the deleted object.
    #[tokio::test]
    async fn object_deleted_mid_update_is_not_found_and_stays_deleted() {
        let s = seeded().await;
        let mut gu = GuaranteedUpdate::new(s.clone(), KEY, None, CTX);
        gu.read_existing().await.unwrap();
        s.delete(KEY, None).await.unwrap();
        let err = gu.commit(with_n(2)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert!(s.get(KEY).await.unwrap().is_none());
    }

    /// A client that pinned a resourceVersion asked for exactly that revision; retrying on
    /// the fresh object would apply its change to state it never saw.
    #[tokio::test]
    async fn client_pinned_stale_revision_conflicts_without_retry() {
        let s = seeded().await;
        let pinned = s.get(KEY).await.unwrap().unwrap().revision;
        s.put(KEY, with_n(5), None).await.unwrap();
        let mut gu = GuaranteedUpdate::new(s.clone(), KEY, Some(pinned), CTX);
        gu.read_existing().await.unwrap();
        let err = gu.commit(with_n(2)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert_eq!(n_of(&s.get(KEY).await.unwrap().unwrap()), 5);
    }

    /// A client that pinned a resourceVersion and lost the object to a delete gets 404 like an
    /// unpinned one, not a 409 that sends it into a retry loop against nothing.
    #[tokio::test]
    async fn client_pinned_revision_on_a_deleted_object_is_not_found() {
        let s = seeded().await;
        let pinned = s.get(KEY).await.unwrap().unwrap().revision;
        let mut gu = GuaranteedUpdate::new(s.clone(), KEY, Some(pinned), CTX);
        gu.read_existing().await.unwrap();
        s.delete(KEY, None).await.unwrap();
        let err = gu.commit(with_n(2)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert!(s.get(KEY).await.unwrap().is_none());
    }

    /// Kinds with AllowCreateOnUpdate must still create on PUT to a missing key.
    #[tokio::test]
    async fn create_on_update_kinds_still_create() {
        let s = Arc::new(SqliteStore::new(":memory:").unwrap());
        let mut gu = GuaranteedUpdate::new(s.clone(), KEY, None, CTX);
        assert!(gu.read().await.unwrap().is_none());
        assert!(gu.commit(with_n(1)).await.unwrap().is_some());
        assert_eq!(n_of(&s.get(KEY).await.unwrap().unwrap()), 1);
    }

    /// Two creators racing on a missing key: the loser retries against the winner instead of
    /// overwriting it or failing with 409.
    #[tokio::test]
    async fn lost_create_race_retries_against_the_winner() {
        let s = Arc::new(SqliteStore::new(":memory:").unwrap());
        let mut gu = GuaranteedUpdate::new(s.clone(), KEY, None, CTX);
        assert!(gu.read().await.unwrap().is_none());
        s.put(KEY, with_n(7), None).await.unwrap();
        assert!(gu.commit(with_n(8)).await.unwrap().is_none());
        let cur = gu.read().await.unwrap().unwrap();
        assert_eq!(n_of(&cur), 7);
        assert!(gu.commit(with_n(8)).await.unwrap().is_some());
    }
}

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

    /// Every production function that calls `.put(` directly, with why it cannot resurrect a
    /// deleted object or clobber a write it did not see. A new entry needs the same
    /// justification; an update-class write belongs on `GuaranteedUpdate` instead.
    ///
    /// create-only: `Some(0)`, fails if the key exists.
    /// pinned: `Some(rv)` of the revision read in the same function (no retry; a lost race
    /// is a 409, or the caller's own loop re-reads).
    /// client rv: the handler rejects (422) a write without the client's resourceVersion.
    /// caller: the expectation is the caller's argument.
    /// new record: a blind write of a record nothing else updates.
    const AUDITED: &[(&str, &str)] = &[
        ("bootstrap_rbac.rs", "reconcile_object"), // create-only / pinned
        ("cert_expiry.rs", "upsert_event"),        // new record
        ("csr_approver.rs", "approve_kubelet_serving_csrs"), // pinned
        ("guaranteed_update.rs", "pending"),       // the shared path
        ("handlers/aggregation.rs", "check_and_persist_availability"), // pinned
        ("handlers/cr.rs", "create_cr"),           // create-only
        ("handlers/cr.rs", "delete_cr"),           // pinned
        ("handlers/cr.rs", "delete_cr_namespaced"), // pinned
        ("handlers/cr.rs", "patch_cr"),            // create-only / pinned
        ("handlers/cr.rs", "patch_cr_namespaced"), // pinned
        ("handlers/cr.rs", "replace_cr"),          // client rv
        ("handlers/cr.rs", "replace_cr_namespaced"), // client rv
        ("handlers/crd.rs", "create_crd"),         // create-only
        ("handlers/crd.rs", "delete_instances"),   // pinned
        ("handlers/crd.rs", "finalize_crd"),       // pinned
        ("handlers/crd.rs", "patch_crd_status"),   // pinned
        ("handlers/crd.rs", "purge_crd"),          // new record (tombstone)
        ("handlers/crd.rs", "put_crd_status"),     // client rv
        ("handlers/crd.rs", "replace_crd"),        // client rv
        ("handlers/crd.rs", "soft_delete_crd"),    // pinned
        ("handlers/csr.rs", "create_csr"),         // create-only
        ("handlers/namespaces.rs", "create_namespace"), // create-only
        ("handlers/namespaces.rs", "delete_namespace"), // pinned
        ("handlers/namespaces.rs", "patch_namespace"), // pinned
        ("handlers/namespaces.rs", "patch_namespace_status"), // pinned
        ("handlers/namespaces.rs", "seed_root_ca_configmap"), // create-only
        ("handlers/resource.rs", "create_resource"), // create-only
        ("handlers/resource.rs", "delete_namespaced_resource"), // pinned
        ("handlers/resource.rs", "delete_resource"), // pinned
        (
            "handlers/resource.rs",
            "propagate_rs_revision_to_deployment",
        ), // pinned
        ("handlers/resource.rs", "write_flowcontrol_status"), // pinned
        ("handlers/resource.rs", "write_vap_status"), // pinned
        ("service_alloc.rs", "put_committing"),    // caller
        ("service_alloc.rs", "repair"),            // sentinel records
        ("service_alloc.rs", "reserve"),           // create-only
        ("handlers/crd.rs", "patch_crd"), // create-only (SSA create); updates use GuaranteedUpdate
        ("handlers/pods.rs", "bind_pod"), // pinned
        ("handlers/pods.rs", "check_pdb_allows_eviction"), // pinned
        ("handlers/pods.rs", "delete_pod"), // pinned
        ("handlers/pods.rs", "evict_pod"), // pinned
        ("lib.rs", "build_routes"),       // router wiring (`.put(handler)`)
        ("lib.rs", "reconcile_extension_apiserver_authentication"), // pinned
        ("lib.rs", "reconcile_kubernetes_endpointslice"), // pinned / create-only
        ("lib.rs", "reconcile_quota_status"), // pinned
        ("lib.rs", "reconcile_system_node_binding_subjects"), // pinned
        ("lib.rs", "seed_cluster_config"), // seed: server-owned constant
        ("lib.rs", "seed_cluster_info"),  // seed
        ("lib.rs", "seed_flowcontrol"),   // seed
        ("lib.rs", "seed_kube_root_ca"),  // seed
        ("lib.rs", "seed_namespaces"),    // seed
        ("lib.rs", "seed_priorityclasses"), // seed
        ("lib.rs", "seed_serviceaccounts"), // seed
        ("lib.rs", "seed_servicecidrs"),  // seed
        ("lib.rs", "seed_services"),      // seed
        ("lib.rs", "upgrade_default_servicecidr_to_dual_stack"), // pinned
        ("service_resolver.rs", "put_loopback_service"), // seed
        ("state.rs", "allocate_service_ip"), // create-only
        ("state.rs", "seed_immortal_namespaces"), // create-only
    ];

    /// `(file, fn)` of every `.put(` outside test code under `src/`.
    fn production_put_sites() -> std::collections::BTreeSet<(String, String)> {
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
        let mut sites = std::collections::BTreeSet::new();
        for f in files {
            let rel = f.strip_prefix(&src).unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(&f).unwrap();
            let mut in_test_mod = false;
            let mut prev_cfg_test = false;
            let mut current_fn = String::new();
            for line in text.lines() {
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
                    if head.is_empty() || head.ends_with("async ") || head.ends_with("pub ") {
                        current_fn = t[i + 3..]
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect();
                    } else if head.ends_with(") ") {
                        current_fn = t[i + 3..]
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect();
                    }
                }
                if !t.starts_with("//") && t.contains(".put(") {
                    sites.insert((rel.clone(), current_fn.clone()));
                }
            }
        }
        sites
    }

    /// An update-class write that calls `store.put` directly is the bug class this module
    /// removes: it either overwrites a write it never saw or resurrects a deleted object.
    /// Fails when a function starts calling `.put(` without being audited here.
    #[test]
    fn every_direct_store_put_is_audited() {
        let found = production_put_sites();
        let audited: std::collections::BTreeSet<(String, String)> = AUDITED
            .iter()
            .map(|(f, n)| (f.to_string(), n.to_string()))
            .collect();
        let unaudited: Vec<_> = found.difference(&audited).collect();
        let stale: Vec<_> = audited.difference(&found).collect();
        assert!(
            unaudited.is_empty() && stale.is_empty(),
            "direct `.put(` sites not audited: {unaudited:?}; audited entries that no longer \
             call `.put(`: {stale:?}"
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

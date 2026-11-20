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
        assert!(gu.commit(with_n(2)).await.unwrap().is_none());
        let err = gu.read_existing().await.unwrap_err();
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

//! Shared test-only helpers for handler unit tests.
//!
//! `fn make_state() -> AppState { ... }` (a minimal in-memory `AppState` with
//! no CIDR config, no SA signing key, and an empty group index) was copied
//! byte-for-byte into ~13 handler test modules. A handful of admission/status
//! test modules need a variant that takes a caller-owned `Arc<SqliteStore>`
//! so they can seed data before the `AppState` is built. Both live here so a
//! future change to `AppState::new`'s signature or defaults is a one-file
//! edit instead of a ~18-file mechanical edit.

use std::sync::Arc;

use u7s_store::SqliteStore;

use crate::state::AppState;

/// Build a minimal in-memory `AppState` backed by a fresh `SqliteStore`.
pub(crate) fn make_state() -> AppState {
    make_state_with_store(Arc::new(
        SqliteStore::new(":memory:").expect("in-memory store"),
    ))
}

/// Same as [`make_state`], but takes a caller-provided store so tests can
/// seed data into it before the `AppState` that will serve it is built.
pub(crate) fn make_state_with_store(store: Arc<SqliteStore>) -> AppState {
    AppState::new(
        store,
        None,
        None,
        std::collections::HashMap::new(),
        "https://localhost:6443".into(),
    )
}

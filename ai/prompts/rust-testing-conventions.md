---
name: rust-testing-conventions
description: Rust unit and integration testing conventions for u7s — inject into every test-coverage worker dispatch.
---

# Rust Testing Conventions for u7s

## Unit tests (primary)

Put unit tests in `#[cfg(test)]` modules at the bottom of the same source file.
They can access private internals. This is the Rust idiom; use it for all
pure-logic, data-structure, and parsing tests.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn my_unit_test() { ... }

    #[tokio::test]
    async fn my_async_unit_test() { ... }
}
```

## Integration tests (for HTTP handler flows and multi-component paths)

Integration tests live in `crates/<crate>/tests/` relative to the crate root
(i.e., next to `src/`). Each `.rs` file in `tests/` compiles as a separate
crate. Shared helpers go in `tests/common/mod.rs` and are declared with
`mod common;` in each test file.

Integration tests **only** access public API. They cannot use `use super::*`.

### Binary crates — prerequisite

Binary crates (`[[bin]]` with only `src/main.rs`) cannot be imported by
integration tests. The idiomatic fix: extract logic into `src/lib.rs` and
re-export it, then have `main.rs` call through. Workers assigned to binary
crates must do this refactor first, then test the public functions.

```
crates/controller-manager/
  src/
    lib.rs      ← extracted logic (pub fn / pub async fn)
    main.rs     ← minimal: parse args, call lib::run()
  tests/
    integration_test.rs
```

## Testing async Axum handlers

Use `tower::ServiceExt::oneshot` — no real server needed:

```rust
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt; // for `.oneshot()`

let app = build_router(state);  // call your router constructor

let response = app
    .oneshot(
        Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces")
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

assert_eq!(response.status(), StatusCode::OK);
```

`tower` is already in the apiserver dependency tree via axum. No new crate
needed.

## SQLite / store isolation in tests

Use in-memory SQLite per test. The store crate's `SqliteStore::new(":memory:")`
gives a fresh, isolated DB with no disk I/O:

```rust
let store = SqliteStore::new(":memory:").await.unwrap();
```

Never share a store instance across tests. In-memory databases are
per-connection; each test function gets its own.

## Coverage targets (per operator directive, 2026-05-22)

- Non-`main.rs` files: **70% line, 95% function** coverage
- `*main.rs` files: extract decision logic into pure/testable functions; accept
  lower absolute numbers on the remaining wiring. Do not attempt to test
  `main()` itself.

## Dev-dependency additions allowed

Workers may add to `[dev-dependencies]` in the crate's `Cargo.toml`:
- `tokio-test` — test helpers for async code
- `axum` `MockConnectInfo` etc. if needed
- Nothing else without checking with the mayor first.

## Extracting errors without Debug

`StatusError` does NOT implement `Debug`. Never use `.unwrap_err()` or
`.expect_err()` on a `Result` whose `Ok` or `Err` variant is `impl IntoResponse`
or `StatusError` — this compiles locally but fails under `cargo llvm-cov` (the
CI coverage job).

Use a `match` instead:

```rust
// WRONG — fails under llvm-cov:
let err = handler(...).await.unwrap_err();

// CORRECT:
let result = handler(...).await;
let err = match result { Err(e) => e, Ok(_) => panic!("expected error") };
assert_eq!(err.0, StatusCode::NOT_FOUND);
```

This applies to both async handler calls and sync functions returning
`Result<_, StatusError>`.

## Cargo fmt

Always run `cargo fmt --all` before pushing. Then verify with
`cargo fmt --all -- --check`. A fmt failure in CI means a re-dispatch round-trip.

## Worker quality gate checklist

Before every push, run in this order:
1. `cargo fmt --all -- --check`
2. `cargo test --workspace --quiet` (or `-p <crate>` for the touched crate)
3. `cargo clippy --workspace --tests -- -D warnings`

These match exactly what CI and the pre-push hook enforce.

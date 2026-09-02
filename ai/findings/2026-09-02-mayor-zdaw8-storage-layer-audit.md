# Storage layer audit: SQL injection, transaction isolation, quota admission races

Bead: mayor-zdaw8

VERDICT UP FRONT: issues-found — one HIGH finding (transaction isolation). SQL
injection surface is clean; quota admission check-then-write is correctly
guarded end-to-end.

## Threat class 1 — SQL injection surfaces: CLEAN

Enumerated every `.execute`/`.execute_batch`/`.prepare`/`.prepare_cached`/
`.query`/`.query_row`/`.query_map` call site in `crates/store/src/sqlite.rs`
(49 non-test call sites) and every `format!(` occurrence (grepped
exhaustively, not spot-checked).

- `list_sync` (`sqlite.rs:1381-1634`) is the only function that builds
  dynamic WHERE clauses (prefix scans, field-selector fast paths,
  pagination). Every dynamic value (`prefix`, `upper` bound,
  `continue_key`, field-selector `value`, `limit`) is passed as a bound
  `?N` rusqlite parameter via the `query_all` helper
  (`sqlite.rs:1367-1379`, takes `&[&dyn rusqlite::ToSql]`). The SQL text
  itself is always a `&'static str` literal selected by a `match`; no
  interpolation of any value into the SQL string.
- The one dynamic *string* built near a query, `sqlite.rs:1482`
  (`let like_prefix = format!("{}%", prefix);`), becomes the bound value
  for `key LIKE ?1` (`sqlite.rs:1486-1489`), not raw SQL text. `prefix`
  here is a server-derived resource-type/namespace root
  (`/registry/pods/<namespace>/`), not raw user text — namespace names
  are RFC-1123-label-restricted upstream, so no `%`/`_` LIKE-metacharacter
  injection is reachable through it either (LOW/DEFER, correctness not
  security, and not exploitable given namespace naming rules).
- All four write paths (`put_sync`, `delete_sync`,
  `create_if_namespace_active_sync`, `delete_namespace_sync`,
  `sqlite.rs:1011-1333`) use static SQL text with `params![...]` for every
  `INSERT`/`UPDATE`/`DELETE` (e.g. `sqlite.rs:1094-1096, 1111-1114,
  1185-1188, 1195, 1253-1256, 1264-1266, 1315-1317, 1324`).
- The other `format!(` hit in production code, `sqlite.rs:895`
  (`shard_key`), only builds an in-memory ring-buffer map key, never SQL.
- Every other `format!(` occurrence (60+, starting at `sqlite.rs:2423`)
  lives inside `mod tests` (`sqlite.rs:2417-5798`, confirmed by brace
  structure — the module runs to EOF), building test fixture keys/values,
  not production SQL.

This confirms and extends Phase 0's single-grep spot check: no query is
built by string-formatting untrusted input anywhere in this file.

## Threat class 2 — Transaction isolation: HIGH finding

**Finding STORE-TXN-1 (HIGH):** every write-path transaction
(`put_sync`, `delete_sync`, `create_if_namespace_active_sync`,
`delete_namespace_sync`) can be left permanently open on the single
shared `write_conn` by any `rusqlite`/`serde_json` error that isn't one
of the explicitly-handled business-logic branches, wedging every future
write on the process until restart.

- `list_sync` (`sqlite.rs:1381-1634`) already has the correct pattern: it
  wraps its body in `Transaction::new_unchecked(conn,
  TransactionBehavior::Deferred)` (`sqlite.rs:1386`), whose `Drop` rolls
  back automatically on any early `?`-return. This is proven by the
  existing test `list_sync_error_path_rolls_back_transaction`
  (`sqlite.rs:4193-4221`), which forces a mid-transaction failure and
  asserts `conn.is_autocommit()`.
- The four write paths instead use raw `conn.execute_batch("BEGIN
  IMMEDIATE")` (`sqlite.rs:1019, 1143, 1220, 1294`) with **manual**
  `conn.execute_batch("ROLLBACK")` calls, issued only on named
  business-logic branches: `AlreadyExists`/`RevisionMismatch`/`NotFound`/
  no-op/`NamespaceTerminating`/exists (`sqlite.rs:1050, 1056, 1064, 1081,
  1162, 1172, 1233, 1247, 1307`). Every OTHER fallible call in these
  functions propagates its error via a bare `?` with NO matching
  rollback:
  - `put_sync`: `sqlite.rs:1024-1035` (`query_row(...).optional()?` —
    `.optional()` only absorbs `QueryReturnedNoRows`, any other
    `rusqlite::Error` still propagates), `1094-1097`, `1100-1104`, `1108`
    (`stamp_resource_version(&value, new_revision)?`, which itself does
    `serde_json::from_slice(value)?` at `sqlite.rs:968` — AFTER the
    global revision counter has already been incremented at `1094-1097`),
    `1111-1122`.
  - `delete_sync`: `sqlite.rs:1145-1157`, `1185-1188`, `1189-1193`,
    `1195`.
  - `create_if_namespace_active_sync`: `sqlite.rs:1223-1229`,
    `1240-1245`, `1253-1256`, `1257-1261`, `1263`, `1264-1273`.
  - `delete_namespace_sync`: `sqlite.rs:1297-1304`
    (`prepare_cached`+`query_map`), and the per-object loop
    `sqlite.rs:1315-1325` (`execute`/`query_row`/`execute` per deleted
    key, all inside the one already-open transaction).
  - Both `StoreError::Sqlite(#[from] rusqlite::Error)` and
    `StoreError::Serialization(#[from] serde_json::Error)`
    (`crates/store/src/lib.rs:179-180, 188-189`) are plain `From` impls
    with no side effect — nothing in the `?`-propagation path issues a
    `ROLLBACK`.
- **Empirically confirmed** (source analysis + a throwaway unit test,
  run then reverted — final working tree is unmodified, verified via
  `git status --short` clean and `git diff --stat` empty after revert):
  mirroring `list_sync_error_path_rolls_back_transaction`'s exact
  technique (delete the `meta` table's `revision` row so `put_sync`'s
  step-5 `query_row` fails with `QueryReturnedNoRows` mid-transaction),
  `put_sync` returns `Err(StoreError::Sqlite(_))` and leaves
  `conn.is_autocommit() == false` — i.e. the connection is stuck inside
  an open `BEGIN IMMEDIATE`.
- Consequence: `write_conn` is one `Arc<Mutex<Connection>>` reused for
  every write for the life of the process (`sqlite.rs:289`, acquired via
  `.blocking_lock()` in `put`/`delete`/`create_if_namespace_active`/
  `delete_namespace_objects`, e.g. `sqlite.rs:1719-1732`). Once wedged,
  every subsequent call's own `conn.execute_batch("BEGIN IMMEDIATE")`
  fails with "cannot start a transaction within a transaction" — a
  cluster-wide write-path outage that only clears on process restart
  (SQLite's crash-recovery on reopen discards the abandoned transaction).
- Trigger conditions: any `rusqlite::Error` other than
  `QueryReturnedNoRows` occurring mid-transaction (disk I/O error,
  `SQLITE_BUSY`, `SQLITE_FULL`, corruption) hits this on ALL FOUR write
  paths regardless of attacker input. Additionally, in `put_sync`/
  `create_if_namespace_active_sync` specifically, a JSON-parse failure
  inside `stamp_resource_version` would also hit it — whether
  attacker-controlled `value` bytes can actually reach that point as
  invalid JSON depends on validation upstream in the apiserver crate,
  which is outside this bead's file scope and was NOT verified here
  (flagging per Rule 12 rather than asserting it either way). The
  I/O-error trigger alone does not depend on that and is sufficient on
  its own.
- This is exactly the risk class Phase 0 flagged as unverified for write
  paths (bead description, citing `sqlite.rs:4183-4216`'s read-path
  comment) — confirmed here to apply, and with materially higher impact
  than the read-path case (`Store::get()` has a stale-revision retry
  fallback to `write_conn` that happens to paper over a wedged
  *read* connection today, per that comment; there is no analogous
  fallback for a wedged *write* connection, since it IS `write_conn`).

Severity: HIGH. Not attacker-triggerable via crafted field values with
certainty (the JSON-parse-failure trigger's reachability from untrusted
input is unverified), but a single transient storage-layer error (which
IS in scope for a control plane's normal operating envelope — disk
pressure, `SQLITE_BUSY` under contention despite the `BEGIN IMMEDIATE`
serialization, corruption) turns into a full, unrecoverable-without-restart
denial of service for every create/update/delete in the cluster.

## Threat class 3 — Check-then-write races (quota admission): CLEAN

`QuotaAdmissionLocks::lock` (`crates/apiserver/src/state.rs:156-167`)
returns an `OwnedSemaphorePermit` from a per-namespace `Semaphore::new(1)`
(`state.rs:144-146`).

- Verified all 3 real (non-test) call sites of
  `quota::check_resource_quota` (`crates/apiserver/src/quota.rs:797`) —
  no other caller exists (grepped exhaustively):
  - `crates/apiserver/src/handlers/resource.rs:2611-2612`: `_quota_lock`
    acquired immediately before the quota check, and — since it is never
    explicitly `drop`ped (grepped for `drop(_quota_lock)`, zero hits
    anywhere in the apiserver crate) — stays alive per Rust's normal drop
    order through the entire `create_if_namespace_active`/`put` retry
    loop, to the function's end at line 2744.
  - `crates/apiserver/src/handlers/pods.rs:608-609`: same pattern, lock
    held through 608-696, spanning the `create_if_namespace_active` retry
    loop.
  - `crates/apiserver/src/handlers/cr.rs:3276-3277`: same pattern, lock
    held through 3276-3355, spanning its `create_if_namespace_active`
    retry loop.
- Since `create_if_namespace_active`/`put`'s `.await` only resolves after
  `create_if_namespace_active_sync`/`put_sync` executes `COMMIT`
  synchronously inside `spawn_blocking` (`sqlite.rs:1275, 1124`), holding
  the permit until the enclosing handler function returns means it is
  held across the full SQL-level critical section, not merely the
  apiserver-side check — two concurrent creates in the same namespace
  cannot both pass the quota check and both commit.
- **Other check-then-write-shaped path found, and it's correctly NOT
  using this lock:** clusterIP allocation
  (`crates/apiserver/src/state.rs:1326-1396`,
  `maybe_allocate_cluster_ip` → `allocate_service_ip`). This does not
  need an app-level lock because it relies on SQL-level atomicity
  instead: `store.put(sentinel_key, ..., Some(0))` (create-only,
  `state.rs:1368-1372`) executes inside ONE `BEGIN IMMEDIATE` transaction
  whose `(Some(_), Some(0)) => AlreadyExists` branch
  (`sqlite.rs:1049-1054`) makes two racing allocations of the same IP
  offset mutually exclusive at the SQLite level; the loser gets
  `AlreadyExists` and tries the next candidate (`state.rs:1382-1384`,
  doc comment at `state.rs:17,22`). This is the same CAS-via-`objects.key`-
  PRIMARY-KEY pattern the file's own top comment calls out — genuinely
  race-safe, no gap.
- DEFER (not exhaustively verified): did not do a full line-by-line sweep
  of every apiserver admission path for an unguarded check-then-write
  uniqueness invariant beyond quota and clusterIP allocation (e.g.
  RBAC role/binding uniqueness, PriorityClass/StorageClass defaulting
  exclusivity). Grepped all `Semaphore` usage in the apiserver crate —
  only `QuotaAdmissionLocks`, `WatchLimitState` (a per-client watch-count
  rate limiter, not a correctness lock,
  `crates/apiserver/src/state.rs:88-131`), and `inflight.rs`'s
  concurrency-limiting middleware (also rate-limiting, not a correctness
  lock) exist. No other check-then-write shape was found within this
  audit's scope, but absence-of-evidence is not proof here — flagging so
  a future pass can target admission paths outside the storage layer
  specifically.

## Summary

| # | Threat class | Verdict | Severity |
|---|---|---|---|
| 1 | SQL injection | clean | — |
| 2 | Transaction isolation (write paths) | issue found | HIGH |
| 3 | Quota admission check-then-write | clean | — |

VERDICT: issues-found (one HIGH: `put_sync`/`delete_sync`/
`create_if_namespace_active_sync`/`delete_namespace_sync` can wedge the
shared write connection open forever on any non-`QueryReturnedNoRows`
storage error, unlike `list_sync` which already has the correct
drop-guard pattern).

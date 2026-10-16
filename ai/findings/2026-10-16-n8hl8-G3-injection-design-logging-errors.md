# G3 audit (mayor-n8hl8): A05 Injection, A06 Insecure Design, A09 Logging, A10 Exceptional Conditions

Date: 2026-10-16. Tree: aec606e3. 3 HIGH, 5 MED, 4 LOW, 2 INFO; most serious: an unauthenticated connection flood kills the whole apiserver process (accept error is fatal, no connection cap, no TLS-handshake or header timeout) (G3-1).

Bead: mayor-n8hl8

PoCs were uncommitted in-crate tests (debug build, since removed from the worktree); numbers are debug-build, so release is faster by a constant factor, not by an order of growth.

---

## G3-1  HIGH  A06/A10  Unauthenticated connection flood kills the process
- Position: unauthenticated network.
- `crates/apiserver/src/lib.rs:4493` `let (tcp_stream, _peer) = listener.accept().await?;` -> any accept error (EMFILE/ENFILE/ENOBUFS) returns `Err` from `serve_tls`, which `run` propagates (`lib.rs:719` `result?`), so the process exits. There is no connection cap, no TLS handshake timeout (`lib.rs:4500` `acceptor.accept` is awaited bare), no HTTP/1 header-read timeout (hyper's 30 s default is inert: it needs `.timer(...)` and `auto::Builder` at `lib.rs:4488` sets none), no h2 keepalive/idle timeout, and no TCP keepalive (`configure_accepted_socket` only sets NODELAY).
- Attacker gets: open silent TCP connections (never complete the handshake) until RLIMIT_NOFILE (raised to <=65536, `lib.rs:83`) -> accept EMFILE -> apiserver exits (whole-cluster API outage, restart loop while the flood continues). On a 1 GiB host the per-connection rustls/tokio state likely OOM-kills the process first. The same missing timeouts allow ordinary slowloris.
- Evidence: by reading (code paths + hyper-1.12.0 `header_read_timeout` docs: "Requires a Timer"). Not run live.
- Fix: log-and-continue on accept errors (with a short sleep on EMFILE), `tokio::time::timeout` around the TLS handshake (~10 s), a global connection semaphore, `http1().timer(TokioTimer).header_read_timeout(..)`, `http2().timer(..).keep_alive_interval(..)`, TCP keepalive.
- Regresses an s851y fix: no.

## G3-2  HIGH  A05  `?container=` path traversal into arbitrary kubelet endpoints (pods/log, attach, exec)
- Position: any authenticated user with `pods/log` get on one pod scheduled to a node (namespaced low-priv; `pods/log` is commonly granted to developers).
- `crates/apiserver/src/handlers/proxy.rs:233-236` (`/containerLogs/{ns}/{pod}/{container}`), `:486` (attach), `:1006-1008` (exec). `validate_path_segment` is applied to namespace and pod name (`:171-172`, `:402-403`, `:884-885`) but NOT to `container`, which comes straight from the (percent-decoded) query string (`:229-230`, `:447-452`, `:927-932`).
- PoC (confirmed): with a pod `dev/mine` on node `n1` and `container=../../pods`, `resolve_log_target` returned `https://10.0.0.5:10250/containerLogs/dev/mine/../../pods`, and `reqwest::Url::parse` normalised it to `/containerLogs/pods`, proving client-side dot-segment resolution. Three `..` (`../../../pods`) therefore yield `/pods`.
- Attacker gets: GET requests to any kubelet path, authenticated with the apiserver's kubelet client identity (nodes/proxy equivalent): `/pods` (every pod spec on the node, across namespaces), `/configz`, `/stats/summary`, `/logs/..` (host log dir, including other tenants' container logs under `/var/log/pods`), `/metrics`. Cross-namespace log/spec read and node introspection from a pods/log grant. For exec/attach (raw request line via tungstenite, no client-side normalisation) kubelet's Go mux would probably 301 a `..` path, but that is luck, not a control; `?`/`#` in `container` also injects query params.
- Also log injection (LOW-class): `proxy.rs:339` logs the raw `kubelet_url` containing the decoded value (`%0A` -> newline).
- Fix: validate `container` with `validate_path_segment` AND require it to exist in the pod's `spec.containers/initContainers/ephemeralContainers` (upstream returns 400 "container X is not valid for pod"). Percent-encode path segments when building kubelet URLs.
- Regresses an s851y fix: no, but it is an incomplete fix of a recent change (`validate_path_segment` was added 2026-10-09, commits 7ed6c27a / 279eff93) that missed the third path segment.

## G3-3  HIGH  A06/A05  YAML alias expansion ("billion laughs") on server-side-apply bodies
- Position: any authenticated user allowed to PATCH any resource (namespaced low-priv with edit on their own ns is enough); body is read after authz.
- `crates/apiserver/src/handlers/json_patch.rs:680` `yaml_rust2::YamlLoader::load_from_str`; yaml-rust2-0.13 `yaml.rs:190` resolves every `*alias` by `v.clone()` of the anchored subtree, and anchored nodes are cloned again at definition (`:204`). The `MAX_YAML_DEPTH` guard (`json_patch.rs:~711`) bounds depth, not total node count. 45 call sites use `ssa_body_to_json` (resource.rs, cr.rs, ...).
- PoC (confirmed): `l0: &l0 [x*10]` then `lN: &lN [*lN-1 x10]`: levels=4, 230 B body -> 42 ms; levels=5, 280 B -> 314 ms; levels=6, 330 B -> 4.2 s (debug); 10x per level, with memory growing the same way. A level-8/9 body of ~450 B allocates GBs -> OOM kill of the apiserver on a 1 GiB host, or at minimum pins a runtime worker for minutes (the parse runs on the async worker, no `spawn_blocking`, no timeout).
- Fix: reject the body if it contains any alias/anchor event (`Yaml::Alias` is never needed for k8s manifests; pre-scan with yaml-rust2's `Parser` events, or count nodes while converting), and cap total nodes. Parse on `spawn_blocking` with a memory budget.
- Regresses an s851y fix: no (depth cap is the earlier mitigation; this is the orthogonal width axis).

## G3-4  MED  A06  Slow-body requests pin the global inflight pool (any authenticated user)
- Position: any authenticated principal. `system:basic-user` gives every authenticated identity `create selfsubjectaccessreviews` (a mutating verb).
- `inflight.rs:225-290` holds the permits across `inner.call(req).await`, which includes the handler reading the request body; there is no body-read / request timeout anywhere (`rg TimeoutLayer|RequestBodyTimeout` finds nothing; `DefaultBodyLimit` caps size only, `lib.rs:639`). The limiter is global (MAX_MUTATING=100, MAX_INFLIGHT=200), not per user, and there is no APF queuing (`apf.rs` is classification only).
- Attacker gets: 100 connections each trickling a POST body -> all mutating permits held; further writes queue (<=512, 30 s) then 429; kubelet node-status/lease writes and controllers fail -> cluster-wide write outage from one low-priv client. 200 held -> reads 429 too.
- Evidence: by reading (not run live).
- Fix: body read timeout (tower-http `RequestBodyTimeoutLayer`, ~30-60 s), per-user fairness (cap permits per username), reserve seats for `system:masters`/`system:nodes`/health.

## G3-5  MED  A06  Per-client watch limit is a no-op: permit released as soon as the stream is constructed
- Position: any authenticated user with `watch`.
- `handlers/watch.rs:1007` `let _watch_permit = sem.try_acquire_owned()...`; the stream is built by `async_stream::stream!` (`:1099`), an `async move` block that captures only variables it names, and `_watch_permit` is not named inside it, so it is dropped when `watch_generic_impl` returns (`:1580-1590`), not when the stream ends. The sibling guard `LongRunningWatchGuard` is deliberately constructed inside the block (`:922` doc) - the permit was not.
- PoC (confirmed): 74 consecutive `watch_generic` calls as the same user all returned Ok while `MAX_WATCHES_PER_CLIENT=64`; `available_permits` was 64 afterwards. The existing unit test only pre-exhausts the semaphore, so it cannot catch this.
- Attacker gets: unlimited concurrent watches per user -> unbounded tasks, fds and broadcast receivers on a 1 GiB host (each watch also adds a full pass of event serialisation per write).
- Fix: move `_watch_permit` into the stream block (`let _p = _watch_permit;` as its first statement) and add a test that holds the returned response and asserts `available_permits` drops. Also cap total watches and consider that each ServiceAccount is a fresh identity (the key is username).
- Regresses an s851y fix: possibly (the limit has existed since at least 2026-08-17; I did not check whether s851y listed it as mitigated).

## G3-6  MED  A06/A10  CPU-bound request work on async workers with superlinear blowup (strategic merge patch)
- Position: any authenticated user with PATCH on a resource carrying a merge-keyed list (pods/containers, env, etc.).
- `patch.rs:~295-490` (`strategic_merge_array`): `patch_items.sort_by_key(.. position(..))` and `original_index(..)` linear scans make a list merge worse than O(n^2) in items. PoC (confirmed, debug): n=2000 items (32 KB patch) 0.6 s; n=4000 2.4 s; n=8000 (128 KB) 20.5 s. At the 4 MiB body cap n is ~250k, i.e. effectively unbounded. It runs inline on a tokio worker (the runtime has `.max(2)` workers on this target host), so two such PATCHes stall everything, including health and watches, with no timeout.
- Same class: `strategic_merge_set_array` (`patch.rs:~383`) `contains` per element (O(n^2)).
- Fix: build a `HashMap<key-fields, idx>` index once; run patch application under `spawn_blocking` with a deadline; cap array lengths.

## G3-7  MED  A06  Memory amplification vs. 1 GiB host: 4 MiB bodies x up to 200 inflight, whole-object `Value` trees
- Position: any authenticated user with create/update.
- `lib.rs:75` `MAX_BODY_BYTES = 4 MiB` x `MAX_MUTATING=100` / `MAX_INFLIGHT=200` (`inflight.rs:35-36`); bodies are fully buffered (`Bytes`) then expanded to `serde_json::Value` (typically 10-20x for small-key JSON), cloned for admission/defaulting/patching, then stored and mirrored into the watch ring (RING_CAPACITY=512 full bodies per shard). 100 concurrent 4 MiB creates can plausibly exceed 1 GiB.
- Evidence: by reading; amplification factor not measured here. Treat as suspicion until measured.
- Fix: size the in-flight body budget in bytes (a byte semaphore, not a request count), lower MAX_BODY_BYTES for non-CR writes (upstream object limit ~3 MiB, typical objects << 1 MiB), reject early on `Content-Length`.

## G3-8  MED  A09  Authn/authz rejections and abuse signals are neither logged nor attributable (beyond 0qjgc)
- Position: all. Complements OPEN mayor-0qjgc (no audit log); these are gaps in the basic operational log too.
- The only access-log line is emitted by `ContentTypeLayer` (`content_type.rs:251`), which sits INSIDE `AuthLayer` (`lib.rs:621-639`: body_limit > inflight > auth > content_type > handler). So 401 (`auth.rs:1263`) and 403 (`auth.rs:1345-1570`) responses never reach it; they only bump `apiserver_request_total` (401 with all-empty labels, no user). Neither the access log nor any other line records the authenticated username or the peer address (`serve_tls` discards `_peer`, `lib.rs:4493`). Failed TLS handshakes log `"TLS accept error: {e}"` with no address (`lib.rs:4503`), so a scanner can flood the log with one warn per attempt.
- Inflight 429s are logged (`inflight.rs:~175`) but no counter exists (`rg metrics:: inflight.rs` is empty), without user or peer; admission rejections (webhook/VAP/quota) have no counter or log line; 500s log only the status code, because `Status::internal(..)` carries the message to the client but nothing to the server log (172 call sites use `e.to_string()`).
- Attacker gets: password-spray / token-guessing / authz probing and abusive-client identification are invisible post-hoc; no basis for alerting beyond a global 401/403 rate.
- Fix: log denial events at `info` with username, groups, verb, resource, source address and request id from the AuthLayer; add `inflight_rejected_total{kind}`, `admission_rejected_total{plugin}` and per-reason authn failure counters; carry the peer address in a request extension.

## G3-9  LOW  A10  Panic on char boundary in `percent_decode`, reachable by anonymous
- `auth.rs:795` `u8::from_str_radix(&s[i + 1..i + 3], 16)` slices a `&str` at byte offsets; if byte `i+3` is inside a multi-byte char it panics. Reached from `field_selector_name` (`auth.rs:1513`, any list/watch-shaped path, before any authorisation decision, so anonymous suffices) and `node_authz.rs:277`.
- PoC (confirmed): `percent_decode("%aé")` panics ("end byte index 3 is not a char boundary"); `http::Uri` accepts `?fieldSelector=%aé` and httparse accepts bytes >= 0x80 in the request target (`httparse-1.10.1 URI_MAP`).
- Impact: a panic in the per-connection service future drops that connection (and all its h2 streams) only; the process survives and no lock is held at that point, so this is not a cluster DoS (hence LOW), but it is a per-request crash primitive on the auth path.
- Fix: decode over bytes (`bytes.get(i+1..i+3)` + hex-digit match) or `str::get`.

## G3-10  LOW  A10  `std::sync` lock poisoning would convert one panic into permanent panics
- 20+ `lock().unwrap()` / `read().unwrap()` on shared caches (`state.rs:99-776`, `auth.rs:982,1170`, `sa_sig_cache.rs:137,157`, `admission.rs:971,997`, `discovery.rs:478,526`). Nothing I found panics while holding them, but any future request-path panic inside a guarded section poisons the lock and every later request panics too: a single bug becomes a persistent process-wide outage. `parking_lot` or `unwrap_or_else(PoisonError::into_inner)` removes the amplifier.

## G3-11  LOW  A10  Unbounded `timeoutSeconds` on admission webhooks, no response-size cap
- `admission.rs:1145` `timeout_seconds.map_or(10, |s| s.max(1) as u64)` has no upper clamp (upstream validates 1..=30). Webhook configurations are admin-created, so this is hardening, not a vulnerability. Responses are read unbounded, same trust model.

## G3-12  LOW  A09/A10  Internal error text returned to clients
- 172 sites `Status::internal(e.to_string())`; `StoreError` Display includes `sqlite error: {0}` and `key not found: /registry/...` (`store/src/lib.rs:169-190`), so internal key layout and SQLite messages reach any client that triggers a 5xx. Upstream also leaks etcd errors, so low risk; combine with G3-8 (log server-side, return a generic message with the request id).

## G3-13  INFO  A06  Single shared SQLite read connection serialises all reads
- `store/src/sqlite.rs:371` `read_conn: Arc<Mutex<Connection>>`, taken via `blocking_lock` in `spawn_blocking` (`:2027`) with no interrupt/progress handler/timeout. Non-indexed field-selector lists (`sqlite.rs:~1840`, "filters in Rust after the query") scan and JSON-parse the whole prefix while holding it, so one `kubectl get ... --field-selector status.phase=X` over a big table blocks every other read, and `spawn_blocking` threads pile up behind the mutex. Design limit for the 1 vCPU target; mitigate with a statement deadline (`sqlite3_interrupt`).

## G3-14  INFO  A05  LIKE wildcard not escaped in the nodeName fast path
- `sqlite.rs:1725` `format!("{}%", prefix)` then `key LIKE ?1`. If `prefix` contained `%` or `_` it would match other keys. Not exploitable today: namespaces are DNS labels and a user must already hold RBAC on the literal namespace. Bound parameters are used everywhere (the only `format!` in SQL is `PRAGMA cache_size = {i64}`, `sqlite.rs:1123`). Use a range scan or `ESCAPE`.

---

## Checked and OK
- SQL injection: all values are bound parameters; the only formatted SQL is a PRAGMA with an `i64`. Limit overflow (`u64::MAX`) is clamped (`clamp_list_limit`).
- Header injection: every user-derived header goes through `HeaderValue::from_str` (rejects CR/LF): `aggregation.rs:322-337`, `resource.rs:469..`, `cr.rs:2425`, `json_patch.rs:583`, `content_type.rs:246`. The 301 `Location` (`proxy.rs:2859`) is derived from the already-routed path.
- Raw request-line construction: portforward (`parse_https_url` rejects CR/LF via `PathAndQuery`) and konnectivity CONNECT (`validate_proxy_target_ip` forces an IP literal, rejects loopback/link-local) are guarded and tested.
- Fail-open: no `unwrap_or(true)`-style authz/admission paths; SA-JWT liveness errors fail closed (`auth.rs:~466`); webhook/VAP default `failurePolicy` is `Fail` (`admission.rs:304`).
- CEL: hand-rolled evaluator has a recursion cap (96); CRD rule evaluation runs under a wall-clock budget on a gated thread pool (`cr.rs:1550`); static + runtime cost estimation present (`cel_cost.rs`); regex pattern rewrite is size-bounded (`crd.rs:195`).
- JSON/YAML depth: YAML depth cap 128; deep JSON (depth 120) through strategic/merge patch on a 512 KiB stack passed (PoC).
- Secrets in logs: no body, token or Authorization logging found (`rg` over tracing macros); the URI (with query) is logged but carries no credentials by design (comment at `content_type.rs:199`).
- Log injection: header values cannot contain CR/LF; only decoded query/body strings can (G3-2 `kubelet_url`).
- TokenRequest expiry clamped (600..172800 s).
- Watch broadcast channels are bounded (1024), slow consumers are lagged rather than buffered; per-watch timeout default 30 min.
- Body size: `DefaultBodyLimit` 4 MiB is outermost and covers `Bytes` extractors (production `to_bytes(.., usize::MAX)` hits are all in tests).

## Not covered
- Live repro of G3-1 (fd exhaustion) and G3-4 (slow body); both rest on code reading plus hyper/h2 source.
- Memory amplification factor (G3-7) not measured; no heap profile taken.
- Protobuf decoder recursion/limits (mayor-lzd66), SQLite transaction/isolation (mayor-zdaw8), watch/list backpressure (mayor-vtq5n): relied on the deep-dive beads, only spot-checked.
- Finalizer/ownerRef GC cycles: GC lives in KCM; apiserver namespace-deletion loop not examined.
- HTTP/2 rapid reset: h2 0.4.15 has default reset-stream caps; not exercised. Default `max_concurrent_streams` 200 per connection x unbounded connections is part of G3-1.
- Aggregation/konnectivity/OIDC outbound request paths (SSRF) only skimmed; webhook `caBundle` parse failure silently falls back to the cluster CA (`admission.rs:~1166`), not fail-open but worth G2's look.

## Cross-lane notes
- G1: `auth.rs` `parse_path` works on the raw percent-encoded URI path whereas axum handlers see decoded `Path` segments, and `field_selector_name` (`auth.rs:1513`) derives the authz `name` from a hand-parsed query; please verify no namespace/name/resourceNames divergence (I found none exploitable). Anonymous reaches the authz stage for any path shape (G3-9).
- G1: G3-2 is effectively a `pods/log` -> `nodes/proxy` privilege escalation.
- G2: webhook caBundle fallback; `allow_unauthenticated()` client verifier (`tls.rs:258,602`) is why G3-1 needs no credentials.
- G2/A08: YAML anchors (G3-3) are also a parser-differential risk vs kubectl/upstream, which limit alias expansion.

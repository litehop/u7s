# Decoder recursion-depth + length-prefix audit

Bead: mayor-lzd66

**VERDICT: protobuf and JSON decode paths are safely depth-bounded by their
libraries (prost RECURSION_LIMIT=100, serde_json remaining_depth=128); the
YAML decode path (`yaml_to_json` in `handlers/json_patch.rs`, reached from
every `apply-patch+yaml` PATCH endpoint) has NO depth guard and is a
confirmed, PoC-reproduced stack-overflow (process abort) DoS from a body of
only ~20 KB — filed as a HIGH follow-on fix bead.**

## Scope note

The bead named `proto.rs` + `content_type.rs`. `content_type.rs` turned out
to be almost entirely response-side (Accept negotiation), not request-body
decoding — the actual JSON/YAML *request*-body decode entry points live in
`util.rs`, `handlers/*.rs`, and (for the vulnerable path) `handlers/json_patch.rs`.
Followed the decode path there since that's where the bead's actual
questions (depth limits, length-prefix safety) are answered.

---

## Q1 — Recursion/nesting depth limit, independent of total size

### Protobuf — HAS a depth limit (100), enforced by prost

All production protobuf decoding delegates to `prost::Message::decode`; there
is no hand-rolled length-prefix/tag parsing in the production path.

- `crates/apiserver/src/proto.rs:458` — `Unknown::decode(proto_bytes)` (envelope).
- `crates/apiserver/src/proto.rs:519` — `TokenRequestProto::decode(raw)`.
- `crates/apiserver/src/proto.rs:550-796` (`decoders()`) dispatches by `kind`
  to `crate::<mod>_gen_adapter::decode_<kind>_proto_gen`, e.g.
  `core_gen_adapter.rs:1535` — `core_v1::Namespace::decode(data)`. Verified
  (via `grep -c "::decode("` across all 13 `*_gen_adapter.rs` files, 128 hits
  total, zero manual byte-slicing) that every one of the ~70 registered kinds
  follows this same `<Type>::decode(data)` pattern — there is no adapter that
  hand-parses wire bytes.
- The one hand-rolled `decode_varint` in `proto.rs:922` is inside
  `#[cfg(test)] mod tests` (module opens at `proto.rs:886`) — test-fixture
  code only, not reachable in production.

prost 0.14.4 (`crates.io` source, confirmed via `Cargo.lock:2285`) enforces a
compiled-in recursion limit:

- `prost-0.14.4/src/lib.rs:30` — `const RECURSION_LIMIT: u32 = 100;`
- `prost-0.14.4/src/encoding.rs:37-56` — `DecodeContext` defaults
  `recurse_count: RECURSION_LIMIT` and `enter_recursion()` decrements it by 1
  per nesting level, gated `#[cfg(not(feature = "no-recursion-limit"))]`.
- `prost-0.14.4/src/encoding.rs:78-91` — `limit_reached()` returns
  `Err(DecodeErrorKind::RecursionLimitReached)` once `recurse_count == 0`.
- Checked before every nested decode: `encoding.rs:808` (`message::merge`,
  entered before `merge_loop` at `encoding.rs:809-817`), `encoding.rs:894`
  (`group::merge`), `encoding.rs:1082` (map `merge_with_default`),
  `encoding.rs:172` (`skip_field`, for unknown nested fields).
- Confirmed the `no-recursion-limit` feature (which would disable this) is
  **not** enabled anywhere: `grep -rn "no-recursion-limit"` across
  `Cargo.lock`, `crates/apiserver/Cargo.toml`, `Cargo.toml`, and
  `crates/proto-generated/{build.rs,Cargo.toml}` — zero hits.
- The `crates/proto-generated` crate's protoc-generated types (the real
  production message types, e.g. `core_v1::Namespace`) are themselves
  `#[derive(Message)]` — i.e. built on the exact same prost machinery, not a
  separate hand-written decoder.

**Depth bound = 100, uniformly enforced, cleanly returns `Err` (not a panic)
on overflow.**

### JSON — HAS a depth limit (128), enforced by serde_json, confirmed in force

Production JSON request-body decoding uses `serde_json::from_slice` widely
(e.g. `util.rs:84`, `handlers/authorization.rs:126,263,369,520,674`,
`handlers/core.rs:169`).

- serde_json 1.0.151 (`Cargo.lock:3064`) — `src/de.rs:34,63` —
  `Deserializer.remaining_depth: u8`, default `128`.
- `src/de.rs:1372-1386` — `check_recursion!` macro decrements
  `remaining_depth` on every recursive `deserialize_map`/`deserialize_seq`
  call and returns `Err(RecursionLimitExceeded)` at 0, gated by
  `if_checking_recursion_limit!` which no-ops only when
  `disable_recursion_limit` is set.
- `disable_recursion_limit` is only set via the opt-in `unbounded_depth`
  feature/API (`Deserializer::disable_recursion_limit()` /
  `into_iter().set_failed()`-style unbounded APIs). Confirmed unused:
  `grep -rn "unbounded_depth|disable_recursion_limit"` across
  `crates/**/*.rs` and `Cargo.toml` — zero hits. `serde_path_to_error` (present
  in `Cargo.lock` as a transitive dependency) is likewise never imported by
  `u7s-apiserver`.

**Depth bound = 128, confirmed in force (not disabled), cleanly returns `Err`.**

### YAML — NO depth limit — CONFIRMED stack-overflow DoS (HIGH)

There is no `serde_yaml` in this codebase (Phase 0's premise didn't hold);
the actual YAML request-body decoder is `yaml-rust2`, used by
`ssa_body_to_json` (`crates/apiserver/src/handlers/json_patch.rs:675-688`),
which is the body parser for every `application/apply-patch+yaml`
Server-Side-Apply PATCH across `handlers/{resource,pods,generic,crd,
namespaces,cr,status}.rs` (also parses JSON, since JSON is valid YAML).

- yaml-rust2 0.12.0's own scanner/parser is **not** the problem: it is fully
  iterative. `Scanner::increase_flow_level` (`scanner.rs:1456-1463`) caps
  FLOW-style `[`/`{` nesting via a `flow_level: u8` counter (`scanner.rs:376`)
  — confirmed empirically: a 2,000-deep `[[[...1...]]]` body returns
  `Err("... recursion limit exceeded at byte 255 ...")`, i.e. a clean error at
  256 levels. `YamlLoader`'s AST builder (`yaml.rs:79-147`) uses an explicit
  heap `doc_stack: Vec<(Yaml, usize)>`, not Rust-call-stack recursion.
  `Parser::state_machine` (`parser.rs:476-516`) is a table-driven state
  machine with an explicit `states: Vec<State>` stack, not recursive descent.
- **BUT**: BLOCK-style (indentation) YAML — the format kubectl apply
  --server-side actually sends, per the code comment at
  `json_patch.rs:640-644` — has no equivalent counter. Nesting is tracked in
  `indents: Vec<Indent>` (`scanner.rs:374`), unbounded.
- **The actual bug is u7s's own code**: `yaml_to_json`
  (`handlers/json_patch.rs:694-736`) recursively converts the parsed `Yaml`
  tree to `serde_json::Value` with **zero depth tracking** — `Yaml::Array(a)
  => ... a.iter().map(yaml_to_json)...` (`json_patch.rs:711`) and
  `Yaml::Hash(m) => ... map.insert(key, yaml_to_json(v)?)`
  (`json_patch.rs:712-729`) both recurse once per input nesting level with no
  cap, for both FLOW and BLOCK style (BLOCK style never even hits
  yaml-rust2's 255-level flow cap).

**PoC (committed, `#[ignore]`d — see below): confirmed real crash.**
Severity: **HIGH**. A single ~20 KB authenticated PATCH request (well under
the 4 MiB `DefaultBodyLimit`, `lib.rs:69,605`) crashes the whole apiserver
process (`SIGABRT`, stack overflow) — not just the requesting connection.
This is a full control-plane availability DoS, not a per-request failure.

---

## Q2 — Length-prefix / truncation safety (protobuf)

Since every proto decode site delegates to `prost::Message::decode` (see Q1),
the relevant length-prefix handling lives in prost itself, not in `proto.rs`.
Enumerated the actual read sites:

| Site (prost-0.14.4) | Check | Verdict |
|---|---|---|
| `encoding/varint.rs:37-55` `decode_varint` | Returns `Err(InvalidVarint)` on empty buffer or unroll-overflow (`varint.rs:144-146`, `varint.rs:165-166`); never allocates, never panics | SAFE |
| `encoding.rs:149-163` `merge_loop` (drives nested message + packed-repeated decode) | `let len = decode_varint(buf)?;` then `if len > remaining as u64 { return Err(BufferUnderflow) }` (`encoding.rs:150-153`) **before** any iteration | SAFE |
| `encoding.rs:697-724` `bytes::merge` (Vec<u8>/Bytes fields) | `if len > buf.remaining() as u64 { return Err(BufferUnderflow) }` (`encoding.rs:705-706`) **before** `buf.copy_to_bytes(len)` (`encoding.rs:722`) | SAFE |
| `encoding.rs:726-742` `bytes::merge_one_copy` (String fields, via `string::merge`) | Same `len > buf.remaining()` check (`encoding.rs:734-735`) before `buf.take(len)` (`encoding.rs:740`) | SAFE |
| `encoding.rs:1066-1090` map `merge_with_default` (HashMap fields) | `ctx.limit_reached()?` (`encoding.rs:1082`) then routes through the same bounds-checked `merge_loop` | SAFE |
| `proto.rs:453-457` `decode_k8s_proto_envelope` | Extra belt-and-braces cap: rejects envelope > `MAX_PROTO_ENVELOPE_BYTES` (16 MiB, `proto.rs:27`) **before** calling `Unknown::decode` at all | SAFE / DEFER (redundant given the 4 MiB global body cap and prost's own remaining-bytes check, but harmless and cheaper to reject early) |

**No allocation anywhere in the traced path is sized from an attacker-claimed
length before that length is checked against the actual remaining buffer.**
A truncated or oversized length prefix on any bytes/string/message/map field
yields `DecodeError` (surfaced as `.ok()?` → `None` → 4xx in all call sites
in `proto.rs`/`*_gen_adapter.rs`), never a panic and never a pre-allocation
proportional to an unchecked multiplier.

**Severity: none found (all SAFE) / one DEFER** (the 16 MiB envelope cap is
already-good defense-in-depth, not a gap — no action needed).

---

## PoC test (committed, ignored)

`crates/apiserver/src/handlers/json_patch.rs` —
`ssa_body_to_json_yaml_to_json_recursion_has_no_depth_guard`
(`#[test] #[ignore]`, runtime <1s when run in isolation). Builds two
BLOCK-style nested-mapping bodies (`"a:\n a:\n  a: 1\n"` pattern) at
geometrically increasing depth, run on a deliberately small
(256 KiB — well below tokio's real ~2 MiB default worker-thread stack)
thread stack:

- depth 500 (~2 KB body): `ssa_body_to_json` returns `Ok` — parses cleanly.
- depth 5,000 (~20 KB body, 10x deeper): **process aborts.**

Actual output from running it in isolation
(`cargo test -p u7s-apiserver --lib -- --ignored --exact --test-threads=1
handlers::json_patch::tests::ssa_body_to_json_yaml_to_json_recursion_has_no_depth_guard`):

```
thread '<unknown>' has overflowed its stack
fatal runtime error: stack overflow, aborting
... (signal: 6, SIGABRT: process abort signal)
```

The point-1 assertion passed silently before the point-2 abort, confirming
the crash is caused by recursion depth (not malformed input, and not
yaml-rust2's separate 255-level FLOW-style cap, which this PoC deliberately
avoids by using BLOCK-style nesting). `#[ignore]`d because a real stack
overflow aborts the whole test process (no catchable panic) — it must never
run as part of the default suite; confirmed `cargo test -p u7s-apiserver
--lib --quiet handlers::json_patch::` reports `26 passed; 0 failed; 1
ignored` and `cargo clippy -p u7s-apiserver --tests -D warnings` is clean.

---

## Follow-on beads

- Fix bead for `yaml_to_json`'s unbounded recursion (HIGH): **mayor-71owd**
  (P1). Fix sketch: thread an explicit `depth:
  usize` parameter through `yaml_to_json`, incrementing on each `Array`/`Hash`
  recursion, and return `None` (→ 400 Bad Request via the existing
  `ok_or_else` in `ssa_body_to_json`) once a cap is exceeded. Pick the cap
  conservatively against the smallest realistic worker-thread stack (tokio's
  default ~2 MiB, `main.rs` sets no `.thread_stack_size` override) with
  margin for the rest of the call stack above `ssa_body_to_json`; matching
  serde_json's 128 for consistency is a reasonable starting point, but the
  fix implementer should re-run this PoC's methodology (geometrically
  increasing depth against a small-but-realistic stack) to pick a safe
  margin rather than guessing. Do not implement inline here per Shape-3
  scope.

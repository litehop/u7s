# apiserver red-team security audit — Phase 0 threat model + attack-surface map

Bead: mayor-s851y
Date: 2026-08-29
Shape: 3 (audit) — read-only, no code changes, no cluster ops

## Verdict

Two P0-class findings, both default/always-on rather than crafted-input edge
cases: (1) `try_verify_sa_jwt`'s signature-cache lets anyone holding one
valid ServiceAccount JWT forge tokens for any other ServiceAccount whose UID
they can learn, with zero cryptographic check on the forged claims
(`auth.rs:510-542`, `sa_sig_cache.rs:211-224`); (2) every u7s cluster binds
`system:node` to the whole `system:nodes` group cluster-wide with no Node
authorizer, so any one compromised kubelet reads every Secret/ConfigMap in
every namespace and can mint tokens for any ServiceAccount (`lib.rs:1349-
1404`) — upstream deprecated exactly this binding in 1.7 and ships it
subject-less. Overall shape: mixed. The parts that were clearly built with
an upstream-parity mindset (impersonation checks, constant-time token
lookup, per-client watch limits, parametrized-looking storage queries) are
solid; the two P0s both come from places where a locally-reasonable-sounding
optimization or a copy-pasted upstream rule list wasn't checked against the
actual security invariant it was replacing.

## Threat model

| Actor | Position | Invariant that must hold |
|---|---|---|
| Unauthenticated | TCP reach to apiserver port | Falls back to `system:anonymous`/`system:unauthenticated` only; no path to a stronger identity without a credential |
| Low-priv authenticated (token/cert) | Any valid credential | RBAC grants are exactly as scoped as their rule text; no cache/verb-mapping shortcut widens them |
| High-priv user | Scope-escape attempt | Impersonation, `escalate`/`bind`-equivalent checks hold |
| Malicious/compromised node (valid kubelet cert) | `system:node:<name>` identity | Access limited to objects related to *its own* node |
| In-cluster pod (SA token) | Namespace-scoped SA | Token only proves identity of the SA that was actually bound to it |

## Attack-surface map

- **Router/dispatch** (`lib.rs`): axum + tower layers, `AuthLayer` outermost-but-one under `DefaultBodyLimit`/`InflightLayer`; `is_exempt` allowlist is a short literal-path list, not a prefix match — correctly conservative.
- **AuthN** (`auth.rs`, 5042 lines): cert (rustls-verified chain, CN/O extraction), static token map (constant-time lookup), SA JWT (RS256 fixed, no alg-confusion). **P0 here** — mayor-4ggk0.
- **AuthZ/RBAC** (`rbac.rs`, 2064 lines; role seeding in `lib.rs`): RBAC-only, no Node authorization mode. **P0 here** — mayor-tkv6j.
- **Admission** (`admission.rs`, 12923 lines): CEL VAP/MAP + webhooks, correct upstream ordering and bootstrap-deadlock exemption; no CEL cost budget found; dry-run/`sideEffects` interaction unconfirmed.
- **Storage** (`crates/store/src/sqlite.rs`, separate crate): no string-formatted SQL found in a single grep pass; `BEGIN IMMEDIATE` used for writes. Not exhaustively reviewed.
- **Serialization** (`proto.rs`, 10845 lines; `content_type.rs`): 4 MiB global body cap; no explicit decode-recursion-depth limit found independent of that cap.
- **Watch/list** (`handlers/watch.rs`, 5281 lines): per-username semaphore, `MAX_WATCHES_PER_CLIENT = 64`, idle-sweep eviction — sound design, not exhaustively reviewed for backpressure/resourceVersion abuse.
- **Subresources** (`handlers/proxy.rs`, 10087 lines — largest handler, least-reviewed given Phase 0 time budget): exec/attach/portforward/logs/proxy. `resolve_pod_proxy_target` dials `status.podIP` verbatim — combined with the RBAC P0, a single compromised node can SSRF proxy traffic for *any* pod, not just its own.
- **CRD lifecycle** (`handlers/crd.rs`, 3691 lines): schema validation present; CEL cost-budget gap shared with admission.
- **Audit logging**: no structured audit subsystem exists at all — only ad-hoc `tracing::debug!`/`warn!`. Both P0s above would be undetectable in production today.
- **Konnectivity**: boundary is `pod_proxy_via_connect_tunnel`'s CONNECT construction; tunnel/agent internals out of scope per the bead.

## HIGH-severity findings from Phase 0

1. **SA JWT signature-cache bypass** — `auth.rs:510-542`, `sa_sig_cache.rs:211-224`. `signature_hash` hashes only the JWT's signature segment, not header+payload. A cache hit skips real RSA verification and calls `jsonwebtoken::dangerous::insecure_decode` (confirmed via `jsonwebtoken` 11.0.0 source: "DANGER: This performs zero validation") on the *current* token's claims. PoC: replay any valid SA token once to warm the cache, then send `header'.payload'.<same-signature-bytes>` with an arbitrary `sub`/`kubernetes.io.serviceaccount.{name,uid}` — accepted once the forged UID matches a real SA. Follow-on: **mayor-4ggk0**.
2. **`system:node` bound cluster-wide with no Node authorizer** — `lib.rs:1349-1404`. Verified against upstream `bootstrappolicy/policy.go` (cached `temp/research/bootstrappolicy_policy.go`): upstream leaves this binding subject-less since 1.7 specifically because RBAC alone can't scope it per-node. u7s binds it to `system:nodes` unconditionally, granting cluster-wide `secrets`/`configmaps` read and `serviceaccounts/token create` for any SA. Follow-on: **mayor-tkv6j**.

## Per-surface follow-on beads filed

- mayor-4ggk0 — P0 fix: SA JWT signature-cache bypass
- mayor-tkv6j — P0 fix: system:node cluster-wide RBAC / missing Node authorizer
- mayor-livvs — AuthN deep-dive (auth.rs remainder)
- mayor-ergg5 — AuthZ/RBAC deep-dive (rbac.rs remainder)
- mayor-qlgws — Admission chain + CRD/CEL sandbox deep-dive
- mayor-usjqk — Subresource handlers deep-dive (exec/attach/portforward/logs/proxy)
- mayor-zdaw8 — Storage layer deep-dive (crates/store)
- mayor-0qjgc — Audit logging gap (no structured audit subsystem)
- mayor-vtq5n — Watch/list streaming deep-dive
- mayor-lzd66 — Serialization decoder recursion-depth deep-dive
- mayor-c6njm — Konnectivity boundary note

# Phase 1 deep-dive: AuthN surface (auth.rs) beyond the JWT signature-cache bypass

Bead: mayor-livvs
Scope: `crates/apiserver/src/auth.rs` (5164 lines) + direct callees in the request
pipeline (`tls.rs`, `sa_sig_cache.rs`, `node_authz.rs`, `rbac.rs`).
Verdict: surface is mostly sound, but one HIGH auth-bypass gap and four
correctness drifts from upstream 1.36 semantics were found. The
signature-cache bypass already fixed under mayor-4ggk0 is confirmed intact
and is NOT re-litigated here.

## Method

Read `auth.rs` end-to-end (module doc through `AuthService::call`, then the
test module for documented intent), traced `tls.rs`'s client-cert verifier
config and `lib.rs`'s `serve_tls` (where `PeerCertificate` is populated) and
`node_authz.rs`'s `node_identity` gate. Cross-checked four behaviors against
upstream `kubernetes/kubernetes` at `release-1.36` (fetched into
`temp/research/impersonation.go`, plus inline review of
`tokenfile.go` and `bearertoken.go` via `gh api`):
`staging/src/k8s.io/apiserver/pkg/endpoints/filters/impersonation/impersonation.go`,
`staging/src/k8s.io/apiserver/pkg/authentication/token/tokenfile/tokenfile.go`,
`staging/src/k8s.io/apiserver/pkg/authentication/request/bearertoken/bearertoken.go`.

## Finding 1 — HIGH: blank token-auth-file line grants unauthenticated access via `Authorization: Bearer <empty>`

**File:** `crates/apiserver/src/auth.rs:132-177` (`load_token_file`), consumed by
`ct_token_lookup` at `auth.rs:192-213` and the bearer-token branch at
`auth.rs:264-279`.

`load_token_file` parses each non-comment line into `token,username,uid[,groups]`
and does `map.insert(token, UserInfo{..})` with **no check that `token` is
non-empty**:

```rust
let token = parts[0].to_owned();
...
map.insert(token, UserInfo { username, uid, groups, extra: HashMap::new() });
```

Upstream's equivalent (`tokenfile.go`'s `NewCSV`) explicitly guards this exact
case:

```go
if record[0] == "" {
    klog.Warningf("empty token has been found in token file '%s', record number '%d'", path, recordNum)
    continue
}
```

If an operator's `--token-auth-file` has any malformed/blank-first-field line
(a stray leading comma from a template, spreadsheet paste, or truncated
secret — an easy, plausible typo class, not a contrived edge case), u7s
silently inserts `"" -> UserInfo{that line's identity}` into `token_map`.
`ct_token_lookup`'s constant-time scan (`auth.rs:192-213`) then matches an
**empty candidate token** — i.e. any request sending header
`Authorization: Bearer ` (the literal word `Bearer`, one space, nothing
after) — against that empty-string key via `subtle::ConstantTimeEq` on two
zero-length slices, which is trivially "equal". No secret is required: any
unauthenticated network client that merely knows (or guesses — this is a
common misconfiguration shape) that such a blank line exists is authenticated
as that line's identity, up to and including `system:masters`. The same gap
is reachable through `authenticate_token_with_audiences` (`auth.rs:381-406`,
the TokenReview API's manual-token-check path), since both call sites share
`ct_token_lookup`.

**Fix sketch:** in `load_token_file`, after computing `token = parts[0].to_owned()`,
add `if token.is_empty() { tracing::warn!(...); continue; }` — mirrors
upstream's `record[0] == ""` guard exactly, one `if` block, no new
dependency.

## Finding 2 — MED: impersonated ServiceAccount identity is missing its default groups

**File:** `crates/apiserver/src/auth.rs:1306-1320`.

```rust
let groups = if impersonate_groups.is_empty() {
    vec!["system:authenticated".to_owned()]
} else {
    impersonate_groups
};
```

Two divergences from upstream's `WithImpersonation` filter
(`impersonation/impersonation.go:84-144`, `release-1.36`):

1. When `Impersonate-User` is `system:serviceaccount:<ns>:<name>` (SA-shaped)
   and no `Impersonate-Group` header was sent, upstream calls
   `serviceaccount.MakeGroupNames(namespace)` to auto-add
   `system:serviceaccounts` and `system:serviceaccounts:<ns>` *before* the
   `system:authenticated` append (`impersonation.go:88-91`). u7s's code path
   never branches on SA-shape here (that branching only happens earlier, for
   the RBAC-resource check at `auth.rs:1182-1207`) — it always falls back to
   `["system:authenticated"]` only, so an impersonated SA identity gets a
   strictly smaller group set than the identity would actually have if it
   authenticated with a real SA JWT (compare `try_verify_sa_jwt`'s own group
   construction at `auth.rs:628-636`, which does add both groups).
2. When `Impersonate-Group` headers *are* present, upstream still
   unconditionally appends `system:authenticated` unless the caller's
   explicit list already contains `system:authenticated` or
   `system:unauthenticated` (`impersonation.go:134-144`). u7s instead uses
   `impersonate_groups` **verbatim** with no such backstop — the code
   comment ("if the caller explicitly supplies groups we use those
   verbatim ... just like the real apiserver does") is incorrect; the real
   apiserver does not do this unconditionally.

**Impact:** both directions are fail-*closed* (missing groups → less access
than upstream), so this is not a privilege-escalation path. But it breaks
impersonation's most common real use — `kubectl auth can-i --as=
system:serviceaccount:ns:name` or `--as=alice --as-group=custom-group` used
by operators to test RBAC before granting it to a real workload/user. A false
"no" from this under-privileged impersonation is exactly the kind of result
that tempts an operator to over-grant a real RoleBinding to "make it work,"
which is a genuine (if indirect) security risk. No test in `auth.rs` currently
asserts on the impersonated identity's *groups* for the SA-shaped or
explicit-Impersonate-Group cases (`impersonation_of_sa_shaped_identity_checks_serviceaccounts_resource`,
`auth.rs:3656-3714`, only asserts the username).

**Fix sketch:** replace the two-line `groups` computation with upstream's
algorithm: if SA-shaped and `impersonate_groups.is_empty()`, seed
`groups` with `["system:serviceaccounts", format!("system:serviceaccounts:{namespace}")]`;
then, regardless of branch, append `"system:authenticated"` unless
`groups` already contains it or `"system:unauthenticated"`.

## Finding 3 — MED: `Impersonate-Extra-*` header keys are never percent-decoded

**File:** `crates/apiserver/src/auth.rs:1271-1283` (collection) and
`1284-1304` (per-value RBAC check), key reused verbatim at `1319`
(`extra: impersonate_extra`).

```rust
let Some(key) = name.as_str().strip_prefix("impersonate-extra-") else { continue };
...
impersonate_extra.entry(key.to_owned()).or_default().push(v.to_owned());
```

HTTP header *names* cannot legally contain `/` (not in RFC 7230's `tchar`
set — confirmed against the `http` crate's own `HEADER_CHARS` table, which
maps byte `0x2F` to `0`/invalid). `client-go`'s
`transport.headerKeyEscape` (`round_trippers.go:697-710`,
`legalHeaderKeyBytes` table) therefore percent-encodes any illegal byte in an
extra key before setting `Impersonate-Extra-<key>`, and upstream's
`buildImpersonationRequests` reverses this with
`unescapeExtraKey`/`url.PathUnescape` (`impersonation.go:204-210, 241`). This
is not a theoretical path: the canonical extra key u7s's own SA-JWT code
uses, `authentication.kubernetes.io/credential-id`
(`auth.rs:643`), is exactly this shape — a real `--as-group`/`rest.Config.Impersonate.Extra`
caller setting that key would have it sent as
`Impersonate-Extra-authentication.kubernetes.io%2fcredential-id`.

u7s stores the **raw, still-percent-encoded** string as both the RBAC
`userextras` subresource name (`auth.rs:1291`, checked per-value) and the
final `UserInfo.extra` key. Any RBAC rule authored with the human-readable
key, or any downstream consumer (SubjectAccessReview extra, audit log)
expecting the decoded key, will never match — the request is always denied
or the extra entry is unusable. Fails closed (an over-restrictive `403`, not
an over-grant), but breaks a documented, real client-go code path.

**Fix sketch:** apply the same `percent_decode` already defined at
`auth.rs:770` (currently only used for `fieldSelector`) to `key` before
inserting into `impersonate_extra` — one call, no new dependency, reuses an
existing well-tested helper in this same file.

## Finding 4 — LOW: non-`Bearer` or wrong-case `Authorization` header hard-fails 401 even with a valid client cert present

**File:** `crates/apiserver/src/auth.rs:263-291` (the `Some(value)` match arm
of `authenticate`).

```rust
if let Some(token) = value.strip_prefix("Bearer ") {
    ... // static map, then JWT, then AuthnResult::BadToken
} else {
    // Malformed Authorization header → treat as bad token.
    AuthnResult::BadToken
}
```

`strip_prefix("Bearer ")` requires the exact case `Bearer` + exactly one
space. Upstream's `bearertoken.go:44-46` does
`strings.ToLower(parts[0]) != "bearer"` (case-insensitive scheme match, per
RFC 7235's case-insensitive auth-scheme token), and — more importantly — a
non-match there returns `(nil, false, nil)`: "this authenticator declined,"
which in the union authenticator lets a still-verified `PeerCertificate`
(already checked once, via the x509 authenticator running independently)
succeed instead. u7s's `else` branch returns `BadToken` unconditionally,
which `AuthService::call` (`auth.rs:1143-1149`) turns straight into a `401`
— it never even looks at `peer_cert`, which was already available and
rustls-verified. A client presenting both a valid mTLS cert and a malformed
or wrong-case (but present) `Authorization` header is rejected outright
where upstream would fall back to the cert. This is intentionally
distinct from the *already-tested* "valid Bearer token wins over a valid
cert" design (`test_x509_auth_does_not_override_bearer_token`,
`auth.rs:3170-3200`) — that test only covers a *successfully-resolved*
token, not a malformed/wrong-scheme header value.

**Fix sketch:** in the `else` branch, fall back to the same
`peer_cert`-then-anonymous logic used in the `None` arm, rather than an
immediate `BadToken` — i.e. treat "present but not a recognized scheme" the
same as "absent" for authentication-source selection. Low priority: no
known u7s client (kubectl, client-go, kubelet) sends a non-`"Bearer "`
scheme today, so this is dormant unless a proxy or unusual client is in the
request path.

## Finding 5 — LOW: `Impersonate-Group`/`-Uid`/`-Extra-*` without `Impersonate-User` is silently dropped instead of `400`

**File:** `crates/apiserver/src/auth.rs:1162` (impersonation block gate) /
`1321-1323` (`else { authenticated_user }`).

The entire impersonation block is gated solely on `Impersonate-User` being
present. If a caller sends `Impersonate-Group`/`Impersonate-Uid`/
`Impersonate-Extra-*` **without** `Impersonate-User`, none of that is
applied and none of it is checked — the request proceeds as the
authenticated user, with the impersonation headers just ignored. Upstream
explicitly rejects this shape with a `400 Bad Request`
(`impersonation.go:269-271`: `"requested %v without impersonating a user"`).
Fails safe here (no privilege change — the headers are simply inert), so
this is a spec-compliance gap rather than a vulnerability, but it silently
masks a malformed client request that upstream would surface as an error.

**Fix sketch:** before the `if let Some(impersonate_user) = ...` gate, check
whether any `Impersonate-Group`/`Impersonate-Uid`/`Impersonate-Extra-*`
header is present while `Impersonate-User` is absent, and return a `400`
Status response (mirroring `unauthorized_response`/`forbidden_response`'s
shape) if so.

## DEFER (documented, no follow-on bead)

- **Duplicate token in `--token-auth-file` resolves last-line-wins** — this
  matches upstream's own `map[token]=...` overwrite semantics exactly
  (`tokenfile.go:75-80`), but upstream logs
  `klog.Warningf("duplicate token has been found...")` and u7s does not.
  Pure observability parity gap, not a security issue — not worth a bead on
  its own.
- **x509 client cert is only tried when no `Authorization` header is present
  at all** (`auth.rs:246-262`) — a deliberate, already-tested design choice
  (`test_x509_auth_does_not_override_bearer_token`) that trades some
  upstream-union flexibility for simpler, fail-closed semantics. Confirmed
  intentional; not re-flagged here except where it interacts with the
  malformed-scheme case above (Finding 4).
- **`extract_client_cert_identity` trusts CN/O verbatim from an
  already-rustls-verified chain** (`auth.rs:302-350`) — confirmed it returns
  `None` (not a privileged default) on a missing/empty CN, and every caller
  (`authenticate`'s `None` arm, `auth.rs:249-254`) treats `None` as "fall
  through to anonymous," never as an implicit privileged identity. No bug
  found in the area the bead flagged.
- **`try_verify_sa_jwt`'s bound-object liveness check TOCTOU window**
  (`auth.rs:439-482`, `579-613`) — the UID-pinned re-read means a
  same-name-different-UID recreation is correctly rejected; the residual
  window between this check and the eventual downstream write is the same
  class of staleness inherent to any online (non-cached) revocation check
  and mirrors upstream's own `Validator.Validate` re-check-per-request
  design. No new drift found.

## Severity summary

HIGH: 1 (Finding 1) · MED: 2 (Findings 2, 3) · LOW: 2 (Findings 4, 5) ·
DEFER: 3 (documented above, no bead)

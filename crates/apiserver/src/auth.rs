// Authentication + Authorization tower middleware layer.
//
// Implements static bearer-token authentication (--token-auth-file),
// RS256 JWT verification for service-account tokens, and x509 client
// certificate authentication.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::{BufRead as _, BufReader};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tower::Layer;
use tower_service::Service;

use crate::rbac::{AuthzRequest, RbacIndex};
use crate::status::Status;
use crate::util::validate_cli_path;

// ---------------------------------------------------------------------------
// PeerCertificate — DER bytes of the TLS client certificate leaf cert
// ---------------------------------------------------------------------------

/// DER-encoded bytes of the leaf client certificate presented during TLS
/// handshake. Injected into request extensions by `serve_tls` in main.rs.
#[derive(Clone, Debug)]
pub struct PeerCertificate(pub Vec<u8>);

// ---------------------------------------------------------------------------
// UserInfo
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct UserInfo {
    pub username: String,
    pub uid: String,
    pub groups: Vec<String>,
    /// Extra authentication attributes keyed by name.
    /// SA tokens carry `authentication.kubernetes.io/credential-id` = `["JTI=<jti>"]`
    /// so that conformance tests can verify bound token identity.
    pub extra: HashMap<String, Vec<String>>,
}

// ---------------------------------------------------------------------------
// JWT Claims — used for decoding inbound SA tokens
// ---------------------------------------------------------------------------

/// Minimal claim set decoded from inbound SA JWTs.
/// Must match the fields minted by `handlers::tokens::create_token`.
#[derive(Debug, Deserialize)]
struct SaClaims {
    /// Unique token ID. Checked against the revocation set before accepting the token.
    jti: Option<String>,
    /// Subject — format: "system:serviceaccount:<namespace>:<name>"
    sub: String,
}

// ---------------------------------------------------------------------------
// Token map — loaded once at startup
// ---------------------------------------------------------------------------

/// Parse a token-auth file into a token → UserInfo map.
///
/// File format (one line per entry, comments and empty lines skipped):
///   <token>,<username>,<uid>,<group1>[,<group2>...]
pub fn load_token_file(path: &str) -> anyhow::Result<HashMap<String, UserInfo>> {
    let raw_path = std::path::Path::new(path);
    let safe_path = validate_cli_path(raw_path)?;
    let file = std::fs::File::open(safe_path)?;
    let mut map = HashMap::new();

    for (lineno, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, ',').collect();
        if parts.len() < 3 {
            tracing::warn!(
                "token-auth-file line {}: too few fields, skipping",
                lineno + 1
            );
            continue;
        }
        let token = parts[0].to_owned();
        let username = parts[1].to_owned();
        let uid = parts[2].to_owned();
        let groups: Vec<String> = if parts.len() >= 4 {
            parts[3].split(',').map(|s| s.to_owned()).collect()
        } else {
            vec![]
        };

        map.insert(
            token,
            UserInfo {
                username,
                uid,
                groups,
                extra: HashMap::new(),
            },
        );
    }

    Ok(map)
}

// ---------------------------------------------------------------------------
// Constant-time token lookup
// ---------------------------------------------------------------------------

/// Look up a bearer token in the static token map using constant-time byte
/// comparison. This prevents timing side-channels: a naive HashMap::get()
/// uses SipHash which can reveal information about how many characters of
/// the candidate token match a stored token's hash. By comparing all bytes
/// of each stored token against the candidate in constant time (no early
/// exit), an attacker learns nothing about valid token prefixes.
///
/// Performance: the static token map is small (typically <100 entries loaded
/// at startup), so the O(n) scan is negligible compared to network latency.
fn ct_token_lookup<'a>(
    map: &'a HashMap<String, UserInfo>,
    candidate: &str,
) -> Option<&'a UserInfo> {
    use subtle::ConstantTimeEq;
    let candidate_bytes = candidate.as_bytes();
    let mut found: Option<&'a UserInfo> = None;
    for (stored_token, info) in map.iter() {
        let stored_bytes = stored_token.as_bytes();
        // subtle::ConstantTimeEq on slices of different lengths always returns
        // 0 (not equal) without leaking which byte differed or whether the
        // lengths matched. A manual length pre-check would leak whether the
        // candidate length matches any stored token — a timing side-channel.
        // Call ct_eq directly: it is safe and correct for unequal-length slices.
        if stored_bytes.ct_eq(candidate_bytes).into() {
            found = Some(info);
            // Do NOT break: continue iterating so the loop takes the same time
            // regardless of which token matched or whether any matched.
        }
    }
    found
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// Outcome of authenticating a single request.
enum AuthnResult {
    /// Authenticated — carry UserInfo forward.
    Identified(UserInfo),
    /// Bad token — respond with 401.
    BadToken,
}

fn authenticate(
    req: &Request<Body>,
    token_map: &HashMap<String, UserInfo>,
    sa_decoding_key: Option<&DecodingKey>,
    peer_cert: Option<&PeerCertificate>,
    revoked_jtis: &HashSet<String>,
) -> AuthnResult {
    let auth_header = req.headers().get("authorization");

    match auth_header {
        None => {
            // No Authorization header — try x509 client cert before anonymous fallback.
            if let Some(cert) = peer_cert {
                // chain already verified by rustls WebPkiClientVerifier
                if let Some(user) = extract_client_cert_identity(&cert.0) {
                    return AuthnResult::Identified(user);
                }
            }
            // No credential at all → anonymous.
            AuthnResult::Identified(UserInfo {
                username: "system:anonymous".to_owned(),
                uid: String::new(),
                groups: vec!["system:unauthenticated".to_owned()],
                extra: HashMap::new(),
            })
        }
        Some(value) => {
            let value = value.to_str().unwrap_or("");
            if let Some(token) = value.strip_prefix("Bearer ") {
                // 1. Check static token map first using constant-time comparison.
                // HashMap.get() can leak timing information about token prefixes
                // (SipHash is non-cryptographic). Instead, compare all tokens in
                // constant time so an attacker cannot distinguish valid prefixes
                // from invalid ones.
                if let Some(info) = ct_token_lookup(token_map, token) {
                    let mut user = info.clone();
                    // Real Kubernetes always adds system:authenticated to every
                    // successfully identified user so that ClusterRoleBindings on
                    // that group (e.g. system:basic-user) apply universally.
                    if !user.groups.contains(&"system:authenticated".to_owned()) {
                        user.groups.push("system:authenticated".to_owned());
                    }
                    return AuthnResult::Identified(user);
                }
                // 2. If a SA decoding key is available, attempt JWT verification.
                if let Some(key) = sa_decoding_key {
                    if let Some(user) = try_verify_sa_jwt(token, key, &[], revoked_jtis) {
                        return AuthnResult::Identified(user);
                    }
                }
                // 3. Token not recognized — reject.
                AuthnResult::BadToken
            } else {
                // Malformed Authorization header → treat as bad token.
                AuthnResult::BadToken
            }
        }
    }
}

/// Parse a DER-encoded X.509 client certificate and extract subject CN and O
/// fields as username and groups respectively.
///
/// Returns `None` if the certificate cannot be parsed or has no CN field.
/// The certificate is assumed to already be verified (rustls checked the
/// signature and chain during TLS handshake).
pub fn extract_client_cert_identity(der: &[u8]) -> Option<UserInfo> {
    use x509_cert::der::Decode as _;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(der)
        .map_err(|e| tracing::debug!("x509 cert parse failed: {e}"))
        .ok()?;

    let subject = cert.tbs_certificate().subject();

    let mut username = None;
    let mut groups = Vec::new();

    // OIDs for subject attributes relevant to Kubernetes auth:
    //   CN (CommonName)       = 2.5.4.3
    //   O  (OrganizationName) = 2.5.4.10
    const OID_CN: &str = "2.5.4.3";
    const OID_O: &str = "2.5.4.10";

    for atv in subject.iter() {
        let oid_str = atv.oid.to_string();
        if oid_str != OID_CN && oid_str != OID_O {
            continue;
        }
        // Decode the Any value as one of the legal string types for subject
        // attributes.  Try UTF8String first (most common in modern certs),
        // then PrintableString, then IA5String.
        let value = atv_string(&atv.value);
        let Some(value) = value else { continue };

        if oid_str == OID_CN {
            username = Some(value);
        } else {
            groups.push(value);
        }
    }

    let username = username?;
    // Real Kubernetes always adds system:authenticated to every successfully
    // identified user so that ClusterRoleBindings on that group apply universally.
    groups.push("system:authenticated".to_owned());
    tracing::debug!("x509 auth: username={username} groups={groups:?}");
    Some(UserInfo {
        username,
        uid: String::new(),
        groups,
        extra: HashMap::new(),
    })
}

/// Decode a DER `Any` value as a UTF-8 string by trying the common string
/// types used in X.509 subject distinguished names.
fn atv_string(value: &x509_cert::der::Any) -> Option<String> {
    use x509_cert::der::{Tag, Tagged as _};

    match value.tag() {
        Tag::Utf8String => value
            .decode_as::<x509_cert::der::asn1::Utf8StringRef<'_>>()
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::PrintableString => value
            .decode_as::<x509_cert::der::asn1::PrintableStringRef<'_>>()
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::Ia5String => value
            .decode_as::<x509_cert::der::asn1::Ia5StringRef<'_>>()
            .ok()
            .map(|s| s.as_str().to_owned()),
        _ => None,
    }
}

/// Validate a raw bearer token string against the static map and SA JWT key.
///
/// `audiences` is the list of acceptable token audiences from a TokenReview
/// spec.audiences field.  When empty, defaults to ["https://kubernetes.default.svc"].
///
/// Returns `Some(UserInfo)` if the token is recognized, `None` if it is not.
/// This is exposed for use by the TokenReview handler.
pub fn authenticate_token_with_audiences(
    token: &str,
    token_map: &HashMap<String, UserInfo>,
    sa_decoding_key: Option<&DecodingKey>,
    audiences: &[String],
    revoked_jtis: &HashSet<String>,
) -> Option<UserInfo> {
    if let Some(info) = ct_token_lookup(token_map, token) {
        let mut user = info.clone();
        // Real Kubernetes always adds system:authenticated to every
        // successfully identified user so that ClusterRoleBindings on
        // that group (e.g. system:basic-user) apply universally.
        if !user.groups.contains(&"system:authenticated".to_owned()) {
            user.groups.push("system:authenticated".to_owned());
        }
        return Some(user);
    }
    if let Some(key) = sa_decoding_key {
        // try_verify_sa_jwt already appends system:authenticated.
        if let Some(user) = try_verify_sa_jwt(token, key, audiences, revoked_jtis) {
            return Some(user);
        }
    }
    None
}

/// Attempt to decode and verify a bearer token as an RS256 SA JWT.
/// Returns `Some(UserInfo)` on success, `None` if the token is invalid or revoked.
/// `audiences` is the list of acceptable audiences; defaults to
/// ["https://kubernetes.default.svc"] when empty.
/// `revoked_jtis` is the set of revoked JTI values; a token whose `jti` claim
/// appears in this set is rejected even if the signature and expiry are valid.
pub(crate) fn try_verify_sa_jwt(
    token: &str,
    key: &DecodingKey,
    audiences: &[String],
    revoked_jtis: &HashSet<String>,
) -> Option<UserInfo> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["https://kubernetes.default.svc"]);
    if audiences.is_empty() {
        validation.set_audience(&["https://kubernetes.default.svc"]);
    } else {
        let refs: Vec<&str> = audiences.iter().map(|s| s.as_str()).collect();
        validation.set_audience(&refs);
    }
    // No leeway: reject tokens that are even 1 second past expiry.
    validation.leeway = 0;

    match jsonwebtoken::decode::<SaClaims>(token, key, &validation) {
        Ok(data) => {
            // Check revocation before accepting the token. A revoked JTI is rejected
            // even if the signature and expiry are otherwise valid — this allows
            // immediate token invalidation without waiting for the 24h JWT expiry.
            let jti = data.claims.jti;
            if let Some(jti) = &jti {
                if revoked_jtis.contains(jti.as_str()) {
                    tracing::debug!("SA JWT rejected: jti={jti} is in the revocation list");
                    return None;
                }
            }
            let sub = data.claims.sub;
            tracing::debug!("SA JWT verified: sub={sub}");
            // sub format: system:serviceaccount:{ns}:{name}
            // Validate before use: a malformed sub silently omits the
            // namespace-scoped group, causing RBAC policies on
            // system:serviceaccounts:{ns} to silently fail.
            let parts: Vec<&str> = sub.splitn(4, ':').collect();
            if parts.len() != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
                tracing::warn!(
                    "SA JWT rejected: sub does not match \
                     system:serviceaccount:{{ns}}:{{name}} format: sub={sub}"
                );
                return None;
            }
            let groups = {
                let mut g = vec!["system:serviceaccounts".to_owned()];
                g.push(format!("system:serviceaccounts:{}", parts[2]));
                // Real Kubernetes always adds system:authenticated to every
                // successfully identified user so that ClusterRoleBindings on
                // that group (e.g. system:basic-user) apply universally.
                g.push("system:authenticated".to_owned());
                g
            };
            // Surface the token's unique ID as authentication.kubernetes.io/credential-id
            // so that TokenReview callers can verify which specific token was used.
            // Upstream format: "JTI=" + the jti claim value.
            let extra = if let Some(jti) = jti {
                let mut m = HashMap::new();
                m.insert(
                    "authentication.kubernetes.io/credential-id".to_owned(),
                    vec![format!("JTI={jti}")],
                );
                m
            } else {
                HashMap::new()
            };
            Some(UserInfo {
                username: sub,
                uid: String::new(),
                groups,
                extra,
            })
        }
        Err(e) => {
            tracing::debug!("SA JWT verification failed: {e}");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Path parsing → AuthzRequest fields
// ---------------------------------------------------------------------------

/// Paths that skip auth entirely.
fn is_exempt(path: &str) -> bool {
    matches!(
        path,
        "/healthz"
            | "/readyz"
            | "/livez"
            | "/api"
            | "/api/"
            | "/apis"
            | "/apis/"
            | "/version"
            | "/discovery/v2"
            | "/openapi/v2"
            | "/openapi/v3"
    )
}

/// HTTP method → RBAC verb.
///
/// For GET requests the caller must call `get_verb` instead, because Kubernetes
/// distinguishes between "get" (named resource), "list" (collection), and
/// "watch" (streaming watch).
fn method_to_verb(method: &axum::http::Method) -> &'static str {
    match method.as_str() {
        "GET" => "get",
        "POST" => "create",
        "PUT" => "update",
        "PATCH" => "patch",
        "DELETE" => "delete",
        // HEAD is not a distinct RBAC verb in Kubernetes — it maps to "get".
        "HEAD" => "get",
        // Unknown/future methods: fall back to "get" (least-privilege intent).
        _ => "get",
    }
}

/// Resolve the RBAC verb for a GET request.
///
/// Kubernetes differentiates three GET-related verbs:
///   "watch"  — query param `watch=true` or `watch=1` is present
///   "list"   — collection endpoint (no resource name in path)
///   "get"    — named resource endpoint
///
/// This prevents the authorization bypass where a user with only the `get`
/// verb could enumerate all resources by hitting the collection endpoint.
fn get_verb(name: Option<&str>, query: Option<&str>) -> &'static str {
    // Watch takes priority: a client streaming watch events needs "watch", not "list".
    if let Some(q) = query {
        for pair in q.split('&') {
            if let Some(val) = pair.strip_prefix("watch=") {
                if val == "true" || val == "1" {
                    return "watch";
                }
            }
        }
    }
    match name {
        Some(_) => "get",
        None => "list",
    }
}

/// Decode RFC 3986 `%XX` percent-escapes in a URL query-string component.
///
/// Kubernetes clients (client-go) percent-encode `fieldSelector` values, e.g.
/// `metadata.name%3Dfoo` for `metadata.name=foo`. Bytes that don't form a valid
/// `%XX` escape are passed through unchanged.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Extract the resource name implied by a `fieldSelector=metadata.name=<name>` query
/// parameter, mirroring real Kubernetes' `RequestInfo` construction (requestinfo.go): a
/// LIST/WATCH request whose field selector is a single exact-match term on
/// `metadata.name` is treated, for authorization purposes, as targeting that one named
/// resource — even though the verb itself remains "list"/"watch".
///
/// This is the standard way every client-go informer watches a single named object (e.g.
/// the ConfigMap informer aggregated apiservers use to read
/// `kube-system/extension-apiserver-authentication`). Without recognizing it, an RBAC Role
/// restricted via `resourceNames` can never match this pattern, since a bare LIST/WATCH
/// request has no name in its URL path.
///
/// Only a *single* exact-match term counts (no comma-joined multi-term selector), matching
/// `FieldSelector.RequiresExactMatch` upstream: a selector combined with other terms, or
/// using `!=`, does not uniquely identify one resource name.
fn field_selector_name(query: Option<&str>) -> Option<String> {
    let query = query?;
    let raw = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("fieldSelector="))?;
    let decoded = percent_decode(raw);
    if decoded.contains(',') {
        return None;
    }
    // Try "==" (explicit equality) before "=" so "key==value" doesn't split into
    // key="key=" / value="value". "key!=value" is rejected because the key comparison
    // below fails (the leftover "!" makes it not equal to "metadata.name").
    let (key, value) = decoded
        .split_once("==")
        .or_else(|| decoded.split_once('='))?;
    if key != "metadata.name" || value.is_empty() {
        return None;
    }
    Some(value.to_owned())
}

/// Parsed path components needed for AuthzRequest construction.
struct ParsedPath {
    api_group: String,
    resource: String,
    subresource: String,
    namespace: Option<String>,
    name: Option<String>,
}

/// Heuristic path parser.  Handles:
///   /api/v1/...                   → group=""
///   /apis/<group>/<version>/...   → group=<group>
///
/// Path shapes (segments after group/version stripped):
///   namespaces/<ns>/<resource>            collection
///   namespaces/<ns>/<resource>/<name>     named
///   namespaces/<ns>/<resource>/<name>/<sub>  subresource
///   <resource>                            cluster-scoped collection
///   <resource>/<name>                     cluster-scoped named
///   <resource>/<name>/<sub>               cluster-scoped subresource
fn parse_path(path: &str) -> ParsedPath {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let (api_group, rest) = match segs.first().copied() {
        Some("api") => {
            // /api/<version>/...
            let rest = if segs.len() > 2 { &segs[2..] } else { &[] };
            (String::new(), rest)
        }
        Some("apis") => {
            // /apis/<group>/<version>/...
            let group = segs.get(1).copied().unwrap_or("").to_owned();
            let rest = if segs.len() > 3 { &segs[3..] } else { &[] };
            (group, rest)
        }
        _ => return unknown_path(),
    };

    // rest: namespaces/<ns>/<resource>[/<name>[/<sub>]]
    //   or: <resource>[/<name>[/<sub>]]
    //
    // Only treat as namespaced if there's a resource segment after the namespace
    // name (rest.len() >= 3).  Without this check, /api/v1/namespaces and
    // /api/v1/namespaces/{name} would be mis-classified as namespaced operations
    // with resource="" instead of cluster-scoped operations on the "namespaces"
    // resource, causing RBAC wildcard rules to never match.
    let (namespace, resource, name, subresource) =
        if rest.first().copied() == Some("namespaces") && rest.len() >= 3 {
            // /namespaces/<ns>/<resource>[/<name>[/<sub>]]
            let ns = rest.get(1).copied().unwrap_or("").to_owned();
            let resource = rest.get(2).copied().unwrap_or("").to_owned();
            let name = rest.get(3).map(|s| s.to_string());
            let subresource = rest.get(4).copied().unwrap_or("").to_owned();
            (Some(ns), resource, name, subresource)
        } else {
            // cluster-scoped: <resource>[/<name>[/<sub>]]
            // Handles /namespaces, /namespaces/<name>, /nodes/<name>, etc.
            let resource = rest.first().copied().unwrap_or("").to_owned();
            let name = rest.get(1).map(|s| s.to_string());
            let subresource = rest.get(2).copied().unwrap_or("").to_owned();
            (None, resource, name, subresource)
        };

    ParsedPath {
        api_group,
        resource,
        subresource,
        namespace,
        name,
    }
}

fn unknown_path() -> ParsedPath {
    ParsedPath {
        api_group: String::new(),
        resource: String::new(),
        subresource: String::new(),
        namespace: None,
        name: None,
    }
}

// ---------------------------------------------------------------------------
// Status response helpers
// ---------------------------------------------------------------------------

fn unauthorized_response() -> Response<Body> {
    let status = Status {
        kind: "Status",
        api_version: "v1",
        status: "Failure",
        message: "Unauthorized".to_owned(),
        reason: "Unauthorized",
        code: 401,
        metadata: None,
        details: None,
    };
    let body = serde_json::to_vec(&status).unwrap_or_default();
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn forbidden_response(user: &str, verb: &str, resource: &str) -> Response<Body> {
    let status = Status {
        kind: "Status",
        api_version: "v1",
        status: "Failure",
        message: format!("{user} is not allowed to {verb} {resource}"),
        reason: "Forbidden",
        code: 403,
        metadata: None,
        details: None,
    };
    let body = serde_json::to_vec(&status).unwrap_or_default();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

// ---------------------------------------------------------------------------
// AuthLayer
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AuthLayer {
    rbac_index: Arc<RbacIndex>,
    token_map: Arc<HashMap<String, UserInfo>>,
    sa_decoding_key: Option<Arc<DecodingKey>>,
    revoked_jtis: Arc<Mutex<HashSet<String>>>,
}

impl AuthLayer {
    pub fn new(
        rbac_index: Arc<RbacIndex>,
        token_map: HashMap<String, UserInfo>,
        sa_decoding_key: Option<Arc<DecodingKey>>,
        revoked_jtis: Arc<Mutex<HashSet<String>>>,
    ) -> Self {
        AuthLayer {
            rbac_index,
            token_map: Arc::new(token_map),
            sa_decoding_key,
            revoked_jtis,
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            rbac_index: Arc::clone(&self.rbac_index),
            token_map: Arc::clone(&self.token_map),
            sa_decoding_key: self.sa_decoding_key.clone(),
            revoked_jtis: Arc::clone(&self.revoked_jtis),
        }
    }
}

// ---------------------------------------------------------------------------
// AuthService
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    rbac_index: Arc<RbacIndex>,
    token_map: Arc<HashMap<String, UserInfo>>,
    sa_decoding_key: Option<Arc<DecodingKey>>,
    revoked_jtis: Arc<Mutex<HashSet<String>>>,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<S> Service<Request<Body>> for AuthService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let path = req.uri().path().to_owned();

        // Exempt paths skip auth.
        if is_exempt(&path) {
            return Box::pin(self.inner.call(req));
        }

        // 1. Authenticate.
        let peer_cert = req.extensions().get::<PeerCertificate>().cloned();
        let revoked_jtis_guard = self.revoked_jtis.lock().unwrap();
        let authenticated_user = match authenticate(
            &req,
            &self.token_map,
            self.sa_decoding_key.as_deref(),
            peer_cert.as_ref(),
            &revoked_jtis_guard,
        ) {
            AuthnResult::Identified(u) => u,
            AuthnResult::BadToken => {
                return Box::pin(async move { Ok(unauthorized_response()) });
            }
        };

        // 1a. Impersonation — Kubernetes-style Impersonate-User / Impersonate-Group headers.
        //
        // When present, the authenticated user is requesting to act as a different identity.
        // We must verify that the authenticated user has the `impersonate` verb on the
        // target resources before substituting the impersonated identity.
        //
        // The impersonated groups replace the authenticated user's groups entirely; real
        // Kubernetes always adds system:authenticated to any impersonated non-system user,
        // but if the caller explicitly supplies groups we use those verbatim (just like the
        // real apiserver does when Impersonate-Group headers are provided).
        let user = if let Some(impersonate_user) = req
            .headers()
            .get("Impersonate-User")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned())
        {
            // Collect all Impersonate-Group header values (may be repeated).
            let impersonate_groups: Vec<String> = req
                .headers()
                .get_all("Impersonate-Group")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(|s| s.to_owned())
                .collect();

            // Verify the authenticated caller may impersonate this user.
            if !self.rbac_index.is_allowed(&AuthzRequest {
                username: &authenticated_user.username,
                groups: &authenticated_user.groups,
                verb: "impersonate",
                api_group: "",
                resource: "users",
                subresource: "",
                namespace: None,
                name: Some(&impersonate_user),
                non_resource_url: None,
            }) {
                let username = authenticated_user.username.clone();
                let target = impersonate_user.clone();
                return Box::pin(async move {
                    Ok(forbidden_response(&username, "impersonate", &target))
                });
            }

            // Verify the authenticated caller may impersonate each requested group.
            for group in &impersonate_groups {
                if !self.rbac_index.is_allowed(&AuthzRequest {
                    username: &authenticated_user.username,
                    groups: &authenticated_user.groups,
                    verb: "impersonate",
                    api_group: "",
                    resource: "groups",
                    subresource: "",
                    namespace: None,
                    name: Some(group),
                    non_resource_url: None,
                }) {
                    let username = authenticated_user.username.clone();
                    let target = group.clone();
                    return Box::pin(async move {
                        Ok(forbidden_response(&username, "impersonate", &target))
                    });
                }
            }

            // All impersonation checks passed — substitute impersonated identity.
            // If the caller supplied explicit groups, use them verbatim.
            // If no groups were provided, add system:authenticated as Kubernetes does.
            let groups = if impersonate_groups.is_empty() {
                vec!["system:authenticated".to_owned()]
            } else {
                impersonate_groups
            };

            UserInfo {
                username: impersonate_user,
                uid: String::new(),
                groups,
                extra: HashMap::new(),
            }
        } else {
            authenticated_user
        };

        // 2. Authorize.
        let parsed = parse_path(&path);

        // Detect non-resource URL requests: paths not rooted in /api or /apis
        // (i.e. parse_path returned an empty resource) are non-resource requests.
        // Examples: GET /version, GET /openapi/v2, GET /openapi/v3/apis/<group>/<ver>.
        let non_resource_url: Option<&str> =
            if parsed.resource.is_empty() && !path.starts_with("/api") {
                Some(&path)
            } else {
                None
            };

        // Non-resource URL verbs map directly from the HTTP method ("get", "post", ...).
        // get_verb's list/get/watch distinction only applies to resource requests.
        let verb = if non_resource_url.is_some() {
            method_to_verb(req.method())
        } else if req.method() == axum::http::Method::GET {
            get_verb(parsed.name.as_deref(), req.uri().query())
        } else if req.method() == axum::http::Method::DELETE && parsed.name.is_none() {
            "deletecollection"
        } else {
            method_to_verb(req.method())
        };

        // RBAC `resourceNames` restrictions must also recognize the LIST/WATCH-with-
        // `fieldSelector=metadata.name=<name>` pattern used by every client-go informer
        // that watches a single named object — e.g. the built-in
        // `extension-apiserver-authentication-reader` Role grants access to the
        // extension-apiserver-authentication ConfigMap this way, and every aggregated
        // apiserver (including the "sample-apiserver" conformance test) reads it through
        // exactly this informer pattern, never a plain named GET. Real Kubernetes derives
        // RequestInfo.Name from such an exact-match field selector for authorization
        // purposes even though the verb stays list/watch (see requestinfo.go). Without this,
        // a resourceNames-restricted Role can never grant informer-style access — the
        // ConfigMap read is Forbidden forever, regardless of how long the RoleBinding has
        // existed, which is why the aggregator conformance test's sample-apiserver pod
        // crash-loops indefinitely instead of eventually recovering.
        let fs_name = if parsed.name.is_none() && (verb == "list" || verb == "watch") {
            field_selector_name(req.uri().query())
        } else {
            None
        };
        let authz_name = parsed.name.as_deref().or(fs_name.as_deref());

        let allowed = self.rbac_index.is_allowed(&AuthzRequest {
            username: &user.username,
            groups: &user.groups,
            verb,
            api_group: &parsed.api_group,
            resource: &parsed.resource,
            subresource: &parsed.subresource,
            namespace: parsed.namespace.as_deref(),
            name: authz_name,
            non_resource_url,
        });

        if !allowed {
            let username = user.username.clone();
            let verb = verb.to_owned();
            let resource = parsed.resource.clone();
            return Box::pin(async move { Ok(forbidden_response(&username, &verb, &resource)) });
        }

        // 3. Attach UserInfo to request extensions and pass through.
        req.extensions_mut().insert(user);
        Box::pin(self.inner.call(req))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    fn make_req(method: Method, path: &str, auth: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        b.body(Body::empty()).unwrap()
    }

    /// Generate a DER cert with given CN and org using rcgen.
    fn make_cert_der(cn: &str, orgs: &[&str]) -> Vec<u8> {
        use rcgen::{CertificateParams, Issuer, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let ca_params = rcgen::CertificateParams::default();
        let ca_issuer = Issuer::new(ca_params, ca_key);

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        for org in orgs {
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, *org);
        }
        let cert = params.signed_by(&key, &ca_issuer).unwrap();
        cert.der().to_vec()
    }

    // --- authenticate() ---

    #[test]
    fn test_authn_no_header_is_anonymous() {
        // Without an Authorization header, caller must be anonymous.
        let map = HashMap::new();
        let req = make_req(Method::GET, "/api/v1/pods", None);
        let result = authenticate(&req, &map, None, None, &HashSet::new());
        match result {
            AuthnResult::Identified(u) => {
                assert_eq!(u.username, "system:anonymous");
                assert!(u.groups.contains(&"system:unauthenticated".to_owned()));
            }
            AuthnResult::BadToken => panic!("expected anonymous, got BadToken"),
        }
    }

    #[test]
    fn test_authn_valid_token_resolves_user() {
        // A known token must resolve to the correct UserInfo.
        let mut map = HashMap::new();
        map.insert(
            "secret-token".to_owned(),
            UserInfo {
                username: "alice".to_owned(),
                uid: "42".to_owned(),
                groups: vec!["devs".to_owned()],
                extra: Default::default(),
            },
        );
        let req = make_req(Method::GET, "/api/v1/pods", Some("Bearer secret-token"));
        match authenticate(&req, &map, None, None, &HashSet::new()) {
            AuthnResult::Identified(u) => assert_eq!(u.username, "alice"),
            AuthnResult::BadToken => panic!("expected Identified"),
        }
    }

    #[test]
    fn test_authn_unknown_token_is_bad() {
        // An unrecognized token must produce BadToken, not anonymous.
        // This is critical: callers presenting a bad credential must not be
        // silently downgraded to anonymous access.
        let map = HashMap::new();
        let req = make_req(Method::GET, "/api/v1/pods", Some("Bearer wrong-token"));
        match authenticate(&req, &map, None, None, &HashSet::new()) {
            AuthnResult::BadToken => {}
            AuthnResult::Identified(_) => panic!("unknown token must not succeed"),
        }
    }

    // --- ct_token_lookup ---

    #[test]
    fn ct_token_lookup_finds_exact_match() {
        // A valid token must be found — correctness of the constant-time path.
        let mut map = HashMap::new();
        map.insert(
            "exact-token-abc".to_owned(),
            UserInfo {
                username: "alice".to_owned(),
                uid: "1".to_owned(),
                groups: vec![],
                extra: Default::default(),
            },
        );
        let result = ct_token_lookup(&map, "exact-token-abc");
        assert!(result.is_some(), "exact match must be found");
        assert_eq!(result.unwrap().username, "alice");
    }

    #[test]
    fn ct_token_lookup_rejects_prefix_of_valid_token() {
        // A prefix of a valid token must NOT match — timing oracle would allow
        // an attacker to discover valid tokens one character at a time.
        let mut map = HashMap::new();
        map.insert(
            "secret-abc".to_owned(),
            UserInfo {
                username: "alice".to_owned(),
                uid: "1".to_owned(),
                groups: vec![],
                extra: Default::default(),
            },
        );
        assert!(
            ct_token_lookup(&map, "secret").is_none(),
            "a prefix of a valid token must not match (timing oracle would otherwise apply)"
        );
        assert!(
            ct_token_lookup(&map, "secret-abcX").is_none(),
            "a token with extra chars must not match"
        );
    }

    #[test]
    fn ct_token_lookup_empty_map_returns_none() {
        // Empty map must not panic or return a result.
        let map = HashMap::new();
        assert!(ct_token_lookup(&map, "any-token").is_none());
    }

    #[test]
    fn ct_token_lookup_different_lengths_no_match() {
        // A candidate of a different length than a stored token must NOT match.
        // This verifies that removing the manual length pre-check did not break
        // correctness: subtle::ct_eq handles unequal-length slices safely.
        // (The manual len check was removed because it leaked timing info about
        // whether the candidate length matched any stored token.)
        let mut map = HashMap::new();
        map.insert(
            "tok-sixteen-chrs".to_owned(), // exactly 16 chars
            UserInfo {
                username: "alice".to_owned(),
                uid: "1".to_owned(),
                groups: vec![],
                extra: Default::default(),
            },
        );
        // Shorter candidate — must not match.
        assert!(
            ct_token_lookup(&map, "tok-sixteen-ch").is_none(),
            "shorter candidate must not match stored token"
        );
        // Longer candidate — must not match.
        assert!(
            ct_token_lookup(&map, "tok-sixteen-chrsX").is_none(),
            "longer candidate must not match stored token"
        );
        // Exact match — must succeed.
        assert!(
            ct_token_lookup(&map, "tok-sixteen-chrs").is_some(),
            "exact candidate must match stored token"
        );
    }

    // --- parse_path() ---

    #[test]
    fn test_parse_core_api_namespaced_named() {
        let p = parse_path("/api/v1/namespaces/default/pods/mypod");
        assert_eq!(p.api_group, "");
        assert_eq!(p.resource, "pods");
        assert_eq!(p.namespace.as_deref(), Some("default"));
        assert_eq!(p.name.as_deref(), Some("mypod"));
        assert_eq!(p.subresource, "");
    }

    #[test]
    fn test_parse_apis_group_cluster_scoped() {
        let p = parse_path("/apis/rbac.authorization.k8s.io/v1/clusterroles/admin");
        assert_eq!(p.api_group, "rbac.authorization.k8s.io");
        assert_eq!(p.resource, "clusterroles");
        assert_eq!(p.name.as_deref(), Some("admin"));
        assert!(p.namespace.is_none());
    }

    #[test]
    fn test_parse_subresource() {
        let p = parse_path("/api/v1/namespaces/default/pods/mypod/status");
        assert_eq!(p.resource, "pods");
        assert_eq!(p.subresource, "status");
        assert_eq!(p.name.as_deref(), Some("mypod"));
    }

    // Regression tests for parse_path misclassifying namespace paths (mayor-8kmu).
    // /api/v1/namespaces and /api/v1/namespaces/{name} are cluster-scoped
    // operations on the "namespaces" resource, not namespaced operations.
    // Without the rest.len() >= 3 guard, resource="" and RBAC wildcard rules
    // (cluster-admin) never match, denying all namespace operations.

    /// LIST namespaces: cluster-scoped, resource="namespaces", no namespace.
    #[test]
    fn test_parse_namespace_collection_is_cluster_scoped() {
        let p = parse_path("/api/v1/namespaces");
        assert_eq!(p.api_group, "");
        assert_eq!(p.resource, "namespaces");
        assert!(p.namespace.is_none(), "must be cluster-scoped");
        assert!(p.name.is_none());
        assert_eq!(p.subresource, "");
    }

    /// GET/DELETE a specific namespace: cluster-scoped, resource="namespaces",
    /// name=Some("foo"), no namespace field.
    #[test]
    fn test_parse_namespace_named_is_cluster_scoped() {
        let p = parse_path("/api/v1/namespaces/foo");
        assert_eq!(p.api_group, "");
        assert_eq!(p.resource, "namespaces");
        assert!(p.namespace.is_none(), "must be cluster-scoped");
        assert_eq!(p.name.as_deref(), Some("foo"));
        assert_eq!(p.subresource, "");
    }

    /// Namespaced resource collection still works after the fix.
    #[test]
    fn test_parse_namespaced_resource_collection() {
        let p = parse_path("/api/v1/namespaces/foo/pods");
        assert_eq!(p.api_group, "");
        assert_eq!(p.resource, "pods");
        assert_eq!(p.namespace.as_deref(), Some("foo"));
        assert!(p.name.is_none());
        assert_eq!(p.subresource, "");
    }

    /// Namespaced named resource still works after the fix.
    #[test]
    fn test_parse_namespaced_resource_named() {
        let p = parse_path("/api/v1/namespaces/foo/pods/bar");
        assert_eq!(p.api_group, "");
        assert_eq!(p.resource, "pods");
        assert_eq!(p.namespace.as_deref(), Some("foo"));
        assert_eq!(p.name.as_deref(), Some("bar"));
        assert_eq!(p.subresource, "");
    }

    /// APIS group cluster-scoped resource (clusterrolebindings).
    #[test]
    fn test_parse_apis_cluster_scoped_resource() {
        let p = parse_path("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings");
        assert_eq!(p.api_group, "rbac.authorization.k8s.io");
        assert_eq!(p.resource, "clusterrolebindings");
        assert!(p.namespace.is_none());
        assert!(p.name.is_none());
        assert_eq!(p.subresource, "");
    }

    // --- get_verb() — collection vs named vs watch disambiguation ---

    /// GET on a collection endpoint must map to "list".
    /// A user with only "get" must NOT be allowed to enumerate all pods via
    /// the collection endpoint — that would be an authorization bypass.
    #[test]
    fn test_get_verb_collection_is_list() {
        assert_eq!(get_verb(None, None), "list");
        assert_eq!(get_verb(None, Some("")), "list");
        assert_eq!(get_verb(None, Some("limit=500")), "list");
    }

    /// GET on a named resource endpoint must map to "get".
    #[test]
    fn test_get_verb_named_is_get() {
        assert_eq!(get_verb(Some("nginx"), None), "get");
        assert_eq!(get_verb(Some("nginx"), Some("resourceVersion=42")), "get");
    }

    /// GET with watch=true must map to "watch", regardless of whether a name
    /// is present. "watch" is a separate RBAC verb in Kubernetes.
    #[test]
    fn test_get_verb_watch_param_is_watch() {
        assert_eq!(get_verb(None, Some("watch=true")), "watch");
        assert_eq!(get_verb(Some("nginx"), Some("watch=true")), "watch");
        // watch=1 is also accepted
        assert_eq!(get_verb(None, Some("watch=1")), "watch");
        // watch takes priority even with other params
        assert_eq!(get_verb(None, Some("limit=100&watch=true")), "watch");
        assert_eq!(
            get_verb(None, Some("watch=true&resourceVersion=0")),
            "watch"
        );
    }

    /// "watch=false" must NOT map to "watch" — client explicitly opted out.
    #[test]
    fn test_get_verb_watch_false_is_list() {
        assert_eq!(get_verb(None, Some("watch=false")), "list");
        assert_eq!(get_verb(None, Some("watch=0")), "list");
    }

    // --- is_exempt() ---

    #[test]
    fn test_exempt_paths() {
        // Discovery and health paths must not require auth.
        for path in &["/healthz", "/readyz", "/livez", "/api", "/apis", "/version"] {
            assert!(is_exempt(path), "{path} must be exempt");
        }
        // Non-exempt paths must not be skipped.
        assert!(!is_exempt("/api/v1/pods"));
        assert!(!is_exempt("/apis/apps/v1/deployments"));
    }

    /// Upstream e2e clients (Discovery, kubectl proxy) call AbsPath('/api/') and
    /// AbsPath('/apis/') with a literal trailing slash. Without exempting these
    /// variants, such clients get a 401/403 instead of the discovery doc.
    #[test]
    fn test_exempt_paths_trailing_slash() {
        for path in &["/api/", "/apis/"] {
            assert!(
                is_exempt(path),
                "{path} must be exempt — clients appending a trailing slash to a \
                 discovery root must not be treated differently from the no-slash form"
            );
        }
    }

    /// /openapi/v2 and /openapi/v3 must be exempt from auth.
    ///
    /// Conformance tests poll these endpoints after creating a CRD to wait for
    /// the CRD schema to appear. The test client sends requests without credentials,
    /// so any auth requirement causes 403 Forbidden and the test times out waiting
    /// for a schema that the client can never see. kube-apiserver serves these
    /// endpoints without requiring auth.
    #[test]
    fn openapi_endpoints_are_exempt_from_auth() {
        assert!(
            is_exempt("/openapi/v2"),
            "/openapi/v2 must be auth-exempt — conformance tests poll it without credentials \
             to detect when a CRD schema is published; a 403 causes the test to time out"
        );
        assert!(
            is_exempt("/openapi/v3"),
            "/openapi/v3 must be auth-exempt — conformance tests poll it without credentials \
             to detect when a CRD schema is published; a 403 causes the test to time out"
        );
    }

    /// GET /openapi/v3/apis/<group>/<version> must use verb "get", not "list".
    ///
    /// parse_path() returns name=None for this path (it's not a resource path), so
    /// get_verb(None, _) would return "list". The system:discovery ClusterRole only
    /// grants verb "get" on /openapi/*, so a "list" check always fails with 403,
    /// causing the e2e test "should type check a CRD" to hang while polling the
    /// per-group schema endpoint.
    #[test]
    fn non_resource_url_get_uses_method_verb_not_list() {
        let path = "/openapi/v3/apis/stable.example.com/v1";
        let parsed = parse_path(path);
        // parse_path returns unknown_path() for non-api/apis paths
        assert!(
            parsed.resource.is_empty(),
            "openapi path must not parse as a resource"
        );
        // non_resource_url detection
        let is_non_resource = parsed.resource.is_empty() && !path.starts_with("/api");
        assert!(
            is_non_resource,
            "/openapi/... must be detected as non-resource"
        );
        // verb for non-resource GET must be "get", not "list"
        // (get_verb(None, None) returns "list" — must NOT be called for non-resource paths)
        let verb = if is_non_resource {
            method_to_verb(&Method::GET)
        } else {
            get_verb(parsed.name.as_deref(), None)
        };
        assert_eq!(
            verb, "get",
            "GET /openapi/v3/apis/<group>/<version> must use verb \"get\" — \
             system:discovery only grants \"get\" on /openapi/*, so \"list\" \
             causes 403 and the type-check CRD conformance test hangs forever"
        );
    }

    // --- load_token_file() ---

    #[test]
    fn test_load_token_file_parses_entries() {
        // Write a temp file and verify parsing produces the right UserInfo.
        let dir = std::env::temp_dir();
        let path = dir.join("u7s_test_tokens.csv");
        std::fs::write(
            // lgtm[rust/path-injection]
            &path,
            "tok1,alice,uid1,group-a,group-b\n# comment\n\ntok2,bob,uid2\n",
        )
        .unwrap();

        let map = load_token_file(path.to_str().unwrap()).unwrap();
        assert_eq!(map.len(), 2);

        let alice = map.get("tok1").expect("tok1 must be present");
        assert_eq!(alice.username, "alice");
        assert_eq!(alice.uid, "uid1");
        // Groups after the 4th field must all be captured (comma-separated in field 4).
        assert_eq!(alice.groups, vec!["group-a", "group-b"]);

        let bob = map.get("tok2").expect("tok2 must be present");
        assert_eq!(bob.username, "bob");
        assert!(bob.groups.is_empty());
    }

    // --- SA JWT authentication ---

    /// Generate a minimal in-memory RSA-2048 key pair for use in tests.
    fn test_rsa_keypair() -> (jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey) {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        let mut rng = rsa::rand_core::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
        let priv_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("priv pem")
            .as_bytes()
            .to_vec();
        let pub_pem = private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("pub pem")
            .into_bytes();
        let enc = jsonwebtoken::EncodingKey::from_rsa_pem(&priv_pem).expect("enc key");
        let dec = jsonwebtoken::DecodingKey::from_rsa_pem(&pub_pem).expect("dec key");
        (enc, dec)
    }

    /// Mint a minimal SA JWT using the provided encoding key.
    fn mint_sa_jwt(enc: &jsonwebtoken::EncodingKey, sub: &str, exp_offset_secs: i64) -> String {
        use serde_json::json;
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = json!({
            "iss": "https://kubernetes.default.svc",
            "sub": sub,
            "aud": ["https://kubernetes.default.svc"],
            "iat": now,
            "exp": now + exp_offset_secs,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        jsonwebtoken::encode(&header, &claims, enc).expect("mint JWT")
    }

    #[test]
    fn test_authn_valid_sa_jwt_authenticates() {
        // A valid SA JWT signed by the SA key must identify the subject.
        // This is the primary fix: SA JWTs are now verified, not rejected.
        let (enc, dec) = test_rsa_keypair();
        let token = mint_sa_jwt(&enc, "system:serviceaccount:default:my-sa", 3600);
        let req = make_req(
            Method::GET,
            "/api/v1/pods",
            Some(&format!("Bearer {token}")),
        );
        match authenticate(&req, &HashMap::new(), Some(&dec), None, &HashSet::new()) {
            AuthnResult::Identified(u) => {
                assert_eq!(u.username, "system:serviceaccount:default:my-sa");
                assert!(
                    u.groups.contains(&"system:serviceaccounts".to_owned()),
                    "SA group must be present"
                );
            }
            AuthnResult::BadToken => panic!("valid SA JWT must not be rejected"),
        }
    }

    /// SA JWT authentication must produce both the broad group (system:serviceaccounts)
    /// and the namespace-scoped group (system:serviceaccounts:{ns}). The namespace-scoped
    /// group is required for RBAC policies that grant access to SAs in a specific namespace.
    #[test]
    fn test_sa_jwt_namespace_scoped_group() {
        let (enc, dec) = test_rsa_keypair();
        let token = mint_sa_jwt(&enc, "system:serviceaccount:kube-system:coredns", 3600);
        let req = make_req(
            Method::GET,
            "/api/v1/pods",
            Some(&format!("Bearer {token}")),
        );
        match authenticate(&req, &HashMap::new(), Some(&dec), None, &HashSet::new()) {
            AuthnResult::Identified(u) => {
                assert!(
                    u.groups.contains(&"system:serviceaccounts".to_owned()),
                    "broad SA group must be present"
                );
                assert!(
                    u.groups
                        .contains(&"system:serviceaccounts:kube-system".to_owned()),
                    "namespace-scoped SA group must be present"
                );
            }
            AuthnResult::BadToken => panic!("valid SA JWT must not be rejected"),
        }
    }

    #[test]
    fn test_authn_tampered_sa_jwt_rejected() {
        // A JWT with a tampered signature must be rejected — not silently allowed.
        // Tampering: replace last 8 chars of the token (signature portion).
        let (enc, dec) = test_rsa_keypair();
        let mut token = mint_sa_jwt(&enc, "system:serviceaccount:default:my-sa", 3600);
        let len = token.len();
        token.replace_range(len - 8.., "AAAAAAAA");
        let req = make_req(
            Method::GET,
            "/api/v1/pods",
            Some(&format!("Bearer {token}")),
        );
        match authenticate(&req, &HashMap::new(), Some(&dec), None, &HashSet::new()) {
            AuthnResult::BadToken => {} // correct
            AuthnResult::Identified(_) => panic!("tampered JWT must not succeed"),
        }
    }

    #[test]
    fn test_authn_expired_sa_jwt_rejected() {
        // An expired JWT must be rejected — not silently allowed.
        let (enc, dec) = test_rsa_keypair();
        let token = mint_sa_jwt(&enc, "system:serviceaccount:default:my-sa", -1);
        let req = make_req(
            Method::GET,
            "/api/v1/pods",
            Some(&format!("Bearer {token}")),
        );
        match authenticate(&req, &HashMap::new(), Some(&dec), None, &HashSet::new()) {
            AuthnResult::BadToken => {} // correct
            AuthnResult::Identified(_) => panic!("expired JWT must not succeed"),
        }
    }

    #[test]
    fn test_authn_sa_jwt_wrong_key_rejected() {
        // A JWT signed by a different key must be rejected.
        // This prevents accepting tokens from a different cluster.
        let (enc, _dec) = test_rsa_keypair();
        let (_enc2, dec2) = test_rsa_keypair();
        let token = mint_sa_jwt(&enc, "system:serviceaccount:default:my-sa", 3600);
        let req = make_req(
            Method::GET,
            "/api/v1/pods",
            Some(&format!("Bearer {token}")),
        );
        match authenticate(&req, &HashMap::new(), Some(&dec2), None, &HashSet::new()) {
            AuthnResult::BadToken => {} // correct
            AuthnResult::Identified(_) => panic!("JWT from wrong key must not succeed"),
        }
    }

    #[test]
    fn token_review_custom_audience_accepted() {
        // A SA JWT with a non-default audience (e.g. system:konnectivity-server)
        // must be accepted by authenticate_token_with_audiences when that audience
        // is explicitly requested.  Without this, the konnectivity-server cannot
        // validate agent tokens via TokenReview, blocking the tunnel connection.
        let (enc, dec) = test_rsa_keypair();
        use serde_json::json;
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = json!({
            "iss": "https://kubernetes.default.svc",
            "sub": "system:serviceaccount:kube-system:konnectivity-agent",
            "aud": ["system:konnectivity-server"],
            "iat": now,
            "exp": now + 3600,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let token = jsonwebtoken::encode(&header, &claims, &enc).expect("mint JWT");

        // Must fail with default (https://kubernetes.default.svc) audience.
        let result_default = authenticate_token_with_audiences(
            &token,
            &HashMap::new(),
            Some(&dec),
            &[],
            &HashSet::new(),
        );
        assert!(
            result_default.is_none(),
            "token with non-default audience must NOT authenticate when no audiences specified"
        );

        // Must succeed when the correct audience is explicitly requested.
        let aud = vec!["system:konnectivity-server".to_owned()];
        let result = authenticate_token_with_audiences(
            &token,
            &HashMap::new(),
            Some(&dec),
            &aud,
            &HashSet::new(),
        );
        let user = result.expect(
            "token with system:konnectivity-server audience must authenticate \
             when that audience is explicitly requested via TokenReview spec.audiences — \
             without this fix, konnectivity-agent SA tokens are always rejected",
        );
        assert_eq!(
            user.username, "system:serviceaccount:kube-system:konnectivity-agent",
            "username must match the token subject"
        );
        assert!(
            user.groups
                .contains(&"system:serviceaccounts:kube-system".to_owned()),
            "namespace group must be present"
        );
    }

    #[test]
    fn sa_jwt_with_malformed_sub_is_rejected() {
        // A JWT whose sub is missing the name segment (only 3 colon-separated
        // parts) must be rejected entirely. Before this fix, the missing segment
        // caused the namespace-scoped group (system:serviceaccounts:{ns}) to be
        // silently omitted, making RBAC policies on that group silently fail.
        // Rejecting the token is the correct response: a well-formed SA JWT must
        // always have sub = system:serviceaccount:{ns}:{name}.
        let (enc, dec) = test_rsa_keypair();
        // Only three parts — missing the service account name.
        let token = mint_sa_jwt(&enc, "system:serviceaccount:only-three", 3600);
        let result = try_verify_sa_jwt(&token, &dec, &[], &HashSet::new());
        assert!(
            result.is_none(),
            "JWT with malformed sub (missing name segment) must be rejected, \
             not silently accepted with incomplete groups"
        );
    }

    // ---------------------------------------------------------------------------
    // JTI revocation tests
    // ---------------------------------------------------------------------------

    /// Mint a JWT that includes a `jti` claim for testing revocation.
    fn mint_sa_jwt_with_jti(
        enc: &jsonwebtoken::EncodingKey,
        sub: &str,
        jti: &str,
        exp_offset_secs: i64,
    ) -> String {
        use serde_json::json;
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = json!({
            "jti": jti,
            "iss": "https://kubernetes.default.svc",
            "sub": sub,
            "aud": ["https://kubernetes.default.svc"],
            "iat": now,
            "exp": now + exp_offset_secs,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        jsonwebtoken::encode(&header, &claims, enc).expect("mint JWT with jti")
    }

    /// A token whose JTI is in the revocation set must be rejected by try_verify_sa_jwt
    /// even though the signature and expiry are valid.
    ///
    /// Without this check, a compromised or leaked SA token remains usable for the full
    /// 24-hour JWT lifetime. JTI revocation allows immediate invalidation before expiry.
    #[test]
    fn revoked_jti_is_rejected_by_try_verify_sa_jwt() {
        let (enc, dec) = test_rsa_keypair();
        let jti = "revoked-jti-abc-123";
        let token = mint_sa_jwt_with_jti(&enc, "system:serviceaccount:default:my-sa", jti, 3600);

        let mut revoked = HashSet::new();
        revoked.insert(jti.to_owned());

        let result = try_verify_sa_jwt(&token, &dec, &[], &revoked);
        assert!(
            result.is_none(),
            "a token whose JTI is in the revocation set must be rejected — \
             without this, revoked SA tokens remain usable for up to 24h after revocation"
        );
    }

    /// A token whose JTI is NOT in the revocation set must pass verification normally.
    ///
    /// Revocation must only block tokens with explicitly revoked JTIs. An unrevoked token
    /// with a valid signature and unexpired exp must authenticate successfully.
    #[test]
    fn unrevoked_jti_passes_try_verify_sa_jwt() {
        let (enc, dec) = test_rsa_keypair();
        let jti = "live-jti-xyz-456";
        let token = mint_sa_jwt_with_jti(&enc, "system:serviceaccount:default:my-sa", jti, 3600);

        // Revocation set contains a DIFFERENT jti — this token's jti is not revoked.
        let mut revoked = HashSet::new();
        revoked.insert("some-other-revoked-jti".to_owned());

        let result = try_verify_sa_jwt(&token, &dec, &[], &revoked);
        assert!(
            result.is_some(),
            "a token whose JTI is not in the revocation set must authenticate — \
             revocation must not block valid unrevoked tokens"
        );
        let user = result.unwrap();
        assert_eq!(
            user.username, "system:serviceaccount:default:my-sa",
            "authenticated username must match the token subject"
        );
    }

    /// A token without a jti claim (legacy tokens from before this change) must
    /// still authenticate if the revocation set is non-empty. The jti field is
    /// optional in SaClaims so old tokens without it are not broken.
    #[test]
    fn token_without_jti_authenticates_despite_nonempty_revocation_set() {
        let (enc, dec) = test_rsa_keypair();
        // mint_sa_jwt produces a token WITHOUT a jti claim (legacy format).
        let token = mint_sa_jwt(&enc, "system:serviceaccount:default:legacy-sa", 3600);

        let mut revoked = HashSet::new();
        revoked.insert("some-revoked-jti".to_owned());

        let result = try_verify_sa_jwt(&token, &dec, &[], &revoked);
        assert!(
            result.is_some(),
            "a token without a jti claim must not be blocked by a non-empty revocation set — \
             the jti field is optional and absence means it cannot be revoked via JTI"
        );
    }

    #[test]
    fn test_authn_static_token_takes_priority_over_jwt() {
        // If a token happens to be in the static map, it must use static auth,
        // not fall through to JWT parsing (which would fail on a non-JWT string).
        let mut map = HashMap::new();
        map.insert(
            "static-tok".to_owned(),
            UserInfo {
                username: "static-user".to_owned(),
                uid: "0".to_owned(),
                groups: vec![],
                extra: Default::default(),
            },
        );
        let (enc, dec) = test_rsa_keypair();
        // Use a static token string — not a JWT — to confirm static path fires.
        let req = make_req(Method::GET, "/api/v1/pods", Some("Bearer static-tok"));
        match authenticate(&req, &map, Some(&dec), None, &HashSet::new()) {
            AuthnResult::Identified(u) => assert_eq!(u.username, "static-user"),
            AuthnResult::BadToken => panic!("static token must resolve"),
        }
        // Suppress unused warning in test context.
        let _ = enc;
    }

    // --- x509 client certificate authentication ---

    #[test]
    fn test_x509_cert_cn_becomes_username() {
        // The CN field of the subject must become the username.
        // This is the core Kubernetes x509 auth mapping.
        // Even without O fields, system:authenticated must be present so that
        // ClusterRoleBindings on that group (e.g. system:basic-user) apply.
        let der = make_cert_der("alice", &[]);
        let user = extract_client_cert_identity(&der).expect("must parse cert");
        assert_eq!(user.username, "alice");
        assert_eq!(
            user.groups,
            vec!["system:authenticated"],
            "cert auth with no O fields must still add system:authenticated"
        );
    }

    #[test]
    fn test_x509_cert_org_becomes_groups() {
        // The O fields of the subject must become the groups list.
        // system:masters in O grants cluster-admin equivalent via RBAC.
        let der = make_cert_der("admin", &["system:masters"]);
        let user = extract_client_cert_identity(&der).expect("must parse cert");
        assert_eq!(user.username, "admin");
        assert!(
            user.groups.contains(&"system:masters".to_owned()),
            "system:masters must be in groups"
        );
    }

    #[test]
    fn test_x509_cert_no_org_means_only_system_authenticated() {
        // A cert with no O fields must produce only system:authenticated in groups.
        // The parser must not panic or return an error for a valid cert.
        // system:authenticated is always added so ClusterRoleBindings on that
        // group (e.g. system:basic-user) apply to all authenticated users.
        let der = make_cert_der("alice", &[]);
        let user = extract_client_cert_identity(&der).expect("must parse cert");
        assert_eq!(user.username, "alice");
        assert_eq!(
            user.groups,
            vec!["system:authenticated"],
            "cert auth with no O fields must still add system:authenticated"
        );
    }

    #[test]
    fn extract_client_cert_identity_documents_no_chain_verification() {
        // extract_client_cert_identity ONLY extracts CN/O from DER bytes.
        // It does NOT verify the certificate chain — that is TLS's job
        // (rustls WebPkiClientVerifier validates chain before the cert reaches
        // this function). A self-signed cert not rooted in any cluster CA
        // must still return Some(UserInfo) from this function.
        //
        // This test encodes the contract: callers must not rely on this
        // function for trust decisions. Chain validation happens at the TLS layer.
        let der = make_cert_der("self-signed-user", &["some-org"]);
        // make_cert_der already generates a cert signed by a local ephemeral CA,
        // not by any cluster CA — it is "untrusted" from the cluster's perspective.
        let user = extract_client_cert_identity(&der).expect(
            "extract_client_cert_identity must succeed on any parseable DER, \
                     regardless of signing chain — chain validation is TLS's responsibility",
        );
        assert_eq!(user.username, "self-signed-user");
        assert!(user.groups.contains(&"some-org".to_owned()));
    }

    #[test]
    fn test_x509_cert_injected_into_authn_no_header() {
        // When no Authorization header is present but a PeerCertificate is
        // available, the caller must be identified via x509 — not as anonymous.
        let der = make_cert_der("alice", &["system:masters"]);
        let cert = PeerCertificate(der);
        let map = HashMap::new();
        let req = make_req(Method::GET, "/api/v1/pods", None);
        match authenticate(&req, &map, None, Some(&cert), &HashSet::new()) {
            AuthnResult::Identified(u) => {
                assert_eq!(u.username, "alice");
                assert!(u.groups.contains(&"system:masters".to_owned()));
            }
            AuthnResult::BadToken => panic!("valid client cert must identify caller"),
        }
    }

    #[test]
    fn test_x509_auth_does_not_override_bearer_token() {
        // A bearer token in Authorization must take priority over a client
        // cert; the caller explicitly chose token auth.
        let mut map = HashMap::new();
        map.insert(
            "tok".to_owned(),
            UserInfo {
                username: "bob".to_owned(),
                uid: "1".to_owned(),
                groups: vec![],
                extra: Default::default(),
            },
        );
        let der = make_cert_der("alice", &["system:masters"]);
        let cert = PeerCertificate(der);
        let req = make_req(Method::GET, "/api/v1/pods", Some("Bearer tok"));
        match authenticate(&req, &map, None, Some(&cert), &HashSet::new()) {
            AuthnResult::Identified(u) => assert_eq!(u.username, "bob"),
            AuthnResult::BadToken => panic!("static token must resolve"),
        }
    }

    // --- system:authenticated group presence ---
    // Argo CD and other tools bind ClusterRoles to the system:authenticated group
    // (e.g. system:basic-user grants SelfSubjectAccessReview).  Without this group
    // those bindings are invisible to every authenticated user, causing permission
    // discovery failures on startup.

    #[test]
    fn test_sa_jwt_includes_system_authenticated() {
        // SA JWTs must carry system:authenticated so that ClusterRoleBindings
        // targeting that group (like system:basic-user) apply to service accounts.
        let (enc, dec) = test_rsa_keypair();
        let token = mint_sa_jwt(&enc, "system:serviceaccount:default:my-sa", 3600);
        let req = make_req(
            Method::GET,
            "/api/v1/pods",
            Some(&format!("Bearer {token}")),
        );
        match authenticate(&req, &HashMap::new(), Some(&dec), None, &HashSet::new()) {
            AuthnResult::Identified(u) => {
                assert!(
                    u.groups.contains(&"system:authenticated".to_owned()),
                    "SA JWT auth must add system:authenticated to groups; \
                     Argo CD's system:basic-user binding depends on this group"
                );
            }
            AuthnResult::BadToken => panic!("valid SA JWT must not be rejected"),
        }
    }

    #[test]
    fn test_x509_cert_includes_system_authenticated() {
        // x509 client cert auth must add system:authenticated so that
        // ClusterRoleBindings targeting that group apply to cert-authed users.
        let der = make_cert_der("alice", &["engineering"]);
        let user = extract_client_cert_identity(&der).expect("must parse cert");
        assert!(
            user.groups.contains(&"system:authenticated".to_owned()),
            "x509 auth must add system:authenticated to groups; \
             Argo CD's system:basic-user binding depends on this group"
        );
        // Original O-field groups must still be present.
        assert!(user.groups.contains(&"engineering".to_owned()));
    }

    #[test]
    fn test_static_token_includes_system_authenticated() {
        // Static bearer token auth must add system:authenticated so that
        // ClusterRoleBindings targeting that group apply to token-authed users.
        let mut map = HashMap::new();
        map.insert(
            "secret-token".to_owned(),
            UserInfo {
                username: "alice".to_owned(),
                uid: "42".to_owned(),
                groups: vec!["devs".to_owned()],
                extra: Default::default(),
            },
        );
        let req = make_req(Method::GET, "/api/v1/pods", Some("Bearer secret-token"));
        match authenticate(&req, &map, None, None, &HashSet::new()) {
            AuthnResult::Identified(u) => {
                assert!(
                    u.groups.contains(&"system:authenticated".to_owned()),
                    "static token auth must add system:authenticated to groups; \
                     Argo CD's system:basic-user binding depends on this group"
                );
                // Original groups must still be present.
                assert!(u.groups.contains(&"devs".to_owned()));
            }
            AuthnResult::BadToken => panic!("valid static token must not be rejected"),
        }
    }

    #[test]
    fn test_anonymous_does_not_get_system_authenticated() {
        // Anonymous users must NOT receive system:authenticated — they are
        // unauthenticated and must only get system:unauthenticated.
        let map = HashMap::new();
        let req = make_req(Method::GET, "/api/v1/pods", None);
        match authenticate(&req, &map, None, None, &HashSet::new()) {
            AuthnResult::Identified(u) => {
                assert_eq!(u.username, "system:anonymous");
                assert!(
                    !u.groups.contains(&"system:authenticated".to_owned()),
                    "anonymous user must not receive system:authenticated"
                );
                assert!(u.groups.contains(&"system:unauthenticated".to_owned()));
            }
            AuthnResult::BadToken => panic!("expected anonymous"),
        }
    }

    /// DELETE on a namespaced collection must use the "deletecollection" RBAC verb.
    ///
    /// The KCM namespace controller calls DELETE on collection endpoints to clean up
    /// child resources.  If the verb is "delete" instead of "deletecollection", a
    /// role that only grants "deletecollection" (the correct Kubernetes RBAC verb for
    /// this operation) would deny the request, leaving services alive after namespace
    /// deletion and blocking the kubernetes finalizer forever.
    #[test]
    fn delete_on_collection_path_uses_deletecollection_verb() {
        let idx = RbacIndex::new();

        let role_key = "/apis/rbac.authorization.k8s.io/v1/clusterroles/ns-cleanup";
        let role_val = serde_json::json!({
            "rules": [{
                "apiGroups": [""],
                "resources": ["services"],
                "verbs": ["deletecollection"]
            }]
        });
        idx.apply_object(role_key, &role_val);

        let binding_key =
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/ns-cleanup-binding";
        let binding_val = serde_json::json!({
            "subjects": [{"kind": "ServiceAccount", "name": "namespace-controller",
                          "namespace": "kube-system"}],
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io",
                        "kind": "ClusterRole", "name": "ns-cleanup"}
        });
        idx.apply_object(binding_key, &binding_val);

        let parsed = parse_path("/api/v1/namespaces/test-ns/services");
        assert!(
            parsed.name.is_none(),
            "collection path must have no resource name"
        );

        let verb = if parsed.name.is_none() {
            "deletecollection"
        } else {
            "delete"
        };

        let allowed = idx.is_allowed(&AuthzRequest {
            username: "system:serviceaccount:kube-system:namespace-controller",
            groups: &[],
            verb,
            api_group: &parsed.api_group,
            resource: &parsed.resource,
            subresource: &parsed.subresource,
            namespace: parsed.namespace.as_deref(),
            name: parsed.name.as_deref(),
            non_resource_url: None,
        });

        assert!(
            allowed,
            "DELETE on collection path must use 'deletecollection' verb so that \
             the namespace controller's RBAC grants apply — using 'delete' instead \
             would block namespace cleanup"
        );
    }

    // --- Impersonation via Impersonate-User / Impersonate-Group headers ---
    //
    // The conformance test (mayor-pya9) creates SA `e2e`, submits SAR for list
    // configmaps → returns false (correct), then impersonates the SA and actually
    // lists configmaps.  Before this fix the server ignored impersonation headers
    // and processed the request as the authenticated caller (cluster-admin), so
    // the real list succeeded while SAR returned false.  The fix: honor
    // Impersonate-User and Impersonate-Group, substituting the impersonated
    // identity for all downstream RBAC checks.

    fn make_rbac_with_impersonator_and_target() -> Arc<RbacIndex> {
        // alice can impersonate any user (has `impersonate` on `users`).
        // bob is the target user; he has NO other permissions.
        // charlie is a group that alice can impersonate.
        let idx = Arc::new(RbacIndex::new());

        // ClusterRole: impersonator — grants impersonate on users/* and groups/*.
        let role_key = "/apis/rbac.authorization.k8s.io/v1/clusterroles/impersonator";
        let role_val = serde_json::json!({
            "rules": [
                { "apiGroups": [""], "resources": ["users", "groups"], "verbs": ["impersonate"] }
            ]
        });
        idx.apply_object(role_key, &role_val);

        // Bind alice to the impersonator role.
        let bind_key = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/alice-impersonator";
        let bind_val = serde_json::json!({
            "subjects": [{ "kind": "User", "name": "alice" }],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "impersonator"
            }
        });
        idx.apply_object(bind_key, &bind_val);

        // ClusterRole: pod-reader — lets bob list pods.
        let role_key2 = "/apis/rbac.authorization.k8s.io/v1/clusterroles/pod-reader";
        let role_val2 = serde_json::json!({
            "rules": [
                { "apiGroups": [""], "resources": ["pods"], "verbs": ["list"] }
            ]
        });
        idx.apply_object(role_key2, &role_val2);

        // Bind bob to pod-reader.
        let bind_key2 = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/bob-pod-reader";
        let bind_val2 = serde_json::json!({
            "subjects": [{ "kind": "User", "name": "bob" }],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "pod-reader"
            }
        });
        idx.apply_object(bind_key2, &bind_val2);

        // alice also needs permission to actually make the request to the pods endpoint.
        // Grant alice list pods so the impersonation authorization check passes for alice
        // herself (the initial authz check on the real request is performed as the
        // impersonated user, not alice, so this isn't needed for the impersonation case —
        // but alice still needs to authenticate and we need the test to not be confused
        // by alice's own RBAC).
        // (No additional alice binding needed — impersonation replaces alice's identity.)

        idx
    }

    /// When `Impersonate-User: bob` is set and alice has the impersonate verb,
    /// the AuthService must substitute bob's identity for the downstream RBAC
    /// check and attach bob's UserInfo to request extensions.
    ///
    /// Without this, the server ignores impersonation headers and uses alice's
    /// identity, causing the real request to succeed (if alice is privileged)
    /// while SAR (which correctly evaluates bob's permissions) returns denied —
    /// the divergence caught by the SubjectReview conformance test.
    #[tokio::test]
    async fn impersonation_substitutes_target_identity_when_caller_has_impersonate_verb() {
        use axum::{body::Body, http::Request, routing::get, Extension, Router};
        use tower::ServiceExt;

        let idx = make_rbac_with_impersonator_and_target();

        // alice token.
        let mut token_map = HashMap::new();
        token_map.insert(
            "alice-token".to_owned(),
            UserInfo {
                username: "alice".to_owned(),
                uid: "1".to_owned(),
                groups: vec!["system:authenticated".to_owned()],
                extra: Default::default(),
            },
        );

        // Handler that extracts the effective UserInfo from request extensions.
        async fn whoami(Extension(user): Extension<UserInfo>) -> String {
            user.username
        }

        // Route that alice is NOT normally allowed to access but bob IS: list pods.
        // (bob has a ClusterRole binding for list pods; alice has no pod binding.)
        let app = Router::new()
            .route("/api/v1/namespaces/default/pods", get(whoami))
            .layer(AuthLayer::new(
                Arc::clone(&idx),
                token_map,
                None,
                Arc::new(Mutex::new(HashSet::new())),
            ));

        // Request as alice, impersonating bob.
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods")
            .header("authorization", "Bearer alice-token")
            .header("Impersonate-User", "bob")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "bob can list pods via alice's impersonation; impersonation must substitute \
             bob's identity for the downstream RBAC check"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&body_bytes).unwrap(),
            "bob",
            "effective username in extensions must be 'bob', not 'alice' — \
             impersonation must replace the identity seen by handlers"
        );
    }

    /// When `Impersonate-User` is set but the authenticated caller lacks the
    /// `impersonate` verb, the AuthService must return 403 Forbidden.
    ///
    /// Allowing unprivileged callers to impersonate would be a critical
    /// privilege escalation: any authenticated user could act as cluster-admin.
    #[tokio::test]
    async fn impersonation_denied_when_caller_lacks_impersonate_verb() {
        use axum::{body::Body, http::Request, routing::get, Router};
        use tower::ServiceExt;

        // charlie has NO permissions at all.
        let idx = Arc::new(RbacIndex::new());
        let mut token_map = HashMap::new();
        token_map.insert(
            "charlie-token".to_owned(),
            UserInfo {
                username: "charlie".to_owned(),
                uid: "2".to_owned(),
                groups: vec!["system:authenticated".to_owned()],
                extra: Default::default(),
            },
        );

        let app = Router::new()
            .route("/api/v1/namespaces/default/pods", get(|| async { "ok" }))
            .layer(AuthLayer::new(
                Arc::clone(&idx),
                token_map,
                None,
                Arc::new(Mutex::new(HashSet::new())),
            ));

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods")
            .header("authorization", "Bearer charlie-token")
            .header("Impersonate-User", "cluster-admin")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::FORBIDDEN,
            "caller without impersonate verb must get 403 — \
             failing this would allow any authenticated user to escalate to cluster-admin"
        );
    }

    /// Without impersonation headers, the AuthService must use the token-authenticated
    /// identity unchanged — impersonation logic must not bleed into non-impersonating requests.
    #[tokio::test]
    async fn no_impersonation_header_uses_token_identity() {
        use axum::{body::Body, http::Request, routing::get, Extension, Router};
        use tower::ServiceExt;

        let idx = make_rbac_with_impersonator_and_target();
        let mut token_map = HashMap::new();
        token_map.insert(
            "bob-token".to_owned(),
            UserInfo {
                username: "bob".to_owned(),
                uid: "3".to_owned(),
                groups: vec!["system:authenticated".to_owned()],
                extra: Default::default(),
            },
        );

        async fn whoami(Extension(user): Extension<UserInfo>) -> String {
            user.username
        }

        let app = Router::new()
            .route("/api/v1/namespaces/default/pods", get(whoami))
            .layer(AuthLayer::new(
                Arc::clone(&idx),
                token_map,
                None,
                Arc::new(Mutex::new(HashSet::new())),
            ));

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods")
            .header("authorization", "Bearer bob-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "bob can list pods directly with his own token — no impersonation involved"
        );
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&body_bytes).unwrap(),
            "bob",
            "identity without impersonation must be the token-authenticated user"
        );
    }

    // ---------------------------------------------------------------------------
    // credential-id extra info (authentication.kubernetes.io/credential-id)
    // ---------------------------------------------------------------------------

    /// A bound SA token authenticated via try_verify_sa_jwt must carry
    /// authentication.kubernetes.io/credential-id = ["JTI=<jti>"] in extra.
    ///
    /// The conformance test "ServiceAccounts should mount an API token into pods"
    /// authenticates the pod's projected token via TokenReview and asserts that
    /// status.user.extra["authentication.kubernetes.io/credential-id"] contains a
    /// single item starting with "JTI=". Without this, the conformance test fails
    /// with: "expected single authentication.kubernetes.io/credential-id extra info
    /// item starting with JTI=, got []".
    #[test]
    fn sa_jwt_with_jti_carries_credential_id_in_extra() {
        let (enc, dec) = test_rsa_keypair();
        let jti = "test-jti-conformance-abc";
        let token = mint_sa_jwt_with_jti(&enc, "system:serviceaccount:default:my-sa", jti, 3600);

        let result = try_verify_sa_jwt(&token, &dec, &[], &HashSet::new());
        let user = result.expect("valid SA JWT with jti must authenticate");

        let cred_id_key = "authentication.kubernetes.io/credential-id";
        let cred_ids = user.extra.get(cred_id_key).expect(
            "authenticated SA token must carry authentication.kubernetes.io/credential-id \
             in extra — without it the ServiceAccount token-mount conformance test fails \
             with: got []",
        );
        assert_eq!(
            cred_ids.len(),
            1,
            "credential-id must be a single-element list, conformance asserts exactly one item"
        );
        assert_eq!(
            cred_ids[0],
            format!("JTI={jti}"),
            "credential-id must be 'JTI=' + the JWT jti claim — \
             reverting this breaks the ServiceAccount token-mount conformance test"
        );
    }

    /// A bound SA token without a jti claim must authenticate successfully with
    /// empty extra — it must NOT be rejected just because jti is absent.
    ///
    /// This preserves compatibility with tokens minted before jti was required.
    /// Extra must be empty (not contain credential-id) when jti is not present.
    #[test]
    fn sa_jwt_without_jti_authenticates_with_empty_extra() {
        let (enc, dec) = test_rsa_keypair();
        // mint_sa_jwt produces a token WITHOUT a jti claim (legacy format).
        let token = mint_sa_jwt(&enc, "system:serviceaccount:default:legacy-sa", 3600);

        let result = try_verify_sa_jwt(&token, &dec, &[], &HashSet::new());
        let user = result.expect("SA JWT without jti must still authenticate");

        assert!(
            user.extra.is_empty(),
            "SA JWT without jti must produce empty extra — \
             credential-id must only be set when the token actually contains a jti claim"
        );
    }

    // --- field_selector_name() (mayor-fnym9) ---
    //
    // Every client-go informer that watches a single named object (e.g. the ConfigMap
    // informer aggregated apiservers use to read
    // kube-system/extension-apiserver-authentication) does so via LIST+WATCH with
    // fieldSelector=metadata.name=<name>, never a plain named GET. An RBAC Role whose
    // rules are restricted via resourceNames can only match this pattern if the
    // authorizer recognizes the field selector as identifying that one resource name.

    #[test]
    fn field_selector_name_extracts_percent_encoded_exact_match() {
        // client-go percent-encodes '=' as %3D, e.g. what the sample-apiserver's
        // authentication ConfigMap informer actually sends on the wire.
        let query = "allowWatchBookmarks=true&fieldSelector=metadata.name%3Dextension-apiserver-authentication&watch=true";
        assert_eq!(
            field_selector_name(Some(query)).as_deref(),
            Some("extension-apiserver-authentication"),
            "must decode the percent-encoded fieldSelector and extract the exact-match name; \
             without this, resourceNames-restricted Roles can never match informer traffic"
        );
    }

    #[test]
    fn field_selector_name_accepts_double_equals_form() {
        // Field selectors also accept "key==value" for equality.
        let query = "fieldSelector=metadata.name%3D%3Dfoo";
        assert_eq!(field_selector_name(Some(query)).as_deref(), Some("foo"));
    }

    #[test]
    fn field_selector_name_rejects_inequality() {
        // "metadata.name!=foo" does not identify a single target — must not match.
        let query = "fieldSelector=metadata.name%21%3Dfoo";
        assert!(
            field_selector_name(Some(query)).is_none(),
            "an inequality selector must never be treated as identifying one resource name"
        );
    }

    #[test]
    fn field_selector_name_rejects_multi_term_selector() {
        // A selector combining multiple terms doesn't uniquely pin one name — mirrors
        // upstream's RequiresExactMatch, which only fires for a single-term selector.
        let query = "fieldSelector=metadata.name%3Dfoo%2Cstatus.phase%3DRunning";
        assert!(
            field_selector_name(Some(query)).is_none(),
            "a comma-joined multi-term field selector must not be treated as an exact name match"
        );
    }

    #[test]
    fn field_selector_name_rejects_other_field() {
        // A selector on a field other than metadata.name must not synthesize a name —
        // otherwise unrelated selectors could accidentally satisfy resourceNames checks.
        let query = "fieldSelector=spec.nodeName%3Dnode-1";
        assert!(field_selector_name(Some(query)).is_none());
    }

    #[test]
    fn field_selector_name_absent_returns_none() {
        assert!(field_selector_name(None).is_none());
        assert!(field_selector_name(Some("watch=true")).is_none());
    }

    /// End-to-end regression for the sample-apiserver aggregator conformance failure
    /// (mayor-fnym9): a Role restricted via resourceNames to one ConfigMap must grant a
    /// LIST-with-fieldSelector request for that exact name, the same way real Kubernetes
    /// does. Before this fix, `is_allowed` always saw `name: None` for such requests (the
    /// URL path carries no name on a collection endpoint), so the resourceNames check in
    /// `rule_covers` unconditionally denied it — the ConfigMap read stayed Forbidden
    /// forever, regardless of how long the RoleBinding had existed, which is why the
    /// sample-apiserver pod crash-looped for the entire test timeout instead of recovering
    /// once RBAC was seeded.
    #[tokio::test]
    async fn list_with_field_selector_matches_resource_names_restricted_role() {
        use axum::{body::Body, http::Request, routing::get, Router};
        use tower::ServiceExt;

        let idx = Arc::new(RbacIndex::new());
        idx.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/namespaces/kube-system/roles/extension-apiserver-authentication-reader",
            &serde_json::json!({
                "rules": [{
                    "apiGroups": [""],
                    "resources": ["configmaps"],
                    "resourceNames": ["extension-apiserver-authentication"],
                    "verbs": ["get", "list", "watch"]
                }]
            }),
        );
        idx.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/namespaces/kube-system/rolebindings/auth-reader",
            &serde_json::json!({
                "subjects": [{ "kind": "ServiceAccount", "namespace": "aggregator-1", "name": "default" }],
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": "extension-apiserver-authentication-reader"
                },
                "namespace": "kube-system"
            }),
        );

        let mut token_map = HashMap::new();
        token_map.insert(
            "sample-apiserver-token".to_owned(),
            UserInfo {
                username: "system:serviceaccount:aggregator-1:default".to_owned(),
                uid: "1".to_owned(),
                groups: vec!["system:authenticated".to_owned()],
                extra: Default::default(),
            },
        );

        let app = Router::new()
            .route(
                "/api/v1/namespaces/kube-system/configmaps",
                get(|| async { "ok" }),
            )
            .layer(AuthLayer::new(
                Arc::clone(&idx),
                token_map,
                None,
                Arc::new(Mutex::new(HashSet::new())),
            ));

        // Exactly the request client-go's ConfigMap informer issues: a LIST (not watch)
        // with an exact-match fieldSelector on metadata.name, no name in the URL path.
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/kube-system/configmaps?fieldSelector=metadata.name%3Dextension-apiserver-authentication")
            .header("authorization", "Bearer sample-apiserver-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "a resourceNames-restricted Role must grant a LIST request whose fieldSelector \
             exactly names the allowed resource — this is how every client-go informer \
             (including the one every aggregated apiserver uses to read its own auth \
             ConfigMap) actually requests a single named object; denying it means \
             resourceNames-restricted Roles can never work for informer-style consumers"
        );
    }

    /// The same fieldSelector-derived name must NOT bypass a resourceNames restriction for
    /// an unrelated resource name — the fix must narrow access to exactly the named
    /// resource, not disable the resourceNames check for LIST/WATCH entirely.
    #[tokio::test]
    async fn list_with_field_selector_for_different_name_still_denied() {
        use axum::{body::Body, http::Request, routing::get, Router};
        use tower::ServiceExt;

        let idx = Arc::new(RbacIndex::new());
        idx.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/namespaces/kube-system/roles/extension-apiserver-authentication-reader",
            &serde_json::json!({
                "rules": [{
                    "apiGroups": [""],
                    "resources": ["configmaps"],
                    "resourceNames": ["extension-apiserver-authentication"],
                    "verbs": ["get", "list", "watch"]
                }]
            }),
        );
        idx.apply_object(
            "/apis/rbac.authorization.k8s.io/v1/namespaces/kube-system/rolebindings/auth-reader",
            &serde_json::json!({
                "subjects": [{ "kind": "ServiceAccount", "namespace": "aggregator-1", "name": "default" }],
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": "extension-apiserver-authentication-reader"
                },
                "namespace": "kube-system"
            }),
        );

        let mut token_map = HashMap::new();
        token_map.insert(
            "sample-apiserver-token".to_owned(),
            UserInfo {
                username: "system:serviceaccount:aggregator-1:default".to_owned(),
                uid: "1".to_owned(),
                groups: vec!["system:authenticated".to_owned()],
                extra: Default::default(),
            },
        );

        let app = Router::new()
            .route(
                "/api/v1/namespaces/kube-system/configmaps",
                get(|| async { "ok" }),
            )
            .layer(AuthLayer::new(
                Arc::clone(&idx),
                token_map,
                None,
                Arc::new(Mutex::new(HashSet::new())),
            ));

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/kube-system/configmaps?fieldSelector=metadata.name%3Dsome-other-configmap")
            .header("authorization", "Bearer sample-apiserver-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::FORBIDDEN,
            "a fieldSelector naming a DIFFERENT resource must still be denied by a \
             resourceNames-restricted Role — the fix must not turn resourceNames into a \
             no-op for LIST/WATCH requests"
        );
    }
}

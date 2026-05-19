// Authentication + Authorization tower middleware layer.
//
// Implements static bearer-token authentication (--token-auth-file)
// and RS256 JWT verification for service-account tokens.

use std::collections::HashMap;
use std::future::Future;
use std::io::{BufRead as _, BufReader};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tower::Layer;
use tower_service::Service;

use crate::rbac::{AuthzRequest, RbacIndex};
use crate::status::Status;

// ---------------------------------------------------------------------------
// UserInfo
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    #[allow(dead_code)]
    pub uid: String,
    pub groups: Vec<String>,
}

// ---------------------------------------------------------------------------
// JWT Claims — used for decoding inbound SA tokens
// ---------------------------------------------------------------------------

/// Minimal claim set decoded from inbound SA JWTs.
/// Must match the fields minted by `handlers::tokens::create_token`.
#[derive(Debug, Deserialize)]
struct SaClaims {
    /// Subject — format: "system:serviceaccount:<namespace>:<name>"
    sub: String,
    /// Issuer — validated against expected value.
    #[allow(dead_code)]
    iss: String,
}

// ---------------------------------------------------------------------------
// Token map — loaded once at startup
// ---------------------------------------------------------------------------

/// Parse a token-auth file into a token → UserInfo map.
///
/// File format (one line per entry, comments and empty lines skipped):
///   <token>,<username>,<uid>,<group1>[,<group2>...]
pub fn load_token_file(path: &str) -> anyhow::Result<HashMap<String, UserInfo>> {
    let file = std::fs::File::open(path)?;
    let mut map = HashMap::new();

    for (lineno, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, ',').collect();
        if parts.len() < 3 {
            tracing::warn!("token-auth-file line {}: too few fields, skipping", lineno + 1);
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

        map.insert(token, UserInfo { username, uid, groups });
    }

    Ok(map)
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
) -> AuthnResult {
    let auth_header = req.headers().get("authorization");

    match auth_header {
        None => {
            // No Authorization header → anonymous.
            AuthnResult::Identified(UserInfo {
                username: "system:anonymous".to_owned(),
                uid: String::new(),
                groups: vec!["system:unauthenticated".to_owned()],
            })
        }
        Some(value) => {
            let value = value.to_str().unwrap_or("");
            if let Some(token) = value.strip_prefix("Bearer ") {
                // 1. Check static token map first.
                if let Some(info) = token_map.get(token) {
                    return AuthnResult::Identified(info.clone());
                }
                // 2. If a SA decoding key is available, attempt JWT verification.
                if let Some(key) = sa_decoding_key {
                    if let Some(user) = try_verify_sa_jwt(token, key) {
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

/// Attempt to decode and verify a bearer token as an RS256 SA JWT.
/// Returns `Some(UserInfo)` on success, `None` if the token is invalid.
fn try_verify_sa_jwt(token: &str, key: &DecodingKey) -> Option<UserInfo> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["https://kubernetes.default.svc"]);
    validation.set_audience(&["https://kubernetes.default.svc"]);
    // No leeway: reject tokens that are even 1 second past expiry.
    validation.leeway = 0;

    match jsonwebtoken::decode::<SaClaims>(token, key, &validation) {
        Ok(data) => {
            let sub = data.claims.sub;
            tracing::debug!("SA JWT verified: sub={sub}");
            Some(UserInfo {
                username: sub,
                uid: String::new(),
                groups: vec!["system:serviceaccounts".to_owned()],
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
    matches!(path, "/healthz" | "/readyz" | "/livez" | "/api" | "/apis")
}

/// HTTP method → RBAC verb.
fn method_to_verb(method: &axum::http::Method) -> &'static str {
    match method.as_str() {
        "GET" => "get",
        "POST" => "create",
        "PUT" => "update",
        "PATCH" => "patch",
        "DELETE" => "delete",
        _ => "get",
    }
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
    let (namespace, resource, name, subresource) = if rest.first().copied() == Some("namespaces") {
        let ns = rest.get(1).copied().unwrap_or("").to_owned();
        let resource = rest.get(2).copied().unwrap_or("").to_owned();
        let name = rest.get(3).map(|s| s.to_string());
        let subresource = rest.get(4).copied().unwrap_or("").to_owned();
        (Some(ns), resource, name, subresource)
    } else {
        let resource = rest.first().copied().unwrap_or("").to_owned();
        let name = rest.get(1).map(|s| s.to_string());
        let subresource = rest.get(2).copied().unwrap_or("").to_owned();
        (None, resource, name, subresource)
    };

    ParsedPath { api_group, resource, subresource, namespace, name }
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
}

impl AuthLayer {
    pub fn new(
        rbac_index: Arc<RbacIndex>,
        token_map: HashMap<String, UserInfo>,
        sa_decoding_key: Option<Arc<DecodingKey>>,
    ) -> Self {
        AuthLayer {
            rbac_index,
            token_map: Arc::new(token_map),
            sa_decoding_key,
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
        let user = match authenticate(&req, &self.token_map, self.sa_decoding_key.as_deref()) {
            AuthnResult::Identified(u) => u,
            AuthnResult::BadToken => {
                return Box::pin(async move { Ok(unauthorized_response()) });
            }
        };

        // 2. Authorize.
        let parsed = parse_path(&path);
        let verb = method_to_verb(req.method());

        let allowed = self.rbac_index.is_allowed(&AuthzRequest {
            username: &user.username,
            groups: &user.groups,
            verb,
            api_group: &parsed.api_group,
            resource: &parsed.resource,
            subresource: &parsed.subresource,
            namespace: parsed.namespace.as_deref(),
            name: parsed.name.as_deref(),
        });

        if !allowed {
            let username = user.username.clone();
            let verb = verb.to_owned();
            let resource = parsed.resource.clone();
            return Box::pin(async move {
                Ok(forbidden_response(&username, &verb, &resource))
            });
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

    // --- authenticate() ---

    #[test]
    fn test_authn_no_header_is_anonymous() {
        // Without an Authorization header, caller must be anonymous.
        let map = HashMap::new();
        let req = make_req(Method::GET, "/api/v1/pods", None);
        let result = authenticate(&req, &map, None);
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
            },
        );
        let req = make_req(Method::GET, "/api/v1/pods", Some("Bearer secret-token"));
        match authenticate(&req, &map, None) {
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
        match authenticate(&req, &map, None) {
            AuthnResult::BadToken => {}
            AuthnResult::Identified(_) => panic!("unknown token must not succeed"),
        }
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

    // --- is_exempt() ---

    #[test]
    fn test_exempt_paths() {
        // Discovery and health paths must not require auth.
        for path in &["/healthz", "/readyz", "/livez", "/api", "/apis"] {
            assert!(is_exempt(path), "{path} must be exempt");
        }
        // Non-exempt paths must not be skipped.
        assert!(!is_exempt("/api/v1/pods"));
        assert!(!is_exempt("/apis/apps/v1/deployments"));
    }

    // --- load_token_file() ---

    #[test]
    fn test_load_token_file_parses_entries() {
        // Write a temp file and verify parsing produces the right UserInfo.
        let dir = std::env::temp_dir();
        let path = dir.join("u7s_test_tokens.csv");
        std::fs::write(
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
        let priv_pem = private_key.to_pkcs8_pem(LineEnding::LF).expect("priv pem").as_bytes().to_vec();
        let pub_pem = private_key.to_public_key().to_public_key_pem(LineEnding::LF).expect("pub pem").into_bytes();
        let enc = jsonwebtoken::EncodingKey::from_rsa_pem(&priv_pem).expect("enc key");
        let dec = jsonwebtoken::DecodingKey::from_rsa_pem(&pub_pem).expect("dec key");
        (enc, dec)
    }

    /// Mint a minimal SA JWT using the provided encoding key.
    fn mint_sa_jwt(
        enc: &jsonwebtoken::EncodingKey,
        sub: &str,
        exp_offset_secs: i64,
    ) -> String {
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
        let req = make_req(Method::GET, "/api/v1/pods", Some(&format!("Bearer {token}")));
        match authenticate(&req, &HashMap::new(), Some(&dec)) {
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

    #[test]
    fn test_authn_tampered_sa_jwt_rejected() {
        // A JWT with a tampered signature must be rejected — not silently allowed.
        // Tampering: replace last 8 chars of the token (signature portion).
        let (enc, dec) = test_rsa_keypair();
        let mut token = mint_sa_jwt(&enc, "system:serviceaccount:default:my-sa", 3600);
        let len = token.len();
        token.replace_range(len - 8.., "AAAAAAAA");
        let req = make_req(Method::GET, "/api/v1/pods", Some(&format!("Bearer {token}")));
        match authenticate(&req, &HashMap::new(), Some(&dec)) {
            AuthnResult::BadToken => {} // correct
            AuthnResult::Identified(_) => panic!("tampered JWT must not succeed"),
        }
    }

    #[test]
    fn test_authn_expired_sa_jwt_rejected() {
        // An expired JWT must be rejected — not silently allowed.
        let (enc, dec) = test_rsa_keypair();
        let token = mint_sa_jwt(&enc, "system:serviceaccount:default:my-sa", -1);
        let req = make_req(Method::GET, "/api/v1/pods", Some(&format!("Bearer {token}")));
        match authenticate(&req, &HashMap::new(), Some(&dec)) {
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
        let req = make_req(Method::GET, "/api/v1/pods", Some(&format!("Bearer {token}")));
        match authenticate(&req, &HashMap::new(), Some(&dec2)) {
            AuthnResult::BadToken => {} // correct
            AuthnResult::Identified(_) => panic!("JWT from wrong key must not succeed"),
        }
    }

    #[test]
    fn test_authn_static_token_takes_priority_over_jwt() {
        // If a token happens to be in the static map, it must use static auth,
        // not fall through to JWT parsing (which would fail on a non-JWT string).
        let mut map = HashMap::new();
        map.insert(
            "static-tok".to_owned(),
            UserInfo { username: "static-user".to_owned(), uid: "0".to_owned(), groups: vec![] },
        );
        let (enc, dec) = test_rsa_keypair();
        // Use a static token string — not a JWT — to confirm static path fires.
        let req = make_req(Method::GET, "/api/v1/pods", Some("Bearer static-tok"));
        match authenticate(&req, &map, Some(&dec)) {
            AuthnResult::Identified(u) => assert_eq!(u.username, "static-user"),
            AuthnResult::BadToken => panic!("static token must resolve"),
        }
        // Suppress unused warning in test context.
        let _ = enc;
    }
}

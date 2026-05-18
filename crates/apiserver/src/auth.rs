// Authentication + Authorization tower middleware layer.
//
// Implements static bearer-token authentication (--token-auth-file)
// and RBAC authorization via RbacIndex.  JWT/SA validation is P2-07.

use std::collections::HashMap;
use std::future::Future;
use std::io::{BufRead as _, BufReader};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
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
                match token_map.get(token) {
                    Some(info) => AuthnResult::Identified(info.clone()),
                    None => AuthnResult::BadToken,
                }
            } else {
                // Malformed Authorization header → treat as bad token.
                AuthnResult::BadToken
            }
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
}

impl AuthLayer {
    pub fn new(rbac_index: Arc<RbacIndex>, token_map: HashMap<String, UserInfo>) -> Self {
        AuthLayer {
            rbac_index,
            token_map: Arc::new(token_map),
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
        let user = match authenticate(&req, &self.token_map) {
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
        let result = authenticate(&req, &map);
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
        match authenticate(&req, &map) {
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
        match authenticate(&req, &map) {
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
}

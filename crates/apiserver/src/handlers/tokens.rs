// TokenRequest handler — POST /api/v1/namespaces/:ns/serviceaccounts/:name/token
//
// Mints an RS256 JWT for the named ServiceAccount and returns a Kubernetes
// TokenRequest response (201 Created).
//
// Safety net for projected-token refresh failures (mayor-tq5y): the JWT lifetime
// is floored at MIN_JWT_LIFETIME_SECS (24 h) regardless of the requested
// expirationSeconds.  The response still echoes the *requested* expirationSeconds
// so that kubelet's token_manager schedules refreshes at the normal interval (≈80%
// of the requested TTL).  If a refresh call fails (e.g. transient VM network
// hiccup), the existing JWT stays valid for up to 24 h instead of expiring after
// the short requested window.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use bytes::Bytes;
use jsonwebtoken::{Algorithm, Header};
use serde::{Deserialize, Serialize};
use u7s_store::Store;

use crate::{
    keys::{cluster_object_key, object_key},
    proto::{decode_k8s_proto_envelope, decode_token_request},
    state::AppState,
    status::Status,
    types::ObjectMeta,
};

// ---------------------------------------------------------------------------
// Request body (subset used by kubectl)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenRequest {
    spec: TokenRequestSpec,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenRequestSpec {
    #[serde(default = "default_expiration")]
    expiration_seconds: u64,
    #[serde(default)]
    audiences: Vec<String>,
    #[serde(default)]
    bound_object_ref: Option<serde_json::Value>,
}

fn default_expiration() -> u64 {
    3607
}

/// Minimum actual JWT lifetime regardless of the requested expirationSeconds.
///
/// Kubelet's token_manager schedules token refreshes based on `spec.expirationSeconds`
/// from the TokenRequest *response* (not the JWT `exp` claim).  By flooring the JWT
/// lifetime at 24 h we ensure that if kubelet fails to deliver a refresh (transient
/// network partition, apiserver restart, etc.) the existing JWT remains valid for the
/// full duration of a typical conformance run without requiring a successful refresh
/// every ~48 min.
pub(crate) const MIN_JWT_LIFETIME_SECS: u64 = 86_400; // 24 h

// ---------------------------------------------------------------------------
// JWT claims
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct KubernetesClaims {
    /// Unique token ID used for revocation. Checked against AppState::revoked_jtis on every request.
    jti: String,
    iss: String,
    sub: String,
    aud: Vec<String>,
    exp: u64,
    iat: u64,
    /// Unique token ID — enables per-token revocation and replay detection.
    /// Each minted token gets a fresh UUID v4 so even two tokens for the same
    /// SA issued at the same second are distinct.
    jti: String,
    #[serde(rename = "kubernetes.io")]
    kubernetes_io: KubernetesClaimsExt,
}

#[derive(Serialize)]
struct KubernetesClaimsExt {
    namespace: String,
    serviceaccount: SaRef,
}

#[derive(Serialize)]
struct SaRef {
    name: String,
    uid: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub async fn create_token<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, sa_name)): Path<(String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    // 1. Validate namespace exists.
    let ns = crate::types::Namespace::parse(&raw_ns).map_err(Status::bad_request)?;
    let ns_key = cluster_object_key("namespaces", ns.as_str());
    let ns_exists = state
        .store
        .get(&ns_key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .is_some();
    if !ns_exists {
        return Err(Status::not_found(ns.as_str(), "Namespace"));
    }

    // 2. Validate ServiceAccount exists.
    let sa_key = object_key("serviceaccounts", ns.as_str(), &sa_name);
    let sa = state
        .store
        .get(&sa_key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&sa_name, "ServiceAccount"))?;

    // 3. Require a signing key.
    let encoding_key = state
        .sa_key
        .as_ref()
        .ok_or_else(|| Status::internal("SA signing key not available".into()))?;

    // 4. Parse request body.
    //    kubectl 1.31+ sends Content-Type: application/vnd.kubernetes.protobuf for subresource
    //    POSTs. The k8s proto envelope's inner raw bytes are a native protobuf TokenRequest,
    //    not JSON. Detect the envelope and decode via the proto path; fall back to JSON otherwise.
    let mut spec = if body.is_empty() {
        TokenRequestSpec {
            expiration_seconds: default_expiration(),
            audiences: vec!["https://kubernetes.default.svc".to_owned()],
            bound_object_ref: None,
        }
    } else if let Some(env) = decode_k8s_proto_envelope(&body) {
        // Proto path: inner raw is a protobuf-encoded TokenRequest.
        let fields = decode_token_request(&env.raw)
            .ok_or_else(|| Status::bad_request("invalid protobuf TokenRequest".into()))?;
        TokenRequestSpec {
            expiration_seconds: fields.expiration_seconds.unwrap_or_else(default_expiration),
            audiences: fields.audiences,
            bound_object_ref: fields.bound_object_ref,
        }
    } else {
        // JSON path: body is plain JSON (older kubectl, direct API calls).
        let req: TokenRequest = serde_json::from_slice(&body)
            .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;
        req.spec
    };
    if spec.audiences.is_empty() {
        spec.audiences = vec!["https://kubernetes.default.svc".to_owned()];
    }

    // Clamp expiration to Kubernetes-specified range: [600, 172800] (10 min to 48 h).
    spec.expiration_seconds = spec.expiration_seconds.clamp(600, 172_800);

    // 5. Extract UID from the stored ServiceAccount object.
    let uid = serde_json::from_slice::<serde_json::Value>(&sa.value)
        .ok()
        .and_then(|v| {
            let meta: ObjectMeta =
                serde_json::from_value(v["metadata"].clone()).unwrap_or_default();
            meta.uid
        })
        .unwrap_or_default();

    // 6. Mint JWT.
    //
    // The JWT `exp` is floored at MIN_JWT_LIFETIME_SECS (24 h) as a safety net for
    // transient refresh failures (mayor-tq5y).  The response still returns the
    // caller-requested `expirationSeconds` so that kubelet's token_manager schedules
    // refreshes at the normal short interval.  If a refresh attempt fails, the
    // existing JWT stays valid for up to 24 h.
    let now = unix_now();
    let jwt_lifetime = spec.expiration_seconds.max(MIN_JWT_LIFETIME_SECS);
    let jwt_exp = now + jwt_lifetime;
    tracing::debug!(
        ns = ns.as_str(),
        sa = %sa_name,
        requested_secs = spec.expiration_seconds,
        jwt_lifetime_secs = jwt_lifetime,
        "TokenRequest: minting SA JWT"
    );
    let claims = KubernetesClaims {
        jti: uuid::Uuid::new_v4().to_string(),
        iss: "https://kubernetes.default.svc".to_owned(),
        sub: format!("system:serviceaccount:{}:{}", ns.as_str(), sa_name),
        aud: spec.audiences,
        exp: jwt_exp,
        iat: now,
        jti: uuid::Uuid::new_v4().to_string(),
        kubernetes_io: KubernetesClaimsExt {
            namespace: ns.as_str().to_owned(),
            serviceaccount: SaRef {
                name: sa_name.clone(),
                uid,
            },
        },
    };

    let header = Header::new(Algorithm::RS256);
    let token = jsonwebtoken::encode(&header, &claims, encoding_key)
        .map_err(|e| Status::internal(format!("JWT encode error: {e}")))?;

    // 7. Build response.
    // Include spec.expirationSeconds and spec.audiences in the response so that kubelet's
    // token_manager can read them. Kubelet reads spec.expirationSeconds to schedule token
    // refresh; if absent it logs "Expiration seconds was nil for token request" and falls back.
    // Echo spec.boundObjectRef from the request so kubelet's DeleteServiceAccountToken can
    // access BoundObjectRef.UID without a nil-pointer dereference (token_manager.go:139).
    //
    // expirationTimestamp uses the requested (short) lifetime so kubelet computes the
    // correct refresh window.  The JWT itself uses jwt_exp (≥ 24 h) as the safety net.
    let expiration_timestamp = secs_to_rfc3339(now + spec.expiration_seconds);
    let mut spec_resp = serde_json::json!({
        "audiences": claims.aud,
        "expirationSeconds": spec.expiration_seconds
    });
    if let Some(bor) = spec.bound_object_ref {
        spec_resp["boundObjectRef"] = bor;
    }
    let resp = serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": spec_resp,
        "status": {
            "token": token,
            "expirationTimestamp": expiration_timestamp
        }
    });

    Ok((StatusCode::CREATED, Json(resp)))
}

// ---------------------------------------------------------------------------
// Time helpers (no chrono dep)
// ---------------------------------------------------------------------------

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

use crate::util::secs_to_rfc3339;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// secs_to_rfc3339 must produce correct date for a known epoch offset.
    /// 2024-01-01T00:00:00Z = 1704067200 seconds since epoch.
    #[test]
    fn rfc3339_known_date() {
        assert_eq!(secs_to_rfc3339(1_704_067_200), "2024-01-01T00:00:00Z");
    }

    /// secs_to_rfc3339 must handle the Unix epoch itself.
    #[test]
    fn rfc3339_epoch() {
        assert_eq!(secs_to_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    /// secs_to_rfc3339 must handle a leap year correctly (2000 is a leap year).
    /// 2000-02-29T00:00:00Z = 951782400 seconds since epoch.
    #[test]
    fn rfc3339_leap_year_feb29() {
        assert_eq!(secs_to_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    /// default_expiration must be 3607 seconds, matching upstream Kubernetes default.
    /// The 7-second offset from 1 hour is intentional in upstream to avoid thundering herd:
    /// different SAs requesting the default get slightly different actual lifetimes due to
    /// clock skew, preventing all tokens from expiring at the same instant.
    #[test]
    fn default_expiration_is_3607() {
        assert_eq!(default_expiration(), 3607);
    }

    /// unix_now must return a plausible timestamp (after 2024-01-01).
    #[test]
    fn unix_now_is_recent() {
        let now = unix_now();
        // 2024-01-01T00:00:00Z
        assert!(
            now > 1_704_067_200,
            "unix_now() returned implausibly old timestamp: {now}"
        );
    }

    /// JWT claims serialise with the correct field names, including the
    /// kubernetes.io extension claim — critical because miscased field names
    /// would cause token validation failures.
    #[test]
    fn claims_serialize_field_names() {
        let claims = KubernetesClaims {
            jti: "test-jti-1".to_owned(),
            iss: "https://kubernetes.default.svc".to_owned(),
            sub: "system:serviceaccount:default:my-sa".to_owned(),
            aud: vec!["https://kubernetes.default.svc".to_owned()],
            exp: 1_704_070_800,
            iat: 1_704_067_200,
            jti: "test-jti-value".to_owned(),
            kubernetes_io: KubernetesClaimsExt {
                namespace: "default".to_owned(),
                serviceaccount: SaRef {
                    name: "my-sa".to_owned(),
                    uid: String::new(),
                },
            },
        };

        let v: serde_json::Value = serde_json::to_value(&claims).unwrap();
        assert_eq!(v["iss"], "https://kubernetes.default.svc");
        assert_eq!(v["sub"], "system:serviceaccount:default:my-sa");
        assert!(v["aud"].is_array());
        // The renamed field must appear as "kubernetes.io"
        assert!(
            v["kubernetes.io"].is_object(),
            "kubernetes.io claim must be present"
        );
        assert_eq!(v["kubernetes.io"]["namespace"], "default");
        assert_eq!(v["kubernetes.io"]["serviceaccount"]["name"], "my-sa");
        assert_eq!(
            v["jti"], "test-jti-value",
            "jti claim must be serialised so it appears in minted tokens"
        );
    }

    /// SA UID must appear in the kubernetes.io.serviceaccount.uid claim so that
    /// token recipients can correlate the token to a specific SA object. An empty
    /// UID breaks the Kubernetes token projection contract.
    #[test]
    fn claims_serialize_sa_uid() {
        let claims = KubernetesClaims {
            jti: "test-jti-2".to_owned(),
            iss: "https://kubernetes.default.svc".to_owned(),
            sub: "system:serviceaccount:kube-system:coredns".to_owned(),
            aud: vec!["https://kubernetes.default.svc".to_owned()],
            exp: 1_704_070_800,
            iat: 1_704_067_200,
            jti: "test-jti".to_owned(),
            kubernetes_io: KubernetesClaimsExt {
                namespace: "kube-system".to_owned(),
                serviceaccount: SaRef {
                    name: "coredns".to_owned(),
                    uid: "abc-123".to_owned(),
                },
            },
        };

        let v: serde_json::Value = serde_json::to_value(&claims).unwrap();
        assert_eq!(
            v["kubernetes.io"]["serviceaccount"]["uid"], "abc-123",
            "SA UID must be propagated into JWT claims"
        );
    }

    /// expiration_seconds must be clamped to [600, 172800] (Kubernetes spec).
    /// A value below 600 must become 600; a value above 172800 must become 172800.
    /// Without clamping, tokens could be minted with arbitrarily long or zero TTLs.
    #[test]
    fn expiration_seconds_clamped() {
        assert_eq!(
            u64::MAX.clamp(600, 172_800),
            172_800,
            "overflow must clamp to max"
        );
        assert_eq!(1u64.clamp(600, 172_800), 600, "underflow must clamp to min");
        assert_eq!(
            3600u64.clamp(600, 172_800),
            3600,
            "in-range value must be unchanged"
        );
    }
}

// ---------------------------------------------------------------------------
// Handler-level tests — exercise create_token end-to-end with an in-memory
// store so every error path in the handler is reachable from tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod handler_tests {
    use std::sync::Arc;

    use axum::{
        extract::{Path, State},
        response::IntoResponse,
    };
    use bytes::Bytes;
    use u7s_store::{SqliteStore, Store};

    use super::*;
    use crate::state::AppState;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build AppState without an SA signing key (covers the "key unavailable" path).
    fn make_state_no_key() -> (AppState, Arc<SqliteStore>) {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        (state, store)
    }

    /// Build AppState with a freshly generated RSA signing key.
    fn make_state_with_key() -> (AppState, Arc<SqliteStore>) {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        let mut rng = rsa::rand_core::OsRng;
        let rsa_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
        let priv_pem = rsa_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("priv pem")
            .as_bytes()
            .to_vec();
        let pub_pem = rsa_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("pub pem")
            .into_bytes();
        let enc_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(&priv_pem).expect("encoding key from pem");
        let dec_key =
            jsonwebtoken::DecodingKey::from_rsa_pem(&pub_pem).expect("decoding key from pem");

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            Some(enc_key),
            Some(dec_key),
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        (state, store)
    }

    async fn seed_namespace(store: &Arc<SqliteStore>, ns: &str) {
        let key = format!("/registry/namespaces/{ns}");
        let val = serde_json::json!({"kind": "Namespace", "metadata": {"name": ns}});
        store
            .put(&key, Bytes::from(serde_json::to_vec(&val).unwrap()), None)
            .await
            .expect("seed namespace");
    }

    async fn seed_serviceaccount(store: &Arc<SqliteStore>, ns: &str, name: &str, uid: &str) {
        let key = format!("/registry/serviceaccounts/{ns}/{name}");
        let val = serde_json::json!({
            "kind": "ServiceAccount",
            "metadata": {"name": name, "namespace": ns, "uid": uid}
        });
        store
            .put(&key, Bytes::from(serde_json::to_vec(&val).unwrap()), None)
            .await
            .expect("seed serviceaccount");
    }

    /// Collect the response body bytes from an `impl IntoResponse`.
    async fn collect_body(r: impl IntoResponse) -> serde_json::Value {
        let resp = r.into_response();
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body collect");
        serde_json::from_slice(&b).expect("response must be valid JSON")
    }

    /// base64url-decode a JWT claims section (middle dot-separated part) and parse as JSON.
    fn decode_jwt_claims(token: &str) -> serde_json::Value {
        use base64::Engine;
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have three dot-separated parts");
        let claims_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("claims must be valid base64url");
        serde_json::from_slice(&claims_json).expect("claims must be valid JSON")
    }

    // -----------------------------------------------------------------------
    // create_token — error paths
    // -----------------------------------------------------------------------

    /// An invalid namespace name (e.g. containing uppercase) must return 400 BadRequest.
    /// create_token calls Namespace::parse which rejects names that violate DNS label rules.
    /// Without this gate, invalid namespace names could be used to probe the store.
    #[tokio::test]
    async fn create_token_invalid_namespace_returns_400() {
        let (state, _store) = make_state_no_key();
        let result = create_token(
            State(state),
            Path(("INVALID_NS".to_owned(), "my-sa".to_owned())),
            Bytes::new(),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("invalid namespace must be rejected"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::BAD_REQUEST,
            "invalid namespace must yield 400 BadRequest"
        );
    }

    /// A valid namespace that does not exist in the store must return 404 NotFound.
    /// The namespace existence check prevents token issuance for non-existent namespaces,
    /// which would allow callers to mint tokens scoped to phantom namespaces.
    #[tokio::test]
    async fn create_token_missing_namespace_returns_404() {
        let (state, _store) = make_state_no_key();
        let result = create_token(
            State(state),
            Path(("default".to_owned(), "my-sa".to_owned())),
            Bytes::new(),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("missing namespace must be rejected"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::NOT_FOUND,
            "missing namespace must yield 404 NotFound"
        );
        assert!(
            err.1.message.contains("Namespace"),
            "error message must name the missing resource kind"
        );
    }

    /// A valid namespace that exists but whose ServiceAccount does not must return 404.
    /// Token minting for a non-existent ServiceAccount is forbidden — the SA must exist
    /// in the cluster for the token to be meaningful.
    #[tokio::test]
    async fn create_token_missing_serviceaccount_returns_404() {
        let (state, store) = make_state_no_key();
        seed_namespace(&store, "default").await;

        let result = create_token(
            State(state),
            Path(("default".to_owned(), "ghost-sa".to_owned())),
            Bytes::new(),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("missing SA must be rejected"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::NOT_FOUND,
            "missing ServiceAccount must yield 404 NotFound"
        );
        assert!(
            err.1.message.contains("ServiceAccount"),
            "error message must name the missing kind"
        );
    }

    /// When no SA signing key is configured, create_token must return 500 InternalServerError.
    /// Without this gate a nil-key panic could crash the process; this path ensures a clean
    /// error response instead.
    #[tokio::test]
    async fn create_token_no_signing_key_returns_500() {
        let (state, store) = make_state_no_key();
        seed_namespace(&store, "default").await;
        seed_serviceaccount(&store, "default", "my-sa", "uid-1").await;

        let result = create_token(
            State(state),
            Path(("default".to_owned(), "my-sa".to_owned())),
            Bytes::new(),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("missing signing key must return an error"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "missing signing key must yield 500 InternalServerError"
        );
        assert!(
            err.1.message.contains("signing key"),
            "error message must mention the missing signing key"
        );
    }

    /// A malformed JSON request body must return 400 BadRequest.
    /// The handler parses the body only when it is non-empty; an invalid JSON body
    /// must be rejected before any token minting occurs.
    #[tokio::test]
    async fn create_token_malformed_json_body_returns_400() {
        let (state, store) = make_state_with_key();
        seed_namespace(&store, "default").await;
        seed_serviceaccount(&store, "default", "my-sa", "uid-2").await;

        let result = create_token(
            State(state),
            Path(("default".to_owned(), "my-sa".to_owned())),
            Bytes::from_static(b"{not valid json"),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("malformed JSON must be rejected"),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::BAD_REQUEST,
            "malformed JSON body must yield 400 BadRequest"
        );
        assert!(
            err.1.message.contains("invalid JSON"),
            "error message must mention invalid JSON"
        );
    }

    // -----------------------------------------------------------------------
    // create_token — happy paths
    // -----------------------------------------------------------------------

    /// An empty body must succeed: create_token must use the default audience and 3600s TTL.
    /// kubectl omits the request body in some versions; the handler must treat an absent body
    /// identically to the Kubernetes-defaults body.
    #[tokio::test]
    async fn create_token_empty_body_uses_defaults_and_returns_201() {
        let (state, store) = make_state_with_key();
        seed_namespace(&store, "default").await;
        seed_serviceaccount(&store, "default", "my-sa", "uid-3").await;

        let result = create_token(
            State(state),
            Path(("default".to_owned(), "my-sa".to_owned())),
            Bytes::new(),
        )
        .await;
        let resp = match result {
            Ok(r) => r.into_response(),
            Err(e) => panic!("empty-body token request must succeed: status={}", e.0),
        };

        assert_eq!(
            resp.status(),
            axum::http::StatusCode::CREATED,
            "successful token request must return 201 Created"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body collect");
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        let token = body["status"]["token"]
            .as_str()
            .expect("response must contain status.token");
        assert!(!token.is_empty(), "minted token must not be empty");

        let exp_ts = body["status"]["expirationTimestamp"]
            .as_str()
            .expect("response must contain status.expirationTimestamp");
        assert!(!exp_ts.is_empty(), "expirationTimestamp must not be empty");

        assert_eq!(
            body["kind"], "TokenRequest",
            "response kind must be TokenRequest"
        );
        assert_eq!(
            body["apiVersion"], "authentication.k8s.io/v1",
            "response apiVersion must be authentication.k8s.io/v1"
        );
    }

    /// A body with an explicit audience list must mint a token with those audiences.
    /// kubelet and admission webhooks supply explicit audiences; the token's `aud` claim
    /// must match exactly so validators can enforce audience-based access control.
    #[tokio::test]
    async fn create_token_explicit_audience_appears_in_token() {
        let (state, store) = make_state_with_key();
        seed_namespace(&store, "default").await;
        seed_serviceaccount(&store, "default", "my-sa", "uid-4").await;

        let req_body = serde_json::json!({
            "spec": {
                "expirationSeconds": 7200,
                "audiences": ["https://my-app.example.com"]
            }
        });

        let result = create_token(
            State(state),
            Path(("default".to_owned(), "my-sa".to_owned())),
            Bytes::from(serde_json::to_vec(&req_body).unwrap()),
        )
        .await;
        let resp_body = match result {
            Ok(r) => collect_body(r).await,
            Err(e) => panic!(
                "explicit-audience token request must succeed: status={}",
                e.0
            ),
        };

        let token = resp_body["status"]["token"]
            .as_str()
            .expect("token must be present");
        let claims = decode_jwt_claims(token);

        assert_eq!(
            claims["aud"][0], "https://my-app.example.com",
            "explicit audience must appear in JWT aud claim"
        );
    }

    /// A body with an empty audiences list must fall back to the default kubernetes audience.
    /// The Kubernetes TokenRequest spec says an empty audiences list means the default audience;
    /// omitting this fallback would produce tokens that no standard validator accepts.
    #[tokio::test]
    async fn create_token_empty_audiences_filled_with_default() {
        let (state, store) = make_state_with_key();
        seed_namespace(&store, "default").await;
        seed_serviceaccount(&store, "default", "my-sa", "uid-5").await;

        let req_body = serde_json::json!({
            "spec": {
                "audiences": []
            }
        });

        let result = create_token(
            State(state),
            Path(("default".to_owned(), "my-sa".to_owned())),
            Bytes::from(serde_json::to_vec(&req_body).unwrap()),
        )
        .await;
        let resp_body = match result {
            Ok(r) => collect_body(r).await,
            Err(e) => panic!("empty-audiences token request must succeed: status={}", e.0),
        };

        let token = resp_body["status"]["token"]
            .as_str()
            .expect("token must be present");
        let claims = decode_jwt_claims(token);

        assert_eq!(
            claims["aud"][0], "https://kubernetes.default.svc",
            "empty audiences must default to https://kubernetes.default.svc"
        );
    }

    /// The SA UID from the store must be embedded in the minted token's kubernetes.io claim.
    /// Without the UID, token recipients cannot distinguish tokens minted for different SA
    /// objects that share the same name across successive create/delete cycles.
    #[tokio::test]
    async fn create_token_sa_uid_embedded_in_jwt_claims() {
        let (state, store) = make_state_with_key();
        seed_namespace(&store, "kube-system").await;
        seed_serviceaccount(&store, "kube-system", "coredns", "uid-coredns-42").await;

        let result = create_token(
            State(state),
            Path(("kube-system".to_owned(), "coredns".to_owned())),
            Bytes::new(),
        )
        .await;
        let resp_body = match result {
            Ok(r) => collect_body(r).await,
            Err(e) => panic!(
                "token request for kube-system/coredns must succeed: status={}",
                e.0
            ),
        };

        let token = resp_body["status"]["token"]
            .as_str()
            .expect("token must be present");
        let claims = decode_jwt_claims(token);

        assert_eq!(
            claims["kubernetes.io"]["serviceaccount"]["uid"], "uid-coredns-42",
            "SA UID from store must appear in JWT kubernetes.io.serviceaccount.uid"
        );
        assert_eq!(
            claims["kubernetes.io"]["namespace"], "kube-system",
            "namespace must appear in JWT kubernetes.io.namespace"
        );
        assert_eq!(
            claims["sub"], "system:serviceaccount:kube-system:coredns",
            "sub claim must be the canonical service account subject"
        );
    }

    /// A protobuf-encoded TokenRequest body (as sent by kubectl 1.31+) must be decoded
    /// and produce a JWT whose `aud` claim matches the audience in the proto body.
    ///
    /// This is the primary regression test for mayor-hy77: kubectl 1.31+ always sends
    /// Content-Type: application/vnd.kubernetes.protobuf for subresource POSTs, and the
    /// handler was previously failing with "invalid JSON: expected value at line 1 column 1".
    ///
    /// The proto body is constructed by hand (no prost/protobuf dep) matching the wire format:
    ///   k8s magic (4 bytes)
    ///   Unknown envelope field 2 (raw bytes):
    ///     TokenRequest field 2 (spec):
    ///       field 1 (audiences): one string entry
    #[tokio::test]
    async fn create_token_proto_body_succeeds() {
        let (state, store) = make_state_with_key();
        seed_namespace(&store, "default").await;
        seed_serviceaccount(&store, "default", "my-sa", "uid-proto-test").await;

        // Build a minimal protobuf-encoded TokenRequest by hand.
        // Audience string to encode:
        let audience = b"https://kubernetes.default.svc.cluster.local";

        // TokenRequestSpec field 1 (audience, wire type 2):
        //   tag = (1 << 3) | 2 = 0x0a
        let mut spec_bytes = Vec::new();
        spec_bytes.push(0x0a); // field 1, wire type 2
        spec_bytes.push(audience.len() as u8); // length varint (fits in 1 byte)
        spec_bytes.extend_from_slice(audience);

        // TokenRequest field 2 (spec, wire type 2):
        //   tag = (2 << 3) | 2 = 0x12
        let mut token_request_bytes = Vec::new();
        token_request_bytes.push(0x12); // field 2, wire type 2
        token_request_bytes.push(spec_bytes.len() as u8);
        token_request_bytes.extend_from_slice(&spec_bytes);

        // k8s Unknown envelope field 2 (raw, wire type 2):
        //   tag = (2 << 3) | 2 = 0x12
        let mut envelope_bytes = Vec::new();
        envelope_bytes.push(0x12); // field 2, wire type 2
        envelope_bytes.push(token_request_bytes.len() as u8);
        envelope_bytes.extend_from_slice(&token_request_bytes);

        // Full body: k8s magic + envelope.
        let mut body = vec![0x6b, 0x38, 0x73, 0x00]; // k8s proto magic
        body.extend_from_slice(&envelope_bytes);

        let result = create_token(
            State(state),
            Path(("default".to_owned(), "my-sa".to_owned())),
            Bytes::from(body),
        )
        .await;
        let resp_body = match result {
            Ok(r) => collect_body(r).await,
            Err(e) => panic!(
                "proto-body token request must succeed: status={} message={}",
                e.0, e.1.message
            ),
        };

        let token = resp_body["status"]["token"]
            .as_str()
            .expect("token must be present in response");
        let claims = decode_jwt_claims(token);

        assert_eq!(
            claims["aud"][0], "https://kubernetes.default.svc.cluster.local",
            "audience from protobuf body must appear in JWT aud claim"
        );
    }

    /// Regression test for mayor-0awf: when a TokenRequest body includes spec.boundObjectRef,
    /// the response must echo it back in spec.boundObjectRef.
    ///
    /// kubelet's DeleteServiceAccountToken (token_manager.go:139) accesses
    /// tr.Spec.BoundObjectRef.UID for every cached token on pod teardown. If boundObjectRef is
    /// absent from the response, the cached entry has a nil pointer, causing a panic and
    /// preventing pod cleanup. The real kube-apiserver always echoes this field back.
    ///
    /// This test will fail if the boundObjectRef echo is removed from create_token.
    #[tokio::test]
    async fn create_token_echoes_bound_object_ref() {
        let (state, store) = make_state_with_key();
        seed_namespace(&store, "default").await;
        seed_serviceaccount(&store, "default", "my-sa", "uid-bor-test").await;

        let req_body = serde_json::json!({
            "spec": {
                "audiences": ["https://kubernetes.default.svc"],
                "expirationSeconds": 3607,
                "boundObjectRef": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "name": "my-pod",
                    "uid": "pod-uid-abc-123"
                }
            }
        });

        let result = create_token(
            State(state),
            Path(("default".to_owned(), "my-sa".to_owned())),
            Bytes::from(serde_json::to_vec(&req_body).unwrap()),
        )
        .await;
        let resp_body = match result {
            Ok(r) => collect_body(r).await,
            Err(e) => panic!(
                "token request with boundObjectRef must succeed: status={} message={}",
                e.0, e.1.message
            ),
        };

        // spec.boundObjectRef must be present — without it kubelet panics at token_manager.go:139
        let bor = &resp_body["spec"]["boundObjectRef"];
        assert!(
            bor.is_object(),
            "spec.boundObjectRef must be present in response to prevent kubelet nil-pointer panic (mayor-0awf)"
        );
        assert_eq!(
            bor["kind"], "Pod",
            "boundObjectRef.kind must be echoed from request"
        );
        assert_eq!(
            bor["name"], "my-pod",
            "boundObjectRef.name must be echoed from request"
        );
        assert_eq!(
            bor["uid"], "pod-uid-abc-123",
            "boundObjectRef.uid must be echoed — kubelet reads this to identify the bound pod"
        );
        assert_eq!(
            bor["apiVersion"], "v1",
            "boundObjectRef.apiVersion must be echoed from request"
        );
    }

    /// When a TokenRequest body omits spec.boundObjectRef, the response must not fabricate one.
    /// Only echo what the caller sends — do not invent a boundObjectRef when the request omits it.
    #[tokio::test]
    async fn create_token_omits_bound_object_ref_when_absent() {
        let (state, store) = make_state_with_key();
        seed_namespace(&store, "default").await;
        seed_serviceaccount(&store, "default", "my-sa", "uid-no-bor").await;

        let req_body = serde_json::json!({
            "spec": {
                "audiences": ["https://kubernetes.default.svc"],
                "expirationSeconds": 3607
            }
        });

        let result = create_token(
            State(state),
            Path(("default".to_owned(), "my-sa".to_owned())),
            Bytes::from(serde_json::to_vec(&req_body).unwrap()),
        )
        .await;
        let resp_body = match result {
            Ok(r) => collect_body(r).await,
            Err(e) => panic!(
                "token request without boundObjectRef must succeed: status={}",
                e.0
            ),
        };

        assert!(
            resp_body["spec"]["boundObjectRef"].is_null(),
            "spec.boundObjectRef must be absent when not sent in request (must not fabricate)"
        );
    }

    /// A very short expiration (below 600s) must be clamped to 600s by the handler.
    /// This prevents tokens with zero or near-zero TTLs from being minted, which would
    /// be rejected by validators and could cause tight kubelet refresh loops.
    #[tokio::test]
    async fn create_token_short_expiration_clamped_to_600() {
        let (state, store) = make_state_with_key();
        seed_namespace(&store, "default").await;
        seed_serviceaccount(&store, "default", "my-sa", "uid-6").await;

        let req_body = serde_json::json!({
            "spec": {
                "expirationSeconds": 1
            }
        });

        let result = create_token(
            State(state),
            Path(("default".to_owned(), "my-sa".to_owned())),
            Bytes::from(serde_json::to_vec(&req_body).unwrap()),
        )
        .await;
        let resp_body = match result {
            Ok(r) => collect_body(r).await,
            Err(e) => panic!(
                "short-expiration token request must succeed (after clamping): status={}",
                e.0
            ),
        };

        let token = resp_body["status"]["token"]
            .as_str()
            .expect("token must be present");
        let claims = decode_jwt_claims(token);

        let iat = claims["iat"].as_u64().expect("iat must be present");
        let exp = claims["exp"].as_u64().expect("exp must be present");
        assert!(
            exp - iat >= 600,
            "expiration must be clamped to at least 600s, got exp-iat={}",
            exp - iat
        );
    }

    /// Regression test for mayor-o30k: response must include spec.expirationSeconds so kubelet's
    /// token_manager can schedule token refresh without falling back.
    ///
    /// Kubelet reads spec.expirationSeconds from the TokenRequest response to know when to
    /// refresh. If absent it logs "Expiration seconds was nil for token request" and uses a
    /// conservative fallback, causing unnecessary kubelet–apiserver round-trips. Without
    /// spec.expirationSeconds in the response this test will fail, re-exposing the bug.
    #[tokio::test]
    async fn create_token_response_includes_spec_expiration_seconds() {
        let (state, store) = make_state_with_key();
        seed_namespace(&store, "default").await;
        seed_serviceaccount(&store, "default", "my-sa", "uid-spec-test").await;

        let req_body = serde_json::json!({
            "spec": {
                "expirationSeconds": 600
            }
        });

        let result = create_token(
            State(state),
            Path(("default".to_owned(), "my-sa".to_owned())),
            Bytes::from(serde_json::to_vec(&req_body).unwrap()),
        )
        .await;
        let resp_body = match result {
            Ok(r) => collect_body(r).await,
            Err(e) => panic!(
                "token request must succeed: status={} message={}",
                e.0, e.1.message
            ),
        };

        // status.token must be non-empty.
        let token = resp_body["status"]["token"]
            .as_str()
            .expect("status.token must be present");
        assert!(!token.is_empty(), "status.token must not be empty");

        // status.expirationTimestamp must be present — kubelet uses it to know the absolute expiry.
        let exp_ts = resp_body["status"]["expirationTimestamp"]
            .as_str()
            .expect("status.expirationTimestamp must be present");
        assert!(
            !exp_ts.is_empty(),
            "status.expirationTimestamp must not be empty"
        );

        // spec.expirationSeconds must be echoed back — kubelet reads this to schedule refresh.
        // Without it, kubelet logs "Expiration seconds was nil for token request".
        let resp_exp_secs = resp_body["spec"]["expirationSeconds"]
            .as_u64()
            .expect("spec.expirationSeconds must be present in response (mayor-o30k regression)");
        assert_eq!(
            resp_exp_secs, 600,
            "spec.expirationSeconds in response must match the requested value"
        );

        // spec.audiences must also be present.
        assert!(
            resp_body["spec"]["audiences"].is_array(),
            "spec.audiences must be present in response"
        );

        // status.expirationTimestamp must be approximately now + 600s.
        // Parse the RFC3339 timestamp and verify it's in the expected range.
        let parsed = exp_ts.trim_end_matches('Z');
        assert!(
            parsed.contains('T'),
            "expirationTimestamp must be in RFC3339 format"
        );
    }

    /// Every minted SA JWT must contain a non-empty jti (JWT ID) claim.
    ///
    /// The jti claim uniquely identifies each minted token. Without it, a leaked token
    /// cannot be invalidated before its 24 h expiry — the entire token space for a given
    /// SA within its TTL is a single credential. With jti, a revocation store can
    /// reject individual tokens by ID. This test fails if jti is removed from the claims.
    #[tokio::test]
    async fn create_token_jwt_has_jti_claim() {
        let (state, store) = make_state_with_key();
        seed_namespace(&store, "default").await;
        seed_serviceaccount(&store, "default", "my-sa", "uid-jti-test").await;

        let result = create_token(
            State(state),
            Path(("default".to_owned(), "my-sa".to_owned())),
            Bytes::new(),
        )
        .await;
        let resp_body = match result {
            Ok(r) => collect_body(r).await,
            Err(e) => panic!("token request must succeed: status={}", e.0),
        };

        let token = resp_body["status"]["token"]
            .as_str()
            .expect("status.token must be present");
        let claims = decode_jwt_claims(token);

        let jti = claims["jti"].as_str().unwrap_or("");
        assert!(
            !jti.is_empty(),
            "minted SA JWT must contain a non-empty jti claim — \
             without jti, leaked tokens cannot be individually revoked before expiry"
        );
        assert_eq!(
            jti.len(),
            36,
            "jti must be a UUID (36 chars including hyphens), got: {jti:?}"
        );
    }

    /// Two successive token requests must produce JWTs with different jti values.
    ///
    /// If two tokens share the same jti, a revocation store cannot distinguish them —
    /// revoking one would revoke the other, or neither. Each token must be individually
    /// addressable. This test fails if jti is a constant or derived from non-random data.
    #[tokio::test]
    async fn create_token_successive_mints_have_unique_jti() {
        let (state, store) = make_state_with_key();
        seed_namespace(&store, "default").await;
        seed_serviceaccount(&store, "default", "my-sa", "uid-jti-unique").await;

        let mint = |state: AppState| async move {
            let result = create_token(
                State(state),
                Path(("default".to_owned(), "my-sa".to_owned())),
                Bytes::new(),
            )
            .await
            .expect("mint must succeed");
            let body = collect_body(result).await;
            let token = body["status"]["token"]
                .as_str()
                .expect("token must be present")
                .to_owned();
            let claims = decode_jwt_claims(&token);
            claims["jti"]
                .as_str()
                .expect("jti must be present")
                .to_owned()
        };

        let jti1 = mint(state.clone()).await;
        let jti2 = mint(state).await;

        assert_ne!(
            jti1, jti2,
            "successive token mints for the same SA must produce different jti values — \
             duplicate jti values prevent individual token revocation"
        );
    }

    /// Regression test for mayor-tq5y: JWT lifetime must be floored at 24 h even when
    /// a shorter expirationSeconds is requested.
    ///
    /// Kubelet schedules token refreshes based on spec.expirationSeconds from the response.
    /// If a refresh call fails (transient VM network partition, apiserver restart), the pod
    /// continues using the existing token from the volume.  With a 3607 s JWT the pod would
    /// get Unauthorized within ~1 h of a failed refresh.  By flooring the JWT exp at 24 h
    /// the pod stays authenticated for a full conformance run even if kubelet misses every
    /// single refresh attempt.
    ///
    /// This test fails if the floor is removed: exp - iat would equal 3607 instead of ≥ 86400.
    #[tokio::test]
    async fn create_token_jwt_lifetime_floored_at_24h() {
        let (state, store) = make_state_with_key();
        seed_namespace(&store, "default").await;
        seed_serviceaccount(&store, "default", "my-sa", "uid-tq5y").await;

        // Request the Kubernetes-default projected-volume TTL (what kubelet typically sends).
        let req_body = serde_json::json!({
            "spec": {
                "expirationSeconds": 3607,
                "audiences": ["https://kubernetes.default.svc"]
            }
        });

        let result = create_token(
            State(state),
            Path(("default".to_owned(), "my-sa".to_owned())),
            Bytes::from(serde_json::to_vec(&req_body).unwrap()),
        )
        .await;
        let resp_body = match result {
            Ok(r) => collect_body(r).await,
            Err(e) => panic!(
                "token request must succeed: status={} message={}",
                e.0, e.1.message
            ),
        };

        // The response spec.expirationSeconds must still be the requested 3607 s so that
        // kubelet schedules refreshes at the normal ~48-min interval.
        let resp_exp_secs = resp_body["spec"]["expirationSeconds"]
            .as_u64()
            .expect("spec.expirationSeconds must be present");
        assert_eq!(
            resp_exp_secs, 3607,
            "spec.expirationSeconds in response must equal the requested value \
             so kubelet schedules refreshes at the right interval"
        );

        // The JWT exp must be at least 86400 s (24 h) from iat regardless of the requested
        // expirationSeconds.  If this fails, reverted MIN_JWT_LIFETIME_SECS means the pod
        // gets Unauthorized within ~1 h if kubelet fails to refresh (mayor-tq5y).
        let token = resp_body["status"]["token"]
            .as_str()
            .expect("status.token must be present");
        let claims = decode_jwt_claims(token);
        let iat = claims["iat"].as_u64().expect("iat must be present");
        let exp = claims["exp"].as_u64().expect("exp must be present");
        assert!(
            exp - iat >= MIN_JWT_LIFETIME_SECS,
            "JWT lifetime (exp-iat={}) must be >= MIN_JWT_LIFETIME_SECS={} even when \
             expirationSeconds={} was requested — removing this floor re-exposes mayor-tq5y",
            exp - iat,
            MIN_JWT_LIFETIME_SECS,
            resp_exp_secs
        );

        // The status.expirationTimestamp must reflect the SHORT requested window (3607 s),
        // not the longer JWT lifetime, so kubelet computes the correct refresh schedule.
        // (kubelet uses expirationTimestamp + spec.expirationSeconds to derive the refresh window)
        let exp_ts = resp_body["status"]["expirationTimestamp"]
            .as_str()
            .expect("status.expirationTimestamp must be present");
        assert!(
            exp_ts.contains('T') && exp_ts.ends_with('Z'),
            "expirationTimestamp must be in RFC3339 format, got: {exp_ts}"
        );
    }
}

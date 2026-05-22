// TokenRequest handler — POST /api/v1/namespaces/:ns/serviceaccounts/:name/token
//
// Mints a short-lived RS256 JWT for the named ServiceAccount and returns a
// Kubernetes TokenRequest response (201 Created).

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
}

fn default_expiration() -> u64 {
    3600
}

// ---------------------------------------------------------------------------
// JWT claims
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct KubernetesClaims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    exp: u64,
    iat: u64,
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

pub async fn create_token(
    State(state): State<AppState>,
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

    // 4. Parse request body — accept empty body (kubectl omits it in some versions).
    let mut spec = if body.is_empty() {
        TokenRequestSpec {
            expiration_seconds: default_expiration(),
            audiences: vec!["https://kubernetes.default.svc".to_owned()],
        }
    } else {
        let req: TokenRequest = serde_json::from_slice(&body)
            .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;
        let mut spec = req.spec;
        if spec.audiences.is_empty() {
            spec.audiences = vec!["https://kubernetes.default.svc".to_owned()];
        }
        spec
    };

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
    let now = unix_now();
    let exp = now + spec.expiration_seconds;
    let claims = KubernetesClaims {
        iss: "https://kubernetes.default.svc".to_owned(),
        sub: format!("system:serviceaccount:{}:{}", ns.as_str(), sa_name),
        aud: spec.audiences,
        exp,
        iat: now,
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
    let expiration_timestamp = secs_to_rfc3339(exp);
    let resp = serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
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

    /// default_expiration must be 3600 seconds (1 hour), matching Kubernetes default.
    #[test]
    fn default_expiration_is_one_hour() {
        assert_eq!(default_expiration(), 3600);
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
            iss: "https://kubernetes.default.svc".to_owned(),
            sub: "system:serviceaccount:default:my-sa".to_owned(),
            aud: vec!["https://kubernetes.default.svc".to_owned()],
            exp: 1_704_070_800,
            iat: 1_704_067_200,
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
    }

    /// SA UID must appear in the kubernetes.io.serviceaccount.uid claim so that
    /// token recipients can correlate the token to a specific SA object. An empty
    /// UID breaks the Kubernetes token projection contract.
    #[test]
    fn claims_serialize_sa_uid() {
        let claims = KubernetesClaims {
            iss: "https://kubernetes.default.svc".to_owned(),
            sub: "system:serviceaccount:kube-system:coredns".to_owned(),
            aud: vec!["https://kubernetes.default.svc".to_owned()],
            exp: 1_704_070_800,
            iat: 1_704_067_200,
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
}

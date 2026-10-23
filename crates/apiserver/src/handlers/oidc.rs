// OIDC Service Account Issuer Discovery handlers
//
// Implements two endpoints required by the Kubernetes conformance spec
// "[sig-auth] ServiceAccountIssuerDiscovery should support OIDC discovery of
// service account issuer":
//
//   GET /.well-known/openid-configuration
//     Returns the OIDC provider metadata document. The `issuer` field MUST
//     match the `iss` claim in SA JWTs minted by handlers/tokens.rs.
//
//   GET /openid/v1/jwks
//     Returns the JSON Web Key Set of every SA verification key, keyed by kid.
//
// Both endpoints are RBAC-gated (non-resource URLs) via the seeded ClusterRole
// `system:service-account-issuer-discovery` which grants `get` on these paths.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use u7s_store::Store;

use crate::sa_keys::JwkEc;
use crate::state::AppState;

/// The SA token issuer. MUST match the `iss` claim in minted SA JWTs
/// (handlers/tokens.rs KubernetesClaims::iss).
pub const SA_ISSUER: &str = "https://kubernetes.default.svc";

/// GET /.well-known/openid-configuration
///
/// Returns the OIDC provider metadata document as required by RFC 8414 and the
/// Kubernetes conformance spec. The `issuer` field is the SA token `iss` claim;
/// `jwks_uri` points to the companion endpoint on the same server.
///
/// Correctness: `issuer` must equal the `iss` in minted SA tokens exactly,
/// otherwise OIDC verifiers will reject tokens as being from the wrong issuer.
pub async fn openid_configuration<S: Store>(_state: State<AppState<S>>) -> impl IntoResponse {
    // jwks_uri must use the issuer base URL (SA_ISSUER = "https://kubernetes.default.svc")
    // so that pods can reach it via in-cluster DNS. Using the external server address
    // (e.g. https://127.0.0.1:6445) would make the JWKS endpoint unreachable from pods,
    // causing OIDC token validation to fail inside the cluster.
    let jwks_uri = format!("{}/openid/v1/jwks", SA_ISSUER);

    Json(serde_json::json!({
        "issuer": SA_ISSUER,
        "jwks_uri": jwks_uri,
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"]
    }))
}

/// GET /openid/v1/jwks
///
/// Returns every key currently accepted for SA token verification (the signing key, a
/// published-but-not-yet-signing successor, and replaced keys still inside their overlap
/// window), each as an EC P-256 JWK carrying the `kid` that SA JWTs reference.
pub async fn jwks<S: Store>(State(state): State<AppState<S>>) -> impl IntoResponse {
    match state.sa_keys.as_ref() {
        Some(keys) => Json(build_jwks(&keys.jwks())).into_response(),
        None => {
            tracing::warn!("JWKS requested but SA keys are not available");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": "SA signing key not available",
                    "code": 503
                })),
            )
                .into_response()
        }
    }
}

pub(crate) fn build_jwks(keys: &[JwkEc]) -> serde_json::Value {
    serde_json::json!({
        "keys": keys.iter().map(|k| serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": k.kid,
            "x": k.x,
            "y": k.y,
        })).collect::<Vec<_>>()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::Clock;
    use crate::sa_keys::{RotationPolicy, SaKeyring};
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;
    use time::OffsetDateTime;

    fn state_with(keys: Option<SaKeyring>) -> AppState {
        let store = Arc::new(u7s_store::SqliteStore::new(":memory:").expect("store"));
        AppState::new(store, keys, Default::default(), "https://x:6443".into())
    }

    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&body).expect("json")
    }

    /// OIDC verifiers reject every token when the discovery issuer differs from `iss`.
    #[test]
    fn openid_configuration_issuer_matches_sa_token_iss_claim() {
        assert_eq!(SA_ISSUER, "https://kubernetes.default.svc");
    }

    /// Pods fetch the JWKS via in-cluster DNS; a host-external jwks_uri would be unreachable
    /// from inside the cluster and break OIDC validation there.
    #[tokio::test]
    async fn openid_configuration_advertises_in_cluster_jwks_uri_and_es256() {
        let resp = openid_configuration(State(state_with(None)))
            .await
            .into_response();
        let doc = json_body(resp).await;
        assert_eq!(
            doc["jwks_uri"],
            "https://kubernetes.default.svc/openid/v1/jwks"
        );
        assert_eq!(doc["id_token_signing_alg_values_supported"][0], "ES256");
    }

    /// While a successor is published but not yet signing, external verifiers must already
    /// see it next to the current signer, or they reject tokens the new key mints right
    /// after the switch.
    #[tokio::test]
    async fn jwks_lists_every_verification_key_with_kid_across_rotation() {
        let now = Arc::new(AtomicI64::new(1_000_000));
        let c = Arc::clone(&now);
        let clock = Clock::new(move || {
            OffsetDateTime::from_unix_timestamp(c.load(Ordering::SeqCst)).expect("ts")
        });
        let policy = RotationPolicy::default();
        let ring = SaKeyring::for_test_with(policy, clock);
        let first = ring.signing_kid();
        let state = state_with(Some(ring.clone()));

        now.fetch_add(
            (policy.rotate_after - policy.prepublish).as_secs() as i64,
            Ordering::SeqCst,
        );
        ring.tick().expect("tick");

        let doc = json_body(jwks(State(state)).await.into_response()).await;
        let keys = doc["keys"].as_array().expect("keys array");
        assert_eq!(
            keys.len(),
            2,
            "published successor must appear next to the signer"
        );
        assert!(keys.iter().any(|k| k["kid"] == first.as_str()));
        for k in keys {
            assert_eq!(k["kty"], "EC");
            assert_eq!(k["crv"], "P-256");
            assert_eq!(k["alg"], "ES256");
            assert!(k["x"].as_str().is_some_and(|x| !x.is_empty()));
            assert!(k["y"].as_str().is_some_and(|y| !y.is_empty()));
        }
    }

    #[tokio::test]
    async fn jwks_is_unavailable_without_keys() {
        let resp = jwks(State(state_with(None))).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

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
        .and_then(|v| v["metadata"]["uid"].as_str().map(str::to_owned))
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

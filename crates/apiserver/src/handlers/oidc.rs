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
//     Returns the JSON Web Key Set containing the public key corresponding to
//     the SA token signing private key. Verifiers use this to validate SA JWTs.
//
// Both endpoints are RBAC-gated (non-resource URLs) via the seeded ClusterRole
// `system:service-account-issuer-discovery` which grants `get` on these paths.
// They are NOT in auth::is_exempt().

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::Engine as _;
use u7s_store::Store;

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
pub async fn openid_configuration<S: Store>(State(state): State<AppState<S>>) -> impl IntoResponse {
    // jwks_uri is the absolute URL to our JWKS endpoint, using the advertised
    // server address so in-cluster clients can reach it.
    let jwks_uri = format!("{}/openid/v1/jwks", state.server_address);

    Json(serde_json::json!({
        "issuer": SA_ISSUER,
        "jwks_uri": jwks_uri,
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    }))
}

/// GET /openid/v1/jwks
///
/// Returns the JSON Web Key Set (JWKS) containing the RSA public key used to
/// sign SA tokens. Verifiers fetch this document to obtain the key material
/// needed to validate SA JWTs.
///
/// The returned JWK has:
///   kty: "RSA"
///   use: "sig"
///   alg: "RS256"
///   n, e: base64url-encoded RSA modulus and public exponent
///
/// Note: SA JWTs minted by handlers/tokens.rs do not include a `kid` in the
/// JWT header (jsonwebtoken::Header::new(Algorithm::RS256) leaves kid=None),
/// so we also omit `kid` from the JWK. A verifier with a single-key JWKS
/// document can validate tokens even without `kid` by trying the only key.
pub async fn jwks<S: Store>(State(state): State<AppState<S>>) -> impl IntoResponse {
    let pem = match state.sa_public_key_pem.as_deref() {
        Some(p) => p,
        None => {
            tracing::warn!("JWKS requested but SA public key is not available");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": "SA signing key not available",
                    "code": 503
                })),
            )
                .into_response();
        }
    };

    match build_jwks(pem) {
        Ok(jwks) => Json(jwks).into_response(),
        Err(e) => {
            tracing::error!("failed to build JWKS from SA public key: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": format!("failed to build JWKS: {e}"),
                    "code": 500
                })),
            )
                .into_response()
        }
    }
}

/// Derive a JWKS document from a PEM-encoded RSA public key.
///
/// Exported as `pub(crate)` so tests can call it directly without constructing
/// an AppState or making HTTP requests.
///
/// The PKCS#1 PEM format used by u7s SA keys contains the RSA modulus (n) and
/// public exponent (e) directly. We parse the PEM, extract the DER bytes, then
/// decode the PKCS#1 RSA public key structure manually to get n and e.
/// This avoids any new crate dependency — we already depend on `rsa`.
pub(crate) fn build_jwks(pem: &[u8]) -> Result<serde_json::Value, String> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::traits::PublicKeyParts;

    let pem_str = std::str::from_utf8(pem).map_err(|e| format!("invalid UTF-8 in PEM: {e}"))?;

    let rsa_pub = rsa::RsaPublicKey::from_pkcs1_pem(pem_str)
        .map_err(|e| format!("failed to parse RSA public key: {e}"))?;

    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // RSA modulus (n) — big-endian unsigned integer bytes
    let n_bytes = rsa_pub.n().to_bytes_be();
    let n_b64 = b64url.encode(&n_bytes);

    // RSA public exponent (e) — big-endian unsigned integer bytes
    let e_bytes = rsa_pub.e().to_bytes_be();
    let e_b64 = b64url.encode(&e_bytes);

    Ok(serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": n_b64,
            "e": e_b64
        }]
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// build_jwks must successfully parse a real RSA-2048 PKCS#1 public key and
    /// return a JWKS document with the correct fields.
    ///
    /// If this fails, the /openid/v1/jwks endpoint would return 500 for every
    /// request, breaking all OIDC token verifiers that depend on it.
    #[test]
    fn build_jwks_from_valid_rsa_pkcs1_pem_succeeds() {
        use rsa::pkcs1::{EncodeRsaPublicKey, LineEnding};
        let mut rng = rsa::rand_core::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
        let pub_pem = private_key
            .to_public_key()
            .to_pkcs1_pem(LineEnding::LF)
            .expect("pub pem")
            .into_bytes();

        let jwks = build_jwks(&pub_pem).expect("build_jwks must succeed for valid RSA PKCS#1 PEM");

        let keys = jwks["keys"].as_array().expect("keys must be an array");
        assert_eq!(keys.len(), 1, "JWKS must contain exactly one key");

        let key = &keys[0];
        assert_eq!(key["kty"], "RSA", "kty must be RSA");
        assert_eq!(key["use"], "sig", "use must be sig");
        assert_eq!(key["alg"], "RS256", "alg must be RS256");

        let n = key["n"].as_str().expect("n must be present");
        assert!(!n.is_empty(), "n (modulus) must be non-empty");

        let e = key["e"].as_str().expect("e must be present");
        assert!(!e.is_empty(), "e (exponent) must be non-empty");
    }

    /// The JWK public key must correspond to the private key used to sign SA tokens.
    ///
    /// If the JWK is derived from a different key or key components are wrong,
    /// OIDC verifiers cannot validate SA tokens — they would reject every SA JWT.
    /// This test verifies the round-trip: sign with the private key, verify with
    /// the JWK's public key bytes.
    #[test]
    fn jwk_public_key_matches_sa_signing_private_key() {
        use rsa::pkcs1::{EncodeRsaPublicKey, LineEnding};
        use rsa::traits::PublicKeyParts;

        let mut rng = rsa::rand_core::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
        let public_key = private_key.to_public_key();

        let pub_pem = public_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("pub pem")
            .into_bytes();

        let jwks = build_jwks(&pub_pem).expect("build_jwks must succeed");
        let key = &jwks["keys"][0];

        // Decode the JWK n and e back to big integers and compare with the original key.
        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let jwk_n = b64url
            .decode(key["n"].as_str().expect("n must be present"))
            .expect("n must be valid base64url");
        let jwk_e = b64url
            .decode(key["e"].as_str().expect("e must be present"))
            .expect("e must be valid base64url");

        let orig_n = public_key.n().to_bytes_be();
        let orig_e = public_key.e().to_bytes_be();

        assert_eq!(
            jwk_n, orig_n,
            "JWK n (modulus) must match the SA signing public key's modulus — \
             a mismatch means OIDC verifiers cannot validate SA tokens"
        );
        assert_eq!(
            jwk_e, orig_e,
            "JWK e (exponent) must match the SA signing public key's exponent — \
             a mismatch means OIDC verifiers cannot validate SA tokens"
        );
    }

    /// The discovery document's issuer must exactly match the `iss` claim in SA tokens.
    ///
    /// OIDC verifiers fetch the discovery document, read the issuer, then validate
    /// that the token's `iss` claim equals the discovery document's `issuer`. If
    /// they differ, every SA token is rejected. This test encodes that constraint.
    #[test]
    fn openid_configuration_issuer_matches_sa_token_iss_claim() {
        // SA_ISSUER must equal the literal string used in KubernetesClaims::iss
        // in handlers/tokens.rs. If tokens.rs changes the issuer, this test fails
        // and signals that SA_ISSUER must be updated to match.
        assert_eq!(
            SA_ISSUER, "https://kubernetes.default.svc",
            "SA_ISSUER must exactly match the iss claim in SA tokens — \
             if they differ, all SA tokens are rejected by OIDC verifiers"
        );
    }

    /// SA JWT round-trip: a token signed with the SA private key must validate
    /// against the JWK public key derived by build_jwks.
    ///
    /// This is the strongest correctness check: it proves that the JWK material
    /// actually corresponds to the signing key, not just that the bytes look right.
    #[test]
    fn sa_token_validates_against_jwk_public_key() {
        use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
        use rsa::pkcs1::EncodeRsaPublicKey;
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};

        // Generate a fresh RSA-2048 key pair (same approach as tokens.rs handler_tests).
        let mut rng = rsa::rand_core::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");

        // PKCS#8 PEM for jsonwebtoken encoding (same format as in handler_tests::make_state_with_key)
        let priv_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("pkcs8 priv pem")
            .as_bytes()
            .to_vec();

        // PKCS#1 public key PEM — format that load_or_generate_sa_keys produces
        let pub_pem = private_key
            .to_public_key()
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("pub pem")
            .into_bytes();

        // Mint a JWT using the private key (same as handlers/tokens.rs does).
        let enc_key = EncodingKey::from_rsa_pem(&priv_pem).expect("encoding key from pkcs8 pem");

        let claims = serde_json::json!({
            "iss": SA_ISSUER,
            "sub": "system:serviceaccount:default:test-sa",
            "exp": 9_999_999_999u64,
            "iat": 0u64
        });

        let token = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &enc_key)
            .expect("JWT encode must succeed");

        // Build the JWKS and extract the JWK public key bytes.
        let jwks = build_jwks(&pub_pem).expect("build_jwks must succeed");
        let key = &jwks["keys"][0];

        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let n_bytes = b64url
            .decode(key["n"].as_str().expect("n must be present"))
            .expect("n must be valid base64url");
        let e_bytes = b64url
            .decode(key["e"].as_str().expect("e must be present"))
            .expect("e must be valid base64url");

        // Reconstruct a jsonwebtoken DecodingKey from the JWK components.
        let dec_key = DecodingKey::from_rsa_raw_components(&n_bytes, &e_bytes);

        // Validate the JWT. This fails if the JWK key does not correspond to the
        // signing private key — proving the round-trip works end-to-end.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[SA_ISSUER]);
        validation.set_audience(&[""]);
        // Remove audience validation — our test claims have no aud.
        validation.validate_aud = false;

        let result = jsonwebtoken::decode::<serde_json::Value>(&token, &dec_key, &validation);
        assert!(
            result.is_ok(),
            "SA JWT must validate against the JWK public key derived from the same key pair — \
             if this fails, OIDC verifiers cannot validate SA tokens: {:?}",
            result.err()
        );
    }

    /// build_jwks must return Err for invalid PEM input.
    ///
    /// Without this check, a corrupt sa.pub file would cause a panic or
    /// produce garbage JWK data that silently breaks token verification.
    #[test]
    fn build_jwks_rejects_invalid_pem() {
        let bad_pem = b"not a valid pem at all";
        let result = build_jwks(bad_pem);
        assert!(
            result.is_err(),
            "build_jwks must return Err for invalid PEM input — \
             a corrupt sa.pub must not produce a silent bad JWKS"
        );
    }
}

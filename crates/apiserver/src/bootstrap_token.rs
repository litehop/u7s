//! Bootstrap-token authentication: `Bearer <id>.<secret>` resolved against
//! `kube-system/bootstrap-token-<id>` Secrets of type `bootstrap.kubernetes.io/token`.
//!
//! Mirrors upstream `plugin/pkg/auth/authenticator/token/bootstrap` and
//! `staging/src/k8s.io/cluster-bootstrap`. Reading the Secret on every attempt (no cache)
//! means a minted token works immediately and a deleted or expired one stops at once, with
//! no apiserver restart.

use std::collections::{BTreeSet, HashMap};

use subtle::ConstantTimeEq;
use u7s_store::Store;

use crate::auth::UserInfo;
use crate::keys::object_key;
use crate::util::rfc3339_to_unix_secs;

pub(crate) const SECRET_TYPE: &str = "bootstrap.kubernetes.io/token";
pub(crate) const SECRET_NAME_PREFIX: &str = "bootstrap-token-";
pub(crate) const NAMESPACE: &str = "kube-system";
pub(crate) const USER_PREFIX: &str = "system:bootstrap:";
const DEFAULT_GROUP: &str = "system:bootstrappers";
const GROUP_PREFIX: &str = "system:bootstrappers:";
const TOKEN_ID_LEN: usize = 6;
const TOKEN_SECRET_LEN: usize = 16;

fn is_id_charset(s: &str) -> bool {
    s.bytes()
        .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase())
}

pub(crate) fn is_valid_token_id(id: &str) -> bool {
    id.len() == TOKEN_ID_LEN && is_id_charset(id)
}

pub(crate) fn is_valid_token_secret(secret: &str) -> bool {
    secret.len() == TOKEN_SECRET_LEN && is_id_charset(secret)
}

/// Splits `<id>.<secret>`; `None` when the string is not shaped like a bootstrap token, so
/// other authenticators can still claim it.
fn parse_token(token: &str) -> Option<(&str, &str)> {
    let (id, secret) = token.split_once('.')?;
    (is_valid_token_id(id) && is_valid_token_secret(secret)).then_some((id, secret))
}

/// Upstream `BootstrapGroupPattern`: `system:bootstrappers:[a-z0-9:-]{0,255}[a-z0-9]`.
fn is_valid_extra_group(group: &str) -> bool {
    let Some(rest) = group.strip_prefix(GROUP_PREFIX) else {
        return false;
    };
    let bytes = rest.as_bytes();
    bytes.len() <= 256
        && bytes
            .last()
            .is_some_and(|c| c.is_ascii_digit() || c.is_ascii_lowercase())
        && bytes
            .iter()
            .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase() || *c == b':' || *c == b'-')
}

/// Decoded `data[key]` as a string; empty when absent or not valid base64/UTF-8 (upstream
/// `GetData`).
fn data_str(body: &serde_json::Value, key: &str) -> String {
    body["data"][key]
        .as_str()
        .and_then(|b64| {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).ok()
        })
        .and_then(|raw| String::from_utf8(raw).ok())
        .unwrap_or_default()
}

/// Upstream `HasExpired`: no `expiration` key never expires; an unparseable one counts as
/// expired so a typo cannot create an immortal token.
fn has_expired(body: &serde_json::Value, now_secs: i64) -> bool {
    let expiration = data_str(body, "expiration");
    if expiration.is_empty() {
        return false;
    }
    match rfc3339_to_unix_secs(&expiration) {
        Some(at) => at <= now_secs,
        None => true,
    }
}

fn groups(body: &serde_json::Value) -> Option<Vec<String>> {
    let mut set = BTreeSet::from([DEFAULT_GROUP.to_owned()]);
    let extra = data_str(body, "auth-extra-groups");
    if !extra.is_empty() {
        for g in extra.split(',') {
            if !is_valid_extra_group(g) {
                return None;
            }
            set.insert(g.to_owned());
        }
    }
    Some(set.into_iter().collect())
}

/// Pure decision for one candidate token against its stored Secret (upstream
/// `AuthenticateToken` after the lister lookup).
fn authenticate_secret(
    body: &serde_json::Value,
    token_id: &str,
    token_secret: &str,
    now_secs: i64,
) -> Option<UserInfo> {
    if !body["metadata"]["deletionTimestamp"].is_null() {
        return None;
    }
    if body["type"].as_str() != Some(SECRET_TYPE) || !body["data"].is_object() {
        return None;
    }
    let stored = data_str(body, "token-secret");
    if !bool::from(stored.as_bytes().ct_eq(token_secret.as_bytes())) {
        return None;
    }
    if data_str(body, "token-id") != token_id {
        return None;
    }
    if has_expired(body, now_secs) {
        return None;
    }
    if data_str(body, "usage-bootstrap-authentication") != "true" {
        return None;
    }
    Some(UserInfo {
        username: format!("{USER_PREFIX}{token_id}"),
        uid: String::new(),
        groups: groups(body)?,
        extra: HashMap::new(),
    })
}

/// Resolves a bearer token to a bootstrap-token identity, or `None` to decline.
pub(crate) async fn authenticate<S: Store>(token: &str, store: &S) -> Option<UserInfo> {
    let (id, secret) = parse_token(token)?;
    let key = object_key("secrets", NAMESPACE, &format!("{SECRET_NAME_PREFIX}{id}"));
    let obj = match store.get(&key).await {
        Ok(Some(obj)) => obj,
        Ok(None) => return None,
        Err(e) => {
            tracing::warn!("bootstrap token lookup: store error reading {key}: {e}");
            return None;
        }
    };
    let body: serde_json::Value = serde_json::from_slice(&obj.value).ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    authenticate_secret(&body, id, secret, now)
}

/// Deletes a token Secret by name. Already gone (expired, cleaned) counts as done; a store
/// failure is logged and left to the token's TTL.
pub(crate) async fn delete_token_secret<S: Store>(store: &S, name: &str) {
    let key = object_key("secrets", NAMESPACE, name);
    match store.delete(&key, None).await {
        Ok(_) | Err(u7s_store::StoreError::NotFound { .. }) => {}
        Err(e) => tracing::warn!("failed to delete bootstrap token Secret {name}: {e}"),
    }
}

/// Create/update validation for `type: bootstrap.kubernetes.io/token` Secrets. Upstream's
/// apiserver does not validate these (kubeadm does client-side); u7s rejects malformed ones
/// so a typo cannot silently produce an unusable or mis-named join credential.
pub(crate) fn validate_secret(body: &serde_json::Value) -> Result<(), String> {
    if body["type"].as_str() != Some(SECRET_TYPE) {
        return Ok(());
    }
    let id = data_str(body, "token-id");
    if !is_valid_token_id(&id) {
        return Err(format!(
            "Secret.data[token-id]: Invalid value: must be 6 characters of [a-z0-9] for type {SECRET_TYPE}"
        ));
    }
    if !is_valid_token_secret(&data_str(body, "token-secret")) {
        return Err(format!(
            "Secret.data[token-secret]: Invalid value: must be 16 characters of [a-z0-9] for type {SECRET_TYPE}"
        ));
    }
    let want = format!("{SECRET_NAME_PREFIX}{id}");
    if body["metadata"]["name"].as_str() != Some(want.as_str()) {
        return Err(format!(
            "Secret.metadata.name: Invalid value: must be {want:?} for type {SECRET_TYPE} (bootstrap-token-<token-id>)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;

    fn b64(s: &str) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, s)
    }

    fn token_secret(extra: &[(&str, &str)]) -> serde_json::Value {
        let mut data = serde_json::Map::new();
        for (k, v) in [
            ("token-id", "abcdef"),
            ("token-secret", "0123456789abcdef"),
            ("usage-bootstrap-authentication", "true"),
        ] {
            data.insert(k.into(), json!(b64(v)));
        }
        for (k, v) in extra {
            data.insert((*k).into(), json!(b64(v)));
        }
        json!({
            "metadata": {"name": "bootstrap-token-abcdef", "namespace": "kube-system"},
            "type": SECRET_TYPE,
            "data": data,
        })
    }

    fn authn(body: &serde_json::Value) -> Option<UserInfo> {
        authenticate_secret(body, "abcdef", "0123456789abcdef", NOW)
    }

    #[test]
    fn valid_token_authenticates_as_bootstrap_user_in_bootstrappers_group() {
        let user = authn(&token_secret(&[])).expect("a valid join token must authenticate");
        assert_eq!(user.username, "system:bootstrap:abcdef");
        assert_eq!(user.groups, vec!["system:bootstrappers"]);
    }

    #[test]
    fn expired_token_is_rejected_so_a_leaked_join_token_stops_working() {
        let past = "2027-01-15T07:59:59Z"; // NOW is 2027-01-15T08:00:00Z
        assert!(authn(&token_secret(&[("expiration", past)])).is_none());
        let future = "2027-01-15T09:00:00Z";
        assert!(authn(&token_secret(&[("expiration", future)])).is_some());
    }

    #[test]
    fn expiration_with_numeric_offset_is_honoured_in_both_directions() {
        // NOW is 2027-01-15T08:00:00Z == 17:00 at +09:00. A token minted with a local-time
        // offset must neither be rejected while valid nor outlive its expiry.
        let future = "2027-01-15T18:00:00+09:00";
        assert!(authn(&token_secret(&[("expiration", future)])).is_some());
        let past = "2027-01-15T16:59:59+09:00";
        assert!(
            authn(&token_secret(&[("expiration", past)])).is_none(),
            "an expired offset-form token must not keep joining nodes"
        );
    }

    #[test]
    fn out_of_range_expiration_fields_count_as_expired() {
        for bad in ["2099-13-01T00:00:00Z", "2099-01-32T00:00:00Z"] {
            assert!(
                authn(&token_secret(&[("expiration", bad)])).is_none(),
                "{bad} is unparseable and must be treated as expired, as upstream does"
            );
        }
    }

    #[test]
    fn unparseable_expiration_counts_as_expired_not_immortal() {
        assert!(authn(&token_secret(&[("expiration", "tomorrow")])).is_none());
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let body = token_secret(&[]);
        assert!(authenticate_secret(&body, "abcdef", "0123456789abcdeX", NOW).is_none());
    }

    #[test]
    fn usage_authentication_not_true_is_rejected() {
        let mut body = token_secret(&[]);
        body["data"]["usage-bootstrap-authentication"] = json!(b64("false"));
        assert!(
            authn(&body).is_none(),
            "a signing-only token must not authenticate API calls"
        );
        body["data"]
            .as_object_mut()
            .unwrap()
            .remove("usage-bootstrap-authentication");
        assert!(authn(&body).is_none());
    }

    #[test]
    fn wrong_secret_type_is_rejected() {
        let mut body = token_secret(&[]);
        body["type"] = json!("Opaque");
        assert!(
            authn(&body).is_none(),
            "any Secret named bootstrap-token-* must not mint identities"
        );
    }

    #[test]
    fn token_id_mismatch_with_requested_id_is_rejected() {
        let mut body = token_secret(&[]);
        body["data"]["token-id"] = json!(b64("zzzzzz"));
        assert!(authn(&body).is_none());
    }

    #[test]
    fn deleted_secret_awaiting_removal_is_rejected() {
        let mut body = token_secret(&[]);
        body["metadata"]["deletionTimestamp"] = json!("2027-01-15T07:00:00Z");
        assert!(authn(&body).is_none());
    }

    #[test]
    fn malformed_token_shapes_decline_before_any_lookup() {
        for t in [
            "",
            "abcdef",
            "abcde.0123456789abcdef",
            "ABCDEF.0123456789abcdef",
            "abcdef.0123456789abcde",
            "abcdef.0123456789abcdefg",
            "abcdef.0123456789abcdef.x",
            "abc-ef.0123456789abcdef",
        ] {
            assert!(
                parse_token(t).is_none(),
                "{t:?} must not parse as a bootstrap token"
            );
        }
        assert_eq!(
            parse_token("abcdef.0123456789abcdef"),
            Some(("abcdef", "0123456789abcdef"))
        );
    }

    #[test]
    fn extra_groups_are_added_sorted_and_deduplicated() {
        let body = token_secret(&[(
            "auth-extra-groups",
            "system:bootstrappers:worker,system:bootstrappers:ingress,system:bootstrappers:worker",
        )]);
        assert_eq!(
            authn(&body).unwrap().groups,
            vec![
                "system:bootstrappers",
                "system:bootstrappers:ingress",
                "system:bootstrappers:worker"
            ]
        );
    }

    #[test]
    fn extra_group_outside_bootstrappers_prefix_rejects_token_to_block_privilege_escalation() {
        for g in [
            "system:masters",
            "system:bootstrappers",
            "system:bootstrappers:",
            "system:bootstrappers:Worker",
            "system:bootstrappers:worker-",
            "system:bootstrappers:ok,system:masters",
        ] {
            let body = token_secret(&[("auth-extra-groups", g)]);
            assert!(
                authn(&body).is_none(),
                "extra group {g:?} must invalidate the token"
            );
        }
    }

    #[test]
    fn secret_validation_accepts_well_formed_token() {
        assert!(validate_secret(&token_secret(&[])).is_ok());
    }

    #[test]
    fn secret_validation_ignores_other_secret_types() {
        let body = json!({"metadata": {"name": "anything"}, "type": "Opaque", "data": {}});
        assert!(validate_secret(&body).is_ok());
    }

    #[test]
    fn secret_validation_rejects_bad_formats_and_names() {
        let mut bad_id = token_secret(&[]);
        bad_id["data"]["token-id"] = json!(b64("ABCDEF"));
        assert!(validate_secret(&bad_id).unwrap_err().contains("token-id"));

        let mut bad_secret = token_secret(&[]);
        bad_secret["data"]["token-secret"] = json!(b64("short"));
        assert!(validate_secret(&bad_secret)
            .unwrap_err()
            .contains("token-secret"));

        let mut missing_secret = token_secret(&[]);
        missing_secret["data"]
            .as_object_mut()
            .unwrap()
            .remove("token-secret");
        assert!(validate_secret(&missing_secret).is_err());

        let mut wrong_name = token_secret(&[]);
        wrong_name["metadata"]["name"] = json!("bootstrap-token-zzzzzz");
        assert!(
            validate_secret(&wrong_name)
                .unwrap_err()
                .contains("metadata.name"),
            "a Secret whose name differs from its token-id is unreachable by the authenticator \
             yet looks like a live token"
        );
    }
}

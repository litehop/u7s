//! ServiceAccount token signing keys: ES256 (ECDSA P-256), rotated automatically with an
//! overlap so no token is rejected before its own expiry.
//!
//! The persisted keyring is an ordered list of keys, each with a `sign_from` instant. The
//! signer at time `t` is the last key whose `sign_from <= t`; every key in the list verifies.
//! A new key is generated (and so published in the JWKS and accepted for verification)
//! `prepublish` before it starts signing, and the key it replaces is dropped
//! `retire_after` (max token lifetime plus margin) after that switch, by which time every
//! token it signed has expired. Because the signer is a pure function of the persisted list
//! and the clock, a crash between any two steps resumes correctly from the file alone.
//!
//! Legacy SA token Secrets (non-expiring JWTs) are not supported: tokens must carry a `kid`
//! from this keyring and an `exp`.

use crate::pki::{Clock, Swap};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Longest JWT lifetime the apiserver will mint (TokenRequest's maximum
/// `expirationSeconds`, 48 h). Retirement of a key is scheduled from this.
pub(crate) const MAX_TOKEN_LIFETIME: Duration = Duration::from_secs(172_800);

/// DER prefix of a P-256 SubjectPublicKeyInfo; the 65-byte uncompressed point follows.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

#[derive(Clone, Copy, Debug)]
pub(crate) struct RotationPolicy {
    /// A key signs for this long before its successor takes over.
    pub rotate_after: Duration,
    /// The successor is published for verification this long before it signs.
    pub prepublish: Duration,
    /// No token is minted with a lifetime beyond this.
    pub max_token_lifetime: Duration,
    /// Slack on top of `max_token_lifetime` before a replaced key is dropped.
    pub retire_margin: Duration,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            rotate_after: Duration::from_secs(90 * 24 * 60 * 60),
            prepublish: Duration::from_secs(24 * 60 * 60),
            max_token_lifetime: MAX_TOKEN_LIFETIME,
            retire_margin: Duration::from_secs(60 * 60),
        }
    }
}

impl RotationPolicy {
    pub(crate) fn retire_after(&self) -> i64 {
        (self.max_token_lifetime + self.retire_margin).as_secs() as i64
    }

    /// Compressed schedule for real-time rotation tests: keys rotate every `secs` seconds and
    /// tokens live at most `secs / 6`, so an old key is gone about `secs / 4` after the switch.
    #[cfg(feature = "pki-test-knobs")]
    pub(crate) fn test_knob() -> Option<Self> {
        let secs: u64 = std::env::var("U7S_PKI_TEST_SA_ROTATION_SECS")
            .ok()?
            .parse()
            .expect("U7S_PKI_TEST_SA_ROTATION_SECS must be an integer number of seconds");
        tracing::warn!("pki-test-knobs: SA signing key rotates every {secs}s");
        Some(Self {
            rotate_after: Duration::from_secs(secs),
            prepublish: Duration::from_secs(secs / 4),
            max_token_lifetime: Duration::from_secs(secs / 6),
            retire_margin: Duration::from_secs(secs / 12),
        })
    }

    #[cfg(not(feature = "pki-test-knobs"))]
    pub(crate) fn test_knob() -> Option<Self> {
        None
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.prepublish < self.rotate_after,
            "SA key prepublish window must be shorter than the rotation period"
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct KeyEntry {
    kid: String,
    /// Base64 (standard) PKCS#8 DER of the P-256 private key.
    private_key: String,
    /// Unix seconds from which this key signs.
    sign_from: i64,
}

#[derive(Serialize, Deserialize)]
struct KeyringFile {
    keys: Vec<KeyEntry>,
}

struct Material {
    kid: String,
    point: Vec<u8>,
}

fn load_material(entry: &KeyEntry) -> anyhow::Result<(Material, Vec<u8>)> {
    let der = STANDARD
        .decode(&entry.private_key)
        .map_err(|e| anyhow::anyhow!("SA key {}: private key is not base64: {e}", entry.kid))?;
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der)
        .map_err(|e| anyhow::anyhow!("SA key {}: not a P-256 PKCS#8 key: {e}", entry.kid))?;
    let point = pair.public_key().as_ref().to_vec();
    let kid = kid_of(&point);
    anyhow::ensure!(
        kid == entry.kid,
        "SA key file is inconsistent: stored kid {} does not match its key ({kid})",
        entry.kid
    );
    Ok((Material { kid, point }, der))
}

fn kid_of(point: &[u8]) -> String {
    let mut spki = P256_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(point);
    URL_SAFE_NO_PAD.encode(Sha256::digest(spki))
}

fn generate_entry(sign_from: i64) -> anyhow::Result<KeyEntry> {
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .map_err(|e| anyhow::anyhow!("generating SA signing key: {e}"))?;
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref())
        .map_err(|e| anyhow::anyhow!("re-reading generated SA signing key: {e}"))?;
    Ok(KeyEntry {
        kid: kid_of(pair.public_key().as_ref()),
        private_key: STANDARD.encode(doc.as_ref()),
        sign_from,
    })
}

/// Advance the key list to `now`: drop keys whose replacement has been signing for longer
/// than any token they minted can live, and queue a successor once the newest key is within
/// `prepublish` of its own retirement from signing. Returns whether the list changed.
fn plan(keys: &mut Vec<KeyEntry>, now: i64, policy: &RotationPolicy) -> anyhow::Result<bool> {
    let mut changed = false;
    while keys.len() >= 2 && keys[1].sign_from + policy.retire_after() <= now {
        keys.remove(0);
        changed = true;
    }
    let newest = keys.last().map_or(now, |k| k.sign_from);
    let rotate_after = policy.rotate_after.as_secs() as i64;
    let prepublish = policy.prepublish.as_secs() as i64;
    if newest + rotate_after - prepublish <= now {
        keys.push(generate_entry(
            (newest + rotate_after).max(now + prepublish),
        )?);
        changed = true;
    }
    Ok(changed)
}

fn signer_index(keys: &[KeyEntry], now: i64) -> usize {
    keys.iter().rposition(|k| k.sign_from <= now).unwrap_or(0)
}

pub(crate) struct JwkEc {
    pub kid: String,
    pub x: String,
    pub y: String,
}

struct Snapshot {
    signer_kid: String,
    signer: Arc<EncodingKey>,
    verify: HashMap<String, Arc<DecodingKey>>,
    jwks: Vec<JwkEc>,
    public_pem: Vec<u8>,
}

fn build_snapshot(keys: &[KeyEntry], now: i64) -> anyhow::Result<Snapshot> {
    let signer_entry = &keys[signer_index(keys, now)];
    let mut verify = HashMap::new();
    let mut jwks = Vec::new();
    let mut public_pem = Vec::new();
    let mut signer = None;
    for entry in keys {
        let (m, der) = load_material(entry)?;
        let x = URL_SAFE_NO_PAD.encode(&m.point[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&m.point[33..65]);
        verify.insert(
            m.kid.clone(),
            Arc::new(
                DecodingKey::from_ec_components(&x, &y)
                    .map_err(|e| anyhow::anyhow!("SA key {}: {e}", m.kid))?,
            ),
        );
        let mut spki = P256_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(&m.point);
        public_pem.extend(crate::tls::pem_encode("PUBLIC KEY", &spki));
        if m.kid == signer_entry.kid {
            signer = Some(Arc::new(EncodingKey::from_ec_der(&der)));
        }
        jwks.push(JwkEc { kid: m.kid, x, y });
    }
    Ok(Snapshot {
        signer_kid: signer_entry.kid.clone(),
        signer: signer.expect("signer is one of keys"),
        verify,
        jwks,
        public_pem,
    })
}

struct Inner {
    key_path: String,
    pub_path: String,
    policy: RotationPolicy,
    clock: Clock,
    keys: Mutex<Vec<KeyEntry>>,
    snapshot: Swap<Arc<Snapshot>>,
}

/// Shared handle to the SA keyring; cheap to clone.
#[derive(Clone)]
pub struct SaKeyring(Arc<Inner>);

impl SaKeyring {
    /// Load the keyring at `key_path`, or create it with one fresh key. A file that is not a
    /// valid keyring is an error: silently replacing it would invalidate every issued token.
    pub(crate) fn load_or_generate(
        key_path: &str,
        pub_path: &str,
        policy: RotationPolicy,
        clock: Clock,
    ) -> anyhow::Result<Self> {
        policy.validate()?;
        let now = clock.now().unix_timestamp();
        let path = crate::util::validate_cli_path(std::path::Path::new(key_path))?;
        let (keys, fresh) = if path.exists() {
            let bytes = std::fs::read(path)?;
            let file: KeyringFile = serde_json::from_slice(&bytes).map_err(|e| {
                anyhow::anyhow!(
                    "{key_path} is not an SA keyring ({e}); restore it from backup, or delete it \
                     to start a new keyring (every issued ServiceAccount token stops verifying)"
                )
            })?;
            anyhow::ensure!(!file.keys.is_empty(), "{key_path}: keyring has no keys");
            anyhow::ensure!(
                file.keys
                    .windows(2)
                    .all(|w| w[0].sign_from < w[1].sign_from),
                "{key_path}: keys are not in strictly increasing sign_from order"
            );
            (file.keys, false)
        } else {
            (vec![generate_entry(now)?], true)
        };
        let snapshot = Swap::new(Arc::new(build_snapshot(&keys, now)?));
        let ring = Self(Arc::new(Inner {
            key_path: key_path.to_owned(),
            pub_path: pub_path.to_owned(),
            policy,
            clock,
            keys: Mutex::new(keys),
            snapshot,
        }));
        if fresh {
            tracing::info!("generated SA signing key → {key_path}");
            ring.persist(&ring.0.keys.lock().unwrap_or_else(|e| e.into_inner()))?;
        }
        ring.tick()?;
        Ok(ring)
    }

    fn persist(&self, keys: &[KeyEntry]) -> anyhow::Result<()> {
        let json = serde_json::to_vec_pretty(&KeyringFile {
            keys: keys.to_vec(),
        })?;
        crate::tls::replace_file(&self.0.key_path, &json, true)?;
        let snap = build_snapshot(keys, self.0.clock.now().unix_timestamp())?;
        crate::tls::replace_file(&self.0.pub_path, &snap.public_pem, false)
    }

    /// Advance to the clock's current time: add a successor key, drop retired keys, and move
    /// signing to whichever key is now due. The file is replaced atomically before the
    /// in-memory view changes, so a crash leaves either the old or the new keyring.
    pub(crate) fn tick(&self) -> anyhow::Result<()> {
        let now = self.0.clock.now().unix_timestamp();
        let mut keys = self.0.keys.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = keys.clone();
        if plan(&mut next, now, &self.0.policy)? {
            self.persist(&next)?;
            tracing::info!(
                "SA keyring updated: {} key(s), signing kid {}",
                next.len(),
                next[signer_index(&next, now)].kid
            );
            *keys = next;
        }
        let snap = build_snapshot(&keys, now)?;
        if snap.signer_kid != self.0.snapshot.get().signer_kid {
            tracing::info!("SA tokens now signed with kid {}", snap.signer_kid);
        }
        self.0.snapshot.set(Arc::new(snap));
        Ok(())
    }

    pub(crate) async fn run(self, interval: Duration) {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(e) = self.tick() {
                tracing::error!("SA key rotation failed (will retry): {e:#}");
            }
        }
    }

    pub(crate) fn max_token_lifetime(&self) -> Duration {
        self.0.policy.max_token_lifetime
    }

    /// Sign `claims` as an ES256 JWT carrying the signing key's `kid`.
    pub(crate) fn sign<T: Serialize>(&self, claims: &T) -> jsonwebtoken::errors::Result<String> {
        let snap = self.0.snapshot.get();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(snap.signer_kid.clone());
        jsonwebtoken::encode(&header, claims, &snap.signer)
    }

    /// The verification key selected by `token`'s `kid` header; `None` for an unknown or
    /// missing `kid`, or any algorithm other than ES256.
    pub(crate) fn decoding_key_for(&self, token: &str) -> Option<Arc<DecodingKey>> {
        let header = jsonwebtoken::decode_header(token).ok()?;
        if header.alg != Algorithm::ES256 {
            return None;
        }
        self.0
            .snapshot
            .get()
            .verify
            .get(header.kid.as_deref()?)
            .cloned()
    }

    /// Every verification key, for the JWKS endpoint.
    pub(crate) fn jwks(&self) -> Vec<JwkEc> {
        self.0
            .snapshot
            .get()
            .jwks
            .iter()
            .map(|k| JwkEc {
                kid: k.kid.clone(),
                x: k.x.clone(),
                y: k.y.clone(),
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn signing_kid(&self) -> String {
        self.0.snapshot.get().signer_kid.clone()
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self::for_test_with(RotationPolicy::default(), Clock::default())
    }

    #[cfg(test)]
    pub(crate) fn for_test_with(policy: RotationPolicy, clock: Clock) -> Self {
        let dir = std::env::temp_dir().join(format!("u7s-sa-keys-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let p = |n: &str| dir.join(n).to_string_lossy().into_owned();
        Self::load_or_generate(&p("sa.key"), &p("sa.pub"), policy, clock).expect("test keyring")
    }

    #[cfg(test)]
    pub(crate) fn kids(&self) -> Vec<String> {
        self.jwks().into_iter().map(|k| k.kid).collect()
    }
}

#[cfg(test)]
mod tests;

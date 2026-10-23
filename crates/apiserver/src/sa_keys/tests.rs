use super::*;
use std::sync::atomic::{AtomicI64, Ordering};
use time::OffsetDateTime;

const T0: i64 = 1_000_000;

struct Fixture {
    now: Arc<AtomicI64>,
    dir: std::path::PathBuf,
    policy: RotationPolicy,
}

impl Fixture {
    fn new() -> Self {
        Self {
            now: Arc::new(AtomicI64::new(T0)),
            dir: std::env::temp_dir().join(format!("u7s-sa-keys-{}", uuid::Uuid::new_v4())),
            policy: RotationPolicy::default(),
        }
    }

    fn clock(&self) -> Clock {
        let now = Arc::clone(&self.now);
        Clock::new(move || OffsetDateTime::from_unix_timestamp(now.load(Ordering::SeqCst)).unwrap())
    }

    fn open(&self) -> anyhow::Result<SaKeyring> {
        std::fs::create_dir_all(&self.dir).unwrap();
        SaKeyring::load_or_generate(
            self.dir.join("sa.key").to_str().unwrap(),
            self.dir.join("sa.pub").to_str().unwrap(),
            self.policy,
            self.clock(),
        )
    }

    fn advance(&self, d: Duration) {
        self.now.fetch_add(d.as_secs() as i64, Ordering::SeqCst);
    }

    fn at(&self, secs_since_t0: i64) {
        self.now.store(T0 + secs_since_t0, Ordering::SeqCst);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
}

fn claims() -> Claims {
    Claims {
        sub: "system:serviceaccount:default:a".into(),
        exp: u64::MAX / 2,
    }
}

fn mint(ring: &SaKeyring) -> String {
    ring.sign(&claims()).unwrap()
}

fn verifies(ring: &SaKeyring, token: &str) -> bool {
    let Some(key) = ring.decoding_key_for(token) else {
        return false;
    };
    let mut v = jsonwebtoken::Validation::new(Algorithm::ES256);
    v.validate_aud = false;
    v.required_spec_claims.clear();
    jsonwebtoken::decode::<Claims>(token, &key, &v).is_ok()
}

fn rotate_at(p: &RotationPolicy) -> i64 {
    (p.rotate_after - p.prepublish).as_secs() as i64
}

fn switch_at(p: &RotationPolicy) -> i64 {
    p.rotate_after.as_secs() as i64
}

#[test]
fn tokens_carry_the_signing_kid_and_es256() {
    let f = Fixture::new();
    let ring = f.open().unwrap();
    let header = jsonwebtoken::decode_header(mint(&ring)).unwrap();
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(
        header.kid.as_deref(),
        Some(ring.signing_kid().as_str()),
        "without a kid a verifier holding several keys cannot pick one"
    );
}

#[test]
fn token_with_unknown_or_missing_kid_or_wrong_alg_is_rejected() {
    let f = Fixture::new();
    let ring = f.open().unwrap();
    let other = SaKeyring::for_test();
    assert!(
        !verifies(&ring, &mint(&other)),
        "a token from a foreign keyring (unknown kid) must be rejected"
    );

    let mut no_kid = Header::new(Algorithm::ES256);
    no_kid.kid = None;
    let t = jsonwebtoken::encode(&no_kid, &claims(), &ring.0.snapshot.get().signer).unwrap();
    assert!(
        ring.decoding_key_for(&t).is_none(),
        "kid-less tokens (legacy shape) must not be tried against any key"
    );

    let mut hs = Header::new(Algorithm::HS256);
    hs.kid = Some(ring.signing_kid());
    let t = jsonwebtoken::encode(&hs, &claims(), &EncodingKey::from_secret(b"s")).unwrap();
    assert!(
        ring.decoding_key_for(&t).is_none(),
        "a known kid must not unlock any algorithm other than ES256"
    );
}

#[test]
fn old_key_verifies_through_overlap_then_is_rejected_after_retirement() {
    let f = Fixture::new();
    let ring = f.open().unwrap();
    let a = ring.signing_kid();
    let token_a = mint(&ring);

    f.at(rotate_at(&f.policy));
    ring.tick().unwrap();
    assert_eq!(
        ring.signing_kid(),
        a,
        "successor is published but must not sign yet"
    );
    assert_eq!(
        ring.kids().len(),
        2,
        "successor is published for verification before it signs"
    );

    f.at(switch_at(&f.policy));
    ring.tick().unwrap();
    let b = ring.signing_kid();
    assert_ne!(a, b, "signing must move to the new key at the switch");
    let token_b = mint(&ring);
    assert_eq!(
        jsonwebtoken::decode_header(&token_b)
            .unwrap()
            .kid
            .as_deref(),
        Some(b.as_str())
    );
    assert!(
        verifies(&ring, &token_a),
        "tokens minted by the old key must keep working until they can have expired"
    );
    assert!(verifies(&ring, &token_b));

    let retire = switch_at(&f.policy) + f.policy.retire_after();
    f.at(retire - 1);
    ring.tick().unwrap();
    assert!(
        verifies(&ring, &token_a),
        "old key must survive until max token lifetime plus margin has elapsed"
    );

    f.at(retire);
    ring.tick().unwrap();
    assert!(
        !verifies(&ring, &token_a),
        "retired key must stop verifying, or a leaked old key stays valid forever"
    );
    assert!(verifies(&ring, &token_b));
    assert_eq!(ring.kids(), vec![b]);
}

#[test]
fn retirement_outlasts_the_longest_token_ever_minted() {
    let p = RotationPolicy::default();
    assert!(
        p.retire_after() > MAX_TOKEN_LIFETIME.as_secs() as i64,
        "a key must outlive the longest token it could have signed at the switch instant"
    );
}

#[test]
fn restart_at_every_step_keeps_the_same_view() {
    let f = Fixture::new();
    let ring = f.open().unwrap();
    let a = ring.signing_kid();
    let token_a = mint(&ring);

    f.at(rotate_at(&f.policy));
    ring.tick().unwrap();
    let kids_published = ring.kids();
    drop(ring);
    let ring = f.open().unwrap();
    assert_eq!(
        ring.kids(),
        kids_published,
        "crash after publishing the successor must resume with the same keys, not mint a third"
    );
    assert_eq!(ring.signing_kid(), a);

    f.at(switch_at(&f.policy));
    drop(ring);
    let ring = f.open().unwrap();
    assert_ne!(
        ring.signing_kid(),
        a,
        "a restart past the switch instant must sign with the successor"
    );
    assert!(
        verifies(&ring, &token_a),
        "token minted before the restart still verifies"
    );

    f.at(switch_at(&f.policy) + f.policy.retire_after());
    drop(ring);
    let ring = f.open().unwrap();
    assert!(
        !verifies(&ring, &token_a),
        "restart after retirement must not resurrect the old key"
    );
    assert_eq!(ring.kids().len(), 1);
}

#[test]
fn pubkey_bundle_lists_every_verification_key() {
    let f = Fixture::new();
    let ring = f.open().unwrap();
    f.at(rotate_at(&f.policy));
    ring.tick().unwrap();
    let pem = std::fs::read_to_string(f.dir.join("sa.pub")).unwrap();
    assert_eq!(pem.matches("BEGIN PUBLIC KEY").count(), 2);
}

#[test]
fn only_one_successor_is_queued_at_a_time() {
    let f = Fixture::new();
    let ring = f.open().unwrap();
    f.at(rotate_at(&f.policy));
    for _ in 0..5 {
        ring.tick().unwrap();
    }
    assert_eq!(
        ring.kids().len(),
        2,
        "repeated ticks must not pile up pending keys"
    );
}

#[test]
fn long_downtime_still_publishes_successor_before_it_signs() {
    let f = Fixture::new();
    let ring = f.open().unwrap();
    let a = ring.signing_kid();
    drop(ring);
    f.advance(f.policy.rotate_after * 3);
    let ring = f.open().unwrap();
    assert_eq!(
        ring.signing_kid(),
        a,
        "the successor needs its prepublish window even after downtime so JWKS caches learn it"
    );
    assert_eq!(ring.kids().len(), 2);
    f.advance(f.policy.prepublish);
    ring.tick().unwrap();
    assert_ne!(ring.signing_kid(), a);
}

#[test]
fn corrupt_or_foreign_keyring_file_fails_loud_and_is_left_untouched() {
    let f = Fixture::new();
    std::fs::create_dir_all(&f.dir).unwrap();
    let path = f.dir.join("sa.key");
    std::fs::write(&path, "-----BEGIN RSA PRIVATE KEY-----\nlegacy\n").unwrap();
    assert!(
        f.open().is_err(),
        "an unreadable keyring must not be silently replaced"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "-----BEGIN RSA PRIVATE KEY-----\nlegacy\n"
    );
}

#[test]
fn tampered_kid_in_keyring_file_is_rejected() {
    let f = Fixture::new();
    drop(f.open().unwrap());
    let path = f.dir.join("sa.key");
    let mut file: KeyringFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file.keys[0].kid = "forged".into();
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    assert!(
        f.open().is_err(),
        "kid must be derived from the key, not trusted from the file"
    );
}

#[cfg(unix)]
#[test]
fn keyring_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let ring = f.open().unwrap();
    f.at(rotate_at(&f.policy));
    ring.tick().unwrap();
    let mode = std::fs::metadata(f.dir.join("sa.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "a readable signing key lets any local user forge SA tokens"
    );
}

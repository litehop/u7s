//! In-memory cache of RS256 signature-verification outcomes for inbound service-account
//! JWTs — added because every Bearer-token request re-runs the full RSA modular
//! exponentiation (`num_bigint_dig::biguint::monty::montgomery`, 4.4% of apiserver
//! self-time per the 2026-08-06 samply triage), even when the exact same token is
//! presented hundreds of times per minute by the same client (see
//! `ai/findings/jwt-signature-verify-cache-scoping-2026-08-06.md`, mayor-32uy1).
//!
//! # What is cached
//!
//! ONLY the boolean outcome of the cryptographic signature check, keyed by
//! `SHA-256(raw signature bytes)`. Nothing else — not the decoded claims, not the
//! audience/issuer decision, not the bound-object liveness check (`auth::object_is_live`
//! stays fully per-request by design, mayor-504t7). RS256/PKCS#1v1.5 signing is
//! deterministic for a fixed (message, key) pair, so an identical signature is only
//! producible from an identical `header.payload` — the cache key therefore uniquely
//! (cryptographically) identifies the exact token that produced it. Keying on the
//! signature alone (rather than the full token string or the `kid`) means a client
//! replaying the identical token gets a cache hit while a single flipped bit anywhere in
//! the token — header, payload, or signature — always misses.
//!
//! # Why a cache hit still re-checks audience
//!
//! A hit means "this exact `header.payload.signature` was already cryptographically
//! verified" — it says nothing about whether the CALLER'S acceptable-audience list this
//! time around matches the token's `aud` claim, because `try_verify_sa_jwt`'s
//! `audiences` parameter varies per call site (default `["https://kubernetes.default.svc"]`
//! for normal Bearer-token auth, caller-supplied for `TokenReview.spec.audiences`). The
//! call site therefore always re-validates `aud` against the freshly-decoded claims, hit or
//! miss; only the RSA verify itself is skipped on a hit.
//!
//! # TTL — never later than the token's real `exp`
//!
//! An entry expires at `min(token.exp, now + MAX_TTL)`, converted to a monotonic `Instant`
//! at insert time. This must never be later than the token's own expiry: it is what makes
//! it safe for a hit to skip re-running `exp` validation entirely (a live hit is proof the
//! real `exp` hasn't passed yet). This is stricter than upstream Kubernetes' unioned
//! token-authenticator cache, which uses a flat 10s TTL uncorrelated with the token's own
//! `exp` (see the scoping doc, section 3).
//!
//! # No negative caching
//!
//! An invalid signature is never cached: its `exp` claim cannot be trusted (it wasn't
//! verified), so there is no sound TTL to bound how long a false rejection — or worse, a
//! resurrected acceptance if the underlying key material later changes — could be served.
//!
//! # Eviction
//!
//! Capacity-bounded, insertion-order (FIFO) eviction — not access-order LRU. The two are
//! only ever observably different when a cache hit changes eviction order, but the real
//! workload this cache targets (9 unique ServiceAccounts across 17,010 requests in the
//! 0806-0917 baseline) stays far under the default 512-entry cap, so eviction essentially
//! never fires in production. Under sustained overflow (more unique live tokens than
//! capacity), sequential access defeats LRU exactly as it defeats FIFO — see
//! `lru_eviction_under_load_does_not_violate_correctness` in `auth.rs`, which asserts this
//! exact thrashing behavior. A `VecDeque` insertion-order queue is a fraction of the code a
//! true access-order LRU (or the `hashlink` dependency) would need for no observable benefit
//! at the current cardinality.

use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Hard ceiling on how long a cached result may be served, independent of the token's own
/// `exp`. SA tokens minted by `handlers::tokens::create_token` typically carry much shorter
/// windows than this; the cap only binds for an unusually long-lived token.
const MAX_TTL: Duration = Duration::from_secs(5 * 60);

/// Default cache capacity — 512 entries. 5x headroom over the 9-unique-ServiceAccount
/// cardinality observed in the 0806-0917 conformance baseline (see mayor-6sbvc). Override
/// via `--sa-sig-cache-size` or `U7S_SA_SIG_CACHE_SIZE`.
pub const DEFAULT_CAPACITY: usize = 512;

struct Entry {
    /// Always `true` — invalid signatures are never cached (see module doc, "No negative
    /// caching"). Kept as an explicit field (rather than the entry's mere presence meaning
    /// "valid") so `SigCache::get`'s return type stays self-describing at call sites.
    signature_valid: bool,
    /// Reserved for a future SA-key-rotation scheme keyed by JWT `kid`. Always `None` today:
    /// u7s has exactly one `sa_decoding_key` (`state.rs`) and never sets a `kid` header
    /// (`oidc.rs`), so there is nothing to key rotation-invalidation on yet (mayor-32uy1
    /// finding #6). Not read anywhere today — kept only so adding rotation later doesn't
    /// require an `Entry` shape change.
    #[allow(dead_code)]
    kid: Option<String>,
    /// Monotonic instant at which this entry stops being servable. Computed once at insert
    /// time via `capped_expiry` — see that function's doc for the security invariant.
    expires_at: Instant,
    #[allow(dead_code)]
    inserted_at: Instant,
}

struct CacheState {
    map: HashMap<[u8; 32], Entry>,
    /// Insertion-order queue used only to pick an eviction victim — see module doc
    /// ("Eviction") for why insertion order (not access order) is sufficient here.
    order: VecDeque<[u8; 32]>,
}

/// Cache of SA-JWT signature-verification outcomes. See the module doc for the full design
/// rationale (cache key, TTL invariant, eviction policy, why audience is re-checked on every
/// call regardless of hit/miss).
pub struct SigCache {
    capacity: usize,
    state: RwLock<CacheState>,
    /// Test-only: counts every invocation of the real (expensive) `jsonwebtoken::decode`
    /// RSA-verify path, success or failure. Compiles to nothing in release builds — see
    /// `record_verify_attempt`. Mirrors `state::CrSchemaCache::compile_count`'s idiom for
    /// the same purpose (proving a cache actually skips the expensive path on a hit).
    #[cfg(test)]
    verify_count: std::sync::atomic::AtomicUsize,
}

impl SigCache {
    /// `capacity` is clamped to at least 1 — a zero-capacity cache would make every `insert`
    /// immediately evict itself, which is a pointless but not unsafe configuration; clamping
    /// avoids a div-by-zero-flavored footgun for a stray `--sa-sig-cache-size 0`.
    pub fn new_with_capacity(capacity: usize) -> Self {
        SigCache {
            capacity: capacity.max(1),
            state: RwLock::new(CacheState {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
            #[cfg(test)]
            verify_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Returns `Some(true)` if a live (not yet expired as of `now`) entry exists for `key`.
    /// Returns `None` on a miss (absent or expired) — the caller must fall through to a full
    /// signature verification. `now` is caller-supplied (never sampled internally) so tests
    /// can simulate the passage of time without a real sleep.
    pub fn get(&self, key: &[u8; 32], now: Instant) -> Option<bool> {
        let hit = {
            let state = self.state.read().unwrap();
            state
                .map
                .get(key)
                .and_then(|entry| (entry.expires_at > now).then_some(entry.signature_valid))
        };
        if hit.is_some() {
            crate::metrics::SA_SIG_CACHE_HITS_TOTAL.inc();
        } else {
            crate::metrics::SA_SIG_CACHE_MISSES_TOTAL.inc();
        }
        hit
    }

    /// Records a verified-valid signature. Only ever called after a real signature
    /// verification succeeds — there is no way to insert a negative (invalid) result, by
    /// design (see module doc, "No negative caching"). `expires_at` must be produced by
    /// `capped_expiry`; `now` is the insert timestamp, caller-supplied for the same
    /// testability reason as `get`.
    pub fn insert(&self, key: [u8; 32], kid: Option<String>, expires_at: Instant, now: Instant) {
        let size = {
            let mut state = self.state.write().unwrap();
            if !state.map.contains_key(&key) {
                state.order.push_back(key);
            }
            state.map.insert(
                key,
                Entry {
                    signature_valid: true,
                    kid,
                    expires_at,
                    inserted_at: now,
                },
            );
            // At most one entry over capacity per call (one key inserted per call), but loop
            // defensively rather than assume that invariant holds forever.
            while state.map.len() > self.capacity {
                match state.order.pop_front() {
                    Some(oldest) => {
                        state.map.remove(&oldest);
                    }
                    None => break,
                }
            }
            state.map.len()
        };
        crate::metrics::SA_SIG_CACHE_SIZE.set(size as i64);
    }

    /// Test-only accounting hook: increments once per invocation of the real
    /// `jsonwebtoken::decode` RSA-verify path, regardless of success or failure. Called
    /// unconditionally from `auth::try_verify_sa_jwt`'s cache-miss branch; compiles to an
    /// empty function body in release builds (the field it touches only exists under
    /// `#[cfg(test)]`), so it costs nothing outside tests.
    pub(crate) fn record_verify_attempt(&self) {
        #[cfg(test)]
        self.verify_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn verify_count(&self) -> usize {
        self.verify_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.state.read().unwrap().map.len()
    }
}

/// SHA-256 over the raw (base64url-decoded) signature bytes — the third dot-separated
/// segment of a compact JWS. Deliberately NOT the full token string (so a client-controlled
/// header/payload byte flip elsewhere never accidentally collides) and NOT the `kid` alone
/// (see `Entry::kid`'s doc for why `kid` can't identify anything on its own today). Returns
/// `None` for a malformed token (not exactly 3 dot-separated segments, or a non-base64url
/// signature segment) — callers fall through to full verification, which rejects the token
/// with a proper decode error rather than silently skipping the cache.
pub fn signature_hash(token: &str) -> Option<[u8; 32]> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let _payload = parts.next()?;
    let sig_b64 = parts.next()?;
    if parts.next().is_some() {
        return None; // more than 3 segments — malformed compact JWS
    }
    let sig_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig_b64).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&sig_bytes);
    Some(hasher.finalize().into())
}

/// Computes the `Instant` at which a freshly-verified signature's cache entry must expire:
/// the earlier of the token's real expiry and `now + MAX_TTL`. `now_unix` (wall-clock,
/// matching the JWT `exp` claim's Unix-seconds units) and `now` (monotonic, matching
/// `SigCache`'s `Instant` bookkeeping) are both caller-supplied rather than sampled
/// internally, so tests can inject a synthetic "current time" without a real sleep.
///
/// SECURITY INVARIANT: the returned `Instant` must never represent a point later than the
/// token's real `exp`. This is what makes it safe for `SigCache::get` to skip re-running
/// `exp` validation on a hit — a live entry is proof the real expiry hasn't passed.
pub fn capped_expiry(token_exp_unix: u64, now_unix: u64, now: Instant) -> Instant {
    let remaining = token_exp_unix.saturating_sub(now_unix);
    now + Duration::from_secs(remaining).min(MAX_TTL)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole cache design rests on signature bytes uniquely identifying the token that
    /// produced them; if two different signatures ever hashed to the same key, an attacker's
    /// forged-but-different token could ride in on a victim's cached "valid" result.
    #[test]
    fn signature_hash_differs_for_different_signature_bytes() {
        // Both signature segments are valid base64url (len % 4 == 0); they must decode to
        // *different* bytes for this test to mean anything — an invalid-base64 segment on
        // both sides would make signature_hash return None for both and vacuously pass.
        let a = "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl"; // header.payload.sig("signature")
        let b = "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJm"; // last byte of the signature differs
        assert_ne!(
            signature_hash(a),
            signature_hash(b),
            "two different signature segments must never hash to the same cache key — a \
             collision here would let a tampered token ride a victim's cached result"
        );
    }

    /// The same exact token presented twice is the entire point of this cache — if
    /// `signature_hash` weren't deterministic, every request would be a guaranteed miss and
    /// the RSA modexp would never actually be skipped.
    #[test]
    fn signature_hash_is_deterministic_for_the_same_token() {
        let token = "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl";
        assert_eq!(
            signature_hash(token),
            signature_hash(token),
            "hashing the same token twice must produce the same key, or a repeat request \
             from the same client would never hit the cache"
        );
    }

    /// A malformed token (missing a segment) must not panic or silently produce a hashable
    /// key — the call site relies on `None` here to know it must fall through to
    /// `jsonwebtoken::decode`, which will reject the token with a real error.
    #[test]
    fn signature_hash_rejects_malformed_token_shapes() {
        assert_eq!(
            signature_hash("only.two"),
            None,
            "a 2-segment token is not a valid JWS"
        );
        assert_eq!(
            signature_hash("a.b.c.d"),
            None,
            "a 4-segment token is not a valid compact JWS"
        );
    }

    /// If `capped_expiry` ever let a short-TTL token's cache entry outlive its real `exp`
    /// because the 5-minute cap dominated instead, an already-expired token could still
    /// authenticate off a stale cache hit — the exact security regression the operator's
    /// exp-bound design exists to prevent.
    #[test]
    fn capped_expiry_never_exceeds_the_shorter_of_real_exp_or_the_cap() {
        let now = Instant::now();
        let now_unix = 1_000_000u64;

        // Real exp (60s out) is shorter than MAX_TTL (5min) — must bind to the real exp.
        let short = capped_expiry(now_unix + 60, now_unix, now);
        assert_eq!(
            short,
            now + Duration::from_secs(60),
            "a token expiring sooner than the 5-minute cap must expire from the cache at its \
             own exp, not the cap"
        );

        // Real exp (1 day out) is far longer than MAX_TTL — must bind to the cap instead.
        let long = capped_expiry(now_unix + 86_400, now_unix, now);
        assert_eq!(
            long,
            now + MAX_TTL,
            "a long-lived token must still be capped at MAX_TTL — an uncapped TTL would let \
             a compromised-but-still-cryptographically-valid signature ride the cache far \
             longer than intended"
        );
    }

    /// An already-expired token (`exp` in the past) must produce a cache entry that expires
    /// immediately (zero remaining TTL), never a negative-turned-huge duration from
    /// wraparound — `saturating_sub` is what prevents that.
    #[test]
    fn capped_expiry_of_an_already_expired_token_is_now() {
        let now = Instant::now();
        let now_unix = 1_000_000u64;
        let expiry = capped_expiry(now_unix - 100, now_unix, now);
        assert_eq!(
            expiry, now,
            "a token whose exp is already in the past must not get any cache lifetime"
        );
    }

    /// Basic insert/get/eviction mechanics, independent of any real JWT — the 4 mandatory
    /// integration tests in auth.rs exercise this through the real auth path, but the raw
    /// cache mechanics deserve direct coverage too since they're the actual eviction logic.
    #[test]
    fn insert_over_capacity_evicts_oldest_first() {
        let cache = SigCache::new_with_capacity(2);
        let now = Instant::now();
        let far_future = now + Duration::from_secs(60);
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let k3 = [3u8; 32];

        cache.insert(k1, None, far_future, now);
        cache.insert(k2, None, far_future, now);
        assert_eq!(cache.len(), 2, "cache at capacity must hold both entries");

        cache.insert(k3, None, far_future, now);
        assert_eq!(
            cache.len(),
            2,
            "cache must not grow past its configured capacity"
        );
        assert_eq!(
            cache.get(&k1, now),
            None,
            "the oldest-inserted key must be the one evicted, not an arbitrary survivor"
        );
        assert_eq!(
            cache.get(&k3, now),
            Some(true),
            "the just-inserted key must survive its own insert"
        );
    }
}

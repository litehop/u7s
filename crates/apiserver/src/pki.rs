//! Single issuance path for every certificate u7s mints, plus the in-memory inventory of
//! what was issued. rcgen's `CertificateParams::default()` validity is 1975..4096, so no
//! `CertificateParams` is built anywhere except `Pki::params`.

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use time::OffsetDateTime;

pub(crate) const ROOT_CA_LIFETIME: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
pub(crate) const CLIENT_CERT_LIFETIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);
pub(crate) const SERVING_CERT_LIFETIME: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Leaves are valid from slightly before issuance so a peer whose clock lags a little does
/// not reject a freshly minted cert. The window is shifted, not widened: the cert lives
/// exactly its lifetime. Capped at a twelfth of the lifetime so a short-lived cert is not
/// born (nearly) expired.
const BACKDATE: Duration = Duration::from_secs(5 * 60);

/// Lifetime, in seconds, applied to the apiserver serving cert, the apiserver-held
/// kubelet-client and proxy-client identities, and the KCM and scheduler client certs so rotation can be observed in
/// real time.
/// Compiled only with the `pki-test-knobs` feature, which no shipped build enables, so a
/// production binary neither reads the variable nor can be made to issue short-lived certs.
#[cfg(feature = "pki-test-knobs")]
pub(crate) fn test_lifetime() -> Option<Duration> {
    let secs: u64 = std::env::var("U7S_PKI_TEST_LIFETIME_SECS")
        .ok()?
        .parse()
        .expect("U7S_PKI_TEST_LIFETIME_SECS must be an integer number of seconds");
    tracing::warn!("pki-test-knobs: serving, kubelet-client, proxy-client, kcm-client and scheduler-client lifetime is {secs}s");
    Some(Duration::from_secs(secs))
}

#[cfg(not(feature = "pki-test-knobs"))]
pub(crate) fn test_lifetime() -> Option<Duration> {
    None
}

/// Renew once this fraction of a cert's lifetime has elapsed.
pub(crate) const RENEW_FRACTION: f64 = 2.0 / 3.0;

/// A cert whose window exceeds its policy lifetime by more than this was not issued under
/// the current policy (legacy rcgen default: 1975..4096) and is due immediately.
const LEGACY_SLACK: Duration = Duration::from_secs(60);

/// Time source for issuance and renewal decisions, injectable so tests can move time.
#[derive(Clone)]
pub struct Clock(Arc<dyn Fn() -> OffsetDateTime + Send + Sync>);

impl Clock {
    pub fn new(now: impl Fn() -> OffsetDateTime + Send + Sync + 'static) -> Self {
        Self(Arc::new(now))
    }

    pub fn now(&self) -> OffsetDateTime {
        (self.0)()
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new(OffsetDateTime::now_utc)
    }
}

/// When a cert valid over `not_before..not_after` is due for renewal under a policy that
/// issues `lifetime`-long certs: `fraction` of the way through its window, or immediately
/// if its window is longer than the policy allows.
pub(crate) fn renew_at(
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    lifetime: Duration,
    fraction: f64,
) -> OffsetDateTime {
    let window = not_after - not_before;
    if window > lifetime + LEGACY_SLACK {
        return not_before;
    }
    not_before + window * fraction
}

/// A value read by many tasks and replaced wholesale; readers get a snapshot and never
/// block the writer for longer than a clone.
pub struct Swap<T>(Arc<RwLock<T>>);

impl<T> Clone for Swap<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: Clone> Swap<T> {
    pub fn new(value: T) -> Self {
        Self(Arc::new(RwLock::new(value)))
    }

    pub fn get(&self) -> T {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set(&self, value: T) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = value;
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum KeyAlgorithm {
    #[default]
    EcdsaP256,
}

impl KeyAlgorithm {
    pub(crate) fn signature_algorithm(self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            Self::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        }
    }

    pub(crate) fn generate_key(self) -> anyhow::Result<KeyPair> {
        Ok(KeyPair::generate_for(self.signature_algorithm())?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CertRole {
    Leaf,
    #[allow(dead_code)]
    Intermediate,
    Root,
}

pub(crate) struct CertSpec<'a> {
    /// Stable inventory key, e.g. "admin".
    pub name: &'static str,
    pub common_name: &'a str,
    pub organization: Option<&'a str>,
    pub role: CertRole,
    pub lifetime: Duration,
    /// Intended usages, for the inventory only; the certs carry no EKU extension.
    pub usages: &'static [&'static str],
    pub sans: Vec<SanType>,
}

#[derive(Clone, Debug)]
pub(crate) struct CertRecord {
    pub name: &'static str,
    pub subject: String,
    pub usages: &'static [&'static str],
    pub role: CertRole,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

#[derive(Clone, Default)]
pub struct CertInventory {
    certs: Arc<RwLock<Vec<CertRecord>>>,
    /// Cert name -> why its last rotation (or the publication of the rotated cert) failed.
    failures: Arc<RwLock<BTreeMap<&'static str, String>>>,
}

impl CertInventory {
    fn record(&self, record: CertRecord) {
        let mut all = self.certs.write().unwrap_or_else(|e| e.into_inner());
        all.retain(|r| r.name != record.name);
        all.push(record);
    }

    pub(crate) fn snapshot(&self) -> Vec<CertRecord> {
        self.certs.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Remember that `name` could not be rotated or published and count it, so an operator
    /// sees the stale cert instead of only a log line.
    pub(crate) fn record_failure(&self, name: &'static str, error: impl std::fmt::Display) {
        crate::metrics::CERT_ROTATION_FAILURES
            .with_label_values(&[name])
            .inc();
        self.failures
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name, error.to_string());
    }

    pub(crate) fn clear_failure(&self, name: &'static str) {
        self.failures
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(name);
    }

    pub(crate) fn failures(&self) -> Vec<(&'static str, String)> {
        self.failures
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(n, e)| (*n, e.clone()))
            .collect()
    }
}

#[derive(Clone, Default)]
pub struct Pki {
    pub(crate) algorithm: KeyAlgorithm,
    pub(crate) inventory: CertInventory,
    pub(crate) clock: Clock,
}

pub(crate) struct Issued {
    pub key: KeyPair,
    pub cert: rcgen::Certificate,
}

/// The CA a leaf is signed by, with its `not_after` so a leaf never outlives it.
pub(crate) struct Signer<'a> {
    pub issuer: &'a Issuer<'a, KeyPair>,
    pub not_after: OffsetDateTime,
}

impl Pki {
    pub(crate) fn generate_key(&self) -> anyhow::Result<KeyPair> {
        self.algorithm.generate_key()
    }

    pub(crate) fn params(
        &self,
        spec: &CertSpec<'_>,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> CertificateParams {
        let mut params = CertificateParams::default();
        params.not_before = not_before;
        params.not_after = not_after;
        if spec.role != CertRole::Leaf {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        params.subject_alt_names = spec.sans.clone();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, spec.common_name);
        if let Some(org) = spec.organization {
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, org);
        }
        params
    }

    /// Generate a key and issue a cert for it: self-signed when `signer` is None,
    /// otherwise signed by it with `not_after` clamped to the signer's.
    pub(crate) fn issue(
        &self,
        spec: &CertSpec<'_>,
        signer: Option<&Signer<'_>>,
    ) -> anyhow::Result<Issued> {
        let key = self.generate_key()?;
        let now = OffsetDateTime::from_unix_timestamp(self.clock.now().unix_timestamp())?;
        let not_before = now - BACKDATE.min(spec.lifetime / 12);
        let mut not_after = not_before + spec.lifetime;
        if let Some(s) = signer {
            not_after = not_after.min(s.not_after);
        }
        let params = self.params(spec, not_before, not_after);
        let cert = match signer {
            Some(s) => params.signed_by(&key, s.issuer)?,
            None => params.self_signed(&key)?,
        };
        self.record(spec, not_before, not_after);
        Ok(Issued { key, cert })
    }

    /// Record a cert loaded from disk with the validity it actually carries.
    pub(crate) fn record_loaded(&self, spec: &CertSpec<'_>, der: &[u8]) -> anyhow::Result<()> {
        let (not_before, not_after) = cert_validity(der)?;
        self.record(spec, not_before, not_after);
        Ok(())
    }

    fn record(&self, spec: &CertSpec<'_>, not_before: OffsetDateTime, not_after: OffsetDateTime) {
        self.inventory.record(CertRecord {
            name: spec.name,
            subject: spec.common_name.to_owned(),
            usages: spec.usages,
            role: spec.role,
            not_before,
            not_after,
        });
    }
}

/// Err unless `der` is a CA certificate: BasicConstraints CA:TRUE, and keyCertSign when a
/// KeyUsage extension is present. webpki does not check constraints on a trust anchor
/// itself, so a leaf accepted here would let its key holder mint accepted client certs.
pub(crate) fn ensure_ca_cert(der: &[u8]) -> anyhow::Result<()> {
    use x509_cert::der::Decode as _;
    use x509_cert::ext::pkix::{BasicConstraints as Bc, KeyUsage};
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("cert is not valid DER X.509: {e}"))?;
    let tbs = cert.tbs_certificate();
    let is_ca = tbs
        .get_extension::<Bc>()
        .map_err(|e| anyhow::anyhow!("bad BasicConstraints: {e}"))?
        .is_some_and(|(_, bc)| bc.ca);
    anyhow::ensure!(is_ca, "cert is not a CA (BasicConstraints CA:TRUE missing)");
    if let Some((_, usage)) = tbs
        .get_extension::<KeyUsage>()
        .map_err(|e| anyhow::anyhow!("bad KeyUsage: {e}"))?
    {
        anyhow::ensure!(usage.key_cert_sign(), "CA cert KeyUsage lacks keyCertSign");
    }
    Ok(())
}

pub(crate) fn cert_validity(der: &[u8]) -> anyhow::Result<(OffsetDateTime, OffsetDateTime)> {
    use x509_cert::der::Decode as _;
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("cert is not valid DER X.509: {e}"))?;
    let validity = cert.tbs_certificate().validity();
    let to_time = |t: x509_cert::time::Time| -> anyhow::Result<OffsetDateTime> {
        Ok(OffsetDateTime::from_unix_timestamp(
            t.to_unix_duration().as_secs() as i64,
        )?)
    };
    Ok((to_time(validity.not_before)?, to_time(validity.not_after)?))
}

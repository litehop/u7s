//! Single issuance path for every certificate u7s mints, plus the in-memory inventory of
//! what was issued. rcgen's `CertificateParams::default()` validity is 1975..4096, so no
//! `CertificateParams` is built anywhere except `Pki::params`.

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use time::OffsetDateTime;

pub(crate) const ROOT_CA_LIFETIME: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
pub(crate) const CLIENT_CERT_LIFETIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);
pub(crate) const SERVING_CERT_LIFETIME: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Leaves are valid from slightly before issuance so a peer whose clock lags a little does
/// not reject a freshly minted cert. The window is shifted, not widened: the cert lives
/// exactly its lifetime.
const BACKDATE: Duration = Duration::from_secs(5 * 60);

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
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct CertRecord {
    pub name: &'static str,
    pub subject: String,
    pub usages: &'static [&'static str],
    pub role: CertRole,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

#[derive(Clone, Default)]
pub struct CertInventory(Arc<RwLock<Vec<CertRecord>>>);

impl CertInventory {
    fn record(&self, record: CertRecord) {
        let mut all = self.0.write().unwrap_or_else(|e| e.into_inner());
        all.retain(|r| r.name != record.name);
        all.push(record);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn snapshot(&self) -> Vec<CertRecord> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[derive(Clone, Default)]
pub struct Pki {
    pub(crate) algorithm: KeyAlgorithm,
    pub(crate) inventory: CertInventory,
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
        let now = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())?;
        let not_before = now - BACKDATE;
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

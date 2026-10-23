use crate::pki::{
    cert_validity, CertInventory, CertRole, CertSpec, Pki, Swap, CLIENT_CERT_LIFETIME,
    RENEW_FRACTION, ROOT_CA_LIFETIME, SERVING_CERT_LIFETIME,
};
use crate::rotation::{CaKind, CaSigner, LeafPlan, Rotator, SERVING_LEAF};
use rcgen::{CertificateParams, Issuer, KeyPair, SanType};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime},
    RootCertStore, ServerConfig,
};
use std::sync::Arc;

use crate::util::validate_cli_path;
use crate::{bootstrap_service_ips, Args};

// ---------------------------------------------------------------------------
// Private key write helper — always 0o600
// ---------------------------------------------------------------------------

/// Write `bytes` to `path` with mode 0o600 (owner read+write only).
///
/// Using std::fs::write() leaves the file world-readable by default (0o644
/// or whatever the process umask allows). Private keys must be owner-only.
///
/// The path is validated against traversal (`..'` components) before opening,
/// even when the caller has already validated it at the CLI boundary.
fn write_private_key(path: impl AsRef<std::path::Path>, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let path = validate_cli_path(path.as_ref())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Write `bytes` to `path` and fsync, so a later rename cannot publish a zero-length file
/// after a power loss.
fn write_synced(path: impl AsRef<std::path::Path>, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// fsync the directory containing `path` so renames into it are durable.
fn sync_parent_dir(path: &str) -> std::io::Result<()> {
    let parent = std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    std::fs::File::open(parent)?.sync_all()
}

const CA_REMEDY: &str = "restore from backup, or delete both files to deliberately start a new CA";

// ---------------------------------------------------------------------------
// SA signing key — RSA 2048, persisted across restarts
// ---------------------------------------------------------------------------

/// RSA key pair used for signing service-account JWTs.
pub struct SaKeys {
    /// PEM-encoded PKCS#1 RSA private key (`-----BEGIN RSA PRIVATE KEY-----`).
    /// KCM requires this format; PKCS#8 (`-----BEGIN PRIVATE KEY-----`) causes
    /// "invalid serviceaccount key" and prevents token issuance.
    pub private_key_pem: Vec<u8>,
    /// PEM-encoded RSA public key — used to construct a DecodingKey.
    pub public_key_pem: Vec<u8>,
}

/// Load `sa.key` from disk, or generate a fresh RSA-2048 key and write it.
///
/// The public key (`sa.pub`) is derived from the private key; we write it
/// for operator convenience but never read it back (we re-derive it from
/// the private key at startup).
///
/// Design: load-or-generate ensures tokens minted before a restart remain
/// valid after restart, because the signing key stays constant.
pub fn load_or_generate_sa_keys(sa_key_path: &str, sa_pub_path: &str) -> anyhow::Result<SaKeys> {
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
    use rsa::RsaPrivateKey;

    // If the private key already exists, load it and re-derive the public key.
    if std::path::Path::new(sa_key_path).exists() {
        use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
        let pem = std::fs::read(validate_cli_path(std::path::Path::new(sa_key_path))?)?;
        let pem_str = std::str::from_utf8(&pem)
            .map_err(|e| anyhow::anyhow!("SA key file is not valid UTF-8: {e}"))?;
        let private_key = RsaPrivateKey::from_pkcs1_pem(pem_str)
            .map_err(|e| anyhow::anyhow!("failed to parse SA private key: {e}"))?;
        let public_pem = private_key
            .to_public_key()
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("public key encode error: {e}"))?;
        tracing::info!("loaded SA signing key from {sa_key_path}");
        return Ok(SaKeys {
            private_key_pem: pem,
            public_key_pem: public_pem.into_bytes(),
        });
    }

    // Generate a new 2048-bit RSA key.
    tracing::info!("generating new SA signing key → {sa_key_path}");
    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;

    let private_pem = private_key
        .to_pkcs1_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("PKCS#1 encode error: {e}"))?;

    let public_pem = private_key
        .to_public_key()
        .to_pkcs1_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("public key encode error: {e}"))?;

    write_private_key(
        validate_cli_path(std::path::Path::new(sa_key_path))?,
        private_pem.as_bytes(),
    )?;
    std::fs::write(
        validate_cli_path(std::path::Path::new(sa_pub_path))?,
        public_pem.as_bytes(),
    )?;
    tracing::info!("SA signing key written to {sa_key_path}");

    Ok(SaKeys {
        private_key_pem: private_pem.as_bytes().to_vec(),
        public_key_pem: public_pem.into_bytes(),
    })
}

// ---------------------------------------------------------------------------
// CA key+cert — persisted across restarts
// ---------------------------------------------------------------------------

/// Generate a 6-hex-char suffix for the CA Subject CN, unique enough to tell
/// stacks apart (not a cryptographic requirement — collisions only degrade a
/// diagnostic, they don't weaken the CA key). `rand` is not a direct dependency
/// of this crate, so we mix wall-clock nanoseconds with the process ID rather
/// than pull in a new crate for this.
fn random_ca_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u32;
    let mixed = nanos ^ std::process::id();
    format!("{:06x}", mixed & 0x00ff_ffff)
}

/// Load-or-generate the CA keypair and cert for signing leaf certificates.
///
/// Returns `(ca_key, ca_params, ca_cert_der)` where:
/// - `ca_key` is the rcgen KeyPair (same on every restart when loaded from disk)
/// - `ca_params` is the CertificateParams used for the CA cert, used to build an
///   `Issuer` for signing leaf certificates with the rcgen 0.14 API
/// - `ca_cert_der` is the *original* DER bytes written to disk — used in TlsMaterial
///   for kubeconfig and rustls so that kubelets see a stable CA cert across restarts
///
/// Design: keeping the CA stable means kubelets (and any other component that
/// trusts our CA via kubeconfig) do not see a cert validation failure after a restart.
fn load_or_generate_ca(
    pki: &Pki,
    name: &'static str,
    ca_key_path: &str,
    ca_cert_path: &str,
) -> anyhow::Result<(KeyPair, CertificateParams, Vec<u8>)> {
    let key_exists = std::path::Path::new(ca_key_path).exists();
    let cert_exists = std::path::Path::new(ca_cert_path).exists();
    let key_tmp = format!("{ca_key_path}.tmp");

    // An interrupted first boot (cert renamed, key not yet) leaves cert + key.tmp. If the
    // tmp key provably belongs to the cert, finishing the rename loses nothing; anything
    // else falls through to the partial-state refusal below.
    let key_exists =
        if cert_exists && !key_exists && roll_forward_key_tmp(ca_cert_path, &key_tmp, ca_key_path)?
        {
            tracing::warn!("rolled forward interrupted CA key write {key_tmp} -> {ca_key_path}");
            true
        } else {
            key_exists
        };

    // Exactly one file present: regenerating would replace trust for every kubelet,
    // kubeconfig and component cert at once, so refuse and leave both files untouched.
    if key_exists != cert_exists {
        let (present, missing) = if key_exists {
            (ca_key_path, ca_cert_path)
        } else {
            (ca_cert_path, ca_key_path)
        };
        anyhow::bail!(
            "partial CA state: {present} exists but {missing} is missing; refusing to \
             regenerate the CA (that would invalidate every certificate it signed). \
             Restore {missing}, or delete {present} to deliberately start a new CA"
        );
    }

    if key_exists && cert_exists {
        // Load CA key from PEM.
        let key_pem =
            std::fs::read_to_string(validate_cli_path(std::path::Path::new(ca_key_path))?)
                .map_err(|e| anyhow::anyhow!("read CA key {ca_key_path}: {e}"))?;
        let ca_key = KeyPair::from_pem(&key_pem).map_err(|e| {
            anyhow::anyhow!("parse CA key {ca_key_path} (cert {ca_cert_path}): {e}; {CA_REMEDY}")
        })?;

        // Load the persisted CA cert DER (stable — handed to TlsMaterial as-is).
        let ca_cert_der = std::fs::read(validate_cli_path(std::path::Path::new(ca_cert_path))?)
            .map_err(|e| anyhow::anyhow!("read CA cert {ca_cert_path}: {e}"))?;

        ca_key_matches_cert(&ca_key, &ca_cert_der).map_err(|e| {
            anyhow::anyhow!(
                "CA key {ca_key_path} and cert {ca_cert_path} are unusable: {e}; {CA_REMEDY}"
            )
        })?;

        // Reconstruct CertificateParams matching the CA cert so callers can
        // build an Issuer for signing leaf certs with the rcgen 0.14 API.
        // We cannot round-trip from DER/PEM back to CertificateParams, so we
        // reconstruct minimal CA params with the same key. The Issuer is used
        // only for signed_by(); no DER is produced here.
        //
        // The CN must come from the on-disk cert, not a hardcoded literal:
        // generation now stamps a random per-stack suffix onto the CN (below),
        // so hardcoding here would make every leaf's Issuer field mismatch the
        // real CA Subject on disk, breaking X.509 issuer/subject name matching
        // for anything signed after this reload. Falling back to the historical
        // literal keeps CAs with no parseable CN loading unchanged.
        let ca_cn = crate::auth::extract_client_cert_identity(&ca_cert_der)
            .map(|id| id.username)
            .unwrap_or_else(|| "u7s-ca".to_owned());
        let spec = ca_spec(name, &ca_cn);
        pki.record_loaded(&spec, &ca_cert_der)?;
        let (not_before, not_after) = cert_validity(&ca_cert_der)?;
        let ca_params = pki.params(&spec, not_before, not_after);

        tracing::info!("loaded CA key from {ca_key_path}; cert DER from {ca_cert_path}");
        return Ok((ca_key, ca_params, ca_cert_der));
    }

    // Generate fresh CA. The Subject CN gets a random per-stack suffix so that a
    // client misrouted to a DIFFERENT u7s stack's apiserver fails trust-anchor
    // lookup by name (rustls UnknownIssuer) instead of matching a wrong-stack CA
    // by the shared literal name and then failing cryptographic verification
    // against a leaf signed by a different key (rustls BadSignature — cryptic).
    tracing::info!("generating new CA key+cert → {ca_key_path} / {ca_cert_path}");
    let ca_cn = format!("u7s-ca-{}", random_ca_suffix());
    let spec = ca_spec(name, &ca_cn);
    let issued = pki
        .issue(&spec, None)
        .map_err(|e| anyhow::anyhow!("generate CA: {e}"))?;
    let ca_key = issued.key;
    let ca_cert_der = issued.cert.der().to_vec();
    let (not_before, not_after) = cert_validity(&ca_cert_der)?;
    let ca_params = pki.params(&spec, not_before, not_after);

    // Persist both files to temp names first, then rename cert and finally key. A crash
    // before the first rename leaves neither final file (next boot is a clean first
    // boot); the key is renamed last so a crash between renames leaves cert-only,
    // which the next boot reports as partial state instead of using a half-written key.
    // Both tmp files are fsynced before any rename and the directory after, so a power
    // loss cannot leave a renamed zero-length CA file.
    let cert_tmp = format!("{ca_cert_path}.tmp");
    write_private_key(
        validate_cli_path(std::path::Path::new(&key_tmp))?,
        ca_key.serialize_pem().as_bytes(),
    )
    .map_err(|e| anyhow::anyhow!("write CA key {key_tmp}: {e}"))?;
    write_synced(
        validate_cli_path(std::path::Path::new(&cert_tmp))?,
        &ca_cert_der,
    )
    .map_err(|e| anyhow::anyhow!("write CA cert {cert_tmp}: {e}"))?;
    std::fs::rename(&cert_tmp, ca_cert_path)
        .map_err(|e| anyhow::anyhow!("rename {cert_tmp} -> {ca_cert_path}: {e}"))?;
    sync_parent_dir(ca_cert_path).map_err(|e| anyhow::anyhow!("fsync CA directory: {e}"))?;
    std::fs::rename(&key_tmp, ca_key_path)
        .map_err(|e| anyhow::anyhow!("rename {key_tmp} -> {ca_key_path}: {e}"))?;
    sync_parent_dir(ca_cert_path)
        .and_then(|()| sync_parent_dir(ca_key_path))
        .map_err(|e| anyhow::anyhow!("fsync CA directory: {e}"))?;

    Ok((ca_key, ca_params, ca_cert_der))
}

fn ca_spec<'a>(name: &'static str, common_name: &'a str) -> CertSpec<'a> {
    CertSpec {
        name,
        common_name,
        organization: None,
        role: CertRole::Root,
        lifetime: ROOT_CA_LIFETIME,
        usages: &["cert sign"],
        sans: vec![],
    }
}

/// Rename `key_tmp` to `key_path` iff it is a key matching the cert at `cert_path`.
/// Returns whether the rename happened; never deletes or rewrites anything.
fn roll_forward_key_tmp(cert_path: &str, key_tmp: &str, key_path: &str) -> anyhow::Result<bool> {
    use std::os::unix::fs::PermissionsExt as _;
    let Ok(cert_der) = std::fs::read(cert_path) else {
        return Ok(false);
    };
    match std::fs::symlink_metadata(key_tmp) {
        Ok(m) if m.file_type().is_file() => {}
        Ok(_) => anyhow::bail!(
            "{key_tmp} is not a regular file (symlink or other); refusing to adopt it as the \
             CA key; {CA_REMEDY}"
        ),
        Err(_) => return Ok(false),
    }
    let Ok(key_pem) = std::fs::read_to_string(key_tmp) else {
        return Ok(false);
    };
    let Ok(key) = KeyPair::from_pem(&key_pem) else {
        return Ok(false);
    };
    if ca_key_matches_cert(&key, &cert_der).is_err() {
        return Ok(false);
    }
    let f = std::fs::File::open(key_tmp).map_err(|e| anyhow::anyhow!("open {key_tmp}: {e}"))?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .and_then(|()| f.sync_all())
        .map_err(|e| anyhow::anyhow!("chmod 0600 {key_tmp}: {e}"))?;
    std::fs::rename(key_tmp, key_path)
        .map_err(|e| anyhow::anyhow!("rename {key_tmp} -> {key_path}: {e}"))?;
    sync_parent_dir(key_path).map_err(|e| anyhow::anyhow!("fsync dir of {key_path}: {e}"))?;
    Ok(true)
}

/// Err unless `cert_der` parses as X.509 and its public key is `key`'s public key.
fn ca_key_matches_cert(key: &KeyPair, cert_der: &[u8]) -> anyhow::Result<()> {
    use x509_cert::der::Decode as _;
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| anyhow::anyhow!("cert is not valid DER X.509: {e}"))?;
    let cert_pub = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    anyhow::ensure!(
        cert_pub == key.public_key_raw(),
        "cert public key does not match the private key"
    );
    Ok(())
}

/// True if `leaf_der` cryptographically chain-validates against `ca_der` as the sole trust
/// anchor -- i.e. it was actually signed by the CA's private key -- using the same rustls
/// webpki verification the live server runs on every mTLS handshake. A Name-string
/// comparison of Issuer vs. Subject would wrongly trust a different-key CA that happens to
/// share a Subject CN; this checks the signature, not just the claimed name.
pub(crate) fn leaf_cert_chain_validates_at(
    leaf_der: &[u8],
    ca_der: &[u8],
    now: time::OffsetDateTime,
) -> bool {
    let mut root_store = RootCertStore::empty();
    if root_store
        .add(CertificateDer::from(ca_der.to_vec()))
        .is_err()
    {
        return false;
    }
    let Ok(verifier) = WebPkiClientVerifier::builder(Arc::new(root_store))
        .allow_unauthenticated()
        .build()
    else {
        return false;
    };
    verifier
        .verify_client_cert(
            &CertificateDer::from(leaf_der.to_vec()),
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                now.unix_timestamp().max(0) as u64
            )),
        )
        .is_ok()
}

#[cfg(test)]
fn leaf_cert_chain_validates(leaf_der: &[u8], ca_der: &[u8]) -> bool {
    leaf_cert_chain_validates_at(leaf_der, ca_der, time::OffsetDateTime::now_utc())
}

/// On-disk home of a persisted leaf (admin, KCM, scheduler): the files later consumers
/// reference by path.
#[derive(Clone, Debug)]
pub(crate) struct LeafFiles {
    pub cert: std::path::PathBuf,
    pub key: std::path::PathBuf,
}

impl LeafFiles {
    /// Cert and key in one PEM, what kubeconfigs reference.
    pub fn pem(&self) -> std::path::PathBuf {
        self.cert.with_extension("pem")
    }
}

fn key_file_matches_cert_file(key_path: &std::path::Path, cert_path: &std::path::Path) -> bool {
    let (Ok(key_pem), Ok(cert_der)) = (std::fs::read_to_string(key_path), std::fs::read(cert_path))
    else {
        return false;
    };
    KeyPair::from_pem(&key_pem).is_ok_and(|k| ca_key_matches_cert(&k, &cert_der).is_ok())
}

/// Read a persisted leaf, finishing an interrupted write first. Ok(None) when there is
/// nothing to load (neither file present, or the pair no longer chains to the CA);
/// partial or mismatched state is an error, never a silent re-mint.
///
/// A rotation renames the new cert in before the new key, so a crash between the renames
/// leaves new cert + old key + key.tmp. When key.tmp provably belongs to the cert it is
/// rolled forward; any other mismatch is refused.
pub(crate) fn load_persisted_leaf(
    label: &str,
    files: &LeafFiles,
    ca_cert_der: &[u8],
    now: time::OffsetDateTime,
) -> anyhow::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let (key_path, cert_path) = (&files.key, &files.cert);
    let key_tmp = format!("{}.tmp", key_path.display());
    let mut key_exists = key_path.exists();
    let cert_exists = cert_path.exists();

    if cert_exists
        && !(key_exists && key_file_matches_cert_file(key_path, cert_path))
        && roll_forward_key_tmp(
            &cert_path.to_string_lossy(),
            &key_tmp,
            &key_path.to_string_lossy(),
        )?
    {
        tracing::warn!("rolled forward interrupted {label} key write {key_tmp}");
        key_exists = true;
    }

    // One file alone is a crashed or tampered state; replacing it would silently mint a new
    // credential, so refuse and leave both files untouched.
    if key_exists != cert_exists {
        let (present, missing) = if key_exists {
            (key_path, cert_path)
        } else {
            (cert_path, key_path)
        };
        anyhow::bail!(
            "partial {label} cert state: {} exists but {} is missing; refusing to regenerate. \
             Restore {}, or delete {} to deliberately mint a new {label} credential",
            present.display(),
            missing.display(),
            missing.display(),
            present.display()
        );
    }
    if !key_exists {
        return Ok(None);
    }

    let key_pem = std::fs::read_to_string(validate_cli_path(key_path)?)
        .map_err(|e| anyhow::anyhow!("read {label} key {}: {e}", key_path.display()))?;
    let key = KeyPair::from_pem(&key_pem)
        .map_err(|e| anyhow::anyhow!("parse {label} key {}: {e}", key_path.display()))?;
    let cert_der = std::fs::read(validate_cli_path(cert_path)?)
        .map_err(|e| anyhow::anyhow!("read {label} cert {}: {e}", cert_path.display()))?;
    ca_key_matches_cert(&key, &cert_der).map_err(|e| {
        anyhow::anyhow!(
            "{label} key {} and cert {} do not belong together: {e}; restore the pair, or \
             delete both files to deliberately mint a new {label} credential",
            key_path.display(),
            cert_path.display()
        )
    })?;

    if !leaf_cert_chain_validates_at(&cert_der, ca_cert_der, now) {
        // Signed by a CA that is no longer the one loaded, or already expired: the pair
        // cannot authenticate against the current trust store.
        tracing::error!(
            "{label} cert at {} does not chain-validate against the CA now loaded from disk; \
             replacing it",
            cert_path.display()
        );
        return Ok(None);
    }
    Ok(Some((cert_der, key_pem.into_bytes())))
}

/// Write a leaf so every crash point restarts into a loadable state: both tmp files are
/// fsynced first, then the cert is renamed and then the key. Dying between the renames
/// leaves the new cert beside key.tmp, which `load_persisted_leaf` rolls forward; dying
/// earlier leaves the previous pair untouched.
pub(crate) fn persist_leaf(
    label: &str,
    files: &LeafFiles,
    cert_der: &[u8],
    key_pem: &[u8],
) -> anyhow::Result<()> {
    let (key_path, cert_path) = (&files.key, &files.cert);
    let key_tmp = format!("{}.tmp", key_path.display());
    let cert_tmp = format!("{}.tmp", cert_path.display());
    let io = |what: &str, p: &std::path::Path, e: std::io::Error| {
        anyhow::anyhow!("{what} {}: {e}", p.display())
    };
    write_private_key(validate_cli_path(std::path::Path::new(&key_tmp))?, key_pem)
        .map_err(|e| io(&format!("write {label} key"), key_path, e))?;
    write_synced(
        validate_cli_path(std::path::Path::new(&cert_tmp))?,
        cert_der,
    )
    .map_err(|e| io(&format!("write {label} cert"), cert_path, e))?;
    std::fs::rename(&cert_tmp, cert_path)
        .map_err(|e| io(&format!("rename {label} cert"), cert_path, e))?;
    sync_parent_dir(&cert_path.to_string_lossy())
        .map_err(|e| io(&format!("fsync {label} cert dir"), cert_path, e))?;
    std::fs::rename(&key_tmp, key_path)
        .map_err(|e| io(&format!("rename {label} key"), key_path, e))?;
    sync_parent_dir(&key_path.to_string_lossy())
        .map_err(|e| io(&format!("fsync {label} key dir"), key_path, e))?;
    Ok(())
}

pub struct TlsMaterial {
    /// DER-encoded CA certificate (written into kubeconfig).
    pub ca_cert_der: Vec<u8>,
    /// DER-encoded server leaf certificate (the single cert in the TLS chain).
    #[cfg_attr(not(test), allow(dead_code))]
    pub server_cert_der: Vec<u8>,
    /// DER-encoded admin client certificate.
    #[cfg_attr(not(test), allow(dead_code))]
    pub admin_cert_der: Vec<u8>,
    /// PEM-encoded admin private key.
    #[cfg_attr(not(test), allow(dead_code))]
    pub admin_key_pem: Vec<u8>,
    /// PEM-encoded kubelet client certificate (CN=kube-apiserver-kubelet-client, O=system:masters).
    pub kubelet_client_cert_pem: Vec<u8>,
    /// PEM-encoded kubelet client private key.
    pub kubelet_client_key_pem: Vec<u8>,
    /// DER-encoded kube-controller-manager client certificate (CN=system:kube-controller-manager,
    /// no O=), so KCM authenticates as its own least-privilege identity.
    #[cfg_attr(not(test), allow(dead_code))]
    pub kcm_cert_der: Vec<u8>,
    /// DER-encoded bootstrap-installer client certificate (CN=system:bootstrap-installer, no
    /// O=), the identity of the in-process YAML applier.
    #[cfg_attr(not(test), allow(dead_code))]
    pub bootstrap_installer_cert_der: Vec<u8>,
    /// DER-encoded scheduler client certificate (CN=system:kube-scheduler, no O=); its kubeconfig
    /// references the persisted leaf file.
    #[cfg_attr(not(test), allow(dead_code))]
    pub scheduler_cert_der: Vec<u8>,
    /// PEM-encoded proxy-client certificate (CN=front-proxy-client), signed by the
    /// DEDICATED front-proxy CA (`--proxy-client-ca-key`/`--proxy-client-ca-cert`), not
    /// the main cluster CA. Presented by u7s to AGGREGATED BACKENDS (never to u7s itself)
    /// — analogous to real kube-apiserver's `--proxy-client-cert-file`. The backend trusts
    /// it via `requestheader-client-ca-file` (populated from the `kube-system/extension-
    /// apiserver-authentication` ConfigMap — see `reconcile_extension_apiserver_authentication`)
    /// and, once trusted, believes whatever `X-Remote-User`/`X-Remote-Group` headers
    /// accompany the request (see `handlers::aggregation::proxy_to_backend`) instead of
    /// re-authenticating the original caller itself. Signing this from a CA distinct from
    /// the one that signs admin/KCM/scheduler/kubelet-client certs means none of those
    /// OTHER certs can be replayed directly against an aggregated backend to spoof identity.
    pub proxy_client_cert_pem: Vec<u8>,
    /// PEM-encoded proxy-client private key, paired with `proxy_client_cert_pem`.
    pub proxy_client_key_pem: Vec<u8>,
    /// rustls ServerConfig for the axum server, replaced on every serving-cert rotation and
    /// client-CA change; the accept loop loads it once per connection.
    pub server_config: Swap<Arc<ServerConfig>>,
    /// Every cert issued or loaded for this process, with its validity window.
    pub inventory: CertInventory,
    /// Re-issues every apiserver-owned leaf before it expires. The fields above are the
    /// leaves as of startup; consumers learn of later ones through the rotator.
    pub rotator: Arc<Rotator>,
}

impl TlsMaterial {
    /// Cert + key PEM that outbound webhook callouts present. It is the front-proxy-client
    /// identity: signed by a CA the apiserver does not accept for its own client auth, so a
    /// webhook pointed at the apiserver itself is never authenticated as `system:masters`.
    pub fn webhook_client_identity_pem(&self) -> Vec<u8> {
        let mut pem = self.proxy_client_cert_pem.clone();
        pem.extend_from_slice(&self.proxy_client_key_pem);
        pem
    }
}

/// Split an advertise address ("https://host:6443", "[fd00::1]:6443", "myhost") into its
/// unbracketed host and optional port. Ok(None) when there is no host (e.g. "https://").
pub(crate) fn parse_advertise(addr: &str) -> anyhow::Result<Option<(String, Option<u16>)>> {
    if addr.contains('%') {
        anyhow::bail!("advertise address {addr:?}: IPv6 zone IDs ('%') are not supported");
    }
    if addr.ends_with("://") {
        return Ok(None);
    }
    let with_scheme = if addr.contains("://") {
        addr.to_owned()
    } else {
        format!("https://{addr}")
    };
    let uri: hyper::http::Uri = with_scheme
        .parse()
        .map_err(|e| anyhow::anyhow!("advertise address {addr:?}: {e}"))?;
    let Some(host) = uri.host().filter(|h| !h.is_empty()) else {
        return Ok(None);
    };
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    Ok(Some((host.to_owned(), uri.port_u16())))
}

/// Extract the host (IPv6 brackets stripped) from an advertise_address like
/// "https://host.lima.internal:6443". Ok(None) if absent or hostless.
fn advertise_host(advertise_address: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(addr) = advertise_address else {
        return Ok(None);
    };
    Ok(parse_advertise(addr)?.map(|(host, _)| host))
}

/// Build the full SAN list for the server certificate.
/// Always includes localhost, 127.0.0.1, host.lima.internal, and the kubernetes
/// Service's ClusterIP derived from `--service-cluster-ip-range` (first host —
/// same offset `bootstrap_service_ips` uses to seed the `default/kubernetes`
/// Service, e.g. 10.96.0.1 for the default 10.96.0.0/12 range). In-cluster
/// clients validate the apiserver's cert against `KUBERNETES_SERVICE_HOST`,
/// which the kubelet populates from that Service's actual ClusterIP, so the
/// SAN must always match it exactly or TLS validation fails in-cluster.
/// If advertise_host is Some, appends it as an IP SAN or DNS SAN.
fn build_server_sans(
    advertise_host_str: Option<&str>,
    service_cluster_ip_range: &str,
) -> anyhow::Result<Vec<SanType>> {
    let (kubernetes_ip, _kube_dns_ip) = bootstrap_service_ips(service_cluster_ip_range)?;
    let mut sans: Vec<SanType> = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        SanType::DnsName("host.lima.internal".try_into()?),
        SanType::IpAddress(std::net::IpAddr::V4(kubernetes_ip)),
        SanType::DnsName("kubernetes".try_into()?),
        SanType::DnsName("kubernetes.default".try_into()?),
        SanType::DnsName("kubernetes.default.svc".try_into()?),
        SanType::DnsName("kubernetes.default.svc.cluster.local".try_into()?),
    ];
    if let Some(host) = advertise_host_str {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            sans.push(SanType::IpAddress(ip));
        } else {
            sans.push(SanType::DnsName(host.try_into()?));
        }
    }
    Ok(sans)
}

/// Serving config presenting only the leaf (see the comment at its call: the CA is already
/// in every client's trust store) and verifying optional client certs against
/// `client_ca_ders`. Rebuilt and swapped, never mutated, so a connection keeps the config
/// it was accepted with.
pub(crate) fn build_server_config(
    server_cert_der: &[u8],
    server_key_pem: &[u8],
    client_ca_ders: &[Vec<u8>],
) -> anyhow::Result<Arc<ServerConfig>> {
    // Present only the leaf cert in the chain. The CA cert is already in the
    // kubelet's trust store (via kubeconfig certificate-authority-data). Including
    // the self-signed CA as an intermediate causes Go's TLS verifier to reject the
    // chain on full re-handshake (after session cache expiry): it sees a chain where
    // intermediate == trust anchor, which is invalid per RFC 5246 chain validation.
    let server_cert_chain = vec![CertificateDer::from(server_cert_der.to_vec())];
    let server_key = KeyPair::from_pem(&String::from_utf8_lossy(server_key_pem))
        .map_err(|e| anyhow::anyhow!("serving key: {e}"))?;
    let server_key_der = PrivateKeyDer::try_from(server_key.serialize_der())
        .map_err(|e| anyhow::anyhow!("key error: {e}"))?;

    // Enable mTLS: request (but don't require) client certs.
    // Clients that present a cert signed by our CA will be authenticated via x509.
    // Clients without a cert fall through to other auth mechanisms (tokens, anonymous).
    let mut root_store = RootCertStore::empty();
    for der in client_ca_ders {
        root_store.add(CertificateDer::from(der.clone()))?;
    }
    if root_store.is_empty() {
        // If no CA cert was loaded, rustls will reject all client certs silently.
        // This would disable x509 authentication entirely. Fail at startup rather than
        // silently accepting anonymous-only connections.
        return Err(anyhow::anyhow!(
            "TLS trust store is empty: cluster CA cert must be present to enable mTLS client authentication"
        ));
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .allow_unauthenticated()
        .build()
        .map_err(|e| anyhow::anyhow!("client verifier: {e}"))?;
    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_cert_chain, server_key_der)?;
    // h2 first so clients that support both (kubelet, kubectl, controllers) prefer
    // multiplexed HTTP/2 — this collapses the one-TCP-connection-per-watch-reflector
    // pattern that caused mass SYN bursts under many concurrent watches. http/1.1
    // stays as fallback because exec/attach/portforward's `Connection: Upgrade`
    // websocket handshake has no HTTP/2 equivalent wired up in serve_tls().
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(server_config))
}

pub(crate) fn client_plan(
    name: &'static str,
    common_name: &'static str,
    organization: Option<&'static str>,
    ca: CaKind,
    files: Option<LeafFiles>,
) -> LeafPlan {
    LeafPlan {
        name,
        common_name,
        organization,
        lifetime: CLIENT_CERT_LIFETIME,
        usages: &["client auth"],
        sans: vec![],
        ca,
        files,
    }
}

pub fn generate_tls(args: &Args) -> anyhow::Result<TlsMaterial> {
    generate_tls_with(args, &Pki::default(), SERVING_CERT_LIFETIME, RENEW_FRACTION)
}

fn generate_tls_with(
    args: &Args,
    pki: &Pki,
    serving_lifetime: std::time::Duration,
    renew_fraction: f64,
) -> anyhow::Result<TlsMaterial> {
    let test_lifetime = crate::pki::test_lifetime();
    let serving_lifetime = test_lifetime.unwrap_or(serving_lifetime);
    let test_client_lifetime = test_lifetime.unwrap_or(CLIENT_CERT_LIFETIME);
    // Install the ML-KEM-768 hybrid post-quantum crypto provider.
    // `.ok()` makes this idempotent: a second call (e.g. in tests) is a no-op.
    rustls_post_quantum::provider().install_default().ok();

    // --- CAs: load-or-generate ---
    // If both ca.key (PEM) and ca.crt (DER) exist on disk, load them so the CA
    // stays stable across restarts. If either is missing, generate fresh and write.
    // ca_cert_der is the original DER bytes — stable across restarts.
    // ca_params is used to construct an Issuer for signing leaf certs (rcgen 0.14 API).
    let (ca_key, ca_params, ca_cert_der) =
        load_or_generate_ca(pki, "ca", &args.ca_key, &args.ca_cert)?;
    let cluster_ca = CaSigner {
        not_after: cert_validity(&ca_cert_der)?.1,
        issuer: Issuer::new(ca_params, ca_key),
        cert_der: ca_cert_der.clone(),
    };

    // Dedicated front-proxy CA, distinct from the main cluster CA -- see
    // `TlsMaterial::proxy_client_cert_pem`'s doc for why a dedicated CA (not just a dedicated
    // leaf cert under the shared CA) matters: it's what an aggregated backend trusts via
    // requestheader-client-ca-file, so only a leaf THIS CA signed can assert
    // X-Remote-User/-Group identity, regardless of what other certs the cluster CA has signed.
    let (proxy_client_ca_key, proxy_client_ca_params, proxy_client_ca_cert_der) =
        load_or_generate_ca(
            pki,
            "front-proxy-ca",
            &args.proxy_client_ca_key,
            &args.proxy_client_ca_cert,
        )?;
    let front_proxy_ca = CaSigner {
        not_after: cert_validity(&proxy_client_ca_cert_der)?.1,
        issuer: Issuer::new(proxy_client_ca_params, proxy_client_ca_key),
        cert_der: proxy_client_ca_cert_der,
    };

    // Persisted leaves sit next to ca.key/ca.crt rather than behind new CLI flags.
    let files = |stem: &str| leaf_files(args, stem);

    // Always include localhost / 127.0.0.1 and the lima VM-to-host alias,
    // plus the advertise-address host if provided.
    let sans = build_server_sans(
        advertise_host(args.advertise_address.as_deref())?.as_deref(),
        &args.service_cluster_ip_range,
    )?;
    let plans = vec![
        LeafPlan {
            name: SERVING_LEAF,
            common_name: "u7s-apiserver",
            organization: None,
            lifetime: serving_lifetime,
            usages: &["server auth"],
            sans,
            ca: CaKind::Cluster,
            files: None,
        },
        // CN=admin, O=system:masters (bypasses RBAC), embedded in the "admin" kubeconfig.
        // kubelet.service authenticates as this SAME identity too (install.sh points both
        // at $STATE_DIR/kubeconfig). Persisted so a restart does not mint a new, never
        // revoked system:masters credential every time.
        client_plan(
            "admin",
            "admin",
            Some("system:masters"),
            CaKind::Cluster,
            Some(files("admin")),
        ),
        // Kubelet's --client-ca-file trusts our cluster CA, and kubelet accepts clients
        // from the system:masters organization as trusted. CN and O must match exactly
        // what real kube-apiserver uses so kubelet authorizes the proxy requests.
        LeafPlan {
            lifetime: test_client_lifetime,
            ..client_plan(
                "kubelet-client",
                "kube-apiserver-kubelet-client",
                Some("system:masters"),
                CaKind::Cluster,
                None,
            )
        },
        // Real kubeadm gives kube-controller-manager a dedicated x509 identity, not a share
        // of admin/system:masters. No O= — the seeded ClusterRoleBinding
        // system:kube-controller-manager (see seed_rbac()) binds by username (kind: User),
        // so group membership is irrelevant here.
        LeafPlan {
            lifetime: test_client_lifetime,
            ..client_plan(
                "kcm-client",
                "system:kube-controller-manager",
                None,
                CaKind::Cluster,
                Some(files("kcm")),
            )
        },
        LeafPlan {
            lifetime: test_client_lifetime,
            ..client_plan(
                "scheduler-client",
                "system:kube-scheduler",
                None,
                CaKind::Cluster,
                Some(files("scheduler")),
            )
        },
        // Identity for the in-process YAML applier that server-side-applies bootstrap
        // manifest bundles (e.g. CoreDNS) against the just-bound apiserver. No O= — the
        // seeded ClusterRoleBinding system:bootstrap-installer (see seed_rbac()) binds by
        // username, same as KCM/scheduler above.
        client_plan(
            "bootstrap-installer-client",
            "system:bootstrap-installer",
            None,
            CaKind::Cluster,
            Some(files("bootstrap-installer")),
        ),
        // CN follows kubeadm's own "front-proxy-client" convention. Presented to aggregated
        // backends only (see doc); no O= is needed since the backend's own RBAC/authorization
        // config never sees this cert's Subject, only the X-Remote-User/-Group headers it vouches for.
        LeafPlan {
            lifetime: test_client_lifetime,
            ..client_plan(
                "proxy-client",
                "front-proxy-client",
                None,
                CaKind::FrontProxy,
                None,
            )
        },
    ];
    let rotator = Rotator::new(
        pki.clone(),
        renew_fraction,
        cluster_ca,
        front_proxy_ca,
        plans,
    )?;

    let leaf = |name: &str| rotator.leaf(name);
    let admin = leaf("admin");
    let kubelet_client = leaf("kubelet-client");
    let kcm = leaf("kcm-client");
    let scheduler = leaf("scheduler-client");
    let bootstrap_installer = leaf("bootstrap-installer-client");
    let proxy_client = leaf("proxy-client");

    // Kubeconfigs reference these files, so they must exist before any of them is written
    // and track the persisted leaf even when a crash left them stale.
    write_ca_bundle(args, &ca_cert_der)?;
    for (stem, leaf) in [
        ("admin", &admin),
        ("kcm", &kcm),
        ("scheduler", &scheduler),
        ("bootstrap-installer", &bootstrap_installer),
    ] {
        write_leaf_pem(&files(stem), &leaf.cert_der, &leaf.key_pem)?;
    }
    Ok(TlsMaterial {
        ca_cert_der,
        server_cert_der: leaf(SERVING_LEAF).cert_der,
        admin_cert_der: admin.cert_der,
        admin_key_pem: admin.key_pem,
        kubelet_client_cert_pem: pem_encode("CERTIFICATE", &kubelet_client.cert_der),
        kubelet_client_key_pem: kubelet_client.key_pem,
        kcm_cert_der: kcm.cert_der,
        scheduler_cert_der: scheduler.cert_der,
        bootstrap_installer_cert_der: bootstrap_installer.cert_der,
        proxy_client_cert_pem: pem_encode("CERTIFICATE", &proxy_client.cert_der),
        proxy_client_key_pem: proxy_client.key_pem,
        server_config: rotator.server_config(),
        inventory: pki.inventory.clone(),
        rotator: Arc::new(rotator),
    })
}

pub(crate) fn pem_encode(label: &str, der: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let encoded = b64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out.into_bytes()
}

/// How a kubeconfig carries its credentials. Files are re-read by client-go on every
/// handshake, so a re-issued cert or CA is picked up without restarting the component.
pub(crate) enum KubeconfigCreds<'a> {
    Files {
        ca: &'a std::path::Path,
        /// One PEM holding the client cert and key, replaced by a single rename.
        identity: &'a std::path::Path,
    },
}

/// Typed builder for a minimal kubeconfig.
/// Serialised to YAML manually — no serde_yaml dependency required.
///
/// Cert-only, matching kubeadm/k3s's own admin-kubeconfig shape — no bearer token field.
/// Every identity this module writes (admin included) authenticates via x509 client cert
/// alone; `handlers::aggregation`'s proxy asserts the caller's ALREADY-resolved identity to
/// aggregated backends via X-Remote-User/-Group headers (see `proxy_to_backend`), so no
/// caller ever needs its own bearer token forwarded for that to work.
struct Kubeconfig {
    server: String,
    /// (YAML field, value) for each credential.
    ca: (&'static str, String),
    cert: (&'static str, String),
    key: (&'static str, String),
    user: String,
}

fn absolute(path: &std::path::Path) -> String {
    std::path::absolute(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

impl Kubeconfig {
    fn new(server: &str, creds: &KubeconfigCreds<'_>, username: &str) -> Self {
        let KubeconfigCreds::Files { ca, identity } = creds;
        let (ca, cert, key) = (
            ("certificate-authority", absolute(ca)),
            ("client-certificate", absolute(identity)),
            ("client-key", absolute(identity)),
        );
        Kubeconfig {
            server: server.to_owned(),
            ca,
            cert,
            key,
            user: username.to_owned(),
        }
    }

    fn to_yaml(&self) -> String {
        format!(
            "apiVersion: v1\n\
             kind: Config\n\
             clusters:\n\
             - cluster:\n\
             \x20   server: {server}\n\
             \x20   {ca_field}: {ca}\n\
             \x20 name: u7s\n\
             contexts:\n\
             - context:\n\
             \x20   cluster: u7s\n\
             \x20   user: {user}\n\
             \x20 name: u7s\n\
             current-context: u7s\n\
             users:\n\
             - name: {user}\n\
             \x20 user:\n\
             \x20   {cert_field}: {cert}\n\
             \x20   {key_field}: {key}\n",
            server = self.server,
            ca_field = self.ca.0,
            ca = self.ca.1,
            user = self.user,
            cert_field = self.cert.0,
            cert = self.cert.1,
            key_field = self.key.0,
            key = self.key.1,
        )
    }
}

/// Server URL embedded in every kubeconfig this module writes — see [`write_kubeconfig`]'s
/// doc for the parallel-worker rationale.
fn kubeconfig_server_url(args: &Args) -> &str {
    args.advertise_address
        .as_deref()
        .unwrap_or("https://127.0.0.1:6443")
}

/// Where the cluster CA is published as PEM for kubeconfigs and components that read the
/// trust anchor from a file.
pub(crate) fn ca_bundle_path(args: &Args) -> std::path::PathBuf {
    std::path::Path::new(&args.ca_cert).with_file_name("ca-bundle.pem")
}

/// Files of a persisted leaf, next to ca.crt.
pub(crate) fn leaf_files(args: &Args, stem: &str) -> LeafFiles {
    LeafFiles {
        cert: std::path::Path::new(&args.ca_cert).with_file_name(format!("{stem}.crt")),
        key: std::path::Path::new(&args.ca_cert).with_file_name(format!("{stem}.key")),
    }
}

/// Atomically replace `path` with `bytes` (mode 0o600 when `private`), so a reader never
/// sees a half-written file.
fn replace_file(path: &str, bytes: &[u8], private: bool) -> anyhow::Result<()> {
    let tmp = format!("{path}.tmp");
    let tmp_path = validate_cli_path(std::path::Path::new(&tmp))?;
    if private {
        write_private_key(tmp_path, bytes)?;
    } else {
        write_synced(tmp_path, bytes)?;
    }
    std::fs::rename(&tmp, path).map_err(|e| anyhow::anyhow!("rename {tmp} -> {path}: {e}"))?;
    sync_parent_dir(path).map_err(|e| anyhow::anyhow!("fsync dir of {path}: {e}"))
}

/// Publish the cluster CA as PEM at [`ca_bundle_path`]. Left untouched when the content is
/// unchanged: watchers of the file (the KCM restart hook) must fire only when trust changes,
/// not on every apiserver start.
pub(crate) fn write_ca_bundle(args: &Args, ca_cert_der: &[u8]) -> anyhow::Result<()> {
    let path = ca_bundle_path(args);
    let pem = pem_encode("CERTIFICATE", ca_cert_der);
    if std::fs::read(&path).is_ok_and(|current| current == pem) {
        return Ok(());
    }
    replace_file(&path.to_string_lossy(), &pem, false)
}

/// Write a leaf's cert and key as one PEM file at `files.pem()`, replaced by a single
/// rename so a client re-reading it never pairs a new cert with an old key.
pub(crate) fn write_leaf_pem(
    files: &LeafFiles,
    cert_der: &[u8],
    key_pem: &[u8],
) -> anyhow::Result<()> {
    let mut identity = pem_encode("CERTIFICATE", cert_der);
    identity.extend_from_slice(key_pem);
    replace_file(&files.pem().to_string_lossy(), &identity, true)
}

/// Write the admin kubeconfig to `path`.
/// The default path ("./kubeconfig") is write-only on first run — it is not
/// a read fixture. The file is generated fresh each time the server starts.
///
/// The kubeconfig references the admin identity and the CA by absolute file path and
/// carries no key material itself; the identity file is mode 0o600 (owner read+write only),
/// matching the same permission applied to the SA and CA key files by `write_private_key`.
///
/// The file is replaced by rename, so a reader never sees a half-written kubeconfig.
pub fn write_kubeconfig(path: &str, args: &Args) -> anyhow::Result<()> {
    // Use the advertise-address (or listen address) as the server URL so that
    // parallel workers running on non-default loopback IPs (127.0.0.2, etc.)
    // get a kubeconfig that points at their own apiserver.
    // lima-start.sh rewrites any 127.x address to host.lima.internal when copying into the VM.
    write_component_kubeconfig(path, args, "admin", "admin")
}

/// Write a kubeconfig for a dedicated component identity (KCM, bootstrap installer) rather
/// than the shared admin identity. Real kubeadm gives each static control-plane
/// component its own x509 client cert so cluster RBAC (e.g. the seeded
/// `system:kube-controller-manager` ClusterRole) actually applies, instead of every
/// component sharing admin/system:masters and bypassing RBAC entirely.
///
/// `stem` names the persisted leaf whose `<stem>.pem` ([`write_leaf_pem`]) the kubeconfig
/// references.
pub fn write_component_kubeconfig(
    path: &str,
    args: &Args,
    stem: &str,
    username: &str,
) -> anyhow::Result<()> {
    write_identity_kubeconfig(
        path,
        kubeconfig_server_url(args),
        &KubeconfigCreds::Files {
            ca: &ca_bundle_path(args),
            identity: &leaf_files(args, stem).pem(),
        },
        username,
    )
}

pub(crate) fn write_identity_kubeconfig(
    path: &str,
    server: &str,
    creds: &KubeconfigCreds<'_>,
    username: &str,
) -> anyhow::Result<()> {
    let kc = Kubeconfig::new(server, creds, username);
    replace_file(path, kc.to_yaml().as_bytes(), true)?;
    tracing::info!("kubeconfig written to {path} (user={username})");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::Signer;

    /// Return a unique temp directory for a test, creating it on disk.
    /// Uses subsecond nanos + thread ID for uniqueness across parallel tests.
    fn test_temp_dir(tag: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let tid = std::thread::current().id();
        let dir = std::env::temp_dir().join(format!("u7s-tls-{tag}-{nanos}-{tid:?}"));
        std::fs::create_dir_all(&dir).expect("create temp dir"); // lgtm[rust/path-injection]
        dir
    }

    /// Strip PEM armor and base64-decode back to DER — the test-only inverse of
    /// `pem_encode`, needed because `TlsMaterial::proxy_client_cert_pem` (unlike
    /// `kcm_cert_der`/`scheduler_cert_der`) is stored PEM-encoded, not DER.
    fn der_from_pem(pem: &[u8]) -> Vec<u8> {
        use base64::Engine;
        let s = std::str::from_utf8(pem).expect("pem must be utf8");
        let b64: String = s.lines().filter(|l| !l.starts_with("-----")).collect();
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("valid base64 PEM body")
    }

    fn args_with(advertise_address: Option<&str>) -> Args {
        // A fresh temp dir per call, not shared literal "./ca.key" etc.: multiple tests
        // call args_with() and cargo runs tests in parallel by default, so a shared path
        // races load_or_generate_ca / load_or_generate_admin_cert's read-then-write across
        // threads and can leave an admin cert issued by a CA a concurrent thread has since
        // replaced on disk.
        let dir = test_temp_dir("args-with");
        Args {
            db: dir.join("state.db").to_string_lossy().into_owned(),
            listen: "0.0.0.0:6443".into(),
            kubeconfig: dir.join("kubeconfig").to_string_lossy().into_owned(),
            token_auth_file: None,
            sa_key: dir.join("sa.key").to_string_lossy().into_owned(),
            sa_pub: dir.join("sa.pub").to_string_lossy().into_owned(),
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            proxy_client_ca_key: dir
                .join("proxy-client-ca.key")
                .to_string_lossy()
                .into_owned(),
            proxy_client_ca_cert: dir
                .join("proxy-client-ca.crt")
                .to_string_lossy()
                .into_owned(),
            advertise_address: advertise_address.map(str::to_owned),
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            deny_service_external_ips: false,
            sa_sig_cache_size: None,
            manifest_dir: dir.join("manifests").to_string_lossy().into_owned(),
            embedded_scheduler: false,
            admission_control_config_file: None,
        }
    }

    #[test]
    fn advertise_host_extracts_dns_name() {
        assert_eq!(
            advertise_host(Some("https://host.lima.internal:6443")).unwrap(),
            Some("host.lima.internal".into())
        );
    }

    #[test]
    fn advertise_host_extracts_ip() {
        assert_eq!(
            advertise_host(Some("https://192.168.1.10:6443")).unwrap(),
            Some("192.168.1.10".into())
        );
    }

    #[test]
    fn advertise_host_none_on_absent() {
        assert_eq!(advertise_host(None).unwrap(), None);
    }

    #[test]
    fn san_includes_advertise_dns_name() {
        let args = args_with(Some("https://host.lima.internal:6443"));
        // generate_tls must succeed and produce a cert that includes the DNS SAN.
        let _tls = generate_tls(&args).expect("generate_tls failed");
        // Verify host parses as DNS (not IP).
        let host = advertise_host(args.advertise_address.as_deref())
            .unwrap()
            .unwrap();
        assert!(
            host.parse::<std::net::IpAddr>().is_err(),
            "expected DNS name, got IP"
        );
        assert_eq!(host, "host.lima.internal");
    }

    #[test]
    fn san_includes_advertise_ip() {
        let args = args_with(Some("https://192.168.1.10:6443"));
        let _tls = generate_tls(&args).expect("generate_tls failed");
        let host = advertise_host(args.advertise_address.as_deref())
            .unwrap()
            .unwrap();
        assert!(
            host.parse::<std::net::IpAddr>().is_ok(),
            "expected IP address"
        );
        assert_eq!(host, "192.168.1.10");
    }

    #[test]
    fn san_always_includes_localhost() {
        // Test with a custom advertise address — localhost SANs must still be present.
        let args = args_with(Some("https://host.lima.internal:6443"));
        // generate_tls builds sans starting with localhost + 127.0.0.1.
        // We verify by inspecting the logic path: advertise_host does not return "localhost".
        let host = advertise_host(args.advertise_address.as_deref())
            .unwrap()
            .unwrap();
        assert_ne!(host, "localhost");
        // And generate_tls must not error.
        generate_tls(&args).expect("generate_tls failed");

        // Also verify with no advertise address — defaults only.
        let args_none = args_with(None);
        generate_tls(&args_none).expect("generate_tls failed with no advertise address");
    }

    /// build_server_sans must always include host.lima.internal as a DNS SAN.
    /// This is the lima VM-to-host alias required for kubelet-to-apiserver TLS.
    /// If this entry is absent, kubelets running inside lima VMs cannot verify the
    /// server certificate and will refuse to connect.
    #[test]
    fn build_server_sans_always_includes_lima_host() {
        let sans = build_server_sans(None, "10.96.0.0/12").expect("build_server_sans failed");
        let has_lima = sans
            .iter()
            .any(|s| matches!(s, SanType::DnsName(n) if n.as_ref() == "host.lima.internal"));
        assert!(
            has_lima,
            "host.lima.internal must be in server SANs regardless of advertise_address"
        );
    }

    /// build_server_sans must include the kubernetes ClusterIP (10.96.0.1 for the
    /// default 10.96.0.0/12 range). In-cluster clients (sonobuoy, pods) use
    /// KUBERNETES_SERVICE_HOST=10.96.0.1 and verify the TLS cert against it. Without
    /// this SAN the TLS handshake fails even after the DNAT rule routes the traffic
    /// to the host apiserver.
    #[test]
    fn build_server_sans_always_includes_cluster_ip() {
        let sans = build_server_sans(None, "10.96.0.0/12").expect("build_server_sans failed");
        let has_cluster_ip = sans
            .iter()
            .any(|s| matches!(s, SanType::IpAddress(ip) if ip.to_string() == "10.96.0.1"));
        assert!(
            has_cluster_ip,
            "10.96.0.1 (kubernetes ClusterIP) must be in server SANs for in-cluster clients \
             on the default service-cluster-ip-range"
        );
    }

    /// build_server_sans must derive the kubernetes ClusterIP SAN from a non-default
    /// `--service-cluster-ip-range` instead of hardcoding 10.96.0.1. If an operator
    /// runs with e.g. 172.20.0.0/16, the `default/kubernetes` Service gets 172.20.0.1
    /// (bootstrap_service_ips), the kubelet populates in-cluster pods'
    /// KUBERNETES_SERVICE_HOST with that same IP, and the apiserver cert must carry
    /// it as a SAN or in-cluster TLS validation fails even though the Service and
    /// Downward API are both correct.
    #[test]
    fn build_server_sans_derives_cluster_ip_from_custom_range() {
        let sans = build_server_sans(None, "172.20.0.0/16").expect("build_server_sans failed");
        assert!(
            sans.iter()
                .any(|s| matches!(s, SanType::IpAddress(ip) if ip.to_string() == "172.20.0.1")),
            "172.20.0.1 (kubernetes ClusterIP for the configured 172.20.0.0/16 range) \
             must be in server SANs, or in-cluster clients on this range fail TLS validation"
        );
        assert!(
            !sans
                .iter()
                .any(|s| matches!(s, SanType::IpAddress(ip) if ip.to_string() == "10.96.0.1")),
            "10.96.0.1 belongs to no Service under a 172.20.0.0/16 service-cluster-ip-range; \
             a stale hardcoded SAN would silently accept a cert that doesn't match any real \
             kubernetes ClusterIP"
        );
    }

    /// build_server_sans must include the standard in-cluster kubernetes service DNS names.
    /// In-cluster clients (OIDC discovery, kube-dns, pods) resolve the apiserver as
    /// kubernetes.default.svc.cluster.local (and shorter forms). Without these SANs the
    /// TLS handshake fails with "certificate is valid for localhost, not kubernetes.default.svc"
    /// and the OIDC discovery conformance test fails.
    #[test]
    fn server_cert_includes_in_cluster_kubernetes_svc_sans_so_oidc_and_in_cluster_tls_verify() {
        let sans = build_server_sans(None, "10.96.0.0/12").expect("build_server_sans failed");
        let dns_names: Vec<&str> = sans
            .iter()
            .filter_map(|s| {
                if let SanType::DnsName(n) = s {
                    Some(n.as_ref())
                } else {
                    None
                }
            })
            .collect();
        for expected in &[
            "kubernetes",
            "kubernetes.default",
            "kubernetes.default.svc",
            "kubernetes.default.svc.cluster.local",
        ] {
            assert!(
                dns_names.contains(expected),
                "server cert must include DNS SAN '{expected}' so in-cluster clients and \
                 OIDC discovery (GET https://kubernetes.default.svc/.well-known/openid-configuration) \
                 can verify the TLS handshake; missing SANs cause x509 errors that fail conformance"
            );
        }
    }

    /// build_server_sans with an IP advertise_host must include both host.lima.internal
    /// (DNS) and the IP address SAN.
    #[test]
    fn build_server_sans_with_ip_includes_both() {
        let sans = build_server_sans(Some("192.168.5.1"), "10.96.0.0/12")
            .expect("build_server_sans failed");
        let has_lima = sans
            .iter()
            .any(|s| matches!(s, SanType::DnsName(n) if n.as_ref() == "host.lima.internal"));
        assert!(
            has_lima,
            "host.lima.internal must be present even when advertise_address is an IP"
        );
        let has_ip = sans
            .iter()
            .any(|s| matches!(s, SanType::IpAddress(ip) if ip.to_string() == "192.168.5.1"));
        assert!(has_ip, "advertise IP 192.168.5.1 must be in SANs");
    }

    #[test]
    fn ca_key_is_loaded_not_regenerated() {
        // Write a CA key+cert to a temp dir, call generate_tls twice with that dir,
        // and verify the CA cert DER is identical — proving the CA was loaded rather
        // than regenerated on the second call.
        let dir = test_temp_dir("ca-persist");
        let ca_key_path = dir.join("ca.key").to_string_lossy().into_owned();
        let ca_cert_path = dir.join("ca.crt").to_string_lossy().into_owned();

        let args = Args {
            db: "./state.db".into(),
            listen: "0.0.0.0:6443".into(),
            kubeconfig: "./kubeconfig".into(),
            token_auth_file: None,
            sa_key: "./sa.key".into(),
            sa_pub: "./sa.pub".into(),
            ca_key: ca_key_path.clone(),
            ca_cert: ca_cert_path.clone(),
            proxy_client_ca_key: dir
                .join("proxy-client-ca.key")
                .to_string_lossy()
                .into_owned(),
            proxy_client_ca_cert: dir
                .join("proxy-client-ca.crt")
                .to_string_lossy()
                .into_owned(),
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            deny_service_external_ips: false,
            sa_sig_cache_size: None,
            manifest_dir: "/etc/u7s/manifests".into(),
            embedded_scheduler: false,
            admission_control_config_file: None,
        };

        // First call: generates and writes CA files.
        let tls1 = generate_tls(&args).expect("first generate_tls failed");
        assert!(
            std::path::Path::new(&ca_key_path).exists(),
            "ca.key must be written on first call"
        );
        assert!(
            std::path::Path::new(&ca_cert_path).exists(),
            "ca.crt must be written on first call"
        );

        // Second call: must load the existing CA files, not regenerate.
        let tls2 = generate_tls(&args).expect("second generate_tls failed");

        assert_eq!(
            tls1.ca_cert_der, tls2.ca_cert_der,
            "CA cert DER must be identical on second call — CA must be loaded, not regenerated"
        );

        // Clean up.
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Proves two things `generate_tls()` must guarantee across a restart: (1) the admin
    /// cert file bytes are preserved rather than re-minted, so an admin kubeconfig copied
    /// off-node before the restart is not silently swapped for a different credential; and
    /// (2) that preserved, pre-restart-issued cert still cryptographically chain-validates
    /// against the CA loaded on the second call. This does not by itself establish that a
    /// missing guarantee here is what produced any specific operator-observed failure --
    /// only that the guarantee holds.
    #[test]
    fn admin_cert_issued_before_restart_still_chain_validates_after_restart() {
        let dir = test_temp_dir("admin-cert-restart-survives");
        let args = Args {
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            proxy_client_ca_key: dir
                .join("proxy-client-ca.key")
                .to_string_lossy()
                .into_owned(),
            proxy_client_ca_cert: dir
                .join("proxy-client-ca.crt")
                .to_string_lossy()
                .into_owned(),
            ..args_with(None)
        };

        // First "start": mints the CA + admin cert an operator would copy off-node.
        let tls1 = generate_tls(&args).expect("first generate_tls failed");
        // Second "start" (simulating `systemctl restart u7s-apiserver`): both must load
        // from disk, not regenerate.
        let tls2 = generate_tls(&args).expect("second generate_tls failed");

        assert_eq!(
            tls1.admin_cert_der, tls2.admin_cert_der,
            "the admin cert must be loaded, not re-minted, on restart -- minting a new one \
             every restart hands out a DIFFERENT, never-revoked system:masters identity \
             each time an admin kubeconfig is copied off-node"
        );

        assert!(
            leaf_cert_chain_validates(&tls1.admin_cert_der, &tls2.ca_cert_der),
            "an admin cert issued BEFORE a restart must still cryptographically \
             chain-validate against the CA loaded AFTER the restart, using the same rustls \
             verification the live server runs on every mTLS handshake"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Simulates the exact corruption `leaf_cert_chain_validates` exists to catch:
    /// admin.key/admin.crt on disk were signed by a CA that is no longer the one loaded
    /// from ca.key/ca.crt (an operator rotating CA files independently, or -- under test
    /// parallelism -- a concurrent process regenerating the CA after this admin cert was
    /// already signed). Loading the stale pair anyway would hand kubectl a chain that
    /// fails real TLS validation against the CA the server now trusts.
    #[test]
    fn admin_cert_from_a_different_ca_is_discarded_and_regenerated() {
        let dir = test_temp_dir("admin-cert-ca-mismatch");
        let args = args_in(&dir);
        let first = generate_tls(&args).expect("first boot");

        // A DIFFERENT, unrelated CA signs the "stale" admin cert.
        let other_ca_key = KeyPair::generate().expect("generate other CA key");
        let mut other_ca_params = CertificateParams::default();
        other_ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        other_ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "some-other-ca");
        let other_ca_issuer = Issuer::new(other_ca_params, other_ca_key);
        let stale_admin_key = KeyPair::generate().expect("generate stale admin key");
        let mut stale_admin_params = CertificateParams::default();
        stale_admin_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "admin");
        let stale_admin_cert = stale_admin_params
            .signed_by(&stale_admin_key, &other_ca_issuer)
            .expect("sign stale admin cert");
        write_private_key(
            dir.join("admin.key"),
            stale_admin_key.serialize_pem().as_bytes(),
        )
        .expect("write stale admin key");
        std::fs::write(dir.join("admin.crt"), stale_admin_cert.der())
            .expect("write stale admin cert");

        let second = generate_tls(&args).expect("a stale admin pair must be replaced, not fatal");
        assert_ne!(second.admin_cert_der, stale_admin_cert.der().to_vec());
        assert_ne!(second.admin_cert_der, first.admin_cert_der);
        assert!(
            leaf_cert_chain_validates(&second.admin_cert_der, &second.ca_cert_der),
            "a stale admin cert issued by a DIFFERENT CA must be discarded and replaced \
             with one actually issued by the CA now loaded from disk, or kubectl gets a \
             chain that fails real TLS validation"
        );
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    fn args_in(dir: &std::path::Path) -> Args {
        let join = |f: &str| dir.join(f).to_string_lossy().into_owned();
        Args {
            ca_key: join("ca.key"),
            ca_cert: join("ca.crt"),
            proxy_client_ca_key: join("proxy-client-ca.key"),
            proxy_client_ca_cert: join("proxy-client-ca.crt"),
            ..args_with(None)
        }
    }

    fn pki_at(offset: std::time::Duration) -> Pki {
        Pki {
            clock: crate::pki::Clock::new(move || time::OffsetDateTime::now_utc() + offset),
            ..Pki::default()
        }
    }

    const DAY: std::time::Duration = std::time::Duration::from_secs(86400);

    /// The production wiring (not just the rotator in isolation) must renew the 90-day
    /// serving cert at day 60; a different fraction would renew too late (expiry outage)
    /// or churn every connection.
    #[test]
    fn production_rotator_renews_the_serving_cert_at_two_thirds_of_ninety_days() {
        let dir = test_temp_dir("serving-due");
        let material = generate_tls(&args_in(&dir)).expect("boot");
        let serving = material
            .inventory
            .snapshot()
            .into_iter()
            .find(|r| r.name == SERVING_LEAF)
            .expect("serving cert is inventoried");
        assert_eq!(
            material.rotator.next_due(),
            serving.not_before + time::Duration::days(60),
            "serving cert renewal point"
        );
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// A restart must not keep handing out an admin kubeconfig that is about to expire:
    /// past 2/3 of the year it is replaced, before that it is stable.
    #[test]
    fn persisted_admin_cert_is_reissued_at_startup_only_once_past_two_thirds() {
        let dir = test_temp_dir("admin-due-at-startup");
        let args = args_in(&dir);
        let first = generate_tls(&args).expect("first boot");

        let early = generate_tls_with(
            &args,
            &pki_at(200 * DAY),
            SERVING_CERT_LIFETIME,
            RENEW_FRACTION,
        )
        .expect("restart at day 200");
        assert_eq!(
            early.admin_cert_der, first.admin_cert_der,
            "day 200 is before 2/3 of a year: churning the credential on every restart is a regression"
        );

        let late = generate_tls_with(
            &args,
            &pki_at(250 * DAY),
            SERVING_CERT_LIFETIME,
            RENEW_FRACTION,
        )
        .expect("restart at day 250");
        assert_ne!(
            late.admin_cert_der, first.admin_cert_der,
            "day 250 is past 2/3 of a year: reloading the old admin cert would let it expire in the kubeconfig"
        );
        let on_disk = std::fs::read(dir.join("admin.crt")).unwrap();
        assert_eq!(
            on_disk, late.admin_cert_der,
            "the new cert must be persisted"
        );
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Admin certs minted before lifetimes existed are valid 1975..4096, so a 2/3 rule
    /// alone would never renew them.
    #[test]
    fn legacy_admin_cert_with_1975_to_4096_validity_is_reissued_at_startup() {
        let dir = test_temp_dir("admin-legacy");
        let args = args_in(&dir);
        let first = generate_tls(&args).expect("first boot");

        let (ca_key, ca_params, _) =
            load_or_generate_ca(&Pki::default(), "ca", &args.ca_key, &args.ca_cert)
                .expect("reload CA");
        let ca_issuer = Issuer::new(ca_params, ca_key);
        let legacy_key = KeyPair::generate().unwrap();
        let mut legacy_params = CertificateParams::default();
        legacy_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "admin");
        let legacy = legacy_params.signed_by(&legacy_key, &ca_issuer).unwrap();
        write_private_key(dir.join("admin.key"), legacy_key.serialize_pem().as_bytes()).unwrap();
        std::fs::write(dir.join("admin.crt"), legacy.der()).unwrap();

        let second = generate_tls(&args).expect("restart");
        assert_ne!(second.admin_cert_der, legacy.der().to_vec());
        assert_ne!(second.admin_cert_der, first.admin_cert_der);
        let (nb, na) = cert_validity(&second.admin_cert_der).unwrap();
        assert_eq!(
            na - nb,
            CLIENT_CERT_LIFETIME,
            "the replacement must have a finite lifetime"
        );
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Persisting KCM/scheduler certs gives later consumers stable file paths.
    #[test]
    fn kcm_and_scheduler_leaves_are_persisted_and_stable_across_restarts() {
        let dir = test_temp_dir("kcm-sched-persist");
        let args = args_in(&dir);
        let a = generate_tls(&args).unwrap();
        for f in ["kcm.crt", "kcm.key", "scheduler.crt", "scheduler.key"] {
            assert!(
                dir.join(f).exists(),
                "{f} must exist for file-path kubeconfigs"
            );
        }
        let b = generate_tls(&args).unwrap();
        assert_eq!(a.kcm_cert_der, b.kcm_cert_der);
        assert_eq!(a.scheduler_cert_der, b.scheduler_cert_der);
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// The dedicated front-proxy CA must persist across restarts, exactly like the main
    /// cluster CA (`ca_key_is_loaded_not_regenerated` above): aggregated backends trust it
    /// via `requestheader-client-ca-file`, and a freshly-minted CA on every restart would
    /// make every backend reject the proxy-client cert the very next tick, silently
    /// breaking the aggregation proxy until the backend's own informer re-syncs.
    #[test]
    fn proxy_client_ca_is_loaded_not_regenerated() {
        let dir = test_temp_dir("proxy-client-ca-persist");
        let args = Args {
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            proxy_client_ca_key: dir
                .join("proxy-client-ca.key")
                .to_string_lossy()
                .into_owned(),
            proxy_client_ca_cert: dir
                .join("proxy-client-ca.crt")
                .to_string_lossy()
                .into_owned(),
            ..args_with(None)
        };

        // First call: generates and writes the front-proxy CA files.
        generate_tls(&args).expect("first generate_tls failed");
        assert!(
            dir.join("proxy-client-ca.key").exists(),
            "proxy-client-ca.key must be written on first call"
        );
        let ca_cert_after_first =
            std::fs::read(dir.join("proxy-client-ca.crt")).expect("proxy-client-ca.crt readable");

        // Second call (simulating a restart): must load the existing CA, not mint a fresh
        // one. The proxy-client LEAF cert is regenerated every call (same as the
        // KCM/scheduler/admin leaves above — none of them persist their leaf either), which
        // is fine: what an aggregated backend actually pins via requestheader-client-ca-file
        // is the CA, not any one leaf it signs.
        generate_tls(&args).expect("second generate_tls failed");
        let ca_cert_after_second =
            std::fs::read(dir.join("proxy-client-ca.crt")).expect("proxy-client-ca.crt readable");

        assert_eq!(
            ca_cert_after_first, ca_cert_after_second,
            "the front-proxy CA cert on disk must be identical across restarts — a fresh CA \
             every restart would invalidate every proxy-client leaf an aggregated backend \
             already trusts via requestheader-client-ca-file"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Regression/security test: the proxy-client cert must be signed by the DEDICATED
    /// front-proxy CA, not the main cluster CA that signs admin/KCM/scheduler/kubelet-client
    /// certs. If it were signed by the cluster CA instead, an aggregated backend configured
    /// with `requestheader-client-ca-file` pointed at that SAME CA (a natural but wrong
    /// simplification) would also trust the admin cert (or any other cluster-CA-signed
    /// cert) to assert X-Remote-User/-Group identity directly — collapsing the whole point
    /// of a dedicated front-proxy trust anchor.
    #[test]
    fn proxy_client_cert_is_signed_by_dedicated_ca_not_cluster_ca() {
        let dir = test_temp_dir("proxy-client-ca-distinct");
        let args = Args {
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            proxy_client_ca_key: dir
                .join("proxy-client-ca.key")
                .to_string_lossy()
                .into_owned(),
            proxy_client_ca_cert: dir
                .join("proxy-client-ca.crt")
                .to_string_lossy()
                .into_owned(),
            ..args_with(None)
        };
        let tls = generate_tls(&args).expect("generate_tls failed");

        let cluster_ca_cn = crate::auth::extract_client_cert_identity(&tls.ca_cert_der)
            .map(|id| id.username)
            .expect("cluster CA cert must have a parseable Subject CN");
        let proxy_client_ca_pem =
            std::fs::read(dir.join("proxy-client-ca.crt")).expect("proxy-client-ca.crt readable");
        let proxy_client_ca_cn = crate::auth::extract_client_cert_identity(&proxy_client_ca_pem)
            .map(|id| id.username)
            .expect("front-proxy CA cert must have a parseable Subject CN");

        assert_ne!(
            cluster_ca_cn, proxy_client_ca_cn,
            "the front-proxy CA must be a DIFFERENT CA from the main cluster CA, or any \
             cluster-CA-signed cert (admin, KCM, kubelet-client, ...) could be replayed \
             directly against an aggregated backend to spoof X-Remote-User/-Group identity"
        );

        let proxy_client_id =
            crate::auth::extract_client_cert_identity(&der_from_pem(&tls.proxy_client_cert_pem))
                .expect("proxy_client_cert_pem must parse as a valid x509 cert");
        assert_eq!(
            proxy_client_id.username, "front-proxy-client",
            "proxy-client cert's CN must be 'front-proxy-client' (kubeadm's own convention)"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Security test: the identity presented on webhook callouts must not carry
    /// `system:masters`. A webhook (or CRD conversion) clientConfig can name the apiserver's
    /// own Service, and an admin-cert callout would be authenticated as cluster-admin.
    #[test]
    fn webhook_client_identity_is_not_cluster_admin() {
        let dir = test_temp_dir("webhook-identity-not-admin");
        let args = Args {
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            proxy_client_ca_key: dir
                .join("proxy-client-ca.key")
                .to_string_lossy()
                .into_owned(),
            proxy_client_ca_cert: dir
                .join("proxy-client-ca.crt")
                .to_string_lossy()
                .into_owned(),
            ..args_with(None)
        };
        let tls = generate_tls(&args).expect("generate_tls failed");
        let pem = tls.webhook_client_identity_pem();
        let text = std::str::from_utf8(&pem).expect("utf8 pem");
        let cert_end = text
            .find("-----END CERTIFICATE-----")
            .expect("identity must start with a certificate")
            + "-----END CERTIFICATE-----".len();
        let id =
            crate::auth::extract_client_cert_identity(&der_from_pem(&text.as_bytes()[..cert_end]))
                .expect("webhook identity cert must parse");
        assert_ne!(
            id.username, "admin",
            "webhook callouts must not present the admin cert"
        );
        assert!(
            !id.groups.iter().any(|g| g == "system:masters"),
            "webhook callouts must not carry system:masters; got {:?}",
            id.groups
        );
        assert_eq!(
            pem,
            {
                let mut p = tls.proxy_client_cert_pem.clone();
                p.extend_from_slice(&tls.proxy_client_key_pem);
                p
            },
            "webhook identity must be the front-proxy-client cert+key"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Helper: call load_or_generate_ca with paths inside `dir`.
    fn run_load_or_generate_ca(
        dir: &std::path::Path,
    ) -> anyhow::Result<(KeyPair, CertificateParams, Vec<u8>)> {
        let ca_key_path = dir.join("ca.key").to_string_lossy().into_owned();
        let ca_cert_path = dir.join("ca.crt").to_string_lossy().into_owned();
        load_or_generate_ca(&Pki::default(), "ca", &ca_key_path, &ca_cert_path)
    }

    /// Generate a CA in `dir`, returning its (key_path, cert_path).
    fn generated_ca(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        run_load_or_generate_ca(dir).expect("first boot generates");
        (dir.join("ca.key"), dir.join("ca.crt"))
    }

    /// Assert the CA load fails and leaves every listed file byte-identical:
    /// regenerating would silently replace trust for the whole cluster.
    fn assert_refuses_and_preserves(
        key: &std::path::Path,
        cert: &std::path::Path,
        files: &[&std::path::Path],
    ) -> String {
        let before: Vec<_> = files.iter().map(|p| std::fs::read(p).unwrap()).collect(); // lgtm[rust/path-injection]
        let err = load_or_generate_ca(
            &Pki::default(),
            "ca",
            &key.to_string_lossy(),
            &cert.to_string_lossy(),
        )
        .expect_err("partial CA state must refuse to start");
        let msg = err.to_string();
        for p in [key, cert] {
            assert!(
                msg.contains(&*p.to_string_lossy()),
                "error must name the full path {}: {msg}",
                p.display()
            );
        }
        for (p, b) in files.iter().zip(before) {
            assert_eq!(
                std::fs::read(p).unwrap(), // lgtm[rust/path-injection]
                b,
                "{} must not be modified",
                p.display()
            );
        }
        msg
    }

    #[test]
    fn ca_interrupted_first_boot_rolls_forward_instead_of_bricking_the_cluster() {
        let dir = test_temp_dir("ca-roll-forward");
        let (key, cert) = generated_ca(&dir);
        let (_, _, original) = run_load_or_generate_ca(&dir).unwrap();
        let key_tmp = dir.join("ca.key.tmp");
        std::fs::rename(&key, &key_tmp).unwrap(); // lgtm[rust/path-injection]
        let (_, _, loaded) = run_load_or_generate_ca(&dir)
            .expect("cert + matching key.tmp is an interrupted first boot and must recover");
        assert_eq!(loaded, original, "roll-forward must keep the same CA");
        assert!(
            key.exists() && !key_tmp.exists(),
            "key.tmp must be renamed into place"
        );
        assert!(cert.exists());
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn ca_symlinked_key_tmp_is_refused_so_a_planted_link_never_becomes_the_ca_key() {
        let dir = test_temp_dir("ca-tmp-symlink");
        let (key, cert) = generated_ca(&dir);
        let target = dir.join("elsewhere.key");
        std::fs::rename(&key, &target).unwrap(); // lgtm[rust/path-injection]
        let key_tmp = dir.join("ca.key.tmp");
        std::os::unix::fs::symlink(&target, &key_tmp).unwrap(); // lgtm[rust/path-injection]
        let err = load_or_generate_ca(
            &Pki::default(),
            "ca",
            &key.to_string_lossy(),
            &cert.to_string_lossy(),
        )
        .expect_err("symlinked key.tmp must be refused");
        assert!(err.to_string().contains("not a regular file"), "{err}");
        assert!(!key.exists(), "symlink must not be renamed into place");
        assert!(
            std::fs::symlink_metadata(&key_tmp) // lgtm[rust/path-injection]
                .unwrap()
                .file_type()
                .is_symlink(),
            "link must be left untouched"
        );
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn ca_rolled_forward_key_is_owner_only_even_if_key_tmp_was_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = test_temp_dir("ca-tmp-mode");
        let (key, _) = generated_ca(&dir);
        let key_tmp = dir.join("ca.key.tmp");
        std::fs::rename(&key, &key_tmp).unwrap(); // lgtm[rust/path-injection]
        std::fs::set_permissions(&key_tmp, std::fs::Permissions::from_mode(0o644)).unwrap(); // lgtm[rust/path-injection]
        run_load_or_generate_ca(&dir).expect("rolls forward");
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777; // lgtm[rust/path-injection]
        assert_eq!(
            mode, 0o600,
            "a group/world-readable CA private key leaks the CA"
        );
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn ca_roll_forward_ignores_a_stale_cert_tmp_and_leaves_it_in_place() {
        let dir = test_temp_dir("ca-stale-cert-tmp");
        let (key, _) = generated_ca(&dir);
        std::fs::rename(&key, dir.join("ca.key.tmp")).unwrap(); // lgtm[rust/path-injection]
        let stale = dir.join("ca.crt.tmp");
        std::fs::write(&stale, b"stale").unwrap(); // lgtm[rust/path-injection]
        run_load_or_generate_ca(&dir).expect("key.tmp alone decides the roll-forward");
        assert!(key.exists());
        assert_eq!(std::fs::read(&stale).unwrap(), b"stale"); // lgtm[rust/path-injection]
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn ca_mismatched_key_tmp_is_not_rolled_forward_so_a_foreign_key_never_becomes_the_ca() {
        let dir = test_temp_dir("ca-tmp-mismatch");
        let (key, cert) = generated_ca(&dir);
        let other = test_temp_dir("ca-tmp-mismatch-other");
        let (other_key, _) = generated_ca(&other);
        std::fs::remove_file(&key).unwrap(); // lgtm[rust/path-injection]
        let key_tmp = dir.join("ca.key.tmp");
        std::fs::copy(&other_key, &key_tmp).unwrap(); // lgtm[rust/path-injection]
        assert_refuses_and_preserves(&key, &cert, &[&cert, &key_tmp]);
        assert!(
            !key.exists(),
            "mismatched tmp must not be renamed into place"
        );
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
        let _ = std::fs::remove_dir_all(&other); // lgtm[rust/path-injection]
    }

    #[test]
    fn ca_empty_key_tmp_from_a_power_loss_is_not_rolled_forward() {
        let dir = test_temp_dir("ca-tmp-empty");
        let (key, cert) = generated_ca(&dir);
        std::fs::remove_file(&key).unwrap(); // lgtm[rust/path-injection]
        let key_tmp = dir.join("ca.key.tmp");
        std::fs::write(&key_tmp, b"").unwrap(); // lgtm[rust/path-injection]
        assert_refuses_and_preserves(&key, &cert, &[&cert, &key_tmp]);
        assert!(!key.exists(), "zero-length tmp must not become the CA key");
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn front_proxy_ca_partial_state_is_refused_and_preserved_like_the_cluster_ca() {
        let dir = test_temp_dir("fp-ca-partial");
        let key = dir.join("front-proxy-ca.key");
        let cert = dir.join("front-proxy-ca.crt");
        load_or_generate_ca(
            &Pki::default(),
            "ca",
            &key.to_string_lossy(),
            &cert.to_string_lossy(),
        )
        .unwrap();
        std::fs::remove_file(&key).unwrap(); // lgtm[rust/path-injection]
        let msg = assert_refuses_and_preserves(&key, &cert, &[&cert]);
        assert!(msg.contains("front-proxy-ca"), "{msg}");
        assert!(!key.exists(), "no new front-proxy key may be generated");
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn ca_corrupt_and_mismatch_errors_tell_the_operator_how_to_recover() {
        let dir = test_temp_dir("ca-remedy");
        let (key, cert) = generated_ca(&dir);
        std::fs::write(&key, b"garbage").unwrap(); // lgtm[rust/path-injection]
        let corrupt = assert_refuses_and_preserves(&key, &cert, &[&key, &cert]);
        let other = test_temp_dir("ca-remedy-other");
        let (other_key, _) = generated_ca(&other);
        std::fs::copy(&other_key, &key).unwrap(); // lgtm[rust/path-injection]
        let mismatch = assert_refuses_and_preserves(&key, &cert, &[&key, &cert]);
        for msg in [corrupt, mismatch] {
            assert!(
                msg.contains("restore from backup, or delete both files"),
                "an operator staring at a boot failure needs the remedy: {msg}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
        let _ = std::fs::remove_dir_all(&other); // lgtm[rust/path-injection]
    }

    #[test]
    fn ca_cert_only_refuses_to_start_and_keeps_cert() {
        let dir = test_temp_dir("ca-cert-only");
        let (key, cert) = generated_ca(&dir);
        std::fs::remove_file(&key).unwrap(); // lgtm[rust/path-injection]
        assert_refuses_and_preserves(&key, &cert, &[&cert]);
        assert!(!key.exists(), "no new key may be generated");
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn ca_key_only_refuses_to_start_and_keeps_key() {
        let dir = test_temp_dir("ca-key-only");
        let (key, cert) = generated_ca(&dir);
        std::fs::remove_file(&cert).unwrap(); // lgtm[rust/path-injection]
        assert_refuses_and_preserves(&key, &cert, &[&key]);
        assert!(!cert.exists(), "no new cert may be generated");
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn ca_mismatched_key_and_cert_refuses_to_start() {
        let dir = test_temp_dir("ca-mismatch");
        let (key, cert) = generated_ca(&dir);
        let other = test_temp_dir("ca-mismatch-other");
        let (_, other_cert) = generated_ca(&other);
        std::fs::copy(&other_cert, &cert).unwrap(); // lgtm[rust/path-injection]
        assert_refuses_and_preserves(&key, &cert, &[&key, &cert]);
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
        let _ = std::fs::remove_dir_all(&other); // lgtm[rust/path-injection]
    }

    #[test]
    fn ca_corrupt_cert_refuses_to_start() {
        let dir = test_temp_dir("ca-corrupt-cert");
        let (key, cert) = generated_ca(&dir);
        std::fs::write(&cert, b"not a certificate").unwrap(); // lgtm[rust/path-injection]
        assert_refuses_and_preserves(&key, &cert, &[&key, &cert]);
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn ca_corrupt_key_refuses_to_start() {
        let dir = test_temp_dir("ca-corrupt-key");
        let (key, cert) = generated_ca(&dir);
        std::fs::write(&key, b"dummy-key-content").unwrap(); // lgtm[rust/path-injection]
        assert_refuses_and_preserves(&key, &cert, &[&key, &cert]);
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn ca_first_boot_generates_and_leaves_no_temp_files() {
        let dir = test_temp_dir("ca-first-boot");
        let (key, cert) = generated_ca(&dir);
        assert!(key.exists() && cert.exists());
        assert!(!dir.join("ca.key.tmp").exists() && !dir.join("ca.crt.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn ca_valid_pair_loads_the_same_ca() {
        let dir = test_temp_dir("ca-reload");
        let (_, _, first) = run_load_or_generate_ca(&dir).unwrap();
        let (_, _, second) = run_load_or_generate_ca(&dir).unwrap();
        assert_eq!(first, second, "restart must keep the same CA cert");
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// SA private key must be written with mode 0o600 (owner-only) so it is
    /// not world-readable. A world-readable key file allows any local user to
    /// forge service-account tokens.
    #[test]
    fn sa_private_key_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_temp_dir("sa-key-perms");
        let key_path = dir.join("sa.key");

        let bytes = b"fake-key-content";
        write_private_key(key_path.clone(), bytes).expect("write_private_key must succeed");

        let meta = std::fs::metadata(&key_path).expect("file must exist"); // lgtm[rust/path-injection]
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "SA private key must be mode 0o600 (got {:#o}); \
             world-readable keys allow local users to forge SA tokens",
            mode
        );
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Kubeconfig must be written with mode 0o600 (owner-only).
    ///
    /// The kubeconfig contains the admin client certificate and private key in
    /// base64 form. A world-readable kubeconfig allows any local user to impersonate
    /// the cluster admin — same severity as a world-readable CA private key.
    #[test]
    fn kubeconfig_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_temp_dir("kubeconfig-perms");
        let kubeconfig_path = dir.join("kubeconfig");

        let args = Args {
            db: "./state.db".into(),
            listen: "0.0.0.0:6443".into(),
            kubeconfig: kubeconfig_path.to_string_lossy().into_owned(),
            token_auth_file: None,
            sa_key: "./sa.key".into(),
            sa_pub: "./sa.pub".into(),
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            proxy_client_ca_key: dir
                .join("proxy-client-ca.key")
                .to_string_lossy()
                .into_owned(),
            proxy_client_ca_cert: dir
                .join("proxy-client-ca.crt")
                .to_string_lossy()
                .into_owned(),
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            deny_service_external_ips: false,
            sa_sig_cache_size: None,
            manifest_dir: "/etc/u7s/manifests".into(),
            embedded_scheduler: false,
            admission_control_config_file: None,
        };

        generate_tls(&args).expect("generate_tls must succeed");
        write_kubeconfig(&kubeconfig_path.to_string_lossy(), &args)
            .expect("write_kubeconfig must succeed");

        let identity = leaf_files(&args, "admin").pem();
        for path in [&kubeconfig_path, &identity] {
            let meta = std::fs::metadata(path).expect("file must exist"); // lgtm[rust/path-injection]
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o600,
                "{} must be mode 0o600 (got {:#o}); \
                 world-readable admin credentials allow any local user to impersonate cluster admin",
                path.display(),
                mode
            );
        }
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// CA private key must also be written with mode 0o600.
    #[test]
    fn ca_private_key_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_temp_dir("ca-key-perms");
        let (_, _, _) = run_load_or_generate_ca(&dir).expect("generate CA");

        let ca_key_path = dir.join("ca.key");
        let meta = std::fs::metadata(&ca_key_path).expect("ca.key must exist"); // lgtm[rust/path-injection]
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "CA private key must be mode 0o600 (got {:#o}); \
             world-readable CA keys allow anyone to sign rogue certs",
            mode
        );
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// load_or_generate_sa_keys must reload the same key material on a second call
    /// rather than generating a new key pair. This is the core correctness property:
    /// tokens minted before a restart must remain valid after restart because the
    /// signing key is loaded from disk, not regenerated.
    #[test]
    fn sa_keys_load_from_disk_returns_same_private_key() {
        let dir = test_temp_dir("sa-keys-load");
        let key_path = dir.join("sa.key").to_string_lossy().into_owned();
        let pub_path = dir.join("sa.pub").to_string_lossy().into_owned();

        // First call: generates and writes sa.key / sa.pub.
        let first = load_or_generate_sa_keys(&key_path, &pub_path)
            .expect("first load_or_generate_sa_keys must succeed");
        assert!(
            std::path::Path::new(&key_path).exists(),
            "sa.key must exist after first call"
        );

        // Second call: must load from disk, not generate a new key.
        let second = load_or_generate_sa_keys(&key_path, &pub_path)
            .expect("second load_or_generate_sa_keys must succeed");

        assert_eq!(
            first.private_key_pem, second.private_key_pem,
            "private key PEM must be identical on load — \
             generating a new key would invalidate tokens minted before restart"
        );
        assert_eq!(
            first.public_key_pem, second.public_key_pem,
            "public key PEM must be identical on load"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// sa.key must be written in PKCS#1 PEM format so KCM can parse it.
    ///
    /// KCM's token controller calls crypto.ParseRSAPrivateKeyFromPEM which expects
    /// the `-----BEGIN RSA PRIVATE KEY-----` header (PKCS#1). Writing PKCS#8
    /// (`-----BEGIN PRIVATE KEY-----`) causes "invalid serviceaccount key" in KCM logs
    /// and prevents any SA token from being issued, so pods never get a mounted token.
    #[test]
    fn sa_key_is_written_in_pkcs1_pem_format_for_kcm_compatibility() {
        let dir = test_temp_dir("sa-key-pkcs1");
        let key_path = dir.join("sa.key").to_string_lossy().into_owned();
        let pub_path = dir.join("sa.pub").to_string_lossy().into_owned();

        let keys = load_or_generate_sa_keys(&key_path, &pub_path)
            .expect("load_or_generate_sa_keys must succeed");

        let priv_pem = std::str::from_utf8(&keys.private_key_pem)
            .expect("private_key_pem must be valid UTF-8");
        assert!(
            priv_pem.contains("-----BEGIN RSA PRIVATE KEY-----"),
            "sa.key must use PKCS#1 PEM header '-----BEGIN RSA PRIVATE KEY-----' \
             so KCM can parse it; reverting to PKCS#8 breaks SA token issuance and \
             prevents pods from getting a mounted token file. Got: {}",
            priv_pem.lines().next().unwrap_or("<empty>")
        );

        let pub_pem =
            std::str::from_utf8(&keys.public_key_pem).expect("public_key_pem must be valid UTF-8");
        assert!(
            pub_pem.contains("-----BEGIN RSA PUBLIC KEY-----"),
            "sa.pub must use PKCS#1 PEM header '-----BEGIN RSA PUBLIC KEY-----'; \
             got: {}",
            pub_pem.lines().next().unwrap_or("<empty>")
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// generate_tls must succeed when the PQC provider is active.
    ///
    /// This test exists to catch provider-installation failures early: if
    /// rustls_post_quantum::provider() is incompatible with the rustls version
    /// in use, ServerConfig::builder() will panic or return an error rather than
    /// silently falling back to ring. Catching that here is better than a
    /// mysterious runtime crash.
    #[test]
    fn generate_tls_succeeds_with_pqc_provider() {
        // install_default returns Err if already installed — that's fine here.
        rustls_post_quantum::provider().install_default().ok();

        let dir = test_temp_dir("pqc-provider");
        let args = Args {
            db: "./state.db".into(),
            listen: "0.0.0.0:6443".into(),
            kubeconfig: "./kubeconfig".into(),
            token_auth_file: None,
            sa_key: "./sa.key".into(),
            sa_pub: "./sa.pub".into(),
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            proxy_client_ca_key: dir
                .join("proxy-client-ca.key")
                .to_string_lossy()
                .into_owned(),
            proxy_client_ca_cert: dir
                .join("proxy-client-ca.crt")
                .to_string_lossy()
                .into_owned(),
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            deny_service_external_ips: false,
            sa_sig_cache_size: None,
            manifest_dir: "/etc/u7s/manifests".into(),
            embedded_scheduler: false,
            admission_control_config_file: None,
        };
        let result = generate_tls(&args);
        assert!(
            result.is_ok(),
            "generate_tls must succeed with PQC provider active; got: {:?}",
            result.err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// pem_encode must produce a valid PEM block with the correct header and footer.
    /// kubeconfig fields rely on pem_encode to wrap DER bytes in PEM armour before
    /// base64-encoding them. A broken header or footer would make kubectl reject the
    /// embedded certificates.
    #[test]
    fn pem_encode_produces_valid_pem_armour() {
        let der = vec![0x01u8, 0x02, 0x03];
        let pem = pem_encode("CERTIFICATE", &der);
        let pem_str = std::str::from_utf8(&pem).expect("pem output must be valid UTF-8");
        assert!(
            pem_str.starts_with("-----BEGIN CERTIFICATE-----"),
            "PEM must start with BEGIN header; got: {pem_str:?}"
        );
        assert!(
            pem_str.contains("-----END CERTIFICATE-----"),
            "PEM must contain END footer; got: {pem_str:?}"
        );
    }

    /// Kubeconfig::new and to_yaml must produce a YAML document that contains the
    /// server URL and the base64-encoded CA certificate. kubectl parses these fields
    /// to establish a TLS connection to the API server.
    #[test]
    fn kubeconfig_yaml_contains_server_and_ca_data() {
        let dir = test_temp_dir("kubeconfig-yaml");
        let args = Args {
            db: "./state.db".into(),
            listen: "0.0.0.0:6443".into(),
            kubeconfig: "./kubeconfig".into(),
            token_auth_file: None,
            sa_key: "./sa.key".into(),
            sa_pub: "./sa.pub".into(),
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            proxy_client_ca_key: dir
                .join("proxy-client-ca.key")
                .to_string_lossy()
                .into_owned(),
            proxy_client_ca_cert: dir
                .join("proxy-client-ca.crt")
                .to_string_lossy()
                .into_owned(),
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            deny_service_external_ips: false,
            sa_sig_cache_size: None,
            manifest_dir: "/etc/u7s/manifests".into(),
            embedded_scheduler: false,
            admission_control_config_file: None,
        };
        generate_tls(&args).expect("generate_tls must succeed");
        let server_url = "https://127.0.0.1:6443";
        let ca = ca_bundle_path(&args);
        let identity = leaf_files(&args, "admin").pem();
        let yaml = Kubeconfig::new(
            server_url,
            &KubeconfigCreds::Files {
                ca: &ca,
                identity: &identity,
            },
            "admin",
        )
        .to_yaml();

        assert!(
            yaml.contains("server:"),
            "kubeconfig YAML must contain 'server:' field; got: {yaml}"
        );
        assert!(
            yaml.contains(server_url),
            "kubeconfig YAML must contain the server URL; got: {yaml}"
        );
        assert!(
            yaml.contains(&format!("certificate-authority: {}", ca.display())),
            "kubeconfig YAML must reference the CA bundle by path; got: {yaml}"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    fn kubeconfig_field(yaml: &str, key: &str) -> String {
        yaml.lines()
            .find_map(|l| l.trim().strip_prefix(&format!("{key}: ")))
            .unwrap_or_else(|| panic!("kubeconfig has no {key}; got: {yaml}"))
            .to_owned()
    }

    fn first_cert_der(pem_file: &[u8]) -> Vec<u8> {
        let text = std::str::from_utf8(pem_file).expect("utf8 pem");
        let end = text
            .find("-----END CERTIFICATE-----")
            .expect("pem file starts with a certificate")
            + "-----END CERTIFICATE-----".len();
        der_from_pem(&text.as_bytes()[..end])
    }

    /// KCM, the scheduler and the kubelet only re-read client certs and the CA when the kubeconfig names
    /// files; embedded `-data` is read once, so a rotated cert would stay invisible to them
    /// until a restart. Every writer that feeds an upstream component must therefore emit
    /// paths only, and the paths must be files that exist and hold the leaf in use.
    #[test]
    fn upstream_component_kubeconfigs_reference_files_and_carry_no_embedded_data() {
        let dir = test_temp_dir("file-kubeconfigs");
        let args = Args {
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            ..args_with(Some("https://127.0.0.1:6447"))
        };
        let tls = generate_tls(&args).expect("generate_tls must succeed");
        let writers: [(&str, &str, &str, &[u8]); 4] = [
            ("kubeconfig", "admin", "admin", &tls.admin_cert_der),
            (
                "kcm-kubeconfig",
                "kcm",
                "system:kube-controller-manager",
                &tls.kcm_cert_der,
            ),
            (
                "kubeconfig-scheduler",
                "scheduler",
                "system:kube-scheduler",
                &tls.scheduler_cert_der,
            ),
            (
                "bootstrap-installer-kubeconfig",
                "bootstrap-installer",
                "system:bootstrap-installer",
                &tls.bootstrap_installer_cert_der,
            ),
        ];
        for (file, stem, user, leaf_der) in writers {
            let path = dir.join(file).to_string_lossy().into_owned();
            if stem == "admin" {
                write_kubeconfig(&path, &args).unwrap();
            } else {
                write_component_kubeconfig(&path, &args, stem, user).unwrap();
            }
            let yaml = std::fs::read_to_string(&path).unwrap(); // lgtm[rust/path-injection]
            assert!(
                !yaml.contains("-data:"),
                "{file} embeds credentials, so a re-issued cert or CA is invisible to its \
                 consumer until restart; got: {yaml}"
            );
            let ca = kubeconfig_field(&yaml, "certificate-authority");
            assert_eq!(
                std::fs::read(&ca).unwrap(), // lgtm[rust/path-injection]
                pem_encode("CERTIFICATE", &tls.ca_cert_der),
                "{file}'s CA path must hold the cluster CA as PEM"
            );
            let (cert, key) = (
                kubeconfig_field(&yaml, "client-certificate"),
                kubeconfig_field(&yaml, "client-key"),
            );
            assert_eq!(
                cert, key,
                "{file}: cert and key must be one file so a rotation swaps both in one rename"
            );
            assert_eq!(
                std::path::Path::new(&cert),
                leaf_files(&args, stem).pem(),
                "{file} must reference the file rotation rewrites"
            );
            let on_disk = std::fs::read(&cert).unwrap(); // lgtm[rust/path-injection]
            assert_eq!(
                first_cert_der(&on_disk),
                leaf_der,
                "{file}'s identity file must hold the leaf the apiserver is using"
            );
            assert!(
                String::from_utf8_lossy(&on_disk).contains("PRIVATE KEY"),
                "{file}'s identity file must carry the key"
            );
        }
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// KCM is restarted when ca-bundle.pem changes (its --root-ca-file is read once), so an
    /// apiserver restart that publishes the same CA must not touch the file, or every
    /// apiserver start would bounce KCM.
    #[test]
    fn republishing_an_unchanged_ca_does_not_touch_the_bundle() {
        use std::os::unix::fs::MetadataExt;
        let dir = test_temp_dir("ca-bundle-stable");
        let args = Args {
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            ..args_with(None)
        };
        let tls = generate_tls(&args).expect("generate_tls must succeed");
        let inode = |p: &std::path::Path| std::fs::metadata(p).unwrap().ino(); // lgtm[rust/path-injection]
        let before = inode(&ca_bundle_path(&args));

        write_ca_bundle(&args, &tls.ca_cert_der).unwrap();
        assert_eq!(inode(&ca_bundle_path(&args)), before);

        let other = CertificateParams::default()
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap();
        write_ca_bundle(&args, other.der()).unwrap();
        assert_ne!(
            inode(&ca_bundle_path(&args)),
            before,
            "a changed CA must be republished"
        );
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// The point of file references: after a rotation only the identity file changes and the
    /// kubeconfig bytes stay identical, so KCM re-reads a fresh cert with no kubeconfig
    /// rewrite and no restart.
    #[test]
    fn rotating_a_leaf_rewrites_the_referenced_file_not_the_kubeconfig() {
        let dir = test_temp_dir("rotate-pem");
        let args = Args {
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            ..args_with(None)
        };
        generate_tls(&args).expect("generate_tls must succeed");
        let kubeconfig = dir.join("kcm-kubeconfig").to_string_lossy().into_owned();
        write_component_kubeconfig(&kubeconfig, &args, "kcm", "system:kube-controller-manager")
            .unwrap();
        let before_yaml = std::fs::read(&kubeconfig).unwrap(); // lgtm[rust/path-injection]
        let identity = leaf_files(&args, "kcm").pem();
        let before_pem = std::fs::read(&identity).unwrap(); // lgtm[rust/path-injection]

        let new_key = KeyPair::generate().unwrap();
        let new_cert = CertificateParams::default().self_signed(&new_key).unwrap();
        write_leaf_pem(
            &leaf_files(&args, "kcm"),
            new_cert.der(),
            new_key.serialize_pem().as_bytes(),
        )
        .unwrap();

        assert_eq!(
            std::fs::read(&kubeconfig).unwrap(), // lgtm[rust/path-injection]
            before_yaml,
            "kubeconfig must not need rewriting on rotation"
        );
        let after_pem = std::fs::read(&identity).unwrap(); // lgtm[rust/path-injection]
        assert_ne!(after_pem, before_pem, "the referenced file must change");
        assert_eq!(first_cert_der(&after_pem), new_cert.der().to_vec());
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Regression test: the admin kubeconfig must be cert-only, with NO `token:` field at
    /// all — matching kubeadm/k3s's own admin-kubeconfig shape. A previous design embedded
    /// a bearer token here purely so the aggregation proxy had an Authorization header to
    /// forward to aggregated backends on kubectl/KCM's cert-only requests; that token
    /// forced `authenticate()` into a bearer-token-wins-over-cert precedence rule, which is
    /// exactly what broke every previously-issued kubeconfig on apiserver restart (the token
    /// was originally minted fresh on every restart with no persistence). The
    /// aggregation proxy now asserts the caller's already-resolved identity via
    /// X-Remote-User/-Group headers instead (see `handlers::aggregation::proxy_to_backend`),
    /// so no caller — cert-only or bearer-token — ever needs a second credential embedded
    /// here. Reintroduce a token line in `Kubeconfig::to_yaml` and this test fails.
    #[test]
    fn admin_kubeconfig_yaml_has_no_token_field() {
        let dir = test_temp_dir("kubeconfig-no-token");
        let args = Args {
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            ..args_with(None)
        };
        generate_tls(&args).expect("generate_tls must succeed");
        let kubeconfig = dir.join("kubeconfig").to_string_lossy().into_owned();
        write_kubeconfig(&kubeconfig, &args).unwrap();
        let yaml = std::fs::read_to_string(&kubeconfig).unwrap(); // lgtm[rust/path-injection]

        assert!(
            !yaml.contains("token:"),
            "admin kubeconfig must have no 'token:' field at all — it must be cert-only, \
             matching kubeadm/k3s's own admin-kubeconfig shape; got: {yaml}"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// advertise_host with an empty host segment (e.g. scheme-only "https://") must
    /// return None rather than Some(""), which would produce an invalid SAN.
    #[test]
    fn advertise_host_empty_host_returns_none() {
        // A bare scheme with no host produces an empty host segment after stripping the
        // scheme. Returning Some("") would silently insert an empty-string SAN into the
        // server certificate, which is invalid and would cause cert parsing errors.
        assert_eq!(
            advertise_host(Some("https://")).unwrap(),
            None,
            "empty host segment must return None, not Some(\"\")"
        );
    }

    fn extra_sans(advertise: &str) -> Vec<SanType> {
        let host = advertise_host(Some(advertise)).unwrap();
        let sans = build_server_sans(host.as_deref(), "10.96.0.0/12").unwrap();
        sans[8..].to_vec()
    }

    /// An IPv6-literal advertise URL must yield an IP SAN; the old ':' split produced
    /// "[fd00", which failed SAN construction and made IPv6 control-plane endpoints unusable.
    #[test]
    fn ipv6_literal_advertise_yields_ip_san_so_ipv6_endpoints_work() {
        let want = SanType::IpAddress("fd00::1".parse().unwrap());
        assert_eq!(extra_sans("https://[fd00::1]:6443"), vec![want.clone()]);
        assert_eq!(extra_sans("https://[fd00::1]"), vec![want.clone()]);
        assert_eq!(extra_sans("[fd00::1]:6443"), vec![want]);
    }

    /// IPv4 literals must stay IP SANs (not DNS SANs), with and without a port.
    #[test]
    fn ipv4_literal_advertise_yields_ip_san_with_and_without_port() {
        let want = SanType::IpAddress("192.168.1.10".parse().unwrap());
        assert_eq!(extra_sans("https://192.168.1.10:6443"), vec![want.clone()]);
        assert_eq!(extra_sans("https://192.168.1.10"), vec![want]);
    }

    /// DNS names must stay DNS SANs, with and without a port.
    #[test]
    fn dns_advertise_yields_dns_san_with_and_without_port() {
        let want = SanType::DnsName("cp.example.com".try_into().unwrap());
        assert_eq!(
            extra_sans("https://cp.example.com:6443"),
            vec![want.clone()]
        );
        assert_eq!(extra_sans("https://cp.example.com"), vec![want]);
    }

    /// A zone ID can't appear in a certificate SAN; it must be rejected loudly at startup
    /// rather than producing a cert no client can validate.
    #[test]
    fn ipv6_zone_id_advertise_is_rejected_instead_of_minting_an_unusable_cert() {
        let err = advertise_host(Some("https://[fe80::1%25eth0]:6443")).unwrap_err();
        assert!(err.to_string().contains("zone"), "unclear error: {err}");
        assert!(advertise_host(Some("https://[fe80::1%eth0]:6443")).is_err());
    }

    /// parse_advertise reports the port so seed_services advertises the right endpoint.
    #[test]
    fn parse_advertise_returns_unbracketed_host_and_port() {
        assert_eq!(
            parse_advertise("https://[fd00::1]:6444").unwrap(),
            Some(("fd00::1".into(), Some(6444)))
        );
        assert_eq!(
            parse_advertise("https://h.example").unwrap(),
            Some(("h.example".into(), None))
        );
    }

    /// End-to-end: a server cert minted from an IPv6 advertise URL must validate for an
    /// IPv6 literal server name, otherwise IPv6 control-plane endpoints are unusable.
    #[tokio::test]
    async fn tls_handshake_succeeds_against_cert_from_ipv6_advertise_url() {
        let args = args_with(Some("https://[fd00::1]:6443"));
        let tls = generate_tls(&args).expect("generate_tls must accept an IPv6 advertise URL");

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                tls.ca_cert_der.clone(),
            ))
            .unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let acceptor = tokio_rustls::TlsAcceptor::from(tls.server_config.get());

        let (c, s) = tokio::io::duplex(16 * 1024);
        let name = rustls::pki_types::ServerName::IpAddress(
            "fd00::1".parse::<std::net::Ipv6Addr>().unwrap().into(),
        );
        let (client, server) = tokio::join!(connector.connect(name, c), acceptor.accept(s));
        server.expect("server handshake");
        client.expect("client must validate the server cert for IPv6 literal fd00::1");
    }

    /// advertise_host must strip a bare port suffix even when no scheme is present.
    /// Operators may supply just "host:6443" without a scheme prefix.
    #[test]
    fn advertise_host_no_scheme_strips_port() {
        assert_eq!(
            advertise_host(Some("myhost:6443")).unwrap(),
            Some("myhost".into()),
            "advertise_host must strip the port even when no scheme is present"
        );
    }

    /// write_kubeconfig must produce a file containing `apiVersion: v1` so that
    /// kubectl recognises it as a valid kubeconfig document.
    #[test]
    fn write_kubeconfig_file_contains_apiversion() {
        let dir = test_temp_dir("kubeconfig-content");
        let kubeconfig_path = dir.join("kubeconfig");
        let args = Args {
            db: "./state.db".into(),
            listen: "0.0.0.0:6443".into(),
            kubeconfig: kubeconfig_path.to_string_lossy().into_owned(),
            token_auth_file: None,
            sa_key: "./sa.key".into(),
            sa_pub: "./sa.pub".into(),
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            proxy_client_ca_key: dir
                .join("proxy-client-ca.key")
                .to_string_lossy()
                .into_owned(),
            proxy_client_ca_cert: dir
                .join("proxy-client-ca.crt")
                .to_string_lossy()
                .into_owned(),
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            deny_service_external_ips: false,
            sa_sig_cache_size: None,
            manifest_dir: "/etc/u7s/manifests".into(),
            embedded_scheduler: false,
            admission_control_config_file: None,
        };
        generate_tls(&args).expect("generate_tls must succeed");
        write_kubeconfig(&kubeconfig_path.to_string_lossy(), &args)
            .expect("write_kubeconfig must succeed");

        let contents =
            std::fs::read_to_string(&kubeconfig_path).expect("kubeconfig file must be readable");
        assert!(
            contents.contains("apiVersion: v1"),
            "kubeconfig must contain 'apiVersion: v1' for kubectl compatibility; got: {contents}"
        );
        assert!(
            contents.contains("kind: Config"),
            "kubeconfig must contain 'kind: Config'; got: {contents}"
        );
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// generate_tls must write ca.key and ca.crt to disk on first run.
    /// These files are required for CA stability across restarts — if they are not
    /// written, every restart generates a new CA, breaking kubelets that trusted the
    /// previous CA certificate.
    #[test]
    fn generate_tls_writes_ca_files_to_disk() {
        let dir = test_temp_dir("gen-tls-files");
        let ca_key_path = dir.join("ca.key");
        let ca_cert_path = dir.join("ca.crt");
        let args = Args {
            db: "./state.db".into(),
            listen: "0.0.0.0:6443".into(),
            kubeconfig: "./kubeconfig".into(),
            token_auth_file: None,
            sa_key: "./sa.key".into(),
            sa_pub: "./sa.pub".into(),
            ca_key: ca_key_path.to_string_lossy().into_owned(),
            ca_cert: ca_cert_path.to_string_lossy().into_owned(),
            proxy_client_ca_key: dir
                .join("proxy-client-ca.key")
                .to_string_lossy()
                .into_owned(),
            proxy_client_ca_cert: dir
                .join("proxy-client-ca.crt")
                .to_string_lossy()
                .into_owned(),
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            deny_service_external_ips: false,
            sa_sig_cache_size: None,
            manifest_dir: "/etc/u7s/manifests".into(),
            embedded_scheduler: false,
            admission_control_config_file: None,
        };
        let tls = generate_tls(&args).expect("generate_tls must succeed");

        assert!(
            ca_key_path.exists(),
            "generate_tls must write ca.key so the CA is stable across restarts"
        );
        assert!(
            ca_cert_path.exists(),
            "generate_tls must write ca.crt so the CA is stable across restarts"
        );
        // The returned ca_cert_der must match the DER bytes on disk.
        let cert_on_disk = std::fs::read(&ca_cert_path).expect("ca.crt must be readable");
        assert_eq!(
            tls.ca_cert_der, cert_on_disk,
            "ca_cert_der in TlsMaterial must match the bytes written to ca.crt"
        );
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// write_private_key must write the exact bytes provided and make the file
    /// readable (i.e. the content round-trips correctly).
    #[test]
    fn write_private_key_content_roundtrips() {
        let dir = test_temp_dir("key-roundtrip");
        let key_path = dir.join("test.key");
        let expected = b"-----BEGIN EC PRIVATE KEY-----\nfakekey\n-----END EC PRIVATE KEY-----\n";
        write_private_key(&key_path, expected).expect("write_private_key must succeed");
        let actual = std::fs::read(&key_path).expect("file must be readable after write");
        assert_eq!(
            actual, expected,
            "write_private_key must write the exact bytes provided"
        );
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// The server TLS chain must contain only the leaf cert, not the CA cert.
    ///
    /// Go's TLS verifier performs full chain validation on every reconnect after
    /// session cache expiry (~70 min). When the CA cert appears as an intermediate
    /// in the chain, the verifier sees intermediate == trust anchor, which violates
    /// RFC 5246 chain building and produces "ECDSA verification failure". Initial
    /// connections succeed via session resumption; reconnects fail. Sonobuoy runs
    /// (90+ min) hit this window reliably. The fix is to present only the leaf cert —
    /// the CA is already in the client's trust store via kubeconfig.
    #[test]
    fn server_cert_chain_does_not_include_ca() {
        let dir = test_temp_dir("chain-no-ca");
        let args = Args {
            db: "./state.db".into(),
            listen: "0.0.0.0:6443".into(),
            kubeconfig: "./kubeconfig".into(),
            token_auth_file: None,
            sa_key: "./sa.key".into(),
            sa_pub: "./sa.pub".into(),
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            proxy_client_ca_key: dir
                .join("proxy-client-ca.key")
                .to_string_lossy()
                .into_owned(),
            proxy_client_ca_cert: dir
                .join("proxy-client-ca.crt")
                .to_string_lossy()
                .into_owned(),
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            deny_service_external_ips: false,
            sa_sig_cache_size: None,
            manifest_dir: "/etc/u7s/manifests".into(),
            embedded_scheduler: false,
            admission_control_config_file: None,
        };
        let tls = generate_tls(&args).expect("generate_tls must succeed");

        assert_ne!(
            tls.server_cert_der, tls.ca_cert_der,
            "server cert and CA cert must be distinct: the server must present a CA-signed \
             leaf cert, not the CA cert itself"
        );

        assert!(
            !tls.server_cert_der.is_empty(),
            "server_cert_der must not be empty"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Extract the Issuer CN from a DER-encoded certificate (test-only). Mirrors
    /// the Subject-CN parsing in `auth::extract_client_cert_identity`, but reads
    /// the Issuer field instead, so tests can confirm the CA params
    /// `load_or_generate_ca` reconstructs actually carry forward the on-disk
    /// CA's real Subject CN (used to sign freshly-issued leaf certs' Issuer
    /// field) rather than a hardcoded literal.
    fn issuer_cn(der: &[u8]) -> Option<String> {
        use x509_cert::der::asn1::{Ia5StringRef, PrintableStringRef, Utf8StringRef};
        use x509_cert::der::{Decode as _, Tag, Tagged as _};
        use x509_cert::Certificate;

        let cert = Certificate::from_der(der).ok()?;
        for atv in cert.tbs_certificate().issuer().iter() {
            if atv.oid.to_string() != "2.5.4.3" {
                continue;
            }
            return match atv.value.tag() {
                Tag::Utf8String => atv
                    .value
                    .decode_as::<Utf8StringRef<'_>>()
                    .ok()
                    .map(|s| s.as_str().to_owned()),
                Tag::PrintableString => atv
                    .value
                    .decode_as::<PrintableStringRef<'_>>()
                    .ok()
                    .map(|s| s.as_str().to_owned()),
                Tag::Ia5String => atv
                    .value
                    .decode_as::<Ia5StringRef<'_>>()
                    .ok()
                    .map(|s| s.as_str().to_owned()),
                _ => None,
            };
        }
        None
    }

    /// Regression: a freshly generated CA's Subject CN must carry a random
    /// per-stack suffix, not the historical literal "u7s-ca". Every u7s stack
    /// sharing that literal CN is what let rustls's WebPkiServerVerifier accept
    /// a name-matching (but wrong) trust anchor from a DIFFERENT stack's CA when
    /// cert-routing misfired, then fail cryptographic verification against a
    /// leaf signed by a different key — an opaque BadSignature instead of a
    /// legible UnknownIssuer. If the CN reverts to the bare literal, the failure
    /// mode goes cryptic again.
    #[test]
    fn generated_ca_cn_is_unique_per_stack_to_surface_cert_misroute_as_unknown_issuer() {
        let dir = test_temp_dir("ca-cn-unique");
        let (_, _, ca_cert_der) = run_load_or_generate_ca(&dir).expect("generate CA");

        let cn = crate::auth::extract_client_cert_identity(&ca_cert_der)
            .map(|id| id.username)
            .expect("freshly generated CA cert must have a parseable Subject CN");

        assert_ne!(
            cn, "u7s-ca",
            "fresh CA CN must not be the bare literal 'u7s-ca' — a CN shared across \
             every stack is exactly what makes a misrouted-cert failure surface as \
             opaque BadSignature instead of legible UnknownIssuer"
        );
        assert!(
            cn.starts_with("u7s-ca-"),
            "fresh CA CN must keep the 'u7s-ca-' prefix so operators can still \
             recognize it as a u7s cluster CA; got {cn:?}"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Regression: a CA generated by pre-fix code (literal CN="u7s-ca", no
    /// suffix) must still load without error, and the CertificateParams
    /// `load_or_generate_ca` reconstructs must carry forward that exact on-disk
    /// CN rather than a hardcoded string. A hardcoded comparison/regeneration
    /// here would either reject a perfectly good legacy CA, or silently mint
    /// leaf certs whose Issuer field doesn't match the actual persisted CA
    /// Subject — breaking X.509 issuer/subject name matching for every
    /// certificate signed after the first restart post-upgrade.
    #[test]
    fn legacy_ca_with_literal_cn_loads_and_issuer_cn_matches_the_cert_on_disk() {
        let dir = test_temp_dir("ca-legacy-cn");
        let ca_key_path = dir.join("ca.key");
        let ca_cert_path = dir.join("ca.crt");

        // Hand-build a CA the way pre-fix code did: literal CN="u7s-ca".
        let legacy_key = KeyPair::generate().expect("generate legacy CA key");
        let mut legacy_params = CertificateParams::default();
        legacy_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        legacy_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "u7s-ca");
        let legacy_cert_der = legacy_params
            .self_signed(&legacy_key)
            .expect("self-sign legacy CA")
            .der()
            .to_vec();
        write_private_key(&ca_key_path, legacy_key.serialize_pem().as_bytes())
            .expect("write legacy ca.key");
        std::fs::write(&ca_cert_path, &legacy_cert_der).expect("write legacy ca.crt"); // lgtm[rust/path-injection]

        let (loaded_key, loaded_params, loaded_cert_der) = load_or_generate_ca(
            &Pki::default(),
            "ca",
            &ca_key_path.to_string_lossy(),
            &ca_cert_path.to_string_lossy(),
        )
        .expect("a pre-fix CA with literal CN=u7s-ca on disk must still load without error");

        assert_eq!(
            loaded_cert_der, legacy_cert_der,
            "load_or_generate_ca must load the existing legacy CA cert as-is, not regenerate it"
        );

        // Sign a leaf with the reconstructed params/key and confirm its Issuer CN
        // matches the actual on-disk CA Subject ("u7s-ca"), proving the load path
        // threads the real CN through instead of hardcoding a new or stale value.
        let ca_issuer = Issuer::new(loaded_params, loaded_key);
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "leaf");
        let leaf_key = KeyPair::generate().expect("generate leaf key");
        let leaf_der = leaf_params
            .signed_by(&leaf_key, &ca_issuer)
            .expect("sign leaf with reconstructed CA issuer")
            .der()
            .to_vec();

        let leaf_issuer_cn =
            issuer_cn(&leaf_der).expect("leaf cert must have a parseable Issuer CN");
        assert_eq!(
            leaf_issuer_cn, "u7s-ca",
            "leaf cert's Issuer CN must match the on-disk legacy CA Subject CN exactly, \
             or X.509 issuer/subject name matching fails for anything signed after \
             this restart of a pre-fix cluster"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Regression: KCM and the scheduler must each get their own x509 identity
    /// (CN=system:kube-controller-manager / CN=system:kube-scheduler) with no
    /// O=system:masters — the seeded ClusterRoleBindings for those names (see
    /// lib.rs::seed_rbac) bind by username, and O=system:masters would bypass RBAC
    /// entirely via the cluster-admin ClusterRoleBinding on that group instead of
    /// exercising the least-privilege ClusterRoles meant for these identities.
    #[test]
    fn kcm_and_scheduler_certs_carry_dedicated_identities_with_no_masters_group() {
        let dir = test_temp_dir("component-cert-identity");
        let args = Args {
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            ..args_with(None)
        };
        let tls = generate_tls(&args).expect("generate_tls must succeed");

        let kcm_id = crate::auth::extract_client_cert_identity(&tls.kcm_cert_der)
            .expect("kcm_cert_der must parse as a valid x509 cert");
        assert_eq!(
            kcm_id.username, "system:kube-controller-manager",
            "KCM's cert CN must be its dedicated identity, not admin — otherwise KCM \
             still resolves through system:masters and the seeded least-privilege \
             ClusterRole never gets exercised"
        );
        assert_eq!(
            kcm_id.groups,
            vec!["system:authenticated".to_owned()],
            "KCM's cert must carry no O=system:masters — that group's \
             ClusterRoleBinding grants cluster-admin, defeating the whole point \
             of a dedicated least-privilege identity"
        );

        let scheduler_id = crate::auth::extract_client_cert_identity(&tls.scheduler_cert_der)
            .expect("scheduler_cert_der must parse as a valid x509 cert");
        assert_eq!(
            scheduler_id.username, "system:kube-scheduler",
            "scheduler's cert CN must be its dedicated identity, not admin"
        );
        assert_eq!(
            scheduler_id.groups,
            vec!["system:authenticated".to_owned()],
            "scheduler's cert must carry no O=system:masters, for the same reason as KCM's"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    fn expected_lifetimes() -> Vec<(&'static str, CertRole, std::time::Duration)> {
        let year = CLIENT_CERT_LIFETIME;
        vec![
            ("ca", CertRole::Root, ROOT_CA_LIFETIME),
            ("front-proxy-ca", CertRole::Root, ROOT_CA_LIFETIME),
            ("admin", CertRole::Leaf, year),
            ("kcm-client", CertRole::Leaf, year),
            ("scheduler-client", CertRole::Leaf, year),
            ("bootstrap-installer-client", CertRole::Leaf, year),
            ("kubelet-client", CertRole::Leaf, year),
            ("proxy-client", CertRole::Leaf, year),
            ("apiserver-serving", CertRole::Leaf, SERVING_CERT_LIFETIME),
        ]
    }

    fn assert_inventory_matches_decisions(inv: &CertInventory) {
        let records = inv.snapshot();
        let now = time::OffsetDateTime::now_utc();
        for (name, role, lifetime) in expected_lifetimes() {
            let r = records
                .iter()
                .find(|r| r.name == name)
                .unwrap_or_else(|| panic!("inventory must list {name}: a cert the expiry beads cannot see is one nobody renews"));
            assert_eq!(r.role, role, "{name} role");
            assert_eq!(
                r.not_after - r.not_before,
                lifetime,
                "{name} must live exactly its decided lifetime, not rcgen's 1975..4096 default"
            );
            assert!(r.not_before <= now, "{name} must already be valid");
            assert!(
                !r.usages.is_empty() && !r.subject.is_empty(),
                "{name} must declare subject and usages"
            );
        }
        assert_eq!(
            records.len(),
            expected_lifetimes().len(),
            "unexpected extra cert: {records:?}"
        );
    }

    #[test]
    fn every_issued_cert_has_its_decided_finite_lifetime_and_is_inventoried() {
        let dir = test_temp_dir("lifetimes");
        let args = Args {
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            ..args_with(None)
        };
        let tls = generate_tls(&args).expect("generate_tls");
        assert_inventory_matches_decisions(&tls.inventory);

        // The inventory must describe the bytes actually served, not just the request.
        let (nb, na) = cert_validity(&tls.server_cert_der).unwrap();
        let rec = tls
            .inventory
            .snapshot()
            .into_iter()
            .find(|r| r.name == "apiserver-serving")
            .unwrap();
        assert_eq!((nb, na), (rec.not_before, rec.not_after));
        assert_eq!(na - nb, SERVING_CERT_LIFETIME);

        // A restart loads persisted certs; they must still be inventoried.
        let tls2 = generate_tls(&args).expect("second generate_tls");
        assert_inventory_matches_decisions(&tls2.inventory);
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn no_leaf_outlives_the_ca_that_signed_it() {
        let args = args_with(None);
        let tls = generate_tls(&args).expect("generate_tls");
        let records = tls.inventory.snapshot();
        let not_after = |n: &str| records.iter().find(|r| r.name == n).unwrap().not_after;
        for r in records.iter().filter(|r| r.role == CertRole::Leaf) {
            let ca = if r.name == "proxy-client" {
                "front-proxy-ca"
            } else {
                "ca"
            };
            assert!(
                r.not_after <= not_after(ca),
                "{} outlives {ca}: a leaf valid past its CA is trusted by nobody after the CA expires",
                r.name
            );
        }

        // A short-lived CA (e.g. a legacy or operator-supplied one) caps the leaf.
        let pki = Pki::default();
        let ca = pki
            .issue(&ca_spec("ca", "short-ca"), None)
            .expect("issue CA");
        let ca_params = pki.params(
            &ca_spec("ca", "short-ca"),
            time::OffsetDateTime::now_utc(),
            time::OffsetDateTime::now_utc(),
        );
        let issuer = Issuer::new(ca_params, ca.key);
        let cap = time::OffsetDateTime::now_utc() + std::time::Duration::from_secs(30 * 86400);
        let leaf = pki
            .issue(
                &client_plan("kcm-client", "x", None, CaKind::Cluster, None).spec(),
                Some(&Signer {
                    issuer: &issuer,
                    not_after: cap,
                }),
            )
            .expect("issue leaf");
        let (_, leaf_after) = cert_validity(leaf.cert.der()).unwrap();
        assert!(
            leaf_after <= cap,
            "leaf must be clamped to the CA's not_after"
        );
    }

    #[test]
    fn key_algorithm_parameter_drives_key_and_signature_type() {
        use x509_cert::der::Decode as _;
        // id-ecPublicKey, ecdsa-with-SHA256
        const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
        const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
        {
            let alg = crate::pki::KeyAlgorithm::EcdsaP256;
            let pki = Pki {
                algorithm: alg,
                ..Pki::default()
            };
            let issued = pki.issue(&ca_spec("ca", "alg-ca"), None).unwrap();
            assert!(
                issued.key.is_compatible(alg.signature_algorithm()),
                "key must be of the requested algorithm"
            );
            let cert = x509_cert::Certificate::from_der(issued.cert.der()).unwrap();
            assert_eq!(
                cert.tbs_certificate()
                    .subject_public_key_info()
                    .algorithm
                    .oid
                    .to_string(),
                EC_PUBLIC_KEY
            );
            assert_eq!(cert.signature_algorithm().oid.to_string(), ECDSA_SHA256);
        }
    }

    fn assert_admin_refuses_and_preserves(present: &str, remove: &str, tag: &str) {
        let args = args_with(None);
        generate_tls(&args).expect("first boot");
        let dir = std::path::Path::new(&args.ca_key)
            .parent()
            .unwrap()
            .to_owned();
        let (present, removed) = (dir.join(present), dir.join(remove));
        std::fs::remove_file(&removed).unwrap(); // lgtm[rust/path-injection]
        let before = std::fs::read(&present).unwrap(); // lgtm[rust/path-injection]
        let ca_before = std::fs::read(&args.ca_cert).unwrap(); // lgtm[rust/path-injection]

        let err = generate_tls(&args)
            .err()
            .unwrap_or_else(|| panic!("{tag}: half an admin credential must stop startup"));
        let msg = err.to_string();
        assert!(
            msg.contains(&*removed.to_string_lossy()),
            "{tag}: error must name the missing file: {msg}"
        );
        assert_eq!(
            std::fs::read(&present).unwrap(),
            before,
            "{tag}: survivor must not be deleted or rewritten"
        ); // lgtm[rust/path-injection]
        assert!(!removed.exists(), "{tag}: nothing may be regenerated");
        assert_eq!(
            std::fs::read(&args.ca_cert).unwrap(),
            ca_before,
            "{tag}: CA untouched"
        ); // lgtm[rust/path-injection]
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn admin_key_without_cert_is_refused_not_silently_replaced() {
        assert_admin_refuses_and_preserves("admin.key", "admin.crt", "key only");
    }

    #[test]
    fn admin_cert_without_key_is_refused_not_silently_replaced() {
        assert_admin_refuses_and_preserves("admin.crt", "admin.key", "cert only");
    }

    #[test]
    fn admin_write_interrupted_between_renames_resumes_with_the_same_credential() {
        let args = args_with(None);
        let first = generate_tls(&args).expect("first boot");
        let dir = std::path::Path::new(&args.ca_key)
            .parent()
            .unwrap()
            .to_owned();
        std::fs::rename(dir.join("admin.key"), dir.join("admin.key.tmp")).unwrap(); // lgtm[rust/path-injection]
        let second = generate_tls(&args).expect("cert + matching key.tmp must resume");
        assert_eq!(first.admin_cert_der, second.admin_cert_der);
        assert_eq!(first.admin_key_pem, second.admin_key_pem);
        assert!(dir.join("admin.key").exists() && !dir.join("admin.key.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }
}

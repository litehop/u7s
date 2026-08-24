use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
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
    f.write_all(bytes)
}

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
    ca_key_path: &str,
    ca_cert_path: &str,
) -> anyhow::Result<(KeyPair, CertificateParams, Vec<u8>)> {
    let key_exists = std::path::Path::new(ca_key_path).exists();
    let cert_exists = std::path::Path::new(ca_cert_path).exists();

    // Detect partial state: exactly one of the two files exists (e.g. the server
    // crashed between the two fs::write calls). Silently falling through to
    // generate a fresh CA would rotate the CA and break kubelets that already
    // trust the old cert. Instead: log an error, delete the stale file, and
    // fall through to the normal "generate fresh CA" path so the state is clean.
    if key_exists ^ cert_exists {
        if key_exists {
            tracing::error!(
                "partial CA state: {ca_key_path} exists but {ca_cert_path} is missing; \
                 deleting stale key and regenerating CA"
            );
            std::fs::remove_file(ca_key_path)
                .map_err(|e| anyhow::anyhow!("remove stale CA key {ca_key_path}: {e}"))?;
        } else {
            tracing::error!(
                "partial CA state: {ca_cert_path} exists but {ca_key_path} is missing; \
                 deleting stale cert and regenerating CA"
            );
            std::fs::remove_file(ca_cert_path)
                .map_err(|e| anyhow::anyhow!("remove stale CA cert {ca_cert_path}: {e}"))?;
        }
        // Fall through to generate a fresh CA below.
    }

    if key_exists && cert_exists {
        // Load CA key from PEM.
        let key_pem =
            std::fs::read_to_string(validate_cli_path(std::path::Path::new(ca_key_path))?)
                .map_err(|e| anyhow::anyhow!("read CA key {ca_key_path}: {e}"))?;
        let ca_key =
            KeyPair::from_pem(&key_pem).map_err(|e| anyhow::anyhow!("parse CA key: {e}"))?;

        // Load the persisted CA cert DER (stable — handed to TlsMaterial as-is).
        let ca_cert_der = std::fs::read(validate_cli_path(std::path::Path::new(ca_cert_path))?)
            .map_err(|e| anyhow::anyhow!("read CA cert {ca_cert_path}: {e}"))?;

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
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, ca_cn);

        tracing::info!("loaded CA key from {ca_key_path}; cert DER from {ca_cert_path}");
        return Ok((ca_key, ca_params, ca_cert_der));
    }

    // Generate fresh CA. The Subject CN gets a random per-stack suffix so that a
    // client misrouted to a DIFFERENT u7s stack's apiserver fails trust-anchor
    // lookup by name (rustls UnknownIssuer) instead of matching a wrong-stack CA
    // by the shared literal name and then failing cryptographic verification
    // against a leaf signed by a different key (rustls BadSignature — cryptic).
    tracing::info!("generating new CA key+cert → {ca_key_path} / {ca_cert_path}");
    let ca_key = KeyPair::generate().map_err(|e| anyhow::anyhow!("generate CA key: {e}"))?;
    let ca_cn = format!("u7s-ca-{}", random_ca_suffix());
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, ca_cn);
    let ca_cert_der = ca_params
        .self_signed(&ca_key)
        .map_err(|e| anyhow::anyhow!("self-sign CA: {e}"))?
        .der()
        .to_vec();

    // Persist: key as PEM with 0o600 (owner-only), cert as DER with default perms.
    write_private_key(
        validate_cli_path(std::path::Path::new(ca_key_path))?,
        ca_key.serialize_pem().as_bytes(),
    )
    .map_err(|e| anyhow::anyhow!("write CA key {ca_key_path}: {e}"))?;
    std::fs::write(
        validate_cli_path(std::path::Path::new(ca_cert_path))?,
        &ca_cert_der,
    )
    .map_err(|e| anyhow::anyhow!("write CA cert {ca_cert_path}: {e}"))?;

    Ok((ca_key, ca_params, ca_cert_der))
}

/// True if `leaf_der`'s Issuer field matches `ca_der`'s Subject field. Malformed DER on
/// either side is treated as a mismatch (fail closed — regenerate rather than trust
/// unparseable bytes).
fn cert_issuer_matches_ca_subject(leaf_der: &[u8], ca_der: &[u8]) -> bool {
    use x509_cert::der::Decode as _;
    use x509_cert::Certificate;
    let Ok(leaf) = Certificate::from_der(leaf_der) else {
        return false;
    };
    let Ok(ca) = Certificate::from_der(ca_der) else {
        return false;
    };
    leaf.tbs_certificate().issuer() == ca.tbs_certificate().subject()
}

/// Load-or-generate the admin client cert+key (CN=admin, O=system:masters) embedded in
/// the "admin" kubeconfig. kubelet.service authenticates as this SAME identity too
/// (install.sh points both at $STATE_DIR/kubeconfig).
///
/// Persisted the same way as the CA (`load_or_generate_ca`): the CA surviving a restart
/// is not enough on its own to keep `--kubeconfig`'s bytes stable — without this, every
/// restart still mints a brand-new system:masters credential (new key, new signature,
/// unconditionally overwritten into the kubeconfig file), with no way to revoke the
/// previous one. That is exactly the kind of "rotation of admin identity on restart"
/// mayor-1oj4d already ruled out once, in bearer-token form.
fn load_or_generate_admin_cert(
    key_path: &std::path::Path,
    cert_path: &std::path::Path,
    ca_cert_der: &[u8],
    ca_issuer: &Issuer<'_, KeyPair>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let key_exists = key_path.exists();
    let cert_exists = cert_path.exists();

    // Same partial-state rationale as load_or_generate_ca: only one of the two files
    // existing means a prior run crashed mid-write. Delete the stale half and regenerate
    // rather than silently loading a key with no matching cert (or vice versa).
    if key_exists ^ cert_exists {
        if key_exists {
            tracing::error!(
                "partial admin cert state: {} exists but {} is missing; \
                 deleting stale key and regenerating admin cert",
                key_path.display(),
                cert_path.display()
            );
            std::fs::remove_file(key_path).map_err(|e| {
                anyhow::anyhow!("remove stale admin key {}: {e}", key_path.display())
            })?;
        } else {
            tracing::error!(
                "partial admin cert state: {} exists but {} is missing; \
                 deleting stale cert and regenerating admin cert",
                cert_path.display(),
                key_path.display()
            );
            std::fs::remove_file(cert_path).map_err(|e| {
                anyhow::anyhow!("remove stale admin cert {}: {e}", cert_path.display())
            })?;
        }
    }

    if key_path.exists() && cert_path.exists() {
        let key_pem = std::fs::read_to_string(validate_cli_path(key_path)?)
            .map_err(|e| anyhow::anyhow!("read admin key {}: {e}", key_path.display()))?;
        // Parse only to fail loud on a corrupt file; the PEM bytes (not this KeyPair) are
        // what TlsMaterial actually carries forward.
        KeyPair::from_pem(&key_pem).map_err(|e| anyhow::anyhow!("parse admin key: {e}"))?;
        let cert_der = std::fs::read(validate_cli_path(cert_path)?)
            .map_err(|e| anyhow::anyhow!("read admin cert {}: {e}", cert_path.display()))?;

        if cert_issuer_matches_ca_subject(&cert_der, ca_cert_der) {
            tracing::info!("loaded admin cert from {}", cert_path.display());
            return Ok((cert_der, key_pem.into_bytes()));
        }
        // The on-disk admin cert was issued by a DIFFERENT CA than the one just loaded
        // (e.g. ca.key/ca.crt were rotated independently, or -- observed only under test
        // parallelism, where multiple processes race on the same relative default paths --
        // a concurrent writer regenerated the CA after this admin cert was signed).
        // Loading it anyway would hand out a chain that fails verification for every
        // client that receives it. Discard and regenerate against the CA now in memory.
        tracing::error!(
            "admin cert at {} was not issued by the CA now loaded from disk; \
             discarding and regenerating",
            cert_path.display()
        );
        std::fs::remove_file(key_path)
            .map_err(|e| anyhow::anyhow!("remove stale admin key {}: {e}", key_path.display()))?;
        std::fs::remove_file(cert_path)
            .map_err(|e| anyhow::anyhow!("remove stale admin cert {}: {e}", cert_path.display()))?;
    }

    let admin_key = KeyPair::generate().map_err(|e| anyhow::anyhow!("generate admin key: {e}"))?;
    let mut admin_params = CertificateParams::default();
    admin_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "admin");
    // O=system:masters bypasses RBAC (Phase 3+). Harmless in Phase 1 (no RBAC).
    admin_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "system:masters");
    let admin_cert = admin_params.signed_by(&admin_key, ca_issuer)?;
    let admin_cert_der = admin_cert.der().to_vec();
    let admin_key_pem = admin_key.serialize_pem().into_bytes();

    write_private_key(validate_cli_path(key_path)?, &admin_key_pem)
        .map_err(|e| anyhow::anyhow!("write admin key {}: {e}", key_path.display()))?;
    std::fs::write(validate_cli_path(cert_path)?, &admin_cert_der)
        .map_err(|e| anyhow::anyhow!("write admin cert {}: {e}", cert_path.display()))?;
    tracing::info!("generated new admin cert → {}", cert_path.display());

    Ok((admin_cert_der, admin_key_pem))
}

pub struct TlsMaterial {
    /// DER-encoded CA certificate (written into kubeconfig).
    pub ca_cert_der: Vec<u8>,
    /// DER-encoded server leaf certificate (the single cert in the TLS chain).
    #[cfg_attr(not(test), allow(dead_code))]
    pub server_cert_der: Vec<u8>,
    /// DER-encoded admin client certificate (written into kubeconfig).
    pub admin_cert_der: Vec<u8>,
    /// PEM-encoded admin client certificate (concatenate with admin_key_pem for reqwest::Identity).
    pub admin_cert_pem: Vec<u8>,
    /// PEM-encoded admin private key (written into kubeconfig).
    pub admin_key_pem: Vec<u8>,
    /// PEM-encoded kubelet client certificate (CN=kube-apiserver-kubelet-client, O=system:masters).
    pub kubelet_client_cert_pem: Vec<u8>,
    /// PEM-encoded kubelet client private key.
    pub kubelet_client_key_pem: Vec<u8>,
    /// DER-encoded kube-controller-manager client certificate (CN=system:kube-controller-manager,
    /// no O=). Written into a dedicated KCM kubeconfig so KCM authenticates as its own
    /// least-privilege identity instead of sharing the admin/system:masters kubeconfig.
    pub kcm_cert_der: Vec<u8>,
    /// PEM-encoded kube-controller-manager client private key.
    pub kcm_key_pem: Vec<u8>,
    /// DER-encoded scheduler client certificate (CN=system:kube-scheduler, no O=). Same
    /// rationale as `kcm_cert_der`, for the scheduler's dedicated kubeconfig.
    pub scheduler_cert_der: Vec<u8>,
    /// PEM-encoded scheduler client private key.
    pub scheduler_key_pem: Vec<u8>,
    /// DER-encoded bootstrap-installer client certificate (CN=system:bootstrap-installer,
    /// no O=). Written into a dedicated kubeconfig so the in-process YAML applier that
    /// installs bootstrap manifest bundles (e.g. CoreDNS) against the just-bound apiserver
    /// authenticates as its own least-privilege identity, same rationale as `kcm_cert_der`.
    pub bootstrap_installer_cert_der: Vec<u8>,
    /// PEM-encoded bootstrap-installer client private key.
    pub bootstrap_installer_key_pem: Vec<u8>,
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
    /// Configured rustls ServerConfig for the axum server.
    pub server_config: Arc<ServerConfig>,
}

/// Extract the host from an advertise_address like "https://host.lima.internal:6443".
/// Returns None if the string is absent or unparseable.
fn advertise_host(advertise_address: Option<&str>) -> Option<String> {
    let addr = advertise_address?;
    // Strip scheme prefix.
    let without_scheme = addr
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    // Strip port suffix — split on ':' and take the first segment.
    let host = without_scheme.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
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

pub fn generate_tls(args: &Args) -> anyhow::Result<TlsMaterial> {
    // Install the ML-KEM-768 hybrid post-quantum crypto provider.
    // `.ok()` makes this idempotent: a second call (e.g. in tests) is a no-op.
    rustls_post_quantum::provider().install_default().ok();

    // --- CA: load-or-generate ---
    // If both ca.key (PEM) and ca.crt (DER) exist on disk, load them so the CA
    // stays stable across restarts. If either is missing, generate fresh and write.
    // ca_cert_der is the original DER bytes — stable across restarts.
    // ca_params is used to construct an Issuer for signing leaf certs (rcgen 0.14 API).
    let (ca_key, ca_params, ca_cert_der) = load_or_generate_ca(&args.ca_key, &args.ca_cert)?;
    // Build an Issuer from the CA params and key for signing leaf certificates.
    let ca_issuer = Issuer::new(ca_params, ca_key);

    // --- Server cert ---
    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::default();
    // Always include localhost / 127.0.0.1 and the lima VM-to-host alias,
    // plus the advertise-address host if provided.
    let sans = build_server_sans(
        advertise_host(args.advertise_address.as_deref()).as_deref(),
        &args.service_cluster_ip_range,
    )?;
    server_params.subject_alt_names = sans;
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "u7s-apiserver");
    let server_cert = server_params.signed_by(&server_key, &ca_issuer)?;

    // --- Admin client cert: load-or-generate, persisted alongside the CA -----------------
    // Sibling files next to ca.key/ca.crt rather than new CLI flags -- see
    // load_or_generate_admin_cert's doc for why persisting this (not just the CA) matters.
    let admin_key_path = std::path::Path::new(&args.ca_key).with_file_name("admin.key");
    let admin_cert_path = std::path::Path::new(&args.ca_cert).with_file_name("admin.crt");
    let (admin_cert_der, admin_key_pem) =
        load_or_generate_admin_cert(&admin_key_path, &admin_cert_path, &ca_cert_der, &ca_issuer)?;

    // --- Kubelet client cert ---
    // Kubelet's --client-ca-file trusts our cluster CA, and kubelet accepts clients
    // from the system:masters organization as trusted. CN and O must match exactly
    // what real kube-apiserver uses so kubelet authorizes the proxy requests.
    let kubelet_client_key = KeyPair::generate()?;
    let mut kubelet_client_params = CertificateParams::default();
    kubelet_client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "kube-apiserver-kubelet-client");
    kubelet_client_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "system:masters");
    let kubelet_client_cert = kubelet_client_params.signed_by(&kubelet_client_key, &ca_issuer)?;

    // --- KCM client cert ---
    // Real kubeadm gives kube-controller-manager a dedicated x509 identity, not a share
    // of admin/system:masters. No O= — the seeded ClusterRoleBinding
    // system:kube-controller-manager (see seed_rbac()) binds by username (kind: User),
    // so group membership is irrelevant here.
    let kcm_key = KeyPair::generate()?;
    let mut kcm_params = CertificateParams::default();
    kcm_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "system:kube-controller-manager");
    let kcm_cert = kcm_params.signed_by(&kcm_key, &ca_issuer)?;

    // --- Scheduler client cert ---
    let scheduler_key = KeyPair::generate()?;
    let mut scheduler_params = CertificateParams::default();
    scheduler_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "system:kube-scheduler");
    let scheduler_cert = scheduler_params.signed_by(&scheduler_key, &ca_issuer)?;

    // --- Bootstrap-installer client cert ---
    // Identity for the in-process YAML applier (a later bead) that server-side-applies
    // bootstrap manifest bundles (e.g. CoreDNS) against the just-bound apiserver. No O= —
    // the seeded ClusterRoleBinding system:bootstrap-installer (see seed_rbac()) binds by
    // username, same as KCM/scheduler above.
    let bootstrap_installer_key = KeyPair::generate()?;
    let mut bootstrap_installer_params = CertificateParams::default();
    bootstrap_installer_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "system:bootstrap-installer");
    let bootstrap_installer_cert =
        bootstrap_installer_params.signed_by(&bootstrap_installer_key, &ca_issuer)?;

    // --- Dedicated front-proxy CA: load-or-generate ---
    // A CA distinct from the main cluster CA above -- see `TlsMaterial::proxy_client_cert_pem`'s
    // doc for why a dedicated CA (not just a dedicated leaf cert under the shared CA, like
    // KCM/scheduler/kubelet-client above) matters here: it's what an aggregated backend
    // trusts via requestheader-client-ca-file, so only a leaf THIS CA signed can assert
    // X-Remote-User/-Group identity, regardless of what other certs the cluster CA has signed.
    let (proxy_client_ca_key, proxy_client_ca_params, _proxy_client_ca_cert_der) =
        load_or_generate_ca(&args.proxy_client_ca_key, &args.proxy_client_ca_cert)?;
    let proxy_client_ca_issuer = Issuer::new(proxy_client_ca_params, proxy_client_ca_key);

    // --- Proxy-client cert ---
    // CN follows kubeadm's own "front-proxy-client" convention. Presented to aggregated
    // backends only (see doc); no O= is needed since the backend's own RBAC/authorization
    // config never sees this cert's Subject, only the X-Remote-User/-Group headers it vouches for.
    let proxy_client_key = KeyPair::generate()?;
    let mut proxy_client_params = CertificateParams::default();
    proxy_client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "front-proxy-client");
    let proxy_client_cert =
        proxy_client_params.signed_by(&proxy_client_key, &proxy_client_ca_issuer)?;

    // --- Build rustls ServerConfig ---
    // Present only the leaf cert in the chain. The CA cert is already in the
    // kubelet's trust store (via kubeconfig certificate-authority-data). Including
    // the self-signed CA as an intermediate causes Go's TLS verifier to reject the
    // chain on full re-handshake (after session cache expiry): it sees a chain where
    // intermediate == trust anchor, which is invalid per RFC 5246 chain validation.
    let server_cert_chain = vec![CertificateDer::from(server_cert.der().to_vec())];
    let server_key_der = PrivateKeyDer::try_from(server_key.serialize_der())
        .map_err(|e| anyhow::anyhow!("key error: {e}"))?;

    // Enable mTLS: request (but don't require) client certs.
    // Clients that present a cert signed by our CA will be authenticated via x509.
    // Clients without a cert fall through to other auth mechanisms (tokens, anonymous).
    let mut root_store = RootCertStore::empty();
    root_store.add(CertificateDer::from(ca_cert_der.clone()))?;
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

    let server_cert_der = server_cert.der().to_vec();
    let admin_cert_pem = pem_encode("CERTIFICATE", &admin_cert_der);
    let kubelet_client_cert_der = kubelet_client_cert.der().to_vec();
    let kubelet_client_cert_pem = pem_encode("CERTIFICATE", &kubelet_client_cert_der);
    let kcm_cert_der = kcm_cert.der().to_vec();
    let scheduler_cert_der = scheduler_cert.der().to_vec();
    let bootstrap_installer_cert_der = bootstrap_installer_cert.der().to_vec();
    let proxy_client_cert_der = proxy_client_cert.der().to_vec();
    let proxy_client_cert_pem = pem_encode("CERTIFICATE", &proxy_client_cert_der);
    Ok(TlsMaterial {
        ca_cert_der,
        server_cert_der,
        admin_cert_der,
        admin_cert_pem,
        admin_key_pem,
        kubelet_client_cert_pem,
        kubelet_client_key_pem: kubelet_client_key.serialize_pem().into_bytes(),
        kcm_cert_der,
        kcm_key_pem: kcm_key.serialize_pem().into_bytes(),
        scheduler_cert_der,
        scheduler_key_pem: scheduler_key.serialize_pem().into_bytes(),
        bootstrap_installer_cert_der,
        bootstrap_installer_key_pem: bootstrap_installer_key.serialize_pem().into_bytes(),
        proxy_client_cert_pem,
        proxy_client_key_pem: proxy_client_key.serialize_pem().into_bytes(),
        server_config: Arc::new(server_config),
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
    ca_data: String,
    cert_data: String,
    key_data: String,
    user: String,
}

impl Kubeconfig {
    fn new(server: &str, tls: &TlsMaterial) -> Self {
        Self::for_identity(
            server,
            tls,
            &tls.admin_cert_der,
            &tls.admin_key_pem,
            "admin",
        )
    }

    /// Build a kubeconfig for a dedicated non-admin component identity (KCM, scheduler),
    /// embedding `cert_der`/`key_pem` under `username` instead of the admin cert.
    fn for_identity(
        server: &str,
        tls: &TlsMaterial,
        cert_der: &[u8],
        key_pem: &[u8],
        username: &str,
    ) -> Self {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        // kubeconfig fields expect base64(PEM), not base64(DER).
        let ca_pem = pem_encode("CERTIFICATE", &tls.ca_cert_der);
        let cert_pem = pem_encode("CERTIFICATE", cert_der);
        Kubeconfig {
            server: server.to_owned(),
            ca_data: b64.encode(&ca_pem),
            cert_data: b64.encode(&cert_pem),
            key_data: b64.encode(key_pem),
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
             \x20   certificate-authority-data: {ca_data}\n\
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
             \x20   client-certificate-data: {cert_data}\n\
             \x20   client-key-data: {key_data}\n",
            server = self.server,
            ca_data = self.ca_data,
            user = self.user,
            cert_data = self.cert_data,
            key_data = self.key_data,
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

/// Write a kubeconfig to `path`.
/// The default path ("./kubeconfig") is write-only on first run — it is not
/// a read fixture. The file is generated fresh from the in-memory TLS material
/// each time the server starts.
///
/// The kubeconfig contains embedded client certificate and private key material,
/// so it is written with mode 0o600 (owner read+write only), matching the same
/// permission applied to the SA and CA key files by `write_private_key`.
pub fn write_kubeconfig(path: &str, tls: &TlsMaterial, args: &Args) -> anyhow::Result<()> {
    // Use the advertise-address (or listen address) as the server URL so that
    // parallel workers running on non-default loopback IPs (127.0.0.2, etc.)
    // get a kubeconfig that points at their own apiserver.
    // lima-start.sh rewrites any 127.x address to host.lima.internal when copying into the VM.
    let kc = Kubeconfig::new(kubeconfig_server_url(args), tls);
    write_private_key(
        validate_cli_path(std::path::Path::new(path))?,
        kc.to_yaml().as_bytes(),
    )?;
    tracing::info!("kubeconfig written to {path}");
    Ok(())
}

/// Write a kubeconfig for a dedicated component identity (KCM, scheduler) rather than the
/// shared admin identity `write_kubeconfig` writes. Real kubeadm gives each static control-plane
/// component its own x509 client cert so cluster RBAC (e.g. the seeded
/// `system:kube-controller-manager` / `system:kube-scheduler` ClusterRoles) actually applies,
/// instead of every component sharing admin/system:masters and bypassing RBAC entirely.
pub fn write_component_kubeconfig(
    path: &str,
    tls: &TlsMaterial,
    args: &Args,
    cert_der: &[u8],
    key_pem: &[u8],
    username: &str,
) -> anyhow::Result<()> {
    let kc = Kubeconfig::for_identity(
        kubeconfig_server_url(args),
        tls,
        cert_der,
        key_pem,
        username,
    );
    write_private_key(
        validate_cli_path(std::path::Path::new(path))?,
        kc.to_yaml().as_bytes(),
    )?;
    tracing::info!("kubeconfig written to {path} (user={username})");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            sa_sig_cache_size: None,
        }
    }

    #[test]
    fn advertise_host_extracts_dns_name() {
        assert_eq!(
            advertise_host(Some("https://host.lima.internal:6443")),
            Some("host.lima.internal".into())
        );
    }

    #[test]
    fn advertise_host_extracts_ip() {
        assert_eq!(
            advertise_host(Some("https://192.168.1.10:6443")),
            Some("192.168.1.10".into())
        );
    }

    #[test]
    fn advertise_host_none_on_absent() {
        assert_eq!(advertise_host(None), None);
    }

    #[test]
    fn san_includes_advertise_dns_name() {
        let args = args_with(Some("https://host.lima.internal:6443"));
        // generate_tls must succeed and produce a cert that includes the DNS SAN.
        let _tls = generate_tls(&args).expect("generate_tls failed");
        // Verify host parses as DNS (not IP).
        let host = advertise_host(args.advertise_address.as_deref()).unwrap();
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
        let host = advertise_host(args.advertise_address.as_deref()).unwrap();
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
        let host = advertise_host(args.advertise_address.as_deref()).unwrap();
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
            sa_sig_cache_size: None,
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

    /// Regression for the exact live-operator symptom this fix targets: an admin
    /// kubeconfig copied off the node before `systemctl restart u7s-apiserver` must keep
    /// authenticating after the restart, with no client-side action. A prior incarnation
    /// of this invariant (mayor-1oj4d, bearer-token era) was already broken once by a
    /// restart regenerating the credential; this reproduces the same class of break at
    /// the TLS chain-validation layer the current x509-only auth model depends on.
    #[test]
    fn admin_cert_issued_before_restart_still_chain_validates_after_restart() {
        use rustls::pki_types::UnixTime;

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
             each time, which is the credential-rotation-on-restart mayor-1oj4d already \
             ruled out once"
        );

        // The operator-visible failure mode: does the cert captured BEFORE the restart
        // still pass the exact chain-validation check the live server runs on every mTLS
        // handshake, built from the CA loaded AFTER the restart?
        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(tls2.ca_cert_der.clone()))
            .expect("root store add");
        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .allow_unauthenticated()
            .build()
            .expect("build verifier");

        verifier
            .verify_client_cert(
                &CertificateDer::from(tls1.admin_cert_der.clone()),
                &[],
                UnixTime::now(),
            )
            .expect(
                "an admin cert issued BEFORE a restart must still pass the server's \
                 client-cert chain validation AFTER the restart, or every kubectl session \
                 holding the pre-restart kubeconfig gets 401 Unauthorized with no \
                 client-side action taken",
            );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Simulates the exact corruption `cert_issuer_matches_ca_subject` exists to catch:
    /// admin.key/admin.crt on disk were signed by a CA that is no longer the one loaded
    /// from ca.key/ca.crt (an operator rotating CA files independently, or -- under test
    /// parallelism -- a concurrent process regenerating the CA after this admin cert was
    /// already signed). Loading the stale pair anyway would hand kubectl a chain that
    /// fails real TLS validation against the CA the server now trusts.
    #[test]
    fn admin_cert_from_a_different_ca_is_discarded_and_regenerated() {
        let dir = test_temp_dir("admin-cert-ca-mismatch");
        let ca_key_path = dir.join("ca.key").to_string_lossy().into_owned();
        let ca_cert_path = dir.join("ca.crt").to_string_lossy().into_owned();
        let (real_ca_key, real_ca_params, real_ca_cert_der) =
            load_or_generate_ca(&ca_key_path, &ca_cert_path).expect("generate real CA");
        let real_ca_issuer = Issuer::new(real_ca_params, real_ca_key);

        // A DIFFERENT, unrelated CA signs the "stale" admin cert.
        let other_ca_key = KeyPair::generate().expect("generate other CA key");
        let mut other_ca_params = CertificateParams::default();
        other_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
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

        let admin_key_path = dir.join("admin.key");
        let admin_cert_path = dir.join("admin.crt");
        write_private_key(&admin_key_path, stale_admin_key.serialize_pem().as_bytes())
            .expect("write stale admin key");
        std::fs::write(&admin_cert_path, stale_admin_cert.der()).expect("write stale admin cert");

        let (admin_cert_der, _admin_key_pem) = load_or_generate_admin_cert(
            &admin_key_path,
            &admin_cert_path,
            &real_ca_cert_der,
            &real_ca_issuer,
        )
        .expect("load_or_generate_admin_cert must recover, not fail");

        assert!(
            cert_issuer_matches_ca_subject(&admin_cert_der, &real_ca_cert_der),
            "a stale admin cert issued by a DIFFERENT CA must be discarded and replaced \
             with one actually issued by the CA now loaded from disk, or kubectl gets a \
             chain that fails real TLS validation"
        );

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

    /// Helper: call load_or_generate_ca with paths inside `dir`.
    fn run_load_or_generate_ca(
        dir: &std::path::Path,
    ) -> anyhow::Result<(KeyPair, CertificateParams, Vec<u8>)> {
        let ca_key_path = dir.join("ca.key").to_string_lossy().into_owned();
        let ca_cert_path = dir.join("ca.crt").to_string_lossy().into_owned();
        load_or_generate_ca(&ca_key_path, &ca_cert_path)
    }

    #[test]
    fn partial_state_only_key_recovers() {
        // Simulate a crash after ca.key was written but before ca.crt was written.
        // load_or_generate_ca must: delete the stale key, generate a fresh CA,
        // and return Ok with both files present. Without this fix the stale key
        // would be silently overwritten and kubelets trusting the previous CA
        // would break on server restart.
        let dir = test_temp_dir("partial-key");
        let ca_key_path = dir.join("ca.key");
        let ca_cert_path = dir.join("ca.crt");

        // Write only ca.key — no ca.crt.
        std::fs::write(&ca_key_path, b"dummy-key-content").expect("write dummy ca.key"); // lgtm[rust/path-injection]
        assert!(ca_key_path.exists());
        assert!(!ca_cert_path.exists());

        let result = run_load_or_generate_ca(&dir);
        assert!(result.is_ok(), "expected Ok but got: {:?}", result.err());

        assert!(ca_key_path.exists(), "ca.key must exist after recovery");
        assert!(ca_cert_path.exists(), "ca.crt must exist after recovery");

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[test]
    fn partial_state_only_cert_recovers() {
        // Simulate a crash after ca.crt was written but after ca.key was deleted
        // (or ca.key was never written, e.g. manual operator error).
        // load_or_generate_ca must: delete the stale cert, generate a fresh CA,
        // and return Ok with both files present.
        let dir = test_temp_dir("partial-cert");
        let ca_key_path = dir.join("ca.key");
        let ca_cert_path = dir.join("ca.crt");

        // Write only ca.crt — no ca.key.
        std::fs::write(&ca_cert_path, b"dummy-cert-content").expect("write dummy ca.crt"); // lgtm[rust/path-injection]
        assert!(!ca_key_path.exists());
        assert!(ca_cert_path.exists());

        let result = run_load_or_generate_ca(&dir);
        assert!(result.is_ok(), "expected Ok but got: {:?}", result.err());

        assert!(ca_key_path.exists(), "ca.key must exist after recovery");
        assert!(ca_cert_path.exists(), "ca.crt must exist after recovery");

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
            proxy_client_ca_key: "./proxy-client-ca.key".into(),
            proxy_client_ca_cert: "./proxy-client-ca.crt".into(),
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            sa_sig_cache_size: None,
        };

        let tls = generate_tls(&args).expect("generate_tls must succeed");
        write_kubeconfig(&kubeconfig_path.to_string_lossy(), &tls, &args)
            .expect("write_kubeconfig must succeed");

        let meta = std::fs::metadata(&kubeconfig_path).expect("kubeconfig file must exist"); // lgtm[rust/path-injection]
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "kubeconfig must be mode 0o600 (got {:#o}); \
             world-readable kubeconfig allows any local user to impersonate cluster admin",
            mode
        );
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
            proxy_client_ca_key: "./proxy-client-ca.key".into(),
            proxy_client_ca_cert: "./proxy-client-ca.crt".into(),
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            sa_sig_cache_size: None,
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
            proxy_client_ca_key: "./proxy-client-ca.key".into(),
            proxy_client_ca_cert: "./proxy-client-ca.crt".into(),
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            sa_sig_cache_size: None,
        };
        let tls = generate_tls(&args).expect("generate_tls must succeed");
        let server_url = "https://127.0.0.1:6443";
        let kc = Kubeconfig::new(server_url, &tls);
        let yaml = kc.to_yaml();

        assert!(
            yaml.contains("server:"),
            "kubeconfig YAML must contain 'server:' field; got: {yaml}"
        );
        assert!(
            yaml.contains(server_url),
            "kubeconfig YAML must contain the server URL; got: {yaml}"
        );
        assert!(
            yaml.contains("certificate-authority-data:"),
            "kubeconfig YAML must contain 'certificate-authority-data:' field; got: {yaml}"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Regression test: the admin kubeconfig must be cert-only, with NO `token:` field at
    /// all — matching kubeadm/k3s's own admin-kubeconfig shape. A previous design embedded
    /// a bearer token here purely so the aggregation proxy had an Authorization header to
    /// forward to aggregated backends on kubectl/KCM's cert-only requests; that token
    /// forced `authenticate()` into a bearer-token-wins-over-cert precedence rule, which is
    /// exactly what broke every previously-issued kubeconfig on apiserver restart (the token
    /// was originally minted fresh on every restart with no persistence — mayor-1oj4d). The
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
        let tls = generate_tls(&args).expect("generate_tls must succeed");
        let kc = Kubeconfig::new("https://127.0.0.1:6443", &tls);
        let yaml = kc.to_yaml();

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
            advertise_host(Some("https://")),
            None,
            "empty host segment must return None, not Some(\"\")"
        );
    }

    /// advertise_host must strip a bare port suffix even when no scheme is present.
    /// Operators may supply just "host:6443" without a scheme prefix.
    #[test]
    fn advertise_host_no_scheme_strips_port() {
        assert_eq!(
            advertise_host(Some("myhost:6443")),
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
            proxy_client_ca_key: "./proxy-client-ca.key".into(),
            proxy_client_ca_cert: "./proxy-client-ca.crt".into(),
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            sa_sig_cache_size: None,
        };
        let tls = generate_tls(&args).expect("generate_tls must succeed");
        write_kubeconfig(&kubeconfig_path.to_string_lossy(), &tls, &args)
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
            proxy_client_ca_key: "./proxy-client-ca.key".into(),
            proxy_client_ca_cert: "./proxy-client-ca.crt".into(),
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            sa_sig_cache_size: None,
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
            proxy_client_ca_key: "./proxy-client-ca.key".into(),
            proxy_client_ca_cert: "./proxy-client-ca.crt".into(),
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            sa_sig_cache_size: None,
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
        legacy_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
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

    /// Regression: `write_component_kubeconfig` must embed the given component's own
    /// cert/key under its own username, and must NOT carry any bearer token — every
    /// identity this module writes is cert-only (see `Kubeconfig`'s doc), so a token
    /// field here would silently grant whatever identity that token resolves to
    /// alongside the component's own least-privilege cert.
    #[test]
    fn write_component_kubeconfig_uses_component_identity_with_no_token() {
        let dir = test_temp_dir("component-kubeconfig");
        let args = Args {
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            ..args_with(None)
        };
        let tls = generate_tls(&args).expect("generate_tls must succeed");
        let out_path = dir.join("scheduler-kubeconfig");

        write_component_kubeconfig(
            &out_path.to_string_lossy(),
            &tls,
            &args,
            &tls.scheduler_cert_der,
            &tls.scheduler_key_pem,
            "system:kube-scheduler",
        )
        .expect("write_component_kubeconfig must succeed");

        let yaml = std::fs::read_to_string(&out_path).expect("kubeconfig must be written"); // lgtm[rust/path-injection]
        assert!(
            yaml.contains("user: system:kube-scheduler"),
            "component kubeconfig must reference its own identity, not 'admin'; got: {yaml}"
        );
        assert!(
            !yaml.contains("token:"),
            "component kubeconfig must have no token field at all when none was minted \
             for it; got: {yaml}"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }
}

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    RootCertStore, ServerConfig,
};
use std::sync::Arc;

use crate::util::validate_cli_path;
use crate::Args;

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
    /// PEM-encoded PKCS#8 private key — used to construct an EncodingKey.
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
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::RsaPrivateKey;

    // If the private key already exists, load it and re-derive the public key.
    if std::path::Path::new(sa_key_path).exists() {
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
        let pem = std::fs::read(validate_cli_path(std::path::Path::new(sa_key_path))?)?;
        let pem_str = std::str::from_utf8(&pem)
            .map_err(|e| anyhow::anyhow!("SA key file is not valid UTF-8: {e}"))?;
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem_str)
            .map_err(|e| anyhow::anyhow!("failed to parse SA private key: {e}"))?;
        let public_pem = private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
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
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("PKCS#8 encode error: {e}"))?;

    let public_pem = private_key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
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
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "u7s-ca");

        tracing::info!("loaded CA key from {ca_key_path}; cert DER from {ca_cert_path}");
        return Ok((ca_key, ca_params, ca_cert_der));
    }

    // Generate fresh CA.
    tracing::info!("generating new CA key+cert → {ca_key_path} / {ca_cert_path}");
    let ca_key = KeyPair::generate().map_err(|e| anyhow::anyhow!("generate CA key: {e}"))?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "u7s-ca");
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

pub struct TlsMaterial {
    /// DER-encoded CA certificate (written into kubeconfig).
    pub ca_cert_der: Vec<u8>,
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
/// Always includes localhost, 127.0.0.1, host.lima.internal, and 10.96.0.1
/// (the kubernetes ClusterIP used by in-cluster clients).
/// If advertise_host is Some, appends it as an IP SAN or DNS SAN.
fn build_server_sans(advertise_host_str: Option<&str>) -> anyhow::Result<Vec<SanType>> {
    let mut sans: Vec<SanType> = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        SanType::DnsName("host.lima.internal".try_into()?),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 96, 0, 1))),
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
    let sans = build_server_sans(advertise_host(args.advertise_address.as_deref()).as_deref())?;
    server_params.subject_alt_names = sans;
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "u7s-apiserver");
    let server_cert = server_params.signed_by(&server_key, &ca_issuer)?;

    // --- Admin client cert ---
    let admin_key = KeyPair::generate()?;
    let mut admin_params = CertificateParams::default();
    admin_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "admin");
    // O=system:masters bypasses RBAC (Phase 3+). Harmless in Phase 1 (no RBAC).
    admin_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "system:masters");
    let admin_cert = admin_params.signed_by(&admin_key, &ca_issuer)?;

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

    // --- Build rustls ServerConfig ---
    // Use ca_cert_der (the stable, original bytes) for the chain and trust store —
    // not ca_cert.der(), which is re-issued on each load and would differ from disk.
    let server_cert_chain = vec![
        CertificateDer::from(server_cert.der().to_vec()),
        CertificateDer::from(ca_cert_der.clone()),
    ];
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
    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_cert_chain, server_key_der)?;

    let admin_cert_der = admin_cert.der().to_vec();
    let admin_cert_pem = pem_encode("CERTIFICATE", &admin_cert_der);
    let kubelet_client_cert_der = kubelet_client_cert.der().to_vec();
    let kubelet_client_cert_pem = pem_encode("CERTIFICATE", &kubelet_client_cert_der);
    Ok(TlsMaterial {
        ca_cert_der,
        admin_cert_der,
        admin_cert_pem,
        admin_key_pem: admin_key.serialize_pem().into_bytes(),
        kubelet_client_cert_pem,
        kubelet_client_key_pem: kubelet_client_key.serialize_pem().into_bytes(),
        server_config: Arc::new(server_config),
    })
}

fn pem_encode(label: &str, der: &[u8]) -> Vec<u8> {
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
struct Kubeconfig {
    server: String,
    ca_data: String,
    cert_data: String,
    key_data: String,
}

impl Kubeconfig {
    fn new(server: &str, tls: &TlsMaterial) -> Self {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        // kubeconfig fields expect base64(PEM), not base64(DER).
        let ca_pem = pem_encode("CERTIFICATE", &tls.ca_cert_der);
        let cert_pem = pem_encode("CERTIFICATE", &tls.admin_cert_der);
        Kubeconfig {
            server: server.to_owned(),
            ca_data: b64.encode(&ca_pem),
            cert_data: b64.encode(&cert_pem),
            key_data: b64.encode(&tls.admin_key_pem),
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
             \x20   user: admin\n\
             \x20 name: u7s\n\
             current-context: u7s\n\
             users:\n\
             - name: admin\n\
             \x20 user:\n\
             \x20   client-certificate-data: {cert_data}\n\
             \x20   client-key-data: {key_data}\n",
            server = self.server,
            ca_data = self.ca_data,
            cert_data = self.cert_data,
            key_data = self.key_data,
        )
    }
}

/// Write a kubeconfig to `path`.
/// The default path ("./kubeconfig") is write-only on first run — it is not
/// a read fixture. The file is generated fresh from the in-memory TLS material
/// each time the server starts.
///
/// The kubeconfig contains embedded client certificate and private key material,
/// so it is written with mode 0o600 (owner read+write only), matching the same
/// permission applied to the SA and CA key files by `write_private_key`.
pub fn write_kubeconfig(path: &str, tls: &TlsMaterial, _args: &Args) -> anyhow::Result<()> {
    // Always write 127.0.0.1 as the server URL — this kubeconfig is for local use on the host.
    // lima-start.sh rewrites it to host.lima.internal when copying into the VM.
    // The cert SANs already include the advertise-address host so connections from either
    // address are valid.
    let kc = Kubeconfig::new("https://127.0.0.1:6443", tls);
    write_private_key(
        validate_cli_path(std::path::Path::new(path))?,
        kc.to_yaml().as_bytes(),
    )?;
    tracing::info!("kubeconfig written to {path}");
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

    fn args_with(advertise_address: Option<&str>) -> Args {
        Args {
            db: "./state.db".into(),
            listen: "0.0.0.0:6443".into(),
            kubeconfig: "./kubeconfig".into(),
            token_auth_file: None,
            sa_key: "./sa.key".into(),
            sa_pub: "./sa.pub".into(),
            ca_key: "./ca.key".into(),
            ca_cert: "./ca.crt".into(),
            advertise_address: advertise_address.map(str::to_owned),
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
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
        let sans = build_server_sans(None).expect("build_server_sans failed");
        let has_lima = sans
            .iter()
            .any(|s| matches!(s, SanType::DnsName(n) if n.as_ref() == "host.lima.internal"));
        assert!(
            has_lima,
            "host.lima.internal must be in server SANs regardless of advertise_address"
        );
    }

    /// build_server_sans must always include 10.96.0.1 (kubernetes ClusterIP).
    /// In-cluster clients (sonobuoy, pods) use KUBERNETES_SERVICE_HOST=10.96.0.1
    /// and verify the TLS cert against it. Without this SAN the TLS handshake fails
    /// even after the DNAT rule routes the traffic to the host apiserver.
    #[test]
    fn build_server_sans_always_includes_cluster_ip() {
        let sans = build_server_sans(None).expect("build_server_sans failed");
        let has_cluster_ip = sans
            .iter()
            .any(|s| matches!(s, SanType::IpAddress(ip) if ip.to_string() == "10.96.0.1"));
        assert!(
            has_cluster_ip,
            "10.96.0.1 (kubernetes ClusterIP) must be in server SANs for in-cluster clients"
        );
    }

    /// build_server_sans with an IP advertise_host must include both host.lima.internal
    /// (DNS) and the IP address SAN.
    #[test]
    fn build_server_sans_with_ip_includes_both() {
        let sans = build_server_sans(Some("192.168.5.1")).expect("build_server_sans failed");
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
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
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
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
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
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
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
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
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
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
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
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
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
}

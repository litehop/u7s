use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, SanType};
use rustls::{ServerConfig, pki_types::{CertificateDer, PrivateKeyDer}};
use std::sync::Arc;

use crate::Args;

pub struct TlsMaterial {
    /// DER-encoded CA certificate (written into kubeconfig).
    pub ca_cert_der: Vec<u8>,
    /// DER-encoded admin client certificate (written into kubeconfig).
    pub admin_cert_der: Vec<u8>,
    /// PEM-encoded admin private key (written into kubeconfig).
    pub admin_key_pem: Vec<u8>,
    /// Configured rustls ServerConfig for the axum server.
    pub server_config: Arc<ServerConfig>,
}

pub fn generate_tls(_args: &Args) -> anyhow::Result<TlsMaterial> {
    // --- CA ---
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(
        rcgen::DnType::CommonName, "u7s-ca",
    );
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // --- Server cert ---
    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::default();
    server_params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    ];
    server_params.distinguished_name.push(
        rcgen::DnType::CommonName, "u7s-apiserver",
    );
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

    // --- Admin client cert ---
    let admin_key = KeyPair::generate()?;
    let mut admin_params = CertificateParams::default();
    admin_params.distinguished_name.push(rcgen::DnType::CommonName, "admin");
    // O=system:masters bypasses RBAC (Phase 3+). Harmless in Phase 1 (no RBAC).
    admin_params.distinguished_name.push(rcgen::DnType::OrganizationName, "system:masters");
    let admin_cert = admin_params.signed_by(&admin_key, &ca_cert, &ca_key)?;

    // --- Build rustls ServerConfig ---
    let server_cert_chain = vec![CertificateDer::from(server_cert.der().to_vec())];
    let server_key_der = PrivateKeyDer::try_from(server_key.serialize_der())
        .map_err(|e| anyhow::anyhow!("key error: {e}"))?;
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(server_cert_chain, server_key_der)?;

    Ok(TlsMaterial {
        ca_cert_der:    ca_cert.der().to_vec(),
        admin_cert_der: admin_cert.der().to_vec(),
        admin_key_pem:  admin_key.serialize_pem().into_bytes(),
        server_config:  Arc::new(server_config),
    })
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
        Kubeconfig {
            server: server.to_owned(),
            ca_data: b64.encode(&tls.ca_cert_der),
            cert_data: b64.encode(&tls.admin_cert_der),
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
pub fn write_kubeconfig(path: &str, tls: &TlsMaterial) -> anyhow::Result<()> {
    let kc = Kubeconfig::new("https://127.0.0.1:6443", tls);
    std::fs::write(path, kc.to_yaml())?;
    tracing::info!("kubeconfig written to {path}");
    Ok(())
}

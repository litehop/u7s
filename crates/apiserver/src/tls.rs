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

pub fn write_kubeconfig(path: &str, tls: &TlsMaterial) -> anyhow::Result<()> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    let ca_data   = b64.encode(&tls.ca_cert_der);
    let cert_data = b64.encode(&tls.admin_cert_der);
    let key_data  = b64.encode(&tls.admin_key_pem);

    let kubeconfig = format!(r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
    certificate-authority-data: {ca_data}
  name: u7s
contexts:
- context:
    cluster: u7s
    user: admin
  name: u7s
current-context: u7s
users:
- name: admin
  user:
    client-certificate-data: {cert_data}
    client-key-data: {key_data}
"#);

    std::fs::write(path, kubeconfig)?;
    tracing::info!("kubeconfig written to {path}");
    Ok(())
}

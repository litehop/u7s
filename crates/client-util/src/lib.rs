/// u7s-client-util — shared kubeconfig parsing and TLS client construction.
///
/// Both u7s-scheduler and u7s-controller-manager need to read a kubeconfig
/// file, extract TLS credentials, and build a tokio-rustls TlsConnector for
/// mTLS connections to the API server. This crate holds that shared logic
/// so each binary doesn't duplicate it.
use std::sync::Arc;

use anyhow::Context;
use base64::Engine;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsConnector;

/// Parsed credentials extracted from a kubeconfig file.
pub struct ClientCreds {
    /// Base URL of the API server, e.g. "https://127.0.0.1:6443"
    pub server: String,
    /// DER-encoded CA certificate used to verify the server.
    pub ca_cert: CertificateDer<'static>,
    /// DER-encoded client certificate.
    pub client_cert: CertificateDer<'static>,
    /// DER-encoded client private key.
    pub client_key: PrivateKeyDer<'static>,
}

/// Parse a kubeconfig file and return TLS credentials.
///
/// Performs manual YAML field extraction without a serde_yaml dependency.
/// The format is the fixed structure written by u7s-apiserver's tls.rs.
pub fn parse_kubeconfig(path: &str) -> anyhow::Result<ClientCreds> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading kubeconfig {path}"))?;

    let b64 = base64::engine::general_purpose::STANDARD;

    let server = extract_yaml_value(&raw, "server:").context("kubeconfig: missing server")?;
    let ca_data = extract_yaml_value(&raw, "certificate-authority-data:")
        .context("kubeconfig: missing certificate-authority-data")?;
    let cert_data = extract_yaml_value(&raw, "client-certificate-data:")
        .context("kubeconfig: missing client-certificate-data")?;
    let key_data = extract_yaml_value(&raw, "client-key-data:")
        .context("kubeconfig: missing client-key-data")?;

    let ca_der = b64.decode(ca_data.trim()).context("decode CA cert")?;
    let cert_der = b64.decode(cert_data.trim()).context("decode client cert")?;
    let key_pem = b64.decode(key_data.trim()).context("decode client key")?;

    let client_key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .context("parse client key PEM")?
        .context("no private key in kubeconfig client-key-data")?;

    Ok(ClientCreds {
        server: server.trim().to_owned(),
        ca_cert: CertificateDer::from(ca_der),
        client_cert: CertificateDer::from(cert_der),
        client_key,
    })
}

/// Extract the first occurrence of a YAML scalar value for `key` in `text`.
/// Handles both "  key: value" and "key: value" with arbitrary leading whitespace.
pub fn extract_yaml_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(key) {
            return Some(rest.trim());
        }
    }
    None
}

/// Build a tokio-rustls TlsConnector from parsed kubeconfig credentials.
///
/// Configures mTLS: the CA cert is used to verify the server; the client
/// cert/key are presented for mutual authentication.
pub fn build_tls_connector(creds: &ClientCreds) -> anyhow::Result<TlsConnector> {
    use rustls::ClientConfig;

    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(creds.ca_cert.clone())
        .context("add CA cert to root store")?;

    let client_cert_chain = vec![creds.client_cert.clone()];
    let client_key = creds.client_key.clone_key();

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_cert_chain, client_key)
        .context("configure mTLS client cert")?;

    Ok(TlsConnector::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify extract_yaml_value handles both leading-whitespace and flush-left forms,
    // since real kubeconfig files indent nested fields.
    #[test]
    fn extract_yaml_value_strips_leading_whitespace() {
        let text = "clusters:\n  - cluster:\n      server: https://127.0.0.1:6443\n";
        let result = extract_yaml_value(text, "server:");
        assert_eq!(result, Some("https://127.0.0.1:6443"));
    }

    #[test]
    fn extract_yaml_value_returns_none_for_missing_key() {
        let text = "clusters:\n  - cluster:\n      server: https://127.0.0.1:6443\n";
        assert!(extract_yaml_value(text, "certificate-authority-data:").is_none());
    }

    #[test]
    fn extract_yaml_value_returns_first_match() {
        // If the key appears twice, the first value wins. This matters because
        // kubeconfig can have multiple clusters; we always take the first.
        let text = "server: first\nserver: second\n";
        assert_eq!(extract_yaml_value(text, "server:"), Some("first"));
    }
}

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

    let ca_pem = b64.decode(ca_data.trim()).context("decode CA cert")?;
    let cert_pem = b64.decode(cert_data.trim()).context("decode client cert")?;
    let key_pem = b64.decode(key_data.trim()).context("decode client key")?;

    // The kubeconfig fields hold base64(PEM); rustls needs DER.
    // rustls_pemfile::certs() strips the PEM envelope and yields raw DER.
    let ca_cert = rustls_pemfile::certs(&mut ca_pem.as_slice())
        .next()
        .context("no certificate in kubeconfig certificate-authority-data")?
        .context("parse CA cert PEM")?;
    let client_cert = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .next()
        .context("no certificate in kubeconfig client-certificate-data")?
        .context("parse client cert PEM")?;
    let client_key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .context("parse client key PEM")?
        .context("no private key in kubeconfig client-key-data")?;

    Ok(ClientCreds {
        server: server.trim().to_owned(),
        ca_cert,
        client_cert,
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

    #[test]
    fn extract_yaml_value_empty_input_returns_none() {
        // An empty kubeconfig string must not panic or return garbage.
        assert!(extract_yaml_value("", "server:").is_none());
    }

    #[test]
    fn extract_yaml_value_key_only_no_value() {
        // "server:" with nothing after the colon returns an empty string, not None.
        // The caller trims whitespace, so both "" and " " yield "".
        let text = "server:\n";
        assert_eq!(extract_yaml_value(text, "server:"), Some(""));
    }

    #[test]
    fn extract_yaml_value_flush_left_key() {
        // Key at column 0, no indentation.
        let text = "server: https://127.0.0.1:6443\n";
        assert_eq!(
            extract_yaml_value(text, "server:"),
            Some("https://127.0.0.1:6443")
        );
    }

    // ---------------------------------------------------------------------------
    // Helpers shared by parse_kubeconfig and build_tls_connector tests.
    // ---------------------------------------------------------------------------

    /// Generate a self-signed CA cert + a leaf cert signed by it, all as PEM.
    /// Returns (ca_pem, leaf_cert_pem, leaf_key_pem).
    /// This mirrors what the apiserver's tls.rs does to produce kubeconfig data.
    fn make_test_certs() -> (String, String, String) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

        // CA
        let ca_key = KeyPair::generate().expect("generate CA key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-ca");
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
        let ca_pem = pem_encode_str("CERTIFICATE", ca_cert.der()).to_string();
        let ca_issuer = Issuer::new(ca_params, ca_key);

        // Leaf (client) cert
        let leaf_key = KeyPair::generate().expect("generate leaf key");
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-client");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_issuer)
            .expect("sign leaf cert");
        let leaf_cert_pem = pem_encode_str("CERTIFICATE", leaf_cert.der());
        let leaf_key_pem = leaf_key.serialize_pem();

        (ca_pem, leaf_cert_pem, leaf_key_pem)
    }

    /// PEM-encode DER bytes into a String.
    fn pem_encode_str(label: &str, der: &[u8]) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let encoded = b64.encode(der);
        let mut out = format!("-----BEGIN {label}-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str(&format!("-----END {label}-----\n"));
        out
    }

    /// Build the kubeconfig YAML string that parse_kubeconfig expects.
    /// The fields are base64(PEM) exactly as the apiserver writes them.
    fn make_kubeconfig_yaml(server: &str, ca_pem: &str, cert_pem: &str, key_pem: &str) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let ca_data = b64.encode(ca_pem.as_bytes());
        let cert_data = b64.encode(cert_pem.as_bytes());
        let key_data = b64.encode(key_pem.as_bytes());
        format!(
            "apiVersion: v1\n\
             kind: Config\n\
             clusters:\n\
             - cluster:\n\
             \x20   server: {server}\n\
             \x20   certificate-authority-data: {ca_data}\n\
             \x20 name: u7s\n\
             users:\n\
             - name: admin\n\
             \x20 user:\n\
             \x20   client-certificate-data: {cert_data}\n\
             \x20   client-key-data: {key_data}\n",
        )
    }

    /// Write a string to a temp file and return the path.
    fn write_temp_file(content: &str, suffix: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let tid = std::thread::current().id();
        let path =
            std::env::temp_dir().join(format!("u7s-client-util-{suffix}-{nanos}-{tid:?}.txt"));
        std::fs::write(&path, content).expect("write temp file");
        path
    }

    // ---------------------------------------------------------------------------
    // parse_kubeconfig — happy path
    // ---------------------------------------------------------------------------

    /// parse_kubeconfig must extract all four fields from a well-formed kubeconfig.
    /// This verifies the full read → base64-decode → PEM-parse pipeline that callers
    /// (controller-manager, scheduler) rely on at startup.
    #[test]
    fn parse_kubeconfig_happy_path() {
        let (ca_pem, cert_pem, key_pem) = make_test_certs();
        let yaml = make_kubeconfig_yaml("https://127.0.0.1:6443", &ca_pem, &cert_pem, &key_pem);
        let path = write_temp_file(&yaml, "happy");
        let creds =
            parse_kubeconfig(path.to_str().unwrap()).expect("parse_kubeconfig must succeed");
        assert_eq!(creds.server, "https://127.0.0.1:6443");
        // ca_cert and client_cert are non-empty DER blobs.
        assert!(!creds.ca_cert.is_empty(), "ca_cert DER must be non-empty");
        assert!(
            !creds.client_cert.is_empty(),
            "client_cert DER must be non-empty"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ---------------------------------------------------------------------------
    // parse_kubeconfig — error paths
    // ---------------------------------------------------------------------------

    /// A kubeconfig file that doesn't exist must return an error, not panic.
    #[test]
    fn parse_kubeconfig_missing_file_errors() {
        let result = parse_kubeconfig("/tmp/u7s-client-util-nonexistent-99999.yaml");
        assert!(
            result.is_err(),
            "missing file must return Err, not panic or Ok"
        );
        let msg = format!("{:#}", result.err().unwrap());
        assert!(
            msg.contains("reading kubeconfig"),
            "error must mention reading kubeconfig; got: {msg}"
        );
    }

    /// A kubeconfig missing the `server:` field must return a clear error.
    /// The field is required; silently using an empty URL would produce a
    /// confusing connection error at runtime instead of a startup failure.
    #[test]
    fn parse_kubeconfig_missing_server_errors() {
        let (ca_pem, cert_pem, key_pem) = make_test_certs();
        // Omit the server: field entirely.
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let yaml = format!(
            "certificate-authority-data: {}\nclient-certificate-data: {}\nclient-key-data: {}\n",
            b64.encode(ca_pem.as_bytes()),
            b64.encode(cert_pem.as_bytes()),
            b64.encode(key_pem.as_bytes()),
        );
        let path = write_temp_file(&yaml, "no-server");
        let result = parse_kubeconfig(path.to_str().unwrap());
        assert!(result.is_err(), "missing server must return Err");
        let msg = format!("{:#}", result.err().unwrap());
        assert!(
            msg.contains("missing server"),
            "error must mention missing server; got: {msg}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Bad base64 in certificate-authority-data must return an error describing
    /// the decode failure, not a panic or a silent empty cert.
    #[test]
    fn parse_kubeconfig_bad_base64_errors() {
        let yaml = "server: https://127.0.0.1:6443\n\
                    certificate-authority-data: !!!not-base64!!!\n\
                    client-certificate-data: aGVsbG8=\n\
                    client-key-data: aGVsbG8=\n";
        let path = write_temp_file(yaml, "bad-b64");
        let result = parse_kubeconfig(path.to_str().unwrap());
        assert!(result.is_err(), "bad base64 must return Err");
        let msg = format!("{:#}", result.err().unwrap());
        assert!(
            msg.contains("decode CA cert"),
            "error must mention decode CA cert; got: {msg}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Valid base64 that decodes to non-PEM bytes in client-key-data must return
    /// an error. The key field must be a PEM-encoded private key, not arbitrary bytes.
    #[test]
    fn parse_kubeconfig_bad_key_pem_errors() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let (ca_pem, cert_pem, _) = make_test_certs();
        // Use random bytes as the key — valid base64 but not a PEM key.
        let bad_key = b64.encode(b"this is not a pem private key");
        let yaml = format!(
            "server: https://127.0.0.1:6443\n\
             certificate-authority-data: {}\n\
             client-certificate-data: {}\n\
             client-key-data: {bad_key}\n",
            b64.encode(ca_pem.as_bytes()),
            b64.encode(cert_pem.as_bytes()),
        );
        let path = write_temp_file(&yaml, "bad-key");
        let result = parse_kubeconfig(path.to_str().unwrap());
        assert!(result.is_err(), "non-PEM key must return Err");
        let msg = format!("{:#}", result.err().unwrap());
        // Either "parse client key PEM" (parse error) or "no private key" (empty result).
        assert!(
            msg.contains("parse client key") || msg.contains("no private key"),
            "error must describe key failure; got: {msg}"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ---------------------------------------------------------------------------
    // build_tls_connector — happy path
    // ---------------------------------------------------------------------------

    /// build_tls_connector must succeed when given valid DER certs and a valid key.
    /// The TlsConnector is what controller-manager and scheduler use to open mTLS
    /// connections to the apiserver; a failure here is a hard startup crash.
    #[test]
    fn build_tls_connector_succeeds_with_valid_creds() {
        let (ca_pem, cert_pem, key_pem) = make_test_certs();
        let yaml = make_kubeconfig_yaml("https://127.0.0.1:6443", &ca_pem, &cert_pem, &key_pem);
        let path = write_temp_file(&yaml, "connector");
        let creds = parse_kubeconfig(path.to_str().unwrap()).expect("parse must succeed");
        let result = build_tls_connector(&creds);
        assert!(
            result.is_ok(),
            "build_tls_connector must succeed with valid creds; got: {:?}",
            result.err()
        );
        let _ = std::fs::remove_file(&path);
    }
}

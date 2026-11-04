//! `u7s-apiserver node-csr`: generates a node's client key and PKCS#10 CSR for
//! `CN=system:node:<name>, O=system:nodes`. `openssl req` caps CN at X.509's
//! ub-common-name (64), which would reject node names over 52 chars; upstream
//! kubelet builds the same CSR in Go with no such cap, so node names up to the
//! 253-char DNS subdomain limit must join.

use clap::Parser;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;

#[derive(Parser)]
pub struct NodeCsrArgs {
    #[arg(long)]
    node_name: String,
    /// Created with mode 0600.
    #[arg(long)]
    key_out: String,
    #[arg(long)]
    csr_out: String,
}

/// Returns `(private key PKCS#8 PEM, CSR PEM)`.
fn generate(node_name: &str) -> anyhow::Result<(String, String)> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::OrganizationName, "system:nodes");
    params
        .distinguished_name
        .push(DnType::CommonName, format!("system:node:{node_name}"));
    let csr = params.serialize_request(&key)?.pem()?;
    Ok((key.serialize_pem(), csr))
}

pub fn run(args: NodeCsrArgs) -> anyhow::Result<()> {
    let (key_pem, csr_pem) = generate(&args.node_name)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&args.key_out)?
        .write_all(key_pem.as_bytes())?;
    std::fs::write(&args.csr_out, csr_pem)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// Name lengths straddling every X.509 / openssl boundary: 52 (CN = 64), 53, 63 (DNS
    /// label max), 64, and 253 (DNS subdomain max, the longest valid node name).
    const LENGTHS: [usize; 5] = [52, 53, 63, 64, 253];

    fn node_name(len: usize) -> String {
        // 63-char labels joined by dots, like a GCP FQDN, then trimmed to `len`.
        let label = "a".repeat(63);
        let mut s = format!("{label}.{label}.{label}.{label}");
        s.truncate(len);
        if s.ends_with('.') {
            s.pop();
            s.push('a');
        }
        s
    }

    #[test]
    fn any_valid_node_name_yields_a_csr_the_apiserver_accepts_with_the_exact_identity() {
        for len in LENGTHS {
            let name = node_name(len);
            assert_eq!(name.len(), len);
            let (_, csr_pem) = generate(&name).unwrap();
            let req = crate::handlers::csr::parse_csr_pem(csr_pem.as_bytes())
                .unwrap_or_else(|e| panic!("{len}-char name: CSR unparsable: {e}"));
            crate::handlers::csr::check_csr_signature(&req)
                .unwrap_or_else(|e| panic!("{len}-char name: bad CSR signature: {e}"));

            let (mut cn, mut orgs) = (vec![], vec![]);
            for atv in req.info.subject.iter() {
                let v = crate::auth::atv_string(&atv.value).unwrap();
                match atv.oid.to_string().as_str() {
                    "2.5.4.3" => cn.push(v),
                    "2.5.4.10" => orgs.push(v),
                    other => panic!("unexpected subject attribute {other}"),
                }
            }
            assert_eq!(
                cn,
                [format!("system:node:{name}")],
                "{len}-char name: the CN must be the full node identity or the node authorizer \
                 and KCM's approver reject the node"
            );
            assert_eq!(orgs, ["system:nodes"], "{len}-char name");

            let body = serde_json::json!({
                "metadata": {"name": "join-x"},
                "spec": {
                    "request": base64::engine::general_purpose::STANDARD.encode(&csr_pem),
                    "signerName": "kubernetes.io/kube-apiserver-client-kubelet",
                    "usages": ["digital signature", "key encipherment", "client auth"],
                },
            });
            crate::handlers::csr::validate_csr_spec(&body)
                .unwrap_or_else(|_| panic!("{len}-char name: CSR create validation rejected it"));
            crate::handlers::csr::reject_system_masters_client_csr(&body).unwrap_or_else(|_| {
                panic!("{len}-char name: client-CSR subject check rejected it")
            });
        }
    }

    #[test]
    fn key_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("u7s-node-csr-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let args = || NodeCsrArgs {
            node_name: "n1".into(),
            key_out: dir.join("k.key").to_str().unwrap().into(),
            csr_out: dir.join("k.csr").to_str().unwrap().into(),
        };
        run(args()).unwrap();
        let mode = std::fs::metadata(dir.join("k.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "node identity key must not be group/world readable"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

use super::*;
use crate::pki::{ensure_signed_by, INTERMEDIATE_CA_LIFETIME};

fn plan_without_files(name: &'static str) -> LeafPlan {
    LeafPlan {
        name,
        common_name: "system:node:n1",
        organization: Some("system:nodes"),
        lifetime: Duration::from_secs(3600),
        usages: &["client auth"],
        sans: vec![],
        ca: CaKind::Cluster,
        files: None,
    }
}

const INTERMEDIATE_LIFE: Duration = Duration::from_secs(3000);
/// The intermediate is backdated by a twelfth of its life (250s) and due at 2/3 of its
/// window, so it falls due 1750s after the first boot.
const INTERMEDIATE_DUE_AFTER: i64 = 1751;

/// Boot `INTERMEDIATE_DUE_AFTER` seconds before the real clock so that advancing to the
/// rotation point lands on real "now", where rustls (which reads the real clock) accepts
/// what the rotation just issued.
fn start_before_intermediate_due(h: &Harness, admin: Duration) -> Rotator {
    h.advance(-INTERMEDIATE_DUE_AFTER);
    h.start_with_intermediate(admin, INTERMEDIATE_LIFE).unwrap()
}

#[tokio::test]
async fn client_without_its_intermediate_is_rejected_and_with_it_accepted() {
    let h = Harness::new("leaf-only");
    let r = h.start(CLIENT_CERT_LIFETIME).unwrap();
    let root = h.cluster_ca().cert_der;
    let admin = r.leaf("admin");
    assert!(
        admin.issuer_der.is_some(),
        "cluster leaves are signed by the intermediate, never by the root"
    );
    let leaf_only = Leaf {
        issuer_der: None,
        ..admin.clone()
    };
    let cfg = r.server_config();
    assert!(
        !server_accepts(cfg.get(), &connector(&root, Some(&leaf_only))).await,
        "a client that pins only the root and sends just its leaf cannot be verified: this is \
         why every client cert file and issued CSR certificate must carry the intermediate"
    );
    assert!(
        server_accepts(cfg.get(), &connector(&root, Some(&admin))).await,
        "the same leaf with its intermediate must authenticate"
    );
}

#[tokio::test]
async fn leaves_verify_to_the_root_only_through_the_intermediate() {
    let h = Harness::new("through-intermediate");
    let r = h.start(CLIENT_CERT_LIFETIME).unwrap();
    let root = h.cluster_ca().cert_der;
    let now = h.pki.clock.now();
    let admin = r.leaf("admin");
    assert!(leaf_cert_chain_validates_at(
        &admin.cert_der,
        &root,
        &[r.intermediate_der()],
        now
    ));
    assert!(
        !leaf_cert_chain_validates_at(&admin.cert_der, &root, &[], now),
        "without the intermediate the leaf must not verify: the root never signed it"
    );
    assert!(
        ensure_signed_by(&r.intermediate_der(), &root).is_ok(),
        "the root signs the intermediate"
    );
    assert!(
        ensure_signed_by(&admin.cert_der, &root).is_err(),
        "the root must sign only intermediates"
    );
}

#[tokio::test]
async fn after_intermediate_rotation_old_leaves_and_root_only_clients_keep_working() {
    let h = Harness::new("int-rotation");
    let r = start_before_intermediate_due(&h, CLIENT_CERT_LIFETIME);
    let root = h.cluster_ca().cert_der;
    let (old_int, old_admin) = (r.intermediate_der(), r.leaf("admin"));
    let notes = Mutex::new(Vec::new());
    let note = |n: &'static str, _: &Leaf| notes.lock().unwrap().push(n);

    r.rotate_due(&note).unwrap();
    assert!(
        !notes.lock().unwrap().contains(&INTERMEDIATE),
        "the intermediate must not rotate before 2/3 of its life"
    );
    assert_eq!(r.intermediate_der(), old_int);

    h.advance(INTERMEDIATE_DUE_AFTER);
    r.rotate_due(&note).unwrap();
    assert!(notes.lock().unwrap().contains(&INTERMEDIATE));
    let new_int = r.intermediate_der();
    assert_ne!(
        new_int, old_int,
        "the intermediate must be re-issued at 2/3 of its life"
    );

    let cfg = r.server_config();
    assert!(
        server_accepts(cfg.get(), &connector(&root, Some(&old_admin))).await,
        "a client cert issued before the rotation (chain: old intermediate) must still \
         authenticate, with no restart and no new trust distributed"
    );
    let new_admin = r.leaf("admin");
    assert_eq!(new_admin.issuer_der.as_deref(), Some(new_int.as_slice()));
    assert!(
        server_accepts(cfg.get(), &connector(&root, Some(&new_admin))).await,
        "a newly issued leaf must chain to the new intermediate"
    );
    let now = h.pki.clock.now();
    assert!(
        !leaf_cert_chain_validates_at(&new_admin.cert_der, &root, &[old_int], now),
        "new leaves must be signed by the new intermediate, not the retired one"
    );
    assert!(
        server_accepts(cfg.get(), &connector(&root, None)).await,
        "a kubeconfig pinning only the root must verify the serving cert after rotation"
    );
}

#[test]
fn leaves_signed_by_the_previous_intermediate_are_reissued_at_once_even_if_not_due() {
    let h = Harness::new("int-forces-leaves");
    let r = h
        .start_with_intermediate(Duration::from_secs(100), INTERMEDIATE_LIFE)
        .unwrap();
    // Admin is re-issued shortly before the intermediate falls due, so it is fresh when the
    // intermediate rotates.
    h.advance(1700);
    r.rotate_due(&|_, _| {}).unwrap();
    let before = r.leaf("admin");
    h.advance(INTERMEDIATE_DUE_AFTER - 1700);
    assert!(
        h.pki.clock.now() < before.not_before + time::Duration::seconds(66),
        "admin must not be due on its own, or the test proves nothing"
    );
    let notes = Mutex::new(Vec::new());
    r.rotate_due(&|n, _| notes.lock().unwrap().push(n)).unwrap();
    assert!(notes.lock().unwrap().contains(&INTERMEDIATE));
    let after = r.leaf("admin");
    assert_ne!(
        after.cert_der, before.cert_der,
        "a leaf that is not due must still be re-issued when its intermediate was replaced, \
         or the old intermediate can never be retired"
    );
    assert_eq!(
        after.issuer_der.as_deref(),
        Some(r.intermediate_der().as_slice())
    );
}

#[test]
fn restart_after_an_interrupted_rotation_reissues_leaves_of_the_previous_intermediate() {
    let h = Harness::new("int-resume");
    let first = h.start(CLIENT_CERT_LIFETIME).unwrap();
    let (old_int, old_admin) = (first.intermediate_der(), first.leaf("admin"));
    // The new intermediate reached disk but the leaves were not re-issued: simulate by
    // dropping the intermediate files while the admin pair signed by the old one stays.
    for f in [
        "intermediate.crt",
        "intermediate.key",
        "intermediate-cert.pem",
    ] {
        std::fs::remove_file(h.dir.join(f)).unwrap(); // lgtm[rust/path-injection]
    }
    let resumed = h.start(CLIENT_CERT_LIFETIME).unwrap();
    assert_ne!(resumed.intermediate_der(), old_int);
    let admin = resumed.leaf("admin");
    assert_ne!(
        admin.cert_der, old_admin.cert_der,
        "a persisted leaf signed by a previous intermediate must be replaced on resume, not \
         served with a chain that no longer matches the signing material"
    );
    assert_eq!(
        admin.issuer_der.as_deref(),
        Some(resumed.intermediate_der().as_slice())
    );
}

#[test]
fn intermediate_is_loaded_not_regenerated_across_restarts() {
    let h = Harness::new("int-stable");
    let first = h.start(CLIENT_CERT_LIFETIME).unwrap();
    let second = h.start(CLIENT_CERT_LIFETIME).unwrap();
    assert_eq!(
        first.intermediate_der(),
        second.intermediate_der(),
        "restarting must not mint a new intermediate: every restart would re-issue every leaf"
    );
    assert_eq!(first.leaf("admin").cert_der, second.leaf("admin").cert_der);
}

#[test]
fn partial_intermediate_state_is_refused_and_preserved() {
    for (keep, gone) in [
        ("intermediate.crt", "intermediate.key"),
        ("intermediate.key", "intermediate.crt"),
    ] {
        let h = Harness::new("int-partial");
        drop(h.start(CLIENT_CERT_LIFETIME).unwrap());
        std::fs::remove_file(h.dir.join(gone)).unwrap(); // lgtm[rust/path-injection]
        let kept = std::fs::read(h.dir.join(keep)).unwrap(); // lgtm[rust/path-injection]
        let err = h
            .start(CLIENT_CERT_LIFETIME)
            .err()
            .expect("one half of the intermediate pair must fail loudly")
            .to_string();
        assert!(err.contains("partial intermediate cert state"), "{err}");
        assert_eq!(
            std::fs::read(h.dir.join(keep)).unwrap(), // lgtm[rust/path-injection]
            kept,
            "the surviving file must be left untouched for the operator"
        );
        assert!(
            !h.dir.join(gone).exists(),
            "a half-present intermediate must never be silently re-minted"
        );
    }
}

#[test]
fn crash_between_intermediate_cert_and_key_rename_rolls_forward() {
    let h = Harness::new("int-crash");
    let r = h
        .start_with_intermediate(CLIENT_CERT_LIFETIME, INTERMEDIATE_LIFE)
        .unwrap();
    let (cert_path, key_path) = (
        h.dir.join("intermediate.crt"),
        h.dir.join("intermediate.key"),
    );
    let old_key = std::fs::read(&key_path).unwrap(); // lgtm[rust/path-injection]
    h.advance(INTERMEDIATE_DUE_AFTER);
    r.rotate_due(&|_, _| {}).unwrap();
    let (new_cert, new_key) = (
        std::fs::read(&cert_path).unwrap(), // lgtm[rust/path-injection]
        std::fs::read(&key_path).unwrap(),  // lgtm[rust/path-injection]
    );
    assert_eq!(
        new_cert,
        r.intermediate_der(),
        "what signs is what is on disk"
    );

    // Killed after the cert rename, before the key rename.
    std::fs::write(&key_path, &old_key).unwrap(); // lgtm[rust/path-injection]
    std::fs::write(h.dir.join("intermediate.key.tmp"), &new_key).unwrap(); // lgtm[rust/path-injection]
    let restarted = h
        .start_with_intermediate(CLIENT_CERT_LIFETIME, INTERMEDIATE_LIFE)
        .expect("a half-finished intermediate rotation must be loadable");
    assert_eq!(
        restarted.intermediate_der(),
        new_cert,
        "restart must finish the rotation, not mint a third intermediate"
    );
    assert_eq!(std::fs::read(&key_path).unwrap(), new_key); // lgtm[rust/path-injection]
}

#[test]
fn kcm_signing_files_hold_one_certificate_matching_the_key_and_follow_rotation() {
    use rustls::pki_types::pem::PemObject as _;
    let h = Harness::new("int-kcm-files");
    let r = h
        .start_with_intermediate(CLIENT_CERT_LIFETIME, INTERMEDIATE_LIFE)
        .unwrap();
    let published = |r: &Rotator| {
        let pem = std::fs::read(h.dir.join("intermediate-cert.pem")).unwrap(); // lgtm[rust/path-injection]
        let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
            .map(|c| c.unwrap().to_vec())
            .collect();
        assert_eq!(
            certs.len(),
            1,
            "kube-controller-manager refuses a --cluster-signing-cert-file with more than one \
             certificate, so signing stops entirely"
        );
        assert_eq!(certs[0], r.intermediate_der());
        let key = rcgen::KeyPair::from_pem(
            &std::fs::read_to_string(h.dir.join("intermediate.key")).unwrap(), // lgtm[rust/path-injection]
        )
        .unwrap();
        assert!(
            crate::tls::ca_key_matches_cert(&key, &certs[0]).is_ok(),
            "the signing cert and key KCM reloads must be a pair"
        );
    };
    published(&r);
    h.advance(INTERMEDIATE_DUE_AFTER);
    r.rotate_due(&|_, _| {}).unwrap();
    published(&r);
}

#[test]
fn failed_intermediate_rotation_keeps_the_old_one_and_is_visible_until_it_succeeds() {
    let h = Harness::new("int-failure");
    let r = h
        .start_with_intermediate(CLIENT_CERT_LIFETIME, INTERMEDIATE_LIFE)
        .unwrap();
    let old = r.intermediate_der();
    h.advance(INTERMEDIATE_DUE_AFTER);
    let moved = h.dir.with_extension("away");
    std::fs::rename(&h.dir, &moved).unwrap(); // lgtm[rust/path-injection]
    r.rotate_due(&|_, _| {}).unwrap_err();
    assert_eq!(
        r.intermediate_der(),
        old,
        "a rotation that could not be made durable must not switch the signer: KCM and the \
         apiserver would disagree after a restart"
    );
    assert!(
        h.pki
            .inventory
            .failures()
            .iter()
            .any(|(n, _)| *n == INTERMEDIATE),
        "the failure must reach the expiry Events and metric, not only the log"
    );
    std::fs::rename(&moved, &h.dir).unwrap(); // lgtm[rust/path-injection]
    r.rotate_due(&|_, _| {}).unwrap();
    assert_ne!(r.intermediate_der(), old);
    assert!(h.pki.inventory.failures().is_empty());
}

#[test]
fn intermediate_is_inventoried_and_may_only_sign_end_entities() {
    use x509_cert::der::Decode as _;
    use x509_cert::ext::pkix::BasicConstraints as Bc;
    let h = Harness::new("int-inventory");
    let r = h.start(CLIENT_CERT_LIFETIME).unwrap();
    let record = h
        .pki
        .inventory
        .snapshot()
        .into_iter()
        .find(|c| c.name == INTERMEDIATE)
        .expect("the visibility beads can only warn about a cert the inventory lists");
    assert_eq!(record.role, CertRole::Intermediate);
    assert_eq!(
        record.not_after - record.not_before,
        INTERMEDIATE_CA_LIFETIME
    );
    let cert = x509_cert::Certificate::from_der(&r.intermediate_der()).unwrap();
    let (_, bc) = cert
        .tbs_certificate()
        .get_extension::<Bc>()
        .unwrap()
        .unwrap();
    assert!(bc.ca);
    assert_eq!(
        bc.path_len_constraint,
        Some(0),
        "a leaked intermediate key must not be able to mint another CA"
    );
}

#[test]
fn intermediate_signed_by_a_different_root_is_replaced_not_trusted() {
    let h = Harness::new("int-foreign-root");
    let foreign = Rotator::new(
        h.pki.clone(),
        crate::pki::RENEW_FRACTION,
        h.other_ca(),
        h.other_ca(),
        h.intermediate_files(),
        INTERMEDIATE_CA_LIFETIME,
        h.plans(CLIENT_CERT_LIFETIME),
    )
    .unwrap();
    let r = h.start(CLIENT_CERT_LIFETIME).unwrap();
    assert_ne!(r.intermediate_der(), foreign.intermediate_der());
    assert!(
        ensure_signed_by(&r.intermediate_der(), &h.cluster_ca().cert_der).is_ok(),
        "the intermediate in use must chain to the root clients pin"
    );
}

#[tokio::test]
async fn kcm_signed_client_cert_carries_the_chain_and_authenticates() {
    use base64::Engine as _;
    use rustls::pki_types::pem::PemObject as _;
    let h = Harness::new("kcm-chain");
    let r = h.start(CLIENT_CERT_LIFETIME).unwrap();
    let root = h.cluster_ca().cert_der;
    // What kube-controller-manager signs: a bare leaf under the intermediate.
    let kubelet = issue_leaf(
        &h.pki,
        &r.ca_for(CaKind::Cluster),
        &plan_without_files("kubelet"),
    )
    .unwrap();
    let bare = Leaf {
        issuer_der: None,
        ..kubelet.clone()
    };
    let cfg = r.server_config();
    assert!(
        !server_accepts(cfg.get(), &connector(&root, Some(&bare))).await,
        "the bare KCM-issued leaf must not authenticate on its own"
    );

    let engine = base64::engine::general_purpose::STANDARD;
    let issued = engine.encode(crate::tls::pem_encode("CERTIFICATE", &kubelet.cert_der));
    let stored = crate::handlers::csr::append_signing_chain(&issued, &[r.intermediate_der()])
        .expect("the apiserver appends the signing intermediate to the issued certificate");
    let pem = engine.decode(stored).unwrap();
    let chain: Vec<Vec<u8>> = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
        .map(|c| c.unwrap().to_vec())
        .collect();
    let as_stored = Leaf {
        issuer_der: Some(chain[1].clone()),
        cert_der: chain[0].clone(),
        ..kubelet
    };
    assert!(
        server_accepts(cfg.get(), &connector(&root, Some(&as_stored))).await,
        "the certificate as stored in the CSR (leaf + intermediate), which the kubelet \
         presents verbatim, must authenticate against a root-only trust store"
    );
}

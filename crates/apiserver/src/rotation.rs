//! Re-issues every apiserver-owned leaf before it expires and publishes the new one with no
//! restart: persisted leaves are rewritten crash-safely, the serving cert and client-CA
//! trust are swapped into a fresh `ServerConfig`, and the caller is told what changed so it
//! can refresh whatever else holds the old identity in memory.
//!
//! The cluster CA is two-tier. The long-lived root (pinned by every client) signs only the
//! intermediate; the intermediate signs every cluster leaf and is itself re-issued at the
//! renewal fraction of its life. Leaves present the intermediate after themselves, so
//! clients that trust only the root keep verifying across an intermediate rotation.

use crate::pki::{
    cert_validity, ensure_ca_cert, ensure_signed_by, renew_at, CertRole, CertSpec, Pki, Signer,
    Swap,
};
use crate::tls::{
    build_server_config, intermediate_cert_pem_path, leaf_cert_chain_validates_at,
    load_persisted_leaf, pem_encode, persist_leaf, random_ca_suffix, replace_file, LeafFiles,
};
use rcgen::{Issuer, KeyPair, SanType};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;

type OnRotated = dyn Fn(&'static str, &Leaf) + Send + Sync;

pub(crate) const SERVING_LEAF: &str = "apiserver-serving";
/// Name under which a re-issued signing intermediate is reported to the rotation callback.
pub(crate) const INTERMEDIATE: &str = "intermediate";

/// Longest the rotation task sleeps before re-reading the clock, so a wall-clock jump
/// cannot delay a renewal by more than this.
const MAX_IDLE: Duration = Duration::from_secs(3600);
const MIN_IDLE: Duration = Duration::from_secs(1);
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaKind {
    Cluster,
    FrontProxy,
}

pub(crate) struct CaSigner {
    pub issuer: Issuer<'static, KeyPair>,
    pub cert_der: Vec<u8>,
    pub not_after: OffsetDateTime,
    /// The self-signed root this signer chains to; `cert_der` itself for a root.
    pub anchor_der: Vec<u8>,
}

impl CaSigner {
    /// The CA cert a leaf must present after itself; None when leaves chain straight to
    /// the anchor.
    fn presented_intermediate(&self) -> Option<&[u8]> {
        (self.anchor_der != self.cert_der).then_some(self.cert_der.as_slice())
    }
}

pub(crate) struct LeafPlan {
    pub name: &'static str,
    pub common_name: &'static str,
    pub organization: Option<&'static str>,
    pub lifetime: Duration,
    pub usages: &'static [&'static str],
    pub sans: Vec<SanType>,
    pub ca: CaKind,
    /// Where the leaf lives across restarts; None leaves are re-issued at every start.
    pub files: Option<LeafFiles>,
}

impl LeafPlan {
    pub(crate) fn spec(&self) -> CertSpec<'_> {
        CertSpec {
            name: self.name,
            common_name: self.common_name,
            organization: self.organization,
            role: CertRole::Leaf,
            lifetime: self.lifetime,
            usages: self.usages,
            sans: self.sans.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Leaf {
    pub cert_der: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
    /// The intermediate that signed this leaf, presented after it in every chain.
    pub issuer_der: Option<Vec<u8>>,
}

impl Leaf {
    fn from_parts(
        cert_der: Vec<u8>,
        key_pem: Vec<u8>,
        issuer_der: Option<Vec<u8>>,
    ) -> anyhow::Result<Self> {
        let (not_before, not_after) = cert_validity(&cert_der)?;
        Ok(Self {
            cert_der,
            key_pem,
            not_before,
            not_after,
            issuer_der,
        })
    }

    /// The leaf followed by its intermediate, as presented in a TLS handshake.
    pub(crate) fn chain_ders(&self) -> Vec<Vec<u8>> {
        std::iter::once(self.cert_der.clone())
            .chain(self.issuer_der.clone())
            .collect()
    }

    /// The leaf and its intermediate as PEM blocks.
    pub(crate) fn chain_pem(&self) -> Vec<u8> {
        self.chain_ders()
            .iter()
            .flat_map(|der| pem_encode("CERTIFICATE", der))
            .collect()
    }

    /// Chain and key in one PEM, what a client presents.
    pub(crate) fn identity_pem(&self) -> Vec<u8> {
        let mut pem = self.chain_pem();
        pem.extend_from_slice(&self.key_pem);
        pem
    }
}

struct State {
    leaves: HashMap<&'static str, Leaf>,
    client_cas: Vec<Vec<u8>>,
    /// The intermediate that signs cluster leaves.
    cluster_ca: Arc<CaSigner>,
}

pub struct Rotator {
    pki: Pki,
    fraction: f64,
    root_ca: CaSigner,
    front_proxy_ca: Arc<CaSigner>,
    intermediate_files: LeafFiles,
    intermediate_lifetime: Duration,
    plans: Vec<LeafPlan>,
    state: Mutex<State>,
    server_config: Swap<Arc<ServerConfig>>,
}

fn due_at(plan: &LeafPlan, leaf: &Leaf, fraction: f64) -> OffsetDateTime {
    renew_at(leaf.not_before, leaf.not_after, plan.lifetime, fraction)
}

fn intermediate_spec(common_name: &str, lifetime: Duration) -> CertSpec<'_> {
    CertSpec {
        name: INTERMEDIATE,
        common_name,
        organization: None,
        role: CertRole::Intermediate,
        lifetime,
        usages: &["cert sign"],
        sans: vec![],
    }
}

fn intermediate_due_at(cert_der: &[u8], lifetime: Duration, fraction: f64) -> OffsetDateTime {
    match cert_validity(cert_der) {
        Ok((not_before, not_after)) => renew_at(not_before, not_after, lifetime, fraction),
        Err(_) => OffsetDateTime::UNIX_EPOCH,
    }
}

fn common_name(cert_der: &[u8]) -> anyhow::Result<String> {
    crate::auth::extract_client_cert_identity(cert_der)
        .map(|id| id.username)
        .ok_or_else(|| anyhow::anyhow!("intermediate CA cert has no common name"))
}

/// Wrap an intermediate cert and key as a signer chained to `root`. The issuer name is read
/// back off the cert, never rebuilt, so leaves carry exactly the subject on disk.
fn intermediate_signer(
    pki: &Pki,
    root: &CaSigner,
    key: KeyPair,
    cert_der: Vec<u8>,
    lifetime: Duration,
) -> anyhow::Result<CaSigner> {
    let cn = common_name(&cert_der)?;
    let (not_before, not_after) = cert_validity(&cert_der)?;
    let params = pki.params(&intermediate_spec(&cn, lifetime), not_before, not_after);
    Ok(CaSigner {
        issuer: Issuer::new(params, key),
        cert_der,
        not_after,
        anchor_der: root.cert_der.clone(),
    })
}

/// Write the single-certificate PEM that kube-controller-manager reads as its signing cert.
/// Skipped when already current so a restart does not touch files KCM watches.
fn publish_intermediate_pem(files: &LeafFiles, cert_der: &[u8]) -> anyhow::Result<()> {
    let path = intermediate_cert_pem_path(files);
    let pem = pem_encode("CERTIFICATE", cert_der);
    if std::fs::read(&path).is_ok_and(|current| current == pem) {
        return Ok(());
    }
    replace_file(&path.to_string_lossy(), &pem, false)
}

/// Mint an intermediate under `root`, make it durable, then publish it for KCM. The
/// crt/key pair is written with the same crash-safe protocol as a leaf, so a crash at any
/// point restarts into either the previous intermediate or the complete new one.
fn issue_intermediate(
    pki: &Pki,
    root: &CaSigner,
    files: &LeafFiles,
    lifetime: Duration,
) -> anyhow::Result<CaSigner> {
    let cn = format!("u7s-intermediate-{}", random_ca_suffix());
    let issued = pki.issue(
        &intermediate_spec(&cn, lifetime),
        Some(&Signer {
            issuer: &root.issuer,
            not_after: root.not_after,
        }),
    )?;
    let cert_der = issued.cert.der().to_vec();
    persist_leaf(
        INTERMEDIATE,
        files,
        &cert_der,
        issued.key.serialize_pem().as_bytes(),
    )?;
    publish_intermediate_pem(files, &cert_der)?;
    intermediate_signer(pki, root, issued.key, cert_der, lifetime)
}

/// The persisted intermediate if it is signed by `root`, current, and not yet due; otherwise
/// a new one. Partial or mismatched files are an error, never a silent re-mint.
fn load_or_issue_intermediate(
    pki: &Pki,
    root: &CaSigner,
    files: &LeafFiles,
    lifetime: Duration,
    fraction: f64,
) -> anyhow::Result<CaSigner> {
    let now = pki.clock.now();
    let signed_by_root = |der: &[u8]| {
        ensure_ca_cert(der).is_ok()
            && ensure_signed_by(der, &root.cert_der).is_ok()
            && cert_validity(der).is_ok_and(|(nb, na)| nb <= now && now < na)
    };
    if let Some((cert_der, key_pem)) = load_persisted_leaf(INTERMEDIATE, files, &signed_by_root)? {
        if now < intermediate_due_at(&cert_der, lifetime, fraction) {
            let cn = common_name(&cert_der)?;
            pki.record_loaded(&intermediate_spec(&cn, lifetime), &cert_der)?;
            publish_intermediate_pem(files, &cert_der)?;
            let key = KeyPair::from_pem(&String::from_utf8_lossy(&key_pem))?;
            tracing::info!("loaded intermediate CA from {}", files.cert.display());
            return intermediate_signer(pki, root, key, cert_der, lifetime);
        }
        tracing::info!("intermediate CA loaded from disk is due for renewal; re-issuing");
    }
    issue_intermediate(pki, root, files, lifetime)
}

/// A persisted leaf on disk, if it is usable now, signed by the current CA, and not past its
/// renewal point.
fn load_leaf(
    pki: &Pki,
    ca: &CaSigner,
    plan: &LeafPlan,
    fraction: f64,
) -> anyhow::Result<Option<Leaf>> {
    let Some(files) = &plan.files else {
        return Ok(None);
    };
    let now = pki.clock.now();
    let issuer_der = ca.presented_intermediate().map(<[u8]>::to_vec);
    let intermediates: Vec<Vec<u8>> = issuer_der.iter().cloned().collect();
    let chains =
        |der: &[u8]| leaf_cert_chain_validates_at(der, &ca.anchor_der, &intermediates, now);
    let Some((cert_der, key_pem)) = load_persisted_leaf(plan.name, files, &chains)? else {
        return Ok(None);
    };
    let leaf = Leaf::from_parts(cert_der, key_pem, issuer_der)?;
    if now >= due_at(plan, &leaf, fraction) {
        tracing::info!(
            "{} loaded from disk is due for renewal (notAfter {}); re-issuing",
            plan.name,
            leaf.not_after
        );
        return Ok(None);
    }
    pki.record_loaded(&plan.spec(), &leaf.cert_der)?;
    tracing::info!("loaded {} from {}", plan.name, files.cert.display());
    Ok(Some(leaf))
}

/// Mint a fresh leaf and, for persisted ones, write it before it is used anywhere.
fn issue_leaf(pki: &Pki, ca: &CaSigner, plan: &LeafPlan) -> anyhow::Result<Leaf> {
    let issued = pki.issue(
        &plan.spec(),
        Some(&Signer {
            issuer: &ca.issuer,
            not_after: ca.not_after,
        }),
    )?;
    let leaf = Leaf::from_parts(
        issued.cert.der().to_vec(),
        issued.key.serialize_pem().into_bytes(),
        ca.presented_intermediate().map(<[u8]>::to_vec),
    )?;
    if let Some(files) = &plan.files {
        persist_leaf(plan.name, files, &leaf.cert_der, &leaf.key_pem)?;
    }
    Ok(leaf)
}

impl Rotator {
    /// Load the signing intermediate (issuing it under `root_ca` when absent, due or no
    /// longer signed by the root), then each persisted leaf that is still usable and not yet
    /// due; issue every other one. Refuses (rather than re-mints) on partial or mismatched
    /// persisted state.
    pub(crate) fn new(
        pki: Pki,
        fraction: f64,
        root_ca: CaSigner,
        front_proxy_ca: CaSigner,
        intermediate_files: LeafFiles,
        intermediate_lifetime: Duration,
        plans: Vec<LeafPlan>,
    ) -> anyhow::Result<Self> {
        let cluster_ca = Arc::new(load_or_issue_intermediate(
            &pki,
            &root_ca,
            &intermediate_files,
            intermediate_lifetime,
            fraction,
        )?);
        let front_proxy_ca = Arc::new(front_proxy_ca);
        let mut leaves = HashMap::new();
        for plan in &plans {
            let ca = match plan.ca {
                CaKind::Cluster => &cluster_ca,
                CaKind::FrontProxy => &front_proxy_ca,
            };
            let leaf = match load_leaf(&pki, ca, plan, fraction)? {
                Some(leaf) => leaf,
                None => issue_leaf(&pki, ca, plan)?,
            };
            leaves.insert(plan.name, leaf);
        }
        let client_cas = vec![root_ca.cert_der.clone()];
        let serving = leaves
            .get(SERVING_LEAF)
            .ok_or_else(|| anyhow::anyhow!("no {SERVING_LEAF} leaf planned"))?;
        let server_config = Swap::new(build_server_config(serving, &client_cas)?);
        Ok(Self {
            pki,
            fraction,
            root_ca,
            front_proxy_ca,
            intermediate_files,
            intermediate_lifetime,
            plans,
            state: Mutex::new(State {
                leaves,
                client_cas,
                cluster_ca,
            }),
            server_config,
        })
    }

    pub(crate) fn leaf(&self, name: &str) -> Leaf {
        self.lock().leaves[name].clone()
    }

    /// DER of the intermediate currently signing cluster leaves.
    pub(crate) fn intermediate_der(&self) -> Vec<u8> {
        self.lock().cluster_ca.cert_der.clone()
    }

    pub(crate) fn server_config(&self) -> Swap<Arc<ServerConfig>> {
        self.server_config.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn ca_for(&self, kind: CaKind) -> Arc<CaSigner> {
        match kind {
            CaKind::Cluster => Arc::clone(&self.lock().cluster_ca),
            CaKind::FrontProxy => Arc::clone(&self.front_proxy_ca),
        }
    }

    /// Replace the CAs that client certificates are verified against. Connections accepted
    /// from now on use the new store; open ones keep the one they were accepted with.
    pub(crate) fn set_client_cas(&self, client_cas: Vec<Vec<u8>>) -> anyhow::Result<()> {
        let mut state = self.lock();
        let config = build_server_config(&state.leaves[SERVING_LEAF], &client_cas)?;
        self.server_config.set(config);
        state.client_cas = client_cas;
        Ok(())
    }

    /// When the next leaf, or the intermediate, falls due.
    pub(crate) fn next_due(&self) -> OffsetDateTime {
        let state = self.lock();
        self.plans
            .iter()
            .map(|p| due_at(p, &state.leaves[p.name], self.fraction))
            .chain(std::iter::once(intermediate_due_at(
                &state.cluster_ca.cert_der,
                self.intermediate_lifetime,
                self.fraction,
            )))
            .min()
            .expect("at least the serving leaf is planned")
    }

    /// Replace the intermediate if it is past its renewal point. The new pair is durable and
    /// published for KCM before it signs anything here; the old one keeps verifying every
    /// leaf already issued because those leaves present it themselves.
    fn rotate_intermediate(&self, now: OffsetDateTime) -> anyhow::Result<Option<Leaf>> {
        let current = self.ca_for(CaKind::Cluster);
        if now < intermediate_due_at(&current.cert_der, self.intermediate_lifetime, self.fraction) {
            return Ok(None);
        }
        let next = issue_intermediate(
            &self.pki,
            &self.root_ca,
            &self.intermediate_files,
            self.intermediate_lifetime,
        )?;
        let notice = Leaf::from_parts(next.cert_der.clone(), Vec::new(), None)?;
        self.lock().cluster_ca = Arc::new(next);
        tracing::info!("rotated intermediate CA: new notAfter {}", notice.not_after);
        Ok(Some(notice))
    }

    /// Re-issue the intermediate and every leaf that is past its renewal point (or was signed
    /// by a previous intermediate) and publish it: the new leaf is durable (if persisted) and
    /// swapped in before `on_rotated` runs. A failure leaves that item's previous version live
    /// and is reported after the others were attempted.
    pub(crate) fn rotate_due(
        &self,
        on_rotated: &(dyn Fn(&'static str, &Leaf) + Send + Sync),
    ) -> anyhow::Result<()> {
        let now = self.pki.clock.now();
        let mut failures = Vec::new();
        match self.rotate_intermediate(now) {
            Ok(Some(notice)) => {
                self.pki.inventory.clear_failure(INTERMEDIATE);
                on_rotated(INTERMEDIATE, &notice);
            }
            Ok(None) => {}
            Err(e) => {
                self.pki
                    .inventory
                    .record_failure(INTERMEDIATE, format!("{e:#}"));
                failures.push(format!("{INTERMEDIATE}: {e:#}"));
            }
        }
        for plan in &self.plans {
            let ca = self.ca_for(plan.ca);
            let due = {
                let state = self.lock();
                let leaf = &state.leaves[plan.name];
                now >= due_at(plan, leaf, self.fraction)
                    || leaf.issuer_der.as_deref() != ca.presented_intermediate()
            };
            if !due {
                continue;
            }
            match issue_leaf(&self.pki, &ca, plan) {
                Ok(leaf) => {
                    {
                        let mut state = self.lock();
                        if plan.name == SERVING_LEAF {
                            match build_server_config(&leaf, &state.client_cas) {
                                Ok(config) => self.server_config.set(config),
                                Err(e) => {
                                    self.pki
                                        .inventory
                                        .record_failure(plan.name, format!("{e:#}"));
                                    failures.push(format!("{}: {e:#}", plan.name));
                                    continue;
                                }
                            }
                        }
                        state.leaves.insert(plan.name, leaf.clone());
                    }
                    tracing::info!("rotated {}: new notAfter {}", plan.name, leaf.not_after);
                    self.pki.inventory.clear_failure(plan.name);
                    on_rotated(plan.name, &leaf);
                }
                Err(e) => {
                    self.pki
                        .inventory
                        .record_failure(plan.name, format!("{e:#}"));
                    failures.push(format!("{}: {e:#}", plan.name));
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("certificate rotation failed for {}", failures.join("; "))
        }
    }

    /// Rotate leaves as they fall due, for the life of the process.
    pub(crate) async fn run(self: Arc<Self>, on_rotated: Arc<OnRotated>) {
        loop {
            let wait = (self.next_due() - self.pki.clock.now())
                .try_into()
                .unwrap_or(Duration::ZERO)
                .clamp(MIN_IDLE, MAX_IDLE);
            tokio::time::sleep(wait).await;
            let (me, cb) = (Arc::clone(&self), Arc::clone(&on_rotated));
            match tokio::task::spawn_blocking(move || me.rotate_due(&*cb)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::error!("{e:#}; retrying in {RETRY_AFTER_FAILURE:?}");
                    tokio::time::sleep(RETRY_AFTER_FAILURE).await;
                }
                Err(e) => {
                    tracing::error!("certificate rotation task panicked: {e}");
                    tokio::time::sleep(RETRY_AFTER_FAILURE).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;

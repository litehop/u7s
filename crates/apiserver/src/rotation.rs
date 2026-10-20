//! Re-issues every apiserver-owned leaf before it expires and publishes the new one with no
//! restart: persisted leaves are rewritten crash-safely, the serving cert and client-CA
//! trust are swapped into a fresh `ServerConfig`, and the caller is told what changed so it
//! can refresh whatever else holds the old identity in memory.

use crate::pki::{cert_validity, renew_at, CertRole, CertSpec, Pki, Signer, Swap};
use crate::tls::{build_server_config, load_persisted_leaf, persist_leaf, LeafFiles};
use rcgen::{Issuer, KeyPair, SanType};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;

type OnRotated = dyn Fn(&'static str, &Leaf) + Send + Sync;

pub(crate) const SERVING_LEAF: &str = "apiserver-serving";

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
}

impl Leaf {
    fn from_parts(cert_der: Vec<u8>, key_pem: Vec<u8>) -> anyhow::Result<Self> {
        let (not_before, not_after) = cert_validity(&cert_der)?;
        Ok(Self {
            cert_der,
            key_pem,
            not_before,
            not_after,
        })
    }
}

struct State {
    leaves: HashMap<&'static str, Leaf>,
    client_cas: Vec<Vec<u8>>,
}

pub struct Rotator {
    pki: Pki,
    fraction: f64,
    cluster_ca: CaSigner,
    front_proxy_ca: CaSigner,
    plans: Vec<LeafPlan>,
    state: Mutex<State>,
    server_config: Swap<Arc<ServerConfig>>,
}

fn ca_of<'a>(cluster: &'a CaSigner, front_proxy: &'a CaSigner, kind: CaKind) -> &'a CaSigner {
    match kind {
        CaKind::Cluster => cluster,
        CaKind::FrontProxy => front_proxy,
    }
}

fn due_at(plan: &LeafPlan, leaf: &Leaf, fraction: f64) -> OffsetDateTime {
    renew_at(leaf.not_before, leaf.not_after, plan.lifetime, fraction)
}

/// A persisted leaf on disk, if it is usable now and not past its renewal point.
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
    let Some((cert_der, key_pem)) = load_persisted_leaf(plan.name, files, &ca.cert_der, now)?
    else {
        return Ok(None);
    };
    let leaf = Leaf::from_parts(cert_der, key_pem)?;
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
    )?;
    if let Some(files) = &plan.files {
        persist_leaf(plan.name, files, &leaf.cert_der, &leaf.key_pem)?;
    }
    Ok(leaf)
}

impl Rotator {
    /// Load each persisted leaf that is still usable and not yet due, and issue every other
    /// one. Refuses (rather than re-mints) on partial or mismatched persisted state.
    pub(crate) fn new(
        pki: Pki,
        fraction: f64,
        cluster_ca: CaSigner,
        front_proxy_ca: CaSigner,
        plans: Vec<LeafPlan>,
    ) -> anyhow::Result<Self> {
        let mut leaves = HashMap::new();
        for plan in &plans {
            let ca = ca_of(&cluster_ca, &front_proxy_ca, plan.ca);
            let leaf = match load_leaf(&pki, ca, plan, fraction)? {
                Some(leaf) => leaf,
                None => issue_leaf(&pki, ca, plan)?,
            };
            leaves.insert(plan.name, leaf);
        }
        let client_cas = vec![cluster_ca.cert_der.clone()];
        let serving = leaves
            .get(SERVING_LEAF)
            .ok_or_else(|| anyhow::anyhow!("no {SERVING_LEAF} leaf planned"))?;
        let server_config = Swap::new(build_server_config(
            &serving.cert_der,
            &serving.key_pem,
            &client_cas,
        )?);
        Ok(Self {
            pki,
            fraction,
            cluster_ca,
            front_proxy_ca,
            plans,
            state: Mutex::new(State { leaves, client_cas }),
            server_config,
        })
    }

    pub(crate) fn leaf(&self, name: &str) -> Leaf {
        self.lock().leaves[name].clone()
    }

    pub(crate) fn server_config(&self) -> Swap<Arc<ServerConfig>> {
        self.server_config.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Replace the CAs that client certificates are verified against. Connections accepted
    /// from now on use the new store; open ones keep the one they were accepted with.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn set_client_cas(&self, client_cas: Vec<Vec<u8>>) -> anyhow::Result<()> {
        let mut state = self.lock();
        let serving = &state.leaves[SERVING_LEAF];
        let config = build_server_config(&serving.cert_der, &serving.key_pem, &client_cas)?;
        self.server_config.set(config);
        state.client_cas = client_cas;
        Ok(())
    }

    /// When the next leaf falls due.
    pub(crate) fn next_due(&self) -> OffsetDateTime {
        let state = self.lock();
        self.plans
            .iter()
            .map(|p| due_at(p, &state.leaves[p.name], self.fraction))
            .min()
            .expect("at least the serving leaf is planned")
    }

    /// Re-issue every leaf that is past its renewal point and publish it: the new leaf is
    /// durable (if persisted) and swapped in before `on_rotated` runs. A failure leaves that
    /// leaf's previous version live and is reported after the other leaves were attempted.
    pub(crate) fn rotate_due(
        &self,
        on_rotated: &(dyn Fn(&'static str, &Leaf) + Send + Sync),
    ) -> anyhow::Result<()> {
        let now = self.pki.clock.now();
        let mut failures = Vec::new();
        for plan in &self.plans {
            let due = {
                let state = self.lock();
                now >= due_at(plan, &state.leaves[plan.name], self.fraction)
            };
            if !due {
                continue;
            }
            match issue_leaf(
                &self.pki,
                ca_of(&self.cluster_ca, &self.front_proxy_ca, plan.ca),
                plan,
            ) {
                Ok(leaf) => {
                    {
                        let mut state = self.lock();
                        if plan.name == SERVING_LEAF {
                            match build_server_config(
                                &leaf.cert_der,
                                &leaf.key_pem,
                                &state.client_cas,
                            ) {
                                Ok(config) => self.server_config.set(config),
                                Err(e) => {
                                    failures.push(format!("{}: {e:#}", plan.name));
                                    continue;
                                }
                            }
                        }
                        state.leaves.insert(plan.name, leaf.clone());
                    }
                    tracing::info!("rotated {}: new notAfter {}", plan.name, leaf.not_after);
                    on_rotated(plan.name, &leaf);
                }
                Err(e) => failures.push(format!("{}: {e:#}", plan.name)),
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

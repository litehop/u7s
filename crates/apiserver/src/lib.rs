mod admission;
mod admissionreg_gen_adapter;
mod apf;
mod apiextensions_gen;
mod apiextensions_gen_adapter;
mod apiregistration_gen_adapter;
mod apps_gen;
mod apps_gen_adapter;
mod args;
mod auth;
mod autoscaling_gen_adapter;
mod batch_gen_adapter;
mod bootstrap_apply;
mod certificates_v1beta1_gen_adapter;
mod content_type;
mod coord_gen_adapter;
mod core_gen_adapter;
pub mod handlers;
mod inflight;
mod keys;
mod limit_range;
mod metrics;
mod net_disc_cert_policy_events_gen;
mod net_disc_cert_policy_events_gen_adapter;
mod patch;
mod proto;
#[cfg(test)]
mod proto_descriptor;
mod quota;
mod rbac;
mod rbac_gen_adapter;
mod resource_gen_adapter;
mod sa_sig_cache;
mod state;
mod status;
mod storage_node_flow_gen_adapter;
#[cfg(test)]
mod test_utils;
mod tls;
mod types;
mod util;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use socket2::{Domain, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tower_service::Service;
use u7s_store::SqliteStore;

pub use admission::{build_review, AdmissionContext, AdmissionReview};
pub use args::Args;
use auth::{AuthLayer, PeerCertificate};
use content_type::ContentTypeLayer;
use inflight::InflightLayer;
pub use metrics::record_request_total;
use state::AppState;
use tls::{generate_tls, load_or_generate_sa_keys, write_component_kubeconfig, write_kubeconfig};
pub use util::resolve_dhat_backtrace_depth;

/// Maximum request body size in bytes. Applied as the outermost layer so
/// unauthenticated requests are rejected before auth processing, preventing
/// OOM attacks via large unauthenticated bodies. 4 MiB gives headroom above
/// etcd's 1.5 MiB object limit while staying well below OOM risk.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Target soft `RLIMIT_NOFILE`. macOS defaults to a soft limit of 256, which
/// sustained load — one FD per persistent watch stream, per in-flight TLS
/// accept, per konnectivity tunnel — exceeds trivially; the resulting EMFILE
/// used to propagate via `?` straight out of `main()` with no graceful
/// degradation. Matches upstream kube-apiserver's systemd `LimitNOFILE`
/// convention (raised further there, but 65536 is ample headroom here).
const DESIRED_NOFILE_LIMIT: u64 = 65536;

/// Raises the process's own open-file-descriptor limit as far toward
/// [`DESIRED_NOFILE_LIMIT`] as the OS hard limit (and, on macOS,
/// `kern.maxfilesperproc`) allows. Makes the binary self-protecting under
/// sustained load even when launched outside `scripts/u7s-start.sh`, which
/// also raises the shell-level ulimit before exec'ing this binary. Best
/// effort: logs and continues on failure rather than refusing to start,
/// since a lower-than-desired limit only narrows headroom, it doesn't make
/// the server incorrect.
fn raise_fd_limit() {
    match rlimit::increase_nofile_limit(DESIRED_NOFILE_LIMIT) {
        Ok(limit) if limit < DESIRED_NOFILE_LIMIT => {
            tracing::warn!(
                "RLIMIT_NOFILE raised to only {limit} (wanted {DESIRED_NOFILE_LIMIT}) — \
                 capped by the OS hard limit; sustained load may still hit EMFILE"
            );
        }
        Ok(limit) => tracing::info!("RLIMIT_NOFILE raised to {limit}"),
        Err(e) => tracing::warn!(
            "failed to raise RLIMIT_NOFILE: {e} — process may hit EMFILE under sustained load"
        ),
    }
}

/// Requested TCP accept-queue depth. ~32x macOS's default `kern.ipc.somaxconn` clamp of
/// 128: on Linux (usually unclamped, or clamped much higher) this gives real headroom
/// under bursty conformance load; on macOS the kernel silently truncates it back to 128
/// regardless — [`backlog_clamp_warning`] is how that gets surfaced in logs instead of
/// hidden.
const LISTEN_BACKLOG: i32 = 4096;

/// Binds and listens on `addr` with an explicit [`LISTEN_BACKLOG`], instead of the OS
/// default `TcpListener::bind` would silently inherit (128 on stock macOS). A too-small
/// backlog means SYNs arriving faster than `accept()` drains the queue get dropped by the
/// kernel before user code ever sees them — invisible to the apiserver's own
/// request-completion logs, which is exactly what made the VIP-timeout family of
/// conformance failures hard to pin down.
fn bind_listener(addr: &str) -> anyhow::Result<TcpListener> {
    let addr: std::net::SocketAddr = addr.parse()?;
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(LISTEN_BACKLOG)?;
    tracing::info!("bound TCP listener on {addr} with backlog={LISTEN_BACKLOG}");
    if let Some(msg) = backlog_clamp_warning(LISTEN_BACKLOG, os_backlog_ceiling()) {
        tracing::warn!("{msg}");
    }
    Ok(TcpListener::from_std(socket.into())?)
}

/// Best-effort read of the OS's accept-queue ceiling (Linux: `/proc/sys/net/core/somaxconn`;
/// macOS: `kern.ipc.somaxconn`), so [`bind_listener`] can warn when it silently truncates
/// [`LISTEN_BACKLOG`]. `None` on read failure or an unrecognized platform — treated as
/// "can't tell", not as evidence there's no clamp, since this is purely observational.
fn os_backlog_ceiling() -> Option<i32> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/net/core/somaxconn")
            .ok()?
            .trim()
            .parse()
            .ok()
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("sysctl")
            .args(["-n", "kern.ipc.somaxconn"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8(output.stdout).ok()?.trim().parse().ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Pure decision logic behind [`bind_listener`]'s clamp warning, split out from the
/// `tracing::warn!` call so it's unit-testable without capturing log output. Returns
/// `Some(message)` naming both the requested and clamped values when the OS ceiling
/// truncated `requested`, so an operator reading logs doesn't have to re-derive which
/// number is which.
fn backlog_clamp_warning(requested: i32, ceiling: Option<i32>) -> Option<String> {
    let ceiling = ceiling?;
    (ceiling < requested).then(|| {
        format!(
            "requested TCP listen backlog {requested}, but OS ceiling (somaxconn) is only \
             {ceiling} — the kernel silently truncated it; raise somaxconn if sustained \
             connection bursts risk dropping SYNs before the apiserver ever sees them"
        )
    })
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    // 2. Init tracing. try_init() rather than init(): idempotent if a global subscriber is
    // already installed (e.g. this crate's own test_utils::tracing_capture, shared by several
    // tests in this binary) instead of panicking — the shipped main.rs binary only ever calls
    // run() once, so this never masks a real double-init bug in production.
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    // Raise the FD limit before opening the DB, generating TLS certs, or
    // binding the listener socket below — see raise_fd_limit's doc comment.
    raise_fd_limit();

    // 3. Compute advertised server address early — needed for endpoint seeding below.
    // Identical logic to step 8; kept here so seed_services gets the right IP before TLS init.
    let server_address_early = match args.advertise_address.as_deref() {
        Some(addr) => addr.to_owned(),
        None => {
            if args.listen.starts_with("0.0.0.0:") {
                let port = &args.listen["0.0.0.0:".len()..];
                format!("https://127.0.0.1:{port}")
            } else {
                format!("https://{}", args.listen)
            }
        }
    };
    // Parse "https://HOST:PORT" → (host, port). Fall back to defaults on malformed input.
    let (apiserver_ip, apiserver_port) = parse_advertise_address(&server_address_early);

    // Open store.
    let store = Arc::new(SqliteStore::new(&args.db)?);
    seed_namespaces(&store).await?;
    seed_rbac(&store).await?;
    seed_flowcontrol(&store).await?;
    seed_services(
        &store,
        &apiserver_ip,
        apiserver_port,
        &args.service_cluster_ip_range,
    )
    .await?;
    seed_serviceaccounts(&store).await?;
    seed_servicecidrs(&store, &args.service_cluster_ip_range).await?;

    // 4. Generate TLS certs.
    let tls_material = generate_tls(&args)?;

    // 4a. Seed kube-root-ca.crt into every namespace seeded above. Upstream, KCM's
    // root-ca-cert-publisher creates this ConfigMap asynchronously per-namespace; a pod
    // (e.g. the CI smoke pod in "default") can be admitted — with a hard dependency on
    // this ConfigMap via its auto-mounted SA token volume — before the publisher's first
    // reconcile. The kubelet then fails to mount the projected volume with "configmap
    // kube-root-ca.crt not found" and the pod hangs forever. Seeding it here, before the
    // server starts accepting requests, closes that race for every namespace that exists
    // at boot. KCM's publisher still POSTs its own copy later — that becomes a 409 which
    // the generic create-conflict path already handles.
    seed_kube_root_ca(&store, &tls_material.ca_cert_der).await?;

    // 5. Write kubeconfig.
    write_kubeconfig(&args.kubeconfig, &tls_material, &args)?;

    // 5a. Write dedicated kubeconfigs for KCM and the scheduler so each authenticates as
    // its own least-privilege x509 identity (system:kube-controller-manager /
    // system:kube-scheduler) instead of sharing the admin/system:masters kubeconfig above.
    // seed_rbac() already seeds a ClusterRole + ClusterRoleBinding for each name; nothing
    // authenticated as either identity before these files existed.
    let kcm_kubeconfig_path =
        std::path::Path::new(&args.kubeconfig).with_file_name("kcm-kubeconfig");
    write_component_kubeconfig(
        &kcm_kubeconfig_path.to_string_lossy(),
        &tls_material,
        &args,
        &tls_material.kcm_cert_der,
        &tls_material.kcm_key_pem,
        "system:kube-controller-manager",
    )?;
    // Named "kubeconfig-scheduler", not "scheduler-kubeconfig": several out-of-scope
    // scripts (run-all.sh, reset.sh, sample-run-metrics.sh) pkill/pgrep the scheduler
    // process by matching the literal substring "<workdir>/kubeconfig" in its argv. This
    // filename keeps that substring intact as a prefix so those scripts keep reaping the
    // scheduler correctly without needing their own changes.
    let scheduler_kubeconfig_path =
        std::path::Path::new(&args.kubeconfig).with_file_name("kubeconfig-scheduler");
    write_component_kubeconfig(
        &scheduler_kubeconfig_path.to_string_lossy(),
        &tls_material,
        &args,
        &tls_material.scheduler_cert_der,
        &tls_material.scheduler_key_pem,
        "system:kube-scheduler",
    )?;
    // No consumer yet: the in-process YAML applier that will use this identity to install
    // bootstrap manifest bundles (e.g. CoreDNS) against this apiserver is a later bead.
    // Written eagerly here (like kcm/scheduler above) so seed_rbac()'s ClusterRoleBinding
    // for this identity has a matching credential once the applier lands.
    let bootstrap_installer_kubeconfig_path =
        std::path::Path::new(&args.kubeconfig).with_file_name("bootstrap-installer-kubeconfig");
    write_component_kubeconfig(
        &bootstrap_installer_kubeconfig_path.to_string_lossy(),
        &tls_material,
        &args,
        &tls_material.bootstrap_installer_cert_der,
        &tls_material.bootstrap_installer_key_pem,
        "system:bootstrap-installer",
    )?;

    // 6. Load optional static token map.
    let token_map = match &args.token_auth_file {
        Some(path) => {
            tracing::info!("loading token auth file: {path}");
            auth::load_token_file(path)?
        }
        None => std::collections::HashMap::new(),
    };

    // 7. Load or generate the SA signing key.
    let (sa_encoding_key, sa_decoding_key, sa_public_key_pem) =
        match load_or_generate_sa_keys(&args.sa_key, &args.sa_pub) {
            Ok(sa_keys) => {
                let enc = jsonwebtoken::EncodingKey::from_rsa_pem(&sa_keys.private_key_pem)
                    .map_err(|e| {
                        tracing::error!("failed to load SA signing key: {e}");
                        e
                    })
                    .ok();
                let dec = jsonwebtoken::DecodingKey::from_rsa_pem(&sa_keys.public_key_pem)
                    .map_err(|e| {
                        tracing::error!("failed to load SA public key: {e}");
                        e
                    })
                    .ok();
                (enc, dec, Some(sa_keys.public_key_pem))
            }
            Err(e) => {
                tracing::error!("SA key gen/load failed: {e}");
                (None, None, None)
            }
        };

    // 8. Compute advertised server address.
    let server_address = match args.advertise_address {
        Some(addr) => addr,
        None => {
            // When listening on 0.0.0.0, default to loopback so local kubectl works.
            if args.listen.starts_with("0.0.0.0:") {
                let port = &args.listen["0.0.0.0:".len()..];
                format!("https://127.0.0.1:{port}")
            } else {
                format!("https://{}", args.listen)
            }
        }
    };
    tracing::info!("advertised server address: {server_address}");

    // 9. Build service IP allocator from the configured CIDR.
    let service_ip_allocator = if args.service_cluster_ip_range.is_empty() {
        tracing::info!(
            "service clusterIP auto-allocation disabled (empty --service-cluster-ip-range)"
        );
        None
    } else {
        match state::ServiceIpAllocator::from_cidr(&args.service_cluster_ip_range) {
            Ok(alloc) => {
                tracing::info!(
                    "service clusterIP auto-allocation enabled: {}",
                    args.service_cluster_ip_range
                );
                Some(alloc)
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "invalid --service-cluster-ip-range '{}': {e}",
                    args.service_cluster_ip_range
                ));
            }
        }
    };

    // 10. Build app state (shared with the auth layer).
    // Combine admin cert PEM + admin key PEM for the webhook mTLS client identity.
    // The webhook client will present this certificate when connecting to admission
    // webhook servers, so they can verify they are talking to the apiserver.
    let mut webhook_identity_pem = tls_material.admin_cert_pem.clone();
    webhook_identity_pem.extend_from_slice(&tls_material.admin_key_pem);
    // Combine kubelet client cert PEM + key PEM for the kubelet proxy client identity.
    // The apiserver presents this certificate when proxying log/exec/attach requests to
    // the kubelet. Kubelet accepts certs with O=system:masters signed by the cluster CA.
    let mut kubelet_client_identity_pem = tls_material.kubelet_client_cert_pem.clone();
    kubelet_client_identity_pem.extend_from_slice(&tls_material.kubelet_client_key_pem);
    // Combine proxy-client cert PEM + key PEM for the mTLS identity presented to
    // AGGREGATED BACKENDS (see `TlsMaterial::proxy_client_cert_pem`'s doc) — distinct from
    // webhook_identity_pem (the admin cert) above.
    let mut proxy_client_identity_pem = tls_material.proxy_client_cert_pem.clone();
    proxy_client_identity_pem.extend_from_slice(&tls_material.proxy_client_key_pem);
    let mut state = state::AppState::new_with_config(state::AppStateConfig {
        store: Arc::clone(&store),
        sa_key: sa_encoding_key,
        sa_decoding_key,
        token_map,
        server_address,
        cluster_ca_der: Some(tls_material.ca_cert_der.clone()),
        webhook_identity_pem: Some(webhook_identity_pem),
        service_ip_allocator,
        kubelet_client_identity_pem: Some(kubelet_client_identity_pem),
        kubelet_preferred_address: args.kubelet_preferred_address,
        kubelet_port: args.kubelet_port,
        continue_token_key: None, // fresh random key generated at startup
        konnectivity_proxy_addr: args.konnectivity_proxy_addr,
        sa_public_key_pem,
    });
    // Not part of AppStateConfig: see the field's own doc — mirrors node_kubelet_ports below.
    state.proxy_client_identity_pem = Some(Arc::new(proxy_client_identity_pem));
    state.node_kubelet_ports = parse_node_kubelet_ports(&args.node_kubelet_port)?;
    // Not ready until the boot-time manifest-apply task (12a below) resolves successfully —
    // see the field's own doc. Overwrites new_with_config's ready-by-default value.
    state.boot_ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Resolve the SA-JWT signature-verify cache capacity: --sa-sig-cache-size, then
    // U7S_SA_SIG_CACHE_SIZE, then the default. Overwrites the AppStateConfig-default cache
    // AppState::new_with_config already built — see sa_sig_cache field's doc for why this
    // isn't threaded through AppStateConfig like most other fields.
    let sa_sig_cache_capacity = args.sa_sig_cache_size.unwrap_or_else(|| {
        std::env::var("U7S_SA_SIG_CACHE_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(sa_sig_cache::DEFAULT_CAPACITY)
    });
    state.sa_sig_cache = Arc::new(sa_sig_cache::SigCache::new_with_capacity(
        sa_sig_cache_capacity,
    ));

    // 10a. Populate RBAC index from persisted objects before serving.
    state.init().await;

    // 10b. Seed service IP hint from already-allocated sentinels in the store.
    state.init_service_ip_hint().await;

    // 10c-pre. Populate admission config cache from persisted objects before serving.
    // This ensures the first admission check after startup reads from cache, not the store.
    state.init_admission_cache().await;

    // 10c-pre2. Populate the APIService cache from persisted objects before serving, so the
    // first /apis/{group}/{version}/... request and the first plain GET /apis after startup
    // read from cache instead of falling back to the store.
    state.init_apiservice_cache().await;

    // 10c-pre3. Populate the FlowSchema/PriorityLevelConfiguration cache from the objects
    // seed_flowcontrol just wrote, so AuthLayer's APF classification has FlowSchemas/
    // PriorityLevelConfigurations to match against from the very first request.
    state.init_flowcontrol_cache().await;

    // 10c. Keep the kubernetes Endpoints in sync with the kubernetes EndpointSlice.
    // KCM's endpointslice-controller may update the EndpointSlice with the apiserver
    // address from its own kubeconfig (e.g. a Lima VM gateway IP), which differs from
    // the loopback address in the Endpoints. This reconciler updates the Endpoints to
    // match, so Endpoints.subsets[*].addresses[*].ip always equals EndpointSlice.addresses.
    let (_reconciler_shutdown_tx, mut reconciler_shutdown_rx) = tokio::sync::watch::channel(false);
    {
        let reconcile_store = Arc::clone(&store);
        tokio::spawn(async move {
            let mut consecutive_errors: u32 = 0;
            loop {
                let ok = reconcile_kubernetes_endpointslice(&reconcile_store).await;
                if ok {
                    consecutive_errors = 0;
                } else {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                }
                // Exponential backoff: 5s, 10s, 20s, 40s, 80s, 160s, capped at 300s.
                let delay_secs = (5u64 << consecutive_errors.min(6)).min(300);
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(delay_secs)) => {}
                    _ = reconciler_shutdown_rx.changed() => break,
                }
            }
        });
    }

    // 10d. Keep ResourceQuota status.used in sync with live object counts.
    let (_quota_reconciler_shutdown_tx, mut quota_reconciler_shutdown_rx) =
        tokio::sync::watch::channel(false);
    {
        let reconcile_store = Arc::clone(&store);
        tokio::spawn(async move {
            let mut consecutive_errors: u32 = 0;
            loop {
                let ok = reconcile_quota_status(&reconcile_store).await;
                if ok {
                    consecutive_errors = 0;
                } else {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                }
                let delay_secs = if consecutive_errors == 0 {
                    30
                } else {
                    (5u64 << consecutive_errors.min(6)).min(300)
                };
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(delay_secs)) => {}
                    _ = quota_reconciler_shutdown_rx.changed() => break,
                }
            }
        });
    }

    // 10e. Health-check every registered APIService's backend and keep
    // status.conditions[type=Available] up to date (see handlers::aggregation for why this
    // is a fixed-interval sweep rather than a full informer-driven controller).
    let (_apiservice_reconciler_shutdown_tx, mut apiservice_reconciler_shutdown_rx) =
        tokio::sync::watch::channel(false);
    {
        let reconcile_state = state.clone();
        tokio::spawn(async move {
            loop {
                handlers::aggregation::reconcile_apiservice_availability(&reconcile_state).await;
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
                    _ = apiservice_reconciler_shutdown_rx.changed() => break,
                }
            }
        });
    }

    // 10f. Publish/reconcile kube-system/extension-apiserver-authentication for aggregated
    // backends (see reconcile_extension_apiserver_authentication's doc for why this is a
    // polling loop rather than a one-shot seed).
    let (_authinfo_reconciler_shutdown_tx, mut authinfo_reconciler_shutdown_rx) =
        tokio::sync::watch::channel(false);
    {
        let reconcile_store = Arc::clone(&store);
        let ca_cert_path = args.ca_cert.clone();
        let proxy_client_ca_cert_path = args.proxy_client_ca_cert.clone();
        tokio::spawn(async move {
            let mut consecutive_errors: u32 = 0;
            loop {
                let ok = reconcile_extension_apiserver_authentication(
                    &reconcile_store,
                    &ca_cert_path,
                    &proxy_client_ca_cert_path,
                )
                .await;
                if ok {
                    consecutive_errors = 0;
                } else {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                }
                let delay_secs = if consecutive_errors == 0 {
                    10
                } else {
                    (5u64 << consecutive_errors.min(6)).min(300)
                };
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(delay_secs)) => {}
                    _ = authinfo_reconciler_shutdown_rx.changed() => break,
                }
            }
        });
    }

    // 10g. Periodically sweep WatchLimitState for client identities with no watch stream
    // currently open (see `WatchLimitState::sweep_idle`'s doc for why a periodic sweep,
    // not an event hook, is the only fit here — unlike QuotaAdmissionLocks, a client
    // identity has no clean per-identity deletion event). 5 minutes: this is memory
    // hygiene, not a live correctness constraint, so a slow cadence is fine.
    let (_watch_limit_sweep_shutdown_tx, mut watch_limit_sweep_shutdown_rx) =
        tokio::sync::watch::channel(false);
    {
        let watch_limit = state.watch_limit.clone();
        tokio::spawn(async move {
            loop {
                watch_limit.sweep_idle();
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {}
                    _ = watch_limit_sweep_shutdown_rx.changed() => break,
                }
            }
        });
    }

    // 11. Build axum router and attach tower layers.
    //     Order (outermost first): body_limit → inflight → auth → content_type → handler.
    //     DefaultBodyLimit must be outermost so unauthenticated requests are rejected before
    //     auth processing — this prevents OOM via large unauthenticated request bodies.
    //     4 MiB matches etcd's practical limit (~1.5 MiB) with headroom for kubectl manifests.
    let app = build_router(state.clone())
        .layer(ContentTypeLayer)
        .layer(AuthLayer::new(
            Arc::clone(&state.rbac_index),
            (*state.token_map).clone(),
            state.sa_decoding_key.clone(),
            Arc::clone(&state.store),
            Arc::clone(&state.sa_sig_cache),
            Arc::clone(&state.flowcontrol_cache),
        ))
        .layer(InflightLayer::new())
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES));

    // 12. Bind TLS listener and serve. Uses bind_listener (socket2) rather than
    //     TcpListener::bind so we can set an explicit accept-queue backlog — see
    //     LISTEN_BACKLOG's doc comment for why the OS default isn't enough headroom.
    let listener = bind_listener(&args.listen)?;

    // 12a. Kick off the in-process bootstrap YAML applier now that the listen socket is bound,
    // authenticating as system:bootstrap-installer (mayor-1pwxi): SSA-apply every manifest under
    // args.manifest_dir (default `/etc/u7s/manifests`, see
    // `docs/decisions/well-known-manifest-folder.md`) — including the vendored CoreDNS manifest
    // (mayor-fiq79), which ships as a real file there like any other vendored or
    // operator-supplied manifest, no bespoke code path. A bad manifest here is fatal — an
    // operator who dropped a broken manifest needs the apiserver to refuse to start, not run
    // half-configured — so its result is threaded back via well_known_manifest_rx and raced
    // against serve_tls below instead of being discarded. On success it also flips
    // `state.boot_ready` so `/healthz` starts reporting 200 (see the field's doc) — on failure
    // it stays `false` forever, since the `tokio::select!` below tears the process down anyway.
    // This fatal-at-boot behavior is unchanged by the SIGHUP-triggered reload spawned right
    // below, which reuses the same manifest directory but with log-and-skip semantics instead
    // (mayor-bh36n).
    let (well_known_manifest_tx, well_known_manifest_rx) = tokio::sync::oneshot::channel();
    let well_known_manifest_dir = args.manifest_dir.clone();
    let boot_ready = Arc::clone(&state.boot_ready);
    let reload_kubeconfig_path = bootstrap_installer_kubeconfig_path.clone();
    let reload_manifest_dir = well_known_manifest_dir.clone();
    tokio::spawn(async move {
        let result = bootstrap_apply::apply_well_known_manifest_dir(
            &bootstrap_installer_kubeconfig_path,
            std::path::Path::new(&well_known_manifest_dir),
        )
        .await;
        record_manifest_apply_outcome(&boot_ready, &result);
        let _ = well_known_manifest_tx.send(result);
    });

    // 12b. SIGHUP triggers a re-scan of the same well-known manifest directory in this same
    // process — no restart, no dropped connections — mirroring the universal `kill -HUP`
    // reload convention (nginx, sshd, systemd's own daemon-reload). `scripts/install.sh` wires
    // `ExecReload=/bin/kill -HUP $MAINPID` into u7s-apiserver.service so `systemctl reload
    // u7s-apiserver` delivers this signal. Runs as its own long-lived task, entirely
    // independent of the boot-time select! below: a SIGHUP never touches the listener or any
    // in-flight request, it only re-invokes the same apply routine boot used. Unlike that
    // boot-time apply, a bad manifest hit during a SIGHUP reload is logged and skipped rather
    // than fatal (bootstrap_apply::reload_well_known_manifest_dir — operator decision on
    // mayor-bh36n, 2026-08-26) — crashing an already-serving apiserver over a bad manifest edit
    // is a far bigger blast radius than at cold boot, where fatal-and-refuse-to-start remains
    // correct. Because `kill -HUP` reports success to systemd the moment the signal is
    // delivered, regardless of what this async re-scan finds, reload failure is visible only
    // through apiserver's own logs (`journalctl -u u7s-apiserver`) — never through systemctl's
    // reload exit status.
    tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(sighup) => sighup,
            Err(e) => {
                tracing::error!(
                    "failed to install SIGHUP handler: {e:#} — \
                         'systemctl reload u7s-apiserver' will not work"
                );
                return;
            }
        };
        while sighup.recv().await.is_some() {
            tracing::info!(
                "SIGHUP received; re-applying well-known manifest directory {reload_manifest_dir}"
            );
            bootstrap_apply::reload_well_known_manifest_dir(
                &reload_kubeconfig_path,
                std::path::Path::new(&reload_manifest_dir),
            )
            .await;
        }
    });

    tokio::select! {
        result = serve_tls(listener, app, tls_material.server_config) => result?,
        Ok(Err(e)) = well_known_manifest_rx => {
            tracing::error!(
                "fatal: boot-time apply of {} failed: {e:#}",
                args.manifest_dir
            );
            return Err(e);
        }
    }
    Ok(())
}

/// Flips `boot_ready` to ready only when the boot-time manifest apply actually succeeded.
/// Pulled out of the `tokio::spawn`ed task above so the "only success marks ready" rule is
/// testable without spinning up a real boot sequence — see `record_manifest_apply_outcome_*`
/// tests below.
fn record_manifest_apply_outcome(
    boot_ready: &std::sync::atomic::AtomicBool,
    result: &anyhow::Result<()>,
) {
    if result.is_ok() {
        boot_ready.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// Reports the apiserver's own listener as up, but only once the boot-time bootstrap manifest
/// apply (`state.boot_ready`, see its doc) has resolved successfully. Before that, requests
/// return 503 rather than 200 — the previous behavior of always answering "ok" here is exactly
/// what forced `scripts/install.sh`'s `wait_for_apiserver` to bolt on a fixed sleep-and-recheck
/// to guess whether the manifest apply had finished; gating the response itself instead makes
/// the first 200 a deterministic "boot is fully done" signal, so that heuristic is no longer
/// needed.
async fn healthz(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    if state.boot_ready.load(std::sync::atomic::Ordering::Acquire) {
        (StatusCode::OK, "ok").into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "boot-time manifest apply in progress",
        )
            .into_response()
    }
}

fn build_router(state: AppState) -> Router {
    Router::new()
        // Health endpoints — no auth required; kube-controller-manager polls these
        // before declaring the apiserver ready. Listed in is_exempt() in auth.rs.
        // /healthz alone gates on boot_ready (see healthz's doc) — /livez and /readyz stay
        // unconditional "ok" so a slow boot-time manifest apply can't trip a liveness-probe
        // restart loop.
        .route("/healthz", get(healthz))
        .route("/livez", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ok" }))
        // Prometheus text-exposition metrics — RBAC-gated like every other route (NOT listed
        // in auth::is_exempt), matching upstream kube-apiserver where /metrics requires the
        // same bearer-token auth as any other endpoint. The bootstrap system:monitoring
        // ClusterRole already grants nonResourceURLs access to it.
        .route("/metrics", get(handlers::metrics::metrics))
        // Server version — no auth required (sonobuoy, kubectl version)
        .route("/version", get(handlers::discovery::version))
        // OIDC SA issuer discovery — RBAC-gated via system:service-account-issuer-discovery ClusterRole
        .route(
            "/.well-known/openid-configuration",
            get(handlers::oidc::openid_configuration),
        )
        .route("/openid/v1/jwks", get(handlers::oidc::jwks))
        // OpenAPI stubs — clients like Argo CD and kubectl call these on startup
        .route("/openapi/v2", get(handlers::discovery::openapi_v2))
        .route("/openapi/v3", get(handlers::discovery::openapi_v3))
        .route(
            "/openapi/v3/api/v1",
            get(handlers::discovery::openapi_v3_core),
        )
        .route(
            "/openapi/v3/apis/{group}/{version}",
            get(handlers::discovery::openapi_v3_group),
        )
        // Core discovery
        .route("/api", get(handlers::discovery::api_versions))
        // Upstream e2e clients (Discovery, kubectl proxy) call AbsPath('/api/') with a
        // literal trailing slash; without this sibling route they 404.
        .route("/api/", get(handlers::discovery::api_versions))
        .route("/api/v1", get(handlers::discovery::api_v1_resources))
        // AggregatedDiscovery (k8s 1.27+ GA) — returns APIGroupDiscoveryList
        // Serves both the dedicated endpoint and the Accept-header-based negotiation on /apis.
        .route(
            "/discovery/v2",
            get(handlers::discovery::aggregated_discovery_v2),
        )
        // Non-core group discovery
        .route("/apis", get(handlers::discovery::api_group_list))
        // Upstream e2e clients (Discovery, kubectl proxy) call AbsPath('/apis/') and
        // AbsPath('/apis/{group}/') with a literal trailing slash; without these
        // sibling routes they 404.
        .route("/apis/", get(handlers::discovery::api_group_list))
        .route("/apis/{group}", get(handlers::discovery::api_group))
        .route("/apis/{group}/", get(handlers::discovery::api_group))
        .route(
            "/apis/{group}/{version}",
            get(handlers::discovery::api_group_resources),
        )
        // Namespaces — collection
        .route(
            "/api/v1/namespaces",
            get(handlers::namespaces::list_namespaces).post(handlers::namespaces::create_namespace),
        )
        // Namespaces — finalize subresource (must be before the named-resource catch-all)
        // The KCM namespace controller calls PUT /api/v1/namespaces/{name}/finalize after
        // draining resources to remove the "kubernetes" finalizer. Without this route the
        // request hits 404 and the namespace stays stuck in Terminating forever.
        .route(
            "/api/v1/namespaces/{name}/finalize",
            axum::routing::put(handlers::namespaces::finalize_namespace),
        )
        // Namespaces — status subresource (must be before named-resource catch-all)
        // The KCM namespace controller PATCHes this to set status.conditions (e.g.
        // NamespaceDeletionContentFailure) during namespace deletion. Without it the
        // condition never gets set and conformance test OrderedNamespaceDeletion times out.
        .route(
            "/api/v1/namespaces/{name}/status",
            get(handlers::namespaces::get_namespace_status)
                .put(handlers::namespaces::put_namespace_status)
                .patch(handlers::namespaces::patch_namespace_status),
        )
        // Namespaces — named resource
        .route(
            "/api/v1/namespaces/{name}",
            get(handlers::namespaces::get_namespace)
                .put(handlers::namespaces::replace_namespace)
                .patch(handlers::namespaces::patch_namespace)
                .delete(handlers::namespaces::delete_namespace),
        )
        // Pods — collection
        .route(
            "/api/v1/namespaces/{ns}/pods",
            get(handlers::pods::list_pods)
                .post(handlers::pods::create_pod)
                .delete(handlers::pods::delete_collection_pods),
        )
        // Pods — named resource
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}",
            get(handlers::pods::get_pod)
                .put(handlers::pods::replace_pod)
                .delete(handlers::pods::delete_pod)
                .patch(handlers::pods::patch_pod),
        )
        // Pods — binding subresource (scheduler write path)
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/binding",
            axum::routing::post(handlers::pods::bind_pod),
        )
        // Pods — eviction subresource: graceful deletion via the Eviction API
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/eviction",
            axum::routing::post(handlers::pods::evict_pod),
        )
        // Pods — status subresource
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/status",
            get(handlers::pods::get_pod_status)
                .put(handlers::pods::replace_pod_status)
                .patch(handlers::pods::patch_pod_status),
        )
        // Pods — resize subresource (in-place resource update, GA k8s 1.33+)
        // Must be before the generic catch-all so axum doesn't interpret "resize" as a pod name.
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/resize",
            axum::routing::get(handlers::pods::get_pod_resize)
                .patch(handlers::pods::patch_pod_resize)
                .put(handlers::pods::patch_pod_resize),
        )
        // Pods — ephemeralcontainers subresource (GA since k8s 1.25)
        // Must be before the generic catch-all.
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/ephemeralcontainers",
            get(handlers::pods::get_ephemeral_containers)
                .patch(handlers::pods::patch_ephemeral_containers)
                .put(handlers::pods::put_ephemeral_containers),
        )
        // Pods — log subresource (kubelet proxy): must be before generic catch-all
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/log",
            get(handlers::proxy::pod_log),
        )
        // Pods — exec/attach/portforward: 501 stubs until SPDY/WebSocket is implemented.
        //
        // exec/attach's POST legs run the same pre-upgrade checks (pod lookup +
        // admission) as their GET/WebSocket siblings before returning 501 — see
        // pod_exec_post/pod_attach_post: a denied GET/WebSocket dial is retried by
        // client-go as POST/SPDY, and that retry must surface the same denial Status
        // instead of a generic 405.
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/exec",
            get(handlers::proxy::pod_exec).post(handlers::proxy::pod_exec_post),
        )
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/attach",
            get(handlers::proxy::pod_attach).post(handlers::proxy::pod_attach_post),
        )
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/portforward",
            get(handlers::proxy::pod_portforward).post(handlers::proxy::pod_portforward),
        )
        // Pods — proxy subresource: forward to pod IP at http://{podIP}:{containerPort}/{path}
        //
        // axum's `{*path}` wildcard requires a NON-EMPTY trailing segment. A dial to
        // /proxy or /proxy/ (the root form used by the RC serve-image conformance test)
        // does not match `/{*path}` and falls through to 404. Register the no-subpath
        // forms explicitly before the wildcard route.
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/proxy",
            get(handlers::proxy::pod_proxy_root)
                .post(handlers::proxy::pod_proxy_root)
                .put(handlers::proxy::pod_proxy_root)
                .delete(handlers::proxy::pod_proxy_root)
                .patch(handlers::proxy::pod_proxy_root)
                .options(handlers::proxy::pod_proxy_root)
                .head(handlers::proxy::pod_proxy_root),
        )
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/proxy/",
            get(handlers::proxy::pod_proxy_root)
                .post(handlers::proxy::pod_proxy_root)
                .put(handlers::proxy::pod_proxy_root)
                .delete(handlers::proxy::pod_proxy_root)
                .patch(handlers::proxy::pod_proxy_root)
                .options(handlers::proxy::pod_proxy_root)
                .head(handlers::proxy::pod_proxy_root),
        )
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/proxy/{*path}",
            get(handlers::proxy::pod_proxy)
                .post(handlers::proxy::pod_proxy)
                .put(handlers::proxy::pod_proxy)
                .delete(handlers::proxy::pod_proxy)
                .patch(handlers::proxy::pod_proxy)
                .options(handlers::proxy::pod_proxy)
                .head(handlers::proxy::pod_proxy),
        )
        // Nodes — proxy subresource: forward to kubelet at https://<node-ip>:10250/<path>
        .route(
            "/api/v1/nodes/{name}/proxy/{*path}",
            get(handlers::proxy::node_proxy)
                .post(handlers::proxy::node_proxy)
                .put(handlers::proxy::node_proxy)
                .delete(handlers::proxy::node_proxy)
                .patch(handlers::proxy::node_proxy)
                .options(handlers::proxy::node_proxy)
                .head(handlers::proxy::node_proxy),
        )
        // Services — proxy subresource: forward to a ready endpoint backing the Service.
        // axum's `{*path}` wildcard requires a NON-EMPTY segment. Register the no-subpath
        // forms before the wildcard route so /proxy and /proxy/ reach the root handler.
        .route(
            "/api/v1/namespaces/{ns}/services/{name}/proxy",
            get(handlers::proxy::service_proxy_root)
                .post(handlers::proxy::service_proxy_root)
                .put(handlers::proxy::service_proxy_root)
                .delete(handlers::proxy::service_proxy_root)
                .patch(handlers::proxy::service_proxy_root)
                .options(handlers::proxy::service_proxy_root)
                .head(handlers::proxy::service_proxy_root),
        )
        .route(
            "/api/v1/namespaces/{ns}/services/{name}/proxy/",
            get(handlers::proxy::service_proxy_root)
                .post(handlers::proxy::service_proxy_root)
                .put(handlers::proxy::service_proxy_root)
                .delete(handlers::proxy::service_proxy_root)
                .patch(handlers::proxy::service_proxy_root)
                .options(handlers::proxy::service_proxy_root)
                .head(handlers::proxy::service_proxy_root),
        )
        .route(
            "/api/v1/namespaces/{ns}/services/{name}/proxy/{*path}",
            get(handlers::proxy::service_proxy)
                .post(handlers::proxy::service_proxy)
                .put(handlers::proxy::service_proxy)
                .delete(handlers::proxy::service_proxy)
                .patch(handlers::proxy::service_proxy)
                .options(handlers::proxy::service_proxy)
                .head(handlers::proxy::service_proxy),
        )
        // Core group (group="", apiVersion=v1) — cluster-scoped resources (e.g. nodes)
        .route(
            "/api/v1/{resource}",
            get(handlers::core::core_list_resource)
                .post(handlers::core::core_create_resource)
                .delete(handlers::core::core_delete_collection_resource),
        )
        // Core group — cluster-scoped named resource
        .route(
            "/api/v1/{resource}/{name}",
            get(handlers::core::core_get_resource)
                .put(handlers::core::core_replace_resource)
                .delete(handlers::core::core_delete_resource)
                .patch(handlers::core::core_patch_resource),
        )
        // Core group — cluster-scoped status subresource
        .route(
            "/api/v1/{resource}/{name}/status",
            get(handlers::core::core_get_resource_status)
                .put(handlers::core::core_put_resource_status)
                .patch(handlers::core::core_patch_resource_status),
        )
        // Core group — namespaced resources collection (e.g. services, configmaps)
        .route(
            "/api/v1/namespaces/{ns}/{resource}",
            get(handlers::core::core_list_namespaced_resource)
                .post(handlers::core::core_create_namespaced_resource)
                .delete(handlers::core::core_delete_collection_namespaced_resource),
        )
        // ReplicationController scale subresource — core/v1 RC lives under group="" store key,
        // so it cannot share the apps/v1 scale route. Registered before the generic catch-all.
        .route(
            "/api/v1/namespaces/{ns}/replicationcontrollers/{name}/scale",
            get(handlers::scale::get_rc_scale)
                .put(handlers::scale::put_rc_scale)
                .patch(handlers::scale::patch_rc_scale),
        )
        // Core group — namespaced named resource
        .route(
            "/api/v1/namespaces/{ns}/{resource}/{name}",
            get(handlers::core::core_get_namespaced_resource)
                .put(handlers::core::core_replace_namespaced_resource)
                .delete(handlers::core::core_delete_namespaced_resource)
                .patch(handlers::core::core_patch_namespaced_resource),
        )
        // Core group — namespaced status subresource
        .route(
            "/api/v1/namespaces/{ns}/{resource}/{name}/status",
            get(handlers::core::core_get_namespaced_resource_status)
                .put(handlers::core::core_put_namespaced_resource_status)
                .patch(handlers::core::core_patch_namespaced_resource_status),
        )
        // CRDs — cluster-scoped, specific paths before generic catch-all
        .route(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            get(handlers::crd::list_crds)
                .post(handlers::crd::create_crd)
                .delete(handlers::crd::delete_collection_crds),
        )
        .route(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}",
            get(handlers::crd::get_crd)
                .put(handlers::crd::replace_crd)
                .patch(handlers::crd::patch_crd)
                .delete(handlers::crd::delete_crd),
        )
        // CRD status subresource — must be registered before the generic cluster-scoped
        // /apis/{group}/{version}/{resource}/{name}/status catch-all, whose CR-aware
        // handler searches for a CRD-of-CRDs that can never exist.
        .route(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}/status",
            get(handlers::crd::get_crd_status)
                .put(handlers::crd::put_crd_status)
                .patch(handlers::crd::patch_crd_status),
        )
        // Authorization reviews (specific paths before generic catch-all)
        .route(
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            post(handlers::authorization::self_subject_access_review),
        )
        .route(
            "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
            post(handlers::authorization::self_subject_rules_review),
        )
        .route(
            "/apis/authorization.k8s.io/v1/subjectaccessreviews",
            post(handlers::authorization::subject_access_review),
        )
        .route(
            "/apis/authorization.k8s.io/v1/namespaces/{ns}/localsubjectaccessreviews",
            post(handlers::authorization::local_subject_access_review),
        )
        .route(
            "/apis/authentication.k8s.io/v1/tokenreviews",
            post(handlers::authorization::token_review),
        )
        .route(
            "/apis/authentication.k8s.io/v1/selfsubjectreviews",
            post(handlers::authorization::self_subject_review),
        )
        // ServiceAccounts — token subresource (TokenRequest API)
        .route(
            "/api/v1/namespaces/{ns}/serviceaccounts/{name}/token",
            axum::routing::post(handlers::tokens::create_token),
        )
        // CertificateSigningRequests — dedicated POST handler with strict validation
        // Must be registered before the generic cluster-scoped catch-all.
        .route(
            "/apis/certificates.k8s.io/v1/certificatesigningrequests",
            get(handlers::csr::list_csr)
                .post(handlers::csr::create_csr)
                .delete(handlers::csr::delete_collection_csr),
        )
        // CSR /approval subresource — PUT and PATCH only merge status.conditions;
        // spec and status.certificate are never touched. Must be before the named
        // resource catch-all so axum doesn't interpret "approval" as a resource name.
        .route(
            "/apis/certificates.k8s.io/v1/certificatesigningrequests/{name}/approval",
            get(handlers::csr::get_csr)
                .put(handlers::approval::put_approval)
                .patch(handlers::approval::patch_approval),
        )
        // ClusterTrustBundle (certificates.k8s.io/v1beta1) — dedicated POST handler
        // validates spec.trustBundle (PEM X.509 CA certs) before storing; every kubelet
        // that mounts it via a clusterTrustBundle projected volume trusts its contents.
        // Must be registered before the generic cluster-scoped catch-all.
        .route(
            "/apis/certificates.k8s.io/v1beta1/clustertrustbundles",
            get(handlers::certificates::list_cluster_trust_bundles)
                .post(handlers::certificates::create_cluster_trust_bundle)
                .delete(handlers::certificates::delete_collection_cluster_trust_bundles),
        )
        // PodCertificateRequest (certificates.k8s.io/v1beta1) — dedicated POST handler
        // validates the +required spec fields and strips any client-supplied status
        // (status is the signer's exclusive right, written only via /status). Must be
        // registered before the generic namespaced catch-all.
        .route(
            "/apis/certificates.k8s.io/v1beta1/namespaces/{ns}/podcertificaterequests",
            get(handlers::certificates::list_pod_certificate_requests)
                .post(handlers::certificates::create_pod_certificate_request)
                .delete(handlers::certificates::delete_collection_pod_certificate_requests)
                .patch(handlers::certificates::patch_collection_pod_certificate_requests),
        )
        // Generic cluster-scoped resources — collection
        .route(
            "/apis/{group}/{version}/{resource}",
            get(handlers::resource::list_resource)
                .post(handlers::resource::create_resource)
                .delete(handlers::resource::delete_collection_resource),
        )
        // Generic cluster-scoped resources — named
        .route(
            "/apis/{group}/{version}/{resource}/{name}",
            get(handlers::resource::get_resource)
                .put(handlers::resource::replace_resource)
                .delete(handlers::resource::delete_resource)
                .patch(handlers::resource::patch_resource),
        )
        // Generic namespaced resources — collection
        .route(
            "/apis/{group}/{version}/namespaces/{ns}/{resource}",
            get(handlers::resource::list_namespaced_resource)
                .post(handlers::resource::create_namespaced_resource)
                .delete(handlers::resource::delete_collection_namespaced_resource)
                .patch(handlers::resource::patch_collection_namespaced_resource),
        )
        // Scale subresource — apps/v1 workloads (deployments, replicasets, statefulsets)
        // Must be registered before the generic namespaced named-resource catch-all.
        .route(
            "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
            get(handlers::scale::get_scale)
                .put(handlers::scale::put_scale)
                .patch(handlers::scale::patch_scale),
        )
        // Scale subresource — CRD-backed resources whose CRD declares `subresources.scale`.
        // A literal `apps/v1` request always matches the more specific route above first
        // (matchit prioritises literal path segments over `{group}`/`{version}` params), so
        // this only ever serves CRDs. Without this route, an HPA targeting a CRD-backed
        // resource gets an immediate 404 reading replicas — there is no scale route at all
        // for CRDs otherwise.
        .route(
            "/apis/{group}/{version}/namespaces/{ns}/{resource}/{name}/scale",
            get(handlers::cr::get_cr_namespaced_scale)
                .put(handlers::cr::put_cr_namespaced_scale)
                .patch(handlers::cr::patch_cr_namespaced_scale),
        )
        // Generic namespaced resources — named
        .route(
            "/apis/{group}/{version}/namespaces/{ns}/{resource}/{name}",
            get(handlers::resource::get_namespaced_resource)
                .put(handlers::resource::replace_namespaced_resource)
                .delete(handlers::resource::delete_namespaced_resource)
                .patch(handlers::resource::patch_namespaced_resource),
        )
        // Cluster-scoped status subresource — CR-aware handler falls through to
        // registry resources; generic GET/PATCH still handle non-CR resources.
        .route(
            "/apis/{group}/{version}/{resource}/{name}/status",
            get(handlers::cr::get_cr_status)
                .put(handlers::cr::put_cr_status)
                .patch(handlers::status::patch_resource_status),
        )
        // Cluster-scoped scale subresource — same CRD-only reasoning as the namespaced
        // scale route above; cluster-scoped CRDs can also declare `subresources.scale`.
        .route(
            "/apis/{group}/{version}/{resource}/{name}/scale",
            get(handlers::cr::get_cr_scale)
                .put(handlers::cr::put_cr_scale)
                .patch(handlers::cr::patch_cr_scale),
        )
        // Generic namespaced — status subresource
        .route(
            "/apis/{group}/{version}/namespaces/{ns}/{resource}/{name}/status",
            get(handlers::status::get_namespaced_resource_status)
                .put(handlers::status::put_namespaced_resource_status)
                .patch(handlers::status::patch_namespaced_resource_status),
        )
        .fallback(fallback_handler)
        // API aggregation: for any /apis/{group}/{version}/* request whose group+version
        // matches a registered APIService with a live backend, proxy it there instead of
        // the routes above. Runs as a layer (not a route) so it covers every verb/subpath
        // uniformly without a new route per HTTP method — see handlers::aggregation for why.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            handlers::aggregation::proxy_middleware::<SqliteStore>,
        ))
        .with_state(state)
}

async fn fallback_handler() -> status::StatusError {
    use axum::http::StatusCode;
    status::StatusError(
        StatusCode::NOT_FOUND,
        status::Status {
            kind: "Status",
            api_version: "v1",
            status: "Failure",
            message: "the server could not find the requested resource".into(),
            reason: "NotFound",
            code: 404,
            metadata: None,
            details: None,
        },
    )
}

/// The RFC3339 timestamp stamped as `creationTimestamp` on every object this apiserver seeds
/// on its very first boot (namespaces, bootstrap RBAC, ...). Computed once per process and
/// reused everywhere, rather than reading the clock fresh at each seed site, so objects seeded
/// moments apart during the same boot don't report different creation times, and so a value
/// that upstream treats as immutable can't drift across repeated seed calls within one run.
fn boot_timestamp() -> &'static str {
    static TS: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TS.get_or_init(util::utc_now_rfc3339)
}

async fn seed_namespaces(store: &SqliteStore) -> anyhow::Result<()> {
    use bytes::Bytes;
    use u7s_store::Store;
    // Static UIDs — no uuid crate needed.
    const NS: &[(&str, &str)] = &[
        ("default", "00000000-0000-0000-0000-000000000001"),
        ("kube-system", "00000000-0000-0000-0000-000000000002"),
        ("kube-node-lease", "00000000-0000-0000-0000-000000000003"),
        ("kube-public", "00000000-0000-0000-0000-000000000004"),
    ];
    for (name, uid) in NS {
        let key = keys::cluster_object_key("namespaces", name);
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": name,
                "uid": uid,
                "creationTimestamp": boot_timestamp(),
                "labels": { "kubernetes.io/metadata.name": name },
                "finalizers": ["kubernetes"]
            },
            "status": { "phase": "Active" }
        });
        let bytes = Bytes::from(body.to_string());
        match store.put(&key, bytes, Some(0)).await {
            Ok(_) => tracing::info!("seeded namespace: {name}"),
            Err(u7s_store::StoreError::AlreadyExists { .. }) => {
                // Already exists — idempotent, ignore.
            }
            Err(e) => return Err(anyhow::anyhow!("seed namespace {name}: {e}")),
        }
    }
    Ok(())
}

async fn seed_rbac(store: &SqliteStore) -> anyhow::Result<()> {
    use bytes::Bytes;
    use u7s_store::Store;

    const GROUP: &str = "rbac.authorization.k8s.io";
    // Never actually written to the store — the `put!` macro below overwrites
    // `metadata.creationTimestamp` on every body with `boot_timestamp()` before serializing
    // it. Kept as an obviously-fake sentinel (rather than a real-looking date) so a future
    // regression in that override shows up as a loud, unmistakable garbage value instead of
    // silently reintroducing the old "2024-01-01" lie.
    const TS: &str = "TIMESTAMP-OVERWRITTEN-BY-PUT-MACRO";

    // Helper: create-only put for a single seeded RBAC object. Like upstream kube-apiserver,
    // bootstrap RBAC is stamped once per cluster lifetime: on first boot this creates the
    // object with `boot_timestamp()`; on every later boot the object already exists, so the
    // write is rejected (AlreadyExists) and swallowed, leaving whatever an operator has since
    // changed on it untouched. uid_suffix must be unique across all seeded objects.
    macro_rules! put {
        ($key:expr, $body:expr, $name:expr, $kind:expr) => {{
            let mut body = $body;
            body["metadata"]["creationTimestamp"] = serde_json::Value::from(boot_timestamp());
            match store
                .put(&$key, Bytes::from(body.to_string()), Some(0))
                .await
            {
                Ok(_) => tracing::info!("seeded {}: {}", $kind, $name),
                Err(u7s_store::StoreError::AlreadyExists { .. }) => {
                    // Already exists — idempotent, and intentionally not re-applied so an
                    // operator's edit to a seeded Role/ClusterRole/ClusterRoleBinding survives
                    // a restart instead of being silently reverted.
                }
                Err(e) => return Err(anyhow::anyhow!("seed {} {}: {}", $kind, $name, e)),
            }
        }};
    }

    // -----------------------------------------------------------------------
    // ClusterRole: system:node — permissions kubelet needs.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:node");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:node", "uid": "00000000-0000-0000-0000-000000000010", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["nodes"],        "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": [""], "resources": ["nodes/status"], "verbs": ["get","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"],         "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["pods/status"],  "verbs": ["get","update","patch"] },
            { "apiGroups": [""], "resources": ["pods/log"],     "verbs": ["get"] },
            { "apiGroups": [""], "resources": ["events"],       "verbs": ["create","patch","update"] },
            // Kubelet's own service informer populates Service-discovery env vars
            // (SERVICE_HOST/SERVICE_PORT) injected into every pod's containers. Without this
            // rule the informer's List/Watch is denied, the informer never completes its first
            // sync, and every container on that node fails to start with
            // CreateContainerConfigError: "services have not yet been read at least once" --
            // silently masked as long as the only kubelet ever exercised authenticates as
            // system:masters (admin) instead of a real system:node identity. Matches upstream
            // bootstrappolicy.go's NodeRules() exactly.
            { "apiGroups": [""], "resources": ["services"],     "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["configmaps"],          "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["secrets"],             "verbs": ["get","list","watch"] },
            // Kubelet calls TokenRequest to project SA tokens into pods (projected volumes).
            // Without this rule the kubelet's POST to serviceaccounts/{name}/token returns 403
            // and containers never get an SA token, breaking in-cluster API calls.
            { "apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"] },
            { "apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["csinodes"], "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["csidrivers"], "verbs": ["get","list","watch"] },
            // Kubelet webhook authorizer and authenticator call back to the apiserver via
            // SubjectAccessReview and TokenReview. Without these the kubelet denies all
            // proxy requests (logs, exec, attach) with "Authorization error".
            { "apiGroups": ["authorization.k8s.io"], "resources": ["subjectaccessreviews"], "verbs": ["create"] },
            { "apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"] },
            // Used to create a certificatesigningrequest for a node-specific client certificate,
            // and watch for it to be signed. This allows the kubelet to rotate its own
            // certificate. Matches upstream bootstrappolicy.go's NodeRules() exactly — without
            // this, a joined node has no permission to even submit its own self-renewal CSR,
            // regardless of whether the selfnodeclient ClusterRole/binding (which only governs
            // KCM's SAR-based auto-approval) exists.
            { "apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests"], "verbs": ["create","get","list","watch"] }
        ]
    });
    put!(key, body, "system:node", "ClusterRole");

    // ClusterRoleBinding: system:node — binds system:nodes group to the ClusterRole.
    let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:node");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:node", "uid": "00000000-0000-0000-0000-000000000011", "creationTimestamp": TS },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:nodes" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:node" }
    });
    put!(key, body, "system:node", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: cluster-admin — wildcard access to all resources.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "cluster-admin");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "cluster-admin", "uid": "00000000-0000-0000-0000-000000000012", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] },
            { "nonResourceURLs": ["*"], "verbs": ["*"] }
        ]
    });
    put!(key, body, "cluster-admin", "ClusterRole");

    // ClusterRoleBinding: system:masters → cluster-admin.
    // This replaces the former hardcoded bypass in is_allowed() / user_holds_all_rules().
    let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:masters");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:masters", "uid": "00000000-0000-0000-0000-000000000013", "creationTimestamp": TS },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:masters" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin" }
    });
    put!(key, body, "system:masters", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: system:basic-user — grants every authenticated user the
    // ability to create SelfSubjectAccessReviews, SelfSubjectRulesReviews, and
    // SelfSubjectReviews (matching upstream bootstrappolicy.go's basicUserRules).
    // Argo CD calls the first two on startup to discover its own permissions, and
    // `kubectl auth whoami` requires the third; without this role those requests
    // are denied with 403.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:basic-user");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:basic-user", "uid": "00000000-0000-0000-0000-000000000014", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["authorization.k8s.io"], "resources": ["selfsubjectaccessreviews","selfsubjectrulesreviews"], "verbs": ["create"] },
            { "apiGroups": ["authentication.k8s.io"], "resources": ["selfsubjectreviews"], "verbs": ["create"] }
        ]
    });
    put!(key, body, "system:basic-user", "ClusterRole");

    // ClusterRoleBinding: system:basic-user → system:authenticated.
    let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:basic-user");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:basic-user", "uid": "00000000-0000-0000-0000-000000000015", "creationTimestamp": TS },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:authenticated" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:basic-user" }
    });
    put!(key, body, "system:basic-user", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: system:discovery — read access to API discovery endpoints.
    // Grants get on /api, /apis, /openapi/v2, etc. so unauthenticated discovery works.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:discovery");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:discovery", "uid": "00000000-0000-0000-0000-000000000016", "creationTimestamp": TS },
        "rules": [
            { "nonResourceURLs": ["/api","/api/*","/apis","/apis/*","/healthz","/readyz","/livez","/openapi","/openapi/*","/version"], "verbs": ["get"] }
        ]
    });
    put!(key, body, "system:discovery", "ClusterRole");

    // ClusterRoleBinding: system:discovery → system:authenticated.
    let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:discovery");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:discovery", "uid": "00000000-0000-0000-0000-000000000017", "creationTimestamp": TS },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:authenticated" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:discovery" }
    });
    put!(key, body, "system:discovery", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: system:public-info-viewer — health/liveness/version endpoints
    // for both authenticated and unauthenticated clients (e.g. load balancers).
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:public-info-viewer");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:public-info-viewer", "uid": "00000000-0000-0000-0000-000000000018", "creationTimestamp": TS },
        "rules": [
            { "nonResourceURLs": ["/healthz","/readyz","/livez","/version","/version/"], "verbs": ["get"] }
        ]
    });
    put!(key, body, "system:public-info-viewer", "ClusterRole");

    // ClusterRoleBinding: system:public-info-viewer → authenticated + unauthenticated.
    let key = keys::group_object_key(
        GROUP,
        "clusterrolebindings",
        None,
        "system:public-info-viewer",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:public-info-viewer", "uid": "00000000-0000-0000-0000-000000000019", "creationTimestamp": TS },
        "subjects": [
            { "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:authenticated" },
            { "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:unauthenticated" }
        ],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:public-info-viewer" }
    });
    put!(key, body, "system:public-info-viewer", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: system:kube-controller-manager — KCM needs these to run its
    // reconciliation loops for deployments, replicasets, endpoints, etc.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:kube-controller-manager",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:kube-controller-manager", "uid": "00000000-0000-0000-0000-000000000020", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] },
            { "apiGroups": [""], "resources": ["endpoints","pods","replicationcontrollers","serviceaccounts","configmaps","secrets","services","namespaces","nodes","persistentvolumes","persistentvolumeclaims","resourcequotas"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["resourcequotas/status"], "verbs": ["get","update","patch"] },
            { "apiGroups": ["apps"], "resources": ["daemonsets","deployments","replicasets","statefulsets","controllerrevisions"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["apps"], "resources": ["daemonsets/status","deployments/status","replicasets/status","statefulsets/status"], "verbs": ["get","update","patch"] },
            { "apiGroups": ["batch"], "resources": ["jobs","cronjobs"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            // The endpointslice controller mirrors each Service's endpoints into
            // EndpointSlice objects; the generic read-only discovery rule below doesn't
            // cover this because it needs write verbs too.
            { "apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles","clusterrolebindings","roles","rolebindings"], "verbs": ["get","list","watch","create","update","patch","escalate","bind"] },
            { "apiGroups": ["authorization.k8s.io"], "resources": ["subjectaccessreviews"], "verbs": ["create"] },
            { "apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["storageclasses","csinodes","csidrivers","csistoragecapacities"], "verbs": ["get","list","watch"] },
            // attachdetach-controller creates/deletes VolumeAttachments to drive CSI
            // ControllerPublish/Unpublish (matches upstream's per-controller
            // system:controller:attachdetach-controller role — see the seeded-but-unused
            // copy elsewhere in this function). With --use-service-account-credentials=false
            // this identity runs that controller too, so the grant has to live here instead:
            // without `create`, kubelet's volume manager waits forever for an attach that
            // never happens and every CSI pod using an attachable driver (e.g. csi-hostpath)
            // hangs in ContainerCreating, live-confirmed via kcm.log's "system:kube-controller-manager
            // is not allowed to create volumeattachments" before this fix.
            { "apiGroups": ["storage.k8s.io"], "resources": ["volumeattachments"], "verbs": ["get","list","watch","create","delete"] },
            // namespace-controller needs these two subresources specifically (the base
            // "namespaces" rule above doesn't cover them) to record deletion-progress
            // conditions and clear the "kubernetes" finalizer once a namespace's contents
            // are gone — without it, a deleted namespace hangs in Terminating forever.
            { "apiGroups": [""], "resources": ["namespaces/status","namespaces/finalize"], "verbs": ["get","update","patch"] },
            // The garbage-collector, resourcequota, and namespace controllers all do
            // generic, type-agnostic discovery/cleanup across the entire API surface —
            // they must handle arbitrary/future resource types, including CRDs, without a
            // hardcoded list (e.g. namespace deletion has to delete every object of every
            // type living in that namespace, whatever type that turns out to be). This is
            // the exact union of verbs upstream's own bootstrap policy grants their
            // per-controller ClusterRoles (system:controller:generic-garbage-collector:
            // get/list/watch/patch/update/delete; system:controller:resourcequota-controller:
            // get/list/watch; system:controller:namespace-controller:
            // get/list/watch/delete/deletecollection — see the seeded-but-currently-unused
            // copies of those three roles below). With
            // --use-service-account-credentials=false all three controllers run as this
            // single identity, so the grant has to live here instead. Stops short of
            // create/escalate/bind on arbitrary types, so this is still not
            // cluster-admin-equivalent.
            { "apiGroups": ["*"], "resources": ["*"], "verbs": ["get","list","watch","patch","update","delete","deletecollection"] }
        ]
    });
    put!(key, body, "system:kube-controller-manager", "ClusterRole");

    // ClusterRoleBinding: system:kube-controller-manager → user system:kube-controller-manager.
    let key = keys::group_object_key(
        GROUP,
        "clusterrolebindings",
        None,
        "system:kube-controller-manager",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:kube-controller-manager", "uid": "00000000-0000-0000-0000-000000000021", "creationTimestamp": TS },
        "subjects": [{ "kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "system:kube-controller-manager" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:kube-controller-manager" }
    });
    put!(
        key,
        body,
        "system:kube-controller-manager",
        "ClusterRoleBinding"
    );

    // -----------------------------------------------------------------------
    // ClusterRole: system:kube-scheduler — scheduler needs watch on pods/nodes
    // and update on pod bindings to place workloads.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:kube-scheduler");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:kube-scheduler", "uid": "00000000-0000-0000-0000-000000000022", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","delete"] },
            { "apiGroups": [""], "resources": ["pods/binding","pods/status"], "verbs": ["update","patch","create"] },
            { "apiGroups": [""], "resources": ["nodes"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] },
            { "apiGroups": [""], "resources": ["services","replicationcontrollers","persistentvolumeclaims","persistentvolumes"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["apps"], "resources": ["statefulsets","replicasets"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["policy"], "resources": ["poddisruptionbudgets"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["storageclasses","csinodes","csidrivers","csistoragecapacities"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"] },
            { "apiGroups": ["authorization.k8s.io"], "resources": ["subjectaccessreviews"], "verbs": ["create"] }
        ]
    });
    put!(key, body, "system:kube-scheduler", "ClusterRole");

    // ClusterRoleBinding: system:kube-scheduler → user system:kube-scheduler.
    let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:kube-scheduler");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:kube-scheduler", "uid": "00000000-0000-0000-0000-000000000023", "creationTimestamp": TS },
        "subjects": [{ "kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "system:kube-scheduler" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:kube-scheduler" }
    });
    put!(key, body, "system:kube-scheduler", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: system:bootstrap-installer — minimal-scope identity for the
    // in-process YAML applier (a later bead) that server-side-applies bootstrap
    // manifest bundles (e.g. CoreDNS's ClusterRole/ClusterRoleBinding/ServiceAccount/
    // ConfigMap/Deployment/Service) against the just-bound apiserver. Deliberately
    // upsert-only: no delete/deletecollection verbs anywhere in this role, since the
    // applier never removes objects — broadening this is a separate, later change.
    // "get" is included so the applier can check whether a document is already
    // installed before PATCHing — re-PATCHing an object that already exists on every
    // boot risks corrupting any list field whose merge key collides across entries
    // (e.g. kube-dns's Service ports, which share port 53 across UDP and TCP).
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:bootstrap-installer");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:bootstrap-installer", "uid": "00000000-0000-0000-0000-000000000079", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles","clusterrolebindings"], "verbs": ["get","create","patch","update"] },
            { "apiGroups": [""], "resources": ["serviceaccounts","configmaps","services","namespaces"], "verbs": ["get","create","patch","update"] },
            { "apiGroups": ["apps"], "resources": ["deployments","daemonsets"], "verbs": ["get","create","patch","update"] }
        ]
    });
    put!(key, body, "system:bootstrap-installer", "ClusterRole");

    // ClusterRoleBinding: system:bootstrap-installer → user system:bootstrap-installer.
    let key = keys::group_object_key(
        GROUP,
        "clusterrolebindings",
        None,
        "system:bootstrap-installer",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:bootstrap-installer", "uid": "00000000-0000-0000-0000-00000000007a", "creationTimestamp": TS },
        "subjects": [{ "kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "system:bootstrap-installer" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:bootstrap-installer" }
    });
    put!(
        key,
        body,
        "system:bootstrap-installer",
        "ClusterRoleBinding"
    );

    // -----------------------------------------------------------------------
    // ClusterRole: system:node-proxier — kube-proxy needs watch on services/endpoints.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:node-proxier");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:node-proxier", "uid": "00000000-0000-0000-0000-000000000024", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["endpoints","services","nodes"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] },
            { "apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["networking.k8s.io"], "resources": ["servicecidrs"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(key, body, "system:node-proxier", "ClusterRole");

    // ClusterRoleBinding: system:node-proxier → user system:kube-proxy.
    let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:node-proxier");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:node-proxier", "uid": "00000000-0000-0000-0000-000000000025", "creationTimestamp": TS },
        "subjects": [{ "kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "system:kube-proxy" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:node-proxier" }
    });
    put!(key, body, "system:node-proxier", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: system:monitoring — read-only access to health/metrics endpoints.
    // Upstream also advertises "/metrics/slis" plus "/livez/*","/readyz/*","/healthz/*"
    // (per-healthcheck subpaths). Neither is advertised here: we have no healthz
    // checker framework (our /healthz, /readyz, /livez handlers are unconditional
    // "ok", not a set of named checks), so there is no SLI data to back a
    // "/metrics/slis" route — advertising it in RBAC without a route would be a
    // 404 trap for any caller who reads this ClusterRole and expects the endpoint
    // to exist.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:monitoring");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:monitoring", "uid": "00000000-0000-0000-0000-000000000026", "creationTimestamp": TS },
        "rules": [
            { "nonResourceURLs": ["/metrics","/healthz","/readyz","/livez"], "verbs": ["get"] }
        ]
    });
    put!(key, body, "system:monitoring", "ClusterRole");

    // -----------------------------------------------------------------------
    // ClusterRole: system:persistent-volume-provisioner — for external PV provisioners.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:persistent-volume-provisioner",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:persistent-volume-provisioner", "uid": "00000000-0000-0000-0000-000000000027", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["persistentvolumes"], "verbs": ["get","list","watch","create","delete"] },
            { "apiGroups": [""], "resources": ["persistentvolumeclaims"], "verbs": ["get","list","watch","update"] },
            { "apiGroups": [""], "resources": ["storageclasses"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","update","patch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["storageclasses"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(
        key,
        body,
        "system:persistent-volume-provisioner",
        "ClusterRole"
    );

    // -----------------------------------------------------------------------
    // ClusterRole: system:volume-scheduler — volume binding for scheduler.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:volume-scheduler");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:volume-scheduler", "uid": "00000000-0000-0000-0000-000000000028", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["persistentvolumes"], "verbs": ["get","list","patch","update","watch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["storageclasses"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["persistentvolumeclaims"], "verbs": ["get","list","patch","update","watch"] }
        ]
    });
    put!(key, body, "system:volume-scheduler", "ClusterRole");

    // -----------------------------------------------------------------------
    // ClusterRole: system:node-bootstrapper — TLS bootstrap for kubelets.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:node-bootstrapper");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:node-bootstrapper", "uid": "00000000-0000-0000-0000-000000000029", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests"], "verbs": ["create","get","list","watch"] }
        ]
    });
    put!(key, body, "system:node-bootstrapper", "ClusterRole");

    // ClusterRoleBinding: system:node-bootstrapper → system:bootstrappers group.
    // Upstream binds this via kubeadm's `kubeadm:kubelet-bootstrap` ClusterRoleBinding —
    // this ClusterRole existed in u7s already but was never bound to anything, so no
    // bootstrap identity could ever submit a join CSR. system:bootstrappers is the group
    // a bootstrap-token-authenticated caller belongs to (mirroring upstream's
    // node-bootstrap-token-auth flow).
    let key = keys::group_object_key(
        GROUP,
        "clusterrolebindings",
        None,
        "system:node-bootstrapper",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:node-bootstrapper", "uid": "00000000-0000-0000-0000-00000000007b", "creationTimestamp": TS },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:bootstrappers" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:node-bootstrapper" }
    });
    put!(key, body, "system:node-bootstrapper", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: system:certificates.k8s.io:certificatesigningrequests:nodeclient
    // and ...:selfnodeclient — these are not real subresources of the CSR object;
    // KCM's builtin csrapproving controller (pkg/controller/certificates/approver/
    // sarapprove.go) checks auto-approval eligibility by issuing a SubjectAccessReview
    // against exactly these resource/subresource pairs, built from the CSR's (now
    // server-stamped, see stamp_csr_identity in handlers/csr.rs) spec.username/groups.
    // nodeclient authorizes a brand-new node join CSR; selfnodeclient authorizes an
    // already-joined node renewing its own client cert. Pure seed data — u7s's RBAC
    // engine already supports arbitrary "resource/subresource" strings generically.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:certificates.k8s.io:certificatesigningrequests:nodeclient",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:certificates.k8s.io:certificatesigningrequests:nodeclient", "uid": "00000000-0000-0000-0000-00000000007c", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests/nodeclient"], "verbs": ["create"] }
        ]
    });
    put!(
        key,
        body,
        "system:certificates.k8s.io:certificatesigningrequests:nodeclient",
        "ClusterRole"
    );

    // ClusterRoleBinding: nodeclient ClusterRole → system:bootstrappers group.
    // Matches upstream's `kubeadm:node-autoapprove-bootstrap` ClusterRoleBinding.
    let key = keys::group_object_key(
        GROUP,
        "clusterrolebindings",
        None,
        "system:certificates.k8s.io:certificatesigningrequests:nodeclient",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:certificates.k8s.io:certificatesigningrequests:nodeclient", "uid": "00000000-0000-0000-0000-00000000007d", "creationTimestamp": TS },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:bootstrappers" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:certificates.k8s.io:certificatesigningrequests:nodeclient" }
    });
    put!(
        key,
        body,
        "system:certificates.k8s.io:certificatesigningrequests:nodeclient",
        "ClusterRoleBinding"
    );

    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient", "uid": "00000000-0000-0000-0000-00000000007e", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests/selfnodeclient"], "verbs": ["create"] }
        ]
    });
    put!(
        key,
        body,
        "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient",
        "ClusterRole"
    );

    // ClusterRoleBinding: selfnodeclient ClusterRole → system:nodes group (already bound
    // to system:node above) — an already-joined node may renew its own client cert.
    // Matches upstream's `kubeadm:node-autoapprove-certificate-rotation` ClusterRoleBinding.
    let key = keys::group_object_key(
        GROUP,
        "clusterrolebindings",
        None,
        "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient", "uid": "00000000-0000-0000-0000-00000000007f", "creationTimestamp": TS },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:nodes" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient" }
    });
    put!(
        key,
        body,
        "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient",
        "ClusterRoleBinding"
    );

    // -----------------------------------------------------------------------
    // ClusterRole: system:heapster — legacy metrics aggregator.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:heapster");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:heapster", "uid": "00000000-0000-0000-0000-000000000030", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["events","namespaces","nodes","pods"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(key, body, "system:heapster", "ClusterRole");

    // -----------------------------------------------------------------------
    // ClusterRole: system:service-account-issuer-discovery — allows token projections.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:service-account-issuer-discovery",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:service-account-issuer-discovery", "uid": "00000000-0000-0000-0000-000000000031", "creationTimestamp": TS },
        "rules": [
            { "nonResourceURLs": ["/.well-known/openid-configuration","/openid/v1/jwks"], "verbs": ["get"] }
        ]
    });
    put!(
        key,
        body,
        "system:service-account-issuer-discovery",
        "ClusterRole"
    );

    // ClusterRoleBinding: system:service-account-issuer-discovery → system:serviceaccounts.
    // Grants every service account GET access to the OIDC discovery endpoints
    // (/.well-known/openid-configuration and /openid/v1/jwks). Without this binding,
    // pods cannot access these endpoints and the OIDC conformance test fails with 403.
    // Matches upstream Kubernetes bootstrap policy.
    let key = keys::group_object_key(
        GROUP,
        "clusterrolebindings",
        None,
        "system:service-account-issuer-discovery",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:service-account-issuer-discovery", "uid": "00000000-0000-0000-0000-000000000067", "creationTimestamp": TS },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:serviceaccounts" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:service-account-issuer-discovery" }
    });
    put!(
        key,
        body,
        "system:service-account-issuer-discovery",
        "ClusterRoleBinding"
    );

    // -----------------------------------------------------------------------
    // ClusterRole: admin — namespace-scoped admin (aggregate-to-admin).
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "admin");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {
            "name": "admin",
            "uid": "00000000-0000-0000-0000-000000000032",
            "creationTimestamp": TS,
            "labels": { "rbac.authorization.k8s.io/aggregate-to-cluster-admin": "true" }
        },
        "rules": [
            { "apiGroups": [""], "resources": ["pods","services","endpoints","persistentvolumeclaims","configmaps","secrets","serviceaccounts","events","replicationcontrollers"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["apps"], "resources": ["daemonsets","deployments","replicasets","statefulsets","controllerrevisions"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["batch"], "resources": ["jobs","cronjobs"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles","rolebindings"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection","bind","escalate"] },
            { "apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies","ingresses"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["policy"], "resources": ["poddisruptionbudgets"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            // Read+write on the "escalating" pod/service subresources upstream's editRules()
            // grants directly (never via the view aggregation, so "view" must NOT get these):
            // Read covers a plain GET dial (e.g. `kubectl exec`/`attach`/`port-forward`), write
            // covers the arbitrary HTTP methods `pods/proxy`+`services/proxy` forward to the
            // target pod/service and the POST retry leg exec/attach fall back to.
            { "apiGroups": [""], "resources": ["pods/attach","pods/exec","pods/portforward","pods/proxy","services/proxy"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            // Upstream grants `impersonate` on serviceaccounts to edit/admin so a namespace
            // editor can act as one of "their" ServiceAccounts (e.g. to debug a workload
            // identity) without cluster-admin. auth.rs's Impersonate-User handling branches on
            // SA-shaped usernames to authorize against this namespaced resource.
            { "apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["impersonate"] },
            { "apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"] },
            // kubectl drain / voluntary disruption POSTs an Eviction rather than deleting the
            // Pod directly — without this a namespace editor could delete Pods but not evict
            // them through PodDisruptionBudget-aware eviction.
            { "apiGroups": [""], "resources": ["pods/eviction"], "verbs": ["create"] },
            // replicationcontrollers/scale: write comes from upstream's editRules() directly;
            // read comes from the view aggregation editRules() pulls in. The resolved "edit"/
            // "admin" ClusterRole grants both, matching this codebase's convention (see
            // leases/networkpolicies/poddisruptionbudgets above) of encoding the fully-resolved
            // permission set rather than replicating which upstream helper contributed what.
            { "apiGroups": [""], "resources": ["replicationcontrollers/scale"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            // Upstream's editRules() never grants write on "namespaces" or "resourcequotas"
            // directly — its own comment on the "edit" ClusterRole explicitly excludes
            // "quota/limits which are used to control namespaces" from edit's write powers.
            // The resolved "edit"/"admin" ClusterRole only gets the READ-ONLY grant
            // viewRules() contributes via the aggregation edit/admin pull in, so this
            // duplicates "view"'s base rule below rather than granting CRUD.
            { "apiGroups": [""], "resources": ["namespaces","resourcequotas"], "verbs": ["get","list","watch"] },
            // Upstream's editRules() never mentions any of these /status subresources —
            // they reach the resolved "edit"/"admin" ClusterRole only via the view
            // aggregation, so admin/edit get exactly the same READ-ONLY grant as "view"
            // below. Status is deliberately excluded from edit/admin's write powers
            // (see upstream's "edit" ClusterRole comment: "/status subresources ... are
            // the domain of the system"); only controller identities like
            // system:kube-controller-manager can write status.
            { "apiGroups": [""], "resources": ["pods/status","services/status","resourcequotas/status","namespaces/status","replicationcontrollers/status","persistentvolumeclaims/status"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["apps"], "resources": ["statefulsets/status","daemonsets/status","deployments/status","replicasets/status"], "verbs": ["get","list","watch"] },
            // Unlike the /status entries above, statefulsets/scale, deployments/scale, and
            // replicasets/scale ARE granted write directly by upstream's editRules(), so
            // admin/edit get full CRUD here — the same convention already used for
            // replicationcontrollers/scale above.
            { "apiGroups": ["apps"], "resources": ["statefulsets/scale","deployments/scale","replicasets/scale"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers/status"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["batch"], "resources": ["cronjobs/status","jobs/status"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["policy"], "resources": ["poddisruptionbudgets/status"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["networking.k8s.io"], "resources": ["ingresses/status"], "verbs": ["get","list","watch"] },
            // discovery.k8s.io/endpointslices: upstream's editRules() never mentions the
            // discovery group at all — only viewRules() does — so the resolved edit/admin
            // grant is this same READ-ONLY rule, not full CRUD. Writing EndpointSlices is
            // reserved for the endpointslice controller (system:kube-controller-manager).
            { "apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(key, body, "admin", "ClusterRole");

    // -----------------------------------------------------------------------
    // ClusterRole: edit — namespace-scoped write access.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "edit");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {
            "name": "edit",
            "uid": "00000000-0000-0000-0000-000000000033",
            "creationTimestamp": TS,
            "labels": { "rbac.authorization.k8s.io/aggregate-to-admin": "true" }
        },
        "rules": [
            { "apiGroups": [""], "resources": ["pods","services","endpoints","persistentvolumeclaims","configmaps","secrets","serviceaccounts","events","replicationcontrollers"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["apps"], "resources": ["daemonsets","deployments","replicasets","statefulsets","controllerrevisions"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["batch"], "resources": ["jobs","cronjobs"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies","ingresses"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["policy"], "resources": ["poddisruptionbudgets"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            // See the identical block in "admin" above for why each of these exists.
            { "apiGroups": [""], "resources": ["pods/attach","pods/exec","pods/portforward","pods/proxy","services/proxy"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["impersonate"] },
            { "apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"] },
            { "apiGroups": [""], "resources": ["pods/eviction"], "verbs": ["create"] },
            { "apiGroups": [""], "resources": ["replicationcontrollers/scale"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            // See the identical block in "admin" above for why each of these exists.
            { "apiGroups": [""], "resources": ["namespaces","resourcequotas"], "verbs": ["get","list","watch"] },
            // See the identical block in "admin" above for why each of these exists.
            { "apiGroups": [""], "resources": ["pods/status","services/status","resourcequotas/status","namespaces/status","replicationcontrollers/status","persistentvolumeclaims/status"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["apps"], "resources": ["statefulsets/status","daemonsets/status","deployments/status","replicasets/status"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["apps"], "resources": ["statefulsets/scale","deployments/scale","replicasets/scale"], "verbs": ["get","list","watch","create","update","patch","delete","deletecollection"] },
            { "apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers/status"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["batch"], "resources": ["cronjobs/status","jobs/status"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["policy"], "resources": ["poddisruptionbudgets/status"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["networking.k8s.io"], "resources": ["ingresses/status"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(key, body, "edit", "ClusterRole");

    // -----------------------------------------------------------------------
    // ClusterRole: view — namespace-scoped read-only access.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "view");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {
            "name": "view",
            "uid": "00000000-0000-0000-0000-000000000034",
            "creationTimestamp": TS,
            "labels": { "rbac.authorization.k8s.io/aggregate-to-edit": "true" }
        },
        "rules": [
            { "apiGroups": [""], "resources": ["pods","services","endpoints","persistentvolumeclaims","configmaps","serviceaccounts","events","replicationcontrollers","namespaces","nodes","resourcequotas","limitranges"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["apps"], "resources": ["daemonsets","deployments","replicasets","statefulsets","controllerrevisions"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["batch"], "resources": ["jobs","cronjobs"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers"], "verbs": ["get","list","watch"] },
            // NOTE: intentionally no coordination.k8s.io/leases rule here — upstream's
            // viewRules() doesn't grant leases either; edit/admin get it directly.
            { "apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies","ingresses"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["policy"], "resources": ["poddisruptionbudgets"], "verbs": ["get","list","watch"] },
            // replicationcontrollers/scale is non-escalating and part of upstream's viewRules()
            // directly (unlike pods/attach|exec|portforward|proxy and services/proxy, which
            // are intentionally excluded from "view" — see the edit/admin ClusterRoles above).
            { "apiGroups": [""], "resources": ["replicationcontrollers/scale"], "verbs": ["get","list","watch"] },
            // Upstream's viewRules() grants read on each workload type's /status
            // subresource directly — these are non-escalating (unlike pods/attach|exec|
            // portforward|proxy and services/proxy above), so "view" gets them too.
            { "apiGroups": [""], "resources": ["pods/status","services/status","resourcequotas/status","namespaces/status","replicationcontrollers/status","persistentvolumeclaims/status"], "verbs": ["get","list","watch"] },
            // statefulsets/scale, deployments/scale, replicasets/scale are read-only here —
            // upstream's viewRules() grants Read on them directly; the Write half comes only
            // from editRules(), so "edit"/"admin" (not "view") get full CRUD (see above).
            { "apiGroups": ["apps"], "resources": ["statefulsets/status","statefulsets/scale","daemonsets/status","deployments/status","deployments/scale","replicasets/status","replicasets/scale"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers/status"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["batch"], "resources": ["cronjobs/status","jobs/status"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["policy"], "resources": ["poddisruptionbudgets/status"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["networking.k8s.io"], "resources": ["ingresses/status"], "verbs": ["get","list","watch"] },
            // discovery.k8s.io/endpointslices has no rule at all in "view" today — upstream
            // grants get/list/watch directly.
            { "apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(key, body, "view", "ClusterRole");

    // -----------------------------------------------------------------------
    // Controller ClusterRoles — each KCM sub-controller needs its own least-
    // privilege role so it only touches the resources it manages.
    // -----------------------------------------------------------------------

    // system:controller:attachdetach-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:attachdetach-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:attachdetach-controller", "uid": "00000000-0000-0000-0000-000000000035", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["persistentvolumes","persistentvolumeclaims","nodes","pods"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["nodes/status"], "verbs": ["patch","update"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["volumeattachments","csinodes","csidrivers"], "verbs": ["get","list","watch","create","update","patch","delete"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:attachdetach-controller",
        "ClusterRole"
    );

    // system:controller:certificate-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:certificate-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:certificate-controller", "uid": "00000000-0000-0000-0000-000000000036", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests"], "verbs": ["get","list","watch","delete"] },
            { "apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests/status","certificatesigningrequests/approval"], "verbs": ["update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:certificate-controller",
        "ClusterRole"
    );

    // system:controller:clusterrole-aggregation-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:clusterrole-aggregation-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:clusterrole-aggregation-controller", "uid": "00000000-0000-0000-0000-000000000037", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"], "verbs": ["get","list","watch","update","patch"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:clusterrole-aggregation-controller",
        "ClusterRole"
    );

    // system:controller:cronjob-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:cronjob-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:cronjob-controller", "uid": "00000000-0000-0000-0000-000000000038", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["batch"], "resources": ["cronjobs","jobs"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:cronjob-controller",
        "ClusterRole"
    );

    // system:controller:daemon-set-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:daemon-set-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:daemon-set-controller", "uid": "00000000-0000-0000-0000-000000000039", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["apps"], "resources": ["daemonsets","daemonsets/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["nodes","pods","podtemplates"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["create","delete","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:daemon-set-controller",
        "ClusterRole"
    );

    // system:controller:deployment-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:deployment-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:deployment-controller", "uid": "00000000-0000-0000-0000-000000000040", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["apps"], "resources": ["deployments","deployments/status","replicasets"], "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:deployment-controller",
        "ClusterRole"
    );

    // system:controller:disruption-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:disruption-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:disruption-controller", "uid": "00000000-0000-0000-0000-000000000041", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["apps"], "resources": ["deployments","replicasets","statefulsets"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["policy"], "resources": ["poddisruptionbudgets","poddisruptionbudgets/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:disruption-controller",
        "ClusterRole"
    );

    // system:controller:endpoint-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:endpoint-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:endpoint-controller", "uid": "00000000-0000-0000-0000-000000000042", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["endpoints","pods","services"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] },
            { "apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get","list","watch","create","update","patch","delete"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:endpoint-controller",
        "ClusterRole"
    );

    // system:controller:expand-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:expand-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:expand-controller", "uid": "00000000-0000-0000-0000-000000000043", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["persistentvolumes","persistentvolumeclaims","persistentvolumeclaims/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["storageclasses"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:expand-controller",
        "ClusterRole"
    );

    // system:controller:generic-garbage-collector
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:generic-garbage-collector",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:generic-garbage-collector", "uid": "00000000-0000-0000-0000-000000000044", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["*"], "resources": ["*"], "verbs": ["get","list","watch","patch","update","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:generic-garbage-collector",
        "ClusterRole"
    );

    // system:controller:horizontal-pod-autoscaler
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:horizontal-pod-autoscaler",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:horizontal-pod-autoscaler", "uid": "00000000-0000-0000-0000-000000000045", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers","horizontalpodautoscalers/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["pods","replicationcontrollers","replicationcontrollers/scale"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": ["apps"], "resources": ["deployments","deployments/scale","replicasets","replicasets/scale","statefulsets","statefulsets/scale"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] },
            { "apiGroups": ["metrics.k8s.io"], "resources": ["pods","nodes"], "verbs": ["get","list"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:horizontal-pod-autoscaler",
        "ClusterRole"
    );

    // system:controller:job-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:job-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:job-controller", "uid": "00000000-0000-0000-0000-000000000046", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["batch"], "resources": ["jobs","jobs/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","create","delete","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(key, body, "system:controller:job-controller", "ClusterRole");

    // system:controller:namespace-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:namespace-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:namespace-controller", "uid": "00000000-0000-0000-0000-000000000047", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["*"], "resources": ["*"], "verbs": ["get","list","watch","delete","deletecollection"] },
            { "apiGroups": [""], "resources": ["namespaces","namespaces/status","namespaces/finalize"], "verbs": ["get","list","watch","update","patch"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:namespace-controller",
        "ClusterRole"
    );

    // system:controller:node-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:node-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:node-controller", "uid": "00000000-0000-0000-0000-000000000048", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["nodes","nodes/status"], "verbs": ["get","list","watch","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:node-controller",
        "ClusterRole"
    );

    // system:controller:persistent-volume-binder
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:persistent-volume-binder",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:persistent-volume-binder", "uid": "00000000-0000-0000-0000-000000000049", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["persistentvolumes","persistentvolumeclaims","persistentvolumeclaims/status","pods"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["namespaces","nodes","services"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["storageclasses"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update","watch","list","get"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:persistent-volume-binder",
        "ClusterRole"
    );

    // system:controller:pod-garbage-collector
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:pod-garbage-collector",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:pod-garbage-collector", "uid": "00000000-0000-0000-0000-000000000050", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","delete"] },
            { "apiGroups": [""], "resources": ["nodes"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:pod-garbage-collector",
        "ClusterRole"
    );

    // system:controller:pvc-protection-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:pvc-protection-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:pvc-protection-controller", "uid": "00000000-0000-0000-0000-000000000051", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["persistentvolumeclaims","persistentvolumeclaims/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:pvc-protection-controller",
        "ClusterRole"
    );

    // system:controller:replicaset-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:replicaset-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:replicaset-controller", "uid": "00000000-0000-0000-0000-000000000052", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["apps"], "resources": ["replicasets","replicasets/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","create","delete","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:replicaset-controller",
        "ClusterRole"
    );

    // system:controller:replication-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:replication-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:replication-controller", "uid": "00000000-0000-0000-0000-000000000053", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["replicationcontrollers","replicationcontrollers/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","create","delete","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:replication-controller",
        "ClusterRole"
    );

    // system:controller:resourcequota-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:resourcequota-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:resourcequota-controller", "uid": "00000000-0000-0000-0000-000000000054", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["*"], "resources": ["*"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["resourcequotas","resourcequotas/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:resourcequota-controller",
        "ClusterRole"
    );

    // system:controller:route-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:route-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:route-controller", "uid": "00000000-0000-0000-0000-000000000055", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["nodes"], "verbs": ["get","list","watch","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:route-controller",
        "ClusterRole"
    );

    // system:controller:service-account-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:service-account-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:service-account-controller", "uid": "00000000-0000-0000-0000-000000000056", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:service-account-controller",
        "ClusterRole"
    );

    // system:controller:service-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:service-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:service-controller", "uid": "00000000-0000-0000-0000-000000000057", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["services","services/status","nodes","endpoints"], "verbs": ["get","list","watch","update","patch","create","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:service-controller",
        "ClusterRole"
    );

    // system:controller:statefulset-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:statefulset-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:statefulset-controller", "uid": "00000000-0000-0000-0000-000000000058", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["apps"], "resources": ["statefulsets","statefulsets/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["pods","persistentvolumeclaims"], "verbs": ["get","list","watch","create","delete","update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:statefulset-controller",
        "ClusterRole"
    );

    // system:controller:ttl-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:ttl-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:ttl-controller", "uid": "00000000-0000-0000-0000-000000000059", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["nodes"], "verbs": ["get","list","watch","patch","update"] }
        ]
    });
    put!(key, body, "system:controller:ttl-controller", "ClusterRole");

    // system:controller:ttl-after-finished-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:ttl-after-finished-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:ttl-after-finished-controller", "uid": "00000000-0000-0000-0000-000000000060", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["get","list","watch","delete"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:ttl-after-finished-controller",
        "ClusterRole"
    );

    // system:controller:endpointslice-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:endpointslice-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:endpointslice-controller", "uid": "00000000-0000-0000-0000-000000000061", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["pods","services","endpoints","nodes"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:endpointslice-controller",
        "ClusterRole"
    );

    // system:controller:endpointslicemirroring-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:endpointslicemirroring-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:endpointslicemirroring-controller", "uid": "00000000-0000-0000-0000-000000000062", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["endpoints","endpointslices","services"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:endpointslicemirroring-controller",
        "ClusterRole"
    );

    // system:controller:ephemeral-volume-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:ephemeral-volume-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:ephemeral-volume-controller", "uid": "00000000-0000-0000-0000-000000000063", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["persistentvolumeclaims"], "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:ephemeral-volume-controller",
        "ClusterRole"
    );

    // system:controller:storage-version-garbage-collector
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:storage-version-garbage-collector",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:storage-version-garbage-collector", "uid": "00000000-0000-0000-0000-000000000064", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["internal.apiserver.k8s.io"], "resources": ["storageversions","storageversions/status"], "verbs": ["get","list","watch","patch","update","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:storage-version-garbage-collector",
        "ClusterRole"
    );

    // system:controller:legacy-service-account-token-cleaner
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:legacy-service-account-token-cleaner",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:legacy-service-account-token-cleaner", "uid": "00000000-0000-0000-0000-000000000065", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["secrets"], "verbs": ["get","list","watch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:legacy-service-account-token-cleaner",
        "ClusterRole"
    );

    // system:controller:root-ca-cert-publisher
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:root-ca-cert-publisher",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:root-ca-cert-publisher", "uid": "00000000-0000-0000-0000-000000000066", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["configmaps"], "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:root-ca-cert-publisher",
        "ClusterRole"
    );

    // -----------------------------------------------------------------------
    // ClusterRole: system:auth-delegator — lets extension API servers (e.g. an
    // aggregated sample-apiserver or CRD conversion webhook) delegate
    // authn/authz decisions back to us via TokenReview/SubjectAccessReview.
    // Without this, a RoleBinding/ClusterRoleBinding an extension apiserver's
    // own manifest creates against this ClusterRole grants nothing, and its
    // in-cluster lookups (e.g. requestheader-client-ca-file from the
    // extension-apiserver-authentication configmap) fail Forbidden instead of
    // the tolerated NotFound, which is treated as fatal and crash-loops it.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:auth-delegator");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:auth-delegator", "uid": "00000000-0000-0000-0000-000000000068", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"] },
            { "apiGroups": ["authorization.k8s.io"], "resources": ["subjectaccessreviews"], "verbs": ["create"] }
        ]
    });
    put!(key, body, "system:auth-delegator", "ClusterRole");

    // -----------------------------------------------------------------------
    // Role: kube-system/extension-apiserver-authentication-reader — grants
    // read access to the extension-apiserver-authentication configmap.
    // Extension apiservers bind their own service account to this Role name
    // (it must already exist, same as real kube-apiserver's bootstrap
    // policy) so their RunOnce lookup of that configmap gets a tolerated
    // NotFound instead of a fatal Forbidden.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(
        GROUP,
        "roles",
        Some("kube-system"),
        "extension-apiserver-authentication-reader",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": { "name": "extension-apiserver-authentication-reader", "namespace": "kube-system", "uid": "00000000-0000-0000-0000-000000000069", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["extension-apiserver-authentication"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(
        key,
        body,
        "kube-system/extension-apiserver-authentication-reader",
        "Role"
    );

    Ok(())
}

/// Parse repeated `--node-kubelet-port <node-name>=<host-port>` entries into a name -> port
/// map. Errors loud on any malformed entry (missing '=', non-numeric port) rather than
/// silently dropping it — a typo here would otherwise surface much later as a mysterious
/// exec/log/attach misroute to the wrong node instead of a clear startup failure.
fn parse_node_kubelet_ports(
    entries: &[String],
) -> anyhow::Result<std::collections::HashMap<String, u16>> {
    let mut map = std::collections::HashMap::new();
    for entry in entries {
        let (name, port_str) = entry.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("--node-kubelet-port must be NAME=PORT, got {entry:?}")
        })?;
        let port: u16 = port_str
            .parse()
            .map_err(|e| anyhow::anyhow!("--node-kubelet-port: invalid port in {entry:?}: {e}"))?;
        map.insert(name.to_owned(), port);
    }
    Ok(map)
}

/// Parse "https://HOST:PORT" into (host, port). Returns ("127.0.0.1", 6443) on any parse error.
fn parse_advertise_address(addr: &str) -> (String, u16) {
    let without_scheme = addr
        .strip_prefix("https://")
        .or_else(|| addr.strip_prefix("http://"))
        .unwrap_or(addr);
    // Handle IPv6 bracketed addresses like [::1]:6443.
    if let Some(bracket_end) = without_scheme.find(']') {
        let host = without_scheme[1..bracket_end].to_owned();
        let port = without_scheme
            .get(bracket_end + 2..)
            .and_then(|p| p.parse().ok())
            .unwrap_or(6443);
        return (host, port);
    }
    match without_scheme.rsplit_once(':') {
        Some((host, port_str)) => {
            let port = port_str.parse().unwrap_or(6443);
            (host.to_owned(), port)
        }
        None => ("127.0.0.1".to_owned(), 6443),
    }
}

/// Derive the ClusterIPs for the two well-known bootstrap Services from the configured
/// `--service-cluster-ip-range`: `default/kubernetes` gets the first host (kubeadm's
/// `.1` convention), `kube-system/kube-dns` gets the tenth host (kubeadm's `.10`
/// convention). Both must land inside the configured range — a Service outside its
/// ServiceCIDR fails the startup coherence check, and kube-proxy/kubelet would program
/// rules for an IP the range doesn't actually own.
///
/// An empty range only disables *user* Service clusterIP auto-allocation (see
/// `--service-cluster-ip-range`'s doc comment in args.rs); the two bootstrap Services
/// still need concrete IPs, so fall back to the historical default range in that case.
fn bootstrap_service_ips(
    service_cluster_ip_range: &str,
) -> anyhow::Result<(std::net::Ipv4Addr, std::net::Ipv4Addr)> {
    let range = if service_cluster_ip_range.is_empty() {
        "10.96.0.0/12"
    } else {
        service_cluster_ip_range
    };
    let allocator = state::ServiceIpAllocator::from_cidr(range)
        .map_err(|e| anyhow::anyhow!("invalid --service-cluster-ip-range '{range}': {e}"))?;
    let kubernetes_ip = allocator.nth_host(1).map_err(|e| {
        anyhow::anyhow!(
            "--service-cluster-ip-range '{range}' too small for kubernetes Service: {e}"
        )
    })?;
    let kube_dns_ip = allocator.nth_host(10).map_err(|e| {
        anyhow::anyhow!("--service-cluster-ip-range '{range}' too small for kube-dns Service: {e}")
    })?;
    Ok((kubernetes_ip, kube_dns_ip))
}

async fn seed_services(
    store: &SqliteStore,
    apiserver_ip: &str,
    apiserver_port: u16,
    service_cluster_ip_range: &str,
) -> anyhow::Result<()> {
    use bytes::Bytes;
    use u7s_store::Store;

    let (kubernetes_cluster_ip, kube_dns_cluster_ip) =
        bootstrap_service_ips(service_cluster_ip_range)?;

    // default/kubernetes — reaches the API server from inside pods via
    // in-cluster DNS (kubernetes.default.svc.cluster.local:443 → 10.96.0.1).
    let k8s_key = keys::object_key("services", "default", "kubernetes");
    let k8s_body = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "kubernetes",
            "namespace": "default",
            "uid": "00000000-0000-0000-0000-000000000020",
            "creationTimestamp": "2024-01-01T00:00:00Z",
            "labels": { "component": "apiserver", "provider": "kubernetes" }
        },
        "spec": {
            "clusterIP": kubernetes_cluster_ip.to_string(),
            "ports": [{ "name": "https", "port": 443, "targetPort": 6443, "protocol": "TCP" }],
            "sessionAffinity": "None",
            "type": "ClusterIP"
        }
    });
    match store
        .put(&k8s_key, Bytes::from(k8s_body.to_string()), Some(0))
        .await
    {
        Ok(_) => tracing::info!("seeded Service: default/kubernetes"),
        Err(u7s_store::StoreError::AlreadyExists { .. }) => {}
        Err(e) => return Err(anyhow::anyhow!("seed Service default/kubernetes: {e}")),
    }

    // kube-system/kube-dns itself is applied later, from the vendored CoreDNS bundle (see
    // bootstrap_apply.rs), so the whole CoreDNS install lives in one manifest. Its clusterIP
    // is still reserved here in the allocator's own sentinel keyspace ahead of that apply.
    // Without this, allocate_service_ip (hint starts at offset 2, +1 per call) has no
    // idea offset 10 is taken and will hand it to the 9th ordinary dynamic Service,
    // colliding with kube-dns's VIP.
    let dns_ip_sentinel_key = format!("{}{}", state::SERVICE_IP_PREFIX, kube_dns_cluster_ip);
    match store
        .put(
            &dns_ip_sentinel_key,
            Bytes::from_static(b"{\"kind\":\"ServiceIPAllocation\"}"),
            Some(0),
        )
        .await
    {
        Ok(_) => {}
        Err(u7s_store::StoreError::AlreadyExists { .. }) => {}
        Err(e) => return Err(anyhow::anyhow!("seed kube-dns clusterIP sentinel: {e}")),
    }

    // default/kubernetes Endpoints — controllers (e.g. endpoint controller, admission webhooks)
    // watch this object to locate the apiserver. Without it they log errors and may fail to start.
    let ep_key = keys::object_key("endpoints", "default", "kubernetes");
    let ep_body = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Endpoints",
        "metadata": {
            "name": "kubernetes",
            "namespace": "default",
            "uid": "00000000-0000-0000-0000-000000000022",
            "creationTimestamp": "2024-01-01T00:00:00Z",
            "labels": { "endpointslice.kubernetes.io/skip-mirror": "true" }
        },
        "subsets": [{
            "addresses": [{ "ip": apiserver_ip }],
            "ports": [{ "name": "https", "port": 443, "protocol": "TCP" }]
        }]
    });
    match store
        .put(&ep_key, Bytes::from(ep_body.to_string()), Some(0))
        .await
    {
        Ok(_) => tracing::info!("seeded Endpoints: default/kubernetes"),
        Err(u7s_store::StoreError::AlreadyExists { .. }) => {}
        Err(e) => return Err(anyhow::anyhow!("seed Endpoints default/kubernetes: {e}")),
    }

    // default/kubernetes EndpointSlice — kube-proxy (added in k8s 1.34+) uses EndpointSlices
    // exclusively. The Endpoints above carry skip-mirror:true so the mirroring controller won't
    // create a slice; we seed it directly, matching upstream apiserver behaviour where the
    // apiserver's own reconciler calls EnsureEndpointSliceFromEndpoints on each cycle.
    // The address here must be routable from inside pods — use the advertised IP, which callers
    // set to host.lima.internal's IP when running in a lima VM so kube-proxy's IPVS rule
    // programs 10.96.0.1:443 → <host-ip>:6443 rather than → 127.0.0.1:6443 (the VM loopback).
    let eps_key = keys::group_object_key(
        "discovery.k8s.io",
        "endpointslices",
        Some("default"),
        "kubernetes",
    );
    let eps_body = serde_json::json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": "kubernetes",
            "namespace": "default",
            "uid": "00000000-0000-0000-0000-000000000023",
            "creationTimestamp": "2024-01-01T00:00:00Z",
            "labels": {
                "kubernetes.io/service-name": "kubernetes",
                "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io"
            }
        },
        "addressType": "IPv4",
        "endpoints": [{
            "addresses": [apiserver_ip],
            "conditions": { "ready": true, "serving": true, "terminating": false }
        }],
        "ports": [{ "name": "https", "port": apiserver_port, "protocol": "TCP" }]
    });
    match store
        .put(&eps_key, Bytes::from(eps_body.to_string()), Some(0))
        .await
    {
        Ok(_) => tracing::info!("seeded EndpointSlice: default/kubernetes"),
        Err(u7s_store::StoreError::AlreadyExists { .. }) => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
                "seed EndpointSlice default/kubernetes: {e}"
            ))
        }
    }

    Ok(())
}

/// Extract all IP addresses from the kubernetes Endpoints subsets.
pub fn kubernetes_endpoints_addrs(ep: &serde_json::Value) -> Vec<String> {
    ep["subsets"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|s| s["addresses"].as_array().into_iter().flatten())
        .filter_map(|a| a["ip"].as_str().map(str::to_owned))
        .collect()
}

/// Extract all IP addresses from the kubernetes EndpointSlice endpoints array.
pub fn kubernetes_endpointslice_addrs(eps: &serde_json::Value) -> Vec<String> {
    eps["endpoints"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|e| e["addresses"].as_array().into_iter().flatten())
        .filter_map(|a| a.as_str().map(str::to_owned))
        .collect()
}

/// Reconcile the kubernetes Endpoints to match the kubernetes EndpointSlice.
///
/// kube-controller-manager's endpointslice-controller runs inside the Lima VM and
/// patches the kubernetes EndpointSlice with the apiserver address from its kubeconfig
/// (e.g. the Lima VM gateway IP 192.168.5.2) and the actual apiserver port (e.g. 6445).
/// This leaves the EndpointSlice with different addresses and ports than the Endpoints
/// (which only has the loopback 127.0.0.1 and port 443 from seeding), causing the
/// conformance test to fail with:
///   "EndpointSlice addresses do not match Endpoints addresses"
///   "EndpointSlice ports do not match Endpoints ports"
///
/// The correct fix is to update the Endpoints to match the EndpointSlice addresses AND
/// ports. This ensures:
///   1. The conformance test passes (Endpoints and EndpointSlice agree on both)
///   2. kube-proxy routing works (EndpointSlice unchanged; 192.168.5.2:6445 stays as backend)
///
/// Concretely: when KCM sets EndpointSlice to addresses=[127.0.0.1, 192.168.5.2], port=6445,
/// this reconciler updates Endpoints to the same addresses and port, making them equal.
pub async fn reconcile_kubernetes_endpointslice(store: &SqliteStore) -> bool {
    use bytes::Bytes;
    use u7s_store::Store;

    let ep_key = keys::object_key("endpoints", "default", "kubernetes");
    let eps_key = keys::group_object_key(
        "discovery.k8s.io",
        "endpointslices",
        Some("default"),
        "kubernetes",
    );

    let ep_obj = match store.get(&ep_key).await {
        Ok(Some(o)) => o,
        Ok(None) => return true,
        Err(_) => return false,
    };
    let ep_revision = ep_obj.revision;
    let mut ep: serde_json::Value = match serde_json::from_slice::<serde_json::Value>(&ep_obj.value)
    {
        Ok(v) => v,
        Err(_) => return false,
    };

    let eps = match store.get(&eps_key).await {
        Ok(Some(o)) => match serde_json::from_slice::<serde_json::Value>(&o.value) {
            Ok(v) => v,
            Err(_) => return false,
        },
        Ok(None) => return true,
        Err(_) => return false,
    };

    let mut ep_addrs = kubernetes_endpoints_addrs(&ep);
    let mut eps_addrs = kubernetes_endpointslice_addrs(&eps);
    ep_addrs.sort();
    eps_addrs.sort();

    // Extract ports from the EndpointSlice (top-level ports field).
    let eps_ports = eps["ports"].as_array().cloned().unwrap_or_default();

    // Extract ports from the Endpoints (first subset ports field).
    let ep_ports = ep["subsets"]
        .as_array()
        .and_then(|s| s.first())
        .and_then(|s| s["ports"].as_array())
        .cloned()
        .unwrap_or_default();

    // Build sorted port-number lists for comparison.
    let mut ep_port_nums: Vec<u64> = ep_ports.iter().filter_map(|p| p["port"].as_u64()).collect();
    let mut eps_port_nums: Vec<u64> = eps_ports
        .iter()
        .filter_map(|p| p["port"].as_u64())
        .collect();
    ep_port_nums.sort();
    eps_port_nums.sort();

    if ep_addrs == eps_addrs && ep_port_nums == eps_port_nums {
        return true;
    }

    // Update Endpoints subsets to match EndpointSlice addresses and ports.
    let target_addr_objects: Vec<serde_json::Value> = eps_addrs
        .iter()
        .map(|ip| serde_json::json!({ "ip": ip }))
        .collect();

    ep["subsets"] = serde_json::json!([{
        "addresses": target_addr_objects,
        "ports": eps_ports
    }]);

    store
        .put(&ep_key, Bytes::from(ep.to_string()), Some(ep_revision))
        .await
        .is_ok()
}

/// Update `status.used` on every ResourceQuota in the store to reflect live object counts.
///
/// Lists all ResourceQuota objects, computes usage via `count_quota_usage`, and writes back
/// only when `status.used` differs from the live count. Uses optimistic concurrency
/// (`Some(revision)`) so a concurrent write wins and the next reconcile cycle corrects it.
///
/// Returns `true` if no storage errors occurred, `false` otherwise.
pub async fn reconcile_quota_status(store: &SqliteStore) -> bool {
    use bytes::Bytes;
    use u7s_store::{ListOptions, Store};

    let prefix = keys::group_list_prefix("", "resourcequotas", None);
    let quotas = match store.list(&prefix, ListOptions::default()).await {
        Ok(resp) => resp.items,
        Err(e) => {
            tracing::warn!("quota reconciler: failed to list ResourceQuotas: {e}");
            return false;
        }
    };

    let mut all_ok = true;
    for item in quotas {
        let revision = item.revision;
        let mut quota: serde_json::Value = match serde_json::from_slice(&item.value) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let key = item.key.clone();

        let live_used = quota::count_quota_usage(store, &quota).await;

        // Compare only the keys we computed against current values for those same keys.
        // KCM writes status.used for all hard-limit resources (including CPU/memory).
        // We only compute count-based resources (pods, services, …).  Comparing or
        // replacing the full map would clobber KCM's CPU/memory entries.
        let current_for_live_keys: std::collections::BTreeMap<String, String> = quota["status"]
            ["used"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter(|(k, _)| live_used.contains_key(k.as_str()))
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("0").to_string()))
                    .collect()
            })
            .unwrap_or_default();

        if live_used == current_for_live_keys {
            continue;
        }

        // Merge our computed values into the existing used map; do not replace keys
        // that KCM (or another writer) set for resources we do not compute.
        if let Some(used_map) = quota["status"]["used"].as_object_mut() {
            for (k, v) in &live_used {
                used_map.insert(k.clone(), serde_json::Value::String(v.clone()));
            }
        } else {
            // No existing used map — create one from our values.
            let used_json: serde_json::Value = live_used
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect();
            quota["status"]["used"] = used_json;
        }

        if let Err(e) = store
            .put(&key, Bytes::from(quota.to_string()), Some(revision))
            .await
        {
            tracing::warn!("quota reconciler: failed to update {key}: {e}");
            all_ok = false;
        }
    }

    all_ok
}

/// Publish/reconcile `kube-system/extension-apiserver-authentication` so aggregated
/// backends (e.g. metrics-server's `ConfigMapCAFileContent` informer) stop retrying
/// against a missing ConfigMap. Mirrors upstream's `clusterauthenticationtrust`
/// controller (`pkg/controlplane/controller/clusterauthenticationtrust`), which re-syncs
/// this ConfigMap whenever its `dynamiccertificates.CAContentProvider` sees new CA
/// content — implemented here as a polling reconcile loop, not a one-shot seed, so this
/// doesn't need to be revisited if/when u7s ever adds CA rotation (both CA certs are read
/// fresh from disk on every tick).
///
/// Populates the real front-proxy trust anchor: `requestheader-client-ca-file` (the
/// dedicated proxy-client CA, `TlsMaterial::proxy_client_cert_pem`'s doc) plus the fixed
/// `requestheader-username-headers`/`-group-headers`/`-extra-headers-prefix`/
/// `-allowed-names` u7s always uses (see `handlers::aggregation::proxy_to_backend`) —
/// matching upstream's own `clusterauthenticationtrust` controller output. `client-ca-file`
/// (the main cluster CA) is unrelated to request-header auth but is populated for the same
/// reason upstream does: some aggregated backends mirror it into their own `--client-ca-file`
/// for direct x509 auth of non-proxied callers.
///
/// Returns `true` on success (including "already up to date"), `false` on any I/O or
/// store error, so the caller's exponential-backoff loop can distinguish real failures
/// from no-op ticks.
pub async fn reconcile_extension_apiserver_authentication(
    store: &SqliteStore,
    ca_cert_path: &str,
    proxy_client_ca_cert_path: &str,
) -> bool {
    use bytes::Bytes;
    use u7s_store::Store;

    let ca_cert_der = match std::fs::read(ca_cert_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                "extension-apiserver-authentication reconciler: failed to read CA cert \
                 {ca_cert_path}: {e}"
            );
            return false;
        }
    };
    let ca_pem =
        String::from_utf8_lossy(&tls::pem_encode("CERTIFICATE", &ca_cert_der)).into_owned();

    let proxy_client_ca_der = match std::fs::read(proxy_client_ca_cert_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                "extension-apiserver-authentication reconciler: failed to read front-proxy \
                 CA cert {proxy_client_ca_cert_path}: {e}"
            );
            return false;
        }
    };
    let proxy_client_ca_pem =
        String::from_utf8_lossy(&tls::pem_encode("CERTIFICATE", &proxy_client_ca_der)).into_owned();

    let key = keys::object_key(
        "configmaps",
        "kube-system",
        "extension-apiserver-authentication",
    );
    let (expected_revision, mut body) = match store.get(&key).await {
        Ok(Some(obj)) => {
            let existing: serde_json::Value = match serde_json::from_slice(&obj.value) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        "extension-apiserver-authentication reconciler: failed to parse \
                         existing ConfigMap: {e}"
                    );
                    return false;
                }
            };
            if existing["data"]["client-ca-file"].as_str() == Some(ca_pem.as_str())
                && existing["data"]["requestheader-client-ca-file"].as_str()
                    == Some(proxy_client_ca_pem.as_str())
            {
                return true;
            }
            (obj.revision, existing)
        }
        Ok(None) => (
            0,
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "extension-apiserver-authentication",
                    "namespace": "kube-system",
                    "creationTimestamp": "2024-01-01T00:00:00Z"
                },
                "data": {}
            }),
        ),
        Err(e) => {
            tracing::warn!(
                "extension-apiserver-authentication reconciler: failed to read ConfigMap: {e}"
            );
            return false;
        }
    };
    body["data"]["client-ca-file"] = serde_json::Value::String(ca_pem);
    body["data"]["requestheader-client-ca-file"] = serde_json::Value::String(proxy_client_ca_pem);
    body["data"]["requestheader-allowed-names"] =
        serde_json::Value::String("[\"front-proxy-client\"]".to_owned());
    body["data"]["requestheader-extra-headers-prefix"] =
        serde_json::Value::String("[\"X-Remote-Extra-\"]".to_owned());
    body["data"]["requestheader-group-headers"] =
        serde_json::Value::String("[\"X-Remote-Group\"]".to_owned());
    body["data"]["requestheader-username-headers"] =
        serde_json::Value::String("[\"X-Remote-User\"]".to_owned());

    match store
        .put(&key, Bytes::from(body.to_string()), Some(expected_revision))
        .await
    {
        Ok(_) => {
            tracing::info!(
                "reconciled ConfigMap kube-system/extension-apiserver-authentication \
                 (client-ca-file / requestheader-* updated)"
            );
            true
        }
        Err(e) => {
            tracing::warn!(
                "extension-apiserver-authentication reconciler: failed to write ConfigMap: {e}"
            );
            false
        }
    }
}

async fn seed_serviceaccounts(store: &SqliteStore) -> anyhow::Result<()> {
    use bytes::Bytes;
    use u7s_store::Store;

    // Static UIDs — no uuid crate needed for seeded objects; deterministic values
    // are required so token recipients can correlate a JWT's kubernetes.io.serviceaccount.uid
    // claim back to the ServiceAccount object. Without a UID the claim is empty, which
    // violates the Kubernetes token projection contract.
    const NAMESPACES: &[(&str, &str)] = &[
        ("default", "00000000-0000-0000-0001-000000000001"),
        ("kube-system", "00000000-0000-0000-0001-000000000002"),
        ("kube-node-lease", "00000000-0000-0000-0001-000000000003"),
        ("kube-public", "00000000-0000-0000-0001-000000000004"),
    ];
    for (ns, uid) in NAMESPACES {
        let key = keys::object_key("serviceaccounts", ns, "default");
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": "default",
                "namespace": ns,
                "uid": uid,
                "creationTimestamp": "2024-01-01T00:00:00Z"
            }
        });
        match store
            .put(&key, Bytes::from(body.to_string()), Some(0))
            .await
        {
            Ok(_) => tracing::info!("seeded ServiceAccount: {ns}/default"),
            Err(u7s_store::StoreError::AlreadyExists { .. }) => {}
            Err(e) => return Err(anyhow::anyhow!("seed ServiceAccount {ns}/default: {e}")),
        }
    }
    Ok(())
}

/// Seed the `kube-root-ca.crt` ConfigMap (data: `ca.crt` = the cluster CA bundle) into
/// every namespace that exists at boot. See the call site in `main` for why this must
/// happen before the server starts accepting requests.
async fn seed_kube_root_ca(store: &SqliteStore, ca_cert_der: &[u8]) -> anyhow::Result<()> {
    use bytes::Bytes;
    use u7s_store::Store;

    const NAMESPACES: &[&str] = &["default", "kube-system", "kube-node-lease", "kube-public"];
    let ca_pem = String::from_utf8_lossy(&tls::pem_encode("CERTIFICATE", ca_cert_der)).into_owned();

    for ns in NAMESPACES {
        let key = keys::object_key("configmaps", ns, "kube-root-ca.crt");
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "kube-root-ca.crt",
                "namespace": ns,
                "creationTimestamp": "2024-01-01T00:00:00Z"
            },
            "data": { "ca.crt": ca_pem }
        });
        match store
            .put(&key, Bytes::from(body.to_string()), Some(0))
            .await
        {
            Ok(_) => tracing::info!("seeded ConfigMap: {ns}/kube-root-ca.crt"),
            Err(u7s_store::StoreError::AlreadyExists { .. }) => {}
            Err(e) => return Err(anyhow::anyhow!("seed ConfigMap {ns}/kube-root-ca.crt: {e}")),
        }
    }
    Ok(())
}

/// Seed the default API Priority and Fairness resources.
///
/// A real kube-apiserver seeds these via its `priority-and-fairness-config-consumer`
/// post-start hook. We don't have that hook, so we seed them at startup instead.
/// Without these defaults, the APF conformance test times out waiting for the state
/// to converge (FlowSchema .status.conditions[Ready] never becomes True without the
/// PriorityLevelConfiguration it references existing).
async fn seed_flowcontrol(store: &SqliteStore) -> anyhow::Result<()> {
    use bytes::Bytes;
    use u7s_store::Store;

    const GROUP: &str = "flowcontrol.apiserver.k8s.io";
    const TS: &str = "2024-01-01T00:00:00Z";

    // Seed 8 default PriorityLevelConfigurations.
    // Uses unconditional put (None version) so the canonical values are
    // always written on startup, just like seed_rbac does for ClusterRoles.

    // exempt — system:masters requests bypass all queuing
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "exempt");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "exempt", "uid": "00000000-0000-0000-0000-000000000100",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Exempt", "exempt": {} },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration exempt: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: exempt");

    // catch-all — last-resort bucket for unclassified requests
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "catch-all");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "catch-all", "uid": "00000000-0000-0000-0000-000000000101",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 5,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 128, "handSize": 6, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration catch-all: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: catch-all");

    // system — for kube-system service accounts
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "system");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "system", "uid": "00000000-0000-0000-0000-000000000102",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 30,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 64, "handSize": 6, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration system: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: system");

    // leader-election — for controller leader elections
    let key = keys::group_object_key(
        GROUP,
        "prioritylevelconfigurations",
        None,
        "leader-election",
    );
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "leader-election", "uid": "00000000-0000-0000-0000-000000000103",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 10,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 16, "handSize": 4, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration leader-election: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: leader-election");

    // workload-high — for high-priority workload controllers
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "workload-high");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "workload-high", "uid": "00000000-0000-0000-0000-000000000104",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 40,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 128, "handSize": 6, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration workload-high: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: workload-high");

    // workload-low — for low-priority workload controllers
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "workload-low");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "workload-low", "uid": "00000000-0000-0000-0000-000000000105",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 100,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 128, "handSize": 6, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration workload-low: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: workload-low");

    // global-default — catch-most bucket for authenticated requests
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "global-default");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "global-default", "uid": "00000000-0000-0000-0000-000000000106",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 20,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 128, "handSize": 6, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration global-default: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: global-default");

    // node-high — for node-critical requests (node status, kubelet heartbeat)
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "node-high");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "node-high", "uid": "00000000-0000-0000-0000-000000000107",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 40,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 64, "handSize": 6, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration node-high: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: node-high");

    // Seed 13 default FlowSchemas.
    // Each references a PriorityLevelConfiguration by name.

    // exempt — for system:masters; no queuing at all
    let key = keys::group_object_key(GROUP, "flowschemas", None, "exempt");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "exempt", "uid": "00000000-0000-0000-0000-000000000200",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 1,
            "priorityLevelConfiguration": { "name": "exempt" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:masters" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema exempt: {e}"))?;
    tracing::info!("seeded FlowSchema: exempt");

    // probes — for unauthenticated health check probes
    let key = keys::group_object_key(GROUP, "flowschemas", None, "probes");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "probes", "uid": "00000000-0000-0000-0000-000000000201",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 2,
            "priorityLevelConfiguration": { "name": "exempt" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:unauthenticated" } }],
                        "nonResourceRules": [{ "verbs": ["get"],
                                               "nonResourceURLs": ["/healthz", "/readyz", "/livez"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema probes: {e}"))?;
    tracing::info!("seeded FlowSchema: probes");

    // system-leader-election — for kcm/scheduler leader elections
    let key = keys::group_object_key(GROUP, "flowschemas", None, "system-leader-election");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "system-leader-election", "uid": "00000000-0000-0000-0000-000000000202",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 100,
            "priorityLevelConfiguration": { "name": "leader-election" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "ServiceAccount",
                                       "serviceAccount": { "name": "*", "namespace": "kube-system" } }],
                        "resourceRules": [{ "verbs": ["get", "create", "update"],
                                            "apiGroups": ["coordination.k8s.io"],
                                            "resources": ["leases"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema system-leader-election: {e}"))?;
    tracing::info!("seeded FlowSchema: system-leader-election");

    // endpoint-controller — endpoints/endpointslice controllers
    let key = keys::group_object_key(GROUP, "flowschemas", None, "endpoint-controller");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "endpoint-controller", "uid": "00000000-0000-0000-0000-000000000203",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 150,
            "priorityLevelConfiguration": { "name": "workload-high" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [
                            { "kind": "ServiceAccount", "serviceAccount": { "name": "endpoint-controller", "namespace": "kube-system" } },
                            { "kind": "ServiceAccount", "serviceAccount": { "name": "endpointslice-controller", "namespace": "kube-system" } },
                            { "kind": "ServiceAccount", "serviceAccount": { "name": "endpointslicemirroring-controller", "namespace": "kube-system" } }
                        ],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema endpoint-controller: {e}"))?;
    tracing::info!("seeded FlowSchema: endpoint-controller");

    // workload-leader-election — for workload-level leader elections
    let key = keys::group_object_key(GROUP, "flowschemas", None, "workload-leader-election");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "workload-leader-election", "uid": "00000000-0000-0000-0000-000000000204",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 200,
            "priorityLevelConfiguration": { "name": "leader-election" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "ServiceAccount",
                                       "serviceAccount": { "name": "*", "namespace": "kube-system" } }],
                        "resourceRules": [{ "verbs": ["get", "create", "update"],
                                            "apiGroups": ["coordination.k8s.io"],
                                            "resources": ["leases"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema workload-leader-election: {e}"))?;
    tracing::info!("seeded FlowSchema: workload-leader-election");

    // system-node-high — high-priority node requests (heartbeat, status updates)
    let key = keys::group_object_key(GROUP, "flowschemas", None, "system-node-high");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "system-node-high", "uid": "00000000-0000-0000-0000-000000000205",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 400,
            "priorityLevelConfiguration": { "name": "node-high" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:nodes" } }],
                        "resourceRules": [
                            { "verbs": ["get", "create", "update", "patch"],
                              "apiGroups": [""], "resources": ["nodes", "nodes/status"] },
                            { "verbs": ["get", "create", "update", "patch"],
                              "apiGroups": ["coordination.k8s.io"], "resources": ["leases"] }
                        ] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema system-node-high: {e}"))?;
    tracing::info!("seeded FlowSchema: system-node-high");

    // system-nodes — general node requests
    let key = keys::group_object_key(GROUP, "flowschemas", None, "system-nodes");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "system-nodes", "uid": "00000000-0000-0000-0000-000000000206",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 500,
            "priorityLevelConfiguration": { "name": "system" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:nodes" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema system-nodes: {e}"))?;
    tracing::info!("seeded FlowSchema: system-nodes");

    // kube-controller-manager — KCM requests
    let key = keys::group_object_key(GROUP, "flowschemas", None, "kube-controller-manager");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "kube-controller-manager", "uid": "00000000-0000-0000-0000-000000000207",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 800,
            "priorityLevelConfiguration": { "name": "workload-high" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "User", "user": { "name": "system:kube-controller-manager" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema kube-controller-manager: {e}"))?;
    tracing::info!("seeded FlowSchema: kube-controller-manager");

    // kube-scheduler — scheduler requests
    let key = keys::group_object_key(GROUP, "flowschemas", None, "kube-scheduler");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "kube-scheduler", "uid": "00000000-0000-0000-0000-000000000208",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 800,
            "priorityLevelConfiguration": { "name": "workload-high" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "User", "user": { "name": "system:kube-scheduler" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema kube-scheduler: {e}"))?;
    tracing::info!("seeded FlowSchema: kube-scheduler");

    // kube-system-service-accounts — all service accounts in kube-system
    let key = keys::group_object_key(GROUP, "flowschemas", None, "kube-system-service-accounts");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "kube-system-service-accounts", "uid": "00000000-0000-0000-0000-000000000209",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 900,
            "priorityLevelConfiguration": { "name": "workload-high" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "ServiceAccount",
                                       "serviceAccount": { "name": "*", "namespace": "kube-system" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema kube-system-service-accounts: {e}"))?;
    tracing::info!("seeded FlowSchema: kube-system-service-accounts");

    // service-accounts — all service accounts in all namespaces
    let key = keys::group_object_key(GROUP, "flowschemas", None, "service-accounts");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "service-accounts", "uid": "00000000-0000-0000-0000-000000000210",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 9000,
            "priorityLevelConfiguration": { "name": "workload-low" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:serviceaccounts" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema service-accounts: {e}"))?;
    tracing::info!("seeded FlowSchema: service-accounts");

    // global-default — catch-most for authenticated users
    let key = keys::group_object_key(GROUP, "flowschemas", None, "global-default");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "global-default", "uid": "00000000-0000-0000-0000-000000000211",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 9900,
            "priorityLevelConfiguration": { "name": "global-default" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:authenticated" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema global-default: {e}"))?;
    tracing::info!("seeded FlowSchema: global-default");

    // catch-all — last resort for unauthenticated or unmatched requests
    let key = keys::group_object_key(GROUP, "flowschemas", None, "catch-all");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "catch-all", "uid": "00000000-0000-0000-0000-000000000212",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 10000,
            "priorityLevelConfiguration": { "name": "catch-all" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:unauthenticated" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema catch-all: {e}"))?;
    tracing::info!("seeded FlowSchema: catch-all");

    Ok(())
}

/// Seed the default `kubernetes` ServiceCIDR object.
///
/// A real kube-apiserver creates this via `service-cidr-controller` in KCM.
/// u7s seeds it at startup (consistent with how default/kubernetes Service and
/// RBAC bootstrap objects are seeded) so the conformance spec
/// "[sig-network] ServiceCIDR and IPAddress API should support ServiceCIDR API
/// operations" does not fail instantly with "ServiceCIDR kubernetes not found".
async fn seed_servicecidrs(store: &SqliteStore, service_cidr: &str) -> anyhow::Result<()> {
    use bytes::Bytes;
    use u7s_store::Store;

    if service_cidr.is_empty() {
        return Ok(());
    }

    let key = keys::group_object_key("networking.k8s.io", "servicecidrs", None, "kubernetes");
    let body = serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "ServiceCIDR",
        "metadata": {
            "name": "kubernetes",
            "uid": "00000000-0000-0000-0000-000000000030",
            "creationTimestamp": "2024-01-01T00:00:00Z"
        },
        "spec": {
            "cidrs": [service_cidr]
        },
        "status": {
            "conditions": [{
                "type": "Ready",
                "status": "True",
                "lastTransitionTime": "2024-01-01T00:00:00Z",
                "reason": "AppliedCIDR",
                "message": "Kubernetes Service CIDR is ready"
            }]
        }
    });
    match store
        .put(&key, Bytes::from(body.to_string()), Some(0))
        .await
    {
        Ok(_) => tracing::info!("seeded ServiceCIDR: kubernetes"),
        Err(u7s_store::StoreError::AlreadyExists { .. }) => {}
        Err(e) => return Err(anyhow::anyhow!("seed ServiceCIDR kubernetes: {e}")),
    }

    Ok(())
}

/// Disable Nagle's algorithm on an accepted connection.
///
/// Watch clients (e.g. KCM's ConsistencyStore) do read-after-write: they check their
/// informer cache immediately after a write response, and only advance that cache on
/// the trailing watch BOOKMARK. Nagle buffering can hold the BOOKMARK on the wire long
/// enough for the client to recheck first, see a stale RV, and retry — which, under a
/// fast enough round-trip (e.g. protobuf-encoded traffic), can retry before the
/// BOOKMARK ever lands, causing the client to repeat the same write forever.
fn configure_accepted_socket(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::warn!("failed to set TCP_NODELAY on accepted connection: {e}");
    }
}

async fn serve_tls(
    listener: TcpListener,
    app: Router,
    server_config: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(server_config);
    // Auto-negotiating builder: dispatches each connection to HTTP/1.1 or HTTP/2 by
    // peeking at the first bytes for the HTTP/2 connection preface. Clients that
    // saw h2 win ALPN (rustls ServerConfig.alpn_protocols in tls.rs) send that
    // preface immediately, so in practice ALPN is what steers this — but the
    // dispatch itself works from the wire, independent of the ALPN result.
    let conn_builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    tracing::info!("listening on {}", listener.local_addr()?);

    loop {
        let (tcp_stream, _peer) = listener.accept().await?;
        configure_accepted_socket(&tcp_stream);
        let acceptor = acceptor.clone();
        let app = app.clone();
        let conn_builder = conn_builder.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("TLS accept error: {e}");
                    return;
                }
            };

            // Extract the peer certificate once per connection, then share it
            // across all requests on this connection via an Arc.
            let peer_cert: Arc<Option<PeerCertificate>> = Arc::new(
                tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .map(|c| PeerCertificate(c.as_ref().to_vec())),
            );

            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let service = hyper::service::service_fn(move |mut req: axum::http::Request<_>| {
                let peer_cert = Arc::clone(&peer_cert);
                let mut app = app.clone();
                async move {
                    if let Some(cert) = peer_cert.as_ref().as_ref() {
                        req.extensions_mut().insert(cert.clone());
                    }
                    Ok::<_, std::convert::Infallible>(app.call(req).await.unwrap())
                }
            });
            // serve_connection_with_upgrades() preserves WebSocket-upgrade support for
            // connections that negotiate HTTP/1.1 (exec/attach/portforward use
            // `Connection: Upgrade`, which has no HTTP/2 equivalent wired up here).
            // Without it, hyper sends the 101 Switching Protocols response but never
            // hands the connection off to the upgrade handler — the on_upgrade callback
            // never runs, the splice never starts, and kubectl times out with
            // "unexpected output from server". Connections that negotiate HTTP/2
            // (kubelet's watch reflectors) skip this path entirely and get hyper's
            // native h2 stream multiplexing instead of one TCP connection per watch.
            if let Err(e) = conn_builder
                .serve_connection_with_upgrades(io, service)
                .await
            {
                tracing::debug!("connection error: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use u7s_store::{SqliteStore, Store};

    fn make_store() -> SqliteStore {
        SqliteStore::new(":memory:").expect("open in-memory db")
    }

    fn test_user() -> axum::Extension<crate::auth::UserInfo> {
        axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        })
    }

    /// Multiple --node-kubelet-port flags must each contribute one entry to the map —
    /// a real 2-node-or-more join needs one flag per non-primary node.
    #[test]
    fn parse_node_kubelet_ports_collects_multiple_entries() {
        let entries = vec!["lima-node-2".to_string(), "lima-node-3".to_string()]
            .into_iter()
            .zip(["10261", "10262"])
            .map(|(name, port)| format!("{name}={port}"))
            .collect::<Vec<_>>();
        let map = parse_node_kubelet_ports(&entries).expect("well-formed entries must parse");
        assert_eq!(map.get("lima-node-2"), Some(&10261));
        assert_eq!(map.get("lima-node-3"), Some(&10262));
    }

    /// A malformed --node-kubelet-port must fail the server at startup, not silently
    /// misroute proxy requests for the intended node forever (the value would otherwise
    /// just be dropped, and that node would fall back to the wrong global port with no
    /// indication why exec/logs/attach for its pods keep hitting the primary instead).
    #[test]
    fn parse_node_kubelet_ports_rejects_entry_without_equals() {
        let entries = vec!["lima-node-2-10261".to_string()];
        assert!(
            parse_node_kubelet_ports(&entries).is_err(),
            "an entry missing '=' must be a hard startup error, not a silently dropped flag"
        );
    }

    /// A non-numeric or out-of-range port must also fail loud, for the same reason.
    #[test]
    fn parse_node_kubelet_ports_rejects_non_numeric_port() {
        let entries = vec!["lima-node-2=not-a-port".to_string()];
        assert!(parse_node_kubelet_ports(&entries).is_err());
    }

    /// If raise_fd_limit regresses to a no-op, the process is left on whatever tiny
    /// default RLIMIT_NOFILE the OS/shell handed it (256 on stock macOS) and will hit
    /// EMFILE the first time sustained load — persistent watches, TLS accepts,
    /// konnectivity tunnels — pushes past it, exactly as happened in production.
    #[test]
    fn raise_fd_limit_grows_soft_limit_when_headroom_exists() {
        let (before_soft, hard) = rlimit::Resource::NOFILE
            .get()
            .expect("getrlimit(NOFILE) must succeed on a real OS");

        raise_fd_limit();

        let (after_soft, _) = rlimit::Resource::NOFILE
            .get()
            .expect("getrlimit(NOFILE) must succeed on a real OS");

        if before_soft < hard.min(DESIRED_NOFILE_LIMIT) {
            assert!(
                after_soft > before_soft,
                "expected raise_fd_limit to grow the soft NOFILE limit above {before_soft} \
                 (hard={hard}), but it stayed at {after_soft}"
            );
        }
    }

    /// A too-small OS ceiling must not be silently absorbed — this is the entire point
    /// of the warning (mirrors macOS's real default of 128 vs our requested 4096, the
    /// exact gap the VIP-timeout audit flagged as a candidate for dropped SYNs under
    /// bursty conformance load).
    #[test]
    fn backlog_clamp_warning_fires_when_os_ceiling_is_lower() {
        let msg = backlog_clamp_warning(4096, Some(128))
            .expect("OS ceiling 128 < requested 4096 must produce a warning");
        assert!(
            msg.contains("128") && msg.contains("4096"),
            "warning must name both the requested and clamped values so an operator \
             doesn't have to re-derive which is which: {msg}"
        );
    }

    /// A sufficiently high OS ceiling (e.g. an untuned Linux host with no clamp) must
    /// stay silent — a warning that fires unconditionally would train operators to
    /// ignore this log line, defeating the point of adding it.
    #[test]
    fn backlog_clamp_warning_silent_when_os_ceiling_is_sufficient() {
        assert_eq!(backlog_clamp_warning(4096, Some(65536)), None);
    }

    /// An unrecognized platform or failed sysctl/proc read must not be conflated with
    /// "no clamp exists" — staying silent is the honest behavior when we genuinely
    /// don't know the ceiling.
    #[test]
    fn backlog_clamp_warning_silent_when_ceiling_unknown() {
        assert_eq!(backlog_clamp_warning(4096, None), None);
    }

    // In-memory sink for tracing-subscriber's fmt layer, so the RUST_LOG-scoping
    // test below can assert on which events actually got rendered, mirroring the
    // pattern used for access-log tests elsewhere in this crate.
    #[derive(Clone, Default)]
    struct SharedBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'w> tracing_subscriber::fmt::MakeWriter<'w> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'w self) -> Self::Writer {
            self.clone()
        }
    }

    /// `run-all.sh`'s `-v` tier sets `RUST_LOG` to
    /// `u7s_apiserver=debug,u7s_store=debug,u7s_scheduler=debug,info` — this test
    /// mirrors that exact string through the same `EnvFilter` construction `run()`
    /// uses above. Before this tiering existed, `--verbose` set a blanket
    /// `RUST_LOG=debug`, which also enabled `h2`'s per-HTTP/2-frame tracing: on a
    /// real conformance run that noise alone was 89.9% of a 653MB apiserver.log,
    /// burying every debug! call the project actually added (request timing,
    /// storage-write internals, admission-chain latency, scheduler decisions). If
    /// the `-v` preset ever regresses back to a blanket `debug`, `h2`'s debug event
    /// below starts passing through again and this test must fail.
    #[test]
    fn v_tier_rust_log_scopes_debug_to_u7s_crates_not_h2() {
        let buf = SharedBuf::default();
        let filter = tracing_subscriber::EnvFilter::new(
            "u7s_apiserver=debug,u7s_store=debug,u7s_scheduler=debug,info",
        );
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .with_env_filter(filter)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        tracing::debug!(target: "h2::codec", "frame-level h2 noise");
        tracing::debug!(target: "u7s_apiserver::handlers::pods", "pod handler detail");

        let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            !log.contains("frame-level h2 noise"),
            "the -v tier must not enable h2's per-frame debug logging — a blanket \
             RUST_LOG=debug buried every u7s debug! call under exactly this kind of \
             third-party noise (89.9% of a 653MB conformance log): {log}"
        );
        assert!(
            log.contains("pod handler detail"),
            "the -v tier must still enable u7s_apiserver's own debug logging — \
             that's the entire point of --verbose/-v, so a filter that silences it \
             along with h2 would defeat the feature: {log}"
        );
    }

    /// Regression guard for the socket2 refactor in `bind_listener`: it builds the
    /// listener manually (non-blocking, reuse-addr, bind, listen) instead of going
    /// through `TcpListener::bind`, so a future edit that drops `set_nonblocking` or
    /// otherwise misconfigures the socket must fail this test rather than silently
    /// producing a listener tokio can't actually accept connections on.
    #[tokio::test]
    async fn bind_listener_produces_a_working_listener() {
        let listener =
            bind_listener("127.0.0.1:0").expect("bind_listener must succeed on an ephemeral port");
        let addr = listener
            .local_addr()
            .expect("bound listener must report its local address");

        let accept = tokio::spawn(async move { listener.accept().await });
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("a client must be able to connect to the freshly bound listener");
        accept
            .await
            .expect("accept task must not panic")
            .expect("listener must successfully accept the pending connection");
    }

    #[tokio::test]
    async fn seed_namespaces_creates_default_and_kube_system() {
        // All four namespaces must exist after a single call — required by Kubernetes API contract.
        let store = make_store();
        seed_namespaces(&store).await.expect("seed must not fail");

        for name in ["default", "kube-system", "kube-node-lease", "kube-public"] {
            let key = keys::cluster_object_key("namespaces", name);
            let obj = store.get(&key).await.expect("get must not fail");
            assert!(obj.is_some(), "namespace '{name}' must exist after seeding");
            let parsed: serde_json::Value =
                serde_json::from_slice(&obj.unwrap().value).expect("valid json");
            assert_eq!(parsed["kind"].as_str(), Some("Namespace"));
            assert_eq!(parsed["metadata"]["name"].as_str(), Some(name));
            assert_eq!(parsed["status"]["phase"].as_str(), Some("Active"));
        }
    }

    #[tokio::test]
    async fn seeded_namespace_creation_timestamp_reflects_actual_cluster_boot_not_a_hardcoded_lie()
    {
        // kubectl derives the AGE column from creationTimestamp. Before this fix every seeded
        // namespace was hardcoded to "2024-01-01T00:00:00Z", so a cluster booted today reported
        // an AGE of 2+ years — a user-visible lie about how long the cluster has existed.
        let before_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after the epoch")
            .as_secs() as i64;

        let store = make_store();
        seed_namespaces(&store).await.expect("seed must not fail");

        let key = keys::cluster_object_key("namespaces", "kube-system");
        let obj = store
            .get(&key)
            .await
            .expect("get must not fail")
            .expect("kube-system must exist after seeding");
        let ns: serde_json::Value = serde_json::from_slice(&obj.value).expect("valid json");
        let ts = ns["metadata"]["creationTimestamp"]
            .as_str()
            .expect("creationTimestamp must be a string");

        assert_ne!(
            ts, "2024-01-01T00:00:00Z",
            "seeded namespace must not carry the old hardcoded fake creation date"
        );
        // boot_timestamp() is a process-wide OnceLock: in `cargo test --workspace` this test
        // binary runs thousands of tests in one process, and whichever test first touches
        // boot_timestamp() (possibly minutes before this test executes) freezes it for the
        // rest of the run. A tight few-second bound would be flaky for that reason alone, so
        // this uses a generous one-hour window — still 2+ orders of magnitude tighter than the
        // multi-year drift the old hardcoded "2024-01-01" constant produced, which is the
        // actual regression this test guards against.
        let ts_secs = util::rfc3339_to_unix_secs(ts).expect("must be a valid RFC3339 timestamp");
        assert!(
            (ts_secs - before_secs).abs() <= 3600,
            "seeded namespace's creationTimestamp ({ts}) must reflect the actual process boot \
             time, not an arbitrary or multi-year-stale value"
        );
    }

    #[tokio::test]
    async fn seed_namespaces_is_idempotent() {
        // A second call must not error — CAS rv=0 returns AlreadyExists which is silently ignored.
        let store = make_store();
        seed_namespaces(&store)
            .await
            .expect("first seed must not fail");
        seed_namespaces(&store)
            .await
            .expect("second seed must not fail");
    }

    /// Regression: every connection accepted by the apiserver's HTTP(S) listener must have
    /// TCP_NODELAY enabled. Watch clients (KCM's ConsistencyStore) read-after-write against
    /// their informer cache, which only advances on the trailing watch BOOKMARK; leaving
    /// Nagle's algorithm enabled delays that BOOKMARK on the wire long enough for the client
    /// to recheck first, retry, and — under a fast round-trip — never converge (observed as
    /// an unbounded ReplicaSet hash-collision storm). This test fails on revert: if
    /// `configure_accepted_socket` stops calling `set_nodelay(true)`, `nodelay()` on the
    /// accepted stream returns `false`.
    #[tokio::test]
    async fn configure_accepted_socket_enables_tcp_nodelay() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let server = tokio::spawn(async move {
            let (tcp_stream, _peer) = listener.accept().await.expect("accept");
            configure_accepted_socket(&tcp_stream);
            tcp_stream.nodelay().expect("nodelay query must succeed")
        });

        let _client = TcpStream::connect(addr).await.expect("client connect");
        let nodelay_enabled = server.await.expect("server task must not panic");

        assert!(
            nodelay_enabled,
            "accepted connections must have TCP_NODELAY enabled so watch BOOKMARKs are not \
             delayed by Nagle buffering past a controller's read-after-write recheck"
        );
    }

    #[tokio::test]
    async fn seed_rbac_creates_system_node_clusterrole() {
        // Ensures kubelet nodes using real RBAC credentials (CN=system:node:<name>,
        // O=system:nodes) get a non-empty RBAC policy on startup rather than 403.
        // The ClusterRole and ClusterRoleBinding must be stored under the same key
        // prefix that state::AppState::init() scans so the RBAC index is populated.
        const GROUP: &str = "rbac.authorization.k8s.io";

        let store = make_store();
        seed_rbac(&store).await.expect("seed must not fail");

        // ClusterRole must exist and have the expected structure.
        let cr_key = keys::group_object_key(GROUP, "clusterroles", None, "system:node");
        let cr_obj = store.get(&cr_key).await.expect("get must not fail");
        assert!(
            cr_obj.is_some(),
            "ClusterRole system:node must exist after seeding"
        );
        let cr: serde_json::Value =
            serde_json::from_slice(&cr_obj.unwrap().value).expect("valid json");
        assert_eq!(cr["kind"].as_str(), Some("ClusterRole"));
        assert_eq!(cr["metadata"]["name"].as_str(), Some("system:node"));
        // All Kubernetes objects must have a non-null creationTimestamp in metadata.
        assert!(
            !cr["metadata"]["creationTimestamp"].is_null(),
            "ClusterRole metadata must contain a non-null creationTimestamp"
        );
        // Must include rules for nodes, pods, events, configmaps, secrets, leases, and csinodes.
        // Missing csinodes causes kubelet to get 403 for CSINode PATCH/WATCH, which client-go
        // surfaces as "invalid JSON: expected value at line 1 column 1".
        let rules = cr["rules"].as_array().expect("rules must be an array");
        assert!(!rules.is_empty(), "ClusterRole must have at least one rule");
        let resources: Vec<String> = rules
            .iter()
            .flat_map(|r| {
                r["resources"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect();
        for expected in [
            "nodes",
            "pods",
            "events",
            "configmaps",
            "secrets",
            "leases",
            "csinodes",
        ] {
            assert!(
                resources.iter().any(|r| r == expected),
                "ClusterRole rules must cover resource '{expected}'"
            );
        }

        // ClusterRoleBinding must exist and bind system:nodes group.
        let crb_key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:node");
        let crb_obj = store.get(&crb_key).await.expect("get must not fail");
        assert!(
            crb_obj.is_some(),
            "ClusterRoleBinding system:node must exist after seeding"
        );
        let crb: serde_json::Value =
            serde_json::from_slice(&crb_obj.unwrap().value).expect("valid json");
        assert_eq!(crb["kind"].as_str(), Some("ClusterRoleBinding"));
        assert_eq!(crb["metadata"]["name"].as_str(), Some("system:node"));
        // All Kubernetes objects must have a non-null creationTimestamp in metadata.
        assert!(
            !crb["metadata"]["creationTimestamp"].is_null(),
            "ClusterRoleBinding metadata must contain a non-null creationTimestamp"
        );
        let subjects = crb["subjects"]
            .as_array()
            .expect("subjects must be an array");
        assert_eq!(subjects.len(), 1, "must have exactly one subject");
        assert_eq!(subjects[0]["kind"].as_str(), Some("Group"));
        assert_eq!(subjects[0]["name"].as_str(), Some("system:nodes"));
        assert_eq!(crb["roleRef"]["name"].as_str(), Some("system:node"));
        assert_eq!(crb["roleRef"]["kind"].as_str(), Some("ClusterRole"));
    }

    #[tokio::test]
    async fn seed_rbac_creates_cluster_admin_and_system_masters_binding() {
        // The cluster-admin ClusterRole and system:masters ClusterRoleBinding must exist after
        // seeding.  This replaces the former hardcoded bypass in is_allowed(); if these objects
        // are missing on startup, system:masters users will be denied all requests.
        const GROUP: &str = "rbac.authorization.k8s.io";

        let store = make_store();
        seed_rbac(&store).await.expect("seed must not fail");

        // cluster-admin ClusterRole must exist with wildcard rules.
        let ca_role_key = keys::group_object_key(GROUP, "clusterroles", None, "cluster-admin");
        let ca_role_obj = store.get(&ca_role_key).await.expect("get must not fail");
        assert!(
            ca_role_obj.is_some(),
            "ClusterRole cluster-admin must exist after seeding"
        );
        let ca_role: serde_json::Value =
            serde_json::from_slice(&ca_role_obj.unwrap().value).expect("valid json");
        assert_eq!(ca_role["kind"].as_str(), Some("ClusterRole"));
        assert_eq!(ca_role["metadata"]["name"].as_str(), Some("cluster-admin"));
        let rules = ca_role["rules"].as_array().expect("rules must be an array");
        assert!(
            !rules.is_empty(),
            "cluster-admin must have at least one rule"
        );
        // Verify wildcard access: all rules must grant ["*"] on verbs.
        for rule in rules {
            let verbs = rule["verbs"].as_array().expect("verbs must be an array");
            assert!(
                verbs.iter().any(|v| v.as_str() == Some("*")),
                "cluster-admin rules must grant wildcard verbs"
            );
        }

        // system:masters ClusterRoleBinding must exist and bind to cluster-admin.
        let ca_bind_key =
            keys::group_object_key(GROUP, "clusterrolebindings", None, "system:masters");
        let ca_bind_obj = store.get(&ca_bind_key).await.expect("get must not fail");
        assert!(
            ca_bind_obj.is_some(),
            "ClusterRoleBinding system:masters must exist after seeding"
        );
        let ca_bind: serde_json::Value =
            serde_json::from_slice(&ca_bind_obj.unwrap().value).expect("valid json");
        assert_eq!(ca_bind["kind"].as_str(), Some("ClusterRoleBinding"));
        assert_eq!(ca_bind["metadata"]["name"].as_str(), Some("system:masters"));
        let subjects = ca_bind["subjects"]
            .as_array()
            .expect("subjects must be an array");
        assert_eq!(subjects.len(), 1, "must have exactly one subject");
        assert_eq!(subjects[0]["kind"].as_str(), Some("Group"));
        assert_eq!(subjects[0]["name"].as_str(), Some("system:masters"));
        assert_eq!(
            ca_bind["roleRef"]["name"].as_str(),
            Some("cluster-admin"),
            "ClusterRoleBinding must reference cluster-admin role"
        );
        assert_eq!(ca_bind["roleRef"]["kind"].as_str(), Some("ClusterRole"));
    }

    #[tokio::test]
    async fn seed_rbac_is_idempotent() {
        // Create-only puts must not fail on a second call — a restart re-runs seeding even
        // though every object already exists, and each AlreadyExists must be swallowed rather
        // than propagated as an error.
        let store = make_store();
        seed_rbac(&store).await.expect("first seed must not fail");
        seed_rbac(&store).await.expect("second seed must not fail");
    }

    #[tokio::test]
    async fn seed_rbac_reseed_does_not_clobber_an_operators_edit_to_a_bootstrap_clusterrole() {
        // Upstream kube-apiserver stamps bootstrap RBAC once per cluster lifetime; if an
        // operator edits a seeded ClusterRole after boot and the apiserver restarts, that
        // edit must survive. Before this fix, seed_rbac() unconditionally upserted every
        // object on every boot (store.put(..., None)), so a restart would silently revert
        // any such edit back to the hardcoded seed body.
        const GROUP: &str = "rbac.authorization.k8s.io";

        let store = make_store();
        seed_rbac(&store).await.expect("first seed must not fail");

        // Simulate an operator hand-editing the seeded cluster-admin ClusterRole after boot.
        let key = keys::group_object_key(GROUP, "clusterroles", None, "cluster-admin");
        let existing = store
            .get(&key)
            .await
            .expect("get must not fail")
            .expect("cluster-admin must exist after first seed");
        let mut edited: serde_json::Value =
            serde_json::from_slice(&existing.value).expect("valid json");
        edited["metadata"]["annotations"] = serde_json::json!({"operator-edited": "true"});
        store
            .put(
                &key,
                bytes::Bytes::from(edited.to_string()),
                Some(existing.revision),
            )
            .await
            .expect("operator edit must succeed");

        // A restart re-runs seed_rbac(); it must not clobber the operator's edit.
        seed_rbac(&store).await.expect("second seed must not fail");

        let after = store
            .get(&key)
            .await
            .expect("get must not fail")
            .expect("cluster-admin must still exist after reseed");
        let after_json: serde_json::Value =
            serde_json::from_slice(&after.value).expect("valid json");
        assert_eq!(
            after_json["metadata"]["annotations"]["operator-edited"].as_str(),
            Some("true"),
            "reseeding a bootstrap ClusterRole on restart must not revert an operator's \
             edit to it — upstream only stamps bootstrap RBAC once per cluster lifetime"
        );
    }

    #[tokio::test]
    async fn seed_rbac_seeds_at_least_49_clusterroles() {
        // SubjectAccessReview conformance requires ~80 default ClusterRoles (upstream k8s).
        // We seed a minimum of 49 so that `kubectl get clusterroles | wc -l` shows 50+
        // (49 rows + 1 header). If seed_rbac() is removed or reduced, this count drops
        // to 0 and all RBAC-gated conformance tests fail.
        use u7s_store::{ListOptions, Store};
        const GROUP: &str = "rbac.authorization.k8s.io";

        let store = make_store();
        seed_rbac(&store).await.expect("seed must not fail");

        // Enumerate all keys under the clusterroles prefix and count them.
        let prefix = keys::group_list_prefix(GROUP, "clusterroles", None);
        let all = store
            .list(&prefix, ListOptions::default())
            .await
            .expect("list must not fail");
        let count = all.items.len();

        assert!(
            count >= 49,
            "seed_rbac must create at least 49 ClusterRoles so that \
             `kubectl get clusterroles | wc -l` shows 50+ (got {count}). \
             SubjectAccessReview conformance fails when default roles are absent."
        );

        // Spot-check the controller roles that KCM sub-controllers depend on.
        for name in [
            "system:controller:deployment-controller",
            "system:controller:replicaset-controller",
            "system:controller:endpoint-controller",
            "system:controller:namespace-controller",
            "system:controller:service-account-controller",
            "system:kube-controller-manager",
            "system:kube-scheduler",
            "cluster-admin",
            "admin",
            "edit",
            "view",
        ] {
            let key = keys::group_object_key(GROUP, "clusterroles", None, name);
            let obj = store.get(&key).await.expect("get must not fail");
            assert!(
                obj.is_some(),
                "ClusterRole '{name}' must exist after seeding — \
                 KCM or scheduler depends on it for authorization"
            );
        }
    }

    #[tokio::test]
    async fn seed_rbac_seeds_discovery_and_public_info_viewer_with_correct_bindings() {
        // The SubjectAccessReview conformance test checks that unauthenticated users
        // can GET /healthz and /livez, and that authenticated users can hit /api and /apis.
        // This requires:
        //   1. ClusterRole system:public-info-viewer bound to system:unauthenticated.
        //   2. ClusterRole system:discovery bound to system:authenticated.
        // Without these, conformance fails with 403 on every health/discovery probe.
        use u7s_store::Store;
        const GROUP: &str = "rbac.authorization.k8s.io";

        let store = make_store();
        seed_rbac(&store).await.expect("seed must not fail");

        // system:public-info-viewer must exist.
        let key = keys::group_object_key(GROUP, "clusterroles", None, "system:public-info-viewer");
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_some(),
            "ClusterRole system:public-info-viewer must exist — needed for unauthenticated /healthz"
        );

        // system:public-info-viewer binding must include system:unauthenticated.
        let key = keys::group_object_key(
            GROUP,
            "clusterrolebindings",
            None,
            "system:public-info-viewer",
        );
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_some(),
            "ClusterRoleBinding system:public-info-viewer must exist"
        );
        let crb: serde_json::Value =
            serde_json::from_slice(&obj.unwrap().value).expect("valid json");
        let subjects = crb["subjects"].as_array().expect("subjects must be array");
        let has_unauthenticated = subjects
            .iter()
            .any(|s| s["name"].as_str() == Some("system:unauthenticated"));
        assert!(
            has_unauthenticated,
            "system:public-info-viewer binding must include system:unauthenticated \
             so load-balancer health probes can reach /healthz without credentials"
        );

        // system:discovery must exist.
        let key = keys::group_object_key(GROUP, "clusterroles", None, "system:discovery");
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_some(),
            "ClusterRole system:discovery must exist — needed for authenticated API discovery"
        );

        // system:discovery binding must include system:authenticated.
        let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:discovery");
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_some(),
            "ClusterRoleBinding system:discovery must exist"
        );
        let crb: serde_json::Value =
            serde_json::from_slice(&obj.unwrap().value).expect("valid json");
        let subjects = crb["subjects"].as_array().expect("subjects must be array");
        let has_authenticated = subjects
            .iter()
            .any(|s| s["name"].as_str() == Some("system:authenticated"));
        assert!(
            has_authenticated,
            "system:discovery binding must include system:authenticated \
             so kubectl and other clients can discover the API"
        );
    }

    #[tokio::test]
    async fn seed_flowcontrol_creates_required_default_objects() {
        // The APF conformance test expects default FlowSchemas and PriorityLevelConfigurations
        // to exist on startup. Without them the test times out waiting for FlowSchema status
        // conditions to converge (they reference PLCs that must exist).
        const GROUP: &str = "flowcontrol.apiserver.k8s.io";

        let store = make_store();
        seed_flowcontrol(&store).await.expect("seed must not fail");

        // All 8 default PriorityLevelConfigurations must exist.
        for name in [
            "exempt",
            "catch-all",
            "system",
            "leader-election",
            "workload-high",
            "workload-low",
            "global-default",
            "node-high",
        ] {
            let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, name);
            let obj = store.get(&key).await.expect("get must not fail");
            assert!(
                obj.is_some(),
                "PriorityLevelConfiguration '{name}' must exist — APF FlowSchemas reference it"
            );
            let parsed: serde_json::Value =
                serde_json::from_slice(&obj.unwrap().value).expect("valid json");
            assert_eq!(
                parsed["kind"].as_str(),
                Some("PriorityLevelConfiguration"),
                "PriorityLevelConfiguration '{name}' must have correct kind"
            );
            assert_eq!(
                parsed["metadata"]["name"].as_str(),
                Some(name),
                "PriorityLevelConfiguration must have correct name"
            );
        }

        // All 13 default FlowSchemas must exist.
        for name in [
            "exempt",
            "probes",
            "system-leader-election",
            "endpoint-controller",
            "workload-leader-election",
            "system-node-high",
            "system-nodes",
            "kube-controller-manager",
            "kube-scheduler",
            "kube-system-service-accounts",
            "service-accounts",
            "global-default",
            "catch-all",
        ] {
            let key = keys::group_object_key(GROUP, "flowschemas", None, name);
            let obj = store.get(&key).await.expect("get must not fail");
            assert!(
                obj.is_some(),
                "FlowSchema '{name}' must exist — APF conformance test lists and checks these"
            );
            let parsed: serde_json::Value =
                serde_json::from_slice(&obj.unwrap().value).expect("valid json");
            assert_eq!(
                parsed["kind"].as_str(),
                Some("FlowSchema"),
                "FlowSchema '{name}' must have correct kind"
            );
        }
    }

    #[tokio::test]
    async fn seed_flowcontrol_exempt_plc_has_correct_type() {
        // The 'exempt' PriorityLevelConfiguration must have type=Exempt (not Limited).
        // system:masters requests must bypass all queuing; if type=Limited they get queued
        // and the apiserver may deadlock during bootstrap when it needs its own RBAC calls.
        const GROUP: &str = "flowcontrol.apiserver.k8s.io";

        let store = make_store();
        seed_flowcontrol(&store).await.expect("seed must not fail");

        let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "exempt");
        let obj = store.get(&key).await.expect("get must not fail").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&obj.value).expect("valid json");
        assert_eq!(
            parsed["spec"]["type"].as_str(),
            Some("Exempt"),
            "exempt PriorityLevelConfiguration must have type=Exempt so system:masters requests bypass queuing"
        );
    }

    #[tokio::test]
    async fn seed_flowcontrol_is_idempotent() {
        // Unconditional puts must not fail on a second call.
        let store = make_store();
        seed_flowcontrol(&store)
            .await
            .expect("first seed must not fail");
        seed_flowcontrol(&store)
            .await
            .expect("second seed must not fail");
    }

    #[tokio::test]
    async fn seed_rbac_creates_basic_user_role_and_authenticated_binding() {
        // Argo CD calls SelfSubjectAccessReview on startup to discover its own permissions.
        // This requires:
        //   1. ClusterRole system:basic-user granting create on selfsubjectaccessreviews.
        //   2. ClusterRoleBinding system:basic-user binding system:authenticated → that role.
        // Without these, every authenticated user gets 403 on discovery, breaking Argo CD startup.
        const GROUP: &str = "rbac.authorization.k8s.io";

        let store = make_store();
        seed_rbac(&store).await.expect("seed must not fail");

        // ClusterRole system:basic-user must exist with the right rules.
        let bu_role_key = keys::group_object_key(GROUP, "clusterroles", None, "system:basic-user");
        let bu_role_obj = store.get(&bu_role_key).await.expect("get must not fail");
        assert!(
            bu_role_obj.is_some(),
            "ClusterRole system:basic-user must exist after seeding"
        );
        let bu_role: serde_json::Value =
            serde_json::from_slice(&bu_role_obj.unwrap().value).expect("valid json");
        assert_eq!(bu_role["kind"].as_str(), Some("ClusterRole"));
        assert_eq!(
            bu_role["metadata"]["name"].as_str(),
            Some("system:basic-user")
        );
        let rules = bu_role["rules"].as_array().expect("rules must be an array");
        let resources: Vec<String> = rules
            .iter()
            .flat_map(|r| {
                r["resources"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect();
        assert!(
            resources.iter().any(|r| r == "selfsubjectaccessreviews"),
            "system:basic-user must grant selfsubjectaccessreviews"
        );
        assert!(
            resources.iter().any(|r| r == "selfsubjectrulesreviews"),
            "system:basic-user must grant selfsubjectrulesreviews"
        );
        assert!(
            resources.iter().any(|r| r == "selfsubjectreviews"),
            "system:basic-user must grant selfsubjectreviews — without it, `kubectl auth \
             whoami` (and any non-system:masters caller) gets 403 on every SelfSubjectReview, \
             matching upstream bootstrappolicy.go's basicUserRules"
        );

        // ClusterRoleBinding system:basic-user must bind system:authenticated group.
        let bu_bind_key =
            keys::group_object_key(GROUP, "clusterrolebindings", None, "system:basic-user");
        let bu_bind_obj = store.get(&bu_bind_key).await.expect("get must not fail");
        assert!(
            bu_bind_obj.is_some(),
            "ClusterRoleBinding system:basic-user must exist after seeding"
        );
        let bu_bind: serde_json::Value =
            serde_json::from_slice(&bu_bind_obj.unwrap().value).expect("valid json");
        assert_eq!(bu_bind["kind"].as_str(), Some("ClusterRoleBinding"));
        assert_eq!(
            bu_bind["metadata"]["name"].as_str(),
            Some("system:basic-user")
        );
        let subjects = bu_bind["subjects"]
            .as_array()
            .expect("subjects must be an array");
        assert_eq!(subjects.len(), 1, "must have exactly one subject");
        assert_eq!(subjects[0]["kind"].as_str(), Some("Group"));
        assert_eq!(
            subjects[0]["name"].as_str(),
            Some("system:authenticated"),
            "binding must target system:authenticated so all authed users get basic-user permissions"
        );
        assert_eq!(
            bu_bind["roleRef"]["name"].as_str(),
            Some("system:basic-user"),
            "ClusterRoleBinding must reference system:basic-user role"
        );
        assert_eq!(bu_bind["roleRef"]["kind"].as_str(), Some("ClusterRole"));
    }

    #[tokio::test]
    async fn system_monitoring_role_does_not_grant_metrics_slis() {
        // Upstream's system:monitoring ClusterRole advertises "/metrics/slis", but we have
        // no healthz-checker framework behind it (our /healthz, /readyz, /livez handlers are
        // unconditional "ok", not a set of named checks producing per-check SLI data), so no
        // axum route ever serves it. If "/metrics/slis" were listed here, any caller who reads
        // this ClusterRole and is granted "get" on it would be RBAC-authorized for an endpoint
        // that 404s on every request — a silent over-promise. This test pins the ClusterRole to
        // only what we actually serve; if it starts failing, someone re-added the dangling grant
        // (or, if a route for /metrics/slis now exists, this test's assumption should be revisited
        // together with re-adding the grant).
        const GROUP: &str = "rbac.authorization.k8s.io";

        let store = make_store();
        seed_rbac(&store).await.expect("seed must not fail");

        let key = keys::group_object_key(GROUP, "clusterroles", None, "system:monitoring");
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_some(),
            "ClusterRole system:monitoring must exist after seeding"
        );
        let cr: serde_json::Value =
            serde_json::from_slice(&obj.unwrap().value).expect("valid json");
        let non_resource_urls: Vec<&str> = cr["rules"]
            .as_array()
            .expect("rules must be an array")
            .iter()
            .flat_map(|r| {
                r["nonResourceURLs"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .collect();
        assert!(
            !non_resource_urls.contains(&"/metrics/slis"),
            "system:monitoring must not advertise /metrics/slis — no axum route serves it, so \
             granting it here would let RBAC promise an endpoint that 404s for every caller"
        );
        assert!(
            non_resource_urls.contains(&"/metrics"),
            "system:monitoring must still grant /metrics — that route does exist and is the \
             ClusterRole's whole purpose"
        );
    }

    #[tokio::test]
    async fn system_nodes_group_is_authorized_after_rbac_seed_and_init() {
        // Verifies the full chain: seed_rbac writes ClusterRole+ClusterRoleBinding,
        // AppState::init() loads them into the RBAC index, and is_allowed returns
        // true for a kubelet in system:nodes.
        //
        // Without this test the seeded data could be structurally correct (stored under
        // the right key) but still broken at the authorization layer — e.g. if init()
        // builds the wrong api_key or if subject_matches ignores the Group kind.
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        // Populate RBAC index from persisted seed data — mirrors what run() does.
        state.init().await;

        let groups = vec!["system:nodes".to_owned()];

        // A kubelet in system:nodes must be able to GET a pod assigned to it.
        let pod_read = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &groups,
            verb: "get",
            api_group: "",
            resource: "pods",
            subresource: "",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&pod_read),
            "system:nodes must be allowed to GET pods — kubelet needs this to reconcile its pod list"
        );

        // A kubelet in system:nodes must be able to LIST services -- kubelet's own service
        // informer needs this to populate Service-discovery env vars in every pod's
        // containers. A real joined node (mayor-yocic) authenticates as this exact identity,
        // unlike a single-node install's kubelet which shares the admin/system:masters
        // kubeconfig and never exercises this rule at all.
        let service_list = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &groups,
            verb: "list",
            api_group: "",
            resource: "services",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&service_list),
            "system:nodes must be allowed to LIST services — kubelet's service informer needs \
             this or every container on the node fails to start with CreateContainerConfigError \
             (\"services have not yet been read at least once\")"
        );

        // A kubelet in system:nodes must be able to create a lease (heartbeat).
        let lease_create = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &groups,
            verb: "create",
            api_group: "coordination.k8s.io",
            resource: "leases",
            subresource: "",
            namespace: Some("kube-node-lease"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&lease_create),
            "system:nodes must be allowed to create leases — kubelet heartbeat depends on this"
        );

        // A kubelet in system:nodes must be able to create SubjectAccessReviews so its
        // webhook authorizer can call back to the apiserver (needed for logs/exec/attach).
        let sar_create = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &groups,
            verb: "create",
            api_group: "authorization.k8s.io",
            resource: "subjectaccessreviews",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&sar_create),
            "system:nodes must be allowed to create subjectaccessreviews — \
             kubelet webhook authorizer calls back to the apiserver for proxy requests (logs/exec/attach)"
        );

        // A kubelet in system:nodes must be able to create TokenReviews so its
        // webhook authenticator can validate bearer tokens.
        let tr_create = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &groups,
            verb: "create",
            api_group: "authentication.k8s.io",
            resource: "tokenreviews",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&tr_create),
            "system:nodes must be allowed to create tokenreviews — \
             kubelet webhook authenticator calls back to the apiserver"
        );

        // Regression test: kubelet must be allowed to POST
        // /api/v1/namespaces/{ns}/serviceaccounts/{name}/token (TokenRequest subresource).
        // Without this rule the projected SA token volume never gets populated —
        // the kubelet's POST returns 403 and containers never receive an SA token,
        // breaking all in-cluster API calls.
        let sa_token_create = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &groups,
            verb: "create",
            api_group: "",
            resource: "serviceaccounts",
            subresource: "token",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&sa_token_create),
            "system:nodes must be allowed to create serviceaccounts/token — \
             kubelet needs this to project SA tokens into pod volumes"
        );

        // A kubelet in system:nodes must be able to create a plain (no-subresource) CSR
        // to rotate its own client certificate. Matches upstream bootstrappolicy.go's
        // NodeRules() exactly. Without this rule, a joined node has no permission to even
        // submit its own self-renewal CSR — the selfnodeclient ClusterRole/binding only
        // governs KCM's SAR-based auto-approval decision, not the initial create call,
        // so self-renewal is fully broken without both being present together.
        let csr_create = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &groups,
            verb: "create",
            api_group: "certificates.k8s.io",
            resource: "certificatesigningrequests",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&csr_create),
            "system:nodes must be allowed to create certificatesigningrequests — \
             a kubelet cannot submit its own certificate-rotation CSR without this rule"
        );

        // A user NOT in system:nodes must be denied — the binding is group-specific.
        let other_groups = vec!["system:authenticated".to_owned()];
        let pod_read_other = rbac::AuthzRequest {
            username: "someone-else",
            groups: &other_groups,
            verb: "get",
            api_group: "",
            resource: "pods",
            subresource: "",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            !state.rbac_index.is_allowed(&pod_read_other),
            "users not in system:nodes must not inherit kubelet permissions"
        );
    }

    #[tokio::test]
    async fn csr_nodeclient_and_selfnodeclient_rbac_authorized_after_seed_and_init() {
        // Verifies the full chain for the join/rotation RBAC: seed_rbac writes the
        // nodeclient/selfnodeclient ClusterRoles + bindings and binds the previously
        // unbound system:node-bootstrapper ClusterRole, AppState::init() loads them
        // into the RBAC index, and is_allowed matches what KCM's builtin csrapproving
        // controller actually checks — a SubjectAccessReview for
        // create on certificatesigningrequests/nodeclient or /selfnodeclient, built
        // straight from the CSR's (server-stamped) spec.username/groups. If this authz
        // chain is broken, KCM's real controller can never auto-approve a join or
        // self-renewal CSR, even though the ClusterRole/Binding objects exist.
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        // A bootstrap-token-authenticated joiner (group system:bootstrappers) must be
        // authorized for the SAR KCM issues to auto-approve a brand-new node-join CSR.
        let bootstrapper_groups = vec!["system:bootstrappers".to_owned()];
        let nodeclient_sar = rbac::AuthzRequest {
            username: "system:bootstrap:abcdef",
            groups: &bootstrapper_groups,
            verb: "create",
            api_group: "certificates.k8s.io",
            resource: "certificatesigningrequests",
            subresource: "nodeclient",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&nodeclient_sar),
            "system:bootstrappers must be allowed to create certificatesigningrequests/nodeclient \
             — without this, KCM's csrapproving controller can never auto-approve a node-join CSR"
        );

        // The same bootstrapper must also be able to submit the CSR object itself, via the
        // now-bound system:node-bootstrapper ClusterRole (previously seeded but unbound).
        let csr_create = rbac::AuthzRequest {
            username: "system:bootstrap:abcdef",
            groups: &bootstrapper_groups,
            verb: "create",
            api_group: "certificates.k8s.io",
            resource: "certificatesigningrequests",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&csr_create),
            "system:bootstrappers must be allowed to create certificatesigningrequests — \
             system:node-bootstrapper ClusterRole existed but was never bound to any group \
             before this fix, so no bootstrap identity could ever submit a join CSR"
        );

        // An already-joined node (group system:nodes) must be authorized for the SAR KCM
        // issues to auto-approve its own client-cert renewal CSR.
        let node_groups = vec!["system:nodes".to_owned()];
        let selfnodeclient_sar = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &node_groups,
            verb: "create",
            api_group: "certificates.k8s.io",
            resource: "certificatesigningrequests",
            subresource: "selfnodeclient",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&selfnodeclient_sar),
            "system:nodes must be allowed to create certificatesigningrequests/selfnodeclient \
             — without this, KCM's csrapproving controller can never auto-approve a node's own \
             certificate-rotation CSR"
        );

        // A node must NOT be authorized for nodeclient (that's the bootstrap-only join grant)
        // and a bootstrapper must NOT be authorized for selfnodeclient — the two scopes are
        // intentionally not interchangeable, matching upstream's separate ClusterRoleBindings.
        let node_tries_nodeclient = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &node_groups,
            verb: "create",
            api_group: "certificates.k8s.io",
            resource: "certificatesigningrequests",
            subresource: "nodeclient",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            !state.rbac_index.is_allowed(&node_tries_nodeclient),
            "system:nodes must not be granted the nodeclient (join) scope — an already-joined \
             node renewing its own cert is a distinct, narrower authorization than a fresh join"
        );
        let bootstrapper_tries_selfnodeclient = rbac::AuthzRequest {
            username: "system:bootstrap:abcdef",
            groups: &bootstrapper_groups,
            verb: "create",
            api_group: "certificates.k8s.io",
            resource: "certificatesigningrequests",
            subresource: "selfnodeclient",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            !state
                .rbac_index
                .is_allowed(&bootstrapper_tries_selfnodeclient),
            "system:bootstrappers must not be granted the selfnodeclient (self-renewal) scope — \
             a bootstrap identity has no existing node cert to renew"
        );
    }

    #[tokio::test]
    async fn extension_apiserver_can_read_own_auth_configmap_after_namespace_rolebinding() {
        // Aggregated apiservers (sample-apiserver) and CRD conversion webhooks bind
        // their own default ServiceAccount to the well-known
        // "extension-apiserver-authentication-reader" Role via a RoleBinding they
        // create themselves in kube-system — exactly like real kube-apiserver's
        // bootstrap policy, this Role must already exist for that binding to grant
        // anything. Without it, the extension apiserver's own in-cluster lookup of
        // the extension-apiserver-authentication configmap gets Forbidden (not the
        // tolerated NotFound), which is fatal and crash-loops the pod forever, so
        // its Deployment never becomes Available.
        const GROUP: &str = "rbac.authorization.k8s.io";
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        // Simulate the extension apiserver's own RoleBinding, created at runtime
        // (not part of bootstrap seeding) in kube-system, targeting its SA in some
        // other namespace — mirrors what SetUpSampleAPIServer / crd_conversion_webhook
        // do against the real kube-apiserver.
        let binding_key = keys::group_object_key(
            GROUP,
            "rolebindings",
            Some("kube-system"),
            "wardler-auth-reader-aggregator-1234",
        );
        let binding_val = serde_json::json!({
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "extension-apiserver-authentication-reader"
            },
            "subjects": [{
                "kind": "ServiceAccount",
                "name": "default",
                "namespace": "aggregator-1234"
            }]
        });
        use bytes::Bytes;
        use u7s_store::Store;
        store
            .put(&binding_key, Bytes::from(binding_val.to_string()), None)
            .await
            .expect("put rolebinding must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];
        let configmap_read = rbac::AuthzRequest {
            username: "system:serviceaccount:aggregator-1234:default",
            groups: &groups,
            verb: "get",
            api_group: "",
            resource: "configmaps",
            subresource: "",
            namespace: Some("kube-system"),
            name: Some("extension-apiserver-authentication"),
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&configmap_read),
            "the bootstrap Role kube-system/extension-apiserver-authentication-reader \
             must exist so an extension apiserver's own RoleBinding to it actually grants \
             read access — otherwise every aggregated apiserver / CRD conversion webhook \
             crash-loops fatally on startup"
        );
    }

    /// Regression test: a RoleBinding to the built-in "edit" ClusterRole must authorize
    /// DeleteCollection, not just Delete. Upstream's default "edit" ClusterRole grants
    /// "deletecollection" alongside "delete" on every namespaced resource it covers; this
    /// codebase's copy previously omitted it, so a ServiceAccount bound only to "edit" got a
    /// plain RBAC 403 ("is not allowed to deletecollection configmaps") on the last step of
    /// sig-auth's "ValidatingAdmissionPolicy can restrict access by-node" conformance test,
    /// even though it could already DELETE individual configmaps — live-confirmed via
    /// `kubectl auth can-i deletecollection configmaps --as=<sa>` before this fix.
    #[tokio::test]
    async fn edit_rolebinding_can_deletecollection_not_just_delete() {
        const GROUP: &str = "rbac.authorization.k8s.io";
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        // Bind a namespace's default ServiceAccount to the built-in "edit" ClusterRole,
        // mirroring how the sonobuoy conformance test grants its node-scoped client access.
        let binding_key =
            keys::group_object_key(GROUP, "rolebindings", Some("e2e-by-node"), "edit-binding");
        let binding_val = serde_json::json!({
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "edit"
            },
            "subjects": [{
                "kind": "ServiceAccount",
                "name": "default",
                "namespace": "e2e-by-node"
            }]
        });
        use bytes::Bytes;
        use u7s_store::Store;
        store
            .put(&binding_key, Bytes::from(binding_val.to_string()), None)
            .await
            .expect("put rolebinding must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];
        let deletecollection_configmaps = rbac::AuthzRequest {
            username: "system:serviceaccount:e2e-by-node:default",
            groups: &groups,
            verb: "deletecollection",
            api_group: "",
            resource: "configmaps",
            subresource: "",
            namespace: Some("e2e-by-node"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&deletecollection_configmaps),
            "a RoleBinding to 'edit' must authorize DELETECOLLECTION on configmaps — the \
             built-in 'edit' ClusterRole explicitly grants 'delete' on this resource, so \
             silently denying the bulk form of the same operation is a bootstrap-policy gap, \
             not an intentional restriction"
        );
    }

    /// Regression test: RoleBindings to the built-in "edit" AND "admin" ClusterRoles must both
    /// authorize write access to Leases, NetworkPolicies, Ingresses and PodDisruptionBudgets.
    /// Upstream's default "edit" ClusterRole (aggregated from system:aggregate-to-edit + view)
    /// grants full CRUD on coordination.k8s.io/leases and policy/poddisruptionbudgets, and write
    /// verbs on networking.k8s.io/networkpolicies+ingresses (with read coming from the view
    /// aggregation) — this codebase's flat copy of "edit" previously had no rule at all for any
    /// of these four resources, so a namespace editor got a plain RBAC 403 the moment they tried
    /// to manage a Lease (e.g. for leader election), a NetworkPolicy, an Ingress, or a
    /// PodDisruptionBudget. "admin" is upstream's "edit" plus extra escalation powers, so it must
    /// be a strict superset of "edit" — this codebase's "admin" already covered
    /// NetworkPolicies/Ingresses but, like "edit", had silently drifted to lack Leases and
    /// PodDisruptionBudgets too. Both roles are checked here so a regression in either one's
    /// rules fails this test, not just a manual kubectl check.
    #[tokio::test]
    async fn edit_and_admin_rolebindings_can_manage_leases_networkpolicies_ingresses_and_poddisruptionbudgets(
    ) {
        const GROUP: &str = "rbac.authorization.k8s.io";
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        use bytes::Bytes;
        use u7s_store::Store;
        for cluster_role in ["edit", "admin"] {
            let namespace = format!("e2e-{cluster_role}-gaps");
            let binding_key = keys::group_object_key(
                GROUP,
                "rolebindings",
                Some(namespace.as_str()),
                &format!("{cluster_role}-binding"),
            );
            let binding_val = serde_json::json!({
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": cluster_role
                },
                "subjects": [{
                    "kind": "ServiceAccount",
                    "name": "default",
                    "namespace": namespace
                }]
            });
            store
                .put(&binding_key, Bytes::from(binding_val.to_string()), None)
                .await
                .expect("put rolebinding must not fail");
        }

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];
        for cluster_role in ["edit", "admin"] {
            let namespace = format!("e2e-{cluster_role}-gaps");
            for (api_group, resource) in [
                ("coordination.k8s.io", "leases"),
                ("networking.k8s.io", "networkpolicies"),
                ("networking.k8s.io", "ingresses"),
                ("policy", "poddisruptionbudgets"),
            ] {
                let create_req = rbac::AuthzRequest {
                    username: &format!("system:serviceaccount:{namespace}:default"),
                    groups: &groups,
                    verb: "create",
                    api_group,
                    resource,
                    subresource: "",
                    namespace: Some(namespace.as_str()),
                    name: None,
                    non_resource_url: None,
                };
                assert!(
                    state.rbac_index.is_allowed(&create_req),
                    "a RoleBinding to '{cluster_role}' must authorize CREATE on \
                     {api_group}/{resource} — upstream's default '{cluster_role}' ClusterRole \
                     grants this resource group and this codebase's copy previously had no rule \
                     for it at all, so a namespace {cluster_role} user got an RBAC 403 trying to \
                     manage it"
                );
            }
        }
    }

    /// Regression test: a RoleBinding to the built-in "view" ClusterRole must authorize read
    /// (get) access to NetworkPolicies, Ingresses and PodDisruptionBudgets. Upstream's default
    /// "view" ClusterRole grants get/list/watch on networking.k8s.io/networkpolicies+ingresses
    /// and policy/poddisruptionbudgets — this codebase's flat copy of "view" previously had no
    /// rule at all for any of these three resources, so a namespace viewer got a plain RBAC 403
    /// trying to even read a NetworkPolicy, Ingress, or PodDisruptionBudget they don't own, even
    /// though "edit"/"admin" (full CRUD) already covered them. Also asserts "view" was NOT
    /// accidentally granted coordination.k8s.io/leases: upstream grants leases directly to
    /// edit/admin, not via the view aggregation, so a view-bound identity reading a Lease is
    /// over-privileged, not a gap.
    #[tokio::test]
    async fn view_rolebinding_can_read_networkpolicies_ingresses_and_poddisruptionbudgets() {
        const GROUP: &str = "rbac.authorization.k8s.io";
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        let binding_key =
            keys::group_object_key(GROUP, "rolebindings", Some("e2e-view-gaps"), "view-binding");
        let binding_val = serde_json::json!({
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "view"
            },
            "subjects": [{
                "kind": "ServiceAccount",
                "name": "default",
                "namespace": "e2e-view-gaps"
            }]
        });
        use bytes::Bytes;
        use u7s_store::Store;
        store
            .put(&binding_key, Bytes::from(binding_val.to_string()), None)
            .await
            .expect("put rolebinding must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];
        for (api_group, resource) in [
            ("networking.k8s.io", "networkpolicies"),
            ("networking.k8s.io", "ingresses"),
            ("policy", "poddisruptionbudgets"),
        ] {
            let get_req = rbac::AuthzRequest {
                username: "system:serviceaccount:e2e-view-gaps:default",
                groups: &groups,
                verb: "get",
                api_group,
                resource,
                subresource: "",
                namespace: Some("e2e-view-gaps"),
                name: None,
                non_resource_url: None,
            };
            assert!(
                state.rbac_index.is_allowed(&get_req),
                "a RoleBinding to 'view' must authorize GET on {api_group}/{resource} — \
                 upstream's default 'view' ClusterRole grants read on this resource group and \
                 this codebase's copy had no rule for it at all, so a namespace viewer got an \
                 RBAC 403 trying to read it"
            );
        }

        let get_leases = rbac::AuthzRequest {
            username: "system:serviceaccount:e2e-view-gaps:default",
            groups: &groups,
            verb: "get",
            api_group: "coordination.k8s.io",
            resource: "leases",
            subresource: "",
            namespace: Some("e2e-view-gaps"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            !state.rbac_index.is_allowed(&get_leases),
            "a RoleBinding to 'view' must NOT authorize access to coordination.k8s.io/leases — \
             upstream grants leases directly to edit/admin, not via the view aggregation, so \
             granting it here would be an over-broad, not upstream-matching, fix"
        );
    }

    /// Regression test: RoleBindings to the built-in "edit" AND "admin" ClusterRoles must
    /// authorize the escalating pod/service subresources, SA token creation, SA impersonation,
    /// pod eviction, and replicationcontrollers/scale that upstream's default "edit"/"admin"
    /// ClusterRoles grant but this codebase's flat copies never split out any subresource for
    /// at all — before this fix, a ServiceAccount bound only to "edit" got a plain RBAC 403
    /// running `kubectl exec`/`attach`/`port-forward` against a Pod, requesting a token for one
    /// of its own ServiceAccounts, impersonating another of its own ServiceAccounts, draining a
    /// Pod via Eviction, or reading/writing an RC's scale, even though `kubectl create`/`delete`
    /// on the underlying resources already worked. Also asserts "view" was NOT granted the
    /// escalating subresources or serviceaccount impersonation: upstream's viewRules()
    /// deliberately excludes them because "view" is documented to grant read access to
    /// non-escalating resources only. (This test only exercises `rbac_index` directly; the
    /// SA-shaped-Impersonate-User branching that makes the `impersonate`/`serviceaccounts` rule
    /// non-inert lives in auth.rs's `AuthLayer` middleware and is covered there.)
    #[tokio::test]
    async fn edit_and_admin_rolebindings_can_use_escalating_pod_subresources_and_scale() {
        const GROUP: &str = "rbac.authorization.k8s.io";
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        use bytes::Bytes;
        use u7s_store::Store;
        for cluster_role in ["edit", "admin", "view"] {
            let namespace = format!("e2e-{cluster_role}-subres");
            let binding_key = keys::group_object_key(
                GROUP,
                "rolebindings",
                Some(namespace.as_str()),
                &format!("{cluster_role}-binding"),
            );
            let binding_val = serde_json::json!({
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": cluster_role
                },
                "subjects": [{
                    "kind": "ServiceAccount",
                    "name": "default",
                    "namespace": namespace
                }]
            });
            store
                .put(&binding_key, Bytes::from(binding_val.to_string()), None)
                .await
                .expect("put rolebinding must not fail");
        }

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];
        for cluster_role in ["edit", "admin"] {
            let namespace = format!("e2e-{cluster_role}-subres");
            let username = format!("system:serviceaccount:{namespace}:default");
            for (verb, resource, subresource) in [
                ("get", "pods", "exec"),
                ("get", "pods", "attach"),
                ("get", "pods", "portforward"),
                ("create", "pods", "proxy"),
                ("create", "services", "proxy"),
                ("create", "serviceaccounts", "token"),
                ("impersonate", "serviceaccounts", ""),
                ("create", "pods", "eviction"),
                ("get", "replicationcontrollers", "scale"),
                ("update", "replicationcontrollers", "scale"),
            ] {
                let req = rbac::AuthzRequest {
                    username: &username,
                    groups: &groups,
                    verb,
                    api_group: "",
                    resource,
                    subresource,
                    namespace: Some(namespace.as_str()),
                    name: None,
                    non_resource_url: None,
                };
                assert!(
                    state.rbac_index.is_allowed(&req),
                    "a RoleBinding to '{cluster_role}' must authorize {verb} on \
                     {resource}/{subresource} — upstream's default '{cluster_role}' ClusterRole \
                     grants this and this codebase's copy previously had no rule for any \
                     subresource at all, so a namespace {cluster_role} user got an RBAC 403"
                );
            }
        }

        // "view" must NOT gain the escalating subresources — upstream's viewRules()
        // deliberately omits them ("view" is read-only on non-escalating resources).
        let view_username = "system:serviceaccount:e2e-view-subres:default";
        for (verb, resource, subresource) in [
            ("get", "pods", "exec"),
            ("get", "pods", "attach"),
            ("create", "serviceaccounts", "token"),
            ("impersonate", "serviceaccounts", ""),
            ("create", "pods", "eviction"),
        ] {
            let req = rbac::AuthzRequest {
                username: view_username,
                groups: &groups,
                verb,
                api_group: "",
                resource,
                subresource,
                namespace: Some("e2e-view-subres"),
                name: None,
                non_resource_url: None,
            };
            assert!(
                !state.rbac_index.is_allowed(&req),
                "a RoleBinding to 'view' must NOT authorize {verb} on {resource}/{subresource} \
                 — upstream's viewRules() deliberately excludes escalating subresources and \
                 impersonation, so granting this here would be an over-broad, not \
                 upstream-matching, fix"
            );
        }

        // replicationcontrollers/scale IS non-escalating and part of upstream's viewRules()
        // directly, so "view" alone must be able to read (but not write) it.
        let get_scale = rbac::AuthzRequest {
            username: view_username,
            groups: &groups,
            verb: "get",
            api_group: "",
            resource: "replicationcontrollers",
            subresource: "scale",
            namespace: Some("e2e-view-subres"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&get_scale),
            "a RoleBinding to 'view' must authorize GET on replicationcontrollers/scale — \
             upstream's viewRules() grants this non-escalating subresource directly"
        );
        let update_scale = rbac::AuthzRequest {
            username: view_username,
            groups: &groups,
            verb: "update",
            api_group: "",
            resource: "replicationcontrollers",
            subresource: "scale",
            namespace: Some("e2e-view-subres"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            !state.rbac_index.is_allowed(&update_scale),
            "a RoleBinding to 'view' must NOT authorize UPDATE on replicationcontrollers/scale \
             — 'view' is read-only, upstream's editRules() (not viewRules()) grants the write"
        );
    }

    /// Regression test: RoleBindings to the built-in "edit", "admin", AND "view" ClusterRoles
    /// must all authorize GET on every workload/status subresource upstream's viewRules()
    /// grants (pods/status, services/status, resourcequotas/status, namespaces/status,
    /// replicationcontrollers/status, persistentvolumeclaims/status, statefulsets/status,
    /// daemonsets/status, deployments/status, replicasets/status, horizontalpodautoscalers/
    /// status, cronjobs/status, jobs/status, poddisruptionbudgets/status, ingresses/status)
    /// plus discovery.k8s.io/endpointslices — before this fix this codebase's flat admin/
    /// edit/view ClusterRoles never split out ANY /status subresource for any resource, so a
    /// ServiceAccount bound to any of the three got a plain RBAC 403 the moment it tried to
    /// read a workload's status (e.g. `kubectl get deployment -o yaml` still works because
    /// status is embedded in the base object, but a controller or client hitting `/status`
    /// directly did not).
    ///
    /// "edit"/"admin" must ALSO authorize full CRUD on statefulsets/scale, deployments/scale,
    /// and replicasets/scale — upstream's editRules() grants Write on these three directly
    /// (unlike the /status entries, which editRules() never mentions) — while "view" must
    /// stay read-only on them, matching the replicationcontrollers/scale precedent.
    ///
    /// Spot-checks that nothing was over-granted: none of the three roles may WRITE any
    /// /status subresource (upstream reserves status writes for controller identities like
    /// system:kube-controller-manager, never edit/admin/view — see the "edit" ClusterRole's
    /// own upstream doc comment), and none may write discovery.k8s.io/endpointslices either
    /// (upstream's editRules() never mentions the discovery group, so edit/admin only
    /// inherit the read-only grant from the view aggregation, not create/delete).
    #[tokio::test]
    async fn edit_admin_and_view_rolebindings_can_read_status_subresources_and_endpointslices() {
        const GROUP: &str = "rbac.authorization.k8s.io";
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        use bytes::Bytes;
        use u7s_store::Store;
        for cluster_role in ["edit", "admin", "view"] {
            let namespace = format!("e2e-{cluster_role}-status");
            let binding_key = keys::group_object_key(
                GROUP,
                "rolebindings",
                Some(namespace.as_str()),
                &format!("{cluster_role}-binding"),
            );
            let binding_val = serde_json::json!({
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": cluster_role
                },
                "subjects": [{
                    "kind": "ServiceAccount",
                    "name": "default",
                    "namespace": namespace
                }]
            });
            store
                .put(&binding_key, Bytes::from(binding_val.to_string()), None)
                .await
                .expect("put rolebinding must not fail");
        }

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];

        // Every one of these /status subresources (plus endpointslices) must be readable
        // by all three roles — this is the shared, resolved read-only grant upstream's
        // viewRules() contributes to edit/admin via aggregation.
        let readable = [
            ("", "pods", "status"),
            ("", "services", "status"),
            ("", "resourcequotas", "status"),
            ("", "namespaces", "status"),
            ("", "replicationcontrollers", "status"),
            ("", "persistentvolumeclaims", "status"),
            ("apps", "statefulsets", "status"),
            ("apps", "daemonsets", "status"),
            ("apps", "deployments", "status"),
            ("apps", "replicasets", "status"),
            ("autoscaling", "horizontalpodautoscalers", "status"),
            ("batch", "cronjobs", "status"),
            ("batch", "jobs", "status"),
            ("policy", "poddisruptionbudgets", "status"),
            ("networking.k8s.io", "ingresses", "status"),
            ("discovery.k8s.io", "endpointslices", ""),
        ];
        for cluster_role in ["edit", "admin", "view"] {
            let namespace = format!("e2e-{cluster_role}-status");
            let username = format!("system:serviceaccount:{namespace}:default");
            for (api_group, resource, subresource) in readable {
                let get_req = rbac::AuthzRequest {
                    username: &username,
                    groups: &groups,
                    verb: "get",
                    api_group,
                    resource,
                    subresource,
                    namespace: Some(namespace.as_str()),
                    name: None,
                    non_resource_url: None,
                };
                assert!(
                    state.rbac_index.is_allowed(&get_req),
                    "a RoleBinding to '{cluster_role}' must authorize GET on \
                     {api_group}/{resource}/{subresource} — upstream's viewRules() grants \
                     this and this codebase's copy previously had no rule for any /status \
                     subresource at all"
                );

                // Spot-check: none of the three roles may WRITE any /status subresource —
                // upstream reserves status writes for controller identities, never edit/
                // admin/view. (Skip endpointslices here; its write-denial is asserted
                // separately below since it isn't a /status subresource.)
                if subresource == "status" {
                    let update_req = rbac::AuthzRequest {
                        username: &username,
                        groups: &groups,
                        verb: "update",
                        api_group,
                        resource,
                        subresource,
                        namespace: Some(namespace.as_str()),
                        name: None,
                        non_resource_url: None,
                    };
                    assert!(
                        !state.rbac_index.is_allowed(&update_req),
                        "a RoleBinding to '{cluster_role}' must NOT authorize UPDATE on \
                         {api_group}/{resource}/{subresource} — status writes are reserved \
                         for controller identities (e.g. system:kube-controller-manager), \
                         never edit/admin/view, so granting this would be over-broad"
                    );
                }
            }

            // discovery.k8s.io/endpointslices is read-only for all three roles — upstream's
            // editRules() never mentions the discovery group, so edit/admin only inherit
            // the read-only grant from the view aggregation, not create/delete.
            let create_endpointslices = rbac::AuthzRequest {
                username: &username,
                groups: &groups,
                verb: "create",
                api_group: "discovery.k8s.io",
                resource: "endpointslices",
                subresource: "",
                namespace: Some(namespace.as_str()),
                name: None,
                non_resource_url: None,
            };
            assert!(
                !state.rbac_index.is_allowed(&create_endpointslices),
                "a RoleBinding to '{cluster_role}' must NOT authorize CREATE on \
                 discovery.k8s.io/endpointslices — upstream's editRules() never grants write \
                 access to this resource, only system:kube-controller-manager (the \
                 endpointslice controller) may write it"
            );
        }

        // statefulsets/scale, deployments/scale, replicasets/scale: "edit"/"admin" get full
        // CRUD (upstream's editRules() grants Write on these three directly), but "view"
        // must stay read-only — matching the replicationcontrollers/scale precedent.
        let scale_resources = [
            ("apps", "statefulsets"),
            ("apps", "deployments"),
            ("apps", "replicasets"),
        ];
        for cluster_role in ["edit", "admin"] {
            let namespace = format!("e2e-{cluster_role}-status");
            let username = format!("system:serviceaccount:{namespace}:default");
            for (api_group, resource) in scale_resources {
                let update_scale = rbac::AuthzRequest {
                    username: &username,
                    groups: &groups,
                    verb: "update",
                    api_group,
                    resource,
                    subresource: "scale",
                    namespace: Some(namespace.as_str()),
                    name: None,
                    non_resource_url: None,
                };
                assert!(
                    state.rbac_index.is_allowed(&update_scale),
                    "a RoleBinding to '{cluster_role}' must authorize UPDATE on \
                     {api_group}/{resource}/scale — upstream's editRules() grants Write on \
                     this subresource directly"
                );
            }
        }
        let view_namespace = "e2e-view-status";
        let view_username = format!("system:serviceaccount:{view_namespace}:default");
        for (api_group, resource) in scale_resources {
            let get_scale = rbac::AuthzRequest {
                username: &view_username,
                groups: &groups,
                verb: "get",
                api_group,
                resource,
                subresource: "scale",
                namespace: Some(view_namespace),
                name: None,
                non_resource_url: None,
            };
            assert!(
                state.rbac_index.is_allowed(&get_scale),
                "a RoleBinding to 'view' must authorize GET on {api_group}/{resource}/scale \
                 — upstream's viewRules() grants Read on this subresource directly"
            );
            let update_scale = rbac::AuthzRequest {
                username: &view_username,
                groups: &groups,
                verb: "update",
                api_group,
                resource,
                subresource: "scale",
                namespace: Some(view_namespace),
                name: None,
                non_resource_url: None,
            };
            assert!(
                !state.rbac_index.is_allowed(&update_scale),
                "a RoleBinding to 'view' must NOT authorize UPDATE on {api_group}/{resource}/\
                 scale — 'view' is read-only, upstream's editRules() (not viewRules()) grants \
                 the write"
            );
        }
    }

    /// Regression test: RoleBindings to the built-in "edit" AND "admin" ClusterRoles must
    /// authorize GET on the base "namespaces" and "resourcequotas" resources (not just their
    /// /status subresources). Upstream's editRules() never grants write on either resource
    /// directly — its own doc comment on the "edit" ClusterRole explicitly excludes "quota/
    /// limits which are used to control namespaces" from edit's write powers — but the
    /// resolved "edit"/"admin" ClusterRole DOES inherit viewRules()'s read-only grant via the
    /// view aggregation. Before this fix, this codebase's flat admin/edit copies had no rule
    /// at all for the base "namespaces"/"resourcequotas" resources (only their /status
    /// subresources), so a ServiceAccount bound to "edit" or "admin" got a plain RBAC 403
    /// running `kubectl get resourcequota` or `kubectl get namespace <name>` despite view
    /// (a strict subset of edit/admin) already being able to. Also spot-checks that CREATE
    /// stays denied for both roles, matching upstream's explicit non-grant — over-granting
    /// write here would let a namespace editor bypass the quota/limit controls the resource
    /// exists to enforce.
    #[tokio::test]
    async fn edit_and_admin_rolebindings_can_read_base_namespaces_and_resourcequotas() {
        const GROUP: &str = "rbac.authorization.k8s.io";
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        use bytes::Bytes;
        use u7s_store::Store;
        for cluster_role in ["edit", "admin"] {
            let namespace = format!("e2e-{cluster_role}-nsquota");
            let binding_key = keys::group_object_key(
                GROUP,
                "rolebindings",
                Some(namespace.as_str()),
                &format!("{cluster_role}-binding"),
            );
            let binding_val = serde_json::json!({
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": cluster_role
                },
                "subjects": [{
                    "kind": "ServiceAccount",
                    "name": "default",
                    "namespace": namespace
                }]
            });
            store
                .put(&binding_key, Bytes::from(binding_val.to_string()), None)
                .await
                .expect("put rolebinding must not fail");
        }

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];
        for cluster_role in ["edit", "admin"] {
            let namespace = format!("e2e-{cluster_role}-nsquota");
            let username = format!("system:serviceaccount:{namespace}:default");
            for resource in ["namespaces", "resourcequotas"] {
                let get_req = rbac::AuthzRequest {
                    username: &username,
                    groups: &groups,
                    verb: "get",
                    api_group: "",
                    resource,
                    subresource: "",
                    namespace: Some(namespace.as_str()),
                    name: None,
                    non_resource_url: None,
                };
                assert!(
                    state.rbac_index.is_allowed(&get_req),
                    "a RoleBinding to '{cluster_role}' must authorize GET on the base \
                     {resource} resource — upstream's viewRules() grants this and this \
                     codebase's copy previously had no rule for the base resource at all \
                     (only its /status subresource)"
                );

                // Spot-check: neither role may CREATE namespaces/resourcequotas — upstream's
                // editRules() deliberately never grants write on either, since they are used
                // to control namespaces and must remain the domain of the system.
                let create_req = rbac::AuthzRequest {
                    username: &username,
                    groups: &groups,
                    verb: "create",
                    api_group: "",
                    resource,
                    subresource: "",
                    namespace: Some(namespace.as_str()),
                    name: None,
                    non_resource_url: None,
                };
                assert!(
                    !state.rbac_index.is_allowed(&create_req),
                    "a RoleBinding to '{cluster_role}' must NOT authorize CREATE on \
                     {resource} — upstream's editRules() explicitly excludes quota/limit \
                     resources from edit's write powers, so granting this would be over-broad"
                );
            }
        }
    }

    /// Regression test: the KCM resourcequota controller must be able
    /// to PATCH resourcequotas/status after pod creation. With --use-service-account-credentials=false
    /// the KCM uses the system:kube-controller-manager identity for all controllers. If
    /// resourcequotas/status is absent from that ClusterRole, the quota controller gets 403
    /// and quota.status.used is never updated — conformance polls for 300s and times out.
    #[tokio::test]
    async fn kcm_identity_can_patch_resourcequotas_status() {
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];

        // KCM's resourcequota controller patches quota status to update used counts.
        let patch_status = rbac::AuthzRequest {
            username: "system:kube-controller-manager",
            groups: &groups,
            verb: "patch",
            api_group: "",
            resource: "resourcequotas",
            subresource: "status",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&patch_status),
            "system:kube-controller-manager must be allowed to PATCH resourcequotas/status — \
             without this the KCM quota controller gets 403 and quota.status.used is never updated"
        );

        // Also verify GET on resourcequotas/status (quota controller reads current status).
        let get_status = rbac::AuthzRequest {
            username: "system:kube-controller-manager",
            groups: &groups,
            verb: "get",
            api_group: "",
            resource: "resourcequotas",
            subresource: "status",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&get_status),
            "system:kube-controller-manager must be allowed to GET resourcequotas/status — \
             quota controller reads current status before updating it"
        );
    }

    /// Regression test: with --use-service-account-credentials=false, the garbage-collector,
    /// resourcequota, and namespace controllers all run as system:kube-controller-manager and
    /// must be able to discover AND clean up arbitrary/future resource types (including CRDs)
    /// they have no hardcoded knowledge of. Confirmed live, in two stages:
    /// 1. A real KCM process against a read-only version of this rule spammed "is not allowed
    ///    to list poddisruptionbudgets/ingresses/customresourcedefinitions/..." on every one of
    ///    its generic-discovery informers.
    /// 2. After adding read-only get/list/watch, a real namespace deletion (sonobuoy's own
    ///    teardown) hung in Terminating forever: the namespace controller's content-cleanup
    ///    step needs deletecollection across every resource type in the namespace, which
    ///    read-only access does not grant — every teardown failed with a wall of "is not
    ///    allowed to deletecollection <type>" for dozens of types, live-observed in kcm.log.
    /// The verb set here is the union of what upstream's own bootstrap policy grants the three
    /// per-controller ClusterRoles this identity is standing in for (see the seeded-but-unused
    /// system:controller:generic-garbage-collector / resourcequota-controller /
    /// namespace-controller roles elsewhere in this function). Also checks the boundary of
    /// that grant: it still must not include `create` on an arbitrary type, or this would be
    /// silently cluster-admin-equivalent and defeat the whole point of a dedicated identity.
    #[tokio::test]
    async fn kcm_identity_can_discover_and_cleanup_but_not_create_arbitrary_resource_types() {
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];

        let patch_replicaset_status = rbac::AuthzRequest {
            username: "system:kube-controller-manager",
            groups: &groups,
            verb: "patch",
            api_group: "apps",
            resource: "replicasets",
            subresource: "status",
            namespace: Some("kube-system"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&patch_replicaset_status),
            "system:kube-controller-manager must be allowed to PATCH replicasets/status — \
             without it every ReplicaSet sync ends in a 403 and .status.replicas is never \
             updated, live-confirmed via kubectl auth can-i before this fix"
        );

        let create_endpointslice = rbac::AuthzRequest {
            username: "system:kube-controller-manager",
            groups: &groups,
            verb: "create",
            api_group: "discovery.k8s.io",
            resource: "endpointslices",
            subresource: "",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&create_endpointslice),
            "system:kube-controller-manager must be allowed to CREATE endpointslices — the \
             read-only generic-discovery rule doesn't cover this, the endpointslice controller \
             needs its own write grant or every Service's endpoints mirroring silently 403s, \
             live-confirmed via kubectl auth can-i before this fix"
        );

        let list_arbitrary_type = rbac::AuthzRequest {
            username: "system:kube-controller-manager",
            groups: &groups,
            verb: "list",
            api_group: "policy",
            resource: "poddisruptionbudgets",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&list_arbitrary_type),
            "system:kube-controller-manager must be able to LIST resource types outside its \
             explicit rule list (e.g. poddisruptionbudgets) — the GC/quota-monitor controllers \
             discover the full API surface generically, they don't have a hardcoded type list"
        );

        let deletecollection_arbitrary_type = rbac::AuthzRequest {
            username: "system:kube-controller-manager",
            groups: &groups,
            verb: "deletecollection",
            api_group: "policy",
            resource: "poddisruptionbudgets",
            subresource: "",
            namespace: Some("sonobuoy"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state
                .rbac_index
                .is_allowed(&deletecollection_arbitrary_type),
            "system:kube-controller-manager must be allowed to DELETECOLLECTION arbitrary \
             resource types — without it, deleting a namespace hangs in Terminating forever \
             because the namespace controller can never finish clearing its contents, \
             live-confirmed: a real sonobuoy namespace got stuck exactly this way before this fix"
        );

        let namespace_finalize = rbac::AuthzRequest {
            username: "system:kube-controller-manager",
            groups: &groups,
            verb: "update",
            api_group: "",
            resource: "namespaces",
            subresource: "finalize",
            namespace: None,
            name: Some("sonobuoy"),
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&namespace_finalize),
            "system:kube-controller-manager must be allowed to UPDATE namespaces/finalize — \
             without it a namespace whose contents are already gone still never clears its \
             'kubernetes' finalizer and stays Terminating forever"
        );

        let create_arbitrary_type = rbac::AuthzRequest {
            username: "system:kube-controller-manager",
            groups: &groups,
            verb: "create",
            api_group: "policy",
            resource: "poddisruptionbudgets",
            subresource: "",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            !state.rbac_index.is_allowed(&create_arbitrary_type),
            "the generic wildcard rule must stop short of `create` on arbitrary types — if \
             create is also allowed, this identity is silently cluster-admin-equivalent and \
             the dedicated least-privilege identity provides no real boundary"
        );
    }

    /// Regression test (mayor-omwgo): with --use-service-account-credentials=false, the
    /// attach-detach controller also runs as system:kube-controller-manager and must be able
    /// to CREATE and DELETE VolumeAttachments to drive CSI attach/detach. Without `create`
    /// here, a real kube-controller-manager process live-logged "system:kube-controller-manager
    /// is not allowed to create volumeattachments" on every retry, kubelet's volume manager
    /// never saw the volume as attached, and every pod using an attachable CSI driver
    /// (e.g. csi-hostpath) hung in ContainerCreating for the full 300s test timeout —
    /// confirmed via a live sonobuoy `csi-hostpath` run before this fix. Also checks the
    /// boundary: csidrivers gets no dedicated `create` grant from this fix, matching
    /// upstream's real bootstrap policy split between VolumeAttachments (create/delete) and
    /// CSIDriver/CSINode (read-only) for this controller — kubelet and the CSI driver's own
    /// sidecars own those write paths, not KCM.
    #[tokio::test]
    async fn kcm_identity_can_create_and_delete_volumeattachments() {
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];

        let create_va = rbac::AuthzRequest {
            username: "system:kube-controller-manager",
            groups: &groups,
            verb: "create",
            api_group: "storage.k8s.io",
            resource: "volumeattachments",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&create_va),
            "system:kube-controller-manager must be allowed to CREATE volumeattachments — \
             without it the attach-detach controller can never attach a CSI volume and every \
             pod using an attachable driver hangs in ContainerCreating forever, live-confirmed \
             via kcm.log before this fix"
        );

        let delete_va = rbac::AuthzRequest {
            username: "system:kube-controller-manager",
            groups: &groups,
            verb: "delete",
            api_group: "storage.k8s.io",
            resource: "volumeattachments",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&delete_va),
            "system:kube-controller-manager must be allowed to DELETE volumeattachments — \
             without it the attach-detach controller can never detach a CSI volume and the \
             VolumeAttachment object leaks forever after the pod using it is gone"
        );

        // csidrivers gets no dedicated create grant (unlike volumeattachments above) — the
        // attach-detach controller only reads CSIDriver to decide attachability, it never
        // creates one. (update/delete/patch on csidrivers fall through the pre-existing
        // generic-cleanup wildcard shared with the GC/quota/namespace controllers — see
        // kcm_identity_can_discover_and_cleanup_but_not_create_arbitrary_resource_types —
        // but that wildcard deliberately stops short of `create`, same boundary asserted there.)
        let create_csidriver = rbac::AuthzRequest {
            username: "system:kube-controller-manager",
            groups: &groups,
            verb: "create",
            api_group: "storage.k8s.io",
            resource: "csidrivers",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            !state.rbac_index.is_allowed(&create_csidriver),
            "csidrivers must not get a dedicated create grant for this identity — the \
             attach-detach controller never creates a CSIDriver, only volumeattachments needed \
             a new grant for this fix"
        );
    }

    /// Regression test: the scheduler must be able to PATCH pods/binding and pods/status
    /// once it authenticates as its own dedicated identity (system:kube-scheduler) instead
    /// of sharing the admin/system:masters kubeconfig. Without pods/binding, the scheduler
    /// can never actually place a pod on a node — every pod stays Pending forever. Also
    /// verifies the flip side: this identity's ClusterRole is scoped, not cluster-admin, so
    /// it must NOT be allowed to delete a Namespace — a regression here would mean the
    /// dedicated identity is silently as powerful as system:masters, defeating the point of
    /// giving the scheduler its own cert in the first place.
    #[tokio::test]
    async fn scheduler_identity_can_bind_pods_but_not_delete_namespaces() {
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];

        let bind_pod = rbac::AuthzRequest {
            username: "system:kube-scheduler",
            groups: &groups,
            verb: "patch",
            api_group: "",
            resource: "pods",
            subresource: "binding",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&bind_pod),
            "system:kube-scheduler must be allowed to PATCH pods/binding — without this \
             the scheduler can never place a pod on a node and every pod stays Pending forever"
        );

        let patch_pod_status = rbac::AuthzRequest {
            username: "system:kube-scheduler",
            groups: &groups,
            verb: "patch",
            api_group: "",
            resource: "pods",
            subresource: "status",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&patch_pod_status),
            "system:kube-scheduler must be allowed to PATCH pods/status — the scheduler \
             writes scheduling-related conditions onto the pod it just bound"
        );

        let delete_namespace = rbac::AuthzRequest {
            username: "system:kube-scheduler",
            groups: &groups,
            verb: "delete",
            api_group: "",
            resource: "namespaces",
            subresource: "",
            namespace: None,
            name: Some("default"),
            non_resource_url: None,
        };
        assert!(
            !state.rbac_index.is_allowed(&delete_namespace),
            "system:kube-scheduler must NOT be allowed to delete a Namespace — if this \
             identity were granted cluster-admin-equivalent access, the dedicated x509 \
             identity would give no least-privilege benefit over the shared admin kubeconfig \
             it replaces"
        );
    }

    /// Regression test: the bootstrap-installer identity must be able to CREATE a ConfigMap
    /// in an arbitrary namespace — without this rule, the bootstrap-installer applier (a
    /// later bead) cannot install CoreDNS's ConfigMap and the whole bootstrap YAML apply
    /// fails before the cluster ever gets DNS.
    #[tokio::test]
    async fn bootstrap_installer_identity_can_create_configmap() {
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];
        let create_configmap = rbac::AuthzRequest {
            username: "system:bootstrap-installer",
            groups: &groups,
            verb: "create",
            api_group: "",
            resource: "configmaps",
            subresource: "",
            namespace: Some("kube-system"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&create_configmap),
            "system:bootstrap-installer must be allowed to CREATE configmaps — without this \
             rule the bootstrap-installer applier cannot install CoreDNS's ConfigMap and the \
             bootstrap YAML apply fails before the cluster ever gets DNS"
        );
    }

    /// Regression test: the bootstrap-installer identity must be able to PATCH an apps/v1
    /// Deployment — server-side-apply re-runs of the applier (idempotent re-application of
    /// the same manifest bundle) issue PATCH, not just CREATE, so without this verb every
    /// re-apply after the first would 403 and CoreDNS could never be upgraded in place.
    #[tokio::test]
    async fn bootstrap_installer_identity_can_patch_deployment() {
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];
        let patch_deployment = rbac::AuthzRequest {
            username: "system:bootstrap-installer",
            groups: &groups,
            verb: "patch",
            api_group: "apps",
            resource: "deployments",
            subresource: "",
            namespace: Some("kube-system"),
            name: Some("coredns"),
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&patch_deployment),
            "system:bootstrap-installer must be allowed to PATCH apps/v1 deployments — \
             without this, re-applying the bootstrap manifest bundle (e.g. after a version \
             bump) 403s instead of upserting CoreDNS's Deployment"
        );
    }

    /// Regression test: the bootstrap-installer identity must be able to CREATE a
    /// ClusterRoleBinding — CoreDNS's manifest bundle ships its own ClusterRole and
    /// ClusterRoleBinding for the coredns ServiceAccount, and without this rule the
    /// applier can never grant CoreDNS the RBAC it needs to watch Services/Endpoints.
    #[tokio::test]
    async fn bootstrap_installer_identity_can_create_clusterrolebinding() {
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];
        let create_crb = rbac::AuthzRequest {
            username: "system:bootstrap-installer",
            groups: &groups,
            verb: "create",
            api_group: "rbac.authorization.k8s.io",
            resource: "clusterrolebindings",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&create_crb),
            "system:bootstrap-installer must be allowed to CREATE clusterrolebindings — \
             CoreDNS's manifest bundle ships its own ClusterRoleBinding for the coredns \
             ServiceAccount, and without this rule the applier can never grant CoreDNS the \
             RBAC it needs to watch Services/Endpoints"
        );
    }

    /// Regression test / sanity check: the bootstrap-installer identity must NOT be allowed
    /// to DELETE a Namespace. The applier is deliberately upsert-only (create/patch/update
    /// on a fixed set of Kinds) — if a scoping mistake ever granted delete verbs, this
    /// identity would go from "installs a manifest bundle" to "can tear down a whole
    /// namespace", a much larger blast radius than the applier is meant to have.
    #[tokio::test]
    async fn bootstrap_installer_identity_cannot_delete_namespace() {
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];
        let delete_namespace = rbac::AuthzRequest {
            username: "system:bootstrap-installer",
            groups: &groups,
            verb: "delete",
            api_group: "",
            resource: "namespaces",
            subresource: "",
            namespace: None,
            name: Some("kube-system"),
            non_resource_url: None,
        };
        assert!(
            !state.rbac_index.is_allowed(&delete_namespace),
            "system:bootstrap-installer must NOT be allowed to DELETE a Namespace — the \
             applier is deliberately upsert-only, and a regression here would silently \
             widen its blast radius from 'installs a manifest bundle' to 'can tear down a \
             whole namespace'"
        );
    }

    /// bootstrap_service_ips must derive both bootstrap ClusterIPs from whatever range
    /// is configured, falling back to the historical default only when the range is
    /// empty (disabled auto-allocation still needs concrete bootstrap IPs), and must
    /// reject a range too small to hold the tenth host reserved for kube-dns.
    #[test]
    fn bootstrap_service_ips_derives_or_falls_back_correctly() {
        let (k8s_ip, dns_ip) =
            bootstrap_service_ips("10.96.0.0/12").expect("default range must resolve");
        assert_eq!(k8s_ip.to_string(), "10.96.0.1");
        assert_eq!(dns_ip.to_string(), "10.96.0.10");

        let (k8s_ip, dns_ip) =
            bootstrap_service_ips("172.20.0.0/16").expect("custom range must resolve");
        assert_eq!(
            k8s_ip.to_string(),
            "172.20.0.1",
            "kubernetes ClusterIP must derive from the custom range"
        );
        assert_eq!(
            dns_ip.to_string(),
            "172.20.0.10",
            "kube-dns ClusterIP must derive from the custom range"
        );

        let (k8s_ip, dns_ip) = bootstrap_service_ips("")
            .expect("empty range (auto-allocation disabled) must still yield bootstrap IPs");
        assert_eq!(
            k8s_ip.to_string(),
            "10.96.0.1",
            "empty --service-cluster-ip-range only disables allocation for user Services; \
             the bootstrap Services still need a concrete ClusterIP"
        );
        assert_eq!(dns_ip.to_string(), "10.96.0.10");

        assert!(
            bootstrap_service_ips("10.0.0.0/30").is_err(),
            "a /30 has no tenth host for kube-dns — this must fail loudly at startup \
             instead of seeding a wrong or out-of-range ClusterIP"
        );
    }

    #[tokio::test]
    async fn seed_services_creates_kubernetes_service_and_reserves_kube_dns_ip() {
        // default/kubernetes must exist: pods reach the API server via
        // kubernetes.default.svc.cluster.local. kube-system/kube-dns itself is applied later
        // from the vendored CoreDNS bundle, but its clusterIP must already be reserved here so
        // no ordinary dynamic Service can grab 10.96.0.10 first.
        let store = make_store();
        seed_namespaces(&store)
            .await
            .expect("namespaces must be seeded first");
        seed_services(&store, "127.0.0.1", 6443, "10.96.0.0/12")
            .await
            .expect("seed must not fail");

        // Verify default/kubernetes Service.
        let k8s_key = keys::object_key("services", "default", "kubernetes");
        let k8s_obj = store.get(&k8s_key).await.expect("get must not fail");
        assert!(
            k8s_obj.is_some(),
            "Service default/kubernetes must exist after seeding"
        );
        let k8s: serde_json::Value =
            serde_json::from_slice(&k8s_obj.unwrap().value).expect("valid json");
        assert_eq!(k8s["kind"].as_str(), Some("Service"));
        assert_eq!(k8s["metadata"]["name"].as_str(), Some("kubernetes"));
        assert_eq!(k8s["metadata"]["namespace"].as_str(), Some("default"));
        assert_eq!(k8s["spec"]["clusterIP"].as_str(), Some("10.96.0.1"));
        let k8s_ports = k8s["spec"]["ports"]
            .as_array()
            .expect("ports must be an array");
        assert_eq!(
            k8s_ports.len(),
            1,
            "kubernetes Service must have exactly one port"
        );
        assert_eq!(k8s_ports[0]["port"].as_u64(), Some(443));
        assert_eq!(k8s_ports[0]["targetPort"].as_u64(), Some(6443));
        assert_eq!(k8s_ports[0]["protocol"].as_str(), Some("TCP"));

        // Verify kube-dns's clusterIP sentinel is reserved, even though the kube-dns Service
        // object itself is created later by the bootstrap YAML applier, not by seed_services.
        let sentinel_key = format!("{}10.96.0.10", state::SERVICE_IP_PREFIX);
        assert!(
            store
                .get(&sentinel_key)
                .await
                .expect("get must not fail")
                .is_some(),
            "kube-dns's clusterIP (10.96.0.10) must be reserved in the allocator's sentinel \
             keyspace — without it, allocate_service_ip could hand 10.96.0.10 to an ordinary \
             dynamic Service, colliding with the CoreDNS bundle's fixed VIP once it's applied"
        );
    }

    /// seed_services must derive the bootstrap ClusterIPs from a non-default
    /// --service-cluster-ip-range, not hardcode 10.96.0.1/10.96.0.10.
    ///
    /// An operator running u7s with e.g. --service-cluster-ip-range 172.20.0.0/16 would
    /// otherwise get bootstrap Services outside their configured ServiceCIDR — failing
    /// the startup coherence check, and leaving kube-proxy/kubelet programmed against an
    /// IP the range doesn't actually own.
    #[tokio::test]
    async fn seed_services_derives_cluster_ips_from_custom_range() {
        let store = make_store();
        seed_namespaces(&store)
            .await
            .expect("namespaces must be seeded first");
        seed_services(&store, "127.0.0.1", 6443, "172.20.0.0/16")
            .await
            .expect("seed must not fail");

        let k8s_key = keys::object_key("services", "default", "kubernetes");
        let k8s: serde_json::Value = serde_json::from_slice(
            &store
                .get(&k8s_key)
                .await
                .expect("get must not fail")
                .unwrap()
                .value,
        )
        .expect("valid json");
        assert_eq!(
            k8s["spec"]["clusterIP"].as_str(),
            Some("172.20.0.1"),
            "kubernetes Service ClusterIP must be the first host of the configured range, \
             not the 10.96.0.1 hardcode — otherwise it falls outside the seeded ServiceCIDR"
        );

        let sentinel_key = format!("{}172.20.0.10", state::SERVICE_IP_PREFIX);
        assert!(
            store
                .get(&sentinel_key)
                .await
                .expect("get must not fail")
                .is_some(),
            "kube-dns's clusterIP sentinel must reserve the tenth host of the configured \
             range, not the 10.96.0.10 hardcode — otherwise a custom range's dynamic Service \
             allocation could still collide with whatever IP the CoreDNS bundle is later given"
        );
    }

    #[tokio::test]
    async fn seed_services_is_idempotent() {
        // A second call must not error — CAS rv=0 returns AlreadyExists which is silently ignored.
        // This matches the startup guarantee: u7s may restart against an existing database.
        let store = make_store();
        seed_namespaces(&store)
            .await
            .expect("namespaces must be seeded first");
        seed_services(&store, "127.0.0.1", 6443, "10.96.0.0/12")
            .await
            .expect("first seed must not fail");
        seed_services(&store, "127.0.0.1", 6443, "10.96.0.0/12")
            .await
            .expect("second seed must not fail");

        // Data must still be correct after two calls.
        let k8s_key = keys::object_key("services", "default", "kubernetes");
        let k8s_obj = store.get(&k8s_key).await.expect("get must not fail");
        assert!(
            k8s_obj.is_some(),
            "Service default/kubernetes must still exist"
        );
        let sentinel_key = format!("{}10.96.0.10", state::SERVICE_IP_PREFIX);
        assert!(
            store
                .get(&sentinel_key)
                .await
                .expect("get must not fail")
                .is_some(),
            "kube-dns's clusterIP sentinel must still be reserved after a second seed call"
        );
    }

    /// seed_services must also create the 'kubernetes' Endpoints object in the default namespace.
    ///
    /// Controllers such as the endpoint controller and some admission webhooks watch this
    /// object to locate the apiserver IP/port. Without it they log errors on startup and
    /// may refuse to start. The corresponding Service (default/kubernetes) alone is not enough
    /// because older controllers resolve the apiserver address via Endpoints, not EndpointSlices.
    #[tokio::test]
    async fn seed_services_creates_kubernetes_endpoints() {
        let store = make_store();
        seed_namespaces(&store)
            .await
            .expect("namespaces must be seeded first");
        seed_services(&store, "127.0.0.1", 6443, "10.96.0.0/12")
            .await
            .expect("seed must not fail");

        let ep_key = keys::object_key("endpoints", "default", "kubernetes");
        let ep_obj = store.get(&ep_key).await.expect("get must not fail");
        assert!(
            ep_obj.is_some(),
            "Endpoints default/kubernetes must exist after seeding — \
             controllers watch this object to locate the apiserver; \
             without it they log errors and may fail to start"
        );
        let ep: serde_json::Value =
            serde_json::from_slice(&ep_obj.unwrap().value).expect("valid json");
        assert_eq!(ep["kind"].as_str(), Some("Endpoints"));
        assert_eq!(ep["metadata"]["name"].as_str(), Some("kubernetes"));
        assert_eq!(ep["metadata"]["namespace"].as_str(), Some("default"));
        let subsets = ep["subsets"].as_array().expect("subsets must be an array");
        assert!(
            !subsets.is_empty(),
            "Endpoints must have at least one subset"
        );
        let addresses = subsets[0]["addresses"]
            .as_array()
            .expect("addresses must be an array");
        assert!(
            !addresses.is_empty(),
            "subset must have at least one address"
        );
        let ip = addresses[0]["ip"].as_str().unwrap_or("");
        assert!(!ip.is_empty(), "endpoint address must have a non-empty IP");
        let ports = subsets[0]["ports"]
            .as_array()
            .expect("ports must be an array");
        assert!(!ports.is_empty(), "subset must have at least one port");
        assert_eq!(
            ports[0]["port"].as_u64(),
            Some(443),
            "kubernetes Endpoints must expose port 443 — apiserver HTTPS port"
        );
        assert_eq!(
            ports[0]["protocol"].as_str(),
            Some("TCP"),
            "kubernetes Endpoints port must be TCP"
        );
    }

    #[tokio::test]
    async fn seed_services_creates_kubernetes_endpointslice() {
        // kube-proxy (k8s 1.34+) uses EndpointSlices exclusively. The kubernetes Endpoints carries
        // skip-mirror:true so the mirroring controller won't create a slice. Without a seeded
        // EndpointSlice, kube-proxy never programs 10.96.0.1:443 → <apiserver-ip>:6443, so pods
        // cannot reach the apiserver via ClusterIP — sonobuoy aggregator hangs.
        // Use a non-default IP to verify the parameter flows through, not a hardcoded fallback.
        let store = make_store();
        seed_namespaces(&store)
            .await
            .expect("namespaces must be seeded first");
        seed_services(&store, "192.168.5.2", 6443, "10.96.0.0/12")
            .await
            .expect("seed must not fail");

        let eps_key = keys::group_object_key(
            "discovery.k8s.io",
            "endpointslices",
            Some("default"),
            "kubernetes",
        );
        let eps_obj = store.get(&eps_key).await.expect("get must not fail");
        assert!(
            eps_obj.is_some(),
            "EndpointSlice default/kubernetes must exist after seeding — \
             kube-proxy uses EndpointSlices to program ClusterIP iptables rules; \
             without it pods cannot reach the apiserver at 10.96.0.1:443"
        );
        let eps: serde_json::Value =
            serde_json::from_slice(&eps_obj.unwrap().value).expect("valid json");
        assert_eq!(
            eps["addressType"].as_str(),
            Some("IPv4"),
            "addressType must be IPv4 — empty or missing addressType causes kube-proxy to log \
             'EndpointSlice address type not supported' and skip programming the iptables rule"
        );
        assert_eq!(
            eps["metadata"]["labels"]["kubernetes.io/service-name"].as_str(),
            Some("kubernetes"),
            "service-name label must match the kubernetes service so kube-proxy associates this slice"
        );
        let endpoints = eps["endpoints"]
            .as_array()
            .expect("endpoints must be an array");
        assert!(
            !endpoints.is_empty(),
            "EndpointSlice must have at least one endpoint"
        );
        let addresses = endpoints[0]["addresses"]
            .as_array()
            .expect("addresses must be an array");
        assert!(
            !addresses.is_empty(),
            "endpoint must have at least one address"
        );
        assert_eq!(
            addresses[0].as_str(),
            Some("192.168.5.2"),
            "EndpointSlice address must reflect the apiserver_ip parameter — kube-proxy uses \
             this to program IPVS; wrong IP (e.g. 127.0.0.1) black-holes in-pod apiserver traffic"
        );
        let ports = eps["ports"].as_array().expect("ports must be an array");
        assert!(
            !ports.is_empty(),
            "EndpointSlice must have at least one port"
        );
        assert_eq!(
            ports[0]["port"].as_u64(),
            Some(6443),
            "EndpointSlice port must be the actual apiserver port, not the service port 443"
        );
    }

    /// reconcile_kubernetes_endpointslice must propagate EndpointSlice addresses AND ports
    /// into the kubernetes Endpoints so both objects agree.
    ///
    /// kube-controller-manager's endpointslice-controller runs inside the Lima VM and
    /// patches the kubernetes EndpointSlice with the apiserver address as seen from the VM
    /// (e.g. the Lima gateway IP 192.168.5.2) and the actual apiserver port (e.g. 6443).
    /// This leaves the EndpointSlice with addresses and ports that don't match the Endpoints
    /// (which has only 127.0.0.1 and port 443 from seeding). The conformance test
    /// [sig-network] API Server 'should have Endpoints and EndpointSlices pointing to
    /// API Server' checks BOTH addresses and ports, and fails when they disagree.
    ///
    /// The reconciler MUST update Endpoints (not EndpointSlice) because:
    ///   - kube-proxy reads EndpointSlice to program IPVS; removing 192.168.5.2 from the
    ///     EndpointSlice would route all pod→kubernetes traffic to 127.0.0.1:6443 (the VM
    ///     loopback, unreachable), breaking pod connectivity.
    ///   - Updating Endpoints to match EndpointSlice satisfies the conformance assertion
    ///     without breaking kube-proxy routing.
    ///
    /// This test fails if reconcile_kubernetes_endpointslice is removed or inverted:
    ///   - Removed → EndpointSlice keeps 192.168.5.2 and port 6443, Endpoints keeps only
    ///     127.0.0.1 and port 443, both conformance assertions fire.
    ///   - Inverted (remove 192.168.5.2 from EndpointSlice) → kube-proxy loses the only
    ///     reachable backend, pod→kubernetes service connections time out.
    #[tokio::test]
    async fn reconcile_kubernetes_endpointslice_syncs_endpoints_to_match_endpointslice() {
        use bytes::Bytes;
        use u7s_store::Store;

        let store = make_store();
        seed_namespaces(&store)
            .await
            .expect("namespaces must be seeded first");
        seed_services(&store, "127.0.0.1", 6443, "10.96.0.0/12")
            .await
            .expect("seed must not fail");

        let ep_key = keys::object_key("endpoints", "default", "kubernetes");
        let eps_key = keys::group_object_key(
            "discovery.k8s.io",
            "endpointslices",
            Some("default"),
            "kubernetes",
        );

        // Simulate KCM patching the EndpointSlice to add the Lima VM gateway IP and use
        // the actual apiserver port (6443 — the port KCM connects to from inside the VM).
        let eps_obj = store
            .get(&eps_key)
            .await
            .expect("get must not fail")
            .unwrap();
        let mut eps: serde_json::Value =
            serde_json::from_slice(&eps_obj.value).expect("valid json");
        eps["endpoints"] = serde_json::json!([{
            "addresses": ["127.0.0.1", "192.168.5.2"],
            "conditions": { "ready": true, "serving": true, "terminating": false }
        }]);
        // KCM also sets the port to the actual apiserver port.
        eps["ports"] = serde_json::json!([{ "name": "https", "port": 6443, "protocol": "TCP" }]);
        store
            .put(&eps_key, Bytes::from(eps.to_string()), None)
            .await
            .expect("put must not fail");

        // Reconcile — should update Endpoints to match EndpointSlice (addresses AND ports).
        reconcile_kubernetes_endpointslice(&store).await;

        // EndpointSlice must be UNCHANGED (still has both addresses and port 6443).
        let eps_after = store
            .get(&eps_key)
            .await
            .expect("get must not fail")
            .unwrap();
        let eps_val: serde_json::Value =
            serde_json::from_slice(&eps_after.value).expect("valid json");
        let mut eps_addrs: Vec<&str> = eps_val["endpoints"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|e| e["addresses"].as_array().into_iter().flatten())
            .filter_map(|a| a.as_str())
            .collect();
        eps_addrs.sort();
        assert_eq!(
            eps_addrs,
            vec!["127.0.0.1", "192.168.5.2"],
            "EndpointSlice must retain 192.168.5.2 so kube-proxy programs a reachable IPVS \
             backend; removing it would route pod→kubernetes traffic to 127.0.0.1 (VM loopback)"
        );
        assert_eq!(
            eps_val["ports"][0]["port"].as_u64(),
            Some(6443),
            "EndpointSlice port must remain unchanged at 6443"
        );

        // Endpoints must now match EndpointSlice addresses AND ports.
        let ep_after = store
            .get(&ep_key)
            .await
            .expect("get must not fail")
            .unwrap();
        let ep_val: serde_json::Value =
            serde_json::from_slice(&ep_after.value).expect("valid json");
        let mut ep_addrs: Vec<&str> = ep_val["subsets"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|s| s["addresses"].as_array().into_iter().flatten())
            .filter_map(|a| a["ip"].as_str())
            .collect();
        ep_addrs.sort();
        assert_eq!(
            ep_addrs,
            vec!["127.0.0.1", "192.168.5.2"],
            "Endpoints must be updated to match EndpointSlice addresses — the conformance test \
             'should have Endpoints and EndpointSlices pointing to API Server' requires them equal"
        );
        let ep_port = ep_val["subsets"][0]["ports"][0]["port"].as_u64();
        assert_eq!(
            ep_port,
            Some(6443),
            "Endpoints port must be updated to match EndpointSlice port — the conformance test \
             checks both addresses and ports must match"
        );
    }

    /// reconcile_kubernetes_endpointslice must not call store.put when Endpoints already
    /// matches EndpointSlice — unconditional writes generate spurious MODIFIED watch events
    /// every 5 seconds, causing all Endpoints informers to resync unnecessarily.
    #[tokio::test]
    async fn reconcile_kubernetes_endpointslice_skips_put_when_already_in_sync() {
        use bytes::Bytes;
        use u7s_store::Store;

        let store = make_store();
        seed_namespaces(&store)
            .await
            .expect("namespaces must be seeded first");
        seed_services(&store, "127.0.0.1", 6443, "10.96.0.0/12")
            .await
            .expect("seed must not fail");

        let ep_key = keys::object_key("endpoints", "default", "kubernetes");
        let eps_key = keys::group_object_key(
            "discovery.k8s.io",
            "endpointslices",
            Some("default"),
            "kubernetes",
        );

        // Patch EndpointSlice so it differs from seeded Endpoints.
        let eps_obj = store
            .get(&eps_key)
            .await
            .expect("get must not fail")
            .unwrap();
        let mut eps: serde_json::Value =
            serde_json::from_slice(&eps_obj.value).expect("valid json");
        eps["endpoints"] =
            serde_json::json!([{ "addresses": ["192.168.5.2"], "conditions": { "ready": true } }]);
        eps["ports"] = serde_json::json!([{ "name": "https", "port": 6443, "protocol": "TCP" }]);
        store
            .put(&eps_key, Bytes::from(eps.to_string()), None)
            .await
            .expect("put must not fail");

        // First reconcile — Endpoints differ from EndpointSlice, so store.put must be called.
        reconcile_kubernetes_endpointslice(&store).await;
        let revision_after_first = store
            .get(&ep_key)
            .await
            .expect("get must not fail")
            .unwrap()
            .revision;

        // Second reconcile — Endpoints now match EndpointSlice; store.put must NOT be called.
        // If it were called, the revision would increment, generating a spurious MODIFIED event.
        reconcile_kubernetes_endpointslice(&store).await;
        let revision_after_second = store
            .get(&ep_key)
            .await
            .expect("get must not fail")
            .unwrap()
            .revision;

        assert_eq!(
            revision_after_first, revision_after_second,
            "second reconcile must not write to the store when Endpoints already matches \
             EndpointSlice — spurious writes generate MODIFIED watch events every 5 seconds"
        );
    }

    /// Returns a unique temp dir with `ca.crt`/`proxy-client-ca.crt` written to it (contents
    /// `ca_bytes`/`proxy_ca_bytes` respectively). `reconcile_extension_apiserver_authentication`
    /// only reads each file's raw bytes and PEM-wraps them — it never parses them as real
    /// certificates — so arbitrary bytes are sufficient to exercise the reconciler without
    /// paying for real cert generation.
    fn write_temp_ca_certs(
        tag: &str,
        ca_bytes: &[u8],
        proxy_ca_bytes: &[u8],
    ) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let tid = std::thread::current().id();
        let dir = std::env::temp_dir().join(format!("u7s-authinfo-test-{tag}-{nanos}-{tid:?}"));
        std::fs::create_dir_all(&dir).expect("create temp dir"); // lgtm[rust/path-injection]
        std::fs::write(dir.join("ca.crt"), ca_bytes).expect("write temp CA cert"); // lgtm[rust/path-injection]
        std::fs::write(dir.join("proxy-client-ca.crt"), proxy_ca_bytes) // lgtm[rust/path-injection]
            .expect("write temp front-proxy CA cert");
        dir
    }

    /// On a fresh cluster (no prior extension-apiserver-authentication ConfigMap), the
    /// first reconcile tick must create it with `client-ca-file` AND the real front-proxy
    /// trust anchor (`requestheader-client-ca-file` plus the fixed `requestheader-*-headers`/
    /// `-allowed-names` keys) populated. Without `client-ca-file`, metrics-server's
    /// `ConfigMapCAFileContent` informer retries against a 404 forever (the original bug
    /// this reconciler exists to fix); without the `requestheader-*` keys, an aggregated
    /// backend never trusts the proxy-client cert `handlers::aggregation::proxy_to_backend`
    /// presents, so it never trusts the X-Remote-User/-Group headers that ride along with it.
    #[tokio::test]
    async fn reconcile_extension_apiserver_authentication_creates_configmap_on_fresh_cluster() {
        let store = make_store();
        let dir = write_temp_ca_certs("fresh", b"fake-ca-der-bytes-v1", b"fake-proxy-ca-v1");

        let ok = reconcile_extension_apiserver_authentication(
            &store,
            &dir.join("ca.crt").to_string_lossy(),
            &dir.join("proxy-client-ca.crt").to_string_lossy(),
        )
        .await;
        assert!(ok, "reconcile must succeed against a fresh, empty store");

        let key = keys::object_key(
            "configmaps",
            "kube-system",
            "extension-apiserver-authentication",
        );
        let obj = store.get(&key).await.expect("get must not fail").expect(
            "extension-apiserver-authentication ConfigMap must exist after the first \
                 reconcile tick",
        );
        let cm: serde_json::Value = serde_json::from_slice(&obj.value).expect("valid json");
        assert_eq!(cm["kind"].as_str(), Some("ConfigMap"));
        assert_eq!(cm["metadata"]["namespace"].as_str(), Some("kube-system"));
        let expected_pem =
            String::from_utf8(tls::pem_encode("CERTIFICATE", b"fake-ca-der-bytes-v1")).unwrap();
        assert_eq!(
            cm["data"]["client-ca-file"].as_str(),
            Some(expected_pem.as_str()),
            "client-ca-file must contain the PEM-encoded bytes of the on-disk CA cert, or \
             an aggregated backend's RequestHeaderAuthRequestController has nothing to trust"
        );
        let expected_proxy_pem =
            String::from_utf8(tls::pem_encode("CERTIFICATE", b"fake-proxy-ca-v1")).unwrap();
        assert_eq!(
            cm["data"]["requestheader-client-ca-file"].as_str(),
            Some(expected_proxy_pem.as_str()),
            "requestheader-client-ca-file must contain the PEM-encoded dedicated front-proxy \
             CA, or an aggregated backend never trusts the proxy-client cert presented by \
             handlers::aggregation::proxy_to_backend and falls back to treating every \
             proxied request as anonymous"
        );
        assert_eq!(
            cm["data"]["requestheader-username-headers"].as_str(),
            Some("[\"X-Remote-User\"]"),
            "must advertise X-Remote-User as the username header, matching what \
             proxy_to_backend actually sets"
        );
        assert_eq!(
            cm["data"]["requestheader-group-headers"].as_str(),
            Some("[\"X-Remote-Group\"]")
        );
        assert_eq!(
            cm["data"]["requestheader-extra-headers-prefix"].as_str(),
            Some("[\"X-Remote-Extra-\"]")
        );
        assert_eq!(
            cm["data"]["requestheader-allowed-names"].as_str(),
            Some("[\"front-proxy-client\"]")
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// A CA rotation (the on-disk CA cert file's content changes) must be picked up on the
    /// NEXT reconcile tick and written into the ConfigMap. This is the entire reason the
    /// operator chose a continuous reconcile loop (approach B) over a one-shot seed
    /// (approach A): a one-shot seed would freeze the ConfigMap's client-ca-file at
    /// whatever the CA was at boot, silently breaking every aggregated backend's trust
    /// anchor the moment u7s ever rotates its CA — with no code path left to fix it short
    /// of a full restart.
    #[tokio::test]
    async fn reconcile_extension_apiserver_authentication_updates_configmap_on_ca_rotation() {
        let store = make_store();
        let dir = write_temp_ca_certs("rotate", b"fake-ca-der-bytes-v1", b"fake-proxy-ca-v1");
        let ca_path = dir.join("ca.crt");
        let proxy_ca_path = dir.join("proxy-client-ca.crt");

        reconcile_extension_apiserver_authentication(
            &store,
            &ca_path.to_string_lossy(),
            &proxy_ca_path.to_string_lossy(),
        )
        .await;

        // Simulate CA rotation: the file's content changes on disk without a restart.
        std::fs::write(&ca_path, b"fake-ca-der-bytes-v2-rotated").expect("rewrite CA cert"); // lgtm[rust/path-injection]

        let ok = reconcile_extension_apiserver_authentication(
            &store,
            &ca_path.to_string_lossy(),
            &proxy_ca_path.to_string_lossy(),
        )
        .await;
        assert!(ok, "reconcile must succeed after CA rotation");

        let key = keys::object_key(
            "configmaps",
            "kube-system",
            "extension-apiserver-authentication",
        );
        let obj = store
            .get(&key)
            .await
            .expect("get must not fail")
            .expect("ConfigMap must still exist after rotation");
        let cm: serde_json::Value = serde_json::from_slice(&obj.value).expect("valid json");
        let expected_pem = String::from_utf8(tls::pem_encode(
            "CERTIFICATE",
            b"fake-ca-der-bytes-v2-rotated",
        ))
        .unwrap();
        assert_eq!(
            cm["data"]["client-ca-file"].as_str(),
            Some(expected_pem.as_str()),
            "client-ca-file must reflect the rotated CA content — a stale value here means \
             every aggregated backend keeps trusting a retired CA after rotation"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Regression test for the "return early only if BOTH CAs already match" logic: a
    /// front-proxy CA rotation must be picked up even when the (unrelated) main cluster CA
    /// is UNCHANGED. A naive "skip write if client-ca-file matches" check (checking only
    /// one of the two CA fields) would silently leave requestheader-client-ca-file stale
    /// forever once client-ca-file happened to already match, permanently breaking the
    /// aggregation front-proxy trust anchor with no further reconcile tick able to fix it.
    #[tokio::test]
    async fn reconcile_extension_apiserver_authentication_updates_on_proxy_ca_rotation_alone() {
        let store = make_store();
        let dir = write_temp_ca_certs("proxy-rotate", b"stable-cluster-ca", b"proxy-ca-v1");
        let ca_path = dir.join("ca.crt");
        let proxy_ca_path = dir.join("proxy-client-ca.crt");

        reconcile_extension_apiserver_authentication(
            &store,
            &ca_path.to_string_lossy(),
            &proxy_ca_path.to_string_lossy(),
        )
        .await;

        // Rotate ONLY the front-proxy CA; the cluster CA file is untouched.
        std::fs::write(&proxy_ca_path, b"proxy-ca-v2-rotated").expect("rewrite proxy CA"); // lgtm[rust/path-injection]

        reconcile_extension_apiserver_authentication(
            &store,
            &ca_path.to_string_lossy(),
            &proxy_ca_path.to_string_lossy(),
        )
        .await;

        let key = keys::object_key(
            "configmaps",
            "kube-system",
            "extension-apiserver-authentication",
        );
        let obj = store
            .get(&key)
            .await
            .expect("get must not fail")
            .expect("ConfigMap must still exist");
        let cm: serde_json::Value = serde_json::from_slice(&obj.value).expect("valid json");
        let expected_pem =
            String::from_utf8(tls::pem_encode("CERTIFICATE", b"proxy-ca-v2-rotated")).unwrap();
        assert_eq!(
            cm["data"]["requestheader-client-ca-file"].as_str(),
            Some(expected_pem.as_str()),
            "requestheader-client-ca-file must reflect the rotated front-proxy CA even though \
             client-ca-file (the unrelated cluster CA) never changed"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// When both on-disk CA certs are unchanged between ticks, the reconciler must not write
    /// to the store. An unconditional write every tick would bump the ConfigMap's
    /// resourceVersion and fire a spurious MODIFIED event on every poll interval,
    /// flooding any watcher of this ConfigMap (mirrors the same concern already tested for
    /// reconcile_kubernetes_endpointslice above).
    #[tokio::test]
    async fn reconcile_extension_apiserver_authentication_skips_write_when_ca_unchanged() {
        let store = make_store();
        let dir = write_temp_ca_certs("unchanged", b"fake-ca-der-bytes-stable", b"fake-proxy-ca");
        let ca_path = dir.join("ca.crt");
        let proxy_ca_path = dir.join("proxy-client-ca.crt");

        reconcile_extension_apiserver_authentication(
            &store,
            &ca_path.to_string_lossy(),
            &proxy_ca_path.to_string_lossy(),
        )
        .await;
        let key = keys::object_key(
            "configmaps",
            "kube-system",
            "extension-apiserver-authentication",
        );
        let revision_after_first = store
            .get(&key)
            .await
            .expect("get must not fail")
            .unwrap()
            .revision;

        reconcile_extension_apiserver_authentication(
            &store,
            &ca_path.to_string_lossy(),
            &proxy_ca_path.to_string_lossy(),
        )
        .await;
        let revision_after_second = store
            .get(&key)
            .await
            .expect("get must not fail")
            .unwrap()
            .revision;

        assert_eq!(
            revision_after_first, revision_after_second,
            "second reconcile must not write to the store when the CA content is unchanged \
             — spurious writes would generate a MODIFIED watch event every poll interval"
        );

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    #[tokio::test]
    async fn seed_serviceaccounts_creates_default_sa_in_each_namespace() {
        // The default ServiceAccount must exist in every seeded namespace so that
        // pods can obtain a projected SA token via TokenRequest. Without it,
        // the TokenRequest handler returns 404 and in-cluster authentication fails.
        // The SA must also carry a non-empty UID so the kubernetes.io.serviceaccount.uid
        // JWT claim is populated — an empty UID breaks the token projection contract.
        let store = make_store();
        seed_serviceaccounts(&store)
            .await
            .expect("seed must not fail");

        for ns in ["default", "kube-system", "kube-node-lease", "kube-public"] {
            let key = keys::object_key("serviceaccounts", ns, "default");
            let obj = store.get(&key).await.expect("get must not fail");
            assert!(
                obj.is_some(),
                "ServiceAccount {ns}/default must exist after seeding"
            );
            let parsed: serde_json::Value =
                serde_json::from_slice(&obj.unwrap().value).expect("valid json");
            assert_eq!(parsed["kind"].as_str(), Some("ServiceAccount"));
            assert_eq!(parsed["metadata"]["name"].as_str(), Some("default"));
            assert_eq!(parsed["metadata"]["namespace"].as_str(), Some(ns));
            // UID must be non-empty so the JWT kubernetes.io.serviceaccount.uid claim
            // is populated. An empty UID violates the Kubernetes token projection spec.
            let uid = parsed["metadata"]["uid"].as_str().unwrap_or("");
            assert!(
                !uid.is_empty(),
                "ServiceAccount {ns}/default must have a non-empty UID — \
                 an empty UID causes the JWT kubernetes.io.serviceaccount.uid claim \
                 to be empty, breaking in-cluster token correlation"
            );
        }
    }

    #[tokio::test]
    async fn seed_serviceaccounts_is_idempotent() {
        // A second call must not error — CAS rv=0 returns AlreadyExists which is silently ignored.
        let store = make_store();
        seed_serviceaccounts(&store)
            .await
            .expect("first seed must not fail");
        seed_serviceaccounts(&store)
            .await
            .expect("second seed must not fail");
    }

    #[tokio::test]
    async fn seed_kube_root_ca_creates_configmap_in_each_namespace() {
        // Every pod admitted after boot gets a projected SA token volume that references
        // the "kube-root-ca.crt" ConfigMap by name. If it is missing in a namespace, the
        // kubelet fails to mount the volume ("configmap kube-root-ca.crt not found") and
        // the pod hangs forever — this is exactly what happened in the CI kubelet smoke
        // check before this fix, because KCM's root-ca-cert-publisher hadn't reconciled
        // "default" yet when the smoke pod was admitted. Seeding it at boot removes the race.
        let store = make_store();
        seed_kube_root_ca(&store, b"fake-ca-der-bytes")
            .await
            .expect("seed must not fail");

        for ns in ["default", "kube-system", "kube-node-lease", "kube-public"] {
            let key = keys::object_key("configmaps", ns, "kube-root-ca.crt");
            let obj = store.get(&key).await.expect("get must not fail");
            let parsed: serde_json::Value = serde_json::from_slice(
                &obj.unwrap_or_else(|| panic!("kube-root-ca.crt must exist in {ns} at boot"))
                    .value,
            )
            .expect("valid json");
            assert_eq!(parsed["metadata"]["namespace"].as_str(), Some(ns));
            let ca_crt = parsed["data"]["ca.crt"].as_str().unwrap_or("");
            assert!(
                ca_crt.contains("BEGIN CERTIFICATE"),
                "data.ca.crt must be a PEM-encoded certificate so the kubelet-mounted \
                 /var/run/secrets/kubernetes.io/serviceaccount/ca.crt is a valid CA bundle, \
                 not raw DER or an empty placeholder"
            );
        }
    }

    #[tokio::test]
    async fn seed_kube_root_ca_is_idempotent() {
        // A second call (e.g. across restarts, or racing KCM's own publisher which also
        // POSTs this ConfigMap) must not error — CAS rv=0 returns AlreadyExists which is
        // silently ignored.
        let store = make_store();
        seed_kube_root_ca(&store, b"fake-ca-der-bytes")
            .await
            .expect("first seed must not fail");
        seed_kube_root_ca(&store, b"fake-ca-der-bytes")
            .await
            .expect("second seed must not fail");
    }

    #[tokio::test]
    async fn seed_servicecidrs_creates_default_kubernetes_servicecidr() {
        // The default ServiceCIDR named "kubernetes" must exist at startup.
        // The conformance spec "[sig-network] ServiceCIDR and IPAddress API
        // should support ServiceCIDR API operations" fails instantly with
        // "ServiceCIDR kubernetes not found" if this object is absent.
        let store = make_store();
        seed_servicecidrs(&store, "10.96.0.0/12")
            .await
            .expect("seed must not fail");

        let key = keys::group_object_key("networking.k8s.io", "servicecidrs", None, "kubernetes");
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_some(),
            "ServiceCIDR 'kubernetes' must exist after seeding — \
             conformance test cannot proceed without it"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&obj.unwrap().value).expect("valid json");
        assert_eq!(parsed["kind"].as_str(), Some("ServiceCIDR"));
        assert_eq!(parsed["metadata"]["name"].as_str(), Some("kubernetes"));
        assert_eq!(
            parsed["spec"]["cidrs"][0].as_str(),
            Some("10.96.0.0/12"),
            "spec.cidrs must contain the service CIDR range"
        );
    }

    #[tokio::test]
    async fn seed_servicecidrs_is_idempotent() {
        // A second call must not error — CAS rv=0 returns AlreadyExists which is silently ignored.
        // This matches the startup guarantee: u7s may restart against an existing database.
        let store = make_store();
        seed_servicecidrs(&store, "10.96.0.0/12")
            .await
            .expect("first seed must not fail");
        seed_servicecidrs(&store, "10.96.0.0/12")
            .await
            .expect("second seed must not fail — seed must be idempotent");

        let key = keys::group_object_key("networking.k8s.io", "servicecidrs", None, "kubernetes");
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_some(),
            "ServiceCIDR 'kubernetes' must still exist after second seed call"
        );
    }

    #[tokio::test]
    async fn seed_servicecidrs_skips_empty_cidr() {
        // When --service-cluster-ip-range is set to empty string (allocation disabled),
        // seed_servicecidrs must not create any object.
        let store = make_store();
        seed_servicecidrs(&store, "")
            .await
            .expect("seed with empty cidr must not fail");

        let key = keys::group_object_key("networking.k8s.io", "servicecidrs", None, "kubernetes");
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_none(),
            "ServiceCIDR 'kubernetes' must not be created when service CIDR is empty"
        );
    }

    /// GET /openapi/v2 and /openapi/v3 must return 200 (not 403) without credentials.
    ///
    /// Conformance tests poll these endpoints after creating a CRD to wait for the CRD
    /// schema to appear. The test client sends unauthenticated requests (no Bearer token,
    /// no client cert). If auth is required, anonymous users get 403 Forbidden and the
    /// test times out with "failed to wait for OpenAPI spec validating condition: unexpected
    /// response: 403". kube-apiserver serves these endpoints to unauthenticated callers.
    ///
    /// This test fails if the auth exemption for /openapi/v2 and /openapi/v3 is removed.
    #[tokio::test]
    async fn openapi_endpoints_return_200_without_credentials() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Build router with AuthLayer — this is the same stack as production.
        // Without the auth exemption for /openapi/v*, the anonymous request would
        // produce 403 Forbidden because system:anonymous has no RBAC grants.
        let app = build_router(state.clone()).layer(AuthLayer::new(
            std::sync::Arc::clone(&state.rbac_index),
            (*state.token_map).clone(),
            state.sa_decoding_key.clone(),
            std::sync::Arc::clone(&state.store),
            std::sync::Arc::clone(&state.sa_sig_cache),
            std::sync::Arc::clone(&state.flowcontrol_cache),
        ));

        for path in ["/openapi/v2", "/openapi/v3"] {
            // No Authorization header — anonymous request, like the conformance test client.
            let req = Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .expect("request build must not fail");
            let resp = app
                .clone()
                .oneshot(req)
                .await
                .expect("router must not error");
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "{path} must return 200 OK for unauthenticated requests — \
                 conformance tests poll this without credentials after CRD creation; \
                 403 causes 'failed to wait for OpenAPI spec validating condition: \
                 unexpected response: 403'"
            );
        }
    }

    /// Health endpoints must return 200 OK with body "ok".
    ///
    /// kube-controller-manager polls /healthz before it considers the apiserver
    /// ready and starts its control loops. If these routes are absent, kcm
    /// exits immediately after startup with "failed to contact apiserver".
    /// /livez and /readyz are polled by infrastructure health probes.
    #[tokio::test]
    async fn health_endpoints_return_200_ok() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        for path in ["/healthz", "/livez", "/readyz"] {
            let req = Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .expect("request build must not fail");
            let resp = router.call(req).await.expect("router must not error");
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "{path} must return 200 OK — kcm polls this before starting its control loops"
            );
            let body = to_bytes(resp.into_body(), 64)
                .await
                .expect("body collect must not fail");
            assert_eq!(body.as_ref(), b"ok", "{path} body must be 'ok'");
        }
    }

    /// `/healthz` must distinguish "boot-time manifest apply still running" from "boot
    /// complete" (mayor-ajgaj) — unlike `/livez`/`/readyz`, which stay unconditional "ok".
    /// Before this gate, `/healthz` answered 200 the instant the listener came up, racing the
    /// boot-time `apply_well_known_manifest_dir` task; `scripts/install.sh`'s
    /// `wait_for_apiserver` could only paper over that with a fixed sleep-and-recheck. If this
    /// regresses to an unconditional "ok" handler, a since-crashed apiserver (manifest apply
    /// failed) would again look healthy to install.sh for however long the race window is.
    #[tokio::test]
    async fn healthz_reflects_boot_ready_state() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state
            .boot_ready
            .store(false, std::sync::atomic::Ordering::Release);
        let mut router = build_router(state.clone());

        let req = Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .expect("request build must not fail");
        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "/healthz must not report 200 while the boot-time manifest apply is still running \
             — install.sh's wait loop needs this to distinguish a booting apiserver from one \
             that already crashed applying a bad manifest"
        );

        // Simulate the manifest-apply task's own success signal (record_manifest_apply_outcome).
        state
            .boot_ready
            .store(true, std::sync::atomic::Ordering::Release);
        let req = Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .expect("request build must not fail");
        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "/healthz must report 200 once boot is actually complete"
        );
        let body = to_bytes(resp.into_body(), 64)
            .await
            .expect("body collect must not fail");
        assert_eq!(
            body.as_ref(),
            b"ok",
            "/healthz body must be 'ok' once ready"
        );
    }

    /// `record_manifest_apply_outcome` is the only place that flips `boot_ready` to true, so a
    /// failed boot-time manifest apply must never mark the apiserver ready — that's what makes
    /// `/healthz` a deterministic "boot complete" signal instead of the old always-200 handler.
    /// Extracted to a pure function (Rule 14) since the real call site is inside a spawned task
    /// racing `serve_tls` and isn't independently testable there.
    #[test]
    fn record_manifest_apply_outcome_never_marks_ready_on_failure() {
        let boot_ready = std::sync::atomic::AtomicBool::new(false);
        record_manifest_apply_outcome(&boot_ready, &Err(anyhow::anyhow!("bad manifest")));
        assert!(
            !boot_ready.load(std::sync::atomic::Ordering::Acquire),
            "a failed manifest apply must not mark boot ready — otherwise /healthz would \
             report 200 for an apiserver that's about to be torn down by the fatal \
             tokio::select! path in run(), exactly the race this fix closes"
        );

        record_manifest_apply_outcome(&boot_ready, &Ok(()));
        assert!(
            boot_ready.load(std::sync::atomic::Ordering::Acquire),
            "a successful manifest apply must mark boot ready, or /healthz would never leave \
             503 and every real deployment would time out in wait_for_apiserver"
        );
    }

    /// The body size limit must be at least 1 MiB (to accommodate real kubectl
    /// manifests and ConfigMaps) and at most 8 MiB (to prevent OOM from a single
    /// large unauthenticated request). The current limit is 4 MiB.
    ///
    /// Without a body limit, an unauthenticated attacker can POST an arbitrarily
    /// large body to any endpoint and cause the server to OOM before auth runs.
    #[test]
    fn body_limit_is_within_safe_range() {
        // 1 MiB minimum: kubectl configmaps can be up to ~1 MiB in practice.
        // 8 MiB maximum: etcd's default value limit; no valid object exceeds this.
        let limit = MAX_BODY_BYTES;
        let min_safe: usize = 1024 * 1024;
        let max_safe: usize = 8 * 1024 * 1024;
        assert!(
            limit >= min_safe,
            "body limit {} is too small; kubectl manifests can be up to 1 MiB",
            limit
        );
        assert!(
            limit <= max_safe,
            "body limit {} is too large; risk of OOM from a single request",
            limit
        );
    }

    /// Verifies that POST /apis/batch/v1/namespaces/default/jobs creates a Job and
    /// GET /apis/batch/v1/namespaces/default/jobs/{name} retrieves it.
    ///
    /// batch/v1 is a new API group. Without the registry entry, the generic handler
    /// falls through to the CR handler which returns 404 (no CRD installed). This test
    /// encodes the requirement that Job is served by the generic namespaced handler.
    #[tokio::test]
    async fn job_create_and_get_round_trip() {
        use std::sync::Arc;

        let store = Arc::new(make_store());
        let state = state::AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let body = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "ci-job", "namespace": "default" },
            "spec": { "template": { "spec": { "containers": [{ "name": "test", "image": "busybox" }], "restartPolicy": "Never" } } }
        });
        let body_bytes = bytes::Bytes::from(body.to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        // POST creates the Job.
        let create_result = handlers::resource::create_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "batch".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "jobs".to_string(),
            )),
            axum::extract::Query(handlers::json_patch::CreateQuery::default()),
            test_user(),
            headers,
            body_bytes,
        )
        .await;
        assert!(
            create_result.is_ok(),
            "POST /apis/batch/v1/namespaces/default/jobs must succeed — batch/v1 Job must be in registry"
        );

        // GET retrieves the Job.
        let get_result = handlers::resource::get_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "batch".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "jobs".to_string(),
                "ci-job".to_string(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await;
        assert!(
            get_result.is_ok(),
            "GET /apis/batch/v1/namespaces/default/jobs/ci-job must succeed after create"
        );

        // Verify it's stored at the expected key.
        let store_key = keys::group_object_key("batch", "jobs", Some("default"), "ci-job");
        let stored = store
            .get(&store_key)
            .await
            .expect("store.get must not fail");
        assert!(
            stored.is_some(),
            "Job ci-job must be in the store at key {store_key}"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&stored.unwrap().value).expect("valid json");
        assert_eq!(parsed["kind"].as_str(), Some("Job"));
        assert_eq!(parsed["metadata"]["name"].as_str(), Some("ci-job"));
    }

    /// POST /apis/storage.k8s.io/v1/storageclasses with proto body must return non-empty JSON.
    ///
    /// kubectl sends StorageClass with Content-Type: application/vnd.kubernetes.protobuf.
    /// Previously, decode_core_proto_by_kind returned None for "StorageClass", extract_body
    /// returned the raw proto bytes unchanged, Object::from_bytes failed with
    /// "invalid JSON: expected value at line 1 column 1", and the handler returned HTTP 400.
    /// The Go client then received a proper Status error body but the CREATE had failed,
    /// causing all StorageClasses e2e lifecycle tests to fail.
    ///
    /// This test fails if the StorageClass proto decoder is removed from decode_core_proto_by_kind:
    /// create_resource will return Err(Status::bad_request("invalid JSON: ...")) and the test
    /// assertion `create_result.is_ok()` will fail.
    #[tokio::test]
    async fn storageclass_create_via_proto_returns_non_empty_response() {
        use std::sync::Arc;

        // Proto encoding helpers (self-contained — no dependency on proto.rs test-only functions).
        fn encode_varint(mut v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let byte = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
            out
        }
        fn encode_ld(field_number: u64, payload: &[u8]) -> Vec<u8> {
            let tag = (field_number << 3) | 2;
            let mut out = encode_varint(tag);
            out.extend_from_slice(&encode_varint(payload.len() as u64));
            out.extend_from_slice(payload);
            out
        }

        // Build: StorageClass { metadata: ObjectMeta { name: "proto-fast" } }
        let mut obj_meta = encode_ld(1, b"proto-fast"); // ObjectMeta.name (field 1)
        obj_meta.extend_from_slice(&encode_ld(8, &[])); // ObjectMeta.creationTimestamp (field 8, empty Time)
        let storageclass_proto = encode_ld(1, &obj_meta); // StorageClass.metadata (field 1)

        // Build the k8s proto envelope: magic + Unknown{TypeMeta, raw, no contentType}
        const MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];
        let mut type_meta = encode_ld(1, b"storage.k8s.io/v1"); // TypeMeta.apiVersion
        type_meta.extend_from_slice(&encode_ld(2, b"StorageClass")); // TypeMeta.kind
        let mut unknown = encode_ld(1, &type_meta); // Unknown.TypeMeta (field 1)
        unknown.extend_from_slice(&encode_ld(2, &storageclass_proto)); // Unknown.raw (field 2)
        let mut proto_body = MAGIC.to_vec();
        proto_body.extend_from_slice(&unknown);

        let store = Arc::new(make_store());
        let state = state::AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/vnd.kubernetes.protobuf"),
        );

        // POST with proto body — must succeed (not return 400 "invalid JSON").
        let create_result = handlers::resource::create_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".to_string(),
                "v1".to_string(),
                "storageclasses".to_string(),
            )),
            axum::extract::Query(handlers::json_patch::CreateQuery::default()),
            axum::Extension(auth::UserInfo {
                username: "admin".into(),
                uid: "".into(),
                groups: vec!["system:masters".into()],
                extra: Default::default(),
            }),
            headers,
            bytes::Bytes::from(proto_body),
        )
        .await;

        assert!(
            create_result.is_ok(),
            "POST /apis/storage.k8s.io/v1/storageclasses with proto body must succeed — \
             before the fix, decode_core_proto_by_kind returned None for 'StorageClass', \
             extract_body returned raw proto bytes, and the handler returned \
             HTTP 400 'invalid JSON: expected value at line 1 column 1'"
        );
    }

    /// POST /apis/flowcontrol.apiserver.k8s.io/v1/flowschemas with a proto body must return 201.
    ///
    /// The API priority and fairness conformance test sends FlowSchema with
    /// Content-Type: application/vnd.kubernetes.protobuf. Before the fix,
    /// decode_core_proto_by_kind returned None for "FlowSchema", extract_body returned raw
    /// proto bytes, and the handler returned HTTP 400 "invalid JSON: expected value at line 1
    /// column 1". This test fails if the FlowSchema proto decoder is removed.
    #[tokio::test]
    async fn flowschema_create_via_proto_returns_201() {
        use std::sync::Arc;

        fn encode_varint(mut v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let byte = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
            out
        }
        fn encode_ld(field_number: u64, payload: &[u8]) -> Vec<u8> {
            let tag = (field_number << 3) | 2;
            let mut out = encode_varint(tag);
            out.extend_from_slice(&encode_varint(payload.len() as u64));
            out.extend_from_slice(payload);
            out
        }

        // Build: FlowSchema { metadata: ObjectMeta { name: "catch-all" } }
        let meta_bytes = encode_ld(1, b"catch-all"); // ObjectMeta.name (field 1)
        let flowschema_proto = encode_ld(1, &meta_bytes); // FlowSchema.metadata (field 1)

        // Build the k8s proto envelope: magic + Unknown{TypeMeta, raw, no contentType}
        const MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];
        let mut type_meta = encode_ld(1, b"flowcontrol.apiserver.k8s.io/v1"); // TypeMeta.apiVersion
        type_meta.extend_from_slice(&encode_ld(2, b"FlowSchema")); // TypeMeta.kind
        let mut unknown = encode_ld(1, &type_meta); // Unknown.TypeMeta (field 1)
        unknown.extend_from_slice(&encode_ld(2, &flowschema_proto)); // Unknown.raw (field 2)
        let mut proto_body = MAGIC.to_vec();
        proto_body.extend_from_slice(&unknown);

        let store = Arc::new(make_store());
        let state = state::AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/vnd.kubernetes.protobuf"),
        );

        let create_result = handlers::resource::create_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "flowcontrol.apiserver.k8s.io".to_string(),
                "v1".to_string(),
                "flowschemas".to_string(),
            )),
            axum::extract::Query(handlers::json_patch::CreateQuery::default()),
            axum::Extension(auth::UserInfo {
                username: "admin".into(),
                uid: "".into(),
                groups: vec!["system:masters".into()],
                extra: Default::default(),
            }),
            headers,
            bytes::Bytes::from(proto_body),
        )
        .await;

        assert!(
            create_result.is_ok(),
            "POST /apis/flowcontrol.apiserver.k8s.io/v1/flowschemas with proto body must \
             return 201 — before the fix, decode_core_proto_by_kind returned None for \
             'FlowSchema', extract_body returned raw proto bytes, and the handler returned \
             HTTP 400 'invalid JSON: expected value at line 1 column 1'"
        );
    }

    /// Verifies that POST /apis/storage.k8s.io/v1/csinodes creates a CSINode and
    /// GET /apis/storage.k8s.io/v1/csinodes/{name} retrieves it.
    ///
    /// The kubelet sends PATCH (SSA) on first boot to register a CSINode. Without
    /// the resource being in the registry, the generic handler falls through to the
    /// CR handler which returns 404 (no CRD installed). This test encodes the
    /// requirement that CSINode is served by the generic handler via the registry.
    #[tokio::test]
    async fn csinode_create_and_get_round_trip() {
        use std::sync::Arc;

        let store = Arc::new(make_store());
        let state = state::AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "ci-node" },
            "spec": { "drivers": [] }
        });
        let body_bytes = bytes::Bytes::from(body.to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        // POST creates the CSINode — this is what the kubelet does on first boot.
        let create_result = handlers::resource::create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "storage.k8s.io".to_string(),
                "v1".to_string(),
                "csinodes".to_string(),
            )),
            axum::extract::Query(handlers::json_patch::CreateQuery::default()),
            axum::Extension(auth::UserInfo {
                username: "system:node:ci-node".into(),
                uid: "".into(),
                groups: vec!["system:nodes".into()],
                extra: Default::default(),
            }),
            headers,
            body_bytes,
        )
        .await;
        assert!(
            create_result.is_ok(),
            "POST /apis/storage.k8s.io/v1/csinodes must succeed"
        );

        // GET retrieves the CSINode — kubelet later reads it to verify registration.
        let get_result = handlers::resource::get_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".to_string(),
                "v1".to_string(),
                "csinodes".to_string(),
                "ci-node".to_string(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await;
        assert!(
            get_result.is_ok(),
            "GET /apis/storage.k8s.io/v1/csinodes/ci-node must succeed"
        );

        // The CSINode must be stored under the correct key for RBAC to find it.
        let store_key = keys::group_object_key("storage.k8s.io", "csinodes", None, "ci-node");
        let stored = store
            .get(&store_key)
            .await
            .expect("store.get must not fail");
        assert!(
            stored.is_some(),
            "CSINode ci-node must be in the store at key {store_key}"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&stored.unwrap().value).expect("valid json");
        assert_eq!(parsed["kind"].as_str(), Some("CSINode"));
        assert_eq!(parsed["metadata"]["name"].as_str(), Some("ci-node"));
    }

    /// Full SA token round-trip: mint via TokenRequest handler, authenticate via auth middleware.
    ///
    /// This is the end-to-end correctness test for projected SA token volumes:
    ///   1. A ServiceAccount exists in the store (seeded by seed_serviceaccounts).
    ///   2. kubelet POSTs to /api/v1/namespaces/{ns}/serviceaccounts/{name}/token
    ///      and receives a JWT signed by the SA key.
    ///   3. A pod uses that JWT as a Bearer token; the auth middleware verifies it
    ///      using the SA decoding key and maps it to the correct service account identity.
    ///
    /// If either side is broken — the handler returns an invalid/empty token, the JWT
    /// has wrong claims, or the auth middleware rejects a valid token — this test fails.
    #[tokio::test]
    async fn sa_token_request_to_auth_round_trip() {
        use axum::response::IntoResponse as _;
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        use std::sync::Arc;

        // 1. Generate a fresh RSA key pair for this test — the same key must be used
        //    for minting (handler) and verification (auth middleware).
        let mut rng = rsa::rand_core::OsRng;
        let rsa_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
        let priv_pem = rsa_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("priv pem")
            .as_bytes()
            .to_vec();
        let pub_pem = rsa_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("pub pem")
            .into_bytes();
        let enc_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(&priv_pem).expect("encoding key from pem");
        let dec_key =
            jsonwebtoken::DecodingKey::from_rsa_pem(&pub_pem).expect("decoding key from pem");

        // 2. Build AppState with the SA key pair and seed the store.
        let store = Arc::new(make_store());
        seed_namespaces(&store)
            .await
            .expect("seed namespaces must not fail");
        seed_serviceaccounts(&store)
            .await
            .expect("seed serviceaccounts must not fail");

        let state = state::AppState::new(
            Arc::clone(&store),
            Some(enc_key),
            Some(dec_key.clone()),
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // 3. Call the TokenRequest handler directly — this is what kubelet does when it
        //    projects an SA token into a pod volume.
        let token_handler_result = handlers::tokens::create_token(
            axum::extract::State(state),
            axum::extract::Path(("default".to_owned(), "default".to_owned())),
            bytes::Bytes::new(), // empty body → default audience + expiration
        )
        .await;
        let token_resp = match token_handler_result {
            Ok(r) => r.into_response(),
            Err(e) => {
                // StatusError doesn't implement Debug; produce a meaningful panic message.
                panic!("create_token must succeed for a valid SA: status={}", e.0);
            }
        };

        assert_eq!(
            token_resp.status(),
            axum::http::StatusCode::CREATED,
            "TokenRequest must return 201 Created"
        );

        // 4. Extract the token from the response body.
        let body_bytes = axum::body::to_bytes(token_resp.into_body(), usize::MAX)
            .await
            .expect("body collect must not fail");
        let resp_json: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("response must be valid JSON");

        let token = resp_json["status"]["token"]
            .as_str()
            .expect("response must contain status.token string");
        assert!(
            !token.is_empty(),
            "minted token must not be empty — empty token cannot authenticate"
        );

        let exp_ts = resp_json["status"]["expirationTimestamp"]
            .as_str()
            .expect("response must contain status.expirationTimestamp");
        assert!(
            !exp_ts.is_empty(),
            "expirationTimestamp must not be empty — kubelet needs it to know when to refresh"
        );

        // 5. Authenticate the minted token via the auth middleware path.
        //    This verifies the full round-trip: the JWT the handler mints can be
        //    verified by the same decoding key used in production.
        let sig_cache =
            crate::sa_sig_cache::SigCache::new_with_capacity(crate::sa_sig_cache::DEFAULT_CAPACITY);
        let user = auth::authenticate_token_with_audiences(
            token,
            &std::collections::HashMap::new(),
            Some(&dec_key),
            &[],
            store.as_ref(),
            &sig_cache,
        )
        .await
        .expect("minted SA token must authenticate successfully — round-trip broken if None");

        // Username must be the service account identity.
        assert_eq!(
            user.username, "system:serviceaccount:default:default",
            "authenticated username must be the service account subject"
        );

        // Both SA groups must be present — RBAC policies bind to these groups.
        assert!(
            user.groups.contains(&"system:serviceaccounts".to_owned()),
            "broad SA group must be present for RBAC policies that apply to all service accounts"
        );
        assert!(
            user.groups
                .contains(&"system:serviceaccounts:default".to_owned()),
            "namespace-scoped SA group must be present for namespace-scoped RBAC policies"
        );
    }

    /// Full CSR lifecycle: POST → GET → PUT /approval (Approved) → PUT /status (cert) → GET confirms cert.
    ///
    /// This test exercises the entire CertificateSigningRequest flow end-to-end:
    ///   1. Client submits a CSR (POST) — only signerName + valid base64(PEM) spec.request allowed.
    ///   2. GET confirms the CSR is stored and spec is immutable (no status yet).
    ///   3. Approver writes Approved condition via PUT /approval — certificate must NOT appear.
    ///   4. Signer writes status.certificate via PUT /status — certificate appears.
    ///   5. GET confirms final state: Approved condition + certificate present.
    ///
    /// If any step breaks, the automated cert-provisioning pipeline silently stops working.
    #[tokio::test]
    async fn csr_full_lifecycle() {
        use axum::response::IntoResponse as _;
        use base64::Engine as _;
        use rcgen::{CertificateParams, KeyPair};
        use std::sync::Arc;

        // Generate a real base64(PEM) PKCS#10 CSR — same approach used in csr.rs unit tests.
        // kubectl/client-go submit spec.request as base64(PEM), not base64(DER).
        let key_pair = KeyPair::generate().expect("key generation must succeed");
        let params = CertificateParams::default();
        let csr = params
            .serialize_request(&key_pair)
            .expect("CSR generation must succeed");
        let csr_pem = csr.pem().expect("CSR PEM serialization must succeed");
        let csr_b64 = base64::engine::general_purpose::STANDARD.encode(csr_pem);

        let store = Arc::new(make_store());
        let state = state::AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let mut json_headers = axum::http::HeaderMap::new();
        json_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        let user = auth::UserInfo {
            username: "test-user".into(),
            uid: "real-uid".into(),
            groups: vec!["real-group".into()],
            extra: Default::default(),
        };

        // --- Step 1: POST — create the CSR ---
        // spec.username/uid/groups/extra are deliberately spoofed here — KCM's real
        // csrapproving controller authorizes auto-approval directly from these stored
        // fields (see sarapprove.go's authorize()), so a client that could set them could
        // forge the identity being approved. The POST handler must discard every one of
        // these values and stamp the authenticated caller's real identity instead
        // (asserted right after the store read below).
        let create_body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "lifecycle-csr"},
            "spec": {
                "request": csr_b64,
                "signerName": "kubernetes.io/kube-apiserver-client",
                "username": "system:node:should-not-be-trusted",
                "uid": "attacker-chosen-uid",
                "groups": ["system:masters"],
                "extra": {"attacker-key": ["attacker-value"]}
            }
        });
        let create_result = handlers::csr::create_csr(
            axum::extract::State(state.clone()),
            axum::Extension(user),
            json_headers.clone(),
            bytes::Bytes::from(create_body.to_string()),
        )
        .await;
        let create_resp = match create_result {
            Ok(r) => r.into_response(),
            Err(e) => panic!("POST CSR must succeed, got status={}", e.0),
        };
        assert_eq!(
            create_resp.status(),
            axum::http::StatusCode::CREATED,
            "POST /certificatesigningrequests must return 201"
        );

        // Extract resourceVersion from the stored object for OCC in subsequent calls.
        let store_key = keys::group_object_key(
            "certificates.k8s.io",
            "certificatesigningrequests",
            None,
            "lifecycle-csr",
        );
        let stored = store
            .get(&store_key)
            .await
            .expect("store.get must not fail")
            .expect("CSR must be in store after POST");
        let stored_v: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("valid json");
        assert!(
            stored_v["status"].is_null() || stored_v.get("status").is_none(),
            "POST must not store a status field — spec is immutable, status starts empty"
        );

        // This is the bead's core security-fix assertion: the client-supplied spoof
        // above must never reach storage. If stamp_csr_identity regresses (removed, or
        // reordered so a mutating webhook could undo it), these fields would show the
        // attacker-supplied values instead, and this test would fail.
        assert_eq!(
            stored_v["spec"]["username"], "test-user",
            "POST must stamp spec.username from the authenticated caller, discarding any \
             client-supplied value — KCM's csrapproving controller authorizes \
             auto-approval directly from this stored field, so a client-controlled value \
             would let a caller forge the identity being approved"
        );
        assert_eq!(
            stored_v["spec"]["uid"], "real-uid",
            "POST must stamp spec.uid from the authenticated caller, discarding the \
             client-supplied uid spoof"
        );
        assert_eq!(
            stored_v["spec"]["groups"],
            serde_json::json!(["real-group"]),
            "POST must stamp spec.groups from the authenticated caller, discarding the \
             client-supplied system:masters spoof — otherwise a caller could forge \
             membership in a privileged group for KCM's SAR-based auto-approval"
        );
        assert_eq!(
            stored_v["spec"]["extra"],
            serde_json::json!({}),
            "POST must stamp spec.extra from the authenticated caller, discarding the \
             client-supplied extra spoof"
        );

        let rv1 = stored_v["metadata"]["resourceVersion"]
            .as_str()
            .expect("resourceVersion must be set after POST")
            .to_owned();

        // --- Step 2: GET — confirm CSR is retrievable ---
        let get_result = handlers::resource::get_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "certificates.k8s.io".into(),
                "v1".into(),
                "certificatesigningrequests".into(),
                "lifecycle-csr".into(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await;
        assert!(get_result.is_ok(), "GET must succeed after POST");

        // --- Step 3: PUT /approval — write Approved condition ---
        let approval_body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "lifecycle-csr", "resourceVersion": rv1},
            "spec": {
                "request": csr_b64,
                "signerName": "kubernetes.io/kube-apiserver-client"
            },
            "status": {
                "conditions": [{
                    "type": "Approved",
                    "status": "True",
                    "reason": "ManualApproval",
                    "message": "approved by lifecycle test"
                }]
            }
        });
        let approval_result = handlers::approval::put_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path("lifecycle-csr".to_owned()),
            json_headers.clone(),
            bytes::Bytes::from(approval_body.to_string()),
        )
        .await;
        assert!(
            approval_result.is_ok(),
            "PUT /approval must succeed after POST"
        );

        // Verify: Approved condition stored, no certificate yet.
        let stored2 = store
            .get(&store_key)
            .await
            .expect("store.get must not fail")
            .expect("CSR must still be in store after approval");
        let v2: serde_json::Value = serde_json::from_slice(&stored2.value).expect("valid json");
        let conds = v2["status"]["conditions"]
            .as_array()
            .expect("conditions must be an array after approval");
        assert_eq!(
            conds[0]["type"], "Approved",
            "Approved condition must be stored"
        );
        assert!(
            v2["status"]["certificate"].is_null() || v2["status"].get("certificate").is_none(),
            "PUT /approval must NOT write status.certificate — only the signer may do that"
        );
        let rv2 = v2["metadata"]["resourceVersion"]
            .as_str()
            .expect("resourceVersion must be set after approval")
            .to_owned();

        // --- Step 4: PUT /status — signer writes the certificate ---
        let fake_cert = base64::engine::general_purpose::STANDARD.encode(b"FAKE_CERT_PEM");
        let status_body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "lifecycle-csr", "resourceVersion": rv2},
            "status": {
                "certificate": fake_cert,
                "conditions": [{
                    "type": "Approved",
                    "status": "True",
                    "reason": "ManualApproval",
                    "message": "approved by lifecycle test"
                }]
            }
        });
        let status_result = handlers::status::put_resource_status(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "certificates.k8s.io".into(),
                "v1".into(),
                "certificatesigningrequests".into(),
                "lifecycle-csr".into(),
            )),
            json_headers.clone(),
            bytes::Bytes::from(status_body.to_string()),
        )
        .await;
        assert!(
            status_result.is_ok(),
            "PUT /status must succeed for the signer to write the certificate"
        );

        // --- Step 5: GET — confirm final state: Approved + certificate ---
        let final_stored = store
            .get(&store_key)
            .await
            .expect("store.get must not fail")
            .expect("CSR must be in store after status write");
        let v_final: serde_json::Value =
            serde_json::from_slice(&final_stored.value).expect("valid json");

        let final_cert = v_final["status"]["certificate"].as_str();
        assert!(
            final_cert.is_some() && !final_cert.unwrap().is_empty(),
            "status.certificate must be present after signer writes via PUT /status"
        );
        assert_eq!(
            final_cert.unwrap(),
            fake_cert,
            "stored certificate must match what the signer wrote"
        );

        let final_conds = v_final["status"]["conditions"]
            .as_array()
            .expect("conditions must still be present in final state");
        assert_eq!(
            final_conds[0]["type"], "Approved",
            "Approved condition must survive PUT /status — signer must not erase approver's decision"
        );
    }

    /// GET /apis/discovery.k8s.io/v1/namespaces/{ns}/endpointslices must return an empty list,
    /// not 404, for a namespace that has no EndpointSlices yet.
    ///
    /// KCM's endpointslice-controller opens a LIST+WATCH on this path at startup. If the
    /// resource is unregistered the generic handler falls through to the CR handler which
    /// returns 404 (no CRD installed), causing the controller to enter exponential back-off
    /// and log "failed to list *v1.EndpointSlice: Resource not found" every ~45 s.
    #[tokio::test]
    async fn endpointslice_list_returns_empty_for_new_namespace() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/apis/discovery.k8s.io/v1/namespaces/default/endpointslices")
            .body(axum::body::Body::empty())
            .expect("request must build");
        req.extensions_mut().insert(auth::UserInfo {
            username: "test".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });
        let resp = router.call(req).await.expect("router must not error");

        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "GET /apis/discovery.k8s.io/v1/namespaces/default/endpointslices must not return 404 — \
             KCM's endpointslice-controller lists this path at startup; 404 causes log-spam back-off"
        );
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "empty namespace must return 200 with an empty EndpointSliceList"
        );

        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let val: serde_json::Value = serde_json::from_slice(&body).expect("response must be JSON");
        assert_eq!(
            val["kind"], "EndpointSliceList",
            "response kind must be EndpointSliceList — client-go informer requires this exact kind"
        );
        let items = val["items"].as_array().expect("items must be an array");
        assert!(
            items.is_empty(),
            "items must be empty for a namespace with no EndpointSlices"
        );
    }

    /// POST /apis/discovery.k8s.io/v1/namespaces/{ns}/endpointslices with a valid JSON body
    /// must return 201, not 400 "invalid JSON: expected value at line 1 column 1".
    ///
    /// The conformance test
    /// "[sig-network] EndpointSlice [It] should support creating EndpointSlice API operations"
    /// POSTs a new EndpointSlice with Content-Type: application/json and gets HTTP 400.
    /// The error "expected value at line 1 column 1" from Object::from_bytes means the body
    /// reaching the handler is empty — this test verifies that the body is decoded correctly
    /// and the create succeeds with 201.
    #[tokio::test]
    async fn endpointslice_post_with_json_body_returns_201_not_400() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        seed_namespaces(&store).await.expect("seed namespaces");
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        let eps_json = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "test-eps",
                "namespace": "default"
            },
            "addressType": "IPv4",
            "endpoints": [
                {
                    "addresses": ["10.0.0.1"],
                    "conditions": {"ready": true}
                }
            ],
            "ports": [
                {
                    "name": "http",
                    "protocol": "TCP",
                    "port": 80
                }
            ]
        });
        let body_bytes = serde_json::to_vec(&eps_json).expect("json serialize");

        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/apis/discovery.k8s.io/v1/namespaces/default/endpointslices")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body_bytes))
            .expect("request must build");
        req.extensions_mut().insert(auth::UserInfo {
            username: "test".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });
        let resp = router.call(req).await.expect("router must not error");

        let status = resp.status();
        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let body_str = String::from_utf8_lossy(&body);

        assert_eq!(
            status,
            StatusCode::CREATED,
            "POST EndpointSlice with valid JSON body must return 201 — \
             before the fix it returned 400 'invalid JSON: expected value at line 1 column 1' \
             because the body was empty when it reached Object::from_bytes; body: {body_str}"
        );

        let val: serde_json::Value =
            serde_json::from_slice(&body).expect("response must be valid JSON");
        assert_eq!(
            val["kind"], "EndpointSlice",
            "response kind must be EndpointSlice"
        );
        assert_eq!(
            val["metadata"]["name"], "test-eps",
            "name must be preserved"
        );
        assert_eq!(
            val["addressType"], "IPv4",
            "addressType must be preserved — required field for EndpointSlice routing"
        );
    }

    /// POST /apis/discovery.k8s.io/v1/namespaces/{ns}/endpointslices with a
    /// Content-Type: application/vnd.kubernetes.protobuf body must return 201.
    ///
    /// client-go typed client sends EndpointSlice
    /// creates using protobuf encoding. The proto envelope should be decoded by
    /// extract_body before Object::from_bytes is called.
    #[tokio::test]
    async fn endpointslice_post_with_proto_body_returns_201_not_400() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        seed_namespaces(&store).await.expect("seed namespaces");
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        // Build a minimal proto-encoded EndpointSlice matching what client-go sends.
        // Reuse the encode helpers from the proto module tests via the same encoding logic.
        fn encode_varint(mut v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let byte = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
            out
        }
        fn encode_ld(field_number: u64, payload: &[u8]) -> Vec<u8> {
            let tag = (field_number << 3) | 2;
            let mut out = encode_varint(tag);
            out.extend_from_slice(&encode_varint(payload.len() as u64));
            out.extend_from_slice(payload);
            out
        }

        // ObjectMeta: field 1 = name, field 3 = namespace, field 8 = creationTimestamp
        let mut meta = encode_ld(1, b"proto-eps");
        meta.extend_from_slice(&encode_ld(3, b"default"));
        meta.extend_from_slice(&encode_ld(8, &[]));

        // EndpointSlice (discovery.k8s.io/v1/generated.proto):
        //   field 1 = metadata, field 2 = endpoints, field 3 = ports, field 4 = addressType
        let mut eps_proto = encode_ld(1, &meta);
        eps_proto.extend_from_slice(&encode_ld(4, b"IPv4")); // field 4 = addressType

        // k8s proto envelope: magic + Unknown{TypeMeta, raw, no contentType}
        const MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];
        let mut type_meta = encode_ld(1, b"discovery.k8s.io/v1");
        type_meta.extend_from_slice(&encode_ld(2, b"EndpointSlice"));
        let mut unknown = encode_ld(1, &type_meta);
        unknown.extend_from_slice(&encode_ld(2, &eps_proto));
        let mut body_bytes = MAGIC.to_vec();
        body_bytes.extend_from_slice(&unknown);

        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/apis/discovery.k8s.io/v1/namespaces/default/endpointslices")
            .header("content-type", "application/vnd.kubernetes.protobuf")
            .body(axum::body::Body::from(body_bytes))
            .expect("request must build");
        req.extensions_mut().insert(auth::UserInfo {
            username: "test".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });
        let resp = router.call(req).await.expect("router must not error");

        let status = resp.status();
        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let body_str = String::from_utf8_lossy(&body);

        assert_eq!(
            status,
            StatusCode::CREATED,
            "POST EndpointSlice with proto body must return 201 — \
             client-go typed client sends EndpointSlice creates with Content-Type: \
             application/vnd.kubernetes.protobuf; body: {body_str}"
        );

        let val: serde_json::Value =
            serde_json::from_slice(&body).expect("response must be valid JSON");
        assert_eq!(val["kind"], "EndpointSlice");
        assert_eq!(val["metadata"]["name"], "proto-eps");
        assert_eq!(
            val["addressType"], "IPv4",
            "addressType must survive proto decode — required field for EndpointSlice"
        );
    }

    /// DELETE /apis/rbac.authorization.k8s.io/v1/clusterrolebindings must return 200,
    /// not 405 Method Not Allowed.
    ///
    /// Regression test: sonobuoy delete --all sends a collection DELETE to
    /// remove all ClusterRoleBindings it created.  Before the fix the collection route only
    /// registered GET+POST, so axum returned 405.  The test verifies:
    ///   1. The route exists and accepts DELETE (not 405).
    ///   2. Items stored under the prefix are actually removed.
    ///   3. The RBAC index is evicted so permissions are gone immediately.
    #[tokio::test]
    async fn delete_collection_clusterrolebindings_returns_200_not_405() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;
        use u7s_store::Store;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a ClusterRoleBinding so we can verify it is actually deleted.
        let group = "rbac.authorization.k8s.io";
        let crb_key = keys::group_object_key(group, "clusterrolebindings", None, "sonobuoy");
        let crb_body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": { "name": "sonobuoy" },
            "subjects": [],
            "roleRef": { "apiGroup": group, "kind": "ClusterRole", "name": "cluster-admin" }
        });
        store
            .put(&crb_key, bytes::Bytes::from(crb_body.to_string()), Some(0))
            .await
            .expect("seed ClusterRoleBinding must succeed");

        let mut router = build_router(state);

        // Issue DELETE to the collection endpoint (no object name).
        let mut req = Request::builder()
            .method(Method::DELETE)
            .uri("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
            .body(axum::body::Body::empty())
            .expect("request build must not fail");
        req.extensions_mut().insert(auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });
        let resp = router.call(req).await.expect("router must not error");

        // Must not return 405 Method Not Allowed — the route must accept DELETE.
        assert_ne!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "DELETE /apis/rbac.authorization.k8s.io/v1/clusterrolebindings must not return 405 — \
             sonobuoy delete --all sends a collection DELETE to clean up its ClusterRoleBindings"
        );
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "collection DELETE must return 200 Success"
        );

        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let val: serde_json::Value = serde_json::from_slice(&body).expect("response must be JSON");
        assert_eq!(val["kind"], "Status");
        assert_eq!(val["status"], "Success");

        // The seeded ClusterRoleBinding must be gone from the store.
        let stored = store.get(&crb_key).await.expect("store.get must not fail");
        assert!(
            stored.is_none(),
            "ClusterRoleBinding 'sonobuoy' must be deleted from store after collection DELETE"
        );
    }

    /// DELETE /apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings must return
    /// 200, not 405 Method Not Allowed.
    ///
    /// Same root cause as the cluster-scoped variant: the namespaced collection route also
    /// lacked a DELETE handler.  sonobuoy cleans up its namespace-scoped RoleBindings the
    /// same way it cleans cluster-scoped ones.
    #[tokio::test]
    async fn delete_collection_namespaced_rolebindings_returns_200_not_405() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;
        use u7s_store::Store;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let group = "rbac.authorization.k8s.io";
        let rb_key = keys::group_object_key(group, "rolebindings", Some("sonobuoy"), "sonobuoy");
        let rb_body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": { "name": "sonobuoy", "namespace": "sonobuoy" },
            "subjects": [],
            "roleRef": { "apiGroup": group, "kind": "ClusterRole", "name": "cluster-admin" }
        });
        store
            .put(&rb_key, bytes::Bytes::from(rb_body.to_string()), Some(0))
            .await
            .expect("seed RoleBinding must succeed");

        let mut router = build_router(state);

        let mut req = Request::builder()
            .method(Method::DELETE)
            .uri("/apis/rbac.authorization.k8s.io/v1/namespaces/sonobuoy/rolebindings")
            .body(axum::body::Body::empty())
            .expect("request build must not fail");
        req.extensions_mut().insert(auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });
        let resp = router.call(req).await.expect("router must not error");

        assert_ne!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "DELETE on namespaced rolebindings collection must not return 405"
        );
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(val["kind"], "Status");
        assert_eq!(val["status"], "Success");

        let stored = store.get(&rb_key).await.expect("store.get must not fail");
        assert!(
            stored.is_none(),
            "RoleBinding 'sonobuoy/sonobuoy' must be deleted from store after collection DELETE"
        );
    }

    /// DELETE /api/v1/namespaces/{ns}/pods must return 200, not 405.
    ///
    /// sonobuoy cleanup sends DELETE /api/v1/namespaces/sonobuoy/pods?labelSelector=sonobuoy-run=<id>
    /// to remove all pods it created. The pods collection route previously only registered
    /// GET+POST, so axum returned 405. The fix adds DELETE via core_delete_collection_namespaced_resource.
    /// The test verifies: 1) the route accepts DELETE (not 405), 2) a matching pod is
    /// soft-deleted (delete_collection_pods mirrors delete_pod's soft-delete-first semantics
    /// so a running pod is never yanked out from under the kubelet without a
    /// graceful-termination signal), 3) labelSelector actually selects it.
    #[tokio::test]
    async fn delete_collection_namespaced_pods_returns_200_not_405() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;
        use u7s_store::Store;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let ns_key = keys::cluster_object_key("namespaces", "sonobuoy");
        let ns_body = serde_json::json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": { "name": "sonobuoy" }
        });
        store
            .put(&ns_key, bytes::Bytes::from(ns_body.to_string()), Some(0))
            .await
            .expect("seed namespace must succeed");

        let pod_key = keys::group_object_key("", "pods", Some("sonobuoy"), "sonobuoy-worker");
        let pod_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "sonobuoy-worker",
                "namespace": "sonobuoy",
                "labels": { "sonobuoy-run": "abc123" }
            },
            "spec": { "containers": [] }
        });
        store
            .put(&pod_key, bytes::Bytes::from(pod_body.to_string()), Some(0))
            .await
            .expect("seed pod must succeed");

        let mut router = build_router(state);

        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/api/v1/namespaces/sonobuoy/pods?labelSelector=sonobuoy-run%3Dabc123")
            .body(axum::body::Body::empty())
            .expect("request build must not fail");
        let resp = router.call(req).await.expect("router must not error");

        assert_ne!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "DELETE /api/v1/namespaces/sonobuoy/pods must not return 405; \
             sonobuoy cleanup sends this request to remove its pods"
        );
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "collection DELETE on pods must return 200 Success"
        );

        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let val: serde_json::Value = serde_json::from_slice(&body).expect("response must be JSON");
        assert_eq!(val["kind"], "Status");
        assert_eq!(val["status"], "Success");

        let stored = store
            .get(&pod_key)
            .await
            .expect("store.get must not fail")
            .expect(
                "pod 'sonobuoy/sonobuoy-worker' must still exist after collection DELETE with \
                 matching labelSelector — DeleteCollection soft-deletes a running pod first \
                 (deletionTimestamp), exactly like a single-pod DELETE, so the kubelet still \
                 gets a chance to gracefully terminate the container",
            );
        let pod_val: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            pod_val["metadata"]["deletionTimestamp"].is_string(),
            "pod 'sonobuoy/sonobuoy-worker' must have deletionTimestamp set after collection \
             DELETE with matching labelSelector"
        );
    }

    /// DELETE /api/v1/persistentvolumes (collection) must return 200, not 405.
    ///
    /// Regression test: the CSI PV lifecycle conformance test creates and
    /// deletes individual PVs, then calls DeleteCollection to bulk-clean. The cluster-scoped
    /// core/v1 collection route (`/api/v1/{resource}`) registered only GET+POST, unlike its
    /// namespaced sibling which already has DELETE wired — so PersistentVolumes (and every
    /// other cluster-scoped core resource) returned 405 MethodNotAllowed, blocking the test's
    /// cleanup step. The test verifies: 1) the route accepts DELETE (not 405), 2) matching PVs
    /// are actually removed, 3) labelSelector filtering is honored.
    #[tokio::test]
    async fn delete_collection_persistentvolumes_returns_200_not_405() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;
        use u7s_store::Store;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let matching_key = keys::group_object_key("", "persistentvolumes", None, "pv-match");
        let matching_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolume",
            "metadata": { "name": "pv-match", "labels": { "e2e": "abc123" } },
            "spec": { "capacity": { "storage": "1Gi" }, "accessModes": ["ReadWriteOnce"] }
        });
        store
            .put(
                &matching_key,
                bytes::Bytes::from(matching_body.to_string()),
                Some(0),
            )
            .await
            .expect("seed matching PersistentVolume must succeed");

        let other_key = keys::group_object_key("", "persistentvolumes", None, "pv-other");
        let other_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolume",
            "metadata": { "name": "pv-other" },
            "spec": { "capacity": { "storage": "1Gi" }, "accessModes": ["ReadWriteOnce"] }
        });
        store
            .put(
                &other_key,
                bytes::Bytes::from(other_body.to_string()),
                Some(0),
            )
            .await
            .expect("seed unrelated PersistentVolume must succeed");

        let mut router = build_router(state);

        let mut req = Request::builder()
            .method(Method::DELETE)
            .uri("/api/v1/persistentvolumes?labelSelector=e2e%3Dabc123")
            .body(axum::body::Body::empty())
            .expect("request build must not fail");
        req.extensions_mut().insert(auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });
        let resp = router.call(req).await.expect("router must not error");

        assert_ne!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "DELETE /api/v1/persistentvolumes must not return 405 — the CSI PV lifecycle \
             conformance test calls DeleteCollection to bulk-clean PVs it created"
        );
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "collection DELETE on persistentvolumes must return 200 Success"
        );

        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let val: serde_json::Value = serde_json::from_slice(&body).expect("response must be JSON");
        assert_eq!(val["kind"], "Status");
        assert_eq!(val["status"], "Success");

        let stored = store
            .get(&matching_key)
            .await
            .expect("store.get must not fail");
        assert!(
            stored.is_none(),
            "PersistentVolume 'pv-match' must be deleted after collection DELETE with matching labelSelector"
        );
        let stored = store
            .get(&other_key)
            .await
            .expect("store.get must not fail");
        assert!(
            stored.is_some(),
            "PersistentVolume 'pv-other' must survive — it does not match the labelSelector"
        );
    }

    // ---------------------------------------------------------------------------
    // Service clusterIP auto-allocation integration tests
    // ---------------------------------------------------------------------------

    fn make_state_with_cidr(cidr: &str) -> state::AppState {
        use state::ServiceIpAllocator;
        use std::sync::Arc;
        let store = Arc::new(make_store());
        let alloc = ServiceIpAllocator::from_cidr(cidr).expect("valid CIDR");
        state::AppState::new_with_config(state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: None,
            webhook_identity_pem: None,
            service_ip_allocator: Some(alloc),
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        })
    }

    /// POST a Service with no clusterIP → GET it back → clusterIP is in the configured CIDR.
    ///
    /// This is the primary correctness test: the apiserver must auto-assign an IP
    /// so that KCM's endpoints-controller can populate Endpoints and kube-proxy can
    /// program iptables rules. Without a clusterIP, Service traffic is unroutable.
    #[tokio::test]
    async fn service_create_auto_assigns_cluster_ip_from_cidr() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request};
        use std::net::Ipv4Addr;
        use tower_service::Service as _;

        // /29: .0 network, .1 reserved, .2-.6 usable, .7 broadcast
        let state = make_state_with_cidr("10.0.0.0/29");
        let mut router = build_router(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "my-svc", "namespace": "default" },
            "spec": {
                "selector": { "app": "my-app" },
                "ports": [{ "port": 80, "targetPort": 8080 }]
            }
        });
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/namespaces/default/services")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .expect("request must build");
        req.extensions_mut().insert(auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });

        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::CREATED,
            "Service POST must return 201 Created"
        );

        let body_bytes = to_bytes(resp.into_body(), 4096)
            .await
            .expect("collect body");
        let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        let cluster_ip = val["spec"]["clusterIP"].as_str().unwrap_or("");
        assert!(
            !cluster_ip.is_empty(),
            "spec.clusterIP must be auto-assigned — without it Service traffic is unroutable"
        );
        assert_ne!(
            cluster_ip, "None",
            "clusterIP must not be 'None' for a regular Service"
        );

        // Verify it falls within the configured CIDR (10.0.0.0/29).
        let ip: Ipv4Addr = cluster_ip
            .parse()
            .expect("clusterIP must be a valid IPv4 address");
        let base = u32::from("10.0.0.0".parse::<Ipv4Addr>().unwrap());
        let ip_u32 = u32::from(ip);
        assert!(
            ip_u32 >= base && ip_u32 < base + 8,
            "clusterIP {cluster_ip} must be within 10.0.0.0/29"
        );
    }

    /// POST two Services with no clusterIP → they get different IPs.
    ///
    /// Duplicate clusterIPs would cause all traffic for one service to be
    /// mis-routed to the other. The UNIQUE constraint + CAS must prevent this.
    #[tokio::test]
    async fn two_services_get_different_cluster_ips() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request};
        use tower_service::Service as _;

        // /29: 6 usable IPs — enough for two services.
        let state = make_state_with_cidr("10.0.0.0/29");
        let mut router = build_router(state);

        let make_svc_req = |name: &str| {
            let body = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": { "name": name, "namespace": "default" },
                "spec": { "ports": [{ "port": 80 }] }
            });
            let mut req = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/namespaces/default/services")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .expect("request must build");
            req.extensions_mut().insert(auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            });
            req
        };

        let resp1 = router
            .call(make_svc_req("svc-a"))
            .await
            .expect("router call must not error");
        assert_eq!(resp1.status(), axum::http::StatusCode::CREATED);
        let b1 = to_bytes(resp1.into_body(), 4096).await.unwrap();
        let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
        let ip1 = v1["spec"]["clusterIP"].as_str().unwrap_or("").to_string();

        let resp2 = router
            .call(make_svc_req("svc-b"))
            .await
            .expect("router call must not error");
        assert_eq!(resp2.status(), axum::http::StatusCode::CREATED);
        let b2 = to_bytes(resp2.into_body(), 4096).await.unwrap();
        let v2: serde_json::Value = serde_json::from_slice(&b2).unwrap();
        let ip2 = v2["spec"]["clusterIP"].as_str().unwrap_or("").to_string();

        assert!(
            !ip1.is_empty() && !ip2.is_empty(),
            "both services must receive a clusterIP"
        );
        assert_ne!(
            ip1, ip2,
            "two services must not share a clusterIP — duplicate IPs mis-route traffic"
        );
    }

    /// POST /apis/rbac.authorization.k8s.io/v1/clusterroles with ?fieldValidation=Strict must
    /// return 201 Created, not 400.
    ///
    /// `kubectl create` always sends ?fieldValidation=Strict. If the server rejects this query
    /// param, all `kubectl create` RBAC operations fail — including sonobuoy's setup phase which
    /// creates the ClusterRole and ClusterRoleBinding that the aggregator pod needs.
    ///
    /// The fix: accept and ignore ?fieldValidation=<any value> on all write endpoints.
    /// This test exercises the full router path (path matching + handler dispatch) to catch
    /// any routing or middleware bug that might inspect or reject unknown query params.
    #[tokio::test]
    async fn field_validation_query_param_does_not_break_clusterrole_create() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        // Admin user injected directly into request extensions — bypasses the auth layer
        // (which is not wired in this test) while still satisfying the handler's
        // Extension(user): Extension<UserInfo> extractor.
        let admin = auth::UserInfo {
            username: "admin".to_string(),
            uid: String::new(),
            groups: vec!["system:masters".to_string()],
            extra: Default::default(),
        };

        let make_role_req = |name: &str, query: &str| {
            let body = serde_json::json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": { "name": name },
                "rules": [
                    { "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] }
                ]
            });
            let uri = format!(
                "/apis/rbac.authorization.k8s.io/v1/clusterroles?fieldManager=kubectl-create{}",
                query
            );
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .expect("request must build")
        };

        // Case 1: ?fieldValidation=Strict — kubectl create always sends this.
        let mut req = make_role_req("sonobuoy-runner-strict", "&fieldValidation=Strict");
        req.extensions_mut().insert(admin.clone());
        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "POST with ?fieldValidation=Strict must return 201 — \
             kubectl create always sends this param and must not get 400"
        );
        let body_bytes = to_bytes(resp.into_body(), 4096)
            .await
            .expect("collect response body");
        let resp_val: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("response must be JSON");
        assert_eq!(
            resp_val["kind"].as_str(),
            Some("ClusterRole"),
            "response kind must be ClusterRole when fieldValidation=Strict is present"
        );

        // Case 2: ?fieldValidation=Warn — must also succeed.
        let mut req2 = make_role_req("sonobuoy-runner-warn", "&fieldValidation=Warn");
        req2.extensions_mut().insert(admin.clone());
        let resp2 = router.call(req2).await.expect("router must not error");
        assert_eq!(
            resp2.status(),
            StatusCode::CREATED,
            "POST with ?fieldValidation=Warn must return 201"
        );

        // Case 3: no fieldValidation param — baseline must still succeed.
        let mut req3 = make_role_req("sonobuoy-runner-baseline", "");
        req3.extensions_mut().insert(admin.clone());
        let resp3 = router.call(req3).await.expect("router must not error");
        assert_eq!(
            resp3.status(),
            StatusCode::CREATED,
            "POST without ?fieldValidation must return 201 (baseline)"
        );

        // Verify the Strict-case ClusterRole was actually stored (not just accepted silently).
        let stored_key = keys::group_object_key(
            "rbac.authorization.k8s.io",
            "clusterroles",
            None,
            "sonobuoy-runner-strict",
        );
        let stored = store
            .get(&stored_key)
            .await
            .expect("store.get must not fail");
        assert!(
            stored.is_some(),
            "ClusterRole sonobuoy-runner-strict must be persisted — \
             a 201 response without persisting the object would be misleading"
        );
        let stored_val: serde_json::Value = serde_json::from_slice(&stored.unwrap().value)
            .expect("stored value must be valid JSON");
        assert_eq!(
            stored_val["kind"].as_str(),
            Some("ClusterRole"),
            "stored object kind must be ClusterRole"
        );
    }

    /// DELETE /api/v1/persistentvolumes/{name} must not return 405 MethodNotAllowed.
    ///
    /// PersistentVolumes are cluster-scoped (no namespace). The CSI conformance test
    /// creates a PV and then deletes it via DELETE /api/v1/persistentvolumes/{name}.
    /// Without the DELETE verb registered on the cluster-scoped named-resource route,
    /// axum returns 405 and the conformance test fails.
    ///
    /// This test fails (405) if the .delete(core_delete_resource) call is removed from
    /// the /api/v1/{resource}/{name} route in build_router.
    #[tokio::test]
    async fn persistent_volume_delete_returns_non_405() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        let admin = auth::UserInfo {
            username: "admin".to_string(),
            uid: String::new(),
            groups: vec!["system:masters".to_string()],
            extra: Default::default(),
        };

        // Create a PersistentVolume so the DELETE has something to act on.
        let pv_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolume",
            "metadata": { "name": "test-pv" },
            "spec": {
                "capacity": { "storage": "1Gi" },
                "accessModes": ["ReadWriteOnce"],
                "hostPath": { "path": "/tmp/pv" }
            }
        });
        let mut create_req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/persistentvolumes")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(pv_body.to_string()))
            .expect("POST request must build");
        create_req.extensions_mut().insert(admin.clone());
        let create_resp = router
            .call(create_req)
            .await
            .expect("router must not error on POST");
        assert_eq!(
            create_resp.status(),
            StatusCode::CREATED,
            "PersistentVolume POST must return 201 before we can test DELETE"
        );
        // Drain body to reclaim connection.
        let _ = to_bytes(create_resp.into_body(), 4096).await;

        // DELETE the PersistentVolume — must not return 405 MethodNotAllowed.
        // Before the fix: build_router omitted .delete() on /api/v1/{resource}/{name},
        // causing axum to return 405 because the path matched but DELETE was unregistered.
        let mut delete_req = Request::builder()
            .method(Method::DELETE)
            .uri("/api/v1/persistentvolumes/test-pv")
            .body(axum::body::Body::empty())
            .expect("DELETE request must build");
        delete_req.extensions_mut().insert(admin);
        let delete_resp = router
            .call(delete_req)
            .await
            .expect("router must not error on DELETE");
        let delete_status = delete_resp.status();
        assert_ne!(
            delete_status,
            StatusCode::METHOD_NOT_ALLOWED,
            "DELETE /api/v1/persistentvolumes/test-pv must not return 405 — \
             the CSI conformance test deletes PVs after the lifecycle test and \
             a 405 here means the route is not registered"
        );
        assert!(
            delete_status.is_success(),
            "DELETE /api/v1/persistentvolumes/test-pv must succeed (2xx), got {delete_status}"
        );
    }

    /// PATCH/OPTIONS/HEAD on every pod/node/service proxy route must not return 405.
    ///
    /// The `[sig-network] Proxy version v1` conformance tests issue all 7 HTTP verbs
    /// (DELETE GET HEAD OPTIONS PATCH POST PUT) through both the pod-proxy and the
    /// service-proxy subresource, each wrapped in `wait.PollImmediate(10ms, 1min)`.
    /// Before this fix, `build_router` wired only `.get().post().put().delete()` on
    /// all 7 proxy route blocks, so PATCH and OPTIONS returned 405 Method Not Allowed.
    /// Each failing verb then polled for up to a full minute before giving up — turning
    /// a routing gap into hours of conformance wall-clock burn.
    ///
    /// None of the targets below exist, so a request that actually reaches the proxy
    /// handler must 404 ("pod/node/service not found in store"). A 404 proves the verb
    /// was dispatched to the handler; a 405 proves axum's method router rejected the
    /// verb before the handler ever ran — the bug this test guards against.
    #[tokio::test]
    async fn proxy_accepts_all_verbs_else_conformance_proxy_tests_405_and_poll_to_timeout() {
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        // Covers all 7 proxy route blocks in build_router: pod_proxy_root (x2: /proxy
        // and /proxy/), pod_proxy (/proxy/{*path}), node_proxy, service_proxy_root
        // (x2), service_proxy.
        let paths = [
            "/api/v1/namespaces/default/pods/ghost/proxy",
            "/api/v1/namespaces/default/pods/ghost/proxy/",
            "/api/v1/namespaces/default/pods/ghost/proxy/x",
            "/api/v1/nodes/ghost/proxy/x",
            "/api/v1/namespaces/default/services/ghost/proxy",
            "/api/v1/namespaces/default/services/ghost/proxy/",
            "/api/v1/namespaces/default/services/ghost/proxy/x",
        ];

        // Bare `.../proxy` (no trailing slash, no sub-path) 301-redirects for HEAD (like
        // GET) before the store lookup ever runs — the redirect is a URL-normalization
        // step, not a proxy-target check, so it fires even for a target that doesn't
        // exist. Every other path/verb combination still reaches the handler and 404s.
        let bare_root_paths = [
            "/api/v1/namespaces/default/pods/ghost/proxy",
            "/api/v1/namespaces/default/services/ghost/proxy",
        ];

        for method in [Method::PATCH, Method::OPTIONS, Method::HEAD] {
            for path in paths {
                let req = Request::builder()
                    .method(method.clone())
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .expect("request must build");
                let resp = router.call(req).await.expect("router must not error");
                assert_ne!(
                    resp.status(),
                    StatusCode::METHOD_NOT_ALLOWED,
                    "{method} {path} must not return 405 — the Proxy conformance test \
                     issues this verb and wait.PollImmediate()s on it for up to 1 minute \
                     before giving up, which is the wall-clock sink this fix removes"
                );
                let want = if method == Method::HEAD && bare_root_paths.contains(&path) {
                    StatusCode::MOVED_PERMANENTLY
                } else {
                    StatusCode::NOT_FOUND
                };
                assert_eq!(
                    resp.status(),
                    want,
                    "{method} {path} must reach the proxy handler and 404 (target does \
                     not exist), or 301 for a bare-root HEAD — any other status means \
                     the route never dispatched"
                );
            }
        }
    }

    /// POST /api/v1/namespaces/default/secrets with a JSON body must return 201 Created.
    ///
    /// Regression test: Secret creates returned HTTP 400
    /// "invalid JSON: expected value at line 1 column 1".  The conformance suite
    /// (webhook.go:1075 BeforeEach, secrets.go) creates Secrets via client-go which
    /// sends proto-encoded bodies.  This test verifies the JSON path also works — a
    /// broken JSON path means the server cannot accept Secrets from any client.
    ///
    /// Failing case: if the resource is not in the registry, create_namespaced_resource
    /// delegates to the CR handler, which falls through to 404.  If the proto decoder
    /// returns None, extract_body returns raw proto bytes and Object::from_bytes fails
    /// with "invalid JSON".  Both would break all ~31 webhook and secret-volume
    /// conformance tests that depend on Secret creation.
    #[tokio::test]
    async fn secret_create_json_returns_201() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "sample-webhook-secret", "namespace": "default" },
            "type": "Opaque",
            "data": { "key": "dmFsdWU=" }
        });

        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/secrets")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .expect("request build must not fail");
        req.extensions_mut().insert(auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });

        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "POST /api/v1/namespaces/default/secrets must return 201 — \
             before the fix, Secret was not in the registry or the decode path was broken, \
             causing HTTP 400 'invalid JSON' which breaks all ~31 webhook conformance tests \
             that create sample-webhook-secret in BeforeEach"
        );

        let resp_body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&resp_body).expect("response must be JSON");
        assert_eq!(v["kind"], "Secret");
        assert_eq!(v["metadata"]["name"], "sample-webhook-secret");
    }

    /// POST /apis/batch/v1/namespaces/default/jobs with a JSON body must return 201 Created.
    ///
    /// Regression test: batch/v1 Job creates returned HTTP 400
    /// "invalid JSON: expected value at line 1 column 1".  The conformance suite
    /// (job.go:502, job.go:621) creates Jobs via client-go which sends proto-encoded bodies.
    /// This test verifies the JSON path works — a broken JSON path means the server cannot
    /// accept Jobs from any client and all 6 Job/CronJob conformance tests fail immediately.
    #[tokio::test]
    async fn job_create_json_via_router_returns_201() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        let body = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "ci-job", "namespace": "default" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{ "name": "test", "image": "busybox" }],
                        "restartPolicy": "Never"
                    }
                }
            }
        });

        let mut req = Request::builder()
            .method("POST")
            .uri("/apis/batch/v1/namespaces/default/jobs")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .expect("request build must not fail");
        req.extensions_mut().insert(auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });

        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "POST /apis/batch/v1/namespaces/default/jobs must return 201 — \
             before the fix, batch/v1 Job was not in the registry or the decode path was \
             broken, causing HTTP 400 'invalid JSON' which breaks all Job conformance tests"
        );

        let resp_body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&resp_body).expect("response must be JSON");
        assert_eq!(v["kind"], "Job");
        assert_eq!(v["metadata"]["name"], "ci-job");
    }

    /// POST /api/v1/namespaces/default/secrets with a proto-encoded body must return 201.
    ///
    /// Regression test: the conformance client sends Secrets with
    /// Content-Type: application/vnd.kubernetes.protobuf.  If decode_secret_proto returns
    /// None for any reason, extract_body falls back to returning the raw proto bytes, and
    /// Object::from_bytes fails with "invalid JSON: expected value at line 1 column 1".
    ///
    /// This test fails if:
    ///   - decode_secret_proto is removed from decode_core_proto_by_kind
    ///   - Secret::decode fails for a valid proto-encoded secret
    ///   - The proto envelope is not recognised (magic check fails)
    #[tokio::test]
    async fn secret_create_proto_returns_201() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        // Build proto-encoded Secret.
        // Helpers (identical to those in util::tests — kept local to avoid test coupling).
        fn encode_varint(mut v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let byte = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
            out
        }
        fn encode_ld(field: u64, payload: &[u8]) -> Vec<u8> {
            let tag = (field << 3) | 2;
            let mut out = encode_varint(tag);
            out.extend_from_slice(&encode_varint(payload.len() as u64));
            out.extend_from_slice(payload);
            out
        }

        // ObjectMeta { name: "proto-secret", namespace: "default", creationTimestamp: Time{} }
        let mut obj_meta = encode_ld(1, b"proto-secret");
        obj_meta.extend_from_slice(&encode_ld(3, b"default"));
        obj_meta.extend_from_slice(&encode_ld(8, &[])); // empty Time{}

        // Secret { metadata (field 1), type (field 3) }
        // type is wire field 3 per the official k8s proto definition.
        let mut secret_proto = encode_ld(1, &obj_meta);
        secret_proto.extend_from_slice(&encode_ld(3, b"Opaque"));

        // k8s Unknown envelope
        const MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];
        let mut type_meta = encode_ld(1, b"v1");
        type_meta.extend_from_slice(&encode_ld(2, b"Secret"));
        let mut unknown = encode_ld(1, &type_meta);
        unknown.extend_from_slice(&encode_ld(2, &secret_proto));
        let mut proto_body = MAGIC.to_vec();
        proto_body.extend_from_slice(&unknown);

        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/secrets")
            .header("content-type", "application/vnd.kubernetes.protobuf")
            .body(axum::body::Body::from(proto_body))
            .expect("request build must not fail");
        req.extensions_mut().insert(auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });

        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "POST /api/v1/namespaces/default/secrets with proto body must return 201 — \
             the conformance client sends Secrets as proto; if decode_secret_proto returns None \
             extract_body returns raw proto bytes causing 'invalid JSON: expected value at \
             line 1 column 1', breaking all ~31 webhook/secret-volume conformance tests"
        );

        let resp_body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&resp_body).expect("response must be JSON");
        assert_eq!(v["kind"], "Secret", "response kind must be Secret");
        assert_eq!(v["metadata"]["name"], "proto-secret");
    }

    /// POST /apis/batch/v1/namespaces/default/cronjobs with a proto-encoded body must return 201.
    ///
    /// Regression test: the conformance client (cronjob.go:106) creates CronJobs
    /// with Content-Type: application/vnd.kubernetes.protobuf.  If decode_cronjob_proto returns
    /// None, extract_body returns raw proto bytes and Object::from_bytes fails with
    /// "invalid JSON: expected value at line 1 column 1".
    ///
    /// This test fails if:
    ///   - decode_cronjob_proto is removed from decode_core_proto_by_kind
    ///   - CronJob::decode fails for a suspended CronJob proto (the exact conformance scenario)
    ///   - The batch/v1 group is not in the resource registry
    #[tokio::test]
    async fn cronjob_create_proto_suspended_returns_201() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        fn encode_varint(mut v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let byte = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
            out
        }
        fn encode_ld(field: u64, payload: &[u8]) -> Vec<u8> {
            let tag = (field << 3) | 2;
            let mut out = encode_varint(tag);
            out.extend_from_slice(&encode_varint(payload.len() as u64));
            out.extend_from_slice(payload);
            out
        }
        fn encode_varint_field(field: u64, value: u64) -> Vec<u8> {
            let tag = field << 3; // wire type 0
            let mut out = encode_varint(tag);
            out.extend_from_slice(&encode_varint(value));
            out
        }

        // ObjectMeta { name: "test-suspended-cj", namespace: "default" }
        let mut obj_meta = encode_ld(1, b"test-suspended-cj");
        obj_meta.extend_from_slice(&encode_ld(3, b"default"));
        obj_meta.extend_from_slice(&encode_ld(8, &[])); // creationTimestamp

        // JobSpec { backoffLimit: 6 (field 7, wire type 0 = varint) }
        let job_spec = encode_varint_field(7, 6); // backoffLimit = 6

        // JobTemplateSpec sub-message bytes: field 2 = spec (JobSpec)
        // jt_bytes IS the complete sub-message content for JobTemplateSpec
        let jt_bytes = encode_ld(2, &job_spec); // field 2 of JobTemplateSpec = spec = job_spec

        // CronJobSpec { schedule (1), concurrencyPolicy (3), suspend=true (4), jobTemplate (5) }
        let mut cj_spec = encode_ld(1, b"*/5 * * * *"); // schedule
        cj_spec.extend_from_slice(&encode_ld(3, b"Allow")); // concurrencyPolicy
        cj_spec.extend_from_slice(&encode_varint_field(4, 1)); // suspend = true (field 4, wire type 0)
        cj_spec.extend_from_slice(&encode_ld(5, &jt_bytes)); // jobTemplate field 5 = JobTemplateSpec

        // CronJob { metadata (1), spec (2) }
        let mut cj_proto = encode_ld(1, &obj_meta);
        cj_proto.extend_from_slice(&encode_ld(2, &cj_spec));

        // k8s Unknown envelope
        const MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];
        let mut type_meta = encode_ld(1, b"batch/v1");
        type_meta.extend_from_slice(&encode_ld(2, b"CronJob"));
        let mut unknown = encode_ld(1, &type_meta);
        unknown.extend_from_slice(&encode_ld(2, &cj_proto));
        let mut proto_body = MAGIC.to_vec();
        proto_body.extend_from_slice(&unknown);

        let mut req = Request::builder()
            .method("POST")
            .uri("/apis/batch/v1/namespaces/default/cronjobs")
            .header("content-type", "application/vnd.kubernetes.protobuf")
            .body(axum::body::Body::from(proto_body))
            .expect("request build must not fail");
        req.extensions_mut().insert(auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });

        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "POST /apis/batch/v1/namespaces/default/cronjobs with proto body (suspend=true) \
             must return 201 — the conformance client at cronjob.go:106 creates a suspended \
             CronJob via proto; if decode_cronjob_proto returns None for this input, \
             extract_body returns raw proto bytes causing HTTP 400 'invalid JSON'"
        );

        let resp_body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&resp_body).expect("response must be JSON");
        assert_eq!(v["kind"], "CronJob", "response kind must be CronJob");
        assert_eq!(v["metadata"]["name"], "test-suspended-cj");
        assert_eq!(
            v["spec"]["schedule"], "*/5 * * * *",
            "schedule must survive proto decode"
        );
        assert_eq!(
            v["spec"]["suspend"], true,
            "suspend=true must survive proto decode — this is the exact conformance scenario"
        );
    }

    /// GET /apis/flowcontrol.apiserver.k8s.io must return 200 with kind=APIGroup.
    ///
    /// The API priority and fairness conformance test discovers the group via GET /apis,
    /// then probes GET /apis/flowcontrol.apiserver.k8s.io. Before the fix, no route existed
    /// for /apis/{group} and the request returned 404, causing the conformance test to fail
    /// with "expected flowcontrol API group". This test fails if the /apis/{group} route is removed.
    #[tokio::test]
    async fn get_flowcontrol_api_group_route_returns_200() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/apis/flowcontrol.apiserver.k8s.io")
            .body(axum::body::Body::empty())
            .expect("request must build");
        req.extensions_mut().insert(auth::UserInfo {
            username: "test".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });
        let resp = router.call(req).await.expect("router must not error");

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET /apis/flowcontrol.apiserver.k8s.io must return 200 — \
             the conformance test probes this endpoint after discovering the group in /apis; \
             404 causes the API priority and fairness test to abort"
        );

        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let val: serde_json::Value = serde_json::from_slice(&body).expect("response must be JSON");
        assert_eq!(
            val["kind"], "APIGroup",
            "response must have kind=APIGroup — clients use this to discover the preferred version"
        );
        assert_eq!(val["name"], "flowcontrol.apiserver.k8s.io");
    }

    /// GET /apis/, /api/, and /apis/{group}/ (with a literal trailing slash) must
    /// return the same discovery doc as the no-slash form, not 404.
    ///
    /// Upstream e2e clients (Discovery "should validate PreferredVersion for each
    /// APIGroup" and kubectl proxy --port 0) call AbsPath('/apis/'), AbsPath('/api/'),
    /// etc. with a trailing slash. Before the fix, only the no-slash routes were
    /// registered, so these clients got 404 "server could not find the requested
    /// resource" instead of the discovery document.
    #[tokio::test]
    async fn discovery_routes_with_trailing_slash_return_200() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;

        for (path, expected_kind) in [
            ("/api/", "APIVersions"),
            ("/apis/", "APIGroupList"),
            ("/apis/flowcontrol.apiserver.k8s.io/", "APIGroup"),
        ] {
            let store = std::sync::Arc::new(make_store());
            let state = state::AppState::new(
                std::sync::Arc::clone(&store),
                None,
                None,
                std::collections::HashMap::new(),
                "https://localhost:6443".into(),
            );
            let mut router = build_router(state);

            let mut req = Request::builder()
                .method(Method::GET)
                .uri(path)
                .body(axum::body::Body::empty())
                .expect("request must build");
            req.extensions_mut().insert(auth::UserInfo {
                username: "test".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            });
            let resp = router.call(req).await.expect("router must not error");

            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "GET {path} must return 200 — a client that appends a trailing slash to a \
                 discovery path must get the same doc as the no-slash form, else kubectl/ \
                 discovery/proxy clients break"
            );

            let body = to_bytes(resp.into_body(), 8192)
                .await
                .expect("body collect must not fail");
            let val: serde_json::Value =
                serde_json::from_slice(&body).expect("response must be JSON");
            assert_eq!(
                val["kind"], expected_kind,
                "GET {path} must return kind={expected_kind}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // serve_connection with_upgrades regression test
    //
    // Without with_upgrades(), hyper's HTTP/1.1 server sends the 101 Switching
    // Protocols response but never hands the connection off to the upgrade
    // handler. The on_upgrade callback never runs, the WebSocket splice never
    // starts, and kubectl times out with "unexpected output from server".
    //
    // This test fails if with_upgrades() is removed from serve_connection:
    // the WebSocket client sends a message and expects to read it back, but
    // without with_upgrades() the echo handler never runs — the recv() blocks
    // and the timeout fires.
    // -----------------------------------------------------------------------

    /// serve_connection().with_upgrades() must allow WebSocket upgrade handlers to run.
    ///
    /// This is the regression test for the exec "unexpected output from server" bug.
    /// When with_upgrades() was absent from serve_connection(), hyper sent 101 but
    /// never drove the upgrade — the on_upgrade closure never ran, the splice was
    /// never started, and kubectl timed out at 60s with no output.
    ///
    /// This test MUST fail if with_upgrades() is removed: the WebSocket client will
    /// connect (101 received) but recv() will block indefinitely because the echo
    /// handler never runs, causing the 2-second timeout to fire.
    #[tokio::test]
    async fn serve_connection_with_upgrades_allows_websocket_handler_to_run() {
        use axum::{
            extract::ws::{WebSocket, WebSocketUpgrade},
            routing::get,
            Router,
        };
        use futures_util::{SinkExt as _, StreamExt as _};
        use tokio::net::TcpListener;
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest as _};

        // Build an axum router with a single WebSocket echo endpoint.
        let app = Router::new().route(
            "/ws",
            get(|ws: WebSocketUpgrade| async {
                ws.on_upgrade(|mut socket: WebSocket| async move {
                    // Echo one message back and close.
                    if let Some(Ok(msg)) = socket.recv().await {
                        let _ = socket.send(msg).await;
                    }
                })
            }),
        );

        // Bind a real TCP listener on a random port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn the server using our serve_connection pattern WITH with_upgrades().
        // This mirrors what serve_tls() does (minus TLS) and is the exact code path
        // that had the missing with_upgrades() bug. It uses the same auto::Builder
        // serve_tls() uses so this test still exercises the real production dispatch:
        // a plain HTTP/1.1 WebSocket handshake (no ALPN, no h2 preface) must still
        // route to the h1-with-upgrades branch, not silently drop the upgrade.
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(tcp);
            let service = hyper::service::service_fn(move |req| {
                let mut app = app.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        tower_service::Service::call(&mut app, req).await.unwrap(),
                    )
                }
            });
            // with_upgrades() is the fix — removing it causes this test to fail
            // because the on_upgrade closure never runs and the client recv() blocks.
            let _ =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection_with_upgrades(io, service)
                    .await;
        });

        // Connect a WebSocket client and exchange one message.
        let url = format!("ws://{addr}/ws");
        let request = url.into_client_request().unwrap();
        let (mut ws, _) = connect_async(request)
            .await
            .expect("WebSocket connect must succeed");

        let payload = b"hello from websocket";
        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
            payload.to_vec().into(),
        ))
        .await
        .expect("send must succeed");

        // The echo handler must reply within 2 seconds.
        // Without with_upgrades(), the handler never runs and this times out.
        let reply = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
            .await
            .expect(
                "WebSocket reply must arrive within 2s — if it times out, \
                 with_upgrades() is missing from serve_connection() and the \
                 on_upgrade callback never runs",
            )
            .expect("stream must not end without a reply")
            .expect("WebSocket recv must not error");

        match reply {
            tokio_tungstenite::tungstenite::Message::Binary(b) => {
                assert_eq!(
                    b.as_ref(),
                    payload,
                    "echoed bytes must match sent bytes — \
                     a mismatch means the upgrade handler ran but data was corrupted"
                );
            }
            other => {
                panic!(
                    "expected Binary frame with echo, got {other:?} — \
                     the WebSocket upgrade handler must echo the sent message"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // HTTP/2 (ALPN h2) multiplexing regression test
    //
    // Before this fix the apiserver was HTTP/1.1-only: no `alpn_protocols` in
    // generate_tls()'s rustls ServerConfig and a hardcoded http1::Builder in
    // serve_tls(). HTTP/1.1 cannot run two requests concurrently on one TCP
    // connection, so kubelet's client-go stack had no choice but to open one
    // dedicated TCP connection per watch reflector. Under 16-way [Conformance]
    // runs, ~150-200 reflectors reconnecting together produced a SYN burst
    // that overwhelmed the shared `limactl usernet` process and caused
    // `dial tcp 10.96.0.1:443: i/o timeout` failures elsewhere in the suite.
    //
    // This test proves the fix end-to-end, mirroring kubelet's real behavior:
    // a client offers ALPN ["h2", "http/1.1"] (client-go's default order) and
    // then relies on the server having picked h2 to multiplex many concurrent
    // requests over that one connection.
    // -----------------------------------------------------------------------

    /// The server must negotiate ALPN h2 (not fall back to http/1.1) and must
    /// actually run N concurrent requests over the single resulting connection.
    ///
    /// This test MUST fail if reverted:
    /// - If generate_tls() stops setting `alpn_protocols`, the assertion on
    ///   `alpn_protocol()` fails immediately (server negotiates nothing).
    /// - If serve_tls()'s auto::Builder reverts to a plain http1::Builder, the
    ///   HTTP/2 client handshake below never completes (the server's HTTP/1.1
    ///   parser cannot make sense of the raw HTTP/2 connection preface), and
    ///   the surrounding timeout fires.
    /// - If the server ever silently serialized requests instead of truly
    ///   multiplexing them (e.g. a broken auto-detect that fell back to
    ///   handling one stream at a time), the barrier every handler waits on
    ///   would deadlock, since no single request can complete until all N
    ///   have been received concurrently — the surrounding timeout catches
    ///   that too.
    #[tokio::test]
    async fn http2_alpn_negotiated_and_multiplexes_concurrent_requests_on_one_connection() {
        use axum::routing::get;
        use bytes::Bytes;
        use http_body_util::Empty;
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use rustls::pki_types::CertificateDer;
        use rustls::{ClientConfig, RootCertStore};
        use std::time::Duration;
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::Barrier;

        const N: usize = 20;

        rustls_post_quantum::provider().install_default().ok();

        let dir = std::env::temp_dir().join(format!(
            "u7s-h2-alpn-test-{}-{:?}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir"); // lgtm[rust/path-injection]
        let args = Args {
            db: "./state.db".into(),
            listen: "0.0.0.0:6443".into(),
            kubeconfig: "./kubeconfig".into(),
            token_auth_file: None,
            sa_key: "./sa.key".into(),
            sa_pub: "./sa.pub".into(),
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
            advertise_address: None,
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            sa_sig_cache_size: None,
            manifest_dir: "/etc/u7s/manifests".into(),
        };
        let tls = crate::tls::generate_tls(&args).expect("generate_tls must succeed");

        // --- Server: the real, unmodified serve_tls() — the exact production
        // dispatcher under test, not a hand-rolled mirror of it. A route handler
        // that blocks on a barrier proves genuine HTTP/2 multiplexing: if
        // serve_tls() ever fell back to serializing requests, request 2 could
        // never arrive until request 1's handler had already returned, and this
        // would deadlock instead of completing.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind must succeed");
        let server_addr = listener.local_addr().unwrap();
        let barrier = Arc::new(Barrier::new(N));
        let app = Router::new().route(
            "/",
            get({
                let barrier = Arc::clone(&barrier);
                move || {
                    let barrier = Arc::clone(&barrier);
                    async move {
                        barrier.wait().await;
                        "ok"
                    }
                }
            }),
        );
        tokio::spawn(serve_tls(listener, app, tls.server_config.clone()));

        // --- Client: offer ALPN [h2, http/1.1] in that order, exactly like
        // client-go's net/http.Transport (confirmed via live pcap in
        // ai/findings/alpn-check-2026-08-02.md) — then require h2 to have won. ---
        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(tls.ca_cert_der.clone()))
            .expect("add CA cert to root store");
        let mut client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let tcp = TcpStream::connect(server_addr)
            .await
            .expect("TCP connect must succeed");
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls_stream =
            tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
                .await
                .expect("TLS handshake must not hang")
                .expect("TLS handshake must succeed");

        let negotiated = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        assert_eq!(
            negotiated.as_deref(),
            Some(b"h2".as_slice()),
            "server offered ALPN [h2, http/1.1] like kubelet does, but negotiated \
             {negotiated:?} instead of h2 — kubelet's watch reflectors would fall back \
             to one dedicated TCP connection per watch, reproducing the mass SYN-burst \
             regression this test guards against"
        );

        let io = TokioIo::new(tls_stream);
        let (send_request, connection) = tokio::time::timeout(
            Duration::from_secs(5),
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake::<_, Empty<Bytes>>(io),
        )
        .await
        .expect(
            "HTTP/2 handshake must not hang — a server still speaking HTTP/1.1 \
             under the hood would misparse the raw HTTP/2 connection preface",
        )
        .expect("HTTP/2 handshake must succeed");
        tokio::spawn(connection);

        // Fire N concurrent requests over the SAME h2 connection by cloning the
        // sender — this is exactly what client-go's pooled h2 transport does for
        // kubelet's N concurrent watch reflectors instead of dialing N sockets.
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let mut sender = send_request.clone();
            handles.push(tokio::spawn(async move {
                let req = axum::http::Request::builder()
                    .uri("/")
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                sender.send_request(req).await
            }));
        }

        // All N requests are sent over the one TCP connection opened above (bounded
        // by construction: we never call TcpStream::connect() a second time, and
        // send_request.clone() shares the same underlying HTTP/2 connection — the
        // same pooling behavior client-go's transport applies once it has
        // negotiated h2 with a peer). What the barrier below actually proves is
        // that the server can genuinely service N requests concurrently on that
        // single connection rather than one-at-a-time.
        for handle in handles {
            let resp = tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .expect(
                    "all N concurrent requests must complete within 5s — if the server \
                     failed to multiplex them on one h2 connection, the shared barrier \
                     would deadlock waiting for streams that never arrived",
                )
                .expect("request task must not panic")
                .expect("request must succeed");
            assert_eq!(resp.status(), 200);
        }

        let _ = std::fs::remove_dir_all(&dir); // lgtm[rust/path-injection]
    }

    /// Requests to unregistered routes must return HTTP 404 with a valid
    /// Kubernetes Status JSON body.
    ///
    /// Without a fallback handler axum returns an empty-body 404. Clients such
    /// as conformance-test harnesses and kubectl parse the body with serde_json
    /// and fail immediately with "invalid JSON: expected value at line 1 column 1".
    #[tokio::test]
    async fn unregistered_route_returns_json_status_404() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        let req = Request::builder()
            .uri("/completely/unregistered/path")
            .body(axum::body::Body::empty())
            .expect("request must build");
        let resp = router.call(req).await.expect("router must not error");

        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "unregistered route must return 404, not an empty response — \
             clients parse the body as JSON and fail with parse errors on empty bodies"
        );

        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let val: serde_json::Value = serde_json::from_slice(&body).expect(
            "fallback response body must be valid JSON — \
                 empty body causes serde_json to report 'expected value at line 1 column 1'",
        );
        assert_eq!(
            val["kind"], "Status",
            "fallback body must have kind=Status — Kubernetes clients check this field \
             to distinguish API errors from non-Kubernetes HTTP errors"
        );
        assert_eq!(
            val["code"], 404,
            "fallback body must have code=404 — clients use this field for error display"
        );
        assert_eq!(
            val["status"], "Failure",
            "fallback body must have status=Failure per Kubernetes Status schema"
        );
    }

    /// GET /api/v1/namespaces/{ns}/pods/{name} must reach the pod handler, not the fallback.
    ///
    /// dns-common.go:495 polls this exact path to verify a pod exists before exec-ing into it.
    /// If the fallback fires instead of the pod handler, the client receives
    /// "the server could not find the requested resource" which is different from the
    /// "Pod ... not found" the pod handler returns.  DNS conformance burns 614 s retrying.
    ///
    /// This test fails if the pod GET route is mis-registered so axum hits fallback_handler:
    /// the body message would be "the server could not find the requested resource" not
    /// Pod "..." not found".
    #[tokio::test]
    async fn get_pod_with_uuid_name_reaches_pod_handler_not_fallback() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;
        use u7s_store::Store;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed the namespace so parse_namespace does not reject it.
        let ns_key = keys::cluster_object_key("namespaces", "dns-2235");
        let ns_body = serde_json::json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": { "name": "dns-2235" }
        });
        store
            .put(&ns_key, bytes::Bytes::from(ns_body.to_string()), Some(0))
            .await
            .expect("seed namespace must succeed");

        let mut router = build_router(state);

        // UUID-style name — exactly what the DNS conformance test uses.
        let pod_name = "dns-test-99675610-b3d2-4d11-af4a-b660a620ab98";
        let uri = format!("/api/v1/namespaces/dns-2235/pods/{pod_name}");

        let req = Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .body(axum::body::Body::empty())
            .expect("request must build");
        let resp = router.call(req).await.expect("router must not error");

        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "GET {uri} must return 404 — pod was not seeded, but fallback fires with wrong message"
        );

        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let val: serde_json::Value = serde_json::from_slice(&body).expect("response must be JSON");

        // The pod handler returns `Pod "..." not found`.
        // The fallback returns `the server could not find the requested resource`.
        // Only the pod handler message proves the route is registered correctly.
        let message = val["message"].as_str().unwrap_or("");
        assert!(
            message.starts_with("Pod"),
            "GET {uri} must return 'Pod ... not found', not '{}' — \
             if the fallback fires dns-common.go will never see the pod and burns 614 s",
            message
        );
    }

    /// The reconciler task must exit promptly when the shutdown signal fires.
    /// Without a shutdown channel the task runs forever and blocks graceful server shutdown,
    /// leaving orphaned background work that cannot be cancelled or awaited.
    #[tokio::test]
    async fn reconciler_task_exits_on_shutdown_signal() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let store = Arc::new(make_store());
        let reconcile_count = Arc::new(AtomicU32::new(0));

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let count = Arc::clone(&reconcile_count);
        let reconcile_store = Arc::clone(&store);
        let handle = tokio::spawn(async move {
            let mut consecutive_errors: u32 = 0;
            loop {
                let ok = reconcile_kubernetes_endpointslice(&reconcile_store).await;
                count.fetch_add(1, Ordering::Relaxed);
                if ok {
                    consecutive_errors = 0;
                } else {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                }
                let delay_secs = (5u64 << consecutive_errors.min(6)).min(300);
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(delay_secs)) => {}
                    _ = shutdown_rx.changed() => break,
                }
            }
        });

        // Wait for the first reconcile to complete before sending shutdown.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if reconcile_count.load(Ordering::Relaxed) >= 1 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("reconciler must complete first cycle within 5 s");

        let count_before_shutdown = reconcile_count.load(Ordering::Relaxed);

        // Signal shutdown — the task is sleeping (delay_secs = 5) so this must interrupt
        // the sleep and cause the task to exit without running another reconcile cycle.
        shutdown_tx.send(true).expect("send must succeed");

        tokio::time::timeout(std::time::Duration::from_secs(1), handle)
            .await
            .expect("reconciler task must exit within 1 s of receiving shutdown signal")
            .expect("task must not panic");

        let count_after_shutdown = reconcile_count.load(Ordering::Relaxed);
        assert_eq!(
            count_before_shutdown, count_after_shutdown,
            "reconciler must not run another cycle after shutdown signal — \
             without select! the task sleeps 5 s and cannot be cancelled"
        );
    }

    /// After creating a pod against a quota, reconcile_quota_status must update status.used.pods.
    /// Without this reconciler kubectl describe quota always shows 0 used, breaking observability.
    #[tokio::test]
    async fn reconcile_quota_status_updates_used_after_pod_created() {
        use bytes::Bytes;

        let store = Arc::new(make_store());

        let quota = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "test-quota", "namespace": "default" },
            "spec": { "hard": { "pods": "10" } },
            "status": { "used": { "pods": "0" } }
        });
        store
            .put(
                "/registry/resourcequotas/default/test-quota",
                Bytes::from(serde_json::to_vec(&quota).unwrap()),
                None,
            )
            .await
            .unwrap();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "pod-0", "namespace": "default" }
        });
        store
            .put(
                "/registry/pods/default/pod-0",
                Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        let ok = reconcile_quota_status(&store).await;
        assert!(ok, "reconciler must succeed");

        let item = store
            .get("/registry/resourcequotas/default/test-quota")
            .await
            .unwrap()
            .expect("quota must still exist");
        let updated: serde_json::Value = serde_json::from_slice(&item.value).unwrap();
        assert_eq!(
            updated["status"]["used"]["pods"].as_str(),
            Some("1"),
            "status.used.pods must reflect the live pod count — \
             without the reconciler kubectl describe quota shows stale 0"
        );
    }

    /// When status.used already matches live counts, reconcile_quota_status must not write.
    /// Unnecessary writes increment the resource version and trigger spurious watches.
    #[tokio::test]
    async fn reconcile_quota_status_skips_write_when_already_in_sync() {
        use bytes::Bytes;

        let store = Arc::new(make_store());

        let quota = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "synced-quota", "namespace": "default" },
            "spec": { "hard": { "pods": "10" } },
            "status": { "used": { "pods": "1" } }
        });
        store
            .put(
                "/registry/resourcequotas/default/synced-quota",
                Bytes::from(serde_json::to_vec(&quota).unwrap()),
                None,
            )
            .await
            .unwrap();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "pod-0", "namespace": "default" }
        });
        store
            .put(
                "/registry/pods/default/pod-0",
                Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        let revision_before = store
            .get("/registry/resourcequotas/default/synced-quota")
            .await
            .unwrap()
            .unwrap()
            .revision;

        reconcile_quota_status(&store).await;

        let revision_after = store
            .get("/registry/resourcequotas/default/synced-quota")
            .await
            .unwrap()
            .unwrap()
            .revision;

        assert_eq!(
            revision_before, revision_after,
            "reconciler must not write when status.used already matches live counts — \
             spurious writes trigger watches and increment resourceVersion unnecessarily"
        );
    }

    /// The quota reconciler task must exit promptly when the shutdown signal fires.
    #[tokio::test]
    async fn quota_reconciler_task_exits_on_shutdown_signal() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let store = Arc::new(make_store());
        let reconcile_count = Arc::new(AtomicU32::new(0));

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let count = Arc::clone(&reconcile_count);
        let reconcile_store = Arc::clone(&store);
        let handle = tokio::spawn(async move {
            let mut consecutive_errors: u32 = 0;
            loop {
                let ok = reconcile_quota_status(&reconcile_store).await;
                count.fetch_add(1, Ordering::Relaxed);
                if ok {
                    consecutive_errors = 0;
                } else {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                }
                let delay_secs = (5u64 << consecutive_errors.min(6)).min(300);
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(delay_secs)) => {}
                    _ = shutdown_rx.changed() => break,
                }
            }
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if reconcile_count.load(Ordering::Relaxed) >= 1 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("quota reconciler must complete first cycle within 5 s");

        let count_before = reconcile_count.load(Ordering::Relaxed);
        shutdown_tx.send(true).expect("send must succeed");

        tokio::time::timeout(std::time::Duration::from_secs(1), handle)
            .await
            .expect("quota reconciler task must exit within 1 s of receiving shutdown signal")
            .expect("task must not panic");

        assert_eq!(
            count_before,
            reconcile_count.load(Ordering::Relaxed),
            "quota reconciler must not run another cycle after shutdown — \
             without select! the sleeping task cannot be cancelled"
        );
    }

    // -----------------------------------------------------------------------
    // SIGHUP-triggered manifest reload (mayor-bh36n). Unlike every other test in this file,
    // this one drives the real, unmodified `run()` end-to-end (live TLS listener,
    // mTLS-authenticated requests) — that's the only way to prove the signal-handler wiring
    // inside `run()` itself reacts to a real OS SIGHUP without a process restart, rather than
    // just exercising `bootstrap_apply::reload_well_known_manifest_dir` in isolation (already
    // covered by `bootstrap_apply.rs`'s own tests).
    // -----------------------------------------------------------------------

    /// Minimal duplicate of `bootstrap_apply.rs`'s own `read_kubeconfig_creds` field
    /// extraction (same reasoning given there: this test needs the fixed shape
    /// `tls::write_kubeconfig` writes, not a general YAML parser).
    fn sighup_test_extract_kubeconfig_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(key).map(str::trim))
    }

    /// Build an mTLS `reqwest::Client` + base server URL from a kubeconfig `run()` wrote to
    /// disk (the admin/`system:masters` identity), so the test can make real,
    /// RBAC-authenticated requests against the real listener the same way kubectl would.
    fn sighup_test_client_from_kubeconfig(raw: &str) -> (reqwest::Client, String) {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let server = sighup_test_extract_kubeconfig_field(raw, "server:")
            .expect("kubeconfig missing server")
            .to_owned();
        let ca_pem = b64
            .decode(
                sighup_test_extract_kubeconfig_field(raw, "certificate-authority-data:")
                    .expect("kubeconfig missing certificate-authority-data")
                    .trim(),
            )
            .expect("decode CA cert");
        let mut identity_pem = b64
            .decode(
                sighup_test_extract_kubeconfig_field(raw, "client-certificate-data:")
                    .expect("kubeconfig missing client-certificate-data")
                    .trim(),
            )
            .expect("decode client cert");
        identity_pem.extend(
            b64.decode(
                sighup_test_extract_kubeconfig_field(raw, "client-key-data:")
                    .expect("kubeconfig missing client-key-data")
                    .trim(),
            )
            .expect("decode client key"),
        );
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_certs_only([reqwest::Certificate::from_pem(&ca_pem).expect("parse CA cert")])
            .identity(reqwest::Identity::from_pem(&identity_pem).expect("build mTLS identity"))
            .build()
            .expect("build reqwest client");
        (client, server)
    }

    async fn sighup_test_wait_for_file(path: &std::path::Path) -> String {
        for _ in 0..200 {
            if let Ok(s) = std::fs::read_to_string(path) {
                if !s.is_empty() {
                    return s;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("{} never appeared within 5s", path.display());
    }

    /// Regression test for mayor-bh36n: SIGHUP must re-scan and re-apply the well-known
    /// manifest directory in the SAME process — no restart, no dropped listener — and a bad
    /// manifest hit during that reload must be logged and skipped rather than crashing the
    /// apiserver, unlike a bad manifest at cold boot (which stays fatal, unchanged by this
    /// bead). If the SIGHUP handler were ever removed from `run()`, or reload reverted to
    /// boot's fatal-on-first-bad-file behavior, this test fails: the post-SIGHUP manifest would
    /// never apply, or the process would stop answering requests entirely.
    #[tokio::test]
    async fn sighup_reloads_manifests_without_restart_and_skips_a_bad_file_without_crashing() {
        let dir = std::env::temp_dir().join(format!(
            "u7s-sighup-reload-test-{}-{:?}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos(),
            std::thread::current().id()
        ));
        let manifest_dir = dir.join("manifests");
        std::fs::create_dir_all(&manifest_dir).expect("create manifest dir");

        // Bind-then-drop to find a free port: run() binds its own listener internally with no
        // injection point for a test-owned one, so this is the only way to learn the port
        // before spawning it.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
            listener.local_addr().expect("local addr").port()
        };

        let args = Args {
            db: dir.join("state.db").to_string_lossy().into_owned(),
            listen: format!("127.0.0.1:{port}"),
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
            advertise_address: Some(format!("https://127.0.0.1:{port}")),
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            sa_sig_cache_size: None,
            manifest_dir: manifest_dir.to_string_lossy().into_owned(),
        };
        let kubeconfig_path = std::path::PathBuf::from(&args.kubeconfig);

        tokio::spawn(run(args));

        let raw_kubeconfig = sighup_test_wait_for_file(&kubeconfig_path).await;
        let (client, server) = sighup_test_client_from_kubeconfig(&raw_kubeconfig);
        let cm_url =
            |name: &str| format!("{server}/api/v1/namespaces/kube-system/configmaps/{name}");

        // Poll until the listener is actually accepting connections — the kubeconfig is
        // written well before the TLS listener binds and the boot-time manifest scan runs.
        let mut healthy = false;
        for _ in 0..200 {
            if client
                .get(format!("{server}/healthz"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                healthy = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(
            healthy,
            "apiserver must become reachable within 5s of run() starting"
        );

        // Sanity check: this manifest is written AFTER boot, so it must not already be
        // applied — otherwise the assertions below wouldn't actually be proving SIGHUP did
        // anything.
        std::fs::write(
            manifest_dir.join("00-after-boot.yaml"),
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: sighup-reload-test\n  namespace: kube-system\ndata:\n  foo: bar\n",
        )
        .expect("write post-boot manifest");
        let precheck_status = client
            .get(cm_url("sighup-reload-test"))
            .send()
            .await
            .expect("GET must not fail transport-wise")
            .status();
        assert_eq!(
            precheck_status, 404,
            "a manifest written after boot must not already be applied by anything other than \
             SIGHUP — otherwise this test would prove nothing"
        );

        let send_sighup = || {
            let status = std::process::Command::new("kill")
                .arg("-HUP")
                .arg(std::process::id().to_string())
                .status()
                .expect("run kill(1) against our own pid");
            assert!(
                status.success(),
                "kill -HUP must succeed against our own pid"
            );
        };

        send_sighup();

        let mut applied = false;
        for _ in 0..200 {
            if client
                .get(cm_url("sighup-reload-test"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                applied = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(
            applied,
            "SIGHUP must re-scan and re-apply the well-known manifest directory in place — a \
             manifest written after boot must land without a process restart"
        );

        // Now prove the log-and-skip side: a bad file alongside a new good one, in the SAME
        // reload pass, must not stop the good one from applying or take the process down.
        std::fs::write(
            manifest_dir.join("01-bad.yaml"),
            "this: is: not: valid: yaml: [\n",
        )
        .expect("write bad manifest");
        std::fs::write(
            manifest_dir.join("02-after-bad.yaml"),
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: sighup-reload-after-bad\n  namespace: kube-system\ndata:\n  foo: bar\n",
        )
        .expect("write second post-boot manifest");

        send_sighup();

        let mut applied_after_bad = false;
        for _ in 0..200 {
            if client
                .get(cm_url("sighup-reload-after-bad"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                applied_after_bad = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(
            applied_after_bad,
            "a bad manifest file must not stop OTHER files in the same reload pass from \
             applying — this is the entire point of log-and-skip over the boot path's \
             fatal-and-abort"
        );

        let healthz_after = client.get(format!("{server}/healthz")).send().await.expect(
            "apiserver must still be reachable after a SIGHUP hit a bad manifest — a bad \
                 reload must never crash the process",
        );
        assert!(
            healthz_after.status().is_success(),
            "a bad manifest during SIGHUP reload must never crash the process — it must still \
             be serving /healthz"
        );

        let previous_still_present = client
            .get(cm_url("sighup-reload-test"))
            .send()
            .await
            .expect("GET must not fail transport-wise")
            .status();
        assert!(
            previous_still_present.is_success(),
            "state applied by the FIRST successful reload must survive a later reload that \
             hits a bad manifest — a bad edit must not roll back or disturb already-applied \
             state"
        );
    }
}

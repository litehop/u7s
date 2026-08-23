//! `Args` on its own so both `lib.rs` (which needs it for `run`/`tls.rs`)
//! and the thin `main.rs` binary shell (which needs it to call
//! `Args::parse()`) can share the same definition via `lib.rs`'s
//! `pub use args::Args;` re-export.
use clap::Parser;

#[derive(Parser)]
pub struct Args {
    #[arg(long, default_value = "./state.db")]
    pub(crate) db: String,

    #[arg(long, default_value = "0.0.0.0:6443")]
    pub(crate) listen: String,

    /// Output path for the generated kubeconfig. Write-only on first run —
    /// not a read fixture. Generated fresh from TLS material each startup.
    #[arg(long, default_value = "./kubeconfig")]
    pub(crate) kubeconfig: String,

    /// Path to a bearer-token auth file (token,user,uid,group,...).
    /// Optional. When absent, only anonymous access is permitted unless
    /// RBAC grants it.
    #[arg(long)]
    pub(crate) token_auth_file: Option<String>,

    /// Path to the RSA private key used to sign service-account JWTs.
    /// Generated on first run; loaded on subsequent starts to keep tokens valid.
    #[arg(long, default_value = "./sa.key")]
    pub(crate) sa_key: String,

    /// Path to write the RSA public key (companion to --sa-key).
    #[arg(long, default_value = "./sa.pub")]
    pub(crate) sa_pub: String,

    /// Path to the CA private key (PEM). Generated on first run; loaded on
    /// subsequent starts so the CA stays stable across restarts.
    #[arg(long, default_value = "./ca.key")]
    pub(crate) ca_key: String,

    /// Path to the CA certificate (DER). Generated on first run; loaded on
    /// subsequent starts so kubelets trust the same CA after a restart.
    #[arg(long, default_value = "./ca.crt")]
    pub(crate) ca_cert: String,

    /// Path to the dedicated front-proxy CA private key (PEM). Generated on first run;
    /// loaded on subsequent starts so the CA stays stable across restarts. Distinct from
    /// `--ca-key`/`--ca-cert` (the main cluster CA): this CA signs only the proxy-client
    /// leaf cert u7s presents to AGGREGATED BACKENDS (see `TlsMaterial::proxy_client_cert_pem`'s
    /// doc), so a cert issued for any other purpose (e.g. a leaked admin kubeconfig) can
    /// never be replayed against an aggregated backend to spoof `X-Remote-User`/`-Group`.
    #[arg(long, default_value = "./proxy-client-ca.key")]
    pub(crate) proxy_client_ca_key: String,

    /// Path to the dedicated front-proxy CA certificate (DER). Generated on first run;
    /// loaded on subsequent starts. Published into the `kube-system/extension-apiserver-
    /// authentication` ConfigMap's `requestheader-client-ca-file` key so aggregated
    /// backends trust leaf certs signed by it (see `reconcile_extension_apiserver_authentication`).
    #[arg(long, default_value = "./proxy-client-ca.crt")]
    pub(crate) proxy_client_ca_cert: String,

    /// Address advertised to clients in /api discovery (e.g. "https://1.2.3.4:6443").
    /// Defaults to the listen address, substituting 0.0.0.0 with 127.0.0.1.
    #[arg(long)]
    pub(crate) advertise_address: Option<String>,

    /// CIDR range from which clusterIPs are auto-allocated for Services.
    /// Must be a valid IPv4 CIDR with prefix length <= 30 (e.g. "10.96.0.0/12").
    /// Matches kubeadm's default. Set to empty string to disable auto-allocation.
    #[arg(long, default_value = "10.96.0.0/12")]
    pub(crate) service_cluster_ip_range: String,

    /// Hostname or IP to use for all kubelet proxy requests (log, exec, attach, port-forward).
    /// When set, overrides the node's InternalIP from status.addresses. Useful when the
    /// apiserver runs on a different host than the kubelet (e.g. Mac host + Lima VM) and
    /// the node's InternalIP is not directly reachable from the apiserver.
    #[arg(long)]
    pub(crate) kubelet_preferred_address: Option<String>,

    /// Host-side port the kubelet is reachable on for proxy requests (log, exec, attach,
    /// port-forward). The kubelet always serves on 10250 inside the VM; override this when
    /// the lima port-forward maps guest 10250 to a different host port for per-worktree
    /// isolation. Must match the hostPort in lima/kubelet.yaml portForwards. This is the
    /// PRIMARY node's port — every other node needs its own --node-kubelet-port entry.
    #[arg(long, default_value = "10250")]
    pub(crate) kubelet_port: u16,

    /// Per-node override of --kubelet-port, for every node but the primary. Format:
    /// <node-name>=<host-port>. Repeatable — pass one entry per additional node. VM
    /// InternalIPs are not host-routable, so each node's kubelet is reached through its
    /// own host port-forward to 127.0.0.1; without an entry here, proxy requests (log,
    /// exec, attach, port-forward) for a pod on that node would dial --kubelet-port —
    /// the PRIMARY's forward — instead of the node's own.
    #[arg(long)]
    pub(crate) node_kubelet_port: Vec<String>,

    /// Address of a konnectivity-server HTTP CONNECT proxy used to route admission webhook
    /// calls through the tunnel so that pod IPs inside the Lima VM are reachable from the
    /// Mac host. Format: "host:port" (e.g. "127.0.0.1:8135"). Omit to disable proxying.
    #[arg(long)]
    pub(crate) konnectivity_proxy_addr: Option<String>,

    /// Max number of distinct SA-JWT signatures cached to skip the RSA verify (modular
    /// exponentiation) on repeat presentation of the same token. Falls back to the
    /// U7S_SA_SIG_CACHE_SIZE env var, then 512, when unset — see `sa_sig_cache` module doc.
    #[arg(long)]
    pub(crate) sa_sig_cache_size: Option<usize>,
}

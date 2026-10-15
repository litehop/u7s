/// Resolves a `namespace/name:port` Service reference (webhook `clientConfig.service`, CRD
/// conversion webhook, `APIService.spec.service`) to the address the apiserver dials.
///
/// Mirrors upstream's `proxy.ResolveCluster` (apiserver/pkg/util/proxy), the resolver
/// kube-apiserver uses by default for webhooks and the aggregator: a ClusterIP-style Service
/// resolves to `ClusterIP:svcPort`, and kube-proxy's NAT carries host-originated traffic to the
/// backing pod. The caller keeps `<name>.<namespace>.svc` as the URL host so TLS SNI and
/// certificate verification still use the Service DNS name.
use std::net::{IpAddr, SocketAddr};

use u7s_store::Store;

use crate::state::AppState;

pub(crate) const REASON_SERVICE_NOT_FOUND: &str = "ServiceNotFound";
pub(crate) const REASON_SERVICE_PORT_ERROR: &str = "ServicePortError";
pub(crate) const REASON_RESOLVE_FAILED: &str = "ServiceResolveFailed";

#[derive(Debug, PartialEq)]
pub(crate) struct ResolveError {
    pub reason: &'static str,
    pub message: String,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn err(reason: &'static str, message: String) -> ResolveError {
    ResolveError { reason, message }
}

#[derive(Debug, PartialEq)]
pub(crate) enum Dial {
    Ip(IpAddr),
    /// An ExternalName Service's target; the caller resolves it through DNS.
    Host(String),
}

/// Upstream `ResolveCluster` over an already-fetched Service object (`None` = not found).
pub(crate) fn resolve_cluster(
    name: &str,
    port: i32,
    service: Option<&serde_json::Value>,
) -> Result<Dial, ResolveError> {
    let svc = service.ok_or_else(|| {
        err(
            REASON_SERVICE_NOT_FOUND,
            format!("service \"{name}\" not found"),
        )
    })?;
    let spec = &svc["spec"];
    let svc_type = spec["type"].as_str().unwrap_or("ClusterIP");
    let cluster_ip = spec["clusterIP"].as_str().unwrap_or("");

    match svc_type {
        "ClusterIP" if cluster_ip == "None" => Err(err(
            REASON_RESOLVE_FAILED,
            "cannot route to service with ClusterIP \"None\"".to_owned(),
        )),
        "ClusterIP" | "LoadBalancer" | "NodePort" => {
            let found = spec["ports"].as_array().is_some_and(|ports| {
                ports
                    .iter()
                    .any(|p| p["port"].as_i64() == Some(port.into()))
            });
            if !found {
                return Err(err(
                    REASON_SERVICE_PORT_ERROR,
                    format!("no service port {port} found for service \"{name}\""),
                ));
            }
            cluster_ip.parse::<IpAddr>().map(Dial::Ip).map_err(|_| {
                err(
                    REASON_RESOLVE_FAILED,
                    format!("service \"{name}\" has no usable ClusterIP (got \"{cluster_ip}\")"),
                )
            })
        }
        "ExternalName" => Ok(Dial::Host(
            spec["externalName"].as_str().unwrap_or("").to_owned(),
        )),
        other => Err(err(
            REASON_RESOLVE_FAILED,
            format!("unsupported service type \"{other}\""),
        )),
    }
}

/// Fetch the Service from the apiserver's own store and resolve it to a socket address.
/// `port` is the Service port, which is also the port the caller puts in the request URL.
pub(crate) async fn resolve_service_addr<S: Store>(
    state: &AppState<S>,
    namespace: &str,
    name: &str,
    port: i32,
) -> Result<SocketAddr, ResolveError> {
    let key = crate::keys::object_key("services", namespace, name);
    let stored = state.store.get(&key).await.map_err(|e| {
        err(
            REASON_RESOLVE_FAILED,
            format!("reading service \"{name}\": {e}"),
        )
    })?;
    let svc: Option<serde_json::Value> = match stored {
        Some(s) => Some(serde_json::from_slice(&s.value).map_err(|e| {
            err(
                REASON_RESOLVE_FAILED,
                format!("decoding service \"{name}\": {e}"),
            )
        })?),
        None => None,
    };
    let port_u16 = u16::try_from(port).map_err(|_| {
        err(
            REASON_SERVICE_PORT_ERROR,
            format!("invalid service port {port}"),
        )
    })?;
    match resolve_cluster(name, port, svc.as_ref())? {
        Dial::Ip(ip) => Ok(SocketAddr::new(ip, port_u16)),
        Dial::Host(host) => tokio::net::lookup_host((host.as_str(), port_u16))
            .await
            .map_err(|e| {
                err(
                    REASON_RESOLVE_FAILED,
                    format!("resolving ExternalName \"{host}\" of service \"{name}\": {e}"),
                )
            })?
            .next()
            .ok_or_else(|| {
                err(
                    REASON_RESOLVE_FAILED,
                    format!("ExternalName \"{host}\" of service \"{name}\" has no addresses"),
                )
            }),
    }
}

/// Fixtures shared by the caller tests (admission, conversion, aggregation): a TLS backend whose
/// certificate is valid only for a `<svc>.<ns>.svc` name, plus a Service object pointing at it.
/// Nothing resolves that name, so a caller that dials by DNS instead of through the resolver
/// cannot reach the backend.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub(crate) struct TlsBackend {
        pub port: u16,
        pub ca_bundle_b64: String,
        pub hits: Arc<AtomicUsize>,
    }

    /// Answers every request with `200 application/json` + `body`.
    pub(crate) async fn tls_json_backend(dns_name: &str, body: serde_json::Value) -> TlsBackend {
        rustls_post_quantum::provider().install_default().ok();
        let cert = rcgen::generate_simple_self_signed(vec![dns_name.to_owned()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der.clone())],
                PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_task = Arc::clone(&hits);
        let body = body.to_string();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let hits = Arc::clone(&hits_task);
                let body = body.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut req = Vec::new();
                    let mut buf = [0u8; 8192];
                    let header_end = loop {
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        req.extend_from_slice(&buf[..n]);
                        if let Some(p) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                    };
                    let headers = String::from_utf8_lossy(&req[..header_end]).to_lowercase();
                    let content_len = headers
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    while req.len() < header_end + content_len {
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        req.extend_from_slice(&buf[..n]);
                    }
                    hits.fetch_add(1, Ordering::SeqCst);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        let b64_der = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert_der);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            b64_der
                .as_bytes()
                .chunks(64)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        );
        TlsBackend {
            port,
            ca_bundle_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                pem.as_bytes(),
            ),
            hits,
        }
    }

    /// Store a ClusterIP Service whose ClusterIP is loopback, so "dial the ClusterIP" reaches
    /// the local backend.
    pub(crate) async fn put_loopback_service<S: u7s_store::Store>(
        store: &S,
        namespace: &str,
        name: &str,
        port: u16,
    ) {
        let svc = serde_json::json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"namespace": namespace, "name": name},
            "spec": {"type": "ClusterIP", "clusterIP": "127.0.0.1", "ports": [{"port": port}]}
        });
        store
            .put(
                &crate::keys::object_key("services", namespace, name),
                bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
                None,
            )
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn svc(spec: serde_json::Value) -> serde_json::Value {
        json!({"metadata": {"namespace": "one", "name": "alfa"}, "spec": spec})
    }

    fn ports() -> serde_json::Value {
        json!([{"name": "https", "port": 443, "targetPort": 1443}, {"port": 1234}])
    }

    /// Without the ClusterIP the host dials `<svc>.<ns>.svc`, which only cluster DNS knows --
    /// webhooks and aggregated APIs then fail on any install whose host resolver can't see it.
    #[test]
    fn clusterip_service_resolves_to_clusterip() {
        let s = svc(json!({"type": "ClusterIP", "clusterIP": "10.96.0.7", "ports": ports()}));
        assert_eq!(
            resolve_cluster("alfa", 443, Some(&s)),
            Ok(Dial::Ip("10.96.0.7".parse().unwrap()))
        );
    }

    #[test]
    fn missing_type_defaults_to_clusterip() {
        let s = svc(json!({"clusterIP": "10.96.0.7", "ports": ports()}));
        assert_eq!(
            resolve_cluster("alfa", 1234, Some(&s)),
            Ok(Dial::Ip("10.96.0.7".parse().unwrap()))
        );
    }

    #[test]
    fn loadbalancer_and_nodeport_route_via_clusterip() {
        for t in ["LoadBalancer", "NodePort"] {
            let s = svc(json!({"type": t, "clusterIP": "10.96.0.8", "ports": ports()}));
            assert_eq!(
                resolve_cluster("alfa", 443, Some(&s)),
                Ok(Dial::Ip("10.96.0.8".parse().unwrap())),
                "{t}"
            );
        }
    }

    #[test]
    fn missing_service_is_service_not_found() {
        let e = resolve_cluster("alfa", 443, None).unwrap_err();
        assert_eq!(e.reason, REASON_SERVICE_NOT_FOUND);
        assert_eq!(e.message, "service \"alfa\" not found");
    }

    /// A port that the Service does not expose must fail here; dialing the ClusterIP on it would
    /// hang until the webhook timeout instead of reporting the misconfiguration.
    #[test]
    fn unknown_port_is_service_port_error() {
        let s = svc(json!({"type": "ClusterIP", "clusterIP": "10.96.0.7", "ports": ports()}));
        let e = resolve_cluster("alfa", 8443, Some(&s)).unwrap_err();
        assert_eq!(e.reason, REASON_SERVICE_PORT_ERROR);
        assert_eq!(e.message, "no service port 8443 found for service \"alfa\"");
    }

    #[test]
    fn headless_service_is_rejected() {
        let s = svc(json!({"type": "ClusterIP", "clusterIP": "None", "ports": ports()}));
        let e = resolve_cluster("alfa", 443, Some(&s)).unwrap_err();
        assert_eq!(e.message, "cannot route to service with ClusterIP \"None\"");
    }

    #[test]
    fn externalname_resolves_to_its_target_host() {
        let s = svc(json!({"type": "ExternalName", "externalName": "foo.bar.com"}));
        assert_eq!(
            resolve_cluster("alfa", 443, Some(&s)),
            Ok(Dial::Host("foo.bar.com".to_owned()))
        );
    }

    #[test]
    fn unsupported_type_is_rejected() {
        let s = svc(json!({"type": "unsupported"}));
        let e = resolve_cluster("alfa", 443, Some(&s)).unwrap_err();
        assert_eq!(e.message, "unsupported service type \"unsupported\"");
    }

    #[test]
    fn unallocated_clusterip_is_rejected_not_dialed() {
        let s = svc(json!({"type": "ClusterIP", "clusterIP": "", "ports": ports()}));
        assert!(resolve_cluster("alfa", 443, Some(&s)).is_err());
    }
}

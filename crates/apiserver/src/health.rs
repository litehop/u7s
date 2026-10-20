//! `/healthz`, `/livez` and `/readyz`: named checks with upstream's `?verbose`, `?exclude=` and
//! `/<endpoint>/<check>` semantics (apiserver `pkg/server/healthz`).
//!
//! The poststarthook names exist because upstream clients (and the conformance spec "health
//! handlers should contain necessary checks") require them. u7s has no separate hook
//! goroutines: every one of them is satisfied by the single real signal "boot-time bootstrap
//! manifest apply finished" (`AppState::boot_ready`), so they all share that state;
//! `storage-readiness` follows the store probe like `etcd`.

use std::sync::atomic::Ordering;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use u7s_store::Store as _;

use crate::state::AppState;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Endpoint {
    Healthz,
    Livez,
    Readyz,
}

impl Endpoint {
    fn name(self) -> &'static str {
        match self {
            Endpoint::Healthz => "healthz",
            Endpoint::Livez => "livez",
            Endpoint::Readyz => "readyz",
        }
    }
}

const BOOT_HOOKS: &[&str] = &[
    "poststarthook/start-apiserver-admission-initializer",
    "poststarthook/generic-apiserver-start-informers",
    "poststarthook/start-apiextensions-informers",
    "poststarthook/start-apiextensions-controllers",
    "poststarthook/crd-informer-synced",
    "poststarthook/bootstrap-controller",
    "poststarthook/start-system-namespaces-controller",
    "poststarthook/start-service-ip-repair-controllers",
    "poststarthook/scheduling/bootstrap-system-priority-classes",
    "poststarthook/start-cluster-authentication-info-controller",
    "poststarthook/start-kube-aggregator-informers",
    "poststarthook/apiservice-registration-controller",
    "poststarthook/apiservice-status-local-available-controller",
    "poststarthook/apiservice-status-remote-available-controller",
    "poststarthook/kube-apiserver-autoregistration",
    "autoregister-completion",
    "poststarthook/apiservice-openapi-controller",
];

pub struct CheckResult {
    pub name: &'static str,
    pub ok: bool,
}

async fn run_checks(endpoint: Endpoint, state: &AppState) -> Vec<CheckResult> {
    let booted = state.boot_ready.load(Ordering::Acquire);
    let store_ok = state
        .store
        .get("/__health/probe".to_string())
        .await
        .map_err(|e| tracing::warn!("health check etcd failed: {e}"))
        .is_ok();
    let mut out = vec![
        CheckResult {
            name: "ping",
            ok: true,
        },
        CheckResult {
            name: "log",
            ok: true,
        },
        CheckResult {
            name: "etcd",
            ok: store_ok,
        },
    ];
    if endpoint == Endpoint::Readyz {
        out.push(CheckResult {
            name: "informer-sync",
            ok: booted,
        });
    }
    out.extend(
        BOOT_HOOKS
            .iter()
            .map(|&name| CheckResult { name, ok: booted }),
    );
    out.push(CheckResult {
        name: "poststarthook/storage-readiness",
        ok: store_ok,
    });
    out
}

/// Renders the root endpoint exactly like upstream's `handleRootHealth`. `query` is the decoded
/// query string as ordered key/value pairs.
pub fn render_root(
    endpoint: Endpoint,
    checks: &[CheckResult],
    query: &[(String, String)],
) -> (StatusCode, String) {
    let excluded: Vec<&str> = query
        .iter()
        .filter(|(k, _)| k == "exclude")
        .map(|(_, v)| v.as_str())
        .collect();
    let mut unknown: Vec<&str> = excluded.clone();
    let mut lines = String::new();
    let mut failed = false;
    for c in checks {
        if excluded.contains(&c.name) {
            unknown.retain(|n| *n != c.name);
            lines.push_str(&format!("[+]{} excluded: ok\n", c.name));
        } else if c.ok {
            lines.push_str(&format!("[+]{} ok\n", c.name));
        } else {
            lines.push_str(&format!("[-]{} failed: reason withheld\n", c.name));
            failed = true;
        }
    }
    if !unknown.is_empty() {
        unknown.sort_unstable();
        unknown.dedup();
        let quoted: Vec<String> = unknown.iter().map(|n| format!("{n:?}")).collect();
        lines.push_str(&format!(
            "warn: some health checks cannot be excluded: no matches for {}\n",
            quoted.join(",")
        ));
    }
    let name = endpoint.name();
    if failed {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("{lines}{name} check failed\n"),
        );
    }
    if !query.iter().any(|(k, _)| k == "verbose") {
        return (StatusCode::OK, "ok".to_string());
    }
    (StatusCode::OK, format!("{lines}{name} check passed\n"))
}

fn text_response(status: StatusCode, body: String) -> Response {
    let mut resp = (status, body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

async fn root(endpoint: Endpoint, state: AppState, query: Vec<(String, String)>) -> Response {
    let checks = run_checks(endpoint, &state).await;
    let (status, body) = render_root(endpoint, &checks, &query);
    text_response(status, body)
}

async fn sub(endpoint: Endpoint, state: AppState, check: String) -> Response {
    let checks = run_checks(endpoint, &state).await;
    match checks.iter().find(|c| c.name == check) {
        None => (StatusCode::NOT_FOUND, "404 page not found\n").into_response(),
        Some(c) if c.ok => text_response(StatusCode::OK, "ok".to_string()),
        Some(_) => text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal server error: check failed\n".to_string(),
        ),
    }
}

pub async fn healthz(
    State(state): State<AppState>,
    Query(q): Query<Vec<(String, String)>>,
) -> Response {
    root(Endpoint::Healthz, state, q).await
}
pub async fn livez(
    State(state): State<AppState>,
    Query(q): Query<Vec<(String, String)>>,
) -> Response {
    root(Endpoint::Livez, state, q).await
}
pub async fn readyz(
    State(state): State<AppState>,
    Query(q): Query<Vec<(String, String)>>,
) -> Response {
    root(Endpoint::Readyz, state, q).await
}
pub async fn healthz_check(State(state): State<AppState>, Path(check): Path<String>) -> Response {
    sub(Endpoint::Healthz, state, check).await
}
pub async fn livez_check(State(state): State<AppState>, Path(check): Path<String>) -> Response {
    sub(Endpoint::Livez, state, check).await
}
pub async fn readyz_check(State(state): State<AppState>, Path(check): Path<String>) -> Response {
    sub(Endpoint::Readyz, state, check).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(ok: bool) -> Vec<CheckResult> {
        [&["ping", "log", "etcd"][..], BOOT_HOOKS]
            .concat()
            .into_iter()
            .map(|name| CheckResult { name, ok })
            .collect()
    }
    fn q(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn verbose_lists_every_check_so_clients_can_see_what_is_gating_readiness() {
        let (s, body) = render_root(Endpoint::Healthz, &all(true), &q(&[("verbose", "1")]));
        assert_eq!(s, StatusCode::OK);
        assert!(
            body.starts_with("[+]ping ok\n[+]log ok\n[+]etcd ok\n"),
            "{body}"
        );
        assert!(body.contains("[+]poststarthook/bootstrap-controller ok\n"));
        assert!(body.ends_with("healthz check passed\n"));
    }

    #[test]
    fn bare_request_stays_ok_so_existing_probes_keep_working() {
        let (s, body) = render_root(Endpoint::Livez, &all(true), &[]);
        assert_eq!((s, body.as_str()), (StatusCode::OK, "ok"));
    }

    #[test]
    fn failing_check_is_always_verbose_and_withholds_the_reason() {
        let mut checks = all(true);
        checks[2].ok = false;
        let (s, body) = render_root(Endpoint::Readyz, &checks, &[]);
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("[-]etcd failed: reason withheld\n"), "{body}");
        assert!(body.ends_with("readyz check failed\n"));
    }

    #[test]
    fn exclude_lets_operators_ignore_a_failing_check_and_warns_on_typos() {
        let mut checks = all(true);
        checks[2].ok = false;
        let (s, body) = render_root(
            Endpoint::Healthz,
            &checks,
            &q(&[("verbose", ""), ("exclude", "etcd"), ("exclude", "nope")]),
        );
        assert_eq!(s, StatusCode::OK);
        assert!(body.contains("[+]etcd excluded: ok\n"), "{body}");
        assert!(
            body.contains("warn: some health checks cannot be excluded: no matches for \"nope\"\n")
        );
    }
}

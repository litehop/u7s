use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use prometheus::{Encoder, TextEncoder};
use u7s_store::Store;

use crate::state::AppState;

/// Serve `GET /metrics` in the standard Prometheus text-exposition format, the same wire
/// format real kube-apiserver's `/metrics` uses — any Prometheus-ecosystem scraper reads this
/// identically to upstream. RBAC-gated like every other route (see `auth::is_exempt`), not
/// auth-exempt like `/healthz`.
pub async fn metrics<S: Store>(State(state): State<AppState<S>>) -> Response {
    crate::metrics::WATCH_BROADCAST_RECEIVERS.set(state.store.watch_receiver_count() as i64);
    // u7s_watch_closed_total has a small, fixed `reason` domain — pre-populate it so the
    // metric is visible on the very first scrape rather than only after the first watch
    // happens to close for a given reason (see prime_watch_closed_total's doc for why).
    u7s_store::metrics::prime_watch_closed_total();

    let metric_families = prometheus::gather();
    let encoder = TextEncoder::new();
    let mut buf = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buf) {
        tracing::error!("metrics: failed to encode Prometheus text exposition: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to encode metrics",
        )
            .into_response();
    }
    (
        [(header::CONTENT_TYPE, encoder.format_type().to_string())],
        buf,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::extract::State;
    use std::sync::Arc;
    use u7s_store::SqliteStore;

    /// `/metrics` must serve the standard Prometheus text-exposition format and include all
    /// ten Phase-1 metric names — this is the operator-confirmed metric set for this bead; if
    /// any of them silently stop being registered (e.g. a typo'd metric name, a dropped
    /// registration), a Prometheus scraper's dashboards go blank for exactly that series
    /// without any error, which is why this is asserted as a single end-to-end request rather
    /// than by inspecting the metric statics directly.
    #[tokio::test]
    async fn metrics_endpoint_exposes_all_ten_phase_one_metrics_in_text_format() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // A prometheus MetricVec (IntCounterVec/IntGaugeVec) only appears in gathered output
        // once at least one label combination has been recorded. u7s_watch_closed_total is
        // self-priming (the handler calls prime_watch_closed_total on every scrape); the
        // remaining open-cardinality Vec metrics are not, so touch one combination of each
        // here — in a real, long-running apiserver this is always true by the time an operator
        // scrapes /metrics (some request or watch has happened), but this test's process may
        // run with none of the other tests that exercise these label combinations having
        // executed yet. This keeps the test's pass/fail independent of execution order.
        crate::metrics::LONGRUNNING_REQUESTS
            .with_label_values(&[
                "watch",
                "",
                "v1",
                "",
                "",
                "cluster",
                crate::metrics::COMPONENT,
            ])
            .inc();
        crate::metrics::LONGRUNNING_REQUESTS
            .with_label_values(&[
                "watch",
                "",
                "v1",
                "",
                "",
                "cluster",
                crate::metrics::COMPONENT,
            ])
            .dec();
        crate::metrics::WATCH_EVENTS_TOTAL
            .with_label_values(&["", "v1", "metrics-endpoint-test-touch"])
            .inc();
        crate::metrics::REQUEST_TOTAL
            .with_label_values(&[
                "watch",
                "",
                "v1",
                "metrics-endpoint-test-touch",
                "cluster",
                "200",
            ])
            .inc();
        u7s_store::metrics::WATCH_BROADCAST_LAGGED_TOTAL
            .with_label_values(&["/registry/metrics-endpoint-test-touch/"])
            .inc_by(0);
        // The two new bare gauges have no handler-side `.set()` call (unlike
        // u7s_watch_broadcast_receivers, set every scrape from real store state) — they are
        // only ever set from push_event_locked's write path (see sqlite.rs), which this test
        // never exercises. Touch them directly so their `LazyLock` registers, same reasoning
        // as the Vec touches above.
        u7s_store::metrics::WATCH_RING_OCCUPANCY.set(0);
        u7s_store::metrics::DELETION_LOG_LEN.set(0);
        u7s_store::metrics::WATCH_LAG_RECOVERY_DURATION_SECONDS
            .with_label_values(&["/registry/metrics-endpoint-test-touch/"])
            .observe(0.0);
        crate::metrics::WATCH_OPEN_DURATION_SECONDS
            .with_label_values(&["", "metrics-endpoint-test-touch"])
            .observe(0.0);

        let resp = metrics(State(state)).await;
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "/metrics must return 200 when encoding succeeds"
        );

        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            content_type.starts_with("text/plain"),
            "/metrics must advertise the Prometheus text-exposition content type, not JSON or \
             protobuf, so any Prometheus-ecosystem scraper can parse it without special-casing \
             u7s; got {content_type:?}"
        );

        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body must be readable");
        let text = std::str::from_utf8(&body).expect("body must be valid UTF-8");

        assert!(
            text.starts_with("# HELP") || text.starts_with("# TYPE"),
            "Prometheus text exposition must start with a HELP or TYPE comment line; got: {}",
            &text[..text.len().min(80)]
        );

        for metric_name in [
            "apiserver_longrunning_requests",
            "apiserver_watch_events_total",
            "apiserver_request_total",
            "u7s_watch_broadcast_lagged_total",
            "u7s_watch_broadcast_receivers",
            "u7s_watch_closed_total",
            "u7s_watch_ring_occupancy",
            "u7s_deletion_log_len",
            "u7s_watch_lag_recovery_duration_seconds",
            "apiserver_watch_open_duration_seconds",
        ] {
            assert!(
                text.contains(&format!("# TYPE {metric_name} ")),
                "/metrics output must declare {metric_name} via a '# TYPE' line — its absence \
                 means this metric was never registered with the default Prometheus registry \
                 and a scraper would never see it, defeating the whole point of this endpoint. \
                 Full output:\n{text}"
            );
        }
    }
}

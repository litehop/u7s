//! Request-scoped sink for API warnings (`Warning` response headers) and admission audit
//! annotations. Admission plugins push into it from anywhere in a handler without threading a
//! recorder through every signature; [`collect`] wraps each request and renders the headers on
//! the way out. Outside a request scope (unit tests calling handlers directly) pushes are
//! dropped.
//!
//! Header rendering follows upstream's warning recorder: duplicates are dropped, and once the
//! running total passes 4096 runes every warning is replayed truncated to 256 runes.

use std::cell::RefCell;
use std::collections::HashSet;

use axum::{
    extract::Request,
    http::{header::WARNING, HeaderValue},
    middleware::Next,
    response::Response,
};

const TRUNCATE_AT_TOTAL_RUNES: usize = 4 * 1024;
const TRUNCATE_ITEM_RUNES: usize = 256;

#[derive(Debug, Default, Clone)]
pub struct Sink {
    pub warnings: Vec<String>,
    /// Annotations upstream would attach to the audit event for this request, keyed without
    /// the plugin's own prefix (the PodSecurity plugin's keys are `pod-security.kubernetes.io/<key>`).
    pub audit_annotations: Vec<(String, String)>,
}

tokio::task_local! {
    static SINK: RefCell<Sink>;
}

pub fn warn(text: impl Into<String>) {
    let text = text.into();
    let _ = SINK.try_with(|s| s.borrow_mut().warnings.push(text));
}

pub fn audit_annotation(key: impl Into<String>, value: impl Into<String>) {
    let (key, value) = (key.into(), value.into());
    let _ = SINK.try_with(|s| s.borrow_mut().audit_annotations.push((key, value)));
}

/// Run `fut` with a fresh sink and return what it collected.
pub async fn scope<F: std::future::Future>(fut: F) -> (F::Output, Sink) {
    SINK.scope(RefCell::new(Sink::default()), async {
        let out = fut.await;
        let sink = SINK.with(|s| s.take());
        (out, sink)
    })
    .await
}

/// RFC 7234 warning-value: `299 - "<text>"`, text quote-escaped. Control characters and
/// invalid UTF-8 cannot be represented and the warning is dropped, as upstream does.
fn header_value(text: &str) -> Option<String> {
    if text.chars().any(char::is_control) {
        return None;
    }
    let mut out = String::from("299 - \"");
    for c in text.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Some(out)
}

fn truncate_runes(text: &str, max: usize) -> &str {
    match text.char_indices().nth(max) {
        Some((i, _)) => &text[..i],
        None => text,
    }
}

/// Headers for `warnings`, in order, applying upstream's dedupe and truncation rules.
pub fn render_headers(warnings: &[String]) -> Vec<String> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut ordered: Vec<&str> = Vec::new();
    let mut headers: Vec<String> = Vec::new();
    let mut written = 0usize;
    let mut truncating = false;

    for text in warnings
        .iter()
        .map(String::as_str)
        .filter(|t| !t.is_empty())
    {
        if written >= TRUNCATE_AT_TOTAL_RUNES && truncating {
            break;
        }
        if !seen.insert(text) {
            continue;
        }
        ordered.push(text);

        let mut rune_len = text.chars().count();
        let mut shown = text;
        if truncating && rune_len > TRUNCATE_ITEM_RUNES {
            shown = truncate_runes(text, TRUNCATE_ITEM_RUNES);
            rune_len = TRUNCATE_ITEM_RUNES;
        }
        let Some(header) = header_value(shown) else {
            continue;
        };
        if written + rune_len <= TRUNCATE_AT_TOTAL_RUNES || truncating {
            written += rune_len;
            headers.push(header);
            continue;
        }

        truncating = true;
        written = 0;
        headers.clear();
        for prev in &ordered {
            let shown = truncate_runes(prev, TRUNCATE_ITEM_RUNES);
            if let Some(h) = header_value(shown) {
                written += shown.chars().count();
                headers.push(h);
            }
        }
    }
    headers
}

/// Middleware: give the request a sink and attach its warnings as `Warning` headers.
pub async fn collect(req: Request, next: Next) -> Response {
    let (mut resp, sink) = scope(next.run(req)).await;
    for h in render_headers(&sink.warnings) {
        if let Ok(v) = HeaderValue::from_bytes(h.as_bytes()) {
            resp.headers_mut().append(WARNING, v);
        }
    }
    if !sink.audit_annotations.is_empty() {
        tracing::debug!(annotations = ?sink.audit_annotations, "admission audit annotations");
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_warnings_are_sent_once() {
        let w = vec!["a".to_owned(), "b".to_owned(), "a".to_owned()];
        assert_eq!(
            render_headers(&w),
            vec!["299 - \"a\"".to_owned(), "299 - \"b\"".to_owned()],
            "kubectl prints every Warning header; a controller re-evaluating the same template must not spam the user"
        );
    }

    #[test]
    fn quotes_and_backslashes_are_escaped_so_the_header_stays_parseable() {
        let w = vec![r#"say "hi" \o/"#.to_owned()];
        assert_eq!(
            render_headers(&w),
            vec![r#"299 - "say \"hi\" \\o/""#.to_owned()]
        );
    }

    #[test]
    fn warnings_with_control_characters_are_dropped() {
        let w = vec!["line1\nline2".to_owned(), "ok".to_owned()];
        assert_eq!(render_headers(&w), vec!["299 - \"ok\"".to_owned()]);
    }

    #[test]
    fn oversized_total_truncates_each_warning_to_256_runes() {
        let long = |c: char| c.to_string().repeat(1000);
        let w: Vec<String> = ['a', 'b', 'c', 'd', 'e'].iter().map(|c| long(*c)).collect();
        let headers = render_headers(&w);
        assert!(
            headers.len() >= 2,
            "warnings still delivered after truncation kicks in"
        );
        for h in &headers[..headers.len().min(4)] {
            assert_eq!(
                h.len(),
                "299 - \"\"".len() + 256,
                "a header past the 4KiB budget must be cut to 256 runes so one noisy webhook cannot bloat every response"
            );
        }
    }

    #[tokio::test]
    async fn sink_collects_inside_scope_and_ignores_pushes_outside() {
        warn("dropped");
        let ((), sink) = scope(async {
            warn("kept");
            audit_annotation("enforce-policy", "baseline:latest");
        })
        .await;
        assert_eq!(sink.warnings, vec!["kept".to_owned()]);
        assert_eq!(
            sink.audit_annotations,
            vec![("enforce-policy".to_owned(), "baseline:latest".to_owned())]
        );
    }
}

//! Browser-facing request guard for `/api` and `/ui`.
//!
//! - DNS rebinding: a request whose `Host` is not in `allowed_hosts` is
//!   refused. (A request with no `Host` header cannot come from a browser
//!   and is let through.)
//! - CSRF on the JSON API: a state-changing `/api` request must not be
//!   cross-site (`Sec-Fetch-Site`, `Origin`), and a body must be sent as
//!   `application/json`, which a cross-site page cannot do without a CORS
//!   preflight this server never grants. The `/ui` forms have their own
//!   double-submit token check (`ui::csrf`).

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::AppState;

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// `host[:port]` or `[v6]:port` without the port, lower-cased.
fn host_only(raw: &str) -> String {
    let raw = raw.trim().to_ascii_lowercase();
    if let Some(rest) = raw.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("").to_string();
    }
    match raw.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') => h.to_string(),
        _ => raw,
    }
}

fn refuse(status: StatusCode, msg: &str) -> Response {
    let body = serde_json::json!({ "ok": false, "error": "request_refused", "message": msg });
    (status, axum::Json(body)).into_response()
}

pub fn host_allowed(allowed: &[String], h: &HeaderMap) -> bool {
    let Some(host) = header_str(h, header::HOST.as_str()) else { return true };
    let host = host_only(host);
    allowed.iter().any(|a| host_only(a) == host)
}

fn same_origin(h: &HeaderMap) -> bool {
    if header_str(h, "sec-fetch-site") == Some("cross-site") {
        return false;
    }
    let Some(origin) = header_str(h, header::ORIGIN.as_str()) else { return true };
    let Some(host) = header_str(h, header::HOST.as_str()) else { return false };
    origin == format!("http://{host}") || origin == format!("https://{host}")
}

fn has_body(h: &HeaderMap) -> bool {
    match header_str(h, header::CONTENT_LENGTH.as_str()) {
        Some(n) => n.trim() != "0",
        None => h.contains_key(header::TRANSFER_ENCODING) || h.contains_key(header::CONTENT_TYPE),
    }
}

fn is_json(h: &HeaderMap) -> bool {
    header_str(h, header::CONTENT_TYPE.as_str()).is_some_and(|c| {
        let mime = c.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        mime == "application/json" || (mime.starts_with("application/") && mime.ends_with("+json"))
    })
}

pub async fn protect(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let api = path == "/api" || path.starts_with("/api/");
    let ui = path == "/ui" || path.starts_with("/ui/");
    if !(api || ui) {
        return next.run(req).await;
    }
    let h = req.headers();
    if !host_allowed(&state.hub.cfg().allowed_hosts, h) {
        return refuse(StatusCode::FORBIDDEN, "host not allowed (add it to allowed_hosts)");
    }
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if api && !safe {
        if !same_origin(h) {
            return refuse(StatusCode::FORBIDDEN, "cross-site request");
        }
        if has_body(h) && !is_json(h) {
            return refuse(StatusCode::UNSUPPORTED_MEDIA_TYPE, "send the body as application/json");
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_matching_ignores_port_and_case() {
        let allowed = vec!["localhost".to_string(), "127.0.0.1".into(), "::1".into()];
        let mut h = HeaderMap::new();
        for (host, ok) in [
            ("localhost:8765", true),
            ("LOCALHOST", true),
            ("127.0.0.1:1", true),
            ("[::1]:8765", true),
            ("evil.example.com", false),
            ("localhost.evil.example.com:8765", false),
        ] {
            h.insert(header::HOST, host.parse().unwrap());
            assert_eq!(host_allowed(&allowed, &h), ok, "{host}");
        }
    }
}

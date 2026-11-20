//! Browser-facing request guard for `/api` and `/ui`.
//!
//! - DNS rebinding: a request naming a host that is neither in
//!   `allowed_hosts` nor the host of `public_url` is refused, and each
//!   refused host is logged once at warn level. The names checked are the
//!   `Host` header and the request target's authority: HTTP/2 carries the
//!   host in the `:authority` pseudo-header (`uri().authority()`) and may
//!   send no `Host` at all, and an HTTP/1.1 absolute-form target carries one
//!   too. Every name present must be allowed. (A request naming no host
//!   cannot come from a browser and is let through.)
//! - CSRF on the JSON API: a state-changing `/api` request must not be
//!   cross-site (`Sec-Fetch-Site`, `Origin`), and a body must be sent as
//!   `application/json`, which a cross-site page cannot do without a CORS
//!   preflight this server never grants. The `/ui` forms have their own
//!   double-submit token check (`ui::csrf`).

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use ua_core::Config;

use crate::AppState;

/// Refused hosts already logged; bounded so a flood of names cannot grow it.
static LOGGED_HOSTS: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Mutex::default);
const LOGGED_HOSTS_MAX: usize = 256;

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

/// Every host the request names: its `Host` header and its target's
/// authority (HTTP/2 `:authority`, or an absolute-form HTTP/1.1 target).
fn named_hosts<'a>(h: &'a HeaderMap, uri: &'a Uri) -> Vec<&'a str> {
    let mut named = Vec::with_capacity(2);
    if let Some(host) = header_str(h, header::HOST.as_str()) {
        named.push(host);
    }
    if let Some(authority) = uri.authority() {
        named.push(authority.host());
    }
    named
}

/// Whether every host the request names is allowed. A request naming none
/// (not a browser) passes.
pub fn host_allowed(allowed: &[String], h: &HeaderMap, uri: &Uri) -> bool {
    named_hosts(h, uri).into_iter().all(|host| {
        let host = host_only(host);
        allowed.iter().any(|a| host_only(a) == host)
    })
}

/// `host[:port]` the request was sent to, for comparing with `Origin`: the
/// `Host` header, else the HTTP/2 `:authority`.
pub(crate) fn request_authority<'a>(h: &'a HeaderMap, uri: &'a Uri) -> Option<&'a str> {
    header_str(h, header::HOST.as_str()).or_else(|| uri.authority().map(|a| a.as_str()))
}

/// `allowed_hosts` plus the host of `public_url`, when it is set.
pub fn effective_allowed_hosts(cfg: &Config) -> Vec<String> {
    let mut hosts = cfg.allowed_hosts.clone();
    if let Some(h) = cfg
        .public_url
        .as_deref()
        .and_then(|u| url::Url::parse(u).ok())
        .and_then(|u| u.host_str().map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string()))
    {
        hosts.push(h);
    }
    hosts
}

/// True the first time `host` is seen (so it is logged once).
fn first_refusal(host: &str) -> bool {
    let Ok(mut seen) = LOGGED_HOSTS.lock() else { return false };
    if seen.contains(host) || seen.len() >= LOGGED_HOSTS_MAX {
        return false;
    }
    seen.insert(host.to_string())
}

fn same_origin(h: &HeaderMap, uri: &Uri) -> bool {
    if header_str(h, "sec-fetch-site") == Some("cross-site") {
        return false;
    }
    let Some(origin) = header_str(h, header::ORIGIN.as_str()) else { return true };
    let Some(host) = request_authority(h, uri) else { return false };
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
    if !host_allowed(&effective_allowed_hosts(state.hub.cfg()), h, req.uri()) {
        let host: String =
            named_hosts(h, req.uri()).join(" ").chars().filter(|c| !c.is_control()).take(255).collect();
        if first_refusal(&host) {
            tracing::warn!(host = %host, "refused a request for a host outside allowed_hosts and public_url; \
                add it to allowed_hosts if this hub is reached by that name (logged once per host)");
        }
        return refuse(StatusCode::FORBIDDEN, "host not allowed (add it to allowed_hosts)");
    }
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if api && !safe {
        if !same_origin(h, req.uri()) {
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
        let uri = Uri::from_static("/api/whoami");
        for (host, ok) in [
            ("localhost:8765", true),
            ("LOCALHOST", true),
            ("127.0.0.1:1", true),
            ("[::1]:8765", true),
            ("evil.example.com", false),
            ("localhost.evil.example.com:8765", false),
        ] {
            h.insert(header::HOST, host.parse().unwrap());
            assert_eq!(host_allowed(&allowed, &h, &uri), ok, "{host}");
        }
    }

    #[test]
    fn public_url_host_is_allowed_automatically() {
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.public_url = Some("https://hub.example.com".into());
        let allowed = effective_allowed_hosts(&cfg);
        let mut h = HeaderMap::new();
        let uri = Uri::from_static("/api/whoami");
        h.insert(header::HOST, "hub.example.com".parse().unwrap());
        assert!(host_allowed(&allowed, &h, &uri));
        h.insert(header::HOST, "other.example.com".parse().unwrap());
        assert!(!host_allowed(&allowed, &h, &uri));
        cfg.public_url = Some("http://[::1]:8765".into());
        assert!(effective_allowed_hosts(&cfg).contains(&"::1".to_string()));
    }

    /// HTTP/2 names the host in `:authority` (the URI) and may send no
    /// `Host`: the same allowlist applies. When both are present, both must
    /// be allowed.
    #[test]
    fn the_http2_authority_is_checked_like_host() {
        let allowed = vec!["localhost".to_string(), "::1".into(), "hub.example.com".into()];
        let none = HeaderMap::new();
        for (uri, ok) in [
            ("https://hub.example.com/api/whoami", true),
            ("https://hub.example.com:8443/ui", true),
            ("http://[::1]:8765/ui", true),
            ("https://rebound.example.net/api/whoami", false),
            ("https://user@rebound.example.net/api/whoami", false),
            ("/api/whoami", true),
        ] {
            assert_eq!(host_allowed(&allowed, &none, &uri.parse().unwrap()), ok, "{uri}");
        }
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "hub.example.com".parse().unwrap());
        let rebound: Uri = "https://rebound.example.net/api/whoami".parse().unwrap();
        assert!(!host_allowed(&allowed, &h, &rebound), "an allowed Host does not excuse the authority");
        h.insert(header::HOST, "rebound.example.net".parse().unwrap());
        let good: Uri = "https://hub.example.com/api/whoami".parse().unwrap();
        assert!(!host_allowed(&allowed, &h, &good), "an allowed authority does not excuse the Host");
        // Origin comparison uses the authority when there is no Host header.
        let mut o = HeaderMap::new();
        o.insert(header::ORIGIN, "https://hub.example.com".parse().unwrap());
        assert!(same_origin(&o, &good));
        o.insert(header::ORIGIN, "https://rebound.example.net".parse().unwrap());
        assert!(!same_origin(&o, &good));
    }

    #[test]
    fn each_refused_host_is_logged_once() {
        assert!(first_refusal("once.example.com"));
        assert!(!first_refusal("once.example.com"));
        assert!(first_refusal("twice.example.com"));
    }
}

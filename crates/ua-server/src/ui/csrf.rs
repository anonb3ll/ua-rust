//! CSRF protection for state-changing UI requests.
//!
//! Double-submit token: a random per-browser token lives in the `ua_csrf`
//! cookie (`SameSite=Strict`, `HttpOnly`, path `/ui`). Pages render the same
//! token into `hx-headers` on `<body>`, so every htmx request sends it as the
//! `X-CSRF-Token` header; plain forms carry it in a hidden `_csrf` field for
//! clients without JavaScript. A non-safe request is refused unless the
//! presented token equals the cookie (constant-time compare). A cross-site
//! `Sec-Fetch-Site` or an `Origin` that does not match the host is refused
//! before the token is checked.
//!
//! The same middleware sets the UI's security headers (CSP without inline
//! script or style, no framing, no MIME sniffing).

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rand::Rng;
use subtle::ConstantTimeEq;

pub const COOKIE: &str = "ua_csrf";
pub const HEADER: &str = "x-csrf-token";
pub const FIELD: &str = "_csrf";

/// Largest form body buffered to look for the `_csrf` field.
const FORM_LIMIT: usize = 1024 * 1024;

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'";

/// The request's CSRF token, inserted into request extensions.
#[derive(Debug, Clone)]
pub struct CsrfToken(pub String);

fn valid_token(t: &str) -> bool {
    t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

fn new_token() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// The `ua_csrf` cookie value, when it is well formed.
pub fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| valid_token(v))
}

fn refuse(msg: &str) -> Response {
    let body = format!(
        "<!doctype html><title>Request refused</title><p>Request refused: {msg}. Reload the page and try again.</p>"
    );
    let mut resp = (StatusCode::FORBIDDEN, body).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    resp
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// Refuse cross-site requests by `Sec-Fetch-Site` and `Origin`.
fn check_origin(h: &HeaderMap) -> Result<(), Response> {
    if header_str(h, "sec-fetch-site") == Some("cross-site") {
        return Err(refuse("cross-site request"));
    }
    let Some(origin) = header_str(h, header::ORIGIN.as_str()) else { return Ok(()) };
    let host = header_str(h, "x-forwarded-host").or_else(|| header_str(h, header::HOST.as_str()));
    let ok = host.is_some_and(|host| origin == format!("http://{host}") || origin == format!("https://{host}"));
    if ok { Ok(()) } else { Err(refuse("origin does not match this host")) }
}

fn is_form(h: &HeaderMap) -> bool {
    header_str(h, header::CONTENT_TYPE.as_str())
        .is_some_and(|c| c.to_ascii_lowercase().starts_with("application/x-www-form-urlencoded"))
}

fn is_https(req: &Request) -> bool {
    req.uri().scheme_str() == Some("https") || header_str(req.headers(), "x-forwarded-proto") == Some("https")
}

/// The middleware. Layer it on the `/ui` router only.
pub async fn protect(req: Request, next: Next) -> Response {
    let existing = cookie_token(req.headers());
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let secure = is_https(&req);
    let mut req = req;
    if !safe {
        if let Err(r) = check_origin(req.headers()) {
            return r;
        }
        let Some(expected) = existing.clone() else { return refuse("missing CSRF cookie") };
        let mut presented = header_str(req.headers(), HEADER).map(str::to_string);
        if presented.is_none() && is_form(req.headers()) {
            let (parts, body) = req.into_parts();
            let bytes = match axum::body::to_bytes(body, FORM_LIMIT).await {
                Ok(b) => b,
                Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "form too large").into_response(),
            };
            presented = serde_urlencoded::from_bytes::<Vec<(String, String)>>(&bytes)
                .ok()
                .and_then(|pairs| pairs.into_iter().find(|(k, _)| k == FIELD).map(|(_, v)| v));
            req = Request::from_parts(parts, Body::from(bytes));
        }
        let matches =
            presented.is_some_and(|p| p.len() == expected.len() && bool::from(p.as_bytes().ct_eq(expected.as_bytes())));
        if !matches {
            return refuse("missing or invalid CSRF token");
        }
    }
    let (token, fresh) = match existing {
        Some(t) => (t, false),
        None => (new_token(), true),
    };
    req.extensions_mut().insert(CsrfToken(token.clone()));
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    if fresh {
        let cookie = format!(
            "{COOKIE}={token}; Path=/ui; SameSite=Strict; HttpOnly{}",
            if secure { "; Secure" } else { "" }
        );
        if let Ok(v) = HeaderValue::from_str(&cookie) {
            h.append(header::SET_COOKIE, v);
        }
    }
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_parsing_rejects_malformed_tokens() {
        let good = "a".repeat(64);
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_str(&format!("x=1; {COOKIE}={good}")).unwrap());
        assert_eq!(cookie_token(&h), Some(good));
        h.insert(header::COOKIE, HeaderValue::from_static("ua_csrf=short"));
        assert_eq!(cookie_token(&h), None);
    }

    #[test]
    fn origin_must_match_host() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("hub.example.com"));
        h.insert(header::ORIGIN, HeaderValue::from_static("https://hub.example.com"));
        assert!(check_origin(&h).is_ok());
        h.insert(header::ORIGIN, HeaderValue::from_static("https://evil.example.net"));
        assert!(check_origin(&h).is_err());
        h.remove(header::ORIGIN);
        h.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(check_origin(&h).is_err());
    }
}

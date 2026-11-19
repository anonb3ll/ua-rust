//! OAuth 2.1 authorization server for remote MCP clients.
//!
//! Hand-written on axum, following the MCP authorization spec (revision
//! 2026-07-28):
//!
//! - RFC 9728 protected resource metadata at
//!   `/.well-known/oauth-protected-resource[/mcp]`, and a `WWW-Authenticate`
//!   challenge carrying `resource_metadata` on every 401 (see `auth.rs`).
//! - RFC 8414 authorization server metadata at
//!   `/.well-known/oauth-authorization-server`.
//! - `/oauth/authorize`: authorization code with PKCE (S256 only), a
//!   server-rendered consent page for a logged-in human, RFC 8707 resource
//!   indicators and the RFC 9207 `iss` response parameter.
//! - `/oauth/token`: `authorization_code`, `refresh_token` (rotation with
//!   reuse detection that revokes the whole grant) and `client_credentials`
//!   for confidential clients pinned in configuration.
//! - `/oauth/revoke` (RFC 7009) and `/oauth/register` (RFC 7591, can be off).
//! - Client ID Metadata Documents (`cimd`), fetched behind an SSRF guard.
//!
//! Tokens are opaque random strings stored as SHA-256 digests. Access tokens
//! start with `uao_`, refresh tokens with `uar_`.

pub mod cimd;
pub mod store;

mod authorize;
mod metadata;
pub mod register;
mod token;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use ua_core::Config;

use crate::AppState;

/// The single scope this hub grants. Tools are filtered by profile, not scope.
pub const SCOPE: &str = "mcp";
pub const ACCESS_PREFIX: &str = "uao_";
pub const REFRESH_PREFIX: &str = "uar_";
const CODE_PREFIX: &str = "uac_";
/// Lifetime of an authorization code.
const CODE_TTL_SECS: i64 = 120;
/// Lifetime of a pending consent request.
const REQUEST_TTL_SECS: i64 = 600;

/// Routes of the authorization server. Every handler answers 404 while
/// `oauth_enabled` is off.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata::authorization_server))
        .route("/.well-known/oauth-protected-resource", get(metadata::protected_resource_root))
        .route("/.well-known/oauth-protected-resource/mcp", get(metadata::protected_resource_mcp))
        .route("/oauth/authorize", get(authorize::show).post(authorize::decide))
        .route("/oauth/token", post(token::token))
        .route("/oauth/revoke", post(token::revoke))
        .route("/oauth/register", post(register::register))
}

/// The issuer identifier: the public base URL.
pub fn issuer(cfg: &Config) -> String {
    cfg.public_base_url()
}

/// The canonical resource URI of the MCP endpoint.
pub fn mcp_resource(cfg: &Config) -> String {
    format!("{}/mcp", issuer(cfg))
}

/// Where the protected resource metadata of `/mcp` is served.
pub fn resource_metadata_url(cfg: &Config) -> String {
    format!("{}/.well-known/oauth-protected-resource/mcp", issuer(cfg))
}

/// The `WWW-Authenticate` value for a 401. With OAuth on it carries the
/// RFC 9728 `resource_metadata` pointer and the scope to request.
pub fn www_authenticate(cfg: &Config, error: Option<&str>) -> String {
    let mut v = String::from("Bearer realm=\"ua\"");
    if cfg.oauth_enabled {
        v.push_str(&format!(", resource_metadata=\"{}\", scope=\"{SCOPE}\"", resource_metadata_url(cfg)));
    }
    if let Some(e) = error {
        v.push_str(&format!(", error=\"{e}\""));
    }
    v
}

/// Canonical form of a resource indicator: parsed, lower-case scheme and
/// host, no fragment, no trailing slash on a bare origin.
pub fn canonical_resource(raw: &str) -> Option<String> {
    let url = url::Url::parse(raw.trim()).ok()?;
    if url.fragment().is_some() || !matches!(url.scheme(), "https" | "http") || url.host().is_none() {
        return None;
    }
    let s = url.as_str();
    Some(s.strip_suffix('/').unwrap_or(s).to_string())
}

/// Resource indicators this hub issues tokens for: the MCP endpoint (default)
/// and the whole hub (also valid on `/api`).
pub fn accepted_resource(cfg: &Config, requested: Option<&str>) -> Option<String> {
    let Some(raw) = requested.filter(|r| !r.trim().is_empty()) else { return Some(mcp_resource(cfg)) };
    let want = canonical_resource(raw)?;
    let mcp = canonical_resource(&mcp_resource(cfg))?;
    let root = canonical_resource(&issuer(cfg))?;
    if want == mcp {
        Some(mcp_resource(cfg))
    } else if want == root {
        Some(issuer(cfg))
    } else {
        None
    }
}

/// A fresh random credential: `prefix` plus 32 random bytes, base64url.
pub fn random_token(prefix: &str) -> String {
    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(raw))
}

/// A timestamp `secs` from now, in storage form.
pub fn ts_in(secs: i64) -> String {
    let ts = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap_or(jiff::Timestamp::MAX);
    ua_core::time::format_ts(ts)
}

fn not_enabled() -> Response {
    (StatusCode::NOT_FOUND, "OAuth is not enabled on this hub").into_response()
}

/// Escape text for HTML element content and attribute values.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A small, framing-proof, uncached HTML page.
pub fn html_page(status: StatusCode, title: &str, body: &str) -> Response {
    let page = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{t}</title>\
<style>body{{font:16px/1.45 system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;color:#1e293b}}\
.card{{border:1px solid #cbd5e1;border-radius:8px;padding:1.25rem 1.5rem}}h1{{font-size:1.3rem;margin-top:0}}\
label,select,input,button{{display:block;width:100%;box-sizing:border-box;margin:.4rem 0;font:inherit}}\
select,input{{padding:.5rem;border:1px solid #cbd5e1;border-radius:6px}}\
button{{padding:.6rem;border:0;border-radius:6px;background:#1d4ed8;color:#fff;cursor:pointer}}\
button.secondary{{background:#e2e8f0;color:#0f172a}}.hint{{color:#64748b;font-size:.9rem}}code{{word-break:break-all}}\
@media (prefers-color-scheme:dark){{body{{background:#0f172a;color:#e2e8f0}}.card{{border-color:#334155}}\
select,input{{background:#1e293b;color:#e2e8f0;border-color:#334155}}}}</style></head>\
<body><div class=\"card\">{body}</div></body></html>",
        t = html_escape(title),
    );
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        page,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config { public_url: Some("https://hub.example.com".into()), ..Config::default() }
    }

    #[test]
    fn resource_indicators() {
        let c = cfg();
        assert_eq!(accepted_resource(&c, None).as_deref(), Some("https://hub.example.com/mcp"));
        assert_eq!(
            accepted_resource(&c, Some("https://HUB.example.com/mcp")).as_deref(),
            Some("https://hub.example.com/mcp")
        );
        assert_eq!(
            accepted_resource(&c, Some("https://hub.example.com/")).as_deref(),
            Some("https://hub.example.com")
        );
        assert_eq!(accepted_resource(&c, Some("https://other.example.com/mcp")), None);
        assert_eq!(accepted_resource(&c, Some("https://hub.example.com/mcp#x")), None);
    }

    #[test]
    fn challenge_header() {
        let mut c = cfg();
        assert_eq!(www_authenticate(&c, None), "Bearer realm=\"ua\"");
        c.oauth_enabled = true;
        let h = www_authenticate(&c, Some("invalid_token"));
        assert!(h.contains(
            "resource_metadata=\"https://hub.example.com/.well-known/oauth-protected-resource/mcp\""
        ));
        assert!(h.contains("error=\"invalid_token\""));
    }
}

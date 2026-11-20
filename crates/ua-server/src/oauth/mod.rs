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
/// `oauth_enabled` is off. Without the `mcp-server` feature there is no
/// `/mcp`, so its protected resource metadata is not served either.
pub fn routes() -> Router<AppState> {
    let r = Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata::authorization_server))
        .route("/.well-known/oauth-protected-resource", get(metadata::protected_resource_root));
    let r = if crate::MCP_SERVER {
        r.route("/.well-known/oauth-protected-resource/mcp", get(metadata::protected_resource_mcp))
    } else {
        r
    };
    r.route("/oauth/authorize", get(authorize::show).post(authorize::decide))
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

/// The resource a client gets when it names none: the MCP endpoint, or the
/// whole hub in a build without the `mcp-server` feature.
pub fn default_resource(cfg: &Config) -> String {
    if crate::MCP_SERVER { mcp_resource(cfg) } else { issuer(cfg) }
}

/// Where the protected resource metadata of [`default_resource`] is served:
/// `/mcp`'s, or the root document without the `mcp-server` feature.
pub fn resource_metadata_url(cfg: &Config) -> String {
    if crate::MCP_SERVER {
        format!("{}/.well-known/oauth-protected-resource/mcp", issuer(cfg))
    } else {
        format!("{}/.well-known/oauth-protected-resource", issuer(cfg))
    }
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
/// and the whole hub (also valid on `/api`). Without the `mcp-server`
/// feature only the whole hub, which is then the default.
pub fn accepted_resource(cfg: &Config, requested: Option<&str>) -> Option<String> {
    let Some(raw) = requested.filter(|r| !r.trim().is_empty()) else { return Some(default_resource(cfg)) };
    let want = canonical_resource(raw)?;
    let mcp = canonical_resource(&mcp_resource(cfg))?;
    let root = canonical_resource(&issuer(cfg))?;
    if want == mcp && crate::MCP_SERVER {
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

/// Content-Security-Policy of the sign-in, passkey and consent pages: no
/// inline script or style, scripts and styles from this hub only, fetches
/// back to this hub only. `form-action` is left open on purpose: the OAuth
/// consent form's answer redirects to the client's `redirect_uri`, which
/// browsers check against `form-action`.
pub const PAGE_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'";

/// A small, framing-proof, uncached HTML page. Its style comes from
/// [`crate::login::PAGE_CSS_PATH`]; a page needing script loads
/// [`crate::login::LOGIN_JS_PATH`].
pub fn html_page(status: StatusCode, title: &str, body: &str) -> Response {
    let page = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{t}</title>\
<link rel=\"stylesheet\" href=\"{css}\"></head>\
<body><div class=\"card\">{body}</div></body></html>",
        t = html_escape(title),
        css = crate::login::PAGE_CSS_PATH,
    );
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CONTENT_SECURITY_POLICY, PAGE_CSP),
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

    #[cfg(not(feature = "mcp-server"))]
    #[test]
    fn without_an_mcp_server_only_the_hub_is_a_resource() {
        let mut c = cfg();
        assert_eq!(accepted_resource(&c, None).as_deref(), Some("https://hub.example.com"));
        assert_eq!(accepted_resource(&c, Some("https://hub.example.com/mcp")), None);
        assert_eq!(
            accepted_resource(&c, Some("https://hub.example.com/")).as_deref(),
            Some("https://hub.example.com")
        );
        c.oauth_enabled = true;
        let h = www_authenticate(&c, None);
        assert!(
            h.contains("resource_metadata=\"https://hub.example.com/.well-known/oauth-protected-resource\"")
        );
    }

    #[cfg(feature = "mcp-server")]
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

    #[cfg(feature = "mcp-server")]
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

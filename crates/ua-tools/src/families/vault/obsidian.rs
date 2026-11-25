//! `obsidian_*`: a small client for the Obsidian Local REST API community
//! plugin, the running app's live view of the vault.
//!
//! Configure `obsidian_api_url` (`UA_OBSIDIAN_API_URL`, loopback only; the
//! plugin serves HTTPS on 27124 with a self-signed certificate, or plain HTTP)
//! and `obsidian_api_key` (`UA_OBSIDIAN_API_KEY`). Without both, every tool
//! returns `{configured: false, reason: "not-configured", missing}`. The key
//! is held as a secret, sent only as a bearer header and redacted from errors.
//! The plugin serves the hub's vault, the default organization's: every tool
//! refuses another organization's caller (`org_unsupported`) before any
//! request is sent, configured or not.
//!
//! Requests go through `ua_ingress::Outbound` under `obsidian.local_rest`:
//! loopback addresses only (checked at connect time and on the connection's
//! peer), no redirects, no proxy, a 16 MiB body, 20 seconds. Because the
//! plugin's certificate is self-signed, that policy does not verify TLS
//! certificates; it is the only policy that may skip verification, and only
//! because it reaches nothing but loopback.

use std::net::IpAddr;

use reqwest::{Method, StatusCode, Url};
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_ingress::{Outbound, OutboundError, Request, Response, policy};

use super::{LOCK_HEAD_BYTES, frontmatter, locked_error, record, require_hub_org, vault, with_note_locks};
use crate::registry::{Registry, ToolCtx, blocking, tool};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenArgs {
    /// Note to open (inside the vault write directories).
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchArgs {
    /// Text for Obsidian's live fuzzy search.
    pub query: String,
}

/// A heading path, block id or front-matter key.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Target {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppendArgs {
    /// Note to append to (inside the vault write directories).
    pub path: String,
    /// Markdown to append.
    pub content: String,
    /// `heading` (default), `block` or `frontmatter`.
    #[serde(default = "heading")]
    pub target_type: String,
    /// Heading path, block id or front-matter key. Omitted with `heading`, the
    /// text is appended at the document root.
    pub target: Option<Target>,
}

fn heading() -> String {
    "heading".into()
}

struct Api {
    base: String,
    key: SecretString,
}

/// The configured API, `Ok(None)` when unconfigured, or an error for a non-loopback URL.
fn api(ctx: &ToolCtx) -> UaResult<Option<Api>> {
    let cfg = ctx.hub.cfg();
    let (Some(url), Some(key)) = (cfg.obsidian_api_url.as_ref(), cfg.obsidian_api_key.as_ref()) else {
        return Ok(None);
    };
    if url.trim().is_empty() || key.expose_secret().is_empty() {
        return Ok(None);
    }
    let parsed = reqwest::Url::parse(url.trim())
        .map_err(|_| UaError::invalid("obsidian_api_url is not a valid URL"))?;
    let host = parsed.host_str().unwrap_or("").trim_start_matches('[').trim_end_matches(']');
    let loopback =
        host.eq_ignore_ascii_case("localhost") || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if !matches!(parsed.scheme(), "http" | "https")
        || !loopback
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(UaError::denied(
            "obsidian_url",
            "obsidian_api_url must be an http(s) URL on localhost or a loopback address",
        ));
    }
    Ok(Some(Api { base: url.trim().trim_end_matches('/').to_string(), key: key.clone() }))
}

fn not_configured(ctx: &ToolCtx) -> Value {
    let cfg = ctx.hub.cfg();
    let mut missing = Vec::new();
    if cfg.obsidian_api_url.as_deref().is_none_or(|u| u.trim().is_empty()) {
        missing.push("UA_OBSIDIAN_API_URL");
    }
    if cfg.obsidian_api_key.as_ref().is_none_or(|k| k.expose_secret().is_empty()) {
        missing.push("UA_OBSIDIAN_API_KEY");
    }
    json!({"configured": false, "reason": "not-configured", "missing": missing})
}

/// Percent-encode a vault path for the URL, keeping `/`.
fn encode_path(rel: &str) -> String {
    let mut out = String::new();
    for b in rel.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Api {
    async fn send(
        &self,
        method: Method,
        path: &str,
        query: Option<&[(&str, &str)]>,
        body: Option<Value>,
    ) -> UaResult<Response> {
        // Pinned to the configured origin: the policy builds no other client.
        let origin = Url::parse(&self.base).map_err(|_| self.fail("the request URL does not parse"))?;
        let client = Outbound::pinned(policy::OBSIDIAN_LOCAL, &origin)
            .map_err(|e| UaError::internal(format!("cannot build the HTTP client: {e}")))?;
        let mut url = Url::parse(&format!("{}/{}", self.base, path.trim_start_matches('/')))
            .map_err(|_| self.fail("the request URL does not parse"))?;
        if let Some(q) = query {
            url.query_pairs_mut().extend_pairs(q);
        }
        let mut req = Request::new(method, url)
            .header("Accept", "application/json")
            .and_then(|r| r.secret_header("Authorization", &format!("Bearer {}", self.key.expose_secret())))
            .map_err(|e| self.fail(&e.to_string()))?;
        if let Some(b) = body {
            req = req.json(&b).map_err(|e| self.fail(&e.to_string()))?;
        }
        let resp = client.send(req).await.map_err(|e| self.fail(&e.to_string()))?;
        if resp.status() == StatusCode::PRECONDITION_FAILED {
            return Err(UaError::conflict(
                "note changed or locked since check: the plugin refused the write (412) and nothing was written; re-read the note and retry",
            ));
        }
        if !resp.status().is_success() {
            return Err(self.fail(&format!("HTTP {}", resp.status())));
        }
        Ok(resp)
    }

    fn fail(&self, msg: &str) -> UaError {
        let key = self.key.expose_secret();
        let clean = if key.is_empty() { msg.to_string() } else { msg.replace(key, "[REDACTED]") };
        UaError::invalid(format!("Obsidian request failed: {clean}"))
    }
}

/// The body as text, or an error past the policy's cap. Any other read
/// failure reads as an empty body, as before.
async fn text(resp: Response) -> UaResult<String> {
    match resp.bytes().await {
        Ok(b) => Ok(String::from_utf8_lossy(&b).into_owned()),
        Err(e @ OutboundError::TooLarge { .. }) => {
            Err(UaError::invalid(format!("Obsidian request failed: {e}")))
        }
        Err(_) => Ok(String::new()),
    }
}

async fn payload(resp: Response) -> UaResult<Value> {
    if resp.status() == StatusCode::NO_CONTENT {
        return Ok(json!({}));
    }
    let text = text(resp).await?;
    Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

async fn status(ctx: ToolCtx, _: NoArgs) -> UaResult<Value> {
    require_hub_org(&ctx)?;
    let Some(api) = api(&ctx)? else { return Ok(not_configured(&ctx)) };
    let body = payload(api.send(Method::GET, "/", None, None).await?).await?;
    Ok(match body {
        Value::Object(mut m) => {
            m.insert("configured".into(), json!(true));
            Value::Object(m)
        }
        other => json!({"configured": true, "response": other}),
    })
}

async fn open(ctx: ToolCtx, a: OpenArgs) -> UaResult<Value> {
    require_hub_org(&ctx)?;
    let Some(api) = api(&ctx)? else { return Ok(not_configured(&ctx)) };
    if a.path.trim().is_empty() {
        return Err(UaError::invalid("path must not be empty"));
    }
    let v = vault(&ctx)?;
    let p = v.resolve_write(&a.path)?;
    let rel = v.rel(&p);
    let resp = api.send(Method::POST, &format!("/open/{}", encode_path(&rel)), None, None).await?;
    Ok(json!({"path": rel, "opened": true, "response": payload(resp).await?}))
}

async fn active_note(ctx: ToolCtx, _: NoArgs) -> UaResult<Value> {
    require_hub_org(&ctx)?;
    let Some(api) = api(&ctx)? else { return Ok(not_configured(&ctx)) };
    let resp = api.send(Method::GET, "/active/", None, None).await?;
    let path = resp.headers().get("Content-Location").and_then(|h| h.to_str().ok()).map(str::to_string);
    let content = text(resp).await?;
    Ok(json!({"path": path, "content": content}))
}

async fn search(ctx: ToolCtx, a: SearchArgs) -> UaResult<Value> {
    require_hub_org(&ctx)?;
    if a.query.trim().is_empty() {
        return Err(UaError::invalid("query must not be empty"));
    }
    let Some(api) = api(&ctx)? else { return Ok(not_configured(&ctx)) };
    let resp = api.send(Method::POST, "/search/simple/", Some(&[("query", a.query.as_str())]), None).await?;
    Ok(json!({"query": a.query, "results": payload(resp).await?}))
}

/// Lock verdict and the plugin's `ifMatch` version (first 6 hex chars of the
/// sha256 of the note text, one leading BOM dropped) from one read.
fn lock_and_version(p: &std::path::Path, shown: &str) -> UaResult<Option<(bool, String)>> {
    if !p.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read(p)
        .map_err(|e| UaError::invalid(format!("cannot read note {shown:?} to check its lock: {e}")))?;
    let head = &raw[..raw.len().min(LOCK_HEAD_BYTES)];
    if frontmatter::head_is_locked(head, raw.len() > LOCK_HEAD_BYTES) {
        return Ok(Some((true, String::new())));
    }
    let body = raw.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&raw);
    let text = String::from_utf8_lossy(body);
    Ok(Some((false, super::sha256_hex(text.as_bytes())[..6].to_string())))
}

async fn append(ctx: ToolCtx, a: AppendArgs) -> UaResult<Value> {
    require_hub_org(&ctx)?;
    let Some(api) = api(&ctx)? else { return Ok(not_configured(&ctx)) };
    if a.path.trim().is_empty() {
        return Err(UaError::invalid("path must not be empty"));
    }
    if a.content.is_empty() {
        return Err(UaError::invalid("content must not be empty"));
    }
    if !matches!(a.target_type.as_str(), "heading" | "block" | "frontmatter") {
        return Err(UaError::invalid("target_type must be one of heading, block, frontmatter"));
    }
    if a.target_type != "heading" && a.target.is_none() {
        return Err(UaError::invalid(format!("target is required for {} patches", a.target_type)));
    }
    let target: Value = match &a.target {
        None => json!([]),
        Some(Target::One(s)) if a.target_type == "heading" => json!([s]),
        Some(Target::One(s)) => json!(s),
        Some(Target::Many(v)) => json!(v),
    };
    if a.target_type == "frontmatter" {
        let keys: Vec<&str> = match &a.target {
            Some(Target::One(s)) => vec![s.as_str()],
            Some(Target::Many(v)) => v.iter().map(String::as_str).collect(),
            None => Vec::new(),
        };
        if keys.iter().any(|k| k.trim().eq_ignore_ascii_case("locked")) {
            return Err(UaError::denied(
                "note_locked",
                "obsidian_append cannot patch the `locked` front-matter key; a verified human uses vault_write(force=true)",
            ));
        }
    }
    let v = vault(&ctx)?;
    let p = v.resolve_write(&a.path)?;
    let rel = v.rel(&p);
    let (p2, rel2, shown) = (p.clone(), rel.clone(), a.path.clone());
    let version = blocking(move || with_note_locks(&[&rel2], || lock_and_version(&p2, &shown))).await?;
    let mut body = json!({
        "operation": "append",
        "targetType": a.target_type,
        "target": target,
        "content": a.content,
    });
    match version {
        Some((true, _)) => return Err(locked_error(&a.path)),
        Some((false, ver)) => body["ifMatch"] = json!(ver),
        None => {}
    }
    // The PATCH carries ifMatch, so the plugin refuses (412) if the note
    // changed after the check; the in-process lock is not held across the
    // network call.
    let resp = api.send(Method::PATCH, &format!("/vault/{}", encode_path(&rel)), None, Some(body)).await?;
    // The patch was applied; an unreadable reply must not hide that.
    let reply = payload(resp).await.unwrap_or(Value::Null);
    let mut out = json!({"path": rel, "response": reply});
    let (p3, shown) = (p.clone(), a.path.clone());
    let locked_after = blocking(move || super::note_is_locked(&p3, &shown)).await.unwrap_or(false);
    if locked_after {
        out["locked_after_write"] = json!(true);
        out["warning"] = json!(
            "the note became locked while the append was in flight; the appended text may already be in it and was not undone"
        );
    }
    let revision = blocking(move || super::note_revision(&p)).await.ok();
    record(
        &ctx,
        "agent.vault.written",
        json!({"path": out["path"], "mode": "obsidian_append", "append": true, "revision": revision}),
    )
    .await?;
    Ok(out)
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "obsidian_status",
            "Status of the Obsidian Local REST API plugin (authenticated flag, versions). Returns {configured: false, reason: \"not-configured\", missing} when UA_OBSIDIAN_API_URL or UA_OBSIDIAN_API_KEY is unset.",
            status,
        )
        .family("vault")
        .read_only(),
    );
    r.add(
        tool(
            "obsidian_open",
            "Open one note (inside the vault write directories) in the running Obsidian app. Returns {path, opened, response}.",
            open,
        )
        .family("vault"),
    );
    r.add(
        tool(
            "obsidian_active_note",
            "The running Obsidian app's active note. Returns {path, content}.",
            active_note,
        )
        .family("vault")
        .read_only(),
    );
    r.add(
        tool(
            "obsidian_search",
            "Search notes through Obsidian's live full-text index. Returns {query, results}.",
            search,
        )
        .family("vault")
        .read_only(),
    );
    r.add(
        tool(
            "obsidian_append",
            "Append Markdown to a note through the plugin's patch API (heading, block or frontmatter target). A note marked `locked: true`, or a patch of the `locked` key, is refused; the PATCH carries ifMatch so a note changed since the check is refused with nothing written. Returns {path, response}.",
            append,
        )
        .family("vault"),
    );
}

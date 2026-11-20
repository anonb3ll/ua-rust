//! Config-gated Zulip relay: `zulip_send_message` and `zulip_fetch_messages`.
//!
//! Both tools are off until `zulip_site`, `zulip_email` and `zulip_api_key`
//! are set. The API key is read from config or `UA_ZULIP_API_KEY` and is never
//! logged, never placed in a ledger event and never written to the database.
//! `zulip_send_message` additionally stays retired unless `zulip_retired` is
//! `0`, `false`, `no` or `off`. There is no poll timer and no service unit:
//! a caller drives every send and fetch.
//!
//! Fetch position is one row in `zulip_fetch_cursors` per agent, channel and
//! topic. Omitting `anchor` continues from that row. The key never enters the
//! row.

use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{Config, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, ledger};

use crate::families::plans::write_identity;
use crate::registry::{Registry, ToolCtx, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "zulip.v1",
    sql: "
CREATE TABLE IF NOT EXISTS zulip_fetch_cursors (
    agent_label TEXT NOT NULL,
    channel TEXT NOT NULL,
    topic TEXT NOT NULL DEFAULT '',
    next_anchor TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (agent_label, channel, topic)
);
",
};

const MAX_CONTENT_CHARS: usize = 4000;
const MAX_TOPIC_CHARS: usize = 200;
const MAX_FETCH_LIMIT: i64 = 100;
const TIMEOUT: Duration = Duration::from_secs(10);

/// Logical channel name → Zulip stream name.
const CHANNELS: &[(&str, &str)] =
    &[("coord", "coord"), ("meta", "meta"), ("ops", "ops"), ("requests", "Requests"), ("review", "Review")];

struct Creds {
    site: reqwest::Url,
    email: String,
    key: SecretString,
}

fn zulip_retired(raw: Option<&str>) -> bool {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => true,
        Some(value) => !matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"),
    }
}

fn loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// `https` anywhere, or `http` on loopback only. No userinfo, query or fragment.
fn parse_site(raw: &str) -> UaResult<reqwest::Url> {
    let site = raw.trim().trim_end_matches('/');
    if site.is_empty() || site.chars().any(char::is_whitespace) {
        return Err(UaError::invalid(
            "zulip_site must be an https URL without credentials, a query or a fragment",
        ));
    }
    let mut url = reqwest::Url::parse(site).map_err(|_| {
        UaError::invalid("zulip_site must be an https URL without credentials, a query or a fragment")
    })?;
    let host = url.host_str().unwrap_or("");
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && loopback_host(host));
    let clean = url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && !host.is_empty();
    if !scheme_ok || !clean {
        return Err(UaError::invalid(
            "zulip_site must be an https URL without credentials, a query or a fragment",
        ));
    }
    url.set_path("/");
    Ok(url)
}

fn credentials(cfg: &Config) -> UaResult<Creds> {
    let site = cfg.zulip_site.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let email = cfg.zulip_email.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let key = cfg.zulip_api_key.as_ref().map(|s| s.expose_secret().trim()).filter(|s| !s.is_empty());
    match (site, email, key) {
        (Some(site), Some(email), Some(key)) => Ok(Creds {
            site: parse_site(site)?,
            email: email.to_string(),
            key: SecretString::from(key.to_string()),
        }),
        _ => Err(UaError::invalid("Zulip is not configured: set zulip_site, zulip_email and zulip_api_key")),
    }
}

fn canonical_channel(channel: &str) -> UaResult<(&'static str, &'static str)> {
    let key = channel.trim();
    CHANNELS
        .iter()
        .find(|(logical, _)| *logical == key)
        .copied()
        .ok_or_else(|| UaError::invalid("channel must be one of coord, meta, ops, requests, review"))
}

fn clean_label(raw: &str) -> UaResult<String> {
    let label = raw.trim();
    if label.is_empty() || label.chars().count() > 200 || label.chars().any(char::is_control) {
        return Err(UaError::invalid("agent_label must be 1-200 characters without control characters"));
    }
    Ok(label.to_string())
}

fn bound_text(raw: &str, what: &str, max: usize) -> UaResult<String> {
    let text = raw.trim();
    if text.is_empty() {
        return Err(UaError::invalid(format!("{what} must not be empty")));
    }
    if text.chars().count() > max {
        return Err(UaError::invalid(format!("{what} exceeds maximum length of {max} characters")));
    }
    Ok(text.to_string())
}

fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn http_client() -> UaResult<reqwest::Client> {
    install_crypto();
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| UaError::internal("could not build the Zulip HTTP client"))
}

/// Failure text that cannot carry the URL, the key or the response body.
const HTTP_FAILED: &str = "Zulip API request failed";

async fn zulip_form(creds: &Creds, path: &str, form: &[(&str, &str)]) -> UaResult<Value> {
    let url = creds.site.join(path).map_err(|_| UaError::internal("could not build the Zulip URL"))?;
    let client = http_client()?;
    // The serializer is not `Send`; drop it before the request is awaited.
    let encoded = {
        let mut encoded = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in form {
            encoded.append_pair(key, value);
        }
        encoded.finish()
    };
    let response = client
        .post(url)
        .basic_auth(&creds.email, Some(creds.key.expose_secret()))
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(encoded)
        .send()
        .await
        .map_err(|_| UaError::invalid(HTTP_FAILED))?;
    if !response.status().is_success() {
        return Err(UaError::invalid(HTTP_FAILED));
    }
    response.json().await.map_err(|_| UaError::invalid(HTTP_FAILED))
}

async fn zulip_get(creds: &Creds, path: &str, query: &[(&str, String)]) -> UaResult<Value> {
    let url = creds.site.join(path).map_err(|_| UaError::internal("could not build the Zulip URL"))?;
    let client = http_client()?;
    let response = client
        .get(url)
        .basic_auth(&creds.email, Some(creds.key.expose_secret()))
        .query(query)
        .send()
        .await
        .map_err(|_| UaError::invalid(HTTP_FAILED))?;
    if !response.status().is_success() {
        return Err(UaError::invalid(HTTP_FAILED));
    }
    response.json().await.map_err(|_| UaError::invalid(HTTP_FAILED))
}

// --- zulip_send_message -------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SendArgs {
    /// Agent label the message is sent as. A verified caller must name itself.
    pub agent_label: String,
    /// Allowlisted channel: `ops`, `requests`, `coord`, `review` or `meta`.
    pub channel: String,
    /// Stream topic, 1-200 characters.
    pub topic: String,
    /// Message body, 1-4000 characters. Not stored in the ledger.
    pub content: String,
}

async fn zulip_send_message(ctx: ToolCtx, a: SendArgs) -> UaResult<Value> {
    let agent = write_identity(&ctx.caller, Some(&clean_label(&a.agent_label)?))?;
    let (logical, stream) = canonical_channel(&a.channel)?;
    let topic = bound_text(&a.topic, "topic", MAX_TOPIC_CHARS)?;
    let content = bound_text(&a.content, "content", MAX_CONTENT_CHARS)?;
    let creds = credentials(ctx.hub.cfg())?;
    if zulip_retired(ctx.hub.cfg().zulip_retired.as_deref()) {
        return Err(UaError::invalid(
            "Zulip outbound sending is retired (zulip_retired defaults to on). \
             Set zulip_retired to 0, false, no or off only for an explicitly approved rollback",
        ));
    }
    let body = match zulip_form(
        &creds,
        "api/v1/messages",
        &[("type", "stream"), ("to", stream), ("topic", &topic), ("content", &content)],
    )
    .await
    {
        Ok(body) => body,
        Err(_) => {
            return Ok(json!({
                "sent": false,
                "agent": agent,
                "channel": logical,
                "topic": topic,
                "error": HTTP_FAILED,
            }));
        }
    };
    let accepted = body.get("result").and_then(Value::as_str) == Some("success");
    if !accepted {
        return Ok(json!({
            "sent": false,
            "agent": agent,
            "channel": logical,
            "topic": topic,
            "error": "Zulip API rejected the message",
        }));
    }
    let message_id = body.get("id").cloned().unwrap_or(Value::Null);
    let by = agent.clone();
    let topic_event = topic.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            ledger::append(
                tx,
                EventInput::new(
                    "agent.zulip.sent",
                    json!({
                        "agent": &by,
                        "channel": logical,
                        "topic": topic_event,
                        "message_id": message_id,
                    }),
                )
                .by(by),
            )?;
            Ok(())
        })
        .await?;
    Ok(json!({
        "sent": true,
        "message_id": body.get("id").cloned().unwrap_or(Value::Null),
        "agent": agent,
        "channel": logical,
        "topic": topic,
    }))
}

// --- zulip_fetch_messages -----------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FetchArgs {
    /// Agent label the fetch runs as. A verified caller must name itself.
    pub agent_label: String,
    /// Allowlisted channel: `ops`, `requests`, `coord`, `review` or `meta`.
    pub channel: String,
    /// Optional topic narrow, 1-200 characters when set.
    pub topic: Option<String>,
    /// `newest`, or a message id to read after. Omit to continue from the stored cursor.
    pub anchor: Option<String>,
    /// How many messages to return, 1-100. Default 20.
    pub limit: Option<i64>,
}

fn load_cursor(c: &Connection, agent: &str, channel: &str, topic: &str) -> UaResult<Option<String>> {
    let found = c
        .query_row(
            "SELECT next_anchor FROM zulip_fetch_cursors \
             WHERE agent_label = ?1 AND channel = ?2 AND topic = ?3",
            params![agent, channel, topic],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found)
}

fn narrow(stream: &str, topic: Option<&str>) -> String {
    let mut parts = vec![json!({"operator": "channel", "operand": stream})];
    if let Some(topic) = topic {
        parts.push(json!({"operator": "topic", "operand": topic}));
    }
    serde_json::to_string(&parts).unwrap_or_else(|_| "[]".into())
}

fn inbound_message(message: &Value, channel: &str, own_email: &str) -> Option<Value> {
    let id = message.get("id").and_then(Value::as_i64)?;
    let sender = message.get("sender_email").and_then(Value::as_str)?;
    let content = message.get("content").and_then(Value::as_str)?;
    if sender == own_email {
        return None;
    }
    Some(json!({
        "id": id,
        "sender_email": sender,
        "sender_full_name": message.get("sender_full_name").and_then(Value::as_str).unwrap_or(""),
        "type": message.get("type").and_then(Value::as_str).unwrap_or("stream"),
        "channel": channel,
        "topic": message.get("subject").and_then(Value::as_str).unwrap_or(""),
        "content": content,
        "timestamp": message.get("timestamp").cloned().unwrap_or(Value::Null),
    }))
}

/// `newest`, or a non-negative message id. Returns `(anchor, num_before, num_after)`.
fn anchor_window(anchor: &str, limit: i64) -> UaResult<(String, i64, i64)> {
    let anchor = anchor.trim();
    if anchor == "newest" {
        return Ok(("newest".into(), limit, 0));
    }
    if !anchor.is_empty() && anchor.bytes().all(|b| b.is_ascii_digit()) {
        return Ok((anchor.to_string(), 0, limit));
    }
    Err(UaError::invalid("anchor must be 'newest' or a non-negative message ID"))
}

async fn zulip_fetch_messages(ctx: ToolCtx, a: FetchArgs) -> UaResult<Value> {
    let agent = write_identity(&ctx.caller, Some(&clean_label(&a.agent_label)?))?;
    let (logical, stream) = canonical_channel(&a.channel)?;
    let topic = match a.topic.as_deref() {
        None => None,
        Some(topic) => Some(bound_text(topic, "topic", MAX_TOPIC_CHARS)?),
    };
    let limit = a.limit.unwrap_or(20);
    if !(1..=MAX_FETCH_LIMIT).contains(&limit) {
        return Err(UaError::invalid(format!("limit must be an integer from 1 to {MAX_FETCH_LIMIT}")));
    }
    let topic_key = topic.clone().unwrap_or_default();
    let stored = if a.anchor.is_none() {
        let (agent, logical, topic_key) = (agent.clone(), logical.to_string(), topic_key.clone());
        ctx.hub.db().read_async(move |c| load_cursor(c, &agent, &logical, &topic_key)).await?
    } else {
        None
    };
    let anchor_raw = a
        .anchor
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or(stored.as_deref())
        .unwrap_or("newest");
    let (anchor, num_before, num_after) = anchor_window(anchor_raw, limit)?;
    let creds = credentials(ctx.hub.cfg())?;
    let query = [
        ("anchor", anchor.clone()),
        ("num_before", num_before.to_string()),
        ("num_after", num_after.to_string()),
        ("narrow", narrow(stream, topic.as_deref())),
        ("apply_markdown", "false".into()),
    ];
    let failed = json!({
        "received": false,
        "agent": &agent,
        "channel": logical,
        "topic": &topic,
        "anchor": &anchor,
        "error": HTTP_FAILED,
    });
    let body = match zulip_get(&creds, "api/v1/messages", &query).await {
        Ok(body) => body,
        Err(_) => return Ok(failed),
    };
    if body.get("result").and_then(Value::as_str) != Some("success") {
        return Ok(json!({
            "received": false,
            "agent": agent,
            "channel": logical,
            "topic": topic,
            "anchor": anchor,
            "error": "Zulip API rejected the message fetch",
        }));
    }
    let Some(raw_messages) = body.get("messages").and_then(Value::as_array) else {
        return Ok(json!({
            "received": false,
            "agent": agent,
            "channel": logical,
            "topic": topic,
            "anchor": anchor,
            "error": "Zulip API returned an invalid message list",
        }));
    };
    let message_ids: Vec<i64> =
        raw_messages.iter().filter_map(|m| m.get("id").and_then(Value::as_i64)).collect();
    let own_email = creds.email.clone();
    let messages: Vec<Value> =
        raw_messages.iter().filter_map(|m| inbound_message(m, logical, &own_email)).collect();
    let next_anchor = if let Some(max_id) = message_ids.iter().copied().max() {
        Some(max_id.to_string())
    } else if anchor.bytes().all(|b| b.is_ascii_digit()) {
        Some(anchor.clone())
    } else {
        None
    };
    let count = messages.len();
    let by = agent.clone();
    let cursor_anchor = next_anchor.clone();
    let (logical_owned, topic_owned, anchor_owned) = (logical.to_string(), topic.clone(), anchor.clone());
    ctx.hub
        .db()
        .write_async(move |tx| {
            if let Some(next) = &cursor_anchor {
                let now = ua_core::time::now();
                tx.execute(
                    "INSERT INTO zulip_fetch_cursors (agent_label, channel, topic, next_anchor, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5) \
                     ON CONFLICT(agent_label, channel, topic) DO UPDATE SET \
                       next_anchor = excluded.next_anchor, updated_at = excluded.updated_at",
                    params![by, logical_owned, topic_key, next, now],
                )?;
            }
            ledger::append(
                tx,
                EventInput::new(
                    "agent.zulip.fetched",
                    json!({
                        "agent": &by,
                        "channel": logical_owned,
                        "topic": topic_owned,
                        "anchor": anchor_owned,
                        "next_anchor": cursor_anchor,
                        "messages": count,
                    }),
                )
                .by(by),
            )?;
            Ok(())
        })
        .await?;
    Ok(json!({
        "received": true,
        "agent": agent,
        "channel": logical,
        "topic": topic,
        "anchor": anchor,
        "next_anchor": next_anchor.as_deref().and_then(|s| s.parse::<i64>().ok()),
        "messages": messages,
    }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "zulip_send_message",
            "Send one message to an allowlisted Zulip channel (ops, requests, coord, review, meta). \
             Off unless zulip_site, zulip_email and zulip_api_key are configured. Also refused while \
             zulip_retired is unset or not one of 0, false, no, off. The API key is never logged or stored. \
             Returns {sent, message_id, agent, channel, topic} or {sent: false, error}.",
            zulip_send_message,
        )
        .family("zulip"),
    );
    r.add(
        tool(
            "zulip_fetch_messages",
            "Fetch messages from one allowlisted Zulip channel. anchor `newest` reads recent messages; \
             a message id reads only newer ones. Omit anchor to continue from the stored cursor for this \
             agent, channel and topic. Messages sent by the configured bot are omitted. Off unless Zulip \
             is configured. Does not send, mark read, or run commands. The API key is never logged or stored. \
             Returns {received, messages, next_anchor, anchor}.",
            zulip_fetch_messages,
        )
        .family("zulip"),
    );
}

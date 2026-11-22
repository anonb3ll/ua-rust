//! Outbound notifications through a generic webhook.
//!
//! Tools: `notify`, `batch_notify`, `flush_digest`, `notify_delivery_status`.
//!
//! Every notification is first written to `notify_outbox`. With
//! `notify_webhook_url` configured it is POSTed as JSON
//! (`{"text", "kind", "category", "agent", "outbox_id", "sent_at", "source"}`;
//! `text` makes common chat incoming-webhooks work unchanged), with the
//! configured secret header, and retried on network errors, 429 and 5xx up to
//! `notify_max_attempts` times. Without a URL the row stays in the outbox with
//! status `not_configured`. A delivered row's text is cleared; failed and
//! unconfigured rows keep it so an operator can resend. The delivery status
//! tool never returns message text.
//!
//! `batch_notify` queues messages per category in `pending_notifications`;
//! `flush_digest` (or reaching `max_batch_size`) sends them as one digest.
//! `notify` is denied to the developer and reviewer profiles by the profile
//! lists, as in the original hub.
//!
//! Deliveries go through `ua_ingress::Outbound` under `notify.webhook`. The
//! URL is the operator's, so it may name a private network or this host,
//! over http or https; link-local (cloud metadata), multicast and reserved
//! addresses are refused. No redirect is followed (the secret header would
//! go with it) and no proxy is used. The secret header, and credentials in
//! the URL (sent as basic auth), are bound to the URL's origin.

use std::time::Duration;

use base64::Engine;

use rusqlite::{Connection, params};
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{Config, UaError, UaResult};
use ua_ingress::{Outbound, OutboundError, Request, Url, policy};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use crate::families::plans::write_identity;
use crate::registry::{Registry, ToolCtx, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "notify.v1",
    sql: "
CREATE TABLE IF NOT EXISTS notify_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('notify','digest')),
    category TEXT,
    agent TEXT,
    message TEXT,
    chars INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','delivered','failed','not_configured')),
    attempts INTEGER NOT NULL DEFAULT 0,
    http_status INTEGER,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    delivered_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_notify_outbox_status ON notify_outbox(status, id);

CREATE TABLE IF NOT EXISTS pending_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL DEFAULT 'general',
    message TEXT NOT NULL,
    agent TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pending_notifications_cat ON pending_notifications(category, id);
",
};

const MAX_CHARS: usize = 8000;
const TRUNCATED: &str = "\n…(truncated)";
const MAX_ATTEMPTS_CAP: u32 = 10;
const BACKOFF_BASE_MS: u64 = 200;
const ERROR_CHARS: usize = 300;

// ---------------------------------------------------------------------------
// Delivery.

/// The configured webhook, or `None` when notifications are not configured.
struct Webhook {
    /// The POST without its body: URL and secret headers.
    request: Request,
    attempts: u32,
}

/// `%XX` escapes decoded, as the URL's user name and password are written.
fn percent_decode(s: &str) -> Option<String> {
    let (b, mut out, mut i) = (s.as_bytes(), Vec::new(), 0);
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%'
            && let (Some(h), Some(l)) =
                (b.get(i + 1).and_then(|c| hex(*c)), b.get(i + 2).and_then(|c| hex(*c)))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Credentials in the URL (`user:password@host`), taken out of it as a
/// basic-auth header value. The HTTP client this replaced sent them so.
fn take_basic_auth(url: &mut Url) -> UaResult<Option<String>> {
    if url.username().is_empty() && url.password().is_none() {
        return Ok(None);
    }
    let bad = || UaError::invalid("notify_webhook_url carries credentials that are not valid UTF-8");
    let user = percent_decode(url.username()).ok_or_else(bad)?;
    let pass = url.password().map(|p| percent_decode(p).ok_or_else(bad)).transpose()?;
    let _ = url.set_username("");
    let _ = url.set_password(None);
    let pair = format!("{user}:{}", pass.unwrap_or_default());
    Ok(Some(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair))))
}

fn webhook(cfg: &Config) -> UaResult<Option<Webhook>> {
    let Some(raw) = cfg.notify_webhook_url.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let mut url =
        Url::parse(raw).map_err(|_| UaError::invalid("notify_webhook_url does not parse as a URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(UaError::invalid("notify_webhook_url must be http or https"));
    }
    let basic = take_basic_auth(&mut url)?;
    let mut request = Request::post(url);
    if let Some(value) = basic {
        request = request.secret_header("authorization", &value).map_err(|_| {
            UaError::invalid("notify_webhook_url carries credentials that are not a valid header")
        })?;
    }
    if let Some(secret) = &cfg.notify_webhook_secret {
        let name = reqwest::header::HeaderName::from_bytes(cfg.notify_webhook_header.trim().as_bytes())
            .map_err(|_| UaError::invalid("notify_webhook_header is not a valid header name"))?;
        let bad_value = || UaError::invalid("notify_webhook_secret is not a valid header value");
        reqwest::header::HeaderValue::from_str(secret.expose_secret().trim()).map_err(|_| bad_value())?;
        request =
            request.secret_header(name.as_str(), secret.expose_secret().trim()).map_err(|_| bad_value())?;
    }
    Ok(Some(Webhook { request, attempts: cfg.notify_max_attempts.clamp(1, MAX_ATTEMPTS_CAP) }))
}

/// Outcome of the delivery attempts for one outbox row.
struct Delivery {
    delivered: bool,
    attempts: u32,
    http_status: Option<u16>,
    error: Option<String>,
}

fn clip(s: &str) -> String {
    s.chars().take(ERROR_CHARS).collect()
}

/// The outbox error for a failed attempt, and whether to try again. Never
/// quotes the URL, which may embed a credential.
fn failure(e: &OutboundError) -> (String, bool) {
    match e {
        OutboundError::Timeout | OutboundError::NotSent { timed_out: true, .. } => {
            ("webhook timed out".into(), true)
        }
        OutboundError::NotSent { .. } | OutboundError::Lookup { .. } => {
            ("webhook connection failed".into(), true)
        }
        // Refused by the policy: the same answer every time.
        OutboundError::AddressRefused { reason, .. } | OutboundError::PeerRefused { reason, .. } => {
            (format!("webhook address refused ({reason})"), false)
        }
        OutboundError::UrlRefused { why, .. } => (format!("webhook URL refused ({why})"), false),
        OutboundError::Unverified => ("webhook peer address could not be checked".into(), false),
        _ => ("webhook request failed".into(), true),
    }
}

async fn post(hook: &Webhook, body: &Value, timeout: Duration) -> Delivery {
    // The policy never follows a redirect: the secret header would go with it.
    // The client is pinned to the configured URL's origin.
    let client = match Outbound::pinned(policy::NOTIFY_WEBHOOK, hook.request.url()) {
        Ok(c) => c,
        Err(e) => {
            return Delivery {
                delivered: false,
                attempts: 0,
                http_status: None,
                error: Some(clip(&format!("could not build the HTTP client: {e}"))),
            };
        }
    };
    let mut last = Delivery { delivered: false, attempts: 0, http_status: None, error: None };
    let req = match hook.request.clone().json(body) {
        Ok(r) => r,
        Err(e) => {
            return Delivery { error: Some(clip(&format!("webhook request failed: {e}"))), ..last };
        }
    };
    for attempt in 1..=hook.attempts {
        last.attempts = attempt;
        let sent = tokio::time::timeout(timeout, client.send(req.clone()))
            .await
            .unwrap_or(Err(OutboundError::Timeout));
        let retry = match sent {
            Ok(resp) => {
                let status = resp.status();
                last.http_status = Some(status.as_u16());
                if status.is_success() {
                    last.delivered = true;
                    last.error = None;
                    return last;
                }
                last.error = Some(format!("webhook answered HTTP {}", status.as_u16()));
                status.is_server_error() || status.as_u16() == 429
            }
            Err(e) => {
                let (error, retry) = failure(&e);
                last.error = Some(clip(&error));
                retry
            }
        };
        if !retry || attempt == hook.attempts {
            break;
        }
        tokio::time::sleep(Duration::from_millis(BACKOFF_BASE_MS << (attempt - 1).min(6))).await;
    }
    last
}

/// A new outbox row plus its ledger event, in one transaction.
fn enqueue(
    tx: &mut WriteTx<'_>,
    kind: &str,
    category: Option<&str>,
    agent: &str,
    message: &str,
    configured: bool,
) -> UaResult<i64> {
    let now = ua_core::time::now();
    let status = if configured { "pending" } else { "not_configured" };
    let chars = message.chars().count() as i64;
    tx.execute(
        "INSERT INTO notify_outbox (kind, category, agent, message, chars, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![kind, category, agent, message, chars, status, now],
    )?;
    let id = tx.last_insert_rowid();
    ledger::append(
        tx,
        EventInput::new(
            ua_core::DEFAULT_ORG,
            "agent.notify.queued",
            json!({ "outbox_id": id, "kind": kind, "category": category, "chars": chars, "status": status }),
        )
        .by(agent.to_string()),
    )?;
    Ok(id)
}

/// Write the delivery outcome and its ledger event.
fn settle(tx: &mut WriteTx<'_>, id: i64, agent: &str, d: &Delivery) -> UaResult<()> {
    let now = ua_core::time::now();
    let status = if d.delivered { "delivered" } else { "failed" };
    tx.execute(
        "UPDATE notify_outbox SET status = ?1, attempts = attempts + ?2, http_status = ?3, last_error = ?4, \
         updated_at = ?5, delivered_at = CASE WHEN ?1 = 'delivered' THEN ?5 ELSE delivered_at END, \
         message = CASE WHEN ?1 = 'delivered' THEN NULL ELSE message END WHERE id = ?6",
        params![status, d.attempts, d.http_status, d.error, now, id],
    )?;
    ledger::append(
        tx,
        EventInput::new(
            ua_core::DEFAULT_ORG,
            format!("agent.notify.{status}"),
            json!({ "outbox_id": id, "attempts": d.attempts, "http_status": d.http_status }),
        )
        .by(agent.to_string()),
    )?;
    Ok(())
}

/// Record a message in the outbox and deliver it when a webhook is configured.
async fn send(
    hub: &crate::Hub,
    kind: &'static str,
    category: Option<String>,
    agent: String,
    message: String,
    timeout: Duration,
) -> UaResult<Value> {
    let hook = webhook(hub.cfg())?;
    let configured = hook.is_some();
    let chars = message.chars().count();
    let (a, m, c) = (agent.clone(), message.clone(), category.clone());
    let id = hub.db().write_async(move |tx| enqueue(tx, kind, c.as_deref(), &a, &m, configured)).await?;
    let Some(hook) = hook else {
        return Ok(json!({
            "delivered": false,
            "chars": chars,
            "error": "no notification webhook is configured (UA_NOTIFY_WEBHOOK_URL)",
            "status": "not_configured",
            "outbox_id": id,
            "attempts": 0,
        }));
    };
    let body = json!({
        "text": message,
        "kind": kind,
        "category": category,
        "agent": agent,
        "outbox_id": id,
        "sent_at": ua_core::time::now(),
        "source": "ua-rust",
    });
    let d = post(&hook, &body, timeout).await;
    let out = json!({
        "delivered": d.delivered,
        "chars": chars,
        "error": d.error,
        "status": if d.delivered { "delivered" } else { "failed" },
        "outbox_id": id,
        "attempts": d.attempts,
        "http_status": d.http_status,
    });
    hub.db().write_async(move |tx| settle(tx, id, &agent, &d)).await?;
    Ok(out)
}

/// A hub-originated notification (for example `review_ready`): the same
/// outbox and webhook as `notify`, with `category` naming the event.
pub(crate) async fn send_event(
    hub: &crate::Hub,
    category: &str,
    agent: &str,
    message: &str,
) -> UaResult<Value> {
    let message = prepare_message(message)?;
    let category = clean_category(Some(category))?;
    send(hub, "notify", Some(category), agent.to_string(), message, timeout_of(Some(20))).await
}

// ---------------------------------------------------------------------------
// notify

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NotifyArgs {
    /// The notification text. Over 8000 characters it is truncated.
    pub message: String,
    /// Seconds to wait for each delivery attempt (default 60, clamped to 1-120).
    pub timeout_s: Option<i64>,
}

fn prepare_message(raw: &str) -> UaResult<String> {
    let msg = raw.trim();
    if msg.is_empty() {
        return Err(UaError::invalid("message must not be empty"));
    }
    if msg.chars().count() > MAX_CHARS {
        let mut cut: String = msg.chars().take(MAX_CHARS).collect();
        cut.push_str(TRUNCATED);
        return Ok(cut);
    }
    Ok(msg.to_string())
}

fn timeout_of(raw: Option<i64>) -> Duration {
    Duration::from_secs(raw.unwrap_or(60).clamp(1, 120) as u64)
}

async fn notify(ctx: ToolCtx, a: NotifyArgs) -> UaResult<Value> {
    let message = prepare_message(&a.message)?;
    let agent = ctx.caller.label.clone();
    send(&ctx.hub, "notify", None, agent, message, timeout_of(a.timeout_s)).await
}

// ---------------------------------------------------------------------------
// batch_notify and flush_digest

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchArgs {
    /// Messages to queue; blank entries are skipped.
    pub messages: Vec<String>,
    /// Digest category, e.g. general, drift, audit, task_completion. Default general.
    pub category: Option<String>,
    /// Label the messages are attributed to. A verified caller is always itself.
    pub agent: Option<String>,
    /// Send the category's digest now.
    #[serde(default)]
    pub flush_now: bool,
    /// Pending messages in the category that trigger a send (default 5, 1-100).
    pub max_batch_size: Option<i64>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FlushArgs {
    /// Only this category; omitted flushes every pending category.
    pub category: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusArgs {
    /// Rows to return, newest first (default 20, max 200).
    pub limit: Option<i64>,
}

fn clean_category(raw: Option<&str>) -> UaResult<String> {
    let c = raw.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("general");
    if c.len() > 64 || !c.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')) {
        return Err(UaError::invalid("category must be 1-64 letters, digits, '_', '-' or '.'"));
    }
    Ok(c.to_string())
}

async fn batch_notify(ctx: ToolCtx, a: BatchArgs) -> UaResult<Value> {
    if a.messages.is_empty() {
        return Err(UaError::invalid("messages list must not be empty"));
    }
    let valid: Vec<String> = a
        .messages
        .iter()
        .map(|m| m.trim())
        .filter(|m| !m.is_empty())
        .map(prepare_message)
        .collect::<UaResult<_>>()?;
    if valid.is_empty() {
        return Err(UaError::invalid("all messages in list were empty"));
    }
    let category = clean_category(a.category.as_deref())?;
    let agent = write_identity(&ctx.caller, a.agent.as_deref())?;
    let max_batch = a.max_batch_size.unwrap_or(5).clamp(1, 100);
    let queued = valid.len();
    let (cat, who) = (category.clone(), agent.clone());
    let total: i64 = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let now = ua_core::time::now();
            for m in &valid {
                tx.execute(
                    "INSERT INTO pending_notifications (category, message, agent, created_at) VALUES (?1, ?2, ?3, ?4)",
                    params![cat, m, who, now],
                )?;
            }
            ledger::append(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG, "agent.notify.batched", json!({ "category": cat, "queued": valid.len() }))
                    .by(who.clone()),
            )?;
            Ok(tx.query_row("SELECT COUNT(*) FROM pending_notifications WHERE category = ?1", [&cat], |r| {
                r.get(0)
            })?)
        })
        .await?;
    let flush = a.flush_now || total >= max_batch;
    let delivery =
        if flush { Some(flush_digest(ctx, FlushArgs { category: Some(category) }).await?) } else { None };
    Ok(json!({
        "queued": queued,
        "total_pending": if flush { 0 } else { total },
        "flushed": flush,
        "delivery_result": delivery,
    }))
}

struct PendingRow {
    id: i64,
    category: String,
    message: String,
    agent: String,
}

fn digest_text(rows: &[PendingRow]) -> String {
    let mut lines = vec![format!("Agent notification digest ({} alerts):", rows.len()), String::new()];
    for r in rows {
        let cat = if r.category == "general" { String::new() } else { format!("[{}] ", r.category) };
        lines.push(format!("- {cat}[{}]: {}", r.agent, r.message));
    }
    lines.join("\n")
}

async fn flush_digest(ctx: ToolCtx, a: FlushArgs) -> UaResult<Value> {
    let category = match a.category.as_deref() {
        Some(c) => Some(clean_category(Some(c))?),
        None => None,
    };
    let cat = category.clone();
    // Take the rows in the same transaction that removes them, so two
    // concurrent flushes never send the same message twice.
    let rows: Vec<PendingRow> = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let rows = {
                let mut stmt = tx.prepare(
                    "SELECT id, category, message, agent FROM pending_notifications \
                     WHERE ?1 IS NULL OR category = ?1 ORDER BY id",
                )?;
                let mapped = stmt.query_map([&cat], |r| {
                    Ok(PendingRow {
                        id: r.get(0)?,
                        category: r.get(1)?,
                        message: r.get(2)?,
                        agent: r.get(3)?,
                    })
                })?;
                mapped.collect::<Result<Vec<_>, _>>()?
            };
            for r in &rows {
                tx.execute("DELETE FROM pending_notifications WHERE id = ?1", [r.id])?;
            }
            Ok(rows)
        })
        .await?;
    if rows.is_empty() {
        return Ok(
            json!({ "flushed_count": 0, "delivered": false, "error": "No pending notifications to flush" }),
        );
    }
    let mut text = digest_text(&rows);
    if text.chars().count() > MAX_CHARS {
        text = text.chars().take(MAX_CHARS).collect::<String>() + TRUNCATED;
    }
    // The digest is a system send: entries were attributed when queued.
    let res = send(&ctx.hub, "digest", category, "system".into(), text, timeout_of(None)).await?;
    Ok(json!({
        "flushed_count": rows.len(),
        "delivered": res["delivered"],
        "error": res["error"],
        "status": res["status"],
        "outbox_id": res["outbox_id"],
    }))
}

// ---------------------------------------------------------------------------
// notify_delivery_status

fn delivery_status(c: &Connection, limit: i64, configured: bool) -> UaResult<Value> {
    let lim = limit.clamp(1, 200);
    let mut stmt = c.prepare(
        "SELECT id, kind, category, agent, status, chars, attempts, http_status, last_error, created_at, \
         delivered_at FROM notify_outbox ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([lim], |r| {
        let status: String = r.get(4)?;
        Ok(json!({
            "id": r.get::<_, i64>(0)?,
            "kind": r.get::<_, String>(1)?,
            "category": r.get::<_, Option<String>>(2)?,
            "agent": r.get::<_, Option<String>>(3)?,
            "delivered": status == "delivered",
            "status": status,
            "chars": r.get::<_, i64>(5)?,
            "attempts": r.get::<_, i64>(6)?,
            "http_status": r.get::<_, Option<i64>>(7)?,
            "error": r.get::<_, Option<String>>(8)?,
            "sent_at": r.get::<_, String>(9)?,
            "delivered_at": r.get::<_, Option<String>>(10)?,
        }))
    })?;
    let deliveries: Vec<Value> = rows.collect::<Result<_, _>>()?;
    let success = deliveries.iter().filter(|d| d["delivered"] == true).count();
    let mut pending = serde_json::Map::new();
    {
        let mut stmt = c.prepare("SELECT category, COUNT(*) FROM pending_notifications GROUP BY category")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for row in rows {
            let (cat, n) = row?;
            pending.insert(cat, json!(n));
        }
    }
    Ok(json!({
        "deliveries": deliveries,
        "count": deliveries.len(),
        "last_delivery": deliveries.first(),
        "success_count": success,
        "failure_count": deliveries.len() - success,
        "configured": configured,
        "pending_digest": pending,
    }))
}

async fn notify_delivery_status(ctx: ToolCtx, a: StatusArgs) -> UaResult<Value> {
    let configured = ctx.hub.cfg().notify_webhook_url.as_deref().is_some_and(|u| !u.trim().is_empty());
    let limit = a.limit.unwrap_or(20);
    ctx.hub.db().read_async(move |c| delivery_status(c, limit, configured)).await
}

// ---------------------------------------------------------------------------
// Registration.

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "notify",
            "Send one notification to the operator through the configured webhook (UA_NOTIFY_WEBHOOK_URL). \
             Recorded in the outbox first; without a webhook it stays there with status not_configured. \
             Retries network errors, 429 and 5xx. Over 8000 characters the text is truncated. Returns \
             {delivered, chars, error, status, outbox_id, attempts}.",
            notify,
        )
        .family("notify"),
    );
    r.add(
        tool(
            "batch_notify",
            "Queue messages into a per-category digest buffer. flush_now=true, or reaching max_batch_size \
             (default 5) pending messages in the category, sends them as one digest. Returns {queued, \
             total_pending, flushed, delivery_result}.",
            batch_notify,
        )
        .family("notify"),
    );
    r.add(
        tool(
            "flush_digest",
            "Send queued digest messages as one notification. Omitting category flushes every pending \
             category. Returns {flushed_count, delivered, error}.",
            flush_digest,
        )
        .family("notify"),
    );
    r.add(
        tool(
            "notify_delivery_status",
            "Recent notification outcomes from the outbox, newest first: status (delivered, failed, \
             not_configured), attempts, HTTP status and error. Never returns message text and never sends.",
            notify_delivery_status,
        )
        .family("notify")
        .read_only(),
    );
}

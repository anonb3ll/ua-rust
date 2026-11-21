//! Slack ingress: v0 request signatures, delivery dedupe, the identity
//! admission step, and the coordination commands.
//!
//! This module does not serve HTTP; `ua-server`'s `slack_api` does, and calls
//! these in order: [`verify_slack_signature`] on the raw body (no database),
//! then [`admit`] in one write transaction ([`remember_signed_request`], the
//! identity allowlist, [`remember_delivery`]), then, after acknowledging
//! Slack, [`command_call`] through the governed `Registry::call` as the mapped
//! identity, and [`record_executed`]. `docs/slack.md` describes the route.
//!
//! The signature is HMAC-SHA256 over `v0:{timestamp}:{body}`, compared in
//! constant time. Timestamps more than five minutes from the hub clock are
//! rejected. A signature that already passed is remembered in
//! `slack_seen_signatures` so the same signed bytes cannot be accepted twice.
//! The signing secret comes from `UA_SLACK_SIGNING_SECRET` and is never logged
//! or stored.
//!
//! Signature checking is deliberately not an agent tool: an agent holding a
//! signed body could otherwise burn its replay slot or probe the verifier.

use hmac::{Hmac, KeyInit, Mac};
use icu_properties::CodePointMapData;
use icu_properties::props::GeneralCategory;
use rusqlite::params;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use ua_core::{Config, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use crate::registry::{Registry, ToolCtx, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "slack.v1",
    sql: "
CREATE TABLE IF NOT EXISTS slack_seen_signatures (
    request_sha TEXT PRIMARY KEY,
    seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS slack_seen_signatures_seen_at ON slack_seen_signatures (seen_at);
",
};

/// Slack event ids and trigger ids already handled, so a retried delivery
/// (Slack re-sends an Events API callback it thinks timed out, with a new
/// timestamp and so a new signature) runs once. `state` tracks a command
/// from `accepted` to `finished`; one still `accepted` when the hub starts
/// was lost and is ledgered as abandoned ([`sweep_abandoned`]).
pub const SCHEMA_V2: SchemaPart = SchemaPart {
    name: "slack.v2",
    sql: "
CREATE TABLE IF NOT EXISTS slack_seen_deliveries (
    kind TEXT NOT NULL CHECK (kind IN ('event', 'trigger')),
    delivery_id TEXT NOT NULL,
    seen_at INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'seen' CHECK (state IN ('seen', 'accepted', 'finished', 'abandoned')),
    identity TEXT,
    PRIMARY KEY (kind, delivery_id)
);
CREATE INDEX IF NOT EXISTS slack_seen_deliveries_seen_at ON slack_seen_deliveries (seen_at);
",
};

/// Slack's replay window: five minutes either side of the hub clock.
pub const SIGNATURE_MAX_AGE_S: i64 = 300;
/// Seen signatures older than this are pruned. Twice the window: a request
/// first seen earlier than that has a timestamp the window already refuses.
pub const SEEN_RETENTION_S: i64 = 2 * SIGNATURE_MAX_AGE_S;
/// Delivery ids are kept this long. Slack retries an Events API callback
/// for about an hour at most and a trigger id is good for seconds; a day
/// covers both with room to spare.
pub const DELIVERY_RETENTION_S: i64 = 24 * 3600;
/// Longest event id or trigger id accepted.
pub const MAX_DELIVERY_ID_CHARS: usize = 100;
/// Refuse bodies larger than this before doing any other work.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Longest command text [`parse_slack_command`] reads, in characters. Slack
/// caps slash-command text well below this.
pub const MAX_COMMAND_CHARS: usize = 4000;
/// A Unix timestamp in seconds has 10 digits until 2286; more is malformed.
const MAX_TIMESTAMP_DIGITS: usize = 12;
/// Longest numeric id the parser accepts (fits an `i64`).
const MAX_ID_DIGITS: usize = 18;

const COMMANDS: [&str; 9] =
    ["approve", "assign", "blocker", "contact", "plan", "progress", "review", "status", "task"];

/// Why a Slack signature was refused. Distinct from a parser error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// Missing, malformed, or not the HMAC of this body.
    BadSignature,
    /// Timestamp is more than [`SIGNATURE_MAX_AGE_S`] from `now`.
    Stale,
}

/// `v0=` plus the lowercase hex HMAC-SHA256 of `v0:{timestamp}:{body}`.
pub fn slack_signature(secret: &str, timestamp: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"v0:");
    mac.update(timestamp.as_bytes());
    mac.update(b":");
    mac.update(body);
    format!("v0={}", hex::encode(mac.finalize().into_bytes()))
}

/// `v0=` followed by exactly 64 lowercase hex digits, as Slack sends it.
fn well_formed_signature(signature: &str) -> bool {
    signature.len() == 67
        && signature.starts_with("v0=")
        && signature.as_bytes()[3..].iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Check the Slack v0 signature. `now` is the hub clock as Unix seconds.
/// This does not record a replay; [`remember_signed_request`] does that.
///
/// The timestamp must be 1 to 12 ASCII digits (no sign); the signature must
/// be `v0=` and 64 lowercase hex digits. Anything else is `BadSignature`.
pub fn verify_slack_signature(
    secret: &str,
    timestamp: &str,
    body: &[u8],
    signature: &str,
    now: i64,
) -> Result<(), SignatureError> {
    if secret.is_empty()
        || timestamp.is_empty()
        || timestamp.len() > MAX_TIMESTAMP_DIGITS
        || !timestamp.bytes().all(|b| b.is_ascii_digit())
        || !well_formed_signature(signature)
        || body.len() > MAX_BODY_BYTES
    {
        return Err(SignatureError::BadSignature);
    }
    let Ok(ts) = timestamp.parse::<i64>() else {
        return Err(SignatureError::BadSignature);
    };
    if now.abs_diff(ts) > SIGNATURE_MAX_AGE_S.unsigned_abs() {
        return Err(SignatureError::Stale);
    }
    let expected = slack_signature(secret, timestamp, body);
    // Both are 67 bytes here, so the comparison is constant time.
    if bool::from(expected.as_bytes().ct_eq(signature.as_bytes())) {
        Ok(())
    } else {
        Err(SignatureError::BadSignature)
    }
}

/// SHA-256 of the exact signed base `v0:{timestamp}:{body}`.
pub fn signed_request_sha(timestamp: &str, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"v0:");
    hasher.update(timestamp.as_bytes());
    hasher.update(b":");
    hasher.update(body);
    hex::encode(hasher.finalize())
}

/// Record a signature that already verified, at `now` (Unix seconds). `Err`
/// with `replayed` when this base was accepted before. Rows older than
/// [`SEEN_RETENTION_S`] are pruned first. The body itself is not stored, and
/// the ledger event is attributed to the `system` actor: no agent made it.
pub fn remember_signed_request(tx: &mut WriteTx<'_>, timestamp: &str, body: &[u8], now: i64) -> UaResult<()> {
    let sha = record_signature(tx, timestamp, body, now)?;
    ledger_signature(tx, &sha, timestamp)
}

/// The replay table half of [`remember_signed_request`], with no ledger
/// event: prune, then insert the signed base's hash. `Err` with `replayed`
/// when it was recorded before. Returns the hash.
fn record_signature(tx: &mut WriteTx<'_>, timestamp: &str, body: &[u8], now: i64) -> UaResult<String> {
    record_replay_key(tx, signed_request_sha(timestamp, body), now)
}

/// Insert one replay-table key (pruning first); `Err` with `replayed` when it
/// was recorded before.
fn record_replay_key(tx: &mut WriteTx<'_>, sha: String, now: i64) -> UaResult<String> {
    tx.execute(
        "DELETE FROM slack_seen_signatures WHERE seen_at < ?1",
        params![now.saturating_sub(SEEN_RETENTION_S)],
    )?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO slack_seen_signatures (request_sha, seen_at) VALUES (?1, ?2)",
        params![sha, now],
    )?;
    if inserted == 0 {
        return Err(UaError::denied("replayed", "this signed Slack request was already accepted"));
    }
    Ok(sha)
}

/// The replay-table key of a Socket Mode envelope: SHA-256 of
/// `socket-envelope:{envelope_id}`. It shares `slack_seen_signatures` with
/// signed HTTP requests; the prefix keeps the two key spaces apart (an HTTP
/// key hashes `v0:{timestamp}:{body}`).
pub fn envelope_sha(envelope_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"socket-envelope:");
    hasher.update(envelope_id.as_bytes());
    hex::encode(hasher.finalize())
}

/// What makes one delivery unique before its event or trigger id is read:
/// the signed bytes of an HTTP request, or the envelope id of a Socket Mode
/// envelope (which carries no signature; the WebSocket itself is
/// authenticated by the app token).
#[derive(Debug, Clone, Copy)]
pub enum ReplayKey<'a> {
    Signed { timestamp: &'a str, body: &'a [u8] },
    Envelope { envelope_id: &'a str },
}

fn ledger_signature(tx: &mut WriteTx<'_>, sha: &str, timestamp: &str) -> UaResult<()> {
    ledger::append(
        tx,
        EventInput::new(
            ua_core::DEFAULT_ORG,
            "agent.slack.signature_accepted",
            json!({ "request_sha": sha, "timestamp": timestamp }),
        )
        .by("system"),
    )?;
    Ok(())
}

/// Which Slack id a delivery is deduplicated on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryKind {
    /// An Events API callback, by its envelope `event_id`.
    Event,
    /// A slash command (or, later, an interaction), by its `trigger_id`.
    Trigger,
}

impl DeliveryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryKind::Event => "event",
            DeliveryKind::Trigger => "trigger",
        }
    }

    /// The request kind recorded in ledger events.
    pub fn request(self) -> &'static str {
        match self {
            DeliveryKind::Event => "event",
            DeliveryKind::Trigger => "command",
        }
    }
}

/// A Slack event id or trigger id this hub will store: 1 to
/// [`MAX_DELIVERY_ID_CHARS`] of ASCII letters, digits, `.`, `_` and `-`.
pub fn delivery_id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_DELIVERY_ID_CHARS
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Record a delivery id at `now` (Unix seconds): `true` the first time,
/// `false` for a repeat. Rows older than [`DELIVERY_RETENTION_S`] are pruned
/// first.
pub fn remember_delivery(tx: &mut WriteTx<'_>, kind: DeliveryKind, id: &str, now: i64) -> UaResult<bool> {
    if !delivery_id_ok(id) {
        return Err(UaError::invalid("malformed Slack delivery id"));
    }
    // An `accepted` row waits for the startup sweep however old it is.
    tx.execute(
        "DELETE FROM slack_seen_deliveries WHERE seen_at < ?1 AND state != 'accepted'",
        params![now.saturating_sub(DELIVERY_RETENTION_S)],
    )?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO slack_seen_deliveries (kind, delivery_id, seen_at) VALUES (?1, ?2, ?3)",
        params![kind.as_str(), id, now],
    )?;
    Ok(inserted == 1)
}

/// One verified Slack request, as the route read it. Nothing here comes from
/// a display field: identity is the (`team_id`, `user_id`) pair only.
#[derive(Debug, Clone)]
pub struct Delivery {
    pub kind: DeliveryKind,
    /// `event_id` or `trigger_id`; checked with [`delivery_id_ok`].
    pub delivery_id: String,
    pub team_id: String,
    pub user_id: String,
    /// The parsed command name, when the text parsed.
    pub command: Option<String>,
    /// A reason class the route already refused the request for after
    /// verifying it (`malformed_payload`, `invalid_command`). Recorded once
    /// the identity is known.
    pub refusal: Option<&'static str>,
}

/// What [`admit`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Run it as `identity` (always a human: `slack_identities` maps only to
    /// `human_identities`).
    Accepted { identity: String },
    /// Refused, with a reason class (`unmapped_identity`, `approve_not_enabled`
    /// or the route's own refusal). Nothing runs. `identity` is `None` for
    /// `unmapped_identity`, which is not ledgered.
    Refused { reason: &'static str, identity: Option<String> },
    /// The event id or trigger id was handled before (a Slack retry).
    Deduped { identity: String },
}

/// Admit one verified request in a single write transaction: record its
/// signature in the replay table (a replay is an `Err` with `replayed` and
/// rolls everything back), map (`team_id`, `user_id`) to a hub identity,
/// then dedupe on the delivery id.
///
/// A request with no usable identity (an unmapped pair) adds
/// **no ledger row**: its signature is still remembered, so a replay is
/// still refused, but any member of the workspace (or of a shared channel)
/// can send such requests in a loop, and the ledger is permanent. The caller
/// logs it by reason class. Once the identity is known, the request appends
/// `agent.slack.signature_accepted` (attributed to `system`) and one of
/// `agent.slack.request.refused`, `.deduped` or `.accepted` (attributed to
/// that identity). Payloads carry ids and reason classes, never the body or
/// text.
pub fn admit(
    tx: &mut WriteTx<'_>,
    cfg: &Config,
    timestamp: &str,
    body: &[u8],
    now: i64,
    d: &Delivery,
) -> UaResult<Admission> {
    admit_keyed(tx, cfg, ReplayKey::Signed { timestamp, body }, now, d)
}

/// [`admit`] for either transport. A Socket Mode envelope records
/// [`envelope_sha`] in the replay table (a redelivered envelope is
/// `replayed`) and, once the identity is known, ledgers
/// `agent.slack.envelope_accepted` instead of `agent.slack.signature_accepted`.
/// Everything after that (identity, `can_approve`, dedupe on the event or
/// trigger id, the ledger events) is the same, so a delivery seen on both
/// transports runs once.
pub fn admit_keyed(
    tx: &mut WriteTx<'_>,
    cfg: &Config,
    key: ReplayKey<'_>,
    now: i64,
    d: &Delivery,
) -> UaResult<Admission> {
    let sha = match key {
        ReplayKey::Signed { timestamp, body } => record_signature(tx, timestamp, body, now)?,
        ReplayKey::Envelope { envelope_id } => record_replay_key(tx, envelope_sha(envelope_id), now)?,
    };
    let kind = d.kind.request();
    let Some(mapping) = cfg.slack_identity(&d.team_id, &d.user_id) else {
        return Ok(Admission::Refused { reason: "unmapped_identity", identity: None });
    };
    let identity = mapping.identity.clone();
    match key {
        ReplayKey::Signed { timestamp, .. } => ledger_signature(tx, &sha, timestamp)?,
        ReplayKey::Envelope { .. } => {
            ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    "agent.slack.envelope_accepted",
                    json!({ "envelope_sha": sha }),
                )
                .by("system"),
            )?;
        }
    }
    // `/approve` needs a per-mapping opt-in; the route's own refusals (a
    // malformed payload, `approve` sent as a message) come first.
    let refusal = d.refusal.or_else(|| {
        (d.command.as_deref() == Some("approve") && !mapping.can_approve).then_some(APPROVE_NOT_ENABLED)
    });
    if let Some(reason) = refusal {
        let mut payload = json!({ "kind": kind, "reason": reason });
        if delivery_id_ok(&d.delivery_id) {
            payload["delivery_id"] = json!(d.delivery_id);
        }
        ledger::append(
            tx,
            EventInput::new(ua_core::DEFAULT_ORG, "agent.slack.request.refused", payload)
                .by(identity.clone()),
        )?;
        return Ok(Admission::Refused { reason, identity: Some(identity) });
    }
    if !remember_delivery(tx, d.kind, &d.delivery_id, now)? {
        ledger::append(
            tx,
            EventInput::new(
                ua_core::DEFAULT_ORG,
                "agent.slack.request.deduped",
                json!({ "kind": kind, "delivery_id": d.delivery_id }),
            )
            .by(identity.clone()),
        )?;
        return Ok(Admission::Deduped { identity });
    }
    ledger::append(
        tx,
        EventInput::new(
            ua_core::DEFAULT_ORG,
            "agent.slack.request.accepted",
            json!({ "kind": kind, "delivery_id": d.delivery_id, "command": d.command }),
        )
        .by(identity.clone()),
    )?;
    tx.execute(
        "UPDATE slack_seen_deliveries SET state = 'accepted', identity = ?3 WHERE kind = ?1 AND delivery_id = ?2",
        params![d.kind.as_str(), d.delivery_id, identity],
    )?;
    Ok(Admission::Accepted { identity })
}

/// Refusal reason for `/approve` from a mapping without `can_approve`.
pub const APPROVE_NOT_ENABLED: &str = "approve_not_enabled";

/// At startup, before the routes take traffic: ledger every delivery that
/// was admitted but has no recorded outcome as
/// `agent.slack.request.abandoned` with `outcome: "unknown"` (identity, kind,
/// delivery id, age in seconds; no body), exactly once, and mark it
/// `abandoned`.
///
/// "Unknown" is all the sweep can say. Usually the hub stopped before the
/// command ran, and Slack's retry was answered "Already received.". But the
/// tool call may have committed while its outcome record did not (shutdown
/// deadline, a failed write), or the command may still be running under a
/// second `ua serve` on the same database. Check `tool_calls` for the
/// identity around that time before asking for it to be sent again. (No
/// `tool_calls` id is linked: a call record does not carry the Slack
/// delivery id, and matching by caller and time would not be exact.)
/// Returns how many were ledgered.
pub fn sweep_abandoned(tx: &mut WriteTx<'_>, now: i64) -> UaResult<usize> {
    let rows: Vec<(String, String, i64, Option<String>)> = {
        let mut stmt = tx.prepare(
            "SELECT kind, delivery_id, seen_at, identity FROM slack_seen_deliveries WHERE state = 'accepted' \
             ORDER BY seen_at, delivery_id",
        )?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<Result<_, _>>()?
    };
    for (kind, delivery_id, seen_at, identity) in &rows {
        let request = if kind == "event" { "event" } else { "command" };
        let who = identity.clone().unwrap_or_else(|| "system".into());
        ledger::append(
            tx,
            EventInput::new(
                ua_core::DEFAULT_ORG,
                "agent.slack.request.abandoned",
                json!({
                    "identity": who,
                    "kind": request,
                    "delivery_id": delivery_id,
                    "age_s": now.saturating_sub(*seen_at).max(0),
                    "outcome": "unknown",
                    "detail": "admitted, no outcome recorded; check tool_calls",
                }),
            )
            .by(who.clone()),
        )?;
        tx.execute(
            "UPDATE slack_seen_deliveries SET state = 'abandoned' WHERE kind = ?1 AND delivery_id = ?2",
            params![kind, delivery_id],
        )?;
    }
    Ok(rows.len())
}

/// Ledger the outcome of a command that ran after the acknowledgement, as
/// the identity it ran as: `agent.slack.request.executed` with the tool, `ok`
/// and, on failure, the error code (never the error text or the arguments).
/// Marks the delivery `finished`, so the startup sweep leaves it alone.
pub fn record_executed(
    tx: &mut WriteTx<'_>,
    identity: &str,
    d_kind: DeliveryKind,
    delivery_id: &str,
    command: &str,
    tool: Option<&str>,
    outcome: &UaResult<Value>,
) -> UaResult<()> {
    let mut payload = json!({
        "kind": d_kind.request(),
        "delivery_id": delivery_id,
        "command": command,
        "tool": tool,
        "ok": outcome.is_ok(),
    });
    if let Err(e) = outcome {
        payload["error"] = json!(e.code());
        if let Some(code) = e.reason_code() {
            payload["reason_code"] = json!(code);
        }
        if let UaError::ApprovalRequired { approval_id, .. } = e {
            payload["approval_id"] = json!(approval_id);
        }
    }
    ledger::append(
        tx,
        EventInput::new(ua_core::DEFAULT_ORG, "agent.slack.request.executed", payload)
            .by(identity.to_string()),
    )?;
    tx.execute(
        "UPDATE slack_seen_deliveries SET state = 'finished' WHERE kind = ?1 AND delivery_id = ?2",
        params![d_kind.as_str(), delivery_id],
    )?;
    Ok(())
}

/// Ledger a reply that could not be delivered to Slack's `response_url`, by
/// reason class only (never the URL: it is a short-lived credential).
pub fn record_reply_failed(
    tx: &mut WriteTx<'_>,
    identity: &str,
    delivery_id: &str,
    reason: &'static str,
) -> UaResult<()> {
    ledger::append(
        tx,
        EventInput::new(
            ua_core::DEFAULT_ORG,
            "agent.slack.reply.failed",
            json!({ "kind": "command", "delivery_id": delivery_id, "reason": reason }),
        )
        .by(identity.to_string()),
    )?;
    Ok(())
}

/// The text after any leading `<@U123>` / `<@U123|name>` mentions. Advances
/// an index; nothing is copied.
fn strip_mentions(text: &str) -> &str {
    let mut rest = text.trim();
    while let Some(after) = rest.strip_prefix("<@") {
        let Some(close) = after.find('>') else { break };
        let id = after[..close].split('|').next().unwrap_or("");
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            break;
        }
        rest = after[close + 1..].trim_start();
    }
    rest
}

/// Split on whitespace into at most `max_splits + 1` pieces (Python `split(maxsplit=n)`).
fn split_max(text: &str, max_splits: usize) -> Vec<String> {
    let mut parts = Vec::new();
    let mut rest = text.trim_start();
    for _ in 0..max_splits {
        if rest.is_empty() {
            break;
        }
        match rest.find(char::is_whitespace) {
            Some(i) => {
                parts.push(rest[..i].to_string());
                rest = rest[i..].trim_start();
            }
            None => {
                parts.push(rest.to_string());
                rest = "";
                break;
            }
        }
    }
    if !rest.is_empty() {
        parts.push(rest.to_string());
    }
    parts
}

/// A control or format character (bidirectional controls and isolates,
/// zero-width characters, tags) other than tab and line feed.
fn hidden_char(c: char) -> bool {
    if matches!(c, '\t' | '\n') {
        return false;
    }
    matches!(
        CodePointMapData::<GeneralCategory>::new().get(c),
        GeneralCategory::Control | GeneralCategory::Format
    )
}

/// Slack escapes `&`, `<` and `>` in message text. `&amp;` goes last so
/// `&amp;lt;` reads as the literal `&lt;`.
fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

fn task_id(s: &str) -> bool {
    s.strip_prefix("task-")
        .is_some_and(|n| !n.is_empty() && n.len() <= MAX_ID_DIGITS && n.bytes().all(|b| b.is_ascii_digit()))
}

fn numeric_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_ID_DIGITS && s.bytes().all(|b| b.is_ascii_digit())
}

/// Parse a slash-style coordination command. Anything outside the nine
/// commands is refused. This does not run the command.
///
/// Refused before parsing: text over [`MAX_COMMAND_CHARS`], control and
/// format characters (bidi included; tab and line feed pass), and Slack
/// special mentions (`<!channel>`, `<!here>`, `<!subteam^…>`, any `<!…>`).
/// Leading user mentions are dropped. Arguments are unescaped (`&amp;`,
/// `&lt;`, `&gt;`). Task ids must be `task-<digits>`; approval ids digits.
pub fn parse_slack_command(text: &str) -> UaResult<Value> {
    if text.len() > MAX_COMMAND_CHARS * 4 || text.chars().count() > MAX_COMMAND_CHARS {
        return Err(UaError::invalid(format!(
            "Slack request text is longer than {MAX_COMMAND_CHARS} characters"
        )));
    }
    if let Some(c) = text.chars().find(|&c| hidden_char(c)) {
        return Err(UaError::invalid(format!(
            "Slack request text contains a control or format character (U+{:04X})",
            c as u32
        )));
    }
    if text.contains("<!") {
        return Err(UaError::invalid(
            "Slack request text contains a special mention (<!channel>, <!here>, <!subteam>); remove it",
        ));
    }
    let clean = strip_mentions(text);
    if clean.is_empty() {
        return Err(UaError::invalid("empty Slack request"));
    }
    let parts = split_max(clean, 2);
    let command = parts[0].trim_start_matches('/').to_ascii_lowercase();
    if !COMMANDS.contains(&command.as_str()) {
        return Err(UaError::invalid(format!(
            "unsupported Slack command; use one of {}",
            COMMANDS.join(", ")
        )));
    }
    let args: Vec<String> = parts.into_iter().skip(1).map(|a| unescape(&a)).collect();
    if matches!(command.as_str(), "task" | "plan") && args.is_empty() {
        return Err(UaError::invalid(format!("/{command} requires text")));
    }
    if command == "assign" && args.len() < 2 {
        return Err(UaError::invalid("/assign requires an agent and task text"));
    }
    if matches!(command.as_str(), "progress" | "blocker" | "review") && args.len() < 2 {
        return Err(UaError::invalid(format!("/{command} requires task id and update")));
    }
    if command == "approve" && args.is_empty() {
        return Err(UaError::invalid("/approve requires an approval id"));
    }
    if command == "status" && args.is_empty() {
        return Err(UaError::invalid("/status requires a task id, such as status task-42"));
    }
    if matches!(command.as_str(), "progress" | "blocker" | "review" | "status") && !task_id(&args[0]) {
        return Err(UaError::invalid(format!("/{command} needs a task id such as task-42")));
    }
    if command == "approve" && !numeric_id(&args[0]) {
        return Err(UaError::invalid("/approve needs a numeric approval id"));
    }
    Ok(json!({ "command": command, "args": args }))
}

// --- dispatch -----------------------------------------------------------------

/// One governed registry call a parsed command becomes.
#[derive(Debug, Clone, PartialEq)]
pub struct SlackCall {
    pub tool: &'static str,
    pub args: Value,
}

/// Longest task or plan title taken from Slack text, in characters.
const MAX_TITLE_CHARS: usize = 160;

fn cut(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// A one-line title: newlines folded to spaces, cut to [`MAX_TITLE_CHARS`].
fn title(text: &str) -> String {
    cut(&text.split_whitespace().collect::<Vec<_>>().join(" "), MAX_TITLE_CHARS)
}

/// A Delegation Spec for `/assign`: the Slack text is the objective.
pub fn assign_spec(text: &str, delivery_id: &str) -> String {
    format!(
        "### Objective\n{}\n\n### Scope\nThe work described in the objective, requested from Slack \
         (delivery {delivery_id}).\n\n### Definition of Done\n- The receiving agent reports the result on the \
         delegated task, and the requester can read it with the task id.\n- A request that cannot be done as \
         written is returned with the reason instead of being guessed at.\n- Gates: the test suite, lint, format \
         check and CI pass\n\n### TDD Constraints\nAdd or update focused tests for any behaviour that \
         changes.\n\n### Boundaries\nDo not approve work, change credentials, or act on anything the objective \
         does not name.\n",
        cut(text.trim(), MAX_COMMAND_CHARS)
    )
}

/// Map a parsed command ([`parse_slack_command`] output) to the registry call
/// it runs. `None` for `contact`, which runs no tool. Retry tokens derive
/// from the delivery id, so a retry that slipped past the dedupe returns the
/// first result.
///
/// | Command | Tool |
/// |---|---|
/// | `task <text>` | `task_add` |
/// | `assign <agent> <text>` | `delegate` |
/// | `progress\|blocker\|review task-N <note>` | `task_update` (`doing`, `blocked`, `waiting_review`) |
/// | `plan <text>` | `plan_create` |
/// | `approve <id>` | `approval_resolve` (`approve`) |
/// | `status task-N` | `platform_object_get` (`task`) |
pub fn command_call(parsed: &Value, delivery_id: &str) -> UaResult<Option<SlackCall>> {
    let command = parsed["command"].as_str().unwrap_or_default();
    let args: Vec<&str> =
        parsed["args"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    let key = format!("slack:{delivery_id}");
    let task_number = |s: &str| -> UaResult<i64> {
        s.strip_prefix("task-")
            .and_then(|n| n.parse::<i64>().ok())
            .ok_or_else(|| UaError::invalid("a task id such as task-42 is required"))
    };
    let call = match command {
        "contact" => return Ok(None),
        "task" => SlackCall {
            tool: "task_add",
            args: json!({
                "title": title(&args.join(" ")),
                "notes": cut(&args.join(" "), MAX_COMMAND_CHARS),
                "idempotency_key": key,
            }),
        },
        "assign" => SlackCall {
            tool: "delegate",
            args: json!({
                "to_agent": args.first().copied().unwrap_or_default(),
                "task_spec": assign_spec(&args.get(1..).unwrap_or_default().join(" "), delivery_id),
                "callback": "none",
                "idempotency_key": key,
            }),
        },
        "progress" | "blocker" | "review" => {
            let status = match command {
                "progress" => "doing",
                "blocker" => "blocked",
                _ => "waiting_review",
            };
            SlackCall {
                tool: "task_update",
                args: json!({
                    "id": task_number(args.first().copied().unwrap_or_default())?,
                    "status": status,
                    "append_note": cut(args.get(1).copied().unwrap_or_default(), MAX_COMMAND_CHARS),
                    "idempotency_key": key,
                }),
            }
        }
        "plan" => SlackCall {
            tool: "plan_create",
            args: json!({
                "goal": cut(&args.join(" "), MAX_COMMAND_CHARS),
                "steps": ["Confirm the plan and its next owner"],
            }),
        },
        "approve" => {
            let id = args
                .first()
                .and_then(|a| a.parse::<i64>().ok())
                .ok_or_else(|| UaError::invalid("/approve needs a numeric approval id"))?;
            SlackCall {
                tool: "approval_resolve",
                args: json!({ "id": id, "decision": "approve", "reason": "approved from Slack" }),
            }
        }
        "status" => {
            let id = task_number(args.first().copied().unwrap_or_default())?;
            SlackCall { tool: "platform_object_get", args: json!({ "kind": "task", "id": id.to_string() }) }
        }
        other => return Err(UaError::invalid(format!("unsupported Slack command {other:?}"))),
    };
    Ok(Some(call))
}

/// Escape text for Slack: `&`, `<` and `>` become entities, so nothing a
/// hub value contains (a task title written as `&lt;!channel&gt;`, which the
/// parser unescapes) can turn into a mention or a link when posted back.
pub fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// The short reply for a command's outcome: a fixed sentence per command
/// with ids and, for `status`, the task's title and status only. Errors give
/// their code and the client-safe message ([`UaError::to_json`]), cut short.
/// Everything is escaped with [`slack_escape`].
pub fn reply_text(command: &str, identity: &str, outcome: &UaResult<Value>) -> String {
    let v = match outcome {
        Err(UaError::ApprovalRequired { approval_id, .. }) => {
            return format!("Waiting for a human approval (approval {approval_id}).");
        }
        Err(e) => {
            let body = e.to_json();
            let msg = body["message"].as_str().unwrap_or_default();
            return format!("Refused ({}): {}", e.code(), slack_escape(&cut(msg, 300)));
        }
        Ok(v) => v,
    };
    let id = |v: &Value| v["id"].as_i64().map(|n| n.to_string()).unwrap_or_else(|| "?".into());
    match command {
        "contact" => format!("This Slack user acts as hub identity {}.", slack_escape(identity)),
        "task" => format!("Created task-{}.", id(v)),
        "progress" | "blocker" | "review" => format!("Updated task-{}.", id(v)),
        "assign" => "Delegated.".to_string(),
        "plan" => format!("Created plan {}.", slack_escape(v["plan_id"].as_str().unwrap_or("?"))),
        "approve" => format!("Approved approval {}.", id(&v["approval"])),
        "status" => {
            let t = &v["task"];
            format!(
                "task-{} [{}] {}",
                id(t),
                slack_escape(t["status"].as_str().unwrap_or("?")),
                slack_escape(&cut(t["title"].as_str().unwrap_or_default(), MAX_TITLE_CHARS))
            )
        }
        _ => "Done.".to_string(),
    }
}

// --- response_url --------------------------------------------------------------

/// The only host a reply is posted to (the host of
/// [`ua_ingress::policy::SLACK_RESPONSE_URL`]).
pub const RESPONSE_URL_HOST: &str = "hooks.slack.com";

/// Slack's `response_url`, if it is safe to post to: `https`, exactly the
/// host [`RESPONSE_URL_HOST`] on the default port, no user info, no fragment,
/// at most 2048 bytes. Anything else is `None`.
pub fn response_url(raw: &str) -> Option<url::Url> {
    if raw.is_empty() || raw.len() > 2048 {
        return None;
    }
    let u = url::Url::parse(raw).ok()?;
    let host_ok = matches!(u.host(), Some(url::Host::Domain(h)) if h == RESPONSE_URL_HOST);
    (u.scheme() == "https"
        && host_ok
        && u.port().is_none()
        && u.username().is_empty()
        && u.password().is_none()
        && u.fragment().is_none())
    .then_some(u)
}

/// Post `text` as an ephemeral reply to a checked [`response_url`], through
/// `ua_ingress::Outbound` under the `slack.response_url` policy: https to
/// [`RESPONSE_URL_HOST`] only, no redirects, no proxy, every address the
/// connection may reach must be public (loopback is refused whatever
/// `fetch_allow_loopback` says, so the config changes nothing), 10 seconds for
/// the whole call. The response body is never read. Errors are reason
/// classes: `response_url_refused`, `timeout`, `transport`, `status`.
pub async fn post_reply(_cfg: &Config, url: &url::Url, text: &str) -> Result<(), &'static str> {
    use ua_ingress::{Outbound, OutboundError, Request, policy};
    if response_url(url.as_str()).is_none() {
        return Err("response_url_refused");
    }
    let client = Outbound::new(policy::SLACK_RESPONSE_URL).map_err(|_| "transport")?;
    let body = json!({ "response_type": "ephemeral", "replace_original": false, "text": text });
    let req = Request::post(url.clone()).json(&body).map_err(|_| "transport")?;
    let resp = client.send(req).await.map_err(|e| match e {
        OutboundError::Timeout | OutboundError::NotSent { timed_out: true, .. } => "timeout",
        OutboundError::UrlRefused { .. } => "response_url_refused",
        _ => "transport",
    })?;
    if resp.status().is_success() { Ok(()) } else { Err("status") }
}

// --- Socket Mode -----------------------------------------------------------------

/// Where the Socket Mode transport stands in this process. `ua serve` sets
/// it; `system_doctor` reads it. Never carries the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocketState {
    /// Not configured, or `slack_socket_mode` is off.
    Off = 0,
    /// Configured, but this binary lacks the `slack-socket` feature.
    NotCompiled = 1,
    /// Opening or re-opening a connection.
    Connecting = 2,
    /// Slack said `hello` on the current connection.
    Connected = 3,
    /// Slack refused the app token; the transport stopped retrying.
    AuthFailed = 4,
    /// The transport stopped (shutdown).
    Stopped = 5,
    /// A connection failed or its task panicked; reconnecting with backoff.
    Restarting = 6,
}

impl SocketState {
    pub fn as_str(self) -> &'static str {
        match self {
            SocketState::Off => "off",
            SocketState::NotCompiled => "not_compiled",
            SocketState::Connecting => "connecting",
            SocketState::Connected => "connected",
            SocketState::AuthFailed => "auth_failed",
            SocketState::Stopped => "stopped",
            SocketState::Restarting => "restarting",
        }
    }
}

static SOCKET_STATE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
/// Whether any `ua serve` in this process has started the transport (the
/// state is meaningless in a process that never serves, such as `ua doctor`).
static SOCKET_REPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_socket_state(state: SocketState) {
    SOCKET_REPORTED.store(true, std::sync::atomic::Ordering::Relaxed);
    SOCKET_STATE.store(state as u8, std::sync::atomic::Ordering::Relaxed);
}

/// The transport's state, or `None` when this process does not run it.
pub fn socket_state() -> Option<SocketState> {
    if !SOCKET_REPORTED.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    Some(match SOCKET_STATE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => SocketState::NotCompiled,
        2 => SocketState::Connecting,
        3 => SocketState::Connected,
        4 => SocketState::AuthFailed,
        5 => SocketState::Stopped,
        6 => SocketState::Restarting,
        _ => SocketState::Off,
    })
}

/// Envelopes the transport turned away because a connection was at its
/// in-flight cap (this process, since start).
static SOCKET_BUSY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Count one envelope turned away at the in-flight cap.
pub fn record_socket_busy() {
    SOCKET_BUSY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Envelopes turned away at the in-flight cap since the process started.
pub fn socket_busy_count() -> u64 {
    SOCKET_BUSY.load(std::sync::atomic::Ordering::Relaxed)
}

/// Whether this binary was built with the `slack-socket` feature.
pub const SOCKET_COMPILED: bool = cfg!(feature = "slack-socket");

/// The production Slack Web API base.
pub const SLACK_API: &str = "https://slack.com/api";

/// The gate for Socket Mode: the app token when the transport should run,
/// else why not (one line for the startup log). Never includes the token.
pub fn socket_status(cfg: &Config) -> Result<secrecy::SecretString, &'static str> {
    use secrecy::ExposeSecret;
    if !cfg.slack_socket_mode {
        return Err("Slack Socket Mode off: slack_socket_mode is false");
    }
    if !SOCKET_COMPILED {
        return Err("Slack Socket Mode not started: this binary was built without the slack-socket feature");
    }
    let Some(token) = cfg.slack_app_token() else {
        return Err(
            "Slack Socket Mode not started: slack_socket_mode is on but UA_SLACK_APP_TOKEN is not set",
        );
    };
    if !token.expose_secret().starts_with("xapp-") {
        return Err("Slack Socket Mode not started: UA_SLACK_APP_TOKEN is not an app-level token (xapp-...)");
    }
    if cfg.check_slack_identities().is_err() {
        return Err("Slack Socket Mode not started: slack_identities is invalid");
    }
    Ok(token)
}

/// Why `apps.connections.open` gave no usable URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// Slack refused the token or the app (`invalid_auth`, `not_authed`,
    /// `token_revoked`, ...): retrying cannot help.
    Auth(String),
    /// Slack answered with a URL this hub will not connect to.
    BadUrl(&'static str),
    /// Anything else (network, rate limit, a Slack-side error): retry later.
    Transient(String),
}

/// `apps.connections.open` errors that a retry cannot fix.
const PERMANENT_OPEN_ERRORS: [&str; 17] = [
    "access_denied",
    "account_inactive",
    "ekm_access_denied",
    "enterprise_is_restricted",
    "forbidden_team",
    "invalid_auth",
    "missing_args",
    "missing_scope",
    "no_permission",
    "not_allowed_token_type",
    "not_authed",
    "org_login_required",
    "team_access_not_granted",
    "token_expired",
    "token_revoked",
    "two_factor_setup_required",
    "deprecated_endpoint",
];

// The longest `apps.connections.open` response read is the `slack.web_api`
// policy's cap.
const _: () = assert!(ua_ingress::policy::SLACK_WEB_API.max_body_bytes == 16 * 1024);

/// A socket URL from `apps.connections.open` this hub will connect to:
/// `wss`, host `slack.com` or ending in `.slack.com`, the default port, no
/// user info or fragment, at most 2048 bytes. With `allow_loopback_ws` (the
/// test hook only), also `ws` to a loopback IP.
pub fn socket_url(raw: &str, allow_loopback_ws: bool) -> Result<url::Url, &'static str> {
    if raw.is_empty() || raw.len() > 2048 {
        return Err("bad_length");
    }
    let u = url::Url::parse(raw).map_err(|_| "unparseable")?;
    if !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
        return Err("userinfo_or_fragment");
    }
    let loopback = match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if allow_loopback_ws && u.scheme() == "ws" && loopback {
        return Ok(u);
    }
    if u.scheme() != "wss" {
        return Err("not_wss");
    }
    let slack =
        matches!(u.host(), Some(url::Host::Domain(h)) if h == "slack.com" || h.ends_with(".slack.com"));
    if !slack {
        return Err("not_slack_host");
    }
    if u.port().is_some() {
        return Err("non_default_port");
    }
    Ok(u)
}

/// Ledger a socket URL the hub refused to connect to, by reason class only
/// (the URL carries a connection ticket; it is not recorded).
pub fn record_socket_url_refused(tx: &mut WriteTx<'_>, reason: &'static str) -> UaResult<()> {
    ledger::append(
        tx,
        EventInput::new(ua_core::DEFAULT_ORG, "agent.slack.socket.url_refused", json!({ "reason": reason }))
            .by("system"),
    )?;
    Ok(())
}

/// Ledger a Socket Mode envelope that was acknowledged after the deadline
/// and then failed admission: outcome unknown, by envelope hash and reason
/// class only (Slack will not redeliver an acknowledged envelope).
pub fn record_envelope_outcome_unknown(
    tx: &mut WriteTx<'_>,
    envelope_sha: &str,
    reason: &'static str,
) -> UaResult<()> {
    ledger::append(
        tx,
        EventInput::new(
            ua_core::DEFAULT_ORG,
            "agent.slack.envelope.outcome_unknown",
            json!({ "envelope_sha": envelope_sha, "reason": reason, "outcome": "unknown" }),
        )
        .by("system"),
    )?;
    Ok(())
}

/// Call `apps.connections.open` with the app token (in the `Authorization`
/// header, never a parameter) and return the WebSocket URL to connect to.
/// The request goes only to `https://slack.com/api` (or the test hook's
/// base, where loopback is admitted) through `ua_ingress::Outbound` under
/// the `slack.web_api` policy: no redirects, no proxy, public addresses
/// only, 15 seconds. The response is read up to 16 KiB. The token is never
/// logged and never part of an error.
pub async fn open_socket_url(cfg: &Config, token: &secrecy::SecretString) -> Result<url::Url, OpenError> {
    use secrecy::ExposeSecret;
    use ua_ingress::{Outbound, OutboundError, Request, policy};
    let transport = || OpenError::Transient("transport".into());
    let test = cfg.slack_socket_test_api.as_deref();
    let base = test.unwrap_or(SLACK_API).trim_end_matches('/');
    let rules =
        if test.is_some() { policy::SLACK_WEB_API.loopback_test_hook() } else { policy::SLACK_WEB_API };
    let client = Outbound::new(rules).map_err(|_| OpenError::Transient("client".into()))?;
    let url = url::Url::parse(&format!("{base}/apps.connections.open")).map_err(|_| transport())?;
    let req = Request::post(url)
        .secret_header("Authorization", &format!("Bearer {}", token.expose_secret()))
        .and_then(|r| r.header("Content-Type", "application/x-www-form-urlencoded"))
        .map_err(|_| transport())?;
    let resp = client.send(req).await.map_err(|e| match e {
        OutboundError::Timeout | OutboundError::NotSent { timed_out: true, .. } => {
            OpenError::Transient("timeout".into())
        }
        _ => transport(),
    })?;
    let status = resp.status();
    let body = resp.bytes().await.map_err(|e| match e {
        OutboundError::TooLarge { .. } => OpenError::Transient("response_too_large".into()),
        _ => transport(),
    })?;
    if !status.is_success() {
        return Err(OpenError::Transient(format!("http_{}", status.as_u16())));
    }
    let v: Value = serde_json::from_slice(&body).map_err(|_| OpenError::Transient("not_json".into()))?;
    if v["ok"].as_bool() != Some(true) {
        let code: String = v["error"]
            .as_str()
            .unwrap_or("unknown")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(64)
            .collect();
        return Err(if PERMANENT_OPEN_ERRORS.contains(&code.as_str()) {
            OpenError::Auth(code)
        } else {
            OpenError::Transient(code)
        });
    }
    let raw = v["url"].as_str().unwrap_or_default();
    socket_url(raw, test.is_some()).map_err(OpenError::BadUrl)
}

// --- tools --------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParseArgs {
    /// Command text. A leading `<@ID>` mention is ignored. An optional `/` prefixes the command.
    pub text: String,
}

async fn slack_parse_command(_ctx: ToolCtx, a: ParseArgs) -> UaResult<Value> {
    parse_slack_command(&a.text)
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "slack_parse_command",
            "Parse one Slack coordination command: contact, task, assign, progress, blocker, review, \
             plan, approve or status. A leading mention is stripped; special mentions (<!here>), \
             control and format characters and text over 4000 characters are refused. Returns \
             {command, args}. Does not run the command and does not serve HTTP.",
            slack_parse_command,
        )
        .family("slack")
        .read_only(),
    );
}

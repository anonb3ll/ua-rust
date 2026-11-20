//! The public relay: `relay_manage`.
//!
//! An agent drafts a message for a public surface (today, a comment on a
//! GitHub issue or pull request). The hub runs public-safety gates over it
//! ([`gates`]); a human approves the exact text and destination; only then is
//! it sent ([`github`]). Actions:
//!
//! * `check`: run the gates only. Nothing is stored or recorded.
//! * `draft`: run the gates and store the draft. A blocked draft is recorded
//!   without its text.
//! * `request_send`: re-run the gates under the current configuration, check
//!   the destination and credential, and park a human approval bound to the
//!   draft id, channel, target and exact text.
//! * `send`: the requester repeats the exact text. Refused unless it matches
//!   the stored text byte for byte, the stored draft still matches what the
//!   approval bound, and the gates still pass. Consumes the one-time pass,
//!   marks the draft `sending`, posts, then records `sent`, `failed` or
//!   `uncertain`.
//! * `status`, `list`, `cancel`.
//! * `resolve`: a human who checked the thread records the outcome of an
//!   `uncertain` (or stranded `sending`) send. Never posts.
//!
//! The ledger records the destination, sizes, the text's SHA-256 and the
//! gate verdicts (categories and counts), never the text and never a
//! denylist pattern.

pub mod gates;
pub mod github;

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::{ActorKind, Caller, Config, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use self::gates::{Gates, Verdict};
use self::github::{Outcome, Target};
use crate::approvals::{self, GateOutcome};
use crate::families::managed_secrets;
use crate::families::plans::parse_params;
use crate::registry::{Registry, ToolCtx, tool};

/// The tool name approvals are recorded under.
pub const TOOL: &str = "relay_manage";
/// The only channel in this build.
pub const CHANNEL: &str = "github";
/// Refuse texts larger than this many bytes before running any gate.
const MAX_INPUT_BYTES: usize = 4 * gates::MAX_CHARS_CEILING;
const ERROR_CHARS: usize = 300;

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "relay.v1",
    sql: "
CREATE TABLE IF NOT EXISTS relay_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    target TEXT NOT NULL,
    text TEXT,
    text_sha256 TEXT NOT NULL,
    chars INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('pass','block')),
    findings TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL CHECK (status IN
        ('blocked','draft','pending_approval','sending','sent','failed','uncertain','cancelled')),
    approval_id INTEGER,
    requested_by TEXT NOT NULL,
    receipt TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    sent_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_relay_messages_status ON relay_messages(status, id);
CREATE INDEX IF NOT EXISTS idx_relay_messages_requester ON relay_messages(requested_by, id);
CREATE INDEX IF NOT EXISTS idx_relay_messages_content ON relay_messages(target, text_sha256);
",
};

fn sha256(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn clip(s: &str) -> String {
    s.chars().take(ERROR_CHARS).collect()
}

fn require_identity(caller: &Caller) -> UaResult<()> {
    if caller.kind == ActorKind::Anonymous {
        return Err(UaError::denied("identity_required", "the relay requires an authenticated identity"));
    }
    Ok(())
}

// --- rows ------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Row {
    id: i64,
    channel: String,
    target: String,
    text: Option<String>,
    text_sha256: String,
    chars: i64,
    bytes: i64,
    verdict: String,
    findings: Value,
    status: String,
    approval_id: Option<i64>,
    requested_by: String,
    receipt: Option<Value>,
    error: Option<String>,
    created_at: String,
    updated_at: String,
    sent_at: Option<String>,
}

fn row_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let json_col = |s: Option<String>| s.and_then(|s| serde_json::from_str(&s).ok());
    Ok(Row {
        id: r.get("id")?,
        channel: r.get("channel")?,
        target: r.get("target")?,
        text: r.get("text")?,
        text_sha256: r.get("text_sha256")?,
        chars: r.get("chars")?,
        bytes: r.get("bytes")?,
        verdict: r.get("verdict")?,
        findings: json_col(r.get("findings")?).unwrap_or(Value::Null),
        status: r.get("status")?,
        approval_id: r.get("approval_id")?,
        requested_by: r.get("requested_by")?,
        receipt: json_col(r.get("receipt")?),
        error: r.get("error")?,
        created_at: r.get("created_at")?,
        updated_at: r.get("updated_at")?,
        sent_at: r.get("sent_at")?,
    })
}

fn load(c: &Connection, id: i64) -> UaResult<Row> {
    c.query_row("SELECT * FROM relay_messages WHERE id = ?1", [id], row_from)
        .optional()?
        .ok_or_else(|| UaError::not_found(format!("relay draft {id}")))
}

impl Row {
    /// Without the text: for lists and for callers other than the requester.
    fn summary(&self) -> Value {
        json!({
            "draft_id": self.id,
            "channel": self.channel,
            "target": self.target,
            "status": self.status,
            "verdict": self.verdict,
            "categories": self.findings.get("categories").cloned().unwrap_or(json!({})),
            "chars": self.chars,
            "bytes": self.bytes,
            "text_sha256": self.text_sha256,
            "approval_id": self.approval_id,
            "requested_by": self.requested_by,
            "receipt": self.receipt,
            "error": self.error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "sent_at": self.sent_at,
        })
    }

    /// The payload a human approves. Every value that changes what is sent,
    /// or where, is in it; the gate adds the requester.
    fn approval_payload(&self) -> Value {
        json!({
            "action": "send",
            "draft_id": self.id,
            "channel": self.channel,
            "target": self.target,
            "text": self.text,
            "text_sha256": self.text_sha256,
            "chars": self.chars,
        })
    }

    fn owned_by(&self, caller: &Caller) -> UaResult<()> {
        if self.requested_by == caller.label {
            Ok(())
        } else {
            Err(UaError::denied(
                "not_requester",
                format!(
                    "relay draft {} belongs to {}; only its requester can do that",
                    self.id, self.requested_by
                ),
            ))
        }
    }
}

fn set_status(tx: &WriteTx<'_>, id: i64, status: &str) -> UaResult<()> {
    tx.execute(
        "UPDATE relay_messages SET status = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, status, ua_core::time::now()],
    )?;
    Ok(())
}

fn emit(tx: &mut WriteTx<'_>, caller: &Caller, channel: &str, payload: Value) -> UaResult<()> {
    ledger::append(tx, EventInput::new(channel, payload).by(caller.label.clone()))?;
    Ok(())
}

// --- arguments ------------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManageArgs {
    /// One of check, draft, request_send, send, status, list, cancel, resolve.
    pub action: String,
    /// The action's arguments. check/draft: `{target, text, channel?}` with
    /// target `owner/repo#123` and channel `github` (the default).
    /// request_send: `{draft_id}`. send: `{draft_id, text}` where text is the
    /// exact approved text. status: `{draft_id}` or `{approval_id}`. list:
    /// `{status?, limit?}`. cancel: `{draft_id, reason?}`. resolve (a human):
    /// `{draft_id, outcome: delivered|not_delivered, reason?}`.
    pub params: Option<Value>,
}

fn default_channel() -> String {
    CHANNEL.into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftParams {
    #[serde(default = "default_channel")]
    channel: String,
    #[serde(alias = "destination")]
    target: String,
    text: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdParams {
    draft_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SendParams {
    draft_id: i64,
    text: String,
    #[serde(default, alias = "destination")]
    target: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusParams {
    draft_id: Option<i64>,
    approval_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParams {
    status: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelParams {
    draft_id: i64,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveParams {
    draft_id: i64,
    /// `delivered` or `not_delivered`.
    outcome: String,
    reason: Option<String>,
}

/// A `sending` draft older than this is presumed stranded (the request
/// timeout is 20 seconds), so a human may record its outcome.
const SENDING_STALE_SECS: i64 = 120;

// --- check and draft --------------------------------------------------------------------------

/// A validated draft: the destination and the gates' verdict on the text.
struct Prepared {
    target: Target,
    text: String,
    verdict: Verdict,
}

fn prepare(cfg: &Config, p: DraftParams) -> UaResult<Prepared> {
    if p.channel.trim() != CHANNEL {
        return Err(UaError::invalid(format!(
            "unknown relay channel {:?}; this hub relays to: {CHANNEL}",
            p.channel
        )));
    }
    let target = github::parse_target(&p.target)?;
    github::require_allowed(cfg, &target)?;
    if p.text.trim().is_empty() {
        return Err(UaError::invalid("text must be a non-empty string"));
    }
    if p.text.len() > MAX_INPUT_BYTES {
        return Err(UaError::invalid(format!("text is over {MAX_INPUT_BYTES} bytes")));
    }
    let verdict = Gates::from_config(cfg)?.check(&p.text);
    Ok(Prepared { target, text: p.text, verdict })
}

fn check(ctx: &ToolCtx, p: DraftParams) -> UaResult<Value> {
    let d = prepare(ctx.hub.cfg(), p)?;
    let mut out = d.verdict.to_json();
    out["channel"] = json!(CHANNEL);
    out["target"] = json!(d.target.canonical());
    out["chars"] = json!(d.text.chars().count());
    out["bytes"] = json!(d.text.len());
    out["text_sha256"] = json!(sha256(&d.text));
    out["recorded"] = json!(false);
    Ok(out)
}

async fn draft(ctx: ToolCtx, p: DraftParams) -> UaResult<Value> {
    require_identity(&ctx.caller)?;
    let d = prepare(ctx.hub.cfg(), p)?;
    let caller = ctx.caller.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let passed = d.verdict.passed();
            let report = d.verdict.to_json();
            let (sha, chars, bytes) = (sha256(&d.text), d.text.chars().count() as i64, d.text.len() as i64);
            let status = if passed { "draft" } else { "blocked" };
            let now = ua_core::time::now();
            // A blocked draft is kept without its text: it may hold the very
            // secret or personal data the gates caught.
            let stored_text = passed.then_some(d.text.as_str());
            tx.execute(
                "INSERT INTO relay_messages (channel, target, text, text_sha256, chars, bytes, verdict, findings, \
                 status, requested_by, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
                params![
                    CHANNEL,
                    d.target.canonical(),
                    stored_text,
                    sha,
                    chars,
                    bytes,
                    d.verdict.label(),
                    report.to_string(),
                    status,
                    caller.label,
                    now
                ],
            )?;
            let id = tx.last_insert_rowid();
            emit(
                tx,
                &caller,
                "relay.drafted",
                json!({
                    "draft_id": id, "channel": CHANNEL, "target": d.target.canonical(), "chars": chars,
                    "bytes": bytes, "text_sha256": sha, "verdict": d.verdict.label(),
                    "categories": d.verdict.categories(),
                }),
            )?;
            let mut out = report;
            out["draft_id"] = json!(id);
            out["status"] = json!(status);
            out["channel"] = json!(CHANNEL);
            out["target"] = json!(d.target.canonical());
            out["chars"] = json!(chars);
            out["text_sha256"] = json!(sha);
            out["hint"] = json!(if passed {
                "call relay_manage request_send {draft_id} to ask a human to approve this exact text"
            } else {
                "nothing can be sent: fix every finding and draft again"
            });
            Ok(out)
        })
        .await
}

// --- request_send ---------------------------------------------------------------------------

/// The draft's text, re-checked under the current configuration: the
/// destination is still allowed, the gates still pass, and the adapter has a
/// usable credential. Run before a human is asked and again before sending.
fn recheck(c: &Connection, cfg: &Config, row: &Row) -> UaResult<(Target, String)> {
    let text =
        row.text.clone().ok_or_else(|| UaError::conflict(format!("relay draft {} has no text", row.id)))?;
    if sha256(&text) != row.text_sha256 {
        return Err(UaError::denied(
            "approval_mismatch",
            format!("relay draft {} changed after it was drafted; nothing was sent", row.id),
        ));
    }
    let target = github::parse_target(&row.target)?;
    github::require_allowed(cfg, &target)?;
    let verdict = Gates::from_config(cfg)?.check(&text);
    if !verdict.passed() {
        return Err(UaError::denied(
            "relay_blocked",
            format!(
                "relay draft {} no longer passes the public-safety gates ({}); nothing was sent. Draft again.",
                row.id,
                serde_json::to_string(&verdict.categories()).unwrap_or_default()
            ),
        ));
    }
    github::api_base(cfg)?;
    let name = github::secret_name(cfg)?;
    if !managed_secrets::bound_to(c, name, github::CONSUMER)? {
        return Err(UaError::denied(
            "relay_unavailable",
            format!("managed secret {name:?} is not set or not bound to consumer {:?}", github::CONSUMER),
        ));
    }
    Ok((target, text))
}

async fn request_send(ctx: ToolCtx, p: IdParams) -> UaResult<Value> {
    require_identity(&ctx.caller)?;
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    ctx.hub
        .db()
        .write_async(move |tx| {
            let row = load(tx, p.draft_id)?;
            row.owned_by(&caller)?;
            match row.status.as_str() {
                "draft" => {}
                "pending_approval" => {
                    let approval = row.approval_id.map(|a| approvals::get(tx, a)).transpose()?;
                    return Ok(json!({
                        "draft_id": row.id, "status": row.status, "approval_id": row.approval_id,
                        "approval_status": approval.map(|a| a.status), "already_requested": true,
                    }));
                }
                other => {
                    return Err(UaError::conflict(format!(
                        "relay draft {} is {other}; only a draft that passed the gates can be sent for approval",
                        row.id
                    )));
                }
            }
            let (target, text) = recheck(tx, hub.cfg(), &row)?;
            let payload = row.approval_payload();
            let approval_id = match approvals::gate(tx, hub.cfg(), &caller, TOOL, &payload)? {
                GateOutcome::Pending { approval_id } => approval_id,
                // A fresh draft id has never been requested, so no decision
                // can exist for it yet; refuse rather than spend one.
                other => {
                    return Err(UaError::internal(format!(
                        "unexpected approval state for relay draft {}: {other:?}",
                        row.id
                    )));
                }
            };
            tx.execute(
                "UPDATE relay_messages SET status = 'pending_approval', approval_id = ?2, updated_at = ?3 WHERE id = ?1",
                params![row.id, approval_id, ua_core::time::now()],
            )?;
            emit(
                tx,
                &caller,
                "relay.send_requested",
                json!({
                    "draft_id": row.id, "approval_id": approval_id, "channel": row.channel,
                    "target": target.canonical(), "chars": row.chars, "bytes": row.bytes,
                    "text_sha256": row.text_sha256,
                }),
            )?;
            Ok(json!({
                "draft_id": row.id,
                "status": "pending_approval",
                "approval_id": approval_id,
                "channel": row.channel,
                "target": target.canonical(),
                "text": text,
                "hint": "a human approves with approval_resolve(id, 'approve'); then call relay_manage send \
                         {draft_id, text} with exactly this text",
            }))
        })
        .await
}

// --- send ------------------------------------------------------------------------------------

/// Everything the network step needs, resolved under the write lock.
struct Ready {
    row: Row,
    target: Target,
    text: String,
    approval_id: i64,
    token: SecretString,
}

fn first_difference(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count()
}

/// Phase one, in one write transaction: verify everything, consume the pass
/// and mark the draft `sending`. `Ok(Err(..))` commits (a re-parked
/// approval) and still refuses.
fn begin_send(
    tx: &mut WriteTx<'_>,
    cfg: &Config,
    caller: &Caller,
    p: &SendParams,
) -> UaResult<Result<Ready, UaError>> {
    let row = load(tx, p.draft_id)?;
    row.owned_by(caller)?;
    match row.status.as_str() {
        "pending_approval" => {}
        "draft" => {
            return Err(UaError::conflict(format!(
                "relay draft {} has no approval request; call request_send first",
                row.id
            )));
        }
        "sent" => return Err(UaError::conflict(format!("relay draft {} was already sent", row.id))),
        other => {
            return Err(UaError::conflict(format!("relay draft {} is {other}; it cannot be sent", row.id)));
        }
    }
    let stored = row.text.clone().unwrap_or_default();
    if p.text != stored {
        return Err(UaError::denied(
            "text_mismatch",
            format!(
                "the text differs from the approved text of relay draft {} (first difference at character {}); \
                 nothing was sent. Draft again for a new approval.",
                row.id,
                first_difference(&p.text, &stored)
            ),
        ));
    }
    if let Some(t) = p.target.as_deref()
        && github::parse_target(t).map(|t| t.canonical()).ok().as_deref() != Some(row.target.as_str())
    {
        return Err(UaError::denied(
            "target_mismatch",
            format!("relay draft {} was approved for another target; nothing was sent", row.id),
        ));
    }
    let (target, text) = recheck(tx, cfg, &row)?;
    // One live attempt per text and target: an earlier send with no known
    // outcome may already be public.
    let open: Option<i64> = tx
        .query_row(
            "SELECT id FROM relay_messages WHERE target = ?1 AND text_sha256 = ?2 AND id != ?3 \
             AND status IN ('sending','uncertain') LIMIT 1",
            params![row.target, row.text_sha256, row.id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(other) = open {
        return Err(UaError::conflict_code(
            "relay_duplicate",
            format!(
                "relay draft {other} sent this exact text to {} with no confirmed outcome; it may already be \
                 public, so this one is not sent",
                row.target
            ),
        ));
    }
    let name = github::secret_name(cfg)?;
    let token = managed_secrets::load_for_consumer(tx, cfg, name, github::CONSUMER).map_err(|e| {
        UaError::denied(
            "relay_unavailable",
            format!("the relay's GitHub credential is not usable: {}", e.reason_code().unwrap_or(e.code())),
        )
    })?;
    if token.expose_secret().trim().is_empty() || token.expose_secret().contains(['\r', '\n', '\0']) {
        return Err(UaError::denied(
            "relay_unavailable",
            "the relay's GitHub credential is not a single-line token",
        ));
    }
    let payload = row.approval_payload();
    if let Some(id) = row.approval_id {
        let approval = approvals::get(tx, id)?;
        if approval.tool != TOOL || approval.payload != payload {
            return Err(UaError::denied(
                "approval_mismatch",
                format!(
                    "relay draft {} no longer matches what approval {id} bound (text, target or channel changed); \
                     nothing was sent",
                    row.id
                ),
            ));
        }
        match approval.status.as_str() {
            "approved" | "pending" => {}
            "denied" => {
                set_status(tx, row.id, "cancelled")?;
                return Ok(Err(UaError::denied(
                    "approval_denied",
                    format!(
                        "approval {id} was denied: {}; relay draft {} is cancelled",
                        approval.reason.unwrap_or_default(),
                        row.id
                    ),
                )));
            }
            other => {
                return Err(UaError::conflict(format!(
                    "approval {id} is {other}; draft again for a new human decision"
                )));
            }
        }
    }
    let approval_id = match approvals::gate(tx, cfg, caller, TOOL, &payload)? {
        GateOutcome::Pass { approval_id } => approval_id,
        GateOutcome::Pending { approval_id } => {
            // Still waiting, or the pass expired and a new request was parked.
            if row.approval_id != Some(approval_id) {
                tx.execute(
                    "UPDATE relay_messages SET approval_id = ?2, updated_at = ?3 WHERE id = ?1",
                    params![row.id, approval_id, ua_core::time::now()],
                )?;
            }
            return Ok(Err(UaError::ApprovalRequired { tool: TOOL.into(), approval_id }));
        }
        GateOutcome::Denied { approval_id, reason } => {
            return Err(UaError::denied(
                "approval_denied",
                format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
            ));
        }
    };
    tx.execute(
        "UPDATE relay_messages SET status = 'sending', approval_id = ?2, updated_at = ?3 WHERE id = ?1",
        params![row.id, approval_id, ua_core::time::now()],
    )?;
    emit(
        tx,
        caller,
        "relay.sending",
        json!({
            "draft_id": row.id, "approval_id": approval_id, "channel": row.channel, "target": row.target,
            "chars": row.chars, "bytes": row.bytes, "text_sha256": row.text_sha256,
        }),
    )?;
    Ok(Ok(Ready { row, target, text, approval_id, token }))
}

async fn send(ctx: ToolCtx, p: SendParams) -> UaResult<Value> {
    require_identity(&ctx.caller)?;
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    let ready = ctx.hub.db().write_async(move |tx| begin_send(tx, hub.cfg(), &caller, &p)).await??;
    let outcome = github::post_comment(ctx.hub.cfg(), &ready.token, &ready.target, &ready.text).await;
    let Ready { row, approval_id, .. } = ready;
    let (status, channel, receipt, http_status, error) = match &outcome {
        Outcome::Sent(r) => ("sent", "relay.sent", Some(r.clone()), r.get("http_status").cloned(), None),
        Outcome::Failed { http_status, error } => {
            ("failed", "relay.send_failed", None, http_status.map(|s| json!(s)), Some(clip(error)))
        }
        Outcome::Uncertain { http_status, error } => {
            ("uncertain", "relay.send_uncertain", None, http_status.map(|s| json!(s)), Some(clip(error)))
        }
    };
    let caller = ctx.caller.clone();
    let (rec, err) = (receipt.clone(), error.clone());
    let row2 = row.clone();
    let recorded = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let now = ua_core::time::now();
            tx.execute(
                "UPDATE relay_messages SET status = ?2, receipt = ?3, error = ?4, updated_at = ?5, \
                 sent_at = CASE WHEN ?2 = 'sent' THEN ?5 ELSE sent_at END WHERE id = ?1",
                params![row2.id, status, rec.as_ref().map(Value::to_string), err, now],
            )?;
            emit(
                tx,
                &caller,
                channel,
                json!({
                    "draft_id": row2.id, "approval_id": approval_id, "channel": row2.channel,
                    "target": row2.target, "chars": row2.chars, "bytes": row2.bytes,
                    "text_sha256": row2.text_sha256, "http_status": http_status,
                    "comment_id": rec.as_ref().and_then(|r| r.get("comment_id").cloned()),
                    "error": err,
                }),
            )
        })
        .await;
    if let Err(e) = &recorded {
        tracing::warn!(draft_id = row.id, error = %e, "relay outcome not recorded");
    }
    match outcome {
        Outcome::Sent(receipt) => Ok(json!({
            "draft_id": row.id,
            "status": "sent",
            "approval_id": approval_id,
            "channel": row.channel,
            "target": row.target,
            "receipt": receipt,
            "recording_gap": recorded.is_err(),
        })),
        Outcome::Failed { error, .. } => Err(UaError::invalid(format!(
            "relay send of draft {} failed before reaching GitHub: {}. The approval was consumed; draft again for \
             a new human decision.",
            row.id,
            clip(&error)
        ))),
        Outcome::Uncertain { error, .. } => Err(UaError::conflict_code(
            "relay_uncertain",
            format!(
                "relay send of draft {} has an unknown outcome: {}. The comment may be public, so it is not \
                 retried; check the thread before drafting again.",
                row.id,
                clip(&error)
            ),
        )),
    }
}

// --- status, list, cancel ----------------------------------------------------------------------

fn can_see_text(caller: &Caller, row: &Row) -> bool {
    caller.is_human() || row.requested_by == caller.label
}

async fn status(ctx: ToolCtx, p: StatusParams) -> UaResult<Value> {
    let caller = ctx.caller.clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            let row = match (p.draft_id, p.approval_id) {
                (Some(id), None) => load(c, id)?,
                (None, Some(a)) => c
                    .query_row("SELECT * FROM relay_messages WHERE approval_id = ?1", [a], row_from)
                    .optional()?
                    .ok_or_else(|| UaError::not_found(format!("no relay draft with approval {a}")))?,
                _ => return Err(UaError::invalid("give exactly one of draft_id or approval_id")),
            };
            if !caller.is_human() && row.requested_by != caller.label {
                return Err(UaError::not_found(format!("relay draft {}", row.id)));
            }
            let approval = row.approval_id.map(|a| approvals::get(c, a)).transpose()?;
            let mut out = row.summary();
            out["findings"] = row.findings.get("findings").cloned().unwrap_or(json!([]));
            out["approval_status"] = json!(approval.as_ref().map(|a| a.status.clone()));
            out["resolved_by"] = json!(approval.and_then(|a| a.resolved_by));
            if can_see_text(&caller, &row) {
                out["text"] = json!(row.text);
            }
            Ok(out)
        })
        .await
}

const STATUSES: [&str; 8] =
    ["blocked", "draft", "pending_approval", "sending", "sent", "failed", "uncertain", "cancelled"];

async fn list(ctx: ToolCtx, p: ListParams) -> UaResult<Value> {
    if let Some(s) = p.status.as_deref()
        && !STATUSES.contains(&s)
    {
        return Err(UaError::invalid(format!("status must be one of {STATUSES:?}")));
    }
    let limit = p.limit.clamp(1, 200);
    // Humans see every draft; an agent sees its own.
    let who = (!ctx.caller.is_human()).then(|| ctx.caller.label.clone());
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(
                "SELECT * FROM relay_messages WHERE (?1 IS NULL OR status = ?1) AND (?2 IS NULL OR requested_by = ?2) \
                 ORDER BY id DESC LIMIT ?3",
            )?;
            let rows: Vec<Value> = stmt
                .query_map(params![p.status, who, limit], row_from)?
                .map(|r| r.map(|r| r.summary()))
                .collect::<Result<_, _>>()?;
            Ok(json!({ "drafts": rows, "count": rows.len() }))
        })
        .await
}

async fn cancel(ctx: ToolCtx, p: CancelParams) -> UaResult<Value> {
    require_identity(&ctx.caller)?;
    let caller = ctx.caller.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let row = load(tx, p.draft_id)?;
            if !caller.is_human() {
                row.owned_by(&caller)?;
            }
            if !matches!(row.status.as_str(), "draft" | "blocked" | "pending_approval") {
                return Err(UaError::conflict(format!("relay draft {} is {}; it cannot be cancelled", row.id, row.status)));
            }
            let now = ua_core::time::now();
            let reason = p.reason.as_deref().map(clip).unwrap_or_else(|| "relay draft cancelled".into());
            // Withdraw the human decision too, so it can never be spent.
            let mut approval_status = None;
            if let Some(a) = row.approval_id {
                let new = match approvals::get(tx, a)?.status.as_str() {
                    "pending" => Some("denied"),
                    "approved" => Some("revoked"),
                    _ => None,
                };
                if let Some(new) = new {
                    tx.execute(
                        "UPDATE approvals SET status = ?2, reason = ?3, resolved_by = COALESCE(resolved_by, ?4), \
                         resolved_at = COALESCE(resolved_at, ?5), updated_at = ?5 WHERE id = ?1",
                        params![a, new, reason, caller.label, now],
                    )?;
                    approval_status = Some(new);
                }
            }
            // The text never went out; do not keep it.
            tx.execute(
                "UPDATE relay_messages SET status = 'cancelled', text = NULL, error = ?2, updated_at = ?3 WHERE id = ?1",
                params![row.id, reason, now],
            )?;
            emit(
                tx,
                &caller,
                "relay.cancelled",
                json!({
                    "draft_id": row.id, "approval_id": row.approval_id, "approval_status": approval_status,
                    "target": row.target, "previous_status": row.status,
                }),
            )?;
            Ok(json!({
                "draft_id": row.id, "status": "cancelled", "approval_id": row.approval_id,
                "approval_status": approval_status,
            }))
        })
        .await
}

/// A human records the outcome of a send that has none: `uncertain`, or
/// `sending` long after its request must have ended. Never posts anything.
async fn resolve(ctx: ToolCtx, p: ResolveParams) -> UaResult<Value> {
    if !ctx.caller.is_human() {
        return Err(UaError::denied(
            "not_human",
            "recording a relay send's outcome needs a verified human who checked the thread",
        ));
    }
    let status = match p.outcome.as_str() {
        "delivered" => "sent",
        "not_delivered" => "failed",
        other => {
            return Err(UaError::invalid(format!(
                "outcome must be delivered or not_delivered, not {other:?}"
            )));
        }
    };
    let caller = ctx.caller.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let row = load(tx, p.draft_id)?;
            let stale = ua_core::time::parse_ts(&row.updated_at)
                .is_some_and(|t| ua_core::time::now_ms() / 1000 - t.as_second() > SENDING_STALE_SECS);
            match row.status.as_str() {
                "uncertain" => {}
                "sending" if stale => {}
                "sending" => {
                    return Err(UaError::conflict(format!(
                        "relay draft {} is still being sent; record its outcome once the request has ended",
                        row.id
                    )));
                }
                other => {
                    return Err(UaError::conflict(format!(
                        "relay draft {} is {other}; only an uncertain or stranded send can be resolved",
                        row.id
                    )));
                }
            }
            let now = ua_core::time::now();
            let reason = p.reason.as_deref().map(clip);
            let receipt = json!({ "manual": true, "delivered": status == "sent", "resolved_by": caller.label });
            tx.execute(
                "UPDATE relay_messages SET status = ?2, receipt = ?3, error = COALESCE(?4, error), updated_at = ?5, \
                 sent_at = CASE WHEN ?2 = 'sent' THEN ?5 ELSE sent_at END WHERE id = ?1",
                params![row.id, status, receipt.to_string(), reason, now],
            )?;
            emit(
                tx,
                &caller,
                "relay.resolved",
                json!({
                    "draft_id": row.id, "approval_id": row.approval_id, "target": row.target,
                    "previous_status": row.status, "outcome": p.outcome, "reason": reason,
                }),
            )?;
            Ok(json!({ "draft_id": row.id, "status": status, "previous_status": row.status, "reposted": false }))
        })
        .await
}

// --- registration ------------------------------------------------------------------------------

const ACTIONS: [&str; 8] = ["check", "draft", "request_send", "send", "status", "list", "cancel", "resolve"];

async fn relay_manage(ctx: ToolCtx, a: ManageArgs) -> UaResult<Value> {
    let action = a.action.trim().to_ascii_lowercase();
    let f = "relay";
    match action.as_str() {
        "check" => {
            let p = parse_params(f, &action, a.params)?;
            crate::registry::blocking(move || check(&ctx, p)).await
        }
        "draft" => draft(ctx, parse_params(f, &action, a.params)?).await,
        "request_send" => request_send(ctx, parse_params(f, &action, a.params)?).await,
        "send" => send(ctx, parse_params(f, &action, a.params)?).await,
        "status" => status(ctx, parse_params(f, &action, a.params)?).await,
        "list" => list(ctx, parse_params(f, &action, a.params)?).await,
        "cancel" => cancel(ctx, parse_params(f, &action, a.params)?).await,
        "resolve" => resolve(ctx, parse_params(f, &action, a.params)?).await,
        _ => Err(UaError::invalid(format!("action must be one of {ACTIONS:?}"))),
    }
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            TOOL,
            "Public relay: post an agent's message to a public surface (a comment on an issue or pull request in a \
             repository listed in relay_github_repos) only after public-safety gates pass and a human approves the \
             exact text. Actions: check (gates only), draft, request_send (parks the approval), send (repeat the \
             exact approved text), status, list, cancel, resolve (a human records an uncertain send's outcome). Gates refuse secrets, hidden or bidirectional Unicode, \
             private addresses and internal host names, home paths, e-mail addresses and other personal data, \
             over-long text and the operator's private denylist; they never rewrite the text.",
            relay_manage,
        )
        .gates_in_handler()
        .family("relay"),
    );
}

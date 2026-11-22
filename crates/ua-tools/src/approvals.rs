//! The approval queue.
//!
//! A gated call either consumes a matching one-time pass (same tool, same
//! canonical arguments, same requester, approved by a different human within
//! the pass TTL), fails with a recorded denial, or parks as `pending`. A retry
//! of an identical pending request reuses the existing row.

use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::{Caller, Config, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use crate::registry::{Registry, ToolCtx, blocking, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "approvals.v1",
    sql: "
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    requested_by TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','denied','consumed','revoked','expired')),
    reason TEXT,
    resolved_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    consumed_at TEXT,
    run_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_lookup ON approvals(tool, status, requested_by);
",
};

/// `approvals.resolved_transport`: which adapter the latest decision on the
/// row came through (`ui`, `http`, `mcp`, `cli`, `stdio`, `internal`,
/// `slack`), so an approval made from chat is told apart from one made in
/// the Control Center. Evidence only: no rule reads it. NULL for rows
/// resolved before this part.
///
/// `resolved_by`, `resolved_at` and `resolved_transport` always describe the
/// **latest** decision: approve or deny, then a revoke (through
/// `approval_resolve` or the relay withdrawing its draft) overwrites them.
/// The earlier decision is not lost: each `approval_resolve` decision is an
/// `agent.approval.resolved` ledger event with its own `resolved_by` and
/// `transport`, and a relay withdrawal is a `relay.cancelled` event with its
/// `transport`.
pub const SCHEMA_V2: SchemaPart = SchemaPart {
    name: "approvals.v2",
    sql: "
ALTER TABLE approvals ADD COLUMN resolved_transport TEXT;
",
};

/// The caller's transport as stored and ledgered (`"slack"`, `"ui"`, ...).
pub(crate) fn transport_name(caller: &Caller) -> String {
    serde_json::to_value(caller.transport)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

/// Result of the gate check for one call.
#[derive(Debug, Clone, PartialEq)]
pub enum GateOutcome {
    Pass { approval_id: i64 },
    Pending { approval_id: i64 },
    Denied { approval_id: i64, reason: Option<String> },
}

/// Canonical text form of arguments: sorted keys at every depth, no
/// whitespace ([`ua_core::canonical`], independent of serde_json's map order).
pub fn canonical_payload(args: &Value) -> String {
    ua_core::canonical::to_string(args)
}

/// The SHA-256 (hex) of the canonical form of an approval payload: what the
/// ledger events of an approval carry (`payload_sha256`, and on a refusal
/// `approved_payload_sha256` / `presented_payload_sha256`) so an auditor can
/// tie the request, the decision, the use and any refusal to one exact
/// payload without the ledger holding the payload itself.
///
/// The relay's message text leaves its approval once the approval is
/// decided; the text stays bound through the payload's `text_sha256`. Its
/// hash is therefore taken over the payload without the text fields, so it
/// is the same before and after the decision.
pub fn payload_sha256(tool: &str, payload: &Value) -> String {
    let form = if tool == crate::families::relay::TOOL {
        crate::families::relay::without_text(payload)
    } else {
        payload.clone()
    };
    canonical_sha256(&canonical_payload(&form))
}

/// SHA-256 (hex) of a canonical text.
pub(crate) fn canonical_sha256(canon: &str) -> String {
    hex::encode(Sha256::digest(canon.as_bytes()))
}

/// The top-level fields in which two payloads differ, by name, sorted. A
/// field present in only one of them counts.
pub fn changed_fields(approved: &Value, presented: &Value) -> Vec<String> {
    let empty = serde_json::Map::new();
    let a = approved.as_object().unwrap_or(&empty);
    let b = presented.as_object().unwrap_or(&empty);
    let mut keys: Vec<String> =
        a.keys().chain(b.keys()).filter(|k| a.get(*k) != b.get(*k)).cloned().collect();
    keys.sort();
    keys.dedup();
    keys
}

/// The ledger channel of a gated call refused because of its approval state.
pub const REFUSED: &str = "agent.approval.refused";

/// Why a gated call was refused because of its approval state: the
/// `reason` of an [`REFUSED`] event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// The approval that covered the call has expired.
    Expired,
    /// An approval exists for this action, but the call's arguments,
    /// revision or target differ from what it bound.
    BindingChanged,
    /// The call names an approval that does not exist or can no longer be
    /// used (spent or revoked), or it needs one that was never given.
    NoMatchingApproval,
    /// A human denied exactly this call.
    Denied,
    /// The approval binds this action but not this mode of it (a forced
    /// merge, or a merge of an unfinished task, under a policy
    /// authorization that does not allow it).
    NotCovered,
    /// The approval may not be used by this caller, or its approver no
    /// longer holds the authority (see `detail`).
    NotEligible,
}

impl RefusalReason {
    pub fn code(self) -> &'static str {
        match self {
            RefusalReason::Expired => "expired",
            RefusalReason::BindingChanged => "binding_changed",
            RefusalReason::NoMatchingApproval => "no_matching_approval",
            RefusalReason::Denied => "denied",
            RefusalReason::NotCovered => "not_covered",
            RefusalReason::NotEligible => "not_eligible",
        }
    }
}

/// One refusal as [`refused`] ledgers it. It identifies what the refusal was
/// about without carrying it: ids, payload hashes and field names, never
/// payload content.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub tool: String,
    pub reason: RefusalReason,
    /// The one-time approval involved, when there is one.
    pub approval_id: Option<i64>,
    /// The policy authorization involved, when there is one.
    pub authorization_id: Option<i64>,
    pub task_id: Option<i64>,
    /// [`payload_sha256`] of what the approval bound.
    pub approved_sha256: Option<String>,
    /// [`payload_sha256`] of what the refused call presented.
    pub presented_sha256: Option<String>,
    /// For `binding_changed`: the top-level fields that differ, by name.
    pub changed_fields: Vec<String>,
    /// The approval's status when it was not usable (`consumed`, `revoked`).
    pub approval_status: Option<String>,
    /// For `expired`: when the approval expired.
    pub expired_at: Option<String>,
    /// A short code refining the reason (`self_spend`, `authorizer_not_human`,
    /// `force`, `in_flight`).
    pub detail: Option<&'static str>,
    /// The tool the call came through, when it reached `tool` through another.
    pub via: Option<String>,
}

impl Refusal {
    pub fn new(tool: impl Into<String>, reason: RefusalReason) -> Self {
        Refusal {
            tool: tool.into(),
            reason,
            approval_id: None,
            authorization_id: None,
            task_id: None,
            approved_sha256: None,
            presented_sha256: None,
            changed_fields: Vec::new(),
            approval_status: None,
            expired_at: None,
            detail: None,
            via: None,
        }
    }

    pub fn approval(mut self, id: i64) -> Self {
        self.approval_id = Some(id);
        self
    }

    pub fn authorization(mut self, id: i64) -> Self {
        self.authorization_id = Some(id);
        self
    }

    pub fn task(mut self, id: Option<i64>) -> Self {
        self.task_id = id;
        self
    }

    pub fn hashes(mut self, approved: Option<String>, presented: Option<String>) -> Self {
        self.approved_sha256 = approved;
        self.presented_sha256 = presented;
        self
    }

    pub fn changed(mut self, fields: Vec<String>) -> Self {
        self.changed_fields = fields;
        self
    }

    pub fn status(mut self, status: impl Into<String>) -> Self {
        self.approval_status = Some(status.into());
        self
    }

    pub fn expired_at(mut self, at: Option<String>) -> Self {
        self.expired_at = at;
        self
    }

    pub fn detail(mut self, detail: &'static str) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn via(mut self, via: Option<&str>) -> Self {
        self.via = via.map(str::to_string);
        self
    }

    fn payload(&self, requested_by: &str) -> Value {
        let mut out = json!({
            "tool": self.tool,
            "reason": self.reason.code(),
            "requested_by": requested_by,
        });
        let fields: [(&str, Option<Value>); 10] = [
            ("approval_id", self.approval_id.map(Value::from)),
            ("authorization_id", self.authorization_id.map(Value::from)),
            ("task_id", self.task_id.map(Value::from)),
            ("approved_payload_sha256", self.approved_sha256.clone().map(Value::from)),
            ("presented_payload_sha256", self.presented_sha256.clone().map(Value::from)),
            ("changed_fields", (!self.changed_fields.is_empty()).then(|| json!(self.changed_fields))),
            ("approval_status", self.approval_status.clone().map(Value::from)),
            ("expired_at", self.expired_at.clone().map(Value::from)),
            ("detail", self.detail.map(Value::from)),
            ("via", self.via.clone().map(Value::from)),
        ];
        for (k, v) in fields {
            if let Some(v) = v {
                out[k] = v;
            }
        }
        out
    }
}

/// Ledger one refusal of `requested_by`'s call as an [`REFUSED`] event. The
/// event survives the refused call: appended with
/// [`ledger::append_surviving`], it is recorded even when the call's write
/// transaction then fails and rolls back. `dedupe` makes a repeat of the
/// same refusal fact (one expiry) a no-op. Every approval and authorization
/// row is in the default organization, so the event is too.
pub fn refused(
    tx: &mut WriteTx<'_>,
    requested_by: &str,
    r: &Refusal,
    dedupe: Option<String>,
) -> UaResult<()> {
    let mut input =
        EventInput::new(ua_core::DEFAULT_ORG, REFUSED, r.payload(requested_by)).by(requested_by.to_string());
    if let Some(k) = dedupe {
        input = input.dedupe(k);
    }
    ledger::append_surviving(tx, input)?;
    Ok(())
}

/// [`refused`] in a write of its own, for a refusal decided before any
/// write transaction was opened.
pub async fn refused_now(hub: &crate::Hub, requested_by: &str, r: Refusal) -> UaResult<()> {
    let who = requested_by.to_string();
    hub.db().write_async(move |tx| refused(tx, &who, &r, None)).await
}

/// A live pass for the same action bound to other values: what
/// [`stale_pass`] finds.
#[derive(Debug, Clone, PartialEq)]
pub struct Stale {
    pub approval_id: i64,
    /// The top-level fields in which the call differs from the pass.
    pub changed: Vec<String>,
    /// [`payload_sha256`] of the pass's payload.
    pub approved_sha256: String,
}

/// Live passes [`stale_pass`] looks at, newest first.
const STALE_SCAN: i64 = 200;

/// The newest live (approved, unexpired, unconsumed) pass of `requester`
/// for `tool` that agrees with `presented` on every `subject` field (the
/// same task, say) but differs from it elsewhere: the human approved this
/// action for other values (an older head, another target). `None` when
/// there is none, or when `subject` is empty.
pub fn stale_pass(
    c: &rusqlite::Connection,
    cfg: &Config,
    requester: &str,
    tool: &str,
    presented: &Value,
    subject: &[&str],
) -> UaResult<Option<Stale>> {
    if subject.is_empty() {
        return Ok(None);
    }
    let mut stmt = c.prepare(
        "SELECT id, payload, resolved_at FROM approvals WHERE tool = ?1 AND requested_by = ?2 \
         AND status = 'approved' ORDER BY id DESC LIMIT ?3",
    )?;
    let rows: Vec<(i64, String, Option<String>)> = stmt
        .query_map(params![tool, requester, STALE_SCAN], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    for (id, text, resolved_at) in rows {
        if pass_expired(cfg, resolved_at.as_deref()) {
            continue;
        }
        let Ok(old) = serde_json::from_str::<Value>(&text) else { continue };
        if subject.iter().any(|k| old.get(*k).is_none() || old.get(*k) != presented.get(*k)) {
            continue;
        }
        let changed = changed_fields(&old, presented);
        if !changed.is_empty() {
            return Ok(Some(Stale { approval_id: id, changed, approved_sha256: payload_sha256(tool, &old) }));
        }
    }
    Ok(None)
}

/// When a pass resolved at `resolved_at` expires under the configured TTL.
pub(crate) fn pass_expires_at(cfg: &Config, resolved_at: Option<&str>) -> Option<String> {
    let ttl_s = (cfg.approval_pass_ttl_hours * 3600.0) as i64;
    resolved_at
        .and_then(ua_core::time::parse_ts)
        .and_then(|t| t.checked_add(jiff::SignedDuration::from_secs(ttl_s)).ok())
        .map(ua_core::time::format_ts)
}

pub(crate) fn pass_expired(cfg: &Config, resolved_at: Option<&str>) -> bool {
    let Some(ts) = resolved_at.and_then(ua_core::time::parse_ts) else { return true };
    let age_s = (jiff_now_s() - ts.as_second()) as f64;
    age_s > cfg.approval_pass_ttl_hours * 3600.0
}

fn jiff_now_s() -> i64 {
    ua_core::time::now_ms() / 1000
}

/// Evaluate the gate for one call inside the caller's write transaction.
pub fn gate(
    tx: &mut WriteTx<'_>,
    cfg: &Config,
    caller: &Caller,
    tool: &str,
    args: &Value,
) -> UaResult<GateOutcome> {
    gate_via(tx, cfg, caller, tool, args, None)
}

/// [`gate`] for a call that reached `tool` through another tool `via` (a
/// consolidated tool's action, see [`crate::routes`]). The approval binds
/// `tool` and `args` exactly as a direct call would; the ledger events of
/// the request and of the pass it consumes also name `via`.
pub fn gate_via(
    tx: &mut WriteTx<'_>,
    cfg: &Config,
    caller: &Caller,
    tool: &str,
    args: &Value,
    via: Option<&str>,
) -> UaResult<GateOutcome> {
    let canon = canonical_payload(args);
    let sha = payload_sha256(tool, args);
    let now = ua_core::time::now();
    let task_id = args.get("task_id").and_then(Value::as_i64);

    // A recorded denial of this exact call wins.
    let denied: Option<(i64, Option<String>)> = tx
        .query_row(
            "SELECT id, reason FROM approvals WHERE tool = ?1 AND payload = ?2 AND requested_by = ?3 \
             AND status = 'denied' ORDER BY id DESC LIMIT 1",
            params![tool, canon, caller.label],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((approval_id, reason)) = denied {
        let r = Refusal::new(tool, RefusalReason::Denied)
            .approval(approval_id)
            .task(task_id)
            .hashes(Some(sha.clone()), Some(sha))
            .via(via);
        refused(tx, &caller.label, &r, None)?;
        return Ok(GateOutcome::Denied { approval_id, reason });
    }

    // Consume the oldest live pass.
    let passes: Vec<(i64, Option<String>)> = {
        let mut stmt = tx.prepare(
            "SELECT id, resolved_at FROM approvals WHERE tool = ?1 AND payload = ?2 AND requested_by = ?3 \
             AND status = 'approved' ORDER BY id ASC",
        )?;
        stmt.query_map(params![tool, canon, caller.label], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?
    };
    // The newest pass found expired, if no live one covers the call.
    let mut lapsed: Option<(i64, Option<String>)> = None;
    for (id, resolved_at) in passes {
        if pass_expired(cfg, resolved_at.as_deref()) {
            tx.execute(
                "UPDATE approvals SET status = 'expired', updated_at = ?2 WHERE id = ?1",
                params![id, now],
            )?;
            lapsed = Some((id, resolved_at));
            continue;
        }
        tx.execute(
            "UPDATE approvals SET status = 'consumed', consumed_at = ?2, updated_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        let mut event = json!({ "approval_id": id, "tool": tool, "payload_sha256": sha });
        if let Some(v) = via {
            event["via"] = json!(v);
        }
        ledger::append(
            tx,
            EventInput::new(ua_core::DEFAULT_ORG, "agent.approval.consumed", event).by(caller.label.clone()),
        )?;
        return Ok(GateOutcome::Pass { approval_id: id });
    }
    if let Some((id, resolved_at)) = lapsed {
        // The call parks a new request below; the expiry that refused it is
        // ledgered once per pass, even if this transaction rolls back.
        let r = Refusal::new(tool, RefusalReason::Expired)
            .approval(id)
            .task(task_id)
            .hashes(Some(sha.clone()), Some(sha.clone()))
            .expired_at(pass_expires_at(cfg, resolved_at.as_deref()))
            .via(via);
        refused(tx, &caller.label, &r, Some(format!("{REFUSED}:expired:{id}")))?;
    }

    // Reuse an identical pending request, or park a new one.
    let pending: Option<i64> = tx
        .query_row(
            "SELECT id FROM approvals WHERE tool = ?1 AND payload = ?2 AND requested_by = ?3 \
             AND status = 'pending' ORDER BY id ASC LIMIT 1",
            params![tool, canon, caller.label],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(approval_id) = pending {
        return Ok(GateOutcome::Pending { approval_id });
    }
    park(tx, caller, tool, &canon, &now, via).map(|approval_id| GateOutcome::Pending { approval_id })
}

/// [`payload_sha256`] of a payload already in canonical text form.
fn canonical_sha256_of(tool: &str, canon: &str) -> String {
    match serde_json::from_str::<Value>(canon) {
        Ok(v) => payload_sha256(tool, &v),
        Err(_) => canonical_sha256(canon),
    }
}

/// Insert a pending request for `canon` and ledger it.
fn park(
    tx: &mut WriteTx<'_>,
    caller: &Caller,
    tool: &str,
    canon: &str,
    now: &str,
    via: Option<&str>,
) -> UaResult<i64> {
    tx.execute(
        "INSERT INTO approvals (tool, payload, requested_by, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'pending', ?4, ?4)",
        params![tool, canon, caller.label, now],
    )?;
    let approval_id = tx.last_insert_rowid();
    let mut event = json!({
        "approval_id": approval_id,
        "tool": tool,
        "requested_by": caller.label,
        "payload_sha256": canonical_sha256_of(tool, canon),
    });
    if let Some(v) = via {
        event["via"] = json!(v);
    }
    ledger::append(
        tx,
        EventInput::new(ua_core::DEFAULT_ORG, "agent.approval.requested", event).by(caller.label.clone()),
    )?;
    Ok(approval_id)
}

/// Where an approval for one exact call stands, without consuming a pass.
#[derive(Debug, Clone, PartialEq)]
pub enum RequestState {
    /// A live, unconsumed pass: the call would run.
    Approved {
        approval_id: i64,
    },
    Pending {
        approval_id: i64,
    },
    Denied {
        approval_id: i64,
        reason: Option<String>,
    },
}

impl RequestState {
    pub fn approval_id(&self) -> i64 {
        match self {
            RequestState::Approved { approval_id }
            | RequestState::Pending { approval_id }
            | RequestState::Denied { approval_id, .. } => *approval_id,
        }
    }

    pub fn status(&self) -> &'static str {
        match self {
            RequestState::Approved { .. } => "approved",
            RequestState::Pending { .. } => "pending",
            RequestState::Denied { .. } => "denied",
        }
    }
}

/// The state of `requester`'s approval for this exact call, read-only: a
/// denial wins (as in [`gate`]), then a live pass, then a pending request.
/// `None` when nothing was asked yet.
pub fn peek(
    c: &rusqlite::Connection,
    cfg: &Config,
    requester: &str,
    tool: &str,
    args: &Value,
) -> UaResult<Option<RequestState>> {
    let canon = canonical_payload(args);
    let denied: Option<(i64, Option<String>)> = c
        .query_row(
            "SELECT id, reason FROM approvals WHERE tool = ?1 AND payload = ?2 AND requested_by = ?3 \
             AND status = 'denied' ORDER BY id DESC LIMIT 1",
            params![tool, canon, requester],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((approval_id, reason)) = denied {
        return Ok(Some(RequestState::Denied { approval_id, reason }));
    }
    let mut stmt = c.prepare(
        "SELECT id, resolved_at FROM approvals WHERE tool = ?1 AND payload = ?2 AND requested_by = ?3 \
         AND status = 'approved' ORDER BY id ASC",
    )?;
    let passes: Vec<(i64, Option<String>)> = stmt
        .query_map(params![tool, canon, requester], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    if let Some((approval_id, _)) = passes.into_iter().find(|(_, at)| !pass_expired(cfg, at.as_deref())) {
        return Ok(Some(RequestState::Approved { approval_id }));
    }
    let pending: Option<i64> = c
        .query_row(
            "SELECT id FROM approvals WHERE tool = ?1 AND payload = ?2 AND requested_by = ?3 \
             AND status = 'pending' ORDER BY id ASC LIMIT 1",
            params![tool, canon, requester],
            |r| r.get(0),
        )
        .optional()?;
    Ok(pending.map(|approval_id| RequestState::Pending { approval_id }))
}

/// Ask for an approval of this exact call without running it: report a
/// pass, denial or pending request that already exists, else park a new
/// pending request. Never consumes a pass; [`gate`] does that when the call
/// runs.
pub fn request(
    tx: &mut WriteTx<'_>,
    cfg: &Config,
    caller: &Caller,
    tool: &str,
    args: &Value,
) -> UaResult<RequestState> {
    if let Some(state) = peek(tx, cfg, &caller.label, tool, args)? {
        return Ok(state);
    }
    let now = ua_core::time::now();
    let approval_id = park(tx, caller, tool, &canonical_payload(args), &now, None)?;
    Ok(RequestState::Pending { approval_id })
}

/// One approval row as returned to clients.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalRow {
    pub id: i64,
    pub tool: String,
    pub payload: Value,
    pub requested_by: Option<String>,
    pub status: String,
    pub reason: Option<String>,
    pub resolved_by: Option<String>,
    /// The adapter the latest decision came through (`ui`, `http`, `mcp`,
    /// `cli`, `stdio`, `internal`, `slack`); `None` for a row resolved before
    /// this was recorded. See [`SCHEMA_V2`] for the latest-decision rule.
    pub resolved_transport: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub resolved_at: Option<String>,
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// What the approver is shown beside the payload (in `approval_pending`
    /// for pending requests, and in [`get`]) for a tool that keeps more than
    /// its approval binds (the full diff of a
    /// `harness_config_apply`). Never compared: the payload alone is the
    /// binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Value>,
}

/// Display-only detail for a pending approval ([`ApprovalRow::display`]).
fn display(c: &rusqlite::Connection, row: &ApprovalRow) -> UaResult<Option<Value>> {
    if row.tool == crate::families::harness_config::APPLY_TOOL {
        return crate::families::harness_config::approval_display(c, row.id, &row.payload);
    }
    Ok(None)
}

fn row_to_approval(r: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRow> {
    let payload: String = r.get("payload")?;
    Ok(ApprovalRow {
        id: r.get("id")?,
        tool: r.get("tool")?,
        payload: serde_json::from_str(&payload).unwrap_or(Value::String(payload)),
        requested_by: r.get("requested_by")?,
        status: r.get("status")?,
        reason: r.get("reason")?,
        resolved_by: r.get("resolved_by")?,
        resolved_transport: r.get("resolved_transport")?,
        created_at: r.get("created_at")?,
        updated_at: r.get("updated_at")?,
        resolved_at: r.get("resolved_at")?,
        run_id: r.get("run_id")?,
        expires_at: None,
        display: None,
    })
}

/// One approval row, with its display-only detail ([`ApprovalRow::display`])
/// whatever its status, so every reader of one approval sees what the
/// approver saw.
pub fn get(conn: &rusqlite::Connection, id: i64) -> UaResult<ApprovalRow> {
    let mut row = conn
        .query_row("SELECT * FROM approvals WHERE id = ?1", [id], row_to_approval)
        .optional()?
        .ok_or_else(|| UaError::not_found(format!("approval {id}")))?;
    row.display = display(conn, &row)?;
    Ok(row)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PendingArgs {
    /// Only rows for this tool.
    pub tool: Option<String>,
    /// Maximum rows per bucket, 1-500.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Keep the newest expired passes instead of the oldest.
    #[serde(default)]
    pub newest_expired: bool,
}

/// Most approved rows `approval_pending` reads to split live from expired
/// passes.
const APPROVED_SCAN: i64 = 2000;

fn default_limit() -> i64 {
    100
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolveArgs {
    /// Approval id.
    pub id: i64,
    /// `approve`, `deny` or `revoke`.
    pub decision: String,
    /// Ignored when the caller is verified; the verified identity is used.
    pub resolved_by: Option<String>,
    pub reason: Option<String>,
}

fn list_pending(ctx: &ToolCtx, args: PendingArgs) -> UaResult<Value> {
    let limit = args.limit.clamp(1, 500) as usize;
    let cfg = ctx.hub.cfg().clone();
    ctx.hub.db().read(|c| {
        let tool_filter = args.tool.clone();
        // Bounded in SQL: the oldest `limit` pending requests, and the newest
        // APPROVED_SCAN approved rows (live passes are recent; older ones
        // are only counted).
        let mut stmt = c.prepare(
            "SELECT * FROM approvals WHERE status = 'pending' AND (?1 IS NULL OR tool = ?1) ORDER BY id ASC LIMIT ?2",
        )?;
        let mut pending: Vec<ApprovalRow> =
            stmt.query_map(params![tool_filter, limit as i64], row_to_approval)?.collect::<Result<_, _>>()?;
        for a in &mut pending {
            a.display = display(c, a)?;
        }
        let mut stmt = c.prepare(
            "SELECT * FROM approvals WHERE status = 'approved' AND (?1 IS NULL OR tool = ?1) \
             ORDER BY id DESC LIMIT ?2",
        )?;
        let mut approved: Vec<ApprovalRow> =
            stmt.query_map(params![tool_filter, APPROVED_SCAN], row_to_approval)?.collect::<Result<_, _>>()?;
        approved.reverse();
        let approved_total: i64 = c.query_row(
            "SELECT COUNT(*) FROM approvals WHERE status = 'approved' AND (?1 IS NULL OR tool = ?1)",
            params![tool_filter],
            |r| r.get(0),
        )?;
        let (mut live, mut expired): (Vec<_>, Vec<_>) =
            approved.into_iter().partition(|a| !pass_expired(&cfg, a.resolved_at.as_deref()));
        for a in live.iter_mut().chain(expired.iter_mut()) {
            a.expires_at = pass_expires_at(&cfg, a.resolved_at.as_deref());
        }
        // Approved rows past the scan are old, so expired.
        let expired_total = usize::try_from(approved_total).unwrap_or(0).saturating_sub(live.len());
        live.truncate(limit);
        if args.newest_expired && expired.len() > limit {
            expired.drain(..expired.len() - limit);
        } else {
            expired.truncate(limit);
        }
        let mut out = json!({
            "pending": pending,
            "approved_unconsumed": live,
            "expired_passes": expired,
            "gated_tools": cfg.approval_tools,
            "pass_ttl_hours": cfg.approval_pass_ttl_hours,
        });
        if args.newest_expired {
            out["expired_passes_total"] = json!(expired_total);
        }
        Ok(out)
    })
}

fn resolve(ctx: &ToolCtx, args: ResolveArgs) -> UaResult<Value> {
    let caller = ctx.caller.clone();
    let cfg = ctx.hub.cfg().clone();
    ctx.hub.db().write(|tx| {
        let row = get(tx, args.id)?;
        // The resolver is always the caller. `resolved_by` is accepted for
        // contract compatibility but never trusted: an unverified caller
        // naming a human must not be able to approve as that human.
        let resolver = caller.label.clone();
        if let Some(claimed) = args.resolved_by.as_deref().map(str::trim).filter(|s| !s.is_empty())
            && claimed != resolver
        {
            return Err(UaError::denied(
                "resolver_mismatch",
                format!("resolved_by {claimed:?} does not match the caller {resolver:?}"),
            ));
        }
        let now = ua_core::time::now();
        let new_status = match args.decision.as_str() {
            "approve" => {
                if row.status != "pending" {
                    return Err(UaError::conflict(format!("approval {} is {}, not pending", row.id, row.status)));
                }
                if !caller.is_human() {
                    return Err(UaError::denied(
                        "not_human",
                        "only a verified human operator can approve (a human bearer token, or `ua call --label <human>` on the hub host)",
                    ));
                }
                if row.requested_by.as_deref() == Some(resolver.as_str()) {
                    return Err(UaError::denied("self_approval", "the approver must differ from the requester"));
                }
                "approved"
            }
            "deny" => {
                if row.status != "pending" {
                    return Err(UaError::conflict(format!("approval {} is {}, not pending", row.id, row.status)));
                }
                "denied"
            }
            "revoke" => {
                if row.status != "approved" {
                    return Err(UaError::conflict(format!(
                        "only an unconsumed approved pass can be revoked; approval {} is {}",
                        row.id, row.status
                    )));
                }
                "revoked"
            }
            other => return Err(UaError::invalid(format!("decision must be approve, deny or revoke, not {other:?}"))),
        };
        if new_status != "approved" && !caller.is_human() {
            // Deny and revoke stay open to the requester.
            if row.requested_by.as_deref() != Some(resolver.as_str()) {
                return Err(UaError::denied("not_human", "only a human or the requester can deny or revoke"));
            }
        }
        let transport = transport_name(&caller);
        tx.execute(
            "UPDATE approvals SET status = ?2, reason = ?3, resolved_by = ?4, resolved_at = ?5, updated_at = ?5, \
             resolved_transport = ?6 WHERE id = ?1",
            params![row.id, new_status, args.reason, resolver, now, transport],
        )?;
        if row.tool == crate::families::relay::TOOL {
            // The relay keeps a message's text in its approval only while
            // the approval is pending, and drops a withdrawn draft's text.
            crate::families::relay::approval_decided(tx, &caller, &row, new_status)?;
        }
        let mut event = json!({
            "approval_id": row.id,
            "tool": row.tool,
            "decision": args.decision,
            "resolved_by": resolver,
            "transport": transport,
            "payload_sha256": payload_sha256(&row.tool, &row.payload),
        });
        if new_status == "approved" {
            // The expiry under the TTL configured when the human approved.
            event["expires_at"] = json!(pass_expires_at(&cfg, Some(&now)));
        }
        ledger::append(
            tx,
            EventInput::new(ua_core::DEFAULT_ORG, "agent.approval.resolved", event).by(caller.label.clone()),
        )?;
        Ok(json!({ "ok": true, "approval": get(tx, row.id)? }))
    })
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "approval_pending",
            "List queued approval requests oldest-first, split into pending, live one-shot passes and expired passes.",
            |ctx: ToolCtx, a: PendingArgs| blocking(move || list_pending(&ctx, a)),
        )
        .family("approvals")
        .read_only(),
    );
    r.add(
        tool(
            "approval_resolve",
            "Approve, deny or revoke one approval. Approve needs a human approver different from the requester.",
            |ctx: ToolCtx, a: ResolveArgs| blocking(move || resolve(&ctx, a)),
        )
        .family("approvals"),
    );
}

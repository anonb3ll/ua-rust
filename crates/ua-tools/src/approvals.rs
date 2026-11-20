//! The approval queue.
//!
//! A gated call either consumes a matching one-time pass (same tool, same
//! canonical arguments, same requester, approved by a different human within
//! the pass TTL), fails with a recorded denial, or parks as `pending`. A retry
//! of an identical pending request reuses the existing row.
//!
//! An **ad-hoc** request ([`request_ad_hoc`], `ad_hoc = 1`) asks a human to
//! sign off on a call of a tool that nothing gates (`POST
//! /api/approvals/request`). It is resolved like any request (a verified
//! human other than the requester approves), but an approved ad-hoc row is a
//! standalone sign-off, not a pass: [`gate`] never consumes, reuses or
//! matches one, and it does not expire with the pass TTL.

use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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

/// Ad-hoc sign-off requests: see the module docs.
pub const SCHEMA_V2: SchemaPart = SchemaPart {
    name: "approvals.v2",
    sql: "
ALTER TABLE approvals ADD COLUMN ad_hoc INTEGER NOT NULL DEFAULT 0;
",
};

/// Result of the gate check for one call.
#[derive(Debug, Clone, PartialEq)]
pub enum GateOutcome {
    Pass { approval_id: i64 },
    Pending { approval_id: i64 },
    Denied { approval_id: i64, reason: Option<String> },
}

/// Canonical text form of arguments: sorted keys, no whitespace.
pub fn canonical_payload(args: &Value) -> String {
    // serde_json's default map is ordered by key, so this is canonical.
    serde_json::to_string(args).unwrap_or_else(|_| "{}".into())
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
    let canon = canonical_payload(args);
    let now = ua_core::time::now();

    // A recorded denial of this exact call wins.
    let denied: Option<(i64, Option<String>)> = tx
        .query_row(
            "SELECT id, reason FROM approvals WHERE tool = ?1 AND payload = ?2 AND requested_by = ?3 \
             AND status = 'denied' AND ad_hoc = 0 ORDER BY id DESC LIMIT 1",
            params![tool, canon, caller.label],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((approval_id, reason)) = denied {
        return Ok(GateOutcome::Denied { approval_id, reason });
    }

    // Consume the oldest live pass.
    let passes: Vec<(i64, Option<String>)> = {
        let mut stmt = tx.prepare(
            "SELECT id, resolved_at FROM approvals WHERE tool = ?1 AND payload = ?2 AND requested_by = ?3 \
             AND status = 'approved' AND ad_hoc = 0 ORDER BY id ASC",
        )?;
        stmt.query_map(params![tool, canon, caller.label], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?
    };
    for (id, resolved_at) in passes {
        if pass_expired(cfg, resolved_at.as_deref()) {
            tx.execute(
                "UPDATE approvals SET status = 'expired', updated_at = ?2 WHERE id = ?1",
                params![id, now],
            )?;
            continue;
        }
        tx.execute(
            "UPDATE approvals SET status = 'consumed', consumed_at = ?2, updated_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        ledger::append(
            tx,
            EventInput::new("agent.approval.consumed", json!({ "approval_id": id, "tool": tool }))
                .by(caller.label.clone()),
        )?;
        return Ok(GateOutcome::Pass { approval_id: id });
    }

    // Reuse an identical pending request, or park a new one.
    let pending: Option<i64> = tx
        .query_row(
            "SELECT id FROM approvals WHERE tool = ?1 AND payload = ?2 AND requested_by = ?3 \
             AND status = 'pending' AND ad_hoc = 0 ORDER BY id ASC LIMIT 1",
            params![tool, canon, caller.label],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(approval_id) = pending {
        return Ok(GateOutcome::Pending { approval_id });
    }
    tx.execute(
        "INSERT INTO approvals (tool, payload, requested_by, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'pending', ?4, ?4)",
        params![tool, canon, caller.label, now],
    )?;
    let approval_id = tx.last_insert_rowid();
    ledger::append(
        tx,
        EventInput::new(
            "agent.approval.requested",
            json!({ "approval_id": approval_id, "tool": tool, "requested_by": caller.label }),
        )
        .by(caller.label.clone()),
    )?;
    Ok(GateOutcome::Pending { approval_id })
}

/// Queue an ad-hoc sign-off request for a call nothing gates, inside the
/// caller's write transaction. Nothing runs and nothing is consumed: a
/// recorded denial of the identical request answers `Denied`, an approved
/// identical sign-off answers `Pass` (left as it is), an identical pending
/// request is reused, and otherwise a new `pending` row with `ad_hoc = 1` is
/// parked and ledgered.
pub fn request_ad_hoc(
    tx: &mut WriteTx<'_>,
    caller: &Caller,
    tool: &str,
    args: &Value,
) -> UaResult<GateOutcome> {
    let canon = canonical_payload(args);
    let latest: Option<(i64, String, Option<String>)> = tx
        .query_row(
            "SELECT id, status, reason FROM approvals WHERE tool = ?1 AND payload = ?2 AND requested_by = ?3 \
             AND ad_hoc = 1 AND status IN ('pending', 'approved', 'denied') ORDER BY id DESC LIMIT 1",
            params![tool, canon, caller.label],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    match latest {
        Some((approval_id, status, _)) if status == "pending" => {
            return Ok(GateOutcome::Pending { approval_id });
        }
        Some((approval_id, status, _)) if status == "approved" => {
            return Ok(GateOutcome::Pass { approval_id });
        }
        Some((approval_id, _, reason)) => return Ok(GateOutcome::Denied { approval_id, reason }),
        None => {}
    }
    let now = ua_core::time::now();
    tx.execute(
        "INSERT INTO approvals (tool, payload, requested_by, status, created_at, updated_at, ad_hoc) \
         VALUES (?1, ?2, ?3, 'pending', ?4, ?4, 1)",
        params![tool, canon, caller.label, now],
    )?;
    let approval_id = tx.last_insert_rowid();
    ledger::append(
        tx,
        EventInput::new(
            "agent.approval.requested",
            json!({ "approval_id": approval_id, "tool": tool, "requested_by": caller.label, "ad_hoc": true }),
        )
        .by(caller.label.clone()),
    )?;
    Ok(GateOutcome::Pending { approval_id })
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
    pub created_at: String,
    pub updated_at: String,
    pub resolved_at: Option<String>,
    pub run_id: Option<String>,
    /// A standalone sign-off for a call nothing gates; never consumed.
    pub ad_hoc: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
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
        created_at: r.get("created_at")?,
        updated_at: r.get("updated_at")?,
        resolved_at: r.get("resolved_at")?,
        run_id: r.get("run_id")?,
        ad_hoc: r.get::<_, i64>("ad_hoc")? != 0,
        expires_at: None,
    })
}

pub fn get(conn: &rusqlite::Connection, id: i64) -> UaResult<ApprovalRow> {
    conn.query_row("SELECT * FROM approvals WHERE id = ?1", [id], row_to_approval)
        .optional()?
        .ok_or_else(|| UaError::not_found(format!("approval {id}")))
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
        let fetch = |status: &str| -> UaResult<Vec<ApprovalRow>> {
            let mut stmt = c.prepare(
                "SELECT * FROM approvals WHERE status = ?1 AND (?2 IS NULL OR tool = ?2) ORDER BY id ASC",
            )?;
            let rows = stmt.query_map(params![status, tool_filter], row_to_approval)?;
            Ok(rows.collect::<Result<_, _>>()?)
        };
        let mut pending = fetch("pending")?;
        pending.truncate(limit);
        // Approved ad-hoc rows are sign-offs, not passes: listed apart, with
        // no expiry.
        let (mut ad_hoc, passes): (Vec<_>, Vec<_>) = fetch("approved")?.into_iter().partition(|a| a.ad_hoc);
        ad_hoc.truncate(limit);
        let (mut live, mut expired): (Vec<_>, Vec<_>) =
            passes.into_iter().partition(|a| !pass_expired(&cfg, a.resolved_at.as_deref()));
        let ttl_s = (cfg.approval_pass_ttl_hours * 3600.0) as i64;
        for a in live.iter_mut().chain(expired.iter_mut()) {
            a.expires_at = a
                .resolved_at
                .as_deref()
                .and_then(ua_core::time::parse_ts)
                .and_then(|t| t.checked_add(jiff::SignedDuration::from_secs(ttl_s)).ok())
                .map(ua_core::time::format_ts);
        }
        let expired_total = expired.len();
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
            "ad_hoc_approved": ad_hoc,
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
        tx.execute(
            "UPDATE approvals SET status = ?2, reason = ?3, resolved_by = ?4, resolved_at = ?5, updated_at = ?5 \
             WHERE id = ?1",
            params![row.id, new_status, args.reason, resolver, now],
        )?;
        if row.tool == crate::families::relay::TOOL {
            // The relay keeps a message's text in its approval only while
            // the approval is pending, and drops a withdrawn draft's text.
            crate::families::relay::approval_decided(tx, &caller, &row, new_status)?;
        }
        ledger::append(
            tx,
            EventInput::new(
                "agent.approval.resolved",
                json!({
                    "approval_id": row.id, "tool": row.tool, "decision": args.decision, "resolved_by": resolver,
                    "ad_hoc": row.ad_hoc,
                }),
            )
            .by(caller.label.clone()),
        )?;
        Ok(json!({ "ok": true, "approval": get(tx, row.id)? }))
    })
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "approval_pending",
            "List queued approval requests oldest-first, split into pending, live one-shot passes, expired passes \
             and approved ad-hoc sign-offs (ad_hoc: true rows for calls nothing gates; never consumed).",
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

#[cfg(test)]
mod tests {
    use ua_core::identity::Transport;
    use ua_core::{ActorKind, Profile};

    use super::*;

    #[test]
    fn the_gate_never_consumes_an_ad_hoc_sign_off() {
        let cfg = Config::for_home(std::env::temp_dir());
        let hub = crate::Hub::in_memory(cfg.clone()).unwrap();
        let who = Caller {
            label: "builder-1".into(),
            kind: ActorKind::Agent,
            profile: Profile::Developer,
            enforce_profile: true,
            session_key: None,
            transport: Transport::Http,
        };
        let args = json!({ "id": 1, "append_note": "x" });
        let (c, a) = (who.clone(), args.clone());
        let ad_hoc = hub.db().write(move |tx| request_ad_hoc(tx, &c, "task_update", &a)).unwrap();
        let GateOutcome::Pending { approval_id } = ad_hoc else { panic!("{ad_hoc:?}") };
        hub.db()
            .write(|tx| {
                tx.execute(
                    "UPDATE approvals SET status = 'approved', resolved_by = 'operator', resolved_at = ?2 WHERE id = ?1",
                    params![approval_id, ua_core::time::now()],
                )?;
                Ok(())
            })
            .unwrap();
        // Were the tool gated later, the identical call parks its own request
        // instead of consuming the sign-off.
        let (c, a, cf) = (who.clone(), args.clone(), cfg.clone());
        let out = hub.db().write(move |tx| gate(tx, &cf, &c, "task_update", &a)).unwrap();
        let GateOutcome::Pending { approval_id: parked } = out else { panic!("{out:?}") };
        assert_ne!(parked, approval_id);
        let row = hub.db().read(|c| get(c, approval_id)).unwrap();
        assert_eq!((row.status.as_str(), row.ad_hoc), ("approved", true));
        assert!(!hub.db().read(|c| get(c, parked)).unwrap().ad_hoc);
        // A repeated ad-hoc request reports the sign-off, unconsumed.
        let out = hub.db().write(move |tx| request_ad_hoc(tx, &who, "task_update", &args)).unwrap();
        assert_eq!(out, GateOutcome::Pass { approval_id });
        assert_eq!(hub.db().read(|c| get(c, approval_id)).unwrap().status, "approved");
    }
}

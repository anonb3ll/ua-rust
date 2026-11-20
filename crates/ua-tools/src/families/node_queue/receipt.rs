//! Receipts: how a node reports what became of a claimed item, and how the
//! hub settles the item's dispatch run from it.

use rusqlite::params;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};
use ua_store::WriteTx;

use super::{
    acceptance, check_item_id, clip, close_linked_run, command, credentials, device_agent, evidence_ref,
    load_item, now, owned_node, record, relay,
};
use crate::families::audit::rules::redact_secrets;
use crate::registry::{Registry, ToolCtx, tool};

/// Statuses a node may report.
pub const RECEIPT_STATUSES: [&str; 3] = ["finished", "failed", "killed"];

fn text(m: &Map<String, Value>, key: &str, max: usize) -> Value {
    m.get(key).and_then(Value::as_str).map_or(Value::Null, |s| json!(clip(s, max)))
}

/// Free text the node wrote: credential-shaped spans redacted, then bounded.
fn free_text(m: &Map<String, Value>, key: &str, max: usize) -> Option<String> {
    m.get(key).and_then(Value::as_str).map(|s| clip(&redact_secrets(s).0, max))
}

/// The stored form of a receipt: known fields only, each bounded, and its
/// free text (`text`, `reason`, `log_capture.error`) redacted.
pub(crate) fn bounded(m: &Map<String, Value>, node: &str) -> Value {
    let files: Vec<Value> = m
        .get("files_modified")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).take(200).map(|s| json!(clip(s, 500))).collect())
        .unwrap_or_default();
    let exit_code = match m.get("exit_code") {
        Some(Value::Number(n)) if n.is_i64() => json!(n.as_i64()),
        _ => Value::Null,
    };
    let attempt = match m.get("attempt") {
        Some(Value::Number(n)) if n.is_i64() => json!(n.as_i64()),
        _ => Value::Null,
    };
    let log_capture = m.get("log_capture").and_then(Value::as_object).map(|lc| {
        let state = lc
            .get("state")
            .and_then(Value::as_str)
            .filter(|s| ["pending", "complete", "error", "unknown"].contains(s))
            .unwrap_or("unknown");
        json!({
            "state": state,
            "truncated": lc.get("truncated").and_then(Value::as_bool),
            "error": free_text(lc, "error", 300),
            "state_path": text(lc, "state_path", 500),
        })
    });
    json!({
        "status": m.get("status").and_then(Value::as_str).unwrap_or(""),
        "reason": free_text(m, "reason", 300),
        "text": free_text(m, "text", 8000).unwrap_or_default(),
        "exit_code": exit_code,
        "backend_status": text(m, "backend_status", 40),
        "files_modified": files,
        "started_at": text(m, "started_at", 40),
        "finished_at": text(m, "finished_at", 40),
        "attempt": attempt,
        "session_id": text(m, "session_id", 200),
        "log_path": text(m, "log_path", 500),
        "truncated": m.get("truncated").and_then(Value::as_bool).unwrap_or(false),
        "log_capture": log_capture,
        "recorded_at": now(),
        "node": node,
    })
}

/// `Ok(Err(refusal))` is a refusal whose ledger record must still commit.
type Posted = UaResult<Result<Value, UaError>>;

fn post(
    tx: &mut WriteTx<'_>,
    cfg: &ua_core::Config,
    agent: &str,
    node: &str,
    id: &str,
    receipt: &Map<String, Value>,
) -> Posted {
    let row = owned_node(tx, node, agent)?;
    let node = row.node;
    let Some(item) = load_item(tx, id)?.filter(|i| i.node == node) else {
        return Err(UaError::not_found(format!("item {id} is not queued for node {node:?}")));
    };
    let status = receipt.get("status").and_then(Value::as_str).unwrap_or("");
    if let Some(first) = item.receipt() {
        if first["hub_generated"] == json!(true) {
            return Err(UaError::conflict_code(
                "outcome_unknown",
                format!(
                    "item {id} was failed by the hub ({}); execution outcome requires reconciliation",
                    first["reason"].as_str().unwrap_or("hub_generated")
                ),
            ));
        }
        // A retry of a stored receipt: the first one stands. Settling the
        // run is retried in case it was refused the first time.
        let first_status = first["status"].as_str().unwrap_or(&item.status).to_string();
        let reason = first["reason"].as_str().map(str::to_string);
        let run = close_linked_run(tx, &item, &first_status, reason.as_deref(), agent, true)?;
        return Ok(Ok(json!({
            "item_id": id, "duplicate": true, "status": item.status, "run_outcome": run, "receipt": first,
        })));
    }
    if let Some(a) = receipt.get("attempt").and_then(Value::as_i64)
        && a != item.attempts
    {
        return Err(UaError::conflict_code(
            "stale_attempt",
            format!("stale receipt: attempt {a} is not the latest claim ({})", item.attempts),
        ));
    }
    if item.status != "claimed" {
        return Err(UaError::conflict(format!("item {id} is {}, not claimed", item.status)));
    }
    if item.backend == "command" {
        let token = receipt.get("fence_token").and_then(Value::as_str).unwrap_or("");
        if let Err(e) = command::check_fence(tx, &item, token) {
            record(
                tx,
                "stale_fence",
                json!({ "node": node, "item_id": id, "attempt": item.attempts }),
                agent,
            )?;
            return Ok(Err(e));
        }
    }
    let stored = bounded(receipt, &node);
    let session = stored["session_id"].as_str().map(str::to_string);
    let ts = now();
    let n = tx.execute(
        "UPDATE node_dispatch SET status = ?2, receipt_json = ?3, completed_at = ?4, \
         session_id = COALESCE(?5, session_id), lease_expires_at = NULL, updated_at = ?4 \
         WHERE id = ?1 AND receipt_json IS NULL AND status = 'claimed' AND attempts = ?6",
        params![id, status, stored.to_string(), ts, session, item.attempts],
    )?;
    if n != 1 {
        return Err(UaError::conflict(format!("item {id} changed under this receipt")));
    }
    if item.backend == "command" {
        command::record_completion(tx, &item, status, &stored)?;
    }
    let event_id = record(
        tx,
        "receipt",
        json!({ "node": node, "item_id": id, "status": status, "task_id": item.task_id, "attempt": item.attempts }),
        agent,
    )?;
    relay::drop_open_followups(tx, id, "session_ended_before_delivery")?;
    credentials::revoke_for_item(tx, id, "session_end", agent)?;
    let run = close_linked_run(tx, &item, status, stored["reason"].as_str(), agent, true)?;
    acceptance::on_receipt(tx, cfg, &item)?;
    Ok(Ok(json!({
        "item_id": id,
        "duplicate": false,
        "status": status,
        "evidence_ref": evidence_ref(&node, id),
        "event_id": event_id,
        "run_outcome": run,
        "receipt": stored,
    })))
}

/// A cancel of a dispatch run that was routed to a node. A queued item is
/// cancelled at once (`already_gone`: nothing ran); a claimed one is flagged
/// for the node (`node_cancel_requested`): cessation stays unconfirmed until
/// its receipt. `None` when the run is not node-routed.
pub(crate) fn cancel_for_run(
    tx: &mut WriteTx<'_>,
    evidence: &str,
    actor: &str,
) -> UaResult<Option<&'static str>> {
    let Some(rest) = evidence.strip_prefix("node:") else { return Ok(None) };
    let Some((_, id)) = rest.rsplit_once(':') else { return Ok(None) };
    let Some(item) = load_item(tx, id)? else { return Ok(Some("already_gone")) };
    if item.is_terminal() {
        // A lapsed lease ended the item, not the node: nothing proves it stopped.
        return Ok(Some(if item.outcome_unknown() { "outcome_unknown" } else { "already_gone" }));
    }
    if item.status == "queued" {
        let ts = now();
        tx.execute(
            "UPDATE node_dispatch SET status = 'cancelled', cancel_requested = 1, completed_at = ?2, updated_at = ?2 \
             WHERE id = ?1 AND status = 'queued'",
            params![item.id, ts],
        )?;
        record(
            tx,
            "cancelled",
            json!({ "node": item.node, "item_id": item.id, "actor": actor, "reason": "dispatch_cancel" }),
            actor,
        )?;
        relay::drop_open_followups(tx, &item.id, "item_cancelled")?;
        return Ok(Some("already_gone"));
    }
    if !item.cancel_requested {
        tx.execute(
            "UPDATE node_dispatch SET cancel_requested = 1, updated_at = ?2 WHERE id = ?1",
            params![item.id, now()],
        )?;
        record(
            tx,
            "cancel_requested",
            json!({ "node": item.node, "item_id": item.id, "actor": actor, "reason": "dispatch_cancel" }),
            actor,
        )?;
    }
    credentials::revoke_for_item(tx, &item.id, "cancelled", actor)?;
    Ok(Some("node_cancel_requested"))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiptArgs {
    /// Your node's name.
    pub node: String,
    /// The claimed item.
    pub item_id: String,
    /// `{status: finished|failed|killed, attempt, reason?, text?, exit_code?, backend_status?,
    /// files_modified?, session_id?, started_at?, finished_at?, log_path?, truncated?, log_capture?,
    /// fence_token? (supervised commands)}`. `attempt` is required: the integer `attempt` of the
    /// claim being reported. `text`, `reason` and `log_capture.error` are redacted before storage.
    pub receipt: Value,
}

async fn node_receipt(ctx: ToolCtx, a: ReceiptArgs) -> UaResult<Value> {
    let agent = device_agent(&ctx.caller)?;
    let id = check_item_id(&a.item_id)?;
    let Some(receipt) = a.receipt.as_object().cloned() else {
        return Err(UaError::invalid("receipt must be a JSON object"));
    };
    let status = receipt.get("status").and_then(Value::as_str).unwrap_or("");
    if !RECEIPT_STATUSES.contains(&status) {
        return Err(UaError::invalid(format!(
            "receipt.status must be one of {}",
            RECEIPT_STATUSES.join(", ")
        )));
    }
    if !receipt.get("attempt").is_some_and(Value::is_i64) {
        return Err(UaError::invalid("receipt.attempt is required"));
    }
    let id2 = id.clone();
    let hub = ctx.hub.clone();
    let out =
        ctx.hub.db().write_async(move |tx| post(tx, hub.cfg(), &agent, &a.node, &id2, &receipt)).await??;
    let hub = ctx.hub.clone();
    let _ =
        tokio::task::spawn_blocking(move || command::deliver_pending(&hub, command::NoticeScope::Item(&id)))
            .await;
    Ok(out)
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "node_receipt",
            "Device plane: report what became of a claimed item (finished, failed or killed). The first receipt \
             wins; a retry returns it with duplicate=true. A receipt must name the claim's attempt; one for an \
             earlier attempt is refused (stale_attempt), and a supervised command must echo its fence_token (stale_fence). Settles the \
             item's dispatch run. Returns {item_id, duplicate, status, evidence_ref, event_id, run_outcome, receipt}.",
            node_receipt,
        )
        .family("nodes"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipts_keep_known_fields_bounded() {
        let raw = json!({
            "status": "finished",
            "text": "x".repeat(9000),
            "exit_code": true,
            "files_modified": vec!["a"; 300],
            "secret": "not stored",
            "attempt": 2,
        });
        let b = bounded(raw.as_object().unwrap(), "n1");
        assert_eq!(b["text"].as_str().unwrap().len(), 8000);
        assert_eq!(b["exit_code"], Value::Null);
        assert_eq!(b["files_modified"].as_array().unwrap().len(), 200);
        assert!(b.get("secret").is_none());
        assert_eq!(b["attempt"], 2);
        assert_eq!(b["node"], "n1");
    }

    #[test]
    fn receipt_free_text_is_redacted() {
        // `gh[pousr]_` plus 36 alphanumerics: the GitHub token shape in
        // `audit::rules::secret_shapes`, which `redact_secrets` replaces with
        // `[REDACTED_SECRET]`.
        let token = "ghp_FakeToken0Example1Mixed2Case3Abc4567";
        let raw = json!({
            "status": "failed",
            "attempt": 1,
            "text": format!("pushed with {token}"),
            "reason": format!("auth {token}"),
            "log_capture": { "state": "error", "error": format!("token {token}") },
        });
        let b = bounded(raw.as_object().unwrap(), "n1");
        let rendered = b.to_string();
        assert!(!rendered.contains(token), "{b}");
        assert_eq!(b["text"], "pushed with [REDACTED_SECRET]");
        assert_eq!(b["reason"], "auth [REDACTED_SECRET]");
        assert_eq!(b["log_capture"]["error"], "token [REDACTED_SECRET]");
    }

    #[test]
    fn item_shape_is_checked() {
        assert!(super::super::valid_item_id("nd-0123456789abcdef"));
        assert!(!super::super::valid_item_id("nd-0123456789ABCDEF"));
        assert!(!super::super::valid_item_id("nd-0123"));
    }
}

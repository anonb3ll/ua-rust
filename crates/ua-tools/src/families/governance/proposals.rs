//! Batch work proposals with frozen authority.
//!
//! An agent files a proposal of 1-50 work items; a human operator approves
//! or rejects each item; every approved item becomes one task.
//!
//! - **Authority**: any verified identity may file (an agent as itself; a
//!   human for anyone). Only a human identity may decide. An unverified
//!   local caller must name a configured human as `approver`. Only the
//!   proposer may withdraw, and only while nothing is decided.
//! - **Item states**: `pending` -> `approved` | `rejected` | `withdrawn`
//!   (`approving` exists only in data from the original hub, where approval
//!   spanned two transactions; `work_proposal_recover` settles it). The
//!   operator may edit an item while approving it; the contract frozen is the
//!   edited one (`filed_digest` keeps the digest as filed). The proposal's
//!   status rolls up from its items.
//! - **Frozen contract**: `contract_digest` is SHA-256 over the canonical
//!   JSON of the item's title, notes and scope. The spawned task's notes
//!   start with the item notes, then `[proposal: <id>#<index>]`,
//!   `[contract: <digest>]`, `[scope: <json>]` and `[reporting: <mode>]`.
//!   `task_claim` (and `task_update` into `doing`) re-checks it with
//!   [`check_contract`] and refuses (`contract_mismatch`) when the item, the
//!   task title or the notes prefix drifted, or when a task an approval
//!   spawned lost its markers altogether. Lines appended later (a claim
//!   line, a progress note) do not break it.
//!
//! An approval creates its task and marks the item approved in one write
//! transaction. Every transition appends an `agent.work_proposal.*` event in
//! the same transaction; payloads carry ids, statuses and digests only.

use std::collections::BTreeSet;

use regex::Regex;
use rusqlite::{Connection, OptionalExtension, Row, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, WriteTx, ledger};

use super::now;
use crate::families::agents::verified;
use crate::families::tasks::{NewTask, PRIORITIES, insert_task};
use crate::registry::ToolCtx;

const STATUSES: [&str; 5] = ["pending", "approving", "approved", "rejected", "withdrawn"];
const REPORTING_MODES: [&str; 2] = ["final_only", "milestones"];
const MAX_ITEMS: usize = 50;
const MAX_TITLE: usize = 200;
const MAX_NOTES: usize = 8000;
const MAX_FILES: usize = 200;
const MAX_PATH: usize = 500;
const MAX_REPO: usize = 200;
const MAX_LIST: i64 = 200;
const DEFAULT_STALE_S: i64 = 300;

// --- canonical form and digest --------------------------------------------------

/// Compact JSON with sorted keys (the original hub's canonical form).
fn canonical(v: &Value) -> String {
    // serde_json's map is ordered by key, so this is already sorted.
    serde_json::to_string(v).unwrap_or_default()
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeIn {
    /// Repository the work touches, at most 200 characters.
    pub repo: Option<String>,
    /// Paths the work touches (deduplicated and sorted), at most 200.
    pub files: Option<Vec<String>>,
}

fn scope_value(s: Option<&ScopeIn>) -> UaResult<Value> {
    let Some(s) = s else { return Ok(json!({ "files": [], "repo": null })) };
    if let Some(r) = &s.repo
        && (r.trim().is_empty() || r.chars().count() > MAX_REPO)
    {
        return Err(UaError::invalid(format!(
            "scope.repo must be a non-empty string of at most {MAX_REPO} chars"
        )));
    }
    let mut files = BTreeSet::new();
    for f in s.files.iter().flatten() {
        if f.trim().is_empty() || f.chars().count() > MAX_PATH {
            return Err(UaError::invalid(format!(
                "each scope.files entry must be a non-empty string of at most {MAX_PATH} chars"
            )));
        }
        files.insert(f.clone());
    }
    if files.len() > MAX_FILES {
        return Err(UaError::invalid(format!("scope.files may list at most {MAX_FILES} paths")));
    }
    Ok(json!({ "files": files.into_iter().collect::<Vec<_>>(), "repo": s.repo }))
}

fn scope_from_value(v: &Value) -> ScopeIn {
    ScopeIn {
        repo: v.get("repo").and_then(Value::as_str).map(str::to_string),
        files: v
            .get("files")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()),
    }
}

/// SHA-256 over the canonical JSON of an item's title, notes and scope.
pub(crate) fn contract_digest(title: &str, notes: &str, scope: &Value) -> String {
    let body = json!({ "notes": notes, "scope": scope, "title": title });
    hex::encode(Sha256::digest(canonical(&body).as_bytes()))
}

fn check_title(v: &str, field: &str) -> UaResult<String> {
    let t = v.trim();
    if t.is_empty() {
        return Err(UaError::invalid(format!("{field} must be a non-empty string")));
    }
    if t.chars().count() > MAX_TITLE {
        return Err(UaError::invalid(format!("{field} must be at most {MAX_TITLE} chars")));
    }
    if t.contains('\n') || t.starts_with('#') {
        return Err(UaError::invalid(format!("{field} must be a one-line summary, not a heading or a body")));
    }
    Ok(t.to_string())
}

fn check_notes(v: Option<&str>) -> UaResult<String> {
    let n = v.unwrap_or("");
    if n.chars().count() > MAX_NOTES {
        return Err(UaError::invalid(format!("notes must be a string of at most {MAX_NOTES} chars")));
    }
    Ok(n.trim().to_string())
}

fn check_priority(v: Option<&str>) -> UaResult<String> {
    let p = v.unwrap_or("med");
    if !PRIORITIES.contains(&p) {
        return Err(UaError::invalid(format!("priority must be one of {PRIORITIES:?}")));
    }
    Ok(p.to_string())
}

/// A validated item with its digest.
#[derive(Debug, Clone)]
struct Clean {
    title: String,
    notes: String,
    scope: Value,
    priority: String,
    digest: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ItemIn {
    /// One-line summary, at most 200 characters.
    pub title: String,
    /// The work's specification, at most 8000 characters.
    pub notes: Option<String>,
    /// What the work touches: `{repo, files}`.
    pub scope: Option<ScopeIn>,
    /// `high`, `med` (default) or `low`.
    pub priority: Option<String>,
}

fn clean_item(i: &ItemIn, index: usize) -> UaResult<Clean> {
    let title = check_title(&i.title, &format!("item {index} title"))?;
    let notes = check_notes(i.notes.as_deref())?;
    let scope = scope_value(i.scope.as_ref())?;
    let priority = check_priority(i.priority.as_deref())?;
    let digest = contract_digest(&title, &notes, &scope);
    Ok(Clean { title, notes, scope, priority, digest })
}

/// The notes a spawned task starts with: the item notes, then the markers.
fn compose_task_notes(
    notes: &str,
    scope_json: &str,
    proposal_id: &str,
    index: i64,
    digest: &str,
    mode: &str,
) -> String {
    let markers = format!(
        "[proposal: {proposal_id}#{index}]\n[contract: {digest}]\n[scope: {scope_json}]\n[reporting: {mode}]"
    );
    if notes.is_empty() { markers } else { format!("{notes}\n\n{markers}") }
}

// --- rows -----------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Proposal {
    id: String,
    title: String,
    proposer: String,
    status: String,
    reporting_mode: String,
    created_at: String,
    updated_at: String,
    withdrawn_at: Option<String>,
}

fn proposal_from(r: &Row<'_>) -> rusqlite::Result<Proposal> {
    Ok(Proposal {
        id: r.get("id")?,
        title: r.get("title")?,
        proposer: r.get("proposer")?,
        status: r.get("status")?,
        reporting_mode: r.get("reporting_mode")?,
        created_at: r.get("created_at")?,
        updated_at: r.get("updated_at")?,
        withdrawn_at: r.get("withdrawn_at")?,
    })
}

#[derive(Debug, Clone)]
struct Item {
    idx: i64,
    title: String,
    notes: String,
    scope_json: String,
    priority: String,
    status: String,
    filed_digest: String,
    contract_digest: String,
    edited: bool,
    approving_by: Option<String>,
    approving_at: Option<String>,
    decided_by: Option<String>,
    decided_at: Option<String>,
    task_id: Option<i64>,
}

fn item_from(r: &Row<'_>) -> rusqlite::Result<Item> {
    Ok(Item {
        idx: r.get("idx")?,
        title: r.get("title")?,
        notes: r.get("notes")?,
        scope_json: r.get("scope_json")?,
        priority: r.get("priority")?,
        status: r.get("status")?,
        filed_digest: r.get("filed_digest")?,
        contract_digest: r.get("contract_digest")?,
        edited: r.get::<_, i64>("edited")? != 0,
        approving_by: r.get("approving_by")?,
        approving_at: r.get("approving_at")?,
        decided_by: r.get("decided_by")?,
        decided_at: r.get("decided_at")?,
        task_id: r.get("task_id")?,
    })
}

fn valid_id(id: &str) -> bool {
    id.len() == 15 && id.starts_with("wp_") && id[3..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn load(c: &Connection, id: &str) -> UaResult<Proposal> {
    let id = id.trim();
    let row = if valid_id(id) {
        c.query_row("SELECT * FROM work_proposals WHERE id = ?1", [id], proposal_from).optional()?
    } else {
        None
    };
    row.ok_or_else(|| UaError::not_found(format!("unknown work proposal {id:?}")))
}

fn items(c: &Connection, id: &str) -> UaResult<Vec<Item>> {
    let mut stmt = c.prepare("SELECT * FROM work_proposal_items WHERE proposal_id = ?1 ORDER BY idx")?;
    let rows = stmt.query_map([id], item_from)?.collect::<Result<_, _>>()?;
    Ok(rows)
}

fn rollup(statuses: &[String]) -> &'static str {
    if !statuses.is_empty() && statuses.iter().all(|s| s == "withdrawn") {
        return "withdrawn";
    }
    for s in ["approving", "pending", "approved"] {
        if statuses.iter().any(|x| x == s) {
            return s;
        }
    }
    "rejected"
}

fn refresh(tx: &WriteTx<'_>, id: &str) -> UaResult<&'static str> {
    let statuses: Vec<String> = items(tx, id)?.into_iter().map(|i| i.status).collect();
    let status = rollup(&statuses);
    tx.execute(
        "UPDATE work_proposals SET status = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, status, now()],
    )?;
    Ok(status)
}

fn public_item(i: &Item) -> Value {
    json!({
        "index": i.idx,
        "title": i.title,
        "notes": i.notes,
        "scope": serde_json::from_str::<Value>(&i.scope_json).unwrap_or(Value::Null),
        "priority": i.priority,
        "status": i.status,
        "filed_digest": i.filed_digest,
        "contract_digest": i.contract_digest,
        "edited": i.edited,
        "approving_by": i.approving_by,
        "approving_at": i.approving_at,
        "decided_by": i.decided_by,
        "decided_at": i.decided_at,
        "task_id": i.task_id,
    })
}

fn public(c: &Connection, p: &Proposal, with_items: bool) -> UaResult<Value> {
    let its = items(c, &p.id)?;
    let mut out = json!({
        "id": p.id,
        "title": p.title,
        "proposer": p.proposer,
        "status": p.status,
        "reporting_mode": p.reporting_mode,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
        "withdrawn_at": p.withdrawn_at,
    });
    if with_items {
        out["items"] = json!(its.iter().map(public_item).collect::<Vec<_>>());
    } else {
        let mut counts = serde_json::Map::new();
        for i in &its {
            let n = counts.get(&i.status).and_then(Value::as_i64).unwrap_or(0);
            counts.insert(i.status.clone(), json!(n + 1));
        }
        out["item_counts"] = Value::Object(counts);
    }
    Ok(out)
}

fn emit(tx: &mut WriteTx<'_>, kind: &str, by: &str, payload: Value) -> UaResult<()> {
    ledger::append(tx, EventInput::new(format!("agent.work_proposal.{kind}"), payload).by(by.to_string()))?;
    Ok(())
}

// --- file -----------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileArgs {
    /// The proposal's one-line title.
    pub title: String,
    /// 1-50 items `{title, notes, scope: {repo, files}, priority}`.
    pub items: Vec<ItemIn>,
    /// File for another identity (a human caller only); defaults to the caller.
    pub proposer: Option<String>,
    /// `final_only` (default) or `milestones`.
    pub reporting_mode: Option<String>,
}

/// `coordination_manage(action="work_proposal_file")`.
pub(crate) async fn work_proposal_file(ctx: ToolCtx, a: FileArgs) -> UaResult<Value> {
    let named = a.proposer.as_deref().map(str::trim).filter(|p| !p.is_empty());
    let who = match verified(&ctx.caller) {
        Some(v) => {
            let human = ctx.caller.is_human() || ctx.hub.cfg().is_human(v);
            match named {
                Some(p) if !p.eq_ignore_ascii_case(v) && !human => {
                    return Err(UaError::denied(
                        "identity_mismatch",
                        format!("caller {v:?} cannot file a work proposal as {p:?}"),
                    ));
                }
                Some(p) => p.to_string(),
                None => v.to_string(),
            }
        }
        None => named.unwrap_or(ctx.caller.label.as_str()).to_string(),
    };
    let title = check_title(&a.title, "title")?;
    let mode = a.reporting_mode.unwrap_or_else(|| "final_only".into());
    if !REPORTING_MODES.contains(&mode.as_str()) {
        return Err(UaError::invalid(format!("reporting_mode must be one of {REPORTING_MODES:?}")));
    }
    if a.items.is_empty() {
        return Err(UaError::invalid("a work proposal needs at least one item"));
    }
    if a.items.len() > MAX_ITEMS {
        return Err(UaError::invalid(format!("a work proposal may carry at most {MAX_ITEMS} items")));
    }
    let clean = a.items.iter().enumerate().map(|(i, it)| clean_item(it, i)).collect::<UaResult<Vec<_>>>()?;
    let id = format!("wp_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    ctx.hub
        .db()
        .write_async(move |tx| {
            let ts = now();
            tx.execute(
                "INSERT INTO work_proposals (id, title, proposer, status, reporting_mode, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?5)",
                params![id, title, who, mode, ts],
            )?;
            for (i, it) in clean.iter().enumerate() {
                tx.execute(
                    "INSERT INTO work_proposal_items (proposal_id, idx, title, notes, scope_json, priority, status, \
                     filed_digest, contract_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?7)",
                    params![id, i as i64, it.title, it.notes, canonical(&it.scope), it.priority, it.digest],
                )?;
            }
            emit(
                tx,
                "filed",
                &who,
                json!({
                    "proposal_id": id,
                    "proposer": who,
                    "status": "pending",
                    "items": clean.len(),
                    "digests": clean.iter().map(|c| c.digest.clone()).collect::<Vec<_>>(),
                    "reporting_mode": mode,
                }),
            )?;
            Ok(json!({ "ok": true, "proposal": public(tx, &load(tx, &id)?, true)? }))
        })
        .await
}

// --- decide ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ItemEdits {
    pub title: Option<String>,
    pub notes: Option<String>,
    pub scope: Option<ScopeIn>,
    pub priority: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    /// Item index (0-based).
    pub index: i64,
    /// Approve (spawns one task) or reject.
    pub approve: bool,
    /// Approval only: change title, notes, scope or priority; the contract
    /// is re-frozen over the edited item.
    pub edits: Option<ItemEdits>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecideArgs {
    /// The proposal (`wp_` + 12 hex).
    pub proposal_id: String,
    /// One or more `{index, approve, edits?}`.
    pub decisions: Vec<Decision>,
    /// For an unverified local caller only: a configured human identity.
    pub approver: Option<String>,
}

fn approver(ctx: &ToolCtx, named: Option<&str>) -> UaResult<String> {
    let refusal = "only a human operator may approve or reject work proposal items; agents may file proposals \
                   but not decide them";
    let cfg = ctx.hub.cfg();
    let named = named.map(str::trim).filter(|n| !n.is_empty());
    match verified(&ctx.caller) {
        Some(v) => {
            if !(ctx.caller.is_human() || cfg.is_human(v)) {
                return Err(UaError::denied(
                    "human_required",
                    format!("{refusal} ({v:?} is not a human identity)"),
                ));
            }
            if let Some(n) = named
                && !n.eq_ignore_ascii_case(v)
            {
                return Err(UaError::invalid(format!(
                    "approver must be the verified caller {v:?}, not {n:?}"
                )));
            }
            Ok(v.to_string())
        }
        None => match named {
            Some(n) if cfg.is_human(n) => Ok(n.to_string()),
            _ => Err(UaError::denied(
                "human_required",
                format!("{refusal}; with no verified identity, pass approver=<a human identity>"),
            )),
        },
    }
}

fn apply_edits(i: &Item, edits: Option<&ItemEdits>) -> UaResult<(Clean, bool)> {
    let scope: Value = serde_json::from_str(&i.scope_json).unwrap_or(json!({ "files": [], "repo": null }));
    let Some(e) = edits else {
        return Ok((
            Clean {
                title: i.title.clone(),
                notes: i.notes.clone(),
                scope,
                priority: i.priority.clone(),
                digest: i.contract_digest.clone(),
            },
            i.edited,
        ));
    };
    if e.title.is_none() && e.notes.is_none() && e.scope.is_none() && e.priority.is_none() {
        return Err(UaError::invalid(format!("edits for item {} must change something", i.idx)));
    }
    let merged = ItemIn {
        title: e.title.clone().unwrap_or_else(|| i.title.clone()),
        notes: Some(e.notes.clone().unwrap_or_else(|| i.notes.clone())),
        scope: Some(e.scope.clone().unwrap_or_else(|| scope_from_value(&scope))),
        priority: Some(e.priority.clone().unwrap_or_else(|| i.priority.clone())),
    };
    Ok((clean_item(&merged, i.idx as usize)?, true))
}

/// `coordination_manage(action="work_proposal_decide")`.
pub(crate) async fn work_proposal_decide(ctx: ToolCtx, a: DecideArgs) -> UaResult<Value> {
    let who = approver(&ctx, a.approver.as_deref())?;
    if a.decisions.is_empty() {
        return Err(UaError::invalid("decide needs at least one decision {index, approve, edits?}"));
    }
    let mut seen = BTreeSet::new();
    for d in &a.decisions {
        if d.index < 0 {
            return Err(UaError::invalid("decision index must be a non-negative integer"));
        }
        if !seen.insert(d.index) {
            return Err(UaError::invalid(format!("item {} is decided twice in one call", d.index)));
        }
        if d.edits.is_some() && !d.approve {
            return Err(UaError::invalid(format!("only an approval may carry edits (item {})", d.index)));
        }
    }
    let pid = a.proposal_id.trim().to_string();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let p = load(tx, &pid)?;
            if p.status == "withdrawn" {
                return Err(UaError::conflict(format!("work proposal {pid} is withdrawn")));
            }
            let rows = items(tx, &pid)?;
            for d in &a.decisions {
                let Some(row) = rows.iter().find(|r| r.idx == d.index) else {
                    return Err(UaError::invalid(format!("work proposal {pid} has no item {}", d.index)));
                };
                if row.status != "pending" {
                    return Err(UaError::conflict(format!("item {} is {}, not pending", d.index, row.status)));
                }
            }
            let ts = now();
            for d in a.decisions.iter().filter(|d| !d.approve) {
                let Some(row) = rows.iter().find(|r| r.idx == d.index) else { continue };
                tx.execute(
                    "UPDATE work_proposal_items SET status = 'rejected', decided_by = ?3, decided_at = ?4 \
                     WHERE proposal_id = ?1 AND idx = ?2 AND status = 'pending'",
                    params![pid, d.index, who, ts],
                )?;
                emit(
                    tx,
                    "item_rejected",
                    &who,
                    json!({ "proposal_id": pid, "index": d.index, "status": "rejected",
                            "contract_digest": row.contract_digest }),
                )?;
            }
            for d in a.decisions.iter().filter(|d| d.approve) {
                let Some(row) = rows.iter().find(|r| r.idx == d.index) else { continue };
                let (frozen, edited) = apply_edits(row, d.edits.as_ref())?;
                let scope_json = canonical(&frozen.scope);
                let notes =
                    compose_task_notes(&frozen.notes, &scope_json, &pid, d.index, &frozen.digest, &p.reporting_mode);
                let task_id = insert_task(tx, NewTask::simple(frozen.title.clone(), notes, &frozen.priority), &who)?;
                tx.execute(
                    "UPDATE work_proposal_items SET title = ?3, notes = ?4, scope_json = ?5, priority = ?6, \
                     contract_digest = ?7, edited = ?8, status = 'approved', approving_by = ?9, approving_at = ?10, \
                     decided_by = ?9, decided_at = ?10, task_id = ?11 \
                     WHERE proposal_id = ?1 AND idx = ?2 AND status = 'pending'",
                    params![
                        pid,
                        d.index,
                        frozen.title,
                        frozen.notes,
                        scope_json,
                        frozen.priority,
                        frozen.digest,
                        edited as i64,
                        who,
                        ts,
                        task_id
                    ],
                )?;
                emit(
                    tx,
                    "item_approved",
                    &who,
                    json!({ "proposal_id": pid, "index": d.index, "status": "approved",
                            "contract_digest": frozen.digest, "edited": edited, "task_id": task_id }),
                )?;
            }
            refresh(tx, &pid)?;
            Ok(json!({ "ok": true, "proposal": public(tx, &load(tx, &pid)?, true)? }))
        })
        .await
}

// --- withdraw -------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WithdrawArgs {
    /// The proposal.
    pub proposal_id: String,
    /// Attribution for an unverified caller; a verified caller acts as itself.
    pub actor: Option<String>,
    /// Why, at most 500 characters.
    pub reason: Option<String>,
}

/// `coordination_manage(action="work_proposal_withdraw")`.
pub(crate) async fn work_proposal_withdraw(ctx: ToolCtx, a: WithdrawArgs) -> UaResult<Value> {
    let who = crate::families::tasks::acting_identity(&ctx.caller, a.actor.as_deref())?;
    let reason = super::clean_reason(a.reason.as_deref(), None)?;
    let pid = a.proposal_id.trim().to_string();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let p = load(tx, &pid)?;
            if !who.eq_ignore_ascii_case(&p.proposer) {
                return Err(UaError::denied(
                    "not_proposer",
                    format!("only the proposer {:?} may withdraw work proposal {pid}", p.proposer),
                ));
            }
            if p.status == "withdrawn" {
                return Err(UaError::conflict(format!("work proposal {pid} is already withdrawn")));
            }
            let statuses: Vec<String> = items(tx, &pid)?.into_iter().map(|i| i.status).collect();
            if statuses.iter().any(|s| s == "approving") {
                return Err(UaError::conflict(format!("work proposal {pid} has an approval in progress")));
            }
            if statuses.iter().any(|s| s != "pending") {
                return Err(UaError::conflict(format!(
                    "work proposal {pid} already has decided items; it can no longer be withdrawn"
                )));
            }
            let ts = now();
            tx.execute(
                "UPDATE work_proposal_items SET status = 'withdrawn', decided_by = ?2, decided_at = ?3 \
                 WHERE proposal_id = ?1 AND status = 'pending'",
                params![pid, who, ts],
            )?;
            tx.execute("UPDATE work_proposals SET withdrawn_at = ?2 WHERE id = ?1", params![pid, ts])?;
            refresh(tx, &pid)?;
            emit(
                tx,
                "withdrawn",
                &who,
                json!({ "proposal_id": pid, "status": "withdrawn", "reason": reason }),
            )?;
            Ok(json!({ "ok": true, "proposal": public(tx, &load(tx, &pid)?, true)? }))
        })
        .await
}

// --- reads ----------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetArgs {
    /// The proposal.
    pub proposal_id: String,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Only proposals in this status.
    pub status: Option<String>,
    /// Only this proposer's proposals.
    pub proposer: Option<String>,
    /// Rows, newest first: 1-200 (default 50).
    pub limit: Option<i64>,
}

/// `coordination_manage(action="work_proposal_get")`.
pub(crate) async fn work_proposal_get(ctx: ToolCtx, a: GetArgs) -> UaResult<Value> {
    ctx.hub
        .db()
        .read_async(move |c| Ok(json!({ "proposal": public(c, &load(c, &a.proposal_id)?, true)? })))
        .await
}

/// `coordination_manage(action="work_proposal_list")`.
pub(crate) async fn work_proposal_list(ctx: ToolCtx, a: ListArgs) -> UaResult<Value> {
    if let Some(s) = &a.status
        && !STATUSES.contains(&s.as_str())
    {
        return Err(UaError::invalid(format!("status must be one of {STATUSES:?}")));
    }
    let limit = a.limit.unwrap_or(50);
    if !(1..=MAX_LIST).contains(&limit) {
        return Err(UaError::invalid(format!("limit must be an integer from 1 to {MAX_LIST}")));
    }
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(
                "SELECT * FROM work_proposals WHERE (?1 IS NULL OR status = ?1) \
                 AND (?2 IS NULL OR proposer = ?2 COLLATE NOCASE) ORDER BY created_at DESC, rowid DESC LIMIT ?3",
            )?;
            let rows: Vec<Proposal> =
                stmt.query_map(params![a.status, a.proposer, limit], proposal_from)?.collect::<Result<_, _>>()?;
            let out = rows.iter().map(|p| public(c, p, false)).collect::<UaResult<Vec<_>>>()?;
            Ok(json!({ "proposals": out }))
        })
        .await
}

// --- recovery -------------------------------------------------------------------

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoverArgs {
    /// Only items stuck in `approving` at least this long (default 300 s).
    pub older_than_s: Option<i64>,
}

/// The task spawned for this item's current contract, if one exists.
fn find_task(c: &Connection, pid: &str, idx: i64, digest: &str) -> UaResult<Option<i64>> {
    let marker = format!("[proposal: {pid}#{idx}]");
    let contract = format!("[contract: {digest}]");
    let mut stmt = c.prepare("SELECT id, notes FROM tasks WHERE instr(notes, ?1) > 0 ORDER BY id")?;
    let rows: Vec<(i64, Option<String>)> =
        stmt.query_map([&marker], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
    Ok(rows.into_iter().find(|(_, n)| n.as_deref().unwrap_or("").contains(&contract)).map(|(id, _)| id))
}

/// `coordination_manage(action="work_proposal_recover")`: settle items left
/// in `approving`: forward to `approved` when the task for the item's current
/// contract exists, else back to `pending`. Idempotent.
pub(crate) async fn work_proposal_recover(ctx: ToolCtx, a: RecoverArgs) -> UaResult<Value> {
    let older = a.older_than_s.unwrap_or(DEFAULT_STALE_S);
    if older < 0 {
        return Err(UaError::invalid("older_than_s must be a non-negative number"));
    }
    let actor = verified(&ctx.caller).unwrap_or("work-proposal-recovery").to_string();
    let now_ts = jiff::Timestamp::now();
    let cutoff = ua_core::time::format_ts(
        now_ts.checked_sub(jiff::SignedDuration::from_secs(older)).unwrap_or(now_ts),
    );
    ctx.hub
        .db()
        .write_async(move |tx| {
            let mut stmt = tx.prepare(
                "SELECT proposal_id, idx FROM work_proposal_items WHERE status = 'approving' \
                 AND (approving_at IS NULL OR approving_at <= ?1) ORDER BY proposal_id, idx",
            )?;
            let stale: Vec<(String, i64)> =
                stmt.query_map([&cutoff], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
            drop(stmt);
            let mut forward = Vec::new();
            let mut back = Vec::new();
            let mut touched = BTreeSet::new();
            for (pid, idx) in stale {
                let digest: String = tx.query_row(
                    "SELECT contract_digest FROM work_proposal_items WHERE proposal_id = ?1 AND idx = ?2",
                    params![pid, idx],
                    |r| r.get(0),
                )?;
                match find_task(tx, &pid, idx, &digest)? {
                    Some(task_id) => {
                        tx.execute(
                            "UPDATE work_proposal_items SET status = 'approved', task_id = ?3, \
                             decided_by = approving_by, decided_at = ?4 \
                             WHERE proposal_id = ?1 AND idx = ?2 AND status = 'approving'",
                            params![pid, idx, task_id, now()],
                        )?;
                        emit(
                            tx,
                            "item_recovered",
                            &actor,
                            json!({ "proposal_id": pid, "index": idx, "status": "approved",
                                    "contract_digest": digest, "task_id": task_id }),
                        )?;
                        forward.push(json!({ "proposal_id": pid, "index": idx, "task_id": task_id }));
                    }
                    None => {
                        tx.execute(
                            "UPDATE work_proposal_items SET status = 'pending', approving_by = NULL, approving_at = NULL \
                             WHERE proposal_id = ?1 AND idx = ?2 AND status = 'approving'",
                            params![pid, idx],
                        )?;
                        emit(
                            tx,
                            "item_rolled_back",
                            &actor,
                            json!({ "proposal_id": pid, "index": idx, "status": "pending", "contract_digest": digest }),
                        )?;
                        back.push(json!({ "proposal_id": pid, "index": idx }));
                    }
                }
                touched.insert(pid);
            }
            for pid in touched {
                refresh(tx, &pid)?;
            }
            Ok(json!({ "recovered_forward": forward, "rolled_back": back }))
        })
        .await
}

// --- the claim-time check ---------------------------------------------------------

static PROPOSAL_MARK: std::sync::LazyLock<Option<Regex>> =
    std::sync::LazyLock::new(|| Regex::new(r"\[proposal: (wp_[0-9a-f]{12})#(\d+)\]").ok());
static CONTRACT_MARK: std::sync::LazyLock<Option<Regex>> =
    std::sync::LazyLock::new(|| Regex::new(r"\[contract: ([^\]]*)\]").ok());

fn mismatch(msg: String) -> UaError {
    UaError::denied("contract_mismatch", msg)
}

/// Fail closed when a proposal-spawned task no longer matches its frozen
/// contract. A task with neither a proposal nor a contract marker passes.
pub(crate) fn check_contract(c: &Connection, task_id: i64, title: &str, notes: &str) -> UaResult<()> {
    let (Some(prx), Some(crx)) = (PROPOSAL_MARK.as_ref(), CONTRACT_MARK.as_ref()) else {
        return Err(UaError::internal("contract marker patterns failed to compile"));
    };
    let proposals: BTreeSet<(String, String)> =
        prx.captures_iter(notes).map(|m| (m[1].to_string(), m[2].to_string())).collect();
    let contracts: Vec<String> = crx.captures_iter(notes).map(|m| m[1].to_string()).collect();
    if proposals.is_empty() && contracts.is_empty() {
        // A task an approval spawned must keep its markers: rewriting the
        // notes away does not take it out of its contract.
        let owner: Option<(String, i64)> = c
            .query_row(
                "SELECT proposal_id, idx FROM work_proposal_items WHERE task_id = ?1 AND status = 'approved' LIMIT 1",
                [task_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        return match owner {
            Some((pid, idx)) => Err(mismatch(format!(
                "task {task_id} was spawned by work proposal item {pid}#{idx} but its notes lost the contract                  markers; restore the approved notes before claiming it"
            ))),
            None => Ok(()),
        };
    }
    if proposals.is_empty() {
        return Err(mismatch(format!(
            "task {task_id} carries a [contract: ...] marker but no [proposal: ...] marker; its contract cannot be \
             verified, so the claim is refused"
        )));
    }
    if proposals.len() > 1 {
        return Err(mismatch(format!("task {task_id} names more than one proposal; contract refused")));
    }
    let Some((pid, raw_idx)) = proposals.into_iter().next() else { return Ok(()) };
    let idx: i64 =
        raw_idx.parse().map_err(|_| mismatch(format!("task {task_id} names a malformed item index")))?;
    let row = c
        .query_row(
            "SELECT * FROM work_proposal_items WHERE proposal_id = ?1 AND idx = ?2",
            params![pid, idx],
            item_from,
        )
        .optional()?;
    let mode: Option<String> = c
        .query_row("SELECT reporting_mode FROM work_proposals WHERE id = ?1", [&pid], |r| r.get(0))
        .optional()?;
    let (Some(row), Some(mode)) = (row, mode) else {
        return Err(mismatch(format!("task {task_id} names unknown work proposal item {pid}#{idx}")));
    };
    let at = format!("task {task_id} (proposal {pid}#{idx})");
    if row.status != "approved" {
        return Err(mismatch(format!(
            "{at}: item is {}, not approved; its contract is not in force",
            row.status
        )));
    }
    if let Some(owner) = row.task_id
        && owner != task_id
    {
        return Err(mismatch(format!("{at}: the contract belongs to task {owner}")));
    }
    let scope: Value = serde_json::from_str(&row.scope_json).unwrap_or(Value::Null);
    let scope = scope_value(Some(&scope_from_value(&scope)))?;
    if contract_digest(&row.title, &row.notes, &scope) != row.contract_digest {
        return Err(mismatch(format!("{at}: the frozen item no longer matches its contract digest")));
    }
    if contracts != [row.contract_digest.clone()] {
        return Err(mismatch(format!("{at}: the task's [contract: ...] marker does not match the item")));
    }
    if title != row.title {
        return Err(mismatch(format!("{at}: the task title differs from the approved contract")));
    }
    let expected = compose_task_notes(&row.notes, &row.scope_json, &pid, idx, &row.contract_digest, &mode);
    if !(notes == expected || notes.starts_with(&format!("{expected}\n"))) {
        return Err(mismatch(format!("{at}: the task notes differ from the approved contract")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_is_over_sorted_compact_json() {
        let scope = scope_value(Some(&ScopeIn {
            repo: Some("o/r".into()),
            files: Some(vec!["b.rs".into(), "a.rs".into(), "a.rs".into()]),
        }))
        .unwrap();
        assert_eq!(canonical(&scope), r#"{"files":["a.rs","b.rs"],"repo":"o/r"}"#);
        let body = json!({ "notes": "n", "scope": scope, "title": "t" });
        assert_eq!(
            canonical(&body),
            r#"{"notes":"n","scope":{"files":["a.rs","b.rs"],"repo":"o/r"},"title":"t"}"#
        );
        assert_eq!(contract_digest("t", "n", &scope).len(), 64);
    }

    #[test]
    fn the_rollup_follows_the_items() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(rollup(&s(&["withdrawn", "withdrawn"])), "withdrawn");
        assert_eq!(rollup(&s(&["approved", "pending"])), "pending");
        assert_eq!(rollup(&s(&["approved", "rejected"])), "approved");
        assert_eq!(rollup(&s(&["rejected"])), "rejected");
    }
}

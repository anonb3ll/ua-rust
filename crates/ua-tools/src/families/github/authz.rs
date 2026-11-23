//! Policy authorizations: a human's record that a standing policy covers
//! merging one exact head.
//!
//! An approval is a human deciding one call. A policy authorization is a
//! human saying "the policy `<policy_ref>` covers merging head X of task T in
//! repository R, until <expiry>". It is its own kind of approval, kept in
//! `policy_authorizations`, never in the approvals queue:
//!
//! - `policy_authorization_record` is for a verified human only. The task
//!   must be unfinished and its project bound to `repo`; the head is a full
//!   40-character SHA; the human may not be the task's claimant or next
//!   owner (separation of duties). It expires after `expires_in_hours`
//!   (default 24, at most 720).
//! - `policy_authorization_list` reads them, each with `valid` (active and
//!   unexpired).
//! - `policy_authorization_revoke` (verified humans only) withdraws an
//!   active one before it is spent.
//! - `git_merge_task(policy_authorization_id=...)` accepts one in place of a
//!   one-time approval when it is valid, for that task, for the task
//!   project's bound repository and for exactly the head being merged, the
//!   caller is not the authorizer, and the authorizer is still a configured
//!   human identity at spend time. On that path `force` is refused, and
//!   `allow_in_flight` only when the authorization was recorded with
//!   `allow_in_flight=true`. The merge reserves the authorization (fenced on
//!   the head) just before `git merge` and puts it back to active when the
//!   merge fails, so a failed merge does not burn it; a dry run only reports
//!   that it would cover the merge.
//!
//! Every write appends an `agent.github.policy_authorization.*` event. The
//! `recorded` and `consumed` events carry `payload_sha256`, the SHA-256 of
//! the canonical form of what the authorization binds ([`binding`]: task,
//! repository and head). A merge it refuses appends an
//! `agent.approval.refused` event naming the authorization, the reason, the
//! bound and the presented hashes and the fields that differ; the event is
//! kept even though the refused call's transaction rolls back.

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{Config, UaError, UaResult};
use ua_store::WriteTx;

use super::client::{BoundRepo, full_sha};
use crate::approvals::{self, Refusal, RefusalReason};
use crate::families::continuity::same_label;
use crate::families::governance::{bound_repo, normalize_repo};
use crate::families::tasks::{emit, is_terminal, require_org, require_task, row_object, str_field};
use crate::registry::{Registry, ToolCtx, tool};

const DEFAULT_HOURS: u32 = 24;
const MAX_HOURS: u32 = 720;
const POLICY_REF_MAX: usize = 200;
/// Rows a list scans before filtering.
const SCAN_MAX: i64 = 2000;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordArgs {
    /// `owner/name`: the repository the task's project is bound to.
    pub repo: String,
    /// The pull request number, when the head belongs to one (recorded, not matched).
    pub pr: Option<u64>,
    /// The exact head the policy covers: the full 40-character commit SHA.
    pub head_sha: String,
    /// The hub task the merge belongs to.
    pub task_id: i64,
    /// A short reference to the standing policy (1-200 characters, no
    /// whitespace), e.g. `release-policy-2026-10` or `decision:42`. Never the
    /// text of a conversation.
    pub policy_ref: String,
    /// Hours until it expires: default 24, 1-720.
    pub expires_in_hours: Option<u32>,
    /// Also cover a merge of the task while it is still `doing` or `blocked`
    /// (`git_merge_task(allow_in_flight=true)`). Default false: the task must
    /// be `done`.
    #[serde(default)]
    pub allow_in_flight: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevokeArgs {
    /// The authorization to withdraw.
    pub id: i64,
    /// Why, at most 500 characters.
    pub reason: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Only this repository (`owner/name`).
    pub repo: Option<String>,
    /// Only this pull request number.
    pub pr: Option<u64>,
    /// Only this task.
    pub task_id: Option<i64>,
    /// Only this exact head (40 hex).
    pub head_sha: Option<String>,
    /// Include consumed, revoked and expired rows (default: only valid ones).
    #[serde(default)]
    pub include_inactive: bool,
    /// Rows to return, newest first (default 50, at most 500).
    pub limit: Option<i64>,
}

fn policy_ref(raw: &str) -> UaResult<String> {
    let r = raw.trim();
    let ok = (1..=POLICY_REF_MAX).contains(&r.chars().count())
        && r.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:/#@".contains(c));
    if ok {
        Ok(r.to_string())
    } else {
        Err(UaError::invalid(format!(
            "policy_ref must be 1-{POLICY_REF_MAX} characters of letters, digits and -_.:/#@ (a reference, not text)"
        )))
    }
}

fn after_hours(hours: u32) -> String {
    let now = jiff::Timestamp::now();
    ua_core::time::format_ts(now.checked_add(jiff::SignedDuration::from_hours(hours as i64)).unwrap_or(now))
}

fn expired(expires_at: &str) -> bool {
    ua_core::time::parse_ts(expires_at).is_none_or(|t| t <= jiff::Timestamp::now())
}

fn public(mut row: Map<String, Value>) -> Value {
    let status = str_field(&row, "status").unwrap_or_default().to_string();
    let lapsed = str_field(&row, "expires_at").is_none_or(expired);
    let state = if status == "active" && lapsed { "expired".to_string() } else { status.clone() };
    row.insert("state".into(), json!(state));
    row.insert("valid".into(), json!(status == "active" && !lapsed));
    Value::Object(row)
}

/// An authorization's organization, as a SQL expression over `p`: its
/// task's. `policy_authorizations` carries no `org_id` yet (a later change);
/// one whose task was deleted stays the default organization's, as every
/// authorization was before.
const AUTH_ORG: &str = "COALESCE((SELECT t.org_id FROM tasks t WHERE t.id = p.task_id), 'default')";

/// Authorization `id` of organization `org`; another organization's answers
/// as a missing one.
fn get(conn: &Connection, org: &str, id: i64) -> UaResult<Option<Map<String, Value>>> {
    Ok(conn
        .query_row(
            &format!("SELECT p.* FROM policy_authorizations p WHERE p.id = ?1 AND {AUTH_ORG} = ?2"),
            params![id, org],
            row_object,
        )
        .optional()?)
}

/// One authorization row of organization `org`, if it exists.
pub(crate) fn row(conn: &Connection, org: &str, id: i64) -> UaResult<Option<Map<String, Value>>> {
    get(conn, org, id)
}

/// The tool a policy authorization stands in for.
const MERGE_TOOL: &str = "git_merge_task";

/// What a policy authorization binds, in the form its events hash: the
/// task, the repository (lower case; `null` when unbound) and the exact head.
pub(crate) fn binding(task_id: i64, repo: Option<&str>, head: &str) -> Value {
    json!({
        "task_id": task_id,
        "repo": repo.map(str::to_ascii_lowercase),
        "head_sha": full_sha(head).unwrap_or_else(|| head.to_string()),
    })
}

/// [`binding`] of a stored authorization row.
fn row_binding(row: &Map<String, Value>) -> Value {
    binding(
        row.get("task_id").and_then(Value::as_i64).unwrap_or_default(),
        str_field(row, "repo"),
        str_field(row, "head_sha").unwrap_or_default(),
    )
}

/// SHA-256 of the canonical form of a [`binding`].
pub(crate) fn binding_sha256(b: &Value) -> String {
    approvals::payload_sha256(MERGE_TOOL, b)
}

/// Ledger `r` as a refusal by `caller` and return the refusal error. When
/// the refusal cannot be ledgered, that error is returned instead: the call
/// is refused either way.
fn refuse(tx: &mut WriteTx<'_>, caller: &str, r: Refusal, err: UaError) -> UaError {
    // The refusal is about a policy authorization, a default-organization
    // row until `policy_authorizations` carries `org_id`.
    match approvals::refused(tx, ua_core::DEFAULT_ORG, caller, &r, None) {
        Ok(()) => err,
        Err(e) => e,
    }
}

/// `policy_authorization_record`.
async fn record(ctx: ToolCtx, a: RecordArgs) -> UaResult<Value> {
    if !ctx.caller.is_human() {
        return Err(UaError::denied(
            "not_human",
            "only a verified human records a policy authorization; an agent asks for an approval instead",
        ));
    }
    let who = ctx.caller.label.clone();
    let repo = normalize_repo(&a.repo)?;
    let head = full_sha(&a.head_sha).ok_or_else(|| {
        UaError::invalid("head_sha must be the full 40-character commit SHA (exact-head binding)")
    })?;
    let policy = policy_ref(&a.policy_ref)?;
    let hours = a.expires_in_hours.unwrap_or(DEFAULT_HOURS);
    if !(1..=MAX_HOURS).contains(&hours) {
        return Err(UaError::invalid(format!("expires_in_hours must be 1-{MAX_HOURS}")));
    }
    let (id, pr, in_flight) = (a.task_id, a.pr, a.allow_in_flight);
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            // The task's organization's bindings decide: the task is looked
            // up in the caller's organization, so that is the task row's.
            BoundRepo::check(tx, &org, &repo)?;
            let task = require_task(tx, &org, id)?;
            if is_terminal(str_field(&task, "status").unwrap_or("open")) {
                return Err(UaError::conflict(format!(
                    "task {id} is closed; a policy authorization is a pre-merge step"
                )));
            }
            let project = str_field(&task, "project").unwrap_or("default");
            match bound_repo(tx, &org, project)? {
                Some(b) if b.eq_ignore_ascii_case(&repo) => {}
                other => {
                    return Err(UaError::denied(
                        "repo_mismatch",
                        format!(
                            "task {id}'s project {project:?} is bound to {:?}, not {repo:?}",
                            other.unwrap_or_default()
                        ),
                    ));
                }
            }
            let claimant = str_field(&task, "claimed_by").map(str::to_string);
            for holder in [claimant.as_deref(), str_field(&task, "next_owner")].into_iter().flatten() {
                if same_label(Some(holder), &who) {
                    return Err(UaError::denied(
                        "self_authorization",
                        format!("{who:?} holds task {id} and may not authorize merging its own work"),
                    ));
                }
            }
            let now = ua_core::time::now();
            let expires = after_hours(hours);
            tx.execute(
                "INSERT INTO policy_authorizations (repo, pr, head_sha, task_id, policy_ref, authorized_by, \
                 task_claimant, status, created_at, expires_at, allow_in_flight) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, ?9, ?10)",
                params![repo, pr.map(|p| p as i64), head, id, policy, who, claimant, now, expires, in_flight],
            )?;
            let auth_id = tx.last_insert_rowid();
            let sha = binding_sha256(&binding(id, Some(&repo), &head));
            emit(
                tx,
                &org,
                "agent.github.policy_authorization.recorded",
                json!({
                    "authorization_id": auth_id, "repo": repo, "pr": pr, "head_sha": head, "task_id": id,
                    "policy_ref": policy, "expires_at": expires, "allow_in_flight": in_flight,
                    "payload_sha256": sha,
                }),
                &who,
            )?;
            let row = get(tx, &org, auth_id)?.unwrap_or_default();
            Ok(json!({ "status": "recorded", "authorization": public(row) }))
        })
        .await
}

/// `policy_authorization_list`.
async fn list(ctx: ToolCtx, a: ListArgs) -> UaResult<Value> {
    let repo = a.repo.as_deref().map(normalize_repo).transpose()?;
    let head = a
        .head_sha
        .as_deref()
        .map(|h| full_sha(h).ok_or_else(|| UaError::invalid("head_sha must be 40 hex")))
        .transpose()?;
    let limit = a.limit.unwrap_or(50).clamp(1, 500);
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(&format!(
                "SELECT p.* FROM policy_authorizations p WHERE {AUTH_ORG} = ?6 AND (?1 IS NULL OR p.repo = ?1) \
                 AND (?2 IS NULL OR p.task_id = ?2) AND (?3 IS NULL OR p.head_sha = ?3) \
                 AND (?5 IS NULL OR p.pr = ?5) ORDER BY p.id DESC LIMIT ?4"
            ))?;
            let rows: Vec<Map<String, Value>> = stmt
                .query_map(params![repo, a.task_id, head, SCAN_MAX, a.pr.map(|p| p as i64), org], row_object)?
                .collect::<Result<_, _>>()?;
            let mut out: Vec<Value> =
                rows.into_iter().map(public).filter(|r| a.include_inactive || r["valid"] == true).collect();
            out.truncate(limit as usize);
            Ok(json!({ "count": out.len(), "authorizations": out }))
        })
        .await
}

/// `policy_authorization_revoke`.
async fn revoke(ctx: ToolCtx, a: RevokeArgs) -> UaResult<Value> {
    if !ctx.caller.is_human() {
        return Err(UaError::denied("not_human", "only a verified human revokes a policy authorization"));
    }
    let who = ctx.caller.label.clone();
    let reason =
        a.reason.as_deref().map(|r| crate::families::continuity::bounded(r, "reason", 500)).transpose()?;
    let id = a.id;
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let row =
                get(tx, &org, id)?.ok_or_else(|| UaError::not_found(format!("policy authorization {id}")))?;
            if str_field(&row, "status") != Some("active") {
                return Err(UaError::conflict(format!(
                    "policy authorization {id} is {}; only an active one can be revoked",
                    str_field(&row, "status").unwrap_or("?")
                )));
            }
            let now = ua_core::time::now();
            let n = tx.execute(
                "UPDATE policy_authorizations SET status = 'revoked', revoked_at = ?2, revoked_by = ?3, \
                 revoke_reason = ?4 WHERE id = ?1 AND status = 'active'",
                params![id, now, who, reason],
            )?;
            if n != 1 {
                return Err(UaError::conflict(format!("policy authorization {id} changed meanwhile")));
            }
            emit(
                tx,
                &org,
                "agent.github.policy_authorization.revoked",
                json!({ "authorization_id": id, "task_id": row.get("task_id"),
                        "reason": reason.as_deref().map(|r| crate::families::tasks::ledger_text(&org, r)) }),
                &who,
            )?;
            let row = get(tx, &org, id)?.unwrap_or_default();
            Ok(json!({ "status": "revoked", "authorization": public(row) }))
        })
        .await
}

/// Check that authorization `auth_id` covers merging `head` of task
/// `task_id` in `repo` for `caller`. Returns the row. A refusal is ledgered
/// (`agent.approval.refused`, kept even when the caller's transaction then
/// rolls back) before its error is returned.
pub(crate) fn covering(
    tx: &mut WriteTx<'_>,
    cfg: &Config,
    org: &str,
    auth_id: i64,
    task_id: i64,
    repo: Option<&str>,
    head: &str,
    caller: &str,
) -> UaResult<Map<String, Value>> {
    let mismatch = |why: String| UaError::denied("policy_authorization_mismatch", why);
    let presented = binding(task_id, repo, head);
    let presented_sha = binding_sha256(&presented);
    let base = |reason| {
        Refusal::new(MERGE_TOOL, reason)
            .authorization(auth_id)
            .task(Some(task_id))
            .hashes(None, Some(presented_sha.clone()))
    };
    let Some(row) = get(tx, org, auth_id)? else {
        let r = base(RefusalReason::NoMatchingApproval);
        return Err(refuse(tx, caller, r, UaError::not_found(format!("policy authorization {auth_id}"))));
    };
    let approved = row_binding(&row);
    let approved_sha = Some(binding_sha256(&approved));
    let base = |reason| base(reason).hashes(approved_sha.clone(), Some(presented_sha.clone()));
    let status = str_field(&row, "status").unwrap_or("?").to_string();
    if status != "active" {
        let r = base(RefusalReason::NoMatchingApproval).status(status.clone());
        return Err(refuse(tx, caller, r, mismatch(format!("policy authorization {auth_id} is {status}"))));
    }
    if str_field(&row, "expires_at").is_none_or(expired) {
        let r = base(RefusalReason::Expired).expired_at(str_field(&row, "expires_at").map(str::to_string));
        return Err(refuse(tx, caller, r, mismatch(format!("policy authorization {auth_id} has expired"))));
    }
    let changed = approvals::changed_fields(&approved, &presented);
    let why = if row.get("task_id").and_then(Value::as_i64) != Some(task_id) {
        Some(format!("policy authorization {auth_id} is for another task"))
    } else if repo.is_none() {
        Some(format!("task {task_id}'s project is not bound to a repository"))
    } else if !str_field(&row, "repo").is_some_and(|r| repo.is_some_and(|b| r.eq_ignore_ascii_case(b))) {
        Some(format!("policy authorization {auth_id} is for another repository"))
    } else if str_field(&row, "head_sha") != full_sha(head).as_deref() {
        Some(format!(
            "policy authorization {auth_id} covers head {}, not {head}: a new commit needs a new authorization",
            str_field(&row, "head_sha").unwrap_or_default()
        ))
    } else {
        None
    };
    if let Some(why) = why {
        let r = base(RefusalReason::BindingChanged).changed(changed);
        return Err(refuse(tx, caller, r, mismatch(why)));
    }
    if same_label(str_field(&row, "authorized_by"), caller) {
        let r = base(RefusalReason::NotEligible).detail("self_spend");
        return Err(refuse(
            tx,
            caller,
            r,
            mismatch("the authorizer may not spend its own authorization".into()),
        ));
    }
    // The authority is the human's: someone no longer configured as a human
    // identity cannot cover a merge any more.
    let by = str_field(&row, "authorized_by").unwrap_or_default().to_string();
    if !cfg.is_human(&by) {
        let r = base(RefusalReason::NotEligible).detail("authorizer_not_human");
        let err = UaError::denied(
            "authorizer_not_human",
            format!(
                "policy authorization {auth_id} was recorded by {by:?}, who is no longer a human identity"
            ),
        );
        return Err(refuse(tx, caller, r, err));
    }
    Ok(row)
}

/// Ledger the refusal of a merge under authorization `auth_id` that the
/// authorization binds but does not cover in this mode (`detail`: `force`,
/// `in_flight`), and return `err`.
pub(crate) fn refuse_mode(
    tx: &mut WriteTx<'_>,
    caller: &str,
    auth_id: i64,
    task_id: i64,
    row: Option<&Map<String, Value>>,
    detail: &'static str,
    err: UaError,
) -> UaError {
    let sha = row.map(|r| binding_sha256(&row_binding(r)));
    let r = Refusal::new(MERGE_TOOL, RefusalReason::NotCovered)
        .authorization(auth_id)
        .task(Some(task_id))
        .hashes(sha, None)
        .detail(detail);
    refuse(tx, caller, r, err)
}

/// Whether authorization row `row` also covers an in-flight task.
pub(crate) fn allows_in_flight(row: &Map<String, Value>) -> bool {
    row.get("allow_in_flight").and_then(Value::as_i64).unwrap_or(0) != 0
}

/// Spend authorization `auth_id` for a merge of exactly `head` (inside the
/// caller's write). Returns the `consumed_at` stamp [`restore`] fences on.
pub(crate) fn consume(
    tx: &mut WriteTx<'_>,
    org: &str,
    auth: &Map<String, Value>,
    auth_id: i64,
    task_id: i64,
    head: &str,
    caller: &str,
) -> UaResult<String> {
    let now = crate::families::continuity::now_micros();
    let n = tx.execute(
        "UPDATE policy_authorizations SET status = 'consumed', consumed_at = ?2, consumed_by = ?3 \
         WHERE id = ?1 AND status = 'active' AND head_sha = ?4 AND task_id = ?5",
        params![auth_id, now, caller, head, task_id],
    )?;
    if n != 1 {
        return Err(UaError::conflict(format!("policy authorization {auth_id} was spent meanwhile")));
    }
    emit(
        tx,
        org,
        "agent.github.policy_authorization.consumed",
        json!({
            "authorization_id": auth_id, "task_id": task_id, "head_sha": head, "tool": MERGE_TOOL,
            "payload_sha256": binding_sha256(&row_binding(auth)),
        }),
        caller,
    )?;
    Ok(now)
}

/// Put an authorization this merge consumed back to active after the merge
/// failed. Fenced on the consumer, the stamp and the head, so it never
/// revives one spent or revoked by anyone else.
pub(crate) fn restore(
    tx: &mut WriteTx<'_>,
    org: &str,
    auth_id: i64,
    head: &str,
    caller: &str,
    consumed_at: &str,
    why: &str,
) -> UaResult<bool> {
    let n = tx.execute(
        "UPDATE policy_authorizations SET status = 'active', consumed_at = NULL, consumed_by = NULL \
         WHERE id = ?1 AND status = 'consumed' AND consumed_by = ?2 AND consumed_at = ?3 AND head_sha = ?4",
        params![auth_id, caller, consumed_at, head],
    )?;
    if n == 1 {
        let why: String = why.chars().take(300).collect();
        emit(
            tx,
            org,
            "agent.github.policy_authorization.restored",
            json!({ "authorization_id": auth_id, "head_sha": head,
                    "reason": crate::families::tasks::ledger_text(org, &why) }),
            caller,
        )?;
    }
    Ok(n == 1)
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "policy_authorization_record",
            "Record that a standing policy covers merging one exact head (verified humans only): repo (the task \
             project's bound owner/name), pr, head_sha (full 40 hex), task_id, policy_ref (a short reference), \
             expires_in_hours (default 24, max 720), allow_in_flight (default false: the task must be done). The \
             task's claimant or next owner may not authorize its own work. git_merge_task(policy_authorization_id) \
             then accepts it in place of a one-time approval for exactly that task, repository and head.",
            record,
        )
        .family("approvals"),
    );
    r.add(
        tool(
            "policy_authorization_revoke",
            "Revoke an active policy authorization before it is spent (verified humans only): id, reason.",
            revoke,
        )
        .family("approvals"),
    );
    r.add(
        tool(
            "policy_authorization_list",
            "List policy authorizations newest first, each with state (active, expired, consumed, revoked) and \
             valid. Filters: repo, pr, task_id, head_sha; include_inactive=true adds spent and expired rows.",
            list,
        )
        .family("approvals")
        .read_only(),
    );
}

//! `task_add`, `task_update`, `task_delete` and `task_claim`.

use rusqlite::types::Value as Sql;
use rusqlite::{OptionalExtension, params, params_from_iter};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{Profile, UaError, UaResult};
use ua_org::authz::{Authority, Authz};

use super::*;
use crate::families::governance;
use crate::registry::{Registry, ToolCtx, tool};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddArgs {
    /// One-line summary. Not empty, not a markdown heading, no newlines.
    pub title: String,
    /// The specification body.
    pub notes: Option<String>,
    /// `high`, `med` (default) or `low`.
    pub priority: Option<String>,
    /// Create a subtask under this task (nesting depth is capped at 8).
    pub parent_id: Option<i64>,
    /// Quarantine the task as untrusted content. Inherited from the parent.
    #[serde(default)]
    pub untrusted: bool,
    /// Project stream slug. Defaults to the parent's project, else `default`.
    pub project: Option<String>,
    /// Portfolio bucket slug. Defaults to the parent's domain, else `general`.
    pub domain: Option<String>,
    /// ISO date or datetime when the task is due.
    pub due_at: Option<String>,
    /// Completion pointer (PR URL, commit, CI run).
    pub evidence_ref: Option<String>,
    /// Retry token: a repeated key returns the first result without a new task.
    pub idempotency_key: Option<String>,
    /// Actor lane (who acts on it): `default`, `dispatch-ready`, `tracking`,
    /// an agent label, ... Defaults to the parent's lane, else `default`.
    pub lane: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateArgs {
    /// Task id.
    pub id: i64,
    /// `open`, `doing`, `waiting_review`, `blocked`, `done` or `cancelled`.
    /// `done` stamps `completed_at`; any non-terminal status clears it.
    pub status: Option<String>,
    pub title: Option<String>,
    /// Replace the notes. Use `append_note` to add to them instead.
    pub notes: Option<String>,
    /// Append one note line(s). A note already recorded verbatim is not appended twice.
    pub append_note: Option<String>,
    pub priority: Option<String>,
    /// Reparent under this task; `0` detaches to the top level.
    pub parent_id: Option<i64>,
    /// `true` quarantines; clearing a quarantine needs a verified human.
    pub untrusted: Option<bool>,
    /// `true` archives (files away) the task, `false` unarchives it. Parking
    /// stale work is `coordination_manage(action="queue_park")`.
    pub archived: Option<bool>,
    /// Move the task to this project stream.
    pub project: Option<String>,
    /// Guard: refuse unless the task currently belongs to this project.
    pub expected_project: Option<String>,
    /// Guard: refuse unless the task's `updated_at` still equals this value.
    pub expected_updated_at: Option<String>,
    pub domain: Option<String>,
    pub due_at: Option<String>,
    /// Remove `due_at`.
    #[serde(default)]
    pub clear_due_at: bool,
    pub evidence_ref: Option<String>,
    /// Retry token: a repeated key returns the first result.
    pub idempotency_key: Option<String>,
    pub lane: Option<String>,
    /// Attribution for an unverified caller; ignored when the caller is verified.
    pub actor: Option<String>,
    /// Clear `claimed_by`/`claimed_at`/`lock_expires_at` without changing
    /// status. Only the claimant may release a live claim; anyone may release
    /// an expired one.
    #[serde(default)]
    pub release_claim: bool,
    /// Agent label expected to act next; empty string clears.
    pub next_owner: Option<String>,
    /// What the task waits on; empty string clears.
    pub waiting_on: Option<String>,
    /// Condition that ends the task; empty string clears.
    pub terminal_predicate: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteArgs {
    /// Task id. The whole subtree is deleted with it.
    pub id: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimArgs {
    /// Task id.
    pub id: i64,
    /// Claiming agent label. A verified caller may only claim as itself;
    /// defaults to the caller's label.
    pub agent: Option<String>,
    /// Lease length, 1 to 604800 seconds (default 3600).
    pub timeout_seconds: Option<i64>,
    /// Guard: refuse unless the task belongs to this project.
    pub expected_project: Option<String>,
    /// Claim scope: the task must be in the open pool (`default`,
    /// `dispatch-ready`) or exactly this lane. Omitted, only the open pool or
    /// a lane named after the claiming agent is claimable.
    pub expected_lane: Option<String>,
    /// Record where the work lives. Stored as given; no worktree is created.
    pub worktree_path: Option<String>,
    /// Record the work branch. Stored as given; no branch is created.
    pub branch: Option<String>,
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "task_add",
            "Add a task (or a subtask with parent_id). Returns {id}.",
            |ctx: ToolCtx, a: AddArgs| async move { add(ctx, a).await },
        )
        .family("tasks"),
    );
    r.add(
        tool(
            "task_update",
            "Update a task's status, fields, notes, archive state or claim. Only the fields passed change. \
             Returns the full updated task row.",
            |ctx: ToolCtx, a: UpdateArgs| async move { update(ctx, a).await },
        )
        .family("tasks"),
    );
    r.add(
        tool(
            "task_delete",
            "Delete a task and its whole subtree. Returns {deleted, children_deleted, worktrees}.",
            |ctx: ToolCtx, a: DeleteArgs| async move { delete(ctx, a).await },
        )
        .family("tasks"),
    );
    r.add(
        tool(
            "task_claim",
            "Atomically claim a task: sets claimed_by, claimed_at, lock_expires_at and status doing. \
             A task someone else holds under a live lease is not claimed: the reply is \
             {id, claimed: false, safe_wait} and nothing is written.",
            |ctx: ToolCtx, a: ClaimArgs| async move { claim(ctx, a).await },
        )
        .family("tasks"),
    );
}

fn check_title(title: &str) -> UaResult<String> {
    let t = title.trim();
    if t.is_empty() {
        return Err(UaError::invalid("title must not be empty"));
    }
    if t.starts_with('#') || title.contains('\n') {
        let preview: String = t.chars().take(60).collect();
        return Err(UaError::invalid(format!(
            "title looks like a markdown heading or a multi-line body, not a title ({preview:?})"
        )));
    }
    Ok(title.to_string())
}

fn opt_trim(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// task_add
// ---------------------------------------------------------------------------

async fn add(ctx: ToolCtx, a: AddArgs) -> UaResult<Value> {
    let title = check_title(&a.title)?;
    let priority = a.priority.unwrap_or_else(|| "med".into());
    check_one_of("priority", &priority, &PRIORITIES)?;
    let project = a.project.as_deref().map(|p| check_slug("project", p)).transpose()?;
    let domain = a.domain.as_deref().map(|d| check_slug("domain", d)).transpose()?;
    let lane = a.lane.as_deref().map(|l| check_slug("lane", l)).transpose()?;
    let key = check_idempotency_key(a.idempotency_key.as_deref())?;
    // Handoff keys are the hub's own: a client key in their form could probe
    // or squat the task a conversation handoff created.
    if key.as_deref().is_some_and(|k| k.starts_with(crate::families::continuity::HANDOFF_KEY_PREFIX)) {
        return Err(UaError::invalid(format!(
            "idempotency_key must not start with {:?}: that prefix is reserved for conversation handoffs",
            crate::families::continuity::HANDOFF_KEY_PREFIX
        )));
    }
    let by = ctx.caller.label.clone();
    let org = ctx.caller.org_id.clone();

    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            if let Some(k) = &key
                && let Some(prior) = idempotent_replay(tx, &org, "task_add", k)?
            {
                return Ok(prior);
            }
            let id = insert_task(
                tx,
                &org,
                NewTask {
                    title,
                    notes: a.notes,
                    priority,
                    parent_id: a.parent_id,
                    untrusted: a.untrusted,
                    project,
                    domain,
                    due_at: opt_trim(a.due_at),
                    evidence_ref: opt_trim(a.evidence_ref),
                    lane,
                },
                &by,
            )?;
            let res = json!({ "id": id });
            if let Some(k) = &key {
                idempotent_record(tx, &org, "task_add", k, &res)?;
            }
            Ok(res)
        })
        .await
}

/// A task to insert. The title and priority are already validated; the
/// project, domain and lane are checked slugs or `None` (inherit, else default).
pub(crate) struct NewTask {
    pub title: String,
    pub notes: Option<String>,
    pub priority: String,
    pub parent_id: Option<i64>,
    pub untrusted: bool,
    pub project: Option<String>,
    pub domain: Option<String>,
    pub due_at: Option<String>,
    pub evidence_ref: Option<String>,
    pub lane: Option<String>,
}

impl NewTask {
    /// A top-level task with defaults for everything but title, notes and priority.
    pub(crate) fn simple(title: String, notes: String, priority: &str) -> Self {
        Self {
            title,
            notes: Some(notes),
            priority: priority.to_string(),
            parent_id: None,
            untrusted: false,
            project: None,
            domain: None,
            due_at: None,
            evidence_ref: None,
            lane: None,
        }
    }
}

/// Insert one task of organization `org` and its `agent.task.created` event
/// in the caller's write transaction. Returns the new id. Every task
/// creation goes through here. A parent must be in `org`; an organization
/// `orgs` does not hold is refused before anything is written.
pub(crate) fn insert_task(tx: &mut WriteTx<'_>, org: &str, t: NewTask, by: &str) -> UaResult<i64> {
    require_org(tx, org)?;
    check_title(&t.title)?;
    check_one_of("priority", &t.priority, &PRIORITIES)?;
    let (mut project, mut domain, mut lane, mut untrusted) = (t.project, t.domain, t.lane, t.untrusted);
    if let Some(pid) = t.parent_id {
        check_nesting(tx, org, pid, None)?;
        let parent = require_task(tx, org, pid)?;
        project = project.or_else(|| str_field(&parent, "project").map(String::from));
        domain = domain.or_else(|| str_field(&parent, "domain").map(String::from));
        lane = lane.or_else(|| str_field(&parent, "lane").map(String::from));
        untrusted |= int_field(&parent, "untrusted").unwrap_or(0) != 0;
    }
    let ts = now();
    tx.execute(
        "INSERT INTO tasks (title, notes, priority, parent_id, created_at, updated_at, untrusted, \
         project, domain, due_at, evidence_ref, lane, org_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            t.title,
            t.notes,
            t.priority,
            t.parent_id,
            ts,
            untrusted as i64,
            project.unwrap_or_else(|| "default".into()),
            domain.unwrap_or_else(|| "general".into()),
            t.due_at,
            t.evidence_ref,
            lane.unwrap_or_else(|| "default".into()),
            org,
        ],
    )?;
    let id = tx.last_insert_rowid();
    emit(
        tx,
        org,
        "agent.task.created",
        json!({ "task_id": id, "title": ledger_text(org, &t.title), "priority": t.priority, "parent_id": t.parent_id }),
        by,
    )?;
    Ok(id)
}

// ---------------------------------------------------------------------------
// task_update
// ---------------------------------------------------------------------------

/// A client key scoped to the caller: `<label>:<key>`, stored as
/// `task_update:<label>:<key>` (prefixed with the organization outside the
/// default one, see [`idem_key`]). `%`, `:` and `/` in the label are
/// percent-escaped, so the label always ends at the first `:` after the tool
/// name and two labels never produce the same stored key. Keys stored in the
/// old unscoped `task_update:<key>` form are not read: nothing else reads
/// them, and a retry that spans the upgrade only applies the same fields
/// again (an appended note that is already there is not appended twice).
fn caller_scoped_key(caller: &ua_core::Caller, key: &str) -> String {
    let label = caller.label.replace('%', "%25").replace(':', "%3A").replace('/', "%2F");
    format!("{label}:{key}")
}

/// True when `note` (all of its stripped lines, in order) already appears in `current`.
fn note_is_duplicate(current: &str, note: &str) -> bool {
    let existing: Vec<&str> = current.lines().map(str::trim).collect();
    let wanted: Vec<&str> = note.lines().map(str::trim).collect();
    !wanted.is_empty() && existing.windows(wanted.len()).any(|w| w == wanted.as_slice())
}

struct Sets {
    clauses: Vec<String>,
    values: Vec<Sql>,
    changed: Vec<&'static str>,
}

impl Sets {
    fn set(&mut self, field: &'static str, value: Sql) {
        self.values.push(value);
        self.clauses.push(format!("{field} = ?{}", self.values.len()));
        if !self.changed.contains(&field) {
            self.changed.push(field);
        }
    }

    fn raw(&mut self, field: &'static str, clause: &str) {
        self.clauses.push(format!("{field} = {clause}"));
        if !self.changed.contains(&field) {
            self.changed.push(field);
        }
    }
}

fn text(v: impl Into<String>) -> Sql {
    Sql::Text(v.into())
}

fn opt_text(v: Option<String>) -> Sql {
    v.map(Sql::Text).unwrap_or(Sql::Null)
}

async fn update(ctx: ToolCtx, a: UpdateArgs) -> UaResult<Value> {
    if let Some(s) = &a.status {
        check_one_of("status", s, &STATUSES)?;
    }
    if let Some(t) = &a.title {
        check_title(t)?;
    }
    if a.append_note.as_deref().is_some_and(|n| n.trim().is_empty()) {
        return Err(UaError::invalid("append_note must not be empty"));
    }
    if a.append_note.is_some() && a.notes.is_some() {
        return Err(UaError::invalid("pass append_note or notes, not both"));
    }
    if let Some(p) = &a.priority {
        check_one_of("priority", p, &PRIORITIES)?;
    }
    let project = a.project.as_deref().map(|p| check_slug("project", p)).transpose()?;
    let domain = a.domain.as_deref().map(|d| check_slug("domain", d)).transpose()?;
    let lane = a.lane.as_deref().map(|l| check_slug("lane", l)).transpose()?;
    if a.due_at.is_some() && a.clear_due_at {
        return Err(UaError::invalid("pass either due_at or clear_due_at=true, not both"));
    }
    let next_owner = match a.next_owner.as_deref().map(str::trim) {
        None => None,
        Some("") => Some(None),
        Some(o) => Some(Some(check_slug("next_owner", o)?)),
    };
    for (field, v) in [("waiting_on", &a.waiting_on), ("terminal_predicate", &a.terminal_predicate)] {
        if v.as_deref().is_some_and(|s| s.len() > 500) {
            return Err(UaError::invalid(format!("{field} must be at most 500 characters")));
        }
    }
    // Stored per caller (`task_update:<label>:<key>`): another caller's use
    // of the same key, or a squat of a predictable one, is a different row.
    let key =
        check_idempotency_key(a.idempotency_key.as_deref())?.map(|k| caller_scoped_key(&ctx.caller, &k));
    let caller = ctx.caller.clone();
    let org = caller.org_id.clone();
    let cfg = ctx.hub.cfg().clone();
    let identity = if is_verified(&caller) {
        caller.label.clone()
    } else {
        opt_trim(a.actor.clone()).unwrap_or_else(|| caller.label.clone())
    };

    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let id = a.id;
            // The task is looked up first, in the caller's organization, so a
            // key never answers for a task the caller cannot see.
            let old = require_task(tx, &org, id)?;
            if let Some(k) = &key
                && let Some(prior) = idempotent_replay(tx, &org, "task_update", k)?
            {
                // A replay is only ever this caller's earlier update of this
                // task; the same key on another task is a client bug, not a
                // retry, and is refused rather than answered with the
                // first task's snapshot or silently dropped.
                if prior.get("id").and_then(Value::as_i64) == Some(id) {
                    return Ok(prior);
                }
                return Err(UaError::conflict_code(
                    "idempotency_key_reused",
                    format!("idempotency_key was already used for another task update; task {id} was not changed"),
                ));
            }
            let old_status = str_field(&old, "status").unwrap_or("open").to_string();
            let old_project = str_field(&old, "project").unwrap_or("default").to_string();
            let old_lane = str_field(&old, "lane").unwrap_or("default").to_string();
            let claimed_by = str_field(&old, "claimed_by").map(String::from);
            let ts = now();
            let claim_expired = claimed_by.is_some()
                && str_field(&old, "lock_expires_at").is_some_and(|exp| ts_le(exp, &ts));

            // Guards.
            if let Some(ep) = &a.expected_project
                && ep != &old_project
            {
                return Err(UaError::invalid(format!("task {id} belongs to project {old_project:?}, not {ep:?}")));
            }
            if let Some(eu) = &a.expected_updated_at
                && Some(eu.as_str()) != str_field(&old, "updated_at")
            {
                return Err(UaError::conflict(format!(
                    "task {id} changed: expected updated_at {eu:?}, found {:?}",
                    str_field(&old, "updated_at")
                )));
            }
            if let Some(holder) = &claimed_by
                && holder != &identity
            {
                if a.release_claim && !claim_expired {
                    return Err(UaError::conflict(format!(
                        "task {id} is claimed by {holder:?} with an active lease; only the claimant or an \
                         expired claim may be released"
                    )));
                }
                if caller.profile == Profile::Reviewer && !(a.release_claim && claim_expired) {
                    return Err(UaError::denied(
                        "reviewer_claimed_task",
                        format!(
                            "task {id} is claimed by {holder:?}; the reviewer profile may not update another agent's claimed \
                             task. Groom unclaimed or self-claimed tasks, or ask the claimant"
                        ),
                    ));
                }
            }
            let quarantined = int_field(&old, "untrusted").unwrap_or(0) != 0;
            let clearing_quarantine = a.untrusted == Some(false) && quarantined;
            if clearing_quarantine && !Authz::new(&cfg).holds(&caller, &[Authority::Operator], &org) {
                return Err(UaError::denied(
                    "untrusted_clear_needs_human",
                    format!("clearing task {id}'s untrusted quarantine needs a verified human"),
                ));
            }
            if let Some(pid) = a.parent_id
                && pid != 0
            {
                check_nesting(tx, &org, pid, Some(id))?;
            }

            let mut s = Sets { clauses: Vec::new(), values: Vec::new(), changed: Vec::new() };
            if let Some(v) = &a.title {
                s.set("title", text(v.clone()));
            }
            let mut notes_after = str_field(&old, "notes").unwrap_or_default().to_string();
            if let Some(v) = &a.notes {
                s.set("notes", text(v.clone()));
                notes_after = v.clone();
            }
            if let Some(note) = &a.append_note {
                let note = note.trim();
                let current = str_field(&old, "notes").unwrap_or_default();
                if !note_is_duplicate(current, note) {
                    let joined = if current.is_empty() { note.to_string() } else { format!("{current}\n{note}") };
                    s.set("notes", text(joined.clone()));
                    notes_after = joined;
                }
            }
            if let Some(v) = &a.priority {
                s.set("priority", text(v.clone()));
            }
            if let Some(p) = &project
                && p != &old_project
            {
                let goal_project: Option<String> = tx
                    .query_row(
                        "SELECT g.project FROM task_goal_links l JOIN goals g ON g.id = l.goal_id WHERE l.task_id = ?1",
                        [id],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(gp) = goal_project
                    && &gp != p
                {
                    return Err(UaError::invalid(format!(
                        "task {id} serves a goal in project {gp:?}; refusing to move it to {p:?}"
                    )));
                }
                s.set("project", text(p.clone()));
            }
            if let Some(v) = &domain {
                s.set("domain", text(v.clone()));
            }
            if let Some(v) = &lane {
                s.set("lane", text(v.clone()));
            }
            if let Some(v) = opt_trim(a.evidence_ref.clone()) {
                s.set("evidence_ref", text(v));
            }
            if let Some(u) = a.untrusted {
                s.set("untrusted", Sql::Integer(u as i64));
            }
            match a.archived {
                Some(true) => s.set("archived_at", text(ts.clone())),
                Some(false) => s.raw("archived_at", "NULL"),
                None => {}
            }
            if let Some(d) = opt_trim(a.due_at.clone()) {
                s.set("due_at", text(d));
            } else if a.clear_due_at {
                s.raw("due_at", "NULL");
            }
            match a.parent_id {
                Some(0) => s.raw("parent_id", "NULL"),
                Some(p) => s.set("parent_id", Sql::Integer(p)),
                None => {}
            }

            // Status transitions.
            let new_status = a.status.clone().unwrap_or_else(|| old_status.clone());
            let mut clear_claim = a.release_claim && claimed_by.is_some();
            let mut ownership_ended = clear_claim;
            if let Some(st) = &a.status {
                s.set("status", text(st.clone()));
                if st == "done" {
                    let notes_after = a.notes.as_deref().or(str_field(&old, "notes")).unwrap_or_default();
                    if has_marker(notes_after, PROJECT_SPEC_MARKER) {
                        let r = rollup(tx, &org, id)?;
                        if r["complete"] != json!(true) {
                            let listed: Vec<String> = r["active"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .map(|t| format!("#{} ({})", t["id"], t["status"].as_str().unwrap_or("")))
                                .collect();
                            return Err(UaError::invalid(format!(
                                "cannot mark project-spec task {id} done while active descendants exist: {}",
                                listed.join(", ")
                            )));
                        }
                    }
                    s.set("completed_at", Sql::Text(str_field(&old, "completed_at").unwrap_or(&ts).to_string()));
                } else if st != "cancelled" {
                    s.raw("completed_at", "NULL");
                }
                if !is_terminal(st) && is_terminal(&old_status) {
                    clear_claim |= claimed_by.is_some();
                }
                if is_terminal(st) && !is_terminal(&old_status) {
                    ownership_ended = true;
                }
                // A closed task is no longer parked: the park ends with it.
                if is_terminal(st) && old.get("parked_at").is_some_and(|v| !v.is_null()) {
                    for col in ["parked_at", "parked_by", "parked_reason", "folded_into"] {
                        s.raw(col, "NULL");
                    }
                }
                if st == "doing" && old_status != "doing" {
                    let lane_after = lane.as_deref().unwrap_or(&old_lane);
                    if UNCLAIMABLE_LANES.contains(&lane_after) {
                        return Err(UaError::invalid(format!(
                            "task {id} is in lane {lane_after:?}, an umbrella that is never claimable work; move it \
                             to a work lane first"
                        )));
                    }
                    let lineage = match a.parent_id {
                        Some(0) => Vec::new(),
                        Some(p) => {
                            let mut l = ancestors(tx, &org, p)?;
                            l.push(p);
                            l
                        }
                        None => ancestors(tx, &org, id)?,
                    };
                    for anc in lineage {
                        let st: Option<String> = tx
                            .query_row("SELECT status FROM tasks WHERE org_id = ?1 AND id = ?2", params![org, anc], |r| {
                                r.get(0)
                            })
                            .optional()?;
                        if st.as_deref() == Some("cancelled") {
                            return Err(UaError::invalid(format!("task {id} has cancelled ancestor {anc}")));
                        }
                    }
                    let stays_archived =
                        a.archived == Some(true) || (a.archived.is_none() && old.get("archived_at") != Some(&Value::Null));
                    if stays_archived {
                        return Err(UaError::invalid(format!(
                            "task {id} is archived: pass archived=false to unarchive it before work starts"
                        )));
                    }
                    // A lapsed claim survives only for its own claimant.
                    if let Some(holder) = &claimed_by
                        && claim_expired
                        && !clear_claim
                    {
                        if holder == &identity {
                            s.set("lock_expires_at", text(after_seconds(DEFAULT_LEASE_SECONDS)));
                        } else {
                            clear_claim = true;
                        }
                    }
                    // Entering doing from another status is a new claim: the one
                    // claim gate applies to the agent that will hold it, and a
                    // proposal-spawned task must still match its contract.
                    let doing_agent = claimed_by.clone().filter(|_| !clear_claim).unwrap_or_else(|| identity.clone());
                    governance::check_claim(tx, &org, Some(&doing_agent), Some(id), false)?;
                    let title_after = a.title.as_deref().or(str_field(&old, "title")).unwrap_or_default();
                    governance::check_contract(tx, &org, id, title_after, &notes_after)?;
                }
            }
            if clear_claim {
                s.raw("claimed_by", "NULL");
                s.raw("claimed_at", "NULL");
                s.raw("lock_expires_at", "NULL");
            }

            // Ownership record.
            let old_next_owner = str_field(&old, "next_owner").map(String::from);
            if ownership_ended {
                if matches!(next_owner, Some(Some(_))) {
                    return Err(UaError::invalid(
                        "next_owner cannot be set on a call that closes the task or releases its claim",
                    ));
                }
                if old_next_owner.is_some() || claimed_by.is_some() {
                    s.raw("next_owner", "NULL");
                    s.raw("ownership_generation", "ownership_generation + 1");
                }
            } else if let Some(no) = &next_owner
                && no != &old_next_owner
            {
                s.set("next_owner", opt_text(no.clone()));
                s.raw("ownership_generation", "ownership_generation + 1");
            }
            for (field, v) in [("waiting_on", &a.waiting_on), ("terminal_predicate", &a.terminal_predicate)] {
                if let Some(v) = v {
                    let v = v.trim();
                    let val = if v.is_empty() { Sql::Null } else { text(v) };
                    s.set(field, val);
                }
            }

            let revision = next_revision(str_field(&old, "updated_at"));
            s.values.push(text(revision));
            s.clauses.push(format!("updated_at = ?{}", s.values.len()));
            s.values.push(Sql::Integer(id));
            s.values.push(text(org.clone()));
            let sql = format!(
                "UPDATE tasks SET {} WHERE id = ?{} AND org_id = ?{}",
                s.clauses.join(", "),
                s.values.len() - 1,
                s.values.len()
            );
            tx.execute(&sql, params_from_iter(s.values.iter()))?;

            let by = identity.clone();
            emit(
                tx,
                &org,
                "agent.task.updated",
                json!({ "task_id": id, "fields": s.changed, "from_status": old_status, "status": new_status }),
                &by,
            )?;
            if new_status == "done" && old_status != "done" {
                emit(tx, &org, "agent.task.completed", json!({ "task_id": id }), &by)?;
            }
            if clear_claim && let Some(holder) = &claimed_by {
                emit(
                    tx,
                    &org,
                    "agent.task.claim_released",
                    json!({ "task_id": id, "claimant": ledger_text(&org, holder), "expired": claim_expired }),
                    &by,
                )?;
            }
            if clearing_quarantine {
                emit(tx, &org, "agent.task.untrusted_cleared", json!({ "task_id": id }), &by)?;
            }
            let reply = task_reply(tx, &org, id)?;
            if let Some(k) = &key {
                idempotent_record(tx, &org, "task_update", k, &reply)?;
            }
            Ok(reply)
        })
        .await
}

// ---------------------------------------------------------------------------
// task_delete
// ---------------------------------------------------------------------------

async fn delete(ctx: ToolCtx, a: DeleteArgs) -> UaResult<Value> {
    let by = ctx.caller.label.clone();
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let subtree = subtree_ids(tx, &org, a.id)?;
            if subtree.is_empty() {
                return Ok(json!({ "deleted": false, "children_deleted": 0, "worktrees": {} }));
            }
            if org != ua_core::DEFAULT_ORG {
                drop_orphaned_task_rows(tx, &org, &subtree)?;
            }
            let n = tx.execute("DELETE FROM tasks WHERE org_id = ?1 AND id = ?2", params![org, a.id])?;
            let children = subtree.len() - 1;
            emit(tx, &org, "agent.task.deleted", json!({ "task_id": a.id, "subtree": subtree }), &by)?;
            Ok(json!({
                "deleted": n > 0,
                "children_deleted": if n > 0 { children } else { 0 },
                "worktrees": {},
            }))
        })
        .await
}

/// Delete the holds rooted in `subtree` (and their members) and the policy
/// authorizations naming a task in it, before organization `org`'s
/// (non-default) task is deleted.
///
/// `policy_authorizations` carries no `org_id` yet and no foreign key to
/// `tasks`: its organization is its task's, and once that task is gone the
/// lookup falls back to the default organization. Left behind, another
/// organization's authorization repository, PR and head would show in the
/// default organization's views. The row is deleted rather than blanked: a
/// blanked row would still be a default organization row it never created.
///
/// Holds carry their organization (`task_holds.org_id`), so a hold of a
/// deleted task can no longer fall into the default organization; they are
/// still deleted with their root, in their own organization only, so that
/// deleting another organization's task leaves the same state as before
/// holds had the column. The default organization keeps its rows, as before:
/// its holds may outlive their root.
fn drop_orphaned_task_rows(tx: &rusqlite::Connection, org: &str, subtree: &[i64]) -> UaResult<()> {
    let has = |name: &str| -> UaResult<bool> {
        Ok(tx
            .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [name], |_| Ok(()))
            .optional()?
            .is_some())
    };
    let ids = serde_json::to_string(subtree)?;
    if has("task_holds")? {
        if has("task_hold_members")? {
            tx.execute(
                "DELETE FROM task_hold_members WHERE org_id = ?2 AND hold_id IN \
                     (SELECT id FROM task_holds WHERE org_id = ?2 AND root_task_id IN (SELECT value FROM json_each(?1)))",
                params![ids, org],
            )?;
        }
        tx.execute(
            "DELETE FROM task_holds WHERE org_id = ?2 AND root_task_id IN (SELECT value FROM json_each(?1))",
            params![ids, org],
        )?;
    }
    if has("policy_authorizations")? {
        tx.execute(
            "DELETE FROM policy_authorizations WHERE task_id IN (SELECT value FROM json_each(?1))",
            [&ids],
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// task_claim
// ---------------------------------------------------------------------------

/// The first `claimed-by: <label>` marker in the notes.
fn notes_claimant(notes: &str) -> Option<String> {
    let lower = notes.to_ascii_lowercase();
    let pos = lower.find("claimed-by:")?;
    let rest = notes[pos + "claimed-by:".len()..].trim_start();
    let label: String =
        rest.chars().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')).collect();
    (!label.is_empty()).then_some(label)
}

fn lane_claim_allowed(task_lane: &str, expected: Option<&str>, agent: &str) -> bool {
    if OPEN_POOL_LANES.contains(&task_lane) {
        return true;
    }
    match expected {
        None => task_lane == agent,
        Some(e) => task_lane == e,
    }
}

async fn claim(ctx: ToolCtx, a: ClaimArgs) -> UaResult<Value> {
    let agent = acting_identity(&ctx.caller, a.agent.as_deref())?;
    let timeout = a.timeout_seconds.unwrap_or(DEFAULT_LEASE_SECONDS);
    if !(1..=MAX_LEASE_SECONDS).contains(&timeout) {
        return Err(UaError::invalid(format!(
            "timeout_seconds must be between 1 and {MAX_LEASE_SECONDS} (7 days)"
        )));
    }
    let expected_lane = a.expected_lane.as_deref().map(|l| check_slug("expected_lane", l)).transpose()?;
    let worktree_path = opt_trim(a.worktree_path);
    let branch = opt_trim(a.branch);
    let org = ctx.caller.org_id.clone();

    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let id = a.id;
            let row = require_task(tx, &org, id)?;
            let status = str_field(&row, "status").unwrap_or("open").to_string();
            let lane = str_field(&row, "lane").unwrap_or("default").to_string();
            let project = str_field(&row, "project").unwrap_or("default").to_string();
            if UNCLAIMABLE_LANES.contains(&lane.as_str()) {
                return Err(UaError::invalid(format!(
                    "task {id} is in lane {lane:?}, an umbrella that is never claimable work; move it to a work lane first"
                )));
            }
            for anc in ancestors(tx, &org, id)? {
                let st: Option<String> = tx
                    .query_row("SELECT status FROM tasks WHERE org_id = ?1 AND id = ?2", params![org, anc], |r| r.get(0))
                    .optional()?;
                if st.as_deref() == Some("cancelled") {
                    return Err(UaError::invalid(format!("task {id} has cancelled ancestor {anc}")));
                }
            }
            if let Some(ep) = &a.expected_project
                && ep != &project
            {
                return Err(UaError::invalid(format!("task {id} belongs to project {project:?}, not {ep:?}")));
            }
            if !lane_claim_allowed(&lane, expected_lane.as_deref(), &agent) {
                let scope = expected_lane.as_deref().unwrap_or("default");
                return Err(UaError::invalid(format!("task {id} is in lane {lane:?}; claim scoped to {scope:?}")));
            }
            if is_terminal(&status) {
                return Err(UaError::invalid(format!("task {id} is already {status}")));
            }
            if row.get("archived_at").is_some_and(|v| !v.is_null()) {
                return Err(UaError::invalid(format!("task {id} is archived: unarchive it before claiming")));
            }
            // A task spawned from an approved work proposal fails closed when
            // its title or notes drifted from the frozen contract.
            governance::check_contract(
                tx,
                &org,
                id,
                str_field(&row, "title").unwrap_or_default(),
                str_field(&row, "notes").unwrap_or_default(),
            )?;

            let ts = now();
            let holder = str_field(&row, "claimed_by").map(String::from);
            let expires = str_field(&row, "lock_expires_at").map(String::from);
            let lock_active = holder.is_some() && expires.as_deref().is_none_or(|e| !ts_le(e, &ts));
            if lock_active && holder.as_deref() != Some(agent.as_str()) {
                let next_owner = str_field(&row, "next_owner").map(String::from);
                return Ok(json!({
                    "id": id,
                    "claimed": false,
                    "safe_wait": {
                        "owner": next_owner.or_else(|| holder.clone()),
                        "waiting_on": row.get("waiting_on").cloned().unwrap_or(Value::Null),
                        "until": expires,
                        "generation": int_field(&row, "ownership_generation").unwrap_or(0),
                        "claimed_by": holder,
                    },
                }));
            }
            let renewal = lock_active && status == "doing";
            // The one claim gate. A live renewal of the caller's own lease
            // passes a subtree hold (an in-flight run may finish); a lease with
            // no expiry is not a renewal, since it would renew forever.
            governance::check_claim(tx, &org, Some(&agent), Some(id), renewal && expires.is_some())?;
            let takeover = if !lock_active { holder.clone().filter(|h| h != &agent) } else { None };

            let mut notes = str_field(&row, "notes").unwrap_or_default().to_string();
            if notes_claimant(&notes).as_deref() != Some(agent.as_str()) {
                notes = if notes.trim().is_empty() {
                    format!("claimed-by: {agent}")
                } else {
                    format!("{}\n\nclaimed-by: {agent}", notes.trim_end())
                };
            }
            let revision = next_revision(str_field(&row, "updated_at"));
            let claimed_at = if renewal {
                str_field(&row, "claimed_at").map(String::from).unwrap_or_else(|| revision.clone())
            } else {
                revision.clone()
            };
            let generation = int_field(&row, "ownership_generation").unwrap_or(0);
            let (next_owner, waiting_on, generation) = if renewal {
                (str_field(&row, "next_owner").map(String::from), str_field(&row, "waiting_on").map(String::from), generation)
            } else {
                (Some(agent.clone()), None, generation + 1)
            };
            let lock_expires = after_seconds(timeout);
            let n = tx.execute(
                "UPDATE tasks SET status = 'doing', claimed_by = ?1, claimed_at = ?2, lock_expires_at = ?3, notes = ?4, \
                 updated_at = ?5, next_owner = ?6, waiting_on = ?7, ownership_generation = ?8, \
                 worktree_path = COALESCE(?9, worktree_path), branch = COALESCE(?10, branch) \
                 WHERE id = ?11 AND org_id = ?13 AND status NOT IN ('done', 'cancelled') \
                 AND (claimed_by IS NULL OR claimed_by = ?1 OR lock_expires_at <= ?12)",
                params![
                    agent,
                    claimed_at,
                    lock_expires,
                    notes,
                    revision,
                    next_owner,
                    waiting_on,
                    generation,
                    worktree_path,
                    branch,
                    id,
                    ts,
                    org
                ],
            )?;
            if n == 0 {
                return Err(UaError::conflict(format!("lost race to claim task {id}")));
            }
            emit(
                tx,
                &org,
                "agent.task.claimed",
                json!({
                    "task_id": id,
                    "agent": ledger_text(&org, &agent),
                    "lock_expires_at": lock_expires,
                    "renewal": renewal,
                    "replaced_expired_claim": ledger_label(&org, takeover.as_deref()),
                }),
                &agent,
            )?;
            let mut reply = task_reply(tx, &org, id)?;
            reply["claimed"] = json!(true);
            reply["renewal"] = json!(renewal);
            Ok(reply)
        })
        .await
}

//! Deliverable tools: the registry layer over the [`ua_deliverables`] domain
//! crate (`docs/deliverables.md`).
//!
//! Tools: `deliverable_create`, `deliverable_revise`, `deliverable_get` and
//! `deliverable_list`.
//!
//! This module holds what needs the rest of the hub: the argument structs,
//! the registrations, and the glue that resolves the task, the caller's
//! authority over it and the task's repository binding before it calls the
//! domain functions. It reuses the task workflow record's rules rather than
//! keeping its own:
//!
//! - who may create a deliverable or record a revision is who may write the
//!   task's workflow record (its claimant, its next owner, a lifecycle
//!   operator or a human: `continuity::require_writer`);
//! - the repository is the task's project's bound repository, resolved as
//!   task checks resolve it (`continuity::task_repo`), never named by the
//!   caller;
//! - recording a revision sets the capsule's `head_sha` through the same
//!   write as `task_workflow_set` (`continuity::write_capsule`), in the same
//!   transaction as the revision, so the checks on the task are graded at
//!   the recorded commit. The capsule head is the one place that says which
//!   commit the task is at; a deliverable stores no head of its own.
//!
//! Reads: tasks carry no read restriction inside an organization today, so a
//! deliverable is readable by every caller of the task's organization, and
//! by nobody else (a row of another organization answers `not_found`).

use rusqlite::Connection;
use rusqlite::types::Value as Sql;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_deliverables::{Kind, NewDeliverable, NewRevision, REVISIONS_PER_READ};
use ua_store::{Part, SchemaPart};

use crate::families::continuity::{capsule_head, require_writer, review_ready, task_repo, write_capsule};
use crate::families::tasks::{TASK_ORG, acting_identity, require_task};
use crate::registry::{Registry, ToolCtx, tool};

const FAMILY: &str = "deliverables";

pub fn schema_parts() -> Vec<Part> {
    ua_deliverables::schema_parts()
}

/// `deliverables.v2.task_org`: a deliverable's `task_id` points at a task in
/// the deliverable's own organization. It lives here, not in
/// `ua-deliverables`, because that crate's store has no `tasks` table.
/// `task_id` carries no foreign key, so a missing task passes as before, and
/// `deliverables_fixed` already refuses any change of `task_id`. Applied
/// after `organization.v1.tools.tasks` and `organization.v1.deliverables`.
pub const TASK_ORG_SCHEMA: SchemaPart = SchemaPart {
    name: "deliverables.v2.task_org",
    sql: "
CREATE TRIGGER IF NOT EXISTS deliverables_task_org BEFORE INSERT ON deliverables
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'a deliverable must point at a task in its own organization'); END;
",
};

// --- arguments ----------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateArgs {
    /// The task the deliverable is for.
    pub task_id: i64,
    /// What the deliverable is, 1-200 characters.
    pub title: String,
    /// `commit` (the default): a commit in the repository the task's project
    /// is bound to (`project_repo_bind`). A task has one commit deliverable.
    pub kind: Option<String>,
    /// Acting identity for an unverified caller; a verified caller acts as itself.
    pub actor: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviseArgs {
    /// The deliverable.
    pub deliverable_id: i64,
    /// The full 40-character hex commit SHA of this version of the work. It
    /// becomes the task's workflow head, where its checks are graded.
    pub commit: String,
    /// What changed in this revision, at most 500 characters.
    pub summary: Option<String>,
    /// Acting identity for an unverified caller; a verified caller acts as itself.
    pub actor: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetArgs {
    /// The deliverable.
    pub id: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// The task.
    pub task_id: i64,
}

// --- glue ---------------------------------------------------------------------------

fn positive(id: i64, field: &str) -> UaResult<i64> {
    if id > 0 { Ok(id) } else { Err(UaError::invalid(format!("{field} must be a positive integer"))) }
}

/// Refuse a caller of an unknown organization, or of another organization
/// than the task's.
fn require_caller_org(conn: &Connection, ctx: &ToolCtx) -> UaResult<()> {
    ua_deliverables::require_org_exists(conn, &ctx.caller.org_id)?;
    ua_org::authz::require_same_org(&ctx.caller, TASK_ORG)
}

/// The task's bound repository, or a refusal: a commit deliverable needs one.
fn bound_repo(conn: &Connection, task: &serde_json::Map<String, Value>, id: i64) -> UaResult<String> {
    task_repo(conn, task)?.ok_or_else(|| {
        UaError::denied(
            "repo_unbound",
            format!(
                "task {id}'s project has no bound repository (project_repo_bind): a commit deliverable needs one"
            ),
        )
    })
}

/// A deliverable with its revisions (newest first) and the task's workflow
/// head, which is where its checks are graded.
fn view(conn: &Connection, d: &ua_deliverables::Deliverable) -> UaResult<Value> {
    let revisions = ua_deliverables::revisions(conn, &d.org_id, d.id, REVISIONS_PER_READ)?;
    let count = ua_deliverables::revision_count(conn, &d.org_id, d.id)?;
    let head = capsule_head(conn, d.task_id)?;
    let latest = revisions.first();
    Ok(json!({
        "deliverable": d.to_json(),
        "latest_revision": latest.map(ua_deliverables::Revision::to_json),
        "revision_count": count,
        "revisions": revisions.iter().map(ua_deliverables::Revision::to_json).collect::<Vec<_>>(),
        "workflow_head": head,
        "latest_is_workflow_head": latest.is_some_and(|l| head.as_deref() == Some(l.identity.as_str())),
    }))
}

async fn create(ctx: ToolCtx, a: CreateArgs) -> UaResult<Value> {
    let task_id = positive(a.task_id, "task_id")?;
    let kind = Kind::parse(a.kind.as_deref().unwrap_or("commit"))?;
    let title = ua_deliverables::title(&a.title)?;
    let who = acting_identity(&ctx.caller, a.actor.as_deref())?;
    let ctx2 = ctx.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_caller_org(tx, &ctx2)?;
            let task = require_task(tx, task_id)?;
            require_writer(&ctx2, &task, &who, task_id)?;
            let repo = bound_repo(tx, &task, task_id)?;
            let (d, created) = ua_deliverables::create(
                tx,
                NewDeliverable { org_id: TASK_ORG, task_id, kind, title: &title, repo: &repo, by: &who },
            )?;
            let mut out = view(tx, &d)?;
            out["created"] = json!(created);
            Ok(out)
        })
        .await
}

async fn revise(ctx: ToolCtx, a: ReviseArgs) -> UaResult<Value> {
    let id = positive(a.deliverable_id, "deliverable_id")?;
    let commit = ua_deliverables::commit_identity(&a.commit)?;
    let summary = ua_deliverables::summary(a.summary.as_deref())?;
    let who = acting_identity(&ctx.caller, a.actor.as_deref())?;
    let ctx2 = ctx.clone();
    let (out, task_id, moved) = ctx
        .hub
        .db()
        .write_async(move |tx| {
            require_caller_org(tx, &ctx2)?;
            let d = ua_deliverables::deliverable(tx, &ctx2.caller.org_id, id)?
                .ok_or_else(|| UaError::not_found(format!("no deliverable with id {id}")))?;
            let task = require_task(tx, d.task_id)?;
            require_writer(&ctx2, &task, &who, d.task_id)?;
            let repo = bound_repo(tx, &task, d.task_id)?;
            let (d, rev, recorded) = ua_deliverables::record_revision(
                tx,
                NewRevision {
                    org_id: TASK_ORG,
                    deliverable_id: d.id,
                    commit: &commit,
                    repo: &repo,
                    summary: summary.as_deref(),
                    producer: &who,
                },
            )?;
            // The capsule head moves to the revision through the workflow
            // record's own write (and its ledger event), in this transaction.
            let moved = capsule_head(tx, d.task_id)?.as_deref() != Some(rev.identity.as_str());
            if moved {
                write_capsule(
                    tx,
                    &ctx2,
                    d.task_id,
                    &who,
                    vec![("head_sha", Sql::Text(rev.identity.clone()))],
                    None,
                )?;
            }
            let mut out = view(tx, &d)?;
            out["revision"] = rev.to_json();
            out["recorded"] = json!(recorded);
            Ok((out, d.task_id, moved))
        })
        .await?;
    if moved {
        review_ready(&ctx.hub, task_id).await;
    }
    Ok(out)
}

async fn get(ctx: ToolCtx, a: GetArgs) -> UaResult<Value> {
    let id = positive(a.id, "id")?;
    let db = ctx.hub.db().clone();
    db.read_async(move |c| {
        require_caller_org(c, &ctx)?;
        let d = ua_deliverables::deliverable(c, &ctx.caller.org_id, id)?
            .ok_or_else(|| UaError::not_found(format!("no deliverable with id {id}")))?;
        view(c, &d)
    })
    .await
}

async fn list(ctx: ToolCtx, a: ListArgs) -> UaResult<Value> {
    let task_id = positive(a.task_id, "task_id")?;
    let db = ctx.hub.db().clone();
    db.read_async(move |c| {
        require_caller_org(c, &ctx)?;
        require_task(c, task_id)?;
        let rows = ua_deliverables::for_task(c, &ctx.caller.org_id, task_id)?;
        let mut items = Vec::with_capacity(rows.len());
        for d in &rows {
            let mut item = d.to_json();
            item["revision_count"] = json!(ua_deliverables::revision_count(c, &d.org_id, d.id)?);
            item["latest_revision"] =
                json!(ua_deliverables::latest(c, &d.org_id, d.id)?.map(|r| r.to_json()));
            items.push(item);
        }
        Ok(json!({
            "task_id": task_id,
            "workflow_head": capsule_head(c, task_id)?,
            "deliverables": items,
        }))
    })
    .await
}

// --- registration -------------------------------------------------------------------

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "deliverable_create",
            "Attach a deliverable to a task: what the task produces. Kind `commit` (the default) is a commit in \
             the repository the task's project is bound to; a task has one, and creating it again with the same \
             title returns it (`created: false`). Only the task's claimant, its next owner, a lifecycle operator \
             or a human may. Refused without a repository binding (`repo_unbound`).",
            create,
        )
        .family(FAMILY),
    );
    r.add(
        tool(
            "deliverable_revise",
            "Record a new revision of a commit deliverable: the full 40-hex commit SHA, numbered after the \
             previous one, immutable. It also sets the task's workflow head to that commit (task_workflow_get \
             grades checks there). The same commit and summary again returns the latest revision \
             (`recorded: false`); another summary (`revision_conflict`), an earlier revision's commit \
             (`revision_not_latest`) or a changed repository binding (`repo_mismatch`) is refused. Same writers \
             as deliverable_create.",
            revise,
        )
        .family(FAMILY),
    );
    r.add(
        tool(
            "deliverable_get",
            "Read a deliverable: its task, kind and repository, its revisions (newest first, at most 100) and the \
             task's workflow head, with `latest_is_workflow_head`.",
            get,
        )
        .family(FAMILY)
        .read_only(),
    );
    r.add(
        tool(
            "deliverable_list",
            "List a task's deliverables, each with its revision count and latest revision, and the task's \
             workflow head.",
            list,
        )
        .family(FAMILY)
        .read_only(),
    );
}

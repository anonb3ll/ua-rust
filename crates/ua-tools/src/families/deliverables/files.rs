//! Registry entry points for task-bound file revisions and directory release.

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{Caller, UaError, UaResult};
use ua_deliverables::files::{self, FileRevision, Release, Submission, digest};
use ua_org::authz::{Authority, Authz};
use ua_store::WriteTx;

use super::{FAMILY, caller_task, positive, require_caller_org, require_writer, view, write_capsule};
use crate::approvals::{self, GateOutcome};
use crate::families::governance;
use crate::families::tasks::{check_release_completion, complete_after_release, int_field, str_field};
use crate::registry::{Registry, ToolCtx, tool};

#[cfg(unix)]
use super::file_io::{self, Destination};
#[cfg(not(unix))]
use super::unsupported_io::{self as file_io, Destination};

pub(crate) const RELEASE_TOOL: &str = "deliverable_release";

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SubmitArgs {
    /// Task with a worktree inside the caller's workspace.
    task_id: i64,
    /// Name identifying this file deliverable within the task (1-200 characters).
    title: String,
    /// Relative path to a regular file inside the task worktree, at most 1 MiB.
    path: String,
    /// What changed in this revision, at most 500 characters.
    summary: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct VerifyArgs {
    /// File revision to compare against its source or released copy.
    revision_id: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReleaseArgs {
    /// Exact file revision to release. It must still be the latest.
    revision_id: i64,
    /// A new basename under the operator-configured release directory.
    destination: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CancelArgs {
    /// Approval ID of the exact pending release to cancel.
    approval_id: i64,
}

fn require_file_caller(caller: &Caller) -> UaResult<()> {
    if caller.org_id != ua_core::DEFAULT_ORG {
        return Err(crate::families::workspace::workspace_org_unsupported());
    }
    if ua_org::authz::verified_label(caller).is_none() {
        return Err(UaError::Unauthenticated("file deliverables require a verified agent or human".into()));
    }
    Ok(())
}

fn destination_name(name: &str) -> UaResult<()> {
    if name.len() > 120
        || !name.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || name.ends_with('.')
    {
        return Err(UaError::invalid(
            "destination must be a single visible filename with 1-120 ASCII letters, digits, dots, dashes or underscores",
        ));
    }
    ua_core::safety::guard_secret_filename(std::path::Path::new(name))
}

fn task_source(ctx: &ToolCtx, task: &serde_json::Map<String, Value>, path: &str) -> UaResult<Vec<u8>> {
    let worktree = str_field(task, "worktree_path")
        .filter(|p| !p.is_empty())
        .ok_or_else(|| UaError::denied("task_worktree_required", "the task has no worktree"))?;
    file_io::source(ctx, worktree, path)
}

fn writable_task(conn: &Connection, ctx: &ToolCtx, id: i64) -> UaResult<serde_json::Map<String, Value>> {
    let task = caller_task(conn, ctx, id)?;
    require_writer(ctx, &task, &ctx.caller.label, id)?;
    Ok(task)
}

fn require_live(task: &serde_json::Map<String, Value>) -> UaResult<()> {
    let closed = matches!(str_field(task, "status"), Some("done" | "cancelled"));
    if closed
        || str_field(task, "archived_at").is_some()
        || str_field(task, "parked_at").is_some()
        || int_field(task, "untrusted").unwrap_or(0) != 0
    {
        return Err(UaError::denied("task_unavailable", "file deliverables require an active, trusted task"));
    }
    Ok(())
}

async fn submit(ctx: ToolCtx, a: SubmitArgs) -> UaResult<Value> {
    require_file_caller(&ctx.caller)?;
    let id = positive(a.task_id, "task_id")?;
    let title = ua_deliverables::title(&a.title)?;
    let summary = ua_deliverables::summary(a.summary.as_deref())?;
    let db = ctx.hub.db().clone();
    db.write_async(move |tx| {
        require_caller_org(tx, &ctx)?;
        let task = writable_task(tx, &ctx, id)?;
        require_live(&task)?;
        let bytes = task_source(&ctx, &task, &a.path)?;
        let (file, recorded) = files::submit(
            tx,
            Submission {
                org: &ctx.caller.org_id,
                task_id: id,
                title: &title,
                source_path: &a.path,
                bytes: &bytes,
                summary: summary.as_deref(),
                producer: &ctx.caller.label,
            },
        )?;
        let mut out = view(tx, &file.deliverable)?;
        out["revision"] = file.revision.to_json();
        out["size_bytes"] = json!(file.size_bytes);
        out["recorded"] = json!(recorded);
        Ok(out)
    })
    .await
}

async fn verify(ctx: ToolCtx, a: VerifyArgs) -> UaResult<Value> {
    require_file_caller(&ctx.caller)?;
    let id = positive(a.revision_id, "revision_id")?;
    let db = ctx.hub.db().clone();
    db.read_async(move |conn| {
        let file = files::file_revision(conn, &ctx.caller.org_id, id)?;
        let release = files::release(conn, &ctx.caller.org_id, id)?;
        let (target, matches) = if let Some(r) = release.filter(|r| r.released_at.is_some()) {
            if r.requester != ctx.caller.label {
                writable_task(conn, &ctx, file.deliverable.task_id)?;
            }
            let dir = Destination::configured(&ctx)?;
            require_root(&dir, &r)?;
            destination_name(&r.destination)?;
            ("release", dir.matches(&r.destination, &file.revision.identity)?)
        } else {
            let task = writable_task(conn, &ctx, file.deliverable.task_id)?;
            ("source", digest(&task_source(&ctx, &task, &file.source_path)?) == file.revision.identity)
        };
        Ok(json!({ "revision_id": id, "sha256": file.revision.identity, "target": target, "matches": matches }))
    }).await
}

fn review_binding(
    tx: &mut WriteTx<'_>,
    ctx: &ToolCtx,
    task: &serde_json::Map<String, Value>,
    file: &FileRevision,
) -> UaResult<(i64, i64)> {
    require_live(task)?;
    let org = &ctx.caller.org_id;
    let task_id = file.deliverable.task_id;
    governance::check_claim(tx, org, Some(&ctx.caller.label), Some(task_id), false)?;
    if ua_deliverables::latest(tx, org, file.deliverable.id)?.is_none_or(|r| r.id != file.revision.id) {
        return Err(UaError::conflict_code(
            "revision_not_latest",
            "review the latest file revision before release",
        ));
    }
    let workflow_revision = tx
        .query_row(
            "SELECT revision FROM task_workflow WHERE org_id = ?1 AND task_id = ?2 AND stage = 'review'",
            params![org, task_id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| UaError::denied("review_required", "the task workflow must be in review"))?;
    check_release_completion(tx, org, task_id, task)?;
    let generation = int_field(task, "ownership_generation")
        .ok_or_else(|| UaError::internal("task ownership generation is missing"))?;
    Ok((workflow_revision, generation))
}

fn require_root(dir: &Destination, r: &Release) -> UaResult<()> {
    if r.root_identity != dir.identity {
        return Err(UaError::conflict_code(
            "release_root_changed",
            "the authorized release directory changed",
        ));
    }
    Ok(())
}

fn release_location(ctx: &ToolCtx, r: &Release) -> UaResult<(Destination, String)> {
    let dir = Destination::configured(ctx)?;
    require_root(&dir, r)?;
    destination_name(&r.destination)?;
    let staging_id = r
        .staging_id
        .parse::<ulid::Ulid>()
        .map_err(|_| UaError::internal("release has an invalid staging id"))?;
    Ok((dir, format!(".ua-release-{staging_id}")))
}

enum Admission {
    Authorized(i64),
    Refused(UaError),
}

fn authorize(tx: &mut WriteTx<'_>, ctx: &ToolCtx, a: &ReleaseArgs) -> UaResult<Admission> {
    let org = &ctx.caller.org_id;
    let file = files::file_revision(tx, org, a.revision_id)?;
    if let Some(release) = files::release(tx, org, a.revision_id)? {
        if release.requester != ctx.caller.label || release.destination != a.destination {
            return Err(UaError::conflict_code(
                "revision_release_bound",
                "this revision is already bound to a release",
            ));
        }
        require_root(&Destination::configured(ctx)?, &release)?;
        return Ok(Admission::Authorized(release.approval_id));
    }
    let task = writable_task(tx, ctx, file.deliverable.task_id)?;
    let dir = Destination::configured(ctx)?;
    let (workflow_revision, ownership_generation) = review_binding(tx, ctx, &task, &file)?;
    if files::destination_reserved(tx, org, &dir.identity, &a.destination)? {
        return Err(UaError::conflict_code(
            "release_destination_exists",
            "the release destination is already reserved",
        ));
    }
    dir.check_absent(&a.destination)?;
    let bytes = task_source(ctx, &task, &file.source_path)?;
    if digest(&bytes) != file.revision.identity {
        files::record_tamper(tx, &file, &ctx.caller.label)?;
        return Ok(Admission::Refused(UaError::denied(
            "deliverable_tampered",
            "source bytes changed since submission",
        )));
    }
    let mut payload = json!({
        "task_id": file.deliverable.task_id, "deliverable_id": file.deliverable.id, "revision_id": a.revision_id,
        "sha256": file.revision.identity, "size_bytes": file.size_bytes, "producer": file.revision.producer,
        "workflow_revision": workflow_revision, "ownership_generation": ownership_generation,
        "destination": a.destination, "root_identity": dir.identity,
    });
    // Bind the next approval to this cancellation, including approvals
    // already granted for a different destination of the same revision.
    if let Some(cancelled) = files::latest_cancellation(tx, org, a.revision_id)? {
        payload["cancelled_release_approval_id"] = json!(cancelled);
    }
    match approvals::gate(tx, ctx.hub.cfg(), &ctx.caller, RELEASE_TOOL, &payload)? {
        GateOutcome::Pending { approval_id } => {
            Ok(Admission::Refused(UaError::ApprovalRequired { tool: RELEASE_TOOL.into(), approval_id }))
        }
        GateOutcome::Denied { approval_id, reason } => Ok(Admission::Refused(UaError::denied(
            "approval_denied",
            format!("release approval {approval_id} was denied: {}", reason.unwrap_or_default()),
        ))),
        GateOutcome::Pass { approval_id } => {
            let row = approvals::get(tx, org, approval_id)?;
            let approver = row.resolved_by.ok_or_else(|| UaError::internal("approval has no resolver"))?;
            require_independent(&payload, &ctx.caller.label, &approver)?;
            files::authorize(
                tx,
                &file,
                &Release {
                    approval_id,
                    revision_id: a.revision_id,
                    requester: ctx.caller.label.clone(),
                    approver,
                    destination: a.destination.clone(),
                    root_identity: dir.identity.clone(),
                    staging_id: ulid::Ulid::generate().to_string(),
                    workflow_revision,
                    ownership_generation,
                    payload: Some(bytes),
                    released_at: None,
                    cancelled_at: None,
                },
            )?;
            Ok(Admission::Authorized(approval_id))
        }
    }
}

pub(crate) fn require_independent(payload: &Value, requester: &str, resolver: &str) -> UaResult<()> {
    let producer = payload["producer"].as_str().ok_or_else(|| {
        UaError::denied("approval_binding_missing", "release approval is missing its file producer")
    })?;
    if resolver.eq_ignore_ascii_case(requester) || resolver.eq_ignore_ascii_case(producer) {
        return Err(UaError::denied(
            "self_approval",
            "the approver must differ from both requester and file producer",
        ));
    }
    Ok(())
}

fn release_output(file: &FileRevision, r: &Release, at: String, created: bool) -> Value {
    json!({
        "revision_id": file.revision.id, "deliverable_id": file.deliverable.id,
        "task_id": file.deliverable.task_id, "sha256": file.revision.identity,
        "destination": r.destination, "approval_id": r.approval_id, "approver": r.approver,
        "released_at": at, "created": created,
    })
}

async fn release(ctx: ToolCtx, a: ReleaseArgs) -> UaResult<Value> {
    require_file_caller(&ctx.caller)?;
    let id = positive(a.revision_id, "revision_id")?;
    destination_name(&a.destination)?;
    let db = ctx.hub.db().clone();
    let ctx2 = ctx.clone();
    let approval_id = match db.write_async(move |tx| authorize(tx, &ctx2, &a)).await? {
        Admission::Authorized(approval_id) => approval_id,
        Admission::Refused(e) => return Err(e),
    };

    // The pass and the approved bytes have committed. Keep the staged inode
    // until the completion transaction commits so a retry can recognize a
    // publication even if the ledger or database commit failed.
    let (out, dir, staging) = db
        .write_async(move |tx| {
            let org = &ctx.caller.org_id;
            let r = files::release_by_approval(tx, org, approval_id)?
                .ok_or_else(|| UaError::internal("authorized release is missing"))?;
            if r.cancelled_at.is_some() {
                return Err(UaError::conflict_code(
                    "release_cancelled",
                    "the authorized release was cancelled",
                ));
            }
            let file = files::file_revision(tx, org, r.revision_id)?;
            let task_id = file.deliverable.task_id;
            let (dir, staging) = release_location(&ctx, &r)?;
            if let Some(at) = &r.released_at {
                if !dir.matches(&r.destination, &file.revision.identity)? {
                    return Err(UaError::denied("deliverable_tampered", "released bytes changed"));
                }
                return Ok((release_output(&file, &r, at.clone(), false), dir, staging));
            }
            let published = dir.confirm_published(&staging, &r.destination, &file.revision.identity)?;
            let expected = (r.workflow_revision, r.ownership_generation);
            let current =
                writable_task(tx, &ctx, task_id).and_then(|task| review_binding(tx, &ctx, &task, &file));
            let finish_task = match current {
                Ok(binding) if binding == expected => true,
                Ok(_) if published => false,
                Ok(_) => {
                    return Err(UaError::conflict_code(
                        "release_review_changed",
                        "task review or ownership changed after approval",
                    ));
                }
                Err(
                    UaError::NotFound(_)
                    | UaError::Denied { .. }
                    | UaError::InvalidArgument(_)
                    | UaError::Conflict(_)
                    | UaError::ConflictCode { .. },
                ) if published => false,
                Err(e) => return Err(e),
            };

            // An authorized file already present at the destination needs
            // its receipt even if the task moved on. Only an unchanged
            // review can complete the task or authorize a new publication.
            let at = files::complete(tx, &file, &r)?;
            if finish_task {
                write_capsule(
                    tx,
                    &ctx,
                    task_id,
                    &ctx.caller.label,
                    vec![("stage", rusqlite::types::Value::Text("done".into()))],
                    Some(r.workflow_revision),
                )?;
                complete_after_release(tx, org, task_id, &ctx.caller.label)?;
            }
            if !published {
                let bytes = r
                    .payload
                    .as_deref()
                    .ok_or_else(|| UaError::internal("authorized release has no bytes"))?;
                if digest(bytes) != file.revision.identity {
                    return Err(UaError::denied("deliverable_tampered", "stored release bytes changed"));
                }
                dir.publish(&staging, &r.destination, bytes, &file.revision.identity)?;
            }
            Ok((release_output(&file, &r, at, true), dir, staging))
        })
        .await?;
    dir.clean_staging(&staging);
    Ok(out)
}

async fn cancel_release(ctx: ToolCtx, a: CancelArgs) -> UaResult<Value> {
    require_file_caller(&ctx.caller)?;
    Authz::new(ctx.hub.cfg()).require(&ctx.caller, &[Authority::Operator], &ctx.caller.org_id)?;
    let approval_id = positive(a.approval_id, "approval_id")?;
    let db = ctx.hub.db().clone();
    let (out, cleanup) = db
        .write_async(move |tx| {
            let org = &ctx.caller.org_id;
            require_caller_org(tx, &ctx)?;
            let r = files::release_by_approval(tx, org, approval_id)?
                .ok_or_else(|| UaError::not_found("file release for this approval"))?;
            let (at, cancelled, cleanup) = if let Some(at) = &r.cancelled_at {
                // Retry private staging cleanup if a prior call committed before cleaning up.
                let cleanup = release_location(&ctx, &r)
                    .ok()
                    .filter(|(dir, staging)| dir.check_unpublished(staging, &r.destination).is_ok());
                (at.clone(), false, cleanup)
            } else {
                if r.released_at.is_some() {
                    return Err(UaError::conflict_code(
                        "release_already_published",
                        "a published file release cannot be cancelled",
                    ));
                }
                let (dir, staging) = release_location(&ctx, &r)?;
                dir.check_unpublished(&staging, &r.destination)?;
                let file = files::file_revision(tx, org, r.revision_id)?;
                let at = files::cancel(tx, &file, &r, &ctx.caller.label)?;
                (at, true, Some((dir, staging)))
            };
            Ok((
                json!({
                    "approval_id": approval_id, "revision_id": r.revision_id,
                    "cancelled_at": at, "cancelled": cancelled,
                }),
                cleanup,
            ))
        })
        .await?;
    if let Some((dir, staging)) = cleanup {
        dir.clean_staging(&staging);
    }
    Ok(out)
}

pub(super) fn register(r: &mut Registry) {
    r.add(tool(
        "deliverable_submit",
        "Record a file revision from a task worktree. The hub hashes the file and records its length and producer. Reuse the title for a new revision.",
        submit,
    ).family(FAMILY));
    r.add(tool(
        "deliverable_verify",
        "Compare a file revision's SHA-256 to its current source or released copy. Returns the verification result without file content.",
        verify,
    ).family(FAMILY).read_only());
    r.add(tool(
        RELEASE_TOOL,
        "Release the latest file revision from a task in review to a new filename in the configured directory. Requires a distinct human's approval of the exact revision, SHA-256 and destination; retry the same request after approval.",
        release,
    ).family(FAMILY).always_gated().gates_in_handler());
    r.add(tool(
        "deliverable_release_cancel",
        "Cancel a pending unpublished file release by its exact approval ID, discard pending bytes and free its destination. Requires a verified human operator.",
        cancel_release,
    ).family(FAMILY));
}

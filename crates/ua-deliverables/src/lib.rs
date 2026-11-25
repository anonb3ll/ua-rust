//! Deliverables: what a task is for, and each version of it.
//!
//! A deliverable is a typed attachment to a task. Its revisions are
//! immutable and ordered: revision 1 is the first one recorded, and a new
//! version of the work is a new revision, never an edit of an old one. For
//! the `commit` kind a revision's identity is
//! the full 40-hex commit SHA, in the repository the task's project is bound
//! to. A file revision records the SHA-256 of a task worktree file.
//! See `docs/deliverables.md`.
//!
//! This crate is the domain: the schema ([`schema`]), validation, and the
//! reads and writes over the deliverable tables. It depends on `ua-core` and
//! `ua-store` only, never on the tool registry. The tools
//! (`deliverable_create`, `deliverable_revise`, `deliverable_get`,
//! `deliverable_list`) are registered by `ua-tools`
//! (`families/deliverables`), which resolves the task, its repository
//! binding and the caller's authority, and calls the functions here inside
//! the same write transaction that moves the task's workflow head. Adapters
//! do not call this crate directly.
//!
//! Every write takes a [`WriteTx`] and appends its `agent.deliverable.*`
//! ledger event in that transaction. Event payloads carry ids, the kind,
//! the repository and the revision identity; never a title or summary.

pub mod files;
pub mod schema;

pub use schema::{SCHEMA, TENANT_PART, schema_parts};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use ua_core::{DEFAULT_ORG, UaError, UaResult};
use ua_store::{EventInput, WriteTx, ledger};

/// Ledger channel of a new deliverable.
pub const CREATED: &str = "agent.deliverable.created";
/// Ledger channel of a new revision.
pub const REVISED: &str = "agent.deliverable.revised";

/// The longest title, in characters.
pub const TITLE_MAX: usize = 200;
/// The longest revision summary, in characters.
pub const SUMMARY_MAX: usize = 500;
/// The most revisions one read returns (newest first).
pub const REVISIONS_PER_READ: i64 = 100;

/// What a deliverable is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A commit in the task's project's bound repository.
    Commit,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Commit => "commit",
        }
    }

    /// Parse the kind for commit creation. File submissions have their own entry point.
    pub fn parse(raw: &str) -> UaResult<Kind> {
        match raw.trim() {
            "commit" => Ok(Kind::Commit),
            "file" => Err(UaError::invalid("kind \"file\" is submitted through deliverable_submit")),
            other => Err(UaError::invalid(format!("kind must be \"commit\", not {other:?}"))),
        }
    }
}

/// A commit revision's identity: the full 40-hex SHA, lowercased. An
/// abbreviated SHA is ambiguous and refused.
pub fn commit_identity(raw: &str) -> UaResult<String> {
    let s = raw.trim().to_ascii_lowercase();
    if s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(s)
    } else {
        Err(UaError::invalid(
            "commit must be the full 40-character hex commit SHA: an abbreviated SHA is ambiguous",
        ))
    }
}

/// A trimmed title of 1 to [`TITLE_MAX`] characters.
pub fn title(raw: &str) -> UaResult<String> {
    let t = raw.trim();
    if t.is_empty() || t.chars().count() > TITLE_MAX {
        return Err(UaError::invalid(format!("title must be 1-{TITLE_MAX} characters")));
    }
    Ok(t.to_string())
}

/// A trimmed summary of at most [`SUMMARY_MAX`] characters; empty is none.
pub fn summary(raw: Option<&str>) -> UaResult<Option<String>> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else { return Ok(None) };
    if s.chars().count() > SUMMARY_MAX {
        return Err(UaError::invalid(format!("summary must be at most {SUMMARY_MAX} characters")));
    }
    Ok(Some(s.to_string()))
}

/// The organization a row is written in, checked: it must exist, and until
/// organizations other than the default exist it must be the default one.
fn row_org(conn: &Connection, org_id: &str) -> UaResult<&'static str> {
    require_org_exists(conn, org_id)?;
    if org_id != DEFAULT_ORG {
        return Err(UaError::denied(
            "org_mismatch",
            format!(
                "only the {DEFAULT_ORG:?} organization holds tasks; refusing a deliverable in {org_id:?}"
            ),
        ));
    }
    Ok(DEFAULT_ORG)
}

/// Refuse an organization that does not exist.
pub fn require_org_exists(conn: &Connection, org_id: &str) -> UaResult<()> {
    let found = conn.query_row("SELECT 1 FROM orgs WHERE id = ?1", [org_id], |_| Ok(())).optional()?;
    if found.is_none() {
        return Err(UaError::denied(
            "unknown_organization",
            format!("organization {org_id:?} does not exist"),
        ));
    }
    Ok(())
}

// --- rows --------------------------------------------------------------------------

/// One deliverable row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deliverable {
    pub id: i64,
    pub org_id: String,
    pub task_id: i64,
    pub kind: String,
    pub title: String,
    pub repo: Option<String>,
    pub created_by: String,
    pub created_at: String,
}

impl Deliverable {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "org_id": self.org_id,
            "task_id": self.task_id,
            "kind": self.kind,
            "title": self.title,
            "repo": self.repo,
            "created_by": self.created_by,
            "created_at": self.created_at,
        })
    }
}

const DELIVERABLE_COLUMNS: &str = "id, org_id, task_id, kind, title, repo, created_by, created_at";

fn deliverable_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Deliverable> {
    Ok(Deliverable {
        id: r.get(0)?,
        org_id: r.get(1)?,
        task_id: r.get(2)?,
        kind: r.get(3)?,
        title: r.get(4)?,
        repo: r.get(5)?,
        created_by: r.get(6)?,
        created_at: r.get(7)?,
    })
}

/// One revision row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    pub id: i64,
    pub deliverable_id: i64,
    pub rev_no: i64,
    pub identity: String,
    pub repo: Option<String>,
    pub summary: Option<String>,
    pub producer: String,
    pub recorded_at: String,
}

impl Revision {
    /// The revision as callers see it: for a commit, `commit` is the identity.
    pub fn to_json(&self) -> Value {
        let mut out = json!({
            "id": self.id,
            "deliverable_id": self.deliverable_id,
            "rev_no": self.rev_no,
            "repo": self.repo,
            "summary": self.summary,
            "producer": self.producer,
            "recorded_at": self.recorded_at,
        });
        let key = if self.repo.is_some() { "commit" } else { "sha256" };
        out[key] = json!(self.identity);
        out
    }
}

const REVISION_COLUMNS: &str = "id, deliverable_id, rev_no, identity, repo, summary, producer, recorded_at";

fn revision_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Revision> {
    Ok(Revision {
        id: r.get(0)?,
        deliverable_id: r.get(1)?,
        rev_no: r.get(2)?,
        identity: r.get(3)?,
        repo: r.get(4)?,
        summary: r.get(5)?,
        producer: r.get(6)?,
        recorded_at: r.get(7)?,
    })
}

// --- reads -------------------------------------------------------------------------

/// Deliverable `id` in organization `org_id`; `None` for an unknown id or
/// another organization's row.
pub fn deliverable(conn: &Connection, org_id: &str, id: i64) -> UaResult<Option<Deliverable>> {
    Ok(conn
        .query_row(
            &format!("SELECT {DELIVERABLE_COLUMNS} FROM deliverables WHERE org_id = ?1 AND id = ?2"),
            params![org_id, id],
            deliverable_row,
        )
        .optional()?)
}

/// Task `task_id`'s deliverables in organization `org_id`, oldest first.
pub fn for_task(conn: &Connection, org_id: &str, task_id: i64) -> UaResult<Vec<Deliverable>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {DELIVERABLE_COLUMNS} FROM deliverables WHERE org_id = ?1 AND task_id = ?2 ORDER BY id"
    ))?;
    let rows = stmt.query_map(params![org_id, task_id], deliverable_row)?.collect::<Result<_, _>>()?;
    Ok(rows)
}

/// The newest revisions of a deliverable, newest first, at most `limit`.
pub fn revisions(
    conn: &Connection,
    org_id: &str,
    deliverable_id: i64,
    limit: i64,
) -> UaResult<Vec<Revision>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {REVISION_COLUMNS} FROM deliverable_revisions WHERE org_id = ?1 AND deliverable_id = ?2 \
         ORDER BY rev_no DESC LIMIT ?3"
    ))?;
    let rows =
        stmt.query_map(params![org_id, deliverable_id, limit], revision_row)?.collect::<Result<_, _>>()?;
    Ok(rows)
}

/// The latest revision of a deliverable, if it has one.
pub fn latest(conn: &Connection, org_id: &str, deliverable_id: i64) -> UaResult<Option<Revision>> {
    Ok(revisions(conn, org_id, deliverable_id, 1)?.into_iter().next())
}

/// How many revisions a deliverable has.
pub fn revision_count(conn: &Connection, org_id: &str, deliverable_id: i64) -> UaResult<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM deliverable_revisions WHERE org_id = ?1 AND deliverable_id = ?2",
        params![org_id, deliverable_id],
        |r| r.get(0),
    )?)
}

/// The commit deliverable revision of `task_id` matching `identity` (full
/// 40-hex commit SHA, case-insensitive), if one was recorded in `org_id`.
pub fn commit_revision_for_task(
    conn: &Connection,
    org_id: &str,
    task_id: i64,
    identity: &str,
) -> UaResult<Option<Revision>> {
    let identity = identity.trim().to_ascii_lowercase();
    Ok(conn
        .query_row(
            "SELECT r.id, r.deliverable_id, r.rev_no, r.identity, r.repo, r.summary, r.producer, r.recorded_at \
             FROM deliverable_revisions r \
             JOIN deliverables d ON d.id = r.deliverable_id AND d.org_id = r.org_id \
             WHERE d.org_id = ?1 AND d.task_id = ?2 AND d.kind = 'commit' AND r.identity = ?3",
            params![org_id, task_id, identity],
            revision_row,
        )
        .optional()?)
}

// --- writes ------------------------------------------------------------------------

/// A deliverable to create. The caller has resolved the task, the caller's
/// authority over it and, for a commit, the task's bound repository.
#[derive(Debug, Clone)]
pub struct NewDeliverable<'a> {
    /// The task's organization.
    pub org_id: &'a str,
    pub task_id: i64,
    pub kind: Kind,
    /// Already validated with [`title`].
    pub title: &'a str,
    /// The task's project's bound repository (`owner/name`).
    pub repo: &'a str,
    pub by: &'a str,
}

/// Create a deliverable, or return the task's existing one when it is the
/// same (`created` false). A task has at most one commit deliverable; a
/// second one with another title is refused (`deliverable_exists`).
pub fn create(tx: &mut WriteTx<'_>, d: NewDeliverable<'_>) -> UaResult<(Deliverable, bool)> {
    let org = row_org(tx, d.org_id)?;
    let existing = for_task(tx, org, d.task_id)?.into_iter().find(|x| x.kind == d.kind.as_str());
    if let Some(x) = existing {
        if x.title == d.title && x.repo.as_deref() == Some(d.repo) {
            return Ok((x, false));
        }
        return Err(UaError::conflict_code(
            "deliverable_exists",
            format!(
                "task {} already has {} deliverable {} ({:?} in {}); a task has one commit deliverable, so \
                 record a revision on it",
                d.task_id,
                x.kind,
                x.id,
                x.title,
                x.repo.as_deref().unwrap_or("no repository")
            ),
        ));
    }
    let now = ua_core::time::now();
    tx.execute(
        "INSERT INTO deliverables (org_id, task_id, kind, title, repo, created_by, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![org, d.task_id, d.kind.as_str(), d.title, d.repo, d.by, now],
    )?;
    let id = tx.last_insert_rowid();
    ledger::append(
        tx,
        EventInput::new(
            DEFAULT_ORG,
            CREATED,
            json!({
                "org_id": org, "deliverable_id": id, "task_id": d.task_id, "kind": d.kind.as_str(), "repo": d.repo,
            }),
        )
        .by(d.by.to_string()),
    )?;
    let row = deliverable(tx, org, id)?.ok_or_else(|| UaError::internal("the new deliverable is missing"))?;
    Ok((row, true))
}

/// A revision to record. The caller has resolved the deliverable's task,
/// the caller's authority over it and the task's bound repository now.
#[derive(Debug, Clone)]
pub struct NewRevision<'a> {
    /// The caller's organization (the deliverable must be in it).
    pub org_id: &'a str,
    pub deliverable_id: i64,
    /// The commit as given; validated with [`commit_identity`].
    pub commit: &'a str,
    /// The task's project's bound repository now.
    pub repo: &'a str,
    /// Already validated with [`summary`].
    pub summary: Option<&'a str>,
    pub producer: &'a str,
}

/// Record a revision, or return the latest one when it is the same commit
/// with the same summary (`recorded` false).
///
/// Refused: an abbreviated or non-hex commit; a bound repository other than
/// the deliverable's (`repo_mismatch`); the latest commit again with another
/// summary (`revision_conflict`); an earlier revision's commit
/// (`revision_not_latest`: revisions only move forward).
pub fn record_revision(tx: &mut WriteTx<'_>, r: NewRevision<'_>) -> UaResult<(Deliverable, Revision, bool)> {
    let org = row_org(tx, r.org_id)?;
    let identity = commit_identity(r.commit)?;
    let d = deliverable(tx, org, r.deliverable_id)?
        .ok_or_else(|| UaError::not_found(format!("no deliverable with id {}", r.deliverable_id)))?;
    if d.kind != Kind::Commit.as_str() {
        return Err(UaError::invalid(format!("deliverable {} is not a commit deliverable", d.id)));
    }
    let want = d.repo.as_deref().unwrap_or_default();
    if !want.eq_ignore_ascii_case(r.repo) {
        return Err(UaError::denied(
            "repo_mismatch",
            format!(
                "deliverable {} is in repository {want:?}, but task {}'s project is bound to {:?} now; a revision \
                 is a commit in the deliverable's repository",
                d.id, d.task_id, r.repo
            ),
        ));
    }
    let latest = latest(tx, org, d.id)?;
    let seen: Option<Revision> = tx
        .query_row(
            &format!(
                "SELECT {REVISION_COLUMNS} FROM deliverable_revisions WHERE org_id = ?1 AND deliverable_id = ?2 \
                 AND identity = ?3"
            ),
            params![org, d.id, identity],
            revision_row,
        )
        .optional()?;
    if let Some(seen) = seen {
        let is_latest = latest.as_ref().is_some_and(|l| l.id == seen.id);
        if !is_latest {
            return Err(UaError::conflict_code(
                "revision_not_latest",
                format!(
                    "commit {} is revision {} of deliverable {}, and revision {} is newer; revisions only move \
                     forward, so record the work as a new commit",
                    short(&identity),
                    seen.rev_no,
                    d.id,
                    latest.as_ref().map_or(0, |l| l.rev_no)
                ),
            ));
        }
        if seen.summary.as_deref() != r.summary {
            return Err(UaError::conflict_code(
                "revision_conflict",
                format!(
                    "commit {} is already revision {} of deliverable {} with another summary; a revision is \
                     immutable",
                    short(&identity),
                    seen.rev_no,
                    d.id
                ),
            ));
        }
        return Ok((d, seen, false));
    }
    let rev_no = latest.as_ref().map_or(1, |l| l.rev_no + 1);
    let now = ua_core::time::now();
    tx.execute(
        "INSERT INTO deliverable_revisions (org_id, deliverable_id, rev_no, identity, repo, summary, producer, \
         recorded_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![org, d.id, rev_no, identity, want, r.summary, r.producer, now],
    )?;
    let id = tx.last_insert_rowid();
    ledger::append(
        tx,
        EventInput::new(
            DEFAULT_ORG,
            REVISED,
            json!({
                "org_id": org, "deliverable_id": d.id, "task_id": d.task_id, "revision_id": id, "rev_no": rev_no,
                "kind": d.kind, "identity": identity, "repo": want,
            }),
        )
        .by(r.producer.to_string()),
    )?;
    let rev = tx.query_row(
        &format!("SELECT {REVISION_COLUMNS} FROM deliverable_revisions WHERE id = ?1"),
        [id],
        revision_row,
    )?;
    Ok((d, rev, true))
}

fn short(sha: &str) -> &str {
    &sha[..sha.len().min(12)]
}

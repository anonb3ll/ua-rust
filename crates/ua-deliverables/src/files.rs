//! File revisions and the durable release record. The registry layer checks
//! task authority, reads the source, and materializes the authorized bytes.

use super::*;
use sha2::{Digest, Sha256};

pub const MAX_BYTES: usize = 1024 * 1024;
pub const AUTHORIZED: &str = "agent.deliverable.release_authorized";
pub const RELEASED: &str = "agent.deliverable.released";
pub const TAMPERED: &str = "agent.deliverable.tampered";

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub struct Submission<'a> {
    pub org: &'a str,
    pub task_id: i64,
    pub title: &'a str,
    pub source_path: &'a str,
    pub bytes: &'a [u8],
    pub summary: Option<&'a str>,
    pub producer: &'a str,
}

pub struct FileRevision {
    pub deliverable: Deliverable,
    pub revision: Revision,
    pub source_path: String,
    pub size_bytes: i64,
}

pub fn file_revision(conn: &Connection, org: &str, revision_id: i64) -> UaResult<FileRevision> {
    let (deliverable_id, source_path, size_bytes) = conn
        .query_row(
            "SELECT r.deliverable_id, f.source_path, f.size_bytes FROM deliverable_files f
             JOIN deliverable_revisions r ON r.id = f.revision_id AND r.org_id = f.org_id
             WHERE f.org_id = ?1 AND f.revision_id = ?2",
            params![org, revision_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or_else(|| UaError::not_found(format!("no file revision {revision_id}")))?;
    let deliverable = deliverable(conn, org, deliverable_id)?
        .ok_or_else(|| UaError::internal("file revision's deliverable is missing"))?;
    let revision = conn.query_row(
        &format!("SELECT {REVISION_COLUMNS} FROM deliverable_revisions WHERE org_id = ?1 AND id = ?2"),
        params![org, revision_id],
        revision_row,
    )?;
    Ok(FileRevision { deliverable, revision, source_path, size_bytes })
}

/// A title identifies a file deliverable within its task. Reusing the latest
/// bytes, path and summary is a retry. Each new version records its own producer.
pub fn submit(tx: &mut WriteTx<'_>, input: Submission<'_>) -> UaResult<(FileRevision, bool)> {
    let org = row_org(tx, input.org)?;
    let title = title(input.title)?;
    let summary = summary(input.summary)?;
    if input.bytes.len() > MAX_BYTES {
        return Err(UaError::invalid("deliverable file exceeds 1 MiB"));
    }
    let now = ua_core::time::now();
    let existing: Option<i64> = tx
        .query_row(
            "SELECT id FROM deliverables WHERE org_id = ?1 AND task_id = ?2 AND kind = 'file' AND title = ?3",
            params![org, input.task_id, title],
            |row| row.get(0),
        )
        .optional()?;
    let id = match existing {
        Some(id) => id,
        None => {
            tx.execute(
                "INSERT INTO deliverables (org_id, task_id, kind, title, created_by, created_at)
                 VALUES (?1, ?2, 'file', ?3, ?4, ?5)",
                params![org, input.task_id, title, input.producer, now],
            )?;
            let id = tx.last_insert_rowid();
            ledger::append(
                tx,
                EventInput::new(
                    DEFAULT_ORG,
                    CREATED,
                    json!({
                        "org_id": org, "task_id": input.task_id, "deliverable_id": id, "kind": "file",
                    }),
                )
                .by(input.producer),
            )?;
            id
        }
    };
    let identity = digest(input.bytes);
    let newest = latest(tx, org, id)?;
    let seen: Option<i64> = tx
        .query_row(
            "SELECT id FROM deliverable_revisions WHERE org_id = ?1 AND deliverable_id = ?2 AND identity = ?3",
            params![org, id, identity],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(seen) = seen {
        if newest.as_ref().is_none_or(|r| r.id != seen) {
            return Err(UaError::conflict_code(
                "revision_not_latest",
                "a newer file revision is already recorded",
            ));
        }
        let row = file_revision(tx, org, seen)?;
        if row.revision.summary != summary || row.source_path != input.source_path {
            return Err(UaError::conflict_code(
                "revision_conflict",
                "the same bytes are already recorded with different metadata",
            ));
        }
        return Ok((row, false));
    }
    let rev_no = newest.map_or(1, |r| r.rev_no + 1);
    tx.execute(
        "INSERT INTO deliverable_revisions (org_id, deliverable_id, rev_no, identity, summary, producer, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![org, id, rev_no, identity, summary, input.producer, now],
    )?;
    let revision_id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO deliverable_files (org_id, revision_id, source_path, size_bytes) VALUES (?1, ?2, ?3, ?4)",
        params![org, revision_id, input.source_path, input.bytes.len() as i64],
    )?;
    ledger::append(
        tx,
        EventInput::new(DEFAULT_ORG, REVISED, json!({
            "org_id": org, "task_id": input.task_id, "deliverable_id": id, "kind": "file",
            "revision_id": revision_id, "rev_no": rev_no, "identity": identity, "size_bytes": input.bytes.len(),
        }))
        .by(input.producer),
    )?;
    Ok((file_revision(tx, org, revision_id)?, true))
}

pub struct Release {
    pub approval_id: i64,
    pub requester: String,
    pub approver: String,
    pub destination: String,
    pub root_identity: String,
    pub staging_id: String,
    pub workflow_revision: i64,
    pub ownership_generation: i64,
    pub payload: Option<Vec<u8>>,
    pub released_at: Option<String>,
}

pub fn release(conn: &Connection, org: &str, revision_id: i64) -> UaResult<Option<Release>> {
    Ok(conn
        .query_row(
            "SELECT approval_id, requester, approver, destination, root_identity, staging_id,
                    workflow_revision, ownership_generation, payload, released_at
             FROM deliverable_releases WHERE org_id = ?1 AND revision_id = ?2",
            params![org, revision_id],
            |row| {
                Ok(Release {
                    approval_id: row.get(0)?,
                    requester: row.get(1)?,
                    approver: row.get(2)?,
                    destination: row.get(3)?,
                    root_identity: row.get(4)?,
                    staging_id: row.get(5)?,
                    workflow_revision: row.get(6)?,
                    ownership_generation: row.get(7)?,
                    payload: row.get(8)?,
                    released_at: row.get(9)?,
                })
            },
        )
        .optional()?)
}

pub fn destination_reserved(conn: &Connection, org: &str, root: &str, name: &str) -> UaResult<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM deliverable_releases
         WHERE org_id = ?1 AND root_identity = ?2 AND destination = ?3 COLLATE NOCASE)",
        params![org, root, name],
        |row| row.get(0),
    )?)
}

pub fn authorize(tx: &mut WriteTx<'_>, file: &FileRevision, release: &Release) -> UaResult<()> {
    let org = row_org(tx, &file.deliverable.org_id)?;
    let revision_id = file.revision.id;
    tx.execute(
        "INSERT INTO deliverable_releases (org_id, revision_id, approval_id, requester, approver, destination,
            root_identity, staging_id, workflow_revision, ownership_generation, payload)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![org, revision_id, release.approval_id, release.requester, release.approver, release.destination,
            release.root_identity, release.staging_id, release.workflow_revision, release.ownership_generation,
            release.payload],
    )?;
    release_event(tx, file, release, AUTHORIZED)
}

pub fn complete(tx: &mut WriteTx<'_>, file: &FileRevision, release: &Release) -> UaResult<String> {
    let org = row_org(tx, &file.deliverable.org_id)?;
    let now = ua_core::time::now();
    let changed = tx.execute(
        "UPDATE deliverable_releases SET released_at = ?3, payload = NULL
         WHERE org_id = ?1 AND revision_id = ?2 AND released_at IS NULL",
        params![org, file.revision.id, now],
    )?;
    if changed != 1 {
        return Err(UaError::conflict("release is already complete"));
    }
    release_event(tx, file, release, RELEASED)?;
    Ok(now)
}

fn release_event(
    tx: &mut WriteTx<'_>,
    file: &FileRevision,
    release: &Release,
    channel: &str,
) -> UaResult<()> {
    ledger::append(
        tx,
        EventInput::new(DEFAULT_ORG, channel, json!({
            "task_id": file.deliverable.task_id, "deliverable_id": file.deliverable.id,
            "revision_id": file.revision.id, "sha256": file.revision.identity, "size_bytes": file.size_bytes,
            "approval_id": release.approval_id, "approver": release.approver,
            "destination": release.destination, "root_identity": release.root_identity,
        }))
        .by(release.requester.as_str()),
    )?;
    Ok(())
}

pub fn record_tamper(tx: &mut WriteTx<'_>, file: &FileRevision, requester: &str) -> UaResult<()> {
    row_org(tx, &file.deliverable.org_id)?;
    ledger::append(
        tx,
        EventInput::new(
            DEFAULT_ORG,
            TAMPERED,
            json!({
                "task_id": file.deliverable.task_id, "deliverable_id": file.deliverable.id,
                "revision_id": file.revision.id, "sha256": file.revision.identity,
            }),
        )
        .by(requester),
    )?;
    Ok(())
}

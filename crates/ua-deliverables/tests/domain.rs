//! The domain API and the schema on a bare database, without the tool
//! registry: creating a deliverable, recording revisions, the refusals, the
//! ledger events, and the triggers that keep revisions immutable, ordered
//! and in their deliverable's organization.

use rusqlite::params;
use sha2::{Digest, Sha256};
use ua_core::{DEFAULT_ORG, UaError};
use ua_deliverables::{Kind, NewDeliverable, NewRevision};
use ua_store::{Db, Part, ledger};

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const REPO: &str = "example/widgets";

fn db() -> Db {
    let mut parts: Vec<Part> =
        vec![ledger::SCHEMA.into(), ledger::META_SCHEMA.into(), ua_store::org::STORE_PART.into()];
    parts.extend(ua_deliverables::schema_parts());
    Db::open_in_memory(&parts).unwrap()
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

fn new(task_id: i64, title: &str) -> NewDeliverable<'_> {
    NewDeliverable { org_id: DEFAULT_ORG, task_id, kind: Kind::Commit, title, repo: REPO, by: "builder-1" }
}

fn rev<'a>(deliverable_id: i64, commit: &'a str, summary: Option<&'a str>) -> NewRevision<'a> {
    NewRevision { org_id: DEFAULT_ORG, deliverable_id, commit, repo: REPO, summary, producer: "builder-1" }
}

/// `(channel, payload)` of every ledger row, in order.
fn events(db: &Db) -> Vec<(String, serde_json::Value)> {
    db.read(|c| {
        let mut stmt = c.prepare("SELECT channel, payload, org_id FROM event_log ORDER BY seq")?;
        let rows = stmt
            .query_map([], |r| {
                let org: String = r.get(2)?;
                assert_eq!(org, DEFAULT_ORG);
                Ok((r.get::<_, String>(0)?, serde_json::from_str(&r.get::<_, String>(1)?).unwrap()))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .unwrap()
}

#[test]
fn the_released_schema_part_keeps_its_name_and_checksum() {
    let got =
        (ua_deliverables::SCHEMA.name, hex::encode(Sha256::digest(ua_deliverables::SCHEMA.sql.as_bytes())));
    assert_eq!(got.0, "deliverables.v1");
    assert_eq!(
        got.1, "440b48c402a6b8b9dcc8c275a95c25ba380d1649214ab1bfad4e3539d74a82aa",
        "deliverables.v1 changed: never edit a released part, add a new one"
    );
}

#[test]
fn cancellation_migration_preserves_pending_and_completed_intents() {
    use ua_deliverables::files::{destination_reserved, release, release_by_approval};
    use ua_store::schema::apply;

    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON").unwrap();
    let mut parts: Vec<Part> =
        vec![ledger::SCHEMA.into(), ledger::META_SCHEMA.into(), ua_store::org::STORE_PART.into()];
    let releases = ua_deliverables::schema_parts();
    parts.extend_from_slice(&releases[..4]);
    apply(&mut conn, &parts).unwrap();
    conn.execute_batch(
        "INSERT INTO deliverables (id, org_id, task_id, kind, title, created_by, created_at)
         VALUES (2, 'default', 1, 'file', 'pending', 'builder-1', 'created'),
                (4, 'default', 2, 'file', 'complete', 'builder-1', 'created');
         INSERT INTO deliverable_revisions (id, org_id, deliverable_id, rev_no, identity, producer, recorded_at)
         SELECT id, org_id, id, 1, printf('%064d', id), 'builder-1', 'recorded' FROM deliverables;
         INSERT INTO deliverable_files (revision_id, org_id, source_path, size_bytes)
         VALUES (2, 'default', 'draft.txt', 4), (4, 'default', 'final.txt', 4);
         INSERT INTO deliverable_releases (
             revision_id, org_id, approval_id, requester, approver, destination, root_identity, staging_id,
             workflow_revision, ownership_generation, payload, released_at
         )
         VALUES (2, 'default', 17, 'builder-1', 'operator', 'draft.txt', 'test-root', 'stage-a', 8, 3,
                 X'74657374', NULL),
                (4, 'default', 32, 'builder-1', 'operator', 'final.txt', 'test-root', 'stage-b', 2, 1,
                 NULL, 'completed');",
    )
    .unwrap();
    parts.extend_from_slice(&releases[4..]);
    assert_eq!(
        apply(&mut conn, &parts).unwrap(),
        ["deliverables.v3.release_cancellation", "organization.v1.deliverable_release_cancellation"]
    );
    assert!(apply(&mut conn, &parts).unwrap().is_empty());
    let pending = release(&conn, DEFAULT_ORG, 2).unwrap().unwrap();
    assert_eq!((pending.approval_id, pending.staging_id.as_str()), (17, "stage-a"));
    assert_eq!((pending.workflow_revision, pending.ownership_generation), (8, 3));
    assert_eq!(pending.payload.as_deref(), Some(b"test".as_slice()));
    assert!(pending.cancelled_at.is_none());
    let completed = release_by_approval(&conn, DEFAULT_ORG, 32).unwrap().unwrap();
    assert_eq!((completed.revision_id, completed.released_at.as_deref()), (4, Some("completed")));
    assert!(completed.payload.is_none());
    assert!(destination_reserved(&conn, DEFAULT_ORG, "test-root", "FINAL.TXT").unwrap());
    assert!(destination_reserved(&conn, DEFAULT_ORG, "test-root", "DRAFT.TXT").unwrap());
    for sql in [
        "UPDATE deliverable_releases SET destination = 'elsewhere.txt' WHERE approval_id = 17",
        "UPDATE deliverable_releases SET cancelled_at = 'cancelled', payload = NULL WHERE approval_id = 17",
        "UPDATE deliverable_releases SET released_at = NULL, cancelled_at = 'cancelled',
         cancelled_by = 'operator' WHERE approval_id = 32",
        "DELETE FROM deliverable_releases WHERE approval_id = 17",
    ] {
        assert!(conn.execute(sql, []).is_err(), "{sql}");
    }
}

#[test]
fn revisions_are_numbered_in_order_and_each_is_ledgered() {
    let db = db();
    let (d, created) = db.write(|tx| ua_deliverables::create(tx, new(7, "changelog generator"))).unwrap();
    assert!(created);
    assert_eq!((d.task_id, d.kind.as_str(), d.repo.as_deref()), (7, "commit", Some(REPO)));
    // The same deliverable again is the same row; another title is refused.
    let (again, created) = db.write(|tx| ua_deliverables::create(tx, new(7, "changelog generator"))).unwrap();
    assert!(!created);
    assert_eq!(again, d);
    let e = db.write(|tx| ua_deliverables::create(tx, new(7, "something else"))).unwrap_err();
    assert_eq!(reason(&e), "deliverable_exists", "{e}");

    let (_, r1, recorded) = db.write(|tx| ua_deliverables::record_revision(tx, rev(d.id, A, None))).unwrap();
    assert!(recorded);
    assert_eq!((r1.rev_no, r1.identity.as_str(), r1.repo.as_deref()), (1, A, Some(REPO)));
    let upper = B.to_ascii_uppercase();
    let (_, r2, _) =
        db.write(|tx| ua_deliverables::record_revision(tx, rev(d.id, &upper, Some("fix")))).unwrap();
    assert_eq!((r2.rev_no, r2.identity.as_str()), (2, B), "the identity is lowercased");
    // The latest again, unchanged: the same revision, nothing new.
    let (_, same, recorded) =
        db.write(|tx| ua_deliverables::record_revision(tx, rev(d.id, B, Some("fix")))).unwrap();
    assert!(!recorded);
    assert_eq!(same, r2);

    let evs = events(&db);
    let channels: Vec<&str> = evs.iter().map(|(c, _)| c.as_str()).collect();
    assert_eq!(channels, [ua_deliverables::CREATED, ua_deliverables::REVISED, ua_deliverables::REVISED]);
    let p = &evs[2].1;
    assert_eq!(p["org_id"], DEFAULT_ORG);
    assert_eq!(p["deliverable_id"], d.id);
    assert_eq!(p["task_id"], 7);
    assert_eq!(p["revision_id"], r2.id);
    assert_eq!(p["rev_no"], 2);
    assert_eq!(p["identity"], B);
    assert_eq!(p["repo"], REPO);
    // No content: neither the title nor the summary.
    for (_, p) in &evs {
        let text = p.to_string();
        assert!(!text.contains("changelog generator") && !text.contains("\"fix\""), "{text}");
    }
}

#[test]
fn bad_revisions_are_refused_with_a_reason() {
    let db = db();
    let (d, _) = db.write(|tx| ua_deliverables::create(tx, new(3, "x"))).unwrap();
    db.write(|tx| ua_deliverables::record_revision(tx, rev(d.id, A, Some("first")))).unwrap();
    db.write(|tx| ua_deliverables::record_revision(tx, rev(d.id, B, None))).unwrap();
    for bad in ["abcdef1", "g".repeat(40).as_str(), "", &A[..39]] {
        let e = db.write(|tx| ua_deliverables::record_revision(tx, rev(d.id, bad, None))).unwrap_err();
        assert_eq!(e.code(), "invalid_argument", "{bad}: {e}");
    }
    let e = db.write(|tx| ua_deliverables::record_revision(tx, rev(d.id, B, Some("other")))).unwrap_err();
    assert_eq!(reason(&e), "revision_conflict", "{e}");
    let e = db.write(|tx| ua_deliverables::record_revision(tx, rev(d.id, A, Some("first")))).unwrap_err();
    assert_eq!(reason(&e), "revision_not_latest", "{e}");
    let moved = NewRevision { repo: "example/other", ..rev(d.id, "c".repeat(40).leak(), None) };
    let e = db.write(|tx| ua_deliverables::record_revision(tx, moved)).unwrap_err();
    assert_eq!(reason(&e), "repo_mismatch", "{e}");
    let e = db.write(|tx| ua_deliverables::record_revision(tx, rev(d.id + 100, A, None))).unwrap_err();
    assert_eq!(e.code(), "not_found", "{e}");
    let elsewhere = NewRevision { org_id: "org-nowhere", ..rev(d.id, A, None) };
    let e = db.write(|tx| ua_deliverables::record_revision(tx, elsewhere)).unwrap_err();
    assert_eq!(reason(&e), "unknown_organization", "{e}");
    let e = db
        .write(|tx| ua_deliverables::create(tx, NewDeliverable { org_id: "org-nowhere", ..new(4, "y") }))
        .unwrap_err();
    assert_eq!(reason(&e), "unknown_organization", "{e}");
    assert!(Kind::parse("file").is_err() && Kind::parse("doc").is_err());
    // Nothing refused reached the ledger or the table.
    let n: i64 = db
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM deliverable_revisions", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(n, 2);
    assert_eq!(events(&db).len(), 3);
}

#[test]
fn the_schema_keeps_revisions_immutable_ordered_and_in_their_organization() {
    let db = db();
    let (d, _) = db.write(|tx| ua_deliverables::create(tx, new(5, "x"))).unwrap();
    db.write(|tx| ua_deliverables::record_revision(tx, rev(d.id, A, None))).unwrap();
    let sql = |stmt: &'static str| {
        db.write(move |tx| Ok(tx.execute(stmt, params![])?)).map(|_| ()).unwrap_err().to_string()
    };
    assert!(
        sql("UPDATE deliverable_revisions SET identity = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'")
            .contains("immutable")
    );
    assert!(sql("UPDATE deliverable_revisions SET summary = 'edited'").contains("immutable"));
    assert!(sql("DELETE FROM deliverable_revisions").contains("immutable"));
    assert!(sql("DELETE FROM deliverables").contains("never deleted"));
    assert!(sql("UPDATE deliverables SET task_id = 6").contains("never change"));
    assert!(sql("UPDATE deliverables SET repo = 'example/other'").contains("never change"));
    assert!(sql("UPDATE deliverables SET org_id = 'other'").contains("org_id cannot change"));
    // Out of order, in another organization, or for no deliverable.
    let insert = |org: &str, deliverable: i64, rev_no: i64| {
        let org = org.to_string();
        db.write(move |tx| {
            Ok(tx.execute(
                "INSERT INTO deliverable_revisions (org_id, deliverable_id, rev_no, identity, producer, recorded_at) \
                 VALUES (?1, ?2, ?3, 'cccccccccccccccccccccccccccccccccccccccc', 'x', 'now')",
                params![org, deliverable, rev_no],
            )?)
        })
        .unwrap_err()
        .to_string()
    };
    assert!(insert(DEFAULT_ORG, d.id, 3).contains("in order"));
    assert!(insert(DEFAULT_ORG, d.id + 9, 1).contains("existing deliverable"));
    let e = insert("other", d.id, 2);
    assert!(e.contains("unknown organization") || e.contains("existing deliverable"), "{e}");
    // An abbreviated or upper-case identity cannot be stored at all.
    let e = db
        .write(move |tx| {
            Ok(tx.execute(
                "INSERT INTO deliverable_revisions (org_id, deliverable_id, rev_no, identity, producer, recorded_at) \
                 VALUES ('default', ?1, 2, 'ABCDEF1', 'x', 'now')",
                params![d.id],
            )?)
        })
        .unwrap_err();
    assert_eq!(e.code(), "conflict", "{e}");
}

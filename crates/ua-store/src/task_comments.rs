//! Repository traits and SQLite implementation for `task_comments` and
//! `task_comment_threads` (`docs/store.md`).
//!
//! Every query binds `org_id` explicitly and returns neutral `Ok(None)` (or
//! empty lists) for rows belonging to another organization. Timestamps are
//! passed in by callers; this module never reads the system clock.

use rusqlite::{Connection, OptionalExtension, params};
use ua_core::{UaError, UaResult};

use crate::WriteTx;

const COMMENT_COLS: &str = "id, org_id, task_id, parent_comment_id, author, body, mentions, refs, \
                            idempotency_key, thread_revision, created_at";

/// One row from `task_comments`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCommentRow {
    pub id: i64,
    pub org_id: String,
    pub task_id: i64,
    pub parent_comment_id: Option<i64>,
    pub author: String,
    pub body: String,
    /// Raw `mentions` column text (JSON array in normal writes; not schema-checked).
    pub mentions_json: String,
    /// Raw `refs` column text (JSON object in normal writes; not schema-checked).
    pub refs_json: String,
    pub idempotency_key: Option<String>,
    pub thread_revision: i64,
    pub created_at: String,
}

/// One row from `task_comment_threads`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCommentThreadRow {
    pub org_id: String,
    pub task_id: i64,
    pub revision: i64,
    pub updated_at: String,
}

/// Values to insert into `task_comments`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTaskComment {
    pub org_id: String,
    pub task_id: i64,
    pub parent_comment_id: Option<i64>,
    pub author: String,
    pub body: String,
    pub mentions_json: String,
    pub refs_json: String,
    pub idempotency_key: Option<String>,
    pub thread_revision: i64,
    pub created_at: String,
}

/// Tenant-scoped reads over `task_comments` and `task_comment_threads`.
pub trait TaskCommentsRead {
    /// Comment `id` in `org_id`, or `Ok(None)` when absent or in another organization.
    fn get_task_comment(&mut self, org_id: &str, id: i64) -> UaResult<Option<TaskCommentRow>>;

    /// All comments on `task_id` in `org_id`, ordered by `id` ascending.
    fn list_task_comments(&mut self, org_id: &str, task_id: i64) -> UaResult<Vec<TaskCommentRow>>;

    /// Thread metadata (`revision`, `updated_at`) for `task_id` in `org_id`.
    fn get_task_comment_thread(
        &mut self,
        org_id: &str,
        task_id: i64,
    ) -> UaResult<Option<TaskCommentThreadRow>>;

    /// Existing comment matching `(org_id, task_id, author, idempotency_key)`.
    fn find_task_comment_by_idempotency_key(
        &mut self,
        org_id: &str,
        task_id: i64,
        author: &str,
        idempotency_key: &str,
    ) -> UaResult<Option<TaskCommentRow>>;
}

/// Tenant-scoped writes over `task_comments` and `task_comment_threads`,
/// running inside the caller's `WriteTx<'_>`.
pub trait TaskCommentsWrite: TaskCommentsRead {
    /// Create or increment `task_comment_threads` for `(org_id, task_id)` at
    /// `updated_at`, returning the resulting `revision`.
    ///
    /// A conflict against a thread owned by another organization neither
    /// mutates that thread nor leaks its revision, returning `UaError::NotFound`.
    fn bump_task_comment_thread(&mut self, org_id: &str, task_id: i64, updated_at: &str) -> UaResult<i64>;

    /// Insert a new comment row and return its assigned `id`.
    fn insert_task_comment(&mut self, row: &NewTaskComment) -> UaResult<i64>;
}

/// Thin read adapter over a pooled read-only SQLite connection.
pub struct SqliteTaskComments<'a> {
    conn: &'a Connection,
}

impl<'a> SqliteTaskComments<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }
}

fn decode_comment(r: &rusqlite::Row<'_>) -> rusqlite::Result<TaskCommentRow> {
    Ok(TaskCommentRow {
        id: r.get(0)?,
        org_id: r.get(1)?,
        task_id: r.get(2)?,
        parent_comment_id: r.get(3)?,
        author: r.get(4)?,
        body: r.get(5)?,
        mentions_json: r.get(6)?,
        refs_json: r.get(7)?,
        idempotency_key: r.get(8)?,
        thread_revision: r.get(9)?,
        created_at: r.get(10)?,
    })
}

fn get_task_comment_sql(c: &Connection, org_id: &str, id: i64) -> UaResult<Option<TaskCommentRow>> {
    Ok(c.query_row(
        &format!("SELECT {COMMENT_COLS} FROM task_comments WHERE org_id = ?1 AND id = ?2"),
        params![org_id, id],
        decode_comment,
    )
    .optional()?)
}

fn list_task_comments_sql(c: &Connection, org_id: &str, task_id: i64) -> UaResult<Vec<TaskCommentRow>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {COMMENT_COLS} FROM task_comments WHERE org_id = ?1 AND task_id = ?2 ORDER BY id"
    ))?;
    let rows = stmt.query_map(params![org_id, task_id], decode_comment)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn get_task_comment_thread_sql(
    c: &Connection,
    org_id: &str,
    task_id: i64,
) -> UaResult<Option<TaskCommentThreadRow>> {
    Ok(c.query_row(
        "SELECT org_id, task_id, revision, updated_at FROM task_comment_threads \
         WHERE org_id = ?1 AND task_id = ?2",
        params![org_id, task_id],
        |r| {
            Ok(TaskCommentThreadRow {
                org_id: r.get(0)?,
                task_id: r.get(1)?,
                revision: r.get(2)?,
                updated_at: r.get(3)?,
            })
        },
    )
    .optional()?)
}

fn find_task_comment_by_idempotency_key_sql(
    c: &Connection,
    org_id: &str,
    task_id: i64,
    author: &str,
    idempotency_key: &str,
) -> UaResult<Option<TaskCommentRow>> {
    Ok(c.query_row(
        &format!(
            "SELECT {COMMENT_COLS} FROM task_comments \
             WHERE org_id = ?1 AND task_id = ?2 AND author = ?3 AND idempotency_key = ?4"
        ),
        params![org_id, task_id, author, idempotency_key],
        decode_comment,
    )
    .optional()?)
}

impl TaskCommentsRead for SqliteTaskComments<'_> {
    fn get_task_comment(&mut self, org_id: &str, id: i64) -> UaResult<Option<TaskCommentRow>> {
        get_task_comment_sql(self.conn, org_id, id)
    }

    fn list_task_comments(&mut self, org_id: &str, task_id: i64) -> UaResult<Vec<TaskCommentRow>> {
        list_task_comments_sql(self.conn, org_id, task_id)
    }

    fn get_task_comment_thread(
        &mut self,
        org_id: &str,
        task_id: i64,
    ) -> UaResult<Option<TaskCommentThreadRow>> {
        get_task_comment_thread_sql(self.conn, org_id, task_id)
    }

    fn find_task_comment_by_idempotency_key(
        &mut self,
        org_id: &str,
        task_id: i64,
        author: &str,
        idempotency_key: &str,
    ) -> UaResult<Option<TaskCommentRow>> {
        find_task_comment_by_idempotency_key_sql(self.conn, org_id, task_id, author, idempotency_key)
    }
}

impl TaskCommentsRead for WriteTx<'_> {
    fn get_task_comment(&mut self, org_id: &str, id: i64) -> UaResult<Option<TaskCommentRow>> {
        get_task_comment_sql(self, org_id, id)
    }

    fn list_task_comments(&mut self, org_id: &str, task_id: i64) -> UaResult<Vec<TaskCommentRow>> {
        list_task_comments_sql(self, org_id, task_id)
    }

    fn get_task_comment_thread(
        &mut self,
        org_id: &str,
        task_id: i64,
    ) -> UaResult<Option<TaskCommentThreadRow>> {
        get_task_comment_thread_sql(self, org_id, task_id)
    }

    fn find_task_comment_by_idempotency_key(
        &mut self,
        org_id: &str,
        task_id: i64,
        author: &str,
        idempotency_key: &str,
    ) -> UaResult<Option<TaskCommentRow>> {
        find_task_comment_by_idempotency_key_sql(self, org_id, task_id, author, idempotency_key)
    }
}

impl TaskCommentsWrite for WriteTx<'_> {
    fn bump_task_comment_thread(&mut self, org_id: &str, task_id: i64, updated_at: &str) -> UaResult<i64> {
        self.execute(
            "INSERT INTO task_comment_threads (org_id, task_id, revision, updated_at) \
             VALUES (?1, ?2, 1, ?3) \
             ON CONFLICT(task_id) DO UPDATE SET revision = revision + 1, updated_at = excluded.updated_at \
             WHERE org_id = excluded.org_id",
            params![org_id, task_id, updated_at],
        )?;
        let rev: Option<i64> = self
            .query_row(
                "SELECT revision FROM task_comment_threads WHERE org_id = ?1 AND task_id = ?2",
                params![org_id, task_id],
                |r| r.get(0),
            )
            .optional()?;
        rev.ok_or_else(|| UaError::not_found(format!("unknown task: {task_id}")))
    }

    fn insert_task_comment(&mut self, row: &NewTaskComment) -> UaResult<i64> {
        self.execute(
            "INSERT INTO task_comments (org_id, task_id, parent_comment_id, author, body, mentions, refs, \
             idempotency_key, thread_revision, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                row.org_id,
                row.task_id,
                row.parent_comment_id,
                row.author,
                row.body,
                row.mentions_json,
                row.refs_json,
                row.idempotency_key,
                row.thread_revision,
                row.created_at,
            ],
        )?;
        Ok(self.last_insert_rowid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;
    use crate::ledger;
    use crate::org::{STORE_PART, tenant_part};
    use crate::schema::{Part, SchemaPart};
    use ua_core::DEFAULT_ORG;

    const ORG_B: &str = "org-b";

    const TASKS_TEST_SCHEMA: SchemaPart = SchemaPart {
        name: "test.tasks.comments.v1",
        sql: "
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS task_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    parent_comment_id INTEGER REFERENCES task_comments(id) ON DELETE CASCADE,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    mentions TEXT NOT NULL DEFAULT '[]',
    refs TEXT NOT NULL DEFAULT '{}',
    idempotency_key TEXT,
    thread_revision INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_comments_task ON task_comments(task_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_task_comments_idem
    ON task_comments(task_id, author, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS task_comment_threads (
    task_id INTEGER PRIMARY KEY REFERENCES tasks(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
",
    };

    const TASKS_TENANT_PART: crate::Procedure =
        tenant_part("test.organization.v1.tasks", &["tasks", "task_comments", "task_comment_threads"]);

    fn test_db() -> Db {
        let db = Db::open_in_memory(&[
            Part::from(ledger::SCHEMA),
            Part::from(ledger::META_SCHEMA),
            Part::from(STORE_PART),
            Part::from(TASKS_TEST_SCHEMA),
            Part::from(TASKS_TENANT_PART),
        ])
        .unwrap();
        db.write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                 VALUES (?1, ?1, 'Org B', '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                [ORG_B],
            )?;
            Ok(())
        })
        .unwrap();
        db
    }

    fn seed_task(db: &Db, org_id: &str, title: &str) -> i64 {
        db.write(|tx| {
            tx.execute("INSERT INTO tasks (org_id, title) VALUES (?1, ?2)", params![org_id, title])?;
            Ok(tx.last_insert_rowid())
        })
        .unwrap()
    }

    #[test]
    fn two_org_isolation_across_read_and_write_traits() {
        let db = test_db();
        let task_a = seed_task(&db, DEFAULT_ORG, "Org A task");
        let task_b = seed_task(&db, ORG_B, "Org B task");

        // Write two comments in default org (with thread bumps + parent + idempotency key).
        let (c_a1, c_a2) = db
            .write(|tx| {
                let rev1 = tx.bump_task_comment_thread(DEFAULT_ORG, task_a, "2026-01-01T00:00:01+00:00")?;
                assert_eq!(rev1, 1);
                let id1 = tx.insert_task_comment(&NewTaskComment {
                    org_id: DEFAULT_ORG.into(),
                    task_id: task_a,
                    parent_comment_id: None,
                    author: "builder-1".into(),
                    body: "org-a root comment".into(),
                    mentions_json: "[\"reviewer-1\"]".into(),
                    refs_json: "{\"plan_id\":\"p1\"}".into(),
                    idempotency_key: Some("k-shared".into()),
                    thread_revision: rev1,
                    created_at: "2026-01-01T00:00:01+00:00".into(),
                })?;

                let rev2 = tx.bump_task_comment_thread(DEFAULT_ORG, task_a, "2026-01-01T00:00:02+00:00")?;
                assert_eq!(rev2, 2);
                let id2 = tx.insert_task_comment(&NewTaskComment {
                    org_id: DEFAULT_ORG.into(),
                    task_id: task_a,
                    parent_comment_id: Some(id1),
                    author: "reviewer-1".into(),
                    body: "org-a reply".into(),
                    mentions_json: "[]".into(),
                    refs_json: "{}".into(),
                    idempotency_key: None,
                    thread_revision: rev2,
                    created_at: "2026-01-01T00:00:02+00:00".into(),
                })?;
                Ok((id1, id2))
            })
            .unwrap();

        // Write one comment in org B with the same author & idempotency key on its own task.
        let c_b1 = db
            .write(|tx| {
                let rev = tx.bump_task_comment_thread(ORG_B, task_b, "2026-01-01T00:00:03+00:00")?;
                assert_eq!(rev, 1);
                tx.insert_task_comment(&NewTaskComment {
                    org_id: ORG_B.into(),
                    task_id: task_b,
                    parent_comment_id: None,
                    author: "builder-1".into(),
                    body: "org-b comment".into(),
                    mentions_json: "[]".into(),
                    refs_json: "{}".into(),
                    idempotency_key: Some("k-shared".into()),
                    thread_revision: rev,
                    created_at: "2026-01-01T00:00:03+00:00".into(),
                })
            })
            .unwrap();

        // Read isolation via SqliteTaskComments on pooled read connection.
        db.read(|conn| {
            let mut repo = SqliteTaskComments::new(conn);

            // Point lookups: own org succeeds, foreign org returns neutral Ok(None).
            let got_a = repo.get_task_comment(DEFAULT_ORG, c_a1)?.unwrap();
            assert_eq!(got_a.body, "org-a root comment");
            assert_eq!(got_a.mentions_json, "[\"reviewer-1\"]");
            assert_eq!(got_a.refs_json, "{\"plan_id\":\"p1\"}");
            assert_eq!(repo.get_task_comment(ORG_B, c_a1)?, None);
            assert_eq!(repo.get_task_comment(DEFAULT_ORG, c_b1)?, None);
            assert_eq!(repo.get_task_comment(ORG_B, c_b1)?.unwrap().body, "org-b comment");

            // Listings: ordered by id within own org, empty across org boundary.
            let list_a = repo.list_task_comments(DEFAULT_ORG, task_a)?;
            assert_eq!(list_a.iter().map(|r| r.id).collect::<Vec<_>>(), vec![c_a1, c_a2]);
            assert!(repo.list_task_comments(ORG_B, task_a)?.is_empty());
            assert!(repo.list_task_comments(DEFAULT_ORG, task_b)?.is_empty());
            assert_eq!(repo.list_task_comments(ORG_B, task_b)?.len(), 1);

            // Threads: visible in own org only.
            let th_a = repo.get_task_comment_thread(DEFAULT_ORG, task_a)?.unwrap();
            assert_eq!(th_a.revision, 2);
            assert_eq!(th_a.updated_at, "2026-01-01T00:00:02+00:00");
            assert_eq!(repo.get_task_comment_thread(ORG_B, task_a)?, None);
            assert_eq!(repo.get_task_comment_thread(DEFAULT_ORG, task_b)?, None);
            assert_eq!(repo.get_task_comment_thread(ORG_B, task_b)?.unwrap().revision, 1);

            // Idempotency lookup: scoped strictly by org_id.
            assert_eq!(
                repo.find_task_comment_by_idempotency_key(DEFAULT_ORG, task_a, "builder-1", "k-shared")?
                    .map(|r| r.id),
                Some(c_a1)
            );
            assert_eq!(
                repo.find_task_comment_by_idempotency_key(ORG_B, task_a, "builder-1", "k-shared")?,
                None
            );
            assert_eq!(
                repo.find_task_comment_by_idempotency_key(DEFAULT_ORG, task_b, "builder-1", "k-shared")?,
                None
            );
            assert_eq!(
                repo.find_task_comment_by_idempotency_key(ORG_B, task_b, "builder-1", "k-shared")?
                    .map(|r| r.id),
                Some(c_b1)
            );
            Ok(())
        })
        .unwrap();

        // Write-side isolation: org B attempting to bump org A's thread fails
        // with NotFound and leaves org A's thread completely untouched.
        db.write(|tx| {
            assert_eq!(tx.get_task_comment(ORG_B, c_a1)?, None);
            assert!(tx.list_task_comments(ORG_B, task_a)?.is_empty());
            assert_eq!(tx.get_task_comment_thread(ORG_B, task_a)?, None);
            assert_eq!(
                tx.find_task_comment_by_idempotency_key(ORG_B, task_a, "builder-1", "k-shared")?,
                None
            );

            let err = tx.bump_task_comment_thread(ORG_B, task_a, "2026-12-31T23:59:59+00:00").unwrap_err();
            assert!(matches!(err, UaError::NotFound(_)), "expected NotFound, got {err:?}");

            // Org A's thread revision and timestamp are unchanged.
            let th_a = tx.get_task_comment_thread(DEFAULT_ORG, task_a)?.unwrap();
            assert_eq!(th_a.revision, 2);
            assert_eq!(th_a.updated_at, "2026-01-01T00:00:02+00:00");
            Ok(())
        })
        .unwrap();
    }
}

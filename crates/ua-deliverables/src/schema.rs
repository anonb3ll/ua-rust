//! The deliverable tables, born tenant-scoped.
//!
//! - `deliverables`: one row per deliverable, attached to a task. For the
//!   `commit` kind, `repo` is the repository the task's project was bound to
//!   when the deliverable was created. A deliverable's task, kind and
//!   repository never change, and a deliverable is never deleted.
//! - `deliverable_revisions`: the deliverable's revisions, numbered from 1
//!   in the order they were recorded. A revision is never updated or deleted.
//!
//! Neither table has a foreign key to `tasks`: revisions are immutable, so a
//! deleted task must not cascade into them (the same rule as sealed session
//! handoff notes). The task id stays as the record of what the deliverable
//! was for.
//!
//! Both tables carry `org_id NOT NULL` from this first part, and
//! [`TENANT_PART`] adds the generated organization triggers. A revision's
//! organization is its deliverable's.

use ua_store::{Part, Procedure, SchemaPart};

/// The tables, their indexes and the triggers that keep revisions
/// immutable and ordered.
pub const SCHEMA: SchemaPart = SchemaPart {
    name: "deliverables.v1",
    sql: "
CREATE TABLE IF NOT EXISTS deliverables (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     TEXT NOT NULL,
    task_id    INTEGER NOT NULL CHECK (task_id > 0),
    kind       TEXT NOT NULL CHECK (kind IN ('commit', 'file')),
    title      TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    repo       TEXT CHECK (repo IS NULL OR length(repo) BETWEEN 3 AND 201),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (kind != 'commit' OR repo IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_deliverables_task ON deliverables (org_id, task_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_deliverables_one_commit_per_task
    ON deliverables (org_id, task_id) WHERE kind = 'commit';
CREATE TRIGGER IF NOT EXISTS deliverables_fixed
BEFORE UPDATE OF task_id, kind, repo, created_by, created_at ON deliverables
BEGIN
    SELECT RAISE(ABORT, 'a deliverable''s task, kind and repository never change');
END;
CREATE TRIGGER IF NOT EXISTS deliverables_no_delete
BEFORE DELETE ON deliverables
BEGIN
    SELECT RAISE(ABORT, 'deliverables are never deleted');
END;

CREATE TABLE IF NOT EXISTS deliverable_revisions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id         TEXT NOT NULL,
    deliverable_id INTEGER NOT NULL,
    rev_no         INTEGER NOT NULL CHECK (rev_no >= 1),
    identity       TEXT NOT NULL
                   CHECK (length(identity) IN (40, 64) AND identity NOT GLOB '*[^0-9a-f]*'),
    repo           TEXT,
    summary        TEXT CHECK (summary IS NULL OR length(summary) BETWEEN 1 AND 500),
    producer       TEXT NOT NULL,
    recorded_at    TEXT NOT NULL,
    UNIQUE (deliverable_id, rev_no),
    UNIQUE (deliverable_id, identity)
);
CREATE TRIGGER IF NOT EXISTS deliverable_revisions_same_org
BEFORE INSERT ON deliverable_revisions
WHEN NEW.org_id IS NOT (SELECT org_id FROM deliverables WHERE id = NEW.deliverable_id)
BEGIN
    SELECT RAISE(ABORT, 'a revision belongs to an existing deliverable of its own organization');
END;
CREATE TRIGGER IF NOT EXISTS deliverable_revisions_in_order
BEFORE INSERT ON deliverable_revisions
WHEN NEW.rev_no IS NOT
    (SELECT COALESCE(MAX(rev_no), 0) + 1 FROM deliverable_revisions WHERE deliverable_id = NEW.deliverable_id)
BEGIN
    SELECT RAISE(ABORT, 'revisions are numbered in order, from 1');
END;
CREATE TRIGGER IF NOT EXISTS deliverable_revisions_immutable
BEFORE UPDATE ON deliverable_revisions
BEGIN
    SELECT RAISE(ABORT, 'a revision is immutable');
END;
CREATE TRIGGER IF NOT EXISTS deliverable_revisions_no_delete
BEFORE DELETE ON deliverable_revisions
BEGIN
    SELECT RAISE(ABORT, 'a revision is immutable');
END;
",
};

/// The organization triggers for both tables (`<table>_org_exists`,
/// `<table>_org_immutable`). Their `org_id` is `NOT NULL` from [`SCHEMA`].
pub const TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.deliverables", &["deliverables", "deliverable_revisions"]);

/// The crate's schema parts, in application order. They need
/// `organization.v1.store` applied first.
pub fn schema_parts() -> Vec<Part> {
    vec![SCHEMA.into(), TENANT_PART.into()]
}

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

/// File revision metadata and a durable handoff from the approval transaction
/// to the filesystem. Pending bytes are discarded when a release completes.
pub const FILE_SCHEMA: SchemaPart = SchemaPart {
    name: "deliverables.v2.files",
    sql: "
CREATE UNIQUE INDEX IF NOT EXISTS idx_deliverables_file_title
    ON deliverables (org_id, task_id, title) WHERE kind = 'file';
CREATE TABLE deliverable_files (
    revision_id INTEGER PRIMARY KEY,
    org_id TEXT NOT NULL,
    source_path TEXT NOT NULL CHECK (length(source_path) BETWEEN 1 AND 1024),
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 0 AND 1048576)
);
CREATE TRIGGER deliverable_files_revision BEFORE INSERT ON deliverable_files
WHEN NOT EXISTS (
    SELECT 1 FROM deliverable_revisions r
    JOIN deliverables d ON d.id = r.deliverable_id AND d.org_id = r.org_id
    WHERE r.id = NEW.revision_id AND r.org_id = NEW.org_id AND length(r.identity) = 64
      AND r.repo IS NULL AND d.kind = 'file'
)
BEGIN SELECT RAISE(ABORT, 'a file needs a file revision in its own organization'); END;
CREATE TRIGGER deliverable_files_no_update BEFORE UPDATE ON deliverable_files
BEGIN SELECT RAISE(ABORT, 'file revision metadata is immutable'); END;
CREATE TRIGGER deliverable_files_no_delete BEFORE DELETE ON deliverable_files
BEGIN SELECT RAISE(ABORT, 'file revision metadata is immutable'); END;

CREATE TABLE deliverable_releases (
    revision_id INTEGER PRIMARY KEY,
    org_id TEXT NOT NULL,
    approval_id INTEGER NOT NULL UNIQUE,
    requester TEXT NOT NULL,
    approver TEXT NOT NULL CHECK (approver <> requester COLLATE NOCASE),
    destination TEXT NOT NULL,
    root_identity TEXT NOT NULL,
    staging_id TEXT NOT NULL UNIQUE,
    workflow_revision INTEGER NOT NULL,
    ownership_generation INTEGER NOT NULL,
    payload BLOB,
    released_at TEXT,
    CHECK ((payload IS NULL) = (released_at IS NOT NULL)),
    CHECK (length(payload) <= 1048576),
    UNIQUE (root_identity, destination COLLATE NOCASE)
);
CREATE TRIGGER deliverable_releases_revision BEFORE INSERT ON deliverable_releases
WHEN NOT EXISTS (
    SELECT 1 FROM deliverable_files f WHERE f.revision_id = NEW.revision_id AND f.org_id = NEW.org_id
)
BEGIN SELECT RAISE(ABORT, 'a release needs a file revision in its own organization'); END;
CREATE TRIGGER deliverable_releases_fixed BEFORE UPDATE ON deliverable_releases
WHEN OLD.released_at IS NOT NULL OR NEW.released_at IS NULL OR NEW.payload IS NOT NULL
     OR NEW.revision_id IS NOT OLD.revision_id OR NEW.org_id IS NOT OLD.org_id
     OR NEW.approval_id IS NOT OLD.approval_id OR NEW.requester IS NOT OLD.requester
     OR NEW.approver IS NOT OLD.approver OR NEW.destination IS NOT OLD.destination
     OR NEW.root_identity IS NOT OLD.root_identity OR NEW.staging_id IS NOT OLD.staging_id
     OR NEW.workflow_revision IS NOT OLD.workflow_revision
     OR NEW.ownership_generation IS NOT OLD.ownership_generation
BEGIN SELECT RAISE(ABORT, 'a release may only advance to completed'); END;
CREATE TRIGGER deliverable_releases_no_delete BEFORE DELETE ON deliverable_releases
BEGIN SELECT RAISE(ABORT, 'a release is never deleted'); END;
",
};

pub const FILE_TENANT_PART: Procedure = ua_store::org::tenant_part(
    "organization.v1.deliverable_files",
    &["deliverable_files", "deliverable_releases"],
);

const RELEASE_CANCELLATION_SCHEMA: SchemaPart = SchemaPart {
    name: "deliverables.v3.release_cancellation",
    sql: "
ALTER TABLE deliverable_releases RENAME TO deliverable_releases_v2;
CREATE TABLE deliverable_releases (
    approval_id INTEGER PRIMARY KEY,
    revision_id INTEGER NOT NULL,
    org_id TEXT NOT NULL,
    requester TEXT NOT NULL,
    approver TEXT NOT NULL CHECK (approver <> requester COLLATE NOCASE),
    destination TEXT NOT NULL,
    root_identity TEXT NOT NULL,
    staging_id TEXT NOT NULL UNIQUE,
    workflow_revision INTEGER NOT NULL,
    ownership_generation INTEGER NOT NULL,
    payload BLOB,
    released_at TEXT,
    cancelled_at TEXT,
    cancelled_by TEXT,
    CHECK (released_at IS NULL OR cancelled_at IS NULL),
    CHECK ((cancelled_by IS NULL) = (cancelled_at IS NULL)),
    CHECK ((payload IS NULL) = (released_at IS NOT NULL OR cancelled_at IS NOT NULL)),
    CHECK (length(payload) <= 1048576)
);
INSERT INTO deliverable_releases (
    approval_id, revision_id, org_id, requester, approver, destination, root_identity,
    staging_id, workflow_revision, ownership_generation, payload, released_at
) SELECT
    approval_id, revision_id, org_id, requester, approver, destination, root_identity,
    staging_id, workflow_revision, ownership_generation, payload, released_at
FROM deliverable_releases_v2;
DROP TABLE deliverable_releases_v2;

CREATE UNIQUE INDEX idx_deliverable_releases_active_revision
    ON deliverable_releases (revision_id) WHERE cancelled_at IS NULL;
CREATE UNIQUE INDEX idx_deliverable_releases_active_destination
    ON deliverable_releases (root_identity, destination COLLATE NOCASE) WHERE cancelled_at IS NULL;
CREATE INDEX idx_deliverable_releases_cancelled_revision
    ON deliverable_releases (revision_id, approval_id) WHERE cancelled_at IS NOT NULL;
CREATE TRIGGER deliverable_releases_revision BEFORE INSERT ON deliverable_releases
WHEN NOT EXISTS (
    SELECT 1 FROM deliverable_files f WHERE f.revision_id = NEW.revision_id AND f.org_id = NEW.org_id
)
BEGIN SELECT RAISE(ABORT, 'a release needs a file revision in its own organization'); END;
CREATE TRIGGER deliverable_releases_pending BEFORE INSERT ON deliverable_releases
WHEN NEW.released_at IS NOT NULL OR NEW.cancelled_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'a new release must be pending'); END;
CREATE TRIGGER deliverable_releases_fixed BEFORE UPDATE ON deliverable_releases
WHEN OLD.released_at IS NOT NULL OR OLD.cancelled_at IS NOT NULL
     OR (NEW.released_at IS NULL AND NEW.cancelled_at IS NULL) OR NEW.payload IS NOT NULL
     OR NEW.revision_id IS NOT OLD.revision_id OR NEW.org_id IS NOT OLD.org_id
     OR NEW.approval_id IS NOT OLD.approval_id OR NEW.requester IS NOT OLD.requester
     OR NEW.approver IS NOT OLD.approver OR NEW.destination IS NOT OLD.destination
     OR NEW.root_identity IS NOT OLD.root_identity OR NEW.staging_id IS NOT OLD.staging_id
     OR NEW.workflow_revision IS NOT OLD.workflow_revision
     OR NEW.ownership_generation IS NOT OLD.ownership_generation
BEGIN SELECT RAISE(ABORT, 'a pending release may only advance to completed or cancelled'); END;
CREATE TRIGGER deliverable_releases_no_delete BEFORE DELETE ON deliverable_releases
BEGIN SELECT RAISE(ABORT, 'a release is never deleted'); END;
",
};

const RELEASE_CANCELLATION_TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.deliverable_release_cancellation", &["deliverable_releases"]);

/// The crate's schema parts, in application order. They need
/// `organization.v1.store` applied first.
pub fn schema_parts() -> Vec<Part> {
    vec![
        SCHEMA.into(),
        TENANT_PART.into(),
        FILE_SCHEMA.into(),
        FILE_TENANT_PART.into(),
        RELEASE_CANCELLATION_SCHEMA.into(),
        RELEASE_CANCELLATION_TENANT_PART.into(),
    ]
}

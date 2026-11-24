//! Storage schema of the memory domain: the notes table with its FTS5 index
//! and triggers, the version history and the note vectors.
//!
//! Released parts are checksum-locked by `ua-store` (SHA-256 of `sql`): never
//! edit one; add a new versioned part (`"memory.v2"`) instead.

use ua_store::{Part, Procedure, SchemaPart};

/// Notes, their full-text index and the triggers that keep it current.
///
/// `seq` is the stable integer key the external-content FTS table mirrors
/// (an implicit rowid may change on VACUUM); `id` is the public note id.
/// Every timestamp column holds the storage form of `ua_core::time`
/// (`YYYY-MM-DDTHH:MM:SS+00:00`), so SQL compares them as text.
pub const SCHEMA: SchemaPart = SchemaPart {
    name: "memory.v1",
    sql: "
CREATE TABLE IF NOT EXISTS memory (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    title TEXT,
    content TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    author TEXT,
    updated_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    salience REAL NOT NULL DEFAULT 0.5,
    confidence REAL,
    last_accessed TEXT,
    access_count INTEGER NOT NULL DEFAULT 0,
    source_host TEXT,
    superseded_by TEXT,
    expires_at TEXT,
    feedback_helpful INTEGER NOT NULL DEFAULT 0,
    feedback_not_helpful INTEGER NOT NULL DEFAULT 0,
    feedback_stale INTEGER NOT NULL DEFAULT 0,
    feedback_wrong INTEGER NOT NULL DEFAULT 0,
    recalled_count INTEGER NOT NULL DEFAULT 0,
    upvoted_count INTEGER NOT NULL DEFAULT 0,
    last_recalled_at TEXT,
    epistemic TEXT CHECK (epistemic IS NULL OR epistemic IN ('fact','inferred')),
    evidence TEXT,
    valid_from TEXT,
    valid_to TEXT,
    contradicts TEXT
);
CREATE INDEX IF NOT EXISTS idx_memory_updated ON memory(updated_at);
CREATE INDEX IF NOT EXISTS idx_memory_superseded ON memory(superseded_by);
CREATE INDEX IF NOT EXISTS idx_memory_author ON memory(author);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
    title, content, tags,
    content='memory', content_rowid='seq',
    tokenize='porter unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS memory_fts_ai AFTER INSERT ON memory BEGIN
    INSERT INTO memory_fts(rowid, title, content, tags)
        VALUES (new.seq, new.title, new.content, new.tags);
END;
CREATE TRIGGER IF NOT EXISTS memory_fts_ad AFTER DELETE ON memory BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, title, content, tags)
        VALUES ('delete', old.seq, old.title, old.content, old.tags);
END;
CREATE TRIGGER IF NOT EXISTS memory_fts_au AFTER UPDATE OF title, content, tags ON memory BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, title, content, tags)
        VALUES ('delete', old.seq, old.title, old.content, old.tags);
    INSERT INTO memory_fts(rowid, title, content, tags)
        VALUES (new.seq, new.title, new.content, new.tags);
END;
",
};

/// Prior content and tags of every note, newest 50 per note. The trigger
/// records whichever path changed the note, attributed to whoever wrote the
/// replaced state; `recorded_at` is when it was replaced.
pub const VERSIONS_SCHEMA: SchemaPart = SchemaPart {
    name: "memory_versions.v1",
    sql: "
CREATE TABLE IF NOT EXISTS memory_versions (
    note_id TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    version INTEGER NOT NULL CHECK (version >= 1),
    content TEXT NOT NULL,
    tags TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    actor TEXT,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (note_id, version)
);
CREATE TRIGGER IF NOT EXISTS memory_versions_capture
BEFORE UPDATE OF content, tags ON memory
FOR EACH ROW
WHEN (OLD.content IS NOT NEW.content OR OLD.tags IS NOT NEW.tags)
BEGIN
    INSERT INTO memory_versions (note_id, version, content, tags, updated_at, actor, recorded_at)
    VALUES (
        OLD.id,
        COALESCE((SELECT MAX(version) FROM memory_versions WHERE note_id = OLD.id), 0) + 1,
        OLD.content,
        OLD.tags,
        OLD.updated_at,
        COALESCE(OLD.updated_by, OLD.author),
        strftime('%Y-%m-%dT%H:%M:%S+00:00', 'now')
    );
    DELETE FROM memory_versions
    WHERE note_id = OLD.id
      AND version <= (SELECT MAX(version) FROM memory_versions WHERE note_id = OLD.id) - 50;
END;
",
};

/// One vector per note. `content_sha` is the SHA-256 of the embedded text
/// (title, a blank line, content), so a stale vector is detectable.
pub const EMBEDDINGS_SCHEMA: SchemaPart = SchemaPart {
    name: "memory_embeddings.v1",
    sql: "
CREATE TABLE IF NOT EXISTS memory_embeddings (
    note_id TEXT PRIMARY KEY NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    model TEXT NOT NULL,
    dim INTEGER NOT NULL,
    embedding BLOB NOT NULL,
    content_sha TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memory_embeddings_model ON memory_embeddings(model);
",
};

/// The released, organization-free parts, in application order. The
/// organization parts ([`TENANT_PART`], [`ORG_SCOPE`]) need
/// `organization.v1.store` and are listed by [`org_parts`].
pub fn schema_parts() -> Vec<SchemaPart> {
    vec![SCHEMA, VERSIONS_SCHEMA, EMBEDDINGS_SCHEMA]
}

/// `organization.v1.memory`: `org_id` on `memory`, `memory_versions` and
/// `memory_embeddings` (every existing row filled with the default
/// organization, so nothing is moved or dropped) and their generated
/// `*_org_exists` / `*_org_immutable` triggers. No key rebuild: a note id is
/// hub-generated (random, never caller-chosen) and the version and vector
/// keys are led by it, so two organizations can never collide on a key.
/// Applied after [`schema_parts`] and `organization.v1.store`.
pub const TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.memory", &["memory", "memory_versions", "memory_embeddings"]);

/// `memory.v2.org_scope`: the version-capture trigger recreated so the
/// history row names its note's organization (the `memory_versions.v1`
/// trigger leaves `org_id` to its default, which would file another
/// organization's history under the default one), triggers that keep a
/// version, a vector and a supersede pointer (set by an update, or already
/// set on an insert) in their note's organization,
/// and indexes led by `org_id` for the listing and the vector scan.
///
/// Every row is in the default organization when this part runs (the tenant
/// part has just added the column), so no row moves and none is dropped.
pub const ORG_SCOPE: SchemaPart = SchemaPart {
    name: "memory.v2.org_scope",
    sql: "
DROP TRIGGER IF EXISTS memory_versions_capture;
CREATE TRIGGER memory_versions_capture
BEFORE UPDATE OF content, tags ON memory
FOR EACH ROW
WHEN (OLD.content IS NOT NEW.content OR OLD.tags IS NOT NEW.tags)
BEGIN
    INSERT INTO memory_versions (org_id, note_id, version, content, tags, updated_at, actor, recorded_at)
    VALUES (
        OLD.org_id,
        OLD.id,
        COALESCE((SELECT MAX(version) FROM memory_versions WHERE note_id = OLD.id), 0) + 1,
        OLD.content,
        OLD.tags,
        OLD.updated_at,
        COALESCE(OLD.updated_by, OLD.author),
        strftime('%Y-%m-%dT%H:%M:%S+00:00', 'now')
    );
    DELETE FROM memory_versions
    WHERE note_id = OLD.id
      AND version <= (SELECT MAX(version) FROM memory_versions WHERE note_id = OLD.id) - 50;
END;

CREATE TRIGGER IF NOT EXISTS memory_versions_org_parent BEFORE INSERT ON memory_versions
WHEN EXISTS (SELECT 1 FROM memory WHERE id = NEW.note_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'memory note belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS memory_versions_org_parent_update BEFORE UPDATE OF note_id ON memory_versions
WHEN EXISTS (SELECT 1 FROM memory WHERE id = NEW.note_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'memory note belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS memory_embeddings_org_parent BEFORE INSERT ON memory_embeddings
WHEN EXISTS (SELECT 1 FROM memory WHERE id = NEW.note_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'memory note belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS memory_embeddings_org_parent_update BEFORE UPDATE OF note_id ON memory_embeddings
WHEN EXISTS (SELECT 1 FROM memory WHERE id = NEW.note_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'memory note belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS memory_org_superseded_by BEFORE UPDATE OF superseded_by ON memory
WHEN NEW.superseded_by IS NOT NULL
 AND EXISTS (SELECT 1 FROM memory WHERE id = NEW.superseded_by AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'memory note belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS memory_org_superseded_by_insert BEFORE INSERT ON memory
WHEN NEW.superseded_by IS NOT NULL
 AND EXISTS (SELECT 1 FROM memory WHERE id = NEW.superseded_by AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'memory note belongs to another organization'); END;

CREATE INDEX IF NOT EXISTS idx_memory_org_updated ON memory(org_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_memory_embeddings_org_model ON memory_embeddings(org_id, model);
",
};

/// The organization parts, in application order, after [`schema_parts`] and
/// `organization.v1.store`.
pub fn org_parts() -> Vec<Part> {
    vec![TENANT_PART.into(), ORG_SCOPE.into()]
}

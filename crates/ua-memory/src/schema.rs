//! Memory notes: persistent, searchable notes shared by every agent session.
//!
//! Tools: `memory_save`, `memory_search`, `memory_list`, `memory_get`,
//! `memory_delete`, `memory_restore`, `memory_feedback`,
//! `memory_prune_candidates` and `recall_maintenance`.
//!
//! Storage: the `memory` table, an FTS5 index over title, content and tags
//! (`memory_fts`), prior versions captured by a trigger (`memory_versions`),
//! and optional note vectors (`memory_embeddings`, little-endian f32 BLOBs).
//!
//! Search fuses a lexical leg (FTS5 bm25), an optional semantic leg (cosine
//! over stored vectors, see [`embed`]) and a recency leg with reciprocal rank
//! fusion, then applies a bounded prior from salience, feedback confidence
//! and upvotes. Without the `embeddings` cargo feature the semantic leg is
//! off and search is lexical only.

mod embed;
mod lifecycle;
mod maintenance;
mod note;
mod rank;
mod save;
mod search;

pub use embed::{
    BruteForceIndex, EmbedError, Embedder, NoopEmbedder, VectorIndex, embedder_for, register_embedder,
};
pub(crate) use note::mark_untrusted;

use ua_store::SchemaPart;

use crate::registry::Registry;

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

pub fn schema_parts() -> Vec<SchemaPart> {
    vec![SCHEMA, VERSIONS_SCHEMA, EMBEDDINGS_SCHEMA]
}

pub fn register(r: &mut Registry) {
    save::register(r);
    search::register(r);
    lifecycle::register(r);
    maintenance::register(r);
}

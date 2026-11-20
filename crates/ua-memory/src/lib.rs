//! Memory notes: persistent, searchable notes shared by every agent session.
//!
//! This crate is the memory domain: the storage schema ([`schema`]), the note
//! model and eligibility filter ([`note`]), saving ([`save`]), search, listing
//! and reads ([`search`]) with their rank fusion ([`rank`]) and embeddings
//! ([`embed`]), delete, restore and feedback ([`lifecycle`]), and the
//! report-only maintenance passes ([`maintenance`]). It depends on `ua-core`
//! and `ua-store` only, never on the tool registry.
//!
//! The tools (`memory_save`, `memory_search`, `memory_list`, `memory_get`,
//! `memory_delete`, `memory_restore`, `memory_feedback`,
//! `memory_prune_candidates` and `recall_maintenance`) are registered by
//! `ua-tools` (`families/memory`), which parses their arguments and calls the
//! functions here. Adapters do not call this crate directly: every memory
//! operation an agent or a person makes runs through the governed registry.
//!
//! Storage: the `memory` table, an FTS5 index over title, content and tags
//! (`memory_fts`), prior versions captured by a trigger (`memory_versions`),
//! and optional note vectors (`memory_embeddings`, little-endian f32 BLOBs).
//! The operations also use three tables owned elsewhere: the ledger
//! (`ua_store::ledger::SCHEMA`), `idempotency_keys` (a save's
//! `idempotency_key`) and `agents` (the host stamped on a new note). The hub
//! (`ua_tools::schema_parts`) applies all of them.
//!
//! Search fuses a lexical leg (FTS5 bm25), an optional semantic leg (cosine
//! over stored vectors, see [`embed`]) and a recency leg with reciprocal rank
//! fusion, then applies a bounded prior from salience, feedback confidence
//! and upvotes. Without the `embeddings` cargo feature the semantic leg is
//! off and search is lexical only.

pub mod embed;
pub mod lifecycle;
pub mod maintenance;
pub mod note;
pub mod rank;
pub mod save;
pub mod schema;
pub mod search;

pub use embed::{
    BruteForceIndex, EmbedError, Embedder, NoopEmbedder, VectorIndex, embedder_for, register_embedder,
};
pub use note::mark_untrusted;
pub use schema::{EMBEDDINGS_SCHEMA, SCHEMA, VERSIONS_SCHEMA, schema_parts};

use ua_core::{UaError, UaResult};

/// True when this build has the `embeddings` feature (fastembed). Without it
/// every model resolves to [`NoopEmbedder`] and search is lexical only.
pub const EMBEDDINGS_ENABLED: bool = cfg!(feature = "embeddings");

/// Run blocking work (an embedding model) off the async runtime.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> UaResult<T> + Send + 'static) -> UaResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| UaError::internal(format!("blocking task failed: {e}")))?
}

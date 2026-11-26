//! Embeddings and vector search for memory notes.
//!
//! An [`Embedder`] turns text into vectors. Without the `embeddings` cargo
//! feature every model resolves to [`NoopEmbedder`], which is unavailable, and
//! search stays lexical. With the feature, an unregistered model name resolves
//! to a fastembed model that loads lazily on first use. Embedders registered
//! with [`register_embedder`] take precedence (tests, custom backends).
//!
//! Vectors are stored in `memory_embeddings` as little-endian f32 BLOBs and
//! scanned by a [`VectorIndex`]; [`BruteForceIndex`] computes cosine over every
//! eligible note, which is fast enough at 10^5 notes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, params};
use ua_core::{Config, UaResult};

use super::chunks;
use super::note::{Filter, embed_text, text_sha};

/// Format a canonical vector identity (`backend:model@revision`) stored in
/// `memory_embeddings.model` and `memory_chunks.model`.
pub fn vector_identity(backend: &str, model: &str, revision: &str) -> String {
    format!("{backend}:{model}@{revision}")
}

/// Why an embedding could not be produced.
#[derive(Debug, Clone)]
pub struct EmbedError {
    /// `disabled`, `model_acquisition` or `runtime`.
    pub category: &'static str,
    pub message: String,
}

impl EmbedError {
    pub fn disabled() -> Self {
        Self { category: "disabled", message: "embeddings are not enabled in this build".into() }
    }

    pub fn runtime(message: impl Into<String>) -> Self {
        Self { category: "runtime", message: message.into() }
    }
}

/// Text to vectors. Implementations must be cheap to call from blocking threads.
pub trait Embedder: Send + Sync {
    /// The configured model name (also the lookup key in the embedder registry).
    fn model(&self) -> &str;

    /// Backend identifier (e.g. `local`, `ollama`, `openai_compat`, `custom`).
    /// Included in [`Embedder::identity`] so two backends with the same model
    /// name never compare as equal.
    fn backend(&self) -> &str {
        "custom"
    }

    /// Model revision or digest (e.g. a pinned revision or Ollama digest).
    fn revision(&self) -> &str {
        "unversioned"
    }

    /// Canonical vector identity stored in `memory_embeddings.model` and
    /// `memory_chunks.model`: `<backend>:<model>@<revision>`.
    fn identity(&self) -> String {
        vector_identity(self.backend(), self.model(), self.revision())
    }

    /// False when this embedder never produces vectors (the no-op default).
    fn available(&self) -> bool {
        true
    }

    /// One vector per text, in order.
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError>;
}

/// The default without the `embeddings` feature: never produces vectors.
#[derive(Debug, Clone)]
pub struct NoopEmbedder {
    model: String,
}

impl NoopEmbedder {
    pub fn new(model: impl Into<String>) -> Self {
        Self { model: model.into() }
    }
}

impl Embedder for NoopEmbedder {
    fn model(&self) -> &str {
        &self.model
    }

    fn backend(&self) -> &str {
        "noop"
    }

    fn available(&self) -> bool {
        false
    }

    fn embed(&self, _texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
        Err(EmbedError::disabled())
    }
}

type EmbedderMap = Mutex<HashMap<String, Arc<dyn Embedder>>>;

fn registry() -> &'static EmbedderMap {
    static REG: OnceLock<EmbedderMap> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Use `embedder` for its model name from now on, in this process.
pub fn register_embedder(embedder: Arc<dyn Embedder>) {
    if let Ok(mut reg) = registry().lock() {
        reg.insert(embedder.model().to_string(), embedder);
    }
}

/// The embedder for the configured model (`cfg.embed_model`).
pub fn embedder_for(cfg: &Config) -> Arc<dyn Embedder> {
    let model = cfg.embed_model.clone();
    #[allow(unused_mut)]
    let Ok(mut reg) = registry().lock() else {
        return Arc::new(NoopEmbedder::new(model));
    };
    if let Some(e) = reg.get(&model) {
        return e.clone();
    }
    #[cfg(feature = "embeddings")]
    {
        let e: Arc<dyn Embedder> = Arc::new(fast::FastEmbedder::new(model.clone(), cfg.home.join("models")));
        reg.insert(model, e.clone());
        e
    }
    #[cfg(not(feature = "embeddings"))]
    {
        drop(reg);
        Arc::new(NoopEmbedder::new(model))
    }
}

/// Embed one text, or an error when the embedder is unavailable or fails.
pub fn embed_one(e: &dyn Embedder, text: String) -> Result<Vec<f32>, EmbedError> {
    if !e.available() {
        return Err(EmbedError::disabled());
    }
    e.embed(&[text])?.into_iter().next().ok_or_else(|| EmbedError::runtime("embedder returned no vector"))
}

/// Embed a batch of texts, checking that the embedder returns one vector per input.
pub fn embed_batch(e: &dyn Embedder, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
    if !e.available() {
        return Err(EmbedError::disabled());
    }
    if texts.is_empty() {
        return Ok(Vec::new());
    }
    let out = e.embed(texts)?;
    if out.len() != texts.len() {
        return Err(EmbedError::runtime(format!(
            "embedder returned {} vectors for {} texts",
            out.len(),
            texts.len()
        )));
    }
    Ok(out)
}

/// Embed a note's single vector and (when longer than [`chunks::SINGLE_VECTOR_MAX_CHARS`])
/// its overlapping chunks in a single embedder call.
pub(crate) fn embed_note(
    e: &dyn Embedder,
    title: Option<&str>,
    content: &str,
) -> Result<(Vec<f32>, Vec<Vec<f32>>), EmbedError> {
    let text = embed_text(title, content);
    let pieces = chunks::chunk_text(&text);
    let mut inputs = Vec::with_capacity(1 + pieces.len());
    inputs.push(text);
    inputs.extend(pieces);
    let mut vecs = embed_batch(e, &inputs)?;
    let single = vecs.remove(0);
    Ok((single, vecs))
}

#[cfg(feature = "embeddings")]
mod fast {
    //! fastembed-backed embedder. The model loads on first use; a failed load
    //! is retried at most once a minute.

    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use fastembed::{EmbeddingModel, TextEmbedding, TextInitOptions};

    use super::{EmbedError, Embedder};

    const RETRY_AFTER: Duration = Duration::from_secs(60);
    const LOCAL_MODEL_REVISION: &str = "fastembed-7.7";

    pub struct FastEmbedder {
        name: String,
        cache_dir: PathBuf,
        state: Mutex<State>,
    }

    #[derive(Default)]
    struct State {
        model: Option<TextEmbedding>,
        last_failure: Option<(Instant, String)>,
    }

    impl FastEmbedder {
        pub fn new(name: String, cache_dir: PathBuf) -> Self {
            Self { name, cache_dir, state: Mutex::new(State::default()) }
        }
    }

    /// Accept fastembed's variant name (`BGESmallENV15`), its model code
    /// (`Xenova/bge-small-en-v1.5`) or the upstream id (`BAAI/bge-small-en-v1.5`).
    fn resolve(name: &str) -> Option<EmbeddingModel> {
        if let Ok(m) = name.parse::<EmbeddingModel>() {
            return Some(m);
        }
        let models = TextEmbedding::list_supported_models();
        if let Some(info) = models.iter().find(|i| i.model_code.eq_ignore_ascii_case(name)) {
            return Some(info.model.clone());
        }
        let tail = name.rsplit('/').next().unwrap_or(name);
        models
            .iter()
            .find(|i| i.model_code.rsplit('/').next().is_some_and(|t| t.eq_ignore_ascii_case(tail)))
            .map(|i| i.model.clone())
    }

    impl Embedder for FastEmbedder {
        fn model(&self) -> &str {
            &self.name
        }

        fn backend(&self) -> &str {
            "local"
        }

        fn revision(&self) -> &str {
            LOCAL_MODEL_REVISION
        }

        fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
            let mut st = self.state.lock().map_err(|_| EmbedError::runtime("embedder lock poisoned"))?;
            if st.model.is_none() {
                if let Some((at, msg)) = &st.last_failure
                    && at.elapsed() < RETRY_AFTER
                {
                    return Err(EmbedError { category: "model_acquisition", message: msg.clone() });
                }
                let Some(model) = resolve(&self.name) else {
                    return Err(EmbedError {
                        category: "model_acquisition",
                        message: format!("unknown embedding model {:?}", self.name),
                    });
                };
                let opts = TextInitOptions::new(model).with_cache_dir(self.cache_dir.clone());
                match TextEmbedding::try_new(opts) {
                    Ok(m) => {
                        st.model = Some(m);
                        st.last_failure = None;
                    }
                    Err(e) => {
                        let msg = format!("could not load embedding model {}: {e}", self.name);
                        st.last_failure = Some((Instant::now(), msg.clone()));
                        return Err(EmbedError { category: "model_acquisition", message: msg });
                    }
                }
            }
            let Some(model) = st.model.as_mut() else {
                return Err(EmbedError::runtime("embedding model not loaded"));
            };
            let out = model.embed(texts, None).map_err(|e| EmbedError::runtime(e.to_string()))?;
            if out.len() != texts.len() {
                return Err(EmbedError::runtime(format!(
                    "embedding model returned {} vectors for {} texts",
                    out.len(),
                    texts.len()
                )));
            }
            Ok(out)
        }
    }
}

// ── vector storage ─────────────────────────────────────────────────────────

pub fn to_blob(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|f| f.to_le_bytes()).collect()
}

pub fn from_blob(b: &[u8]) -> Vec<f32> {
    b.as_chunks::<4>().0.iter().map(|c| f32::from_le_bytes(*c)).collect()
}

/// Cosine similarity; 0 for mismatched lengths or a zero vector.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let (mut dot, mut na, mut nb) = (0f64, 0f64, 0f64);
    for (x, y) in a.iter().zip(b) {
        let (x, y) = (f64::from(*x), f64::from(*y));
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 { 0.0 } else { (dot / (na.sqrt() * nb.sqrt())) as f32 }
}

/// Store (or replace) the vector of organization `org`'s note. The
/// `memory_embeddings_org_parent` trigger refuses a note of another
/// organization, and the upsert never rewrites a row of another one.
pub(crate) fn store_vector(
    conn: &Connection,
    org: &str,
    note_id: &str,
    model: &str,
    v: &[f32],
    content_sha: &str,
) -> UaResult<()> {
    conn.execute(
        "INSERT INTO memory_embeddings (org_id, note_id, model, dim, embedding, content_sha, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
         ON CONFLICT(note_id) DO UPDATE SET model = excluded.model, dim = excluded.dim, \
           embedding = excluded.embedding, content_sha = excluded.content_sha, updated_at = excluded.updated_at \
         WHERE memory_embeddings.org_id = excluded.org_id",
        params![org, note_id, model, v.len() as i64, to_blob(v), content_sha, ua_core::time::now()],
    )?;
    Ok(())
}

/// Store (or replace) the chunk vectors of organization `org`'s note.
/// Existing chunks for the note are deleted first so shrinking a note below
/// the chunking threshold removes its old chunks. The `memory_chunks_org_fence`
/// trigger refuses a note of another organization.
pub(crate) fn store_chunks(
    conn: &Connection,
    org: &str,
    note_id: &str,
    model: &str,
    chunks: &[Vec<f32>],
    content_sha: &str,
) -> UaResult<usize> {
    conn.execute("DELETE FROM memory_chunks WHERE org_id = ?1 AND note_id = ?2", params![org, note_id])?;
    if chunks.is_empty() {
        return Ok(0);
    }
    let mut stmt = conn.prepare(
        "INSERT INTO memory_chunks (org_id, note_id, idx, model, dim, embedding, content_sha) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    let mut written = 0usize;
    for (idx, v) in chunks.iter().take(chunks::MAX_CHUNKS).enumerate() {
        stmt.execute(params![org, note_id, idx as i64, model, v.len() as i64, to_blob(v), content_sha])?;
        written += 1;
    }
    Ok(written)
}

/// Nearest-neighbour lookup over stored note vectors and chunks.
///
/// `model` is the active canonical vector identity (`backend:model@revision`).
/// Only rows whose `model` equals `model` and whose `content_sha` matches the
/// SHA-256 of the note's current embedded text are scored; a note's score is
/// `max(single_vector_cosine, best_chunk_cosine)`.
pub trait VectorIndex: Send + Sync {
    /// The `k` best notes passing `filter` with similarity >= `min_similarity`,
    /// best first (ties by id). `filter` names the organization, so only its
    /// notes' vectors are scanned, ranked or returned.
    fn nearest(
        &self,
        conn: &Connection,
        model: &str,
        query: &[f32],
        filter: &Filter,
        min_similarity: f32,
        k: usize,
    ) -> UaResult<Vec<(String, f32)>>;

    /// Similarity of each listed note of organization `org` that has a fresh
    /// vector or chunk of `model`.
    fn similarities(
        &self,
        conn: &Connection,
        org: &str,
        model: &str,
        query: &[f32],
        ids: &[String],
    ) -> UaResult<HashMap<String, f32>>;
}

/// Scans every eligible fresh single vector and chunk vector and computes
/// `max(single, best chunk)` cosine in Rust.
#[derive(Debug, Default, Clone, Copy)]
pub struct BruteForceIndex;

fn note_current_sha<'a>(
    cache: &'a mut HashMap<String, String>,
    note_id: &str,
    title: Option<&str>,
    content: &str,
) -> &'a str {
    cache.entry(note_id.to_string()).or_insert_with(|| text_sha(&embed_text(title, content))).as_str()
}

fn record_max(best: &mut HashMap<String, f32>, note_id: String, sim: f32) {
    best.entry(note_id)
        .and_modify(|cur| {
            if sim > *cur {
                *cur = sim;
            }
        })
        .or_insert(sim);
}

impl VectorIndex for BruteForceIndex {
    fn nearest(
        &self,
        conn: &Connection,
        model: &str,
        query: &[f32],
        filter: &Filter,
        min_similarity: f32,
        k: usize,
    ) -> UaResult<Vec<(String, f32)>> {
        let mut sha_cache: HashMap<String, String> = HashMap::new();
        let mut best: HashMap<String, f32> = HashMap::new();

        // 1. Single-vector scan.
        let single_sql = format!(
            "SELECT e.note_id, e.embedding, e.content_sha, m.title, m.content \
             FROM memory_embeddings e \
             JOIN memory m ON m.id = e.note_id AND m.org_id = e.org_id \
             WHERE e.model = ? AND e.dim = ? AND e.content_sha <> '' AND {}",
            filter.sql
        );
        let mut p = vec![SqlValue::Text(model.into()), SqlValue::Integer(query.len() as i64)];
        p.extend(filter.params.iter().cloned());
        {
            let mut stmt = conn.prepare(&single_sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(p.iter().cloned()), |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?;
            for row in rows {
                let (id, blob, stored_sha, title, content) = row?;
                let current_sha = note_current_sha(&mut sha_cache, &id, title.as_deref(), &content);
                if stored_sha != current_sha {
                    continue;
                }
                let sim = cosine(query, &from_blob(&blob));
                record_max(&mut best, id, sim);
            }
        }

        // 2. Chunk-vector scan: keep max(single, best chunk) per note.
        let chunk_sql = format!(
            "SELECT c.note_id, c.embedding, c.content_sha, m.title, m.content \
             FROM memory_chunks c \
             JOIN memory m ON m.id = c.note_id AND m.org_id = c.org_id \
             WHERE c.model = ? AND c.dim = ? AND c.content_sha <> '' AND {}",
            filter.sql
        );
        {
            let mut stmt = conn.prepare(&chunk_sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(p), |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?;
            for row in rows {
                let (id, blob, stored_sha, title, content) = row?;
                let current_sha = note_current_sha(&mut sha_cache, &id, title.as_deref(), &content);
                if stored_sha != current_sha {
                    continue;
                }
                let sim = cosine(query, &from_blob(&blob));
                record_max(&mut best, id, sim);
            }
        }

        let mut hits: Vec<(String, f32)> =
            best.into_iter().filter(|(_, sim)| *sim >= min_similarity).collect();
        hits.sort_by(|a, b| {
            b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.0.cmp(&b.0))
        });
        hits.truncate(k);
        Ok(hits)
    }

    fn similarities(
        &self,
        conn: &Connection,
        org: &str,
        model: &str,
        query: &[f32],
        ids: &[String],
    ) -> UaResult<HashMap<String, f32>> {
        let mut out = HashMap::new();
        if ids.is_empty() {
            return Ok(out);
        }
        let dim = query.len() as i64;
        let ids_json = serde_json::to_string(ids).unwrap_or_else(|_| "[]".into());
        let mut sha_cache: HashMap<String, String> = HashMap::new();

        {
            let mut stmt = conn.prepare(
                "SELECT e.note_id, e.embedding, e.content_sha, m.title, m.content \
                 FROM memory_embeddings e \
                 JOIN memory m ON m.id = e.note_id AND m.org_id = e.org_id \
                 WHERE e.org_id = ?1 AND e.model = ?2 AND e.dim = ?3 AND e.content_sha <> '' \
                   AND e.note_id IN (SELECT value FROM json_each(?4))",
            )?;
            let rows = stmt.query_map(params![org, model, dim, &ids_json], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?;
            for row in rows {
                let (id, blob, stored_sha, title, content) = row?;
                let current_sha = note_current_sha(&mut sha_cache, &id, title.as_deref(), &content);
                if stored_sha != current_sha {
                    continue;
                }
                record_max(&mut out, id, cosine(query, &from_blob(&blob)));
            }
        }

        {
            let mut stmt = conn.prepare(
                "SELECT c.note_id, c.embedding, c.content_sha, m.title, m.content \
                 FROM memory_chunks c \
                 JOIN memory m ON m.id = c.note_id AND m.org_id = c.org_id \
                 WHERE c.org_id = ?1 AND c.model = ?2 AND c.dim = ?3 AND c.content_sha <> '' \
                   AND c.note_id IN (SELECT value FROM json_each(?4))",
            )?;
            let rows = stmt.query_map(params![org, model, dim, &ids_json], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?;
            for row in rows {
                let (id, blob, stored_sha, title, content) = row?;
                let current_sha = note_current_sha(&mut sha_cache, &id, title.as_deref(), &content);
                if stored_sha != current_sha {
                    continue;
                }
                record_max(&mut out, id, cosine(query, &from_blob(&blob)));
            }
        }
        Ok(out)
    }
}

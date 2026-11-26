//! `memory_prune_candidates`, `recall_maintenance`, and embedding backfill.
//! None of these ever deletes or rewrites a note.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use rusqlite::params;
use serde_json::{Value, json};
use ua_core::{Config, UaError, UaResult};
use ua_store::Db;

use crate::blocking;

use super::chunks::{self, BACKFILL_BATCH};
use super::embed::{self, embedder_for_org};
use super::note::{DELETED_TAG, NOTE_COLS, Note, days_ago, embed_text, fetch, text_sha};

/// Thresholds for [`prune_candidates`]. The `memory_prune_candidates` tool
/// documents each field for agents.
#[derive(Debug, Clone, Default)]
pub struct PruneRequest {
    /// Notes below this salience are candidates. Default 0.3.
    pub salience_threshold: Option<f64>,
    /// Notes not updated for this many days, never accessed and with salience
    /// at most 0.5 are candidates. Default 30.
    pub max_age_days: Option<f64>,
    /// Most candidates returned. Default 50.
    pub limit: Option<i64>,
}

/// Organization `org`'s notes that are not soft-deleted, newest first.
fn live_notes(conn: &rusqlite::Connection, org: &str, extra: &str) -> UaResult<Vec<Note>> {
    let sql = format!(
        "SELECT {NOTE_COLS} FROM memory m \
         WHERE m.org_id = ?2 AND NOT EXISTS (SELECT 1 FROM json_each(m.tags) WHERE value = ?1) {extra} \
         ORDER BY m.updated_at DESC, m.seq DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([DELETED_TAG, org], Note::from_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Organization `org`'s live notes that look superseded, low-salience, or
/// old and never accessed, most reasons first.
/// `cfg.clock` dates the age cutoff.
pub async fn prune_candidates(db: &Db, cfg: &Config, org: &str, a: PruneRequest) -> UaResult<Value> {
    let threshold = a.salience_threshold.unwrap_or(0.3);
    let max_age = a.max_age_days.unwrap_or(30.0);
    if !threshold.is_finite() || !max_age.is_finite() {
        return Err(UaError::invalid("salience_threshold and max_age_days must be finite numbers"));
    }
    let limit = a.limit.unwrap_or(50).max(0) as usize;
    let cutoff = days_ago(&cfg.clock, max_age);
    let org = org.to_string();
    db.read_async(move |c| {
        let mut candidates: Vec<(usize, f64, Value)> = Vec::new();
        for n in live_notes(c, &org, "")? {
            let mut reasons = Vec::new();
            if n.superseded_by.is_some() {
                reasons.push("superseded");
            }
            if n.salience < threshold {
                reasons.push("low_salience");
            }
            if n.updated_at < cutoff && n.access_count == 0 && n.salience <= 0.5 {
                reasons.push("decayed_unused");
            }
            if reasons.is_empty() {
                continue;
            }
            candidates.push((
                reasons.len(),
                n.salience,
                json!({
                    "id": n.id,
                    "title": n.title,
                    "tags": n.tags,
                    "author": n.author,
                    "updated_at": n.updated_at,
                    "salience": n.salience,
                    "access_count": n.access_count,
                    "superseded_by": n.superseded_by,
                    "reasons": reasons,
                }),
            ));
        }
        // Most reasons first, then lowest salience.
        candidates
            .sort_by(|x, y| y.0.cmp(&x.0).then(x.1.partial_cmp(&y.1).unwrap_or(std::cmp::Ordering::Equal)));
        let total = candidates.len();
        let out: Vec<Value> = candidates.into_iter().take(limit).map(|(_, _, v)| v).collect();
        Ok(json!({
            "candidate_count": total,
            "returned_count": out.len(),
            "salience_threshold": threshold,
            "max_age_days": max_age,
            "candidates": out,
        }))
    })
    .await
}

/// Thresholds for [`recall_maintenance`]. The `recall_maintenance` tool
/// documents each field for agents.
#[derive(Debug, Clone)]
pub struct MaintenanceRequest {
    /// Must stay true: this pass only reports.
    pub dry_run: bool,
    /// Notes not updated for this many days, never recalled and with salience
    /// at most 0.5 are stale. Default 120.
    pub stale_days: Option<f64>,
    /// Notes whose stated confidence is below this are flagged. Default 0.35.
    pub confidence_floor: Option<f64>,
    /// Most entries per list. Default 100.
    pub limit: Option<i64>,
}

fn candidate(n: &Note, reason: &str) -> Value {
    json!({
        "id": n.id,
        "title": n.title,
        "tags": n.tags,
        "author": n.author,
        "updated_at": n.updated_at,
        "salience": n.salience,
        "confidence": n.confidence,
        "recalled_count": n.recalled_count,
        "reason": reason,
    })
}

/// Maximum number of [`BACKFILL_BATCH`]-sized batches processed in a single
/// `recall_maintenance` / [`backfill_embeddings`] pass (8 batches × 8 notes =
/// 64 notes), so one maintenance call cannot stall by re-embedding an entire
/// corpus after a vector-identity change.
pub const MAX_BACKFILL_BATCHES_PER_PASS: usize = 8;

/// Cooldown before retrying a note that failed to embed with a runtime error
/// for the same `(identity, content_sha)`. Editing the note (new `content_sha`)
/// or changing the active vector identity bypasses the cooldown immediately.
const FAILED_NOTE_COOLDOWN: Duration = Duration::from_secs(15 * 60);
const MAX_TRACKED_CURSORS: usize = 4096;
const MAX_TRACKED_FAILURES: usize = 8192;

type CursorKey = (u64, String, String);
type FailedKey = (u64, String, String);
type FailedEntry = (String, String, Instant);

fn cursor_map() -> &'static Mutex<HashMap<CursorKey, i64>> {
    static MAP: OnceLock<Mutex<HashMap<CursorKey, i64>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn failed_map() -> &'static Mutex<HashMap<FailedKey, FailedEntry>> {
    static MAP: OnceLock<Mutex<HashMap<FailedKey, FailedEntry>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn load_cursor(db_id: u64, org: &str, identity: &str) -> i64 {
    cursor_map()
        .lock()
        .ok()
        .and_then(|m| m.get(&(db_id, org.to_string(), identity.to_string())).copied())
        .unwrap_or(0)
}

fn save_cursor(db_id: u64, org: &str, identity: &str, cursor: i64) {
    if let Ok(mut m) = cursor_map().lock() {
        let key = (db_id, org.to_string(), identity.to_string());
        if cursor <= 0 {
            m.remove(&key);
        } else {
            if m.len() >= MAX_TRACKED_CURSORS && !m.contains_key(&key) {
                m.clear();
            }
            m.insert(key, cursor);
        }
    }
}

fn is_in_failed_cooldown(db_id: u64, org: &str, note_id: &str, identity: &str, sha: &str) -> bool {
    let Ok(m) = failed_map().lock() else { return false };
    let Some((f_id, f_sha, at)) = m.get(&(db_id, org.to_string(), note_id.to_string())) else {
        return false;
    };
    f_id == identity && f_sha == sha && at.elapsed() < FAILED_NOTE_COOLDOWN
}

fn record_failed_note(db_id: u64, org: &str, note_id: &str, identity: &str, sha: &str) {
    if let Ok(mut m) = failed_map().lock() {
        if m.len() >= MAX_TRACKED_FAILURES {
            m.retain(|_, (_, _, at)| at.elapsed() < FAILED_NOTE_COOLDOWN);
            if m.len() >= MAX_TRACKED_FAILURES {
                m.clear();
            }
        }
        m.insert(
            (db_id, org.to_string(), note_id.to_string()),
            (identity.to_string(), sha.to_string(), Instant::now()),
        );
    }
}

fn clear_failed_note(db_id: u64, org: &str, note_id: &str) {
    if let Ok(mut m) = failed_map().lock() {
        m.remove(&(db_id, org.to_string(), note_id.to_string()));
    }
}

/// Summary of one [`backfill_embeddings`] pass over an organization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackfillReport {
    /// Active canonical vector identity (`backend:model@revision`).
    pub identity: String,
    /// False when the configured embedder is unavailable (no vectors written).
    pub available: bool,
    /// Live notes whose single vector and chunks were written by this pass.
    pub notes_embedded: usize,
    /// Total chunk rows written across those notes.
    pub chunks_written: usize,
    /// Number of bounded write batches (at most [`BACKFILL_BATCH`] notes each).
    pub batches: usize,
    /// Notes whose embedding failed with a runtime error.
    pub failed: usize,
    /// True when the pass stopped early because the embedder reported
    /// `model_acquisition` or `disabled`.
    pub stopped_unavailable: bool,
    /// True when the pass reached the per-call batch cap before exhausting
    /// stale notes; a subsequent pass will continue from the remaining notes.
    pub has_more: bool,
}

impl BackfillReport {
    pub fn to_json(&self) -> Value {
        json!({
            "identity": self.identity,
            "available": self.available,
            "notes_embedded": self.notes_embedded,
            "chunks_written": self.chunks_written,
            "batches": self.batches,
            "failed": self.failed,
            "stopped_unavailable": self.stopped_unavailable,
            "has_more": self.has_more,
        })
    }
}

struct PendingNote {
    id: String,
    title: Option<String>,
    content: String,
    sha: String,
}

struct ScanRow {
    seq: i64,
    id: String,
    title: Option<String>,
    content: String,
    emb_model: Option<String>,
    emb_sha: Option<String>,
}

struct EmbeddedNote {
    id: String,
    expected_sha: String,
    single: Vec<f32>,
    chunks: Vec<Vec<f32>>,
}

/// Collect up to [`BACKFILL_BATCH`] live notes of `org` with `seq > cursor`
/// whose single vector or chunk vectors are missing or stale for `identity`,
/// skipping notes in per-`(identity, content_sha)` failure cooldown.
/// Returns `(notes_to_embed, next_cursor, exhausted)`.
fn next_stale_batch(
    conn: &rusqlite::Connection,
    db_id: u64,
    org: &str,
    identity: &str,
    mut cursor: i64,
) -> UaResult<(Vec<PendingNote>, i64, bool)> {
    const PAGE_SIZE: i64 = 64;
    let mut pending = Vec::new();
    let mut exhausted = false;

    let mut page_stmt = conn.prepare(
        "SELECT m.seq, m.id, m.title, m.content, e.model, e.content_sha \
         FROM memory m \
         LEFT JOIN memory_embeddings e ON e.note_id = m.id AND e.org_id = m.org_id \
         WHERE m.org_id = ?1 \
           AND m.seq > ?2 \
           AND m.superseded_by IS NULL \
           AND NOT EXISTS (SELECT 1 FROM json_each(m.tags) WHERE value = ?3) \
         ORDER BY m.seq ASC \
         LIMIT ?4",
    )?;
    let mut chunk_stmt = conn.prepare(
        "SELECT COUNT(*), \
                COALESCE(SUM(CASE WHEN model = ?3 AND content_sha = ?4 THEN 1 ELSE 0 END), 0) \
         FROM memory_chunks \
         WHERE org_id = ?1 AND note_id = ?2",
    )?;

    while pending.len() < BACKFILL_BATCH {
        let rows: Vec<ScanRow> = page_stmt
            .query_map(params![org, cursor, DELETED_TAG, PAGE_SIZE], |r| {
                Ok(ScanRow {
                    seq: r.get(0)?,
                    id: r.get(1)?,
                    title: r.get(2)?,
                    content: r.get(3)?,
                    emb_model: r.get(4)?,
                    emb_sha: r.get(5)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        if rows.is_empty() {
            exhausted = true;
            break;
        }
        let fetched = rows.len() as i64;
        for row in rows {
            cursor = row.seq;
            let text = embed_text(row.title.as_deref(), &row.content);
            let sha = text_sha(&text);
            let single_fresh =
                row.emb_model.as_deref() == Some(identity) && row.emb_sha.as_deref() == Some(sha.as_str());
            let expected_chunks = chunks::chunk_text(&text).len() as i64;
            let (total_chunks, fresh_chunks): (i64, i64) = chunk_stmt
                .query_row(params![org, &row.id, identity, &sha], |r| Ok((r.get(0)?, r.get(1)?)))?;
            let chunks_fresh = total_chunks == expected_chunks && fresh_chunks == expected_chunks;
            if (!single_fresh || !chunks_fresh) && !is_in_failed_cooldown(db_id, org, &row.id, identity, &sha)
            {
                pending.push(PendingNote { id: row.id, title: row.title, content: row.content, sha });
                if pending.len() == BACKFILL_BATCH {
                    break;
                }
            }
        }
        if fetched < PAGE_SIZE && pending.len() < BACKFILL_BATCH {
            exhausted = true;
            break;
        }
    }
    Ok((pending, cursor, exhausted))
}

/// Backfill missing or stale single vectors and chunk vectors for live notes
/// in organization `org`, committing at most [`BACKFILL_BATCH`] (8) notes per
/// write transaction and capping the pass at [`MAX_BACKFILL_BATCHES_PER_PASS`]
/// batches so one call cannot re-embed an unbounded corpus. Keeps a per-org
/// cursor across passes and places runtime-failing notes on a per-`(identity,
/// content_sha)` cooldown so persistently failing notes never starve later
/// notes. Embeddings are computed outside any database lock, and each write
/// re-verifies the note's text hash before storing.
pub async fn backfill_embeddings(db: &Db, cfg: &Config, org: &str) -> UaResult<BackfillReport> {
    backfill_embeddings_capped(db, cfg, org, Some(MAX_BACKFILL_BATCHES_PER_PASS)).await
}

/// Same as [`backfill_embeddings`] with an explicit optional batch cap
/// (`None` runs until exhausted).
pub async fn backfill_embeddings_capped(
    db: &Db,
    cfg: &Config,
    org: &str,
    max_batches: Option<usize>,
) -> UaResult<BackfillReport> {
    let embedder = embedder_for_org(db, cfg, org).await;
    let identity = embedder.identity();
    let mut report =
        BackfillReport { identity: identity.clone(), available: embedder.available(), ..Default::default() };
    if !embedder.available() {
        return Ok(report);
    }

    let db_id = db.instance_id();
    let mut cursor: i64 = load_cursor(db_id, org, &identity);
    let mut batches_attempted: usize = 0;
    loop {
        let (org_r, id_r) = (org.to_string(), identity.clone());
        let (batch, next_cursor, exhausted) =
            db.read_async(move |c| next_stale_batch(c, db_id, &org_r, &id_r, cursor)).await?;
        if batch.is_empty() {
            save_cursor(db_id, org, &identity, 0);
            break;
        }
        if let Some(cap) = max_batches
            && batches_attempted >= cap
        {
            save_cursor(db_id, org, &identity, cursor);
            report.has_more = true;
            break;
        }
        batches_attempted += 1;
        report.batches += 1;

        let mut embedded: Vec<EmbeddedNote> = Vec::new();
        for note in batch {
            let e = embedder.clone();
            let (title, content) = (note.title, note.content);
            match blocking(move || Ok(embed::embed_note(&*e, title.as_deref(), &content))).await? {
                Ok((single, chunks)) => {
                    clear_failed_note(db_id, org, &note.id);
                    embedded.push(EmbeddedNote { id: note.id, expected_sha: note.sha, single, chunks });
                }
                Err(err) if matches!(err.category, "disabled" | "model_acquisition") => {
                    tracing::debug!(
                        category = err.category,
                        error = %err.message,
                        "memory backfill: embedder unavailable; stopping pass"
                    );
                    report.stopped_unavailable = true;
                    break;
                }
                Err(err) => {
                    tracing::debug!(
                        category = err.category,
                        error = %err.message,
                        note_id = %note.id,
                        "memory backfill: note embed failed"
                    );
                    record_failed_note(db_id, org, &note.id, &identity, &note.sha);
                    report.failed += 1;
                }
            }
        }

        if !embedded.is_empty() {
            let (org_w, id_w, clock) = (org.to_string(), identity.clone(), cfg.clock);
            let (written_notes, written_chunks) = db
                .write_async(move |tx| {
                    // Read inside the write, so vector timestamps follow commit order.
                    let ts = clock.now();
                    let mut notes_n = 0usize;
                    let mut chunks_n = 0usize;
                    let mut seen_ids: HashMap<String, ()> = HashMap::new();
                    for item in embedded {
                        if seen_ids.insert(item.id.clone(), ()).is_some() {
                            continue;
                        }
                        if let Some(n) = fetch(tx, &org_w, &item.id)?
                            && !n.is_deleted()
                            && n.superseded_by.is_none()
                            && text_sha(&embed_text(n.title.as_deref(), &n.content)) == item.expected_sha
                        {
                            embed::store_vector(
                                tx,
                                &org_w,
                                &item.id,
                                &id_w,
                                &item.single,
                                &item.expected_sha,
                                &ts,
                            )?;
                            chunks_n += embed::store_chunks(
                                tx,
                                &org_w,
                                &item.id,
                                &id_w,
                                &item.chunks,
                                &item.expected_sha,
                            )?;
                            notes_n += 1;
                        }
                    }
                    Ok((notes_n, chunks_n))
                })
                .await?;
            report.notes_embedded += written_notes;
            report.chunks_written += written_chunks;
        }

        if report.stopped_unavailable {
            save_cursor(db_id, org, &identity, cursor);
            break;
        }
        cursor = next_cursor;
        if exhausted {
            save_cursor(db_id, org, &identity, 0);
            break;
        }
    }

    Ok(report)
}

/// Freshness breakdown of live memory notes for an organization, computed
/// without network calls or model loading (for `system_doctor`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EmbeddingCounts {
    /// Live (non-deleted, non-superseded) notes in the organization.
    pub live_notes: i64,
    /// Live notes whose single vector and every expected chunk vector match
    /// both the active vector identity and the note's current `content_sha`.
    pub fresh_embedded: i64,
    /// Live notes that have a `memory_embeddings` row, but it is stale
    /// (imported, wrong identity, mismatched `content_sha`, or missing/stale
    /// chunks) and therefore excluded from semantic scoring.
    pub stale_embedded: i64,
}

/// Count live notes, fresh (scorable) embeddings, and stale embeddings for
/// organization `org` against the exact `active_identity` that semantic search
/// uses for that organization (`None` when no embedder is available for `org`).
/// Never loads a model or touches the network.
pub fn embedding_freshness_counts(
    conn: &rusqlite::Connection,
    org: &str,
    active_identity: Option<&str>,
) -> UaResult<EmbeddingCounts> {
    let mut counts = EmbeddingCounts::default();
    let mut stmt = conn.prepare(
        "SELECT m.id, m.title, m.content, e.model, e.content_sha \
         FROM memory m \
         LEFT JOIN memory_embeddings e ON e.note_id = m.id AND e.org_id = m.org_id \
         WHERE m.org_id = ?1 \
           AND m.superseded_by IS NULL \
           AND NOT EXISTS (SELECT 1 FROM json_each(m.tags) WHERE value = ?2)",
    )?;
    let mut chunk_stmt = conn.prepare(
        "SELECT COUNT(*), \
                COALESCE(SUM(CASE WHEN model = ?3 AND content_sha = ?4 THEN 1 ELSE 0 END), 0) \
         FROM memory_chunks \
         WHERE org_id = ?1 AND note_id = ?2",
    )?;
    let rows = stmt.query_map(params![org, DELETED_TAG], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
        ))
    })?;
    for row in rows {
        let (id, title, content, emb_model, emb_sha) = row?;
        counts.live_notes += 1;
        let Some(model) = emb_model else {
            continue;
        };
        let Some(want) = active_identity else {
            counts.stale_embedded += 1;
            continue;
        };
        let text = embed_text(title.as_deref(), &content);
        let sha = text_sha(&text);
        let single_fresh = model == want && emb_sha.as_deref() == Some(sha.as_str());
        if !single_fresh {
            counts.stale_embedded += 1;
            continue;
        }
        let expected_chunks = chunks::chunk_text(&text).len() as i64;
        let (total_chunks, fresh_chunks): (i64, i64) =
            chunk_stmt.query_row(params![org, &id, want, &sha], |r| Ok((r.get(0)?, r.get(1)?)))?;
        if total_chunks == expected_chunks && fresh_chunks == expected_chunks {
            counts.fresh_embedded += 1;
        } else {
            counts.stale_embedded += 1;
        }
    }
    Ok(counts)
}

/// Run one bounded backfill step across every active organization, resolving
/// each organization's embedder independently (honoring its own
/// `orgs.allow_remote_embedder` setting) and never touching suspended orgs.
pub async fn backfill_all_orgs_step(
    db: &Db,
    cfg: &Config,
    max_batches_per_org: usize,
) -> UaResult<Vec<(String, BackfillReport)>> {
    let orgs: Vec<String> = db
        .read_async(|c| {
            let mut stmt =
                c.prepare("SELECT id FROM orgs WHERE status = 'active' ORDER BY id = ?1 DESC, id")?;
            let rows = stmt.query_map([ua_core::DEFAULT_ORG], |r| r.get::<_, String>(0))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await?;
    let mut reports = Vec::with_capacity(orgs.len());
    for org in orgs {
        let rep = backfill_embeddings_capped(db, cfg, &org, Some(max_batches_per_org)).await?;
        reports.push((org, rep));
    }
    Ok(reports)
}

/// Organization `org`'s stale (old, never recalled, salience <= 0.5) and
/// low-confidence notes, plus a best-effort embedding backfill pass in batches
/// of [`BACKFILL_BATCH`] (8) notes. Refuses `dry_run = false`: it never
/// deletes or modifies any note. `cfg.clock` dates the staleness cutoff.
pub async fn recall_maintenance(db: &Db, cfg: &Config, org: &str, a: MaintenanceRequest) -> UaResult<Value> {
    if !a.dry_run {
        return Err(UaError::invalid(
            "recall_maintenance never deletes; it is a report. Review the candidates, then remove specific \
             notes with memory_delete(id=...).",
        ));
    }
    let stale_days = a.stale_days.unwrap_or(120.0);
    let floor = a.confidence_floor.unwrap_or(0.35);
    if !stale_days.is_finite() || !floor.is_finite() {
        return Err(UaError::invalid("stale_days and confidence_floor must be finite numbers"));
    }
    let limit = a.limit.unwrap_or(100).max(0) as usize;
    let cutoff = days_ago(&cfg.clock, stale_days);
    let org_owned = org.to_string();
    let mut out = db
        .read_async(move |c| {
            let mut notes = live_notes(c, &org_owned, "AND m.superseded_by IS NULL")?;
            notes.reverse(); // oldest first
            let (mut stale, mut low) = (Vec::new(), Vec::new());
            for n in &notes {
                if n.updated_at < cutoff && n.recalled_count == 0 && n.salience <= 0.5 {
                    stale.push(candidate(n, "stale_unrecalled"));
                }
                if n.confidence.is_some_and(|x| x < floor) {
                    low.push(candidate(n, "low_confidence"));
                }
            }
            Ok(json!({
                "dry_run": true,
                "deletes_nothing": true,
                "stale_days": stale_days,
                "confidence_floor": floor,
                "stale_count": stale.len(),
                "low_confidence_count": low.len(),
                "stale": stale.into_iter().take(limit).collect::<Vec<_>>(),
                "low_confidence": low.into_iter().take(limit).collect::<Vec<_>>(),
                "next_step": "review, then memory_delete(id=...) per note you want gone",
            }))
        })
        .await?;
    let backfill = match backfill_embeddings(db, cfg, org).await {
        Ok(rep) => rep.to_json(),
        Err(e) => {
            tracing::warn!(error = %e, "recall_maintenance: embedding backfill failed");
            json!({ "error": e.to_string() })
        }
    };
    out["embeddings"] = backfill;
    Ok(out)
}

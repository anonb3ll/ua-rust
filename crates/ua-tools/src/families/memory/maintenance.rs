//! `memory_prune_candidates` and `recall_maintenance`. Both only report;
//! neither deletes or rewrites a note.

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};

use super::note::{DELETED_TAG, NOTE_COLS, Note, days_ago};
use crate::registry::{Registry, ToolCtx, tool};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PruneArgs {
    /// Notes below this salience are candidates. Default 0.3.
    pub salience_threshold: Option<f64>,
    /// Notes not updated for this many days, never accessed and with salience
    /// at most 0.5 are candidates. Default 30.
    pub max_age_days: Option<f64>,
    /// Most candidates returned. Default 50.
    pub limit: Option<i64>,
}

fn live_notes(conn: &rusqlite::Connection, extra: &str) -> UaResult<Vec<Note>> {
    let sql = format!(
        "SELECT {NOTE_COLS} FROM memory m \
         WHERE NOT EXISTS (SELECT 1 FROM json_each(m.tags) WHERE value = ?1) {extra} \
         ORDER BY m.updated_at DESC, m.seq DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([DELETED_TAG], Note::from_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

async fn prune_candidates(ctx: ToolCtx, a: PruneArgs) -> UaResult<Value> {
    let threshold = a.salience_threshold.unwrap_or(0.3);
    let max_age = a.max_age_days.unwrap_or(30.0);
    if !threshold.is_finite() || !max_age.is_finite() {
        return Err(UaError::invalid("salience_threshold and max_age_days must be finite numbers"));
    }
    let limit = a.limit.unwrap_or(50).max(0) as usize;
    let cutoff = days_ago(max_age);
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut candidates: Vec<(usize, f64, Value)> = Vec::new();
            for n in live_notes(c, "")? {
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
            candidates.sort_by(|x, y| {
                y.0.cmp(&x.0).then(x.1.partial_cmp(&y.1).unwrap_or(std::cmp::Ordering::Equal))
            });
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

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceArgs {
    /// Must stay true: this pass only reports.
    #[serde(default = "default_true")]
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

async fn recall_maintenance(ctx: ToolCtx, a: MaintenanceArgs) -> UaResult<Value> {
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
    let cutoff = days_ago(stale_days);
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut notes = live_notes(c, "AND m.superseded_by IS NULL")?;
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
        .await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "memory_prune_candidates",
            "List memory notes that look superseded, low-salience, or old and never accessed, most reasons first. \
             Soft-deleted notes are left out. Deletes nothing.",
            prune_candidates,
        )
        .family("memory")
        .read_only(),
    );
    r.add(
        tool(
            "recall_maintenance",
            "Report stale (old, never recalled, salience <= 0.5) and low-confidence memory notes for human review. \
             Deletes nothing: dry_run=false is refused; prune with memory_delete per id after review.",
            recall_maintenance,
        )
        .family("memory")
        .read_only(),
    );
}

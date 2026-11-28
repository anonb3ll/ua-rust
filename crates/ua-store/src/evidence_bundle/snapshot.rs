//! Checkpoint-time export snapshot (`docs/evidence-export.md`, Determinism).
//!
//! A bundle's `withheld.json` counts and an `org` bundle's dense ordinals come
//! from live tables that later deletes change (an expired-session purge, a
//! deleted task). So the exporter reads them from a snapshot frozen once per
//! checkpoint: re-exporting a checkpoint after deletes stays byte-identical.
//!
//! The snapshot records, for rows at or before the checkpoint's cutoff:
//! - the timestamps of rows in each withheld table (scoped to the
//!   organization for an `org` checkpoint), so any export window can be
//!   counted from it;
//! - the `message_index` rows (ulid, seq, timestamp);
//! - for an `org` checkpoint, the organization's task, approval and
//!   deliverable ids in ascending order, whose positions are the ordinals.
//!
//! `snapshot_checkpoint` writes it (append-only); `export_bundle` uses it when
//! present and otherwise captures the same data live.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use ua_core::{DEFAULT_ORG, UaError, UaResult};

use crate::SchemaPart;
use crate::evidence::{Checkpoint, CheckpointClass, checkpoint_get};
use crate::ledger::GENESIS_HASH;

use super::canonical::to_canonical_bytes;
use super::egress::{
    CLASS_APPROVALS_IN_DEFAULT_LEDGER, CLASS_AUTH_TOKENS, CLASS_MANAGED_SECRETS, CLASS_PASSKEYS,
    CLASS_PRIVATE_MESSAGES, CLASS_PROVIDER_CREDENTIALS, CLASS_SESSION_CREDENTIALS,
};
use super::{cmp_ts, normalize_ts_utc};

/// The snapshot table. Append-only: one row per checkpoint, never updated or
/// deleted, so a re-export reads the same snapshot forever. Keyed by
/// `checkpoint_id` without a foreign key, so the snapshot never stands in the
/// way of the checkpoint table's own rules.
pub const EXPORT_SNAPSHOT_PART: SchemaPart = SchemaPart {
    name: "evidence_bundle_snapshot.v1",
    sql: "
CREATE TABLE IF NOT EXISTS evidence_export_snapshot (
    checkpoint_id TEXT PRIMARY KEY,
    snapshot TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS evidence_export_snapshot_no_update BEFORE UPDATE ON evidence_export_snapshot
BEGIN SELECT RAISE(ABORT, 'evidence export snapshots are append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_export_snapshot_no_delete BEFORE DELETE ON evidence_export_snapshot
BEGIN SELECT RAISE(ABORT, 'evidence export snapshots are append-only'); END;
",
};

/// Snapshot format tag.
pub const SNAPSHOT_FORMAT: &str = "ua.evidence.export_snapshot.v1";

/// One `message_index` row as the snapshot keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotMessageRow {
    pub ulid: Option<String>,
    pub seq: Option<i64>,
    pub created_at: Option<String>,
}

/// The frozen export inputs for one checkpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportSnapshot {
    pub format: String,
    pub cutoff_ts: String,
    /// Withheld class -> normalized timestamps of its rows at or before
    /// `cutoff_ts`, ascending.
    pub withheld_rows: BTreeMap<String, Vec<String>>,
    pub message_rows: Vec<SnapshotMessageRow>,
    /// `org` checkpoints: the organization's ids, ascending. An id's ordinal
    /// is its 1-based position.
    pub task_ids: Vec<i64>,
    pub approval_ids: Vec<i64>,
    pub deliverable_ids: Vec<i64>,
}

fn ordinal_of(ids: &[i64], raw: i64) -> Option<i64> {
    ids.binary_search(&raw).ok().map(|i| i as i64 + 1)
}

impl ExportSnapshot {
    pub fn task_ordinal(&self, raw: i64) -> Option<i64> {
        ordinal_of(&self.task_ids, raw)
    }
    pub fn approval_ordinal(&self, raw: i64) -> Option<i64> {
        ordinal_of(&self.approval_ids, raw)
    }
    pub fn deliverable_ordinal(&self, raw: i64) -> Option<i64> {
        ordinal_of(&self.deliverable_ids, raw)
    }

    /// Withheld counts strictly inside `(start_excl_ts, cutoff_ts]` (and
    /// `(start_seq_excl, end_seq]` for `message_index` rows that carry a seq),
    /// skipping message rows whose ledger events this bundle already counts
    /// as redacted stubs.
    pub fn withheld_in_window(
        &self,
        start_excl_ts: Option<&str>,
        cutoff_ts: &str,
        seq_bounds: Option<(i64, i64)>,
        already_redacted_ulids: &BTreeSet<String>,
    ) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        for (class, stamps) in &self.withheld_rows {
            let n = stamps.iter().filter(|ts| in_time_window(ts, start_excl_ts, cutoff_ts)).count() as u64;
            out.push((class.clone(), n));
        }
        let mut msgs = 0u64;
        for row in &self.message_rows {
            if row.ulid.as_deref().is_some_and(|u| already_redacted_ulids.contains(u)) {
                continue;
            }
            let in_window = if let (Some((min_excl, max_incl)), Some(s)) = (seq_bounds, row.seq) {
                s > min_excl && s <= max_incl
            } else if let Some(ts) = row.created_at.as_deref() {
                in_time_window(ts, start_excl_ts, cutoff_ts)
            } else {
                false
            };
            if in_window {
                msgs += 1;
            }
        }
        out.push((CLASS_PRIVATE_MESSAGES.to_string(), msgs));
        out
    }
}

pub(crate) fn in_time_window(ts: &str, start_excl_ts: Option<&str>, cutoff_ts: &str) -> bool {
    if cmp_ts(ts, cutoff_ts) == Ordering::Greater {
        return false;
    }
    if let Some(start) = start_excl_ts
        && cmp_ts(ts, start) != Ordering::Greater
    {
        return false;
    }
    true
}

pub(crate) fn table_exists(conn: &Connection, table: &str) -> UaResult<bool> {
    Ok(conn
        .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [table], |_| Ok(true))
        .optional()?
        .unwrap_or(false))
}

pub(crate) fn column_exists(conn: &Connection, table: &str, col: &str) -> UaResult<bool> {
    Ok(conn
        .query_row(&format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"), [col], |_| {
            Ok(true)
        })
        .optional()?
        .unwrap_or(false))
}

/// The cutoff timestamp a checkpoint's export window closes at: the
/// timestamp of the hub checkpoint's row, or of an `org` checkpoint's
/// `global_head_hash` row (its window end when the head is genesis).
pub fn checkpoint_cutoff_ts(conn: &Connection, cp: &Checkpoint) -> UaResult<String> {
    match cp.class {
        CheckpointClass::Hub => {
            let seq = cp.seq.ok_or_else(|| UaError::invalid("hub checkpoint has no seq"))?;
            let ts: Option<String> = conn
                .query_row("SELECT created_at FROM event_log WHERE seq = ?1", [seq], |r| r.get(0))
                .optional()?;
            Ok(normalize_ts_utc(&ts.unwrap_or_else(|| cp.signed_at.clone())))
        }
        CheckpointClass::Org => {
            let head = cp
                .global_head_hash
                .as_deref()
                .ok_or_else(|| UaError::invalid("org checkpoint has no head"))?;
            let window_end =
                cp.window.as_ref().map(|w| normalize_ts_utc(&w.end)).unwrap_or_else(|| cp.signed_at.clone());
            if head == GENESIS_HASH {
                return Ok(window_end);
            }
            let ts: Option<String> = conn
                .query_row(
                    "SELECT created_at FROM event_log WHERE entry_hash = ?1 COLLATE NOCASE",
                    [head],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(ts.map(|t| normalize_ts_utc(&t)).unwrap_or(window_end))
        }
    }
}

/// Withheld tables: `(table, class, timestamp columns in preference order)`.
const WITHHELD_TABLES: &[(&str, &str, &[&str])] = &[
    ("managed_secrets", CLASS_MANAGED_SECRETS, &["created_at"]),
    ("provider_accounts", CLASS_PROVIDER_CREDENTIALS, &["created_at"]),
    ("agent_tokens", CLASS_AUTH_TOKENS, &["issued_at", "created_at"]),
    ("oauth_tokens", CLASS_AUTH_TOKENS, &["issued_at", "created_at"]),
    ("oauth_codes", CLASS_AUTH_TOKENS, &["created_at"]),
    ("oauth_grants", CLASS_AUTH_TOKENS, &["created_at"]),
    ("ui_sessions", CLASS_AUTH_TOKENS, &["created_at"]),
    ("passkeys", CLASS_PASSKEYS, &["created_at"]),
    ("session_credentials", CLASS_SESSION_CREDENTIALS, &["issued_at", "created_at"]),
    ("session_handoff_notes", CLASS_PRIVATE_MESSAGES, &["created_at"]),
];

fn table_timestamps(
    conn: &Connection,
    table: &str,
    org_id: Option<&str>,
    ts_cols: &[&str],
    cutoff_ts: &str,
) -> UaResult<Vec<String>> {
    if !table_exists(conn, table)? {
        return Ok(Vec::new());
    }
    let has_org = column_exists(conn, table, "org_id")?;
    if org_id.is_some() && !has_org {
        // A hub-global table is never counted in an `org` bundle: its counts
        // would reveal hub-wide volume.
        return Ok(Vec::new());
    }
    let mut ts_col = None;
    for &c in ts_cols {
        if column_exists(conn, table, c)? {
            ts_col = Some(c);
            break;
        }
    }
    let Some(ts_col) = ts_col else { return Ok(Vec::new()) };
    let stamps: Vec<Option<String>> = match org_id {
        Some(org) => {
            let mut stmt =
                conn.prepare(&format!("SELECT \"{ts_col}\" FROM \"{table}\" WHERE org_id = ?1"))?;
            stmt.query_map([org], |r| r.get(0))?.collect::<Result<_, _>>()?
        }
        None => {
            let mut stmt = conn.prepare(&format!("SELECT \"{ts_col}\" FROM \"{table}\""))?;
            stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?
        }
    };
    Ok(stamps
        .into_iter()
        .flatten()
        .filter(|ts| cmp_ts(ts, cutoff_ts) != Ordering::Greater)
        .map(|ts| normalize_ts_utc(&ts))
        .collect())
}

fn message_rows(
    conn: &Connection,
    org_id: Option<&str>,
    cutoff_ts: &str,
) -> UaResult<Vec<SnapshotMessageRow>> {
    if !table_exists(conn, "message_index")? {
        return Ok(Vec::new());
    }
    let has_org = column_exists(conn, "message_index", "org_id")?;
    if org_id.is_some() && !has_org {
        return Ok(Vec::new());
    }
    let has_ulid = column_exists(conn, "message_index", "event_ulid")?;
    let has_seq = column_exists(conn, "message_index", "event_seq")?;
    let has_created = column_exists(conn, "message_index", "created_at")?;
    if !has_seq && !has_created {
        return Ok(Vec::new());
    }
    let ulid_expr = if has_ulid { "event_ulid" } else { "NULL" };
    let seq_expr = if has_seq { "event_seq" } else { "NULL" };
    let ts_expr = if has_created { "created_at" } else { "NULL" };
    let map = |r: &rusqlite::Row<'_>| -> rusqlite::Result<SnapshotMessageRow> {
        Ok(SnapshotMessageRow { ulid: r.get(0)?, seq: r.get(1)?, created_at: r.get(2)? })
    };
    let rows: Vec<SnapshotMessageRow> = match org_id {
        Some(org) => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {ulid_expr}, {seq_expr}, {ts_expr} FROM message_index WHERE org_id = ?1"
            ))?;
            stmt.query_map([org], map)?.collect::<Result<_, _>>()?
        }
        None => {
            let mut stmt =
                conn.prepare(&format!("SELECT {ulid_expr}, {seq_expr}, {ts_expr} FROM message_index"))?;
            stmt.query_map([], map)?.collect::<Result<_, _>>()?
        }
    };
    let mut out: Vec<SnapshotMessageRow> = rows
        .into_iter()
        .filter(|r| r.created_at.as_deref().is_none_or(|ts| cmp_ts(ts, cutoff_ts) != Ordering::Greater))
        .map(|r| SnapshotMessageRow { created_at: r.created_at.as_deref().map(normalize_ts_utc), ..r })
        .collect();
    out.sort_by(|a, b| a.seq.cmp(&b.seq).then(a.ulid.cmp(&b.ulid)));
    Ok(out)
}

fn org_ids(conn: &Connection, table: &str, org: &str) -> UaResult<Vec<i64>> {
    if !table_exists(conn, table)? || !column_exists(conn, table, "org_id")? {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(&format!("SELECT id FROM \"{table}\" WHERE org_id = ?1 ORDER BY id ASC"))?;
    let ids: Vec<i64> = stmt.query_map([org], |r| r.get(0))?.collect::<Result<_, _>>()?;
    Ok(ids)
}

fn resolved_approval_stamps(conn: &Connection, org: &str, cutoff_ts: &str) -> UaResult<Vec<String>> {
    if !table_exists(conn, "approvals")?
        || !column_exists(conn, "approvals", "org_id")?
        || !column_exists(conn, "approvals", "resolved_at")?
    {
        return Ok(Vec::new());
    }
    let mut stmt =
        conn.prepare("SELECT resolved_at FROM approvals WHERE org_id = ?1 AND resolved_at IS NOT NULL")?;
    let stamps: Vec<String> = stmt.query_map([org], |r| r.get(0))?.collect::<Result<_, _>>()?;
    Ok(stamps
        .into_iter()
        .filter(|ts| cmp_ts(ts, cutoff_ts) != Ordering::Greater)
        .map(|ts| normalize_ts_utc(&ts))
        .collect())
}

/// Capture a checkpoint's export inputs from the live tables.
pub fn snapshot_capture(conn: &Connection, cp: &Checkpoint) -> UaResult<ExportSnapshot> {
    let cutoff_ts = checkpoint_cutoff_ts(conn, cp)?;
    let org = match cp.class {
        CheckpointClass::Org => cp.org_id.as_deref(),
        CheckpointClass::Hub => None,
    };
    let mut withheld_rows: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for &(table, class, ts_cols) in WITHHELD_TABLES {
        let stamps = table_timestamps(conn, table, org, ts_cols, &cutoff_ts)?;
        if !stamps.is_empty() {
            withheld_rows.entry(class.to_string()).or_default().extend(stamps);
        }
    }
    let (task_ids, approval_ids, deliverable_ids) = match org {
        Some(o) => {
            if o != DEFAULT_ORG {
                let stamps = resolved_approval_stamps(conn, o, &cutoff_ts)?;
                if !stamps.is_empty() {
                    withheld_rows.insert(CLASS_APPROVALS_IN_DEFAULT_LEDGER.to_string(), stamps);
                }
            }
            (org_ids(conn, "tasks", o)?, org_ids(conn, "approvals", o)?, org_ids(conn, "deliverables", o)?)
        }
        None => (Vec::new(), Vec::new(), Vec::new()),
    };
    for stamps in withheld_rows.values_mut() {
        stamps.sort_by(|a, b| cmp_ts(a, b).then(a.cmp(b)));
    }
    Ok(ExportSnapshot {
        format: SNAPSHOT_FORMAT.to_string(),
        message_rows: message_rows(conn, org, &cutoff_ts)?,
        cutoff_ts,
        withheld_rows,
        task_ids,
        approval_ids,
        deliverable_ids,
    })
}

/// The stored snapshot for `checkpoint_id`, if the table and row exist.
pub fn snapshot_load(conn: &Connection, checkpoint_id: &str) -> UaResult<Option<ExportSnapshot>> {
    if !table_exists(conn, "evidence_export_snapshot")? {
        return Ok(None);
    }
    let raw: Option<String> = conn
        .query_row(
            "SELECT snapshot FROM evidence_export_snapshot WHERE checkpoint_id = ?1",
            [checkpoint_id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(raw) = raw else { return Ok(None) };
    let snap: ExportSnapshot = serde_json::from_str(&raw).map_err(|e| {
        UaError::internal(format!("evidence export snapshot {checkpoint_id:?} is unreadable: {e}"))
    })?;
    if snap.format != SNAPSHOT_FORMAT {
        return Err(UaError::internal(format!(
            "evidence export snapshot {checkpoint_id:?} has unknown format {:?}",
            snap.format
        )));
    }
    Ok(Some(snap))
}

/// Freeze the export snapshot for `checkpoint_id` if none exists yet.
/// Returns `true` when this call wrote it. Called when the checkpoint is
/// written (`ua evidence checkpoint`) and, for a checkpoint written before
/// snapshots existed, on its first export.
pub fn snapshot_checkpoint(conn: &Connection, checkpoint_id: &str, now: &str) -> UaResult<bool> {
    if !table_exists(conn, "evidence_export_snapshot")? {
        return Err(UaError::internal("evidence_export_snapshot table is missing from this database"));
    }
    if snapshot_load(conn, checkpoint_id)?.is_some() {
        return Ok(false);
    }
    let cp = checkpoint_get(conn, checkpoint_id)?
        .ok_or_else(|| UaError::not_found(format!("no checkpoint {checkpoint_id:?}")))?;
    let snap = snapshot_capture(conn, &cp)?;
    conn.execute(
        "INSERT INTO evidence_export_snapshot (checkpoint_id, snapshot, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![
            checkpoint_id,
            String::from_utf8(to_canonical_bytes(&snap)?)
                .map_err(|e| UaError::internal(format!("encoding snapshot: {e}")))?,
            now
        ],
    )?;
    Ok(true)
}

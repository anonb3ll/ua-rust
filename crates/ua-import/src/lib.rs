//! Import a database from the original Python hub into a ua-rust database.
//!
//! The source is opened read-only (`SQLITE_OPEN_READ_ONLY`, `query_only`) and
//! read inside one read transaction, so the import sees one consistent
//! snapshot. Import a stopped hub or a backup copy: rows changed in the source
//! after they were copied are not copied again.
//!
//! What is copied (see [`map::MAPS`]): tasks with dependencies, comments,
//! goals, workflow records and checks, session handoff notes, plans,
//! delegations, work proposals and items, task holds and members, project repo
//! bindings, memory notes and their versions (ids kept, the full-text index
//! rebuilt), the message index, agents, agent token hashes, approval history,
//! remote nodes, skill versions and assignments, harness config bundles, and
//! the event ledger.
//!
//! Parking: the Python hub parked a task by archiving it and appending a
//! `[parked @ <ts> by <actor>] <reason>` (or `[folded-into: #<root> ...]`)
//! line to its notes. ua-rust keeps parking in its own columns, so an
//! unfinished archived task whose last closure line is a park or a fold is
//! moved to `parked_at`, `parked_by`, `parked_reason` and `folded_into`, and
//! un-archived. Notes are kept as they were.
//!
//! The ledger is copied byte-exactly, keeping `seq` (the Python `ROWID`),
//! ULIDs, `prev_hash` and `entry_hash`. The whole source chain is verified
//! before anything is written; a row that does not verify, or cannot be stored
//! byte-exactly (a non-text value in a hashed column), stops the import with an
//! error instead of rewriting history. The target chain is verified after;
//! because batches commit as they go, take a target snapshot first when
//! importing into a non-empty database (a failed post-import verification leaves
//! imported rows in place without rollback).
//!
//! Runs are idempotent and resumable: `import_runs` records, per source (a
//! SHA-256 of its canonical path) and table, the rows copied and skipped and
//! the last source `rowid` copied. Each batch and its progress row commit
//! together, so a re-run continues after the last committed batch.

mod map;

/// The database locks, which live in `ua_store::lock` (opening the database
/// needs the serve lock); re-exported so the names here keep working.
pub use ua_store::lock::{
    HubLock, ServeLock, canonical_db_path, lock_path, refuse_if_served, serve_lock_path,
};

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params, params_from_iter};
use serde::Serialize;
use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};
use ua_store::ledger::{self, GENESIS_HASH, VerifyReport};
use ua_store::{Db, Part, SchemaPart};
use ua_tools::families::governance::{check_default_branch, normalize_repo};
use ua_tools::families::tasks::check_slug;

use map::{Kind, LEDGER_COLUMNS, MAPS, Ref, TableMap};

/// Import progress, per source and table.
pub const SCHEMA: SchemaPart = ua_store::schema::IMPORT_SCHEMA;

/// Every ua-rust schema part plus the import bookkeeping table.
pub fn schema_parts() -> Vec<Part> {
    let mut parts = ua_tools::schema_parts();
    parts.push(SCHEMA.into());
    parts
}

/// Tuning for a run.
#[derive(Debug, Clone)]
pub struct Options {
    /// Rows per write transaction.
    pub batch_size: usize,
    /// Import even though some source rows carry an `org_id`. ua-rust has no
    /// tenant scope, so those rows lose their boundary. Without this flag a
    /// real import refuses.
    pub drop_org_scope: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { batch_size: 500, drop_org_scope: false }
    }
}

/// Outcome for one mapped table.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TableReport {
    pub table: String,
    /// The table exists in the source.
    pub present: bool,
    pub source_rows: u64,
    /// Rows copied by this run (in a dry run: rows a fresh import would copy,
    /// before reference checks).
    pub copied: u64,
    /// Rows skipped by this run, by reason.
    pub skipped: BTreeMap<String, u64>,
    /// Source rows at or below the resume key when this run started.
    pub already_imported: u64,
    /// Totals over every run for this source.
    pub total_copied: u64,
    pub total_skipped: u64,
    /// Last source `rowid` copied.
    pub last_key: i64,
    /// References to rows that exist nowhere, stored as NULL.
    pub dangling_refs_nulled: u64,
}

/// Verification of the source ledger, done before any write.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SourceLedgerReport {
    pub ok: bool,
    pub rows: u64,
    pub checked: u64,
    pub unhashed: u64,
    pub first_bad_seq: Option<i64>,
    pub reason: Option<String>,
}

/// Maximum task IDs listed in [`Report::task_runs_cleared_ids`].
pub const MAX_REPORTED_TASK_RUN_IDS: usize = 50;

/// What a run did, or (dry run) would do.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// SHA-256 of the source's canonical path; keys `import_runs`.
    pub source_hash: String,
    pub dry_run: bool,
    pub tables: Vec<TableReport>,
    /// Source tables with no ua-rust counterpart. Not copied.
    pub unmapped_tables: Vec<String>,
    /// Virtual tables (search and vector indexes) and their shadow tables.
    /// Not copied: ua-rust rebuilds full-text indexes from the imported rows.
    pub derived_tables: Vec<String>,
    /// Source columns of mapped tables that ua-rust does not store, with the
    /// number of non-NULL values in each.
    pub unmapped_columns: BTreeMap<String, BTreeMap<String, u64>>,
    pub source_ledger: SourceLedgerReport,
    /// Rows per table whose source `org_id` is non-NULL. ua-rust has no tenant
    /// scope: a real import refuses unless `drop_org_scope` is set.
    pub org_scoped_rows: BTreeMap<String, u64>,
    /// Tasks whose `current_run_id` or `current_run_agent` was cleared
    /// because `dispatch_runs` are not imported.
    pub task_runs_cleared: u64,
    /// Sample of task IDs (capped at [`MAX_REPORTED_TASK_RUN_IDS`]) whose run
    /// pointers were cleared.
    pub task_runs_cleared_ids: Vec<i64>,
    /// `project_repo_bindings` rows whose invalid `default_branch` was
    /// cleared to `NULL` rather than dropping the binding.
    pub binding_branches_cleared: u64,
    /// Verification of the target chain after the import (not in a dry run).
    pub target_ledger: Option<VerifyReport>,
    pub notes: Vec<String>,
}

/// Open the Python database strictly read-only.
pub fn open_source(path: &Path) -> anyhow::Result<Connection> {
    if !path.is_file() {
        bail!("source database {} does not exist or is not a file", path.display());
    }
    let conn =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .with_context(|| format!("opening {} read-only", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    conn.execute_batch("PRAGMA query_only = ON;")?;
    Ok(conn)
}

/// SHA-256 (hex) of the canonical source path.
pub fn source_hash(path: &Path) -> anyhow::Result<String> {
    let canon = std::fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(canon.to_string_lossy().as_bytes())))
}

/// Report counts, unmapped tables and columns, source-only conflict checks
/// and the source chain's verification without writing anything anywhere.
pub fn dry_run(source: &Path) -> anyhow::Result<Report> {
    let src = open_source(source)?;
    src.execute_batch("BEGIN")?;
    // An empty in-memory ua-rust database describes the target columns.
    let shape = Db::open_in_memory(&schema_parts())?;
    let mut report = survey(&src, &shape, source_hash(source)?, true)?;
    for map in MAPS {
        if !report.tables.iter().any(|t| t.table == map.source && t.present) {
            continue;
        }
        match map.kind {
            Kind::TaskHolds => check_source_active_holds(&src, 0)?,
            Kind::ProjectRepoBindings => check_source_bindings_overlap(&src, &shape, map, 0)?,
            _ => {}
        }
    }
    for map in MAPS {
        if map.kind == Kind::Ledger {
            continue;
        }
        let Some(rep) = report.tables.iter_mut().find(|t| t.table == map.source) else { continue };
        if !rep.present {
            continue;
        }
        let plan = plan_table(&src, &shape, map)?;
        let sql = format!("SELECT {} FROM {}", select_list(&plan.cols), q(map.source));
        let mut stmt = src.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let vals = row_values(r, 0, plan.cols.len())?;
            if let Some(reason) = filter(map.kind, &plan.cols, &vals) {
                *rep.skipped.entry(reason.into()).or_default() += 1;
                continue;
            }
            rep.copied += 1;
            match map.kind {
                Kind::Tasks => {
                    let has_run = col_value(&plan.cols, &vals, "current_run_id")
                        .is_some_and(|v| *v != SqlValue::Null)
                        || col_value(&plan.cols, &vals, "current_run_agent")
                            .is_some_and(|v| *v != SqlValue::Null);
                    if has_run {
                        record_cleared_task_run(
                            &mut report.task_runs_cleared,
                            &mut report.task_runs_cleared_ids,
                            col_value(&plan.cols, &vals, "id"),
                        );
                    }
                }
                Kind::ProjectRepoBindings => {
                    if let Some(v) = col_value(&plan.cols, &vals, "default_branch")
                        && matches!(normalize_binding_branch(v), BranchNorm::ClearedInvalid)
                    {
                        report.binding_branches_cleared += 1;
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(rep) = report.tables.iter_mut().find(|t| t.table == "event_log") {
        rep.copied = if report.source_ledger.ok { rep.source_rows } else { 0 };
    }
    append_clear_notes(&mut report);
    report.notes.push("dry run: nothing was written; missing references are counted on a real run".into());
    src.execute_batch("COMMIT")?;
    Ok(report)
}

/// Import `source` into `db`, which must carry [`schema_parts`].
pub fn import(db: &Db, source: &Path, opts: &Options) -> anyhow::Result<Report> {
    let batch = opts.batch_size.max(1);
    let src = open_source(source)?;
    src.execute_batch("BEGIN")?;
    let hash = source_hash(source)?;
    let mut report = survey(&src, db, hash.clone(), false)?;
    if !report.source_ledger.ok {
        let l = &report.source_ledger;
        bail!(
            "source ledger does not verify at seq {}: {}; refusing to import (nothing was written)",
            l.first_bad_seq.map(|s| s.to_string()).unwrap_or_else(|| "?".into()),
            l.reason.as_deref().unwrap_or("unknown")
        );
    }
    check_target(&src, db, &report, opts)?;
    if !report.org_scoped_rows.is_empty() {
        report.notes.push("org_id dropped (--drop-org-scope): tenant boundaries are not kept".into());
    }
    let mut copied_any = false;
    let mut cleared_runs = 0u64;
    let mut cleared_run_ids = Vec::new();
    let mut cleared_branches = 0u64;
    let src_has_sqlite_sequence = has_sqlite_sequence(&src)?;
    for map in MAPS {
        let idx = report
            .tables
            .iter()
            .position(|t| t.table == map.source)
            .ok_or_else(|| anyhow!("no report row"))?;
        if !report.tables[idx].present {
            continue;
        }
        let rep = &mut report.tables[idx];
        if map.kind == Kind::Ledger {
            copy_ledger(&src, db, &hash, batch, rep)?;
        } else {
            let plan = plan_table(&src, db, map)?;
            let eff = copy_table(&src, db, &hash, &plan, batch, rep)?;
            cleared_runs += eff.task_runs_cleared;
            for id in eff.task_runs_cleared_ids {
                if cleared_run_ids.len() < MAX_REPORTED_TASK_RUN_IDS {
                    cleared_run_ids.push(id);
                }
            }
            cleared_branches += eff.binding_branches_cleared;
            if let Some(sr) = map.self_ref {
                fix_self_ref(&src, db, map, sr)?;
            }
            if src_has_sqlite_sequence {
                carry_sqlite_sequence(&src, db, map)?;
            }
        }
        copied_any |= rep.copied > 0;
    }
    src.execute_batch("COMMIT")?;

    report.task_runs_cleared = cleared_runs;
    report.task_runs_cleared_ids = cleared_run_ids;
    report.binding_branches_cleared = cleared_branches;
    append_clear_notes(&mut report);

    let parked = translate_parked(db)?;
    if parked > 0 {
        report
            .notes
            .push(format!("{parked} parked task(s) moved from archived_at and notes to the parking columns"));
    }

    if copied_any {
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO memory_fts(memory_fts) VALUES ('rebuild');
                 INSERT INTO task_fts(task_fts) VALUES ('rebuild');",
            )?;
            Ok(())
        })?;
        report.notes.push("full-text indexes rebuilt".into());
    }
    let verified = db.read(ledger::verify)?;
    if !verified.ok {
        bail!(
            "target ledger does not verify after import at seq {:?}: {}",
            verified.first_bad_seq,
            verified.reason.as_deref().unwrap_or("unknown")
        );
    }
    report.target_ledger = Some(verified);
    Ok(report)
}

// ---------------------------------------------------------------------------
// Parking.

/// The last park, fold or unpark line in Python-hub task notes:
/// `(kind, root, at, by, reason)` with kind `parked`, `folded` or `unparked`.
fn closure_line(notes: &str) -> Option<(&'static str, Option<i64>, String, String, String)> {
    let mut last = None;
    for line in notes.lines() {
        let Some(rest) = line.strip_prefix('[') else { continue };
        let Some(close) = rest.find(']') else { continue };
        let (head, reason) = (&rest[..close], rest[close + 1..].trim());
        let Some((kind_part, tail)) = head.split_once(" @ ") else { continue };
        let Some((at, by)) = tail.split_once(" by ") else { continue };
        if at.is_empty() || at.contains(char::is_whitespace) {
            continue;
        }
        let (kind, root) = match kind_part {
            "parked" => ("parked", None),
            "unparked" => ("unparked", None),
            k => match k.strip_prefix("folded-into: #").and_then(|n| n.parse::<i64>().ok()) {
                Some(root) => ("folded", Some(root)),
                None => continue,
            },
        };
        last = Some((kind, root, at.to_string(), by.trim().to_string(), reason.to_string()));
    }
    last
}

/// Move Python-style parked rows to the parking columns. Idempotent: a row
/// already parked, finished or not archived is left alone. Imported tasks
/// are all the default organization's, so only its rows are read.
fn translate_parked(db: &Db) -> anyhow::Result<usize> {
    db.write(|tx| {
        let rows: Vec<(i64, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, notes FROM tasks WHERE org_id = ?1 AND archived_at IS NOT NULL AND parked_at IS NULL \
                 AND status NOT IN ('done','cancelled') AND notes IS NOT NULL",
            )?;
            stmt.query_map([ua_core::DEFAULT_ORG], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?
        };
        let mut moved = 0;
        for (id, notes) in rows {
            let Some((kind, root, at, by, reason)) = closure_line(&notes) else { continue };
            if kind == "unparked" {
                continue;
            }
            let root = root.filter(|r| {
                tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM tasks WHERE org_id = ?2 AND id = ?1)",
                    params![r, ua_core::DEFAULT_ORG],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap_or(false)
            });
            moved += tx.execute(
                "UPDATE tasks SET parked_at = ?1, parked_by = ?2, parked_reason = ?3, folded_into = ?4, \
                 archived_at = NULL WHERE id = ?5 AND org_id = ?6",
                params![at, by, reason, root, id, ua_core::DEFAULT_ORG],
            )?;
        }
        Ok(moved)
    })
    .context("moving parked tasks to the parking columns")
}

// ---------------------------------------------------------------------------
// Inventory.

fn q(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

fn select_list(cols: &[String]) -> String {
    cols.iter().map(|c| q(c)).collect::<Vec<_>>().join(", ")
}

fn columns(conn: &Connection, table: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")?;
    let rows = stmt.query_map([table], |r| r.get::<_, String>(0))?;
    rows.collect()
}

fn count(conn: &Connection, sql: &str, p: impl rusqlite::Params) -> rusqlite::Result<u64> {
    conn.query_row(sql, p, |r| r.get::<_, i64>(0)).map(|n| n.max(0) as u64)
}

/// Tables, unmapped columns, row counts, resume state and the source chain.
fn survey(src: &Connection, target: &Db, source_hash: String, dry_run: bool) -> anyhow::Result<Report> {
    let mut stmt = src.prepare(
        "SELECT name, COALESCE(sql, '') FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name",
    )?;
    let all: Vec<(String, String)> =
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
    let virtuals: Vec<&str> = all
        .iter()
        .filter(|(_, sql)| sql.trim_start().to_ascii_uppercase().starts_with("CREATE VIRTUAL TABLE"))
        .map(|(n, _)| n.as_str())
        .collect();
    let mapped: BTreeSet<&str> = MAPS.iter().map(|m| m.source).collect();
    let mut unmapped_tables = Vec::new();
    let mut derived_tables = Vec::new();
    for (name, _) in &all {
        let derived = virtuals.iter().any(|v| name == v || name.starts_with(&format!("{v}_")));
        if derived {
            derived_tables.push(name.clone());
        } else if !mapped.contains(name.as_str()) {
            unmapped_tables.push(name.clone());
        }
    }
    let present: BTreeSet<&str> = all.iter().map(|(n, _)| n.as_str()).collect();

    let mut tables = Vec::new();
    let mut unmapped_columns = BTreeMap::new();
    for map in MAPS {
        let mut rep = TableReport { table: map.source.into(), ..TableReport::default() };
        if present.contains(map.source) {
            rep.present = true;
            rep.source_rows = count(src, &format!("SELECT COUNT(*) FROM {}", q(map.source)), [])?;
            let plan = plan_table(src, target, map)?;
            let mut cols = BTreeMap::new();
            for c in &plan.unmapped {
                let n = count(src, &format!("SELECT COUNT({}) FROM {}", q(c), q(map.source)), [])?;
                cols.insert(c.clone(), n);
            }
            if !cols.is_empty() {
                unmapped_columns.insert(map.source.to_string(), cols);
            }
            if !dry_run {
                let st = load_state(target, &source_hash, map.source)?;
                rep.last_key = st.last_key;
                rep.total_copied = st.copied;
                rep.total_skipped = st.skipped;
                rep.already_imported = count(
                    src,
                    &format!("SELECT COUNT(*) FROM {} WHERE rowid <= ?1", q(map.source)),
                    [st.last_key],
                )?;
            }
        }
        tables.push(rep);
    }
    let source_ledger = verify_source_ledger(src, present.contains("event_log"))?;
    let org_scoped_rows: BTreeMap<String, u64> = unmapped_columns
        .iter()
        .filter_map(|(t, cols)| cols.get("org_id").filter(|n| **n > 0).map(|n| (t.clone(), *n)))
        .collect();
    Ok(Report {
        source_hash,
        dry_run,
        tables,
        unmapped_tables,
        derived_tables,
        unmapped_columns,
        source_ledger,
        org_scoped_rows,
        task_runs_cleared: 0,
        task_runs_cleared_ids: Vec::new(),
        binding_branches_cleared: 0,
        target_ledger: None,
        notes: Vec::new(),
    })
}

/// The columns copied for one table.
struct Plan<'m> {
    map: &'m TableMap,
    /// Source columns copied to the same-named target column.
    cols: Vec<String>,
    /// Source columns the target does not have.
    unmapped: Vec<String>,
    /// Target columns, in insert order: `cols`, then the extras below.
    insert_cols: Vec<String>,
    /// `message_index.event_seq` is absent in the source and filled per row.
    append_event_seq: bool,
}

fn plan_table<'m>(src: &Connection, target: &Db, map: &'m TableMap) -> anyhow::Result<Plan<'m>> {
    let src_cols = columns(src, map.source)?;
    let dst_cols = target.read(|c| Ok(columns(c, map.target)?))?;
    if dst_cols.is_empty() {
        bail!("target table {} does not exist; open the target with ua_import::schema_parts()", map.target);
    }
    let (cols, unmapped): (Vec<String>, Vec<String>) = src_cols
        .into_iter()
        .partition(|c| c != "org_id" && dst_cols.contains(c) && Some(c.as_str()) != map.rowid_to);
    let mut insert_cols = cols.clone();
    if let Some(r) = map.rowid_to {
        insert_cols.push(r.to_string());
    }
    let append_event_seq = map.kind == Kind::MessageIndex && !cols.iter().any(|c| c == "event_seq");
    if append_event_seq {
        insert_cols.push("event_seq".into());
    }
    if map.kind.writes_default_org() {
        insert_cols.push("org_id".into());
    }
    if map.kind == Kind::MessageIndex && !cols.iter().any(|c| c == "event_ulid") {
        bail!("source message_index has no event_ulid column; cannot link messages to the ledger");
    }
    Ok(Plan { map, cols, unmapped, insert_cols, append_event_seq })
}

// ---------------------------------------------------------------------------
// Resume state.

struct State {
    last_key: i64,
    copied: u64,
    skipped: u64,
}

fn load_state(db: &Db, source_hash: &str, table: &str) -> UaResult<State> {
    db.read(|c| {
        let row = c
            .query_row(
                "SELECT last_key, copied, skipped FROM import_runs WHERE source_hash = ?1 AND table_name = ?2",
                params![source_hash, table],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
            )
            .optional()?;
        let (last_key, copied, skipped) = row.unwrap_or((0, 0, 0));
        Ok(State { last_key, copied: copied.max(0) as u64, skipped: skipped.max(0) as u64 })
    })
}

fn save_state(
    conn: &Connection,
    source_hash: &str,
    table: &str,
    last_key: i64,
    copied: u64,
    skipped: u64,
) -> rusqlite::Result<()> {
    let now = ua_core::time::now();
    conn.execute(
        "INSERT INTO import_runs (source_hash, table_name, copied, skipped, last_key, started_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6) \
         ON CONFLICT (source_hash, table_name) DO UPDATE SET copied = copied + excluded.copied, \
         skipped = skipped + excluded.skipped, last_key = excluded.last_key, updated_at = excluded.updated_at",
        params![source_hash, table, copied as i64, skipped as i64, last_key, now],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Plain tables.

fn row_values(r: &Row<'_>, offset: usize, n: usize) -> rusqlite::Result<Vec<SqlValue>> {
    (0..n).map(|i| r.get::<_, SqlValue>(offset + i)).collect()
}

fn col_value<'v>(cols: &[String], vals: &'v [SqlValue], name: &str) -> Option<&'v SqlValue> {
    cols.iter().position(|c| c == name).and_then(|i| vals.get(i))
}

fn as_text(v: Option<&SqlValue>) -> Option<&str> {
    match v {
        Some(SqlValue::Text(s)) => Some(s.as_str()),
        _ => None,
    }
}

enum BranchNorm {
    Keep(SqlValue),
    ClearedInvalid,
}

fn normalize_binding_branch(v: &SqlValue) -> BranchNorm {
    match v {
        SqlValue::Null => BranchNorm::Keep(SqlValue::Null),
        SqlValue::Text(s) => match check_default_branch(Some(s)) {
            Ok(Some(b)) => BranchNorm::Keep(SqlValue::Text(b)),
            Ok(None) => BranchNorm::Keep(SqlValue::Null),
            Err(_) => BranchNorm::ClearedInvalid,
        },
        _ => BranchNorm::ClearedInvalid,
    }
}

fn record_cleared_task_run(count: &mut u64, ids: &mut Vec<i64>, id_val: Option<&SqlValue>) {
    *count += 1;
    if ids.len() < MAX_REPORTED_TASK_RUN_IDS
        && let Some(SqlValue::Integer(tid)) = id_val
    {
        ids.push(*tid);
    }
}

fn append_clear_notes(report: &mut Report) {
    if report.task_runs_cleared > 0 {
        let n = report.task_runs_cleared;
        let ids: Vec<String> = report.task_runs_cleared_ids.iter().map(|id| format!("#{id}")).collect();
        let note = if (n as usize) > ids.len() && !ids.is_empty() {
            format!(
                "{n} task(s) had current_run_id/current_run_agent cleared because dispatch_runs are not \
                 imported (first {} of {n} task ids: {})",
                ids.len(),
                ids.join(", ")
            )
        } else if !ids.is_empty() {
            format!(
                "{n} task(s) had current_run_id/current_run_agent cleared because dispatch_runs are not \
                 imported (task ids: {})",
                ids.join(", ")
            )
        } else {
            format!(
                "{n} task(s) had current_run_id/current_run_agent cleared because dispatch_runs are not \
                 imported"
            )
        };
        report.notes.push(note);
    }
    if report.binding_branches_cleared > 0 {
        report.notes.push(format!(
            "{} project_repo_bindings row(s) had an invalid default_branch cleared to NULL",
            report.binding_branches_cleared
        ));
    }
}

/// A reason to leave a row out, decided from the row alone.
fn filter(kind: Kind, cols: &[String], vals: &[SqlValue]) -> Option<&'static str> {
    match kind {
        Kind::Approvals => match as_text(col_value(cols, vals, "status")) {
            // A pending request or an approved pass not yet consumed is live
            // authority; only settled history moves across.
            Some("pending") | Some("approved") => Some("live_approval"),
            _ => None,
        },
        Kind::Tokens => {
            let algo = as_text(col_value(cols, vals, "hash_algo"));
            let hash = as_text(col_value(cols, vals, "token_hash")).unwrap_or("");
            let hex64 = hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if algo == Some("sha256") && hex64 { None } else { Some("unsupported_token_hash") }
        }
        Kind::TaskHolds => match as_text(col_value(cols, vals, "status")) {
            Some("active") | Some("released") => None,
            _ => Some("invalid_status"),
        },
        Kind::ProjectRepoBindings => {
            if as_text(col_value(cols, vals, "project")).and_then(|s| check_slug("project", s).ok()).is_none()
            {
                Some("invalid_project")
            } else if as_text(col_value(cols, vals, "repo")).and_then(|r| normalize_repo(r).ok()).is_none() {
                Some("invalid_repo")
            } else {
                None
            }
        }
        _ => None,
    }
}

fn exists(conn: &Connection, table: &str, key: &str, v: &SqlValue) -> rusqlite::Result<bool> {
    conn.query_row(&format!("SELECT 1 FROM {} WHERE {} = ?1 LIMIT 1", q(table), q(key)), [v], |_| Ok(()))
        .optional()
        .map(|o| o.is_some())
}

fn bump(map: &mut BTreeMap<String, u64>, reason: impl Into<String>) {
    *map.entry(reason.into()).or_default() += 1;
}

/// Every refusal that depends only on the source and the target as they are
/// now. It runs before the first write, so a refused import leaves the target
/// untouched.
fn check_target(src: &Connection, db: &Db, report: &Report, opts: &Options) -> anyhow::Result<()> {
    if !report.org_scoped_rows.is_empty() && !opts.drop_org_scope {
        let per_table: Vec<String> =
            report.org_scoped_rows.iter().map(|(t, n)| format!("{t}: {n}")).collect();
        bail!(
            "source rows carry an org_id ({}), and ua-rust has no tenant scope, so importing would silently \
             drop that boundary; refusing (nothing was written). Pass --drop-org-scope to import anyway",
            per_table.join(", ")
        );
    }
    for map in MAPS {
        let Some(rep) = report.tables.iter().find(|t| t.table == map.source).filter(|t| t.present) else {
            continue;
        };
        match map.kind {
            Kind::Ledger => check_ledger_target(src, db, rep.last_key)?,
            Kind::TaskHolds => {
                check_source_active_holds(src, rep.last_key)?;
                check_key_overlap(src, db, map, rep.last_key)?;
            }
            Kind::ProjectRepoBindings => {
                check_source_bindings_overlap(src, db, map, rep.last_key)?;
                check_key_overlap(src, db, map, rep.last_key)?;
            }
            _ => check_key_overlap(src, db, map, rep.last_key)?,
        }
    }
    Ok(())
}

fn check_source_active_holds(src: &Connection, last: i64) -> anyhow::Result<()> {
    let cols = columns(src, "task_holds")?;
    if !cols.iter().any(|c| c == "root_task_id") || !cols.iter().any(|c| c == "status") {
        return Ok(());
    }
    let sql = "SELECT root_task_id, COUNT(*) FROM task_holds \
               WHERE rowid > ?1 AND root_task_id IS NOT NULL AND status = 'active' \
               GROUP BY root_task_id HAVING COUNT(*) > 1 LIMIT 1";
    if let Some((root_id, n)) =
        src.query_row(sql, [last], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))).optional()?
    {
        bail!(
            "source task_holds has {n} active holds for root_task_id {root_id}; ua-rust allows at most one active \
             hold per root (nothing was written)"
        );
    }
    Ok(())
}

fn check_source_bindings_overlap(src: &Connection, db: &Db, map: &TableMap, last: i64) -> anyhow::Result<()> {
    let plan = plan_table(src, db, map)?;
    if !plan.cols.iter().any(|c| c == "project") {
        return Ok(());
    }
    let sel =
        format!("SELECT {} FROM {} WHERE rowid > ?1 ORDER BY rowid", select_list(&plan.cols), q(map.source));
    let mut stmt = src.prepare(&sel)?;
    let mut rows = stmt.query([last])?;
    let mut seen = BTreeSet::new();
    while let Some(r) = rows.next()? {
        let vals = row_values(r, 0, plan.cols.len())?;
        if filter(map.kind, &plan.cols, &vals).is_some() {
            continue;
        }
        if let Some(slug) =
            as_text(col_value(&plan.cols, &vals, "project")).and_then(|s| check_slug("project", s).ok())
            && !seen.insert(slug.clone())
        {
            bail!(
                "source project_repo_bindings has duplicate project slug {slug:?} after trimming \
                 (nothing was written)"
            );
        }
    }
    Ok(())
}

/// The target ledger must hold exactly the rows this importer wrote so far.
fn check_ledger_target(src: &Connection, db: &Db, last: i64) -> anyhow::Result<()> {
    let target_max: Option<i64> =
        db.read(|c| Ok(c.query_row("SELECT MAX(seq) FROM event_log", [], |r| r.get(0))?))?;
    if target_max.unwrap_or(0) > last {
        bail!(
            "target ledger already holds events this import did not write (max seq {} > imported {last}); \
             importing the Python ledger would interleave two histories. Import into a fresh database. \
             Catch-up imports only work before the Rust hub writes its own events (nothing was written)",
            target_max.unwrap_or(0)
        );
    }
    if last > 0 {
        let at_target: Option<(String, Option<String>)> = db.read(|c| {
            Ok(c.query_row("SELECT ulid, entry_hash FROM event_log WHERE seq = ?1", [last], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?)
        })?;
        let at_source: Option<(String, Option<String>)> = src
            .query_row("SELECT ulid, entry_hash FROM event_log WHERE rowid = ?1", [last], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        if at_target.is_none() || at_target != at_source {
            bail!(
                "the source ledger no longer matches the imported prefix at seq {last}; refusing to continue \
                 (nothing was written)"
            );
        }
    }
    Ok(())
}

/// Refuse when a source row still to be copied has the key of a row already in
/// the target. Rows at or below the resume key are this importer's own.
fn check_key_overlap(src: &Connection, db: &Db, map: &TableMap, last: i64) -> anyhow::Result<()> {
    let plan = plan_table(src, db, map)?;
    // Target primary key columns, and the source column that feeds each.
    let pk: Vec<String> = db.read(|c| {
        let mut stmt = c.prepare("SELECT name FROM pragma_table_info(?1) WHERE pk > 0 ORDER BY pk")?;
        let rows = stmt.query_map([map.target], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    })?;
    // A key whose values come from copied columns, the default org, or the source rowid.
    let mut keys: Vec<Vec<String>> = Vec::new();
    if !pk.is_empty()
        && pk.iter().all(|c| plan.cols.contains(c) || (map.kind.writes_default_org() && c == "org_id"))
    {
        keys.push(pk);
    }
    if let Some(r) = map.rowid_to {
        keys.push(vec![r.to_string()]);
    }
    // Hub-wide on purpose: the one-active-hold index is keyed by the
    // hub-global root task id across every organization, so a clash in any
    // organization would fail the copy.
    let active_hold_probe_sql = (map.kind == Kind::TaskHolds)
        .then_some("SELECT 1 FROM task_holds WHERE root_task_id = ?1 AND status = 'active' LIMIT 1");
    if keys.is_empty() && active_hold_probe_sql.is_none() {
        return Ok(());
    }
    let sel = format!(
        "SELECT rowid, {} FROM {} WHERE rowid > ?1 ORDER BY rowid",
        select_list(&plan.cols),
        q(map.source)
    );
    let probes: Vec<String> = keys
        .iter()
        .map(|key| {
            let cond = key
                .iter()
                .enumerate()
                .map(|(i, c)| format!("{} = ?{}", q(c), i + 1))
                .collect::<Vec<_>>()
                .join(" AND ");
            format!("SELECT 1 FROM {} WHERE {cond} LIMIT 1", q(map.target))
        })
        .collect();
    let mut stmt = src.prepare(&sel)?;
    let mut rows = stmt.query([last])?;
    let mut clash: Option<(String, Vec<SqlValue>)> = None;
    let mut active_hold_clash: Option<SqlValue> = None;
    db.read(|c| {
        let mut prepared = probes.iter().map(|p| c.prepare(p)).collect::<Result<Vec<_>, _>>()?;
        let mut active_hold_probe = active_hold_probe_sql.map(|p| c.prepare(p)).transpose()?;
        'rows: while let Some(r) = rows.next()? {
            let rowid: i64 = r.get(0)?;
            let vals = row_values(r, 1, plan.cols.len())?;
            if filter(map.kind, &plan.cols, &vals).is_some() {
                continue;
            }
            for (key, probe) in keys.iter().zip(prepared.iter_mut()) {
                let kv: Vec<SqlValue> = if map.rowid_to == Some(key[0].as_str()) {
                    vec![SqlValue::Integer(rowid)]
                } else {
                    key.iter()
                        .map(|k| {
                            if map.kind.writes_default_org() && k == "org_id" {
                                return SqlValue::Text(ua_core::DEFAULT_ORG.into());
                            }
                            let raw = col_value(&plan.cols, &vals, k).cloned().unwrap_or(SqlValue::Null);
                            if map.kind == Kind::ProjectRepoBindings
                                && k == "project"
                                && let Some(norm) =
                                    as_text(Some(&raw)).and_then(|s| check_slug("project", s).ok())
                            {
                                return SqlValue::Text(norm);
                            }
                            raw
                        })
                        .collect()
                };
                // A NULL key part never collides.
                if kv.contains(&SqlValue::Null) {
                    continue;
                }
                if probe.exists(params_from_iter(kv.iter()))? {
                    clash = Some((key.join(", "), kv));
                    break 'rows;
                }
            }
            if let Some(probe) = active_hold_probe.as_mut() {
                let eff_status = as_text(col_value(&plan.cols, &vals, "status"));
                if eff_status == Some("active")
                    && let Some(root_val) = col_value(&plan.cols, &vals, "root_task_id")
                    && *root_val != SqlValue::Null
                    && probe.exists([root_val])?
                {
                    active_hold_clash = Some(root_val.clone());
                    break 'rows;
                }
            }
        }
        Ok(())
    })?;
    if let Some((key, vals)) = clash {
        bail!(
            "{} already holds a row with key ({key}) = {vals:?} that this import would copy; the target must not \
             hold rows with imported keys. Import into a fresh database (nothing was written)",
            map.target
        );
    }
    if let Some(root) = active_hold_clash {
        bail!(
            "task_holds already holds an active hold for root_task_id = {root:?} that this import would copy; \
             the target must not hold rows with imported active holds. Import into a fresh database (nothing was written)"
        );
    }
    Ok(())
}

#[derive(Default)]
struct CopyEffects {
    task_runs_cleared: u64,
    task_runs_cleared_ids: Vec<i64>,
    binding_branches_cleared: u64,
}

fn copy_table(
    src: &Connection,
    db: &Db,
    source_hash: &str,
    plan: &Plan<'_>,
    batch: usize,
    rep: &mut TableReport,
) -> anyhow::Result<CopyEffects> {
    let map = plan.map;
    let select = format!(
        "SELECT rowid, {} FROM {} WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
        select_list(&plan.cols),
        q(map.source)
    );
    let marks = vec!["?"; plan.insert_cols.len()].join(", ");
    let insert =
        format!("INSERT INTO {} ({}) VALUES ({marks})", q(map.target), select_list(&plan.insert_cols));
    let seq_idx = plan.insert_cols.iter().position(|c| c == "event_seq");
    let ulid_idx = plan.insert_cols.iter().position(|c| c == "event_ulid");
    let id_idx = plan.cols.iter().position(|c| c == "id");
    let run_id_idx = plan.cols.iter().position(|c| c == "current_run_id");
    let run_agent_idx = plan.cols.iter().position(|c| c == "current_run_agent");
    let proj_idx = plan.cols.iter().position(|c| c == "project");
    let repo_idx = plan.cols.iter().position(|c| c == "repo");
    let branch_idx = plan.cols.iter().position(|c| c == "default_branch");
    let mut last_key = rep.last_key;
    let mut effects = CopyEffects::default();
    loop {
        let rows: Vec<(i64, Vec<SqlValue>)> = {
            let mut stmt = src.prepare_cached(&select)?;
            let rows = stmt.query_map(params![last_key, batch as i64], |r| {
                Ok((r.get::<_, i64>(0)?, row_values(r, 1, plan.cols.len())?))
            })?;
            rows.collect::<Result<_, _>>()?
        };
        let Some(&(batch_last, _)) = rows.last() else { break };
        let (copied, skipped, nulled, batch_runs_cleared, batch_run_ids, batch_branches_cleared) = db
            .write(|tx| {
                tx.execute_batch("PRAGMA defer_foreign_keys = ON")?;
                let mut copied = 0u64;
                let mut skipped: BTreeMap<String, u64> = BTreeMap::new();
                let mut nulled = 0u64;
                let mut batch_runs_cleared = 0u64;
                let mut batch_run_ids = Vec::new();
                let mut batch_branches_cleared = 0u64;
                'rows: for (rowid, mut vals) in rows {
                    if let Some(reason) = filter(map.kind, &plan.cols, &vals) {
                        bump(&mut skipped, reason);
                        continue;
                    }
                    for r in map.refs {
                        if let Some(v) = col_value(&plan.cols, &vals, r.col).filter(|v| **v != SqlValue::Null)
                            && !exists(tx, r.table, r.key, v)?
                        {
                            bump(&mut skipped, format!("missing_{}", r.col));
                            continue 'rows;
                        }
                    }
                    if let Some(sr) = map.self_ref
                        && let Some(i) = plan.cols.iter().position(|c| c == sr.col)
                        && vals[i] != SqlValue::Null
                        && !exists(tx, sr.table, sr.key, &vals[i])?
                    {
                        // A forward reference is restored by `fix_self_ref`.
                        if !exists(src, map.source, sr.key, &vals[i])? {
                            nulled += 1;
                        }
                        vals[i] = SqlValue::Null;
                    }
                    if map.kind == Kind::Tasks {
                        let has_run = run_id_idx.is_some_and(|ri| vals[ri] != SqlValue::Null)
                            || run_agent_idx.is_some_and(|ai| vals[ai] != SqlValue::Null);
                        if has_run {
                            if let Some(ri) = run_id_idx {
                                vals[ri] = SqlValue::Null;
                            }
                            if let Some(ai) = run_agent_idx {
                                vals[ai] = SqlValue::Null;
                            }
                            let id_val = id_idx.map(|ii| vals[ii].clone());
                            record_cleared_task_run(
                                &mut batch_runs_cleared,
                                &mut batch_run_ids,
                                id_val.as_ref(),
                            );
                        }
                    }
                    if map.kind == Kind::Nodes
                        && let Some(i) = plan.cols.iter().position(|c| c == "facts_json")
                    {
                        vals[i] = SqlValue::Text("{}".into());
                    }
                    if map.kind == Kind::ProjectRepoBindings {
                        if let Some(pi) = proj_idx
                            && let Some(slug) =
                                as_text(Some(&vals[pi])).and_then(|s| check_slug("project", s).ok())
                        {
                            vals[pi] = SqlValue::Text(slug);
                        }
                        if let Some(ri) = repo_idx
                            && let Some(repo) = as_text(Some(&vals[ri])).and_then(|r| normalize_repo(r).ok())
                        {
                            vals[ri] = SqlValue::Text(repo);
                        }
                        if let Some(bi) = branch_idx {
                            match normalize_binding_branch(&vals[bi]) {
                                BranchNorm::Keep(v) => vals[bi] = v,
                                BranchNorm::ClearedInvalid => {
                                    vals[bi] = SqlValue::Null;
                                    batch_branches_cleared += 1;
                                }
                            }
                        }
                    }
                    if map.rowid_to.is_some() {
                        vals.push(SqlValue::Integer(rowid));
                    }
                    if plan.append_event_seq {
                        vals.push(SqlValue::Null);
                    }
                    if map.kind.writes_default_org() {
                        vals.push(SqlValue::Text(ua_core::DEFAULT_ORG.into()));
                    }
                    if let (Some(si), Some(ui)) = (seq_idx, ulid_idx)
                        && map.kind == Kind::MessageIndex
                    {
                        let seq: Option<i64> = tx
                            .query_row("SELECT seq FROM event_log WHERE ulid = ?1", [&vals[ui]], |r| r.get(0))
                            .optional()?;
                        match seq {
                            Some(s) => vals[si] = SqlValue::Integer(s),
                            None => {
                                bump(&mut skipped, "missing_event");
                                continue;
                            }
                        }
                    }
                    tx.execute(&insert, params_from_iter(vals.iter())).map_err(|e| {
                        UaError::conflict(format!(
                            "{} row with source rowid {rowid} could not be stored: {e}; \
                             the target must not already hold rows with imported keys",
                            map.target
                        ))
                    })?;
                    copied += 1;
                }
                let n_skipped: u64 = skipped.values().sum();
                save_state(tx, source_hash, map.source, batch_last, copied, n_skipped)?;
                Ok((copied, skipped, nulled, batch_runs_cleared, batch_run_ids, batch_branches_cleared))
            })
            .with_context(|| format!("importing {}", map.source))?;
        rep.copied += copied;
        rep.total_copied += copied;
        rep.total_skipped += skipped.values().sum::<u64>();
        rep.dangling_refs_nulled += nulled;
        effects.task_runs_cleared += batch_runs_cleared;
        for id in batch_run_ids {
            if effects.task_runs_cleared_ids.len() < MAX_REPORTED_TASK_RUN_IDS {
                effects.task_runs_cleared_ids.push(id);
            }
        }
        effects.binding_branches_cleared += batch_branches_cleared;
        for (k, v) in skipped {
            *rep.skipped.entry(k).or_default() += v;
        }
        last_key = batch_last;
        rep.last_key = batch_last;
    }
    Ok(effects)
}

/// Restore self-references that pointed forward when their row was copied.
fn fix_self_ref(src: &Connection, db: &Db, map: &TableMap, sr: Ref) -> anyhow::Result<()> {
    let sql =
        format!("SELECT {}, {} FROM {} WHERE {} IS NOT NULL", q(sr.key), q(sr.col), q(map.source), q(sr.col));
    let pairs: Vec<(SqlValue, SqlValue)> = {
        let mut stmt = src.prepare(&sql)?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?
    };
    if pairs.is_empty() {
        return Ok(());
    }
    let update = format!(
        "UPDATE {t} SET {c} = ?2 WHERE {k} = ?1 AND {c} IS NULL AND EXISTS (SELECT 1 FROM {t} WHERE {k} = ?2)",
        t = q(map.target),
        c = q(sr.col),
        k = q(sr.key)
    );
    db.write(|tx| {
        for (key, val) in &pairs {
            tx.execute(&update, [key, val])?;
        }
        Ok(())
    })
    .with_context(|| format!("restoring {}.{}", map.target, sr.col))
}

fn has_sqlite_sequence(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence')",
        [],
        |r| r.get(0),
    )
}

/// Raise a non-ledger target AUTOINCREMENT table's `sqlite_sequence` counter
/// to at least the source's counter so post-cutover inserts never reuse a
/// deleted or skipped id (for example, a deleted task id still referenced by
/// an active `task_holds.root_task_id`, or a skipped approval id).
///
/// Never touches `event_log`, never lowers an existing target sequence or
/// `MAX(rowid)`, never creates duplicate `sqlite_sequence` rows, and skips
/// target tables that do not use `AUTOINCREMENT`.
fn carry_sqlite_sequence(src: &Connection, db: &Db, map: &TableMap) -> anyhow::Result<()> {
    let source_seq: Option<i64> = src.query_row(
        "SELECT MAX(seq) FROM sqlite_sequence WHERE name = ?1 AND typeof(seq) = 'integer'",
        [map.source],
        |r| r.get(0),
    )?;
    let Some(source_seq) = source_seq.filter(|&s| s > 0) else {
        return Ok(());
    };
    db.write(|tx| {
        let target_is_autoinc: bool = tx
            .query_row(
                "SELECT COALESCE(upper(sql), '') FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [map.target],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .is_some_and(|sql| sql.contains("AUTOINCREMENT") && !sql.contains("WITHOUT ROWID"));
        if !target_is_autoinc {
            return Ok(());
        }
        let max_rowid: i64 =
            tx.query_row(&format!("SELECT COALESCE(MAX(rowid), 0) FROM {}", q(map.target)), [], |r| {
                r.get(0)
            })?;
        let (existing_seq, row_count): (Option<i64>, i64) = tx.query_row(
            "SELECT MAX(seq), COUNT(*) FROM sqlite_sequence WHERE name = ?1",
            [map.target],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let floor = existing_seq.unwrap_or(0).max(max_rowid);
        if source_seq > floor {
            if row_count == 0 {
                tx.execute(
                    "INSERT INTO sqlite_sequence (name, seq) VALUES (?1, ?2)",
                    params![map.target, source_seq],
                )?;
            } else {
                tx.execute(
                    "UPDATE sqlite_sequence SET seq = ?1 WHERE name = ?2",
                    params![source_seq, map.target],
                )?;
            }
        }
        Ok(())
    })
    .with_context(|| format!("carrying sqlite_sequence for {}", map.target))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The ledger.

/// One source ledger row, with every hashed column as exact text.
struct SrcEvent {
    seq: i64,
    f: [Option<String>; 10],
}

impl SrcEvent {
    fn get(&self, name: &str) -> Option<&str> {
        LEDGER_COLUMNS.iter().position(|c| *c == name).and_then(|i| self.f[i].as_deref())
    }
}

const REQUIRED: [&str; 4] = ["ulid", "channel", "payload", "created_at"];

fn ledger_select(after: bool) -> String {
    let cols = LEDGER_COLUMNS.join(", ");
    if after {
        format!("SELECT rowid, {cols} FROM event_log WHERE rowid > ?1 ORDER BY rowid LIMIT ?2")
    } else {
        format!("SELECT rowid, {cols} FROM event_log ORDER BY rowid")
    }
}

/// Read a row, refusing any value that is not stored as exact text.
fn read_event(r: &Row<'_>) -> rusqlite::Result<Result<SrcEvent, (i64, String)>> {
    let seq: i64 = r.get(0)?;
    let mut f: [Option<String>; 10] = Default::default();
    for (i, name) in LEDGER_COLUMNS.iter().enumerate() {
        let v = match r.get_ref(i + 1)? {
            ValueRef::Null => None,
            ValueRef::Text(b) => match std::str::from_utf8(b) {
                Ok(s) => Some(s.to_string()),
                Err(_) => return Ok(Err((seq, format!("{name} is not valid UTF-8 text")))),
            },
            other => {
                return Ok(Err((
                    seq,
                    format!(
                        "{name} is stored as {:?}, not text; it cannot be copied byte-exactly",
                        other.data_type()
                    ),
                )));
            }
        };
        if v.is_none() && REQUIRED.contains(name) {
            return Ok(Err((seq, format!("{name} is NULL"))));
        }
        f[i] = v;
    }
    Ok(Ok(SrcEvent { seq, f }))
}

/// Walks the chain the way the Python verifier does: unhashed rows are
/// allowed only before the first hashed row.
struct Chain {
    head: Option<String>,
}

impl Chain {
    fn check(&mut self, ev: &SrcEvent) -> Result<bool, String> {
        let Some(entry) = ev.get("entry_hash") else {
            return if self.head.is_some() {
                Err("unhashed row after the hash chain started".into())
            } else {
                Ok(false)
            };
        };
        let want = self.head.as_deref().unwrap_or(GENESIS_HASH);
        let prev = ev.get("prev_hash");
        if prev != Some(want) {
            return Err("prev_hash does not link to the previous entry".into());
        }
        let recomputed = ledger::compute_entry_hash(
            prev,
            ev.get("ulid").unwrap_or_default(),
            ev.get("channel").unwrap_or_default(),
            ev.get("payload").unwrap_or_default(),
            ev.get("originator"),
            ev.get("episode_id"),
            ev.get("causal_parent_id"),
            ev.get("created_at").unwrap_or_default(),
            ev.get("dedupe_key"),
        );
        if recomputed != entry {
            return Err("entry_hash does not match the row contents".into());
        }
        self.head = Some(entry.to_string());
        Ok(true)
    }
}

fn verify_source_ledger(src: &Connection, present: bool) -> anyhow::Result<SourceLedgerReport> {
    let mut rep = SourceLedgerReport { ok: true, ..SourceLedgerReport::default() };
    if !present {
        return Ok(rep);
    }
    let mut stmt = src.prepare(&ledger_select(false))?;
    let mut rows = stmt.query([])?;
    let mut chain = Chain { head: None };
    while let Some(r) = rows.next()? {
        rep.rows += 1;
        let checked = read_event(r)?.and_then(|ev| chain.check(&ev).map_err(|e| (ev.seq, e)));
        match checked {
            Ok(true) => rep.checked += 1,
            Ok(false) => rep.unhashed += 1,
            Err((seq, reason)) => {
                rep.ok = false;
                rep.first_bad_seq = Some(seq);
                rep.reason = Some(reason);
                break;
            }
        }
    }
    Ok(rep)
}

fn copy_ledger(
    src: &Connection,
    db: &Db,
    source_hash: &str,
    batch: usize,
    rep: &mut TableReport,
) -> anyhow::Result<()> {
    let last = rep.last_key;
    let pending = count(src, "SELECT COUNT(*) FROM event_log WHERE rowid > ?1", [last])?;
    if pending == 0 {
        return Ok(());
    }
    // `check_target` already proved the target ledger is exactly the imported
    // prefix; only its chain head is needed to continue.
    let target_head: Option<String> = db.read(|c| {
        Ok(c.query_row(
            "SELECT entry_hash FROM event_log WHERE entry_hash IS NOT NULL ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?)
    })?;
    let mut chain = Chain { head: target_head };
    let select = ledger_select(true);
    let insert = format!(
        "INSERT INTO event_log (seq, {}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        LEDGER_COLUMNS.join(", ")
    );
    let mut cursor = last;
    loop {
        let rows: Vec<Result<SrcEvent, (i64, String)>> = {
            let mut stmt = src.prepare_cached(&select)?;
            let rows = stmt.query_map(params![cursor, batch as i64], read_event)?;
            rows.collect::<Result<_, _>>()?
        };
        let Some(batch_last) = rows.last().map(|r| match r {
            Ok(ev) => ev.seq,
            Err((seq, _)) => *seq,
        }) else {
            break;
        };
        let copied = db
            .write(|tx| {
                // Re-check inside the write transaction: the target ledger must
                // still end exactly where this import left it. Another writer
                // appending in between would interleave two histories.
                let target_max: Option<i64> =
                    tx.query_row("SELECT MAX(seq) FROM event_log", [], |r| r.get(0))?;
                let expected = (cursor > 0).then_some(cursor);
                if target_max != expected {
                    return Err(UaError::conflict(format!(
                        "the target ledger changed during the import (last seq {target_max:?}, expected \
                         {expected:?}); stop every hub process and retry"
                    )));
                }
                let mut n = 0u64;
                let mut unhashed = 0u64;
                for row in &rows {
                    let ev = row.as_ref().map_err(|(seq, why)| {
                        UaError::conflict(format!(
                            "source event seq {seq}: {why}; refusing to rewrite history"
                        ))
                    })?;
                    let hashed = chain.check(ev).map_err(|why| {
                        UaError::conflict(format!(
                            "source event seq {}: {why}; refusing to rewrite history",
                            ev.seq
                        ))
                    })?;
                    unhashed += u64::from(!hashed);
                    let mut vals: Vec<SqlValue> = vec![SqlValue::Integer(ev.seq)];
                    vals.extend(ev.f.iter().map(|v| v.clone().map_or(SqlValue::Null, SqlValue::Text)));
                    tx.execute(&insert, params_from_iter(vals.iter())).map_err(|e| {
                        UaError::conflict(format!("source event seq {} could not be stored: {e}", ev.seq))
                    })?;
                    n += 1;
                }
                // The legacy prefix is part of the record verify checks it
                // against, written with the rows it counts.
                ledger::record_legacy_prefix(tx, unhashed)?;
                save_state(tx, source_hash, "event_log", batch_last, n, 0)?;
                Ok(n)
            })
            .context("importing event_log")?;
        rep.copied += copied;
        rep.total_copied += copied;
        rep.last_key = batch_last;
        cursor = batch_last;
    }
    Ok(())
}

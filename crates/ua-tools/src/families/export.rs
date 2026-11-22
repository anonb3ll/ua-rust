//! Structured exports: tasks, memory notes and vault journal lines.
//!
//! Tools: `export_tasks`, `export_memory`, `export_journal`, the read-only
//! migration manifest (`export_migration_manifest`, `compare_migration_manifests`)
//! and the consolidated `export_data(action, params)`. Import and rollback are
//! not implemented. The manifest tools are denied to developer and lead
//! sessions, through `export_data` too.
//!
//! An export is returned inline (capped at 2 MB) or, with
//! `write_to_vault=true` (the default, kept for compatibility), written as a
//! new file under `exports/` in the caller's workspace (capped at 32 MB). The
//! file name carries a UTC timestamp and a counter, and is created exclusively
//! so concurrent exports never overwrite each other. Writes are recorded on
//! `agent.export.written`. The manifest applies the ledger's event visibility
//! to message, session-handoff and conversation-handoff event rows, which
//! carry only their id and stored hash when restricted.
//!
//! A migration manifest is streamed from one read transaction: rows go to
//! the fingerprint hash and to the output as they are read, the output is
//! counted against its cap as it grows, and the event log is summarised
//! (count, ulid range, rolling hash) rather than listed.

use std::collections::{BTreeMap, HashSet};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, ToSql, params_from_iter};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

use super::events::{EventReader, VISIBLE_EVENT};
use super::evidence::{CLIENT_EVIDENCE_SOURCE, is_client_channel};
use super::harness_config::render::py_dumps;
use super::injection::mark_untrusted;

use crate::families::observability::normalize_since;
use crate::families::plans::{parse_params, row_map};
use crate::families::workspace::sandbox;
use crate::registry::{Registry, ToolCtx, blocking, tool};

pub const INLINE_MAX_BYTES: usize = 2 * 1024 * 1024;
pub const FILE_MAX_BYTES: usize = 32 * 1024 * 1024;
const EXPORT_DIR: &str = "exports";
const NAME_ATTEMPTS: u32 = 100;

const TASK_COLUMNS: [&str; 11] = [
    "id",
    "title",
    "notes",
    "status",
    "priority",
    "parent_id",
    "created_at",
    "updated_at",
    "completed_at",
    "source_host",
    "project",
];
const TASK_STATUSES: [&str; 6] = ["open", "doing", "waiting_review", "blocked", "done", "cancelled"];

// ---------------------------------------------------------------------------
// Delivery.

/// Where a file export lands: the caller's workspace root.
fn export_root(ctx: &ToolCtx) -> UaResult<PathBuf> {
    Ok(sandbox(ctx)?.root)
}

/// Create a new file `<stem>.<ext>` (or `<stem>-<n>.<ext>`) in `dir`, never
/// opening one that exists.
fn open_exclusive(dir: &Path, stem: &str, ext: &str) -> UaResult<(std::fs::File, PathBuf)> {
    for n in 1..=NAME_ATTEMPTS {
        let name = if n == 1 { format!("{stem}.{ext}") } else { format!("{stem}-{n}.{ext}") };
        let path = dir.join(name);
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => return Ok((f, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(UaError::internal(format!("cannot create the export file: {e}"))),
        }
    }
    Err(UaError::conflict("could not claim a free export name; retry in a second"))
}

fn create_exclusive(dir: &Path, stem: &str, ext: &str, data: &[u8]) -> UaResult<PathBuf> {
    let (mut f, path) = open_exclusive(dir, stem, ext)?;
    let written = f.write_all(data).and_then(|_| f.sync_all());
    if let Err(e) = written {
        let _ = std::fs::remove_file(&path);
        return Err(UaError::internal(format!("export write failed: {e}")));
    }
    Ok(path)
}

/// Return the export inline or write it to the workspace.
async fn deliver(
    ctx: &ToolCtx,
    name: &'static str,
    ext: &'static str,
    content: String,
    rows: usize,
    to_file: bool,
) -> UaResult<Value> {
    let cap = if to_file { FILE_MAX_BYTES } else { INLINE_MAX_BYTES };
    if content.len() > cap {
        return Err(UaError::invalid(format!(
            "export is {} bytes, over the {cap} byte cap; narrow it with filters (status/tag/since)",
            content.len()
        )));
    }
    if !to_file {
        return Ok(json!({ "content": content, "rows": rows }));
    }
    let root = export_root(ctx)?;
    let bytes = content.len();
    let stamp = jiff::Timestamp::now().strftime("%Y%m%dT%H%M%SZ").to_string();
    let path = blocking(move || {
        let dir = ua_core::safety::resolve_in_root(EXPORT_DIR, std::slice::from_ref(&root), true)?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| UaError::internal(format!("cannot create {EXPORT_DIR}/: {e}")))?;
        let file = create_exclusive(&dir, &format!("{name}-{stamp}"), ext, content.as_bytes())?;
        Ok(file.strip_prefix(&root).unwrap_or(&file).to_string_lossy().into_owned())
    })
    .await?;
    let (by, rel) = (ctx.caller.label.clone(), path.clone());
    ctx.hub
        .db()
        .write_async(move |tx| {
            ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    "agent.export.written",
                    json!({ "kind": name, "path": rel, "rows": rows, "bytes": bytes }),
                )
                .by(by),
            )?;
            Ok(())
        })
        .await?;
    Ok(json!({ "path": path, "rows": rows, "bytes": bytes, "root": "workspace" }))
}

// ---------------------------------------------------------------------------
// export_tasks

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TasksArgs {
    /// csv (RFC 4180, default), json or markdown.
    pub format: Option<String>,
    /// One task status, or `all` (default).
    pub status: Option<String>,
    /// Write a file under `exports/` in the workspace (default true) instead of returning it inline.
    pub write_to_vault: Option<bool>,
    /// Only this project stream.
    pub project: Option<String>,
}

fn csv_cell(v: &Value) -> String {
    let s = match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    if s.contains([',', '"', '\r', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s }
}

fn md_cell(v: &Value) -> String {
    let s = match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    s.replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn task_rows(
    c: &Connection,
    status: Option<&str>,
    project: Option<&str>,
) -> UaResult<Vec<Map<String, Value>>> {
    let mut sql = format!("SELECT {} FROM tasks WHERE 1=1", TASK_COLUMNS.join(", "));
    let mut args: Vec<SqlValue> = Vec::new();
    if let Some(s) = status {
        sql.push_str(" AND status = ?");
        args.push(SqlValue::Text(s.into()));
    }
    if let Some(p) = project {
        sql.push_str(" AND project = ?");
        args.push(SqlValue::Text(p.into()));
    }
    sql.push_str(" ORDER BY id");
    let mut stmt = c.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter()), row_map)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

async fn export_tasks(ctx: ToolCtx, a: TasksArgs) -> UaResult<Value> {
    let format = a.format.as_deref().unwrap_or("csv").trim().to_ascii_lowercase();
    if !["csv", "json", "markdown"].contains(&format.as_str()) {
        return Err(UaError::invalid(format!("format must be one of csv, json, markdown, got {format:?}")));
    }
    let status =
        a.status.as_deref().map(str::trim).filter(|s| !s.is_empty() && *s != "all").map(str::to_string);
    if let Some(s) = &status
        && !TASK_STATUSES.contains(&s.as_str())
    {
        return Err(UaError::invalid(format!("status must be one of {TASK_STATUSES:?} or all, got {s:?}")));
    }
    let project = a.project.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let rows = ctx.hub.db().read_async(move |c| task_rows(c, status.as_deref(), project.as_deref())).await?;
    let n = rows.len();
    let null = Value::Null;
    let cell = |r: &Map<String, Value>, k: &str| -> Value { r.get(k).unwrap_or(&null).clone() };
    let (content, ext) = match format.as_str() {
        "csv" => {
            let mut out = TASK_COLUMNS.join(",") + "\r\n";
            for r in &rows {
                let line: Vec<String> = TASK_COLUMNS.iter().map(|k| csv_cell(&cell(r, k))).collect();
                out.push_str(&line.join(","));
                out.push_str("\r\n");
            }
            (out, "csv")
        }
        "json" => (serde_json::to_string_pretty(&rows)? + "\n", "json"),
        _ => {
            let mut lines = vec![
                format!("| {} |", TASK_COLUMNS.join(" | ")),
                format!("| {} |", TASK_COLUMNS.iter().map(|_| "---").collect::<Vec<_>>().join(" | ")),
            ];
            for r in &rows {
                lines.push(format!(
                    "| {} |",
                    TASK_COLUMNS.iter().map(|k| md_cell(&cell(r, k))).collect::<Vec<_>>().join(" | ")
                ));
            }
            (lines.join("\n") + "\n", "md")
        }
    };
    deliver(&ctx, "tasks", ext, content, n, a.write_to_vault.unwrap_or(true)).await
}

// ---------------------------------------------------------------------------
// export_memory

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryArgs {
    /// jsonl (default) or json.
    pub format: Option<String>,
    /// Only notes carrying this tag.
    pub tag: Option<String>,
    /// ISO date: only notes updated on or after it.
    pub since: Option<String>,
    /// Write a file under `exports/` in the workspace (default true) instead of returning it inline.
    pub write_to_vault: Option<bool>,
}

fn json_list(raw: Option<&str>) -> Value {
    raw.and_then(|s| serde_json::from_str::<Value>(s).ok())
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]))
}

fn is_index_id(id: &str) -> bool {
    id.starts_with("masterindex") || id.starts_with("tagindex_")
}

fn memory_records(c: &Connection, tag: Option<&str>, since_day: Option<&str>) -> UaResult<Vec<Value>> {
    let mut stmt = c.prepare(
        "SELECT id, title, content, tags, author, created_at, updated_at, salience, confidence, superseded_by, \
         source_host, epistemic, evidence, valid_from, contradicts, valid_to FROM memory ORDER BY updated_at, id",
    )?;
    let rows = stmt.query_map([], row_map)?;
    let mut out = Vec::new();
    for row in rows {
        let r = row?;
        let s = |k: &str| r.get(k).and_then(Value::as_str);
        let id = s("id").unwrap_or_default();
        if is_index_id(id) {
            continue;
        }
        let tags = json_list(s("tags"));
        if let Some(t) = tag
            && !tags.as_array().is_some_and(|a| a.iter().any(|x| x == t))
        {
            continue;
        }
        if let (Some(day), Some(updated)) = (since_day, s("updated_at"))
            && updated.get(..10).is_some_and(|u| u < day)
        {
            continue;
        }
        let superseded_by = r.get("superseded_by").cloned().unwrap_or(Value::Null);
        out.push(json!({
            "id": id,
            "title": r.get("title"),
            "content": r.get("content"),
            "tags": tags,
            "author": r.get("author"),
            "created_at": r.get("created_at"),
            "updated_at": r.get("updated_at"),
            "salience": r.get("salience"),
            "confidence": r.get("confidence"),
            "superseded": superseded_by.as_str().is_some_and(|v| !v.is_empty()),
            "superseded_by": superseded_by,
            "source_host": r.get("source_host"),
            "epistemic": r.get("epistemic"),
            "evidence": json_list(s("evidence")),
            "valid_from": r.get("valid_from"),
            "contradicts": json_list(s("contradicts")),
            "valid_to": r.get("valid_to"),
        }));
    }
    Ok(out)
}

async fn export_memory(ctx: ToolCtx, a: MemoryArgs) -> UaResult<Value> {
    let format = a.format.as_deref().unwrap_or("jsonl").trim().to_ascii_lowercase();
    if format != "jsonl" && format != "json" {
        return Err(UaError::invalid(format!("format must be one of jsonl, json, got {format:?}")));
    }
    let since_day =
        a.since.as_deref().map(|s| normalize_since("since", s)).transpose()?.map(|s| s[..10].to_string());
    let tag = a.tag.clone();
    let records =
        ctx.hub.db().read_async(move |c| memory_records(c, tag.as_deref(), since_day.as_deref())).await?;
    let n = records.len();
    let (content, ext) = if format == "jsonl" {
        let mut out = String::new();
        for r in &records {
            out.push_str(&serde_json::to_string(r)?);
            out.push('\n');
        }
        (out, "jsonl")
    } else {
        (serde_json::to_string_pretty(&records)? + "\n", "json")
    };
    deliver(&ctx, "memory", ext, content, n, a.write_to_vault.unwrap_or(true)).await
}

// ---------------------------------------------------------------------------
// export_journal

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JournalArgs {
    /// Only lines by this agent label.
    pub agent: Option<String>,
    /// ISO date: only daily notes on or after it.
    pub since: Option<String>,
    /// Write a file under `exports/` in the workspace (default true) instead of returning it inline.
    pub write_to_vault: Option<bool>,
}

/// `- **HH:MM** [Label] text #tags` -> (time, label, text).
fn parse_journal_line(line: &str) -> Option<(&str, &str, &str)> {
    let rest = line.strip_prefix("- **")?;
    let (time, rest) = rest.split_once("** [")?;
    let ok_time = time.len() == 5
        && time.as_bytes()[2] == b':'
        && time.bytes().enumerate().all(|(i, b)| i == 2 || b.is_ascii_digit());
    if !ok_time {
        return None;
    }
    let (label, text) = rest.split_once("] ")?;
    (!label.is_empty() && !label.contains(']')).then_some((time, label, text))
}

fn split_tags(text: &str) -> (String, Vec<String>) {
    let mut words: Vec<&str> = text.split(' ').collect();
    let mut tags = Vec::new();
    while let Some(last) = words.last() {
        if last.len() > 1 && last.starts_with('#') {
            tags.push(last[1..].to_string());
            words.pop();
        } else {
            break;
        }
    }
    tags.reverse();
    (words.join(" ").trim_end().to_string(), tags)
}

fn daily_date(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(".md")?;
    (stem.len() == 10 && stem.parse::<jiff::civil::Date>().is_ok()).then_some(stem)
}

fn journal_entries_in(
    dir: &Path,
    machine: &str,
    agent: Option<&str>,
    since: Option<&str>,
    out: &mut Vec<Value>,
) {
    let Ok(read) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<PathBuf> = read
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .collect();
    files.sort();
    for f in files {
        let Some(date) = f.file_name().and_then(|n| n.to_str()).and_then(daily_date).map(str::to_string)
        else {
            continue;
        };
        if since.is_some_and(|s| date.as_str() < s) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&f) else { continue };
        let text = String::from_utf8_lossy(&bytes);
        for line in text.lines() {
            let Some((time, label, body)) = parse_journal_line(line) else { continue };
            if agent.is_some_and(|a| a != label) {
                continue;
            }
            let (body, tags) = split_tags(body);
            out.push(json!({
                "date": date, "time": time, "agent": label, "machine": machine, "text": body, "tags": tags,
            }));
        }
    }
}

async fn export_journal(ctx: ToolCtx, a: JournalArgs) -> UaResult<Value> {
    let Some(vault) = ctx.hub.cfg().vault_path.clone() else {
        return Err(UaError::invalid("no vault is configured (UA_VAULT_PATH)"));
    };
    let since =
        a.since.as_deref().map(|s| normalize_since("since", s)).transpose()?.map(|s| s[..10].to_string());
    let agent = a.agent.clone();
    let entries = blocking(move || {
        let logs = vault.join("Logs");
        let mut out = Vec::new();
        journal_entries_in(&logs, "desktop", agent.as_deref(), since.as_deref(), &mut out);
        if let Ok(read) = std::fs::read_dir(&logs) {
            let mut subs: Vec<PathBuf> = read
                .filter_map(Result::ok)
                // Real directories only: a symlink could lead out of the vault.
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .map(|e| e.path())
                .collect();
            subs.sort();
            for sub in subs {
                let machine = sub.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
                journal_entries_in(&sub, &machine, agent.as_deref(), since.as_deref(), &mut out);
            }
        }
        out.sort_by(|x, y| {
            let key = |v: &Value| {
                (
                    v["date"].as_str().unwrap_or("").to_string(),
                    v["time"].as_str().unwrap_or("").to_string(),
                    v["machine"].as_str().unwrap_or("").to_string(),
                )
            };
            key(x).cmp(&key(y))
        });
        Ok(out)
    })
    .await?;
    let n = entries.len();
    let mut content = String::new();
    for e in &entries {
        content.push_str(&serde_json::to_string(e)?);
        content.push('\n');
    }
    deliver(&ctx, "journal", "jsonl", content, n, a.write_to_vault.unwrap_or(true)).await
}

// ---------------------------------------------------------------------------
// Migration manifests. Read-only: nothing here imports or rolls back.

/// Task columns a manifest carries. `worktree_path` is left out: it is an
/// absolute path on the exporting machine and means nothing on another one.
const MANIFEST_TASK_COLUMNS: &[&str] = &[
    "id",
    "title",
    "notes",
    "status",
    "priority",
    "parent_id",
    "created_at",
    "updated_at",
    "completed_at",
    "archived_at",
    "source_host",
    "claimed_by",
    "claimed_at",
    "lock_expires_at",
    "untrusted",
    "branch",
    "project",
    "domain",
    "lane",
    "due_at",
    "evidence_ref",
    "next_owner",
    "waiting_on",
];
const MANIFEST_MEMORY_COLUMNS: &[&str] = &[
    "id",
    "title",
    "content",
    "tags",
    "author",
    "updated_by",
    "created_at",
    "updated_at",
    "salience",
    "confidence",
    "superseded_by",
    "source_host",
    "expires_at",
    "feedback_helpful",
    "feedback_not_helpful",
    "feedback_stale",
    "feedback_wrong",
    "epistemic",
    "evidence",
    "valid_from",
    "contradicts",
    "valid_to",
];
/// Columns of an event row listed after `events_since_ulid`.
const MANIFEST_EVENT_COLUMNS: &[&str] = &[
    "ulid",
    "channel",
    "payload",
    "originator",
    "episode_id",
    "causal_parent_id",
    "created_at",
    "entry_hash",
];
/// Columns an unhashed event row is hashed over in the rolling hash.
const ROLLING_ROW_COLUMNS: &[&str] =
    &["ulid", "channel", "payload", "originator", "episode_id", "causal_parent_id", "created_at"];
/// Columns, then the composite key. `actor` may be null; the other link fields may not.
const GRAPH_TABLES: &[(&str, &[&str], &[&str])] = &[
    ("memory_entities", &["note_id", "kind", "value"], &["note_id", "kind", "value"]),
    ("memory_links", &["src_id", "dst_id", "rel", "actor", "created_at"], &["src_id", "dst_id", "rel"]),
];
/// Manifest fields outside the fingerprinted payload.
const UNHASHED_FIELDS: [&str; 2] = ["generated_at", "fingerprint"];
/// `event_log` fields outside it: the listing after a cursor, and the cursor.
const UNHASHED_EVENT_LOG_FIELDS: [&str; 2] = ["rows", "since_ulid"];
/// The manifest layout this hub writes and compares. Version 2 summarises the
/// event log instead of listing it.
pub const MANIFEST_VERSION: u64 = 2;
/// Memory notes one manifest may carry.
pub const MANIFEST_MEMORY_MAX_ROWS: usize = 50_000;

fn manifest_hash(payload: &Value) -> String {
    hex::encode(Sha256::digest(py_dumps(payload, None).as_bytes()))
}

/// The fingerprint of a manifest: SHA-256 of its payload without the fields
/// in [`UNHASHED_FIELDS`]. Keys are sorted, so field order does not matter.
fn manifest_fingerprint(manifest: &Map<String, Value>) -> String {
    let mut payload = manifest.clone();
    for field in UNHASHED_FIELDS {
        payload.remove(field);
    }
    if let Some(Value::Object(log)) = payload.get_mut("event_log") {
        for field in UNHASHED_EVENT_LOG_FIELDS {
            log.remove(field);
        }
    }
    manifest_hash(&Value::Object(payload))
}

fn has_table(c: &Connection, table: &str) -> UaResult<bool> {
    let n: i64 =
        c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1", [table], |r| {
            r.get(0)
        })?;
    Ok(n > 0)
}

fn table_columns(c: &Connection, table: &str) -> UaResult<Vec<String>> {
    let mut stmt = c.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Visit the rows of `table` one at a time, ordered by `order_by`, with the
/// columns of `want` the table has. `filter` is an extra `WHERE` clause on
/// `order_by` (`> ?1`) when a cursor is given. Nothing is collected.
fn for_each_row(
    c: &Connection,
    table: &str,
    want: &[&str],
    order_by: &str,
    after: Option<&str>,
    mut f: impl FnMut(Map<String, Value>) -> UaResult<()>,
) -> UaResult<()> {
    if !has_table(c, table)? {
        return Ok(());
    }
    let available = table_columns(c, table)?;
    let cols: Vec<&str> = want.iter().copied().filter(|col| available.iter().any(|n| n == col)).collect();
    if cols.is_empty() || !available.iter().any(|n| n == order_by) {
        return Ok(());
    }
    let filter = if after.is_some() { format!(" WHERE {order_by} > ?1") } else { String::new() };
    let sql = format!("SELECT {} FROM {table}{filter} ORDER BY {order_by}", cols.join(", "));
    let mut stmt = c.prepare(&sql)?;
    let params: Vec<SqlValue> = after.map(|a| SqlValue::Text(a.to_string())).into_iter().collect();
    let mut rows = stmt.query(params_from_iter(params.iter()))?;
    while let Some(row) = rows.next()? {
        f(row_map(row)?)?;
    }
    Ok(())
}

/// The origin label stamped on a manifest: `source_host` from the config
/// (`UA_SOURCE_HOST`), else `local`.
fn source_host_label(cfg: &ua_core::Config) -> String {
    cfg.source_host.as_deref().map(str::trim).filter(|s| !s.is_empty()).unwrap_or("local").to_string()
}

fn schema_version_label(c: &Connection) -> UaResult<String> {
    let mut stmt = c.prepare("SELECT name FROM schema_parts")?;
    let mut names = stmt.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
    names.sort();
    Ok(names.join(","))
}

/// Mark a client-written (`sdk.`) event's row untrusted, as `event_log_query` does.
fn label_event_row(row: &mut Value) {
    if !row.get("channel").and_then(Value::as_str).is_some_and(is_client_channel) {
        return;
    }
    let originator = row.get("originator").and_then(Value::as_str).map(str::to_string);
    mark_untrusted(row, CLIENT_EVIDENCE_SOURCE, originator.as_deref());
}

/// The limits one manifest build runs under.
#[derive(Debug, Clone, Copy)]
pub struct ManifestCaps {
    /// Largest output, in bytes; the build stops as soon as it would pass it.
    pub bytes: usize,
    /// `inline` or `file`, for the refusal.
    pub kind: &'static str,
    /// Largest number of memory notes.
    pub memory_rows: usize,
}

impl ManifestCaps {
    pub const INLINE: ManifestCaps =
        ManifestCaps { bytes: INLINE_MAX_BYTES, kind: "inline", memory_rows: MANIFEST_MEMORY_MAX_ROWS };
    pub const FILE: ManifestCaps =
        ManifestCaps { bytes: FILE_MAX_BYTES, kind: "file", memory_rows: MANIFEST_MEMORY_MAX_ROWS };

    fn bytes_refusal(&self) -> UaError {
        let hint = if self.kind == "inline" {
            "pass write_to_vault=true for a file, or a later events_since_ulid"
        } else {
            "pass a later events_since_ulid, or prune memory"
        };
        UaError::invalid(format!("manifest is over the {} byte {} cap; {hint}", self.bytes, self.kind))
    }
}

/// Writes the manifest as it is read: the canonical payload goes to the
/// fingerprint hash and to `out` in one pass, and the output is counted
/// against the cap as it grows, so nothing larger than the cap is built.
struct Emitter<'o> {
    hasher: Sha256,
    /// Off while writing a part outside the fingerprinted payload.
    hashing: bool,
    out: &'o mut dyn std::io::Write,
    bytes: usize,
    caps: ManifestCaps,
}

impl Emitter<'_> {
    fn write(&mut self, s: &str, hashed: bool, written: bool) -> UaResult<()> {
        if hashed && self.hashing {
            self.hasher.update(s.as_bytes());
        }
        if written {
            self.bytes += s.len();
            if self.bytes > self.caps.bytes {
                return Err(self.caps.bytes_refusal());
            }
            self.out
                .write_all(s.as_bytes())
                .map_err(|e| UaError::internal(format!("export write failed: {e}")))?;
        }
        Ok(())
    }

    /// Payload text: hashed and written.
    fn put(&mut self, s: &str) -> UaResult<()> {
        self.write(s, true, true)
    }

    fn key(&mut self, first: bool, key: &str) -> UaResult<()> {
        let sep = if first { "" } else { "," };
        self.put(&format!("{sep}{}:", py_dumps(&json!(key), None)))
    }

    /// One JSON array whose items `fill` emits through the closure it is given.
    fn array(
        &mut self,
        fill: impl FnOnce(&mut dyn FnMut(&mut Self, &Value) -> UaResult<()>, &mut Self) -> UaResult<()>,
    ) -> UaResult<()> {
        self.put("[")?;
        let mut first = true;
        let mut item = |em: &mut Self, v: &Value| -> UaResult<()> {
            if !first {
                em.put(",")?;
            }
            first = false;
            em.put(&py_dumps(v, None))
        };
        fill(&mut item, self)?;
        self.put("]")
    }
}

/// What a manifest build produced.
#[derive(Debug)]
pub struct ManifestStats {
    pub tasks: usize,
    pub memory: usize,
    pub fingerprint: String,
    pub bytes: usize,
}

/// `{chain_ok, count, entry_hash_mismatches, first_ulid, last_ulid,
/// rolling_hash}` over the whole event log, ordered by ulid. When `chain_ok`
/// is `false`, `first_bad_seq` (when available) and `chain_error` report where
/// and why the chain broke; both are omitted on healthy logs so healthy key
/// sets and manifest fingerprints stay unchanged.
///
/// `chain_ok` is [`ledger::verify`] (seq-order `prev_hash` linkage from
/// [`ledger::GENESIS_HASH`], no hashless row after a hashed one, and a legacy
/// prefix exactly as long as `ledger_meta.unhashed_legacy_prefix` records)
/// plus zero `entry_hash` mismatches. Each row's `entry_hash` is recomputed
/// from its contents, never taken as stored: the rolling hash is SHA-256 over
/// one line per row holding the recomputed hash, or for a row without one (an
/// imported legacy prefix), the canonical JSON of its [`ROLLING_ROW_COLUMNS`].
/// Stored hashes that differ from their row (or are blank) increment
/// `entry_hash_mismatches` and clear `chain_ok`. The ulid order used for the
/// rolling hash is not checked for linkage: an imported hub can hold ULIDs
/// minted out of write order.
///
/// The summary has no anchor: it records count, the ulid range and the
/// rolling hash, not the head `entry_hash`, so a truncated or rewritten tail
/// still reports `chain_ok: true`. Only comparing the summary against an
/// earlier manifest catches that.
fn event_log_summary(c: &Connection) -> UaResult<Map<String, Value>> {
    let mut hasher = Sha256::new();
    let (mut count, mut mismatches, mut first, mut last) = (0u64, 0u64, Value::Null, Value::Null);
    let has_log = has_table(c, "event_log")?;
    let ledger_report = if has_log { Some(ledger::verify(c)?) } else { None };
    let ledger_ok = ledger_report.as_ref().is_none_or(|r| r.ok);
    if has_log {
        let mut want: Vec<&str> = ROLLING_ROW_COLUMNS.to_vec();
        want.extend(["dedupe_key", "prev_hash", "entry_hash"]);
        // Separate from ledger::verify (seq order): rolling_hash and ulid bounds follow ulid order, which can differ in imported logs.
        for_each_row(c, "event_log", &want, "ulid", None, |mut row| {
            let ulid = row.get("ulid").cloned().unwrap_or(Value::Null);
            if count == 0 {
                first = ulid.clone();
            }
            last = ulid;
            count += 1;
            let stored = row.remove("entry_hash");
            let dedupe_key = row.remove("dedupe_key");
            let prev_hash = row.remove("prev_hash");
            match stored {
                Some(Value::String(h)) if !h.is_empty() => {
                    let text = |k: &str| row.get(k).and_then(Value::as_str);
                    let recomputed = ledger::compute_entry_hash(
                        prev_hash.as_ref().and_then(Value::as_str),
                        text("ulid").unwrap_or_default(),
                        text("channel").unwrap_or_default(),
                        text("payload").unwrap_or_default(),
                        text("originator"),
                        text("episode_id"),
                        text("causal_parent_id"),
                        text("created_at").unwrap_or_default(),
                        dedupe_key.as_ref().and_then(Value::as_str),
                    );
                    if recomputed != h {
                        mismatches += 1;
                    }
                    hasher.update(recomputed.as_bytes());
                }
                Some(Value::String(_)) => {
                    // Blank `""` entry_hash is not a NULL legacy prefix row: count it as a
                    // mismatch and fail `chain_ok`, keeping canonical-row rolling-hash parity.
                    mismatches += 1;
                    hasher.update(py_dumps(&Value::Object(row), None).as_bytes());
                }
                None | Some(Value::Null) => {
                    hasher.update(py_dumps(&Value::Object(row), None).as_bytes());
                }
                Some(_) => {
                    mismatches += 1;
                    hasher.update(py_dumps(&Value::Object(row), None).as_bytes());
                }
            }
            hasher.update(b"\n");
            Ok(())
        })?;
    }
    let chain_ok = ledger_ok && mismatches == 0;
    let mut out = Map::new();
    out.insert("chain_ok".into(), json!(chain_ok));
    out.insert("count".into(), json!(count));
    out.insert("entry_hash_mismatches".into(), json!(mismatches));
    out.insert("first_ulid".into(), first);
    out.insert("last_ulid".into(), last);
    out.insert("rolling_hash".into(), json!(hex::encode(hasher.finalize())));
    if !chain_ok {
        if let Some(rep) = ledger_report.as_ref().filter(|r| !r.ok) {
            if let Some(seq) = rep.first_bad_seq {
                out.insert("first_bad_seq".into(), json!(seq));
            }
            if let Some(reason) = &rep.reason {
                out.insert("chain_error".into(), json!(reason));
            }
        } else if mismatches > 0 {
            out.insert("chain_error".into(), json!("entry_hash mismatch"));
        }
    }
    Ok(out)
}

/// Stream one manifest into `out`. Keys are emitted in sorted order, so the
/// hashed text is exactly `py_dumps(payload)`; `generated_at` and
/// `fingerprint` follow, outside the hash.
fn write_manifest(
    c: &Connection,
    source_host: &str,
    since_ulid: Option<&str>,
    reader: &EventReader,
    caps: ManifestCaps,
    out: &mut dyn std::io::Write,
) -> UaResult<ManifestStats> {
    // One read transaction: every table comes from the same snapshot, so a
    // write landing mid-export cannot leave a task without its events.
    let tx = c.unchecked_transaction()?;
    let mut em = Emitter { hasher: Sha256::new(), hashing: true, out, bytes: 0, caps };
    em.put("{")?;

    // event_log: the summary, then the rows after the cursor.
    em.key(true, "event_log")?;
    let summary = event_log_summary(&tx)?;
    em.put("{")?;
    for (i, (k, v)) in summary.iter().enumerate() {
        em.key(i == 0, k)?;
        em.put(&py_dumps(v, None))?;
    }
    if let Some(since) = since_ulid {
        // The listing depends on the cursor, not on the data: it stays out of
        // the fingerprint, so exports of the same data with different
        // cursors compare equal.
        em.hashing = false;
        em.key(false, "rows")?;
        em.array(|item, em| {
            if !has_table(&tx, "event_log")? {
                return Ok(());
            }
            let columns = MANIFEST_EVENT_COLUMNS.join(", ");
            let sql = format!(
                "SELECT {columns}, ({VISIBLE_EVENT}) AS _visible FROM event_log WHERE ulid > ? ORDER BY ulid"
            );
            let bindings = reader.bindings().into_iter().chain([&since as &dyn ToSql]);
            let mut stmt = tx.prepare(&sql)?;
            let mut rows = stmt.query(params_from_iter(bindings))?;
            while let Some(row) = rows.next()? {
                let visible: bool = row.get("_visible")?;
                let mut row = row_map(row)?;
                let listed = if visible {
                    row.remove("_visible");
                    let mut listed = Value::Object(row);
                    label_event_row(&mut listed);
                    listed
                } else {
                    json!({ "ulid": row["ulid"], "entry_hash": row["entry_hash"], "redacted": true })
                };
                item(em, &listed)?;
            }
            Ok(())
        })?;
        em.key(false, "since_ulid")?;
        em.put(&py_dumps(&json!(since), None))?;
        em.hashing = true;
    }
    em.put("}")?;

    em.key(false, "manifest_version")?;
    em.put(&MANIFEST_VERSION.to_string())?;

    em.key(false, "memory")?;
    let mut note_ids: HashSet<String> = HashSet::new();
    em.array(|item, em| {
        for_each_row(&tx, "memory", MANIFEST_MEMORY_COLUMNS, "id", None, |row| {
            let id = row.get("id").and_then(Value::as_str).map(str::to_string);
            if id.as_deref().is_some_and(is_index_id) {
                return Ok(());
            }
            if note_ids.len() >= caps.memory_rows {
                return Err(UaError::invalid(format!(
                    "memory holds more than {} notes, over the manifest memory cap of {} rows",
                    caps.memory_rows, caps.memory_rows
                )));
            }
            // A row without an id still counts toward the cap.
            note_ids.insert(id.unwrap_or_else(|| format!("\0row{}", note_ids.len())));
            item(em, &Value::Object(row))
        })
    })?;
    let memory = note_ids.len();

    for (table, columns, _) in GRAPH_TABLES {
        em.key(false, table)?;
        em.array(|item, em| {
            for_each_row(&tx, table, columns, columns[0], None, |row| {
                let row = Value::Object(row);
                if graph_row_in_notes(&row, &note_ids) { item(em, &row) } else { Ok(()) }
            })
        })?;
    }

    em.key(false, "schema_version")?;
    em.put(&py_dumps(&json!(schema_version_label(&tx)?), None))?;
    em.key(false, "source_host")?;
    em.put(&py_dumps(&json!(source_host), None))?;

    em.key(false, "tasks")?;
    let mut tasks = 0usize;
    em.array(|item, em| {
        for_each_row(&tx, "tasks", MANIFEST_TASK_COLUMNS, "id", None, |row| {
            tasks += 1;
            item(em, &Value::Object(row))
        })
    })?;
    tx.finish()?;

    // The closing brace ends the hashed payload; the written object goes on.
    em.write("}", true, false)?;
    let fingerprint = hex::encode(std::mem::take(&mut em.hasher).finalize());
    em.write(
        &format!(
            ",{}:{},{}:{}}}",
            py_dumps(&json!("fingerprint"), None),
            py_dumps(&json!(fingerprint), None),
            py_dumps(&json!("generated_at"), None),
            py_dumps(&json!(ua_core::time::now()), None),
        ),
        false,
        true,
    )?;
    Ok(ManifestStats { tasks, memory, fingerprint, bytes: em.bytes })
}

fn graph_row_in_notes(row: &Value, note_ids: &HashSet<String>) -> bool {
    let Some(obj) = row.as_object() else { return false };
    for key in ["note_id", "src_id", "dst_id"] {
        if let Some(id) = obj.get(key).and_then(Value::as_str)
            && !note_ids.contains(id)
        {
            return false;
        }
    }
    true
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManifestArgs {
    /// Write `exports/migration-manifest-<UTC>.json` in the workspace. Default false: return the manifest inline.
    pub write_to_vault: Option<bool>,
    /// A ulid: also list the event-log rows after it (`event_log.rows`). The summary always covers the whole log.
    pub events_since_ulid: Option<String>,
}

fn parse_cursor(raw: Option<&str>) -> UaResult<Option<String>> {
    let Some(raw) = raw.map(str::trim) else { return Ok(None) };
    ulid::Ulid::from_string(raw)
        .map(|u| Some(u.to_string()))
        .map_err(|_| UaError::invalid(format!("events_since_ulid must be a ulid, got {raw:?}")))
}

async fn export_migration_manifest(ctx: ToolCtx, a: ManifestArgs) -> UaResult<Value> {
    let source_host = source_host_label(ctx.hub.cfg());
    let since = parse_cursor(a.events_since_ulid.as_deref())?;
    let reader = EventReader::new(ctx.hub.cfg(), &ctx.caller);
    if !a.write_to_vault.unwrap_or(false) {
        let (stats, text) = ctx
            .hub
            .db()
            .read_async(move |c| {
                let mut buf: Vec<u8> = Vec::new();
                let stats = write_manifest(
                    c,
                    &source_host,
                    since.as_deref(),
                    &reader,
                    ManifestCaps::INLINE,
                    &mut buf,
                )?;
                Ok((stats, buf))
            })
            .await?;
        let manifest: Value = serde_json::from_slice(&text)?;
        return Ok(json!({
            "manifest": manifest,
            "fingerprint": stats.fingerprint,
            "rows": stats.tasks + stats.memory,
            "bytes": stats.bytes,
        }));
    }
    // The file is written as the rows are read; the result only points at it.
    let root = export_root(&ctx)?;
    let stamp = jiff::Timestamp::now().strftime("%Y%m%dT%H%M%SZ").to_string();
    let (rel, stats) = ctx
        .hub
        .db()
        .read_async(move |c| {
            let dir = ua_core::safety::resolve_in_root(EXPORT_DIR, std::slice::from_ref(&root), true)?;
            std::fs::create_dir_all(&dir)
                .map_err(|e| UaError::internal(format!("cannot create {EXPORT_DIR}/: {e}")))?;
            let (file, path) = open_exclusive(&dir, &format!("migration-manifest-{stamp}"), "json")?;
            let mut out = std::io::BufWriter::new(file);
            let written =
                write_manifest(c, &source_host, since.as_deref(), &reader, ManifestCaps::FILE, &mut out)
                    .and_then(|stats| {
                        out.write_all(b"\n")
                            .and_then(|_| out.flush())
                            .and_then(|_| out.get_ref().sync_all())
                            .map_err(|e| UaError::internal(format!("export write failed: {e}")))?;
                        Ok(stats)
                    });
            match written {
                Ok(mut stats) => {
                    stats.bytes += 1;
                    let rel = path.strip_prefix(&root).unwrap_or(&path).to_string_lossy().into_owned();
                    Ok((rel, stats))
                }
                Err(e) => {
                    drop(out);
                    let _ = std::fs::remove_file(&path);
                    Err(e)
                }
            }
        })
        .await?;
    let rows = stats.tasks + stats.memory;
    let (by, path, bytes) = (ctx.caller.label.clone(), rel.clone(), stats.bytes);
    ctx.hub
        .db()
        .write_async(move |tx| {
            ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    "agent.export.written",
                    json!({ "kind": "migration-manifest", "path": path, "rows": rows, "bytes": bytes }),
                )
                .by(by),
            )?;
            Ok(())
        })
        .await?;
    Ok(json!({
        "path": rel,
        "rows": rows,
        "bytes": stats.bytes,
        "root": "workspace",
        "fingerprint": stats.fingerprint,
    }))
}

fn object_rows(value: Option<&Value>, what: &str) -> UaResult<Vec<Map<String, Value>>> {
    let Some(value) = value else { return Ok(Vec::new()) };
    let Some(rows) = value.as_array() else {
        return Err(UaError::invalid(format!("{what} must be a list of objects")));
    };
    rows.iter()
        .map(|row| {
            row.as_object().cloned().ok_or_else(|| UaError::invalid(format!("{what} rows must be objects")))
        })
        .collect()
}

fn scalar_id(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn row_key(row: &Map<String, Value>, keys: &[&str]) -> String {
    if keys == ["id"] {
        return scalar_id(row.get("id"));
    }
    let parts = Value::Array(keys.iter().map(|k| row.get(*k).cloned().unwrap_or(Value::Null)).collect());
    py_dumps(&parts, None)
}

fn rows_differ(left: &Map<String, Value>, right: &Map<String, Value>) -> bool {
    let mut keys: Vec<&String> = left.keys().chain(right.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter().any(|k| left.get(k).unwrap_or(&Value::Null) != right.get(k).unwrap_or(&Value::Null))
}

fn content_key(row: &Map<String, Value>, keys: &[&str]) -> String {
    let mut obj = Map::new();
    for key in keys {
        obj.insert((*key).into(), row.get(*key).cloned().unwrap_or(Value::Null));
    }
    manifest_hash(&Value::Object(obj))
}

fn non_empty_str(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn validate_graph(side: &str, payload: &Value) -> UaResult<()> {
    for (table, columns, _) in GRAPH_TABLES {
        let rows = object_rows(payload.get(*table), table)?;
        for row in &rows {
            let required: Vec<&str> = columns.iter().copied().filter(|c| *c != "actor").collect();
            if required.iter().any(|c| !row.get(*c).is_some_and(Value::is_string)) {
                return Err(UaError::invalid(format!(
                    "{side} {table} rows require string fields: {}",
                    required.join(", ")
                )));
            }
            if let Some(actor) = row.get("actor")
                && !actor.is_null()
                && !actor.is_string()
            {
                return Err(UaError::invalid(format!("{side} {table} actor must be a string or null")));
            }
        }
    }
    Ok(())
}

/// Index one side's rows by key, refusing a row without a key and a key seen twice.
fn index_rows<'r>(
    side: &str,
    kind: &str,
    keys: &[&str],
    rows: &'r [Map<String, Value>],
) -> UaResult<BTreeMap<String, &'r Map<String, Value>>> {
    let mut index = BTreeMap::new();
    for row in rows {
        let key = row_key(row, keys);
        if key.is_empty() {
            return Err(UaError::invalid(format!("{side} {kind} rows require an id")));
        }
        if index.insert(key.clone(), row).is_some() {
            let what =
                if keys == ["id"] { format!("duplicate id {key}") } else { "duplicate graph keys".into() };
            return Err(UaError::invalid(format!("{side} {kind} contains {what}")));
        }
    }
    Ok(index)
}

/// The origin a manifest names. Rows are keyed by id, which only identifies
/// a row within one origin.
fn manifest_origin<'m>(side: &str, m: &'m Value) -> UaResult<&'m str> {
    m.get("source_host")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| UaError::invalid(format!("{side} manifest has no source_host")))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompareArgs {
    /// Manifest object from `export_migration_manifest` (the `manifest` field, not the wrapper). Give this or `left_path`.
    pub left: Option<Value>,
    /// Manifest object to compare against `left`. It must come from the same origin (`source_host`). Give this or `right_path`.
    pub right: Option<Value>,
    /// A manifest file your own `export_migration_manifest` wrote under `exports/`, as it returned its `path`.
    pub left_path: Option<String>,
    /// A manifest file your own `export_migration_manifest` wrote, compared against the left side.
    pub right_path: Option<String>,
}

/// Read a manifest file this caller's `export_migration_manifest` wrote. The
/// path must resolve inside `exports/` in the caller's workspace (the sandbox
/// check every workspace read gets), and an `agent.export.written` entry by
/// the same caller must name it: `exports/` is shared by every agent without
/// its own workspace, so being there is not enough. The file is opened
/// without following a symlink and checked through the open handle.
async fn read_export_file(ctx: &ToolCtx, field: &str, path: String) -> UaResult<Value> {
    let root = export_root(ctx)?;
    let field = field.to_string();
    let (f, p) = (field.clone(), path.clone());
    let (resolved, rel) = blocking(move || {
        let roots = std::slice::from_ref(&root);
        let exports = ua_core::safety::resolve_in_root(EXPORT_DIR, roots, false)?;
        let resolved = ua_core::safety::resolve_in_root(&p, roots, false)?;
        if resolved == exports || !resolved.starts_with(&exports) {
            return Err(UaError::denied(
                "outside_exports",
                format!("{f} {p:?} is not a file under {EXPORT_DIR}/ in the workspace"),
            ));
        }
        let rel = resolved.strip_prefix(&root).unwrap_or(&resolved).to_string_lossy().into_owned();
        Ok((resolved, rel))
    })
    .await?;
    let who = ctx.caller.label.clone();
    let recorded: bool = ctx
        .hub
        .db()
        .read_async(move |c| {
            Ok(c.query_row(
                "SELECT EXISTS (SELECT 1 FROM event_log WHERE channel = 'agent.export.written' \
                 AND originator = ?1 AND json_extract(payload, '$.kind') = 'migration-manifest' \
                 AND json_extract(payload, '$.path') = ?2)",
                rusqlite::params![who, rel],
                |r| r.get(0),
            )?)
        })
        .await?;
    if !recorded {
        return Err(UaError::denied(
            "not_your_export",
            format!("{field} {path:?} is not a manifest your export_migration_manifest wrote"),
        ));
    }
    blocking(move || {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = opts.open(&resolved).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => UaError::not_found(format!("{field} {path:?} does not exist")),
            kind => UaError::invalid(format!("cannot open {field} {path:?}: {kind}")),
        })?;
        let meta =
            file.metadata().map_err(|e| UaError::invalid(format!("cannot read {field} {path:?}: {e}")))?;
        if !meta.is_file() {
            return Err(UaError::invalid(format!("{field} {path:?} is not a file")));
        }
        if meta.len() > FILE_MAX_BYTES as u64 {
            return Err(UaError::invalid(format!(
                "{field} {path:?} is over the {FILE_MAX_BYTES} byte file cap"
            )));
        }
        let reader = std::io::BufReader::new(file.take(FILE_MAX_BYTES as u64 + 1));
        serde_json::from_reader(reader)
            .map_err(|e| UaError::invalid(format!("{field} {path:?} is not a JSON manifest: {e}")))
    })
    .await
}

/// One side's manifest: given inline, or read from the caller's exports.
async fn side_manifest(
    ctx: &ToolCtx,
    side: &str,
    inline: Option<Value>,
    path: Option<String>,
) -> UaResult<Value> {
    match (inline, path) {
        (Some(v), None) => Ok(v),
        (None, Some(p)) => read_export_file(ctx, &format!("{side}_path"), p).await,
        (Some(_), Some(_)) => Err(UaError::invalid(format!("give {side} or {side}_path, not both"))),
        (None, None) => Err(UaError::invalid(format!("{side} or {side}_path is required"))),
    }
}

/// One side's event-log summary, checked.
#[derive(Debug)]
struct EventLog {
    count: u64,
    first: Option<String>,
    last: Option<String>,
    rolling_hash: String,
    /// `chain_ok` as the export stated it (absent: not stated).
    chain_ok: Option<bool>,
    first_bad_seq: Option<i64>,
    chain_error: Option<String>,
    /// The cursor and, per ulid listed after it, a hash of the row.
    rows: Option<(String, BTreeMap<String, String>)>,
}

fn opt_str(side: &str, log: &Map<String, Value>, key: &str) -> UaResult<Option<String>> {
    match log.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(UaError::invalid(format!("{side} event_log.{key} must be a string or null"))),
    }
}

fn opt_i64(side: &str, log: &Map<String, Value>, key: &str) -> UaResult<Option<i64>> {
    let Some(v) = log.get(key).filter(|v| !v.is_null()) else { return Ok(None) };
    let Some(n) = v.as_i64() else {
        return Err(UaError::invalid(format!("{side} event_log.{key} must be an integer or null")));
    };
    Ok(Some(n))
}

fn event_log_of(side: &str, m: &Value) -> UaResult<Option<EventLog>> {
    let Some(raw) = m.get("event_log") else { return Ok(None) };
    let Some(log) = raw.as_object() else {
        return Err(UaError::invalid(format!(
            "{side} event_log must be a summary object {{count, first_ulid, last_ulid, rolling_hash}}"
        )));
    };
    let count = log
        .get("count")
        .and_then(Value::as_u64)
        .ok_or_else(|| UaError::invalid(format!("{side} event_log.count must be a non-negative integer")))?;
    let rolling_hash = log
        .get("rolling_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| UaError::invalid(format!("{side} event_log.rolling_hash must be a string")))?
        .to_string();
    let first = opt_str(side, log, "first_ulid")?;
    let last = opt_str(side, log, "last_ulid")?;
    let rows = match (log.get("rows"), opt_str(side, log, "since_ulid")?) {
        (None, None) => None,
        (Some(rows), Some(since)) => {
            let rows = object_rows(Some(rows), &format!("{side} event_log.rows"))?;
            let mut ulids = BTreeMap::new();
            for row in &rows {
                let Some(ulid) = row.get("ulid").and_then(Value::as_str) else {
                    return Err(UaError::invalid(format!("{side} event_log.rows require a ulid")));
                };
                let hash = manifest_hash(&Value::Object(row.clone()));
                if ulids.insert(ulid.to_string(), hash).is_some() {
                    return Err(UaError::invalid(format!(
                        "{side} event_log.rows contains duplicate ulid {ulid}"
                    )));
                }
            }
            Some((since, ulids))
        }
        _ => {
            return Err(UaError::invalid(format!(
                "{side} event_log has rows without since_ulid, or the reverse"
            )));
        }
    };
    let chain_ok = match log.get("chain_ok") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err(UaError::invalid(format!("{side} event_log.chain_ok must be a boolean"))),
    };
    let first_bad_seq = opt_i64(side, log, "first_bad_seq")?;
    let chain_error = opt_str(side, log, "chain_error")?;
    Ok(Some(EventLog { count, first, last, rolling_hash, chain_ok, first_bad_seq, chain_error, rows }))
}

/// Compare the two event-log summaries and, when both sides listed rows,
/// the rows after the later of the two cursors, by ulid.
fn compare_event_logs(
    left: Option<EventLog>,
    right: Option<EventLog>,
    summary: &mut Map<String, Value>,
    conflicts: &mut Vec<Value>,
) {
    let (l, r) = match (left, right) {
        (None, None) => return,
        (Some(l), Some(r)) => (l, r),
        (l, _) => {
            let side = if l.is_none() { "left" } else { "right" };
            summary.insert("event_log".into(), json!({"compared": false}));
            conflicts.push(json!({"kind": "event_log", "side": side, "type": "event_log_missing"}));
            return;
        }
    };
    let count_match = l.count == r.count;
    let range_match = l.first == r.first && l.last == r.last;
    let rolling_hash_match = l.rolling_hash == r.rolling_hash;
    let side = |e: &EventLog| json!({"count": e.count, "first_ulid": e.first, "last_ulid": e.last, "chain_ok": e.chain_ok});
    let mut out = json!({
        "count_match": count_match,
        "range_match": range_match,
        "rolling_hash_match": rolling_hash_match,
        "left": side(&l),
        "right": side(&r),
    });
    let mut rows_differ = false;
    if let (Some((l_since, l_rows)), Some((r_since, r_rows))) = (&l.rows, &r.rows) {
        // Both sides list every row after their own cursor, so compare only
        // the range both cover.
        let since = std::cmp::max(l_since, r_since);
        let after = |rows: &'_ BTreeMap<String, String>| -> BTreeMap<String, String> {
            rows.iter()
                .filter(|(u, _)| u.as_str() > since.as_str())
                .map(|(u, h)| (u.clone(), h.clone()))
                .collect()
        };
        let (l_after, r_after) = (after(l_rows), after(r_rows));
        let left_only = l_after.keys().filter(|u| !r_after.contains_key(*u)).count();
        let right_only = r_after.keys().filter(|u| !l_after.contains_key(*u)).count();
        let both = l_after.keys().filter(|u| r_after.contains_key(*u)).count();
        // The same ulid with other contents: an edited or forged row.
        let content_differs =
            l_after.iter().filter(|(u, h)| r_after.get(*u).is_some_and(|rh| rh != *h)).count();
        rows_differ = left_only + right_only + content_differs > 0;
        out["rows"] = json!({
            "since_ulid": since,
            "left_only": left_only,
            "right_only": right_only,
            "both": both,
            "content_differs": content_differs,
        });
    }
    for (name, e) in [("left", &l), ("right", &r)] {
        if e.chain_ok == Some(false) {
            let mut conflict = json!({"kind": "event_log", "side": name, "type": "event_log_chain_broken"});
            if let Some(seq) = e.first_bad_seq {
                conflict["first_bad_seq"] = json!(seq);
            }
            if let Some(err) = &e.chain_error {
                conflict["chain_error"] = json!(err);
            }
            conflicts.push(conflict);
        }
    }
    if !(count_match && range_match && rolling_hash_match) || rows_differ {
        conflicts.push(json!({
            "kind": "event_log",
            "type": "event_log_mismatch",
            "count_match": count_match,
            "range_match": range_match,
            "rolling_hash_match": rolling_hash_match,
        }));
    }
    summary.insert("event_log".into(), out);
}

fn compare_kind(
    kind: &str,
    keys: &[&str],
    left_index: &BTreeMap<String, &Map<String, Value>>,
    right_index: &BTreeMap<String, &Map<String, Value>>,
    summary: &mut Map<String, Value>,
    conflicts: &mut Vec<Value>,
) {
    let only_left: Vec<&String> = left_index.keys().filter(|id| !right_index.contains_key(*id)).collect();
    let only_right: Vec<&String> = right_index.keys().filter(|id| !left_index.contains_key(*id)).collect();
    let changed: Vec<&String> = left_index
        .keys()
        .filter(|id| right_index.get(*id).is_some_and(|right| rows_differ(left_index[*id], right)))
        .collect();
    let shared = left_index.keys().filter(|id| right_index.contains_key(*id)).count();
    let same = shared - changed.len();
    summary.insert(
        kind.into(),
        json!({
            "left_only": only_left.len(),
            "right_only": only_right.len(),
            "changed": changed.len(),
            "same": same,
        }),
    );
    let graph = keys != ["id"];
    for id in &changed {
        let mut conflict = json!({"kind": kind, "id": id, "type": "conflicting_edit"});
        if kind == "tasks" {
            let left_claim = non_empty_str(left_index[*id].get("claimed_by"));
            let right_claim = non_empty_str(right_index[*id].get("claimed_by"));
            if left_claim != right_claim {
                conflict["type"] = json!("active_claim_conflict");
                conflict["left_claimed_by"] = json!(left_claim);
                conflict["right_claimed_by"] = json!(right_claim);
            }
        }
        conflicts.push(conflict);
    }
    for id in &only_left {
        conflicts.push(json!({"kind": kind, "id": id, "type": "left_only"}));
    }
    for id in &only_right {
        conflicts.push(json!({"kind": kind, "id": id, "type": "right_only"}));
    }
    if graph {
        return;
    }
    let content_keys: &[&str] = if kind == "tasks" { &["title", "notes"] } else { &["title", "content"] };
    let mut by_content: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (id, row) in left_index.iter().chain(right_index.iter()) {
        by_content.entry(content_key(row, content_keys)).or_default().push(id.clone());
    }
    for mut ids in by_content.into_values() {
        ids.sort();
        ids.dedup();
        if ids.len() > 1 {
            conflicts.push(json!({"kind": kind, "ids": ids, "type": "duplicate_candidate"}));
        }
    }
}

/// Tasks whose `parent_id` names a task that is not in the same manifest.
fn missing_parents(side: &str, tasks: &BTreeMap<String, &Map<String, Value>>, conflicts: &mut Vec<Value>) {
    for (id, row) in tasks {
        let parent = scalar_id(row.get("parent_id"));
        if !parent.is_empty() && !tasks.contains_key(&parent) {
            conflicts.push(json!({"kind": "tasks", "id": id, "side": side, "parent_id": parent, "type": "missing_parent"}));
        }
    }
}

async fn compare_migration_manifests(ctx: ToolCtx, a: CompareArgs) -> UaResult<Value> {
    let left = side_manifest(&ctx, "left", a.left, a.left_path).await?;
    let right = side_manifest(&ctx, "right", a.right, a.right_path).await?;
    compare_manifests(&left, &right)
}

fn compare_manifests(left_m: &Value, right_m: &Value) -> UaResult<Value> {
    let (Some(left), Some(right)) = (left_m.as_object(), right_m.as_object()) else {
        return Err(UaError::invalid("left and right must be manifest objects"));
    };
    let version = json!(MANIFEST_VERSION);
    for (side, m) in [("left", left), ("right", right)] {
        if m.get("manifest_version") != Some(&version) {
            return Err(UaError::invalid(format!(
                "unsupported migration manifest version on the {side} side: {}; this hub compares version \
                 {MANIFEST_VERSION} manifests (re-export older ones)",
                m.get("manifest_version").unwrap_or(&Value::Null)
            )));
        }
    }
    let (left_origin, right_origin) = (manifest_origin("left", left_m)?, manifest_origin("right", right_m)?);
    if left_origin != right_origin {
        return Err(UaError::invalid(format!(
            "the manifests come from different origins ({left_origin:?} and {right_origin:?}); rows are keyed by \
             id, which only identifies a row within one origin"
        )));
    }
    validate_graph("left", left_m)?;
    validate_graph("right", right_m)?;
    let (left_log, right_log) = (event_log_of("left", left_m)?, event_log_of("right", right_m)?);

    // The stated fingerprints are not trusted: recompute both from the payloads.
    let left_fingerprint = manifest_fingerprint(left);
    let right_fingerprint = manifest_fingerprint(right);
    let mut conflicts = Vec::new();
    for (side, m, recomputed) in [("left", left, &left_fingerprint), ("right", right, &right_fingerprint)] {
        if let Some(stated) = m.get("fingerprint")
            && stated.as_str() != Some(recomputed.as_str())
        {
            conflicts.push(json!({"side": side, "stated": stated, "recomputed": recomputed, "type": "fingerprint_mismatch"}));
        }
    }

    let mut summary = Map::new();
    let mut kinds = vec![("tasks", &["id"][..]), ("memory", &["id"][..])];
    for (name, _, keys) in GRAPH_TABLES {
        kinds.push((name, keys));
    }
    for (kind, keys) in kinds {
        let left_rows = object_rows(left_m.get(kind), kind)?;
        let right_rows = object_rows(right_m.get(kind), kind)?;
        let left_index = index_rows("left", kind, keys, &left_rows)?;
        let right_index = index_rows("right", kind, keys, &right_rows)?;
        compare_kind(kind, keys, &left_index, &right_index, &mut summary, &mut conflicts);
        if kind == "tasks" {
            missing_parents("left", &left_index, &mut conflicts);
            missing_parents("right", &right_index, &mut conflicts);
        }
    }
    compare_event_logs(left_log, right_log, &mut summary, &mut conflicts);
    let same = left_fingerprint == right_fingerprint && conflicts.is_empty();
    Ok(json!({
        "source_host": left_origin,
        "left_fingerprint": left_fingerprint,
        "right_fingerprint": right_fingerprint,
        "same": same,
        "summary": summary,
        "requires_human_disposition": !conflicts.is_empty(),
        "conflicts": conflicts,
    }))
}

// ---------------------------------------------------------------------------
// export_data

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DataArgs {
    /// tasks, memory, journal, manifest or compare (the last two need a profile that may call
    /// export_migration_manifest / compare_migration_manifests). Import and rollback are not available.
    pub action: String,
    /// The action's arguments, as for export_tasks / export_memory / export_journal.
    pub params: Option<Value>,
}

/// The registry `export_data` hands its manifest actions to.
fn inner_registry() -> &'static Registry {
    static REG: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();
    REG.get_or_init(crate::builtin_registry)
}

fn inner_params(params: Option<Value>) -> Value {
    match params {
        None | Some(Value::Null) => json!({}),
        Some(v) => v,
    }
}

async fn export_data(ctx: ToolCtx, a: DataArgs) -> UaResult<Value> {
    let action = crate::routes::action_of("export_data", Some(&a.action))?;
    match action {
        "tasks" | "export_tasks" => export_tasks(ctx, parse_params("export", action, a.params)?).await,
        "memory" | "export_memory" => export_memory(ctx, parse_params("export", action, a.params)?).await,
        "journal" | "export_journal" => export_journal(ctx, parse_params("export", action, a.params)?).await,
        // A full governed call under the inner tool's name: its profile entry,
        // policy rules, approval_tools and grants apply, not export_data's.
        "manifest" | "export_migration_manifest" => {
            inner_registry()
                .call(&ctx.hub, &ctx.caller, "export_migration_manifest", inner_params(a.params))
                .await
        }
        "compare" | "compare_migration_manifests" => {
            inner_registry()
                .call(&ctx.hub, &ctx.caller, "compare_migration_manifests", inner_params(a.params))
                .await
        }
        "import" | "rollback" => Err(UaError::invalid(format!(
            "export action {action:?} is not available: migration import and rollback are not implemented"
        ))),
        other => Err(crate::routes::unhandled("export_data", other)),
    }
}

// ---------------------------------------------------------------------------
// Registration.

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "export_tasks",
            "Export tasks as csv (RFC 4180), json or markdown. status is one status or all; project restricts \
             to one stream. write_to_vault (default true) writes exports/tasks-<UTC>.<ext> in the workspace and \
             returns {path, rows, bytes}; false returns {content, rows}. Inline cap 2 MB; file cap 32 MB.",
            export_tasks,
        )
        .family("export"),
    );
    r.add(
        tool(
            "export_memory",
            "Export memory notes as jsonl or json. Index notes are excluded; superseded notes are included and \
             flagged. Optional tag and since (ISO date) filters. write_to_vault (default true) writes a file under \
             exports/ in the workspace; false returns it inline. Inline cap 2 MB; file cap 32 MB.",
            export_memory,
        )
        .family("export"),
    );
    r.add(
        tool(
            "export_journal",
            "Export vault journal lines (`- **HH:MM** [Agent] text #tags`) from Logs/YYYY-MM-DD.md and every \
             Logs/<machine>/ folder as jsonl, each row tagged with machine. Optional agent and since filters. \
             write_to_vault (default true) writes a file under exports/ in the workspace. Needs UA_VAULT_PATH.",
            export_journal,
        )
        .family("export"),
    );
    r.add(
        tool(
            "export_data",
            "Consolidated export entry point: action tasks, memory, journal, manifest or compare with that \
             tool's arguments in `params`. Import and rollback are not available.",
            export_data,
        )
        .family("export"),
    );
    r.add(
        tool(
            "export_migration_manifest",
            "Read-only migration snapshot of tasks, memory notes and memory graph rows when those tables \
             exist, read in one transaction. The event log is summarised as {chain_ok, count, \
             entry_hash_mismatches, first_ulid, last_ulid, rolling_hash}: chain_ok covers seq-order prev_hash \
             linkage from genesis and zero entry-hash mismatches, plus a legacy unhashed prefix whose length \
             must match the length the import recorded in ledger_meta (stores imported before that record \
             existed report false, as event_log_verify does); each row's entry hash is recomputed \
             from its contents, and the rolling hash is SHA-256 over the ulid-ordered recomputed hashes (the \
             canonical row where a row has none). When chain_ok is false, first_bad_seq (when available) \
             and chain_error report where and why the chain broke (omitted on healthy logs). The summary has \
             no anchor: compare against an earlier \
             manifest to detect a truncated or rewritten tail. events_since_ulid also lists the rows after that ulid, with \
             client evidence (sdk. channels) carrying a trust label. Restricted message, session-handoff and \
             conversation-handoff rows contain \
             only their ULID, stored entry hash, and a redacted flag — the accepted integrity exception \
             that keeps the chain checkable without revealing the rows. Row comparisons compare the \
             listed views. The listing and cursor are outside \
             the fingerprint. Stable ids, claims, source hosts and provenance are preserved. \
             The manifest's origin is the `source_host` config value (default `local`). Does not import, \
             rewrite or delete anything. The manifest is streamed and refused as soon as it would pass a cap: \
             2 MB inline, 32 MB as a file, 50000 memory notes. write_to_vault (default false) writes \
             exports/migration-manifest-<UTC>.json in the workspace and returns {path, rows, bytes, \
             fingerprint}; otherwise returns {manifest, fingerprint, rows, bytes}. Fingerprint is SHA-256 of \
             the canonical payload and excludes generated_at. Coordinator profile only.",
            export_migration_manifest,
        )
        .family("export"),
    );
    r.add(
        tool(
            "compare_migration_manifests",
            "Diff two migration manifests (version 2) from the same origin (`source_host`); rows are keyed \
             by id. Each side is an inline manifest (left / right) or a file your own export_migration_manifest \
             wrote under exports/ (left_path / right_path, as it returned the path; the ledger must record it \
             as yours); other paths are refused. \
             Reports left-only, right-only and changed rows, claim conflicts, duplicate title/body candidates, \
             tasks whose parent is missing on either side, stated fingerprints that do not match the payload, \
             whether the event-log count, ulid range and rolling hash match, a side whose chain_ok is false, \
             and, when both exports used events_since_ulid, left-only, right-only and content-differs counts \
             by ulid after the later cursor. Refuses duplicate ids. \
             Fingerprints are recomputed; `same` needs equal fingerprints and no conflicts. Does not change \
             either source or the local database. Returns {same, summary, conflicts, \
             requires_human_disposition}. Coordinator profile only.",
            compare_migration_manifests,
        )
        .family("export")
        .read_only(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ua_core::{Caller, Config, identity::Transport};

    /// Minimal manifest DB using the real ledger and ledger_meta schemas.
    fn db() -> Connection {
        let mut c = Connection::open_in_memory().unwrap();
        ua_store::schema::apply::<ua_store::schema::Part>(
            &mut c,
            &[
                ledger::SCHEMA.into(),
                ledger::META_SCHEMA.into(),
                ua_store::org::STORE_PART.into(),
                super::super::messaging::SCHEMA.into(),
            ],
        )
        .unwrap();
        c.execute_batch(
            "INSERT INTO schema_parts (name, checksum, applied_at)
             VALUES ('core.v1', 'test', '2026-01-01T00:00:00+00:00');
             CREATE TABLE tasks (id INTEGER PRIMARY KEY, title TEXT, claimed_by TEXT, next_owner TEXT);
             CREATE TABLE memory (id TEXT PRIMARY KEY, title TEXT, content TEXT);
             -- The columns VISIBLE_EVENT joins on, minimal versions of the
             -- real tables.
             CREATE TABLE session_handoff_notes (id INTEGER PRIMARY KEY, agent TEXT,
                 assigned_to TEXT, delivered_to TEXT);
             CREATE TABLE agent_sessions (id TEXT PRIMARY KEY, agent TEXT);",
        )
        .unwrap();
        c
    }

    fn insert_chained(c: &Connection, rows: &[(&str, &str, &str, &str)], prev_start: &str) -> Vec<String> {
        let mut prev = prev_start.to_string();
        let mut hashes = Vec::with_capacity(rows.len());
        for &(ulid, channel, payload, ts) in rows {
            let h =
                ledger::compute_entry_hash(Some(&prev), ulid, channel, payload, None, None, None, ts, None);
            c.execute(
                "INSERT INTO event_log (ulid, channel, payload, created_at, prev_hash, entry_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![ulid, channel, payload, ts, prev, h],
            )
            .unwrap();
            prev = h.clone();
            hashes.push(h);
        }
        hashes
    }

    fn caps(bytes: usize, memory_rows: usize) -> ManifestCaps {
        ManifestCaps { bytes, kind: "test", memory_rows }
    }

    fn reader() -> EventReader {
        EventReader::new(&Config::default(), &Caller::local("local", Transport::Stdio))
    }

    #[test]
    fn the_memory_cap_is_named_when_exceeded() {
        let c = db();
        for id in ["masterindex", "n1", "n2", "n3"] {
            c.execute("INSERT INTO memory VALUES (?1, 't', 'c')", [id]).unwrap();
        }
        let mut out = Vec::new();
        let err =
            write_manifest(&c, "local", None, &reader(), caps(1 << 20, 2), &mut out).unwrap_err().to_string();
        assert!(err.contains("memory cap of 2 rows"), "{err}");
        // Index notes do not count: three real notes fit a cap of three.
        let mut out = Vec::new();
        let stats = write_manifest(&c, "local", None, &reader(), caps(1 << 20, 3), &mut out).unwrap();
        assert_eq!(stats.memory, 3);
    }

    #[test]
    fn the_byte_cap_stops_the_build_before_it_is_passed() {
        let c = db();
        let title = "x".repeat(1000);
        for _ in 0..2000 {
            c.execute("INSERT INTO tasks (title) VALUES (?1)", [&title]).unwrap();
        }
        let mut out = Vec::new();
        let err =
            write_manifest(&c, "local", None, &reader(), caps(10_000, 10), &mut out).unwrap_err().to_string();
        assert!(err.contains("over the 10000 byte test cap"), "{err}");
        // Nothing past the cap was produced: about 2 MB of tasks were never serialised.
        assert!(out.len() <= 10_000, "{}", out.len());
    }

    #[test]
    fn the_streamed_manifest_matches_its_fingerprint_and_rolling_hash() {
        let c = db();
        c.execute("INSERT INTO tasks (title) VALUES ('caf\u{e9}')", []).unwrap();
        c.execute("INSERT INTO memory VALUES ('n1', 'note', 'body')", []).unwrap();
        let good = ledger::compute_entry_hash(
            Some(ledger::GENESIS_HASH),
            "01B",
            "agent.x",
            "{}",
            None,
            None,
            None,
            "t1",
            None,
        );
        c.execute(
            "INSERT INTO event_log (ulid, channel, payload, created_at, prev_hash, entry_hash) VALUES
             ('01A', 'legacy', '{}', 't0', NULL, NULL),
             ('01B', 'agent.x', '{}', 't1', ?1, ?2)",
            rusqlite::params![ledger::GENESIS_HASH, &good],
        )
        .unwrap();
        c.execute("INSERT INTO ledger_meta (key, value) VALUES (?1, '1')", [ledger::LEGACY_PREFIX_KEY])
            .unwrap();
        let mut out = Vec::new();
        let stats = write_manifest(&c, "hub-a", Some("01A"), &reader(), caps(1 << 20, 10), &mut out).unwrap();
        assert_eq!(stats.bytes, out.len());
        let parsed: Value = serde_json::from_slice(&out).unwrap();
        let m = parsed.as_object().unwrap();
        assert_eq!(manifest_fingerprint(m), stats.fingerprint);
        assert_eq!(m["fingerprint"], json!(stats.fingerprint));
        let log = &m["event_log"];
        assert_eq!(log["count"], 2);
        assert_eq!(log["first_ulid"], "01A");
        assert_eq!(log["last_ulid"], "01B");
        assert_eq!(log["chain_ok"], true);
        // The unhashed legacy row is hashed as its canonical JSON, the other by its recomputed hash.
        let legacy = json!({
            "ulid": "01A",
            "channel": "legacy",
            "payload": "{}",
            "originator": null,
            "episode_id": null,
            "causal_parent_id": null,
            "created_at": "t0",
        });
        let expected =
            hex::encode(Sha256::digest(format!("{}\n{good}\n", py_dumps(&legacy, None)).as_bytes()));
        assert_eq!(log["rolling_hash"], expected);
        assert_eq!(log["rows"].as_array().unwrap().len(), 1);
        assert_eq!(log["rows"][0]["ulid"], "01B");

        // The cursor listing is outside the fingerprint.
        let mut plain = Vec::new();
        let without = write_manifest(&c, "hub-a", None, &reader(), caps(1 << 20, 10), &mut plain).unwrap();
        assert_eq!(without.fingerprint, stats.fingerprint);
    }

    #[test]
    fn a_tampered_payload_under_its_old_entry_hash_is_reported() {
        let c = db();
        let hash = ledger::compute_entry_hash(
            Some(ledger::GENESIS_HASH),
            "01B",
            "agent.x",
            "{\"n\":1}",
            None,
            None,
            None,
            "t1",
            None,
        );
        c.execute(
            "INSERT INTO event_log (ulid, channel, payload, created_at, prev_hash, entry_hash)
             VALUES ('01B', 'agent.x', '{\"n\":1}', 't1', ?1, ?2)",
            rusqlite::params![ledger::GENESIS_HASH, &hash],
        )
        .unwrap();
        let summary = |c: &Connection| event_log_summary(c).unwrap();
        let before = summary(&c);
        assert_eq!(before["chain_ok"], true);
        assert_eq!(before["entry_hash_mismatches"], 0);
        assert!(before.get("first_bad_seq").is_none());
        assert!(before.get("chain_error").is_none());
        // Rewrite the payload and keep the stored entry_hash.
        c.execute_batch("DROP TRIGGER event_log_no_update;").unwrap();
        c.execute("UPDATE event_log SET payload = '{\"n\":2}' WHERE ulid = '01B'", []).unwrap();
        let after = summary(&c);
        assert_eq!(after["chain_ok"], false);
        assert_eq!(after["entry_hash_mismatches"], 1);
        assert_eq!(after["first_bad_seq"], 1);
        assert!(after["chain_error"].as_str().is_some_and(|s| s.contains("entry_hash")));
        assert_ne!(after["rolling_hash"], before["rolling_hash"]);
        assert_eq!(after["count"], before["count"]);
    }

    #[test]
    fn missing_event_log_summarises_gracefully() {
        let c = Connection::open_in_memory().unwrap();
        let s = event_log_summary(&c).unwrap();
        let mut keys: Vec<&str> = s.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["chain_ok", "count", "entry_hash_mismatches", "first_ulid", "last_ulid", "rolling_hash"]
        );
        assert_eq!(s["chain_ok"], true);
        assert_eq!(s["count"], 0);
        assert_eq!(s["entry_hash_mismatches"], 0);
        assert_eq!(s["first_ulid"], Value::Null);
        assert_eq!(s["last_ulid"], Value::Null);
        assert_eq!(s["rolling_hash"], hex::encode(Sha256::digest(b"")));
    }

    #[test]
    fn deleted_middle_row_breaks_chain_ok() {
        let c = db();
        insert_chained(
            &c,
            &[("01A", "a", "{}", "t0"), ("01B", "b", "{}", "t1"), ("01C", "c", "{}", "t2")],
            ledger::GENESIS_HASH,
        );
        assert_eq!(event_log_summary(&c).unwrap()["chain_ok"], true);
        c.execute_batch("DROP TRIGGER event_log_no_delete;").unwrap();
        c.execute("DELETE FROM event_log WHERE ulid = '01B'", []).unwrap();
        let s = event_log_summary(&c).unwrap();
        assert_eq!(s["chain_ok"], false);
        assert_eq!(s["entry_hash_mismatches"], 0);
        assert_eq!(s["count"], 2);
        assert_eq!(s["first_bad_seq"], 3);
        assert!(s["chain_error"].as_str().is_some_and(|m| m.contains("prev_hash")));
    }

    #[test]
    fn seq_inversion_breaks_chain_ok_but_ulid_inversion_does_not() {
        // Case 1: ulid order is valid, but seq order is inverted (ledger::verify fails).
        let c = db();
        let h1 = ledger::compute_entry_hash(
            Some(ledger::GENESIS_HASH),
            "01A",
            "a",
            "{}",
            None,
            None,
            None,
            "t0",
            None,
        );
        let h2 = ledger::compute_entry_hash(Some(&h1), "01B", "b", "{}", None, None, None, "t1", None);
        c.execute(
            "INSERT INTO event_log (seq, ulid, channel, payload, created_at, prev_hash, entry_hash)
             VALUES (1, '01B', 'b', '{}', 't1', ?1, ?2), (2, '01A', 'a', '{}', 't0', ?3, ?1)",
            rusqlite::params![&h1, &h2, ledger::GENESIS_HASH],
        )
        .unwrap();
        let s = event_log_summary(&c).unwrap();
        assert_eq!(s["chain_ok"], false);
        assert_eq!(s["entry_hash_mismatches"], 0);

        // Case 2: seq order is valid (ledger::verify passes), but ulid order is inverted.
        // The Python hub minted ULIDs outside the write lock, so an inverted ulid order is
        // not a broken chain: only seq order carries linkage.
        let c = db();
        let h1 = ledger::compute_entry_hash(
            Some(ledger::GENESIS_HASH),
            "01B",
            "a",
            "{}",
            None,
            None,
            None,
            "t0",
            None,
        );
        let h2 = ledger::compute_entry_hash(Some(&h1), "01A", "b", "{}", None, None, None, "t1", None);
        c.execute(
            "INSERT INTO event_log (seq, ulid, channel, payload, created_at, prev_hash, entry_hash)
             VALUES (1, '01B', 'a', '{}', 't0', ?1, ?2), (2, '01A', 'b', '{}', 't1', ?2, ?3)",
            rusqlite::params![ledger::GENESIS_HASH, &h1, &h2],
        )
        .unwrap();
        assert!(ledger::verify(&c).unwrap().ok);
        let s = event_log_summary(&c).unwrap();
        assert_eq!(s["chain_ok"], true);
        assert_eq!(s["entry_hash_mismatches"], 0);
    }

    #[test]
    fn hashless_row_after_hashed_row_breaks_chain_ok() {
        // Case 1: unhashed row appears in the middle (caught by both seq and ulid checks).
        let c = db();
        let h1 = ledger::compute_entry_hash(
            Some(ledger::GENESIS_HASH),
            "01A",
            "a",
            "{}",
            None,
            None,
            None,
            "t0",
            None,
        );
        let h3 = ledger::compute_entry_hash(Some(&h1), "01C", "c", "{}", None, None, None, "t2", None);
        c.execute(
            "INSERT INTO event_log (seq, ulid, channel, payload, created_at, prev_hash, entry_hash)
             VALUES (1, '01A', 'a', '{}', 't0', ?1, ?2),
                    (2, '01B', 'b', '{}', 't1', NULL, NULL),
                    (3, '01C', 'c', '{}', 't2', ?2, ?3)",
            rusqlite::params![ledger::GENESIS_HASH, &h1, &h3],
        )
        .unwrap();
        let s = event_log_summary(&c).unwrap();
        assert_eq!(s["chain_ok"], false);
        assert_eq!(s["entry_hash_mismatches"], 0);
    }

    #[test]
    fn legacy_prefix_row_with_a_later_ulid_is_ok() {
        // seq=1 is a NULL legacy prefix (ledger::verify passes), but its ulid '01Z'
        // sorts after seq=2's hashed '01A'. Ulid order is not checked for linkage.
        let c = db();
        let h = ledger::compute_entry_hash(
            Some(ledger::GENESIS_HASH),
            "01A",
            "a",
            "{}",
            None,
            None,
            None,
            "t1",
            None,
        );
        c.execute(
            "INSERT INTO event_log (seq, ulid, channel, payload, created_at, prev_hash, entry_hash)
             VALUES (1, '01Z', 'legacy', '{}', 't0', NULL, NULL),
                    (2, '01A', 'a', '{}', 't1', ?1, ?2)",
            rusqlite::params![ledger::GENESIS_HASH, &h],
        )
        .unwrap();
        c.execute("INSERT INTO ledger_meta (key, value) VALUES (?1, '1')", [ledger::LEGACY_PREFIX_KEY])
            .unwrap();
        assert!(ledger::verify(&c).unwrap().ok);
        let s = event_log_summary(&c).unwrap();
        assert_eq!(s["chain_ok"], true);
        assert_eq!(s["entry_hash_mismatches"], 0);
    }

    #[test]
    fn deleted_first_hashed_row_breaks_chain_ok() {
        let c = db();
        insert_chained(
            &c,
            &[("01A", "a", "{}", "t0"), ("01B", "b", "{}", "t1"), ("01C", "c", "{}", "t2")],
            ledger::GENESIS_HASH,
        );
        assert_eq!(event_log_summary(&c).unwrap()["chain_ok"], true);
        c.execute_batch("DROP TRIGGER event_log_no_delete;").unwrap();
        c.execute("DELETE FROM event_log WHERE ulid = '01A'", []).unwrap();
        let s = event_log_summary(&c).unwrap();
        assert_eq!(s["chain_ok"], false);
        assert_eq!(s["entry_hash_mismatches"], 0);
    }

    #[test]
    fn truncated_or_rewritten_tail_keeps_chain_ok_without_an_anchor() {
        // The summary records count, the ulid range and the rolling hash, not the head
        // entry_hash, so chain_ok alone cannot see a missing or rewritten tail; only
        // comparing the summary against an earlier manifest catches it.
        let c = db();
        let hashes = insert_chained(
            &c,
            &[("01A", "a", "{}", "t0"), ("01B", "b", "{}", "t1"), ("01C", "c", "{}", "t2")],
            ledger::GENESIS_HASH,
        );
        let before = event_log_summary(&c).unwrap();
        assert_eq!(before["chain_ok"], true);

        // A truncated tail.
        c.execute_batch("DROP TRIGGER event_log_no_delete;").unwrap();
        c.execute("DELETE FROM event_log WHERE ulid = '01C'", []).unwrap();
        let truncated = event_log_summary(&c).unwrap();
        assert_eq!(truncated["chain_ok"], true);
        assert_eq!(truncated["count"], 2);
        assert_eq!(truncated["last_ulid"], "01B");
        assert_ne!(truncated["rolling_hash"], before["rolling_hash"]);

        // A rewritten tail: a different valid row chained from 01B's entry_hash.
        insert_chained(&c, &[("01D", "d", "{}", "t3")], &hashes[1]);
        let rewritten = event_log_summary(&c).unwrap();
        assert_eq!(rewritten["chain_ok"], true);
        assert_ne!(rewritten["rolling_hash"], before["rolling_hash"]);
    }

    #[test]
    fn blank_entry_hash_increments_mismatches_and_keeps_rolling_hash_parity() {
        let c = db();
        c.execute(
            "INSERT INTO event_log (ulid, channel, payload, created_at, prev_hash, entry_hash)
             VALUES ('01A', 'agent.x', '{}', 't0', ?1, '')",
            [ledger::GENESIS_HASH],
        )
        .unwrap();
        let s = event_log_summary(&c).unwrap();
        assert_eq!(s["chain_ok"], false);
        assert_eq!(s["entry_hash_mismatches"], 1);
        let row = json!({
            "ulid": "01A",
            "channel": "agent.x",
            "payload": "{}",
            "originator": null,
            "episode_id": null,
            "causal_parent_id": null,
            "created_at": "t0",
        });
        let expected = hex::encode(Sha256::digest(format!("{}\n", py_dumps(&row, None)).as_bytes()));
        assert_eq!(s["rolling_hash"], expected);
    }

    #[test]
    fn unrecorded_vs_recorded_legacy_prefix() {
        let c = db();
        c.execute(
            "INSERT INTO event_log (ulid, channel, payload, created_at, prev_hash, entry_hash)
             VALUES ('01A', 'legacy', '{}', 't0', NULL, NULL),
                    ('01B', 'legacy', '{}', 't1', NULL, NULL)",
            [],
        )
        .unwrap();
        insert_chained(&c, &[("01C", "a", "{}", "t2"), ("01D", "b", "{}", "t3")], ledger::GENESIS_HASH);
        let unrecorded = event_log_summary(&c).unwrap();
        assert_eq!(unrecorded["chain_ok"], false);
        assert_eq!(unrecorded["entry_hash_mismatches"], 0);
        assert_eq!(unrecorded["first_bad_seq"], 1);
        assert!(unrecorded["chain_error"].as_str().is_some_and(|s| s.contains("legacy prefix")));

        c.execute("INSERT INTO ledger_meta (key, value) VALUES (?1, '2')", [ledger::LEGACY_PREFIX_KEY])
            .unwrap();
        let recorded = event_log_summary(&c).unwrap();
        assert_eq!(recorded["chain_ok"], true);
        assert_eq!(recorded["entry_hash_mismatches"], 0);
        assert_eq!(recorded["count"], 4);
        assert!(recorded.get("first_bad_seq").is_none());
        assert!(recorded.get("chain_error").is_none());
    }

    #[test]
    fn event_log_of_validates_break_fields_and_missing_legacy_prefix_omits_first_bad_seq() {
        let c = db();
        insert_chained(&c, &[("01A", "a", "{}", "t0")], ledger::GENESIS_HASH);
        c.execute("INSERT INTO ledger_meta (key, value) VALUES (?1, '2')", [ledger::LEGACY_PREFIX_KEY])
            .unwrap();
        let s = event_log_summary(&c).unwrap();
        assert_eq!(s["chain_ok"], false);
        assert!(s.get("first_bad_seq").is_none());
        assert!(s["chain_error"].as_str().is_some_and(|m| m.contains("legacy prefix")));

        let base = json!({
            "event_log": {
                "count": 1,
                "first_ulid": "01A",
                "last_ulid": "01A",
                "rolling_hash": "0".repeat(64),
                "chain_ok": false,
                "first_bad_seq": null,
                "chain_error": null,
            }
        });
        let parsed = event_log_of("left", &base).unwrap().unwrap();
        assert_eq!(parsed.first_bad_seq, None);
        assert_eq!(parsed.chain_error, None);

        let mut bad_seq = base.clone();
        bad_seq["event_log"]["first_bad_seq"] = json!("not-an-int");
        assert!(event_log_of("left", &bad_seq).unwrap_err().to_string().contains("first_bad_seq"));

        let mut bad_float = base.clone();
        bad_float["event_log"]["first_bad_seq"] = json!(1.5);
        assert!(event_log_of("left", &bad_float).unwrap_err().to_string().contains("first_bad_seq"));

        let mut bad_err = base;
        bad_err["event_log"]["chain_error"] = json!(42);
        assert!(event_log_of("right", &bad_err).unwrap_err().to_string().contains("chain_error"));
    }
}

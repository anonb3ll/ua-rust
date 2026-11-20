//! Structured exports: tasks, memory notes and vault journal lines.
//!
//! Tools: `export_tasks`, `export_memory`, `export_journal`, the read-only
//! migration manifest (`export_migration_manifest`, `compare_migration_manifests`)
//! and the consolidated `export_data(action, params)`. Import and rollback are
//! not implemented.
//!
//! An export is returned inline (capped at 2 MB) or, with
//! `write_to_vault=true` (the default, kept for compatibility), written as a
//! new file under `exports/` in the caller's workspace (capped at 32 MB). The
//! file name carries a UTC timestamp and a counter, and is created exclusively
//! so concurrent exports never overwrite each other. Writes are recorded on
//! `agent.export.written`. No redaction: review an export before sharing it.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, params_from_iter};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

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

fn create_exclusive(dir: &Path, stem: &str, ext: &str, data: &[u8]) -> UaResult<PathBuf> {
    for n in 1..=NAME_ATTEMPTS {
        let name = if n == 1 { format!("{stem}.{ext}") } else { format!("{stem}-{n}.{ext}") };
        let path = dir.join(name);
        let mut f = match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(UaError::internal(format!("cannot create the export file: {e}"))),
        };
        let written = f.write_all(data).and_then(|_| f.sync_all());
        if let Err(e) = written {
            let _ = std::fs::remove_file(&path);
            return Err(UaError::internal(format!("export write failed: {e}")));
        }
        return Ok(path);
    }
    Err(UaError::conflict("could not claim a free export name; retry in a second"))
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
const MANIFEST_EVENT_COLUMNS: &[&str] =
    &["ulid", "channel", "payload", "originator", "episode_id", "causal_parent_id", "created_at"];
/// Columns, then the composite key. `actor` may be null; the other link fields may not.
const GRAPH_TABLES: &[(&str, &[&str], &[&str])] = &[
    ("memory_entities", &["note_id", "kind", "value"], &["note_id", "kind", "value"]),
    ("memory_links", &["src_id", "dst_id", "rel", "actor", "created_at"], &["src_id", "dst_id", "rel"]),
];
/// Manifest fields outside the fingerprinted payload.
const UNHASHED_FIELDS: [&str; 2] = ["generated_at", "fingerprint"];

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

fn manifest_rows(c: &Connection, table: &str, want: &[&str], order_by: &str) -> UaResult<Vec<Value>> {
    if !has_table(c, table)? {
        return Ok(Vec::new());
    }
    let available = table_columns(c, table)?;
    let cols: Vec<&str> = want.iter().copied().filter(|col| available.iter().any(|n| n == col)).collect();
    if cols.is_empty() || !available.iter().any(|n| n == order_by) {
        return Ok(Vec::new());
    }
    let sql = format!("SELECT {} FROM {table} ORDER BY {order_by}", cols.join(", "));
    let mut stmt = c.prepare(&sql)?;
    let rows = stmt.query_map([], row_map)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?.into_iter().map(Value::Object).collect())
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

fn build_manifest(c: &Connection, source_host: &str) -> UaResult<Value> {
    // One read transaction: every table comes from the same snapshot, so a
    // write landing mid-export cannot leave a task without its events.
    let tx = c.unchecked_transaction()?;
    let tasks = manifest_rows(&tx, "tasks", MANIFEST_TASK_COLUMNS, "id")?;
    let memory: Vec<Value> = manifest_rows(&tx, "memory", MANIFEST_MEMORY_COLUMNS, "id")?
        .into_iter()
        .filter(|row| row.get("id").and_then(Value::as_str).is_none_or(|id| !is_index_id(id)))
        .collect();
    let note_ids: Vec<String> =
        memory.iter().filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_string)).collect();
    let mut payload = Map::new();
    payload.insert("manifest_version".into(), json!(1));
    payload.insert("source_host".into(), json!(source_host));
    payload.insert("schema_version".into(), json!(schema_version_label(&tx)?));
    payload.insert("tasks".into(), Value::Array(tasks));
    payload.insert("memory".into(), Value::Array(memory));
    for (table, columns, _) in GRAPH_TABLES {
        let mut rows = manifest_rows(&tx, table, columns, columns[0])?;
        rows.retain(|row| graph_row_in_notes(row, &note_ids));
        payload.insert((*table).into(), Value::Array(rows));
    }
    let mut events = manifest_rows(&tx, "event_log", MANIFEST_EVENT_COLUMNS, "ulid")?;
    events.iter_mut().for_each(label_event_row);
    payload.insert("event_log".into(), Value::Array(events));
    tx.finish()?;
    let fingerprint = manifest_fingerprint(&payload);
    payload.insert("generated_at".into(), json!(ua_core::time::now()));
    payload.insert("fingerprint".into(), json!(fingerprint));
    Ok(Value::Object(payload))
}

fn graph_row_in_notes(row: &Value, note_ids: &[String]) -> bool {
    let Some(obj) = row.as_object() else { return false };
    for key in ["note_id", "src_id", "dst_id"] {
        if let Some(id) = obj.get(key).and_then(Value::as_str)
            && !note_ids.iter().any(|n| n == id)
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
}

async fn export_migration_manifest(ctx: ToolCtx, a: ManifestArgs) -> UaResult<Value> {
    let source_host = source_host_label(ctx.hub.cfg());
    let manifest = ctx.hub.db().read_async(move |c| build_manifest(c, &source_host)).await?;
    let tasks = manifest.get("tasks").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    let memory = manifest.get("memory").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    let rows = tasks + memory;
    let fingerprint = manifest.get("fingerprint").cloned().unwrap_or(Value::Null);
    if a.write_to_vault.unwrap_or(false) {
        // The file holds the manifest; the result only points at it.
        let content = format!("{}\n", py_dumps(&manifest, Some(2)));
        let mut out = deliver(&ctx, "migration-manifest", "json", content, rows, true).await?;
        if let Some(obj) = out.as_object_mut() {
            obj.insert("fingerprint".into(), fingerprint);
        }
        return Ok(out);
    }
    let bytes = py_dumps(&manifest, None).len();
    if bytes > INLINE_MAX_BYTES {
        return Err(UaError::invalid(format!(
            "manifest is {bytes} bytes, over the {INLINE_MAX_BYTES} byte inline cap; pass write_to_vault=true"
        )));
    }
    Ok(json!({ "manifest": manifest, "fingerprint": fingerprint, "rows": rows, "bytes": bytes }))
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
    /// Manifest object from `export_migration_manifest` (the `manifest` field, not the wrapper).
    pub left: Value,
    /// Manifest object to compare against `left`. It must come from the same origin (`source_host`).
    pub right: Value,
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

async fn compare_migration_manifests(_ctx: ToolCtx, a: CompareArgs) -> UaResult<Value> {
    let (Some(left), Some(right)) = (a.left.as_object(), a.right.as_object()) else {
        return Err(UaError::invalid("left and right must be manifest objects"));
    };
    if a.left.get("manifest_version") != Some(&json!(1)) || a.right.get("manifest_version") != Some(&json!(1))
    {
        return Err(UaError::invalid("unsupported migration manifest version"));
    }
    let (left_origin, right_origin) =
        (manifest_origin("left", &a.left)?, manifest_origin("right", &a.right)?);
    if left_origin != right_origin {
        return Err(UaError::invalid(format!(
            "the manifests come from different origins ({left_origin:?} and {right_origin:?}); rows are keyed by \
             id, which only identifies a row within one origin"
        )));
    }
    validate_graph("left", &a.left)?;
    validate_graph("right", &a.right)?;

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
        let left_rows = object_rows(a.left.get(kind), kind)?;
        let right_rows = object_rows(a.right.get(kind), kind)?;
        let left_index = index_rows("left", kind, keys, &left_rows)?;
        let right_index = index_rows("right", kind, keys, &right_rows)?;
        compare_kind(kind, keys, &left_index, &right_index, &mut summary, &mut conflicts);
        if kind == "tasks" {
            missing_parents("left", &left_index, &mut conflicts);
            missing_parents("right", &right_index, &mut conflicts);
        }
    }
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
    /// tasks, memory, journal, manifest or compare. Import and rollback are not available.
    pub action: String,
    /// The action's arguments, as for export_tasks / export_memory / export_journal.
    pub params: Option<Value>,
}

async fn export_data(ctx: ToolCtx, a: DataArgs) -> UaResult<Value> {
    let action = a.action.trim().to_ascii_lowercase();
    match action.as_str() {
        "tasks" | "export_tasks" => export_tasks(ctx, parse_params("export", &action, a.params)?).await,
        "memory" | "export_memory" => export_memory(ctx, parse_params("export", &action, a.params)?).await,
        "journal" | "export_journal" => export_journal(ctx, parse_params("export", &action, a.params)?).await,
        "manifest" | "export_migration_manifest" => {
            export_migration_manifest(ctx, parse_params("export", &action, a.params)?).await
        }
        "compare" | "compare_migration_manifests" => {
            compare_migration_manifests(ctx, parse_params("export", &action, a.params)?).await
        }
        "import" | "rollback" => Err(UaError::invalid(format!(
            "export action {action:?} is not available: migration import and rollback are not implemented"
        ))),
        _ => Err(UaError::invalid("action must be one of tasks, memory, journal, manifest, compare")),
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
            "Read-only migration snapshot of tasks, memory notes, memory graph rows when those tables exist, \
             and the event log, read in one transaction. Stable ids, claims, source hosts and provenance are \
             preserved; client evidence events (sdk. channels) carry a trust label. The manifest's origin is \
             the `source_host` config value (default `local`). Does not import, rewrite or delete anything. \
             write_to_vault (default false) writes exports/migration-manifest-<UTC>.json in the workspace and \
             returns {path, rows, bytes, fingerprint}; otherwise returns {manifest, fingerprint, rows, bytes} \
             (2 MB cap). Fingerprint is SHA-256 of the canonical payload and excludes generated_at.",
            export_migration_manifest,
        )
        .family("export"),
    );
    r.add(
        tool(
            "compare_migration_manifests",
            "Diff two migration manifests from the same origin (`source_host`); rows are keyed by id. \
             Reports left-only, right-only and changed rows, claim conflicts, duplicate title/body candidates, \
             tasks whose parent is missing on either side and stated fingerprints that do not match the \
             payload. Refuses duplicate ids. Fingerprints are recomputed; `same` needs equal fingerprints and \
             no conflicts. Does not change either source or the local database. Returns {same, summary, \
             conflicts, requires_human_disposition}.",
            compare_migration_manifests,
        )
        .family("export")
        .read_only(),
    );
}

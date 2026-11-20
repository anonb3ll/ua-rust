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

use super::harness_config::render::py_dumps;

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
    "worktree_path",
    "branch",
    "project",
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

fn manifest_hash(payload: &Value) -> String {
    hex::encode(Sha256::digest(py_dumps(payload, None).as_bytes()))
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

fn source_host_label() -> String {
    std::env::var("UA_SOURCE_HOST")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "local".into())
}

fn schema_version_label(c: &Connection) -> UaResult<String> {
    let mut stmt = c.prepare("SELECT name FROM schema_parts")?;
    let mut names = stmt.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
    names.sort();
    Ok(names.join(","))
}

fn build_manifest(c: &Connection) -> UaResult<Value> {
    let mut tasks = manifest_rows(c, "tasks", MANIFEST_TASK_COLUMNS, "id")?;
    let memory: Vec<Value> = manifest_rows(c, "memory", MANIFEST_MEMORY_COLUMNS, "id")?
        .into_iter()
        .filter(|row| row.get("id").and_then(Value::as_str).is_none_or(|id| !is_index_id(id)))
        .collect();
    let note_ids: Vec<String> =
        memory.iter().filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_string)).collect();
    let mut payload = Map::new();
    payload.insert("manifest_version".into(), json!(1));
    payload.insert("source_host".into(), json!(source_host_label()));
    payload.insert("schema_version".into(), json!(schema_version_label(c)?));
    payload.insert("tasks".into(), Value::Array(tasks.split_off(0)));
    payload.insert("memory".into(), Value::Array(memory));
    for (table, columns, _) in GRAPH_TABLES {
        let mut rows = manifest_rows(c, table, columns, columns[0])?;
        rows.retain(|row| graph_row_in_notes(row, &note_ids));
        payload.insert((*table).into(), Value::Array(rows));
    }
    let agent_total =
        manifest_rows(c, "agent_events", &["id", "agent", "ts", "kind", "ref_id", "summary"], "id")?;
    // This hub has no tenant column on agent events. A missing table exports
    // nothing; a present table is included whole and nothing is withheld.
    let withheld = 0;
    payload.insert("agent_events".into(), Value::Array(agent_total));
    payload.insert("agent_events_withheld".into(), json!(withheld));
    payload.insert(
        "event_log".into(),
        Value::Array(manifest_rows(c, "event_log", MANIFEST_EVENT_COLUMNS, "ulid")?),
    );
    let payload = Value::Object(payload);
    let fingerprint = manifest_hash(&payload);
    let mut manifest = payload.as_object().cloned().unwrap_or_default();
    manifest.insert("generated_at".into(), json!(ua_core::time::now()));
    manifest.insert("fingerprint".into(), json!(fingerprint));
    Ok(Value::Object(manifest))
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
    let manifest = ctx.hub.db().read_async(build_manifest).await?;
    let tasks = manifest.get("tasks").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    let memory = manifest.get("memory").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    let content = format!("{}\n", py_dumps(&manifest, Some(2)));
    let mut out = deliver(
        &ctx,
        "migration-manifest",
        "json",
        content,
        tasks + memory,
        a.write_to_vault.unwrap_or(false),
    )
    .await?;
    if let Some(obj) = out.as_object_mut() {
        if let Some(fp) = manifest.get("fingerprint").cloned() {
            obj.insert("fingerprint".into(), fp);
        }
        obj.insert("manifest".into(), manifest);
    }
    Ok(out)
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

fn validate_graph(payload: &Value) -> UaResult<()> {
    for (table, columns, keys) in GRAPH_TABLES {
        let rows = object_rows(payload.get(*table), table)?;
        let mut seen = Vec::new();
        for row in &rows {
            let required: Vec<&str> = columns.iter().copied().filter(|c| *c != "actor").collect();
            if required.iter().any(|c| !row.get(*c).is_some_and(Value::is_string)) {
                return Err(UaError::invalid(format!(
                    "{table} rows require string fields: {}",
                    required.join(", ")
                )));
            }
            if let Some(actor) = row.get("actor")
                && !actor.is_null()
                && !actor.is_string()
            {
                return Err(UaError::invalid(format!("{table} actor must be a string or null")));
            }
            let key = row_key(row, keys);
            if seen.contains(&key) {
                return Err(UaError::invalid(format!("{table} contains duplicate graph keys")));
            }
            seen.push(key);
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompareArgs {
    /// Manifest object from `export_migration_manifest` (the `manifest` field, not the wrapper).
    pub left: Value,
    /// Manifest object to compare against `left`.
    pub right: Value,
}

fn compare_kind(
    kind: &str,
    keys: &[&str],
    left_rows: &[Map<String, Value>],
    right_rows: &[Map<String, Value>],
    summary: &mut Map<String, Value>,
    conflicts: &mut Vec<Value>,
) {
    let mut left_index: std::collections::BTreeMap<String, &Map<String, Value>> =
        std::collections::BTreeMap::new();
    let mut right_index: std::collections::BTreeMap<String, &Map<String, Value>> =
        std::collections::BTreeMap::new();
    for row in left_rows {
        left_index.insert(row_key(row, keys), row);
    }
    for row in right_rows {
        right_index.insert(row_key(row, keys), row);
    }
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
    let graph = GRAPH_TABLES.iter().any(|(name, _, _)| *name == kind);
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
    let mut by_content: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for (id, row) in left_index.iter().chain(right_index.iter()) {
        by_content.entry(content_key(row, content_keys)).or_default().push((*id).clone());
    }
    for mut ids in by_content.into_values() {
        ids.sort();
        ids.dedup();
        if ids.len() > 1 {
            conflicts.push(json!({"kind": kind, "ids": ids, "type": "duplicate_candidate"}));
        }
    }
}

async fn compare_migration_manifests(_ctx: ToolCtx, a: CompareArgs) -> UaResult<Value> {
    if !a.left.is_object() || !a.right.is_object() {
        return Err(UaError::invalid("left and right must be manifest objects"));
    }
    if a.left.get("manifest_version") != Some(&json!(1)) || a.right.get("manifest_version") != Some(&json!(1))
    {
        return Err(UaError::invalid("unsupported migration manifest version"));
    }
    validate_graph(&a.left)?;
    validate_graph(&a.right)?;
    let mut summary = Map::new();
    let mut conflicts = Vec::new();
    let mut kinds = vec![("tasks", &["id"][..]), ("memory", &["id"][..])];
    for (name, _, keys) in GRAPH_TABLES {
        kinds.push((name, keys));
    }
    for (kind, keys) in kinds {
        let left_rows = object_rows(a.left.get(kind), kind)?;
        let right_rows = object_rows(a.right.get(kind), kind)?;
        compare_kind(kind, keys, &left_rows, &right_rows, &mut summary, &mut conflicts);
    }
    let task_ids: Vec<String> =
        object_rows(a.left.get("tasks"), "tasks")?.iter().map(|row| scalar_id(row.get("id"))).collect();
    for row in object_rows(a.left.get("tasks"), "tasks")? {
        let parent = scalar_id(row.get("parent_id"));
        if !parent.is_empty() && !task_ids.iter().any(|id| id == &parent) {
            conflicts
                .push(json!({"kind": "tasks", "id": scalar_id(row.get("id")), "type": "missing_parent"}));
        }
    }
    Ok(json!({
        "left_source_host": a.left.get("source_host").cloned().unwrap_or(Value::Null),
        "right_source_host": a.right.get("source_host").cloned().unwrap_or(Value::Null),
        "left_fingerprint": a.left.get("fingerprint").cloned().unwrap_or(Value::Null),
        "right_fingerprint": a.right.get("fingerprint").cloned().unwrap_or(Value::Null),
        "same": a.left.get("fingerprint") == a.right.get("fingerprint"),
        "summary": summary,
        "conflicts": conflicts,
        "requires_human_disposition": !conflicts.is_empty(),
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
             and the event log. Stable ids, claims, source hosts and provenance are preserved. Does not import, \
             rewrite or delete anything. write_to_vault (default false) writes exports/migration-manifest-<UTC>.json \
             in the workspace; otherwise returns {manifest, content, rows}. Fingerprint is SHA-256 of the \
             canonical payload and excludes generated_at.",
            export_migration_manifest,
        )
        .family("export"),
    );
    r.add(
        tool(
            "compare_migration_manifests",
            "Diff two migration manifests. Reports left-only, right-only and changed rows, claim conflicts, \
             duplicate title/body candidates and tasks whose parent is missing. Does not change either source \
             or the local database. Returns {same, summary, conflicts, requires_human_disposition}.",
            compare_migration_manifests,
        )
        .family("export")
        .read_only(),
    );
}

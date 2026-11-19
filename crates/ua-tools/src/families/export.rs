//! Structured exports: tasks, memory notes and vault journal lines.
//!
//! Tools: `export_tasks`, `export_memory`, `export_journal` and the
//! consolidated `export_data(action, params)`.
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
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

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
        std::fs::create_dir_all(&dir).map_err(|e| UaError::internal(format!("cannot create {EXPORT_DIR}/: {e}")))?;
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
                EventInput::new("agent.export.written", json!({ "kind": name, "path": rel, "rows": rows, "bytes": bytes }))
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

fn task_rows(c: &Connection, status: Option<&str>, project: Option<&str>) -> UaResult<Vec<Map<String, Value>>> {
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
    let status = a.status.as_deref().map(str::trim).filter(|s| !s.is_empty() && *s != "all").map(str::to_string);
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
    raw.and_then(|s| serde_json::from_str::<Value>(s).ok()).filter(Value::is_array).unwrap_or_else(|| json!([]))
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
    let since_day = a.since.as_deref().map(|s| normalize_since("since", s)).transpose()?.map(|s| s[..10].to_string());
    let tag = a.tag.clone();
    let records = ctx.hub.db().read_async(move |c| memory_records(c, tag.as_deref(), since_day.as_deref())).await?;
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

fn journal_entries_in(dir: &Path, machine: &str, agent: Option<&str>, since: Option<&str>, out: &mut Vec<Value>) {
    let Ok(read) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<PathBuf> = read
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .collect();
    files.sort();
    for f in files {
        let Some(date) = f.file_name().and_then(|n| n.to_str()).and_then(daily_date).map(str::to_string) else {
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
    let since = a.since.as_deref().map(|s| normalize_since("since", s)).transpose()?.map(|s| s[..10].to_string());
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
                (v["date"].as_str().unwrap_or("").to_string(), v["time"].as_str().unwrap_or("").to_string(), v["machine"].as_str().unwrap_or("").to_string())
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
// export_data

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DataArgs {
    /// tasks, memory or journal. The migration actions (manifest, compare,
    /// import, rollback) are not available in this build.
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
        "manifest" | "compare" | "import" | "rollback" => {
            Err(UaError::invalid(format!("export action {action:?} (migration manifests) is not available in this build")))
        }
        _ => Err(UaError::invalid("action must be one of tasks, memory, journal")),
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
            "Consolidated export entry point: action tasks, memory or journal with that tool's arguments in \
             `params`. The migration-manifest actions are not available in this build.",
            export_data,
        )
        .family("export"),
    );
}

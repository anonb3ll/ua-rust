//! `vault_journal` and `vault_briefing_digest`.
//!
//! The daily journal is `Logs/YYYY-MM-DD.md`, one line per entry:
//! `- **HH:MM** [agent] text #tag`. Other per-day streams may live at
//! `Logs/<stream>/YYYY-MM-DD.md`; the digest merges them.

use std::collections::HashSet;
use std::io::Write;
use std::sync::LazyLock;

use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};

use super::ingest::classify;
use super::{
    READ_MAX_BYTES, Vault, attributed_agent, day_or_today, locked_error, note_is_locked, read_text_lossy,
    record, sha256_hex, vault, with_note_locks,
};
use crate::registry::{Registry, ToolCtx, blocking, tool};

/// A journal entry is a pointer to where the detail lives (a task, commit or
/// memory note), not the detail itself.
pub const JOURNAL_ENTRY_MAX_CHARS: usize = 240;

static ENTRY_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^- \*\*(\d{2}:\d{2})\*\* \[([^\]]+)\] (.+)$").expect("static regex"));
static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"#(\w[\w-]*)").expect("static regex"));
static PR_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"github\.com/[\w.-]+/[\w.-]+/pull/(\d+)").expect("static regex"));
static TASK_REF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"#(\d+)\b").expect("static regex"));

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JournalArgs {
    /// One-line entry, at most 240 characters: what happened and where the
    /// detail lives (task, commit, memory note).
    pub entry: String,
    /// Your agent label. A verified caller's identity is stamped instead; a
    /// contradicting claim is refused.
    pub agent: String,
    /// Tags appended as `#tag`.
    pub tags: Option<Vec<String>>,
    /// Day note to append to, `YYYY-MM-DD` (default: today, local time).
    pub date: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestArgs {
    /// Day to digest, `YYYY-MM-DD` (default: today, local time).
    pub date: Option<String>,
    /// Also report the ingest state of every capture directly in the inbox (default true).
    #[serde(default = "yes")]
    pub include_inbox: bool,
}

fn yes() -> bool {
    true
}

fn validated_entry(entry: &str) -> UaResult<String> {
    let entry = entry.split_whitespace().collect::<Vec<_>>().join(" ");
    if entry.is_empty() {
        return Err(UaError::invalid("journal entry is empty"));
    }
    let n = entry.chars().count();
    if n > JOURNAL_ENTRY_MAX_CHARS {
        return Err(UaError::invalid(format!(
            "journal entry is {n} chars, over the {JOURNAL_ENTRY_MAX_CHARS}-char cap. A journal entry is a bookkeeping index, not the record itself: shorten it to '<what happened>, see task/commit/memory <id>' and put the detail there"
        )));
    }
    Ok(entry)
}

fn journal(v: &Vault, a: JournalArgs) -> UaResult<Value> {
    let entry = validated_entry(&a.entry)?;
    let agent = attributed_agent(&v.caller, Some(&a.agent))?
        .ok_or_else(|| UaError::invalid("agent label is required"))?;
    let day = day_or_today(a.date.as_deref())?;
    let tags: String = a
        .tags
        .unwrap_or_default()
        .iter()
        .map(|t| t.trim().trim_start_matches('#').split_whitespace().collect::<Vec<_>>().join("-"))
        .filter(|t| !t.is_empty())
        .map(|t| format!(" #{t}"))
        .collect();
    let time = jiff::ZonedDateTime::now().strftime("%H:%M").to_string();
    let line = format!("- **{time}** [{agent}] {entry}{tags}\n");
    let header = format!("---\ndate: {day}\ntype: journal\n---\n\n# {day} — Agent journal\n");

    let shown = format!("Logs/{day}.md");
    let p = v.resolve_write(&shown)?;
    let rel = v.rel(&p);
    let created = with_note_locks(&[&rel], || {
        if note_is_locked(&p, &shown)? {
            return Err(locked_error(&shown));
        }
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| UaError::invalid(format!("cannot create Logs/: {e}")))?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
            .map_err(|e| UaError::invalid(format!("cannot append journal note {rel:?}: {e}")))?;
        let created = f.metadata().map(|m| m.len() == 0).unwrap_or(false);
        let mut payload = String::new();
        if created {
            payload.push_str(&header);
        }
        payload.push_str(&line);
        f.write_all(payload.as_bytes()).and_then(|_| f.flush()).map_err(|e| {
            UaError::internal(format!(
                "journal append to {rel:?} failed after the write began ({e}); read the note before journaling again"
            ))
        })?;
        Ok(created)
    })?;
    Ok(json!({
        "path": rel,
        "entry": line.trim_end_matches('\n'),
        "created_note": created,
        "agent": agent,
        "entry_sha256": sha256_hex(line.as_bytes()),
    }))
}

/// Parse journal lines into `{time, agent, text, tags}`. Other lines are skipped.
pub fn parse_entries(text: &str) -> Vec<Value> {
    ENTRY_LINE
        .captures_iter(text)
        .map(|c| {
            let rest = c[3].trim().to_string();
            let tags: Vec<String> = TAG
                .captures_iter(&rest)
                .map(|t| t[1].to_string())
                .filter(|t| !t.chars().all(|ch| ch.is_ascii_digit()))
                .collect();
            json!({"time": &c[1], "agent": &c[2], "text": rest, "tags": tags})
        })
        .collect()
}

/// A PR number or bare `#id` reference: two entries naming the same one are duplicates.
fn dedup_key(text: &str) -> Option<(String, String)> {
    if let Some(c) = PR_URL.captures(text) {
        return Some(("pr".into(), c[1].to_string()));
    }
    TASK_REF.captures(text).map(|c| ("ref".into(), c[1].to_string()))
}

fn digest(v: &Vault, a: DigestArgs, conn: &rusqlite::Connection) -> UaResult<Value> {
    let day = day_or_today(a.date.as_deref())?;
    let logs = v.root.join("Logs");
    // Sources: the daily journal, then each `Logs/<stream>/<day>.md` in name order.
    let mut sources: Vec<(String, std::path::PathBuf)> =
        vec![("journal".into(), logs.join(format!("{day}.md")))];
    if let Ok(rd) = std::fs::read_dir(&logs) {
        let mut streams: Vec<_> = rd
            .filter_map(Result::ok)
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .collect();
        streams.sort();
        for s in streams {
            sources.push((s.clone(), logs.join(&s).join(format!("{day}.md"))));
        }
    }
    let mut merged = Vec::new();
    let mut seen = HashSet::new();
    let mut deduped = 0usize;
    let mut counts = serde_json::Map::new();
    for (source, p) in sources {
        if v.readable(&p).is_none() {
            continue;
        }
        let Some(text) = read_text_lossy(&p, READ_MAX_BYTES) else { continue };
        let entries = parse_entries(&text);
        counts.insert(source.clone(), json!(entries.len()));
        for mut e in entries {
            e["source"] = json!(source);
            if let Some(k) = dedup_key(e["text"].as_str().unwrap_or(""))
                && !seen.insert(k)
            {
                deduped += 1;
                continue;
            }
            merged.push(e);
        }
    }
    merged.sort_by(|x, y| x["time"].as_str().cmp(&y["time"].as_str()));
    let mut out = json!({
        "date": day,
        "entries": merged,
        "source_counts": counts,
        "deduped_count": deduped,
    });
    if a.include_inbox {
        let inbox = inbox_triage(v, conn)?;
        let pending =
            inbox.iter().filter(|e| matches!(e["status"].as_str(), Some("new" | "changed"))).count();
        out["inbox"] = json!(inbox);
        out["inbox_pending_count"] = json!(pending);
    }
    Ok(out)
}

/// Ledger state of every `.md`/`.txt` capture directly in the inbox, by path.
fn inbox_triage(v: &Vault, conn: &rusqlite::Connection) -> UaResult<Vec<Value>> {
    if v.inbox.is_empty() {
        return Ok(Vec::new());
    }
    let dir = v.root.join(&v.inbox);
    if v.readable(&dir).is_none() || !dir.is_dir() {
        return Ok(Vec::new());
    }
    let Ok(rd) = std::fs::read_dir(&dir) else { return Ok(Vec::new()) };
    let mut files: Vec<_> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| super::is_note_name(p) && v.readable(p).is_some_and(|r| r.is_file()))
        .collect();
    files.sort();
    files.iter().map(|p| classify(v, conn, p)).collect()
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "vault_journal",
            "Append a timestamped, agent-attributed line to today's Logs/YYYY-MM-DD.md (created with front matter on first write). Entries are capped at 240 characters: point at the task, commit or memory note that holds the detail. A locked day note takes no appends. Returns {path, entry, created_note}.",
            |ctx: ToolCtx, a: JournalArgs| async move {
                let v = vault(&ctx)?;
                let out = blocking(move || journal(&v, a)).await?;
                let event = json!({
                    "path": out["path"],
                    "agent": out["agent"],
                    "entry_sha256": out["entry_sha256"],
                    "created_note": out["created_note"],
                });
                record(&ctx, "agent.journal.appended", event).await?;
                Ok(out)
            },
        )
        .family("vault"),
    );
    r.add(
        tool(
            "vault_briefing_digest",
            "Merge one day's journal (Logs/DATE.md plus any Logs/<stream>/DATE.md) into a chronological digest, dropping later entries that reference the same PR or #id. With include_inbox (default), also lists each inbox capture's ingest state (new/unchanged/changed/empty) so a briefing never re-proposes finished work. Read-only. Returns {date, entries, source_counts, deduped_count, inbox, inbox_pending_count}.",
            |ctx: ToolCtx, a: DigestArgs| async move {
                let v = vault(&ctx)?;
                ctx.hub.db().read_async(move |conn| digest(&v, a, conn)).await
            },
        )
        .family("vault")
        .read_only(),
    );
}

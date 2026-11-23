//! The inbox ingest pipeline: `vault_ingest_status` (content-hash gate),
//! `vault_archive_plan` (read-only filing plan) and `vault_to_memory_ingest`.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

use super::{
    READ_MAX_BYTES, Vault, attributed_agent, frontmatter, read_note, read_text_lossy, sha256_hex, vault,
};
use crate::registry::{Registry, ToolCtx, blocking, tool};

static PROCESSED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*processed\s*→\s*(?P<target>.+?)\s*$").expect("static regex"));
static SUPERSEDED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?mi)^\s*superseded(?:\s*[-_]\s*by)?\s*:\s*(?P<target>.+?)\s*$").expect("static regex")
});

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IngestStatusArgs {
    /// Vault-relative capture path.
    pub path: String,
    /// Record the current hash as ingested (after folding the capture into the wiki).
    #[serde(default)]
    pub mark: bool,
    /// Your agent label; required with `mark`. A verified identity is stamped instead.
    pub agent: Option<String>,
    /// Wiki pages the capture fed, recorded with `mark`.
    pub pages: Option<Vec<String>>,
    /// Optional note stored with the mark.
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchivePlanArgs {
    /// Inbox directory to plan for (default: the configured inbox).
    pub inbox_path: Option<String>,
    /// Archive root; destinations go below `<archive_root>/<as_of>/` (default `Archive/inbox-archive`).
    pub archive_root: Option<String>,
    /// Date stamp for the destination folder, `YYYY-MM-DD` (default: today).
    pub as_of: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToMemoryArgs {
    /// Vault directories whose top-level `.md` notes are copied (default: `Wiki` and the inbox).
    pub subdirs: Option<Vec<String>>,
    /// Author to stamp on the memory notes (default: the caller's label). A
    /// verified identity is stamped instead.
    pub author: Option<String>,
}

/// Ledger state of one note: `{path, content_hash, status, last_ingested_at, agent, pages}`.
/// `status` is `new`, `unchanged`, `changed` or `empty`. Read-only.
pub(crate) fn classify(v: &Vault, conn: &Connection, p: &Path) -> UaResult<Value> {
    let rel = v.rel(p);
    let data = read_note(p, &rel, READ_MAX_BYTES)?;
    let hash = sha256_hex(&data);
    let row: Option<(String, String, String, String)> = conn
        .query_row(
            "SELECT content_hash, ingested_at, agent, pages FROM vault_ingest_ledger WHERE path = ?1",
            params![rel],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let status = if String::from_utf8_lossy(&data).trim().is_empty() {
        "empty"
    } else {
        match &row {
            None => "new",
            Some((h, ..)) if *h == hash => "unchanged",
            Some(_) => "changed",
        }
    };
    let pages: Value =
        row.as_ref().and_then(|r| serde_json::from_str(&r.3).ok()).unwrap_or_else(|| json!([]));
    Ok(json!({
        "path": rel,
        "content_hash": hash,
        "status": status,
        "last_ingested_at": row.as_ref().map(|r| r.1.clone()),
        "agent": row.as_ref().map(|r| r.2.clone()),
        "pages": pages,
    }))
}

async fn ingest_status(ctx: ToolCtx, a: IngestStatusArgs) -> UaResult<Value> {
    let v = vault(&ctx)?;
    let p = v.resolve(&a.path)?;
    if !p.is_file() {
        return Err(UaError::not_found(format!("no such note: {}", a.path)));
    }
    if !a.mark {
        return ctx.hub.db().read_async(move |conn| classify(&v, conn, &p)).await;
    }
    if ctx.caller.profile == ua_core::Profile::Research {
        return Err(UaError::denied(
            "profile_denied",
            "the research profile cannot mark vault ingest status; read-only checks remain allowed",
        ));
    }
    let agent = attributed_agent(&ctx.caller, a.agent.as_deref())?
        .ok_or_else(|| UaError::invalid("agent label is required to mark an ingest"))?;
    let pages: Vec<String> = a
        .pages
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let reason = a.reason.map(|r| r.trim().to_string()).filter(|r| !r.is_empty());
    let by = ctx.caller.label.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let c = classify(&v, tx, &p)?;
            if c["status"] == "empty" {
                return Err(UaError::invalid(format!("note {:?} is empty; refusing to mark it ingested", a.path)));
            }
            let now = ua_core::time::now();
            let pages_json = serde_json::to_string(&pages)?;
            tx.execute(
                "INSERT INTO vault_ingest_ledger (path, content_hash, agent, pages, reason, ingested_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(path) DO UPDATE SET content_hash = excluded.content_hash, agent = excluded.agent, \
                 pages = excluded.pages, reason = excluded.reason, ingested_at = excluded.ingested_at",
                params![c["path"].as_str(), c["content_hash"].as_str(), agent, pages_json, reason, now],
            )?;
            ledger::append(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG,
                    "agent.vault.ingest_marked",
                    json!({"path": c["path"], "content_hash": c["content_hash"], "agent": agent, "pages": pages}),
                )
                .by(by),
            )?;
            Ok(json!({
                "path": c["path"],
                "content_hash": c["content_hash"],
                "status": "marked",
                "previous_status": c["status"],
                "last_ingested_at": now,
                "agent": agent,
                "pages": pages,
                "reason": reason,
            }))
        })
        .await
}

fn archive_plan(v: &Vault, conn: &Connection, a: ArchivePlanArgs) -> UaResult<Value> {
    let inbox = a.inbox_path.unwrap_or_else(|| v.inbox.clone());
    let archive_root = a.archive_root.unwrap_or_else(|| "Archive/inbox-archive".into());
    if archive_root.split('/').any(|p| p == ".." || p.starts_with('.')) || archive_root.starts_with('/') {
        return Err(UaError::invalid(
            "archive_root must be a vault-relative path without '..' or hidden parts",
        ));
    }
    let root = v.resolve(&inbox)?;
    if !root.is_dir() {
        return Err(UaError::invalid(format!("inbox path is not a directory: {inbox}")));
    }
    let as_of =
        super::day_or_today(a.as_of.as_deref()).map_err(|_| UaError::invalid("as_of must be YYYY-MM-DD"))?;
    let prefix = format!("{}/{as_of}", archive_root.trim_end_matches('/'));
    let (mut ready, mut only, mut auth, mut pending) = (0, 0, 0, 0);
    let mut candidates = Vec::new();
    for note in v.notes_under(&root) {
        let Some(text) = read_text_lossy(&note, READ_MAX_BYTES) else { continue };
        let meta = frontmatter::metadata(&text);
        let processed = PROCESSED.captures(&text).map(|c| c["target"].trim().to_string());
        // A `superseded:` marker counts in the body or in the front matter.
        let superseded = SUPERSEDED.captures(&text).map(|c| c["target"].trim().to_string());
        let status = frontmatter::scalar_lower(&meta, "status");
        let shipped = ["implementation_status", "implementation", "shipped"]
            .iter()
            .any(|k| matches!(frontmatter::scalar_lower(&meta, k).as_deref(), Some("shipped" | "true")));
        let ingest = classify(v, conn, &note)?;
        let ingest_status = ingest["status"].as_str().unwrap_or("new").to_string();
        let (classification, action, reason, promotion) = if superseded.is_some() {
            ("archive-only", "move", "explicit superseded marker", "none")
        } else if processed.is_some() && ingest_status == "unchanged" {
            let authoritative = status.as_deref() == Some("final") || shipped;
            if authoritative {
                ("authoritative", "move", "processed marker and unchanged ingest ledger", "authoritative")
            } else {
                ("archive-only", "move", "processed marker and unchanged ingest ledger", "none")
            }
        } else {
            ("pending", "hold", "missing processed marker or ingest ledger is new/changed", "none")
        };
        if action == "move" {
            ready += 1;
            if classification == "authoritative" {
                auth += 1;
            } else {
                only += 1;
            }
        } else {
            pending += 1;
        }
        let relative = super::rel_to(&root, &note);
        candidates.push(json!({
            "source": v.rel(&note),
            "destination": format!("{prefix}/{relative}"),
            "action": action,
            "classification": classification,
            "promotion": promotion,
            "reason": reason,
            "status": status,
            "shipped": shipped,
            "ingest_status": ingest_status,
            "processed_target": processed,
            "superseded_target": superseded,
        }));
    }
    Ok(json!({
        "inbox": v.rel(&root),
        "archive_root": prefix,
        "read_only": true,
        "counts": {"archive_ready": ready, "archive_only": only, "authoritative": auth, "pending": pending},
        "candidates": candidates,
    }))
}

/// Top-level `.md` notes of one vault directory, sorted, at most 500.
fn top_level_notes(v: &Vault, dir: &str) -> Vec<std::path::PathBuf> {
    let Ok(p) = v.resolve(dir) else { return Vec::new() };
    let Ok(rd) = std::fs::read_dir(&p) else { return Vec::new() };
    let mut out: Vec<_> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|f| {
            f.extension().and_then(|e| e.to_str()) == Some("md")
                && !f.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.'))
                && v.readable(f).is_some_and(|r| r.is_file())
        })
        .collect();
    out.sort();
    out.truncate(500);
    out
}

async fn to_memory(ctx: ToolCtx, a: ToMemoryArgs) -> UaResult<Value> {
    let v = vault(&ctx)?;
    let author =
        attributed_agent(&ctx.caller, a.author.as_deref())?.unwrap_or_else(|| ctx.caller.label.clone());
    let subdirs = a.subdirs.unwrap_or_else(|| vec!["Wiki".into(), v.inbox.clone()]);
    let v2 = v.clone();
    // (subdir, rel path, title, content)
    let notes: Vec<(String, String, String, String)> = blocking(move || {
        let mut out = Vec::new();
        for sub in subdirs.iter().filter(|s| !s.trim().is_empty()) {
            for f in top_level_notes(&v2, sub) {
                let text = read_text_lossy(&f, READ_MAX_BYTES).unwrap_or_default();
                out.push((sub.clone(), v2.rel(&f), super::stem(&f), text.trim().to_string()));
            }
        }
        Ok(out)
    })
    .await?;

    let reg = crate::builtin_registry_shared();
    let (mut ingested, mut skipped, mut unchanged) = (0usize, 0usize, 0usize);
    let mut processed = Vec::new();
    for (sub, rel, title, content) in notes {
        if content.is_empty() {
            skipped += 1;
            continue;
        }
        let sub_tag = format!("vault:{}", sub.trim_matches('/').to_lowercase().replace(' ', "_"));
        let (t, st, org) = (title.clone(), sub_tag.clone(), ctx.caller.org_id.clone());
        // The note this vault page was copied into before, if any, in the
        // caller's organization (the save below writes there too).
        let existing: Option<(String, String)> = ctx
            .hub
            .db()
            .read_async(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT id, content FROM memory WHERE title = ?1 AND org_id = ?3 \
                         AND EXISTS (SELECT 1 FROM json_each(memory.tags) WHERE value = ?2) \
                         AND NOT EXISTS (SELECT 1 FROM json_each(memory.tags) WHERE value = 'meta:deleted') \
                         ORDER BY seq LIMIT 1",
                        params![t, st, org],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?)
            })
            .await?;
        let mut args = json!({
            "content": content,
            "title": title,
            "tags": ["vault", sub_tag],
            "author": author,
        });
        // Evidence refs carry no whitespace: spaces are percent-encoded.
        let evidence = format!("vault:{}", rel.replace(' ', "%20"));
        if evidence.chars().count() <= 206 && !evidence.chars().any(char::is_whitespace) {
            args["evidence"] = json!([evidence]);
        }
        match &existing {
            Some((_, old)) if *old == content => {
                unchanged += 1;
                continue;
            }
            Some((id, _)) => {
                args["id"] = json!(id);
                args["overwrite"] = json!(true);
            }
            None => {}
        }
        match reg.call(&ctx.hub, &ctx.caller, "memory_save", args).await {
            Ok(_) => {
                ingested += 1;
                processed.push(rel);
            }
            Err(e) => {
                tracing::debug!(error = %e, path = %rel, "vault note not copied to memory");
                skipped += 1;
            }
        }
    }
    Ok(json!({
        "ingested_count": ingested,
        "skipped_count": skipped,
        "unchanged_count": unchanged,
        "notes_processed": processed,
    }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "vault_ingest_status",
            "The inbox ingest gate. Hashes a capture (sha256) and compares it with the ingest ledger: new (never ingested), unchanged (skip it), changed (re-ingest it) or empty (reject it). After folding a new/changed capture into the wiki, call again with mark=true, an agent and the wiki pages it fed. Returns {path, content_hash, status, last_ingested_at, agent, pages}.",
            ingest_status,
        )
        .family("vault"),
    );
    r.add(
        tool(
            "vault_archive_plan",
            "Read-only plan for filing processed inbox captures. A `processed → <target>` marker makes a capture movable only while its ingest ledger hash is unchanged; `status: final` or `implementation_status: shipped` front matter marks it authoritative, others archive-only; a `superseded: <target>` marker is movable but never promotes. Destinations keep the inbox-relative path below <archive_root>/<as_of>. Never moves anything.",
            |ctx: ToolCtx, a: ArchivePlanArgs| async move {
                let v = vault(&ctx)?;
                ctx.hub.db().read_async(move |conn| archive_plan(&v, conn, a)).await
            },
        )
        .family("vault")
        .read_only(),
    );
    r.add(
        tool(
            "vault_to_memory_ingest",
            "Copy the top-level .md notes of vault directories (default Wiki and the inbox; at most 500 each, nested folders skipped) into memory notes tagged `vault` and `vault:<dir>`, so memory search sees them. Re-running updates a changed copy and skips an unchanged one. Returns {ingested_count, skipped_count, unchanged_count, notes_processed}.",
            to_memory,
        )
        .family("vault"),
    );
}

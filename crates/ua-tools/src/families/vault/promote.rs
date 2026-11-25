//! `memory_promote`: copy a high-confidence memory note to a
//! `Wiki/Learnings/<slug>.md` page with attribution front matter, and list it
//! in the machine-managed block of `Wiki/Index.md`. Reads the `memory` table
//! directly; the memory family's code is not involved.

use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};

use super::notes::write_note;
use super::{READ_MAX_BYTES, Vault, attributed_agent, note_revision, read_note, record, vault};
use crate::registry::{Registry, ToolCtx, blocking, tool};

const PROMOTE_DIR: &str = "Wiki/Learnings";
const INDEX_REL: &str = "Wiki/Index.md";
const INDEX_SECTION: &str = "Promoted learnings";
const INDEX_START: &str = "<!-- promoted-learnings:start -->";
const INDEX_END: &str = "<!-- promoted-learnings:end -->";

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PromoteArgs {
    /// Memory note id.
    pub id: String,
    /// Page slug (default: from the note title).
    pub slug: Option<String>,
    /// One-line summary for the index entry (default: the note's first line).
    pub summary: Option<String>,
    /// Your agent label, stamped as `promoted_by`. A verified identity is stamped instead.
    pub agent: Option<String>,
    /// Return the page and the planned index line without writing.
    #[serde(default)]
    pub dry_run: bool,
}

struct MemoryRow {
    title: Option<String>,
    content: String,
    author: Option<String>,
    confidence: Option<f64>,
}

fn slugify(text: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for ch in text.to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            dash = false;
        } else if !dash {
            out.push('-');
            dash = true;
        }
    }
    let s = out.trim_matches('-');
    s.chars().take(64).collect::<String>().trim_matches('-').to_string()
}

fn first_line(content: &str) -> String {
    content
        .lines()
        .map(|l| l.trim().trim_start_matches('#').trim())
        .find(|l| !l.is_empty())
        .map(|l| l.chars().take(120).collect())
        .unwrap_or_default()
}

/// One-line scalar for YAML front matter: control characters dropped, quoted.
fn yaml_scalar(s: &str) -> String {
    let clean: String = s.chars().filter(|c| !c.is_control()).collect();
    serde_json::to_string(&clean).unwrap_or_else(|_| "\"\"".into())
}

/// Insert `line` into the managed block (created at the end when absent),
/// sorted and de-duplicated by link target. Text outside the markers is kept.
fn rewrite_index(index: &str, line: &str) -> String {
    let (pre, mut lines, post) = match (index.find(INDEX_START), index.find(INDEX_END)) {
        (Some(s), Some(e)) if s < e => {
            let block = &index[s + INDEX_START.len()..e];
            let lines: Vec<String> =
                block.lines().filter(|l| l.trim().starts_with("- [[")).map(str::to_string).collect();
            (index[..s].to_string(), lines, index[e + INDEX_END.len()..].to_string())
        }
        _ => (format!("{}\n\n## {INDEX_SECTION}\n\n", index.trim_end()), Vec::new(), "\n".to_string()),
    };
    let key = |l: &str| l.split("]]").next().unwrap_or("").to_string();
    let k = key(line);
    lines.retain(|l| key(l) != k);
    lines.push(line.to_string());
    lines.sort_by_key(|l| l.to_lowercase());
    format!("{pre}{INDEX_START}\n{}\n{INDEX_END}{post}", lines.join("\n"))
}

async fn promote(ctx: ToolCtx, a: PromoteArgs) -> UaResult<Value> {
    // The vault is hub-scoped, so copying a note into it is the default
    // organization's alone (`docs/organization.md`, Scoping per subsystem):
    // another organization's note would land where every organization reads.
    if ctx.caller.org_id != ua_core::DEFAULT_ORG {
        return Err(UaError::denied(
            "org_unsupported",
            "memory_promote copies a note into the hub-wide vault and is available to the default \
             organization only; nothing was written",
        ));
    }
    let v = vault(&ctx)?;
    let promoter = attributed_agent(&ctx.caller, a.agent.as_deref())?.unwrap_or_else(|| "unknown".into());
    let id = a.id.trim().to_string();
    let (id2, org) = (id.clone(), ctx.caller.org_id.clone());
    let row: Option<MemoryRow> = ctx
        .hub
        .db()
        .read_async(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT title, content, author, confidence FROM memory WHERE id = ?1 AND org_id = ?2 \
                     AND NOT EXISTS (SELECT 1 FROM json_each(memory.tags) WHERE value = 'meta:deleted')",
                    params![id2, org],
                    |r| {
                        Ok(MemoryRow {
                            title: r.get(0)?,
                            content: r.get(1)?,
                            author: r.get(2)?,
                            confidence: r.get(3)?,
                        })
                    },
                )
                .optional()?)
        })
        .await?;
    let Some(row) = row else {
        return Err(UaError::not_found(format!("no memory note with id {id:?}")));
    };
    let floor = ctx.hub.cfg().promote_min_confidence.clamp(0.0, 1.0);
    let confidence = match row.confidence {
        Some(c) if c.is_finite() && c >= floor => c,
        other => {
            return Err(UaError::invalid(format!(
                "note {id:?} has confidence {}; promotion needs >= {floor:.2}. Raise the note's confidence with memory_save, or promote a stronger note",
                other.map(|c| c.to_string()).unwrap_or_else(|| "none".into())
            )));
        }
    };
    let title = row.title.as_deref().map(str::trim).filter(|t| !t.is_empty()).map(str::to_string);
    let title = title.unwrap_or_else(|| format!("Learning {}", id.chars().take(8).collect::<String>()));
    let mut slug = slugify(a.slug.as_deref().unwrap_or(&title));
    if slug.is_empty() {
        slug = slugify(&id);
    }
    if slug.is_empty() {
        slug = "learning".into();
    }
    let author = row.author.clone().unwrap_or_else(|| "unknown".into());
    let summary = a.summary.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let one_line = summary.unwrap_or_else(|| first_line(&row.content));
    let rel = format!("{PROMOTE_DIR}/{slug}.md");
    let day = jiff::Timestamp::now().strftime("%Y-%m-%d").to_string();
    let page = format!(
        "---\ntype: promoted-learning\nsource_memory_id: {}\npromoted_by: {}\npromoted_at: {day}\noriginal_author: {}\nconfidence: {confidence:.2}\ntags: [wiki, learning, promoted]\n---\n\n# {title}\n\n{}\n\n---\n\n*Promoted from memory note `{id}` by {promoter} on {day}. Original author: {author}.*\n",
        yaml_scalar(&id),
        yaml_scalar(&promoter),
        yaml_scalar(&author),
        row.content.trim(),
    );
    let label = title.replace(['[', ']', '|', '\n'], " ");
    let tail =
        if one_line.is_empty() { String::new() } else { format!(" — {}", one_line.replace('\n', " ")) };
    let index_line = format!("- [[{PROMOTE_DIR}/{slug}|{label}]]{tail}");
    let wiki_link = format!("{PROMOTE_DIR}/{slug}");
    if a.dry_run {
        return Ok(json!({
            "promoted": false,
            "dry_run": true,
            "path": rel,
            "wiki_link": wiki_link,
            "index_line": index_line,
            "markdown": page,
            "source_id": id,
        }));
    }

    let (rel2, line2) = (rel.clone(), index_line.clone());
    let (written, index_state) = blocking(move || write_page_and_index(&v, &rel2, &page, &line2)).await?;
    let mut payload = json!({
        "source_id": id,
        "path": written.rel,
        "revision": written.revision,
        "index_updated": index_state == "updated",
    });
    record(&ctx, "agent.memory.promoted", payload.take()).await?;
    let mut out = json!({
        "promoted": true,
        "dry_run": false,
        "path": written.rel,
        "wiki_link": wiki_link,
        "index_line": index_line,
        "index_updated": index_state == "updated",
        "source_id": id,
        "promoted_by": promoter,
        "revision": written.revision,
    });
    if index_state == "locked" {
        out["index_skipped"] = json!("locked");
    }
    Ok(out)
}

/// Write the page (refused if it changed under us or is locked), then merge
/// the index line. A locked index is left alone and reported.
fn write_page_and_index(
    v: &Vault,
    rel: &str,
    page: &str,
    line: &str,
) -> UaResult<(super::notes::Written, &'static str)> {
    let p = v.resolve_write(rel)?;
    let current = note_revision(&p)?;
    let written = write_note(v, rel, &p, page.as_bytes(), "overwrite", false, Some(&current), false)?;
    let ip = v.resolve_write(INDEX_REL)?;
    for _ in 0..3 {
        let revision = note_revision(&ip)?;
        let text = if ip.is_file() {
            String::from_utf8_lossy(&read_note(&ip, INDEX_REL, READ_MAX_BYTES)?).into_owned()
        } else {
            String::new()
        };
        let next = rewrite_index(&text, line);
        if next == text {
            return Ok((written, "unchanged"));
        }
        match write_note(v, INDEX_REL, &ip, next.as_bytes(), "overwrite", false, Some(&revision), false) {
            Ok(_) => return Ok((written, "updated")),
            Err(UaError::Conflict(_)) => continue,
            Err(UaError::Denied { reason_code, .. }) if reason_code == "note_locked" => {
                return Ok((written, "locked"));
            }
            Err(e) => return Err(e),
        }
    }
    Err(UaError::conflict(
        "the promoted page was written, but Wiki/Index.md kept changing; run memory_promote again to add the index line",
    ))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "memory_promote",
            "Promote a high-confidence memory note to a Wiki/Learnings/<slug>.md page with attribution front matter, and link it from the machine-managed `Promoted learnings` block of Wiki/Index.md. Refuses a note whose confidence is below the configured floor (default 0.7). dry_run=true returns the page markdown and planned index line without writing. Never writes a locked note.",
            promote,
        )
        .family("vault"),
    );
}

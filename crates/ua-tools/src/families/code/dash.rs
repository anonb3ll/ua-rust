//! `dash_list`, `dash_search`, `dash_view`: offline Dash/Zeal docsets.
//!
//! Only directories listed in `dash_docsets` (`UA_DASH_DOCSETS`) are scanned;
//! with none configured every tool answers `not_configured`. Docset indexes
//! are opened read-only; page paths are confined to the docset's
//! `Contents/Resources/Documents`.

use std::path::PathBuf;

use regex::Regex;
use rusqlite::{Connection, OpenFlags};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{Config, UaError, UaResult};

use crate::registry::{Registry, ToolCtx, blocking, tool};

const VIEW_MAX_CHARS: usize = 60_000;
const PAGE_MAX_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchArgs {
    /// Symbol or page name to look for.
    pub query: String,
    /// Limit to one docset by id, exact name, or id prefix.
    pub docset: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ViewArgs {
    /// Docset id or name.
    pub docset_id: String,
    /// Page path as returned by dash_search.
    pub path: String,
}

#[derive(Debug, Clone)]
struct Docset {
    name: String,
    id: String,
    path: PathBuf,
    platform: String,
}

fn not_configured() -> UaError {
    UaError::denied(
        "not_configured",
        "Dash docsets are not configured; set UA_DASH_DOCSETS to the directories holding .docset bundles",
    )
}

fn plist_value(plist: &str, key: &str) -> Option<String> {
    let re = Regex::new(&format!(r"<key>{}</key>\s*<string>([^<]*)</string>", regex::escape(key))).ok()?;
    re.captures(plist).and_then(|c| c.get(1)).map(|m| m.as_str().trim().to_string()).filter(|s| !s.is_empty())
}

fn discover(cfg: &Config) -> UaResult<Vec<Docset>> {
    if cfg.dash_docsets.is_empty() {
        return Err(not_configured());
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for parent in &cfg.dash_docsets {
        let Ok(rd) = std::fs::read_dir(parent) else { continue };
        let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        entries.sort();
        for item in entries {
            let is_docset = item.extension().is_some_and(|e| e.eq_ignore_ascii_case("docset"));
            let Ok(real) = item.canonicalize() else { continue };
            if !is_docset || !real.is_dir() || !seen.insert(real.clone()) {
                continue;
            }
            if !real.join("Contents/Resources/docSet.dsidx").is_file() {
                continue;
            }
            let stem = item.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let plist = std::fs::read_to_string(real.join("Contents/Info.plist")).unwrap_or_default();
            out.push(Docset {
                name: plist_value(&plist, "CFBundleName").unwrap_or_else(|| stem.clone()),
                id: plist_value(&plist, "CFBundleIdentifier").unwrap_or_else(|| stem.to_lowercase()),
                platform: plist_value(&plist, "DocSetPlatformFamily").unwrap_or_default(),
                path: real,
            });
        }
    }
    Ok(out)
}

fn list(cfg: &Config) -> UaResult<Value> {
    let docsets: Vec<Value> = discover(cfg)?
        .into_iter()
        .map(|d| json!({ "name": d.name, "id": d.id, "path": d.path.to_string_lossy(), "platform": d.platform }))
        .collect();
    Ok(json!({ "docsets": docsets }))
}

fn like_pattern(q: &str) -> String {
    let mut s = String::from("%");
    for c in q.chars() {
        if matches!(c, '%' | '_' | '\\') {
            s.push('\\');
        }
        s.push(c);
    }
    s.push('%');
    s
}

fn search(cfg: &Config, query: &str, docset: Option<&str>) -> UaResult<Value> {
    let query = query.trim();
    if query.is_empty() {
        return Err(UaError::invalid("query must not be empty"));
    }
    let mut docsets = discover(cfg)?;
    if let Some(filter) = docset.map(|d| d.trim().to_lowercase()).filter(|d| !d.is_empty()) {
        docsets.retain(|d| {
            let id = d.id.to_lowercase();
            id == filter || d.name.to_lowercase() == filter || id.starts_with(&filter)
        });
        if docsets.is_empty() {
            return Err(UaError::not_found(format!("no docset matching {filter:?}")));
        }
    }
    let ql = query.to_lowercase();
    let mut results: Vec<(u8, usize, String, Value)> = Vec::new();
    for d in &docsets {
        let db = d.path.join("Contents/Resources/docSet.dsidx");
        let Ok(conn) = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        else {
            continue;
        };
        let Ok(mut stmt) =
            conn.prepare("SELECT name, type, path FROM searchIndex WHERE name LIKE ?1 ESCAPE '\\' LIMIT 200")
        else {
            continue; // not a searchIndex docset (e.g. an Apple CoreData index)
        };
        let rows = stmt.query_map([like_pattern(query)], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?))
        });
        let Ok(rows) = rows else { continue };
        for (name, ty, path) in rows.flatten() {
            let nl = name.to_lowercase();
            let score = if nl == ql {
                0
            } else if nl.starts_with(&ql) {
                1
            } else {
                2
            };
            let row = json!({ "docset_name": d.name, "docset_id": d.id, "name": name, "type": ty, "path": path });
            results.push((score, name.chars().count(), nl, row));
        }
    }
    results.sort_by(|a, b| (a.0, a.1, &a.2).cmp(&(b.0, b.1, &b.2)));
    let results: Vec<Value> = results.into_iter().take(50).map(|r| r.3).collect();
    Ok(json!({ "results": results }))
}

fn view(cfg: &Config, docset_id: &str, path: &str) -> UaResult<Value> {
    if docset_id.trim().is_empty() {
        return Err(UaError::invalid("docset_id must not be empty"));
    }
    if path.trim().is_empty() {
        return Err(UaError::invalid("path must not be empty"));
    }
    let want = docset_id.trim().to_lowercase();
    let d = discover(cfg)?
        .into_iter()
        .find(|d| d.id.to_lowercase() == want || d.name.to_lowercase() == want)
        .ok_or_else(|| UaError::not_found(format!("docset with id/name {docset_id:?} not found")))?;
    // Index paths may carry anchors, queries and Dash's <dash_entry_...> markers.
    let clean = path.split('#').next().unwrap_or("").split('?').next().unwrap_or("");
    let clean = Regex::new(r"<[^>]+>").map(|re| re.replace_all(clean, "").into_owned()).unwrap_or_default();
    let docs_root = d
        .path
        .join("Contents/Resources/Documents")
        .canonicalize()
        .map_err(|_| UaError::not_found("docset has no Documents directory"))?;
    let candidate = docs_root.join(&clean);
    let resolved = candidate.canonicalize().map_err(|_| UaError::not_found(format!("page not found: {clean}")))?;
    if !resolved.starts_with(&docs_root) {
        return Err(UaError::denied("outside_docset", format!("path {path:?} escapes the docset documents root")));
    }
    let meta = std::fs::metadata(&resolved).map_err(|_| UaError::not_found(format!("page not found: {clean}")))?;
    if !meta.is_file() {
        return Err(UaError::not_found(format!("page not found: {clean}")));
    }
    if meta.len() > PAGE_MAX_BYTES {
        return Err(UaError::invalid("documentation page is too large"));
    }
    let bytes = std::fs::read(&resolved).map_err(|e| UaError::invalid(format!("cannot read page: {e}")))?;
    let html = String::from_utf8_lossy(&bytes);
    let (_, md) = crate::families::web::html_to_markdown(&html, None);
    let content = if md.trim().is_empty() { html.into_owned() } else { md };
    let truncated = content.chars().count() > VIEW_MAX_CHARS;
    let content: String = content.chars().take(VIEW_MAX_CHARS).collect();
    Ok(json!({ "docset_name": d.name, "path": path, "content": content, "truncated": truncated }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "dash_list",
            "List the Dash/Zeal docsets found in the directories UA_DASH_DOCSETS names (fails with \
             not_configured when it is unset). Returns {docsets: [{name, id, path, platform}]}.",
            |ctx: ToolCtx, _a: ListArgs| async move {
                let cfg = ctx.hub.cfg().clone();
                blocking(move || list(&cfg)).await
            },
        )
        .family("code")
        .read_only(),
    );
    r.add(
        tool(
            "dash_search",
            "Search docset symbol names (exact, then prefix, then substring; max 50). docset limits the \
             search to one docset by id, name or id prefix. Returns {results: [{docset_name, docset_id, \
             name, type, path}]}.",
            |ctx: ToolCtx, a: SearchArgs| async move {
                let cfg = ctx.hub.cfg().clone();
                blocking(move || search(&cfg, &a.query, a.docset.as_deref())).await
            },
        )
        .family("code")
        .read_only(),
    );
    r.add(
        tool(
            "dash_view",
            "Render one docset page (path from dash_search) as Markdown, capped at 60000 characters. \
             Paths outside the docset's Documents directory are refused. Returns {docset_name, path, \
             content, truncated}.",
            |ctx: ToolCtx, a: ViewArgs| async move {
                let cfg = ctx.hub.cfg().clone();
                blocking(move || view(&cfg, &a.docset_id, &a.path)).await
            },
        )
        .family("code")
        .read_only(),
    );
}

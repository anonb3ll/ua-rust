//! `fs_index_symbols`, `fs_list_symbols`, `fs_search_symbols`, `fs_repo_map`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::safety::{DEPENDENCY_DIRS, HOOK_DIRS, readable_entry, resolve_in_root};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

use super::lang::{Lang, ParseFailure, SUPPORTED_LANGUAGES, Symbol, function_keyword, parse_symbols};
use crate::families::workspace::{Sandbox, sandbox};
use crate::registry::{Registry, ToolCtx, blocking, tool};

/// Directories never indexed, besides hook and dependency trees.
const SKIP_DIRS: &[&str] = &[
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
    ".worktrees",
];
/// Source files larger than this are skipped.
const INDEX_FILE_MAX_BYTES: u64 = 1024 * 1024;
/// Upper bound on files one index run parses.
const INDEX_MAX_FILES: usize = 20_000;
const SEARCH_LIMIT: i64 = 100;
const SEMANTIC_NOTE: &str = "semantic symbol search is not available in this build (no symbol embeddings); \
                             these results are a lexical name match";

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IndexArgs {
    /// Directory (or one file) to index, relative to the workspace root (default ".").
    #[serde(default = "dot")]
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Source file, relative to the workspace root.
    pub file_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchArgs {
    /// Substring of the symbol name (case-insensitive).
    pub query: String,
    /// Ask for a semantic match. This build answers with a name match and says so.
    #[serde(default)]
    pub semantic: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoMapArgs {
    /// Workspace-relative directory or file to map (default ".").
    #[serde(default = "dot")]
    pub path: String,
    /// Target size of the map in tokens (about 4 characters each), default 1000.
    #[serde(default = "default_budget")]
    pub token_budget: i64,
}

fn dot() -> String {
    ".".into()
}

fn default_budget() -> i64 {
    1000
}

/// The key symbols are stored under: the canonical workspace root.
fn workspace_key(sb: &Sandbox) -> String {
    sb.root.to_string_lossy().into_owned()
}

/// `p` relative to the workspace root with `/` separators ("" for the root).
fn rel_slash(root: &Path, p: &Path) -> String {
    let rel = p.strip_prefix(root).unwrap_or(p);
    rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/")
}

fn skip_dir(name: &str) -> bool {
    let lower = name.to_lowercase();
    HOOK_DIRS.contains(&lower.as_str())
        || DEPENDENCY_DIRS.contains(&lower.as_str())
        || SKIP_DIRS.contains(&lower.as_str())
}

struct FileSymbols {
    rel: String,
    language: &'static str,
    symbols: Vec<Symbol>,
}

struct Scan {
    prefix: String,
    files: Vec<FileSymbols>,
    failures: BTreeMap<&'static str, usize>,
    failed_files: Vec<String>,
    skipped_large: usize,
    truncated: bool,
}

fn source_files(dir: &Path) -> impl Iterator<Item = ignore::DirEntry> {
    ignore::WalkBuilder::new(dir)
        .hidden(false)
        .follow_links(false)
        .require_git(false)
        .git_global(false)
        .sort_by_file_name(|a, b| a.cmp(b))
        .filter_entry(|e| {
            e.depth() == 0
                || !e.file_type().is_some_and(|t| t.is_dir())
                || !skip_dir(&e.file_name().to_string_lossy())
        })
        .build()
        .flatten()
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
}

fn scan(sb: &Sandbox, path: &str) -> UaResult<Scan> {
    let roots = std::slice::from_ref(&sb.root);
    let target = resolve_in_root(path, roots, false)?;
    if !target.exists() {
        return Err(UaError::not_found(format!("target path {path:?} does not exist")));
    }
    let prefix = rel_slash(&sb.root, &target);
    let mut scan = Scan {
        prefix,
        files: Vec::new(),
        failures: BTreeMap::new(),
        failed_files: Vec::new(),
        skipped_large: 0,
        truncated: false,
    };
    let candidates: Box<dyn Iterator<Item = PathBuf>> = if target.is_file() {
        Box::new(std::iter::once(target.clone()))
    } else {
        Box::new(source_files(&target).map(ignore::DirEntry::into_path))
    };
    let mut parsed = 0usize;
    for p in candidates {
        let Some(lang) = Lang::from_path(&p) else { continue };
        let Some((real, _)) = readable_entry(&p, roots) else { continue };
        let Ok(meta) = std::fs::metadata(&real) else { continue };
        if meta.len() > INDEX_FILE_MAX_BYTES {
            scan.skipped_large += 1;
            continue;
        }
        if parsed >= INDEX_MAX_FILES {
            scan.truncated = true;
            break;
        }
        let Ok(bytes) = std::fs::read(&real) else { continue };
        parsed += 1;
        let text = String::from_utf8_lossy(&bytes);
        let rel = rel_slash(&sb.root, &p);
        match parse_symbols(lang, &text) {
            Ok(symbols) => scan.files.push(FileSymbols { rel, language: lang.name(), symbols }),
            Err(f) => {
                *scan.failures.entry(f.code()).or_default() += 1;
                if scan.failed_files.len() < 20 {
                    scan.failed_files.push(rel);
                }
            }
        }
    }
    Ok(scan)
}

fn degraded_detail(failures: &BTreeMap<&'static str, usize>, sample: &[String]) -> Value {
    let affected: usize = failures.values().sum();
    let primary = if failures.contains_key(ParseFailure::GrammarUnavailable.code()) {
        "grammar_unavailable"
    } else {
        "parse_failed"
    };
    json!({
        "mode": "degraded",
        "reason": primary,
        "files_affected": affected,
        "reason_counts": failures,
        "sample_files": sample,
        "warning": format!(
            "{affected} file(s) could not be parsed ({primary}); their symbols are missing. \
             Treat a missing symbol there as unknown, not absent."
        ),
    })
}

/// Replace the stored symbols under `prefix` with `files`. Returns rows written.
fn store(tx: &rusqlite::Transaction<'_>, ws: &str, prefix: &str, files: &[FileSymbols]) -> UaResult<usize> {
    if prefix.is_empty() {
        tx.execute("DELETE FROM code_symbols WHERE workspace = ?1", [ws])?;
    } else {
        tx.execute(
            "DELETE FROM code_symbols WHERE workspace = ?1 \
             AND (file_path = ?2 OR substr(file_path, 1, length(?2) + 1) = ?2 || '/')",
            [ws, prefix],
        )?;
    }
    let mut stmt = tx.prepare(
        "INSERT INTO code_symbols (workspace, file_path, language, symbol_name, symbol_type, symbol_kind, \
         parent_name, signature, docstring, line_no) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )?;
    let mut n = 0;
    for f in files {
        for s in &f.symbols {
            stmt.execute(rusqlite::params![
                ws,
                f.rel,
                f.language,
                s.name,
                s.sym_type,
                s.kind,
                s.parent,
                s.signature,
                s.docstring,
                s.line_no as i64
            ])?;
            n += 1;
        }
    }
    Ok(n)
}

pub(super) async fn index(ctx: &ToolCtx, path: String) -> UaResult<Value> {
    let sb = sandbox(ctx)?;
    let ws = workspace_key(&sb);
    let sb2 = sb.clone();
    let scan = blocking(move || scan(&sb2, &path)).await?;

    let all: Vec<&Symbol> = scan.files.iter().flat_map(|f| f.symbols.iter()).collect();
    let count = |t: &str| all.iter().filter(|s| s.sym_type == t).count();
    let (classes, functions, methods) = (count("class"), count("function"), count("method"));
    let mut languages: BTreeMap<&str, usize> = BTreeMap::new();
    for f in &scan.files {
        *languages.entry(f.language).or_default() += 1;
    }
    let files_indexed = scan.files.len();
    let symbols_indexed = all.len();
    let shown_path = if scan.prefix.is_empty() { ".".to_string() } else { scan.prefix.clone() };

    let event = json!({
        "path": shown_path,
        "files_indexed": files_indexed,
        "symbols_indexed": symbols_indexed,
    });
    let by = ctx.caller.label.clone();
    let (ws2, prefix) = (ws.clone(), scan.prefix.clone());
    let files = scan.files;
    ctx.hub
        .db()
        .write_async(move |tx| {
            store(tx, &ws2, &prefix, &files)?;
            ledger::append(tx, EventInput::new("agent.code.indexed", event).by(by))?;
            Ok(())
        })
        .await?;

    let mut out = json!({
        "workspace": ws,
        "path": shown_path,
        "files_indexed": files_indexed,
        "symbols_indexed": symbols_indexed,
        "classes": classes,
        "functions": functions,
        "methods": methods,
        "languages": languages,
        "skipped_large_files": scan.skipped_large,
        "truncated": scan.truncated,
        "grammars": "statically linked: go, javascript (jsx), python, rust, typescript, tsx",
        "degraded": !scan.failures.is_empty(),
    });
    if !scan.failures.is_empty() {
        let detail = degraded_detail(&scan.failures, &scan.failed_files);
        out["warning"] = detail["warning"].clone();
        out["degraded_detail"] = detail;
    }
    Ok(out)
}

fn row_json(r: &rusqlite::Row<'_>, with_file: bool) -> rusqlite::Result<Value> {
    let mut v = json!({
        "name": r.get::<_, String>("symbol_name")?,
        "type": r.get::<_, String>("symbol_type")?,
        "kind": r.get::<_, String>("symbol_kind")?,
        "parent": r.get::<_, Option<String>>("parent_name")?,
        "signature": r.get::<_, String>("signature")?,
        "docstring": r.get::<_, String>("docstring")?,
        "line_no": r.get::<_, i64>("line_no")?,
    });
    if with_file {
        v["file_path"] = json!(r.get::<_, String>("file_path")?);
        v["language"] = json!(r.get::<_, String>("language")?);
    }
    Ok(v)
}

fn list_symbols(conn: &Connection, sb: &Sandbox, file_path: &str) -> UaResult<Value> {
    let p = resolve_in_root(file_path, std::slice::from_ref(&sb.root), false)?;
    if !p.is_file() {
        return Err(UaError::not_found(format!("file {file_path:?} does not exist")));
    }
    let rel = rel_slash(&sb.root, &p);
    let mut stmt = conn
        .prepare("SELECT * FROM code_symbols WHERE workspace = ?1 AND file_path = ?2 ORDER BY line_no, id")?;
    let rows: Vec<Value> = stmt
        .query_map([workspace_key(sb), rel.clone()], |r| row_json(r, false))?
        .collect::<Result<_, _>>()?;
    if !rows.is_empty() {
        return Ok(json!({ "symbols": rows, "degraded": false, "source": "index" }));
    }
    // Not indexed yet: parse on the fly.
    let Some(lang) = Lang::from_path(&p) else {
        return Ok(json!({
            "symbols": [],
            "degraded": false,
            "source": "parse",
            "note": format!("no grammar for this file type; supported: {}", SUPPORTED_LANGUAGES.join(", ")),
        }));
    };
    let meta =
        std::fs::metadata(&p).map_err(|e| UaError::invalid(format!("cannot read {file_path}: {e}")))?;
    if meta.len() > INDEX_FILE_MAX_BYTES {
        return Err(UaError::invalid(format!("file is larger than {INDEX_FILE_MAX_BYTES} bytes")));
    }
    let bytes = std::fs::read(&p).map_err(|e| UaError::invalid(format!("cannot read {file_path}: {e}")))?;
    match parse_symbols(lang, &String::from_utf8_lossy(&bytes)) {
        Ok(symbols) => Ok(json!({ "symbols": symbols, "degraded": false, "source": "parse" })),
        Err(f) => {
            let mut failures = BTreeMap::new();
            failures.insert(f.code(), 1);
            let detail = degraded_detail(&failures, &[rel]);
            Ok(json!({
                "symbols": [],
                "degraded": true,
                "source": "parse",
                "warning": detail["warning"].clone(),
                "degraded_detail": detail,
            }))
        }
    }
}

fn like_escape(q: &str) -> String {
    let mut s = String::with_capacity(q.len() + 2);
    s.push('%');
    for c in q.chars() {
        if matches!(c, '%' | '_' | '\\') {
            s.push('\\');
        }
        s.push(c);
    }
    s.push('%');
    s
}

fn search_symbols(conn: &Connection, ws: &str, query: &str, semantic: bool) -> UaResult<Value> {
    let q = query.trim();
    let mut stmt = conn.prepare(
        "SELECT * FROM code_symbols WHERE workspace = ?1 AND symbol_name LIKE ?2 ESCAPE '\\' \
         ORDER BY (lower(symbol_name) = lower(?3)) DESC, \
                  (substr(lower(symbol_name), 1, length(?3)) = lower(?3)) DESC, \
                  length(symbol_name), symbol_name, file_path, line_no \
         LIMIT ?4",
    )?;
    let results: Vec<Value> = stmt
        .query_map(rusqlite::params![ws, like_escape(q), q, SEARCH_LIMIT], |r| row_json(r, true))?
        .collect::<Result<_, _>>()?;
    let mut out = json!({ "results": results, "degraded": false });
    if semantic {
        out["semantic"] = json!(false);
        out["note"] = json!(SEMANTIC_NOTE);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Repository map
// ---------------------------------------------------------------------------

struct MapSym {
    file: String,
    language: String,
    name: String,
    sym_type: String,
    kind: String,
    parent: Option<String>,
    signature: String,
    docstring: String,
    line_no: i64,
}

fn load_map_symbols(conn: &Connection, ws: &str) -> UaResult<Vec<MapSym>> {
    let mut stmt = conn.prepare(
        "SELECT file_path, language, symbol_name, symbol_type, symbol_kind, parent_name, signature, docstring, \
         line_no FROM code_symbols WHERE workspace = ?1 ORDER BY id",
    )?;
    let rows = stmt
        .query_map([ws], |r| {
            Ok(MapSym {
                file: r.get(0)?,
                language: r.get(1)?,
                name: r.get(2)?,
                sym_type: r.get(3)?,
                kind: r.get(4)?,
                parent: r.get(5)?,
                signature: r.get(6)?,
                docstring: r.get(7)?,
                line_no: r.get(8)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

fn estimate_tokens(text: &str) -> i64 {
    (text.chars().count() as i64 + 3) / 4
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// PageRank over files and symbols: containment edges (file → symbol,
/// container → member) and reference edges (a symbol whose signature or
/// docstring names another symbol). Returns files, best first.
fn rank_files(syms: &[MapSym]) -> Vec<String> {
    let mut index: HashMap<String, usize> = HashMap::new();
    let node = |key: String, index: &mut HashMap<String, usize>| {
        let n = index.len();
        *index.entry(key).or_insert(n)
    };
    for s in syms {
        node(s.file.clone(), &mut index);
    }
    for s in syms {
        node(format!("{}::{}", s.file, s.name), &mut index);
    }
    let n = index.len();
    let mut out_edges: Vec<Vec<usize>> = vec![Vec::new(); n];
    let id = |k: &str| index.get(k).copied();
    let mut by_name: HashMap<&str, usize> = HashMap::new();
    for s in syms {
        if let Some(i) = id(&format!("{}::{}", s.file, s.name)) {
            by_name.insert(&s.name, i);
        }
    }
    for s in syms {
        let Some(me) = id(&format!("{}::{}", s.file, s.name)) else { continue };
        if let Some(f) = id(&s.file) {
            out_edges[f].push(me);
        }
        if let Some(p) = s.parent.as_ref().and_then(|p| id(&format!("{}::{}", s.file, p))) {
            out_edges[p].push(me);
        }
        let text = format!("{} {}", s.signature, s.docstring);
        for tok in text.split(|c: char| !is_ident(c)) {
            if tok.chars().count() > 3
                && let Some(&other) = by_name.get(tok)
                && other != me
            {
                out_edges[me].push(other);
            }
        }
    }
    let d = 0.85;
    let nf = n as f64;
    let mut pr = vec![1.0 / nf; n];
    for _ in 0..20 {
        let sink: f64 = (0..n).filter(|&u| out_edges[u].is_empty()).map(|u| pr[u]).sum();
        let mut next = vec![(1.0 - d) / nf + d * sink / nf; n];
        for (u, edges) in out_edges.iter().enumerate() {
            if edges.is_empty() {
                continue;
            }
            let share = d * pr[u] / edges.len() as f64;
            for &v in edges {
                next[v] += share;
            }
        }
        pr = next;
    }
    let mut files: BTreeMap<&str, f64> = BTreeMap::new();
    for s in syms {
        let f = files.entry(&s.file).or_insert_with(|| id(&s.file).map(|i| pr[i]).unwrap_or(0.0));
        if let Some(i) = id(&format!("{}::{}", s.file, s.name)) {
            *f += pr[i];
        }
    }
    let mut ranked: Vec<(&str, f64)> = files.into_iter().collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(b.0)));
    ranked.into_iter().map(|(f, _)| f.to_string()).collect()
}

fn file_block(file: &str, syms: &[&MapSym]) -> Vec<String> {
    let mut lines = vec![format!("## `{file}`")];
    let mut syms: Vec<&&MapSym> = syms.iter().collect();
    syms.sort_by_key(|s| s.line_no);
    let containers: Vec<&&MapSym> = syms.iter().copied().filter(|s| s.sym_type == "class").collect();
    let mut shown_methods = std::collections::HashSet::new();
    for c in &containers {
        let mut l = format!("  - `{} {}`", c.kind, c.name);
        if !c.docstring.is_empty() {
            l.push_str(&format!(" — *{}*", c.docstring));
        }
        lines.push(l);
        for m in
            syms.iter().filter(|m| m.sym_type == "method" && m.parent.as_deref() == Some(c.name.as_str()))
        {
            shown_methods.insert((m.name.as_str(), m.line_no));
            lines.push(format!("    - `{} {}{}`", function_keyword(&m.language), m.name, m.signature));
        }
    }
    for f in syms.iter().filter(|s| s.sym_type == "function" && s.parent.is_none()) {
        let mut l = format!("  - `{} {}{}`", function_keyword(&f.language), f.name, f.signature);
        if !f.docstring.is_empty() {
            l.push_str(&format!(" — *{}*", f.docstring));
        }
        lines.push(l);
    }
    // Methods of types declared elsewhere (impl blocks, Go receivers).
    for m in syms
        .iter()
        .filter(|m| m.sym_type == "method" && !shown_methods.contains(&(m.name.as_str(), m.line_no)))
    {
        let parent = m.parent.as_deref().unwrap_or("?");
        lines.push(format!("  - `{} {parent}.{}{}`", function_keyword(&m.language), m.name, m.signature));
    }
    lines.push(String::new());
    lines
}

fn render_map(path: &str, prefix: &str, all: Vec<MapSym>, budget: i64) -> String {
    let owned: Vec<MapSym> = all
        .into_iter()
        .filter(|s| prefix.is_empty() || s.file == prefix || s.file.starts_with(&format!("{prefix}/")))
        .collect();
    if owned.is_empty() {
        return format!("# Repository Map: {path}\n\n*No indexed symbols found under {path:?}.*");
    }
    let mut by_file: HashMap<&str, Vec<&MapSym>> = HashMap::new();
    for s in &owned {
        by_file.entry(&s.file).or_default().push(s);
    }
    let mut lines = vec![format!("# Codebase Map: {path}"), String::new()];
    let mut tokens = estimate_tokens(&lines.join("\n"));
    for file in rank_files(&owned) {
        if tokens >= budget {
            lines.push("... [truncated to fit token budget]".into());
            break;
        }
        let block = file_block(&file, by_file.get(file.as_str()).map(Vec::as_slice).unwrap_or(&[]));
        let block_tokens = estimate_tokens(&block.join("\n"));
        if tokens + block_tokens > budget && lines.len() > 2 {
            lines.push("... [truncated to fit token budget]".into());
            break;
        }
        lines.extend(block);
        tokens += block_tokens;
    }
    lines.join("\n").trim().to_string()
}

async fn repo_map(ctx: ToolCtx, a: RepoMapArgs) -> UaResult<Value> {
    let sb = sandbox(&ctx)?;
    let target = resolve_in_root(&a.path, std::slice::from_ref(&sb.root), false)?;
    if !target.exists() {
        return Err(UaError::not_found(format!("target path {:?} does not exist", a.path)));
    }
    let prefix = rel_slash(&sb.root, &target);
    let ws = workspace_key(&sb);
    let budget = a.token_budget.clamp(1, 100_000);

    let ws2 = ws.clone();
    let mut syms = ctx.hub.db().read_async(move |c| load_map_symbols(c, &ws2)).await?;
    if syms.is_empty() {
        index(&ctx, ".".into()).await?;
        let ws2 = ws.clone();
        syms = ctx.hub.db().read_async(move |c| load_map_symbols(c, &ws2)).await?;
    }
    let path = a.path.clone();
    let map = blocking(move || Ok(render_map(&path, &prefix, syms, budget))).await?;
    Ok(json!({
        "workspace": ws,
        "path": a.path,
        "token_budget": budget,
        "estimated_tokens": estimate_tokens(&map),
        "repo_map": map,
    }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "fs_index_symbols",
            "Index code symbols (classes, structs, traits, interfaces, functions, methods) under a \
             workspace directory with tree-sitter (Rust, Python, JS/JSX, TS/TSX, Go; grammars compiled \
             in). Skips VCS, dependency and build directories, gitignored paths and files over 1 MB, and \
             replaces the stored symbols under that path. Returns {workspace, path, files_indexed, \
             symbols_indexed, classes, functions, methods, languages, degraded, [warning]}.",
            |ctx: ToolCtx, a: IndexArgs| async move { index(&ctx, a.path).await },
        )
        .family("code"),
    );
    r.add(
        tool(
            "fs_list_symbols",
            "List the symbols of one workspace file in line order, from the index or, when the file is \
             not indexed yet, by parsing it now. Returns {symbols: [{name, type, kind, parent, signature, \
             docstring, line_no}], degraded}.",
            |ctx: ToolCtx, a: ListArgs| async move {
                let sb = sandbox(&ctx)?;
                ctx.hub.db().read_async(move |c| list_symbols(c, &sb, &a.file_path)).await
            },
        )
        .family("code")
        .read_only(),
    );
    r.add(
        tool(
            "fs_search_symbols",
            "Search indexed symbols of this workspace by name substring (exact and prefix matches first, \
             max 100). semantic=true is accepted but answered with the name match and a note. Returns \
             {results: [{file_path, language, name, type, kind, parent, signature, docstring, line_no}], \
             degraded, [semantic, note]}.",
            |ctx: ToolCtx, a: SearchArgs| async move {
                let ws = workspace_key(&sandbox(&ctx)?);
                ctx.hub.db().read_async(move |c| search_symbols(c, &ws, &a.query, a.semantic)).await
            },
        )
        .family("code")
        .read_only(),
    );
    r.add(
        tool(
            "fs_repo_map",
            "Markdown map of the codebase under a workspace path: files ranked by PageRank over \
             containment and name references, with their classes and function signatures, trimmed to \
             token_budget (default 1000). Indexes the workspace first when nothing is indexed. Returns \
             {workspace, path, token_budget, estimated_tokens, repo_map}.",
            repo_map,
        )
        .family("code"),
    );
}

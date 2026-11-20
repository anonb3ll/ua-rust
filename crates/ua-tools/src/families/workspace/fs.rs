//! `fs_read`, `fs_write`, `fs_list`, `fs_search`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use globset::{GlobBuilder, GlobMatcher};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::safety::{
    DEPENDENCY_DIRS, HOOK_DIRS, canonicalize_lenient, guard_secret_filename, readable_entry,
    resolve_for_read, resolve_in_root,
};
use ua_core::{UaError, UaResult};

use super::{Sandbox, git_env, record, run_program, sandbox, sha256_hex};
use crate::registry::{Registry, ToolCtx, blocking, tool};

/// Largest file `fs_read` opens.
pub const READ_MAX_BYTES: u64 = 1024 * 1024;
/// Largest `fs_write` payload.
pub const WRITE_MAX_BYTES: usize = 2 * 1024 * 1024;
/// Files larger than this are skipped by `fs_search`.
pub const SEARCH_FILE_MAX_BYTES: u64 = 1024 * 1024;
/// Upper bound on files `fs_search` opens, and entries a recursive `fs_list` visits.
const WALK_MAX_FILES: usize = 50_000;

/// Serializes compare-and-write so two writers cannot interleave.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadArgs {
    /// File path, relative to the workspace root, or absolute inside a read root.
    pub path: String,
    /// First line to return (0-based).
    #[serde(default)]
    pub offset: usize,
    /// Lines to return, 1-5000 (default 2000).
    #[serde(default = "default_read_limit")]
    pub limit: usize,
}

fn default_read_limit() -> usize {
    2000
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteArgs {
    /// File path inside the workspace root. Parent directories are created.
    pub path: String,
    /// Text to write (max 2 MB).
    pub content: String,
    /// Append instead of replacing.
    #[serde(default)]
    pub append: bool,
    /// Replace only if the current file has this SHA-256 (hex); an empty
    /// string requires that the file does not exist yet.
    pub expected_content_hash: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Directory to list (default: the workspace root).
    #[serde(default = "dot")]
    pub path: String,
    /// Glob relative to `path`, e.g. `*.rs` or `src/**/*.rs`. No `..`, not absolute.
    pub glob: Option<String>,
    /// 1-2000 (default 500).
    #[serde(default = "default_list_max")]
    pub max_entries: usize,
}

fn dot() -> String {
    ".".into()
}

fn default_list_max() -> usize {
    500
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchArgs {
    /// Regular expression (Rust `regex` syntax), matched per line.
    pub pattern: String,
    /// Directory to search (default: the workspace root).
    #[serde(default = "dot")]
    pub path: String,
    /// File-name glob such as `*.py`; a glob with `/` matches the path below `path`.
    pub glob: Option<String>,
    /// 1-1000 (default 100).
    #[serde(default = "default_search_max")]
    pub max_results: usize,
}

fn default_search_max() -> usize {
    100
}

fn fs_read(sb: &Sandbox, a: ReadArgs) -> UaResult<Value> {
    let p = resolve_for_read(&a.path, &sb.root, &sb.read_roots)?;
    let meta = std::fs::metadata(&p).map_err(|_| UaError::not_found(format!("no such file: {}", a.path)))?;
    if meta.is_dir() {
        return Err(UaError::invalid(format!("{} is a directory; use fs_list", a.path)));
    }
    if meta.len() > READ_MAX_BYTES {
        return Err(UaError::invalid(format!(
            "file is larger than {READ_MAX_BYTES} bytes; use fs_search to inspect parts of it"
        )));
    }
    let bytes = std::fs::read(&p).map_err(|e| UaError::invalid(format!("cannot read {}: {e}", a.path)))?;
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();
    let limit = a.limit.clamp(1, 5000);
    let start = a.offset.min(lines.len());
    let end = start.saturating_add(limit).min(lines.len());
    let window = &lines[start..end];
    Ok(json!({
        "path": a.path,
        "content": window.join("\n"),
        "total_lines": lines.len(),
        "truncated": end < lines.len(),
    }))
}

/// The nearest directory at or above `p` (inside `root`) holding a `.git` entry.
fn repository_root(p: &Path, root: &Path) -> Option<PathBuf> {
    repository_at_or_above(p.parent()?, root)
}

/// The nearest directory at or above `start` itself (inside `root`) holding a `.git` entry.
fn repository_at_or_above(start: &Path, root: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        if !dir.starts_with(root) {
            return None;
        }
        if dir.join(".git").symlink_metadata().is_ok() {
            return Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    None
}

/// The repository's configured `core.hooksPath`, resolved, when one is set.
async fn configured_hooks_dir(repo: &Path) -> Option<PathBuf> {
    let args: Vec<String> =
        ["config", "--path", "--get", "core.hooksPath"].iter().map(|s| s.to_string()).collect();
    // git is not installed: it cannot run hooks either.
    let out = run_program("git", &args, repo, &git_env(), Duration::from_secs(10), 64 * 1024).await.ok()?;
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.exit_code != 0 || value.is_empty() {
        return None;
    }
    Some(canonicalize_lenient(&repo.join(&value)).unwrap_or_else(|_| repo.join(&value)))
}

fn hook_dir_refusal(shown: &str) -> UaError {
    UaError::denied("hook_dir", format!("{shown:?} is inside the repository's configured hooks directory"))
}

/// Refuse a write into the repository's configured `core.hooksPath`: a custom
/// hooks directory can have any name, so the fixed hook-dir list cannot see it.
pub(crate) async fn guard_configured_hooks(resolved: &Path, root: &Path, shown: &str) -> UaResult<()> {
    let Some(repo) = repository_root(resolved, root) else { return Ok(()) };
    match configured_hooks_dir(&repo).await {
        Some(hooks) if resolved.starts_with(&hooks) => Err(hook_dir_refusal(shown)),
        _ => Ok(()),
    }
}

/// [`guard_configured_hooks`] for a directory a tool rewrites files under:
/// refused when it lies inside the configured hooks directory of the
/// repository holding it, or when that hooks directory lies inside it.
pub(crate) async fn guard_configured_hooks_dir(dir: &Path, root: &Path, shown: &str) -> UaResult<()> {
    let Some(repo) = repository_at_or_above(dir, root) else { return Ok(()) };
    match configured_hooks_dir(&repo).await {
        Some(hooks) if dir.starts_with(&hooks) => Err(hook_dir_refusal(shown)),
        Some(hooks) if hooks.starts_with(dir) => Err(UaError::denied(
            "hook_dir",
            format!("{shown:?} contains the repository's configured hooks directory"),
        )),
        _ => Ok(()),
    }
}

fn write_file(p: &Path, a: &WriteArgs) -> UaResult<()> {
    let _guard = WRITE_LOCK.lock().map_err(|_| UaError::internal("write lock poisoned"))?;
    if let Some(expected) = &a.expected_content_hash {
        let observed = match std::fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(UaError::invalid("conditional writes refuse symlink destinations"));
            }
            Ok(m) if !m.is_file() || m.len() as usize > WRITE_MAX_BYTES => {
                return Err(UaError::invalid("existing file cannot be compared within the write limit"));
            }
            Ok(_) => {
                sha256_hex(&std::fs::read(p).map_err(|e| UaError::invalid(format!("cannot read: {e}")))?)
            }
            Err(_) => String::new(),
        };
        if &observed != expected {
            return Err(UaError::conflict("existing file changed; expected_content_hash does not match"));
        }
    }
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| UaError::invalid(format!("cannot create {}: {e}", parent.display())))?;
    }
    let res = if a.append {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .and_then(|mut f| f.write_all(a.content.as_bytes()))
    } else {
        std::fs::write(p, a.content.as_bytes())
    };
    res.map_err(|e| UaError::invalid(format!("cannot write {}: {e}", a.path)))
}

async fn fs_write(ctx: ToolCtx, a: WriteArgs) -> UaResult<Value> {
    let sb = sandbox(&ctx)?;
    let bytes = a.content.len();
    if bytes > WRITE_MAX_BYTES {
        return Err(UaError::invalid(format!("content exceeds {WRITE_MAX_BYTES} bytes; write in chunks")));
    }
    if let Some(h) = &a.expected_content_hash {
        if a.append {
            return Err(UaError::invalid("expected_content_hash is only supported for replacement writes"));
        }
        if !h.is_empty()
            && !(h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        {
            return Err(UaError::invalid("expected_content_hash must be a SHA-256 hex digest or empty"));
        }
    }
    let p = resolve_in_root(&a.path, std::slice::from_ref(&sb.root), true)?;
    if p.is_dir() {
        return Err(UaError::invalid(format!("{} is a directory", a.path)));
    }
    guard_secret_filename(&p)?;
    guard_configured_hooks(&p, &sb.root, &a.path).await?;
    let sha = sha256_hex(a.content.as_bytes());
    let append = a.append;
    let target = p.clone();
    let path = a.path.clone();
    blocking(move || write_file(&target, &a)).await?;
    record(
        &ctx,
        "agent.fs.written",
        json!({ "path": sb.rel(&p), "bytes": bytes, "append": append, "content_sha256": sha }),
    )
    .await?;
    Ok(json!({ "path": path, "bytes_written": bytes }))
}

fn glob_matcher(glob: &str) -> UaResult<GlobMatcher> {
    let g = Path::new(glob);
    if g.is_absolute() || g.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(UaError::invalid(format!(
            "glob {glob:?} must be relative to path and must not contain '..'"
        )));
    }
    GlobBuilder::new(glob)
        .literal_separator(true)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| UaError::invalid(format!("invalid glob: {e}")))
}

/// Skip hook and dependency trees while walking; they are refused anyway.
fn walk_allowed(entry: &ignore::DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_some_and(|t| t.is_dir()) {
        return true;
    }
    let name = entry.file_name().to_string_lossy().to_lowercase();
    !HOOK_DIRS.contains(&name.as_str()) && !DEPENDENCY_DIRS.contains(&name.as_str())
}

fn fs_list(sb: &Sandbox, a: ListArgs) -> UaResult<Value> {
    let matcher = a.glob.as_deref().map(glob_matcher).transpose()?;
    let dir = resolve_for_read(&a.path, &sb.root, &sb.read_roots)?;
    if !dir.is_dir() {
        return Err(UaError::invalid(format!("not a directory: {}", a.path)));
    }
    let cap = a.max_entries.clamp(1, 2000);
    let recursive = a.glob.as_deref().is_some_and(|g| g.contains('/') || g.contains("**"));

    let mut items: Vec<PathBuf> = Vec::new();
    if recursive {
        let walker = ignore::WalkBuilder::new(&dir)
            .standard_filters(false)
            .hidden(false)
            .follow_links(false)
            .filter_entry(walk_allowed)
            .build();
        for entry in walker.flatten().take(WALK_MAX_FILES) {
            if entry.depth() == 0 {
                continue;
            }
            let rel = entry.path().strip_prefix(&dir).unwrap_or(entry.path());
            if matcher.as_ref().is_some_and(|m| m.is_match(rel)) {
                items.push(entry.into_path());
            }
        }
    } else {
        let rd =
            std::fs::read_dir(&dir).map_err(|e| UaError::invalid(format!("cannot list {}: {e}", a.path)))?;
        for entry in rd.flatten() {
            let name = entry.file_name();
            if matcher.as_ref().is_none_or(|m| m.is_match(Path::new(&name))) {
                items.push(entry.path());
            }
        }
    }
    items.sort_by(|x, y| x.file_name().cmp(&y.file_name()));

    let roots = sb.all_read_roots();
    let mut entries = Vec::new();
    for item in items {
        let Some((real, _)) = readable_entry(&item, &roots) else { continue };
        let Ok(meta) = std::fs::metadata(&real) else { continue };
        entries.push(json!({
            "name": item.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            "type": if meta.is_dir() { "dir" } else { "file" },
            "size": if meta.is_file() { json!(meta.len()) } else { Value::Null },
        }));
        if entries.len() > cap {
            break;
        }
    }
    let truncated = entries.len() > cap;
    entries.truncate(cap);
    Ok(json!({ "entries": entries, "truncated": truncated }))
}

fn fs_search(sb: &Sandbox, a: SearchArgs) -> UaResult<Value> {
    let rx = regex::RegexBuilder::new(&a.pattern)
        .size_limit(16 * 1024 * 1024)
        .build()
        .map_err(|e| UaError::invalid(format!("invalid regex: {e}")))?;
    let matcher = a.glob.as_deref().map(glob_matcher).transpose()?;
    let by_path = a.glob.as_deref().is_some_and(|g| g.contains('/'));
    let dir = resolve_for_read(&a.path, &sb.root, &sb.read_roots)?;
    if !dir.is_dir() {
        return Err(UaError::invalid(format!("not a directory: {}", a.path)));
    }
    let cap = a.max_results.clamp(1, 1000);
    let roots = sb.all_read_roots();

    let walker = ignore::WalkBuilder::new(&dir)
        .hidden(false)
        .follow_links(false)
        .require_git(false)
        .git_global(false)
        .sort_by_file_name(|x, y| x.cmp(y))
        .filter_entry(walk_allowed)
        .build();

    let mut matches = Vec::new();
    let mut truncated = false;
    let mut visited = 0usize;
    'files: for entry in walker.flatten() {
        if entry.file_type().is_some_and(|t| t.is_dir()) {
            continue;
        }
        if let Some(m) = &matcher {
            let rel = entry.path().strip_prefix(&dir).unwrap_or(entry.path());
            let ok = if by_path { m.is_match(rel) } else { m.is_match(Path::new(entry.file_name())) };
            if !ok {
                continue;
            }
        }
        visited += 1;
        if visited > WALK_MAX_FILES {
            truncated = true;
            break;
        }
        // Read the guarded real path, never re-follow the link.
        let Some((real, root)) = readable_entry(entry.path(), &roots) else { continue };
        let Ok(meta) = std::fs::metadata(&real) else { continue };
        if !meta.is_file() || meta.len() > SEARCH_FILE_MAX_BYTES {
            continue;
        }
        let Ok(bytes) = std::fs::read(&real) else { continue };
        if bytes[..bytes.len().min(8192)].contains(&0) {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        let shown = real.strip_prefix(&root).unwrap_or(&real).to_string_lossy().into_owned();
        for (i, line) in text.lines().enumerate() {
            if rx.is_match(line) {
                if matches.len() >= cap {
                    truncated = true;
                    break 'files;
                }
                let line: String = line.chars().take(500).collect();
                matches.push(json!({ "path": shown, "line_no": i + 1, "line": line }));
            }
        }
    }
    Ok(json!({ "matches": matches, "truncated": truncated }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "fs_read",
            "Read a text file from the workspace or a read root, by line (limit 1-5000, default 2000; \
             page with offset). Files over 1 MB are refused. Returns {path, content, total_lines, truncated}.",
            |ctx: ToolCtx, a: ReadArgs| async move {
                let sb = sandbox(&ctx)?;
                blocking(move || fs_read(&sb, a)).await
            },
        )
        .family("workspace")
        .read_only(),
    );
    r.add(
        tool(
            "fs_write",
            "Write or append a text file inside the workspace root (max 2 MB), creating parent \
             directories. Hook directories and credential stores are refused. Returns {path, bytes_written}.",
            fs_write,
        )
        .family("workspace"),
    );
    r.add(
        tool(
            "fs_list",
            "List a directory, optionally filtered by a glob relative to it. Entries a direct read \
             would refuse are omitted. Returns {entries: [{name, type, size}], truncated}.",
            |ctx: ToolCtx, a: ListArgs| async move {
                let sb = sandbox(&ctx)?;
                blocking(move || fs_list(&sb, a)).await
            },
        )
        .family("workspace")
        .read_only(),
    );
    r.add(
        tool(
            "fs_search",
            "Regex-search text files under a directory (gitignore-aware; skips binaries and files over \
             1 MB; lines cut at 500 chars). Returns {matches: [{path, line_no, line}], truncated}.",
            |ctx: ToolCtx, a: SearchArgs| async move {
                let sb = sandbox(&ctx)?;
                blocking(move || fs_search(&sb, a)).await
            },
        )
        .family("workspace")
        .read_only(),
    );
}

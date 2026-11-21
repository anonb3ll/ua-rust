//! `vault_read`, `vault_write`, `vault_move`, `vault_list`, `vault_search`, `vault_links`.

use std::io::{Read, Write};
use std::path::Path;

use globset::GlobBuilder;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};

use super::links::{self, expand_embeds};
use super::{
    LOCK_HEAD_BYTES, READ_MAX_BYTES, REVISION_ABSENT, SEARCH_FILE_MAX_BYTES, Vault, WRITE_MAX_BYTES,
    frontmatter, locked_error, mark_untrusted, note_is_locked, note_revision, read_note, read_text_lossy,
    record, revision_of, stem, vault, with_note_locks,
};
use crate::registry::{Registry, ToolCtx, blocking, tool};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadArgs {
    /// Vault-relative note path (or absolute inside the vault).
    pub path: String,
    /// First line to return (0-based).
    #[serde(default)]
    pub offset: usize,
    /// Lines to return, 1-5000 (default 2000).
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Expand `![[note]]` transclusions inline, two levels deep; a cycle is
    /// shown as a marker instead of repeating.
    #[serde(default)]
    pub expand_embeds: bool,
}

fn default_limit() -> usize {
    2000
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteArgs {
    /// Note path inside one of the vault write directories; `.md` or `.txt`.
    pub path: String,
    /// Note text (max 2 MB). With `template`, fills `{{content}}` or is appended.
    #[serde(default)]
    pub content: String,
    /// `overwrite` (default, replaces the note), `append`, or `create` (the
    /// note must not exist yet). There is no partial-edit mode: read the note
    /// and write it back whole.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Legacy spelling of `mode="append"`.
    #[serde(default)]
    pub append: bool,
    /// Override a `locked: true` note. Only a verified human may pass it.
    #[serde(default)]
    pub force: bool,
    /// Vault path of a template note. `{{date}}`, `{{time}}`, `{{datetime}}`,
    /// `{{yesterday}}`, `{{tomorrow}}`, `{{title}}` (the target's stem) and
    /// `{{content}}` are replaced.
    pub template: Option<String>,
    /// The `revision` `vault_read` returned; the write is refused, with nothing
    /// written, if the note changed since. `absent` means it must not exist yet.
    pub expected_revision: Option<String>,
}

fn default_mode() -> String {
    "overwrite".into()
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveArgs {
    /// Note to move (inside the write directories).
    pub source: String,
    /// Full destination note path (inside the write directories).
    pub destination: String,
    /// Move a locked note or replace an existing destination. Verified humans only.
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Vault directory (default: the vault root).
    #[serde(default = "dot")]
    pub path: String,
    /// Glob relative to `path`, e.g. `*.md` or `**/*.md`. No `..`, not absolute.
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
    /// Vault directory to search (default: the vault root).
    #[serde(default = "dot")]
    pub path: String,
    /// 1-1000 (default 100).
    #[serde(default = "default_search_max")]
    pub max_results: usize,
}

fn default_search_max() -> usize {
    100
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinksArgs {
    /// Vault-relative note path.
    pub path: String,
}

// ── read ───────────────────────────────────────────────────────────────────

fn vault_read(v: &Vault, a: ReadArgs) -> UaResult<Value> {
    let p = v.resolve(&a.path)?;
    if p.is_dir() {
        return Err(UaError::invalid(format!("{} is a directory; use vault_list", a.path)));
    }
    let raw = read_note(&p, &a.path, READ_MAX_BYTES)?;
    let revision = revision_of(&raw);
    let head = &raw[..raw.len().min(LOCK_HEAD_BYTES)];
    let locked = frontmatter::head_is_locked(head, raw.len() > LOCK_HEAD_BYTES);
    let mut content = String::from_utf8_lossy(&raw).into_owned();
    let mut embedded_untrusted = false;
    if a.expand_embeds {
        let (expanded, untrusted) = expand_embeds(v, &content, &p);
        content = expanded;
        embedded_untrusted = untrusted;
    }
    let lines: Vec<&str> = content.lines().collect();
    let limit = a.limit.clamp(1, 5000);
    let start = a.offset.min(lines.len());
    let end = start.saturating_add(limit).min(lines.len());
    let rel = v.rel(&p);
    let mut out = json!({
        "path": rel,
        "content": lines[start..end].join("\n"),
        "total_lines": lines.len(),
        "truncated": end < lines.len(),
        "revision": revision,
        "locked": locked,
    });
    if v.is_inbox(&rel) || embedded_untrusted {
        mark_untrusted(&mut out);
    }
    Ok(out)
}

// ── write ──────────────────────────────────────────────────────────────────

fn valid_revision(r: &str) -> bool {
    r == REVISION_ABSENT
        || r.strip_prefix("sha256:").is_some_and(|h| {
            h.len() == 64 && h.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        })
}

/// Fill a template's placeholders.
pub(crate) fn apply_template(template: &str, target: &Path, content: &str) -> String {
    let now = jiff::ZonedDateTime::now();
    let fmt_day = |z: Option<jiff::ZonedDateTime>| z.map(|z| z.date().to_string()).unwrap_or_default();
    let pairs = [
        ("{{date}}", now.date().to_string()),
        ("{{time}}", now.strftime("%H:%M").to_string()),
        ("{{datetime}}", now.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string()),
        ("{{yesterday}}", fmt_day(now.yesterday().ok())),
        ("{{tomorrow}}", fmt_day(now.tomorrow().ok())),
        ("{{title}}", stem(target)),
        ("{{content}}", content.to_string()),
    ];
    let mut out = template.to_string();
    for (k, val) in &pairs {
        out = out.replace(k, val);
    }
    if !template.contains("{{content}}") && !content.is_empty() {
        out = format!("{}\n\n{content}", out.trim_end());
    }
    out
}

/// Count lines the way `vault_read` does (`\n`, a final unterminated line counts).
fn count_lines(p: &Path) -> Option<usize> {
    let mut f = std::fs::File::open(p).ok()?;
    let mut buf = vec![0u8; 1 << 16];
    let (mut n, mut tail) = (0usize, false);
    loop {
        let read = f.read(&mut buf).ok()?;
        if read == 0 {
            break;
        }
        n += buf[..read].iter().filter(|b| **b == b'\n').count();
        tail = buf[read - 1] != b'\n';
    }
    Some(n + usize::from(tail))
}

/// What a write did, for the result and the ledger event.
pub(crate) struct Written {
    pub rel: String,
    pub bytes: usize,
    pub mode: &'static str,
    pub append: bool,
    pub revision: Option<String>,
    pub total_lines_after: Option<usize>,
}

impl Written {
    pub fn to_json(&self) -> Value {
        json!({
            "path": self.rel,
            "bytes_written": self.bytes,
            "mode": self.mode,
            "append": self.append,
            "total_lines_after": self.total_lines_after,
            "revision": self.revision,
        })
    }

    pub fn event(&self) -> Value {
        json!({
            "path": self.rel,
            "bytes_written": self.bytes,
            "mode": self.mode,
            "append": self.append,
            "revision": self.revision,
        })
    }
}

/// The shared write path: lock guard, revision check and the write, all
/// under the note lock. `mode` is `overwrite`, `append` or `create`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_note(
    v: &Vault,
    shown: &str,
    p: &Path,
    data: &[u8],
    mode: &'static str,
    force: bool,
    expected_revision: Option<&str>,
    require_revision: bool,
) -> UaResult<Written> {
    if data.len() > WRITE_MAX_BYTES {
        return Err(UaError::invalid(format!("content exceeds {WRITE_MAX_BYTES} bytes; write in chunks")));
    }
    let rel = v.rel(p);
    let append = mode == "append";
    with_note_locks(&[&rel], || {
        if !force && note_is_locked(p, shown)? {
            return Err(locked_error(shown));
        }
        let expected = if mode == "create" { Some(REVISION_ABSENT) } else { expected_revision };
        if let Some(exp) = expected {
            let current = note_revision(p)?;
            if current != exp {
                let msg = if exp == REVISION_ABSENT {
                    format!("note {shown:?} already exists (revision {current}); nothing was written")
                } else if current == REVISION_ABSENT {
                    format!(
                        "note {shown:?} does not exist (expected revision {exp}); it was moved or deleted since your read. Nothing was written"
                    )
                } else {
                    format!(
                        "note {shown:?} changed since your read: expected revision {exp}, current revision {current}. Nothing was written: re-read, merge and write again with the new revision"
                    )
                };
                return Err(UaError::conflict(msg));
            }
        } else if require_revision && !append && p.is_file() {
            return Err(UaError::conflict(format!(
                "note {shown:?} exists and this hub requires expected_revision to overwrite; vault_read it and write again with its revision"
            )));
        }
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                UaError::invalid(format!("cannot create the note's directory ({e}); nothing was written"))
            })?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(!append)
            .open(p)
            .map_err(|e| UaError::invalid(format!("cannot open note {rel:?} ({e}); nothing was written")))?;
        f.write_all(data).and_then(|_| f.flush()).map_err(|e| {
            UaError::internal(format!(
                "write to {rel:?} failed after it began ({e}); the note may be partly written: read it before writing again"
            ))
        })?;
        drop(f);
        let revision = if append { note_revision(p).ok() } else { Some(revision_of(data)) };
        Ok(Written {
            rel: rel.clone(),
            bytes: data.len(),
            mode,
            append,
            revision,
            total_lines_after: count_lines(p),
        })
    })
}

fn require_human_force(v: &Vault, force: bool) -> UaResult<()> {
    if force && !v.caller.is_human() {
        return Err(UaError::denied(
            "force_requires_human",
            "force=true overrides a note lock and is reserved for a verified human",
        ));
    }
    Ok(())
}

fn vault_write(v: &Vault, a: WriteArgs, require_revision: bool) -> UaResult<Written> {
    let mode: &'static str = match (a.mode.as_str(), a.append) {
        ("append", _) | ("overwrite", true) => "append",
        ("overwrite", false) => "overwrite",
        ("create", false) => "create",
        ("create", true) => return Err(UaError::invalid("append=true conflicts with mode=\"create\"")),
        (other, _) => {
            return Err(UaError::invalid(format!(
                "mode must be one of overwrite, append, create; got {other:?} (there is no partial-edit mode: read the note, then write it back whole)"
            )));
        }
    };
    if let Some(r) = &a.expected_revision
        && !valid_revision(r)
    {
        return Err(UaError::invalid(format!(
            "expected_revision must be the `revision` vault_read returned ('sha256:' + 64 lowercase hex) or {REVISION_ABSENT:?}; got {r:?}"
        )));
    }
    require_human_force(v, a.force)?;
    let p = v.resolve_write(&a.path)?;
    let content = match &a.template {
        Some(t) => {
            let tp = v.resolve(t)?;
            let raw = read_note(&tp, t, READ_MAX_BYTES)
                .map_err(|_| UaError::not_found(format!("template note not found: {t}")))?;
            apply_template(&String::from_utf8_lossy(&raw), &p, &a.content)
        }
        None => a.content,
    };
    write_note(
        v,
        &a.path,
        &p,
        content.as_bytes(),
        mode,
        a.force,
        a.expected_revision.as_deref(),
        require_revision,
    )
}

// ── move ───────────────────────────────────────────────────────────────────

fn vault_move(v: &Vault, a: MoveArgs) -> UaResult<Value> {
    if !v.operator {
        return Err(UaError::denied(
            "operator_required",
            "vault_move requires an operator (a verified human)",
        ));
    }
    require_human_force(v, a.force)?;
    let src = v.resolve_write(&a.source)?;
    let dst = v.resolve_write(&a.destination)?;
    if src == dst {
        return Err(UaError::invalid("source and destination are the same path"));
    }
    let (src_rel, dst_rel) = (v.rel(&src), v.rel(&dst));
    with_note_locks(&[&src_rel, &dst_rel], || {
        if !src.is_file() {
            return Err(UaError::not_found(format!("no such note: {}", a.source)));
        }
        if dst.is_dir() {
            return Err(UaError::invalid(format!(
                "destination {:?} is a directory; give a full note path",
                a.destination
            )));
        }
        if !a.force && note_is_locked(&src, &a.source)? {
            return Err(locked_error(&a.source));
        }
        if !a.force && dst.exists() {
            return Err(UaError::conflict(format!("destination {:?} already exists", a.destination)));
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| UaError::invalid(format!("cannot create directory: {e}")))?;
        }
        let size = std::fs::metadata(&src).map(|m| m.len()).unwrap_or(0);
        let revision = note_revision(&src)?;
        std::fs::rename(&src, &dst).map_err(|e| UaError::invalid(format!("cannot move note: {e}")))?;
        Ok(json!({"source": src_rel, "destination": dst_rel, "bytes_moved": size, "revision": revision}))
    })
}

// ── list / search ──────────────────────────────────────────────────────────

fn vault_list(v: &Vault, a: ListArgs) -> UaResult<Value> {
    let dir = v.resolve(&a.path)?;
    if !dir.is_dir() {
        return Err(UaError::invalid(format!("not a directory: {}", a.path)));
    }
    let cap = a.max_entries.clamp(1, 2000);
    let matcher = match a.glob.as_deref() {
        Some(g) => {
            if Path::new(g).is_absolute() || g.split('/').any(|part| part == "..") {
                return Err(UaError::invalid("glob must be relative and must not contain '..'"));
            }
            let m = GlobBuilder::new(g)
                .literal_separator(true)
                .build()
                .map_err(|e| UaError::invalid(format!("invalid glob: {e}")))?
                .compile_matcher();
            Some((m, g.contains('/')))
        }
        None => None,
    };
    // A glob with `/` (e.g. `**/*.md`) walks below `dir`; otherwise list one level.
    let candidates: Vec<std::path::PathBuf> = match &matcher {
        Some((_, true)) => walk_all(v, &dir),
        _ => {
            let mut es: Vec<_> = std::fs::read_dir(&dir)
                .map_err(|e| UaError::invalid(format!("cannot list {}: {e}", a.path)))?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .collect();
            es.sort();
            es
        }
    };
    let mut entries = Vec::new();
    let mut truncated = false;
    for entry in candidates {
        let Ok(rel_to_dir) = entry.strip_prefix(&dir) else { continue };
        let shown = rel_to_dir.to_string_lossy().replace('\\', "/");
        if shown.split('/').any(|p| p.starts_with('.')) {
            continue;
        }
        if let Some((m, _)) = &matcher
            && !m.is_match(&shown)
        {
            continue;
        }
        let Some(real) = v.readable(&entry) else { continue };
        if entries.len() >= cap {
            truncated = true;
            break;
        }
        let is_dir = real.is_dir();
        entries.push(json!({
            "name": shown,
            "type": if is_dir { "dir" } else { "file" },
            "size": if is_dir { Value::Null } else { json!(std::fs::metadata(&real).map(|m| m.len()).unwrap_or(0)) },
        }));
    }
    Ok(json!({ "entries": entries, "truncated": truncated }))
}

/// Every non-hidden entry below `dir`, files and directories, sorted.
fn walk_all(v: &Vault, dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.filter_map(Result::ok) {
            if out.len() >= 50_000 {
                break;
            }
            if e.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let p = e.path();
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) && v.readable(&p).is_some() {
                stack.push(p.clone());
            }
            out.push(p);
        }
    }
    out.sort();
    out
}

fn vault_search(v: &Vault, a: SearchArgs) -> UaResult<Value> {
    let rx = regex::RegexBuilder::new(&a.pattern)
        .size_limit(1 << 20)
        .build()
        .map_err(|e| UaError::invalid(format!("invalid regex: {e}")))?;
    let root = v.resolve(&a.path)?;
    if !root.is_dir() {
        return Err(UaError::invalid(format!("not a directory: {}", a.path)));
    }
    let cap = a.max_results.clamp(1, 1000);
    let mut matches = Vec::new();
    let mut truncated = false;
    'notes: for f in v.notes_under(&root) {
        let Some(text) = read_text_lossy(&f, SEARCH_FILE_MAX_BYTES) else { continue };
        for (i, line) in text.lines().enumerate() {
            if rx.is_match(line) {
                if matches.len() >= cap {
                    truncated = true;
                    break 'notes;
                }
                let shown: String = line.chars().take(500).collect();
                matches.push(json!({"path": v.rel(&f), "line_no": i + 1, "line": shown}));
            }
        }
    }
    Ok(json!({ "matches": matches, "truncated": truncated }))
}

// ── links ──────────────────────────────────────────────────────────────────

fn vault_links(v: &Vault, a: LinksArgs) -> UaResult<Value> {
    let p = v.resolve(&a.path)?;
    let raw = read_note(&p, &a.path, READ_MAX_BYTES)?;
    let text = String::from_utf8_lossy(&raw);
    let found = links::extract(&text);
    let mut outgoing: Vec<String> = found.iter().map(|l| l.target.clone()).collect();
    outgoing.sort();
    outgoing.dedup();
    let mut embeds: Vec<String> = found.into_iter().filter(|l| l.embed).map(|l| l.target).collect();
    embeds.sort();
    embeds.dedup();

    let note_stem = stem(&p);
    let rel = v.rel(&p);
    let rel_no_ext = links::target_path(&rel);
    let mut backlinks = Vec::new();
    for f in v.notes_under(&v.root) {
        if f.canonicalize().ok().as_ref() == Some(&p) {
            continue;
        }
        let Some(t) = read_text_lossy(&f, SEARCH_FILE_MAX_BYTES) else { continue };
        let hit = links::extract(&t).iter().any(|l| {
            let tp = links::target_path(&l.target);
            tp == note_stem
                || tp == rel_no_ext
                || (!tp.contains('/') && links::target_name(&l.target) == note_stem)
        });
        if hit {
            backlinks.push(v.rel(&f));
        }
    }
    Ok(json!({ "path": rel, "outgoing": outgoing, "backlinks": backlinks, "embeds": embeds }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "vault_read",
            "Read a vault note (max 1 MB, up to 5000 lines per call; page with offset). expand_embeds=true expands ![[note]] transclusions two levels deep. Returns {path, content, total_lines, truncated, revision, locked}; pass revision to vault_write(expected_revision=...). Inbox notes carry a trust marker.",
            |ctx: ToolCtx, a: ReadArgs| async move {
                let v = vault(&ctx)?;
                blocking(move || vault_read(&v, a)).await
            },
        )
        .family("vault")
        .read_only(),
    );
    r.add(
        tool(
            "vault_write",
            "Create, overwrite or append to a .md/.txt note inside the vault write directories (max 2 MB). mode: overwrite | append | create. template instantiates a vault template ({{date}}, {{time}}, {{datetime}}, {{yesterday}}, {{tomorrow}}, {{title}}, {{content}}). A note with front matter `locked: true` is refused unless a verified human passes force=true. expected_revision makes the write conditional. Returns {path, bytes_written, mode, append, total_lines_after, revision}.",
            |ctx: ToolCtx, a: WriteArgs| async move {
                let v = vault(&ctx)?;
                let require = ctx.hub.cfg().vault_require_revision;
                let w = blocking(move || vault_write(&v, a, require)).await?;
                record(&ctx, "agent.vault.written", w.event()).await?;
                Ok(w.to_json())
            },
        )
        .family("vault"),
    );
    r.add(
        tool(
            "vault_move",
            "Move or rename one note inside the vault write directories (coordinator profile or a verified human). A locked source or an existing destination is refused unless a verified human passes force=true. Returns {source, destination, bytes_moved}.",
            |ctx: ToolCtx, a: MoveArgs| async move {
                let v = vault(&ctx)?;
                let out = blocking(move || vault_move(&v, a)).await?;
                record(&ctx, "agent.vault.moved", out.clone()).await?;
                Ok(out)
            },
        )
        .family("vault"),
    );
    r.add(
        tool(
            "vault_list",
            "List a vault directory, optionally filtered by a glob ('*.md', or '**/*.md' to walk). Hidden entries are omitted. Returns {entries: [{name, type, size}], truncated}.",
            |ctx: ToolCtx, a: ListArgs| async move {
                let v = vault(&ctx)?;
                blocking(move || vault_list(&v, a)).await
            },
        )
        .family("vault")
        .read_only(),
    );
    r.add(
        tool(
            "vault_search",
            "Regex-search .md/.txt notes under a vault directory, skipping hidden directories and notes over 1 MB. Returns {matches: [{path, line_no, line}], truncated}.",
            |ctx: ToolCtx, a: SearchArgs| async move {
                let v = vault(&ctx)?;
                blocking(move || vault_search(&v, a)).await
            },
        )
        .family("vault")
        .read_only(),
    );
    r.add(
        tool(
            "vault_links",
            "A note's [[wikilink]] neighborhood: outgoing link targets and backlinks (notes whose link targets this note's name or vault path). Links inside code are ignored. Returns {path, outgoing, backlinks}.",
            |ctx: ToolCtx, a: LinksArgs| async move {
                let v = vault(&ctx)?;
                blocking(move || vault_links(&v, a)).await
            },
        )
        .family("vault")
        .read_only(),
    );
}

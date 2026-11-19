//! `vault_wiki_custodian`: lint `Wiki/` (broken links, orphans, duplicate
//! identities, missing aliases, stubs, stale pages, ambiguous names, index
//! coverage) and, unless `dry_run`, rewrite the generated `Wiki/Health.md`.
//! The curated `Wiki/Index.md` is never written.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};

use super::notes::write_note;
use super::{SEARCH_FILE_MAX_BYTES, Vault, frontmatter, links, read_text_lossy, stem, vault};
use crate::registry::{Registry, ToolCtx, blocking, tool};

const WIKI: &str = "Wiki";
const HEALTH: &str = "Wiki/Health.md";
const INDEX: &str = "Wiki/Index.md";
/// Pages untouched for longer than this are reported stale.
const STALE_DAYS: i64 = 90;
/// Pages with less body text than this are reported as stubs.
const STUB_CHARS: usize = 80;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CustodianArgs {
    /// Report only: no `Wiki/Health.md` rewrite.
    #[serde(default)]
    pub dry_run: bool,
}

struct Page {
    title: String,
    aliases: Vec<String>,
    tags: Vec<String>,
    links: Vec<String>,
    body_chars: usize,
    mtime: Option<std::time::SystemTime>,
    display: String,
}

fn parse_page(p: &Path) -> Page {
    let text = read_text_lossy(p, SEARCH_FILE_MAX_BYTES).unwrap_or_default();
    let meta = frontmatter::metadata(&text);
    let body = frontmatter::split(&text).1;
    let title = meta
        .get("title")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| body.lines().find_map(|l| l.strip_prefix("# ").map(|t| t.trim().to_string())))
        .unwrap_or_else(|| stem(p));
    let mut link_set: Vec<String> = links::extract(&text).into_iter().map(|l| l.target).collect();
    link_set.sort();
    link_set.dedup();
    Page {
        title,
        aliases: frontmatter::string_list(&meta, "aliases"),
        tags: frontmatter::string_list(&meta, "tags"),
        links: link_set,
        body_chars: body.trim().chars().count(),
        mtime: std::fs::metadata(p).and_then(|m| m.modified()).ok(),
        display: String::new(),
    }
}

fn rel_stem(rel: &str) -> String {
    stem(Path::new(rel))
}

fn custodian(v: &Vault, dry_run: bool) -> UaResult<Value> {
    let wiki_dir = v.root.join(WIKI);
    let mut pages: BTreeMap<String, Page> = BTreeMap::new();
    let mut index: Option<Page> = None;
    let mut excluded: Vec<String> = Vec::new();
    if v.readable(&wiki_dir).is_some() {
        for f in v.notes_under(&wiki_dir) {
            if f.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let rel = v.rel(&f);
            if rel == HEALTH {
                excluded.push(rel);
                continue;
            }
            let page = parse_page(&f);
            if rel == INDEX {
                excluded.push(rel);
                index = Some(page);
                continue;
            }
            pages.insert(rel, page);
        }
    }

    // Stem -> page keys; a stem shared by several keys is displayed by path.
    let mut name_to_keys: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rel in pages.keys() {
        name_to_keys.entry(rel_stem(rel)).or_default().push(rel.clone());
    }
    let mut all_names = name_to_keys.clone();
    for rel in &excluded {
        all_names.entry(rel_stem(rel)).or_default().push(rel.clone());
    }
    for (rel, page) in pages.iter_mut() {
        let shared = all_names.get(&rel_stem(rel)).is_some_and(|k| k.len() > 1);
        page.display = if shared { links::target_path(rel) } else { rel_stem(rel) };
    }
    let display: HashMap<String, String> =
        pages.iter().map(|(k, p)| (k.clone(), p.display.clone())).collect();
    let mut path_to_key: HashMap<String, String> = HashMap::new();
    for rel in pages.keys() {
        let stripped = links::target_path(rel);
        path_to_key.insert(stripped.to_lowercase(), rel.clone());
        if let Some(rest) = stripped.strip_prefix("Wiki/") {
            path_to_key.entry(rest.to_lowercase()).or_insert_with(|| rel.clone());
        }
    }
    let mut alias_to_page: HashMap<String, String> = HashMap::new();
    for (rel, page) in &pages {
        for a in &page.aliases {
            alias_to_page.entry(a.to_lowercase()).or_insert_with(|| rel.clone());
        }
    }

    // Every file name in the vault, and every bare link target written anywhere.
    let mut stems: HashSet<String> = HashSet::new();
    let mut filenames: HashSet<String> = HashSet::new();
    let mut bare_names: HashSet<String> = HashSet::new();
    walk_files(&v.root, &mut |p: &Path| {
        stems.insert(stem(p));
        if let Some(n) = p.file_name() {
            filenames.insert(n.to_string_lossy().to_lowercase());
        }
        if p.extension().and_then(|e| e.to_str()) == Some("md")
            && v.rel(p) != HEALTH
            && let Some(text) = read_text_lossy(p, SEARCH_FILE_MAX_BYTES)
        {
            for l in links::extract(&text) {
                if !links::target_path(&l.target).contains('/') {
                    bare_names.insert(links::target_name(&l.target).to_lowercase());
                }
            }
        }
    });

    let resolve = |target: &str| -> Option<Vec<String>> {
        let tp = links::target_path(target);
        if tp.contains('/')
            && let Some(k) = path_to_key.get(&tp.to_lowercase())
        {
            return Some(vec![k.clone()]);
        }
        let name = links::target_name(target);
        if let Some(keys) = name_to_keys.get(&name) {
            return Some(keys.clone());
        }
        alias_to_page.get(&name.to_lowercase()).map(|k| vec![k.clone()])
    };

    let mut broken = Vec::new();
    let mut incoming: HashMap<String, BTreeSet<String>> =
        pages.keys().map(|k| (k.clone(), BTreeSet::new())).collect();
    for (src, page) in &pages {
        for target in &page.links {
            match resolve(target) {
                Some(keys) => {
                    for k in keys {
                        if let Some(set) = incoming.get_mut(&k) {
                            set.insert(display[src].clone());
                        }
                    }
                }
                None => {
                    let name = links::target_name(target);
                    let file =
                        Path::new(target.trim()).file_name().map(|n| n.to_string_lossy().to_lowercase());
                    let elsewhere = name == "Index"
                        || stems.contains(&name)
                        || file.is_some_and(|f| filenames.contains(&f));
                    if !elsewhere {
                        broken.push(json!({"source": page.display, "target": target}));
                    }
                }
            }
        }
    }
    let mut orphans: Vec<String> =
        incoming.iter().filter(|(_, s)| s.is_empty()).map(|(k, _)| display[k].clone()).collect();
    orphans.sort();

    let ambiguous: Vec<Value> = all_names
        .iter()
        .filter(|(name, keys)| {
            keys.len() > 1 && *name != "Index" && bare_names.contains(&name.to_lowercase())
        })
        .map(|(name, keys)| {
            let mut ks = keys.clone();
            ks.sort();
            json!({"name": name, "paths": ks})
        })
        .collect();

    let index_present = index.is_some();
    let mut covered: HashSet<String> = HashSet::new();
    if let Some(ix) = &index {
        for t in &ix.links {
            if let Some(keys) = resolve(t)
                && keys.len() == 1
            {
                covered.insert(keys[0].clone());
            }
        }
    }
    let unindexed: Vec<String> = if index_present {
        let mut u: Vec<String> =
            pages.keys().filter(|k| !covered.contains(*k)).map(|k| display[k].clone()).collect();
        u.sort();
        u
    } else {
        Vec::new()
    };

    // Duplicate identities: {stem} ∪ {aliases}, lowercased. Two pages that each
    // carry aliases and collide only on the stem are parallel pages, not
    // duplicates; nor is a cross-linked pair that the index covers.
    let aliases_of: HashMap<&String, BTreeSet<String>> =
        pages.iter().map(|(k, p)| (k, p.aliases.iter().map(|a| a.to_lowercase()).collect())).collect();
    let identity = |k: &String| -> BTreeSet<String> {
        let mut s = aliases_of[k].clone();
        s.insert(rel_stem(k).to_lowercase());
        s
    };
    let keys: Vec<&String> = pages.keys().collect();
    let mut duplicates = Vec::new();
    for (i, a) in keys.iter().enumerate() {
        for b in &keys[i + 1..] {
            let shared: BTreeSet<String> = identity(a).intersection(&identity(b)).cloned().collect();
            if shared.is_empty() {
                continue;
            }
            let (aa, ab) = (&aliases_of[*a], &aliases_of[*b]);
            if !aa.is_empty() && !ab.is_empty() && shared.iter().all(|s| !aa.contains(s) && !ab.contains(s)) {
                continue;
            }
            let linked = incoming[*b].contains(&display[*a]) || incoming[*a].contains(&display[*b]);
            if linked && covered.contains(*a) && covered.contains(*b) {
                continue;
            }
            duplicates.push(json!({"a": display[*a], "b": display[*b], "via": shared.iter().next()}));
        }
    }

    let mut missing_aliases: Vec<String> =
        pages.values().filter(|p| p.aliases.is_empty()).map(|p| p.display.clone()).collect();
    missing_aliases.sort();
    let mut empty_pages: Vec<String> =
        pages.values().filter(|p| p.body_chars < STUB_CHARS).map(|p| p.display.clone()).collect();
    empty_pages.sort();
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs((STALE_DAYS * 86_400) as u64))
        .unwrap_or(std::time::UNIX_EPOCH);
    let mut stale: Vec<String> =
        pages.values().filter(|p| p.mtime.is_some_and(|m| m < cutoff)).map(|p| p.display.clone()).collect();
    stale.sort();

    let inbox_count = if v.inbox.is_empty() {
        0
    } else {
        std::fs::read_dir(v.root.join(&v.inbox))
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| {
                        !e.file_name().to_string_lossy().starts_with('.')
                            && e.file_type().map(|t| t.is_file()).unwrap_or(false)
                    })
                    .count()
            })
            .unwrap_or(0)
    };

    let mut out = json!({
        "wiki_notes_count": pages.len(),
        "inbox_notes_count": inbox_count,
        "broken_links": broken,
        "orphans": orphans,
        "duplicate_candidates": duplicates,
        "missing_aliases": missing_aliases,
        "empty_pages": empty_pages,
        "stale_pages": stale,
        "ambiguous_names": ambiguous,
        "index_present": index_present,
        "unindexed_pages": unindexed,
        "index_rebuilt": false,
        "dry_run": dry_run,
    });
    if dry_run {
        return Ok(out);
    }
    let report = health_report(&out, &pages);
    let p = v.resolve_write(HEALTH)?;
    match write_note(v, HEALTH, &p, report.as_bytes(), "overwrite", false, None, false) {
        Ok(w) => {
            out["index_rebuilt"] = json!(true);
            out["health_report"] = json!({"path": w.rel, "revision": w.revision});
        }
        Err(UaError::Denied { reason_code, .. }) if reason_code == "note_locked" => {
            out["health_report_skipped"] = json!("locked");
        }
        Err(e) => return Err(e),
    }
    Ok(out)
}

fn walk_files(dir: &Path, f: &mut dyn FnMut(&Path)) {
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    let mut seen = 0usize;
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.filter_map(Result::ok) {
            seen += 1;
            if seen > 50_000 {
                return;
            }
            if e.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                f(&e.path());
            }
        }
    }
}

fn bullet_list(lines: &mut Vec<String>, heading: &str, items: &[String], empty: &str) {
    lines.push(format!("### {heading}"));
    if items.is_empty() {
        lines.push(format!("- *{empty}*"));
    } else {
        lines.extend(items.iter().map(|i| format!("- {i}")));
    }
    lines.push(String::new());
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| format!("[[{s}]]"))).collect())
        .unwrap_or_default()
}

fn health_report(r: &Value, pages: &BTreeMap<String, Page>) -> String {
    let now = jiff::Timestamp::now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut lines = vec![
        "---".to_string(),
        "title: Wiki Health".into(),
        format!("updated_at: {now}"),
        "tags: [wiki, meta, health]".into(),
        "---".into(),
        String::new(),
        "# Wiki Health Report".into(),
        String::new(),
        "*Generated by the wiki custodian; do not edit by hand. The curated map is [[Index]].*".into(),
        String::new(),
        "## Tag Directory".into(),
        String::new(),
    ];
    let mut tags: BTreeMap<String, Vec<&Page>> = BTreeMap::new();
    for p in pages.values() {
        if p.tags.is_empty() {
            tags.entry("untagged".into()).or_default().push(p);
        }
        for t in &p.tags {
            tags.entry(t.clone()).or_default().push(p);
        }
    }
    for (tag, mut ps) in tags {
        ps.sort_by(|a, b| a.title.cmp(&b.title));
        lines.push(format!("### #{tag}"));
        lines.extend(ps.iter().map(|p| format!("- [[{}]] — {}", p.display, p.title)));
        lines.push(String::new());
    }
    lines.push("## Wiki Health Audit".into());
    lines.push(String::new());
    let broken: Vec<String> = r["broken_links"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|b| {
                    format!(
                        "In [[{}]]: broken link to `[[{}]]`",
                        b["source"].as_str().unwrap_or(""),
                        b["target"].as_str().unwrap_or("")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    bullet_list(&mut lines, "Broken Links", &broken, "No broken links found.");
    bullet_list(&mut lines, "Orphan Pages", &strings(&r["orphans"]), "No orphan pages found.");
    let dups: Vec<String> = r["duplicate_candidates"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|d| {
                    format!(
                        "[[{}]] ↔ [[{}]] — shared identity: `{}`",
                        d["a"].as_str().unwrap_or(""),
                        d["b"].as_str().unwrap_or(""),
                        d["via"].as_str().unwrap_or("")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    bullet_list(&mut lines, "Duplicate Candidates", &dups, "No duplicate candidates found.");
    bullet_list(&mut lines, "Missing Aliases", &strings(&r["missing_aliases"]), "No pages missing aliases.");
    bullet_list(
        &mut lines,
        "Empty / Stub Pages",
        &strings(&r["empty_pages"]),
        "No empty or stub pages found.",
    );
    bullet_list(
        &mut lines,
        &format!("Stale Pages (>{STALE_DAYS}d)"),
        &strings(&r["stale_pages"]),
        "No stale pages found.",
    );
    let amb: Vec<String> = r["ambiguous_names"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|x| {
                    let paths: Vec<String> = x["paths"]
                        .as_array()
                        .map(|p| p.iter().filter_map(|s| s.as_str().map(|s| format!("`{s}`"))).collect())
                        .unwrap_or_default();
                    format!("`{}` → {}", x["name"].as_str().unwrap_or(""), paths.join(", "))
                })
                .collect()
        })
        .unwrap_or_default();
    bullet_list(&mut lines, "Ambiguous Page Names", &amb, "No ambiguous links.");
    if r["index_present"].as_bool() == Some(true) {
        bullet_list(
            &mut lines,
            "Pages Missing From Index",
            &strings(&r["unindexed_pages"]),
            "Every page is indexed.",
        );
    } else {
        lines.push("### Pages Missing From Index".into());
        lines.push("- *No Wiki/Index.md: index coverage unknown.*".into());
        lines.push(String::new());
    }
    lines.join("\n")
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "vault_wiki_custodian",
            "Audit Wiki/: broken [[links]], orphans, duplicate-identity candidates, missing aliases, empty/stub pages, stale pages (>90 days), ambiguous bare names and pages missing from Wiki/Index.md. Unless dry_run, rewrites the generated Wiki/Health.md (skipped when locked); Wiki/Index.md is never touched. Returns {wiki_notes_count, inbox_notes_count, broken_links, orphans, duplicate_candidates, missing_aliases, empty_pages, stale_pages, ambiguous_names, index_present, unindexed_pages, index_rebuilt}.",
            |ctx: ToolCtx, a: CustodianArgs| async move {
                let v = vault(&ctx)?;
                let dry = a.dry_run;
                let out = blocking(move || custodian(&v, dry)).await?;
                if let Some(h) = out.get("health_report") {
                    super::record(&ctx, "agent.vault.health_rebuilt", h.clone()).await?;
                }
                Ok(out)
            },
        )
        .family("vault"),
    );
}

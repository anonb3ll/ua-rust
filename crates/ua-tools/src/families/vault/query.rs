//! `vault_query`: embedding-free graph retrieval. Lexical seeds are walked
//! through Personalized PageRank (Haveliwala 2002) over the `[[wikilink]]`
//! graph. No index, no network: just the notes on disk.

use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};

use super::{SEARCH_FILE_MAX_BYTES, Vault, links, read_text_lossy, stem, vault};
use crate::registry::{Registry, ToolCtx, blocking, tool};

const DAMPING: f64 = 0.85;
const MAX_ITERS: usize = 30;
const EPS: f64 = 1e-6;

static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-z0-9]+").expect("static regex"));
static H1: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^#\s+(.+?)\s*$").expect("static regex"));

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryArgs {
    /// Free-text query; tokens of two or more letters or digits seed the walk.
    pub query: String,
    /// Vault directory to search (default: the vault root).
    #[serde(default = "dot")]
    pub path: String,
    /// 1-50 (default 10).
    #[serde(default = "ten")]
    pub max_results: usize,
}

fn dot() -> String {
    ".".into()
}

fn ten() -> usize {
    10
}

struct Note {
    path: String,
    title: String,
    content: String,
    lower: String,
    stem_lower: String,
    targets: Vec<String>,
}

fn snippet(content: &str, terms: &[String]) -> String {
    let pick = content
        .lines()
        .find(|l| {
            let low = l.to_lowercase();
            terms.iter().any(|t| low.contains(t.as_str()))
        })
        .or_else(|| content.lines().find(|l| !l.trim().is_empty()))
        .unwrap_or("");
    pick.trim().chars().take(200).collect()
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

fn vault_query(v: &Vault, a: QueryArgs) -> UaResult<Value> {
    if a.query.trim().is_empty() {
        return Err(UaError::invalid("query must not be empty"));
    }
    let root = v.resolve(&a.path)?;
    if !root.is_dir() {
        return Err(UaError::invalid(format!("not a directory: {}", a.path)));
    }
    let cap = a.max_results.clamp(1, 50);

    // Stage 1: corpus. The first note in path order wins a stem collision.
    let mut notes: Vec<Note> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for f in v.notes_under(&root) {
        let s = stem(&f);
        if index.contains_key(&s) {
            continue;
        }
        let Some(content) = read_text_lossy(&f, SEARCH_FILE_MAX_BYTES) else { continue };
        let targets = links::extract(&content).into_iter().map(|l| links::target_name(&l.target)).collect();
        let title = H1.captures(&content).map(|c| c[1].trim().to_string()).unwrap_or_else(|| s.clone());
        index.insert(s.clone(), notes.len());
        notes.push(Note {
            path: v.rel(&f),
            title,
            lower: content.to_lowercase(),
            content,
            stem_lower: s.to_lowercase(),
            targets,
        });
    }
    if notes.is_empty() {
        return Ok(json!({"results": [], "graph": {"notes": 0, "edges": 0, "seeds": 0}}));
    }

    // Stage 2: directed adjacency for reporting, undirected union for the walk.
    let n = notes.len();
    let mut out_adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    let mut in_adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    for (i, note) in notes.iter().enumerate() {
        for t in &note.targets {
            if let Some(&j) = index.get(t)
                && j != i
            {
                out_adj[i].insert(j);
                in_adj[j].insert(i);
            }
        }
    }
    let undirected: Vec<Vec<usize>> =
        (0..n).map(|i| out_adj[i].union(&in_adj[i]).copied().collect()).collect();
    let edges: usize = out_adj.iter().map(BTreeSet::len).sum();

    // Stage 3: lexical seeds.
    let lowered = a.query.to_lowercase();
    let terms: Vec<String> =
        TOKEN.find_iter(&lowered).map(|m| m.as_str().to_string()).filter(|t| t.len() >= 2).collect();
    let mut lexical = vec![0.0f64; n];
    for (i, note) in notes.iter().enumerate() {
        let hay = format!("{} {}", note.stem_lower, note.title.to_lowercase());
        for t in &terms {
            if hay.contains(t.as_str()) {
                lexical[i] += 3.0;
            }
            let count = note.lower.matches(t.as_str()).count();
            if count > 0 {
                lexical[i] += 1.0 + 0.1 * count.min(10) as f64;
            }
        }
    }
    let seeds = lexical.iter().filter(|x| **x > 0.0).count();
    let graph = json!({"notes": n, "edges": edges, "seeds": seeds});
    if seeds == 0 {
        return Ok(json!({"results": [], "graph": graph}));
    }

    // Stage 4: Personalized PageRank by power iteration. Dangling mass
    // returns to the teleport distribution instead of vanishing.
    let total: f64 = lexical.iter().sum();
    let teleport: Vec<f64> = lexical.iter().map(|x| x / total).collect();
    let mut p = teleport.clone();
    for _ in 0..MAX_ITERS {
        let mut next: Vec<f64> = teleport.iter().map(|t| (1.0 - DAMPING) * t).collect();
        let mut dangling = 0.0;
        for i in 0..n {
            let mass = DAMPING * p[i];
            if undirected[i].is_empty() {
                dangling += mass;
            } else {
                let share = mass / undirected[i].len() as f64;
                for &j in &undirected[i] {
                    next[j] += share;
                }
            }
        }
        if dangling > 0.0 {
            for i in 0..n {
                next[i] += dangling * teleport[i];
            }
        }
        let delta: f64 = (0..n).map(|i| (next[i] - p[i]).abs()).sum();
        p = next;
        if delta < EPS {
            break;
        }
    }

    // Stage 5: both signals normalized to 0..1, then averaged.
    let max_lex = lexical.iter().cloned().fold(0.0, f64::max);
    let max_ppr = p.iter().cloned().fold(0.0, f64::max);
    let mut ranked: Vec<(f64, f64, f64, usize)> = (0..n)
        .filter(|&i| lexical[i] > 0.0 || p[i] > 0.0)
        .map(|i| {
            let ln = if max_lex > 0.0 { lexical[i] / max_lex } else { 0.0 };
            let pn = if max_ppr > 0.0 { p[i] / max_ppr } else { 0.0 };
            (0.5 * ln + 0.5 * pn, ln, pn, i)
        })
        .collect();
    ranked.sort_by(|x, y| y.0.partial_cmp(&x.0).unwrap_or(std::cmp::Ordering::Equal));
    let results: Vec<Value> = ranked
        .into_iter()
        .take(cap)
        .map(|(score, ln, pn, i)| {
            let note = &notes[i];
            json!({
                "path": note.path,
                "title": note.title,
                "score": round4(score),
                "lexical": round4(ln),
                "pagerank": round4(pn),
                "snippet": snippet(&note.content, &terms),
                "links_out": out_adj[i].len(),
                "links_in": in_adj[i].len(),
            })
        })
        .collect();
    Ok(json!({"results": results, "graph": graph}))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "vault_query",
            "Embedding-free graph retrieval over [[wikilinks]]: lexical seeds walked through Personalized PageRank, so well-linked neighbours of matching notes rank too. No index and no network. Returns {results: [{path, title, score, lexical, pagerank, snippet, links_out, links_in}], graph: {notes, edges, seeds}}. max_results is capped at 50.",
            |ctx: ToolCtx, a: QueryArgs| async move {
                let v = vault(&ctx)?;
                blocking(move || vault_query(&v, a)).await
            },
        )
        .family("vault")
        .read_only(),
    );
}

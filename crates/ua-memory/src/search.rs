//! Reading notes: `memory_search`, `memory_list` and `memory_get`.
//!
//! The three tools are registered `read_only`. `memory_search` and `memory_get`
//! (unless `count_access=false`) also bump a note's access telemetry
//! (`access_count`, `last_accessed`, and for a search `recalled_count`,
//! `last_recalled_at`): a ranking signal and a pruning input, never note
//! content. That write is best effort and runs after the read, outside it:
//! it never fails or changes the answer, it does not move the note's
//! `revision`, and it writes no ledger event. Repeating a call (an MCP
//! client trusting `readOnlyHint`, a workflow retry) only counts the access
//! again.
//!
//! Retrieval legs: lexical (FTS5 bm25) and semantic (vectors, with the
//! `embeddings` feature) are wired and fused. The graph leg reported in
//! `retrieval.graph` is disabled: memory notes carry only typed revision
//! links (`supersedes`, `contradicts`, `memory:` evidence refs), not topical
//! links, and expanding hits along them would surface the superseded and
//! disputed notes the default filters hide. Graph retrieval over linked
//! notes is `vault_query` (Personalized PageRank over the vault's
//! wikilinks).

use std::collections::{HashMap, HashSet};

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use ua_core::{Config, UaError, UaResult};
use ua_store::Db;

use super::embed::{self, BruteForceIndex, VectorIndex, embedder_for};
use super::note::{self, Eligibility, NOTE_COLS, Note, json_list, json_text, mark_untrusted};
use super::rank;
use crate::blocking;

// ── memory_search ──────────────────────────────────────────────────────────

/// What to search for. The `memory_search` tool documents each field for agents.
#[derive(Debug, Clone, Default)]
pub struct SearchRequest {
    /// Search text. Quotes are ignored; every token is matched as a phrase.
    pub query: String,
    /// Keep notes carrying ALL of these tags (`untagged` selects notes without tags).
    pub tags: Option<Vec<String>>,
    /// 1-50, default 10.
    pub limit: Option<i64>,
    /// Keep notes saved from this host (case-insensitive).
    pub source_host: Option<String>,
    /// Include notes whose `expires_at` has passed.
    pub include_expired: bool,
    /// ISO datetime with a UTC offset: answer for that instant. A note
    /// qualifies when valid_from <= as_of < valid_to and it was created by
    /// then, so a note superseded later is returned.
    pub as_of: Option<String>,
    /// Keep notes by this exact author label.
    pub author: Option<String>,
}

struct LexHit {
    score: f64,
    snippet: Option<String>,
    and_mode: bool,
}

struct Gathered {
    lexical: Vec<(String, LexHit)>,
    semantic: Vec<(String, f32)>,
    sims: HashMap<String, f32>,
    notes: Vec<Note>,
    contradictions: HashMap<String, i64>,
}

fn lexical_leg(
    conn: &Connection,
    tokens: &[String],
    filter: &note::Filter,
) -> UaResult<Vec<(String, LexHit)>> {
    let (w_title, w_content, w_tags) = rank::BM25_WEIGHTS;
    let sql = format!(
        "SELECT m.id, bm25(memory_fts, {w_title}, {w_content}, {w_tags}) AS score, \
         snippet(memory_fts, 1, '[', ']', ' … ', 20) \
         FROM memory_fts JOIN memory m ON m.seq = memory_fts.rowid \
         WHERE memory_fts MATCH ? AND {} ORDER BY score, m.seq LIMIT ?",
        filter.sql
    );
    let run = |query: &str, and_mode: bool| -> UaResult<Vec<(String, LexHit)>> {
        if query.is_empty() {
            return Ok(Vec::new());
        }
        let mut p = vec![SqlValue::Text(query.into())];
        p.extend(filter.params.iter().cloned());
        p.push(SqlValue::Integer(rank::FTS_LIMIT as i64));
        let mut stmt = conn.prepare(&sql)?;
        // An FTS syntax error yields no matches rather than failing the search.
        let Ok(rows) = stmt.query_map(rusqlite::params_from_iter(p), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?, r.get::<_, Option<String>>(2)?))
        }) else {
            return Ok(Vec::new());
        };
        Ok(rows
            .filter_map(Result::ok)
            .map(|(id, score, snippet)| (id, LexHit { score, snippet, and_mode }))
            .collect())
    };
    let mut out: Vec<(String, LexHit)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut merge = |hits: Vec<(String, LexHit)>, out: &mut Vec<(String, LexHit)>| {
        for (id, hit) in hits {
            if out.len() < rank::FTS_LIMIT && seen.insert(id.clone()) {
                out.push((id, hit));
            }
        }
    };
    let and_q = rank::and_query(tokens);
    merge(run(&and_q, true)?, &mut out);
    if out.len() < rank::FTS_OR_THRESHOLD {
        let or_q = rank::or_query(tokens);
        // A single token's OR is the AND already run.
        if !or_q.is_empty() && or_q != and_q {
            merge(run(&or_q, false)?, &mut out);
        }
    }
    Ok(out)
}

fn gather(
    conn: &Connection,
    tokens: &[String],
    elig: &Eligibility,
    qvec: Option<&[f32]>,
    model: &str,
) -> UaResult<Gathered> {
    let filter = elig.filter();
    let lexical = lexical_leg(conn, tokens, &filter)?;
    let index = BruteForceIndex;
    let semantic = match qvec {
        Some(v) => {
            index.nearest(conn, model, v, &filter, rank::SEMANTIC_MIN_SIMILARITY, rank::SEMANTIC_TOP_K)?
        }
        None => Vec::new(),
    };
    let mut ids: Vec<String> = lexical.iter().map(|(id, _)| id.clone()).collect();
    for (id, _) in &semantic {
        if !ids.contains(id) {
            ids.push(id.clone());
        }
    }
    let notes = note::fetch_many(conn, &ids, &filter)?;
    // Candidates outside the semantic leg still report their exact similarity.
    let sims = match qvec {
        Some(v) => {
            let outside: Vec<String> =
                ids.iter().filter(|id| !semantic.iter().any(|(s, _)| s == *id)).cloned().collect();
            index.similarities(conn, &elig.org, model, v, &outside)?
        }
        None => HashMap::new(),
    };
    let contradictions = note::open_contradictions(conn, &elig.org, elig.as_of.as_deref(), &elig.now)?;
    Ok(Gathered { lexical, semantic, sims, notes, contradictions })
}

fn snippet_of(content: &str) -> String {
    if content.chars().count() > 150 {
        format!("{}...", content.chars().take(150).collect::<String>())
    } else {
        content.to_string()
    }
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

fn round9(x: f64) -> f64 {
    (x * 1e9).round() / 1e9
}

struct Candidate {
    note: Note,
    item: Value,
    age_day: i64,
    prior: f64,
    lexical_hit: bool,
    semantic_hit: bool,
}

/// Hybrid search over organization `org`'s notes: returns `{results,
/// retrieval}` (and `as_of` when given). Hits get their access and recall
/// counters bumped, best effort.
///
/// Both legs filter on `org` inside their query, so another organization's
/// notes never take a candidate slot, a rank or a result. The lexical score
/// is FTS5's bm25 over the one hub-wide `memory_fts` index, whose corpus
/// statistics count every organization's notes (`docs/organization.md`,
/// accepted leak candidates).
pub async fn search(db: &Db, cfg: &Config, org: &str, a: SearchRequest) -> UaResult<Value> {
    let cleaned = a.query.replace('"', " ");
    let tokens: Vec<String> = cleaned.split_whitespace().map(str::to_string).collect();
    if tokens.is_empty() {
        return Err(UaError::invalid("query must contain at least one search term"));
    }
    let as_of = a.as_of.as_deref().map(|v| note::parse_instant(v, "as_of", false)).transpose()?;
    let limit = a.limit.unwrap_or(10).clamp(1, 50) as usize;
    let now = cfg.clock.now();
    let elig = Eligibility {
        org: org.to_string(),
        tags: a
            .tags
            .unwrap_or_default()
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect(),
        author: a.author,
        source_host: a.source_host,
        include_expired: a.include_expired,
        as_of: as_of.clone(),
        now: now.clone(),
    };

    // Semantic leg: embed the query when an embedder is available.
    let embedder = embedder_for(cfg);
    let model = embedder.identity();
    let (qvec, semantic_failure) = if embedder.available() {
        let (e, text) = (embedder.clone(), a.query.clone());
        match blocking(move || Ok(embed::embed_one(&*e, text))).await? {
            Ok(v) => (Some(v), None),
            Err(err) => {
                tracing::debug!(category = err.category, error = %err.message, "memory_search: lexical only");
                (None, Some(err.category))
            }
        }
    } else {
        (None, Some("disabled"))
    };
    let has_semantic = qvec.is_some();

    let g = {
        let (tokens, elig, model) = (tokens.clone(), elig.clone(), model.clone());
        db.read_async(move |c| gather(c, &tokens, &elig, qvec.as_deref(), &model)).await?
    };

    let lex: HashMap<&str, &LexHit> = g.lexical.iter().map(|(id, h)| (id.as_str(), h)).collect();
    let sem: HashMap<&str, f32> = g.semantic.iter().map(|(id, s)| (id.as_str(), *s)).collect();
    let at = as_of.clone().unwrap_or_else(|| now.clone());
    let at_ms = note::ts_ms(&at).unwrap_or_else(|| cfg.clock.now_ms());

    let mut cands: Vec<Candidate> = Vec::new();
    for n in g.notes {
        let lexical_hit = lex.contains_key(n.id.as_str());
        let semantic_hit = sem.contains_key(n.id.as_str());
        if !lexical_hit && !semantic_hit {
            continue;
        }
        let fts = lex.get(n.id.as_str());
        let similarity =
            sem.get(n.id.as_str()).copied().or_else(|| g.sims.get(&n.id).copied()).unwrap_or(0.0);
        let snippet = fts
            .and_then(|h| h.snippet.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| snippet_of(&n.content));
        let fts_norm = fts.map(|h| (-h.score).clamp(0.0, 10.0) / 10.0).unwrap_or(0.0);

        // Recency dates the claim: valid_from when set, else the last update.
        let anchor = n.valid_from.as_deref().and_then(note::ts_ms).or_else(|| note::ts_ms(&n.updated_at));
        let age_days = anchor.map(|t| ((at_ms - t) as f64 / 86_400_000.0).max(0.0)).unwrap_or(0.0);
        let recency = 2f64.powf(-age_days / rank::RECENCY_HALF_LIFE_DAYS);
        let access = ((n.access_count.max(0) as f64).ln_1p() / 3.0).min(1.0);
        let age_months = age_days / 30.44;
        let discount = if age_months > rank::DECAY_MONTHS {
            0.95f64.powf(age_months - rank::DECAY_MONTHS).max(0.5)
        } else {
            1.0
        };
        let open = g.contradictions.get(&n.id).copied().unwrap_or(0);
        let conf = n.confidence_block(open);
        let posterior = conf["posterior"].as_f64().unwrap_or(0.5);
        let effective = conf["effective"].as_f64().unwrap_or(0.5);
        let vote = rank::vote_term(0, n.upvoted_count);
        let (prior, prior_inputs) = rank::prior_multiplier(n.salience, effective, vote, discount);

        let explanation = json!({
            "lexical": round4(fts_norm),
            "lexical_mode": fts.map(|h| if h.and_mode { "and" } else { "or" }),
            "semantic": if has_semantic { Some(round4(f64::from(similarity))) } else { None },
            "recency": round4(recency),
            "salience": round4(n.salience),
            "access": round4(access),
            "feedback": round4(2.0 * posterior - 1.0),
            "vote": round4(vote),
            "prior": round4(prior),
            "prior_inputs": prior_inputs,
            "confidence_posterior": conf,
            "host": n.source_host,
            "superseded": n.superseded_by.is_some(),
            "expired": n.is_expired_at(&at),
            "matched_tags": matched_tags(&tokens, &n.tags),
            "graph": null,
        });
        let mut item = n.summary();
        item["snippet"] = json!(snippet);
        item["score"] = json!(fts.map(|h| h.score));
        item["similarity"] = if has_semantic { json!(similarity) } else { Value::Null };
        item["combined_score"] = json!(0.0);
        item["recency"] = json!(round4(recency));
        item["explanation"] = explanation;
        cands.push(Candidate { note: n, item, age_day: age_days as i64, prior, lexical_hit, semantic_hit });
    }

    // Fuse per-leg ranks. Recency compares whole days, so same-day notes tie.
    let lex_ids: Vec<String> = g.lexical.iter().map(|(id, _)| id.clone()).collect();
    let lexical_rank = rank::competition_ranks(&lex_ids, |id| {
        lex.get(id).map(|h| (u8::from(!h.and_mode), round9(h.score))).unwrap_or((2, 0.0))
    });
    let sem_ids: Vec<String> = g.semantic.iter().map(|(id, _)| id.clone()).collect();
    let semantic_rank =
        rank::competition_ranks(&sem_ids, |id| -round9(f64::from(sem.get(id).copied().unwrap_or(0.0))));
    let cand_ids: Vec<String> = cands.iter().map(|c| c.note.id.clone()).collect();
    let ages: HashMap<String, i64> = cands.iter().map(|c| (c.note.id.clone(), c.age_day)).collect();
    let recency_rank = rank::competition_ranks(&cand_ids, |id| ages.get(id).copied().unwrap_or(i64::MAX));

    for c in &mut cands {
        let id = c.note.id.as_str();
        let ranks = [
            ("lexical", lexical_rank.get(id).copied()),
            ("semantic", semantic_rank.get(id).copied()),
            ("recency", recency_rank.get(id).copied()),
        ];
        let (rrf, parts) = rank::fuse(&ranks);
        let combined = rrf * c.prior;
        c.item["combined_score"] = json!(combined);
        let prior_inputs = c.item["explanation"]["prior_inputs"].as_object().cloned().unwrap_or_default();
        let expl = &mut c.item["explanation"];
        expl["ranks"] = json!({
            "lexical": ranks[0].1,
            "semantic": ranks[1].1,
            "recency": ranks[2].1,
        });
        expl["rrf"] = json!((rrf * 1e6).round() / 1e6);
        expl["why"] = json!(rank::why(&parts, c.lexical_hit, c.semantic_hit, &prior_inputs));
    }
    cands.sort_by(|a, b| {
        let (sa, sb) = (
            a.item["combined_score"].as_f64().unwrap_or(0.0),
            b.item["combined_score"].as_f64().unwrap_or(0.0),
        );
        sb.partial_cmp(&sa)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.note.title.as_deref().unwrap_or("").cmp(b.note.title.as_deref().unwrap_or("")))
            // Insertion order, not the random note id, so a tie (two notes
            // with the same score and title) orders the same on every run.
            .then_with(|| a.note.seq.cmp(&b.note.seq))
    });
    cands.truncate(limit);

    // Side write: access and recall counters. Best effort; never fails the search.
    let hit_ids: Vec<String> = cands.iter().map(|c| c.note.id.clone()).collect();
    let ts = cfg.clock.now();
    if !hit_ids.is_empty() {
        let (ids, ts2, org) = (json_text(&hit_ids), ts.clone(), org.to_string());
        let res = db
            .write_async(move |tx| {
                tx.execute(
                    "UPDATE memory SET access_count = access_count + 1, last_accessed = ?1, \
                     recalled_count = recalled_count + 1, last_recalled_at = ?1 \
                     WHERE org_id = ?3 AND id IN (SELECT value FROM json_each(?2))",
                    params![ts2, ids, org],
                )?;
                Ok(())
            })
            .await;
        match res {
            Ok(()) => {
                for c in &mut cands {
                    c.item["access_count"] = json!(c.note.access_count + 1);
                    c.item["last_accessed"] = json!(ts);
                }
            }
            Err(e) => tracing::warn!(error = %e, "memory_search: could not record access"),
        }
    }

    let results: Vec<Value> = cands
        .into_iter()
        .map(|mut c| {
            mark_untrusted(&mut c.item);
            c.item
        })
        .collect();
    let mut out = json!({
        "results": results,
        "retrieval": {
            "version": 1,
            "mode": if has_semantic { "hybrid" } else { "lexical_fallback" },
            "lexical": { "status": "queried", "matched_count": g.lexical.len() },
            "semantic": {
                "status": if has_semantic { "available" } else { "unavailable" },
                "matched_count": g.semantic.len(),
                "failure_category": semantic_failure,
            },
            "graph": {
                "status": "disabled",
                "reason": "memory notes have no topical link graph; use vault_query for graph retrieval",
                "seed_count": 0,
                "matched_count": 0,
            },
        },
    });
    if let Some(at) = as_of {
        out["as_of"] = json!(at);
    }
    Ok(out)
}

/// Tags of the note that the query names (whole tag, or its part after a colon).
fn matched_tags(tokens: &[String], tags: &[String]) -> Vec<String> {
    let toks: Vec<String> = tokens.iter().map(|t| t.to_lowercase()).collect();
    tags.iter()
        .filter(|tag| {
            let t = tag.to_lowercase();
            let tail = t.rsplit(':').next().unwrap_or(&t).to_string();
            toks.iter().any(|k| *k == t || *k == tail)
        })
        .cloned()
        .collect()
}

// ── memory_list ────────────────────────────────────────────────────────────

/// What to list. The `memory_list` tool documents each field for agents.
#[derive(Debug, Clone, Default)]
pub struct ListRequest {
    /// Keep notes carrying this tag.
    pub tag: Option<String>,
    /// 1-200, default 50.
    pub limit: Option<i64>,
    /// Include notes whose `expires_at` has passed.
    pub include_expired: bool,
    /// Keep notes by this exact author label.
    pub author: Option<String>,
    /// Keep notes carrying ALL of these tags (together with `tag`).
    pub tags: Option<Vec<String>>,
}

/// Organization `org`'s live notes newest first: returns `{items}`.
/// `cfg.clock` decides expiry.
pub async fn list(db: &Db, cfg: &Config, org: &str, a: ListRequest) -> UaResult<Value> {
    let limit = a.limit.unwrap_or(50).clamp(1, 200);
    let mut wanted: Vec<String> = a.tags.unwrap_or_default();
    if let Some(t) = a.tag {
        wanted.push(t);
    }
    wanted.sort();
    wanted.dedup();
    let elig = Eligibility {
        org: org.to_string(),
        tags: wanted,
        author: a.author,
        include_expired: a.include_expired,
        now: cfg.clock.now(),
        ..Default::default()
    };
    db.read_async(move |c| {
        let f = elig.filter();
        let sql = format!(
            "SELECT {NOTE_COLS} FROM memory m WHERE {} ORDER BY m.updated_at DESC, m.seq DESC LIMIT ?",
            f.sql
        );
        let mut p = f.params;
        p.push(SqlValue::Integer(limit));
        let mut stmt = c.prepare(&sql)?;
        let items: Vec<Value> = stmt
            .query_map(rusqlite::params_from_iter(p), Note::from_row)?
            .map(|r| r.map(|n| n.summary()))
            .collect::<Result<_, _>>()?;
        Ok(json!({ "items": items }))
    })
    .await
}

// ── memory_get ─────────────────────────────────────────────────────────────

/// Which note to read. The `memory_get` tool documents each field for agents.
#[derive(Debug, Clone)]
pub struct GetRequest {
    /// Note id.
    pub id: String,
    /// ISO datetime with a UTC offset: return the note only if it was valid
    /// then; versions are limited to those recorded by then.
    pub as_of: Option<String>,
    /// Add `versions` (prior content and tags, newest first, at most 20) and `versions_total`.
    pub include_versions: bool,
    /// Count this read as an access (the tool's default). A person browsing is not a recall.
    pub count_access: bool,
}

const MAX_VERSIONS_SHOWN: usize = 20;

fn versions(conn: &Connection, org: &str, id: &str, as_of: Option<&str>) -> UaResult<(Vec<Value>, usize)> {
    let mut stmt = conn.prepare(
        "SELECT version, content, tags, updated_at, actor, recorded_at FROM memory_versions \
         WHERE note_id = ?1 AND org_id = ?2 ORDER BY version DESC",
    )?;
    let rows = stmt.query_map(params![id, org], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, String>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (version, content, tags, updated_at, actor, recorded_at) = row?;
        if let Some(at) = as_of
            && recorded_at.as_str() > at
        {
            continue;
        }
        out.push(json!({
            "version": version,
            "content": content,
            "tags": json_list(tags),
            "updated_at": updated_at,
            "actor": actor,
            "recorded_at": recorded_at,
        }));
    }
    let total = out.len();
    out.truncate(MAX_VERSIONS_SHOWN);
    Ok((out, total))
}

fn compose(
    conn: &Connection,
    org: &str,
    id: &str,
    as_of: Option<&str>,
    include_versions: bool,
    now: &str,
) -> UaResult<Value> {
    let n = note::require(conn, org, id)?;
    if let Some(at) = as_of
        && !n.valid_at(at)
    {
        let from = n.valid_from.clone().unwrap_or_else(|| n.created_at.clone());
        let to = n.valid_to.clone().unwrap_or_else(|| {
            if n.superseded_by.is_some() {
                "unknown (superseded before validity was recorded)".into()
            } else {
                "now".into()
            }
        });
        return Err(UaError::invalid(format!(
            "memory note {id:?} was not valid at {at}: it is valid from {from} to {to}. \
             Call memory_get without as_of to read it."
        )));
    }
    let mut res = n.summary();
    res["content"] = json!(n.content);
    res["updated_by"] = json!(n.updated_by);
    res["created_at"] = json!(n.created_at);
    res["revision"] = json!(n.revision());
    if n.is_deleted() {
        res["deleted"] = json!(true);
    }
    let replaced = note::superseded_notes(conn, org, id)?;
    if !replaced.is_empty() {
        res["supersedes"] = json!(replaced);
    }
    res["links"] = note::note_links(conn, org, &n)?;
    let open = note::open_contradictions(conn, org, as_of, now)?.get(id).copied().unwrap_or(0);
    res["confidence_posterior"] = n.confidence_block(open);
    if include_versions {
        let (v, total) = versions(conn, org, id, as_of)?;
        res["versions"] = json!(v);
        res["versions_total"] = json!(total);
    }
    Ok(res)
}

/// One note of organization `org` with its content, revision, links and
/// confidence posterior, including a superseded or deleted one. Another
/// organization's note answers `not_found`, exactly like a missing one.
pub async fn get(db: &Db, cfg: &Config, org: &str, a: GetRequest) -> UaResult<Value> {
    let as_of = a.as_of.as_deref().map(|v| note::parse_instant(v, "as_of", false)).transpose()?;
    let (id, include_versions) = (a.id, a.include_versions);
    let (read_id, read_org, now) = (id.clone(), org.to_string(), cfg.clock.now());
    let mut res = db
        .read_async(move |c| compose(c, &read_org, &read_id, as_of.as_deref(), include_versions, &now))
        .await?;
    if a.count_access {
        // Access telemetry, best effort (see the module docs): it never
        // fails the read.
        let ts = cfg.clock.now();
        let (ts2, org) = (ts.clone(), org.to_string());
        let counted = db
            .write_async(move |tx| {
                Ok(tx.execute(
                    "UPDATE memory SET access_count = access_count + 1, last_accessed = ?1 \
                     WHERE id = ?2 AND org_id = ?3",
                    params![ts2, id, org],
                )?)
            })
            .await;
        match counted {
            Ok(n) if n > 0 => {
                res["access_count"] = json!(res["access_count"].as_i64().unwrap_or(0) + 1);
                res["last_accessed"] = json!(ts);
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "memory_get: could not record access"),
        }
    }
    mark_untrusted(&mut res);
    Ok(res)
}

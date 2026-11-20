//! Rank fusion for `memory_search`.
//!
//! Each leg (lexical, semantic, recency) is ranked on its own and a note
//! scores `sum(w_leg / (k + rank_leg))` over the legs it appears in, so no
//! leg's raw scale can swamp another. A bounded prior in [0.8, 1.2] from
//! salience, the feedback posterior and explicit upvotes multiplies the
//! fused score. Access counts and recall counts are reported, never ranked.

use std::collections::HashMap;

use serde_json::{Map, Value, json};

pub const PRIOR_MIN: f64 = 0.8;
pub const PRIOR_MAX: f64 = 1.2;
pub(crate) const RRF_K: f64 = 60.0;
pub(crate) const FTS_LIMIT: usize = 200;
/// Run the OR fallback when the AND pass finds fewer notes than this.
pub(crate) const FTS_OR_THRESHOLD: usize = 10;
/// Cosine floor for the semantic leg (bge-small scores unrelated texts near 0.6).
pub(crate) const SEMANTIC_MIN_SIMILARITY: f32 = 0.65;
pub(crate) const SEMANTIC_TOP_K: usize = 50;
/// Cosine at or above which `memory_save` reports a similar note.
pub(crate) const DEDUP_THRESHOLD: f32 = 0.85;
pub(crate) const RECENCY_HALF_LIFE_DAYS: f64 = 15.0;
pub(crate) const DECAY_MONTHS: f64 = 6.0;
pub(crate) const W_SALIENCE: f64 = 0.5;
pub(crate) const W_FEEDBACK: f64 = 0.4;
pub(crate) const W_VOTE: f64 = 0.35;
/// Leg weights, in fusion order.
pub(crate) const LEG_WEIGHTS: [(&str, f64); 3] = [("lexical", 1.0), ("semantic", 1.0), ("recency", 0.2)];
/// Column weights for bm25 over (title, content, tags).
pub(crate) const BM25_WEIGHTS: (f64, f64, f64) = (3.0, 1.0, 2.0);

/// Feedback signal -> (alpha, beta) increment per count, from a Beta(1, 1) prior.
pub(crate) const FEEDBACK_INCREMENTS: [(f64, f64); 4] = [(1.0, 0.0), (0.0, 1.0), (0.0, 0.5), (0.0, 2.0)];
pub(crate) const CONTRADICTION_BETA: f64 = 1.0;
pub(crate) const MAX_COUNTED_CONTRADICTIONS: i64 = 5;

const STOPWORDS: &[&str] = &[
    "a", "about", "after", "again", "all", "am", "an", "and", "any", "are", "as", "at", "be", "been",
    "before", "being", "but", "by", "can", "cannot", "could", "did", "do", "does", "doing", "down", "during",
    "each", "few", "for", "from", "further", "had", "has", "have", "having", "he", "her", "here", "hers",
    "how", "i", "if", "in", "into", "is", "it", "its", "itself", "just", "me", "more", "most", "my", "no",
    "nor", "not", "now", "of", "off", "on", "once", "only", "or", "other", "our", "ours", "out", "over",
    "own", "same", "she", "should", "so", "some", "such", "than", "that", "the", "their", "theirs", "them",
    "then", "there", "these", "they", "this", "those", "through", "to", "too", "under", "until", "up",
    "very", "was", "we", "were", "what", "when", "where", "which", "while", "who", "whom", "why", "will",
    "with", "would", "you", "your", "yours",
];

/// A quoted phrase neutralises FTS5 operators; quotes inside are dropped.
fn phrase(token: &str) -> String {
    format!("\"{}\"", token.replace('"', ""))
}

pub(crate) fn and_query(tokens: &[String]) -> String {
    tokens
        .iter()
        .filter(|t| !t.replace('"', "").trim().is_empty())
        .map(|t| phrase(t))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Distinct non-stopword tokens for the OR fallback, in query order.
pub(crate) fn or_tokens(tokens: &[String]) -> Vec<String> {
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for tok in tokens {
        let cleaned = tok.replace('"', "").trim().to_string();
        let key = cleaned.to_lowercase().trim_matches(|c: char| ".,;:!?()[]{}'".contains(c)).to_string();
        if cleaned.is_empty() || key.is_empty() || STOPWORDS.contains(&key.as_str()) || seen.contains(&key) {
            continue;
        }
        seen.push(key);
        out.push(cleaned);
    }
    out
}

pub fn or_query(tokens: &[String]) -> String {
    or_tokens(tokens).iter().map(|t| phrase(t)).collect::<Vec<_>>().join(" OR ")
}

/// 1-based ranks with ties sharing the best rank ("1224"). `key` sorts
/// ascending, best first.
pub fn competition_ranks<K: PartialOrd + Copy>(
    items: &[String],
    key: impl Fn(&str) -> K,
) -> HashMap<String, usize> {
    let mut ordered: Vec<(&String, K)> = items.iter().map(|i| (i, key(i))).collect();
    ordered.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut ranks = HashMap::new();
    let mut prev: Option<K> = None;
    let mut current = 0;
    for (index, (item, value)) in ordered.into_iter().enumerate() {
        if prev.is_none_or(|p| p != value) {
            current = index + 1;
            prev = Some(value);
        }
        ranks.insert(item.clone(), current);
    }
    ranks
}

/// Weighted reciprocal rank fusion over the legs a note appears in.
pub(crate) fn fuse(ranks: &[(&'static str, Option<usize>)]) -> (f64, Vec<(&'static str, f64)>) {
    let mut parts = Vec::new();
    for (leg, rank) in ranks {
        let w = LEG_WEIGHTS.iter().find(|(l, _)| l == leg).map(|(_, w)| *w).unwrap_or(0.0);
        if let Some(r) = rank
            && w > 0.0
        {
            parts.push((*leg, w / (RRF_K + *r as f64)));
        }
    }
    (parts.iter().map(|(_, v)| v).sum(), parts)
}

/// (alpha, beta) of a note's Beta posterior from its feedback counts.
pub fn posterior(feedback: [i64; 4]) -> (f64, f64) {
    let (mut a, mut b) = (1.0, 1.0);
    for (count, (da, db)) in feedback.iter().zip(FEEDBACK_INCREMENTS) {
        let n = (*count).max(0) as f64;
        a += da * n;
        b += db * n;
    }
    (a, b)
}

pub(crate) fn effective_confidence(alpha: f64, beta: f64, open_contradictions: i64) -> f64 {
    let counted = open_contradictions.clamp(0, MAX_COUNTED_CONTRADICTIONS) as f64;
    alpha / (alpha + beta + CONTRADICTION_BETA * counted)
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

/// The `confidence_posterior` block `memory_get` and `memory_search` report.
pub(crate) fn confidence_summary(feedback: [i64; 4], open_contradictions: i64) -> Value {
    let (a, b) = posterior(feedback);
    json!({
        "alpha": round4(a),
        "beta": round4(b),
        "posterior": round4(a / (a + b)),
        "open_contradictions": open_contradictions.min(MAX_COUNTED_CONTRADICTIONS),
        "effective": round4(effective_confidence(a, b, open_contradictions)),
    })
}

/// Bounded [0, 1) contribution of recalls and explicit upvotes.
pub(crate) fn vote_term(recalled: i64, upvoted: i64) -> f64 {
    if recalled <= 0 && upvoted <= 0 {
        return 0.0;
    }
    (0.5 * (recalled.max(0) as f64).ln_1p() + 1.5 * (upvoted.max(0) as f64).ln_1p()).tanh()
}

/// Bounded multiplier from the quality priors, and each prior's signed input.
pub fn prior_multiplier(
    salience: f64,
    confidence: f64,
    vote: f64,
    age_discount: f64,
) -> (f64, Map<String, Value>) {
    let conf = confidence.clamp(0.0, 1.0);
    let inputs = [
        ("salience", W_SALIENCE * (salience - 0.5) * 2.0),
        ("confidence", W_FEEDBACK * (conf - 0.5) * 2.0),
        ("vote", W_VOTE * vote),
    ];
    let sum: f64 = inputs.iter().map(|(_, v)| v).sum();
    let raw = 1.0 + (PRIOR_MAX - 1.0) * sum.tanh();
    let mut map = Map::new();
    for (k, v) in inputs {
        map.insert(k.into(), json!(round4(v)));
    }
    ((raw * age_discount).clamp(PRIOR_MIN, PRIOR_MAX), map)
}

/// Ordered ranking reasons: the content legs that matched, the other legs by
/// contribution, then any prior that raised the note.
pub(crate) fn why(
    parts: &[(&'static str, f64)],
    lexical_hit: bool,
    semantic_hit: bool,
    prior_inputs: &Map<String, Value>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if lexical_hit {
        out.push("lexical".into());
    }
    if semantic_hit {
        out.push("semantic".into());
    }
    let mut legs = parts.to_vec();
    legs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(b.0)));
    for (name, _) in legs {
        if !out.iter().any(|w| w == name) {
            out.push(name.into());
        }
    }
    let mut priors: Vec<(&String, f64)> =
        prior_inputs.iter().map(|(k, v)| (k, v.as_f64().unwrap_or(0.0))).collect();
    priors.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(b.0)));
    for (name, value) in priors {
        if value > 0.05 && !out.iter().any(|w| w == name) {
            out.push(name.clone());
        }
    }
    out
}

/// Deterministic conflict hint between two texts: a `key: value` pair with
/// different values, or one side of a binary antonym pair on each side.
pub fn detect_conflict(a: &str, b: &str) -> bool {
    let kv = |text: &str| -> HashMap<String, String> {
        let mut m = HashMap::new();
        for line in text.lines() {
            let line = line.trim().trim_start_matches(|c: char| "*-+ ".contains(c));
            let Some(pos) = line.find([':', '=']) else { continue };
            let key = line[..pos].trim();
            let value = line[pos + 1..].trim();
            let key_ok =
                key.len() >= 2 && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
            if key_ok && !value.is_empty() {
                m.insert(key.to_lowercase(), value.to_lowercase().trim_matches(['\'', '"']).to_string());
            }
        }
        m
    };
    let (ka, kb) = (kv(a), kv(b));
    if ka.iter().any(|(k, v)| kb.get(k).is_some_and(|w| w != v)) {
        return true;
    }
    let words = |text: &str| -> Vec<String> {
        text.to_lowercase()
            .split(|c: char| !c.is_ascii_alphabetic())
            .filter(|w| !w.is_empty())
            .map(str::to_string)
            .collect()
    };
    let (wa, wb) = (words(a), words(b));
    let has = |ws: &[String], w: &str| ws.iter().any(|x| x == w);
    const PAIRS: [(&str, &str); 10] = [
        ("enabled", "disabled"),
        ("active", "inactive"),
        ("live", "stale"),
        ("success", "failed"),
        ("pass", "fail"),
        ("true", "false"),
        ("allow", "deny"),
        ("allowed", "denied"),
        ("on", "off"),
        ("yes", "no"),
    ];
    PAIRS.iter().any(|(x, y)| {
        (has(&wa, x) && !has(&wa, y) && has(&wb, y) && !has(&wb, x))
            || (has(&wa, y) && !has(&wa, x) && has(&wb, x) && !has(&wb, y))
    })
}

//! Retrieval benchmark over the memory search that ships today.
//!
//! [`Kind::Fixture`] scores the checked-in corpus and compares each class with
//! `bench/floor.json`. [`Kind::LongMemEval`] scores the pinned LongMemEval-S
//! file. Neither path changes ranking. Both runs are deterministic: note text,
//! `valid_from` and `as_of` are fixed, the clock is fixed at [`BENCH_NOW`],
//! and search breaks score ties on title, then insertion order.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ua_core::identity::Transport;
use ua_core::{ActorKind, Caller, Config, Profile, UaError, UaResult};
use ua_store::{Db, ledger};

use crate::save::{self, SaveRequest};
use crate::search::{self, SearchRequest};

const CORPUS: &str = include_str!("../bench/corpus.json");
const FLOOR: &str = include_str!("../bench/floor.json");
const PIN_JSON: &str = include_str!("../bench/longmemeval.json");

const SEARCH_LIMIT: i64 = 10;
const RECALL_K: usize = 5;

/// The instant both bench runs treat as now. Search reads the clock for the
/// recency leg and the prior's age discount, so a wall clock would let the
/// same corpus score differently on different days. Every LongMemEval session
/// predates it by more than 19.5 months, where the age discount is clamped,
/// as it was under the wall clock when the recorded baseline ran.
pub const BENCH_NOW: &str = "2026-03-01T00:00:00+00:00";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Checked-in notes and labelled queries. No network.
    Fixture,
    /// Pinned LongMemEval-S file. Downloaded on demand when `--data` is omitted.
    LongMemEval,
}

/// Local ONNX embedder settings for hybrid benchmark runs (`--features
/// embeddings`, after `ua memory models fetch`).
#[derive(Debug, Clone)]
pub struct EmbedOptions {
    /// Directory holding `models/<slug>/<revision>/` (defaults to `UA_HOME`
    /// or `~/.ua-rust`, matching `ua memory models fetch`).
    pub home: PathBuf,
    /// Pinned local embedding model name (defaults to `BAAI/bge-small-en-v1.5`).
    pub model: String,
    /// Drop `memory_chunks` after ingest so search scores only each note's
    /// single vector (pre-#155 ablation against chunked embeddings).
    pub no_chunks: bool,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub kind: Kind,
    /// LongMemEval only: a local copy of the dataset file. It must match the
    /// pinned sha256. When `None`, the run uses the cache file and, if that
    /// is missing, downloads it with `curl` (the only network access in this
    /// module; the fixture run and the tests never take it).
    pub data: Option<PathBuf>,
    /// LongMemEval only: score this many answerable questions, in file order
    /// (after `ids`, when both are given).
    pub limit: Option<usize>,
    /// LongMemEval only: score exactly these question ids, in file order. An
    /// unknown or abstention id is an error. This is how a stratified sample
    /// drawn elsewhere (the predecessor's `--per-category 20 --seed 2145`) is
    /// reproduced.
    pub ids: Option<Vec<String>>,
    /// When `Some`, score hybrid retrieval using the fetched local ONNX model
    /// instead of the lexical-only default.
    pub embed: Option<EmbedOptions>,
}

impl Options {
    pub fn fixture() -> Self {
        Self { kind: Kind::Fixture, data: None, limit: None, ids: None, embed: None }
    }
}

#[derive(Debug, Clone)]
struct Pin {
    repo: String,
    revision: String,
    file: String,
    sha256: String,
}

struct Corpus {
    notes: Vec<CorpusNote>,
    queries: Vec<CorpusQuery>,
}

struct CorpusNote {
    key: String,
    title: String,
    content: String,
    tags: Vec<String>,
    valid_from: Option<String>,
    /// When the note was written (`created_at`). Defaults to `valid_from`;
    /// see [`backdate_created`].
    recorded_at: Option<String>,
    supersedes: Option<String>,
    contradicts: Vec<String>,
}

struct CorpusQuery {
    id: String,
    class: String,
    query: String,
    as_of: Option<String>,
    must: Vec<String>,
    /// Notes that must not be in the top 5.
    must_not: Vec<String>,
    /// Notes that share the query's terms and are retrieved, but must rank
    /// below every `must` note. Each must actually be retrieved, or the
    /// negative tests nothing and the floor check fails.
    outranked: Vec<String>,
}

struct FloorFile {
    k: usize,
    classes: Vec<FloorClass>,
}

struct FloorClass {
    class: String,
    n: usize,
    recall_at_5: f64,
    mrr: f64,
}

struct LmeQuestion {
    question_id: String,
    question_type: String,
    question: String,
    question_date: Option<String>,
    answer_session_ids: Vec<String>,
    haystack_session_ids: Vec<String>,
    haystack_dates: Vec<String>,
    haystack_sessions: Vec<Vec<LmeTurn>>,
}

struct LmeTurn {
    role: String,
    content: String,
}

struct SessionScore {
    recall_all_5: f64,
    recall_any_5: f64,
    recall_frac_5: f64,
    mrr: f64,
}

/// Run the benchmark named by `opts` and return the JSON report.
pub async fn run(opts: Options) -> UaResult<Value> {
    match opts.kind {
        Kind::Fixture => run_fixture(opts.embed.as_ref()).await,
        Kind::LongMemEval => {
            run_longmemeval(opts.data.as_deref(), opts.limit, opts.ids.as_deref(), opts.embed.as_ref()).await
        }
    }
}

/// A short text table for a report from [`run`].
pub fn table(report: &Value) -> String {
    match report.get("bench").and_then(Value::as_str) {
        Some("fixture") => fixture_table(report),
        Some("longmemeval-s") => longmemeval_table(report),
        _ => "unrecognised bench report".to_string(),
    }
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() { 0.0 } else { round4(xs.iter().sum::<f64>() / xs.len() as f64) }
}

/// `'2023/05/20 (Sat) 02:21'` to `'2023-05-20T02:21:00+00:00'`. Dates in the
/// dataset are naive; UTC is assumed, matching the predecessor harness.
fn parse_session_date(raw: &str) -> UaResult<String> {
    let mut parts = raw.splitn(3, ' ');
    let day = parts.next().unwrap_or("");
    let _weekday = parts.next();
    let clock = parts.next().unwrap_or("");
    if day.len() != 10 || clock.len() != 5 || !day.contains('/') {
        return Err(UaError::invalid(format!("session date {raw:?} is not 'YYYY/MM/DD (Day) HH:MM'")));
    }
    let iso = format!("{}T{clock}:00+00:00", day.replace('/', "-"));
    if ua_core::time::parse_ts(&iso).is_none() {
        return Err(UaError::invalid(format!("session date {raw:?} is not a real timestamp")));
    }
    Ok(iso)
}

fn score_sessions(ranked: &[String], evidence: &[String]) -> UaResult<SessionScore> {
    if evidence.is_empty() {
        return Err(UaError::invalid("a scored question needs at least one evidence session"));
    }
    let wanted: HashSet<&str> = evidence.iter().map(String::as_str).collect();
    let at5: HashSet<&str> =
        ranked.iter().take(RECALL_K).map(String::as_str).filter(|s| wanted.contains(s)).collect();
    let first = ranked.iter().position(|s| wanted.contains(s.as_str()));
    Ok(SessionScore {
        recall_all_5: if at5.len() == wanted.len() { 1.0 } else { 0.0 },
        recall_any_5: if at5.is_empty() { 0.0 } else { 1.0 },
        recall_frac_5: at5.len() as f64 / wanted.len() as f64,
        mrr: first.map(|i| 1.0 / (i + 1) as f64).unwrap_or(0.0),
    })
}

fn score_fixture(
    ranked: &[String],
    must: &[String],
    must_not: &[String],
    outranked: &[String],
) -> (f64, f64) {
    let top: Vec<&str> = ranked.iter().take(RECALL_K).map(String::as_str).collect();
    let all = must.iter().all(|m| top.contains(&m.as_str()));
    let clean = must_not.iter().all(|m| !top.contains(&m.as_str()));
    let last_must = must.iter().filter_map(|m| ranked.iter().position(|r| r == m)).max();
    let below = outranked
        .iter()
        .all(|o| ranked.iter().position(|r| r == o).is_none_or(|p| last_must.is_some_and(|l| p > l)));
    let recall = if all && clean && below && !must.is_empty() { 1.0 } else { 0.0 };
    let mrr = ranked
        .iter()
        .position(|r| must.iter().any(|m| m == r))
        .map(|i| if i < SEARCH_LIMIT as usize { 1.0 / (i + 1) as f64 } else { 0.0 })
        .unwrap_or(0.0);
    (recall, mrr)
}

fn pin() -> UaResult<Pin> {
    parse_pin(PIN_JSON)
}

fn object<'a>(v: &'a Value, what: &str) -> UaResult<&'a Map<String, Value>> {
    v.as_object().ok_or_else(|| UaError::invalid(format!("{what} must be a JSON object")))
}

fn only_keys(obj: &Map<String, Value>, allowed: &[&str], what: &str) -> UaResult<()> {
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(UaError::invalid(format!("{what} has unknown field {key}")));
        }
    }
    Ok(())
}

fn req_str(obj: &Map<String, Value>, key: &str, what: &str) -> UaResult<String> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| UaError::invalid(format!("{what} is missing string {key}")))
}

fn opt_str(obj: &Map<String, Value>, key: &str, what: &str) -> UaResult<Option<String>> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(UaError::invalid(format!("{what}.{key} must be a string"))),
    }
}

fn string_array(v: &Value, what: &str) -> UaResult<Vec<String>> {
    let Some(xs) = v.as_array() else {
        return Err(UaError::invalid(format!("{what} must be an array of strings")));
    };
    xs.iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| UaError::invalid(format!("{what} must be strings")))
        })
        .collect()
}

fn req_strings(obj: &Map<String, Value>, key: &str, what: &str) -> UaResult<Vec<String>> {
    let v = obj.get(key).ok_or_else(|| UaError::invalid(format!("{what} is missing {key}")))?;
    string_array(v, &format!("{what}.{key}"))
}

fn opt_strings(obj: &Map<String, Value>, key: &str, what: &str) -> UaResult<Vec<String>> {
    match obj.get(key) {
        None => Ok(Vec::new()),
        Some(v) => string_array(v, &format!("{what}.{key}")),
    }
}

fn parse_json(raw: &str, what: &str) -> UaResult<Value> {
    serde_json::from_str(raw).map_err(|e| UaError::internal(format!("{what}: {e}")))
}

fn parse_pin(raw: &str) -> UaResult<Pin> {
    let v = parse_json(raw, "bench/longmemeval.json")?;
    let obj = object(&v, "bench/longmemeval.json")?;
    only_keys(obj, &["repo", "revision", "file", "sha256"], "bench/longmemeval.json")?;
    Ok(Pin {
        repo: req_str(obj, "repo", "bench/longmemeval.json")?,
        revision: req_str(obj, "revision", "bench/longmemeval.json")?,
        file: req_str(obj, "file", "bench/longmemeval.json")?,
        sha256: req_str(obj, "sha256", "bench/longmemeval.json")?,
    })
}

fn parse_corpus(raw: &str) -> UaResult<Corpus> {
    let v = parse_json(raw, "bench/corpus.json")?;
    let obj = object(&v, "bench/corpus.json")?;
    only_keys(obj, &["notes", "queries"], "bench/corpus.json")?;
    let notes_v = obj.get("notes").ok_or_else(|| UaError::invalid("bench/corpus.json is missing notes"))?;
    let queries_v =
        obj.get("queries").ok_or_else(|| UaError::invalid("bench/corpus.json is missing queries"))?;
    let notes = notes_v
        .as_array()
        .ok_or_else(|| UaError::invalid("bench/corpus.json notes must be an array"))?
        .iter()
        .map(parse_note)
        .collect::<UaResult<Vec<_>>>()?;
    let queries = queries_v
        .as_array()
        .ok_or_else(|| UaError::invalid("bench/corpus.json queries must be an array"))?
        .iter()
        .map(parse_query)
        .collect::<UaResult<Vec<_>>>()?;
    Ok(Corpus { notes, queries })
}

fn parse_note(v: &Value) -> UaResult<CorpusNote> {
    let obj = object(v, "fixture note")?;
    only_keys(
        obj,
        &["key", "title", "content", "tags", "valid_from", "recorded_at", "supersedes", "contradicts"],
        "fixture note",
    )?;
    let key = req_str(obj, "key", "fixture note")?;
    Ok(CorpusNote {
        title: req_str(obj, "title", &key)?,
        content: req_str(obj, "content", &key)?,
        tags: opt_strings(obj, "tags", &key)?,
        valid_from: opt_str(obj, "valid_from", &key)?,
        recorded_at: opt_str(obj, "recorded_at", &key)?,
        supersedes: opt_str(obj, "supersedes", &key)?,
        contradicts: opt_strings(obj, "contradicts", &key)?,
        key,
    })
}

fn parse_query(v: &Value) -> UaResult<CorpusQuery> {
    let obj = object(v, "fixture query")?;
    only_keys(obj, &["id", "class", "query", "as_of", "must", "must_not", "outranked"], "fixture query")?;
    let id = req_str(obj, "id", "fixture query")?;
    Ok(CorpusQuery {
        class: req_str(obj, "class", &id)?,
        query: req_str(obj, "query", &id)?,
        as_of: opt_str(obj, "as_of", &id)?,
        must: req_strings(obj, "must", &id)?,
        must_not: opt_strings(obj, "must_not", &id)?,
        outranked: opt_strings(obj, "outranked", &id)?,
        id,
    })
}

fn parse_floor(raw: &str) -> UaResult<FloorFile> {
    let v = parse_json(raw, "bench/floor.json")?;
    let obj = object(&v, "bench/floor.json")?;
    only_keys(obj, &["k", "classes"], "bench/floor.json")?;
    let k = obj
        .get("k")
        .and_then(Value::as_u64)
        .ok_or_else(|| UaError::invalid("bench/floor.json is missing k"))? as usize;
    let classes = obj
        .get("classes")
        .and_then(Value::as_array)
        .ok_or_else(|| UaError::invalid("bench/floor.json is missing classes"))?
        .iter()
        .map(|item| {
            let row = object(item, "floor class")?;
            only_keys(row, &["class", "n", "recall_at_5", "mrr"], "floor class")?;
            Ok(FloorClass {
                class: req_str(row, "class", "floor class")?,
                n: row
                    .get("n")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| UaError::invalid("floor class is missing n"))? as usize,
                recall_at_5: row
                    .get("recall_at_5")
                    .and_then(Value::as_f64)
                    .ok_or_else(|| UaError::invalid("floor class is missing recall_at_5"))?,
                mrr: row
                    .get("mrr")
                    .and_then(Value::as_f64)
                    .ok_or_else(|| UaError::invalid("floor class is missing mrr"))?,
            })
        })
        .collect::<UaResult<Vec<_>>>()?;
    Ok(FloorFile { k, classes })
}

fn parse_questions(v: &Value) -> UaResult<Vec<LmeQuestion>> {
    let rows = v.as_array().ok_or_else(|| UaError::invalid("LongMemEval-S file must be a JSON array"))?;
    rows.iter().map(parse_question).collect()
}

fn parse_question(v: &Value) -> UaResult<LmeQuestion> {
    let obj = object(v, "LongMemEval question")?;
    let question_id = req_str(obj, "question_id", "LongMemEval question")?;
    let sessions = obj
        .get("haystack_sessions")
        .and_then(Value::as_array)
        .ok_or_else(|| UaError::invalid(format!("question {question_id} is missing haystack_sessions")))?;
    let mut haystack_sessions = Vec::new();
    for session in sessions {
        let turns = session.as_array().ok_or_else(|| {
            UaError::invalid(format!("question {question_id} has a session that is not an array"))
        })?;
        let mut parsed = Vec::new();
        for turn in turns {
            let row = object(turn, &format!("question {question_id} turn"))?;
            parsed.push(LmeTurn {
                role: req_str(row, "role", &question_id)?,
                content: req_str(row, "content", &question_id)?,
            });
        }
        haystack_sessions.push(parsed);
    }
    Ok(LmeQuestion {
        question_type: req_str(obj, "question_type", &question_id)?,
        question: req_str(obj, "question", &question_id)?,
        question_date: opt_str(obj, "question_date", &question_id)?,
        answer_session_ids: req_strings(obj, "answer_session_ids", &question_id)?,
        haystack_session_ids: req_strings(obj, "haystack_session_ids", &question_id)?,
        haystack_dates: req_strings(obj, "haystack_dates", &question_id)?,
        haystack_sessions,
        question_id,
    })
}

fn dataset_url(pin: &Pin) -> String {
    format!("https://huggingface.co/datasets/{}/resolve/{}/{}", pin.repo, pin.revision, pin.file)
}

fn dataset_help(pin: &Pin) -> String {
    let short = &pin.revision[..8];
    format!(
        "Pinned file {} sha256 {} from Hugging Face {} revision {}.\n\
         Download it with:\n  \
         mkdir -p ~/.cache/ua-longmemeval/{short}\n  \
         curl -fsSL -o ~/.cache/ua-longmemeval/{short}/{} \\\n    \
         {}\n\
         Then run: cargo run -p ua-memory --bin memory-bench -- --longmemeval\n\
         Or pass --data PATH to a copy that already has this hash. \
         When --data is omitted, that command downloads the file on demand.",
        pin.file,
        pin.sha256,
        pin.repo,
        pin.revision,
        pin.file,
        dataset_url(pin),
    )
}

fn cache_file(pin: &Pin) -> PathBuf {
    let dir = match std::env::var_os("UA_LONGMEMEVAL_CACHE") {
        Some(p) => PathBuf::from(p),
        None => {
            let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
            home.join(".cache").join("ua-longmemeval").join(&pin.revision[..8])
        }
    };
    dir.join(&pin.file)
}

fn sha256_file(path: &Path) -> UaResult<String> {
    let mut file =
        std::fs::File::open(path).map_err(|e| UaError::invalid(format!("read {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1 << 20];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf)
            .map_err(|e| UaError::invalid(format!("read {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn check_hash(path: &Path, pin: &Pin) -> UaResult<()> {
    let actual = sha256_file(path)?;
    if actual != pin.sha256 {
        return Err(UaError::invalid(format!(
            "{}: sha256 {actual} does not match pinned {}. {}",
            path.display(),
            pin.sha256,
            dataset_help(pin)
        )));
    }
    Ok(())
}

fn download(url: &str, dest: &Path) -> UaResult<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| UaError::invalid(format!("create {}: {e}", parent.display())))?;
    }
    let partial = dest.with_extension("json.part");
    let status = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "--retry-delay", "2", "-o"])
        .arg(&partial)
        .arg(url)
        .status()
        .map_err(|e| UaError::invalid(format!("could not run curl ({e})")))?;
    if !status.success() {
        let _ = std::fs::remove_file(&partial);
        return Err(UaError::invalid(format!("curl exited {status}")));
    }
    std::fs::rename(&partial, dest).map_err(|e| UaError::invalid(format!("store dataset: {e}")))?;
    Ok(())
}

fn locate_dataset(data: Option<&Path>, pin: &Pin) -> UaResult<PathBuf> {
    if let Some(path) = data {
        if !path.is_file() {
            return Err(UaError::not_found(format!(
                "LongMemEval-S dataset is not at {}. {}",
                path.display(),
                dataset_help(pin)
            )));
        }
        check_hash(path, pin)?;
        return Ok(path.to_path_buf());
    }
    let path = cache_file(pin);
    if !path.is_file() {
        download(&dataset_url(pin), &path).map_err(|e| {
            UaError::not_found(format!(
                "LongMemEval-S dataset is not at {} and the download failed ({e}). {}",
                path.display(),
                dataset_help(pin)
            ))
        })?;
    }
    check_hash(&path, pin)?;
    Ok(path)
}

fn bench_config(home: &Path) -> Config {
    let mut cfg = Config::for_home(home);
    // A name nothing registers, so a default build stays lexical.
    cfg.embed_model = "bench-lexical".into();
    cfg.clock = ua_core::time::Clock::fixed(BENCH_NOW).expect("BENCH_NOW is a valid instant");
    cfg
}

fn bench_config_with_embed(scratch_home: &Path, embed: Option<&EmbedOptions>) -> UaResult<Config> {
    let Some(opt) = embed else {
        return Ok(bench_config(scratch_home));
    };
    if !crate::EMBEDDINGS_ENABLED {
        return Err(UaError::invalid(
            "--embed requires building with `--features embeddings` \
             (e.g. `cargo run --release --features embeddings -p ua-memory --bin memory-bench -- --embed`)",
        ));
    }
    let mut cfg = Config::for_home(&opt.home);
    // `opt.home` is used strictly read-only for `local_embedder` model lookup
    // (`$UA_HOME/models`, never writing or downloading); all benchmark SQLite
    // databases live under `scratch_home`.
    cfg.memory.embedder = "local".into();
    cfg.embed_model = opt.model.clone();
    cfg.clock = ua_core::time::Clock::fixed(BENCH_NOW).expect("BENCH_NOW is a valid instant");
    if crate::embed::local_embedder(&cfg).is_none() {
        return Err(UaError::not_found(format!(
            "local embedding model {:?} is not fetched under {}/models; \
             run `ua memory models fetch --model {}` first",
            cfg.embed_model,
            cfg.home.display(),
            cfg.embed_model
        )));
    }
    Ok(cfg)
}

fn embed_report_meta(cfg: &Config, embed: Option<&EmbedOptions>, chunks_scored: usize) -> Option<Value> {
    let opt = embed?;
    let e = crate::embed::embedder_for(cfg);
    Some(json!({
        "model": e.model(),
        "revision": e.revision(),
        "identity": e.identity(),
        "no_chunks": opt.no_chunks,
        "chunks_scored": chunks_scored,
    }))
}

async fn count_memory_chunks(db: &Db) -> UaResult<usize> {
    let n: i64 =
        db.read_async(|c| Ok(c.query_row("SELECT COUNT(*) FROM memory_chunks", [], |r| r.get(0))?)).await?;
    Ok(n.max(0) as usize)
}

fn caller(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: false,
        session_key: None,
        transport: Transport::Cli,
        org_id: ua_core::DEFAULT_ORG.to_string(),
    }
}

fn schema() -> Vec<ua_store::Part> {
    let mut parts: Vec<ua_store::Part> = ua_store::schema::parts(&[ledger::SCHEMA, ledger::META_SCHEMA]);
    parts.push(ua_store::org::STORE_PART.into());
    parts.extend(crate::schema_parts().into_iter().map(ua_store::Part::from));
    parts.extend(crate::org_parts());
    parts
}

fn open_db(path: &Path) -> UaResult<Db> {
    Db::open(path, &schema()).map_err(|e| UaError::internal(format!("open {}: {e}", path.display())))
}

/// `created_at` is stamped at save time (the bench clock). `as_of` keeps a
/// note only when `created_at <= as_of`, so an `as_of` before the save would
/// hide every note. Move `created_at` back to `valid_from` so temporal queries
/// see the note's own date. Recency already reads `valid_from` when it is
/// set, so this does not change ranking for a query without `as_of`.
///
/// This is why the temporal class passes: it measures `as_of` over notes
/// recorded when they became valid. A note recorded late (saved today with a
/// past `valid_from`) stays invisible to an `as_of` between the two. The
/// fixture keeps one such note (`recorded_at`) as a recorded gap.
async fn backdate_created(db: &Db) -> UaResult<()> {
    db.write_async(|tx| {
        tx.execute("UPDATE memory SET created_at = valid_from WHERE valid_from IS NOT NULL", [])?;
        Ok(())
    })
    .await
}

/// Set `created_at` of fixture notes that name a `recorded_at`.
async fn set_recorded(db: &Db, recorded: Vec<(String, String)>) -> UaResult<()> {
    if recorded.is_empty() {
        return Ok(());
    }
    db.write_async(move |tx| {
        for (id, at) in &recorded {
            tx.execute("UPDATE memory SET created_at = ?1 WHERE id = ?2", rusqlite::params![at, id])?;
        }
        Ok(())
    })
    .await
}

/// A scratch directory for one bench run, removed on drop. The name carries
/// the pid, a per-process counter and the start time, so concurrent runs in
/// one process or across processes never share it.
struct Scratch {
    dir: PathBuf,
}

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

impl Scratch {
    fn new(name: &str) -> UaResult<Self> {
        let n = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("ua-memory-bench-{name}-{}-{n}-{nanos}", std::process::id()));
        std::fs::create_dir(&dir).map_err(|e| UaError::internal(format!("create {}: {e}", dir.display())))?;
        Ok(Self { dir })
    }

    /// A fresh subdirectory for one database. SQLite writes `-wal` and
    /// `-shm` files next to it; [`Scratch::release`] removes all of them.
    fn sub(&self, name: &str) -> UaResult<PathBuf> {
        let dir = self.dir.join(name.replace(['/', '\\'], "_"));
        std::fs::create_dir(&dir).map_err(|e| UaError::internal(format!("create {}: {e}", dir.display())))?;
        Ok(dir)
    }

    fn release(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn load_fixture(db: &Db, cfg: &Config, notes: &[CorpusNote]) -> UaResult<HashMap<String, String>> {
    let who = caller("builder-1");
    let mut ids: HashMap<String, String> = HashMap::new();
    for note in notes {
        let supersedes = match &note.supersedes {
            Some(key) => Some(ids.get(key).cloned().ok_or_else(|| {
                UaError::invalid(format!("fixture note {} supersedes unknown key {key}", note.key))
            })?),
            None => None,
        };
        let mut contradicts = Vec::new();
        for key in &note.contradicts {
            contradicts.push(ids.get(key).cloned().ok_or_else(|| {
                UaError::invalid(format!("fixture note {} contradicts unknown key {key}", note.key))
            })?);
        }
        let saved = save::save(
            db,
            cfg,
            &who,
            SaveRequest {
                content: note.content.clone(),
                title: Some(note.title.clone()),
                tags: Some(note.tags.clone()),
                author: Some(who.label.clone()),
                valid_from: note.valid_from.clone(),
                supersedes,
                contradicts: if contradicts.is_empty() { None } else { Some(contradicts) },
                ..Default::default()
            },
        )
        .await?;
        let id =
            saved["id"].as_str().ok_or_else(|| UaError::internal("memory_save returned no id"))?.to_string();
        ids.insert(note.key.clone(), id);
    }
    backdate_created(db).await?;
    let recorded = notes
        .iter()
        .filter_map(|n| n.recorded_at.clone().map(|at| (ids[&n.key].clone(), at)))
        .collect::<Vec<_>>();
    set_recorded(db, recorded).await?;
    Ok(ids)
}

/// True when note `key` is superseded by a note already valid at `at`: a hit
/// on `key` then is a stale result (`docs/memory.md`, target under 2%).
fn stale_at(corpus: &Corpus, key: &str, at: &str) -> bool {
    corpus.notes.iter().any(|n| {
        n.supersedes.as_deref() == Some(key) && n.valid_from.as_deref().is_none_or(|from| from <= at)
    })
}

async fn search_keys(
    db: &Db,
    cfg: &Config,
    ids: &HashMap<String, String>,
    query: &str,
    as_of: Option<String>,
) -> UaResult<(Vec<String>, String)> {
    let key_of: HashMap<&str, &str> = ids.iter().map(|(k, id)| (id.as_str(), k.as_str())).collect();
    let hits = search::search(
        db,
        cfg,
        ua_core::DEFAULT_ORG,
        SearchRequest { query: query.to_string(), as_of, limit: Some(SEARCH_LIMIT), ..Default::default() },
    )
    .await?;
    let mode = hits["retrieval"]["mode"].as_str().unwrap_or("").to_string();
    let ranked = hits["results"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|row| row["id"].as_str())
        .map(|id| key_of.get(id).copied().unwrap_or(id).to_string())
        .collect();
    Ok((ranked, mode))
}

async fn run_fixture(embed: Option<&EmbedOptions>) -> UaResult<Value> {
    let scratch = Scratch::new("fixture")?;
    run_fixture_with_embed(CORPUS, FLOOR, &scratch, embed).await
}

#[cfg(test)]
async fn run_fixture_with(corpus_raw: &str, floor_raw: &str, scratch: &Scratch) -> UaResult<Value> {
    run_fixture_with_embed(corpus_raw, floor_raw, scratch, None).await
}

/// The fixture run over a corpus and floor (the checked-in ones outside
/// tests), with its databases under `scratch`. Each query's copy is removed
/// when the query finishes; only the base corpus database stays until
/// `scratch` drops.
async fn run_fixture_with_embed(
    corpus_raw: &str,
    floor_raw: &str,
    scratch: &Scratch,
    embed: Option<&EmbedOptions>,
) -> UaResult<Value> {
    let cfg = bench_config_with_embed(&scratch.dir, embed)?;
    run_fixture_with_cfg(corpus_raw, floor_raw, scratch, &cfg, embed).await
}

async fn run_fixture_with_cfg(
    corpus_raw: &str,
    floor_raw: &str,
    scratch: &Scratch,
    cfg: &Config,
    embed: Option<&EmbedOptions>,
) -> UaResult<Value> {
    let corpus = parse_corpus(corpus_raw)?;
    let floor = parse_floor(floor_raw)?;
    if floor.k != RECALL_K {
        return Err(UaError::internal(format!(
            "bench/floor.json k is {}, the harness scores @{RECALL_K}",
            floor.k
        )));
    }
    for q in &corpus.queries {
        if q.must.is_empty() {
            return Err(UaError::invalid(format!("fixture query {} has no must notes", q.id)));
        }
        for key in q.must.iter().chain(&q.must_not).chain(&q.outranked) {
            if !corpus.notes.iter().any(|n| &n.key == key) {
                return Err(UaError::invalid(format!("fixture query {} names unknown note {key}", q.id)));
            }
        }
    }

    let no_chunks = embed.is_some_and(|e| e.no_chunks);
    let base = scratch.sub("corpus")?.join("corpus.db");
    let (ids, chunks_scored) = {
        let db = open_db(&base)?;
        let ids = load_fixture(&db, cfg, &corpus.notes).await?;
        if no_chunks {
            db.write_async(|tx| {
                tx.execute("DELETE FROM memory_chunks", [])?;
                Ok(())
            })
            .await?;
        }
        let chunks_scored = count_memory_chunks(&db).await?;
        let (busy, _, _) = db.checkpoint_truncate()?;
        if busy {
            return Err(UaError::internal("bench checkpoint was busy; the fixture copy would be partial"));
        }
        (ids, chunks_scored)
    };

    let mut query_rows = Vec::new();
    let mut mode = String::new();
    let mut stale_hits = 0usize;
    let mut must_not_hits = 0usize;
    let mut shown = 0usize;
    let mut vacuous = Vec::new();
    for (i, q) in corpus.queries.iter().enumerate() {
        let dir = scratch.sub(&format!("q{i}"))?;
        let path = dir.join("q.db");
        std::fs::copy(&base, &path).map_err(|e| UaError::internal(format!("copy fixture database: {e}")))?;
        let db = open_db(&path)?;
        let searched = search_keys(&db, cfg, &ids, &q.query, q.as_of.clone()).await;
        drop(db);
        Scratch::release(&dir);
        let (ranked, qmode) = searched?;
        if embed.is_some() && qmode != "hybrid" {
            return Err(UaError::internal(format!(
                "--embed requested hybrid retrieval, but query {} fell back to {qmode:?} \
                 (verify model files with `ua memory models status --verify`)",
                q.id
            )));
        }
        if mode.is_empty() {
            mode = qmode.clone();
        } else if mode != qmode {
            mode = "mixed".into();
        }
        let n = ranked.len().min(RECALL_K);
        shown += n;
        let at = q.as_of.as_deref().unwrap_or(BENCH_NOW);
        stale_hits += ranked.iter().take(n).filter(|key| stale_at(&corpus, key, at)).count();
        must_not_hits += ranked.iter().take(n).filter(|key| q.must_not.iter().any(|m| m == *key)).count();
        for key in &q.outranked {
            if !ranked.contains(key) {
                vacuous.push(json!({
                    "query": q.id,
                    "reason": format!("outranked note {key} was not retrieved, so it no longer tests ranking"),
                }));
            }
        }
        let (recall, mrr) = score_fixture(&ranked, &q.must, &q.must_not, &q.outranked);
        query_rows.push(json!({
            "id": q.id,
            "class": q.class,
            "recall_at_5": recall,
            "mrr": round4(mrr),
            "ranked": ranked,
        }));
    }

    let mut class_names: Vec<String> = Vec::new();
    for q in &corpus.queries {
        if !class_names.iter().any(|c| c == &q.class) {
            class_names.push(q.class.clone());
        }
    }
    let mut classes = Vec::new();
    let mut failures = Vec::new();
    let floors: HashMap<&str, &FloorClass> = floor.classes.iter().map(|c| (c.class.as_str(), c)).collect();
    for name in &class_names {
        let rows: Vec<&Value> = query_rows.iter().filter(|r| r["class"] == json!(name)).collect();
        let recall = mean(&rows.iter().map(|r| r["recall_at_5"].as_f64().unwrap_or(0.0)).collect::<Vec<_>>());
        let mrr = mean(&rows.iter().map(|r| r["mrr"].as_f64().unwrap_or(0.0)).collect::<Vec<_>>());
        classes.push(json!({"class": name, "n": rows.len(), "recall_at_5": recall, "mrr": mrr}));
        match floors.get(name.as_str()) {
            None => failures.push(json!({"class": name, "reason": "no floor"})),
            // A deleted or added query would otherwise move the class mean
            // without anyone changing the floor.
            Some(f) if f.n != rows.len() => failures.push(json!({
                "class": name,
                "reason": format!("bench/floor.json records n={} but the corpus has {} queries", f.n, rows.len()),
            })),
            Some(f) if recall + 1e-9 < f.recall_at_5 || mrr + 1e-9 < f.mrr => failures.push(json!({
                "class": name,
                "recall_at_5": recall,
                "floor_recall_at_5": f.recall_at_5,
                "mrr": mrr,
                "floor_mrr": f.mrr,
            })),
            Some(_) => {}
        }
    }
    for f in &floor.classes {
        if !class_names.iter().any(|c| c == &f.class) {
            failures.push(json!({"class": f.class, "reason": "floor class has no queries"}));
        }
    }
    failures.extend(vacuous);

    let share = |hits: usize| if shown == 0 { 0.0 } else { round4(hits as f64 / shown as f64) };
    let recalls: Vec<f64> = query_rows.iter().map(|r| r["recall_at_5"].as_f64().unwrap_or(0.0)).collect();
    let mrrs: Vec<f64> = query_rows.iter().map(|r| r["mrr"].as_f64().unwrap_or(0.0)).collect();
    let mut retrieval = json!({"mode": mode});
    if let Some(meta) = embed_report_meta(cfg, embed, chunks_scored) {
        retrieval["embed"] = meta;
    }
    Ok(json!({
        "bench": "fixture",
        "build": {"embeddings": crate::EMBEDDINGS_ENABLED},
        "retrieval": retrieval,
        "clock": BENCH_NOW,
        "k": RECALL_K,
        "stale_share": {
            "definition": "share of top-5 hits superseded by a note already valid at the query instant (as_of, else the bench clock)",
            "stale": stale_hits,
            "hits": shown,
            "share": share(stale_hits),
        },
        "must_not_share": share(must_not_hits),
        "overall": {"n": query_rows.len(), "recall_at_5": mean(&recalls), "mrr": mean(&mrrs)},
        "classes": classes,
        "queries": query_rows,
        "floor": {"ok": failures.is_empty(), "failures": failures},
    }))
}

fn fixture_table(report: &Value) -> String {
    let mut lines = vec![format!("{:<16} {:>3} {:>10} {:>8}", "class", "n", "recall@5", "mrr")];
    let mut push = |name: &str, row: &Value| {
        lines.push(format!(
            "{:<16} {:>3} {:>10.4} {:>8.4}",
            name,
            row["n"].as_u64().unwrap_or(0),
            row["recall_at_5"].as_f64().unwrap_or(0.0),
            row["mrr"].as_f64().unwrap_or(0.0),
        ));
    };
    if let Some(rows) = report["classes"].as_array() {
        for row in rows {
            push(row["class"].as_str().unwrap_or("?"), row);
        }
    }
    push("overall", &report["overall"]);
    lines.push(format!(
        "stale share {} ({}/{}), must_not share {}",
        report["stale_share"]["share"].as_f64().unwrap_or(0.0),
        report["stale_share"]["stale"].as_u64().unwrap_or(0),
        report["stale_share"]["hits"].as_u64().unwrap_or(0),
        report["must_not_share"].as_f64().unwrap_or(0.0),
    ));
    if report["floor"]["ok"] != json!(true) {
        lines.push(format!("floor: below bench/floor.json {}", report["floor"]["failures"]));
    }
    lines.join("\n")
}

const LME_TYPES: [&str; 6] = [
    "single-session-user",
    "single-session-assistant",
    "single-session-preference",
    "multi-session",
    "knowledge-update",
    "temporal-reasoning",
];

struct LmeRow {
    id: String,
    kind: String,
    recall_all_5: f64,
    recall_any_5: f64,
    recall_frac_5: f64,
    mrr: f64,
    ranked: Vec<String>,
}

fn render_session(date: &str, turns: &[LmeTurn]) -> (String, String) {
    let body =
        turns.iter().map(|t| format!("{}: {}", t.role, t.content.trim())).collect::<Vec<_>>().join("\n\n");
    (format!("Conversation on {date}"), format!("Conversation date: {date}\n\n{body}"))
}

struct QuestionRun {
    row: LmeRow,
    mode: String,
    search_ms: f64,
    as_of: Option<f64>,
    older: usize,
    older_seen: usize,
    chunks_scored: usize,
}

/// Score one question on its own database in its own scratch subdirectory,
/// which is removed (database, `-wal` and `-shm`) before this returns.
async fn score_question(
    q: &LmeQuestion,
    scratch: &Scratch,
    cfg: &Config,
    no_chunks: bool,
) -> UaResult<QuestionRun> {
    if q.haystack_session_ids.len() != q.haystack_dates.len()
        || q.haystack_session_ids.len() != q.haystack_sessions.len()
    {
        return Err(UaError::invalid(format!("question {} has mismatched haystack arrays", q.question_id)));
    }
    let dir = scratch.sub(&q.question_id)?;
    let run = score_question_in(q, &dir.join("q.db"), cfg, no_chunks).await;
    Scratch::release(&dir);
    run
}

async fn score_question_in(
    q: &LmeQuestion,
    path: &Path,
    cfg: &Config,
    no_chunks: bool,
) -> UaResult<QuestionRun> {
    let db = open_db(path)?;
    let who = caller("longmemeval-harness");
    let mut session_of: HashMap<String, String> = HashMap::new();
    let mut date_of: HashMap<String, String> = HashMap::new();
    for ((sid, date), turns) in q.haystack_session_ids.iter().zip(&q.haystack_dates).zip(&q.haystack_sessions)
    {
        let valid_from = parse_session_date(date)?;
        let (title, body) = render_session(date, turns);
        let saved = save::save(
            &db,
            cfg,
            &who,
            SaveRequest {
                content: body,
                title: Some(title),
                tags: Some(vec!["project:longmemeval-eval".into()]),
                author: Some(who.label.clone()),
                valid_from: Some(valid_from.clone()),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| UaError::invalid(format!("question {}: save session {sid}: {e}", q.question_id)))?;
        let id =
            saved["id"].as_str().ok_or_else(|| UaError::internal("memory_save returned no id"))?.to_string();
        session_of.insert(id, sid.clone());
        date_of.insert(sid.clone(), valid_from);
    }
    backdate_created(&db).await?;
    if no_chunks {
        db.write_async(|tx| {
            tx.execute("DELETE FROM memory_chunks", [])?;
            Ok(())
        })
        .await?;
    }
    let chunks_scored = count_memory_chunks(&db).await?;

    let started = std::time::Instant::now();
    let hits = search::search(
        &db,
        cfg,
        ua_core::DEFAULT_ORG,
        SearchRequest { query: q.question.clone(), limit: Some(SEARCH_LIMIT), ..Default::default() },
    )
    .await
    .map_err(|e| UaError::invalid(format!("question {}: search: {e}", q.question_id)))?;
    let search_ms = started.elapsed().as_secs_f64() * 1000.0;
    let mut mode = hits["retrieval"]["mode"].as_str().unwrap_or("").to_string();
    let ranked = rank_sessions(&hits, &session_of);
    let score = score_sessions(&ranked, &q.answer_session_ids)
        .map_err(|e| UaError::invalid(format!("question {}: {e}", q.question_id)))?;

    let as_of_hit = if q.question_type == "temporal-reasoning"
        && let Some(raw) = q.question_date.as_deref()
        && let Ok(as_of) = parse_session_date(raw)
    {
        let again = search::search(
            &db,
            cfg,
            ua_core::DEFAULT_ORG,
            SearchRequest {
                query: q.question.clone(),
                as_of: Some(as_of),
                limit: Some(SEARCH_LIMIT),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| UaError::invalid(format!("question {}: as_of search: {e}", q.question_id)))?;
        let as_of_mode = again["retrieval"]["mode"].as_str().unwrap_or("");
        if as_of_mode != mode {
            mode = "mixed".into();
        }
        let ranked_as_of = rank_sessions(&again, &session_of);
        let again_score = score_sessions(&ranked_as_of, &q.answer_session_ids)?;
        Some(again_score.recall_all_5)
    } else {
        None
    };

    let (older, older_seen) = older_non_evidence(q, &ranked, &date_of);
    drop(db);
    Ok(QuestionRun {
        row: LmeRow {
            id: q.question_id.clone(),
            kind: q.question_type.clone(),
            recall_all_5: score.recall_all_5,
            recall_any_5: score.recall_any_5,
            recall_frac_5: score.recall_frac_5,
            mrr: score.mrr,
            ranked,
        },
        mode,
        search_ms,
        as_of: as_of_hit,
        older,
        older_seen,
        chunks_scored,
    })
}

fn rank_sessions(hits: &Value, session_of: &HashMap<String, String>) -> Vec<String> {
    hits["results"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|row| row["id"].as_str())
        .map(|id| session_of.get(id).cloned().unwrap_or_else(|| "?".into()))
        .collect()
}

/// Knowledge-update top-5 hits that are not evidence and predate the newest
/// evidence session, out of all top-5 hits. Not the design's stale share:
/// LongMemEval has no supersession links, so most of these are unrelated
/// filler sessions from the 50-session haystack, not superseded facts. The
/// fixture's `stale_share` is the design's metric.
fn older_non_evidence(
    q: &LmeQuestion,
    ranked: &[String],
    date_of: &HashMap<String, String>,
) -> (usize, usize) {
    if q.question_type != "knowledge-update" {
        return (0, 0);
    }
    let evidence: HashSet<&str> = q.answer_session_ids.iter().map(String::as_str).collect();
    let newest = evidence.iter().filter_map(|sid| date_of.get(*sid)).max().cloned();
    let Some(newest) = newest else { return (0, 0) };
    let mut older = 0;
    let mut seen = 0;
    for sid in ranked.iter().take(RECALL_K) {
        seen += 1;
        if evidence.contains(sid.as_str()) {
            continue;
        }
        if date_of.get(sid).is_some_and(|d| d.as_str() < newest.as_str()) {
            older += 1;
        }
    }
    (older, seen)
}

/// The answerable questions to score: `ids` (in file order) when given, then
/// the first `limit`. Returns the selection and its name for the report.
fn select<'a>(
    questions: &'a [LmeQuestion],
    limit: Option<usize>,
    ids: Option<&[String]>,
) -> UaResult<(Vec<&'a LmeQuestion>, &'static str)> {
    let mut chosen: Vec<&LmeQuestion> =
        questions.iter().filter(|q| !q.question_id.ends_with("_abs")).collect();
    let mut how = "full";
    if let Some(ids) = ids {
        let wanted: HashSet<&str> = ids.iter().map(String::as_str).collect();
        if wanted.len() != ids.len() {
            return Err(UaError::invalid("--ids lists a question id more than once"));
        }
        for id in ids {
            if !chosen.iter().any(|q| &q.question_id == id) {
                return Err(UaError::invalid(format!(
                    "--ids names {id}, which is not an answerable question in this file"
                )));
            }
        }
        chosen.retain(|q| wanted.contains(q.question_id.as_str()));
        how = "ids";
    }
    if let Some(n) = limit {
        chosen.truncate(n);
        how = if how == "ids" { "ids+limit" } else { "limit" };
    }
    Ok((chosen, how))
}

fn p95(mut xs: Vec<f64>) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((xs.len() as f64) * 0.95).ceil() as usize - 1;
    (xs[idx.min(xs.len() - 1)] * 10.0).round() / 10.0
}

async fn run_longmemeval(
    data: Option<&Path>,
    limit: Option<usize>,
    ids: Option<&[String]>,
    embed: Option<&EmbedOptions>,
) -> UaResult<Value> {
    let pin = pin()?;
    let path = locate_dataset(data, &pin)?;
    let file =
        std::fs::File::open(&path).map_err(|e| UaError::invalid(format!("read {}: {e}", path.display())))?;
    let raw: Value = serde_json::from_reader(std::io::BufReader::new(file))
        .map_err(|e| UaError::invalid(format!("{} is not JSON: {e}", path.display())))?;
    let questions = parse_questions(&raw)?;
    let scratch = Scratch::new("longmemeval")?;
    let cfg = bench_config_with_embed(&scratch.dir, embed)?;
    run_longmemeval_with_cfg(&pin, &path.display().to_string(), &questions, limit, ids, &scratch, &cfg, embed)
        .await
}

#[allow(clippy::too_many_arguments)]
async fn run_longmemeval_with_cfg(
    pin: &Pin,
    path_display: &str,
    questions: &[LmeQuestion],
    limit: Option<usize>,
    ids: Option<&[String]>,
    scratch: &Scratch,
    cfg: &Config,
    embed: Option<&EmbedOptions>,
) -> UaResult<Value> {
    let total = questions.len();
    let answerable = questions.iter().filter(|q| !q.question_id.ends_with("_abs")).count();
    let (chosen, selection) = select(questions, limit, ids)?;
    if chosen.is_empty() {
        return Err(UaError::invalid(format!(
            "{path_display} has no answerable questions. {}",
            dataset_help(pin)
        )));
    }

    let no_chunks = embed.is_some_and(|e| e.no_chunks);
    let mut rows = Vec::new();
    let mut times = Vec::new();
    let mut as_of_hits = Vec::new();
    let mut older = 0usize;
    let mut older_seen = 0usize;
    let mut chunks_scored = 0usize;
    let mut mode = String::new();
    for (i, q) in chosen.iter().enumerate() {
        let run = score_question(q, scratch, cfg, no_chunks).await?;
        if embed.is_some() && run.mode != "hybrid" {
            return Err(UaError::internal(format!(
                "--embed requested hybrid retrieval, but question {} fell back to {:?} \
                 (verify model files with `ua memory models status --verify`)",
                run.row.id, run.mode
            )));
        }
        if mode.is_empty() {
            mode = run.mode.clone();
        } else if mode != run.mode {
            mode = "mixed".into();
        }
        eprintln!(
            "[{}/{}] {} recall@5={} mrr={:.3}",
            i + 1,
            chosen.len(),
            run.row.id,
            run.row.recall_all_5,
            run.row.mrr
        );
        times.push(run.search_ms);
        if let Some(hit) = run.as_of {
            as_of_hits.push(hit);
        }
        older += run.older;
        older_seen += run.older_seen;
        chunks_scored += run.chunks_scored;
        rows.push(run.row);
    }

    let by_type = LME_TYPES
        .iter()
        .filter_map(|kind| summarize(&rows, Some(kind)).map(|row| json!({"type": kind, "n": row.0, "recall_at_5": row.1, "hits_at_5": row.2, "mrr_at_10": row.3, "recall_any_at_5": row.4, "recall_frac_at_5": row.5})))
        .collect::<Vec<_>>();
    let (n, recall, hits, mrr, any, frac) = summarize(&rows, None).unwrap_or((0, 0.0, 0, 0.0, 0.0, 0.0));
    let questions_out: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "type": r.kind,
                "recall_at_5": r.recall_all_5,
                "mrr_at_10": round4(r.mrr),
                "ranked_sessions": r.ranked,
            })
        })
        .collect();
    let mut retrieval = json!({"mode": mode, "search_limit": SEARCH_LIMIT, "granularity": "session"});
    if let Some(meta) = embed_report_meta(cfg, embed, chunks_scored) {
        retrieval["embed"] = meta;
    }
    Ok(json!({
        "bench": "longmemeval-s",
        "build": {"embeddings": crate::EMBEDDINGS_ENABLED},
        "retrieval": retrieval,
        "clock": BENCH_NOW,
        "dataset": {
            "repo": pin.repo,
            "revision": pin.revision,
            "file": pin.file,
            "sha256": pin.sha256,
            "url": dataset_url(pin),
            "questions": total,
            "answerable": answerable,
            "scored": n,
            "selection": selection,
        },
        "strict_recall_at_5": {"hits": hits, "n": n, "recall": recall},
        "mrr_at_10": mrr,
        "recall_any_at_5": any,
        "recall_frac_at_5": frac,
        "by_type": by_type,
        "as_of_accuracy": {
            "definition": "strict recall@5 on temporal-reasoning questions when as_of is the question date",
            "n": as_of_hits.len(),
            "recall_at_5": mean(&as_of_hits),
        },
        "older_non_evidence_share": {
            "definition": "share of knowledge-update top-5 hits that are not evidence and predate the newest evidence session; not the design's stale share (no supersession links in LongMemEval), so not comparable with its 2% target",
            "hits": older_seen,
            "older": older,
            "share": if older_seen == 0 { 0.0 } else { round4(older as f64 / older_seen as f64) },
        },
        "latency_ms": {
            "definition": "p95 of memory_search only, excluding ingest",
            "p95": p95(times),
            "n": n,
        },
        "questions": questions_out,
    }))
}

fn summarize(rows: &[LmeRow], kind: Option<&str>) -> Option<(usize, f64, usize, f64, f64, f64)> {
    let picked: Vec<&LmeRow> = rows.iter().filter(|r| kind.is_none_or(|k| r.kind == k)).collect();
    if picked.is_empty() {
        return None;
    }
    let n = picked.len();
    let hits = picked.iter().filter(|r| r.recall_all_5 == 1.0).count();
    Some((
        n,
        mean(&picked.iter().map(|r| r.recall_all_5).collect::<Vec<_>>()),
        hits,
        mean(&picked.iter().map(|r| r.mrr).collect::<Vec<_>>()),
        mean(&picked.iter().map(|r| r.recall_any_5).collect::<Vec<_>>()),
        mean(&picked.iter().map(|r| r.recall_frac_5).collect::<Vec<_>>()),
    ))
}

fn longmemeval_table(report: &Value) -> String {
    let mut lines =
        vec![format!("{:<28} {:>5} {:>9} {:>6} {:>8}", "type", "n", "recall@5", "hits", "mrr@10")];
    let strict = &report["strict_recall_at_5"];
    lines.push(format!(
        "{:<28} {:>5} {:>9.4} {:>6} {:>8.4}",
        "overall",
        strict["n"].as_u64().unwrap_or(0),
        strict["recall"].as_f64().unwrap_or(0.0),
        strict["hits"].as_u64().unwrap_or(0),
        report["mrr_at_10"].as_f64().unwrap_or(0.0),
    ));
    if let Some(rows) = report["by_type"].as_array() {
        for row in rows {
            lines.push(format!(
                "{:<28} {:>5} {:>9.4} {:>6} {:>8.4}",
                row["type"].as_str().unwrap_or("?"),
                row["n"].as_u64().unwrap_or(0),
                row["recall_at_5"].as_f64().unwrap_or(0.0),
                row["hits_at_5"].as_u64().unwrap_or(0),
                row["mrr_at_10"].as_f64().unwrap_or(0.0),
            ));
        }
    }
    lines.push(format!(
        "as_of accuracy (temporal strict recall@5): {} (n={})",
        report["as_of_accuracy"]["recall_at_5"].as_f64().unwrap_or(0.0),
        report["as_of_accuracy"]["n"].as_u64().unwrap_or(0),
    ));
    lines.push(format!(
        "older non-evidence share (knowledge-update, not the design's stale share): {} ({}/{})",
        report["older_non_evidence_share"]["share"].as_f64().unwrap_or(0.0),
        report["older_non_evidence_share"]["older"].as_u64().unwrap_or(0),
        report["older_non_evidence_share"]["hits"].as_u64().unwrap_or(0),
    ));
    lines.push(format!(
        "search p95: {} ms (n={})",
        report["latency_ms"]["p95"].as_f64().unwrap_or(0.0),
        report["latency_ms"]["n"].as_u64().unwrap_or(0),
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_date_matches_the_predecessor() {
        assert_eq!(parse_session_date("2023/05/20 (Sat) 02:21").unwrap(), "2023-05-20T02:21:00+00:00");
    }

    #[test]
    fn strict_recall_needs_every_evidence_session() {
        let ranked = ["x", "a", "y", "z", "w", "b"].map(str::to_string).to_vec();
        let s = score_sessions(&ranked, &["a".into(), "b".into()]).unwrap();
        assert_eq!(s.recall_all_5, 0.0);
        assert_eq!(s.recall_any_5, 1.0);
        assert_eq!(s.recall_frac_5, 0.5);
        assert_eq!(s.mrr, 0.5);
        let ranked = ["a", "a", "a", "a", "a", "b"].map(str::to_string).to_vec();
        let s = score_sessions(&ranked, &["a".into(), "b".into()]).unwrap();
        assert_eq!(s.recall_all_5, 0.0);
        assert_eq!(s.mrr, 1.0);
    }

    #[test]
    fn long_note_answer_is_past_the_embedding_window() {
        let corpus = parse_corpus(CORPUS).unwrap();
        let note = corpus.notes.iter().find(|n| n.key == "long-note").unwrap();
        let at = note.content.find("violet-orchid-88").unwrap();
        assert!(at > 4096, "{at}");
        assert!(at > note.content.chars().count() * 2 / 3);
    }

    /// Lowercased alphanumeric words, as FTS5's unicode61 tokenizer splits them.
    fn words(text: &str) -> Vec<String> {
        text.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(str::to_lowercase).collect()
    }

    /// Two words match when equal or when they share a five-letter stem
    /// (`archives` / `archive`), so a stem-only negative still counts.
    fn shares_a_term(query: &str, note: &str) -> bool {
        let stem = |w: &str| w.chars().take(5).collect::<String>();
        let note_words = words(note);
        words(query).iter().any(|q| note_words.iter().any(|n| n == q || (q.len() >= 5 && stem(n) == stem(q))))
    }

    #[test]
    fn fixture_negatives_share_their_query_terms() {
        let corpus = parse_corpus(CORPUS).unwrap();
        let text = |key: &str| {
            let n = corpus.notes.iter().find(|n| n.key == key).unwrap();
            format!("{} {}", n.title, n.content)
        };
        let mut negatives = 0;
        for q in &corpus.queries {
            for key in q.must_not.iter().chain(&q.outranked) {
                negatives += 1;
                assert!(shares_a_term(&q.query, &text(key)), "{}: negative {key} shares no term", q.id);
            }
        }
        assert!(negatives >= 5, "{negatives}");
        // A stem-only query: no query word appears verbatim in its must note.
        let q = corpus.queries.iter().find(|q| q.id == "para-stem").unwrap();
        let must = words(&text(&q.must[0]));
        assert!(words(&q.query).iter().all(|w| !must.contains(w)), "{}", q.query);
    }

    /// `exact-noise` and `long-noise` guard phrase matching. A single-token
    /// query is one phrase with no OR fallback, so they are never returned
    /// while phrases hold. Each holds every word of its query, so a word-bag
    /// match would return it and fail the class.
    #[test]
    fn phrase_negatives_hold_every_query_word() {
        let corpus = parse_corpus(CORPUS).unwrap();
        let mut checked = 0;
        for q in corpus.queries.iter().filter(|q| q.query.split_whitespace().count() == 1) {
            for key in &q.must_not {
                let n = corpus.notes.iter().find(|n| &n.key == key).unwrap();
                let have = words(&format!("{} {}", n.title, n.content));
                for w in words(&q.query) {
                    assert!(have.contains(&w), "{}: {key} lacks {w:?}", q.id);
                }
                checked += 1;
            }
        }
        assert!(checked >= 2, "{checked}");
    }

    fn reasons(report: &Value) -> Vec<String> {
        report["floor"]["failures"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["reason"].as_str().map(str::to_string))
            .collect()
    }

    #[tokio::test]
    async fn fixture_queries_remove_their_database_copies() {
        let scratch = Scratch::new("fixture-test").unwrap();
        let report = run_fixture_with(CORPUS, FLOOR, &scratch).await.unwrap();
        assert_eq!(report["floor"]["ok"], json!(true), "{report}");
        let left: Vec<String> = std::fs::read_dir(&scratch.dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, ["corpus"]);
    }

    #[tokio::test]
    async fn a_floor_n_that_differs_from_the_corpus_fails_the_floor() {
        let mut floor: Value = serde_json::from_str(FLOOR).unwrap();
        for row in floor["classes"].as_array_mut().unwrap() {
            if row["class"] == "temporal" {
                row["n"] = json!(4);
            }
        }
        let scratch = Scratch::new("fixture-test").unwrap();
        let report = run_fixture_with(CORPUS, &floor.to_string(), &scratch).await.unwrap();
        assert_eq!(report["floor"]["ok"], json!(false));
        assert_eq!(reasons(&report), ["bench/floor.json records n=4 but the corpus has 3 queries"]);
    }

    #[tokio::test]
    async fn an_outranked_note_that_is_not_retrieved_fails_the_floor() {
        let mut corpus: Value = serde_json::from_str(CORPUS).unwrap();
        for q in corpus["queries"].as_array_mut().unwrap() {
            if q["id"] == "exact-title" {
                q["outranked"].as_array_mut().unwrap().push(json!("para-auto"));
            }
        }
        let scratch = Scratch::new("fixture-test").unwrap();
        let report = run_fixture_with(&corpus.to_string(), FLOOR, &scratch).await.unwrap();
        assert_eq!(report["floor"]["ok"], json!(false));
        assert_eq!(
            reasons(&report),
            ["outranked note para-auto was not retrieved, so it no longer tests ranking"]
        );
        // The query itself still scores: only the vacuity check fails.
        assert_eq!(report["classes"][0]["recall_at_5"], json!(1.0));
    }

    #[test]
    fn an_outranked_note_above_a_must_note_fails_recall() {
        let s = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let (must, none) = (s(&["m"]), s(&[]));
        assert_eq!(score_fixture(&s(&["m", "o"]), &must, &none, &s(&["o"])), (1.0, 1.0));
        assert_eq!(score_fixture(&s(&["o", "m"]), &must, &none, &s(&["o"])), (0.0, 0.5));
        assert_eq!(score_fixture(&s(&["m"]), &must, &none, &s(&["o"])), (1.0, 1.0));
        assert_eq!(score_fixture(&s(&["m", "x"]), &must, &s(&["x"]), &none), (0.0, 1.0));
    }

    #[test]
    fn floor_records_n_for_every_class() {
        let corpus = parse_corpus(CORPUS).unwrap();
        let floor = parse_floor(FLOOR).unwrap();
        for f in &floor.classes {
            let n = corpus.queries.iter().filter(|q| q.class == f.class).count();
            assert_eq!(f.n, n, "{}", f.class);
        }
        let missing_n = r#"{"k": 5, "classes": [{"class": "x", "recall_at_5": 1.0, "mrr": 1.0}]}"#;
        assert!(parse_floor(missing_n).is_err());
    }

    #[test]
    fn scratch_dirs_are_unique_and_removed() {
        let (a, b) = (Scratch::new("t").unwrap(), Scratch::new("t").unwrap());
        assert_ne!(a.dir, b.dir);
        let kept = a.dir.clone();
        drop(a);
        assert!(!kept.exists());
    }

    fn question(id: &str, sessions: usize) -> LmeQuestion {
        // Same date and same text: every session ties on score and title.
        let turns =
            || vec![LmeTurn { role: "user".into(), content: "I repotted the fern on the balcony.".into() }];
        LmeQuestion {
            question_id: id.into(),
            question_type: "knowledge-update".into(),
            question: "Where is the fern?".into(),
            question_date: None,
            answer_session_ids: vec!["s3".into()],
            haystack_session_ids: (0..sessions).map(|i| format!("s{i}")).collect(),
            haystack_dates: vec!["2023/05/20 (Sat) 02:21".into(); sessions],
            haystack_sessions: (0..sessions).map(|_| turns()).collect(),
        }
    }

    #[tokio::test]
    async fn longmemeval_ties_follow_session_order_and_leave_no_files() {
        let scratch = Scratch::new("lme-test").unwrap();
        let cfg = bench_config(&scratch.dir);
        let q = question("tie/1", 8);
        let first = score_question(&q, &scratch, &cfg, false).await.unwrap();
        let again = score_question(&q, &scratch, &cfg, false).await.unwrap();
        let want: Vec<String> = (0..8).map(|i| format!("s{i}")).collect();
        assert_eq!(first.row.ranked, want);
        assert_eq!(again.row.ranked, want);
        // The question's database, -wal and -shm are gone, not left for exit.
        let left: Vec<_> = std::fs::read_dir(&scratch.dir).unwrap().collect();
        assert!(left.is_empty(), "{left:?}");
        // Older non-evidence: s0-s2 and s4 are not evidence and none predates s3.
        assert_eq!((first.older, first.older_seen), (0, 5));
    }

    #[test]
    fn ids_select_answerable_questions_in_file_order() {
        let qs = vec![question("a", 1), question("b_abs", 1), question("c", 1), question("d", 1)];
        let (all, how) = select(&qs, None, None).unwrap();
        assert_eq!((all.len(), how), (3, "full"));
        let ids = vec!["d".to_string(), "a".to_string()];
        let (picked, how) = select(&qs, None, Some(&ids)).unwrap();
        let got: Vec<&str> = picked.iter().map(|q| q.question_id.as_str()).collect();
        assert_eq!((got, how), (vec!["a", "d"], "ids"));
        let (picked, how) = select(&qs, Some(1), Some(&ids)).unwrap();
        assert_eq!((picked.len(), how), (1, "ids+limit"));
        assert!(select(&qs, None, Some(&["b_abs".to_string()])).is_err());
        assert!(select(&qs, None, Some(&["zz".to_string()])).is_err());
        assert!(select(&qs, None, Some(&["a".to_string(), "a".to_string()])).is_err());
    }

    #[test]
    fn session_render_hides_the_session_id() {
        let turns = vec![LmeTurn { role: "user".into(), content: " hi ".into() }];
        let (title, body) = render_session("2023/05/20 (Sat) 02:21", &turns);
        assert_eq!(title, "Conversation on 2023/05/20 (Sat) 02:21");
        assert_eq!(body, "Conversation date: 2023/05/20 (Sat) 02:21\n\nuser: hi");
        assert!(!body.contains("answer_"));
    }

    struct BenchTestEmbedder {
        model: &'static str,
        revision: &'static str,
        fail: bool,
    }

    impl crate::embed::Embedder for BenchTestEmbedder {
        fn model(&self) -> &str {
            self.model
        }

        fn backend(&self) -> &str {
            "local"
        }

        fn revision(&self) -> &str {
            self.revision
        }

        fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, crate::embed::EmbedError> {
            if self.fail {
                return Err(crate::embed::EmbedError::runtime("simulated corrupt local model"));
            }
            // Inspect only the first 2,048 chars of each input, matching the
            // ~512-token single-vector window where long tails are truncated
            // while chunking surfaces tail chunks inside the window.
            Ok(texts
                .iter()
                .map(|t| {
                    let head: String = t.chars().take(2048).collect();
                    if head.contains("tail-beacon-marker") || head.contains("celestial lighthouse") {
                        vec![1.0, 0.0]
                    } else {
                        vec![0.0, 1.0]
                    }
                })
                .collect())
        }
    }

    fn hybrid_test_config(home: &Path, model: &'static str, revision: &'static str, fail: bool) -> Config {
        crate::embed::register_embedder(std::sync::Arc::new(BenchTestEmbedder { model, revision, fail }));
        let mut cfg = Config::for_home(home);
        cfg.memory.embedder = "local".into();
        cfg.embed_model = model.into();
        cfg.clock = ua_core::time::Clock::fixed(BENCH_NOW).expect("BENCH_NOW is a valid instant");
        cfg
    }

    #[test]
    fn embed_report_meta_uses_hybrid_config_and_records_chunks_scored() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = hybrid_test_config(dir.path(), "bench-meta-test-model", "ea104dacec62c0de", false);
        assert!(embed_report_meta(&cfg, None, 0).is_none());
        let chunked = embed_report_meta(
            &cfg,
            Some(&EmbedOptions {
                home: dir.path().to_path_buf(),
                model: cfg.embed_model.clone(),
                no_chunks: false,
            }),
            4,
        )
        .unwrap();
        let single = embed_report_meta(
            &cfg,
            Some(&EmbedOptions {
                home: dir.path().to_path_buf(),
                model: cfg.embed_model.clone(),
                no_chunks: true,
            }),
            0,
        )
        .unwrap();
        assert_eq!(chunked["model"], "bench-meta-test-model");
        assert_eq!(chunked["revision"], "ea104dacec62c0de");
        assert_eq!(chunked["identity"], "local:bench-meta-test-model@ea104dacec62c0de");
        assert_eq!(chunked["no_chunks"], json!(false));
        assert_eq!(chunked["chunks_scored"], json!(4));
        assert_eq!(single["no_chunks"], json!(true));
        assert_eq!(single["chunks_scored"], json!(0));
        assert_ne!(chunked, single);
    }

    #[tokio::test]
    async fn no_chunks_drops_memory_chunks_and_changes_retrieval_in_fixture_and_longmemeval() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = hybrid_test_config(dir.path(), "bench-no-chunks-effect", "rev-no-chunks-1", false);
        let padding = "filler prose about ordinary weather and routine schedules. ".repeat(60);
        let long_body = format!("{padding}\n\nConclusion: tail-beacon-marker.");
        assert!(long_body.len() > 3000);

        // 1. Fixture path: chunked finds the tail-only semantic match and records chunks_scored > 0;
        //    --no-chunks deletes memory_chunks (chunks_scored == 0) and misses the tail-only match.
        let mini_corpus = json!({
            "notes": [{
                "key": "long-tail-note",
                "title": "Long log",
                "content": long_body,
                "tags": []
            }],
            "queries": [{
                "id": "tail-semantic",
                "class": "long-document",
                "query": "celestial lighthouse",
                "must": ["long-tail-note"]
            }]
        })
        .to_string();
        let mini_floor = json!({
            "k": 5,
            "classes": [{ "class": "long-document", "n": 1, "recall_at_5": 1.0, "mrr": 1.0 }]
        })
        .to_string();

        let scratch_chunked = Scratch::new("fix-chunked").unwrap();
        let opt_chunked =
            EmbedOptions { home: dir.path().to_path_buf(), model: cfg.embed_model.clone(), no_chunks: false };
        let rep_chunked =
            run_fixture_with_cfg(&mini_corpus, &mini_floor, &scratch_chunked, &cfg, Some(&opt_chunked))
                .await
                .unwrap();
        assert_eq!(rep_chunked["retrieval"]["mode"], "hybrid");
        assert_eq!(
            rep_chunked["retrieval"]["embed"]["identity"],
            "local:bench-no-chunks-effect@rev-no-chunks-1"
        );
        assert_eq!(rep_chunked["retrieval"]["embed"]["no_chunks"], json!(false));
        assert!(
            rep_chunked["retrieval"]["embed"]["chunks_scored"].as_u64().unwrap_or(0) > 0,
            "chunked fixture run must score >0 chunks: {rep_chunked}"
        );
        assert_eq!(rep_chunked["overall"]["recall_at_5"], json!(1.0), "{rep_chunked}");

        let scratch_single = Scratch::new("fix-single").unwrap();
        let opt_single =
            EmbedOptions { home: dir.path().to_path_buf(), model: cfg.embed_model.clone(), no_chunks: true };
        let rep_single =
            run_fixture_with_cfg(&mini_corpus, &mini_floor, &scratch_single, &cfg, Some(&opt_single))
                .await
                .unwrap();
        assert_eq!(rep_single["retrieval"]["mode"], "hybrid");
        assert_eq!(rep_single["retrieval"]["embed"]["no_chunks"], json!(true));
        assert_eq!(
            rep_single["retrieval"]["embed"]["chunks_scored"],
            json!(0),
            "--no-chunks fixture run must drop memory_chunks: {rep_single}"
        );
        assert_eq!(
            rep_single["overall"]["recall_at_5"],
            json!(0.0),
            "--no-chunks must remove tail chunk retrieval effect: {rep_single}"
        );

        // 2. LongMemEval path: same --no-chunks effect on chunks_scored and strict recall@5.
        let lme_q = LmeQuestion {
            question_id: "lme-no-chunks-1".into(),
            question_type: "single-session-user".into(),
            question: "celestial lighthouse".into(),
            question_date: None,
            answer_session_ids: vec!["s0".into()],
            haystack_session_ids: vec!["s0".into()],
            haystack_dates: vec!["2023/05/20 (Sat) 02:21".into()],
            haystack_sessions: vec![vec![LmeTurn { role: "user".into(), content: long_body }]],
        };
        let pin = pin().unwrap();
        let lme_scratch_chunked = Scratch::new("lme-chunked").unwrap();
        let lme_chunked = run_longmemeval_with_cfg(
            &pin,
            "in-memory",
            std::slice::from_ref(&lme_q),
            None,
            None,
            &lme_scratch_chunked,
            &cfg,
            Some(&opt_chunked),
        )
        .await
        .unwrap();
        assert_eq!(lme_chunked["retrieval"]["mode"], "hybrid");
        assert_eq!(lme_chunked["retrieval"]["embed"]["no_chunks"], json!(false));
        assert!(
            lme_chunked["retrieval"]["embed"]["chunks_scored"].as_u64().unwrap_or(0) > 0,
            "chunked LongMemEval run must score >0 chunks: {lme_chunked}"
        );
        assert_eq!(lme_chunked["strict_recall_at_5"]["hits"], json!(1), "{lme_chunked}");

        let lme_scratch_single = Scratch::new("lme-single").unwrap();
        let lme_single = run_longmemeval_with_cfg(
            &pin,
            "in-memory",
            &[lme_q],
            None,
            None,
            &lme_scratch_single,
            &cfg,
            Some(&opt_single),
        )
        .await
        .unwrap();
        assert_eq!(lme_single["retrieval"]["mode"], "hybrid");
        assert_eq!(lme_single["retrieval"]["embed"]["no_chunks"], json!(true));
        assert_eq!(
            lme_single["retrieval"]["embed"]["chunks_scored"],
            json!(0),
            "--no-chunks LongMemEval run must drop memory_chunks: {lme_single}"
        );
        assert_eq!(
            lme_single["strict_recall_at_5"]["hits"],
            json!(0),
            "--no-chunks must remove tail chunk retrieval effect in LongMemEval: {lme_single}"
        );
    }

    #[tokio::test]
    async fn longmemeval_embed_fails_instead_of_silently_falling_back() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = hybrid_test_config(dir.path(), "bench-lme-fallback-guard", "rev-fail-1", true);
        let pin = pin().unwrap();
        let scratch = Scratch::new("lme-fallback").unwrap();
        let qs = vec![question("lme-fb-1", 2)];
        let opt =
            EmbedOptions { home: dir.path().to_path_buf(), model: cfg.embed_model.clone(), no_chunks: false };
        let err = run_longmemeval_with_cfg(&pin, "in-memory", &qs, None, None, &scratch, &cfg, Some(&opt))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--embed requested hybrid retrieval") && msg.contains("lexical_fallback"),
            "LongMemEval --embed must fail fast on lexical fallback, got: {msg}"
        );
    }
}

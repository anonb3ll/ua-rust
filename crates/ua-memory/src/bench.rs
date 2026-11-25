//! Retrieval benchmark over the memory search that ships today.
//!
//! [`Kind::Fixture`] scores the checked-in corpus and compares each class with
//! `bench/floor.json`. [`Kind::LongMemEval`] scores the pinned LongMemEval-S
//! file. Neither path changes ranking. The fixture run is deterministic: note
//! text, `valid_from` and `as_of` are fixed, and ties break on title before
//! the random note id.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Checked-in notes and labelled queries. No network.
    Fixture,
    /// Pinned LongMemEval-S file. Downloaded on demand when `--data` is omitted.
    LongMemEval,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub kind: Kind,
    /// Existing dataset file. Hash-checked. Not downloaded.
    pub data: Option<PathBuf>,
    /// LongMemEval only: score this many answerable questions, in file order.
    pub limit: Option<usize>,
}

impl Options {
    pub fn fixture() -> Self {
        Self { kind: Kind::Fixture, data: None, limit: None }
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
    supersedes: Option<String>,
    contradicts: Vec<String>,
}

struct CorpusQuery {
    id: String,
    class: String,
    query: String,
    as_of: Option<String>,
    must: Vec<String>,
    must_not: Vec<String>,
}

struct FloorFile {
    k: usize,
    classes: Vec<FloorClass>,
}

struct FloorClass {
    class: String,
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
        Kind::Fixture => run_fixture().await,
        Kind::LongMemEval => run_longmemeval(opts.data.as_deref(), opts.limit).await,
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

fn score_fixture(ranked: &[String], must: &[String], must_not: &[String]) -> (f64, f64) {
    let top: Vec<&str> = ranked.iter().take(RECALL_K).map(String::as_str).collect();
    let all = must.iter().all(|m| top.contains(&m.as_str()));
    let clean = must_not.iter().all(|m| !top.contains(&m.as_str()));
    let recall = if all && clean && !must.is_empty() { 1.0 } else { 0.0 };
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
        &["key", "title", "content", "tags", "valid_from", "supersedes", "contradicts"],
        "fixture note",
    )?;
    let key = req_str(obj, "key", "fixture note")?;
    Ok(CorpusNote {
        title: req_str(obj, "title", &key)?,
        content: req_str(obj, "content", &key)?,
        tags: opt_strings(obj, "tags", &key)?,
        valid_from: opt_str(obj, "valid_from", &key)?,
        supersedes: opt_str(obj, "supersedes", &key)?,
        contradicts: opt_strings(obj, "contradicts", &key)?,
        key,
    })
}

fn parse_query(v: &Value) -> UaResult<CorpusQuery> {
    let obj = object(v, "fixture query")?;
    only_keys(obj, &["id", "class", "query", "as_of", "must", "must_not"], "fixture query")?;
    let id = req_str(obj, "id", "fixture query")?;
    Ok(CorpusQuery {
        class: req_str(obj, "class", &id)?,
        query: req_str(obj, "query", &id)?,
        as_of: opt_str(obj, "as_of", &id)?,
        must: req_strings(obj, "must", &id)?,
        must_not: opt_strings(obj, "must_not", &id)?,
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
            only_keys(row, &["class", "recall_at_5", "mrr"], "floor class")?;
            Ok(FloorClass {
                class: req_str(row, "class", "floor class")?,
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
    cfg
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

/// `created_at` is stamped at save time. An `as_of` in the past would then
/// hide every note (`created_at <= as_of`). Move `created_at` back to
/// `valid_from` so temporal queries see the note's own date. Recency already
/// reads `valid_from` when it is set, so this does not change ranking for a
/// query without `as_of`.
async fn backdate_created(db: &Db) -> UaResult<()> {
    db.write_async(|tx| {
        tx.execute("UPDATE memory SET created_at = valid_from WHERE valid_from IS NOT NULL", [])?;
        Ok(())
    })
    .await
}

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> UaResult<Self> {
        let dir = std::env::temp_dir().join(format!("ua-memory-bench-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir)
            .map_err(|e| UaError::internal(format!("create {}: {e}", dir.display())))?;
        Ok(Self { dir })
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
    Ok(ids)
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

async fn run_fixture() -> UaResult<Value> {
    let corpus = parse_corpus(CORPUS)?;
    let floor = parse_floor(FLOOR)?;
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
    }

    let scratch = Scratch::new("fixture")?;
    let cfg = bench_config(&scratch.dir);
    let base = scratch.dir.join("corpus.db");
    let ids = {
        let db = open_db(&base)?;
        let ids = load_fixture(&db, &cfg, &corpus.notes).await?;
        let (busy, _, _) = db.checkpoint_truncate()?;
        if busy {
            return Err(UaError::internal("bench checkpoint was busy; the fixture copy would be partial"));
        }
        ids
    };

    let mut query_rows = Vec::new();
    let mut mode = String::new();
    let mut stale_hits = 0usize;
    let mut shown = 0usize;
    for (i, q) in corpus.queries.iter().enumerate() {
        let path = scratch.dir.join(format!("q{i}.db"));
        std::fs::copy(&base, &path).map_err(|e| UaError::internal(format!("copy fixture database: {e}")))?;
        let db = open_db(&path)?;
        let (ranked, qmode) = search_keys(&db, &cfg, &ids, &q.query, q.as_of.clone()).await?;
        drop(db);
        let _ = std::fs::remove_file(&path);
        if mode.is_empty() {
            mode = qmode.clone();
        } else if mode != qmode {
            mode = "mixed".into();
        }
        let n = ranked.len().min(RECALL_K);
        shown += n;
        stale_hits += ranked.iter().take(n).filter(|id| q.must_not.iter().any(|m| m == *id)).count();
        let (recall, mrr) = score_fixture(&ranked, &q.must, &q.must_not);
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

    let recalls: Vec<f64> = query_rows.iter().map(|r| r["recall_at_5"].as_f64().unwrap_or(0.0)).collect();
    let mrrs: Vec<f64> = query_rows.iter().map(|r| r["mrr"].as_f64().unwrap_or(0.0)).collect();
    Ok(json!({
        "bench": "fixture",
        "build": {"embeddings": crate::EMBEDDINGS_ENABLED},
        "retrieval": {"mode": mode},
        "k": RECALL_K,
        "stale_share": if shown == 0 { 0.0 } else { round4(stale_hits as f64 / shown as f64) },
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
    stale: usize,
    stale_seen: usize,
}

async fn score_question(q: &LmeQuestion, scratch: &Scratch, cfg: &Config) -> UaResult<QuestionRun> {
    if q.haystack_session_ids.len() != q.haystack_dates.len()
        || q.haystack_session_ids.len() != q.haystack_sessions.len()
    {
        return Err(UaError::invalid(format!("question {} has mismatched haystack arrays", q.question_id)));
    }
    let path = scratch.dir.join(format!("{}.db", q.question_id.replace('/', "_")));
    let db = open_db(&path)?;
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
    let mode = hits["retrieval"]["mode"].as_str().unwrap_or("").to_string();
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
        let ranked_as_of = rank_sessions(&again, &session_of);
        let again_score = score_sessions(&ranked_as_of, &q.answer_session_ids)?;
        Some(again_score.recall_all_5)
    } else {
        None
    };

    let (stale, stale_seen) = stale_hits(q, &ranked, &date_of)?;
    drop(db);
    let _ = std::fs::remove_file(&path);
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
        stale,
        stale_seen,
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

fn stale_hits(
    q: &LmeQuestion,
    ranked: &[String],
    date_of: &HashMap<String, String>,
) -> UaResult<(usize, usize)> {
    if q.question_type != "knowledge-update" {
        return Ok((0, 0));
    }
    let evidence: HashSet<&str> = q.answer_session_ids.iter().map(String::as_str).collect();
    let newest = evidence.iter().filter_map(|sid| date_of.get(*sid)).max().cloned();
    let Some(newest) = newest else { return Ok((0, 0)) };
    let mut stale = 0;
    let mut seen = 0;
    for sid in ranked.iter().take(RECALL_K) {
        seen += 1;
        if evidence.contains(sid.as_str()) {
            continue;
        }
        if date_of.get(sid).is_some_and(|d| d.as_str() < newest.as_str()) {
            stale += 1;
        }
    }
    Ok((stale, seen))
}

fn p95(mut xs: Vec<f64>) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((xs.len() as f64) * 0.95).ceil() as usize - 1;
    (xs[idx.min(xs.len() - 1)] * 10.0).round() / 10.0
}

async fn run_longmemeval(data: Option<&Path>, limit: Option<usize>) -> UaResult<Value> {
    let pin = pin()?;
    let path = locate_dataset(data, &pin)?;
    let file =
        std::fs::File::open(&path).map_err(|e| UaError::invalid(format!("read {}: {e}", path.display())))?;
    let raw: Value = serde_json::from_reader(std::io::BufReader::new(file))
        .map_err(|e| UaError::invalid(format!("{} is not JSON: {e}", path.display())))?;
    let questions = parse_questions(&raw)?;
    let total = questions.len();
    let mut chosen: Vec<&LmeQuestion> =
        questions.iter().filter(|q| !q.question_id.ends_with("_abs")).collect();
    let answerable = chosen.len();
    if let Some(n) = limit {
        chosen.truncate(n);
    }
    if chosen.is_empty() {
        return Err(UaError::invalid(format!(
            "{} has no answerable questions. {}",
            path.display(),
            dataset_help(&pin)
        )));
    }

    let scratch = Scratch::new("longmemeval")?;
    let cfg = bench_config(&scratch.dir);
    let mut rows = Vec::new();
    let mut times = Vec::new();
    let mut as_of_hits = Vec::new();
    let mut stale = 0usize;
    let mut stale_seen = 0usize;
    let mut mode = String::new();
    for (i, q) in chosen.iter().enumerate() {
        let run = score_question(q, &scratch, &cfg).await?;
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
        stale += run.stale;
        stale_seen += run.stale_seen;
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
    Ok(json!({
        "bench": "longmemeval-s",
        "build": {"embeddings": crate::EMBEDDINGS_ENABLED},
        "retrieval": {"mode": mode, "search_limit": SEARCH_LIMIT, "granularity": "session"},
        "dataset": {
            "repo": pin.repo,
            "revision": pin.revision,
            "file": pin.file,
            "sha256": pin.sha256,
            "url": dataset_url(&pin),
            "questions": total,
            "answerable": answerable,
            "scored": n,
            "selection": if limit.is_some() { "limit" } else { "full" },
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
        "stale_share": {
            "definition": "share of knowledge-update top-5 hits that are not evidence and predate the newest evidence session",
            "hits": stale_seen,
            "stale": stale,
            "share": if stale_seen == 0 { 0.0 } else { round4(stale as f64 / stale_seen as f64) },
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
        "stale share (knowledge-update): {} ({}/{})",
        report["stale_share"]["share"].as_f64().unwrap_or(0.0),
        report["stale_share"]["stale"].as_u64().unwrap_or(0),
        report["stale_share"]["hits"].as_u64().unwrap_or(0),
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

    #[test]
    fn session_render_hides_the_session_id() {
        let turns = vec![LmeTurn { role: "user".into(), content: " hi ".into() }];
        let (title, body) = render_session("2023/05/20 (Sat) 02:21", &turns);
        assert_eq!(title, "Conversation on 2023/05/20 (Sat) 02:21");
        assert_eq!(body, "Conversation date: 2023/05/20 (Sat) 02:21\n\nuser: hi");
        assert!(!body.contains("answer_"));
    }
}

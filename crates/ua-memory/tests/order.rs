//! Result order of `memory_search`: ties on score and title break on
//! insertion order, and that tie-break leaves every non-tied order alone.

use serde_json::Value;
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_memory::save::SaveRequest;
use ua_memory::search::SearchRequest;
use ua_memory::{save, search};
use ua_store::{Db, ledger};

fn db() -> Db {
    let mut parts: Vec<ua_store::Part> = ua_store::schema::parts(&[ledger::SCHEMA, ledger::META_SCHEMA]);
    parts.push(ua_store::org::STORE_PART.into());
    parts.extend(ua_memory::schema_parts().into_iter().map(ua_store::Part::from));
    parts.extend(ua_memory::org_parts());
    Db::open_in_memory(&parts).unwrap()
}

/// A fixed clock: every note here is saved and searched at the same instant.
fn cfg() -> Config {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.embed_model = "lexical-only-order-test-model".into();
    cfg.clock = ua_core::time::Clock::fixed("2026-03-01T00:00:00+00:00").unwrap();
    cfg
}

fn agent() -> Caller {
    Caller {
        label: "builder-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: false,
        session_key: None,
        transport: Transport::Cli,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

async fn put(db: &Db, cfg: &Config, title: &str, content: &str, valid_from: Option<&str>) -> String {
    let saved = save::save(
        db,
        cfg,
        &agent(),
        SaveRequest {
            content: content.into(),
            title: Some(title.into()),
            valid_from: valid_from.map(str::to_string),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    saved["id"].as_str().unwrap().to_string()
}

async fn ranked(db: &Db, cfg: &Config, query: &str) -> Vec<Value> {
    let hits = search::search(
        db,
        cfg,
        ua_core::DEFAULT_ORG,
        SearchRequest { query: query.into(), limit: Some(50), ..Default::default() },
    )
    .await
    .unwrap();
    hits["results"].as_array().unwrap().clone()
}

/// Twelve notes with the same title, text and date tie on every signal.
/// They come back in the order they were saved, on every run; a random
/// note-id tie-break would pass this with probability 1/12!.
#[tokio::test]
async fn score_and_title_ties_break_on_insertion_order() {
    let (db, cfg) = (db(), cfg());
    let mut saved = Vec::new();
    for _ in 0..12 {
        saved
            .push(put(&db, &cfg, "Conversation on 2023/05/20", "The fern moved to the balcony.", None).await);
    }
    for _ in 0..2 {
        let rows = ranked(&db, &cfg, "fern balcony").await;
        let scores: Vec<f64> = rows.iter().map(|r| r["combined_score"].as_f64().unwrap()).collect();
        assert!(scores.windows(2).all(|p| p[0] == p[1]), "fixture must tie: {scores:?}");
        let ids: Vec<&str> = rows.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(ids, saved.iter().map(String::as_str).collect::<Vec<_>>());
    }
}

/// A fixture with no ties: every combined score differs. Its order is
/// recorded from the ranking before the insertion-order tie-break landed,
/// so this test fails if the tie-break moves any non-tied result.
#[tokio::test]
async fn non_tied_order_is_unchanged_by_the_tie_break() {
    let (db, cfg) = (db(), cfg());
    // Titles sort in a different order from the expected ranking, so a
    // title tie-break cannot produce it by accident.
    let notes = [
        ("a-or-weak", "The orchid shelf is by the window.", None),
        ("b-and-strong", "Amber orchid notes: amber orchid, amber orchid, amber orchid.", None),
        ("c-or-strong", "Orchid orchid orchid: the orchid room.", None),
        ("d-and-weak", "An amber light sits near one orchid in the long north hallway.", None),
        ("e-and-old", "Amber orchid amber orchid.", Some("2025-01-01T00:00:00+00:00")),
        ("f-amber-only", "Amber resin is stored in the shed.", None),
    ];
    for (title, content, from) in notes {
        put(&db, &cfg, title, content, from).await;
    }
    let rows = ranked(&db, &cfg, "amber orchid").await;
    let titles: Vec<&str> = rows.iter().map(|r| r["title"].as_str().unwrap()).collect();
    let scores: Vec<f64> = rows.iter().map(|r| r["combined_score"].as_f64().unwrap()).collect();
    for pair in scores.windows(2) {
        assert!(pair[0] > pair[1], "fixture must have no score ties: {scores:?} {titles:?}");
    }
    assert_eq!(titles, GOLDEN_ORDER, "{scores:?}");
    for (got, want) in scores.iter().zip(GOLDEN_SCORES) {
        assert!((got - want).abs() < 1e-12, "{scores:?}");
    }
}

/// Recorded at 3568b28, before the tie-break change (on the wall clock; the
/// fixed clock leaves them unchanged).
const GOLDEN_ORDER: [&str; 6] =
    ["b-and-strong", "d-and-weak", "c-or-strong", "f-amber-only", "a-or-weak", "e-and-old"];
const GOLDEN_SCORES: [f64; 6] = [
    0.019672131147540985,
    0.019151704397606037,
    0.018903688524590165,
    0.01866330390920555,
    0.018430203676105317,
    0.015327468230694037,
];

/// Search dates recency and the age discount from `cfg.clock`, so a fixed
/// clock gives the same explanation on every day the test runs.
#[tokio::test]
async fn search_reads_the_injected_clock() {
    let (db, mut cfg) = (db(), cfg());
    put(&db, &cfg, "Kiln log", "The kiln reached cone six.", Some("2026-01-01T00:00:00+00:00")).await;
    let explain = |rows: Vec<Value>| rows[0]["explanation"].clone();
    // One half-life (15 days) after valid_from: recency 0.5, no age discount.
    cfg.clock = ua_core::time::Clock::fixed("2026-01-16T00:00:00+00:00").unwrap();
    let e = explain(ranked(&db, &cfg, "kiln").await);
    assert_eq!(e["recency"], 0.5, "{e}");
    assert_eq!(e["prior"], 1.0, "{e}");
    // A year later the age discount (0.5) pulls the prior to its floor.
    cfg.clock = ua_core::time::Clock::fixed("2027-01-16T00:00:00+00:00").unwrap();
    let e = explain(ranked(&db, &cfg, "kiln").await);
    assert_eq!(e["prior"], ua_memory::rank::PRIOR_MIN, "{e}");
}

/// Every text embeds to the same vector, so every note ties on similarity.
struct ConstantEmbedder;

impl ua_memory::Embedder for ConstantEmbedder {
    fn model(&self) -> &str {
        "constant-vector-order-test-model"
    }

    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, ua_memory::EmbedError> {
        Ok(texts.iter().map(|_| vec![0.6, 0.8]).collect())
    }
}

/// The semantic leg keeps its top 50 (`SEMANTIC_TOP_K`). With 55 notes tied
/// on similarity, the cut keeps the first 50 saved, in save order; a random
/// note-id tie-break would keep a random 50.
#[tokio::test]
async fn semantic_ties_break_on_insertion_order() {
    ua_memory::register_embedder(std::sync::Arc::new(ConstantEmbedder));
    let db = db();
    let mut cfg = cfg();
    cfg.embed_model = "constant-vector-order-test-model".into();
    let mut saved = Vec::new();
    for i in 0..55 {
        // Every other note is long enough to be chunked, so ties come from
        // both the single-vector and the chunk scan (max of the two).
        let filler = if i % 2 == 0 { "Filler sentence for chunking. ".repeat(100) } else { String::new() };
        saved.push(put(&db, &cfg, "Same title", &format!("Unrelated text number {i}. {filler}"), None).await);
    }
    // No lexical match: only the semantic leg returns candidates.
    let hits = search::search(
        &db,
        &cfg,
        ua_core::DEFAULT_ORG,
        SearchRequest { query: "zyxwvut".into(), limit: Some(50), ..Default::default() },
    )
    .await
    .unwrap();
    assert_eq!(hits["retrieval"]["mode"], "hybrid", "{}", hits["retrieval"]);
    let ids: Vec<&str> =
        hits["results"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert_eq!(ids, saved[..50].iter().map(String::as_str).collect::<Vec<_>>());
}

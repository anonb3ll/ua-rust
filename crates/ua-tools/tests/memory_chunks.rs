//! Chunked embeddings, staleness filtering, vector identity isolation, and
//! maintenance backfill (docs/memory.md §2, acceptance items 3, 4, 5).
//!
//! Every tool call runs through `builtin_registry().call(..)`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rusqlite::params;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, identity::Transport};
use ua_tools::families::memory::{EmbedError, Embedder, register_embedder, vector_identity};
use ua_tools::{Hub, Registry, builtin_registry};

const CONCEPTS: &[&[&str]] = &[
    &["car", "automobile", "vehicle"],
    &["database", "sqlite", "postgres"],
    &["quokka", "marsupial", "rottnest"],
    &["cobalt", "sapphire", "azure"],
];

fn agent(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some(format!("{label}-session")),
        transport: Transport::Mcp,
        org_id: DEFAULT_ORG.into(),
    }
}

fn hub_with_model(model: &str) -> Hub {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.embed_model = model.into();
    cfg.human_identities = vec!["operator".into()];
    Hub::in_memory(cfg).unwrap()
}

/// Simulates a 512-token (2,048-char) encoder: only the first 2,048 Unicode
/// code points of each input text contribute to its vector, so a fact in the
/// tail of a long note is invisible to the single vector and can only be
/// found through its chunk vectors.
struct TruncatingEmbedder {
    model: String,
    backend: String,
    revision: String,
    fail: Arc<AtomicBool>,
}

impl TruncatingEmbedder {
    fn new(backend: &str, model: &str, revision: &str) -> (Self, Arc<AtomicBool>) {
        let fail = Arc::new(AtomicBool::new(false));
        (
            Self {
                model: model.into(),
                backend: backend.into(),
                revision: revision.into(),
                fail: fail.clone(),
            },
            fail,
        )
    }
}

impl Embedder for TruncatingEmbedder {
    fn model(&self) -> &str {
        &self.model
    }

    fn backend(&self) -> &str {
        &self.backend
    }

    fn revision(&self) -> &str {
        &self.revision
    }

    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(EmbedError::runtime("injected embed failure"));
        }
        Ok(texts
            .iter()
            .map(|text| {
                let prefix: String = text.chars().take(2048).collect();
                let mut v = vec![0f32; CONCEPTS.len() + 1];
                for w in prefix.to_lowercase().split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty())
                {
                    match CONCEPTS.iter().position(|c| c.contains(&w)) {
                        Some(i) => v[i] += 1.0,
                        None => v[CONCEPTS.len()] += 0.01,
                    }
                }
                v
            })
            .collect())
    }
}

struct T {
    hub: Hub,
    reg: Registry,
}

impl T {
    fn new(hub: Hub) -> Self {
        Self { hub, reg: builtin_registry() }
    }

    async fn ok(&self, caller: &Caller, tool: &str, args: Value) -> Value {
        self.reg.call(&self.hub, caller, tool, args).await.unwrap_or_else(|e| panic!("{tool} failed: {e}"))
    }

    fn count(&self, sql: &str) -> i64 {
        self.hub.db().read(|c| Ok(c.query_row(sql, [], |r| r.get(0))?)).unwrap()
    }
}

/// Acceptance item 3: a fact only in the last third of a 6,000-char note is
/// recalled through its chunks, a >16-chunk note caps at 16 chunks, and a
/// long note's semantic score is `max(single, best chunk)`.
#[tokio::test]
async fn long_document_tail_recall_max_chunks_and_max_score() {
    let model = "chunks-long-doc-model";
    let (emb, _) = TruncatingEmbedder::new("local", model, "rev-1");
    register_embedder(Arc::new(emb));
    let t = T::new(hub_with_model(model));
    let b1 = agent("builder-1");

    // 6,000-char note: opening is filler ("lorem "), last third holds "quokka".
    let filler = "lorem ".repeat(750); // 4,500 chars
    let tail = format!("{} quokka quokka quokka {}", "ipsum ".repeat(100), "dolor ".repeat(150));
    let long_content = format!("{filler}{tail}");
    assert!(long_content.chars().count() >= 6000);

    let long_id = t.ok(&b1, "memory_save", json!({ "title": "Long report", "content": long_content })).await
        ["id"]
        .as_str()
        .unwrap()
        .to_string();

    let chunk_rows = t.count(&format!("SELECT COUNT(*) FROM memory_chunks WHERE note_id = '{long_id}'"));
    assert!((4..=16).contains(&chunk_rows), "expected 4..=16 chunks, got {chunk_rows}");

    // Query with synonym "marsupial" (zero lexical overlap with "quokka").
    // The single vector only saw the first 2,048 chars (pure "lorem "), so
    // only a tail chunk can match.
    let res = t.ok(&b1, "memory_search", json!({ "query": "marsupial" })).await;
    assert_eq!(res["retrieval"]["mode"], "hybrid");
    assert_eq!(res["retrieval"]["lexical"]["matched_count"], 0);
    assert_eq!(res["retrieval"]["semantic"]["matched_count"], 1);
    let results = res["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["id"], long_id);
    assert!(results[0]["similarity"].as_f64().unwrap() > 0.7, "{res}");

    // Verify score is max(single, best chunk) in the other direction too:
    // put "car" only in the title/opening and verify single-vector high score wins
    // even when later chunks don't contain "car", AND verify a huge >25,000-char
    // note caps at exactly 16 chunks.
    let huge_content = format!("car car car {}", "zebra ".repeat(5000)); // >30,000 chars
    let huge_id =
        t.ok(&b1, "memory_save", json!({ "title": "Huge note", "content": huge_content })).await["id"]
            .as_str()
            .unwrap()
            .to_string();
    assert_eq!(
        t.count(&format!("SELECT COUNT(*) FROM memory_chunks WHERE note_id = '{huge_id}'")),
        16,
        "notes above 16 chunks embed only their first 16"
    );
    let car_hit = t.ok(&b1, "memory_search", json!({ "query": "automobile" })).await;
    assert_eq!(car_hit["results"][0]["id"], huge_id);
    assert!(car_hit["results"][0]["similarity"].as_f64().unwrap() > 0.7, "{car_hit}");

    // Shrinking a long note below 2,048 chars removes its old chunk rows.
    t.ok(&b1, "memory_save", json!({ "id": long_id, "content": "Short replacement note." })).await;
    assert_eq!(
        t.count(&format!("SELECT COUNT(*) FROM memory_chunks WHERE note_id = '{long_id}'")),
        0,
        "shrinking below threshold cleans up old chunks"
    );
}

/// Acceptance item 4: after an edit whose re-embed fails, the old vector and
/// chunks are NOT scored; the maintenance pass backfills them in batches of 8.
#[tokio::test]
async fn failed_reembed_is_unscored_until_maintenance_backfill_in_batches_of_8() {
    let model = "chunks-staleness-backfill-model";
    let (emb, fail_flag) = TruncatingEmbedder::new("local", model, "rev-1");
    register_embedder(Arc::new(emb));
    let t = T::new(hub_with_model(model));
    let b1 = agent("builder-1");

    // Save a long note about "car" (opening) and "quokka" (tail).
    let filler = "lorem ".repeat(700);
    let id = t
        .ok(
            &b1,
            "memory_save",
            json!({ "title": "Car report", "content": format!("car car car {filler} quokka quokka") }),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Baseline: both opening ("automobile") and tail ("marsupial") match.
    assert_eq!(t.ok(&b1, "memory_search", json!({ "query": "automobile" })).await["results"][0]["id"], id);
    assert_eq!(t.ok(&b1, "memory_search", json!({ "query": "marsupial" })).await["results"][0]["id"], id);

    // Inject embed failure and edit the note to talk about "cobalt" instead.
    fail_flag.store(true, Ordering::SeqCst);
    t.ok(
        &b1,
        "memory_save",
        json!({ "id": id, "title": "Mineral report", "content": format!("{filler} cobalt cobalt cobalt") }),
    )
    .await;

    // Re-enable embedder for query embedding only? Keep fail=false while searching
    // BEFORE backfill: the stored vectors still hold the old content_sha, so
    // neither the old single vector ("automobile") nor old chunks ("marsupial")
    // may score!
    fail_flag.store(false, Ordering::SeqCst);
    let stale_car = t.ok(&b1, "memory_search", json!({ "query": "automobile" })).await;
    assert_eq!(
        stale_car["retrieval"]["semantic"]["matched_count"], 0,
        "stale single vector must not score: {stale_car}"
    );
    let stale_tail = t.ok(&b1, "memory_search", json!({ "query": "marsupial" })).await;
    assert_eq!(
        stale_tail["retrieval"]["semantic"]["matched_count"], 0,
        "stale chunk vector must not score: {stale_tail}"
    );
    let new_before = t.ok(&b1, "memory_search", json!({ "query": "sapphire" })).await;
    assert_eq!(
        new_before["retrieval"]["semantic"]["matched_count"], 0,
        "unembedded new content not scored yet"
    );

    // Create 17 more notes while embedder is failing so we have 18 stale/missing
    // notes in total -> backfill must process them in 3 batches (8 + 8 + 2).
    fail_flag.store(true, Ordering::SeqCst);
    for i in 0..17 {
        t.ok(
            &b1,
            "memory_save",
            json!({ "title": format!("Bulk {i}"), "content": format!("note body {i} database sqlite") }),
        )
        .await;
    }

    // Run maintenance pass with embedder healthy again.
    fail_flag.store(false, Ordering::SeqCst);
    let maint = t.ok(&b1, "recall_maintenance", json!({})).await;
    assert_eq!(maint["embeddings"]["available"], true, "{maint}");
    assert_eq!(maint["embeddings"]["notes_embedded"], 18, "{maint}");
    assert_eq!(maint["embeddings"]["batches"], 3, "18 notes = batches of 8 + 8 + 2: {maint}");
    assert_eq!(maint["embeddings"]["failed"], 0, "{maint}");

    // Now the edited long note is found via its new tail ("sapphire" -> "cobalt"),
    // and a second maintenance pass is a clean no-op.
    let after = t.ok(&b1, "memory_search", json!({ "query": "sapphire" })).await;
    assert_eq!(after["results"][0]["id"], id, "{after}");
    let maint2 = t.ok(&b1, "recall_maintenance", json!({})).await;
    assert_eq!(maint2["embeddings"]["notes_embedded"], 0, "second backfill must be idempotent: {maint2}");
    assert_eq!(maint2["embeddings"]["batches"], 0, "{maint2}");
}

/// Acceptance item 4 (imported vectors): vectors imported from Python carry
/// `model = "import:..."` and `content_sha = ""`, are never scored as-is, and
/// are re-embedded by the maintenance pass.
#[tokio::test]
async fn imported_vectors_are_never_scored_as_is_and_are_reembedded_by_backfill() {
    let model = "chunks-import-stale-model";
    let (emb, fail_flag) = TruncatingEmbedder::new("local", model, "rev-1");
    register_embedder(Arc::new(emb));
    let t = T::new(hub_with_model(model));
    let b1 = agent("builder-1");

    // Save note while embedder fails, then plant Python-imported stale rows.
    fail_flag.store(true, Ordering::SeqCst);
    let id = t
        .ok(&b1, "memory_save", json!({ "title": "Imported", "content": "The car is in the shed." }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let unit_car: Vec<u8> = [1.0f32, 0.0, 0.0, 0.0, 0.0].iter().flat_map(|f| f.to_le_bytes()).collect();
    t.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO memory_embeddings (org_id, note_id, model, dim, embedding, content_sha, updated_at) \
                 VALUES ('default', ?1, 'import:bge-small', 5, ?2, '', '2026-01-01T00:00:00+00:00')",
                params![&id, &unit_car],
            )?;
            tx.execute(
                "INSERT INTO memory_chunks (org_id, note_id, idx, model, dim, embedding, content_sha) \
                 VALUES ('default', ?1, 0, 'import:bge-small', 5, ?2, '')",
                params![&id, &unit_car],
            )?;
            Ok(())
        })
        .unwrap();

    fail_flag.store(false, Ordering::SeqCst);
    // Before backfill: imported rows must NOT score.
    let before = t.ok(&b1, "memory_search", json!({ "query": "automobile" })).await;
    assert_eq!(
        before["retrieval"]["semantic"]["matched_count"], 0,
        "imported vectors must not score: {before}"
    );

    // Backfill re-embeds under the active vector identity and cleans up the
    // stale chunk row (since this note is short).
    let maint = t.ok(&b1, "recall_maintenance", json!({})).await;
    assert_eq!(maint["embeddings"]["notes_embedded"], 1, "{maint}");

    let stored_model: String = t
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT model FROM memory_embeddings WHERE note_id = ?1", [&id], |r| r.get(0))?)
        })
        .unwrap();
    assert_eq!(stored_model, vector_identity("local", model, "rev-1"));
    assert_eq!(
        t.count(&format!("SELECT COUNT(*) FROM memory_chunks WHERE note_id = '{id}'")),
        0,
        "stale imported chunk on short note removed by backfill"
    );

    let after = t.ok(&b1, "memory_search", json!({ "query": "automobile" })).await;
    assert_eq!(after["results"][0]["id"], id, "{after}");
}

/// Acceptance item 5: vectors from two backends with the same model name are
/// never compared, and changing identity (backend or revision) marks vectors
/// stale so backfill re-embeds them.
#[tokio::test]
async fn vector_identity_isolates_backends_with_same_model_name_and_reembeds_on_change() {
    let shared_model = "chunks-shared-model-identity-test";
    let (local_emb, _) = TruncatingEmbedder::new("local", shared_model, "rev-1");
    register_embedder(Arc::new(local_emb));
    let t = T::new(hub_with_model(shared_model));
    let b1 = agent("builder-1");

    let id = t
        .ok(&b1, "memory_save", json!({ "title": "Storage", "content": "The sqlite database file." }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();

    let stored: String = t
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT model FROM memory_embeddings WHERE note_id = ?1", [&id], |r| r.get(0))?)
        })
        .unwrap();
    assert_eq!(stored, vector_identity("local", shared_model, "rev-1"));

    // Switch backend to `ollama` with the EXACT SAME model name and revision.
    let (ollama_emb, _) = TruncatingEmbedder::new("ollama", shared_model, "rev-1");
    register_embedder(Arc::new(ollama_emb));

    // Local backend's vector MUST NOT be scored by the ollama backend.
    let cross_backend = t.ok(&b1, "memory_search", json!({ "query": "postgres" })).await;
    assert_eq!(
        cross_backend["retrieval"]["semantic"]["matched_count"], 0,
        "two backends with the same model name must never compare vectors: {cross_backend}"
    );

    // Backfill re-embeds under `ollama:<model>@rev-1`.
    let maint = t.ok(&b1, "recall_maintenance", json!({})).await;
    assert_eq!(maint["embeddings"]["notes_embedded"], 1, "{maint}");
    let after_backend: String = t
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT model FROM memory_embeddings WHERE note_id = ?1", [&id], |r| r.get(0))?)
        })
        .unwrap();
    assert_eq!(after_backend, vector_identity("ollama", shared_model, "rev-1"));
    assert_eq!(t.ok(&b1, "memory_search", json!({ "query": "postgres" })).await["results"][0]["id"], id);

    // Bump revision on the same backend (`rev-1` -> `rev-2`): old vector is stale.
    let (ollama_v2, _) = TruncatingEmbedder::new("ollama", shared_model, "rev-2");
    register_embedder(Arc::new(ollama_v2));
    let after_bump = t.ok(&b1, "memory_search", json!({ "query": "postgres" })).await;
    assert_eq!(after_bump["retrieval"]["semantic"]["matched_count"], 0, "old revision must not score");

    let maint2 = t.ok(&b1, "recall_maintenance", json!({})).await;
    assert_eq!(maint2["embeddings"]["notes_embedded"], 1, "{maint2}");
    let after_rev: String = t
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT model FROM memory_embeddings WHERE note_id = ?1", [&id], |r| r.get(0))?)
        })
        .unwrap();
    assert_eq!(after_rev, vector_identity("ollama", shared_model, "rev-2"));
    assert_eq!(t.ok(&b1, "memory_search", json!({ "query": "postgres" })).await["results"][0]["id"], id);
}

/// Acceptance item 3: verify exact `max(single-vector cosine, best chunk cosine)`
/// in both directions (chunk > single and single > chunk), with the note kept
/// as the returned unit and semantic staying one leg.
#[tokio::test]
async fn semantic_score_is_exact_max_of_single_and_best_chunk() {
    let model = "chunks-exact-max-score-model";
    let (emb, _) = TruncatingEmbedder::new("local", model, "rev-1");
    let identity = emb.identity();
    register_embedder(Arc::new(emb));
    let t = T::new(hub_with_model(model));
    let b1 = agent("builder-1");

    let note_a =
        t.ok(&b1, "memory_save", json!({ "title": "Alpha", "content": "Unrelated body alpha." })).await["id"]
            .as_str()
            .unwrap()
            .to_string();
    let note_b =
        t.ok(&b1, "memory_save", json!({ "title": "Beta", "content": "Unrelated body beta." })).await["id"]
            .as_str()
            .unwrap()
            .to_string();

    let vec_bytes = |cos: f32| -> Vec<u8> {
        let sin = (1.0 - cos * cos).sqrt();
        [cos, sin, 0.0f32, 0.0, 0.0].iter().flat_map(|f| f.to_le_bytes()).collect()
    };

    t.hub
        .db()
        .write(|tx| {
            let sha_a: String = tx.query_row(
                "SELECT content_sha FROM memory_embeddings WHERE note_id = ?1",
                [&note_a],
                |r| r.get(0),
            )?;
            let sha_b: String = tx.query_row(
                "SELECT content_sha FROM memory_embeddings WHERE note_id = ?1",
                [&note_b],
                |r| r.get(0),
            )?;
            tx.execute(
                "UPDATE memory_embeddings SET embedding = ?1 WHERE note_id = ?2",
                params![vec_bytes(0.5), &note_a],
            )?;
            tx.execute(
                "INSERT INTO memory_chunks (org_id, note_id, idx, model, dim, embedding, content_sha) VALUES \
                 ('default', ?1, 0, ?2, 5, ?3, ?4), ('default', ?1, 1, ?2, 5, ?5, ?4)",
                params![&note_a, &identity, vec_bytes(0.2), &sha_a, vec_bytes(0.9)],
            )?;

            tx.execute(
                "UPDATE memory_embeddings SET embedding = ?1 WHERE note_id = ?2",
                params![vec_bytes(0.85), &note_b],
            )?;
            tx.execute(
                "INSERT INTO memory_chunks (org_id, note_id, idx, model, dim, embedding, content_sha) VALUES \
                 ('default', ?1, 0, ?2, 5, ?3, ?4), ('default', ?1, 1, ?2, 5, ?5, ?4)",
                params![&note_b, &identity, vec_bytes(0.3), &sha_b, vec_bytes(0.4)],
            )?;
            Ok(())
        })
        .unwrap();

    let res = t.ok(&b1, "memory_search", json!({ "query": "automobile" })).await;
    assert_eq!(res["retrieval"]["semantic"]["matched_count"], 2, "{res}");
    let results = res["results"].as_array().unwrap();
    assert_eq!(results.len(), 2, "note stays the returned unit (one result per note): {res}");
    assert_eq!(results[0]["id"], note_a, "0.90 chunk score beats 0.85 single score: {res}");
    assert_eq!(results[1]["id"], note_b);
    let sim_a = results[0]["similarity"].as_f64().unwrap();
    let sim_b = results[1]["similarity"].as_f64().unwrap();
    assert!((sim_a - 0.9).abs() < 1e-4, "expected 0.9, got {sim_a}");
    assert!((sim_b - 0.85).abs() < 1e-4, "expected 0.85, got {sim_b}");
}

/// Maintenance backfill runs strictly per organization: a backfill in one org
/// never reads, embeds or writes vectors for another organization's notes.
#[tokio::test]
async fn backfill_is_strictly_per_org_and_never_touches_another_orgs_notes() {
    let model = "chunks-per-org-backfill-model";
    let (emb, fail_flag) = TruncatingEmbedder::new("local", model, "rev-1");
    register_embedder(Arc::new(emb));
    let t = T::new(hub_with_model(model));

    t.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                 VALUES ('org-b', 'org-b', 'Org B', '[\"developer\",\"operator\"]', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

    let a_caller = agent(DEFAULT_ORG);
    let b_caller = Caller { org_id: "org-b".into(), ..agent("builder-b") };

    // Create unembedded long notes in both orgs while embedder is failing.
    fail_flag.store(true, Ordering::SeqCst);
    let filler = "lorem ".repeat(650);
    let note_a = t
        .ok(
            &a_caller,
            "memory_save",
            json!({ "title": "Org A note", "content": format!("{filler} car car car") }),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let note_b = t
        .ok(
            &b_caller,
            "memory_save",
            json!({ "title": "Org B note", "content": format!("{filler} quokka quokka quokka") }),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();

    assert_eq!(t.count("SELECT COUNT(*) FROM memory_embeddings"), 0);
    assert_eq!(t.count("SELECT COUNT(*) FROM memory_chunks"), 0);

    // Backfill as default org: only Org A's note is embedded; Org B stays untouched.
    fail_flag.store(false, Ordering::SeqCst);
    let maint_a = t.ok(&a_caller, "recall_maintenance", json!({})).await;
    assert_eq!(maint_a["embeddings"]["notes_embedded"], 1, "{maint_a}");
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM memory_embeddings WHERE note_id = '{note_a}' AND org_id = 'default'"
        )),
        1
    );
    assert!(
        t.count(&format!(
            "SELECT COUNT(*) FROM memory_chunks WHERE note_id = '{note_a}' AND org_id = 'default'"
        )) >= 2
    );
    assert_eq!(
        t.count(&format!("SELECT COUNT(*) FROM memory_embeddings WHERE note_id = '{note_b}'")),
        0,
        "org-a backfill must never embed org-b notes"
    );
    assert_eq!(
        t.count(&format!("SELECT COUNT(*) FROM memory_chunks WHERE note_id = '{note_b}'")),
        0,
        "org-a backfill must never chunk org-b notes"
    );

    // Org B's own backfill embeds Org B's note without touching Org A.
    let maint_b = t.ok(&b_caller, "recall_maintenance", json!({})).await;
    assert_eq!(maint_b["embeddings"]["notes_embedded"], 1, "{maint_b}");
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM memory_embeddings WHERE note_id = '{note_b}' AND org_id = 'org-b'"
        )),
        1
    );
    assert!(
        t.count(&format!(
            "SELECT COUNT(*) FROM memory_chunks WHERE note_id = '{note_b}' AND org_id = 'org-b'"
        )) >= 2
    );
    let hit_b = t.ok(&b_caller, "memory_search", json!({ "query": "marsupial" })).await;
    assert_eq!(hit_b["results"][0]["id"], note_b, "{hit_b}");
}

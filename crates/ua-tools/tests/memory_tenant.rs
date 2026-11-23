//! `memory`, `memory_versions` and `memory_embeddings` are tenant data
//! (`docs/organization.md`, Scoping per subsystem): `organization.v1.memory`
//! gives them `org_id` and the organization triggers; `memory.v2.org_scope`
//! recreates the version-capture trigger so a history row names its note's
//! organization, keeps a version, a vector and a supersede pointer in their
//! note's organization, and adds the indexes led by `org_id`. No key needed a
//! rebuild (a note id is hub-generated, the version and vector keys are led
//! by it), and the upgrade moves and drops nothing.
//!
//! A second organization is created at the storage level, as no tool creates
//! one yet, and its callers are built by hand. Organization-B notes are
//! written through the tools with an organization-B caller; only the legacy
//! rows of the upgrade test and the defence-in-depth rows are seeded by SQL.
//! Every value is fake.

use std::sync::Arc;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::families::memory::{EmbedError, Embedder, register_embedder};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 2] = ["organization.v1.memory", "memory.v2.org_scope"];
const TABLES: [&str; 3] = ["memory", "memory_versions", "memory_embeddings"];
/// A note id no row has, to compare another organization's answers with.
const ABSENT: &str = "abcdef012345";

/// Organization-B text that must never reach the default organization's
/// ledger, in a payload or as an originator.
const B_AGENT: &str = "kestrel-nightshift-fake";
const B_TITLE: &str = "Falcon fake-title-not-real";
const B_TITLE_EDIT: &str = "Falcon fake-retitle-not-real";
const B_TAG: &str = "falcon-fake-tag-not-real";
const B_BODY: &str = "Wombat cache falcon fake-body-not-real";

const MODEL: &str = "tenant-concepts";

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().filter(|p| !PARTS.contains(&p.name)).collect()
}

fn add_org(db: &ua_store::Db, id: &str) {
    db.write(|tx| {
        tx.execute(
            "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
             VALUES (?1, ?1, 'Org B', '[\"developer\",\"operator\"]', '2026-01-01T00:00:00+00:00')",
            [id],
        )?;
        Ok(())
    })
    .unwrap();
}

fn agent_named(label: &str, org: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some(format!("{label}-s")),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn agent(org: &str) -> Caller {
    agent_named("builder-1", org)
}

/// The configured human identity, in organization `org`.
fn human(org: &str) -> Caller {
    Caller {
        kind: ActorKind::Human,
        profile: Profile::Operator,
        enforce_profile: false,
        ..agent_named("operator", org)
    }
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

/// `got` reads exactly as `missing` does, once each names the same id.
fn same_as_missing(got: &Result<Value, UaError>, missing: &Result<Value, UaError>, id: &str) {
    match (got, missing) {
        (Err(e), Err(m)) => {
            assert_eq!(e.code(), m.code(), "{e} / {m}");
            assert_eq!(
                e.to_string().replace(id, "ID"),
                m.to_string().replace(ABSENT, "ID"),
                "another organization's note must answer as a missing one"
            );
        }
        (Ok(g), Ok(m)) => assert_eq!(g, m, "another organization's note must answer as a missing one"),
        _ => panic!("answers differ: {got:?} / {missing:?}"),
    }
}

/// Maps each word to a concept axis, so "automobile" finds "car" with no
/// lexical overlap. Deterministic and fake.
struct ConceptEmbedder;

const CONCEPTS: &[&[&str]] = &[&["car", "automobile", "vehicle"], &["fruit", "apple", "banana"]];

impl Embedder for ConceptEmbedder {
    fn model(&self) -> &str {
        MODEL
    }

    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
        Ok(texts
            .iter()
            .map(|text| {
                let mut v = vec![0f32; CONCEPTS.len() + 1];
                for w in text.to_lowercase().split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()) {
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

struct H {
    hub: Hub,
    reg: Registry,
    _dir: tempfile::TempDir,
}

impl H {
    fn new() -> Self {
        Self::with_model("tenant-lexical-only-model")
    }

    fn with_model(model: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path());
        cfg.human_identities = vec!["operator".into()];
        cfg.embed_model = model.into();
        let hub = Hub::in_memory(cfg).unwrap();
        add_org(hub.db(), ORG_B);
        Self { hub, reg: builtin_registry(), _dir: dir }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{}: {tool}({args}) failed: {e:?}", who.org_id),
        }
    }

    async fn save(&self, who: &Caller, args: Value) -> String {
        self.ok(who, "memory_save", args).await["id"].as_str().unwrap().to_string()
    }

    fn count(&self, sql: &str) -> i64 {
        let sql = sql.to_string();
        self.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
    }

    fn sql(&self, sql: &str) -> Result<(), String> {
        let sql = sql.to_string();
        self.hub
            .db()
            .write(move |tx| {
                tx.execute_batch(&sql)?;
                Ok(())
            })
            .map_err(|e| e.to_string())
    }

    /// Every row of the three memory tables (access counters included), as
    /// text: a write that changes nothing leaves it identical.
    fn snapshot(&self) -> String {
        self.hub
            .db()
            .read(|c| {
                let mut out = String::new();
                for t in TABLES {
                    let mut stmt = c.prepare(&format!("SELECT * FROM {t} ORDER BY rowid"))?;
                    let n = stmt.column_count();
                    let rows = stmt.query_map([], |r| {
                        let mut row = Vec::new();
                        for i in 0..n {
                            row.push(format!("{:?}", r.get_ref(i)?));
                        }
                        Ok(row.join("|"))
                    })?;
                    for row in rows {
                        out.push_str(&format!("{t}: {}\n", row?));
                    }
                }
                Ok(out)
            })
            .unwrap()
    }

    fn events(&self) -> i64 {
        self.count("SELECT COUNT(*) FROM event_log")
    }
}

fn ids(v: &Value, key: &str) -> Vec<String> {
    v[key].as_array().unwrap().iter().map(|n| n["id"].as_str().unwrap().to_string()).collect()
}

fn names(c: &rusqlite::Connection, kind: &str, table: &str) -> Vec<String> {
    c.prepare(
        "SELECT name FROM sqlite_master WHERE type = ?1 AND tbl_name = ?2 AND sql IS NOT NULL ORDER BY name",
    )
    .unwrap()
    .query_map([kind, table], |r| r.get(0))
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

// --- schema ------------------------------------------------------------------------------------

/// Notes, versions and vectors written before the parts land in the default
/// organization, nothing is dropped, and full-text search still finds them.
#[tokio::test]
async fn a_legacy_database_upgrades_every_note_into_the_default_organization() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.human_identities = vec!["operator".into()];
    cfg.embed_model = "tenant-lexical-only-model".into();
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO memory (id, title, content, tags, author, created_at, updated_at) VALUES
                     ('legacy000001', 'Legacy wombat', 'The wombat cache was on port 1.', '[]', 'builder-1',
                      '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'),
                     ('legacy000002', 'Legacy other', 'Unrelated fake note.', '[]', 'builder-2',
                      '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');
                 UPDATE memory SET content = 'The wombat cache is on port 8080.' WHERE id = 'legacy000001';
                 INSERT INTO memory_embeddings (note_id, model, dim, embedding, content_sha, updated_at) VALUES
                     ('legacy000002', 'fake-model', 1, x'0000803f', 'fake-sha-not-real',
                      '2026-01-01T00:00:00+00:00');",
            )?;
            Ok(())
        })
        .unwrap();
        let versions: i64 =
            db.read(|c| Ok(c.query_row("SELECT COUNT(*) FROM memory_versions", [], |r| r.get(0))?)).unwrap();
        assert_eq!(versions, 1, "the old capture trigger recorded the legacy edit");
    }

    // Open twice: the upgrade is idempotent across restarts.
    for _ in 0..2 {
        let hub = Hub::open(cfg.clone()).unwrap();
        hub.db()
            .read(|c| {
                for (t, rows) in [("memory", 2), ("memory_versions", 1), ("memory_embeddings", 1)] {
                    let (n, default): (i64, i64) = c.query_row(
                        &format!("SELECT COUNT(*), SUM(org_id = 'default') FROM {t}"),
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )?;
                    assert_eq!((n, default), (rows, rows), "{t}: nothing dropped, every row in default");
                    let notnull: i64 = c.query_row(
                        &format!("SELECT \"notnull\" FROM pragma_table_info('{t}') WHERE name = 'org_id'"),
                        [],
                        |r| r.get(0),
                    )?;
                    assert_eq!(notnull, 1, "{t}");
                }
                let triggers: Vec<String> =
                    TABLES.iter().flat_map(|t| names(c, "trigger", t)).collect();
                for want in [
                    "memory_org_exists",
                    "memory_org_immutable",
                    "memory_org_superseded_by",
                    "memory_org_superseded_by_insert",
                    "memory_versions_capture",
                    "memory_versions_org_exists",
                    "memory_versions_org_immutable",
                    "memory_versions_org_parent",
                    "memory_versions_org_parent_update",
                    "memory_embeddings_org_exists",
                    "memory_embeddings_org_immutable",
                    "memory_embeddings_org_parent",
                    "memory_embeddings_org_parent_update",
                    "memory_fts_ai",
                    "memory_fts_ad",
                    "memory_fts_au",
                ] {
                    assert!(triggers.iter().any(|t| t == want), "{want} missing: {triggers:?}");
                }
                let capture: String = c.query_row(
                    "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'memory_versions_capture'",
                    [],
                    |r| r.get(0),
                )?;
                assert!(capture.contains("INSERT INTO memory_versions (org_id,"), "{capture}");
                for (name, head) in [
                    ("memory_org_superseded_by", "BEFORE UPDATE OF superseded_by ON memory"),
                    ("memory_org_superseded_by_insert", "BEFORE INSERT ON memory"),
                ] {
                    let sql: String = c.query_row(
                        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                        [name],
                        |r| r.get(0),
                    )?;
                    assert!(sql.contains(head) && sql.contains("id = NEW.superseded_by"), "{name}: {sql}");
                }
                for ix in ["idx_memory_org_updated", "idx_memory_embeddings_org_model"] {
                    let n: i64 = c.query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                        [ix],
                        |r| r.get(0),
                    )?;
                    assert_eq!(n, 1, "{ix}");
                }
                Ok(())
            })
            .unwrap();
    }

    let hub = Hub::open(cfg).unwrap();
    let reg = builtin_registry();
    let a = agent(DEFAULT_ORG);
    let hits = reg.call(&hub, &a, "memory_search", json!({ "query": "wombat" })).await.unwrap();
    assert_eq!(ids(&hits, "results"), ["legacy000001"], "FTS still finds the legacy note");
    let got = reg
        .call(&hub, &a, "memory_get", json!({ "id": "legacy000001", "include_versions": true }))
        .await
        .unwrap();
    assert_eq!(got["versions_total"], 1);
    assert_eq!(got["versions"][0]["content"], "The wombat cache was on port 1.");
    // A new edit is captured in the note's organization by the new trigger.
    reg.call(&hub, &a, "memory_save", json!({ "id": "legacy000001", "content": "Port 9090 now." }))
        .await
        .unwrap();
    let rows: i64 = hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM memory_versions WHERE note_id = 'legacy000001' AND org_id = 'default'",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(rows, 2);
}

/// A version, a vector and a supersede pointer stay in their note's
/// organization, whoever writes them.
#[tokio::test]
async fn versions_vectors_and_pointers_follow_their_note() {
    register_embedder(Arc::new(ConceptEmbedder));
    let h = H::with_model(MODEL);
    let a = agent(DEFAULT_ORG);
    let b = agent(ORG_B);
    let na = h.save(&a, json!({ "title": "A car", "content": "The car is parked." })).await;
    let nb = h.save(&b, json!({ "title": "B car", "content": "The vehicle is parked." })).await;
    h.ok(&b, "memory_save", json!({ "id": nb, "content": "The automobile moved." })).await;

    // One captured version and one vector, both in organization B.
    for t in ["memory_versions", "memory_embeddings"] {
        assert_eq!(
            h.count(&format!("SELECT COUNT(*) FROM {t} WHERE note_id = '{nb}' AND org_id = '{ORG_B}'")),
            1
        );
        assert_eq!(
            h.count(&format!("SELECT COUNT(*) FROM {t} WHERE note_id = '{nb}' AND org_id <> '{ORG_B}'")),
            0
        );
    }
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM memory_embeddings WHERE note_id = '{na}' AND org_id = 'default'"
        )),
        1
    );

    // The triggers refuse every cross-organization reference.
    for sql in [
        format!(
            "INSERT INTO memory_versions (org_id, note_id, version, content, tags, updated_at, recorded_at) \
             VALUES ('{ORG_B}', '{na}', 9, 'x', '[]', 'x', 'x')"
        ),
        format!(
            "INSERT INTO memory_embeddings (org_id, note_id, model, dim, embedding, content_sha, updated_at) \
             VALUES ('default', '{nb}', 'm', 1, x'00', 's', 'x')"
        ),
        format!("UPDATE memory SET superseded_by = '{nb}' WHERE id = '{na}'"),
        format!(
            "INSERT INTO memory (org_id, id, content, superseded_by, created_at, updated_at) \
             VALUES ('default', 'pointer00001', 'x', '{nb}', 'x', 'x')"
        ),
        format!("UPDATE memory SET org_id = '{ORG_B}' WHERE id = '{na}'"),
        format!(
            "INSERT INTO memory (org_id, id, content, created_at, updated_at) \
             VALUES ('{UNKNOWN}', 'ghost0000001', 'x', 'x', 'x')"
        ),
    ] {
        let e = h.sql(&sql).unwrap_err();
        assert!(
            e.contains("another organization")
                || e.contains("org_id cannot change")
                || e.contains("unknown organization"),
            "{sql}: {e}"
        );
    }
}

// --- isolation ---------------------------------------------------------------------------------

/// Every read and write path answers organization B from B's notes only, and
/// a default note's id answers B exactly as a missing id does.
#[tokio::test]
async fn each_organization_sees_only_its_own_notes() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let b = agent(ORG_B);
    // Low salience, stale and low confidence, so both maintenance reports
    // list every note of the organization that can see it.
    let note = |title: &str| {
        json!({
            "title": title,
            "content": format!("Wombat cache {title} fake-content-not-real."),
            "tags": ["wombat"],
            "salience": 0.1,
            "confidence": 0.1,
        })
    };
    let na = h.save(&a, note("alpha")).await;
    let na2 = h.save(&a, note("alpha two")).await;
    let nb = h.save(&b, note("bravo")).await;
    h.sql("UPDATE memory SET updated_at = '2020-01-01T00:00:00+00:00'").unwrap();

    // The maintenance reports first: a search counts as a recall.
    let p = h.ok(&b, "memory_prune_candidates", json!({ "salience_threshold": 1.0 })).await;
    assert_eq!((ids(&p, "candidates"), p["candidate_count"].clone()), (vec![nb.clone()], json!(1)));
    let m = h.ok(&b, "recall_maintenance", json!({ "confidence_floor": 0.5 })).await;
    assert_eq!(ids(&m, "low_confidence"), std::slice::from_ref(&nb));
    assert_eq!(ids(&m, "stale"), std::slice::from_ref(&nb));
    let m = h.ok(&a, "recall_maintenance", json!({ "confidence_floor": 0.5 })).await;
    assert_eq!(m["stale_count"], 2, "{m}");

    // search, list and export: own notes only.
    let s = h.ok(&b, "memory_search", json!({ "query": "wombat cache" })).await;
    assert_eq!(ids(&s, "results"), std::slice::from_ref(&nb));
    let s = h.ok(&a, "memory_search", json!({ "query": "wombat cache", "limit": 50 })).await;
    let mut got = ids(&s, "results");
    got.sort();
    let mut want = vec![na.clone(), na2.clone()];
    want.sort();
    assert_eq!(got, want);
    assert_eq!(ids(&h.ok(&b, "memory_list", json!({})).await, "items"), std::slice::from_ref(&nb));
    assert_eq!(
        ids(&h.ok(&b, "memory_list", json!({ "tag": "wombat" })).await, "items"),
        std::slice::from_ref(&nb)
    );
    let x = h.ok(&human(ORG_B), "export_memory", json!({ "write_to_vault": false })).await;
    let content = x["content"].as_str().unwrap();
    assert_eq!((x["rows"].clone(), content.contains(&nb), content.contains(&na)), (json!(1), true, false));

    // get, platform_object_get, delete, restore, feedback, update, supersede,
    // contradict: a default note's id answers as a missing one.
    for (tool, args) in [
        ("memory_get", json!({ "id": "ID", "include_versions": true })),
        ("memory_delete", json!({ "id": "ID" })),
        ("memory_restore", json!({ "id": "ID" })),
        ("memory_feedback", json!({ "id": "ID", "signal": "wrong" })),
        ("memory_save", json!({ "id": "ID", "content": "x" })),
        ("memory_save", json!({ "content": "x", "supersedes": "ID" })),
        ("memory_save", json!({ "content": "x", "contradicts": ["ID"] })),
        ("platform_object_get", json!({ "kind": "memory_note", "id": "ID" })),
    ] {
        let with = |id: &str| {
            serde_json::from_str::<Value>(&args.to_string().replace("\"ID\"", &format!("\"{id}\""))).unwrap()
        };
        let before = (h.snapshot(), h.events());
        let got = h.call(&b, tool, with(&na)).await;
        let after = (h.snapshot(), h.events());
        let missing = h.call(&b, tool, with(ABSENT)).await;
        same_as_missing(&got, &missing, &na);
        assert_eq!(after, before, "{tool}({args}) changed nothing");
    }
    // Searching or reading never bumped the default note's counters.
    assert_eq!(h.count(&format!("SELECT access_count FROM memory WHERE id = '{na}'")), 1);

    // A link names only the reader's organization's notes.
    let nb2 = h.save(&b, json!({ "content": "B evidence", "evidence": [format!("memory:{na}")] })).await;
    let g = h.ok(&b, "memory_get", json!({ "id": nb2 })).await;
    assert_eq!(g["links"]["out"][0]["title"], Value::Null, "{g}");
    let ga = h.ok(&a, "memory_get", json!({ "id": na, "count_access": false })).await;
    assert_eq!(ga["links"]["in"], json!([]), "B's ref is not an inbound link of A's note: {ga}");

    // The session packet's related notes are the task organization's.
    let t = h.ok(&b, "task_add", json!({ "title": "Wombat cache migration", "project": "web" })).await["id"]
        .as_i64()
        .unwrap();
    let packet = h.ok(&b, "session_packet", json!({ "task_id": t })).await;
    let mem = ids(&packet, "memory");
    assert!(mem.contains(&nb) && !mem.contains(&na) && !mem.contains(&na2), "{mem:?}");

    // state_sync_verify counts only the caller's notes.
    let v = h.ok(&human(ORG_B), "state_sync_verify", json!({})).await;
    assert_eq!(v["memory_db_count"], 2, "{v}");

    // Promoting into the hub-wide vault is the default organization's alone.
    let e = h.call(&human(ORG_B), "memory_promote", json!({ "id": nb, "dry_run": true })).await.unwrap_err();
    assert_eq!(reason(&e), "org_unsupported", "{e}");
}

/// The semantic leg scans, ranks and returns only the caller's
/// organization's vectors; the similar-note check on create too.
#[tokio::test]
async fn semantic_search_never_reaches_another_organizations_vectors() {
    register_embedder(Arc::new(ConceptEmbedder));
    let h = H::with_model(MODEL);
    let a = agent(DEFAULT_ORG);
    let b = agent(ORG_B);
    let car = h.save(&a, json!({ "title": "Car", "content": "The car lives in the garage." })).await;
    let fruit = h.save(&b, json!({ "title": "Fruit", "content": "Buy an apple and a banana." })).await;

    let r = h.ok(&b, "memory_search", json!({ "query": "automobile" })).await;
    assert_eq!(r["retrieval"]["mode"], "hybrid");
    assert_eq!(r["retrieval"]["semantic"]["matched_count"], 0, "{r}");
    assert_eq!(r["results"], json!([]));
    let r = h.ok(&a, "memory_search", json!({ "query": "automobile" })).await;
    assert_eq!(ids(&r, "results"), std::slice::from_ref(&car));
    let r = h.ok(&a, "memory_search", json!({ "query": "banana" })).await;
    assert_eq!(r["results"], json!([]), "{r}");
    let r = h.ok(&b, "memory_search", json!({ "query": "banana" })).await;
    assert_eq!(ids(&r, "results"), std::slice::from_ref(&fruit));

    // B's near-duplicate of A's note reports no similar note; A's would.
    let check = h.ok(&b, "memory_save", json!({ "content": "A vehicle car.", "check_only": true })).await;
    assert_eq!(check["similar"], json!([]), "{check}");
    let check = h.ok(&a, "memory_save", json!({ "content": "A vehicle car.", "check_only": true })).await;
    assert_eq!(check["similar"][0]["id"], car.as_str(), "{check}");
}

// --- idempotency -------------------------------------------------------------------------------

/// The same label and key in two organizations are two saves, and neither
/// replays the other's receipt; a pre-upgrade raw key replays only in the
/// default organization.
#[tokio::test]
async fn the_same_idempotency_key_in_two_organizations_is_two_saves() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let b = agent(ORG_B);
    let args = json!({ "content": "fake-idem-not-real", "idempotency_key": "k1" });
    let ra = h.ok(&a, "memory_save", args.clone()).await;
    let rb = h.ok(&b, "memory_save", args.clone()).await;
    assert_ne!(ra["id"], rb["id"]);
    assert_eq!(h.ok(&b, "memory_save", args.clone()).await, rb, "B's retry replays B's receipt");
    assert_eq!(h.ok(&a, "memory_save", args.clone()).await, ra);
    assert_eq!(h.count("SELECT COUNT(*) FROM memory"), 2);
    assert_eq!(h.count("SELECT COUNT(*) FROM idempotency_keys WHERE key = 'memory_save/builder-1/k1'"), 1);
    assert_eq!(
        h.count("SELECT COUNT(*) FROM idempotency_keys WHERE key = 'org:org-b/memory_save/builder-1/k1'"),
        1
    );

    // A pre-upgrade raw key naming A's note is never B's receipt.
    let raw = format!("{{\"id\":{},\"created\":true}}", ra["id"]);
    h.sql(&format!(
        "INSERT INTO idempotency_keys (key, tool, result_json, created_at) \
         VALUES ('k2', 'memory_save', '{raw}', '2026-01-01T00:00:00+00:00')"
    ))
    .unwrap();
    let k2 = json!({ "content": "fake-idem-two-not-real", "idempotency_key": "k2" });
    let rb2 = h.ok(&b, "memory_save", k2.clone()).await;
    assert_ne!(rb2["id"], ra["id"]);
    assert_eq!(
        h.ok(&a, "memory_save", k2).await["id"],
        ra["id"],
        "the default organization still replays it"
    );
}

/// An organization id is escaped in the stored key the way the label is, so
/// no organization id, label and key spell another organization's key: org
/// `x/memory_save/y` with label `L` and key `k` and org `x` with label `y`
/// and key `memory_save/L/k` are two saves.
#[tokio::test]
async fn an_organization_id_with_a_slash_cannot_spell_another_organizations_key() {
    let h = H::new();
    let (slashed, plain) = ("x/memory_save/y", "x");
    add_org(h.hub.db(), slashed);
    add_org(h.hub.db(), plain);
    let in_plain = agent_named("y", plain);
    let in_slashed = agent_named("L", slashed);
    let r1 = h
        .ok(
            &in_plain,
            "memory_save",
            json!({ "content": "fake-plain-not-real", "idempotency_key": "memory_save/L/k" }),
        )
        .await;
    let r2 = h
        .ok(&in_slashed, "memory_save", json!({ "content": "fake-slashed-not-real", "idempotency_key": "k" }))
        .await;
    assert_ne!(r1["id"], r2["id"], "a second save, not the other organization's receipt");
    assert_ne!(r1["revision"], r2["revision"]);
    assert_eq!(h.count("SELECT COUNT(*) FROM memory WHERE org_id = 'x/memory_save/y'"), 1);
    assert_eq!(
        h.count(
            "SELECT COUNT(*) FROM idempotency_keys WHERE key IN \
             ('org:x/memory_save/y/memory_save/L/k', 'org:x%2Fmemory_save%2Fy/memory_save/L/k')"
        ),
        2
    );
}

/// A scoped receipt whose note the caller's organization cannot see is never
/// returned (a hand-written row stands in for a key collision): the save is
/// refused, names neither the note nor its revision, and writes nothing.
#[tokio::test]
async fn a_receipt_naming_another_organizations_note_is_never_replayed() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let ra = h
        .ok(&a, "memory_save", json!({ "content": "fake-a-receipt-not-real", "idempotency_key": "ka" }))
        .await;
    let id = ra["id"].as_str().unwrap().to_string();
    let rev = ra["revision"].as_str().unwrap_or("no-revision").to_string();
    h.sql(
        "INSERT INTO idempotency_keys (key, tool, result_json, created_at) \
         SELECT 'org:org-b/memory_save/builder-1/kb', tool, result_json, created_at FROM idempotency_keys \
         WHERE key = 'memory_save/builder-1/ka'",
    )
    .unwrap();
    let before = (h.snapshot(), h.events());
    let e = h
        .call(&agent(ORG_B), "memory_save", json!({ "content": "fake-b-not-real", "idempotency_key": "kb" }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "idempotency_key_conflict", "{e}");
    assert!(!e.to_string().contains(&id) && !e.to_string().contains(&rev), "{e}");
    assert_eq!((h.snapshot(), h.events()), before);
    // The default organization still replays its own receipt.
    assert_eq!(
        h.ok(&a, "memory_save", json!({ "content": "fake-a-receipt-not-real", "idempotency_key": "ka" }))
            .await,
        ra
    );
}

// --- exports -----------------------------------------------------------------------------------

/// A file export lands in the hub's shared workspace, so another
/// organization is refused one (nothing written, nothing ledgered) and keeps
/// the inline export.
#[tokio::test]
async fn another_organization_is_refused_a_file_export() {
    let h = H::new();
    let b = human(ORG_B);
    h.save(&b, json!({ "content": B_BODY, "title": B_TITLE })).await;
    let events = h.events();
    for tool in ["export_memory", "export_tasks"] {
        for args in [json!({}), json!({ "write_to_vault": true })] {
            let e = h.call(&b, tool, args.clone()).await.unwrap_err();
            assert_eq!(reason(&e), "org_unsupported", "{tool}({args}): {e}");
        }
        let inline = h.ok(&b, tool, json!({ "write_to_vault": false })).await;
        assert!(inline.get("content").is_some(), "{tool}: {inline}");
    }
    assert_eq!(h.events(), events, "no agent.export.written event");
    assert!(!h.hub.cfg().workspace_root().join("exports").exists(), "no file in the shared workspace");
}

// --- unknown organization ----------------------------------------------------------------------

#[tokio::test]
async fn an_unknown_organization_is_refused_before_any_write() {
    let h = H::new();
    let na = h.save(&agent(DEFAULT_ORG), json!({ "content": "fake-default-not-real" })).await;
    let ghost = agent(UNKNOWN);
    let before = (h.snapshot(), h.events());
    for (tool, args) in [
        ("memory_save", json!({ "content": "x" })),
        ("memory_save", json!({ "id": na, "content": "x" })),
        ("memory_delete", json!({ "id": na })),
        ("memory_restore", json!({ "id": na })),
        ("memory_feedback", json!({ "id": na, "signal": "helpful" })),
    ] {
        let e = h.call(&ghost, tool, args.clone()).await.unwrap_err();
        assert_eq!(reason(&e), "unknown_organization", "{tool}({args}): {e}");
    }
    // Reads find nothing and write nothing.
    assert_eq!(h.ok(&ghost, "memory_list", json!({})).await["items"], json!([]));
    assert_eq!(h.ok(&ghost, "memory_search", json!({ "query": "fake" })).await["results"], json!([]));
    assert_eq!((h.snapshot(), h.events()), before);
}

/// A suspended organization's caller changes no note.
#[tokio::test]
async fn a_suspended_organization_is_refused_before_any_write() {
    let h = H::new();
    let b = agent(ORG_B);
    let nb = h.save(&b, json!({ "content": "fake-suspended-not-real" })).await;
    h.sql(&format!("UPDATE orgs SET status = 'suspended' WHERE id = '{ORG_B}'")).unwrap();
    let before = (h.snapshot(), h.events());
    for (tool, args) in [
        ("memory_save", json!({ "content": "x" })),
        ("memory_save", json!({ "id": nb, "content": "x" })),
        ("memory_delete", json!({ "id": nb })),
        ("memory_restore", json!({ "id": nb })),
        ("memory_feedback", json!({ "id": nb, "signal": "helpful" })),
    ] {
        let e = h.call(&b, tool, args.clone()).await.unwrap_err();
        assert_eq!(reason(&e), "organization_suspended", "{tool}({args}): {e}");
    }
    assert_eq!((h.snapshot(), h.events()), before);
}

// --- the ledger --------------------------------------------------------------------------------

#[tokio::test]
async fn organization_b_text_and_labels_never_reach_the_default_ledger() {
    let h = H::new();
    let b = agent_named(B_AGENT, ORG_B);
    let first = h.save(&b, json!({ "title": B_TITLE, "content": B_BODY, "tags": [B_TAG] })).await;
    h.ok(&b, "memory_save", json!({ "id": first, "title": B_TITLE_EDIT, "content": B_BODY })).await;
    let second = h
        .save(&b, json!({ "title": B_TITLE, "content": B_BODY, "tags": [B_TAG], "supersedes": first }))
        .await;
    h.ok(&b, "memory_feedback", json!({ "id": second, "signal": "helpful" })).await;
    h.ok(&b, "memory_restore", json!({ "id": first })).await;
    h.ok(&b, "memory_delete", json!({ "id": second })).await;
    h.ok(&b, "memory_restore", json!({ "id": second })).await;

    let rows: Vec<(String, String, Option<String>)> = h
        .hub
        .db()
        .read(|c| {
            Ok(c.prepare("SELECT channel, payload, originator FROM event_log ORDER BY seq")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?)
        })
        .unwrap();
    let ours: Vec<_> = rows.iter().filter(|(c, _, _)| c.starts_with("agent.memory.")).collect();
    assert!(ours.len() >= 7, "the writes were ledgered: {ours:?}");
    for (channel, payload, originator) in &rows {
        for s in [B_AGENT, B_TITLE, B_TITLE_EDIT, B_TAG, B_BODY] {
            assert!(!payload.contains(s), "{s:?} reached a default ledger payload ({channel}): {payload}");
            assert!(!originator.as_deref().unwrap_or_default().contains(s), "{s:?} is an originator");
        }
    }
    for (channel, payload, originator) in &ours {
        assert_eq!(originator.as_deref(), Some("system"), "{channel}");
        assert!(!payload.contains("sha256:"), "a revision hash of B's content: {payload}");
    }
    // Ids remain.
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM event_log WHERE channel = 'agent.memory.superseded' \
             AND json_extract(payload, '$.id') = '{first}' AND json_extract(payload, '$.superseded_by') = '{second}'"
        )),
        1
    );

    // The default organization's events keep their text and originator.
    let a = agent_named("lead-1", DEFAULT_ORG);
    let na = h.save(&a, json!({ "title": "A title", "content": "A body" })).await;
    let p: String = {
        let sql = format!(
            "SELECT payload || '|' || originator FROM event_log WHERE channel = 'agent.memory.saved' \
             AND json_extract(payload, '$.id') = '{na}'"
        );
        h.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
    };
    assert!(
        p.contains("\"title\":\"A title\"") && p.contains("\"author\":\"lead-1\"") && p.ends_with("|lead-1"),
        "{p}"
    );
}

//! The domain API on a bare database, without the tool registry: save,
//! search, read, delete and restore a note.

use serde_json::json;
use ua_core::UaError;
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_memory::save::SaveRequest;
use ua_memory::search::{GetRequest, SearchRequest};
use ua_memory::{lifecycle, save, search};
use ua_store::{Db, ledger};

fn db() -> Db {
    let mut parts: Vec<ua_store::Part> = ua_store::schema::parts(&[ledger::SCHEMA, ledger::META_SCHEMA]);
    parts.push(ua_store::org::STORE_PART.into());
    parts.extend(ua_memory::schema_parts().into_iter().map(ua_store::Part::from));
    parts.extend(ua_memory::org_parts());
    Db::open_in_memory(&parts).unwrap()
}

fn cfg() -> Config {
    let mut cfg = Config::for_home(std::env::temp_dir());
    // No registered embedder for this model: search is lexical only.
    cfg.embed_model = "lexical-only-domain-test-model".into();
    cfg
}

fn agent(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: None,
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

fn get_req(id: &str) -> GetRequest {
    GetRequest { id: id.into(), as_of: None, include_versions: true, count_access: false }
}

#[tokio::test]
async fn save_search_get_delete_restore_without_a_registry() {
    let (db, cfg, a) = (db(), cfg(), agent("builder-1"));
    let saved = save::save(
        &db,
        &cfg,
        &a,
        SaveRequest {
            content: "The wombat cache is enabled on port 8080.".into(),
            title: Some("Wombat cache".into()),
            tags: Some(vec!["infra".into()]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(saved["created"], json!(true));
    let id = saved["id"].as_str().unwrap().to_string();
    assert!(saved["revision"].as_str().unwrap().starts_with("sha256:"));

    let hits = search::search(
        &db,
        &cfg,
        ua_core::DEFAULT_ORG,
        SearchRequest { query: "wombat".into(), ..Default::default() },
    )
    .await
    .unwrap();
    assert_eq!(hits["retrieval"]["mode"], json!("lexical_fallback"));
    assert_eq!(hits["results"][0]["id"], json!(id));
    assert_eq!(hits["results"][0]["trust"]["level"], json!("untrusted"));

    let note = search::get(&db, &cfg, ua_core::DEFAULT_ORG, get_req(&id)).await.unwrap();
    assert_eq!(note["author"], json!("builder-1"));
    assert_eq!(note["access_count"], json!(1), "the search counted one access");

    // Another agent may not delete it; the owner may, and may restore it.
    let err = lifecycle::delete(&db, &cfg, &agent("builder-2"), id.clone()).await.unwrap_err();
    assert!(
        matches!(&err, ua_core::UaError::Denied { reason_code, .. } if reason_code == "not_owner"),
        "{err:?}"
    );
    let deleted = lifecycle::delete(&db, &cfg, &a, id.clone()).await.unwrap();
    assert_eq!(deleted, json!({ "deleted": true }));
    let gone = search::search(
        &db,
        &cfg,
        ua_core::DEFAULT_ORG,
        SearchRequest { query: "wombat".into(), ..Default::default() },
    )
    .await
    .unwrap();
    assert_eq!(gone["results"], json!([]));
    let restored = lifecycle::restore(&db, &cfg, &a, id.clone()).await.unwrap();
    assert_eq!(restored["restored"], json!(true));
    assert_eq!(restored["was_deleted"], json!(true));

    // Each change appended its ledger event in the same transaction.
    let channels: Vec<String> = db
        .read(|c| {
            let mut stmt = c.prepare("SELECT channel FROM event_log ORDER BY seq")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .unwrap();
    assert_eq!(channels, ["agent.memory.saved", "agent.memory.deleted", "agent.memory.restored"]);
}

/// A tombstone written before deletes were tagged `meta:deleted-by-human` is
/// judged by who wrote it: when `updated_by` is a configured human identity,
/// only a human may restore the note.
#[tokio::test]
async fn a_legacy_human_delete_is_restored_only_by_a_human() {
    let db = db();
    let mut cfg = cfg();
    cfg.human_identities = vec!["operator".into()];
    let owner = agent("builder-1");
    let saved = save::save(
        &db,
        &cfg,
        &owner,
        SaveRequest { content: "Legacy note.".into(), title: Some("Legacy".into()), ..Default::default() },
    )
    .await
    .unwrap();
    let id = saved["id"].as_str().unwrap().to_string();
    let legacy_delete = |id: String, by: &'static str| {
        db.write(move |tx| {
            tx.execute(
                "UPDATE memory SET content = 'tombstone', tags = '[\"meta:deleted\"]', updated_by = ?1 \
                 WHERE id = ?2",
                rusqlite::params![by, id],
            )?;
            Ok(())
        })
        .unwrap()
    };

    legacy_delete(id.clone(), "operator");
    let err = lifecycle::restore(&db, &cfg, &owner, id.clone()).await.unwrap_err();
    assert!(matches!(&err, UaError::Denied { reason_code, .. } if reason_code == "human_only"), "{err:?}");
    let human = Caller { kind: ActorKind::Human, ..agent("operator") };
    let restored = lifecycle::restore(&db, &cfg, &human, id.clone()).await.unwrap();
    assert_eq!(restored["restored"], json!(true));

    // Deleted by an identity that is not a configured human: the owner may restore it.
    legacy_delete(id.clone(), "builder-1");
    let restored = lifecycle::restore(&db, &cfg, &owner, id.clone()).await.unwrap();
    assert_eq!(restored["restored"], json!(true));
    assert_eq!(
        search::get(&db, &cfg, ua_core::DEFAULT_ORG, get_req(&id)).await.unwrap()["content"],
        json!("Legacy note.")
    );
}

//! Every memory write and report reads the injected clock (`Config.clock`),
//! not the wall clock: save, delete, restore, feedback, version history and
//! both maintenance reports.

use serde_json::{Value, json};
use ua_core::time::Clock;
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_memory::maintenance::{MaintenanceRequest, PruneRequest};
use ua_memory::save::SaveRequest;
use ua_memory::search::GetRequest;
use ua_memory::{lifecycle, maintenance, save, search};
use ua_store::{Db, ledger};

const T1: &str = "2026-01-10T00:00:00+00:00";
const T2: &str = "2026-02-10T00:00:00+00:00";
const T3: &str = "2026-03-10T00:00:00+00:00";
const T4: &str = "2026-04-10T00:00:00+00:00";

fn db() -> Db {
    let mut parts: Vec<ua_store::Part> = ua_store::schema::parts(&[ledger::SCHEMA, ledger::META_SCHEMA]);
    parts.push(ua_store::org::STORE_PART.into());
    parts.extend(ua_memory::schema_parts().into_iter().map(ua_store::Part::from));
    parts.extend(ua_memory::org_parts());
    Db::open_in_memory(&parts).unwrap()
}

fn at(ts: &str) -> Config {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.embed_model = "lexical-only-clock-test-model".into();
    cfg.clock = Clock::fixed(ts).unwrap();
    cfg
}

fn agent() -> Caller {
    Caller {
        label: "builder-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: None,
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

async fn get(db: &Db, cfg: &Config, id: &str, as_of: Option<&str>) -> Value {
    let req = GetRequest {
        id: id.into(),
        as_of: as_of.map(str::to_string),
        include_versions: true,
        count_access: false,
    };
    search::get(db, cfg, ua_core::DEFAULT_ORG, req).await.unwrap()
}

async fn put(db: &Db, cfg: &Config, req: SaveRequest) -> String {
    save::save(db, cfg, &agent(), req).await.unwrap()["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn save_delete_and_restore_stamp_the_injected_clock() {
    let db = db();
    let req = SaveRequest {
        content: "The kiln reached cone six.".into(),
        title: Some("Kiln".into()),
        ..Default::default()
    };
    let id = put(&db, &at(T1), req).await;
    let note = get(&db, &at(T1), &id, None).await;
    assert_eq!((note["created_at"].as_str(), note["updated_at"].as_str()), (Some(T1), Some(T1)), "{note}");

    // An update stamps updated_at, and the captured prior version is
    // recorded at the same instant, not at SQLite's wall clock.
    let req = SaveRequest {
        id: Some(id.clone()),
        content: "The kiln reached cone seven.".into(),
        ..Default::default()
    };
    put(&db, &at(T2), req).await;
    let note = get(&db, &at(T2), &id, None).await;
    assert_eq!(note["created_at"], T1);
    assert_eq!(note["updated_at"], T2);
    assert_eq!(note["versions"][0]["updated_at"], T1, "{note}");
    assert_eq!(note["versions"][0]["recorded_at"], T2, "{note}");

    lifecycle::delete(&db, &at(T3), &agent(), id.clone()).await.unwrap();
    let note = get(&db, &at(T3), &id, None).await;
    assert_eq!(note["updated_at"], T3);
    assert_eq!(note["versions"][0]["recorded_at"], T3, "{note}");

    lifecycle::restore(&db, &at(T4), &agent(), id.clone()).await.unwrap();
    let note = get(&db, &at(T4), &id, None).await;
    assert_eq!(note["updated_at"], T4);
    assert_eq!(note["content"], "The kiln reached cone seven.");
    let recorded: Vec<&str> =
        note["versions"].as_array().unwrap().iter().map(|v| v["recorded_at"].as_str().unwrap()).collect();
    assert_eq!(recorded, [T4, T3, T2], "{note}");

    // get(as_of) limits history to versions recorded by then.
    let then = get(&db, &at(T4), &id, Some("2026-02-20T00:00:00+00:00")).await;
    assert_eq!(then["versions_total"], 1, "{then}");
}

#[tokio::test]
async fn feedback_counts_contradictions_live_on_the_injected_clock() {
    let db = db();
    let cfg = at(T1);
    let a = put(&db, &cfg, SaveRequest { content: "The cache is redis.".into(), ..Default::default() }).await;
    let disputing = SaveRequest {
        content: "The cache is memcached.".into(),
        contradicts: Some(vec![a.clone()]),
        expires_at: Some(T3.into()),
        ..Default::default()
    };
    put(&db, &cfg, disputing).await;
    let open = |v: Value| v["confidence_posterior"]["open_contradictions"].clone();
    let before = lifecycle::feedback(&db, &at(T2), &agent(), a.clone(), "helpful".into()).await.unwrap();
    assert_eq!(open(before), json!(1));
    let after = lifecycle::feedback(&db, &at(T4), &agent(), a.clone(), "helpful".into()).await.unwrap();
    assert_eq!(open(after), json!(0));
}

#[tokio::test]
async fn maintenance_ages_notes_on_the_injected_clock() {
    let db = db();
    let id =
        put(&db, &at(T1), SaveRequest { content: "An unused scratch note.".into(), ..Default::default() })
            .await;
    let org = ua_core::DEFAULT_ORG;

    let prune = |cfg: Config| {
        let db = &db;
        async move {
            let req = PruneRequest { max_age_days: Some(30.0), ..Default::default() };
            maintenance::prune_candidates(db, &cfg, org, req).await.unwrap()["candidates"].clone()
        }
    };
    assert_eq!(prune(at("2026-01-20T00:00:00+00:00")).await, json!([]));
    let old = prune(at("2026-02-20T00:00:00+00:00")).await;
    assert_eq!(old[0]["id"], json!(id), "{old}");
    assert_eq!(old[0]["reasons"], json!(["decayed_unused"]), "{old}");

    let stale = |cfg: Config| {
        let db = &db;
        async move {
            let req = MaintenanceRequest {
                dry_run: true,
                stale_days: Some(120.0),
                confidence_floor: None,
                limit: None,
            };
            maintenance::recall_maintenance(db, &cfg, org, req).await.unwrap()["stale_count"].clone()
        }
    };
    assert_eq!(stale(at(T4)).await, json!(0));
    assert_eq!(stale(at("2026-06-10T00:00:00+00:00")).await, json!(1));
}

//! Organization keys, standalone table rebuild and tool isolation for `web_search_cache`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::http::header;
use axum::routing::any;
use serde_json::json;
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, identity::Transport};
use ua_tools::{Hub, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 2] = ["web.v2.tenant_keys", "organization.v1.tools.web"];

fn caller(org: &str) -> Caller {
    Caller {
        label: "researcher-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn add_org(hub: &Hub, id: &str) {
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
                 VALUES (?1, ?1, 'Org B', '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                [id],
            )?;
            Ok(())
        })
        .unwrap();
}

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().filter(|p| !PARTS.contains(&p.name)).collect()
}

struct SearchServer {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

/// Local fake DuckDuckGo endpoint that returns a distinct result title/URL on
/// every upstream request, so tests can tell whether a response came from the
/// upstream search or from a specific organization's cache row.
async fn spawn_search_server() -> SearchServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let app = Router::new().route(
        "/ddg",
        any(move || {
            let counter = counter.clone();
            async move {
                let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                let html = format!(
                    r#"<html><body>
                    <div class="result web-result">
                      <h2 class="result__title">
                        <a class="result__a" href="https://example.com/hit-{n}">Hit {n}</a>
                      </h2>
                      <a class="result__snippet">Snippet {n}.</a>
                    </div>
                    </body></html>"#
                );
                ([(header::CONTENT_TYPE, "text/html")], html)
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    SearchServer { addr, hits }
}

#[test]
fn legacy_upgrade_rebuilds_primary_key_preserves_rows_indexes_triggers_and_views() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute(
                "INSERT INTO web_search_cache (provider, query, max_results, results_json, fetched_at)
                 VALUES ('ddg', 'rust async', 5, '[{\"title\":\"Legacy\",\"url\":\"https://example.com/legacy\",\"snippet\":\"old\"}]', '2026-01-02T00:00:00+00:00')",
                [],
            )?;
            // Extra index, trigger and view to prove the standalone rebuild preserves them.
            tx.execute_batch(
                "CREATE INDEX idx_web_search_cache_provider ON web_search_cache(provider);
                 CREATE VIEW v_web_cache_queries AS SELECT provider, query FROM web_search_cache;
                 CREATE TRIGGER trg_web_cache_touch AFTER INSERT ON web_search_cache
                 BEGIN SELECT 1; END;",
            )?;
            Ok(())
        })
        .unwrap();
    }

    // Open twice to prove upgrade is idempotent across restarts.
    for _ in 0..2 {
        let hub = Hub::open(cfg.clone()).unwrap();
        hub.db()
            .read(|c| {
                let row: (String, String, String, i64, String, String) = c.query_row(
                    "SELECT org_id, provider, query, max_results, results_json, fetched_at
                     FROM web_search_cache",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                )?;
                assert_eq!(
                    row,
                    (
                        DEFAULT_ORG.into(),
                        "ddg".into(),
                        "rust async".into(),
                        5,
                        r#"[{"title":"Legacy","url":"https://example.com/legacy","snippet":"old"}]"#.into(),
                        "2026-01-02T00:00:00+00:00".into(),
                    )
                );

                // Verify new composite PK: (org_id, provider, query, max_results) and NOT NULL org_id.
                let mut stmt = c.prepare(
                    "SELECT name, \"notnull\", pk FROM pragma_table_info('web_search_cache') ORDER BY pk",
                )?;
                let cols: Vec<(String, i64, i64)> = stmt
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<Result<_, _>>()?;
                let pk_cols: Vec<&str> =
                    cols.iter().filter(|(_, _, pk)| *pk > 0).map(|(n, _, _)| n.as_str()).collect();
                assert_eq!(pk_cols, ["org_id", "provider", "query", "max_results"]);
                assert!(cols.iter().any(|(n, nn, _)| n == "org_id" && *nn == 1));

                // Verify indexes, custom trigger, org triggers, and view survived.
                for idx in [
                    "idx_web_search_cache_fetched",
                    "idx_web_search_cache_org_fetched",
                    "idx_web_search_cache_provider",
                ] {
                    let n: i64 = c.query_row(
                        "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = 'web_search_cache' AND name = ?1",
                        [idx],
                        |r| r.get(0),
                    )?;
                    assert_eq!(n, 1, "index {idx}");
                }
                for trg in [
                    "trg_web_cache_touch",
                    "web_search_cache_org_exists",
                    "web_search_cache_org_immutable",
                ] {
                    let n: i64 = c.query_row(
                        "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'web_search_cache' AND name = ?1",
                        [trg],
                        |r| r.get(0),
                    )?;
                    assert_eq!(n, 1, "trigger {trg}");
                }
                let views: i64 = c.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'view' AND name = 'v_web_cache_queries'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(views, 1);
                let view_row: (String, String) = c.query_row(
                    "SELECT provider, query FROM v_web_cache_queries",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                assert_eq!(view_row, ("ddg".into(), "rust async".into()));

                for part in PARTS {
                    let n: i64 =
                        c.query_row("SELECT count(*) FROM schema_parts WHERE name = ?1", [part], |r| {
                            r.get(0)
                        })?;
                    assert_eq!(n, 1, "{part}");
                }
                let fk: i64 = c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
                assert_eq!(fk, 1, "foreign keys restored");
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn standalone_rebuild_is_safe_to_rerun_after_crash_before_recording() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let hub = Hub::open(cfg.clone()).unwrap();
        add_org(&hub, ORG_B);
        hub.db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO web_search_cache (org_id, provider, query, max_results, results_json, fetched_at)
                     VALUES ('default', 'ddg', 'shared', 5, '[{\"title\":\"A\"}]', '2026-01-02T00:00:00+00:00'),
                            ('org-b', 'ddg', 'shared', 5, '[{\"title\":\"B\"}]', '2026-01-02T00:00:00+00:00')",
                    [],
                )?;
                // Simulate crash right after web.v2.tenant_keys committed its rebuild
                // but before schema_parts / organization.v1.tools.web were recorded.
                tx.execute_batch(
                    "DROP TRIGGER web_search_cache_org_exists;
                     DROP TRIGGER web_search_cache_org_immutable;
                     DELETE FROM schema_parts WHERE name IN ('web.v2.tenant_keys', 'organization.v1.tools.web');
                     DELETE FROM schema_procedures WHERE name IN ('web.v2.tenant_keys', 'organization.v1.tools.web');",
                )?;
                Ok(())
            })
            .unwrap();
    }

    let hub = Hub::open(cfg.clone()).unwrap();
    hub.db()
        .read(|c| {
            let mut stmt = c.prepare(
                "SELECT org_id, results_json FROM web_search_cache WHERE query = 'shared' ORDER BY org_id",
            )?;
            let rows: Vec<(String, String)> =
                stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
            assert_eq!(
                rows,
                vec![
                    ("default".into(), r#"[{"title":"A"}]"#.into()),
                    ("org-b".into(), r#"[{"title":"B"}]"#.into()),
                ]
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn failed_rebuild_rolls_back_cleanly_and_restores_foreign_keys() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute(
                "INSERT INTO web_search_cache (provider, query, max_results, results_json, fetched_at)
                 VALUES ('ddg', 'keep me', 5, '[]', '2026-01-02T00:00:00+00:00')",
                [],
            )?;
            // Pre-existing conflicting staging table forces CREATE TABLE web_search_cache_new to fail.
            tx.execute_batch("CREATE TABLE web_search_cache_new (x INTEGER);")?;
            Ok(())
        })
        .unwrap();
    }

    let err = Hub::open(cfg.clone()).err().expect("rebuild must fail").to_string();
    assert!(err.contains("web.v2.tenant_keys"), "{err}");

    let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
    db.read(|c| {
        let has_org: i64 = c.query_row(
            "SELECT count(*) FROM pragma_table_info('web_search_cache') WHERE name = 'org_id'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(has_org, 0, "original table schema must remain intact");
        let query: String = c.query_row("SELECT query FROM web_search_cache", [], |r| r.get(0))?;
        assert_eq!(query, "keep me");
        let recorded: i64 = c.query_row(
            "SELECT count(*) FROM schema_parts WHERE name IN ('web.v2.tenant_keys', 'organization.v1.tools.web')",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(recorded, 0);
        let fk: i64 = c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
        assert_eq!(fk, 1);
        Ok(())
    })
    .unwrap();
}

#[test]
fn triggers_reject_unknown_org_and_org_reassignment() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::in_memory(Config::for_home(dir.path())).unwrap();
    add_org(&hub, ORG_B);

    hub.db()
        .write(|tx| {
            let err = tx
                .execute(
                    "INSERT INTO web_search_cache (org_id, provider, query, max_results, results_json, fetched_at)
                     VALUES (?1, 'ddg', 'rust', 5, '[]', '2026-01-02T00:00:00+00:00')",
                    [UNKNOWN],
                )
                .unwrap_err()
                .to_string();
            assert!(err.contains("unknown organization"), "{err}");

            tx.execute(
                "INSERT INTO web_search_cache (org_id, provider, query, max_results, results_json, fetched_at)
                 VALUES (?1, 'ddg', 'rust', 5, '[]', '2026-01-02T00:00:00+00:00')",
                [DEFAULT_ORG],
            )?;

            let err = tx
                .execute(
                    "UPDATE web_search_cache SET org_id = ?1 WHERE org_id = ?2 AND query = 'rust'",
                    [ORG_B, DEFAULT_ORG],
                )
                .unwrap_err()
                .to_string();
            assert!(err.contains("org_id cannot change"), "{err}");
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn cross_org_search_cache_and_eviction_are_isolated() {
    let srv = spawn_search_server().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.fetch_allow_loopback = true;
    cfg.search_provider = "ddg".into();
    cfg.search_endpoint = Some(format!("http://{}/ddg", srv.addr));
    cfg.search_cache_ttl_min = 60.0;
    let hub = Hub::in_memory(cfg).unwrap();
    add_org(&hub, ORG_B);
    let reg = builtin_registry();

    let search = |org: &str, query: &str, max_results: i64| {
        let who = caller(org);
        let args = json!({ "query": query, "max_results": max_results });
        let (reg, hub) = (&reg, &hub);
        async move { reg.call(hub, &who, "web_search", args).await }
    };

    // Org A (default) caches query "same query" -> upstream hit 1.
    let a1 = search(DEFAULT_ORG, "same query", 5).await.unwrap();
    assert_eq!(a1["cached"], false);
    assert_eq!(a1["results"][0]["title"], "Hit 1");
    assert_eq!(srv.hits.load(Ordering::SeqCst), 1);

    // Org B queries the exact same (provider, query, max_results) -> cache miss, upstream hit 2.
    let b1 = search(ORG_B, "same query", 5).await.unwrap();
    assert_eq!(b1["cached"], false);
    assert_eq!(b1["results"][0]["title"], "Hit 2");
    assert_eq!(srv.hits.load(Ordering::SeqCst), 2);

    // Both orgs read back only their own cached results without hitting upstream.
    let a2 = search(DEFAULT_ORG, "same query", 5).await.unwrap();
    assert_eq!(a2["cached"], true);
    assert_eq!(a2["results"], a1["results"]);

    let b2 = search(ORG_B, "same query", 5).await.unwrap();
    assert_eq!(b2["cached"], true);
    assert_eq!(b2["results"], b1["results"]);
    assert_eq!(srv.hits.load(Ordering::SeqCst), 2);

    // An unknown org cannot poison the cache: the registry refuses it before
    // the tool runs, so nothing reaches upstream either.
    let u1 = search(UNKNOWN, "same query", 5).await.unwrap_err();
    assert_eq!(u1.reason_code(), Some("unknown_organization"), "{u1}");
    assert_eq!(srv.hits.load(Ordering::SeqCst), 2);

    // Seed expired rows for both default and org-b.
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO web_search_cache (org_id, provider, query, max_results, results_json, fetched_at)
                 VALUES ('default', 'ddg', 'stale-a', 5, '[]', '2000-01-01T00:00:00+00:00'),
                        ('org-b', 'ddg', 'stale-b', 5, '[]', '2000-01-01T00:00:00+00:00')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

    // A write in default evicts default's stale row, leaving org-b's stale and fresh rows intact.
    let a_new = search(DEFAULT_ORG, "fresh-a", 5).await.unwrap();
    assert_eq!(a_new["cached"], false);

    hub.db()
        .read(|c| {
            let count = |org: &str, query: &str| -> i64 {
                c.query_row(
                    "SELECT count(*) FROM web_search_cache WHERE org_id = ?1 AND query = ?2",
                    [org, query],
                    |r| r.get(0),
                )
                .unwrap()
            };
            assert_eq!(count(DEFAULT_ORG, "stale-a"), 0, "default evicted its own stale row");
            assert_eq!(count(DEFAULT_ORG, "same query"), 1, "default kept its fresh row");
            assert_eq!(count(DEFAULT_ORG, "fresh-a"), 1, "default stored its new row");
            assert_eq!(count(ORG_B, "stale-b"), 1, "default write must not evict org-b's stale row");
            assert_eq!(count(ORG_B, "same query"), 1, "default write must not evict org-b's fresh row");
            assert_eq!(count(UNKNOWN, "same query"), 0, "unknown org row was rejected by trigger");
            Ok(())
        })
        .unwrap();

    // Now a write in org-b evicts org-b's stale row while keeping org-b's and default's fresh rows.
    let b_new = search(ORG_B, "fresh-b", 5).await.unwrap();
    assert_eq!(b_new["cached"], false);

    hub.db()
        .read(|c| {
            let count = |org: &str, query: &str| -> i64 {
                c.query_row(
                    "SELECT count(*) FROM web_search_cache WHERE org_id = ?1 AND query = ?2",
                    [org, query],
                    |r| r.get(0),
                )
                .unwrap()
            };
            assert_eq!(count(ORG_B, "stale-b"), 0, "org-b evicted its own stale row");
            assert_eq!(count(ORG_B, "same query"), 1, "org-b kept its fresh row");
            assert_eq!(count(ORG_B, "fresh-b"), 1, "org-b stored its new row");
            assert_eq!(count(DEFAULT_ORG, "same query"), 1, "org-b write must not touch default");
            assert_eq!(count(DEFAULT_ORG, "fresh-a"), 1, "org-b write must not touch default");
            Ok(())
        })
        .unwrap();
}

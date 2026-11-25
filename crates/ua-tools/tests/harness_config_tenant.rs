//! Organization keys, the standalone table rebuild and tool isolation for the
//! harness config tables (`harness_config_bundles`,
//! `harness_config_proposals`, `harness_config_drift`,
//! `harness_config_report_window`).

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::families::harness_config::policy;
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 2] = ["harness_config.v3.tenant_keys", "organization.v1.tools.harness_config"];
const TABLES: [&str; 4] = [
    "harness_config_bundles",
    "harness_config_proposals",
    "harness_config_drift",
    "harness_config_report_window",
];
/// The tables the rebuild re-creates (the drift table only gains a column).
const REBUILT: [&str; 3] =
    ["harness_config_bundles", "harness_config_proposals", "harness_config_report_window"];

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().filter(|p| !PARTS.contains(&p.name)).collect()
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

fn count(c: &rusqlite::Connection, sql: &str) -> i64 {
    c.query_row(sql, [], |r| r.get(0)).unwrap()
}

fn object_exists(c: &rusqlite::Connection, kind: &str, name: &str) -> bool {
    c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = ?1 AND name = ?2", [kind, name], |r| {
        r.get::<_, i64>(0)
    })
    .unwrap()
        == 1
}

fn org_id_notnull(c: &rusqlite::Connection, table: &str) -> Option<i64> {
    c.query_row(
        &format!("SELECT \"notnull\" FROM pragma_table_info('{table}') WHERE name = 'org_id'"),
        [],
        |r| r.get(0),
    )
    .ok()
}

/// Rows the `harness_config.v1`/`v2` parts would have written: bundles and
/// proposals with a `NULL` `org_id`, a drift row and a report window. Bundle
/// 3 is deleted, so the AUTOINCREMENT high-water mark (3) is above the
/// highest id left (2).
const LEGACY_ROWS: &str = "
INSERT INTO harness_config_bundles (id, version, published_at, published_by, bundle_json, active, org_id)
VALUES (1, 'v1', '2026-01-02T00:00:00+00:00', 'operator', '{\"version\":\"v1\"}', 0, NULL),
       (2, 'v2', '2026-01-03T00:00:00+00:00', 'operator', '{\"version\":\"v2\"}', 1, NULL),
       (3, 'v3', '2026-01-04T00:00:00+00:00', 'operator', '{\"version\":\"v3\"}', 0, NULL);
DELETE FROM harness_config_bundles WHERE id = 3;
INSERT INTO harness_config_proposals (id, node, agent, surface, path, bundle_version, desired_hash, status,
    approval_id, created_at, updated_at, diff_base, org_id)
VALUES ('hc-legacy', 'node-a', 'builder-1', 'claude', 'CLAUDE.md', 'v2', 'h', 'pending', NULL,
    '2026-01-03T00:00:00+00:00', '2026-01-03T00:00:00+00:00', 'none', NULL);
INSERT INTO harness_config_drift (node, surface, path, bundle_version, observed_hash, desired_hash, reported_at)
VALUES ('node-a', 'claude', 'CLAUDE.md', 'v2', NULL, 'h', '2026-01-03T00:00:00+00:00');
INSERT INTO harness_config_report_window (node, window_start, reports)
VALUES ('node-a', '2026-01-03T00:00:00+00:00', 2);
";

#[test]
fn legacy_upgrade_rebuilds_keys_and_keeps_rows_ids_indexes_triggers_and_views() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(LEGACY_ROWS)?;
            // An extra index, trigger and view, to prove the rebuild keeps them.
            tx.execute_batch(
                "CREATE INDEX idx_harness_config_bundles_by ON harness_config_bundles(published_by);
                 CREATE VIEW v_harness_pending AS
                   SELECT p.id, b.version FROM harness_config_proposals p
                   JOIN harness_config_bundles b ON b.version = p.bundle_version WHERE p.status = 'pending';
                 CREATE TRIGGER trg_harness_config_report_window_touch AFTER INSERT ON harness_config_report_window
                 BEGIN SELECT 1; END;",
            )?;
            Ok(())
        })
        .unwrap();
    }

    // Opening twice proves the upgrade is idempotent across restarts.
    for _ in 0..2 {
        let hub = Hub::open(cfg.clone()).unwrap();
        hub.db()
            .read(|c| {
                // Rows survive with their ids, in the default organization.
                let bundles: Vec<(i64, String, String, i64)> = c
                    .prepare("SELECT id, org_id, version, active FROM harness_config_bundles ORDER BY id")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                    .collect::<Result<_, _>>()?;
                assert_eq!(
                    bundles,
                    vec![(1, DEFAULT_ORG.into(), "v1".into(), 0), (2, DEFAULT_ORG.into(), "v2".into(), 1)]
                );
                let proposal: (String, String, Option<String>) = c.query_row(
                    "SELECT org_id, status, diff_base FROM harness_config_proposals WHERE id = 'hc-legacy'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                assert_eq!(proposal, (DEFAULT_ORG.into(), "pending".into(), Some("none".into())));
                let drift: String =
                    c.query_row("SELECT org_id FROM harness_config_drift WHERE node = 'node-a'", [], |r| {
                        r.get(0)
                    })?;
                assert_eq!(drift, DEFAULT_ORG);
                let window: (String, i64) = c.query_row(
                    "SELECT org_id, reports FROM harness_config_report_window WHERE node = 'node-a'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                assert_eq!(window, (DEFAULT_ORG.into(), 2));
                // The AUTOINCREMENT high-water mark is kept: id 3 was deleted
                // and is never handed out again.
                assert_eq!(
                    count(c, "SELECT seq FROM sqlite_sequence WHERE name = 'harness_config_bundles'"),
                    3
                );
                assert_eq!(
                    count(c, "SELECT COUNT(*) FROM sqlite_sequence WHERE name LIKE '%\\_new' ESCAPE '\\'"),
                    0
                );

                for t in TABLES {
                    assert_eq!(org_id_notnull(c, t), Some(1), "{t}.org_id NOT NULL");
                    for suffix in ["org_exists", "org_immutable"] {
                        assert!(object_exists(c, "trigger", &format!("{t}_{suffix}")), "{t}_{suffix}");
                    }
                }
                assert!(object_exists(c, "trigger", "trg_harness_config_report_window_touch"));
                for idx in [
                    "idx_harness_config_bundles_active",
                    "idx_harness_config_bundles_by",
                    "idx_harness_config_bundles_org_active",
                    "idx_harness_config_proposals_node",
                    "idx_harness_config_proposals_approval",
                    "idx_harness_config_proposals_org_node",
                    "idx_harness_config_drift_node",
                ] {
                    assert!(object_exists(c, "index", idx), "index {idx}");
                }
                assert!(object_exists(c, "view", "v_harness_pending"));
                assert_eq!(count(c, "SELECT COUNT(*) FROM v_harness_pending"), 1);
                for t in REBUILT {
                    assert!(!object_exists(c, "table", &format!("{t}_new")), "{t}_new left behind");
                }

                for part in PARTS {
                    let n = count(c, &format!("SELECT COUNT(*) FROM schema_parts WHERE name = '{part}'"));
                    assert_eq!(n, 1, "{part}");
                }
                assert_eq!(count(c, "PRAGMA foreign_keys"), 1, "foreign keys restored");
                Ok(())
            })
            .unwrap();
    }

    // The new keys: one per organization, enforced within one.
    let hub = Hub::open(cfg).unwrap();
    add_org(&hub, ORG_B);
    hub.db()
        .write(|tx| {
            let dup_version = "INSERT INTO harness_config_bundles
                 (org_id, version, published_at, published_by, bundle_json, active)
                 VALUES (?1, 'v1', '2026-01-05T00:00:00+00:00', 'operator', '{}', 0)";
            let err = tx.execute(dup_version, [DEFAULT_ORG]).unwrap_err().to_string();
            assert!(err.contains("UNIQUE constraint failed: harness_config_bundles.org_id"), "{err}");
            tx.execute(dup_version, [ORG_B])?;
            // The next id continues after the deleted one.
            let id: i64 =
                tx.query_row("SELECT id FROM harness_config_bundles WHERE org_id = ?1", [ORG_B], |r| {
                    r.get(0)
                })?;
            assert_eq!(id, 4);

            let dup_window = "INSERT INTO harness_config_report_window (org_id, node, window_start, reports)
                 VALUES (?1, 'node-a', '2026-01-05T00:00:00+00:00', 1)";
            let err = tx.execute(dup_window, [DEFAULT_ORG]).unwrap_err().to_string();
            assert!(err.contains("UNIQUE constraint failed: harness_config_report_window.org_id"), "{err}");
            tx.execute(dup_window, [ORG_B])?;

            // A NULL organization is refused on every table.
            let err = tx
                .execute(
                    "INSERT INTO harness_config_proposals (org_id, id, node, surface, path, bundle_version,
                       desired_hash, created_at, updated_at)
                     VALUES (NULL, 'hc-null', 'node-a', 'claude', 'CLAUDE.md', 'v1', 'h', 'now', 'now')",
                    [],
                )
                .unwrap_err()
                .to_string();
            assert!(err.contains("NOT NULL") || err.contains("unknown organization"), "{err}");
            Ok(())
        })
        .unwrap();
}

/// Review follow-up: the upgrade expires harness config approvals whose
/// payload does not bind `org_id`, inside a schema part that cannot append
/// to the ledger. `system_doctor` reports how many it expired, to a
/// default-organization reader only; an approval already carrying a reason,
/// and one still matching, are not counted.
#[tokio::test]
async fn the_doctor_reports_approvals_the_upgrade_expired() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.human_identities = vec!["operator".into()];
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO approvals (tool, payload, requested_by, status, created_at, updated_at) VALUES
                   ('harness_config_apply', '{\"node\":\"node-a\"}', 'builder-1', 'pending', 't0', 't0'),
                   ('harness_config_publish', '{\"version\":\"v9\"}', 'operator', 'approved', 't0', 't0'),
                   ('harness_config_apply', '{\"node\":\"node-a\",\"org_id\":\"default\"}', 'builder-1',
                    'pending', 't0', 't0'),
                   ('fs_write', '{\"path\":\"x\"}', 'builder-1', 'pending', 't0', 't0');
                 INSERT INTO approvals (tool, payload, requested_by, status, reason, created_at, updated_at) VALUES
                   ('harness_config_apply', '{}', 'builder-1', 'pending', 'fake earlier reason', 't0', 't0');",
            )?;
            Ok(())
        })
        .unwrap();
    }
    let hub = Hub::open(cfg).unwrap();
    add_org(&hub, ORG_B);
    let expired: i64 =
        hub.db().read(|c| Ok(count(c, "SELECT COUNT(*) FROM approvals WHERE status = 'expired'"))).unwrap();
    assert_eq!(expired, 3, "three unscoped harness config approvals were expired");
    let reg = builtin_registry();
    let doctor = |who: Caller| {
        let (reg, hub) = (&reg, &hub);
        async move { reg.call(hub, &who, "system_doctor", json!({})).await.unwrap()["database"].clone() }
    };
    let db = doctor(human()).await;
    assert_eq!(db["harness_config_approvals_expired_at_upgrade"], 2, "{db}");
    let b = Caller {
        profile: Profile::Operator,
        enforce_profile: false,
        ..caller("operator", ActorKind::Human, ORG_B)
    };
    let db_b = doctor(b).await;
    assert!(db_b["harness_config_approvals_expired_at_upgrade"].is_null(), "{db_b}");
}

#[test]
fn the_rebuild_is_safe_to_rerun_after_a_crash_before_recording() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let hub = Hub::open(cfg.clone()).unwrap();
        add_org(&hub, ORG_B);
        hub.db()
            .write(|tx| {
                for org in [DEFAULT_ORG, ORG_B] {
                    tx.execute(
                        "INSERT INTO harness_config_bundles (org_id, version, published_at, published_by,
                           bundle_json, active) VALUES (?1, 'v1', 't', 'operator', ?1, 1)",
                        [org],
                    )?;
                    tx.execute(
                        "INSERT INTO harness_config_proposals (org_id, id, node, surface, path, bundle_version,
                           desired_hash, created_at, updated_at)
                         VALUES (?1, 'hc-' || ?1, 'node-a', 'claude', 'CLAUDE.md', 'v1', 'h', 't', 't')",
                        [org],
                    )?;
                    tx.execute(
                        "INSERT INTO harness_config_drift (org_id, node, surface, path, bundle_version,
                           desired_hash, reported_at) VALUES (?1, 'node-a', 'claude', 'CLAUDE.md', 'v1', 'h', 't')",
                        [org],
                    )?;
                    tx.execute(
                        "INSERT INTO harness_config_report_window (org_id, node, window_start, reports)
                         VALUES (?1, 'node-a', 't', 1)",
                        [org],
                    )?;
                }
                // A crash right after the rebuild committed, before either
                // part was recorded and before the triggers were installed.
                let mut drop = String::new();
                for t in TABLES {
                    drop.push_str(&format!("DROP TRIGGER {t}_org_exists; DROP TRIGGER {t}_org_immutable;"));
                }
                tx.execute_batch(&drop)?;
                tx.execute_batch(
                    "DELETE FROM schema_parts WHERE name IN ('harness_config.v3.tenant_keys', 'organization.v1.tools.harness_config');
                     DELETE FROM schema_procedures WHERE name IN ('harness_config.v3.tenant_keys', 'organization.v1.tools.harness_config');",
                )?;
                Ok(())
            })
            .unwrap();
    }

    let hub = Hub::open(cfg).unwrap();
    hub.db()
        .read(|c| {
            for t in TABLES {
                let orgs: Vec<String> = c
                    .prepare(&format!("SELECT org_id FROM {t} ORDER BY org_id"))?
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                assert_eq!(orgs, [DEFAULT_ORG, ORG_B], "{t} keeps each row's organization");
                for suffix in ["org_exists", "org_immutable"] {
                    assert!(object_exists(c, "trigger", &format!("{t}_{suffix}")), "{t}_{suffix}");
                }
            }
            let bodies: Vec<String> = c
                .prepare("SELECT bundle_json FROM harness_config_bundles ORDER BY org_id")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            assert_eq!(bodies, [DEFAULT_ORG, ORG_B]);
            for part in PARTS {
                let n = count(c, &format!("SELECT COUNT(*) FROM schema_parts WHERE name = '{part}'"));
                assert_eq!(n, 1, "{part}");
            }
            assert_eq!(count(c, "PRAGMA foreign_keys"), 1);
            Ok(())
        })
        .unwrap();
}

#[test]
fn a_failed_rebuild_rolls_back_every_table_and_restores_foreign_keys() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(LEGACY_ROWS)?;
            // An open apply approval in the old payload shape: the rebuild
            // would expire it, and the rollback must undo that too.
            tx.execute(
                "INSERT INTO approvals (tool, payload, requested_by, status, created_at, updated_at)
                 VALUES ('harness_config_apply', '{\"node\":\"node-a\"}', 'builder-1', 'pending',
                   '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            // The bundles and proposals rebuild first and succeed; this stray
            // table makes the report window step fail inside the same
            // transaction.
            tx.execute_batch("CREATE TABLE harness_config_report_window_new (x INTEGER);")?;
            Ok(())
        })
        .unwrap();
    }

    let err = Hub::open(cfg.clone()).err().expect("the rebuild must fail").to_string();
    assert!(err.contains("harness_config.v3.tenant_keys"), "{err}");

    let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
    db.read(|c| {
        // The original shapes: a nullable org_id on bundles and proposals,
        // none on the report window, and the version alone unique.
        assert_eq!(org_id_notnull(c, "harness_config_bundles"), Some(0));
        assert_eq!(org_id_notnull(c, "harness_config_proposals"), Some(0));
        assert_eq!(org_id_notnull(c, "harness_config_report_window"), None);
        assert_eq!(count(c, "SELECT COUNT(*) FROM harness_config_bundles WHERE org_id IS NULL"), 2);
        assert_eq!(count(c, "SELECT COUNT(*) FROM harness_config_proposals WHERE org_id IS NULL"), 1);
        assert_eq!(count(c, "SELECT COUNT(*) FROM harness_config_report_window"), 1);
        assert_eq!(count(c, "SELECT seq FROM sqlite_sequence WHERE name = 'harness_config_bundles'"), 3);
        assert!(!object_exists(c, "table", "harness_config_bundles_new"));
        assert!(!object_exists(c, "table", "harness_config_proposals_new"));
        assert!(!object_exists(c, "index", "idx_harness_config_bundles_org_active"));
        let status: String =
            c.query_row("SELECT status FROM approvals WHERE tool = 'harness_config_apply'", [], |r| {
                r.get(0)
            })?;
        assert_eq!(status, "pending", "the approval expiry rolled back with the rebuild");
        let recorded = count(
            c,
            "SELECT COUNT(*) FROM schema_parts \
             WHERE name IN ('harness_config.v3.tenant_keys', 'organization.v1.tools.harness_config')",
        );
        assert_eq!(recorded, 0);
        assert_eq!(count(c, "PRAGMA foreign_keys"), 1);
        Ok(())
    })
    .unwrap();
}

#[test]
fn triggers_refuse_an_unknown_organization_and_a_changed_org_id() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::in_memory(Config::for_home(dir.path())).unwrap();
    add_org(&hub, ORG_B);
    let inserts = [
        (
            "harness_config_bundles",
            "INSERT INTO harness_config_bundles (org_id, version, published_at, published_by,
           bundle_json, active) VALUES (?1, 'v1', 't', 'operator', '{}', 0)",
        ),
        (
            "harness_config_proposals",
            "INSERT INTO harness_config_proposals (org_id, id, node, surface, path,
           bundle_version, desired_hash, created_at, updated_at)
           VALUES (?1, 'hc-1', 'node-a', 'claude', 'CLAUDE.md', 'v1', 'h', 't', 't')",
        ),
        (
            "harness_config_drift",
            "INSERT INTO harness_config_drift (org_id, node, surface, path, bundle_version,
           desired_hash, reported_at) VALUES (?1, 'node-a', 'claude', 'CLAUDE.md', 'v1', 'h', 't')",
        ),
        (
            "harness_config_report_window",
            "INSERT INTO harness_config_report_window (org_id, node, window_start,
           reports) VALUES (?1, 'node-a', 't', 1)",
        ),
    ];
    hub.db()
        .write(|tx| {
            for (t, sql) in inserts {
                let err = tx.execute(sql, [UNKNOWN]).unwrap_err().to_string();
                assert!(err.contains("unknown organization"), "{t}: {err}");
                tx.execute(sql, [DEFAULT_ORG])?;
                let err =
                    tx.execute(&format!("UPDATE {t} SET org_id = ?1"), [ORG_B]).unwrap_err().to_string();
                assert!(err.contains("org_id cannot change"), "{t}: {err}");
            }
            Ok(())
        })
        .unwrap();
}

// --- tools ------------------------------------------------------------------------

fn caller(label: &str, kind: ActorKind, org: &str) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

/// The node's agent. The same label in both organizations, so only the
/// organization filter tells their rows apart (labels are one hub namespace
/// in practice; this isolates the `org_id` scoping). A node belongs to the
/// organization that registered it (`organization.v1.tools.nodes`), so each
/// organization registers its own node ([`NODE`], [`NODE_B`]).
fn device(org: &str) -> Caller {
    caller("builder-1", ActorKind::Agent, org)
}

fn publisher(org: &str) -> Caller {
    Caller {
        profile: Profile::Operator,
        enforce_profile: false,
        ..caller("operator-2", ActorKind::Human, org)
    }
}

fn human() -> Caller {
    Caller {
        profile: Profile::Operator,
        enforce_profile: false,
        ..caller("operator", ActorKind::Human, DEFAULT_ORG)
    }
}

const NODE: &str = "node-a";
/// Organization B's node: node names are one hub namespace, so B cannot hold
/// a node named [`NODE`] too.
const NODE_B: &str = "node-b";

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

struct H {
    hub: Hub,
    reg: Registry,
    _ws: tempfile::TempDir,
    _home: tempfile::TempDir,
}

impl H {
    fn new() -> Self {
        let ws = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(home.path());
        cfg.human_identities = vec!["operator".into(), "operator-2".into()];
        cfg.workspace = Some(ws.path().to_path_buf());
        let h = Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), _ws: ws, _home: home };
        add_org(&h.hub, ORG_B);
        h
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{tool}({args}) failed: {e:?}"),
        }
    }

    async fn approve(&self, id: i64) {
        self.ok(&human(), "approval_resolve", json!({ "id": id, "decision": "approve" })).await;
    }

    /// Publish in the default organization through the tool, approved by a
    /// second human.
    async fn publish_default(&self, bundle: Value) -> Value {
        let args = json!({ "bundle": bundle });
        let who = publisher(DEFAULT_ORG);
        let parked = self.call(&who, "harness_config_publish", args.clone()).await.unwrap_err();
        let UaError::ApprovalRequired { approval_id, .. } = parked else {
            panic!("expected an approval: {parked:?}")
        };
        self.approve(approval_id).await;
        self.ok(&who, "harness_config_publish", args).await
    }

    /// Organization B's active bundle. B's callers cannot hold operator
    /// authority until memberships exist (`ua_org::authz` admits only the
    /// default organization, so `harness_config_publish` refuses them), so it
    /// is written as B's publish would write it.
    fn seed_bundle(&self, org: &str, bundle: Value) {
        let json = policy::validate(&bundle).unwrap().to_json();
        let version = bundle["version"].as_str().unwrap().to_string();
        let org = org.to_string();
        self.hub
            .db()
            .write(move |tx| {
                tx.execute(
                    "UPDATE harness_config_bundles SET active = 0 WHERE org_id = ?1 AND active = 1",
                    [&org],
                )?;
                tx.execute(
                    "INSERT INTO harness_config_bundles (org_id, version, published_at, published_by, bundle_json,
                       active) VALUES (?1, ?2, '2026-01-02T00:00:00+00:00', 'operator-2', ?3, 1)",
                    rusqlite::params![org, version, json],
                )?;
                Ok(())
            })
            .unwrap();
    }

    async fn register(&self, who: &Caller, node: &str) {
        self.ok(who, "node_register", json!({ "node": node })).await;
    }

    async fn config(&self, who: &Caller, node: &str, args: Value) -> Result<Value, UaError> {
        let mut args = args;
        args["node"] = json!(node);
        self.call(who, "node_config", args).await
    }

    async fn report(&self, who: &Caller, node: &str, got: &Value, surface: &str) -> Value {
        let args = json!({
            "action": "report",
            "bundle_version": got["version"],
            "proposals": [proposal(got, surface)],
        });
        match self.config(who, node, args).await {
            Ok(v) => v,
            Err(e) => panic!("report failed: {e:?}"),
        }
    }

    fn scalar(&self, sql: &str) -> i64 {
        self.hub.db().read(|c| Ok(count(c, sql))).unwrap()
    }

    fn text(&self, sql: &str) -> String {
        self.hub.db().read(|c| Ok(c.query_row(sql, [], |r| r.get::<_, String>(0))?)).unwrap()
    }

    fn counts(&self) -> Vec<i64> {
        self.hub
            .db()
            .read(|c| {
                Ok(TABLES
                    .iter()
                    .chain(&["approvals", "event_log"])
                    .map(|t| count(c, &format!("SELECT COUNT(*) FROM {t}")))
                    .collect())
            })
            .unwrap()
    }
}

fn proposal(get: &Value, surface: &str) -> Value {
    let r = &get["rendered"][surface];
    json!({ "surface": surface, "path": r["path"], "desired_hash": r["hash"], "observed_hash": null })
}

#[tokio::test]
async fn each_organization_serves_and_reads_only_its_own_bundle_and_proposals() {
    let h = H::new();
    // B holds version v1 first; the default organization publishes its own
    // v1 through the tool, with no version conflict.
    h.seed_bundle(ORG_B, json!({ "version": "v1", "rules": { "claude": "org b rules\n" } }));
    let out = h.publish_default(json!({ "version": "v1", "rules": { "claude": "default rules\n" } })).await;
    assert_eq!(out["version"], "v1");
    assert_eq!(
        h.scalar("SELECT COUNT(*) FROM harness_config_bundles WHERE version = 'v1' AND active = 1"),
        2
    );
    // Publishing again in default refuses its own version only.
    let e = h
        .call(&publisher(DEFAULT_ORG), "harness_config_publish", json!({ "bundle": { "version": "v1" } }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "version_published", "{e:?}");

    h.register(&device(DEFAULT_ORG), NODE).await;
    h.register(&device(ORG_B), NODE_B).await;
    let (a, b) = (device(DEFAULT_ORG), device(ORG_B));

    // Each organization's node is served its own organization's bundle.
    let got_a = h.config(&a, NODE, json!({})).await.unwrap();
    assert_eq!(got_a["rendered"]["claude"]["content"], "default rules\n", "{got_a}");
    let got_b = h.config(&b, NODE_B, json!({})).await.unwrap();
    assert_eq!(got_b["rendered"]["claude"]["content"], "org b rules\n", "{got_b}");
    let status_a = h.ok(&a, "harness_config_status", json!({})).await;
    assert_eq!(status_a["active"]["bundle"]["rules"]["claude"], "default rules\n", "{status_a}");
    let status_b = h.ok(&b, "harness_config_status", json!({})).await;
    assert_eq!(status_b["active"]["bundle"]["rules"]["claude"], "org b rules\n", "{status_b}");

    // A drift report in default is invisible to B, and B's to default.
    let r_a = h.report(&a, NODE, &got_a, "claude").await;
    let status_b = h.ok(&b, "harness_config_status", json!({})).await;
    assert_eq!(status_b["pending_proposals"], 0, "{status_b}");
    assert_eq!(status_b["recent_proposals"], json!([]), "{status_b}");
    let r_b = h.report(&b, NODE_B, &got_b, "claude").await;
    assert_ne!(r_a["proposals"][0]["proposal_id"], r_b["proposals"][0]["proposal_id"]);
    let status_a = h.ok(&a, "harness_config_status", json!({})).await;
    assert_eq!(status_a["pending_proposals"], 1, "{status_a}");
    let ids: Vec<&Value> =
        status_a["recent_proposals"].as_array().unwrap().iter().map(|p| &p["id"]).collect();
    assert_eq!(ids, [&r_a["proposals"][0]["proposal_id"]]);
    let status_b = h.ok(&b, "harness_config_status", json!({})).await;
    let ids: Vec<&Value> =
        status_b["recent_proposals"].as_array().unwrap().iter().map(|p| &p["id"]).collect();
    assert_eq!(ids, [&r_b["proposals"][0]["proposal_id"]]);

    // One proposal, drift row and report window per organization, each for
    // its own node.
    for t in ["harness_config_proposals", "harness_config_drift", "harness_config_report_window"] {
        for org in [DEFAULT_ORG, ORG_B] {
            assert_eq!(h.scalar(&format!("SELECT COUNT(*) FROM {t} WHERE org_id = '{org}'")), 1, "{t} {org}");
        }
    }

    // Each approval binds its own organization; approving A's grants B nothing.
    let a_id = r_a["proposals"][0]["approval_id"].as_i64().unwrap();
    h.approve(a_id).await;
    let got_b = h.config(&b, NODE_B, json!({})).await.unwrap();
    assert_eq!(got_b["apply_grants"], json!([]), "{got_b}");
    let got_a = h.config(&a, NODE, json!({})).await.unwrap();
    assert_eq!(got_a["apply_grants"].as_array().unwrap().len(), 1, "{got_a}");

    // A's applied consumes A's pass and leaves B's proposal pending.
    let applied = |hash: &Value| json!({ "action": "applied", "surface": "claude", "desired_hash": hash });
    h.config(&a, NODE, applied(&got_a["rendered"]["claude"]["hash"])).await.unwrap();
    assert_eq!(
        h.text(&format!(
            "SELECT status FROM harness_config_proposals WHERE id = '{}'",
            r_b["proposals"][0]["proposal_id"].as_str().unwrap()
        )),
        "pending"
    );

    // Every event names the default organization (ORG-EVENT-DEFAULT).
    assert_eq!(
        h.scalar(
            "SELECT COUNT(*) FROM event_log WHERE channel = 'agent.harness_config' AND org_id <> 'default'"
        ),
        0
    );
}

#[tokio::test]
async fn an_apply_approval_is_never_consumed_across_organizations() {
    let h = H::new();
    // Identical bundles: the same agent, surface, path, version and hash in
    // both organizations (each on its own node: node names are one hub
    // namespace).
    let bundle = json!({ "version": "v1", "rules": { "claude": "same rules\n" } });
    h.publish_default(bundle.clone()).await;
    h.seed_bundle(ORG_B, bundle);
    h.register(&device(DEFAULT_ORG), NODE).await;
    h.register(&device(ORG_B), NODE_B).await;
    let (a, b) = (device(DEFAULT_ORG), device(ORG_B));
    let got_a = h.config(&a, NODE, json!({})).await.unwrap();
    let got_b = h.config(&b, NODE_B, json!({})).await.unwrap();
    let hash = got_a["rendered"]["claude"]["hash"].clone();
    assert_eq!(got_b["rendered"]["claude"]["hash"], hash);

    let applied = json!({ "action": "applied", "surface": "claude", "desired_hash": hash });
    // Before B reports, A's pending proposal answers B exactly as a missing
    // one (on a surface neither reported).
    let r_a = h.report(&a, NODE, &got_a, "claude").await;
    let a_id = r_a["proposals"][0]["approval_id"].as_i64().unwrap();
    let e = h.config(&b, NODE_B, applied.clone()).await.unwrap_err();
    let agents_hash = got_b["rendered"]["agents"]["hash"].clone();
    let missing = h
        .config(&b, NODE_B, json!({ "action": "applied", "surface": "agents", "desired_hash": agents_hash }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), missing.code());
    assert_eq!(e.to_string(), missing.to_string());
    assert_eq!(e.code(), "not_found", "{e:?}");

    let r_b = h.report(&b, NODE_B, &got_b, "claude").await;
    let b_id = r_b["proposals"][0]["approval_id"].as_i64().unwrap();
    assert_ne!(a_id, b_id, "each organization parks its own approval");
    // Identical observations in two organizations are two drift rows.
    for org in [DEFAULT_ORG, ORG_B] {
        assert_eq!(
            h.scalar(&format!("SELECT COUNT(*) FROM harness_config_drift WHERE org_id = '{org}'")),
            1,
            "{org}"
        );
    }
    let payload = |id: i64| -> Value {
        serde_json::from_str(&h.text(&format!("SELECT payload FROM approvals WHERE id = {id}"))).unwrap()
    };
    assert_eq!(payload(a_id)["org_id"], DEFAULT_ORG);
    assert_eq!(payload(b_id)["org_id"], ORG_B);

    // Approving A's pass does not let B apply: B parks on its own approval.
    h.approve(a_id).await;
    let e = h.config(&b, NODE_B, applied.clone()).await.unwrap_err();
    assert!(matches!(e, UaError::ApprovalRequired { approval_id, .. } if approval_id == b_id), "{e:?}");
    assert_eq!(h.text(&format!("SELECT status FROM approvals WHERE id = {a_id}")), "approved");
    // A still holds and consumes its own pass.
    h.config(&a, NODE, applied).await.unwrap();
    assert_eq!(h.text(&format!("SELECT status FROM approvals WHERE id = {a_id}")), "consumed");

    // What A applied is not B's base: B's re-report binds the same change
    // (from nothing) and reuses its approval.
    let again = h.report(&b, NODE_B, &got_b, "claude").await;
    assert_eq!(again["proposals"][0]["approval_id"], b_id, "{again}");
    assert_eq!(payload(b_id)["change_summary"]["base"], "none");
}

#[tokio::test]
async fn organization_b_writes_through_the_tools_land_in_organization_b() {
    let h = H::new();
    let b = caller("builder-b", ActorKind::Agent, ORG_B);
    h.seed_bundle(ORG_B, json!({ "version": "v7", "rules": { "claude": "org b rules\n" } }));
    h.register(&b, "node-b").await;
    let got = h.config(&b, "node-b", json!({})).await.unwrap();
    assert_eq!(got["version"], "v7");

    let r = h.report(&b, "node-b", &got, "claude").await;
    let proposal_id = r["proposals"][0]["proposal_id"].as_str().unwrap().to_string();
    let approval_id = r["proposals"][0]["approval_id"].as_i64().unwrap();
    assert_eq!(
        h.text(&format!("SELECT org_id FROM harness_config_proposals WHERE id = '{proposal_id}'")),
        ORG_B
    );
    assert_eq!(h.text("SELECT org_id FROM harness_config_drift WHERE node = 'node-b'"), ORG_B);
    assert_eq!(h.text("SELECT org_id FROM harness_config_report_window WHERE node = 'node-b'"), ORG_B);
    for t in ["harness_config_proposals", "harness_config_drift", "harness_config_report_window"] {
        assert_eq!(h.scalar(&format!("SELECT COUNT(*) FROM {t} WHERE org_id <> '{ORG_B}'")), 0, "{t}");
    }
    let payload: Value =
        serde_json::from_str(&h.text(&format!("SELECT payload FROM approvals WHERE id = {approval_id}")))
            .unwrap();
    assert_eq!(payload["org_id"], ORG_B);

    // The approver is shown B's own diff beside B's approval, never a
    // default-organization row that names the same approval id.
    h.hub
        .db()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO harness_config_proposals (org_id, id, node, surface, path, bundle_version, desired_hash,
                   diff_text, diff_base, approval_id, created_at, updated_at)
                 VALUES ('default', 'hc-default-decoy', 'node-b', 'claude', 'CLAUDE.md', 'v7', 'h',
                   '+default secret', 'none', ?1, '2999-01-01T00:00:00+00:00', '2999-01-01T00:00:00+00:00')",
                [approval_id],
            )?;
            Ok(())
        })
        .unwrap();
    // The approval is in organization B's queue (its requester's), and only
    // there.
    let b_human = Caller { org_id: ORG_B.into(), ..human() };
    let queue = h.ok(&human(), "approval_pending", json!({})).await;
    assert!(queue["pending"].as_array().unwrap().iter().all(|a| a["id"] != approval_id), "{queue}");
    let queue = h.ok(&b_human, "approval_pending", json!({})).await;
    let row = queue["pending"].as_array().unwrap().iter().find(|a| a["id"] == approval_id).cloned().unwrap();
    assert_eq!(row["display"]["proposal_id"], proposal_id.as_str(), "{row}");
    assert!(row["display"]["diff"].as_str().unwrap().contains("+org b rules"), "{row}");

    // A second report in B counts against B's window.
    h.report(&b, "node-b", &got, "claude").await;
    assert_eq!(
        h.scalar(
            "SELECT reports FROM harness_config_report_window WHERE org_id = 'org-b' AND node = 'node-b'"
        ),
        2
    );

    // A default-organization human cannot resolve it (it answers as a
    // missing approval), and `ua_org::authz` admits no organization-B human
    // yet, so the pass is granted by SQL.
    let e = h.call(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    assert_eq!(e.unwrap_err().to_string(), UaError::not_found(format!("approval {approval_id}")).to_string());
    h.hub
        .db()
        .write(move |tx| {
            tx.execute(
                "UPDATE approvals SET status = 'approved', resolved_by = 'operator', resolved_at = ?2, \
                 updated_at = ?2 WHERE org_id = 'org-b' AND id = ?1",
                rusqlite::params![approval_id, ua_core::time::now()],
            )?;
            Ok(())
        })
        .unwrap();
    let applied = json!({ "action": "applied", "surface": "claude", "desired_hash": got["rendered"]["claude"]["hash"] });
    let out = h.config(&b, "node-b", applied).await.unwrap();
    assert_eq!(out["proposal_id"], proposal_id.as_str());
    assert_eq!(
        h.text(&format!(
            "SELECT org_id || ':' || status FROM harness_config_proposals WHERE id = '{proposal_id}'"
        )),
        format!("{ORG_B}:applied")
    );

    // B's publish is refused by authority (not by a missing organization)
    // before anything changes.
    let before = h.counts();
    let e = h
        .call(&publisher(ORG_B), "harness_config_publish", json!({ "bundle": { "version": "v8" } }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "operator_required", "{e:?}");
    assert_eq!(h.counts(), before);
}

#[tokio::test]
async fn an_unknown_organization_is_refused_before_any_write() {
    let h = H::new();
    let bundle = json!({ "version": "v1", "rules": { "claude": "rules\n" } });
    h.publish_default(bundle.clone()).await;
    h.register(&device(DEFAULT_ORG), NODE).await;
    let got = h.config(&device(DEFAULT_ORG), NODE, json!({})).await.unwrap();
    let r = h.report(&device(DEFAULT_ORG), NODE, &got, "claude").await;
    h.approve(r["proposals"][0]["approval_id"].as_i64().unwrap()).await;

    let ghost = device(UNKNOWN);
    let before = h.counts();
    let e =
        h.call(&publisher(UNKNOWN), "harness_config_publish", json!({ "bundle": bundle })).await.unwrap_err();
    assert_eq!(reason(&e), "unknown_organization", "{e:?}");
    let report =
        json!({ "action": "report", "bundle_version": "v1", "proposals": [proposal(&got, "claude")] });
    let e = h.config(&ghost, NODE, report).await.unwrap_err();
    assert_eq!(reason(&e), "unknown_organization", "{e:?}");
    // Nothing to insert: the existence trigger would never fire.
    let applied = json!({ "action": "applied", "surface": "claude", "desired_hash": got["rendered"]["claude"]["hash"] });
    let e = h.config(&ghost, NODE, applied).await.unwrap_err();
    assert_eq!(reason(&e), "unknown_organization", "{e:?}");
    assert_eq!(h.counts(), before);

    // Reads in an unknown organization are refused too: the registry
    // refuses the organization before any tool runs.
    let e = h.config(&ghost, NODE, json!({})).await.unwrap_err();
    assert_eq!(reason(&e), "unknown_organization", "{e:?}");
    let e = h.call(&ghost, "harness_config_status", json!({})).await.unwrap_err();
    assert_eq!(reason(&e), "unknown_organization", "{e:?}");
}

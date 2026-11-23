//! Organization keys, the standalone table rebuild and tool isolation for the
//! skill registry tables (`skill_versions`, `skill_assignments`,
//! `skill_publish_staging`).

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 2] = ["skill_registry.v2.tenant_keys", "organization.v1.tools.skills"];
const TABLES: [&str; 3] = ["skill_versions", "skill_assignments", "skill_publish_staging"];

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

const LEGACY_ROWS: &str = "
INSERT INTO skill_versions (id, name, version, content_hash, source, content, published_by, published_at)
VALUES (1, 'review-diff', 1, 'h1', 'skills/review-diff/SKILL.md', 'one', 'ops-bot', '2026-01-02T00:00:00+00:00'),
       (2, 'review-diff', 2, 'h2', 'skills/review-diff/SKILL.md', 'two', 'ops-bot', '2026-01-03T00:00:00+00:00');
INSERT INTO skill_assignments (id, skill_name, target_type, target, pinned_version, assigned_by, assigned_at)
VALUES (1, 'review-diff', 'agent', 'builder-1', 2, 'ops-bot', '2026-01-04T00:00:00+00:00'),
       (2, 'review-diff', 'profile', 'developer', 1, 'ops-bot', '2026-01-04T00:00:00+00:00'),
       (3, 'review-diff', 'agent', 'builder-9', 1, 'ops-bot', '2026-01-04T00:00:00+00:00');
DELETE FROM skill_assignments WHERE id = 3;
INSERT INTO skill_publish_staging (id, name, content, content_hash, source, requested_by, created_at)
VALUES ('sk-legacy', 'review-diff', 'two', 'h2', 'skills/review-diff/SKILL.md', 'ops-bot', '2026-01-03T00:00:00+00:00');
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
                "CREATE INDEX idx_skill_assignments_by ON skill_assignments(assigned_by);
                 CREATE VIEW v_skill_pins AS
                   SELECT a.target, v.version FROM skill_assignments a
                   JOIN skill_versions v ON v.name = a.skill_name AND v.version = a.pinned_version;
                 CREATE TRIGGER trg_skill_assignments_touch AFTER INSERT ON skill_assignments
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
                let versions: Vec<(i64, String, String, i64, String)> = c
                    .prepare("SELECT id, org_id, name, version, content FROM skill_versions ORDER BY id")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
                    .collect::<Result<_, _>>()?;
                assert_eq!(
                    versions,
                    vec![
                        (1, DEFAULT_ORG.into(), "review-diff".into(), 1, "one".into()),
                        (2, DEFAULT_ORG.into(), "review-diff".into(), 2, "two".into()),
                    ]
                );
                let assignments: Vec<(i64, String, String, Option<i64>)> = c
                    .prepare("SELECT id, org_id, target, pinned_version FROM skill_assignments ORDER BY id")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                    .collect::<Result<_, _>>()?;
                assert_eq!(
                    assignments,
                    vec![
                        (1, DEFAULT_ORG.into(), "builder-1".into(), Some(2)),
                        (2, DEFAULT_ORG.into(), "developer".into(), Some(1)),
                    ]
                );
                let staged: String = c.query_row(
                    "SELECT org_id FROM skill_publish_staging WHERE id = 'sk-legacy'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(staged, DEFAULT_ORG);
                // The AUTOINCREMENT high-water mark is kept: id 3 was deleted
                // and is never handed out again.
                assert_eq!(count(c, "SELECT seq FROM sqlite_sequence WHERE name = 'skill_assignments'"), 3);
                assert_eq!(count(c, "SELECT seq FROM sqlite_sequence WHERE name = 'skill_versions'"), 2);
                assert_eq!(
                    count(c, "SELECT COUNT(*) FROM sqlite_sequence WHERE name LIKE '%\\_new' ESCAPE '\\'"),
                    0
                );

                for t in TABLES {
                    let notnull = count(
                        c,
                        &format!("SELECT \"notnull\" FROM pragma_table_info('{t}') WHERE name = 'org_id'"),
                    );
                    assert_eq!(notnull, 1, "{t}.org_id NOT NULL");
                    for suffix in ["org_exists", "org_immutable"] {
                        assert!(object_exists(c, "trigger", &format!("{t}_{suffix}")), "{t}_{suffix}");
                    }
                }
                for trg in [
                    "skill_versions_immutable_update",
                    "skill_versions_immutable_delete",
                    "trg_skill_assignments_touch",
                ] {
                    assert!(object_exists(c, "trigger", trg), "trigger {trg}");
                }
                for idx in [
                    "idx_skill_versions_name",
                    "idx_skill_versions_name_hash",
                    "idx_skill_versions_org_name",
                    "idx_skill_assignments_target",
                    "idx_skill_assignments_org_target",
                    "idx_skill_assignments_by",
                ] {
                    assert!(object_exists(c, "index", idx), "index {idx}");
                }
                assert!(object_exists(c, "view", "v_skill_pins"));
                assert_eq!(count(c, "SELECT COUNT(*) FROM v_skill_pins"), 2);

                for part in PARTS {
                    let n = count(c, &format!("SELECT COUNT(*) FROM schema_parts WHERE name = '{part}'"));
                    assert_eq!(n, 1, "{part}");
                }
                assert_eq!(count(c, "PRAGMA foreign_keys"), 1, "foreign keys restored");
                Ok(())
            })
            .unwrap();
    }

    // The new unique keys: one per organization, enforced within one.
    let hub = Hub::open(cfg).unwrap();
    add_org(&hub, ORG_B);
    hub.db()
        .write(|tx| {
            let dup_version = "INSERT INTO skill_versions
                 (org_id, name, version, content_hash, source, content, published_at)
                 VALUES (?1, 'review-diff', 1, 'hb', 's', 'b', '2026-01-05T00:00:00+00:00')";
            let err = tx.execute(dup_version, [DEFAULT_ORG]).unwrap_err().to_string();
            assert!(err.contains("UNIQUE constraint failed: skill_versions.org_id"), "{err}");
            tx.execute(dup_version, [ORG_B])?;

            let dup_assignment = "INSERT INTO skill_assignments
                 (org_id, skill_name, target_type, target, pinned_version, assigned_at)
                 VALUES (?1, 'review-diff', 'agent', 'builder-1', 1, '2026-01-05T00:00:00+00:00')";
            let err = tx.execute(dup_assignment, [DEFAULT_ORG]).unwrap_err().to_string();
            assert!(err.contains("UNIQUE constraint failed: skill_assignments.org_id"), "{err}");
            tx.execute(dup_assignment, [ORG_B])?;
            // The next id continues after the deleted one.
            let id: i64 =
                tx.query_row("SELECT id FROM skill_assignments WHERE org_id = ?1", [ORG_B], |r| r.get(0))?;
            assert_eq!(id, 4);

            // Versions stay immutable after the rebuild.
            let err = tx.execute("UPDATE skill_versions SET content = 'x' WHERE id = 1", []).unwrap_err();
            assert!(err.to_string().contains("immutable"), "{err}");
            let err = tx.execute("DELETE FROM skill_versions WHERE id = 1", []).unwrap_err();
            assert!(err.to_string().contains("immutable"), "{err}");
            Ok(())
        })
        .unwrap();
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
                        "INSERT INTO skill_versions (org_id, name, version, content_hash, source, content, published_at)
                         VALUES (?1, 'shared', 1, 'h', 's', ?1, '2026-01-02T00:00:00+00:00')",
                        [org],
                    )?;
                    tx.execute(
                        "INSERT INTO skill_assignments (org_id, skill_name, target_type, target, assigned_at)
                         VALUES (?1, 'shared', 'agent', 'builder-1', '2026-01-02T00:00:00+00:00')",
                        [org],
                    )?;
                }
                // A crash right after the rebuild committed, before either
                // part was recorded and before the triggers were installed.
                let mut drop = String::new();
                for t in TABLES {
                    drop.push_str(&format!(
                        "DROP TRIGGER {t}_org_exists; DROP TRIGGER {t}_org_immutable;"
                    ));
                }
                tx.execute_batch(&drop)?;
                tx.execute_batch(
                    "DELETE FROM schema_parts WHERE name IN ('skill_registry.v2.tenant_keys', 'organization.v1.tools.skills');
                     DELETE FROM schema_procedures WHERE name IN ('skill_registry.v2.tenant_keys', 'organization.v1.tools.skills');",
                )?;
                Ok(())
            })
            .unwrap();
    }

    let hub = Hub::open(cfg).unwrap();
    hub.db()
        .read(|c| {
            for t in ["skill_versions", "skill_assignments"] {
                let orgs: Vec<String> = c
                    .prepare(&format!("SELECT org_id FROM {t} ORDER BY org_id"))?
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                assert_eq!(orgs, [DEFAULT_ORG, ORG_B], "{t} keeps each row's organization");
            }
            let contents: Vec<String> = c
                .prepare("SELECT content FROM skill_versions ORDER BY org_id")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            assert_eq!(contents, [DEFAULT_ORG, ORG_B]);
            for t in TABLES {
                for suffix in ["org_exists", "org_immutable"] {
                    assert!(object_exists(c, "trigger", &format!("{t}_{suffix}")), "{t}_{suffix}");
                }
            }
            assert!(object_exists(c, "trigger", "skill_versions_immutable_update"));
            assert!(object_exists(c, "trigger", "skill_versions_immutable_delete"));
            assert_eq!(count(c, "PRAGMA foreign_keys"), 1);
            Ok(())
        })
        .unwrap();
}

#[test]
fn a_failed_rebuild_rolls_back_both_tables_and_restores_foreign_keys() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(LEGACY_ROWS)?;
            // `skill_versions` rebuilds first and succeeds; this stray table
            // makes the `skill_assignments` step fail inside the same
            // transaction.
            tx.execute_batch("CREATE TABLE skill_assignments_new (x INTEGER);")?;
            Ok(())
        })
        .unwrap();
    }

    let err = Hub::open(cfg.clone()).err().expect("the rebuild must fail").to_string();
    assert!(err.contains("skill_registry.v2.tenant_keys"), "{err}");

    let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
    db.read(|c| {
        for t in ["skill_versions", "skill_assignments"] {
            let has_org =
                count(c, &format!("SELECT COUNT(*) FROM pragma_table_info('{t}') WHERE name = 'org_id'"));
            assert_eq!(has_org, 0, "{t} keeps its original shape");
        }
        assert_eq!(count(c, "SELECT COUNT(*) FROM skill_versions"), 2);
        assert_eq!(count(c, "SELECT COUNT(*) FROM skill_assignments"), 2);
        assert!(object_exists(c, "trigger", "skill_versions_immutable_update"));
        assert!(object_exists(c, "trigger", "skill_versions_immutable_delete"));
        assert!(!object_exists(c, "table", "skill_versions_new"));
        let recorded = count(
            c,
            "SELECT COUNT(*) FROM schema_parts \
             WHERE name IN ('skill_registry.v2.tenant_keys', 'organization.v1.tools.skills')",
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
        "INSERT INTO skill_versions (org_id, name, version, content_hash, source, content, published_at)
         VALUES (?1, 'x', 1, 'h', 's', 'c', '2026-01-02T00:00:00+00:00')",
        "INSERT INTO skill_assignments (org_id, skill_name, target_type, target, assigned_at)
         VALUES (?1, 'x', 'agent', 'builder-1', '2026-01-02T00:00:00+00:00')",
        "INSERT INTO skill_publish_staging (org_id, id, name, content, content_hash, source, requested_by, created_at)
         VALUES (?1, 'sk-1', 'x', 'c', 'h', 's', 'ops-bot', '2026-01-02T00:00:00+00:00')",
    ];
    hub.db()
        .write(|tx| {
            for sql in inserts {
                let err = tx.execute(sql, [UNKNOWN]).unwrap_err().to_string();
                assert!(err.contains("unknown organization"), "{sql}: {err}");
                tx.execute(sql, [DEFAULT_ORG])?;
            }
            // `skill_versions` refuses every update; the other two refuse a
            // changed org_id.
            for t in ["skill_assignments", "skill_publish_staging"] {
                let err =
                    tx.execute(&format!("UPDATE {t} SET org_id = ?1"), [ORG_B]).unwrap_err().to_string();
                assert!(err.contains("org_id cannot change"), "{t}: {err}");
            }
            let err = tx.execute("UPDATE skill_versions SET org_id = ?1", [ORG_B]).unwrap_err().to_string();
            assert!(err.contains("immutable") || err.contains("org_id cannot change"), "{err}");
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

/// A lifecycle operator (an agent) of `org`: it changes the registry, a
/// human approves.
fn ops(org: &str) -> Caller {
    caller("ops-bot", ActorKind::Agent, org)
}

fn device(org: &str) -> Caller {
    caller("builder-1", ActorKind::Agent, org)
}

fn human() -> Caller {
    Caller {
        profile: Profile::Operator,
        enforce_profile: false,
        ..caller("operator", ActorKind::Human, DEFAULT_ORG)
    }
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
        cfg.lifecycle_operators = Some(vec!["operator".into(), "ops-bot".into()]);
        cfg.workspace = Some(ws.path().to_path_buf());
        let h = Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), _ws: ws, _home: home };
        add_org(&h.hub, ORG_B);
        h
    }

    async fn call(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, "skill_registry", json!({ "action": action, "params": params })).await
    }

    async fn ok(&self, who: &Caller, action: &str, params: Value) -> Value {
        match self.call(who, action, params.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{action}({params}) failed: {e:?}"),
        }
    }

    async fn approve(&self, id: i64) {
        self.reg
            .call(&self.hub, &human(), "approval_resolve", json!({ "id": id, "decision": "approve" }))
            .await
            .unwrap();
    }

    /// Park the call, approve it as the human operator, and retry it.
    async fn gated(&self, who: &Caller, action: &str, params: Value) -> Value {
        let parked = self.call(who, action, params.clone()).await.unwrap_err();
        let UaError::ApprovalRequired { approval_id, .. } = parked else {
            panic!("expected an approval: {parked:?}")
        };
        self.approve(approval_id).await;
        self.ok(who, action, params).await
    }

    fn write_skill(&self, name: &str, body: &str) {
        let dir = self.hub.cfg().workspace_root().join("skills").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let md = format!(
            "---\nname: {name}\ndescription: Check a change for correctness. Use when asked to review a diff \
             before it lands.\n---\n\n# Check a change\n\n{body}\n"
        );
        std::fs::write(dir.join("SKILL.md"), md).unwrap();
    }

    /// Stage, approve and publish a skill in the default organization.
    async fn publish(&self, name: &str) -> Value {
        let staged = self
            .ok(&ops(DEFAULT_ORG), "publish", json!({ "name": name, "path": format!("skills/{name}") }))
            .await;
        assert_eq!(staged["status"], "approval_pending", "{staged}");
        self.approve(staged["approval_id"].as_i64().unwrap()).await;
        self.ok(&ops(DEFAULT_ORG), "publish", json!({ "staging_id": staged["staging_id"] })).await
    }

    fn counts(&self) -> Vec<i64> {
        self.hub
            .db()
            .read(|c| {
                Ok(["skill_versions", "skill_assignments", "skill_publish_staging", "approvals", "event_log"]
                    .iter()
                    .map(|t| count(c, &format!("SELECT COUNT(*) FROM {t}")))
                    .collect())
            })
            .unwrap()
    }

    fn scalar(&self, sql: &str) -> i64 {
        self.hub.db().read(|c| Ok(count(c, sql))).unwrap()
    }
}

/// Organization B's rows for the same skill name, version, assignment
/// target and staged publish. B's callers cannot hold operator authority
/// until memberships exist (`ua_org::authz` refuses any organization but the
/// default), so B's rows are written as B's publish and assign would write
/// them.
fn seed_org_b(h: &H) {
    h.hub
        .db()
        .write(|tx| {
            let hash = ua_tools::families::harness_config::render::content_hash("org b body");
            tx.execute(
                "INSERT INTO skill_versions (org_id, name, version, content_hash, source, content, published_by,
                   published_at)
                 VALUES (?1, 'review-diff', 1, ?2, 'skills/review-diff/SKILL.md', 'org b body', 'ops-bot',
                   '2026-01-02T00:00:00+00:00')",
                rusqlite::params![ORG_B, hash],
            )?;
            tx.execute(
                "INSERT INTO skill_assignments (org_id, skill_name, target_type, target, pinned_version,
                   assigned_by, assigned_at)
                 VALUES (?1, 'review-diff', 'agent', 'builder-1', 1, 'ops-bot', '2026-01-02T00:00:00+00:00')",
                [ORG_B],
            )?;
            tx.execute(
                "INSERT INTO skill_publish_staging (org_id, id, name, content, content_hash, source, requested_by,
                   created_at)
                 VALUES (?1, 'sk-org-b', 'review-diff', 'org b body', ?2, 'skills/review-diff/SKILL.md', 'ops-bot',
                   '2026-01-02T00:00:00+00:00')",
                rusqlite::params![ORG_B, hash],
            )?;
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn two_organizations_hold_the_same_skill_independently() {
    let h = H::new();
    h.write_skill("review-diff", "Read the whole diff.");
    h.write_skill("only-default", "Read the tests.");

    // Default publishes, assigns and stages through the tools.
    let a = h.publish("review-diff").await;
    assert_eq!(a["skill"]["version"], 1, "{a}");
    let a_hash = a["skill"]["content_hash"].clone();
    h.publish("only-default").await;
    h.gated(&ops(DEFAULT_ORG), "assign", json!({ "skill_name": "review-diff", "target": "builder-1" })).await;

    // B holds the same name, version, assignment target and a staged copy.
    seed_org_b(&h);
    assert_eq!(h.scalar("SELECT COUNT(*) FROM skill_versions WHERE name = 'review-diff' AND version = 1"), 2);
    assert_eq!(h.scalar("SELECT COUNT(*) FROM skill_assignments WHERE target = 'builder-1'"), 2);

    // Each organization reads only its own versions.
    let listed = h.ok(&device(DEFAULT_ORG), "list", json!({})).await;
    let names: Vec<&str> =
        listed["skills"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["only-default", "review-diff"]);
    assert_eq!(listed["skills"][1]["content_hash"], a_hash);
    let listed_b = h.ok(&device(ORG_B), "list", json!({})).await;
    assert_eq!(listed_b["skills"].as_array().unwrap().len(), 1, "{listed_b}");
    assert_eq!(listed_b["skills"][0]["name"], "review-diff");
    assert_ne!(listed_b["skills"][0]["content_hash"], a_hash);

    let got_a = h.ok(&device(DEFAULT_ORG), "get", json!({ "name": "review-diff", "version": 1 })).await;
    assert!(got_a["content"].as_str().unwrap().contains("Read the whole diff."), "{got_a}");
    let got_b = h.ok(&device(ORG_B), "get", json!({ "name": "review-diff" })).await;
    assert_eq!(got_b["content"], "org b body");
    // Another organization's skill answers exactly as a missing one.
    let e = h.call(&device(ORG_B), "get", json!({ "name": "only-default" })).await.unwrap_err();
    let missing = h.call(&device(ORG_B), "get", json!({ "name": "no-such-skill" })).await.unwrap_err();
    assert_eq!(e.code(), missing.code());
    assert_eq!(e.code(), "not_found");

    // Each organization's agent resolves to its own organization's assignment.
    let r_a = h.ok(&device(DEFAULT_ORG), "resolve", json!({ "agent_label": "builder-1" })).await;
    assert_eq!(r_a["skills"].as_array().unwrap().len(), 1, "{r_a}");
    assert_eq!(r_a["skills"][0]["hash"], a_hash);
    let r_b = h.ok(&device(ORG_B), "resolve", json!({ "agent_label": "builder-1" })).await;
    assert_eq!(r_b["skills"].as_array().unwrap().len(), 1, "{r_b}");
    assert_eq!(r_b["skills"][0]["content"], "org b body");

    // Drift compares with the caller's organization's registry only.
    let drift = h.ok(&ops(DEFAULT_ORG), "drift", json!({ "surface_dir": "skills" })).await;
    assert_eq!(drift["synced"].as_array().unwrap().len(), 2, "{drift}");
    let drift_b = h.ok(&device(ORG_B), "drift", json!({ "surface_dir": "skills" })).await;
    assert_eq!(drift_b["stale"][0]["name"], "review-diff", "{drift_b}");
    assert_eq!(drift_b["unregistered"][0]["name"], "only-default", "{drift_b}");

    // B's staged copy is invisible to the default organization.
    let e = h.call(&ops(DEFAULT_ORG), "publish", json!({ "staging_id": "sk-org-b" })).await.unwrap_err();
    assert_eq!(e.code(), "not_found", "{e:?}");
    assert_eq!(
        h.scalar(
            "SELECT COUNT(*) FROM skill_publish_staging WHERE id = 'sk-org-b' AND published_version IS NULL"
        ),
        1
    );

    // Default unassigns and re-assigns its own row; B's is untouched.
    let b_assignment = || {
        h.scalar(
            "SELECT COUNT(*) FROM skill_assignments WHERE org_id = 'org-b' AND target = 'builder-1' \
             AND pinned_version = 1 AND assigned_at = '2026-01-02T00:00:00+00:00'",
        )
    };
    let out = h
        .gated(&ops(DEFAULT_ORG), "unassign", json!({ "skill_name": "review-diff", "target": "builder-1" }))
        .await;
    assert_eq!(out["removed"], true);
    assert_eq!(h.scalar("SELECT COUNT(*) FROM skill_assignments WHERE org_id = 'default'"), 0);
    assert_eq!(b_assignment(), 1);
    let r_b = h.ok(&device(ORG_B), "resolve", json!({ "agent_label": "builder-1" })).await;
    assert_eq!(r_b["skills"].as_array().unwrap().len(), 1, "B still resolves its skill: {r_b}");
    h.gated(&ops(DEFAULT_ORG), "assign", json!({ "skill_name": "review-diff", "target": "builder-1" })).await;
    assert_eq!(b_assignment(), 1, "the default upsert never touches B's row");

    // Publishing a second version in default numbers from default's versions.
    h.write_skill("review-diff", "Read the whole diff twice.");
    let v2 = h.publish("review-diff").await;
    assert_eq!(v2["skill"]["version"], 2, "{v2}");
    assert_eq!(
        h.scalar("SELECT COUNT(*) FROM skill_versions WHERE org_id = 'org-b'"),
        1,
        "B's versions are unchanged"
    );

    // B's callers hold no operator authority yet: B's writes are refused
    // before anything changes.
    let before = h.counts();
    for (action, params) in [
        ("publish", json!({ "name": "review-diff", "path": "skills/review-diff" })),
        ("publish", json!({ "staging_id": "sk-org-b" })),
        ("assign", json!({ "skill_name": "review-diff", "target": "builder-2" })),
        ("unassign", json!({ "skill_name": "review-diff", "target": "builder-1" })),
    ] {
        let e = h.call(&ops(ORG_B), action, params).await.unwrap_err();
        assert_eq!(e.reason_code(), Some("operator_required"), "{action}: {e:?}");
    }
    assert_eq!(h.counts(), before);
    assert_eq!(b_assignment(), 1);

    // Every event names the default organization.
    assert_eq!(
        h.scalar("SELECT COUNT(*) FROM event_log WHERE channel LIKE 'skill.%' AND org_id <> 'default'"),
        0
    );
}

#[tokio::test]
async fn an_unknown_organization_is_refused_before_any_write() {
    let h = H::new();
    h.write_skill("review-diff", "Read the whole diff.");
    h.publish("review-diff").await;
    h.gated(&ops(DEFAULT_ORG), "assign", json!({ "skill_name": "review-diff", "target": "builder-1" })).await;
    let before = h.counts();
    for (action, params) in [
        ("publish", json!({ "name": "review-diff", "path": "skills/review-diff" })),
        ("publish", json!({ "staging_id": "sk-anything" })),
        ("assign", json!({ "skill_name": "review-diff", "target": "builder-1" })),
        // Nothing to insert: the existence trigger would never fire.
        ("unassign", json!({ "skill_name": "review-diff", "target": "builder-1" })),
    ] {
        let e = h.call(&ops(UNKNOWN), action, params).await.unwrap_err();
        assert!(e.to_string().contains("unknown organization"), "{action}: {e:?}");
    }
    assert_eq!(h.counts(), before);
    // Reads in an unknown organization see nothing.
    let listed = h.ok(&device(UNKNOWN), "list", json!({})).await;
    assert_eq!(listed["skills"], json!([]));
}

#[tokio::test]
async fn a_node_is_served_its_own_organizations_skills() {
    let h = H::new();
    h.write_skill("review-diff", "Read the whole diff.");
    h.publish("review-diff").await;
    h.gated(&ops(DEFAULT_ORG), "assign", json!({ "skill_name": "review-diff", "target": "builder-1" })).await;
    seed_org_b(&h);

    // An active harness bundle, published by a second human and approved.
    let publisher = Caller {
        profile: Profile::Operator,
        enforce_profile: false,
        ..caller("operator-2", ActorKind::Human, DEFAULT_ORG)
    };
    let args = json!({ "bundle": { "version": "v1" } });
    let parked = h.reg.call(&h.hub, &publisher, "harness_config_publish", args.clone()).await.unwrap_err();
    let UaError::ApprovalRequired { approval_id, .. } = parked else { panic!("{parked:?}") };
    h.approve(approval_id).await;
    h.reg.call(&h.hub, &publisher, "harness_config_publish", args).await.unwrap();
    // Each organization serves its own active bundle, and B's callers cannot
    // publish until memberships exist: B's copy is written as B's publish
    // would write it.
    h.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO harness_config_bundles (org_id, version, published_at, published_by, bundle_json, active)
                 SELECT ?1, version, published_at, published_by, bundle_json, 1 FROM harness_config_bundles
                 WHERE org_id = 'default' AND active = 1",
                [ORG_B],
            )?;
            Ok(())
        })
        .unwrap();

    for (org, node, body) in
        [(DEFAULT_ORG, "node-a", "Read the whole diff."), (ORG_B, "node-b", "org b body")]
    {
        let who = device(org);
        h.reg.call(&h.hub, &who, "node_register", json!({ "node": node })).await.unwrap();
        let got = h.reg.call(&h.hub, &who, "node_config", json!({ "node": node })).await.unwrap();
        let skills = got["bundle"]["skills"].as_array().unwrap();
        assert_eq!(skills.len(), 1, "{org}: {got}");
        assert!(skills[0]["body"].as_str().unwrap().contains(body), "{org}: {got}");
    }
}

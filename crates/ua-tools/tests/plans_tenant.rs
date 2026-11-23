//! The plans tables are tenant data (`docs/organization.md`, Scoping per
//! subsystem): `plans`, `plan_steps` and `plan_checkpoints`
//! (`organization.v1.tools.plans`, `plans.v2.org_scope`). No key needed a
//! rebuild: a plan id is hub-generated and the step and checkpoint keys hang
//! off it, so there is no rebuild to crash or roll back here.
//!
//! A second organization is created at the storage level, as no tool creates
//! one yet, and its callers are built by hand. The plan tools do not consult
//! `ua_org::authz`, so every organization-B row in these tests is written
//! through the tools with an organization-B caller; nothing is seeded by SQL
//! except the legacy rows of the upgrade test.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 2] = ["organization.v1.tools.plans", "plans.v2.org_scope"];
const TABLES: [&str; 3] = ["plans", "plan_steps", "plan_checkpoints"];
/// Organization-B labels that must never reach the default organization's
/// ledger: a step owner, and the agent a system caller claims to act as.
const B_OWNER: &str = "Project Falcon acquisition";
const B_AGENT: &str = "Kestrel night-shift runner";

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

fn agent(org: &str) -> Caller {
    Caller {
        label: "builder-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("builder-1-s".into()),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

struct H {
    hub: Hub,
    reg: Registry,
}

impl H {
    fn new() -> Self {
        let hub = Hub::in_memory(Config::for_home(std::env::temp_dir())).unwrap();
        add_org(&hub, ORG_B);
        Self { hub, reg: builtin_registry() }
    }

    async fn manage(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, "plan_manage", json!({ "action": action, "params": params })).await
    }

    async fn ok(&self, who: &Caller, action: &str, params: Value) -> Value {
        match self.manage(who, action, params.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{}: plan {action}({params}) failed: {e:?}", who.org_id),
        }
    }

    /// A three-step chain; returns its id.
    async fn create(&self, who: &Caller, goal: &str) -> String {
        let v = self
            .ok(
                who,
                "create",
                json!({
                    "goal": goal,
                    "scope": "shared-scope",
                    "steps": ["first", {"description": "second", "depends_on": [0]}, "third"],
                }),
            )
            .await;
        v["plan_id"].as_str().unwrap().to_string()
    }

    fn count(&self, sql: &str) -> i64 {
        let sql = sql.to_string();
        self.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
    }

    /// Every row of the three tables, as text: a write that changes nothing
    /// leaves it identical.
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

    /// The `org_id` of every row of `table` belonging to `plan_id`.
    fn orgs_of(&self, table: &str, plan_id: &str) -> Vec<String> {
        let key = if table == "plans" { "id" } else { "plan_id" };
        let sql = format!("SELECT org_id FROM {table} WHERE {key} = ?1 ORDER BY rowid");
        let id = plan_id.to_string();
        self.hub
            .db()
            .read(move |c| Ok(c.prepare(&sql)?.query_map([&id], |r| r.get(0))?.collect::<Result<_, _>>()?))
            .unwrap()
    }

    /// Every ledger payload on `channel`, oldest first.
    fn payloads(&self, channel: &str) -> Vec<Value> {
        let channel = channel.to_string();
        self.hub
            .db()
            .read(move |c| {
                let rows: Vec<String> = c
                    .prepare("SELECT payload FROM event_log WHERE channel = ?1 ORDER BY seq")?
                    .query_map([&channel], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                Ok(rows.iter().map(|p| serde_json::from_str(p).unwrap()).collect())
            })
            .unwrap()
    }
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

/// Every write action, aimed at `plan_id`. Step 0 is open and step 1 waits
/// on it, so each would change the plan if it were the caller's.
fn writes(plan_id: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("update", json!({ "plan_id": plan_id, "step_idx": 0, "status": "done" })),
        ("checkpoint", json!({ "plan_id": plan_id, "note": "x" })),
        ("step_retry", json!({ "plan_id": plan_id, "step_idx": 0, "reason": "x" })),
        ("step_claim", json!({ "plan_id": plan_id, "step_idx": 0 })),
        ("handoff", json!({ "plan_id": plan_id, "step_idx": 0 })),
        ("step_add", json!({ "plan_id": plan_id, "description": "x" })),
        ("step_edit", json!({ "plan_id": plan_id, "step_idx": 2, "description": "x" })),
        ("step_remove", json!({ "plan_id": plan_id, "step_idx": 2 })),
        ("step_reorder", json!({ "plan_id": plan_id, "order": [0, 2, 1] })),
        ("edit", json!({ "plan_id": plan_id, "title": "x" })),
        ("close", json!({ "plan_id": plan_id, "reason": "x" })),
    ]
}

// --- schema ------------------------------------------------------------------------------------

#[test]
fn a_legacy_database_upgrades_into_the_default_organization() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO plans (id, goal, created_at, updated_at)
                 VALUES ('legacy1', 'Old plan', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');
                 INSERT INTO plan_steps (plan_id, step_idx, description, created_at, updated_at)
                 VALUES ('legacy1', 0, 'one', 'x', 'x'), ('legacy1', 1, 'two', 'x', 'x'),
                        ('legacy1', 2, 'three', 'x', 'x');
                 DELETE FROM plan_steps WHERE step_idx = 2;
                 INSERT INTO plan_checkpoints (plan_id, seq, created_at) VALUES ('legacy1', 1, 'x');",
            )?;
            Ok(())
        })
        .unwrap();
    }

    // Open twice: the upgrade is idempotent across restarts.
    for _ in 0..2 {
        let hub = Hub::open(cfg.clone()).unwrap();
        hub.db()
            .read(|c| {
                for t in TABLES {
                    let orgs: Vec<String> = c
                        .prepare(&format!("SELECT DISTINCT org_id FROM {t}"))?
                        .query_map([], |r| r.get(0))?
                        .collect::<Result<_, _>>()?;
                    assert_eq!(orgs, vec![DEFAULT_ORG.to_string()], "{t}");
                    let notnull: i64 = c.query_row(
                        "SELECT \"notnull\" FROM pragma_table_info(?1) WHERE name = 'org_id'",
                        [t],
                        |r| r.get(0),
                    )?;
                    assert_eq!(notnull, 1, "{t}");
                }
                assert_eq!(names(c, "trigger", "plans"), ["plans_org_exists", "plans_org_immutable"]);
                for t in ["plan_steps", "plan_checkpoints"] {
                    assert_eq!(
                        names(c, "trigger", t),
                        [
                            format!("{t}_org_exists"),
                            format!("{t}_org_immutable"),
                            format!("{t}_org_parent"),
                            format!("{t}_org_parent_update"),
                        ],
                        "{t}"
                    );
                }
                // The legacy indexes and keys stay; the organization-led index exists.
                assert_eq!(names(c, "index", "plans"), ["idx_plans_org_status", "idx_plans_status"]);
                assert!(names(c, "index", "plan_steps").contains(&"idx_plan_steps_plan".to_string()));
                let fk: i64 = c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
                assert_eq!(fk, 1, "foreign keys stay on");
                let dangling: i64 =
                    c.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0))?;
                assert_eq!(dangling, 0);
                Ok(())
            })
            .unwrap();
    }

    let hub = Hub::open(cfg).unwrap();
    add_org(&hub, ORG_B);
    hub.db()
        .write(|tx| {
            // The AUTOINCREMENT high-water mark is untouched: the deleted step id 3 is never reused.
            tx.execute(
                "INSERT INTO plan_steps (org_id, plan_id, step_idx, description, created_at, updated_at)
                 VALUES ('default', 'legacy1', 2, 'again', 'x', 'x')",
                [],
            )?;
            assert_eq!(tx.last_insert_rowid(), 4);
            // The (plan_id, step_idx) key is still enforced.
            let err = tx
                .execute(
                    "INSERT INTO plan_steps (org_id, plan_id, step_idx, description, created_at, updated_at)
                     VALUES ('default', 'legacy1', 0, 'dup', 'x', 'x')",
                    [],
                )
                .unwrap_err()
                .to_string();
            assert!(err.contains("UNIQUE"), "{err}");
            // A step or checkpoint cannot join a plan of another organization.
            for (t, cols) in [
                (
                    "plan_steps",
                    "(org_id, plan_id, step_idx, description, created_at, updated_at) \
                                VALUES ('org-b', 'legacy1', 9, 'x', 'x', 'x')",
                ),
                (
                    "plan_checkpoints",
                    "(org_id, plan_id, seq, created_at) VALUES ('org-b', 'legacy1', 9, 'x')",
                ),
            ] {
                let err = tx.execute(&format!("INSERT INTO {t} {cols}"), []).unwrap_err().to_string();
                assert!(err.contains("plan belongs to another organization"), "{t}: {err}");
            }
            for t in TABLES {
                // An unknown organization is refused, and a row never moves.
                let err = tx
                    .execute(&format!("INSERT INTO {t} (org_id) SELECT 'nowhere' FROM {t} LIMIT 1"), [])
                    .unwrap_err()
                    .to_string();
                assert!(err.contains("unknown organization"), "{t}: {err}");
                let err =
                    tx.execute(&format!("UPDATE {t} SET org_id = 'org-b'"), []).unwrap_err().to_string();
                assert!(err.contains("org_id cannot change"), "{t}: {err}");
            }
            Ok(())
        })
        .unwrap();
}

/// The legacy plan is the default organization's through the tools, and
/// another organization does not see it.
#[tokio::test]
async fn a_legacy_plan_is_read_and_written_by_the_default_organization() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO plans (id, goal, created_at, updated_at) VALUES ('legacy1', 'Old plan', 'x', 'x');
                 INSERT INTO plan_steps (plan_id, step_idx, description, created_at, updated_at)
                 VALUES ('legacy1', 0, 'one', 'x', 'x');",
            )?;
            Ok(())
        })
        .unwrap();
    }
    let hub = Hub::open(cfg).unwrap();
    add_org(&hub, ORG_B);
    let h = H { hub, reg: builtin_registry() };
    let got = h.ok(&agent(DEFAULT_ORG), "get", json!({ "plan_id": "legacy1" })).await;
    assert_eq!(
        (got["plan"]["goal"].as_str(), got["plan"]["org_id"].as_str()),
        (Some("Old plan"), Some("default"))
    );
    h.ok(&agent(DEFAULT_ORG), "handoff", json!({ "plan_id": "legacy1", "step_idx": 0 })).await;
    assert_eq!(h.orgs_of("plan_checkpoints", "legacy1"), ["default"]);
    let e = h.manage(&agent(ORG_B), "get", json!({ "plan_id": "legacy1" })).await.unwrap_err();
    assert_eq!(e.to_string(), UaError::not_found("no plan with id \"legacy1\"").to_string());
}

// --- isolation ---------------------------------------------------------------------------------

/// Each organization's plan answers to the other exactly as a missing one,
/// through every read and write action, the legacy tools and the platform
/// object read, and nothing of it changes.
#[tokio::test]
async fn plans_are_isolated_in_both_directions() {
    let h = H::new();
    let a_id = h.create(&agent(DEFAULT_ORG), "Alpha plan").await;
    let b_id = h.create(&agent(ORG_B), "Beta plan").await;

    for (me, mine, theirs) in [(DEFAULT_ORG, &a_id, &b_id), (ORG_B, &b_id, &a_id)] {
        let who = agent(me);
        let missing = |e: &UaError| {
            assert_eq!(e.code(), UaError::not_found("").code(), "{me}: {e}");
            assert_eq!(e.to_string(), UaError::not_found(format!("no plan with id {theirs:?}")).to_string());
        };

        // Lists hold only the caller's plan, whatever the status or scope filter.
        for status in ["active", "all"] {
            let l = h.ok(&who, "list", json!({ "status": status, "scope": "shared-scope" })).await;
            let ids: Vec<&str> =
                l["plans"].as_array().unwrap().iter().map(|p| p["id"].as_str().unwrap()).collect();
            assert_eq!(ids, [mine.as_str()], "{me}: {l}");
        }
        let l = h.reg.call(&h.hub, &who, "plan_list", json!({ "status": "all" })).await.unwrap();
        assert_eq!(l["plans"].as_array().unwrap().len(), 1, "{me}: {l}");

        for action in ["get", "resume"] {
            missing(&h.manage(&who, action, json!({ "plan_id": theirs })).await.unwrap_err());
        }
        missing(&h.reg.call(&h.hub, &who, "plan_get", json!({ "plan_id": theirs })).await.unwrap_err());
        let e = h
            .reg
            .call(&h.hub, &who, "platform_object_get", json!({ "kind": "plan", "id": theirs }))
            .await
            .unwrap_err();
        assert_eq!(e.to_string(), UaError::not_found(format!("no plan {theirs:?}")).to_string(), "{me}");
        let own =
            h.reg.call(&h.hub, &who, "platform_object_get", json!({ "kind": "plan", "id": mine })).await;
        assert_eq!(own.unwrap()["plan"]["steps"].as_array().unwrap().len(), 3, "{me}");

        let before = h.snapshot();
        let events = h.count("SELECT COUNT(*) FROM event_log");
        for (action, params) in writes(theirs) {
            missing(&h.manage(&who, action, params).await.unwrap_err());
        }
        let d = h.ok(&who, "delete", json!({ "plan_id": theirs })).await;
        assert_eq!(d, json!({ "deleted": false }), "{me}");
        assert_eq!(h.snapshot(), before, "{me}: the other organization's plan is untouched");
        assert_eq!(h.count("SELECT COUNT(*) FROM event_log"), events, "{me}");
    }
}

// --- organization B's write path ---------------------------------------------------------------

/// Every write action of an organization-B caller lands its rows in
/// organization B, and the default organization's plan is untouched.
#[tokio::test]
async fn organization_b_writes_land_in_organization_b() {
    let h = H::new();
    let a_id = h.create(&agent(DEFAULT_ORG), "Alpha plan").await;
    let a_before: Vec<Vec<String>> = TABLES.iter().map(|t| h.orgs_of(t, &a_id)).collect();
    let a_rows = h.snapshot();

    let b = agent(ORG_B);
    let id = h.create(&b, "Beta plan").await;
    for (action, params) in [
        ("step_add", json!({ "plan_id": id, "description": "fourth" })),
        ("step_edit", json!({ "plan_id": id, "step_idx": 3, "description": "fourth, edited" })),
        ("step_reorder", json!({ "plan_id": id, "order": [0, 1, 3, 2] })),
        ("step_remove", json!({ "plan_id": id, "step_idx": 2 })),
        ("edit", json!({ "plan_id": id, "title": "Beta, renamed" })),
        ("update", json!({ "plan_id": id, "step_idx": 1, "note": "noted", "owner": B_OWNER })),
        ("checkpoint", json!({ "plan_id": id, "note": "saved" })),
        ("step_claim", json!({ "plan_id": id, "step_idx": 0 })),
        ("handoff", json!({ "plan_id": id, "step_idx": 0, "outputs": { "k": "v" } })),
        ("step_retry", json!({ "plan_id": id, "step_idx": 1, "reason": "flaky" })),
    ] {
        h.ok(&b, action, params).await;
    }
    // A system caller keeps the agent label it claims (`write_identity`).
    let sys = Caller::system_for(ORG_B);
    h.ok(&sys, "step_claim", json!({ "plan_id": id, "step_idx": 2, "agent": B_AGENT })).await;
    h.ok(&sys, "handoff", json!({ "plan_id": id, "step_idx": 2, "agent": B_AGENT })).await;
    let got = h.ok(&b, "get", json!({ "plan_id": id })).await;
    assert_eq!(got["plan"]["title"], "Beta, renamed");
    assert_eq!(got["plan"]["org_id"], ORG_B);
    let steps: Vec<(&str, &str)> = got["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["description"].as_str().unwrap(), s["status"].as_str().unwrap()))
        .collect();
    assert_eq!(steps, [("first", "done"), ("second", "failed"), ("third", "done")]);
    assert_eq!(got["steps"][1]["owner"], B_OWNER, "organization B keeps its own owner text: {got}");
    assert_eq!(got["steps"][2]["owner"], B_AGENT, "{got}");
    assert_eq!(got["checkpoints"].as_array().unwrap().len(), 3, "{got}");
    h.ok(&b, "close", json!({ "plan_id": id, "reason": "beta secret reason" })).await;

    assert_eq!(h.orgs_of("plans", &id), [ORG_B]);
    assert_eq!(h.orgs_of("plan_steps", &id), [ORG_B; 3]);
    assert_eq!(h.orgs_of("plan_checkpoints", &id), [ORG_B; 4]);
    let a_after: Vec<Vec<String>> = TABLES.iter().map(|t| h.orgs_of(t, &a_id)).collect();
    assert_eq!(a_after, a_before);

    // Organization B's free text and labels never reach the default
    // organization's ledger: the fields stay, as null.
    let created = h.payloads("agent.plan.created");
    assert_eq!(created[0]["goal"], "Alpha plan");
    assert_eq!(created[0]["scope"], "shared-scope");
    assert_eq!((created[1]["goal"].clone(), created[1]["scope"].clone()), (Value::Null, Value::Null));
    assert_eq!(created[1]["plan_id"], id.as_str());
    for needle in ["Beta", "beta secret", B_OWNER, B_AGENT] {
        let leaked = h.count(&format!("SELECT COUNT(*) FROM event_log WHERE payload LIKE '%{needle}%'"));
        assert_eq!(leaked, 0, "{needle:?} reached the default organization's ledger");
    }
    let updated = h.payloads("agent.plan.step_updated");
    assert_eq!((updated.len(), updated[0]["owner"].clone()), (1, Value::Null), "{updated:?}");
    let claimed = h.payloads("agent.plan.step_claimed");
    assert_eq!(claimed.len(), 2, "{claimed:?}");
    assert!(claimed.iter().all(|p| p["agent"].is_null()), "{claimed:?}");
    let handoffs = h.payloads("agent.plan.handoff");
    assert_eq!(handoffs.len(), 2, "{handoffs:?}");
    for p in &handoffs {
        assert_eq!((p["agent"].clone(), p["next_owner"].clone()), (Value::Null, Value::Null), "{p}");
        assert_eq!(p["next_step_idx"], 1, "{p}");
    }

    let d = h.ok(&b, "delete", json!({ "plan_id": id })).await;
    assert_eq!(d, json!({ "deleted": true }));
    for t in TABLES {
        assert_eq!(h.count(&format!("SELECT COUNT(*) FROM {t} WHERE org_id = 'org-b'")), 0, "{t}");
    }
    assert_eq!(h.snapshot(), a_rows, "organization A's rows survive B's delete");

    // The default organization's own labels are still recorded.
    let me = agent(DEFAULT_ORG);
    h.ok(&me, "update", json!({ "plan_id": a_id, "step_idx": 0, "owner": "alpha-owner" })).await;
    h.ok(&me, "step_claim", json!({ "plan_id": a_id, "step_idx": 2 })).await;
    let h0 = h.ok(&me, "handoff", json!({ "plan_id": a_id, "step_idx": 2 })).await;
    assert_eq!(h0["next_step"]["step_idx"], 0, "{h0}");
    assert_eq!(h.payloads("agent.plan.step_updated").last().unwrap()["owner"], "alpha-owner");
    assert_eq!(h.payloads("agent.plan.step_claimed").last().unwrap()["agent"], "builder-1");
    let last = h.payloads("agent.plan.handoff").pop().unwrap();
    assert_eq!(
        (last["agent"].as_str(), last["next_owner"].as_str()),
        (Some("builder-1"), Some("alpha-owner"))
    );
}

/// A step or checkpoint cannot be moved under another organization's plan
/// (`*_org_parent_update`). Seeded by SQL: no tool rewrites a `plan_id`.
#[tokio::test]
async fn a_step_or_checkpoint_cannot_move_to_another_organizations_plan() {
    let h = H::new();
    let a_id = h.create(&agent(DEFAULT_ORG), "Alpha plan").await;
    let a_other = h.create(&agent(DEFAULT_ORG), "Alpha second plan").await;
    h.ok(&agent(DEFAULT_ORG), "checkpoint", json!({ "plan_id": a_id })).await;
    let b_id = h.create(&agent(ORG_B), "Beta plan").await;
    let before = h.snapshot();
    let (a, other, b) = (a_id.clone(), a_other.clone(), b_id.clone());
    h.hub
        .db()
        .write(move |tx| {
            for t in ["plan_steps", "plan_checkpoints"] {
                let err = tx
                    .execute(&format!("UPDATE {t} SET plan_id = ?1 WHERE plan_id = ?2"), [&b, &a])
                    .unwrap_err()
                    .to_string();
                assert!(err.contains("plan belongs to another organization"), "{t}: {err}");
            }
            // Within one organization the trigger stays out of the way.
            let n =
                tx.execute("UPDATE plan_checkpoints SET plan_id = ?1 WHERE plan_id = ?2", [&other, &a])?;
            assert_eq!(n, 1);
            tx.execute("UPDATE plan_checkpoints SET plan_id = ?1 WHERE plan_id = ?2", [&a, &other])?;
            Ok(())
        })
        .unwrap();
    assert_eq!(h.snapshot(), before);
}

// --- unknown organization ----------------------------------------------------------------------

/// A caller whose organization `orgs` does not hold is refused by the
/// family's own guard (its wording, not the trigger's bare "unknown
/// organization"), before anything is written, including writes with
/// nothing to insert (an update, a delete).
#[tokio::test]
async fn an_unknown_organization_is_refused_before_any_write() {
    let h = H::new();
    let a_id = h.create(&agent(DEFAULT_ORG), "Alpha plan").await;
    let before = h.snapshot();
    let events = h.count("SELECT COUNT(*) FROM event_log");
    let who = agent(UNKNOWN);
    let guard = format!("unknown organization {UNKNOWN:?}; no plan was changed");

    let mut calls = writes(&a_id);
    calls.push(("delete", json!({ "plan_id": a_id })));
    calls.push(("create", json!({ "goal": "x", "steps": ["one"] })));
    for (action, params) in calls {
        let e = h.manage(&who, action, params).await.unwrap_err();
        assert_eq!(reason(&e), "unknown_organization", "{action}: {e}");
        assert!(e.to_string().contains(&guard), "{action}: {e}");
    }
    assert_eq!(h.snapshot(), before);
    assert_eq!(h.count("SELECT COUNT(*) FROM event_log"), events);

    // Reads in an unknown organization see nothing.
    let l = h.ok(&who, "list", json!({ "status": "all" })).await;
    assert_eq!(l["plans"], json!([]));
    let e = h.manage(&who, "get", json!({ "plan_id": a_id })).await.unwrap_err();
    assert_eq!(e.to_string(), UaError::not_found(format!("no plan with id {a_id:?}")).to_string());
}

// --- defence in depth --------------------------------------------------------------------------

/// The step and checkpoint reads filter on `org_id` themselves, not only
/// through the plan: with the parent triggers dropped, another
/// organization's rows seeded under a default-organization plan's id are
/// never read, numbered against or returned. (Seeded by SQL: no tool can
/// write such a row.)
#[tokio::test]
async fn another_organizations_rows_under_a_plan_id_are_never_read() {
    let h = H::new();
    let me = agent(DEFAULT_ORG);
    let id = h.create(&me, "Alpha plan").await;
    h.hub
        .db()
        .write(|tx| {
            tx.execute_batch(
                "DROP TRIGGER plan_steps_org_parent; DROP TRIGGER plan_checkpoints_org_parent;",
            )?;
            tx.execute(
                "INSERT INTO plan_steps (org_id, plan_id, step_idx, description, created_at, updated_at)
                 VALUES ('org-b', ?1, 7, 'intruder', 'x', 'x')",
                [&id],
            )?;
            tx.execute(
                "INSERT INTO plan_checkpoints (org_id, plan_id, seq, note, created_at)
                 VALUES ('org-b', ?1, 50, 'intruder', 'x')",
                [&id],
            )?;
            Ok(())
        })
        .unwrap();

    let got = h.ok(&me, "get", json!({ "plan_id": id })).await;
    assert_eq!(got["steps"].as_array().unwrap().len(), 3, "{got}");
    assert_eq!(got["checkpoints"], json!([]), "{got}");
    let r = h.ok(&me, "resume", json!({ "plan_id": id })).await;
    assert_eq!(r["checkpoint"], Value::Null, "{r}");
    let e = h.manage(&me, "resume", json!({ "plan_id": id, "from_checkpoint": 50 })).await.unwrap_err();
    assert_eq!(
        e.to_string(),
        UaError::not_found(format!("plan {id:?} has no checkpoint seq 50")).to_string()
    );
    let c = h.ok(&me, "checkpoint", json!({ "plan_id": id })).await;
    assert_eq!(c["seq"], 1, "numbered against the caller's organization's checkpoints only: {c}");
    let o =
        h.reg.call(&h.hub, &me, "platform_object_get", json!({ "kind": "plan", "id": id })).await.unwrap();
    assert_eq!(o["plan"]["steps"].as_array().unwrap().len(), 3, "{o}");
    let added = h.ok(&me, "step_add", json!({ "plan_id": id, "description": "fourth" })).await;
    assert_eq!(
        added["step"]["step_idx"], 3,
        "numbered against the caller's organization's steps only: {added}"
    );
    assert_eq!(added["steps"].as_array().unwrap().len(), 4, "{added}");
}

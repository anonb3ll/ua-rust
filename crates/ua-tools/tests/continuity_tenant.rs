//! The task workflow and hold tables are tenant data (`docs/organization.md`,
//! Scoping per subsystem): `task_workflow`, `task_checks` and
//! `review_ready_notices` (`organization.v1.tools.continuity`,
//! `continuity.v2.org_scope`), and `task_holds` and `task_hold_members`
//! (`organization.v1.tools.holds`, `governance.v3.holds_org_scope`). No key
//! needed a rebuild: every key is led by a hub-global task or hold id.
//!
//! A second organization is created at the storage level, as no tool creates
//! one yet, and its callers are built by hand. Organization-B rows are written
//! through the tools with an organization-B caller; only the legacy rows of
//! the upgrade test, the defence-in-depth rows, a verified check (no CI runs
//! here) and organization B's binding are seeded by SQL.

use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::families::github::{WebhookDelivery, receive, signature_for};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 4] = [
    "organization.v1.tools.continuity",
    "continuity.v2.org_scope",
    "organization.v1.tools.holds",
    "governance.v3.holds_org_scope",
];
const TABLES: [&str; 5] =
    ["task_workflow", "task_checks", "review_ready_notices", "task_holds", "task_hold_members"];
/// Organization-B text that must never reach the default organization's
/// ledger, in a payload or as an originator.
const B_AGENT: &str = "kestrel-nightshift";
const B_REASON: &str = "Osprey hold pending counsel";
const B_CHECK: &str = "falcon-secret-check";
const B_DETAIL: &str = "Falcon diligence verdict";
const B_GOAL: &str = "Close the Falcon acquisition";
const B_FOCUS: &str = "Osprey term sheet";
const B_DONE: &str = "Kestrel memo drafted";
const WEBHOOK_SECRET: &str = "tenant-webhook-secret";

fn head(c: char) -> String {
    c.to_string().repeat(40)
}

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().filter(|p| !PARTS.contains(&p.name)).collect()
}

fn add_org(hub: &Hub, id: &str) {
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
                 VALUES (?1, ?1, 'Org B', '[\"developer\",\"coordinator\"]', '2026-01-01T00:00:00+00:00')",
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

fn operator() -> Caller {
    Caller { kind: ActorKind::Human, profile: Profile::Coordinator, ..agent_named("operator", DEFAULT_ORG) }
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

/// `e` reads exactly as `missing` does, once each names the same id.
fn same_as_missing(e: &UaError, missing: &UaError, id: i64, absent: i64) {
    assert_eq!(e.code(), missing.code(), "{e} / {missing}");
    assert_eq!(
        e.to_string().replace(&id.to_string(), "ID"),
        missing.to_string().replace(&absent.to_string(), "ID"),
        "another organization's row must answer as a missing one"
    );
}

struct H {
    hub: Hub,
    reg: Registry,
    _dir: tempfile::TempDir,
}

impl H {
    fn new() -> Self {
        Self::with(|_| {})
    }

    fn with(edit: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path());
        cfg.human_identities = vec!["operator".into()];
        edit(&mut cfg);
        let hub = Hub::in_memory(cfg).unwrap();
        add_org(&hub, ORG_B);
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

    async fn coord(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "coordination_manage", json!({ "action": action, "params": params })).await
    }

    async fn coord_ok(&self, who: &Caller, action: &str, params: Value) -> Value {
        match self.coord(who, action, params.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{}: {action}({params}) failed: {e:?}", who.org_id),
        }
    }

    async fn coord_err(&self, who: &Caller, action: &str, params: Value) -> UaError {
        match self.coord(who, action, params.clone()).await {
            Ok(v) => panic!("{}: {action}({params}) should fail, got {v}", who.org_id),
            Err(e) => e,
        }
    }

    /// A task of `who`'s organization, claimed by `who`.
    async fn claimed(&self, who: &Caller, title: &str, project: Option<&str>) -> i64 {
        let mut args = json!({ "title": title });
        if let Some(p) = project {
            args["project"] = json!(p);
        }
        let id = self.ok(who, "task_add", args).await["id"].as_i64().unwrap();
        self.ok(who, "task_claim", json!({ "id": id })).await;
        id
    }

    fn count(&self, sql: &str) -> i64 {
        let sql = sql.to_string();
        self.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
    }

    fn text(&self, sql: &str) -> Option<String> {
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

    /// Every row of the five tables, as text: a write that changes nothing
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

    fn events(&self) -> i64 {
        self.count("SELECT COUNT(*) FROM event_log")
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

fn hold_roots(v: &Value) -> Vec<i64> {
    v["holds"].as_array().unwrap().iter().map(|x| x["root_task_id"].as_i64().unwrap()).collect()
}

fn check_names(v: &Value) -> Vec<String> {
    v["checks"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap().to_string()).collect()
}

// --- schema ------------------------------------------------------------------------------------

/// Rows written before the parts move to their task's organization: a
/// workflow record, check and review notice to their task's, a hold to its
/// root's and a member to its hold's. A row whose task is gone stays in the
/// default organization.
#[test]
fn a_legacy_database_upgrades_each_row_into_its_tasks_organization() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    let (ha, hb) = (head('a'), head('b'));
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(&format!(
                "INSERT INTO orgs (id, slug, display_name, created_at) VALUES ('org-b', 'org-b', 'Org B', 'x');
                 INSERT INTO tasks (id, org_id, title, created_at, updated_at) VALUES
                     (1, 'default', 'Legacy A', 'x', 'x'), (2, 'org-b', 'Legacy B', 'x', 'x');
                 INSERT INTO task_workflow (task_id, stage, head_sha, revision, updated_by, updated_at)
                     VALUES (1, 'review', '{ha}', 2, 'old', 'x'), (2, 'verify', '{hb}', 3, 'old', 'x');
                 INSERT INTO task_checks (task_id, name, head_sha, outcome, grade, recorded_by, recorded_at)
                     VALUES (1, 'ci', '{ha}', 'pass', 'attested', 'old', 'x'),
                            (2, 'ci', '{hb}', 'pass', 'attested', 'old', 'x');
                 INSERT INTO review_ready_notices (task_id, head_sha, notified_at)
                     VALUES (1, '{ha}', 'x'), (2, '{hb}', 'x'), (999, '{ha}', 'x');
                 INSERT INTO task_holds (id, root_task_id, mode, reason, created_by, created_at)
                     VALUES (10, 1, 'pause', 'a', 'old', 'x'), (20, 2, 'pause', 'b', 'old', 'x'),
                            (30, 999, 'pause', 'gone', 'old', 'x');
                 INSERT INTO task_hold_members (hold_id, task_id, status_at_hold)
                     VALUES (10, 1, 'open'), (20, 2, 'open');"
            ))?;
            Ok(())
        })
        .unwrap();
    }

    // Open twice: the upgrade is idempotent across restarts.
    for _ in 0..2 {
        let hub = Hub::open(cfg.clone()).unwrap();
        hub.db()
            .read(|c| {
                let orgs = |sql: &str| -> Vec<(i64, String)> {
                    c.prepare(sql)
                        .unwrap()
                        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                        .unwrap()
                        .collect::<Result<_, _>>()
                        .unwrap()
                };
                let both = vec![(1, DEFAULT_ORG.to_string()), (2, ORG_B.to_string())];
                assert_eq!(orgs("SELECT task_id, org_id FROM task_workflow ORDER BY task_id"), both);
                assert_eq!(orgs("SELECT task_id, org_id FROM task_checks ORDER BY task_id"), both);
                assert_eq!(
                    orgs("SELECT task_id, org_id FROM review_ready_notices ORDER BY task_id"),
                    [both.clone(), vec![(999, DEFAULT_ORG.to_string())]].concat()
                );
                assert_eq!(
                    orgs("SELECT id, org_id FROM task_holds ORDER BY id"),
                    vec![(10, DEFAULT_ORG.into()), (20, ORG_B.into()), (30, DEFAULT_ORG.into())]
                );
                assert_eq!(
                    orgs("SELECT hold_id, org_id FROM task_hold_members ORDER BY hold_id"),
                    vec![(10, DEFAULT_ORG.into()), (20, ORG_B.into())]
                );
                for t in TABLES {
                    let notnull: i64 = c.query_row(
                        "SELECT \"notnull\" FROM pragma_table_info(?1) WHERE name = 'org_id'",
                        [t],
                        |r| r.get(0),
                    )?;
                    assert_eq!(notnull, 1, "{t}");
                    let triggers = names(c, "trigger", t);
                    for want in [
                        format!("{t}_org_exists"),
                        format!("{t}_org_immutable"),
                        format!("{t}_org_parent"),
                        format!("{t}_org_parent_update"),
                    ] {
                        assert!(triggers.contains(&want), "{t}: {triggers:?}");
                    }
                }
                for (t, want) in [
                    ("task_workflow", "idx_task_workflow_org_stage"),
                    ("task_checks", "idx_task_checks_org_repo_head"),
                    ("task_holds", "idx_task_holds_org_status"),
                    ("task_hold_members", "idx_task_hold_members_org_task"),
                    // The one-active-hold index stays keyed by the hub-global root.
                    ("task_holds", "idx_task_holds_active_root"),
                ] {
                    assert!(names(c, "index", t).contains(&want.to_string()), "{t}: {want}");
                }
                // The recreated immutable triggers are spelled exactly as
                // the generated one: guards the `org_immutable!` macro.
                let sql = |name: &str| -> String {
                    c.query_row(
                        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                        [name],
                        |r| r.get(0),
                    )
                    .unwrap()
                };
                let generated = sql("tasks_org_immutable");
                for t in TABLES {
                    assert_eq!(sql(&format!("{t}_org_immutable")), generated.replace("tasks", t), "{t}");
                }
                let dangling: i64 =
                    c.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0))?;
                assert_eq!(dangling, 0);
                Ok(())
            })
            .unwrap();
    }

    let hub = Hub::open(cfg).unwrap();
    // The recreated immutable triggers still hold.
    for t in TABLES {
        let e = hub
            .db()
            .write(|tx| {
                Ok(tx.execute(&format!("UPDATE {t} SET org_id = 'org-b' WHERE org_id = 'default'"), [])?)
            })
            .unwrap_err()
            .to_string();
        assert!(e.contains("org_id cannot change"), "{t}: {e}");
    }
    // The legacy rows answer through the tools, each in its organization.
    let reg = builtin_registry();
    let (a, b) = (agent(DEFAULT_ORG), agent(ORG_B));
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let coord = |who: &Caller, action: &str, params: Value| {
            let args = json!({ "action": action, "params": params });
            let (reg, hub, who) = (&reg, &hub, who.clone());
            async move { reg.call(hub, &who, "coordination_manage", args).await }
        };
        let v = coord(&b, "task_workflow_get", json!({ "task_id": 2 })).await.unwrap();
        assert_eq!((v["stage"].as_str(), v["revision"].as_i64()), (Some("verify"), Some(3)), "{v}");
        assert_eq!(check_names(&v), ["ci"]);
        assert!(v.get("org_id").is_none(), "a reply keeps its shape: {v}");
        let e = coord(&a, "task_workflow_get", json!({ "task_id": 2 })).await.unwrap_err();
        assert_eq!(e.code(), "not_found", "{e}");
        let v = coord(&a, "task_holds", json!({ "status": "all" })).await.unwrap();
        assert_eq!(hold_roots(&v), [999, 1], "{v}");
        let v = coord(&b, "task_holds", json!({ "status": "all" })).await.unwrap();
        assert_eq!(hold_roots(&v), [2], "{v}");
        assert!(v["holds"][0].get("org_id").is_none(), "{v}");
    });
}

/// Defence in depth: whatever a tool would check, the triggers keep every
/// row's task, a hold's root and a member's hold inside the row's
/// organization.
#[test]
fn the_triggers_refuse_every_cross_organization_reference() {
    let h = H::new();
    let ha = head('a');
    h.sql(
        "INSERT INTO tasks (id, org_id, title, created_at, updated_at) VALUES
             (10, 'default', 'A', 'x', 'x'), (20, 'org-b', 'B', 'x', 'x'), (21, 'org-b', 'B2', 'x', 'x');
         INSERT INTO task_holds (id, org_id, root_task_id, mode, created_by, created_at)
             VALUES (100, 'default', 10, 'pause', 'a', 'x'), (200, 'org-b', 20, 'pause', 'b', 'x');
         INSERT INTO task_hold_members (org_id, hold_id, task_id, status_at_hold) VALUES ('org-b', 200, 21, 'open');",
    )
    .unwrap();
    let refused = |sql: &str| {
        let e = h.sql(sql).unwrap_err();
        assert!(e.contains("another organization"), "{sql}: {e}");
    };
    refused("INSERT INTO task_workflow (org_id, task_id) VALUES ('org-b', 10)");
    refused(&format!(
        "INSERT INTO task_checks (org_id, task_id, name, head_sha, outcome, grade, recorded_by, recorded_at)
         VALUES ('org-b', 10, 'ci', '{ha}', 'pass', 'attested', 'b', 'x')"
    ));
    refused(&format!(
        "INSERT INTO review_ready_notices (org_id, task_id, head_sha, notified_at) VALUES ('org-b', 10, '{ha}', 'x')"
    ));
    refused(
        "INSERT INTO task_holds (org_id, root_task_id, mode, created_by, created_at) VALUES ('org-b', 10, 'pause', 'b', 'x')",
    );
    refused("UPDATE task_holds SET root_task_id = 10 WHERE id = 200");
    // A member's task, and a member's hold.
    refused(
        "INSERT INTO task_hold_members (org_id, hold_id, task_id, status_at_hold) VALUES ('org-b', 200, 10, 'open')",
    );
    refused(
        "INSERT INTO task_hold_members (org_id, hold_id, task_id, status_at_hold) VALUES ('org-b', 100, 20, 'open')",
    );
    refused("UPDATE task_hold_members SET task_id = 10 WHERE hold_id = 200");
    refused("UPDATE task_hold_members SET hold_id = 100 WHERE hold_id = 200");
    // The rows the moves would need inside one organization are accepted, and
    // a task_id moved across is refused.
    h.sql("INSERT INTO task_workflow (org_id, task_id) VALUES ('org-b', 20)").unwrap();
    refused("UPDATE task_workflow SET task_id = 10 WHERE task_id = 20");
    h.sql(&format!(
        "INSERT INTO task_checks (id, org_id, task_id, name, head_sha, outcome, grade, recorded_by, recorded_at)
         VALUES (7, 'org-b', 20, 'ci', '{ha}', 'pass', 'attested', 'b', 'x');
         INSERT INTO review_ready_notices (org_id, task_id, head_sha, notified_at) VALUES ('org-b', 20, '{ha}', 'x');"
    ))
    .unwrap();
    refused("UPDATE task_checks SET task_id = 10 WHERE id = 7");
    refused("UPDATE review_ready_notices SET task_id = 10 WHERE task_id = 20");
    // An unknown organization is refused by the generated trigger.
    let e = h.sql("INSERT INTO task_workflow (org_id, task_id) VALUES ('missing-org', 99)").unwrap_err();
    assert!(e.contains("unknown organization"), "{e}");
}

// --- isolation ---------------------------------------------------------------------------------

/// One organization's claimed task with a workflow record, a check and a
/// hold, written through the tools.
struct Fixture {
    task: i64,
    hold: i64,
}

async fn fixture(h: &H, who: &Caller) -> Fixture {
    let task = h.claimed(who, "Workflow task", None).await;
    h.coord_ok(
        who,
        "task_workflow_set",
        json!({ "task_id": task, "stage": "implement", "goal": "g", "focus": "f", "head_sha": head('c'),
                "expected_checks": ["ci"] }),
    )
    .await;
    h.coord_ok(
        who,
        "task_check_record",
        json!({ "task_id": task, "name": "ci", "outcome": "pass", "head_sha": head('c'), "detail": "d" }),
    )
    .await;
    let held = h.ok(who, "task_add", json!({ "title": "Held task" })).await["id"].as_i64().unwrap();
    let hold =
        h.coord_ok(who, "task_hold", json!({ "root_task_id": held, "reason": "r" })).await["hold"]["id"]
            .as_i64()
            .unwrap();
    Fixture { task, hold }
}

#[tokio::test]
async fn each_organization_sees_only_its_own_workflow_checks_and_holds() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let b = agent(ORG_B);
    let fa = fixture(&h, &a).await;
    let fb = fixture(&h, &b).await;
    let absent = 999_999;

    for (me, mine, theirs) in [(&a, &fa, &fb), (&b, &fb, &fa)] {
        let org = me.org_id.as_str();
        let before = h.snapshot();
        let events = h.events();
        let t = theirs.task;
        let their_root: i64 =
            h.count(&format!("SELECT root_task_id FROM task_holds WHERE id = {}", theirs.hold));

        for (action, args, missing) in [
            ("task_workflow_get", json!({ "task_id": t }), json!({ "task_id": absent })),
            (
                "task_workflow_set",
                json!({ "task_id": t, "stage": "review" }),
                json!({ "task_id": absent, "stage": "review" }),
            ),
            (
                "task_check_record",
                json!({ "task_id": t, "name": "ci", "outcome": "fail", "head_sha": head('c') }),
                json!({ "task_id": absent, "name": "ci", "outcome": "fail", "head_sha": head('c') }),
            ),
            (
                "task_check_verify",
                json!({ "task_id": t, "name": "ci", "head_sha": head('c') }),
                json!({ "task_id": absent, "name": "ci", "head_sha": head('c') }),
            ),
        ] {
            let e = h.coord_err(me, action, args).await;
            let m = h.coord_err(me, action, missing).await;
            same_as_missing(&e, &m, t, absent);
        }
        for (args, missing) in [
            (
                json!({ "root_task_id": their_root, "reason": "x" }),
                json!({ "root_task_id": absent, "reason": "x" }),
            ),
            (
                json!({ "root_task_id": their_root, "mode": "cancel", "reason": "x" }),
                json!({ "root_task_id": absent, "mode": "cancel", "reason": "x" }),
            ),
            (
                json!({ "root_task_id": their_root, "mode": "resume" }),
                json!({ "root_task_id": absent, "mode": "resume" }),
            ),
        ] {
            let e = h.coord_err(me, "task_hold", args).await;
            let m = h.coord_err(me, "task_hold", missing).await;
            same_as_missing(&e, &m, their_root, absent);
        }
        let e = h.coord_err(me, "task_hold_get", json!({ "hold_id": theirs.hold })).await;
        let m = h.coord_err(me, "task_hold_get", json!({ "hold_id": absent })).await;
        same_as_missing(&e, &m, theirs.hold, absent);
        assert_eq!(h.snapshot(), before, "{org}: the other organization's rows are untouched");
        assert_eq!(h.events(), events, "{org}: nothing was ledgered");

        // Reads show only the caller's rows.
        let v = h.coord_ok(me, "task_holds", json!({ "status": "all" })).await;
        assert_eq!(v["holds"].as_array().unwrap().len(), 1, "{org}: {v}");
        assert_eq!(v["holds"][0]["id"], mine.hold, "{org}: {v}");
        let v = h.coord_ok(me, "task_holds", json!({ "status": "all", "root_task_id": their_root })).await;
        assert_eq!(v["holds"], json!([]), "{org}");
        let v = h.coord_ok(me, "task_workflow_get", json!({ "task_id": mine.task })).await;
        assert_eq!(
            (v["stage"].as_str(), check_names(&v)),
            (Some("implement"), vec!["ci".to_string()]),
            "{v}"
        );
        let listed = h.ok(me, "task_list", json!({ "status": "all", "stage": "implement" })).await;
        let ids: Vec<i64> =
            listed["tasks"].as_array().unwrap().iter().map(|x| x["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, [mine.task], "{org}: {listed}");
        // The caller's own hold refuses its own claim (the claim gate).
        let my_root: i64 = h.count(&format!("SELECT root_task_id FROM task_holds WHERE id = {}", mine.hold));
        let e = h.call(me, "task_claim", json!({ "id": my_root })).await.unwrap_err();
        assert_eq!(reason(&e), "task_held", "{org}: {e}");
    }

    // Every row stayed in its organization.
    for t in TABLES {
        let n = h.count(&format!("SELECT COUNT(*) FROM {t} WHERE org_id = 'org-b'"));
        let want = if t == "review_ready_notices" { 0 } else { 1 };
        assert_eq!(n, want, "{t}");
    }
}

/// Defence in depth: with the reference triggers dropped and organization-B
/// rows seeded on default-organization tasks, no lookup of the default
/// organization follows them: the workflow view, `task_list`'s stage filter,
/// the check lookups and upsert, the review notices' rate limit, the hold
/// reads and the claim gate.
#[tokio::test]
async fn the_lookups_never_follow_a_row_into_another_organization() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let (ha, hz) = (head('a'), head('f'));
    let ta = h.claimed(&a, "A task", None).await;
    let ta2 = h.ok(&a, "task_add", json!({ "title": "A unclaimed" })).await["id"].as_i64().unwrap();
    let ta3 = h.claimed(&a, "A review", None).await;
    h.sql(&format!(
        "DROP TRIGGER task_workflow_org_parent;
         DROP TRIGGER task_checks_org_parent;
         DROP TRIGGER review_ready_notices_org_parent;
         DROP TRIGGER task_holds_org_parent;
         DROP TRIGGER task_hold_members_org_parent;
         INSERT INTO task_workflow (org_id, task_id, stage, head_sha, expected_json, expected_jobs_json, revision,
                                    updated_by, updated_at)
             VALUES ('org-b', {ta}, 'review', '{ha}', '[\"ci\"]', '{{\"ci\":\"b-job\"}}', 9, 'b', 'x');
         INSERT INTO task_checks (org_id, task_id, name, head_sha, outcome, grade, ref_kind, ref, repo,
                                  recorded_by, recorded_at)
             VALUES ('org-b', {ta}, 'ci', '{ha}', 'pass', 'verified', 'ci_run', '41', 'shared/repo', 'b', 'x');
         INSERT INTO review_ready_notices (org_id, task_id, head_sha, notified_at)
             VALUES ('org-b', {ta3}, '{hz}', '2999-01-01T00:00:00+00:00');
         INSERT INTO task_holds (id, org_id, root_task_id, mode, created_by, created_at)
             VALUES (500, 'org-b', {ta2}, 'pause', 'b', 'x');
         INSERT INTO task_hold_members (org_id, hold_id, task_id, status_at_hold) VALUES ('org-b', 500, {ta2}, 'open');"
    ))
    .unwrap();

    // The workflow view shows no record and no check.
    let v = h.coord_ok(&a, "task_workflow_get", json!({ "task_id": ta, "head_sha": ha })).await;
    assert_eq!((v["revision"].as_i64(), v["stage"].clone()), (Some(0), Value::Null), "{v}");
    assert_eq!((v["checks"].clone(), v["expected_jobs"].clone()), (json!([]), json!({})), "{v}");
    let listed = h.ok(&a, "task_list", json!({ "status": "all", "stage": "review" })).await;
    assert_eq!(listed["tasks"], json!([]), "{listed}");
    // A stored check of another organization is not the caller's to verify.
    let e =
        h.coord_err(&a, "task_check_verify", json!({ "task_id": ta, "name": "ci", "head_sha": ha })).await;
    assert_eq!(e.code(), "not_found", "{e}");
    // Recording at the same name and head never overwrites the other
    // organization's row, and the skipped upsert is a conflict, not a
    // recorded check, with no ledger event. Nor is the other organization's
    // job binding the caller's: a ref naming another job passes that check
    // (else the refusal would be `invalid_argument`).
    let before = h.events();
    let e = h
        .coord_err(
            &a,
            "task_check_record",
            json!({ "task_id": ta, "name": "ci", "outcome": "fail", "head_sha": ha,
                    "ref": { "kind": "ci_run", "ref": "7", "repo": "owner-a/repo", "job": "a-job" },
                    "verify": false }),
        )
        .await;
    assert_eq!(e.code(), "conflict", "{e}");
    assert_eq!(h.events(), before, "a skipped upsert writes no ledger event");
    assert_eq!(
        h.text(&format!(
            "SELECT grade || '/' || outcome FROM task_checks WHERE org_id = 'org-b' AND task_id = {ta}"
        ))
        .as_deref(),
        Some("verified/pass")
    );

    // Another organization's recent notice on the task does not rate-limit
    // the caller's own.
    h.coord_ok(
        &a,
        "task_workflow_set",
        json!({ "task_id": ta3, "stage": "implement", "head_sha": ha, "expected_checks": ["ci"] }),
    )
    .await;
    h.sql(&format!(
        "INSERT INTO task_checks (org_id, task_id, name, head_sha, outcome, grade, recorded_by, recorded_at)
         VALUES ('default', {ta3}, 'ci', '{ha}', 'pass', 'verified', 'builder-1', 'x')"
    ))
    .unwrap();
    h.coord_ok(&a, "task_workflow_set", json!({ "task_id": ta3, "stage": "review" })).await;
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM review_ready_notices WHERE org_id = 'default' AND task_id = {ta3} AND head_sha = '{ha}'"
        )),
        1
    );

    // The hold reads and the claim gate ignore the other organization's hold.
    let v = h.coord_ok(&a, "task_holds", json!({ "status": "all" })).await;
    assert_eq!(v["holds"], json!([]), "{v}");
    let e = h.coord_err(&a, "task_hold_get", json!({ "hold_id": 500 })).await;
    assert_eq!(e.code(), "not_found", "{e}");
    h.ok(&a, "task_claim", json!({ "id": ta2 })).await;
}

#[tokio::test]
async fn organization_b_writes_land_in_organization_b() {
    let h = H::new();
    let b = agent(ORG_B);
    let hb = head('b');
    let tb = h.claimed(&b, "B task", None).await;
    let child =
        h.ok(&b, "task_add", json!({ "title": "B child", "parent_id": tb })).await["id"].as_i64().unwrap();
    h.coord_ok(
        &b,
        "task_workflow_set",
        json!({ "task_id": tb, "stage": "implement", "head_sha": hb, "expected_checks": ["ci"] }),
    )
    .await;
    h.coord_ok(
        &b,
        "task_check_record",
        json!({ "task_id": tb, "name": "lint", "outcome": "pass", "head_sha": hb }),
    )
    .await;
    // No CI runs here: the verified check the notice needs is seeded.
    h.sql(&format!(
        "INSERT INTO task_checks (org_id, task_id, name, head_sha, outcome, grade, recorded_by, recorded_at)
         VALUES ('org-b', {tb}, 'ci', '{hb}', 'pass', 'verified', 'b', 'x')"
    ))
    .unwrap();
    let v = h.coord_ok(&b, "task_workflow_set", json!({ "task_id": tb, "stage": "review" })).await;
    assert!(v.get("org_id").is_none(), "{v}");
    // The review notice is organization B's, and so is its notification.
    assert_eq!(
        h.text(&format!("SELECT org_id FROM review_ready_notices WHERE task_id = {tb}")).as_deref(),
        Some(ORG_B)
    );
    assert_eq!(
        h.text(&format!("SELECT review_notified_head FROM task_workflow WHERE task_id = {tb}")).as_deref(),
        Some(hb.as_str())
    );
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM notify_outbox WHERE org_id = 'org-b' AND category = 'review_ready' \
             AND status = 'not_configured' AND message IS NULL"
        )),
        1
    );
    assert_eq!(h.count("SELECT COUNT(*) FROM notify_outbox WHERE org_id = 'default'"), 0);
    let hold =
        h.coord_ok(&b, "task_hold", json!({ "root_task_id": tb, "mode": "cancel", "reason": "r" })).await;
    let hold_id = hold["hold"]["id"].as_i64().unwrap();
    assert_eq!(hold["hold"]["member_ids"], json!([tb, child]), "{hold}");
    assert!(hold["hold"].get("org_id").is_none(), "{hold}");
    h.coord_ok(&b, "task_hold", json!({ "root_task_id": tb, "mode": "resume" })).await;

    for t in TABLES {
        let (all, b_rows) = (
            h.count(&format!("SELECT COUNT(*) FROM {t}")),
            h.count(&format!("SELECT COUNT(*) FROM {t} WHERE org_id = 'org-b'")),
        );
        assert!(all > 0 && all == b_rows, "{t}: {b_rows} of {all}");
    }
    assert_eq!(
        h.text(&format!("SELECT status FROM task_holds WHERE id = {hold_id}")).as_deref(),
        Some("released")
    );
    // Organization B's own view.
    let v = h.coord_ok(&b, "task_workflow_get", json!({ "task_id": tb })).await;
    assert_eq!(check_names(&v), ["ci", "lint"], "{v}");
    assert_eq!(v["summary"]["verified"], json!(["ci"]), "{v}");
}

#[tokio::test]
async fn an_unknown_organization_is_refused_before_any_write() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let f = fixture(&h, &a).await;
    let ghost = agent(UNKNOWN);
    let root: i64 = h.count(&format!("SELECT root_task_id FROM task_holds WHERE id = {}", f.hold));
    let before = h.snapshot();
    let events = h.events();
    for (action, params) in [
        ("task_workflow_set", json!({ "task_id": f.task, "stage": "review" })),
        (
            "task_check_record",
            json!({ "task_id": f.task, "name": "ci", "outcome": "fail", "head_sha": head('c') }),
        ),
        ("task_check_verify", json!({ "task_id": f.task, "name": "ci", "head_sha": head('c') })),
        ("task_hold", json!({ "root_task_id": f.task, "reason": "x" })),
        ("task_hold", json!({ "root_task_id": root, "mode": "resume" })),
    ] {
        let e = h.coord_err(&ghost, action, params).await;
        assert_eq!(reason(&e), "unknown_organization", "{action}: {e}");
        assert!(e.to_string().contains("no task was changed"), "{action}: {e}");
    }
    assert_eq!(h.snapshot(), before);
    assert_eq!(h.events(), events);
}

/// Deleting an organization-B task takes the holds rooted in its subtree
/// with it (PR 1's outcome, now in organization B only), and nothing of
/// organization B's shows to the default organization.
#[tokio::test]
async fn deleting_an_organization_b_task_leaves_no_organization_b_hold_visible_to_default() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let b = agent(ORG_B);
    let root = h.ok(&b, "task_add", json!({ "title": "B root" })).await["id"].as_i64().unwrap();
    let child =
        h.ok(&b, "task_add", json!({ "title": "B child", "parent_id": root })).await["id"].as_i64().unwrap();
    let outer =
        h.coord_ok(&b, "task_hold", json!({ "root_task_id": root, "reason": B_REASON })).await["hold"]["id"]
            .as_i64()
            .unwrap();
    let inner =
        h.coord_ok(&b, "task_hold", json!({ "root_task_id": child, "reason": B_REASON })).await["hold"]["id"]
            .as_i64()
            .unwrap();
    let ta = h.ok(&a, "task_add", json!({ "title": "A held" })).await["id"].as_i64().unwrap();
    h.coord_ok(&a, "task_hold", json!({ "root_task_id": ta, "reason": "A reason" })).await;
    assert_eq!(h.count("SELECT COUNT(*) FROM task_holds WHERE org_id = 'org-b'"), 2);

    h.ok(&b, "task_delete", json!({ "id": root })).await;
    h.ok(&a, "task_delete", json!({ "id": ta })).await;

    assert_eq!(h.count("SELECT COUNT(*) FROM task_holds WHERE org_id = 'org-b'"), 0);
    assert_eq!(h.count("SELECT COUNT(*) FROM task_hold_members WHERE org_id = 'org-b'"), 0);
    // The default organization's hold outlives its root, in its organization.
    assert_eq!(
        h.count(&format!("SELECT COUNT(*) FROM task_holds WHERE org_id = 'default' AND root_task_id = {ta}")),
        1
    );
    for who in [operator(), a.clone()] {
        let v = h.coord_ok(&who, "task_holds", json!({ "status": "all" })).await;
        assert_eq!(hold_roots(&v), [ta], "{v}");
        assert!(!v.to_string().contains(B_REASON), "{v}");
        for id in [outer, inner] {
            let e = h.coord_err(&who, "task_hold_get", json!({ "hold_id": id })).await;
            assert_eq!(e.code(), "not_found", "{e}");
        }
    }
    let v = h.coord_ok(&b, "task_holds", json!({ "status": "all" })).await;
    assert_eq!(v["holds"], json!([]), "{v}");
}

/// A delivery signed with the default organization's secret, for a
/// repository both organizations bind, re-verifies only the default
/// organization's checks at the head.
#[tokio::test]
async fn a_webhook_re_verifies_only_default_organization_checks() {
    // A GitHub that knows nothing: every lookup is a 404.
    let app = Router::new().fallback(|| async { (StatusCode::NOT_FOUND, "{}").into_response() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let h = H::with(|cfg| {
        cfg.github_webhook_secret_value = Some(WEBHOOK_SECRET.to_string().into());
        cfg.fetch_allow_loopback = true;
        cfg.github_api_url = base;
        cfg.github_token_value = Some("test-token".to_string().into());
        cfg.github_web_host = Some("github.com".into());
    });
    h.coord_ok(&operator(), "project_repo_bind", json!({ "project": "web", "repo": "shared/repo" })).await;
    h.sql(
        "INSERT INTO project_repo_bindings (org_id, project, repo, default_branch, bound_by, bound_at)
         VALUES ('org-b', 'web', 'shared/repo', 'main', 'operator', 'x')",
    )
    .unwrap();
    let (a, b) = (agent(DEFAULT_ORG), agent(ORG_B));
    let hh = head('d');
    let record = |task: i64| {
        json!({ "task_id": task, "name": "ci", "outcome": "pass", "head_sha": hh,
                "ref": { "kind": "ci_run", "ref": "41" }, "verify": false })
    };
    let ta = h.claimed(&a, "A web", Some("web")).await;
    let tb = h.claimed(&b, "B web", Some("web")).await;
    h.coord_ok(&a, "task_check_record", record(ta)).await;
    h.coord_ok(&b, "task_check_record", record(tb)).await;
    // A row of organization B's on the default organization's task (its
    // trigger dropped) is not the default organization's either.
    h.sql(&format!(
        "DROP TRIGGER task_checks_org_parent;
         INSERT INTO task_checks (org_id, task_id, name, head_sha, outcome, grade, ref_kind, ref, repo,
                                  recorded_by, recorded_at)
             VALUES ('org-b', {ta}, 'b-seeded', '{hh}', 'pass', 'attested', 'ci_run', '42', 'shared/repo', 'b', 'x');"
    ))
    .unwrap();

    let payload =
        json!({ "after": hh, "repository": { "full_name": "shared/repo", "default_branch": "main" } });
    let body = serde_json::to_vec(&payload).unwrap();
    let sig = signature_for(WEBHOOK_SECRET.as_bytes(), &body);
    let out = receive(
        &h.hub,
        WebhookDelivery { event: "push", delivery_id: "push-1", signature: Some(&sig), body: &body },
    )
    .await
    .unwrap();
    assert_eq!(out["handled"], "reverified", "{out}");
    let seen: Vec<(i64, String)> = out["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["task_id"].as_i64().unwrap(), c["name"].as_str().unwrap().to_string()))
        .collect();
    assert_eq!(seen, [(ta, "ci".to_string())], "{out}");
    assert!(out["checks"][0].get("error").is_none(), "{out}");
    assert_eq!(
        h.count(&format!("SELECT COUNT(*) FROM task_checks WHERE task_id = {ta} AND name = 'ci' AND verification_json IS NOT NULL")),
        1
    );
    assert_eq!(
        h.count("SELECT COUNT(*) FROM task_checks WHERE org_id = 'org-b' AND verification_json IS NOT NULL"),
        0
    );
}

#[tokio::test]
async fn organization_b_text_and_labels_never_reach_the_default_ledger() {
    let h = H::new();
    let b = agent_named(B_AGENT, ORG_B);
    let hb = head('b');
    let tb = h.claimed(&b, "B task", None).await;
    h.coord_ok(
        &b,
        "task_workflow_set",
        json!({ "task_id": tb, "stage": "implement", "goal": B_GOAL, "focus": B_FOCUS, "done": [B_DONE],
                "head_sha": hb, "expected_checks": [B_CHECK] }),
    )
    .await;
    h.coord_ok(
        &b,
        "task_check_record",
        json!({ "task_id": tb, "name": B_CHECK, "outcome": "pass", "head_sha": hb, "detail": B_DETAIL }),
    )
    .await;
    h.coord_ok(&b, "task_check_verify", json!({ "task_id": tb, "name": B_CHECK, "head_sha": hb })).await;
    // A verified check (seeded: no CI runs here) makes the task review-ready.
    h.sql(&format!(
        "UPDATE task_checks SET grade = 'verified' WHERE org_id = 'org-b' AND task_id = {tb} AND name = '{B_CHECK}'"
    ))
    .unwrap();
    h.coord_ok(&b, "task_workflow_set", json!({ "task_id": tb, "stage": "review" })).await;
    assert_eq!(h.count("SELECT COUNT(*) FROM review_ready_notices WHERE org_id = 'org-b'"), 1);
    h.coord_ok(&b, "task_hold", json!({ "root_task_id": tb, "mode": "cancel", "reason": B_REASON })).await;
    h.coord_ok(&b, "task_hold", json!({ "root_task_id": tb, "mode": "restore", "reason": B_REASON })).await;
    let other = h.ok(&b, "task_add", json!({ "title": "B other" })).await["id"].as_i64().unwrap();
    h.coord_ok(&b, "task_hold", json!({ "root_task_id": other, "reason": B_REASON })).await;
    h.coord_ok(&b, "task_hold", json!({ "root_task_id": other, "mode": "resume", "reason": B_REASON })).await;

    let rows: Vec<(String, String, Option<String>)> = h
        .hub
        .db()
        .read(|c| {
            Ok(c.prepare("SELECT channel, payload, originator FROM event_log ORDER BY seq")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?)
        })
        .unwrap();
    for channel in ["agent.task.workflow", "agent.task.hold"] {
        assert!(rows.iter().filter(|r| r.0 == channel).count() >= 3, "{channel} was ledgered");
    }
    for (_, payload, originator) in &rows {
        for s in [B_AGENT, B_REASON, B_CHECK, B_DETAIL, B_GOAL, B_FOCUS, B_DONE] {
            assert!(!payload.contains(s), "{s:?} reached a default ledger payload: {payload}");
            assert!(!originator.as_deref().unwrap_or_default().contains(s), "{s:?} is an originator");
        }
    }
    let ready = h
        .text(&format!(
            "SELECT payload FROM event_log WHERE json_extract(payload, '$.kind') = 'review_ready' \
             AND json_extract(payload, '$.task_id') = {tb}"
        ))
        .unwrap();
    assert!(ready.contains("\"checks\":null"), "{ready}");

    // The default organization's events keep their text and originator.
    let a = agent(DEFAULT_ORG);
    let ta = h.claimed(&a, "A task", None).await;
    h.coord_ok(
        &a,
        "task_check_record",
        json!({ "task_id": ta, "name": "visible-check", "outcome": "pass", "head_sha": hb }),
    )
    .await;
    h.coord_ok(&a, "task_hold", json!({ "root_task_id": ta, "reason": "visible reason" })).await;
    for (filter, want) in [
        (
            format!(
                "json_extract(payload, '$.kind') = 'check' AND json_extract(payload, '$.task_id') = {ta}"
            ),
            "visible-check",
        ),
        (
            format!(
                "json_extract(payload, '$.kind') = 'task.hold' AND json_extract(payload, '$.root_task_id') = {ta}"
            ),
            "visible reason",
        ),
    ] {
        let p =
            h.text(&format!("SELECT payload || '|' || originator FROM event_log WHERE {filter}")).unwrap();
        assert!(p.contains(want) && p.ends_with("|builder-1"), "{p}");
    }
}

/// The read-time settle on a default-organization hold read releases only
/// the default organization's due holds: organization B's due hold stays
/// active until organization B reads its holds.
#[tokio::test]
async fn a_hold_read_settles_only_the_readers_due_holds() {
    let h = H::new();
    let (a, b) = (agent(DEFAULT_ORG), agent(ORG_B));
    let root = h.ok(&b, "task_add", json!({ "title": "B root" })).await["id"].as_i64().unwrap();
    let child =
        h.ok(&b, "task_add", json!({ "title": "B child", "parent_id": root })).await["id"].as_i64().unwrap();
    h.ok(&b, "task_claim", json!({ "id": child })).await;
    let hold = h
        .coord_ok(
            &b,
            "task_hold",
            json!({ "root_task_id": root, "reason": "drain", "release_policy": "after_active_runs_finish" }),
        )
        .await["hold"]["id"]
        .as_i64()
        .unwrap();
    // Organization B's member run ends: the hold is now due.
    h.ok(&b, "task_update", json!({ "id": child, "status": "done" })).await;
    let status = |h: &H| h.text(&format!("SELECT status FROM task_holds WHERE id = {hold}"));

    let v = h.coord_ok(&a, "task_holds", json!({ "status": "all" })).await;
    assert_eq!(v["holds"], json!([]), "{v}");
    assert_eq!(status(&h).as_deref(), Some("active"), "a default read must not settle organization B's hold");

    let v = h.coord_ok(&b, "task_holds", json!({})).await;
    assert_eq!(v["holds"], json!([]), "released on organization B's read: {v}");
    assert_eq!(status(&h).as_deref(), Some("released"));
}

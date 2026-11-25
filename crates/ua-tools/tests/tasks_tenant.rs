//! The core task tables are tenant data (`docs/organization.md`, Scoping per
//! subsystem): `tasks`, `task_dependencies`, `task_comments` and
//! `task_comment_threads` (`organization.v1.tools.tasks`,
//! `tasks.v2.org_scope`), with the cross-family rules that a routine run's,
//! a workflow run's, a cycle's and a deliverable's `task_id` points inside
//! its own organization (`routines.v3.task_org`, `workflows.v3.task_org`,
//! `cycles.v3.task_org`, `deliverables.v2.task_org`). No key needed a
//! rebuild: task ids stay hub-global AUTOINCREMENT ids.
//!
//! A second organization is created at the storage level, as no tool creates
//! one yet, and its callers are built by hand. Organization-B rows are written
//! through the tools with an organization-B caller; only the legacy rows of
//! the upgrade test, the defence-in-depth trigger rows and organization B's
//! binding (no caller outside the default organization holds operator
//! authority yet) are seeded by SQL.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::families::github::{WebhookDelivery, poll_once, receive, signature_for};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 6] = [
    "organization.v1.tools.tasks",
    "tasks.v2.org_scope",
    "routines.v3.task_org",
    "workflows.v3.task_org",
    "cycles.v3.task_org",
    "deliverables.v2.task_org",
];
const TABLES: [&str; 4] = ["tasks", "task_dependencies", "task_comments", "task_comment_threads"];
/// Organization-B text that must never reach the default organization's
/// ledger, in a payload or as an originator.
const B_TITLE: &str = "Project Falcon acquisition shortlist";
const B_NOTES: &str = "Falcon board memo: offer ceiling";
const B_BODY: &str = "Kestrel diligence call notes";
const B_REASON: &str = "Osprey parked pending counsel";
const B_AGENT: &str = "kestrel-nightshift";
const B_MENTION: &str = "osprey-counsel";
const B_CHECK: &str = "falcon-secret-check";
const WEBHOOK_SECRET: &str = "tenant-webhook-secret";

/// Parts registered after this family's, which need its `org_id` columns
/// (the continuity, holds, delegation, goal, proposal, policy
/// authorization, dispatch and node queue families').
const LATER: [&str; 14] = [
    "organization.v1.tools.continuity",
    "continuity.v2.org_scope",
    "organization.v1.tools.holds",
    "governance.v3.holds_org_scope",
    "organization.v1.tools.delegation",
    "delegation.v2.org_scope",
    "organization.v1.tools.goals",
    "goals.v2.org_scope",
    "organization.v1.tools.proposals",
    "governance.v4.proposals_org_scope",
    "organization.v1.tools.policy_authorizations",
    "github.v3.policy_authorizations_org_scope",
    "dispatch.v4.org_scope",
    "node_queue.v2.org_scope",
];

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts()
        .into_iter()
        .filter(|p| !PARTS.contains(&p.name) && !LATER.contains(&p.name))
        .collect()
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

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
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
        cfg.profiles.insert("lead-1".into(), "coordinator".into());
        cfg.routines_enabled = true;
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

    async fn err(&self, who: &Caller, tool: &str, args: Value) -> UaError {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => panic!("{}: {tool}({args}) should fail, got {v}", who.org_id),
            Err(e) => e,
        }
    }

    async fn add(&self, who: &Caller, args: Value) -> i64 {
        self.ok(who, "task_add", args).await["id"].as_i64().unwrap()
    }

    async fn comment(&self, who: &Caller, params: Value) -> Result<Value, UaError> {
        self.call(who, "task_comment", json!({ "action": "append", "params": params })).await
    }

    async fn coord(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "coordination_manage", json!({ "action": action, "params": params })).await
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

    /// Every row of the four tables, as text: a write that changes nothing
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

/// `e` reads exactly as `missing` does, once each names the same id.
fn same_as_missing(e: &UaError, missing: &UaError, id: i64, absent: i64) {
    assert_eq!(e.code(), missing.code(), "{e} / {missing}");
    assert_eq!(
        e.to_string().replace(&id.to_string(), "ID"),
        missing.to_string().replace(&absent.to_string(), "ID"),
        "another organization's row must answer as a missing one"
    );
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
                "INSERT INTO tasks (id, title, created_at, updated_at) VALUES
                     (1, 'Legacy root', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');
                 INSERT INTO tasks (id, title, parent_id, created_at, updated_at) VALUES
                     (2, 'Legacy child searchterm', 1, '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');
                 INSERT INTO task_dependencies (task_id, depends_on_task_id, created_by, created_at)
                     VALUES (2, 1, 'old', 'x');
                 INSERT INTO task_comment_threads (task_id, revision, updated_at) VALUES (2, 1, 'x');
                 INSERT INTO task_comments (task_id, author, body, thread_revision, created_at)
                     VALUES (2, 'old', 'legacy comment', 1, 'x');",
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
                    let triggers = names(c, "trigger", t);
                    for want in
                        [format!("{t}_org_exists"), format!("{t}_org_immutable"), format!("{t}_org_parent")]
                    {
                        assert!(triggers.contains(&want), "{t}: {triggers:?}");
                    }
                }
                let idx = names(c, "index", "tasks");
                for want in ["idx_tasks_org_status", "idx_tasks_org_project", "idx_tasks_org_claimed"] {
                    assert!(idx.contains(&want.to_string()), "{idx:?}");
                }
                for (t, trig) in [
                    ("routine_runs", "routine_runs_task_org"),
                    ("workflow_runs", "workflow_runs_task_org"),
                    ("autonomous_cycles", "autonomous_cycles_task_org"),
                    ("deliverables", "deliverables_task_org"),
                ] {
                    assert!(names(c, "trigger", t).contains(&trig.to_string()), "{t}");
                }
                let dangling: i64 =
                    c.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0))?;
                assert_eq!(dangling, 0);
                Ok(())
            })
            .unwrap();
    }

    // The legacy rows answer through the tools, unchanged in shape.
    let hub = Hub::open(cfg).unwrap();
    let reg = builtin_registry();
    let me = agent(DEFAULT_ORG);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let v = reg.call(&hub, &me, "task_list", json!({ "status": "all" })).await.unwrap();
        let ids: Vec<i64> =
            v["tasks"].as_array().unwrap().iter().map(|t| t["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, [1, 2], "{v}");
        assert!(v["tasks"][0].get("org_id").is_none(), "a task reply keeps its shape: {v}");
        let v = reg
            .call(&hub, &me, "task_list", json!({ "status": "all", "query": "searchterm" }))
            .await
            .unwrap();
        assert_eq!(v["tasks"][0]["id"], 2, "{v}");
        let v = reg
            .call(&hub, &me, "task_comment", json!({ "action": "list", "params": { "task_id": 2 } }))
            .await
            .unwrap();
        assert_eq!(v["comments"][0]["body"], "legacy comment", "{v}");
        assert!(v["comments"][0].get("org_id").is_none(), "{v}");
    });
}

/// Defence in depth: whatever a tool would check, the triggers keep every
/// task reference inside one organization, and on the families already
/// converted, every `task_id`.
#[test]
fn the_triggers_refuse_every_cross_organization_task_reference() {
    let h = H::new();
    h.sql(
        "INSERT INTO tasks (id, org_id, title, created_at, updated_at) VALUES
             (10, 'default', 'A', 'x', 'x'), (20, 'org-b', 'B', 'x', 'x'), (21, 'org-b', 'B2', 'x', 'x');
         INSERT INTO task_comments (id, org_id, task_id, author, body, thread_revision, created_at)
             VALUES (100, 'default', 10, 'a', 'a', 1, 'x'), (200, 'org-b', 20, 'b', 'b', 1, 'x');",
    )
    .unwrap();
    let refused = |sql: &str| {
        let e = h.sql(sql).unwrap_err();
        assert!(e.contains("another organization") || e.contains("its own organization"), "{sql}: {e}");
    };
    // A parent, a fold target.
    refused(
        "INSERT INTO tasks (org_id, title, parent_id, created_at, updated_at) VALUES ('org-b', 'x', 10, 'x', 'x')",
    );
    refused("UPDATE tasks SET parent_id = 10 WHERE id = 21");
    refused("UPDATE tasks SET folded_into = 10 WHERE id = 21");
    // Both ends of a dependency.
    refused(
        "INSERT INTO task_dependencies (org_id, task_id, depends_on_task_id, created_by, created_at) VALUES ('org-b', 20, 10, 'b', 'x')",
    );
    refused(
        "INSERT INTO task_dependencies (org_id, task_id, depends_on_task_id, created_by, created_at) VALUES ('org-b', 10, 20, 'b', 'x')",
    );
    h.sql("INSERT INTO task_dependencies (id, org_id, task_id, depends_on_task_id, created_by, created_at) VALUES (5, 'org-b', 21, 20, 'b', 'x')").unwrap();
    refused("UPDATE task_dependencies SET depends_on_task_id = 10 WHERE id = 5");
    // A comment's task and parent comment, and a thread.
    refused(
        "INSERT INTO task_comments (org_id, task_id, author, body, thread_revision, created_at) VALUES ('org-b', 10, 'b', 'b', 1, 'x')",
    );
    refused(
        "INSERT INTO task_comments (org_id, task_id, parent_comment_id, author, body, thread_revision, created_at) VALUES ('org-b', 20, 100, 'b', 'b', 1, 'x')",
    );
    refused("UPDATE task_comments SET task_id = 10 WHERE id = 200");
    refused(
        "INSERT INTO task_comment_threads (org_id, task_id, revision, updated_at) VALUES ('org-b', 10, 1, 'x')",
    );
    // The converted families' task ids.
    h.sql(
        "INSERT INTO routines (id, org_id, title, trigger, lane, project, domain, concurrency, catch_up,
             cursor_at, owner, created_at, updated_at)
         VALUES (7, 'org-b', 'r', 'api', 'default', 'default', 'general', 'skip', 'none', 'x', 'lead-1', 'x', 'x');",
    )
    .unwrap();
    refused(
        "INSERT INTO routine_runs (org_id, routine_id, fire_key, scheduled_for, status, task_id, created_at) VALUES ('org-b', 7, 'k', 'x', 'created', 10, 'x')",
    );
    refused(
        "INSERT INTO workflow_runs (run_id, org_id, kind, name, definition_digest, definition, task_id, owner, owner_profile, status, created_at, updated_at) VALUES ('r1', 'org-b', 'workflow', 'n', 'd', '{}', 10, 'o', 'developer', 'done', 'x', 'x')",
    );
    refused(
        "INSERT INTO autonomous_cycles (org_id, id, task_id, state, max_time_s, max_tokens, max_retries,
             max_cost_cents, created_by, created_at, updated_at)
         VALUES ('org-b', 'c1', 10, 'plan', 60, 100, 3, 50, 'b', 'x', 'x')",
    );
    refused(
        "INSERT INTO deliverables (org_id, task_id, kind, title, repo, created_by, created_at) VALUES ('org-b', 10, 'file', 't', NULL, 'b', 'x')",
    );
    // The same rows inside one organization are accepted.
    h.sql("INSERT INTO task_dependencies (org_id, task_id, depends_on_task_id, created_by, created_at) VALUES ('default', 10, 10, 'a', 'x')").ok();
    h.sql("INSERT INTO deliverables (org_id, task_id, kind, title, repo, created_by, created_at) VALUES ('org-b', 20, 'file', 't', NULL, 'b', 'x')").unwrap();
}

// --- isolation ---------------------------------------------------------------------------------

/// One organization's task, dependency, comments and subtree, through the tools.
struct Fixture {
    task: i64,
    child: i64,
    dep: i64,
    comment: i64,
}

async fn fixture(h: &H, who: &Caller) -> Fixture {
    let task = h
        .add(
            who,
            json!({ "title": "Shared title", "notes": "[project-spec] shared words", "project": "web" }),
        )
        .await;
    let child = h.add(who, json!({ "title": "Child", "parent_id": task })).await;
    let other = h.add(who, json!({ "title": "Other" })).await;
    let dep = h.ok(who, "dependency_add", json!({ "task_id": child, "depends_on_task_id": other })).await
        ["dependency"]["id"]
        .as_i64()
        .unwrap();
    let comment = h.comment(who, json!({ "task_id": task, "body": "hello" })).await.unwrap()["comment"]["id"]
        .as_i64()
        .unwrap();
    Fixture { task, child, dep, comment }
}

#[tokio::test]
async fn each_organization_sees_only_its_own_tasks_through_every_tool() {
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

        // Writes that name the other organization's task answer as for a
        // missing one, and change nothing.
        for (tool, args, missing_args) in [
            (
                "task_update",
                json!({ "id": t, "status": "doing" }),
                json!({ "id": absent, "status": "doing" }),
            ),
            (
                "task_update",
                json!({ "id": t, "append_note": "x" }),
                json!({ "id": absent, "append_note": "x" }),
            ),
            ("task_claim", json!({ "id": t }), json!({ "id": absent })),
            (
                "dependency_add",
                json!({ "task_id": mine.task, "depends_on_task_id": t }),
                json!({ "task_id": mine.task, "depends_on_task_id": absent }),
            ),
            ("project_build", json!({ "parent_task_id": t }), json!({ "parent_task_id": absent })),
            (
                "task_add",
                json!({ "title": "x", "parent_id": t }),
                json!({ "title": "x", "parent_id": absent }),
            ),
        ] {
            let e = h.err(me, tool, args).await;
            let m = h.err(me, tool, missing_args).await;
            same_as_missing(&e, &m, t, absent);
        }
        let e = h.err(me, "dependency_remove", json!({ "dependency_id": theirs.dep })).await;
        let m = h.err(me, "dependency_remove", json!({ "dependency_id": absent })).await;
        same_as_missing(&e, &m, theirs.dep, absent);
        // A move under another organization's task is refused like a missing parent.
        let e = h.err(me, "task_update", json!({ "id": mine.child, "parent_id": t })).await;
        let m = h.err(me, "task_update", json!({ "id": mine.child, "parent_id": absent })).await;
        same_as_missing(&e, &m, t, absent);
        // Delete answers as for a missing task.
        let del = h.ok(me, "task_delete", json!({ "id": t })).await;
        assert_eq!(del, h.ok(me, "task_delete", json!({ "id": absent })).await);
        // Comments.
        let e = h.comment(me, json!({ "task_id": t, "body": "x" })).await.unwrap_err();
        let m = h.comment(me, json!({ "task_id": absent, "body": "x" })).await.unwrap_err();
        same_as_missing(&e, &m, t, absent);
        let e = h
            .comment(me, json!({ "task_id": mine.task, "body": "x", "parent_comment_id": theirs.comment }))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("parent comment is not on this task"), "{e}");
        for (action, p, pm, id) in [
            ("list", json!({ "task_id": t }), json!({ "task_id": absent }), t),
            ("get", json!({ "comment_id": theirs.comment }), json!({ "comment_id": absent }), theirs.comment),
        ] {
            let e = h.err(me, "task_comment", json!({ "action": action, "params": p })).await;
            let m = h.err(me, "task_comment", json!({ "action": action, "params": pm })).await;
            same_as_missing(&e, &m, id, absent);
        }
        assert_eq!(h.snapshot(), before, "{org}: the other organization's rows are untouched");
        assert_eq!(h.events(), events, "{org}: nothing was ledgered");

        // Reads list only the caller's rows.
        let listed = h.ok(me, "task_list", json!({ "status": "all", "fields": "compact" })).await;
        let ids: Vec<i64> =
            listed["tasks"].as_array().unwrap().iter().map(|x| x["id"].as_i64().unwrap()).collect();
        assert!(
            ids.contains(&mine.task) && !ids.contains(&t) && !ids.contains(&theirs.child),
            "{org}: {ids:?}"
        );
        let listed = h.ok(me, "task_list", json!({ "status": "all", "parent_id": t })).await;
        assert_eq!(listed["tasks"], json!([]), "{org}");
        let deps = h.ok(me, "dependency_list", json!({})).await;
        let dep_ids: Vec<i64> =
            deps["dependencies"].as_array().unwrap().iter().map(|d| d["id"].as_i64().unwrap()).collect();
        assert_eq!(dep_ids, [mine.dep], "{org}");
        assert_eq!(
            h.ok(me, "dependency_list", json!({ "task_id": theirs.child })).await["dependencies"],
            json!([])
        );
        let lineage = h.ok(me, "lineage", json!({ "task_id": t })).await;
        assert_eq!(lineage, h.ok(me, "lineage", json!({ "task_id": t })).await);
        assert_eq!(lineage["task"]["title"], Value::Null, "{org}: {lineage}");
        assert_eq!(lineage["empty"], true);
        // The caller's own subtree, rollup and lineage stay its own.
        let own = h.ok(me, "task_update", json!({ "id": mine.task, "priority": "high" })).await;
        assert!(own.get("org_id").is_none(), "{own}");
        assert_eq!(own["rollup"]["counts"]["open"], 1, "{org}: only its own child: {own}");
        let child = h.ok(me, "task_update", json!({ "id": mine.child, "priority": "low" })).await;
        assert_eq!(child["lineage"], json!([mine.task]), "{org}");
        h.ok(me, "project_build", json!({ "parent_task_id": mine.task })).await;
    }
    // The migration manifest is hub-wide: only the default organization may
    // build or compare one, directly or through export_data.
    let lead_b = Caller { profile: Profile::Coordinator, ..agent_named("lead-1", ORG_B) };
    for (tool, args) in [
        ("export_migration_manifest", json!({})),
        ("export_data", json!({ "action": "manifest" })),
        ("compare_migration_manifests", json!({ "left": {}, "right": {} })),
        ("export_data", json!({ "action": "compare", "params": { "left": {}, "right": {} } })),
    ] {
        let e = h.err(&lead_b, tool, args.clone()).await;
        assert_eq!(reason(&e), "org_unsupported", "{tool}({args}): {e}");
    }
    let lead_a = Caller { profile: Profile::Coordinator, ..agent_named("lead-1", DEFAULT_ORG) };
    let m = h.ok(&lead_a, "export_migration_manifest", json!({})).await;
    assert!(m["manifest"]["tasks"].as_array().is_some_and(|t| !t.is_empty()), "{m}");

    // Every row stayed in its organization.
    assert_eq!(h.count("SELECT COUNT(*) FROM tasks WHERE org_id = 'org-b'"), 3);
    assert_eq!(h.count("SELECT COUNT(*) FROM task_dependencies WHERE org_id = 'org-b'"), 1);
    assert_eq!(h.count("SELECT COUNT(*) FROM task_comments WHERE org_id = 'org-b'"), 1);
    assert_eq!(h.count("SELECT COUNT(*) FROM task_comment_threads WHERE org_id = 'org-b'"), 1);
}

/// Defence in depth: with the reference triggers dropped and rows seeded
/// across organizations, the lookups still never follow a reference into
/// another organization (lineage, rollup, a parent comment).
#[tokio::test]
async fn the_lookups_never_follow_a_reference_into_another_organization() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let b = agent(ORG_B);
    let root = h.add(&a, json!({ "title": "A root", "notes": "[project-spec] a" })).await;
    let theirs = h.add(&b, json!({ "title": "B task" })).await;
    let mine = h.add(&b, json!({ "title": "B own" })).await;
    let a_comment = h.comment(&a, json!({ "task_id": root, "body": "a" })).await.unwrap()["comment"]["id"]
        .as_i64()
        .unwrap();
    h.sql(&format!(
        "DROP TRIGGER tasks_org_parent_update;
         DROP TRIGGER task_comments_org_parent;
         UPDATE tasks SET parent_id = {root} WHERE id = {theirs};
         INSERT INTO task_comments (id, org_id, task_id, author, body, thread_revision, created_at)
             VALUES (9000, 'org-b', {mine}, 'x', 'x', 1, 'x');"
    ))
    .unwrap();
    let _ = a_comment;
    // B's task, seeded under A's root, shows no lineage into A.
    let v = h.ok(&b, "task_update", json!({ "id": theirs, "priority": "low" })).await;
    assert_eq!(v["lineage"], json!([]), "{v}");
    // A's rollup counts none of B's tasks.
    let v = h.ok(&a, "task_update", json!({ "id": root, "priority": "low" })).await;
    assert_eq!(v["rollup"]["counts"]["open"], 0, "{v}");
    assert_eq!(v["rollup"]["active"], json!([]), "{v}");
    // A comment of A's on B's task (seeded) is not a parent A can reply to,
    // even on the task it names.
    h.sql(&format!(
        "INSERT INTO task_comments (id, org_id, task_id, author, body, thread_revision, created_at)
             VALUES (9001, 'org-b', {root}, 'x', 'x', 1, 'x');"
    ))
    .unwrap();
    let e = h
        .comment(&a, json!({ "task_id": root, "body": "reply", "parent_comment_id": 9001 }))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("parent comment is not on this task"), "{e}");
}

#[tokio::test]
async fn ranked_search_returns_only_the_callers_matches() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let b = agent(ORG_B);
    let ta = h.add(&a, json!({ "title": "zanzibar ledger", "notes": "zanzibar" })).await;
    let tb = h.add(&b, json!({ "title": "zanzibar ledger", "notes": "zanzibar zanzibar" })).await;
    for (me, mine) in [(&a, ta), (&b, tb)] {
        let v = h.ok(me, "task_list", json!({ "status": "all", "query": "zanzibar" })).await;
        let ids: Vec<i64> =
            v["tasks"].as_array().unwrap().iter().map(|t| t["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, [mine], "{}: {v}", me.org_id);
        let v = h.ok(me, "task_list", json!({ "status": "all", "notes_contain": "zanzibar" })).await;
        assert_eq!(v["tasks"].as_array().unwrap().len(), 1, "{v}");
    }
}

#[tokio::test]
async fn an_unknown_organization_is_refused_before_any_write() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let f = fixture(&h, &a).await;
    let ghost = agent(UNKNOWN);
    let before = h.snapshot();
    let events = h.events();
    for (tool, args) in [
        ("task_add", json!({ "title": "x" })),
        ("task_update", json!({ "id": f.task, "status": "blocked" })),
        ("task_claim", json!({ "id": f.task })),
        ("task_delete", json!({ "id": f.task })),
        ("dependency_add", json!({ "task_id": f.task, "depends_on_task_id": f.child })),
        ("dependency_remove", json!({ "dependency_id": f.dep })),
        ("project_build", json!({ "parent_task_id": f.task })),
        ("task_comment", json!({ "action": "append", "params": { "task_id": f.task, "body": "x" } })),
    ] {
        let e = h.err(&ghost, tool, args).await;
        assert_eq!(reason(&e), "unknown_organization", "{tool}: {e}");
        // The registry refuses the organization before the tool runs.
        assert!(e.to_string().contains("nothing ran and nothing was written"), "{tool}: {e}");
    }
    for (action, params) in [
        ("queue_park", json!({ "task_id": f.task, "reason": "x" })),
        ("task_hold", json!({ "root_task_id": f.task, "reason": "x" })),
        ("task_workflow_set", json!({ "task_id": f.task, "stage": "review" })),
    ] {
        let e = h.coord(&ghost, action, params).await.unwrap_err();
        assert_eq!(reason(&e), "unknown_organization", "{action}: {e}");
    }
    assert_eq!(h.snapshot(), before);
    assert_eq!(h.events(), events);
}

#[tokio::test]
async fn an_idempotency_key_never_replays_across_organizations() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let b = agent(ORG_B);
    let key = "shared-retry-key";
    let ta = h.add(&a, json!({ "title": "A's", "idempotency_key": key })).await;
    let tb = h.add(&b, json!({ "title": "B's", "idempotency_key": key })).await;
    assert_ne!(ta, tb, "B's first use is a fresh task, not A's reply");
    assert_eq!(h.text(&format!("SELECT org_id FROM tasks WHERE id = {tb}")).as_deref(), Some(ORG_B));
    // Each organization's retry replays its own reply.
    assert_eq!(h.add(&a, json!({ "title": "A's", "idempotency_key": key })).await, ta);
    assert_eq!(h.add(&b, json!({ "title": "B's", "idempotency_key": key })).await, tb);
    // The default organization's stored key keeps its form.
    assert_eq!(h.count(&format!("SELECT COUNT(*) FROM idempotency_keys WHERE key = 'task_add:{key}'")), 1);

    let ua = h.ok(&a, "task_update", json!({ "id": ta, "append_note": "a", "idempotency_key": "upd" })).await;
    let ub = h.ok(&b, "task_update", json!({ "id": tb, "append_note": "b", "idempotency_key": "upd" })).await;
    assert_eq!((ua["id"].as_i64(), ub["id"].as_i64()), (Some(ta), Some(tb)), "{ua} / {ub}");
    assert_eq!(h.count("SELECT COUNT(*) FROM tasks WHERE org_id = 'org-b' AND notes = 'b'"), 1);
}

/// Task-update keys are the caller's own and bound to one task: another
/// caller's use of the same key, or a squat of a predictable one, neither
/// replays the first reply nor drops the update, and labels that differ
/// never share a stored key.
#[tokio::test]
async fn a_task_update_key_is_scoped_to_its_caller_and_its_task() {
    let h = H::new();
    let one = agent_named("builder-1", DEFAULT_ORG);
    let two = agent_named("builder-2", DEFAULT_ORG);
    let t1 = h.add(&one, json!({ "title": "first" })).await;
    let t2 = h.add(&one, json!({ "title": "second" })).await;

    let first =
        h.ok(&one, "task_update", json!({ "id": t1, "append_note": "one", "idempotency_key": "k" })).await;
    // Another caller, same key and task: its own update runs.
    let second =
        h.ok(&two, "task_update", json!({ "id": t1, "append_note": "two", "idempotency_key": "k" })).await;
    assert!(second["notes"].as_str().unwrap().contains("two"), "{second}");
    assert_ne!(second, first);
    // The first caller's retry replays its own reply.
    let again =
        h.ok(&one, "task_update", json!({ "id": t1, "append_note": "one", "idempotency_key": "k" })).await;
    assert_eq!(again, first);
    // The same caller's key on another task is refused, and changes nothing.
    let before = h.snapshot();
    let e = h.err(&one, "task_update", json!({ "id": t2, "priority": "high", "idempotency_key": "k" })).await;
    assert_eq!(reason(&e), "idempotency_key_reused", "{e}");
    assert_eq!(h.snapshot(), before);

    // A squatted predictable key does not block another caller.
    h.ok(&two, "task_update", json!({ "id": t2, "priority": "low", "idempotency_key": "deploy-1" })).await;
    let mine = h
        .ok(&one, "task_update", json!({ "id": t1, "priority": "high", "idempotency_key": "deploy-1" }))
        .await;
    assert_eq!((mine["id"].as_i64(), mine["priority"].as_str()), (Some(t1), Some("high")), "{mine}");

    // `x:y` with key `z` and `x` with key `y:z` are different stored keys.
    let xy = agent_named("x:y", DEFAULT_ORG);
    let x = agent_named("x", DEFAULT_ORG);
    h.ok(&xy, "task_update", json!({ "id": t1, "priority": "low", "idempotency_key": "z" })).await;
    let v = h.ok(&x, "task_update", json!({ "id": t2, "priority": "high", "idempotency_key": "y:z" })).await;
    assert_eq!((v["id"].as_i64(), v["priority"].as_str()), (Some(t2), Some("high")), "{v}");
    // The scoped form is what is stored.
    assert_eq!(h.count("SELECT COUNT(*) FROM idempotency_keys WHERE key = 'task_update:builder-2:k'"), 1);
    assert_eq!(h.count("SELECT COUNT(*) FROM idempotency_keys WHERE key = 'task_update:x%3Ay:z'"), 1);
    assert_eq!(h.count("SELECT COUNT(*) FROM idempotency_keys WHERE key = 'task_update:k'"), 0);
}

/// Deleting another organization's task deletes the holds rooted in its
/// subtree and the policy authorizations naming it, so none falls into the
/// default organization once its task is gone. The default organization's
/// rows outlive their task, as before.
#[tokio::test]
async fn deleting_an_organization_b_task_takes_its_holds_and_authorizations_with_it() {
    let h = H::new();
    let op = Caller {
        kind: ActorKind::Human,
        profile: Profile::Coordinator,
        ..agent_named("operator", DEFAULT_ORG)
    };
    let a = agent(DEFAULT_ORG);
    let b = agent(ORG_B);
    let root = h.add(&b, json!({ "title": B_TITLE })).await;
    let child = h.add(&b, json!({ "title": "B child", "parent_id": root })).await;
    h.coord(&b, "task_hold", json!({ "root_task_id": root, "reason": B_REASON })).await.unwrap();
    // A nested hold, rooted inside the subtree.
    h.coord(&b, "task_hold", json!({ "root_task_id": child, "reason": B_REASON })).await.unwrap();
    let ta = h.add(&a, json!({ "title": "A held" })).await;
    h.coord(&a, "task_hold", json!({ "root_task_id": ta, "reason": "A reason" })).await.unwrap();
    // Seeded by SQL: recording one needs the organization's binding.
    let sha = "d".repeat(40);
    h.sql(&format!(
        "INSERT INTO policy_authorizations (org_id, repo, pr, head_sha, task_id, policy_ref, authorized_by, created_at, expires_at)
         VALUES ('org-b', 'owner-b/falcon', 3, '{sha}', {child}, 'osprey-policy', 'operator', 'x', '2999-01-01T00:00:00Z'),
                ('default', 'owner-a/repo', 4, '{sha}', {ta}, 'a-policy', 'operator', 'x', '2999-01-01T00:00:00Z');"
    ))
    .unwrap();
    assert_eq!(h.count("SELECT COUNT(*) FROM task_hold_members"), 4);

    h.ok(&b, "task_delete", json!({ "id": root })).await;
    h.ok(&a, "task_delete", json!({ "id": ta })).await;

    assert_eq!(
        h.count(&format!("SELECT COUNT(*) FROM task_holds WHERE root_task_id IN ({root}, {child})")),
        0
    );
    // The default organization's hold row outlives its root (its members
    // go with their tasks, as before).
    assert_eq!(h.count(&format!("SELECT COUNT(*) FROM task_holds WHERE root_task_id = {ta}")), 1);
    assert_eq!(h.count(&format!("SELECT COUNT(*) FROM policy_authorizations WHERE task_id = {ta}")), 1);
    assert_eq!(h.count(&format!("SELECT COUNT(*) FROM policy_authorizations WHERE task_id = {child}")), 0);
    // The default organization's rows stay, and show only its own.
    let holds = h.coord(&op, "task_holds", json!({ "status": "all" })).await.unwrap();
    let roots: Vec<i64> =
        holds["holds"].as_array().unwrap().iter().map(|x| x["root_task_id"].as_i64().unwrap()).collect();
    assert_eq!(roots, [ta], "{holds}");
    assert!(!holds.to_string().contains(B_REASON), "{holds}");
    let auths = h.ok(&op, "policy_authorization_list", json!({ "include_inactive": true })).await;
    let tasks: Vec<i64> =
        auths["authorizations"].as_array().unwrap().iter().map(|x| x["task_id"].as_i64().unwrap()).collect();
    assert_eq!(tasks, [ta], "{auths}");
    assert!(!auths.to_string().contains("owner-b/falcon"), "{auths}");
}

/// `state_sync_verify` counts only the caller's organization's tasks in
/// `task_fts`'s sync check.
#[tokio::test]
async fn state_sync_verify_counts_only_the_callers_tasks() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let b = agent(ORG_B);
    for i in 0..3 {
        h.add(&a, json!({ "title": format!("A {i}") })).await;
    }
    h.add(&b, json!({ "title": "B only" })).await;
    for (me, n) in [(&b, 1), (&a, 3)] {
        let v = h.ok(me, "state_sync_verify", json!({})).await;
        assert_eq!(v["task_db_count"], n, "{v}");
        let fts = v["checks"]["fts"].as_array().unwrap().iter().find(|f| f["index"] == "task_fts").unwrap();
        assert_eq!((fts["table_rows"].as_i64(), fts["indexed_rows"].as_i64()), (Some(n), Some(n)), "{fts}");
        assert_eq!(fts["in_sync"], true, "{fts}");
    }
}

/// A proposal or contract marker on another organization's task is checked
/// against that organization's work proposals only, and fails closed when
/// it names none of them (`goals_tenant.rs` holds the cross-organization
/// cases).
#[tokio::test]
async fn an_organization_b_contract_marker_is_checked_in_organization_b() {
    let h = H::new();
    let b = agent(ORG_B);
    for (notes, says) in [
        ("[proposal: wp_0123456789ab#0]", "unknown work proposal item"),
        ("[contract: deadbeef]", "no [proposal: ...] marker"),
    ] {
        let t = h.add(&b, json!({ "title": "B marked", "notes": notes })).await;
        let e = h.err(&b, "task_claim", json!({ "id": t })).await;
        assert_eq!(reason(&e), "contract_mismatch", "{e}");
        assert!(e.to_string().contains(says), "{e}");
    }
    // An unmarked task claims as before.
    let t = h.add(&b, json!({ "title": "B plain" })).await;
    h.ok(&b, "task_claim", json!({ "id": t })).await;
}

// --- the ledger --------------------------------------------------------------------------------

#[tokio::test]
async fn organization_b_text_and_labels_never_reach_the_default_ledger() {
    let h = H::new();
    let b = agent_named(B_AGENT, ORG_B);
    let id = h.add(&b, json!({ "title": B_TITLE, "notes": format!("[project-spec] {B_NOTES}") })).await;
    let child = h.add(&b, json!({ "title": B_TITLE, "parent_id": id })).await;
    let other = h.add(&b, json!({ "title": B_TITLE })).await;
    h.ok(&b, "task_claim", json!({ "id": child })).await;
    h.ok(&b, "task_update", json!({ "id": child, "append_note": B_NOTES, "title": format!("{B_TITLE} 2") }))
        .await;
    h.ok(&b, "dependency_add", json!({ "task_id": other, "depends_on_task_id": id })).await;
    h.comment(&b, json!({ "task_id": id, "body": B_BODY, "mentions": [B_MENTION] })).await.unwrap();
    h.ok(&b, "project_build", json!({ "parent_task_id": id })).await;
    h.ok(&b, "task_update", json!({ "id": child, "status": "done", "release_claim": true })).await;
    h.coord(&b, "queue_park", json!({ "task_id": other, "reason": B_REASON })).await.unwrap();
    h.coord(&b, "queue_unpark", json!({ "task_id": other, "reason": B_REASON })).await.unwrap();
    h.coord(&b, "task_hold", json!({ "root_task_id": other, "reason": B_REASON })).await.unwrap();
    h.coord(&b, "task_hold", json!({ "root_task_id": other, "mode": "resume", "reason": B_REASON }))
        .await
        .unwrap();
    let claimed = h.add(&b, json!({ "title": B_TITLE })).await;
    h.ok(&b, "task_claim", json!({ "id": claimed })).await;
    h.coord(
        &b,
        "task_check_record",
        json!({ "task_id": claimed, "name": B_CHECK, "outcome": "pass", "head_sha": "a".repeat(40) }),
    )
    .await
    .unwrap();
    h.ok(&b, "task_delete", json!({ "id": other })).await;

    let rows: Vec<(String, Option<String>)> = h
        .hub
        .db()
        .read(|c| {
            Ok(c.prepare("SELECT payload, originator FROM event_log ORDER BY seq")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?)
        })
        .unwrap();
    assert!(rows.len() > 10, "the writes were ledgered: {}", rows.len());
    for (payload, originator) in &rows {
        for s in [B_TITLE, B_NOTES, B_BODY, B_REASON, B_AGENT, B_MENTION, B_CHECK] {
            assert!(!payload.contains(s), "{s:?} reached a default ledger payload: {payload}");
            assert!(!originator.as_deref().unwrap_or_default().contains(s), "{s:?} is an originator");
        }
    }
    // Ids and statuses remain.
    assert!(h.count(&format!(
        "SELECT COUNT(*) FROM event_log WHERE channel = 'agent.task.created' AND json_extract(payload, '$.task_id') = {id}"
    )) == 1);

    // The default organization's events keep their text and originator.
    let a = agent(DEFAULT_ORG);
    let ida = h.add(&a, json!({ "title": "Default visible title" })).await;
    let p = h
        .text(&format!(
            "SELECT payload || '|' || originator FROM event_log WHERE channel = 'agent.task.created' \
             AND json_extract(payload, '$.task_id') = {ida}"
        ))
        .unwrap();
    assert!(p.contains("Default visible title") && p.ends_with("|builder-1"), "{p}");
}

// --- runners and cross-family paths ------------------------------------------------------------

#[tokio::test]
async fn organization_b_routine_fires_create_organization_b_tasks() {
    let h = H::new();
    let lead = Caller { profile: Profile::Coordinator, ..agent_named("lead-1", ORG_B) };
    let id = h.ok(&lead, "routine_add", json!({ "title": B_TITLE, "trigger": "api" })).await["id"]
        .as_i64()
        .unwrap();
    let fired = h.ok(&lead, "routine_fire", json!({ "routine_id": id, "idempotency_key": "evt-1" })).await;
    assert_eq!(fired["status"], "created", "{fired}");
    let task = fired["task_id"].as_i64().unwrap();
    assert_eq!(h.text(&format!("SELECT org_id FROM tasks WHERE id = {task}")).as_deref(), Some(ORG_B));
    // The task is B's to see, and the default organization's to miss.
    h.ok(&agent(ORG_B), "task_update", json!({ "id": task, "priority": "high" })).await;
    let e = h.err(&agent(DEFAULT_ORG), "task_update", json!({ "id": task, "priority": "high" })).await;
    assert_eq!(e.code(), "not_found", "{e}");
}

#[tokio::test]
async fn an_organization_b_task_resolves_organization_b_s_binding() {
    let h = H::new();
    let op = Caller {
        kind: ActorKind::Human,
        profile: Profile::Coordinator,
        ..agent_named("operator", DEFAULT_ORG)
    };
    h.ok(
        &op,
        "coordination_manage",
        json!({ "action": "project_repo_bind", "params": { "project": "web", "repo": "owner-a/repo" } }),
    )
    .await;
    h.sql(
        "INSERT INTO project_repo_bindings (org_id, project, repo, default_branch, bound_by, bound_at)
         VALUES ('org-b', 'web', 'owner-b/repo', 'trunk', 'operator', 'x')",
    )
    .unwrap();
    let b = agent(ORG_B);
    let task = h.add(&b, json!({ "title": "B web", "project": "web" })).await;
    h.ok(&b, "task_claim", json!({ "id": task })).await;
    let record = |name: &str, repo: Option<&str>| {
        let mut r = json!({ "kind": "ci_run", "ref": "41" });
        if let Some(repo) = repo {
            r["repo"] = json!(repo);
        }
        json!({ "task_id": task, "name": name, "outcome": "pass", "head_sha": "b".repeat(40), "ref": r, "verify": false })
    };
    let v = h.coord(&b, "task_check_record", record("ci", None)).await.unwrap();
    let check = v["checks"].as_array().unwrap().iter().find(|c| c["name"] == "ci").cloned().unwrap();
    assert_eq!(check["ref"]["repo"], "owner-b/repo", "B's own binding fills the repository: {v}");
    let e = h.coord(&b, "task_check_record", record("ci-a", Some("owner-a/repo"))).await.unwrap_err();
    assert_eq!(reason(&e), "repo_mismatch", "{e}");
    // The default organization's task in `web` resolves its own binding.
    let a = agent(DEFAULT_ORG);
    let ta = h.add(&a, json!({ "title": "A web", "project": "web" })).await;
    h.ok(&a, "task_claim", json!({ "id": ta })).await;
    let mut args = record("ci", None);
    args["task_id"] = json!(ta);
    let v = h.coord(&a, "task_check_record", args).await.unwrap();
    assert_eq!(v["checks"][0]["ref"]["repo"], "owner-a/repo", "{v}");
}

/// Every request path the mock GitHub saw.
type Seen = Arc<Mutex<Vec<String>>>;

/// A local GitHub REST mock: PR 5 of `shared/repo` is merged into main; the
/// open-PR list is empty; anything else is 404.
async fn start_github() -> (Seen, String) {
    async fn serve(State(seen): State<Seen>, req: Request) -> Response {
        let path = req.uri().path().to_string();
        seen.lock().unwrap().push(path.clone());
        if path.ends_with("/pulls") {
            return axum::Json(json!([])).into_response();
        }
        if path == "/repos/shared/repo/pulls/5" {
            return axum::Json(json!({
                "number": 5, "merged": true, "merged_at": "2099-01-01T00:00:00Z",
                "merge_commit_sha": "c".repeat(40), "html_url": "https://github.com/shared/repo/pull/5",
                "head": { "ref": "feature" },
                "base": { "ref": "main", "repo": { "default_branch": "main" } },
            }))
            .into_response();
        }
        (StatusCode::NOT_FOUND, axum::Json(json!({ "message": "Not Found" }))).into_response()
    }
    let seen: Seen = Arc::default();
    let app = Router::new().fallback(serve).with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (seen, format!("http://{addr}"))
}

/// Merged-PR reconciliation and the poller run per organization: with only
/// the default organization holding GitHub credentials, they touch only its
/// tasks, even for a repository both organizations bind and a PR both
/// organizations' tasks link. Organization B, with no token, is skipped,
/// never served with the hub's.
#[tokio::test]
async fn github_reconciliation_touches_only_default_organization_tasks() {
    let (seen, base) = start_github().await;
    let h = H::with(|cfg| {
        cfg.github_webhook_secret_value = Some(WEBHOOK_SECRET.to_string().into());
        cfg.fetch_allow_loopback = true;
        cfg.github_api_url = base;
        cfg.github_token_value = Some("test-token".to_string().into());
        cfg.github_web_host = Some("github.com".into());
    });
    let op = Caller {
        kind: ActorKind::Human,
        profile: Profile::Coordinator,
        ..agent_named("operator", DEFAULT_ORG)
    };
    h.ok(
        &op,
        "coordination_manage",
        json!({ "action": "project_repo_bind", "params": { "project": "web", "repo": "shared/repo" } }),
    )
    .await;
    // Organization B binds the shared repository and one of its own.
    h.sql(
        "INSERT INTO project_repo_bindings (org_id, project, repo, default_branch, bound_by, bound_at)
         VALUES ('org-b', 'web', 'shared/repo', 'main', 'operator', 'x'),
                ('org-b', 'falcon', 'owner-b/falcon', 'main', 'operator', 'x')",
    )
    .unwrap();
    let a = agent(DEFAULT_ORG);
    let b = agent(ORG_B);
    let ta =
        h.add(&a, json!({ "title": "A ships", "project": "web", "evidence_ref": "shared/repo#5" })).await;
    let tb =
        h.add(&b, json!({ "title": "B ships", "project": "web", "evidence_ref": "shared/repo#5" })).await;
    let tb_own =
        h.add(&b, json!({ "title": "B own", "project": "falcon", "evidence_ref": "owner-b/falcon#6" })).await;

    // Another organization's caller reconciles its own organization, which
    // has no token: credential off, and the hub's token is never used.
    let e = h.coord(&b, "queue_close_merged", json!({})).await.unwrap_err();
    assert_eq!(reason(&e), "github_credential_off", "{e}");

    let dry = h.coord(&op, "queue_close_merged", json!({})).await.unwrap();
    let would: Vec<i64> =
        dry["would_close"].as_array().unwrap().iter().map(|m| m["task_id"].as_i64().unwrap()).collect();
    assert_eq!(would, [ta], "{dry}");
    let out = h.coord(&op, "queue_close_merged", json!({ "dry_run": false })).await.unwrap();
    let closed: Vec<i64> =
        out["closed"].as_array().unwrap().iter().map(|m| m["task_id"].as_i64().unwrap()).collect();
    assert_eq!(closed, [ta], "{out}");
    assert_eq!(h.text(&format!("SELECT status FROM tasks WHERE id = {ta}")).as_deref(), Some("done"));
    assert_eq!(h.text(&format!("SELECT status FROM tasks WHERE id = {tb}")).as_deref(), Some("open"));
    // The poller lists only the default organization's bound repositories:
    // organization B's own repository is never requested.
    let polled = poll_once(&h.hub).await.unwrap();
    let repos: Vec<&str> =
        polled["repos"].as_array().unwrap().iter().map(|r| r["repo"].as_str().unwrap()).collect();
    assert_eq!(repos, ["shared/repo"], "{polled}");
    assert!(seen.lock().unwrap().iter().all(|p| !p.contains("owner-b")), "{:?}", seen.lock().unwrap());
    assert!(seen.lock().unwrap().iter().any(|p| p.contains("shared/repo")), "the poll did run");
    for t in [tb, tb_own] {
        assert_eq!(h.text(&format!("SELECT status FROM tasks WHERE id = {t}")).as_deref(), Some("open"));
    }

    // A signed delivery for a merged PR on the repository both organizations
    // bind closes the default organization's task, never organization B's.
    let ta2 =
        h.add(&a, json!({ "title": "A ships 2", "project": "web", "evidence_ref": "shared/repo#8" })).await;
    let tb2 =
        h.add(&b, json!({ "title": "B ships 2", "project": "web", "evidence_ref": "shared/repo#8" })).await;
    let payload = json!({
        "action": "closed",
        "number": 8,
        "pull_request": {
            "number": 8, "merged": true, "merged_at": ua_core::time::now(), "updated_at": ua_core::time::now(),
            "merge_commit_sha": "e".repeat(40), "html_url": "https://github.com/shared/repo/pull/8",
            "head": { "ref": "feature-8", "sha": "f".repeat(40) },
            "base": { "ref": "main", "repo": { "full_name": "shared/repo", "default_branch": "main" } },
        },
        "repository": { "full_name": "shared/repo", "default_branch": "main" },
    });
    let body = serde_json::to_vec(&payload).unwrap();
    let sig = signature_for(WEBHOOK_SECRET.as_bytes(), &body);
    let out = receive(
        &h.hub,
        WebhookDelivery { event: "pull_request", delivery_id: "merge-8", signature: Some(&sig), body: &body },
    )
    .await
    .unwrap();
    let closed: Vec<i64> =
        out["result"]["closed"].as_array().unwrap().iter().map(|c| c["task_id"].as_i64().unwrap()).collect();
    assert_eq!(closed, [ta2], "{out}");
    assert_eq!(h.text(&format!("SELECT status FROM tasks WHERE id = {ta2}")).as_deref(), Some("done"));
    assert_eq!(h.text(&format!("SELECT status FROM tasks WHERE id = {tb2}")).as_deref(), Some("open"));
}

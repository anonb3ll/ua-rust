//! The routine and workflow-run tables are tenant data (`docs/organization.md`,
//! Scoping per subsystem): `routines` and `routine_runs`
//! (`organization.v1.tools.routines`, `routines.v2.org_indexes`) and
//! `workflow_runs` and `workflow_checkpoints`
//! (`organization.v1.tools.workflows`, `workflows.v2.org_indexes`). No key
//! rebuild exists: their keys are AUTOINCREMENT ids, hub-generated run ids,
//! and unique pairs led by one of those, so there is no crash re-run or
//! rollback to test here.
//!
//! A second organization is created at the storage level, as no tool creates
//! one yet, and its callers are built by hand. The routine and workflow tools
//! take an organization-B caller directly (they use no `ua_org::authz` rule
//! that would refuse it). The one row no tool can make, an unstarted
//! organization-B fire with a workflow, is seeded by SQL.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::families::routines;
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 4] = [
    "organization.v1.tools.routines",
    "routines.v2.org_indexes",
    "organization.v1.tools.workflows",
    "workflows.v2.org_indexes",
];
const TABLES: [&str; 4] = ["routines", "routine_runs", "workflow_runs", "workflow_checkpoints"];

/// A workflow every organization can run: one read-only step.
/// A one-step workflow over a database-only tool: a workspace tool
/// (`run_cmd_check`) would be refused to organization B, whose callers have
/// no hub workspace (`workspace::sandbox`).
const VET: &str = "inputs: [command]\nsteps:\n  - name: vet\n    tool: memory_search\n    args: { query: \"{{ inputs.command }}\" }\n";

/// The parts before this family's conversion: without its parts, and
/// without the later `*.task_org` parts, whose triggers read its `org_id`.
fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts()
        .into_iter()
        .filter(|p| !PARTS.contains(&p.name) && !p.name.ends_with(".task_org"))
        .collect()
}

fn add_org(hub: &Hub, id: &str) {
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
                 VALUES (?1, ?1, 'Org B', '[\"coordinator\",\"developer\",\"operator\"]', '2026-01-01T00:00:00+00:00')",
                [id],
            )?;
            Ok(())
        })
        .unwrap();
}

fn agent(label: &str, org: &str) -> Caller {
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

/// A routine manager (`lead-1` has coordinator as its configured default).
fn lead(org: &str) -> Caller {
    Caller { profile: Profile::Coordinator, ..agent("lead-1", org) }
}

fn ts(s: &str) -> jiff::Timestamp {
    s.parse().unwrap()
}

struct H {
    hub: Hub,
    reg: Registry,
    _dir: tempfile::TempDir,
}

impl H {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("workflows")).unwrap();
        std::fs::write(dir.path().join("workflows").join("vet.yaml"), VET).unwrap();
        let mut cfg = Config::for_home(dir.path());
        cfg.human_identities = vec!["operator".into()];
        cfg.profiles.insert("lead-1".into(), "coordinator".into());
        cfg.routines_enabled = true;
        cfg.workspace = Some(dir.path().to_path_buf());
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

    fn count(&self, sql: &str) -> i64 {
        self.hub.db().read(|c| Ok(c.query_row(sql, [], |r| r.get(0))?)).unwrap()
    }

    fn text(&self, sql: &str) -> Option<String> {
        self.hub.db().read(|c| Ok(c.query_row(sql, [], |r| r.get(0))?)).unwrap()
    }

    async fn add_routine(&self, who: &Caller, args: Value) -> i64 {
        self.ok(who, "routine_add", args).await["id"].as_i64().unwrap()
    }

    async fn run_vet(&self, who: &Caller) -> String {
        let out =
            self.ok(who, "workflow_run", json!({ "name": "vet", "inputs": { "command": "echo hi" } })).await;
        assert_eq!(out["status"], "done", "{out}");
        out["run_id"].as_str().unwrap().to_string()
    }
}

fn names(c: &rusqlite::Connection, kind: &str, table: &str) -> Vec<String> {
    c.prepare("SELECT name FROM sqlite_master WHERE type = ?1 AND tbl_name = ?2 ORDER BY name")
        .unwrap()
        .query_map([kind, table], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn org_id_notnull(c: &rusqlite::Connection, table: &str) -> Option<i64> {
    c.query_row(
        &format!("SELECT \"notnull\" FROM pragma_table_info('{table}') WHERE name = 'org_id'"),
        [],
        |r| r.get(0),
    )
    .ok()
}

fn is_not_found(e: &UaError) -> bool {
    e.code() == "not_found"
}

// --- upgrade -----------------------------------------------------------------------------------

/// Rows the `routines.v1` and `workflows.v1` parts would have written.
/// Routine 2 is deleted, so the AUTOINCREMENT high-water mark (2) is above
/// the highest id left (1).
const LEGACY_ROWS: &str = "
INSERT INTO routines (id, title, trigger, schedule, lane, project, domain, concurrency, catch_up, cursor_at,
    owner, created_at, updated_at)
VALUES (1, 'Legacy sweep', 'cron', '0 * * * *', 'default', 'default', 'general', 'skip', 'last',
        '2026-01-01T00:00:00+00:00', 'lead-1', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'),
       (2, 'Gone', 'api', NULL, 'default', 'default', 'general', 'skip', 'last',
        '2026-01-01T00:00:00+00:00', 'lead-1', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');
DELETE FROM routines WHERE id = 2;
INSERT INTO routine_runs (routine_id, fire_key, scheduled_for, status, created_at, reason)
VALUES (1, 'cron:2026-01-01T01:00:00+00:00', '2026-01-01T01:00:00+00:00', 'skipped',
        '2026-01-01T01:00:00+00:00', 'overlap');
INSERT INTO workflow_runs (run_id, kind, name, definition_digest, definition, inputs, owner, owner_profile,
    status, next_step, created_at, updated_at)
VALUES ('01JLEGACYRUN0000000000000A', 'workflow', 'vet', 'd', '{}', '{}', 'lead-1', 'coordinator', 'done', 1,
        '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');
INSERT INTO workflow_checkpoints (run_id, seq, step_index, step_name, tool, status, attempts, created_at)
VALUES ('01JLEGACYRUN0000000000000A', 1, 0, 'vet', 'run_cmd_check', 'done', 1, '2026-01-01T00:00:00+00:00');
";

#[tokio::test]
async fn a_legacy_database_upgrades_into_the_default_organization() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.profiles.insert("lead-1".into(), "coordinator".into());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(LEGACY_ROWS)?;
            Ok(())
        })
        .unwrap();
        db.read(|c| {
            for t in TABLES {
                assert_eq!(org_id_notnull(c, t), None, "{t} has no org_id before the parts");
            }
            Ok(())
        })
        .unwrap();
    }

    // Opening twice proves the upgrade is idempotent across restarts.
    for _ in 0..2 {
        let hub = Hub::open(cfg.clone()).unwrap();
        hub.db()
            .read(|c| {
                for t in TABLES {
                    assert_eq!(org_id_notnull(c, t), Some(1), "{t}.org_id NOT NULL");
                    let orgs: Vec<String> = c
                        .prepare(&format!("SELECT DISTINCT org_id FROM {t}"))?
                        .query_map([], |r| r.get(0))?
                        .collect::<Result<_, _>>()?;
                    assert_eq!(orgs, [DEFAULT_ORG], "{t} rows move to the default organization");
                    let triggers = names(c, "trigger", t);
                    for suffix in ["org_exists", "org_immutable"] {
                        assert!(triggers.contains(&format!("{t}_{suffix}")), "{t}_{suffix}: {triggers:?}");
                    }
                }
                for (table, trigger) in [
                    ("routine_runs", "routine_runs_same_org"),
                    ("routine_runs", "routine_runs_same_org_update"),
                    ("workflow_checkpoints", "workflow_checkpoints_same_org"),
                    ("workflow_checkpoints", "workflow_checkpoints_same_org_update"),
                ] {
                    assert!(names(c, "trigger", table).contains(&trigger.to_string()), "{trigger}");
                }
                for (table, index) in [
                    ("routines", "idx_routines_org"),
                    ("routine_runs", "idx_routine_runs_org_routine"),
                    ("routine_runs", "idx_routine_runs_task"),
                    ("workflow_runs", "idx_workflow_runs_org_created"),
                    ("workflow_runs", "idx_workflow_runs_task"),
                    ("workflow_checkpoints", "idx_workflow_checkpoints_org"),
                    ("workflow_checkpoints", "idx_workflow_checkpoints_run"),
                ] {
                    assert!(names(c, "index", table).contains(&index.to_string()), "{index}");
                }
                for part in PARTS {
                    let n: i64 =
                        c.query_row("SELECT COUNT(*) FROM schema_parts WHERE name = ?1", [part], |r| {
                            r.get(0)
                        })?;
                    assert_eq!(n, 1, "{part}");
                }
                // No rebuild: the AUTOINCREMENT high-water mark is untouched.
                let seq: i64 =
                    c.query_row("SELECT seq FROM sqlite_sequence WHERE name = 'routines'", [], |r| r.get(0))?;
                assert_eq!(seq, 2);
                Ok(())
            })
            .unwrap();
    }

    // The default organization's tools see the legacy rows as before.
    let hub = Hub::open(cfg).unwrap();
    let reg = builtin_registry();
    let out = reg.call(&hub, &lead(DEFAULT_ORG), "routine_list", json!({ "recent_runs": 5 })).await.unwrap();
    assert_eq!(out["routines"].as_array().unwrap().len(), 1, "{out}");
    assert_eq!(out["routines"][0]["title"], "Legacy sweep");
    assert_eq!(out["routines"][0]["recent_runs"][0]["reason"], "overlap");
    let run = reg
        .call(&hub, &lead(DEFAULT_ORG), "run_get", json!({ "run_id": "01JLEGACYRUN0000000000000A" }))
        .await
        .unwrap();
    assert_eq!(run["run"]["name"], "vet", "{run}");
    let cps = reg
        .call(
            &hub,
            &lead(DEFAULT_ORG),
            "langgraph_checkpoints",
            json!({ "run_id": "01JLEGACYRUN0000000000000A" }),
        )
        .await
        .unwrap();
    assert_eq!(cps["count"], 1, "{cps}");
    // A new routine continues after the deleted id.
    let id = reg
        .call(&hub, &lead(DEFAULT_ORG), "routine_add", json!({ "title": "New", "trigger": "api" }))
        .await
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    assert_eq!(id, 3);
}

#[tokio::test]
async fn a_child_row_must_be_in_its_parents_organization() {
    let h = H::new();
    let id = h.add_routine(&lead(DEFAULT_ORG), json!({ "title": "A", "trigger": "api" })).await;
    let run_id = h.run_vet(&agent("builder-1", DEFAULT_ORG)).await;
    h.hub
        .db()
        .write(move |tx| {
            let e = tx
                .execute(
                    "INSERT INTO routine_runs (org_id, routine_id, fire_key, scheduled_for, status, created_at)
                     VALUES (?1, ?2, 'event:x', 't', 'skipped', 't')",
                    rusqlite::params![ORG_B, id],
                )
                .unwrap_err()
                .to_string();
            assert!(e.contains("a routine run must be in its routine's organization"), "{e}");
            let e = tx
                .execute(
                    "INSERT INTO workflow_checkpoints (org_id, run_id, seq, step_index, step_name, status, created_at)
                     VALUES (?1, ?2, 99, 0, 'x', 'done', 't')",
                    rusqlite::params![ORG_B, run_id],
                )
                .unwrap_err()
                .to_string();
            assert!(e.contains("a workflow checkpoint must be in its run's organization"), "{e}");
            let e = tx
                .execute("UPDATE routines SET org_id = ?1 WHERE id = ?2", rusqlite::params![ORG_B, id])
                .unwrap_err()
                .to_string();
            assert!(e.contains("org_id cannot change"), "{e}");
            Ok(())
        })
        .unwrap();
}

// --- routines ----------------------------------------------------------------------------------

#[tokio::test]
async fn routines_are_isolated_in_both_directions() {
    let h = H::new();
    let (a, b) = (lead(DEFAULT_ORG), lead(ORG_B));
    let same = json!({ "title": "Same title", "trigger": "api" });
    let ra = h.add_routine(&a, same.clone()).await;
    let rb = h.add_routine(&b, same).await;
    h.ok(&a, "routine_fire", json!({ "routine_id": ra, "idempotency_key": "evt-1" })).await;
    h.ok(&b, "routine_fire", json!({ "routine_id": rb, "idempotency_key": "evt-1" })).await;

    for (who, own, other) in [(&a, ra, rb), (&b, rb, ra)] {
        let list = h.ok(who, "routine_list", json!({ "recent_runs": 10 })).await;
        let rows = list["routines"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "{}: {list}", who.org_id);
        assert_eq!(rows[0]["id"], own);
        assert_eq!(rows[0]["recent_runs"].as_array().unwrap().len(), 1, "{list}");
        assert_eq!(rows[0]["org_id"], who.org_id.as_str());

        // Another organization's routine answers exactly as a missing one.
        for id in [other, 9999] {
            let e = h.err(who, "routine_pause", json!({ "routine_id": id })).await;
            assert!(is_not_found(&e) && e.to_string().contains("unknown routine"), "{e}");
            let e = h.err(who, "routine_fire", json!({ "routine_id": id, "idempotency_key": "evt-2" })).await;
            assert!(is_not_found(&e) && e.to_string().contains("unknown routine"), "{e}");
        }
    }
    // Nothing of the other organization changed.
    assert_eq!(h.count("SELECT COUNT(*) FROM routines WHERE paused = 1"), 0);
    assert_eq!(h.count("SELECT COUNT(*) FROM routine_runs"), 2);
    // Each organization pauses its own.
    h.ok(&b, "routine_pause", json!({ "routine_id": rb })).await;
    assert_eq!(h.text("SELECT org_id FROM routines WHERE paused = 1").as_deref(), Some(ORG_B));
}

#[tokio::test]
async fn organization_b_writes_land_in_organization_b() {
    let h = H::new();
    let b = lead(ORG_B);
    let tasks_before = h.count("SELECT COUNT(*) FROM tasks");
    let id = h
        .add_routine(
            &b,
            json!({ "title": "B's", "trigger": "api", "workflow": "vet", "inputs": { "command": "echo b" } }),
        )
        .await;
    assert_eq!(h.text(&format!("SELECT org_id FROM routines WHERE id = {id}")).as_deref(), Some(ORG_B));

    // B's fire creates its task in B; its workflow does not run (a
    // routine's owner caller is built only in the default organization), and
    // its receipt is B's.
    let fired =
        h.ok(&b, "routine_fire", json!({ "routine_id": id, "idempotency_key": "b-private-key" })).await;
    assert_eq!(fired["status"], "created", "{fired}");
    assert_eq!(fired["workflow"]["status"], "not_run", "{fired}");
    let task = fired["task_id"].as_i64().unwrap_or_else(|| panic!("{fired}"));
    assert_eq!(h.count("SELECT COUNT(*) FROM tasks"), tasks_before + 1);
    assert_eq!(h.text(&format!("SELECT org_id FROM tasks WHERE id = {task}")).as_deref(), Some(ORG_B));
    assert_eq!(h.count("SELECT COUNT(*) FROM workflow_runs"), 0);
    assert_eq!(
        h.text(&format!("SELECT org_id || ':' || status FROM routine_runs WHERE routine_id = {id}"))
            .as_deref(),
        Some("org-b:created")
    );
    // The replay is B's own receipt.
    let replay =
        h.ok(&b, "routine_fire", json!({ "routine_id": id, "idempotency_key": "b-private-key" })).await;
    assert_eq!(replay["replayed"], true, "{replay}");
    // B's client-chosen fire key reaches the (default organization's) ledger
    // only as a digest.
    assert_eq!(h.count("SELECT COUNT(*) FROM event_log WHERE payload LIKE '%b-private-key%' OR dedupe_key LIKE '%b-private-key%'"), 0);

    // B's workflow runs and checkpoints are B's.
    let run_id = h.run_vet(&agent("builder-1", ORG_B)).await;
    assert_eq!(
        h.text(&format!("SELECT org_id FROM workflow_runs WHERE run_id = '{run_id}'")).as_deref(),
        Some(ORG_B)
    );
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM workflow_checkpoints WHERE run_id = '{run_id}' AND org_id = '{ORG_B}'"
        )),
        1
    );
}

#[tokio::test]
async fn the_scheduler_fires_each_routine_in_its_own_organization() {
    let h = H::new();
    let start = "2026-01-01T10:00:00+00:00";
    let cron = |title: &str| {
        json!({ "title": title, "schedule": "*/15 * * * *", "start_at": start, "workflow": "vet",
                "inputs": { "command": "echo tick" } })
    };
    let ra = h.add_routine(&lead(DEFAULT_ORG), cron("A sweep")).await;
    let rb = h.add_routine(&lead(ORG_B), cron("B sweep")).await;

    let out = routines::tick(&h.hub, ts("2026-01-01T10:20:10Z"), true).await.unwrap();
    assert_eq!(out["created"], 2, "{out}");
    assert_eq!(out["skipped"], 0, "{out}");

    // A's fire: a task and a workflow run, both attributed to A's organization.
    let receipt = |id: i64| {
        h.text(&format!(
            "SELECT org_id || '|' || status || '|' || COALESCE(task_id, '') || '|' || COALESCE(workflow_run_id, '') \
             FROM routine_runs WHERE routine_id = {id}"
        ))
        .unwrap()
    };
    let a = receipt(ra);
    let parts: Vec<&str> = a.split('|').collect();
    assert_eq!((parts[0], parts[1]), (DEFAULT_ORG, "created"), "{a}");
    assert!(!parts[2].is_empty() && !parts[3].is_empty(), "{a}");
    assert_eq!(
        h.text(&format!("SELECT org_id || ':' || status FROM workflow_runs WHERE run_id = '{}'", parts[3]))
            .as_deref(),
        Some("default:done")
    );
    // B's fire is recorded in B, with a task in B and no workflow run.
    let b_fire = receipt(rb);
    let parts: Vec<&str> = b_fire.split('|').collect();
    assert_eq!((parts[0], parts[1], parts[3]), (ORG_B, "created", ""), "{b_fire}");
    assert_eq!(h.text(&format!("SELECT org_id FROM tasks WHERE id = {}", parts[2])).as_deref(), Some(ORG_B));
    assert_eq!(h.count("SELECT COUNT(*) FROM workflow_runs"), 1);
    // Each routine's cursor moved; neither was fired twice.
    let again = routines::tick(&h.hub, ts("2026-01-01T10:20:40Z"), true).await.unwrap();
    assert_eq!((again["created"].as_i64(), again["skipped"].as_i64()), (Some(0), Some(0)), "{again}");
}

/// A fire a stopped hub left behind in organization B is never run under a
/// default-organization caller: reconciliation marks it `not_run`. The row
/// is seeded by SQL, as a tool-made fire outside the default organization
/// records its workflow as `not_run` at once.
#[tokio::test]
async fn reconciliation_never_runs_another_organizations_fire_as_the_default() {
    let h = H::new();
    let rb = h
        .add_routine(
            &lead(ORG_B),
            json!({ "title": "B", "trigger": "api", "workflow": "vet", "inputs": { "command": "echo b" } }),
        )
        .await;
    let ra = h
        .add_routine(
            &lead(DEFAULT_ORG),
            json!({ "title": "A", "trigger": "api", "workflow": "vet", "inputs": { "command": "echo a" } }),
        )
        .await;
    h.hub
        .db()
        .write(move |tx| {
            for (org, id) in [(ORG_B, rb), (DEFAULT_ORG, ra)] {
                tx.execute(
                    "INSERT INTO routine_runs (org_id, routine_id, fire_key, scheduled_for, status, created_at)
                     VALUES (?1, ?2, 'api:unstarted', '2099-01-01T00:00:00Z', 'created', '2099-01-01T00:00:00Z')",
                    rusqlite::params![org, id],
                )?;
            }
            Ok(())
        })
        .unwrap();
    let out = routines::reconcile_fires(&h.hub).await.unwrap();
    assert_eq!(out["rerun"].as_array().unwrap().len(), 2, "{out}");
    let status =
        |id: i64| h.text(&format!("SELECT workflow_status FROM routine_runs WHERE routine_id = {id}"));
    assert_eq!(status(rb).as_deref(), Some("not_run"));
    assert_eq!(status(ra).as_deref(), Some("done"));
    // Only A's workflow ran, and in A's organization.
    assert_eq!(h.count("SELECT COUNT(*) FROM workflow_runs"), 1);
    assert_eq!(h.count(&format!("SELECT COUNT(*) FROM workflow_runs WHERE org_id = '{DEFAULT_ORG}'")), 1);
}

// --- workflows ---------------------------------------------------------------------------------

#[tokio::test]
async fn workflow_runs_are_isolated_in_both_directions() {
    let h = H::new();
    let (a, b) = (agent("builder-1", DEFAULT_ORG), agent("builder-1", ORG_B));
    let run_a = h.run_vet(&a).await;
    let run_b = h.run_vet(&b).await;

    for (who, own, other) in [(&a, &run_a, &run_b), (&b, &run_b, &run_a)] {
        // run_list and run_get read only the caller's organization's runs.
        let list = h.ok(who, "run_list", json!({ "kind": "workflow" })).await;
        let ids: Vec<&str> =
            list["runs"].as_array().unwrap().iter().map(|r| r["run_id"].as_str().unwrap()).collect();
        assert_eq!(ids, [own.as_str()], "{}: {list}", who.org_id);
        h.ok(who, "run_get", json!({ "run_id": own })).await;
        let e = h.err(who, "run_get", json!({ "run_id": other })).await;
        assert!(is_not_found(&e), "{e}");

        // langgraph_checkpoints: the caller's checkpoints only.
        let cps = h.ok(who, "langgraph_checkpoints", json!({})).await;
        let runs: Vec<&str> =
            cps["records"].as_array().unwrap().iter().map(|r| r["run_id"].as_str().unwrap()).collect();
        assert_eq!(runs, [own.as_str()], "{cps}");
        let cps = h.ok(who, "langgraph_checkpoints", json!({ "run_id": other })).await;
        assert_eq!(cps["count"], 0, "{cps}");

        // Resuming another organization's run answers as a missing one.
        let e = h.err(who, "workflow_run", json!({ "name": "vet", "run_id": other, "resume": true })).await;
        let missing = h
            .err(
                who,
                "workflow_run",
                json!({ "name": "vet", "run_id": "01JNOSUCHRUN00000000000000", "resume": true }),
            )
            .await;
        assert!(is_not_found(&e) && is_not_found(&missing), "{e} / {missing}");
        assert_eq!(
            e.to_string().replace(other.as_str(), "ID"),
            missing.to_string().replace("01JNOSUCHRUN00000000000000", "ID")
        );
    }
}

#[tokio::test]
async fn langgraph_runs_see_only_the_task_organizations_tasks() {
    let h = H::new();
    let a = agent("builder-1", DEFAULT_ORG);
    let task = h.ok(&a, "task_add", json!({ "title": "Graph work" })).await["id"].as_i64().unwrap();
    h.ok(&a, "task_claim", json!({ "id": task })).await;
    let digest = "a".repeat(64);

    // The default organization's gated step: the approval binds the run's
    // organization.
    let out = h.ok(&a, "langgraph_progress_note", json!({ "task_id": task, "output_digest": digest })).await;
    let approval = out["interrupted_by"]["approval_id"].as_i64().unwrap_or_else(|| panic!("{out}"));
    let payload = h.text(&format!("SELECT payload FROM approvals WHERE id = {approval}")).unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["org_id"], DEFAULT_ORG, "{payload}");
    assert_eq!(payload["run_id"], out["run_id"]);

    // Organization B does not see the default organization's task, so a run
    // on it answers as for a missing task.
    let b = agent("builder-1", ORG_B);
    let runs_before = h.count("SELECT COUNT(*) FROM workflow_runs");
    let e = h.err(&b, "langgraph_progress_note", json!({ "task_id": task, "output_digest": digest })).await;
    assert!(e.to_string().contains(&format!("task #{task} not found")), "{e}");
    let e = h.err(&b, "langgraph_run", json!({ "task_id": task, "query": "x" })).await;
    assert!(e.to_string().contains(&format!("task #{task} not found")), "{e}");
    assert_eq!(h.count("SELECT COUNT(*) FROM workflow_runs"), runs_before);
    // Nor can B resume A's run.
    let out = h
        .ok(
            &b,
            "langgraph_progress_note",
            json!({ "task_id": task, "output_digest": digest, "run_id": out["run_id"] }),
        )
        .await;
    assert_eq!(out["code"], "checkpoint_missing", "{out}");
}

// --- unknown organization ----------------------------------------------------------------------

#[tokio::test]
async fn an_unknown_organization_is_refused_before_any_write() {
    let h = H::new();
    let ra = h.add_routine(&lead(DEFAULT_ORG), json!({ "title": "A", "trigger": "api" })).await;
    let snapshot = |h: &H| {
        [
            "SELECT COUNT(*) FROM routines",
            "SELECT COUNT(*) FROM routine_runs",
            "SELECT COUNT(*) FROM workflow_runs",
            "SELECT COUNT(*) FROM workflow_checkpoints",
            "SELECT COUNT(*) FROM event_log",
            "SELECT COUNT(*) FROM routines WHERE paused = 1",
        ]
        .map(|q| h.count(q))
    };
    let before = snapshot(&h);
    let who = lead(UNKNOWN);
    // The registry refuses the organization before any tool runs.
    let routine_guard = format!("unknown organization {UNKNOWN:?}; nothing ran and nothing was written");
    for (tool, args) in [
        ("routine_add", json!({ "title": "x", "trigger": "api" })),
        // Writes with nothing of their own to insert are refused too.
        ("routine_pause", json!({ "routine_id": ra })),
        ("routine_fire", json!({ "routine_id": ra, "idempotency_key": "k" })),
    ] {
        let e = h.err(&who, tool, args).await;
        assert!(e.to_string().contains(&routine_guard), "{tool}: {e}");
    }
    let e = h
        .err(
            &agent("builder-1", UNKNOWN),
            "workflow_run",
            json!({ "name": "vet", "inputs": { "command": "echo x" } }),
        )
        .await;
    assert!(e.to_string().contains(&routine_guard), "{e}");
    assert_eq!(snapshot(&h), before);
}

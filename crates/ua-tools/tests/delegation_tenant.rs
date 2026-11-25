//! `delegations` is tenant data (`docs/organization.md`, Scoping per
//! subsystem): `organization.v1.tools.delegation` gives it `org_id` and the
//! organization triggers, and `delegation.v2.org_scope` moves each existing
//! delegation to its task's organization, adds the indexes led by `org_id`
//! and keeps a delegation's task inside its own organization. No key needed
//! a rebuild: a delegation id is a hub-global AUTOINCREMENT id.
//!
//! A second organization is created at the storage level, as no tool creates
//! one yet, and its callers are built by hand. Organization-B rows are
//! written through the tools with an organization-B caller; only the legacy
//! rows of the upgrade test and the defence-in-depth rows are seeded by SQL.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 2] = ["organization.v1.tools.delegation", "delegation.v2.org_scope"];
/// An id no delegation has, to compare another organization's answers with.
const ABSENT: i64 = 987_654;

const SPEC: &str = "\
### Objective
Add a CSV export to the report page.

### Scope
- src/report.rs

### Definition of Done
- Calling export on a report with two rows returns a CSV with a header and two lines
- An empty report is refused with an error naming the report id
- Gates: the test suite, lint, format check and CI pass

### TDD Constraints
- Stub: none

### Boundaries
- Do not change the report schema
";

/// Organization-B text that must never reach the default organization's
/// ledger, in a payload or as an originator.
const B_OBJECTIVE: &str = "Falcon acquisition shortlist export";
const B_FROM: &str = "kestrel-nightshift";
const B_TO: &str = "osprey-counsel";
const B_PROJECT: &str = "falcon-deal";
const B_DEADLINE: &str = "2031-05-17";
const B_REASON: &str = "Osprey parked pending counsel";
const B_RESULT: &str = "Kestrel shortlist delivered";

fn b_spec() -> String {
    SPEC.replace("Add a CSV export to the report page.", B_OBJECTIVE)
}

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().filter(|p| !PARTS.contains(&p.name)).collect()
}

fn add_org(db: &ua_store::Db, id: &str) {
    db.write(|tx| {
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
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path());
        cfg.human_identities = vec!["operator".into()];
        let hub = Hub::in_memory(cfg).unwrap();
        add_org(hub.db(), ORG_B);
        Self { hub, reg: builtin_registry(), _dir: dir }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.register_target(who, tool, &args);
        self.reg.call(&self.hub, who, tool, args).await
    }

    /// Register a delegation's `to_agent` as an agent of the caller's
    /// organization before the call: a delegation targets only a registered
    /// agent of the delegator's organization. Agent labels are one hub-wide
    /// namespace, and these tests reuse one target label across
    /// organizations, so the registration moves with the delegator (by SQL,
    /// which writes no ledger event and no row these tests snapshot).
    fn register_target(&self, who: &Caller, tool: &str, args: &Value) {
        let to = match tool {
            "delegate" | "handoff" => args.get("to_agent"),
            "delegation_manage" if args["action"] == "create" => args["params"].get("to_agent"),
            _ => None,
        };
        let Some(to) = to.and_then(Value::as_str) else { return };
        let (to, org) = (to.replace('\'', "''"), who.org_id.replace('\'', "''"));
        let sql = format!(
            "DELETE FROM agents WHERE label = '{to}' AND org_id <> '{org}';
             INSERT OR IGNORE INTO agents (org_id, label, created_at, updated_at)
                 SELECT '{org}', '{to}', 't0', 't0' WHERE EXISTS (SELECT 1 FROM orgs WHERE id = '{org}');"
        );
        self.hub
            .db()
            .write(move |tx| {
                tx.execute_batch(&sql)?;
                Ok(())
            })
            .unwrap();
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{}: {tool}({args}) failed: {e:?}", who.org_id),
        }
    }

    async fn manage(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "delegation_manage", json!({ "action": action, "params": params })).await
    }

    /// `from` delegates `SPEC` to `to`; returns (delegation id, task id).
    async fn delegate(&self, from: &Caller, to: &str) -> (i64, i64) {
        let v = self.ok(from, "delegate", json!({ "task_spec": SPEC, "to_agent": to })).await;
        (v["delegation_id"].as_i64().unwrap(), v["task_id"].as_i64().unwrap())
    }

    async fn claim(&self, who: &Caller, id: i64) -> i64 {
        let v = self.ok(who, "delegate_claim", json!({ "id": id })).await;
        assert_eq!(v["claimed"], true, "{v}");
        v["delegation"]["claim_generation"].as_i64().unwrap()
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

    /// Every delegation and task row, as text: a write that changes nothing
    /// leaves it identical.
    fn snapshot(&self) -> String {
        self.hub
            .db()
            .read(|c| {
                let mut out = String::new();
                for t in ["delegations", "tasks", "idempotency_keys"] {
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

fn ids(v: &Value) -> Vec<i64> {
    v["delegations"].as_array().unwrap().iter().map(|d| d["id"].as_i64().unwrap()).collect()
}

/// `got` (about delegation `id`) reads exactly as `missing` (about
/// [`ABSENT`]) does.
/// An answer with the delegation id `n` in its text replaced, to compare an
/// answer about one delegation with an answer about another.
fn norm(r: &Result<Value, UaError>, n: i64) -> String {
    match r {
        Ok(v) => format!("ok {v}"),
        Err(e) => format!("err {} {}", e.code(), e.to_string().replace(&n.to_string(), "ID")),
    }
}

fn same_as_missing(got: &Result<Value, UaError>, missing: &Result<Value, UaError>, id: i64) {
    assert_eq!(
        norm(got, id),
        norm(missing, ABSENT),
        "another organization's delegation must answer as a missing one"
    );
}

// --- schema ------------------------------------------------------------------------------------

#[test]
fn a_legacy_database_upgrades_with_each_delegation_in_its_tasks_organization() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        add_org(&db, ORG_B);
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO tasks (id, org_id, title, created_at, updated_at) VALUES
                     (1, 'default', 'Legacy default', 'x', 'x'), (2, 'org-b', 'Legacy b', 'x', 'x');
                 INSERT INTO delegations (id, from_agent, to_agent, task_id, task_spec, created_at, updated_at)
                     VALUES (10, 'lead-1', 'builder-1', 1, 'spec a', '2026-01-02T00:00:00+00:00', 'x'),
                            (20, 'lead-1', 'builder-1', 2, 'spec b', '2026-01-02T00:00:00+00:00', 'x');",
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
                let rows: Vec<(i64, String)> = c
                    .prepare("SELECT id, org_id FROM delegations ORDER BY id")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<_, _>>()?;
                assert_eq!(rows, [(10, DEFAULT_ORG.to_string()), (20, ORG_B.to_string())]);
                let notnull: i64 = c.query_row(
                    "SELECT \"notnull\" FROM pragma_table_info('delegations') WHERE name = 'org_id'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(notnull, 1);
                let triggers = names(c, "trigger", "delegations");
                for want in [
                    "delegations_org_exists",
                    "delegations_org_immutable",
                    "delegations_org_parent",
                    "delegations_org_parent_update",
                ] {
                    assert!(triggers.contains(&want.to_string()), "{triggers:?}");
                }
                let idx = names(c, "index", "delegations");
                for want in [
                    "idx_delegations_org_to_agent",
                    "idx_delegations_org_status",
                    "idx_delegations_org_created",
                ] {
                    assert!(idx.contains(&want.to_string()), "{idx:?}");
                }
                // The recreated immutability trigger is the generated one.
                let sql: String = c.query_row(
                    "SELECT sql FROM sqlite_master WHERE name = 'delegations_org_immutable'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(
                    sql,
                    "CREATE TRIGGER delegations_org_immutable BEFORE UPDATE OF org_id ON delegations \
                     WHEN OLD.org_id IS NOT NULL AND NEW.org_id IS NOT OLD.org_id \
                     BEGIN SELECT RAISE(ABORT, 'org_id cannot change'); END"
                );
                Ok(())
            })
            .unwrap();
    }

    let hub = Hub::open(cfg).unwrap();
    let e = hub
        .db()
        .write(|tx| Ok(tx.execute_batch("UPDATE delegations SET org_id = 'default' WHERE id = 20")?))
        .unwrap_err();
    assert!(e.to_string().contains("org_id cannot change"), "{e}");

    // The legacy rows answer through the tools, each to its own organization,
    // in the shape they had.
    let reg = builtin_registry();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        for (org, want) in [(DEFAULT_ORG, 10), (ORG_B, 20)] {
            let me = agent_named("builder-1", org);
            let v = reg.call(&hub, &me, "delegate_list", json!({ "status": "all" })).await.unwrap();
            assert_eq!(ids(&v), [want], "{org}: {v}");
            assert!(v["delegations"][0].get("org_id").is_none(), "a reply keeps its shape: {v}");
        }
    });
}

/// Defence in depth: whatever a tool would check, the triggers keep a
/// delegation's task inside its own organization and its organization fixed.
#[test]
fn the_triggers_refuse_a_cross_organization_task() {
    let h = H::new();
    h.sql(
        "INSERT INTO tasks (id, org_id, title, created_at, updated_at) VALUES
             (10, 'default', 'A', 'x', 'x'), (20, 'org-b', 'B', 'x', 'x');
         INSERT INTO delegations (id, org_id, from_agent, to_agent, task_id, task_spec, created_at, updated_at)
             VALUES (1, 'default', 'a', 'b', 10, 's', 'x', 'x'), (2, 'org-b', 'a', 'b', 20, 's', 'x', 'x');",
    )
    .unwrap();
    for sql in [
        "INSERT INTO delegations (org_id, from_agent, to_agent, task_id, task_spec, created_at, updated_at)
             VALUES ('org-b', 'a', 'b', 10, 's', 'x', 'x')",
        "INSERT INTO delegations (org_id, from_agent, to_agent, task_id, task_spec, created_at, updated_at)
             VALUES ('default', 'a', 'b', 20, 's', 'x', 'x')",
        "UPDATE delegations SET task_id = 10 WHERE id = 2",
        "UPDATE delegations SET task_id = 20 WHERE id = 1",
    ] {
        let e = h.sql(sql).unwrap_err();
        assert!(e.contains("task belongs to another organization"), "{sql}: {e}");
    }
    let e = h.sql("UPDATE delegations SET org_id = 'org-b' WHERE id = 1").unwrap_err();
    assert!(e.contains("org_id cannot change"), "{e}");
    let e = h
        .sql(
            "INSERT INTO delegations (org_id, from_agent, to_agent, task_id, task_spec, created_at, updated_at)
                 VALUES ('missing-org', 'a', 'b', 10, 's', 'x', 'x')",
        )
        .unwrap_err();
    // Refused, whichever trigger fires first.
    assert!(e.contains("unknown organization") || e.contains("another organization"), "{e}");
    // A same-organization row is fine.
    h.sql(
        "INSERT INTO delegations (org_id, from_agent, to_agent, task_id, task_spec, created_at, updated_at)
             VALUES ('org-b', 'a', 'b', 20, 's', 'x', 'x')",
    )
    .unwrap();
}

// --- isolation ---------------------------------------------------------------------------------

/// Each organization sees and moves only its own delegations, in both
/// directions, through every delegation tool; the other's answers as a
/// missing one and nothing changes.
#[tokio::test]
async fn each_organization_sees_and_moves_only_its_own_delegations() {
    let h = H::new();
    for (mine, theirs) in [(DEFAULT_ORG, ORG_B), (ORG_B, DEFAULT_ORG)] {
        let (lead, builder) = (agent_named("lead-1", mine), agent_named("builder-1", mine));
        let (o_lead, o_builder) = (agent_named("lead-1", theirs), agent_named("builder-1", theirs));
        let (d, task) = h.delegate(&lead, "builder-1").await;
        let (pending, _) = h.delegate(&lead, "builder-1").await;
        let generation = h.claim(&builder, d).await;

        // Reads.
        for args in [json!({ "status": "all" }), json!({ "status": "all", "task_id": task })] {
            let v = h.ok(&o_builder, "delegate_list", args.clone()).await;
            assert!(!ids(&v).contains(&d) && !ids(&v).contains(&pending), "{theirs} {args}: {v}");
        }
        let v = h.ok(&builder, "delegate_list", json!({ "status": "all", "to_agent": "builder-1" })).await;
        assert!(ids(&v).contains(&d) && ids(&v).contains(&pending), "{v}");
        assert!(v["delegations"][0].get("org_id").is_none(), "{v}");
        let v = h.ok(&o_lead, "handoff_list", json!({})).await;
        assert!(!v.to_string().contains(&format!("\"task_id\":{task}")), "{v}");
        let got = h.manage(&o_builder, "get", json!({ "id": d })).await;
        same_as_missing(&got, &h.manage(&o_builder, "get", json!({ "id": ABSENT })).await, d);
        let v = h.manage(&builder, "get", json!({ "id": d })).await.unwrap();
        assert_eq!(v["delegation"]["status"], "in_flight");
        assert!(v["delegation"].get("org_id").is_none(), "{v}");
        let got = h
            .call(&o_lead, "platform_object_get", json!({ "kind": "delegation", "id": d.to_string() }))
            .await;
        let missing = h
            .call(&o_lead, "platform_object_get", json!({ "kind": "delegation", "id": ABSENT.to_string() }))
            .await;
        same_as_missing(&got, &missing, d);

        // Writes: every lifecycle action of the other organization's agent of
        // the same label, with the right generation, answers as for a missing
        // id and changes nothing.
        let before = (h.snapshot(), h.events());
        let g = generation;
        for (action, who, args) in [
            ("claim", &o_builder, json!({ "id": pending })),
            ("release", &o_builder, json!({ "id": d, "expected_claim_generation": g })),
            ("retry", &o_builder, json!({ "id": d, "expected_claim_generation": g, "reason": "x" })),
            ("complete", &o_builder, json!({ "id": d, "expected_claim_generation": g, "result": "x" })),
            ("fail", &o_builder, json!({ "id": d, "expected_claim_generation": g, "reason": "x" })),
            ("cancel", &o_lead, json!({ "id": d, "reason": "x" })),
            ("cancel", &o_lead, json!({ "id": pending })),
            ("complete", &o_lead, json!({ "id": pending })),
            ("fail", &o_lead, json!({ "id": pending })),
        ] {
            let id = args["id"].as_i64().unwrap();
            let got = h.manage(who, action, args.clone()).await;
            let mut absent = args.clone();
            absent["id"] = json!(ABSENT);
            same_as_missing(&got, &h.manage(who, action, absent).await, id);
            assert_eq!((h.snapshot(), h.events()), before, "{theirs} {action}({args}) changed something");
        }

        // The owners move it through every state.
        h.ok(&builder, "delegate_release", json!({ "id": d, "expected_claim_generation": g })).await;
        let g = h.claim(&builder, d).await;
        let v =
            h.manage(&builder, "retry", json!({ "id": d, "expected_claim_generation": g })).await.unwrap();
        assert_eq!(v["retried"], true, "{v}");
        let g = h.claim(&builder, d).await;
        let v =
            h.manage(&builder, "complete", json!({ "id": d, "expected_claim_generation": g })).await.unwrap();
        assert_eq!(v["completed"], true, "{v}");
        let v = h.manage(&builder, "fail", json!({ "id": pending })).await.unwrap();
        assert_eq!(v["failed"], true, "{v}");
        let (third, _) = h.delegate(&lead, "builder-1").await;
        let v = h.ok(&lead, "delegate_cancel", json!({ "id": third })).await;
        assert_eq!(v["cancelled"], true, "{v}");
        let mine_rows = h.count(&format!("SELECT COUNT(*) FROM delegations WHERE org_id = '{mine}'"));
        assert!(mine_rows >= 3, "{mine}: {mine_rows}");
    }
}

/// Every other reader: the plans UI's list (`delegate_list`), the evidence
/// report, the session packet, `platform_object_get`, `delegation_stats` and
/// the queue's live-work check. With the same-organization trigger dropped,
/// a row of another organization on this organization's task is still never
/// read: each reader filters on `org_id`, not only on its task.
#[tokio::test]
async fn every_reader_filters_on_the_delegation_s_own_organization() {
    let h = H::new();
    let a = agent_named("builder-1", DEFAULT_ORG);
    let b = agent_named("builder-1", ORG_B);
    let (db, tb) = h.delegate(&agent_named("lead-1", ORG_B), "builder-1").await;

    let v = h.ok(&b, "platform_object_get", json!({ "kind": "delegation", "id": db.to_string() })).await;
    assert_eq!(v["delegation"]["id"], db, "{v}");
    assert!(v["delegation"].get("org_id").is_none(), "{v}");
    let e = h.call(&a, "platform_object_get", json!({ "kind": "delegation", "id": db.to_string() })).await;
    let missing =
        h.call(&a, "platform_object_get", json!({ "kind": "delegation", "id": ABSENT.to_string() })).await;
    same_as_missing(&e, &missing, db);

    let stats = |v: &Value| v["total"].as_i64().unwrap();
    let args = json!({ "action": "delegation_stats", "params": {} });
    assert_eq!(stats(&h.ok(&b, "observability_manage", args.clone()).await), 1);
    assert_eq!(stats(&h.ok(&a, "observability_manage", args.clone()).await), 0);

    // An organization-A task carrying an organization-B delegation, which
    // only a dropped trigger admits.
    let ta = h.ok(&a, "task_add", json!({ "title": "A task" })).await["id"].as_i64().unwrap();
    h.sql(&format!(
        "DROP TRIGGER delegations_org_parent;
         INSERT INTO delegations (id, org_id, from_agent, to_agent, task_id, task_spec, created_at, updated_at)
             VALUES (500, 'org-b', 'lead-1', 'builder-1', {ta}, 'leaked spec', '2026-01-01T00:00:00+00:00', 'x');"
    ))
    .unwrap();
    let v = h.ok(&a, "delegate_list", json!({ "status": "all", "task_id": ta })).await;
    assert!(ids(&v).is_empty(), "{v}");
    let v = h.ok(&a, "evidence_report", json!({ "task_id": ta })).await;
    assert_eq!(v["records"][0]["delegations"], json!([]), "{v}");
    let v = h.ok(&a, "session_packet", json!({ "task_id": ta })).await;
    assert_eq!(v["delegations"], json!([]), "{v}");
    assert!(!v.to_string().contains("leaked spec"), "{v}");
    // The queue does not count the other organization's pending delegation
    // as live work on the task: parking it is allowed.
    let v = h
        .call(
            &a,
            "coordination_manage",
            json!({ "action": "queue_park", "params": { "task_id": ta, "reason": "idle" } }),
        )
        .await;
    assert!(v.is_ok(), "{v:?}");

    // Organization B's own reads of its own task are unchanged.
    let v = h.ok(&b, "evidence_report", json!({ "task_id": tb })).await;
    assert_eq!(v["records"][0]["delegations"][0]["id"], db, "{v}");
    let v = h.ok(&b, "session_packet", json!({ "task_id": tb })).await;
    assert_eq!(v["delegations"][0]["id"], db, "{v}");
}

#[tokio::test]
async fn an_organization_b_delegation_creates_its_task_in_organization_b() {
    let h = H::new();
    let a = agent_named("lead-1", DEFAULT_ORG);
    let b = agent_named("lead-1", ORG_B);
    let parent_a = h.ok(&a, "task_add", json!({ "title": "A parent" })).await["id"].as_i64().unwrap();
    let parent_b = h.ok(&b, "task_add", json!({ "title": "B parent" })).await["id"].as_i64().unwrap();
    let v = h
        .ok(&b, "delegate", json!({ "task_spec": SPEC, "to_agent": "builder-1", "parent_task_id": parent_b }))
        .await;
    let (d, task) = (v["delegation_id"].as_i64().unwrap(), v["task_id"].as_i64().unwrap());
    assert_eq!(h.text(&format!("SELECT org_id FROM delegations WHERE id = {d}")).unwrap(), ORG_B);
    assert_eq!(h.text(&format!("SELECT org_id FROM tasks WHERE id = {task}")).unwrap(), ORG_B);
    let listed = |v: Value| v["tasks"].as_array().unwrap().iter().any(|t| t["id"] == task);
    assert!(listed(h.ok(&b, "task_list", json!({ "status": "all" })).await));
    assert!(!listed(h.ok(&a, "task_list", json!({ "status": "all" })).await));

    // Another organization's parent answers as a missing one; nothing written.
    let before = (h.snapshot(), h.events());
    let got = h
        .call(
            &b,
            "delegate",
            json!({ "task_spec": SPEC, "to_agent": "builder-1", "parent_task_id": parent_a }),
        )
        .await;
    let missing = h
        .call(&b, "delegate", json!({ "task_spec": SPEC, "to_agent": "builder-1", "parent_task_id": ABSENT }))
        .await;
    same_as_missing(&got, &missing, parent_a);
    assert_eq!((h.snapshot(), h.events()), before);
}

/// Arguments of a fenced transition, from (delegation id, claim generation,
/// task id).
type Args = fn(i64, i64, i64) -> Value;

/// Each case on a fresh hub: a default-organization delegation to
/// `builder-1`, claimed by it, whose task (when `running`) is `doing` under
/// run `run-1` of `builder-1`, so every guard but the organization passes.
/// Organization B's `builder-1` then sends `action`: it must answer as for a
/// missing delegation and change nothing. Returns each case that did not.
async fn fenced_cases(running: bool, cases: &[(&str, Args)]) -> Vec<String> {
    let mut wrong = Vec::new();
    for (action, args) in cases {
        let h = H::new();
        let a = agent_named("builder-1", DEFAULT_ORG);
        let b = agent_named("builder-1", ORG_B);
        let (d, task) = h.delegate(&agent_named("lead-1", DEFAULT_ORG), "builder-1").await;
        let g = h.claim(&a, d).await;
        if running {
            h.sql(&format!(
                "UPDATE tasks SET status = 'doing', claimed_by = 'builder-1', current_run_id = 'run-1', \
                 current_run_agent = 'builder-1' WHERE id = {task}"
            ))
            .unwrap();
        }
        let before = (h.snapshot(), h.events());
        let got = h.manage(&b, action, args(d, g, task)).await;
        let missing = h.manage(&b, action, args(ABSENT, g, task)).await;
        let (got, missing) = (norm(&got, d), norm(&missing, ABSENT));
        if got != missing || (h.snapshot(), h.events()) != before {
            wrong.push(format!("{action}({}): {got} != {missing}", args(d, g, task)));
        }
        // The same call in its own organization moves it: only the
        // organization refused organization B.
        let own = h.manage(&a, action, args(d, g, task)).await;
        if (h.snapshot(), h.events()) == before {
            wrong.push(format!(
                "{action}({}) changed nothing in its own organization: {own:?}",
                args(d, g, task)
            ));
        }
    }
    wrong
}

/// Task-fenced transitions (and cancels a run does not hold back) across
/// organizations each answer exactly as a missing delegation.
#[tokio::test]
async fn task_fenced_transitions_across_organizations_answer_as_missing() {
    let cases: [(&str, Args); 5] = [
        ("release", |d, g, t| json!({ "id": d, "expected_claim_generation": g, "task_id": t })),
        ("retry", |d, g, t| json!({ "id": d, "expected_claim_generation": g, "task_id": t })),
        ("complete", |d, g, t| json!({ "id": d, "expected_claim_generation": g, "task_id": t })),
        // No run holds the task, so neither guard holds the cancel back.
        ("cancel", |d, g, _| json!({ "id": d, "expected_claim_generation": g, "expected_run_id": "run-0" })),
        ("cancel", |d, _, _| json!({ "id": d, "require_no_run": true })),
    ];
    let wrong = fenced_cases(false, &cases).await;
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// Run-fenced transitions while the run is current: the run guard passes in
/// organization A, so only the organization filter refuses organization B.
#[tokio::test]
async fn run_fenced_transitions_across_organizations_answer_as_missing() {
    let cases: [(&str, Args); 3] = [
        ("release", |d, g, _| json!({ "id": d, "expected_claim_generation": g, "expected_run_id": "run-1" })),
        ("fail", |d, g, _| json!({ "id": d, "expected_claim_generation": g, "expected_run_id": "run-1" })),
        // A cancel names the superseded run: `run-1` took over from `run-0`.
        ("cancel", |d, g, _| json!({ "id": d, "expected_claim_generation": g, "expected_run_id": "run-0" })),
    ];
    let wrong = fenced_cases(true, &cases).await;
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A claim names only the delegation: another organization's pending one
/// answers as a missing one, and an in-flight one changes nothing.
#[tokio::test]
async fn a_claim_across_organizations_answers_as_missing() {
    let h = H::new();
    let a = agent_named("builder-1", DEFAULT_ORG);
    let b = agent_named("builder-1", ORG_B);
    let (pending, _) = h.delegate(&agent_named("lead-1", DEFAULT_ORG), "builder-1").await;
    let (claimed, _) = h.delegate(&agent_named("lead-1", DEFAULT_ORG), "builder-1").await;
    let g = h.claim(&a, claimed).await;
    let before = (h.snapshot(), h.events());
    for d in [pending, claimed] {
        let got = h.manage(&b, "claim", json!({ "id": d })).await;
        same_as_missing(&got, &h.manage(&b, "claim", json!({ "id": ABSENT })).await, d);
    }
    assert_eq!((h.snapshot(), h.events()), before, "nothing moved");
    h.claim(&a, pending).await;
    let v = h.manage(&a, "release", json!({ "id": claimed, "expected_claim_generation": g })).await;
    assert_eq!(v.unwrap()["released"], true);
}

#[tokio::test]
async fn a_cycle_binds_only_its_own_organization_s_delegation() {
    let h = H::new();
    let a = agent_named("builder-1", DEFAULT_ORG);
    let b = agent_named("builder-1", ORG_B);
    let (da, _) = h.delegate(&agent_named("lead-1", DEFAULT_ORG), "builder-1").await;
    let (db, _) = h.delegate(&agent_named("lead-1", ORG_B), "builder-1").await;
    let start = |d: i64| json!({ "action": "start", "params": { "agent": "builder-1", "delegation_id": d } });
    for (who, theirs) in [(&b, da), (&a, db)] {
        let e = h.call(who, "autonomous_cycle_manage", start(theirs)).await.unwrap_err();
        assert_eq!(e.to_string(), UaError::not_found(format!("no delegation with id {theirs}")).to_string());
    }
    for (who, own, org) in [(&b, db, ORG_B), (&a, da, DEFAULT_ORG)] {
        h.ok(who, "autonomous_cycle_manage", start(own)).await;
        assert_eq!(
            h.count(&format!(
                "SELECT COUNT(*) FROM autonomous_cycles WHERE org_id = '{org}' AND delegation_id = {own}"
            )),
            1
        );
    }
}

#[tokio::test]
async fn an_unknown_organization_is_refused_before_any_write() {
    let h = H::new();
    let (d, _) = h.delegate(&agent_named("lead-1", DEFAULT_ORG), "builder-1").await;
    let lead = agent_named("lead-1", UNKNOWN);
    let builder = agent_named("builder-1", UNKNOWN);
    let before = (h.snapshot(), h.events());
    let e =
        h.call(&lead, "delegate", json!({ "task_spec": SPEC, "to_agent": "builder-1" })).await.unwrap_err();
    assert_eq!(reason(&e), "unknown_organization", "{e}");
    for (action, who, args) in [
        ("claim", &builder, json!({ "id": d })),
        ("release", &builder, json!({ "id": d, "expected_claim_generation": 1 })),
        ("retry", &builder, json!({ "id": d, "expected_claim_generation": 1 })),
        ("complete", &builder, json!({ "id": d })),
        ("fail", &builder, json!({ "id": d })),
        ("cancel", &lead, json!({ "id": d })),
    ] {
        let e = h.manage(who, action, args.clone()).await.unwrap_err();
        assert_eq!(reason(&e), "unknown_organization", "{action}({args}): {e}");
    }
    assert_eq!((h.snapshot(), h.events()), before, "nothing changed");
}

#[tokio::test]
async fn an_idempotency_key_never_replays_across_organizations() {
    let h = H::new();
    let req = json!({ "task_spec": SPEC, "to_agent": "builder-1", "idempotency_key": "k-1" });
    let a = agent_named("lead-1", DEFAULT_ORG);
    let b = agent_named("lead-1", ORG_B);
    let ra = h.ok(&a, "delegate", req.clone()).await;
    let rb = h.ok(&b, "delegate", req.clone()).await;
    assert_ne!(ra["delegation_id"], rb["delegation_id"], "the key was not replayed into organization B");
    assert_eq!(
        h.text(&format!("SELECT org_id FROM delegations WHERE id = {}", rb["delegation_id"])).unwrap(),
        ORG_B
    );
    // Each organization replays its own.
    assert_eq!(h.ok(&a, "delegate", req.clone()).await, ra);
    assert_eq!(h.ok(&b, "delegate", req.clone()).await, rb);
    for (who, want) in [(&a, &ra), (&b, &rb)] {
        let v = h.manage(who, "lookup", json!({ "idempotency_key": "k-1" })).await.unwrap();
        assert_eq!(&v["result"], want, "{v}");
    }
    let keys: Vec<String> = h
        .hub
        .db()
        .read(|c| {
            Ok(c.prepare("SELECT key FROM idempotency_keys WHERE tool = 'delegate' ORDER BY key")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?)
        })
        .unwrap();
    assert_eq!(keys, ["delegate:lead-1:k-1", "org:org-b/delegate:lead-1:k-1"]);

    // Per delegating agent: `a:b` with key `c` and `a` with key `b:c` are two
    // stored keys, never one.
    let colon = agent_named("lead:x", DEFAULT_ORG);
    let plain = agent_named("lead", DEFAULT_ORG);
    let r1 = h
        .ok(&colon, "delegate", json!({ "task_spec": SPEC, "to_agent": "builder-1", "idempotency_key": "k" }))
        .await;
    let r2 = h
        .ok(
            &plain,
            "delegate",
            json!({ "task_spec": SPEC, "to_agent": "builder-1", "idempotency_key": "x:k" }),
        )
        .await;
    assert_ne!(r1["delegation_id"], r2["delegation_id"]);
    assert_eq!(h.count("SELECT COUNT(*) FROM idempotency_keys WHERE key = 'delegate:lead%3Ax:k'"), 1);
}

/// A receipt stored before labels were escaped, under its old key
/// `delegate:lead:x:k` (written here by SQL), still replays to its own agent:
/// a retry after the upgrade creates nothing, and `lookup` finds it.
#[tokio::test]
async fn a_receipt_under_the_old_unescaped_key_replays_to_its_own_agent() {
    let h = H::new();
    let colon = agent_named("lead:x", DEFAULT_ORG);
    let req = json!({ "task_spec": SPEC, "to_agent": "builder-1", "idempotency_key": "k" });
    let first = h.ok(&colon, "delegate", req.clone()).await;
    h.sql("UPDATE idempotency_keys SET key = 'delegate:lead:x:k' WHERE key = 'delegate:lead%3Ax:k'").unwrap();
    assert_eq!(h.count("SELECT COUNT(*) FROM idempotency_keys WHERE key = 'delegate:lead:x:k'"), 1);
    let before = (h.snapshot(), h.events());

    assert_eq!(h.ok(&colon, "delegate", req.clone()).await, first, "the old receipt replayed");
    assert_eq!((h.snapshot(), h.events()), before, "no second task or delegation");
    assert_eq!(h.count("SELECT COUNT(*) FROM delegations"), 1);
    let v = h.manage(&colon, "lookup", json!({ "idempotency_key": "k" })).await.unwrap();
    assert_eq!(v["state"], "committed", "{v}");
    assert_eq!(v["result"], first);
    // The same key from an agent with no `:` in its label is another request.
    let plain = agent_named("lead", DEFAULT_ORG);
    let v = h.manage(&plain, "lookup", json!({ "idempotency_key": "x:k" })).await.unwrap();
    assert_eq!(v["state"], "committed", "the old key is that agent's own current key: {v}");
}

/// The old key `delegate:lead:x:k` holding another agent's receipt (`lead`
/// with key `x:k` stores exactly that key) never replays to `lead:x` with key
/// `k`: its digest names another `from_agent`, so it reads as not found and
/// the request runs fresh.
#[tokio::test]
async fn an_old_key_holding_another_agent_s_receipt_never_replays() {
    let h = H::new();
    let plain = agent_named("lead", DEFAULT_ORG);
    let colon = agent_named("lead:x", DEFAULT_ORG);
    let req = |key: &str| json!({ "task_spec": SPEC, "to_agent": "builder-1", "idempotency_key": key });
    let theirs = h.ok(&plain, "delegate", req("x:k")).await;
    assert_eq!(h.count("SELECT COUNT(*) FROM idempotency_keys WHERE key = 'delegate:lead:x:k'"), 1);

    let v = h.manage(&colon, "lookup", json!({ "idempotency_key": "k" })).await.unwrap();
    assert_eq!(v["state"], "not_found", "{v}");
    let mine = h.ok(&colon, "delegate", req("k")).await;
    assert_ne!(mine["delegation_id"], theirs["delegation_id"], "a fresh delegation, not a replay");
    assert_eq!(
        h.text(&format!("SELECT from_agent FROM delegations WHERE id = {}", mine["delegation_id"])).unwrap(),
        "lead:x"
    );
    // Its own retry now replays its own receipt, under the escaped key.
    assert_eq!(h.ok(&colon, "delegate", req("k")).await, mine);
    assert_eq!(h.ok(&plain, "delegate", req("x:k")).await, theirs);
    assert_eq!(h.count("SELECT COUNT(*) FROM delegations"), 2);
}

#[tokio::test]
async fn organization_b_text_and_labels_never_reach_the_default_ledger() {
    let h = H::new();
    let from = agent_named(B_FROM, ORG_B);
    let to = agent_named(B_TO, ORG_B);
    let spec = b_spec();
    let base = json!({ "task_spec": spec, "to_agent": B_TO, "project": B_PROJECT, "deadline": B_DEADLINE });
    let d = h.ok(&from, "delegate", base.clone()).await["delegation_id"].as_i64().unwrap();
    let g = h.claim(&to, d).await;
    h.ok(&to, "delegate_release", json!({ "id": d, "expected_claim_generation": g })).await;
    let g = h.claim(&to, d).await;
    h.manage(&to, "retry", json!({ "id": d, "expected_claim_generation": g, "reason": B_REASON }))
        .await
        .unwrap();
    let g = h.claim(&to, d).await;
    h.manage(&to, "complete", json!({ "id": d, "expected_claim_generation": g, "result": B_RESULT }))
        .await
        .unwrap();
    let d2 = h.ok(&from, "delegate", base.clone()).await["delegation_id"].as_i64().unwrap();
    h.manage(&to, "fail", json!({ "id": d2, "reason": B_REASON })).await.unwrap();
    let d3 = h
        .ok(&from, "handoff", json!({ "task_spec": spec, "to_agent": B_TO, "deadline": B_DEADLINE }))
        .await["handoff_id"]
        .as_i64()
        .unwrap();
    h.ok(&from, "delegate_cancel", json!({ "id": d3, "reason": B_REASON })).await;

    let rows: Vec<(String, String, Option<String>)> = h
        .hub
        .db()
        .read(|c| {
            Ok(c.prepare("SELECT channel, payload, originator FROM event_log ORDER BY seq")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?)
        })
        .unwrap();
    let delegation_events = rows.iter().filter(|(c, _, _)| c.starts_with("agent.delegation.")).count();
    assert!(delegation_events >= 10, "the writes were ledgered: {delegation_events}");
    for (channel, payload, originator) in &rows {
        for s in [B_OBJECTIVE, B_FROM, B_TO, B_PROJECT, B_DEADLINE, B_REASON, B_RESULT] {
            assert!(!payload.contains(s), "{s:?} reached a default ledger payload ({channel}): {payload}");
            assert!(!originator.as_deref().unwrap_or_default().contains(s), "{s:?} is an originator");
        }
        if channel.starts_with("agent.delegation.") {
            assert_eq!(originator.as_deref(), Some("system"), "{channel}");
        }
    }
    // Ids, statuses and generations remain.
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM event_log WHERE channel = 'agent.delegation.completed' \
             AND json_extract(payload, '$.delegation_id') = {d} AND json_extract(payload, '$.status') = 'completed'"
        )),
        1
    );

    // The default organization's events keep their text and originator.
    let a = agent_named("lead-1", DEFAULT_ORG);
    let da =
        h.ok(&a, "delegate", json!({ "task_spec": SPEC, "to_agent": "builder-1" })).await["delegation_id"]
            .as_i64()
            .unwrap();
    let p = h
        .text(&format!(
            "SELECT payload || '|' || originator FROM event_log WHERE channel = 'agent.delegation.created' \
             AND json_extract(payload, '$.delegation_id') = {da}"
        ))
        .unwrap();
    assert!(p.contains("\"to_agent\":\"builder-1\"") && p.ends_with("|lead-1"), "{p}");
    let p = h
        .text(&format!(
            "SELECT payload FROM event_log WHERE channel = 'agent.task.created' \
             AND json_extract(payload, '$.task_id') = (SELECT task_id FROM delegations WHERE id = {da})"
        ))
        .unwrap();
    assert!(p.contains("Add a CSV export to the report page."), "{p}");
}

/// Owner decision: a delegation targets only a registered agent of the
/// delegator's organization, so one to another organization's agent is
/// refused before anything is written, exactly as one to a label no agent
/// has registered.
#[tokio::test]
async fn a_delegation_to_another_organization_s_agent_fails_closed() {
    let h = H::new();
    let lead = agent_named("lead-1", DEFAULT_ORG);
    // `builder-b` registers in organization B (a heartbeat), never in A.
    h.reg.call(&h.hub, &agent_named("builder-b", ORG_B), "agent_heartbeat", json!({})).await.unwrap();
    let before = (h.snapshot(), h.events());
    let args = |to: &str| json!({ "task_spec": SPEC, "to_agent": to });
    // The raw registry call: `H::call` would register the target first.
    let theirs = h.reg.call(&h.hub, &lead, "delegate", args("builder-b")).await.unwrap_err();
    assert_eq!(theirs.code(), "not_found", "{theirs:?}");
    assert_eq!((h.snapshot(), h.events()), before, "nothing created");
    let unregistered = h.reg.call(&h.hub, &lead, "delegate", args("builder-z")).await.unwrap_err();
    assert_eq!(
        format!("{theirs:?}").replace("builder-b", "L"),
        format!("{unregistered:?}").replace("builder-z", "L"),
        "another organization's agent answers as a label no agent has registered"
    );
}

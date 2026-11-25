//! The autonomous-cycle tables are tenant data (`docs/organization.md`,
//! Scoping per subsystem): `autonomous_cycles`, `autonomous_cycle_transitions`
//! and `autonomous_cycle_usage` (`organization.v1.tools.cycles`,
//! `cycles.v2.org_scope`). No key needed a rebuild: a cycle id is
//! hub-generated and the transition and usage keys are led by it, so there is
//! no rebuild to crash or roll back here. `delegations` stays with the tasks
//! family (every delegation creates its task in the same transaction).
//!
//! A second organization is created at the storage level, as no tool creates
//! one yet, and its callers are built by hand. Organization-B rows are written
//! through the tools with an organization-B caller; only the legacy rows of the
//! upgrade test and the defence-in-depth rows are seeded by SQL.
//!
//! Nothing runs a cycle without a caller (no scheduler or executor reads these
//! tables), so the green-path check is the only runner-like path, and it is
//! covered through `autonomous_cycle_green_path_eligibility` and the gated
//! transitions.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 2] = ["organization.v1.tools.cycles", "cycles.v2.org_scope"];
const TABLES: [&str; 3] = ["autonomous_cycles", "autonomous_cycle_transitions", "autonomous_cycle_usage"];
const CHILDREN: [&str; 2] = ["autonomous_cycle_transitions", "autonomous_cycle_usage"];
/// Organization-B text that must never reach the default organization's
/// ledger: a kill reason, a capability name, and the agent label a system
/// caller claims to act as.
const B_REASON: &str = "Project Falcon acquisition halted";
const B_CAP: &str = "falcon_secret_tool";
const B_AGENT: &str = "Kestrel night-shift runner";

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

fn missing_cycle(id: &str) -> String {
    UaError::not_found(format!("no autonomous cycle with id {id:?}")).to_string()
}

struct H {
    hub: Hub,
    reg: Registry,
}

impl H {
    fn new() -> Self {
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.autonomy_max_tokens = 1000;
        let hub = Hub::in_memory(cfg).unwrap();
        add_org(&hub, ORG_B);
        Self { hub, reg: builtin_registry() }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn manage(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "autonomous_cycle_manage", json!({ "action": action, "params": params })).await
    }

    async fn ok(&self, who: &Caller, action: &str, params: Value) -> Value {
        match self.manage(who, action, params.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{}: cycle {action}({params}) failed: {e:?}", who.org_id),
        }
    }

    /// A fresh cycle in `plan`; returns its id.
    async fn start(&self, who: &Caller, extra: Value) -> String {
        let mut params = json!({ "agent": who.label });
        if let (Some(p), Value::Object(e)) = (params.as_object_mut(), extra) {
            p.extend(e);
        }
        self.ok(who, "start", params).await["cycle"]["id"].as_str().unwrap().to_string()
    }

    async fn go(&self, who: &Caller, cycle: &str, to: &str, key: &str) -> Result<Value, UaError> {
        self.manage(
            who,
            "transition",
            json!({ "cycle_id": cycle, "to_state": to, "idempotency_key": key, "agent": who.label }),
        )
        .await
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

    /// The `org_id` of every row of `table` belonging to cycle `id`.
    fn orgs_of(&self, table: &str, id: &str) -> Vec<String> {
        let key = if table == "autonomous_cycles" { "id" } else { "cycle_id" };
        let sql = format!("SELECT org_id FROM {table} WHERE {key} = ?1 ORDER BY rowid");
        let id = id.to_string();
        self.hub
            .db()
            .read(move |c| Ok(c.prepare(&sql)?.query_map([&id], |r| r.get(0))?.collect::<Result<_, _>>()?))
            .unwrap()
    }

    /// Every `agent.cycle.updated` payload, oldest first.
    fn events(&self) -> Vec<Value> {
        self.hub
            .db()
            .read(|c| {
                let rows: Vec<String> = c
                    .prepare(
                        "SELECT payload FROM event_log WHERE channel = 'agent.cycle.updated' ORDER BY seq",
                    )?
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                Ok(rows.iter().map(|p| serde_json::from_str(p).unwrap()).collect())
            })
            .unwrap()
    }

    /// A default-organization task claimed by `builder-1`, its worktree a
    /// plain directory; returns its id.
    async fn claimed_task(&self, worktree: &std::path::Path) -> i64 {
        let me = agent(DEFAULT_ORG);
        let id = self.call(&me, "task_add", json!({ "title": "Cycle work" })).await.unwrap()["id"]
            .as_i64()
            .unwrap();
        self.call(&me, "task_claim", json!({ "id": id, "worktree_path": worktree.to_string_lossy() }))
            .await
            .unwrap();
        id
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

/// Every write action aimed at cycle `id` (in `plan`), each of which would
/// change it if it were the caller's. `failed` is approval-gated, so it also
/// checks that nothing reaches the gate.
fn writes(id: &str) -> Vec<(&'static str, Value)> {
    vec![
        (
            "transition",
            json!({ "cycle_id": id, "to_state": "delegated", "idempotency_key": "x1", "agent": "builder-1" }),
        ),
        (
            "transition",
            json!({ "cycle_id": id, "to_state": "failed", "idempotency_key": "x2", "agent": "builder-1",
                    "reason": "x" }),
        ),
        ("kill", json!({ "cycle_id": id, "agent": "builder-1", "reason": "x" })),
        ("record_usage", json!({ "cycle_id": id, "agent": "builder-1", "tokens": 1 })),
        (
            "record_usage",
            json!({ "cycle_id": id, "agent": "builder-1", "tokens": 1, "usage_run_id": "r", "usage_id": "u" }),
        ),
    ]
}

// --- schema ------------------------------------------------------------------------------------

const LEGACY_ROWS: &str = "
INSERT INTO autonomous_cycles (id, state, max_time_s, max_tokens, max_retries, max_cost_cents, created_by,
    created_at, updated_at)
VALUES ('legacy1', 'plan', 60, 100, 3, 50, 'builder-1', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');
INSERT INTO autonomous_cycle_transitions (cycle_id, from_state, to_state, idempotency_key, actor, created_at)
VALUES ('legacy1', 'plan', 'delegated', 'k1', 'builder-1', 'x'),
       ('legacy1', 'delegated', 'executing', 'k2', 'builder-1', 'x');
DELETE FROM autonomous_cycle_transitions WHERE idempotency_key = 'k2';
UPDATE autonomous_cycles SET state = 'delegated', version = 1 WHERE id = 'legacy1';
INSERT INTO autonomous_cycle_usage (cycle_id, usage_run_id, usage_id, actor, payload, created_at)
VALUES ('legacy1', 'run-1', 'u1', 'builder-1', '{}', 'x');
";

#[test]
fn a_legacy_database_upgrades_into_the_default_organization() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(LEGACY_ROWS)?;
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
                // `cycles.v3.task_org` (applied after the tasks conversion)
                // keeps a cycle's task in its own organization.
                assert_eq!(
                    names(c, "trigger", "autonomous_cycles"),
                    [
                        "autonomous_cycles_org_exists",
                        "autonomous_cycles_org_immutable",
                        "autonomous_cycles_task_org",
                        "autonomous_cycles_task_org_update",
                    ]
                );
                for t in CHILDREN {
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
                // The legacy indexes stay; the organization-led index exists.
                assert_eq!(
                    names(c, "index", "autonomous_cycles"),
                    [
                        "idx_autonomous_cycles_org_state",
                        "idx_autonomous_cycles_state",
                        "idx_autonomous_cycles_task"
                    ]
                );
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
            // The AUTOINCREMENT high-water mark is untouched: the deleted id 2 is never reused.
            tx.execute(
                "INSERT INTO autonomous_cycle_transitions
                     (org_id, cycle_id, from_state, to_state, idempotency_key, actor, created_at)
                 VALUES ('default', 'legacy1', 'delegated', 'executing', 'k3', 'builder-1', 'x')",
                [],
            )?;
            assert_eq!(tx.last_insert_rowid(), 3);
            // The keys are still enforced.
            let err = tx
                .execute(
                    "INSERT INTO autonomous_cycle_transitions
                         (org_id, cycle_id, from_state, to_state, idempotency_key, actor, created_at)
                     VALUES ('default', 'legacy1', 'plan', 'delegated', 'k1', 'builder-1', 'x')",
                    [],
                )
                .unwrap_err()
                .to_string();
            assert!(err.contains("UNIQUE"), "{err}");
            let err = tx
                .execute(
                    "INSERT INTO autonomous_cycle_usage (org_id, cycle_id, usage_run_id, usage_id, actor, payload,
                         created_at) VALUES ('default', 'legacy1', 'run-1', 'u1', 'builder-1', '{}', 'x')",
                    [],
                )
                .unwrap_err()
                .to_string();
            assert!(err.contains("UNIQUE"), "{err}");
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

/// The legacy cycle is the default organization's through the tools, and
/// another organization does not see it.
#[tokio::test]
async fn a_legacy_cycle_is_read_and_written_by_the_default_organization() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(LEGACY_ROWS)?;
            Ok(())
        })
        .unwrap();
    }
    let hub = Hub::open(cfg).unwrap();
    add_org(&hub, ORG_B);
    let h = H { hub, reg: builtin_registry() };
    let me = agent(DEFAULT_ORG);
    let got = h.ok(&me, "get", json!({ "cycle_id": "legacy1" })).await;
    assert_eq!(
        (got["cycle"]["org_id"].as_str(), got["cycle"]["state"].as_str()),
        (Some("default"), Some("delegated"))
    );
    assert_eq!(got["transitions"].as_array().unwrap().len(), 1, "{got}");
    // The legacy idempotency key still replays.
    let replay = h.go(&me, "legacy1", "delegated", "k1").await.unwrap();
    assert_eq!(replay["idempotent"], true, "{replay}");
    h.go(&me, "legacy1", "executing", "k9").await.unwrap();
    assert_eq!(h.orgs_of("autonomous_cycle_transitions", "legacy1"), ["default", "default"]);

    let e = h.manage(&agent(ORG_B), "get", json!({ "cycle_id": "legacy1" })).await.unwrap_err();
    assert_eq!(e.to_string(), missing_cycle("legacy1"));
}

// --- isolation ---------------------------------------------------------------------------------

/// Each organization's cycle answers to the other exactly as a missing one,
/// through every read and write action, the legacy tools and the green-path
/// check, and nothing of it changes; a gated transition never reaches the
/// approval queue.
#[tokio::test]
async fn cycles_are_isolated_in_both_directions() {
    let h = H::new();
    let wt = tempfile::tempdir().unwrap();
    let task = h.claimed_task(wt.path()).await;
    let a_id = h.start(&agent(DEFAULT_ORG), json!({ "task_id": task })).await;
    let b_id = h.start(&agent(ORG_B), json!({})).await;

    for (me, mine, theirs) in [(DEFAULT_ORG, &a_id, &b_id), (ORG_B, &b_id, &a_id)] {
        let who = agent(me);
        let missing = |e: &UaError| {
            assert_eq!(e.code(), "not_found", "{me}: {e}");
            assert_eq!(e.to_string(), missing_cycle(theirs), "{me}");
        };

        // Lists hold only the caller's cycle, whatever the state filter.
        for params in [json!({}), json!({ "state": "plan" })] {
            let l = h.ok(&who, "list", params.clone()).await;
            let ids: Vec<&str> =
                l["cycles"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap()).collect();
            assert_eq!(ids, [mine.as_str()], "{me}: {params}: {l}");
        }
        let l = h.call(&who, "autonomous_cycle_list", json!({})).await.unwrap();
        assert_eq!(l["cycles"].as_array().unwrap().len(), 1, "{me}: {l}");

        missing(&h.manage(&who, "get", json!({ "cycle_id": theirs })).await.unwrap_err());
        missing(&h.call(&who, "autonomous_cycle_get", json!({ "cycle_id": theirs })).await.unwrap_err());
        missing(
            &h.call(&who, "autonomous_cycle_green_path_eligibility", json!({ "cycle_id": theirs }))
                .await
                .unwrap_err(),
        );
        assert_eq!(h.ok(&who, "get", json!({ "cycle_id": mine })).await["cycle"]["org_id"], me);

        // The default organization's task-bound cycle governs its task only there.
        let found = h.ok(&who, "get_for_task", json!({ "task_id": task })).await;
        let expect = if me == DEFAULT_ORG { json!(a_id) } else { Value::Null };
        assert_eq!(found["cycle"].get("id").cloned().unwrap_or(Value::Null), expect, "{me}: {found}");

        let before = h.snapshot();
        let events = h.count("SELECT COUNT(*) FROM event_log");
        let approvals = h.count("SELECT COUNT(*) FROM approvals");
        for (action, params) in writes(theirs) {
            missing(&h.manage(&who, action, params).await.unwrap_err());
        }
        missing(
            &h.call(
                &who,
                "autonomous_cycle_kill",
                json!({ "cycle_id": theirs, "agent": "builder-1", "reason": "x" }),
            )
            .await
            .unwrap_err(),
        );
        assert_eq!(h.snapshot(), before, "{me}: the other organization's cycle is untouched");
        assert_eq!(h.count("SELECT COUNT(*) FROM event_log"), events, "{me}");
        assert_eq!(h.count("SELECT COUNT(*) FROM approvals"), approvals, "{me}: nothing reached the gate");
    }
}

/// A task, and the delegation tied to one, is read in the cycle's
/// organization: to another organization it answers as a missing one, both
/// when a cycle is started and when the green path judges it.
#[tokio::test]
async fn another_organization_never_reaches_a_task() {
    let h = H::new();
    let wt = tempfile::tempdir().unwrap();
    let task = h.claimed_task(wt.path()).await;
    let me = agent(DEFAULT_ORG);
    let spec = "### Objective\nAdd a CSV export.\n\n### Scope\n- src/report.rs\n\n### Definition of Done\n\
                - Calling export on a report with two rows returns a CSV with a header and two lines\n\n\
                ### TDD Constraints\n- Stub: none\n\n### Boundaries\n- Do not change the report schema\n";
    // A delegation targets a registered agent of the delegator's organization.
    let builder_2 =
        Caller { label: "builder-2".into(), session_key: Some("builder-2-s".into()), ..agent(DEFAULT_ORG) };
    h.call(&builder_2, "agent_heartbeat", json!({})).await.unwrap();
    let deleg = h.call(&me, "delegate", json!({ "task_spec": spec, "to_agent": "builder-2" })).await;
    let deleg = deleg.map(|d| d["delegation_id"].as_i64()).unwrap_or_else(|e| panic!("delegate: {e}"));

    let b = agent(ORG_B);
    let before = h.snapshot();
    let e = h.manage(&b, "start", json!({ "agent": "builder-1", "task_id": task })).await.unwrap_err();
    assert_eq!(e.to_string(), UaError::not_found(format!("no task with id {task}")).to_string());
    let d = deleg.unwrap();
    let e = h.manage(&b, "start", json!({ "agent": "builder-1", "delegation_id": d })).await.unwrap_err();
    assert_eq!(e.to_string(), UaError::not_found(format!("no delegation with id {d}")).to_string());
    // The default organization binds both.
    h.start(&me, json!({ "task_id": task, "delegation_id": d })).await;
    assert_eq!(h.count("SELECT COUNT(*) FROM autonomous_cycles WHERE org_id = 'org-b'"), 0);
    assert_ne!(h.snapshot(), before);

    // The green path, judging a caller-supplied summary of a task-bound cycle:
    // the default organization reaches the worktree (a plain directory, so
    // HEAD cannot resolve), organization B does not see the task at all.
    let summary = json!({ "task_id": task, "cycle": { "state": "pr", "pr_url": "abc1234" } });
    let a = h.call(&me, "autonomous_cycle_green_path_eligibility", summary.clone()).await.unwrap();
    assert!(a["reasons"].to_string().contains("worktree HEAD could not be resolved"), "{a}");
    let v = h.call(&b, "autonomous_cycle_green_path_eligibility", summary).await.unwrap();
    assert_eq!(v["eligible"], false);
    assert!(v["reasons"].to_string().contains("no git worktree found for this task"), "{v}");
}

// --- organization B's write path ---------------------------------------------------------------

/// Every write of an organization-B caller lands its rows in organization
/// B; the default organization's cycle is untouched; organization B's free
/// text and claimed labels never reach the default organization's ledger.
#[tokio::test]
async fn organization_b_writes_land_in_organization_b() {
    let h = H::new();
    let me = agent(DEFAULT_ORG);
    let a_id = h.start(&me, json!({})).await;
    let a_rows = h.snapshot();

    let b = agent(ORG_B);
    let id = h.start(&b, json!({ "budgets": { "tokens": 100 }, "capabilities": ["task_list"] })).await;
    for (i, st) in ["delegated", "executing"].iter().enumerate() {
        h.go(&b, &id, st, &format!("w{i}")).await.unwrap();
    }
    let out = h.ok(&b, "record_usage", json!({ "cycle_id": id, "agent": "builder-1", "tokens": 40 })).await;
    assert_eq!(out["cycle"]["used_tokens"], 40);
    let out = h
        .ok(
            &b,
            "record_usage",
            json!({ "cycle_id": id, "agent": "builder-1", "tokens": 1, "capability": B_CAP }),
        )
        .await;
    assert_eq!(out["cycle"]["state"], "blocked", "{out}");
    assert!(out["reason"].as_str().unwrap().contains(B_CAP), "organization B keeps its own text: {out}");
    // Attempt-keyed usage needs a task the caller owns; this cycle has none.
    let e = h
        .manage(
            &b,
            "record_usage",
            json!({ "cycle_id": id, "agent": "builder-1", "tokens": 1,
                                             "usage_run_id": "run-1", "usage_id": "u1" }),
        )
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "not_owner", "{e}");

    // A gated transition parks an approval bound to organization B.
    let e = h
        .manage(
            &b,
            "transition",
            json!({ "cycle_id": id, "to_state": "failed", "idempotency_key": "f",
                                           "agent": "builder-1", "reason": B_REASON }),
        )
        .await
        .unwrap_err();
    let UaError::ApprovalRequired { approval_id, .. } = e else { panic!("expected an approval, got {e}") };
    let payload: Value = serde_json::from_str(
        &h.hub
            .db()
            .read(move |c| {
                Ok(c.query_row("SELECT payload FROM approvals WHERE id = ?1", [approval_id], |r| {
                    r.get::<_, String>(0)
                })?)
            })
            .unwrap(),
    )
    .unwrap();
    assert_eq!((payload["org_id"].as_str(), payload["cycle_id"].as_str()), (Some(ORG_B), Some(id.as_str())));

    // A start whose capability is outside the registry starts blocked; a
    // system caller keeps the agent label it claims; both are killed.
    let blocked = h.start(&b, json!({ "capabilities": [B_CAP] })).await;
    let sys = Caller::system_for(ORG_B);
    let sys_id = h.start(&sys, json!({ "agent": B_AGENT })).await;
    let t = h.go(&sys, &sys_id, "delegated", "s1").await;
    assert!(t.is_ok(), "{t:?}");
    let k = h.ok(&sys, "kill", json!({ "cycle_id": sys_id, "agent": B_AGENT, "reason": B_REASON })).await;
    assert!(k["cycle"]["stop_reason"].as_str().unwrap().contains(B_AGENT), "{k}");
    h.ok(&b, "kill", json!({ "cycle_id": id, "agent": "builder-1", "reason": B_REASON })).await;

    let got = h.ok(&b, "get", json!({ "cycle_id": id })).await;
    assert_eq!(got["cycle"]["state"], "killed");
    assert_eq!(got["transitions"].as_array().unwrap().len(), 3, "{got}");
    for cycle in [&id, &blocked, &sys_id] {
        assert_eq!(h.orgs_of("autonomous_cycles", cycle), [ORG_B], "{cycle}");
    }
    assert_eq!(h.orgs_of("autonomous_cycle_transitions", &id), [ORG_B; 3]);
    assert_eq!(h.orgs_of("autonomous_cycle_transitions", &sys_id), [ORG_B; 2]);
    let l = h.ok(&b, "list", json!({})).await;
    assert_eq!(l["cycles"].as_array().unwrap().len(), 3, "{l}");
    assert!(
        a_rows.lines().all(|row| h.snapshot().contains(row)),
        "the default organization's rows are untouched"
    );

    // Organization B's text and claimed labels never reach the default
    // organization's ledger: the stop reason stays in the payload, as null.
    for needle in [B_REASON, B_CAP, B_AGENT, "Falcon", "Kestrel"] {
        let leaked = h.count(&format!(
            "SELECT COUNT(*) FROM event_log WHERE payload LIKE '%{needle}%' OR originator LIKE '%{needle}%'"
        ));
        assert_eq!(leaked, 0, "{needle:?} reached the default organization's ledger");
    }
    let b_events: Vec<Value> = h
        .events()
        .into_iter()
        .filter(|e| [&id, &blocked, &sys_id].iter().any(|c| e["cycle_id"] == ***c))
        .collect();
    assert_eq!(b_events.len(), 10, "{b_events:?}");
    assert!(b_events.iter().all(|e| e.get("stop_reason") == Some(&Value::Null)), "{b_events:?}");

    // The default organization's own stop reason is still recorded.
    h.ok(&me, "kill", json!({ "cycle_id": a_id, "agent": "builder-1", "reason": "alpha stop" })).await;
    let last = h.events().pop().unwrap();
    assert_eq!(last["stop_reason"], "killed by builder-1: alpha stop", "{last}");
    let by: String = h
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT originator FROM event_log ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))?)
        })
        .unwrap();
    assert_eq!(by, "builder-1");
}

// --- same-organization parent triggers ---------------------------------------------------------

/// A transition or usage row cannot join, or be moved under, another
/// organization's cycle (`*_org_parent`, `*_org_parent_update`). Seeded by
/// SQL: no tool writes such a row.
#[tokio::test]
async fn a_child_row_must_be_in_its_cycles_organization() {
    let h = H::new();
    let me = agent(DEFAULT_ORG);
    let a = h.start(&me, json!({})).await;
    let a_other = h.start(&me, json!({})).await;
    h.go(&me, &a, "delegated", "k1").await.unwrap();
    let b = h.start(&agent(ORG_B), json!({})).await;
    h.hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO autonomous_cycle_usage (org_id, cycle_id, usage_run_id, usage_id, actor, payload,
                     created_at) VALUES ('default', ?1, 'r', 'u', 'builder-1', '{}', 'x')",
                [&a],
            )?;
            Ok(())
        })
        .unwrap();
    let before = h.snapshot();
    let (a, other, b) = (a.clone(), a_other.clone(), b.clone());
    h.hub
        .db()
        .write(move |tx| {
            // INSERT: organization B under the default organization's cycle, and the reverse.
            for (org, cycle) in [("org-b", &a), ("default", &b)] {
                let err = tx
                    .execute(
                        "INSERT INTO autonomous_cycle_transitions
                             (org_id, cycle_id, from_state, to_state, idempotency_key, actor, created_at)
                         VALUES (?1, ?2, 'plan', 'delegated', 'intruder', 'x', 'x')",
                        [org, cycle.as_str()],
                    )
                    .unwrap_err()
                    .to_string();
                assert!(err.contains("cycle belongs to another organization"), "{org}: {err}");
                let err = tx
                    .execute(
                        "INSERT INTO autonomous_cycle_usage
                             (org_id, cycle_id, usage_run_id, usage_id, actor, payload, created_at)
                         VALUES (?1, ?2, 'r', 'intruder', 'x', '{}', 'x')",
                        [org, cycle.as_str()],
                    )
                    .unwrap_err()
                    .to_string();
                assert!(err.contains("cycle belongs to another organization"), "{org}: {err}");
            }
            // UPDATE: a default-organization row moved under organization B's cycle.
            for t in CHILDREN {
                let err = tx
                    .execute(&format!("UPDATE {t} SET cycle_id = ?1 WHERE cycle_id = ?2"), [&b, &a])
                    .unwrap_err()
                    .to_string();
                assert!(err.contains("cycle belongs to another organization"), "{t}: {err}");
                // Within one organization the trigger stays out of the way.
                assert_eq!(
                    tx.execute(&format!("UPDATE {t} SET cycle_id = ?1 WHERE cycle_id = ?2"), [&other, &a])?,
                    1
                );
                tx.execute(&format!("UPDATE {t} SET cycle_id = ?1 WHERE cycle_id = ?2"), [&a, &other])?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(h.snapshot(), before);
}

// --- unknown organization ----------------------------------------------------------------------

/// A caller whose organization `orgs` does not hold is refused by the
/// family's own guard (its wording, not the trigger's bare "unknown
/// organization"), before anything is written, including writes with
/// nothing to insert and a gated transition (nothing reaches the gate).
#[tokio::test]
async fn an_unknown_organization_is_refused_before_any_write() {
    let h = H::new();
    let a_id = h.start(&agent(DEFAULT_ORG), json!({})).await;
    let before = h.snapshot();
    let events = h.count("SELECT COUNT(*) FROM event_log");
    let approvals = h.count("SELECT COUNT(*) FROM approvals");
    let who = agent(UNKNOWN);
    let guard = format!("unknown organization {UNKNOWN:?}; no autonomous cycle was changed");

    let mut calls = writes(&a_id);
    calls.push(("start", json!({ "agent": "builder-1" })));
    for (action, params) in calls {
        let e = h.manage(&who, action, params.clone()).await.unwrap_err();
        assert_eq!(reason(&e), "unknown_organization", "{action}({params}): {e}");
        assert!(e.to_string().contains(&guard), "{action}: {e}");
    }
    assert_eq!(h.snapshot(), before);
    assert_eq!(h.count("SELECT COUNT(*) FROM event_log"), events);
    assert_eq!(h.count("SELECT COUNT(*) FROM approvals"), approvals);

    // Reads in an unknown organization see nothing.
    let l = h.ok(&who, "list", json!({})).await;
    assert_eq!(l["cycles"], json!([]));
    let e = h.manage(&who, "get", json!({ "cycle_id": a_id })).await.unwrap_err();
    assert_eq!(e.to_string(), missing_cycle(&a_id));
}

// --- defence in depth --------------------------------------------------------------------------

/// The transition and usage reads filter on `org_id` themselves, not only
/// through the cycle: with the parent triggers dropped, another
/// organization's rows seeded under a default-organization cycle are never
/// returned, replayed as an idempotent result, or matched as recorded usage,
/// and a cycle of another organization bound to a task is never its owner's.
/// (Seeded by SQL: no tool can write such a row.)
#[tokio::test]
async fn another_organizations_rows_under_a_cycle_id_are_never_read() {
    let h = H::new();
    let wt = tempfile::tempdir().unwrap();
    let task = h.claimed_task(wt.path()).await;
    let me = agent(DEFAULT_ORG);
    let id = h.start(&me, json!({ "task_id": task })).await;
    let i2 = id.clone();
    // Exactly the payload the default organization's call below records.
    let same_payload =
        json!({ "elapsed_s": 0.0, "tokens": 5, "retries": 0, "cost_cents": 0.0, "capability": null })
            .to_string();
    h.hub
        .db()
        .write(move |tx| {
            tx.execute_batch(
                "DROP TRIGGER autonomous_cycle_transitions_org_parent;
                 DROP TRIGGER autonomous_cycle_usage_org_parent;
                 DROP TRIGGER autonomous_cycles_task_org;",
            )?;
            tx.execute(
                "INSERT INTO autonomous_cycle_transitions
                     (org_id, cycle_id, from_state, to_state, idempotency_key, actor, created_at)
                 VALUES ('org-b', ?1, 'plan', 'delegated', 'k1', 'intruder', 'x')",
                [&i2],
            )?;
            tx.execute(
                "INSERT INTO autonomous_cycle_usage
                     (org_id, cycle_id, usage_run_id, usage_id, actor, payload, created_at)
                 VALUES ('org-b', ?1, 'run-1', 'u1', 'intruder', ?2, 'x')",
                [&i2, &same_payload],
            )?;
            // An organization-B cycle bound to the default organization's task.
            tx.execute(
                "INSERT INTO autonomous_cycles (org_id, id, task_id, state, pr_url, max_time_s, max_tokens,
                     max_retries, max_cost_cents, created_by, created_at, updated_at)
                 VALUES ('org-b', 'b-bound', ?1, 'pr', 'abc1234', 60, 100, 3, 50, 'builder-1', 'x', 'x')",
                [task],
            )?;
            Ok(())
        })
        .unwrap();

    let got = h.ok(&me, "get", json!({ "cycle_id": id })).await;
    assert_eq!(got["transitions"], json!([]), "{got}");
    // The intruder's transition, under the same idempotency key and target,
    // is never replayed as this cycle's result. (The hub-global key then
    // refuses the insert: the parent trigger is what keeps such a row out.)
    let t = h.go(&me, &id, "delegated", "k1").await;
    assert!(!matches!(&t, Ok(v) if v["idempotent"] == true), "replayed another organization's row: {t:?}");
    assert_eq!(h.go(&me, &id, "delegated", "k2").await.unwrap()["idempotent"], false);
    // Likewise the intruder's usage record, with this very payload, is
    // never replayed as this cycle's recorded usage.
    let usage = |usage_id: &str| json!({ "cycle_id": id, "agent": "builder-1", "tokens": 5, "usage_run_id": "run-1", "usage_id": usage_id });
    let u = h.manage(&me, "record_usage", usage("u1")).await;
    assert!(!matches!(&u, Ok(v) if v["replayed"] == true), "replayed another organization's usage: {u:?}");
    let u = h.ok(&me, "record_usage", usage("u3")).await;
    assert_eq!((u["cycle"]["used_tokens"].as_i64(), u.get("replayed")), (Some(5), None), "{u}");
    // The default organization's get_for_task ignores organization B's cycle,
    // and organization B's cycle cannot record attempt usage on the task.
    let found = h.ok(&me, "get_for_task", json!({ "task_id": task })).await;
    assert_eq!(found["cycle"]["id"], id.as_str(), "{found}");
    let e = h
        .manage(
            &agent(ORG_B),
            "record_usage",
            json!({ "cycle_id": "b-bound", "agent": "builder-1", "tokens": 1,
                                                       "usage_run_id": "run-1", "usage_id": "u2" }),
        )
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "not_owner", "{e}");
    let v = h
        .call(&agent(ORG_B), "autonomous_cycle_green_path_eligibility", json!({ "cycle_id": "b-bound" }))
        .await
        .unwrap();
    assert_eq!(v["eligible"], false, "{v}");
    assert!(v["reasons"].to_string().contains("no git worktree found for this task"), "{v}");
}

//! `goals`, `task_goal_links`, `work_proposals` and `work_proposal_items`
//! are tenant data (`docs/organization.md`, Scoping per subsystem):
//! `organization.v1.tools.goals` and `organization.v1.tools.proposals` give
//! them `org_id` and the organization triggers; `goals.v2.org_scope` moves
//! each link to its task's organization and `governance.v4.proposals_org_scope`
//! each item to its proposal's, add the indexes led by `org_id` and keep a
//! goal's parent, a link's task and goal, and an item's proposal and task
//! inside one organization. No key needed a rebuild: a goal id is a hub-global
//! AUTOINCREMENT id and a proposal id is hub-generated.
//!
//! A second organization is created at the storage level, as no tool creates
//! one yet, and its callers are built by hand. Organization-B rows are
//! written through the tools with an organization-B caller; only the legacy
//! rows of the upgrade test, an approval `authz` does not yet admit, and the
//! defence-in-depth rows are seeded by SQL.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 4] = [
    "organization.v1.tools.goals",
    "goals.v2.org_scope",
    "organization.v1.tools.proposals",
    "governance.v4.proposals_org_scope",
];
const TABLES: [&str; 5] = ["goals", "task_goal_links", "work_proposals", "work_proposal_items", "tasks"];
/// A goal id and a proposal id no row has, to compare another
/// organization's answers with.
const ABSENT: i64 = 987_654;
const ABSENT_WP: &str = "wp_00000000abcd";

/// Organization-B text that must never reach the default organization's
/// ledger, in a payload or as an originator.
const B_GOAL: &str = "Falcon acquisition goal";
const B_GOAL_EDIT: &str = "Falcon acquisition revised";
const B_STATEMENT: &str = "Close the Falcon deal by spring";
const B_CLOSE: &str = "Falcon closed out quietly";
const B_REOPEN: &str = "Falcon back on the table";
const B_AGENT: &str = "kestrel-nightshift";
const B_PROPOSAL: &str = "Osprey diligence batch";
const B_ITEM: &str = "Osprey counsel memo";
const B_NOTES: &str = "Draft the Osprey counsel memo";
const B_WITHDRAW: &str = "Osprey parked pending counsel";

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

fn agent(org: &str) -> Caller {
    agent_named("builder-1", org)
}

/// The configured human identity, in organization `org`.
fn human(org: &str) -> Caller {
    Caller {
        kind: ActorKind::Human,
        profile: Profile::Operator,
        enforce_profile: false,
        ..agent_named("operator", org)
    }
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

/// `got` reads exactly as `missing` does, once each names the same id.
fn same_as_missing(got: &Result<Value, UaError>, missing: &Result<Value, UaError>, id: &str, absent: &str) {
    let (Err(e), Err(m)) = (got, missing) else {
        panic!("both must fail: {got:?} / {missing:?}");
    };
    assert_eq!(e.code(), m.code(), "{e} / {m}");
    assert_eq!(
        e.to_string().replace(id, "ID"),
        m.to_string().replace(absent, "ID"),
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
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path());
        cfg.human_identities = vec!["operator".into()];
        let hub = Hub::in_memory(cfg).unwrap();
        add_org(hub.db(), ORG_B);
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

    async fn goal(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "goal_manage", json!({ "action": action, "params": params })).await
    }

    async fn goal_ok(&self, who: &Caller, action: &str, params: Value) -> Value {
        match self.goal(who, action, params.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{}: goal {action}({params}) failed: {e:?}", who.org_id),
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

    async fn task(&self, who: &Caller, title: &str, notes: &str) -> i64 {
        self.ok(who, "task_add", json!({ "title": title, "notes": notes, "project": "web" })).await["id"]
            .as_i64()
            .unwrap()
    }

    async fn add_goal(&self, who: &Caller, title: &str, parent: Option<i64>) -> i64 {
        let mut p = json!({ "title": title, "project": "web" });
        if let Some(pid) = parent {
            p["parent_goal_id"] = json!(pid);
        }
        self.goal_ok(who, "add", p).await["goal"]["id"].as_i64().unwrap()
    }

    /// `who` files a one-item proposal; returns (proposal id, item digest).
    async fn file(&self, who: &Caller, title: &str, item: &str) -> (String, String) {
        let v = self
            .coord_ok(who, "work_proposal_file", json!({ "title": title, "items": [{ "title": item }] }))
            .await;
        (
            v["proposal"]["id"].as_str().unwrap().to_string(),
            v["proposal"]["items"][0]["contract_digest"].as_str().unwrap().to_string(),
        )
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

    /// Every row of the four tables and the task queue, as text: a write
    /// that changes nothing leaves it identical.
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

fn goal_ids(v: &Value) -> Vec<i64> {
    v["goals"].as_array().unwrap().iter().map(|g| g["id"].as_i64().unwrap()).collect()
}

fn proposal_ids(v: &Value) -> Vec<String> {
    v["proposals"].as_array().unwrap().iter().map(|p| p["id"].as_str().unwrap().to_string()).collect()
}

/// The contract block an approval writes into its task's notes, for a
/// one-item proposal filed without notes or scope.
fn contract_notes(pid: &str, digest: &str) -> String {
    format!(
        "[proposal: {pid}#0]\n[contract: {digest}]\n[scope: {{\"files\":[],\"repo\":null}}]\n\
         [reporting: final_only]\n[end contract]"
    )
}

// --- schema ------------------------------------------------------------------------------------

/// Goals and proposals written before the parts land in the default
/// organization; a link moves to its task's organization (and is dropped
/// when its goal is then in another organization), an item to its
/// proposal's.
#[test]
fn a_legacy_database_upgrades_goals_and_proposals_into_their_organizations() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.human_identities = vec!["operator".into()];
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        add_org(&db, ORG_B);
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO tasks (id, org_id, title, project, created_at, updated_at) VALUES
                     (1, 'default', 'Legacy default', 'web', 'x', 'x'), (2, 'org-b', 'Legacy b', 'web', 'x', 'x');
                 INSERT INTO goals (id, title, project, created_at, updated_at) VALUES
                     (1, 'Root', 'web', 'x', 'x');
                 INSERT INTO goals (id, title, project, parent_goal_id, created_at, updated_at) VALUES
                     (2, 'Child', 'web', 1, 'x', 'x');
                 INSERT INTO task_goal_links (task_id, goal_id, linked_at) VALUES (1, 2, 'x'), (2, 1, 'x');
                 INSERT INTO work_proposals (id, title, proposer, created_at, updated_at) VALUES
                     ('wp_0123456789ab', 'Legacy batch', 'lead-1', 'x', 'x');
                 INSERT INTO work_proposal_items (proposal_id, idx, title, filed_digest, contract_digest, status,
                     task_id) VALUES ('wp_0123456789ab', 0, 'One', 'd', 'd', 'approved', 1),
                                     ('wp_0123456789ab', 1, 'Two', 'e', 'e', 'pending', NULL);",
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
                let orgs = |sql: &str| -> Vec<String> {
                    c.prepare(sql)
                        .unwrap()
                        .query_map([], |r| r.get(0))
                        .unwrap()
                        .collect::<Result<_, _>>()
                        .unwrap()
                };
                assert_eq!(orgs("SELECT org_id FROM goals ORDER BY id"), [DEFAULT_ORG, DEFAULT_ORG]);
                // Task 2 is organization B's: its link to a default goal is
                // dropped, never moved into organization B with a foreign goal.
                assert_eq!(
                    orgs("SELECT org_id || ':' || task_id FROM task_goal_links ORDER BY task_id"),
                    ["default:1"]
                );
                assert_eq!(orgs("SELECT org_id FROM work_proposals"), [DEFAULT_ORG]);
                assert_eq!(
                    orgs("SELECT org_id FROM work_proposal_items ORDER BY idx"),
                    [DEFAULT_ORG, DEFAULT_ORG]
                );
                for t in ["goals", "task_goal_links", "work_proposals", "work_proposal_items"] {
                    let notnull: i64 = c.query_row(
                        &format!("SELECT \"notnull\" FROM pragma_table_info('{t}') WHERE name = 'org_id'"),
                        [],
                        |r| r.get(0),
                    )?;
                    assert_eq!(notnull, 1, "{t}");
                    let triggers = names(c, "trigger", t);
                    for want in [format!("{t}_org_exists"), format!("{t}_org_immutable")] {
                        assert!(triggers.contains(&want), "{t}: {triggers:?}");
                    }
                }
                for (t, want) in [
                    ("goals", ["goals_org_parent", "goals_org_parent_update"]),
                    ("task_goal_links", ["task_goal_links_org_parent", "task_goal_links_org_parent_update"]),
                    (
                        "work_proposal_items",
                        ["work_proposal_items_org_parent", "work_proposal_items_org_parent_update"],
                    ),
                ] {
                    let triggers = names(c, "trigger", t);
                    for w in want {
                        assert!(triggers.contains(&w.to_string()), "{t}: {triggers:?}");
                    }
                }
                for (t, want) in [
                    ("goals", "idx_goals_org_project"),
                    ("task_goal_links", "idx_task_goal_links_org_goal"),
                    ("work_proposals", "idx_work_proposals_org_status"),
                    ("work_proposal_items", "idx_work_proposal_items_org_task"),
                ] {
                    assert!(names(c, "index", t).contains(&want.to_string()), "{t}");
                }
                // The recreated immutability triggers are the generated ones.
                for t in ["task_goal_links", "work_proposal_items"] {
                    let sql: String = c.query_row(
                        &format!("SELECT sql FROM sqlite_master WHERE name = '{t}_org_immutable'"),
                        [],
                        |r| r.get(0),
                    )?;
                    assert_eq!(
                        sql,
                        format!(
                            "CREATE TRIGGER {t}_org_immutable BEFORE UPDATE OF org_id ON {t} \
                             WHEN OLD.org_id IS NOT NULL AND NEW.org_id IS NOT OLD.org_id \
                             BEGIN SELECT RAISE(ABORT, 'org_id cannot change'); END"
                        )
                    );
                }
                Ok(())
            })
            .unwrap();
    }

    let hub = Hub::open(cfg).unwrap();
    for sql in [
        "UPDATE goals SET org_id = 'org-b' WHERE id = 1",
        "UPDATE task_goal_links SET org_id = 'org-b' WHERE task_id = 1",
        "UPDATE work_proposals SET org_id = 'org-b'",
        "UPDATE work_proposal_items SET org_id = 'org-b'",
    ] {
        let e = hub.db().write(|tx| Ok(tx.execute_batch(sql)?)).unwrap_err();
        assert!(e.to_string().contains("org_id cannot change"), "{sql}: {e}");
    }

    // The legacy rows answer through the tools in the default organization
    // only, in the shape they had.
    let reg = builtin_registry();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let call = |who: Caller, tool: &'static str, args: Value| {
            let (reg, hub) = (&reg, &hub);
            async move { reg.call(hub, &who, tool, args).await.unwrap() }
        };
        let list = json!({ "action": "list", "params": {} });
        let v = call(agent(DEFAULT_ORG), "goal_manage", list.clone()).await;
        assert_eq!(goal_ids(&v), [1, 2], "{v}");
        assert!(v["goals"][0].get("org_id").is_none(), "a reply keeps its shape: {v}");
        let v = call(agent(ORG_B), "goal_manage", list).await;
        assert_eq!(goal_ids(&v), Vec::<i64>::new(), "{v}");
        let chain = call(
            agent(DEFAULT_ORG),
            "goal_manage",
            json!({ "action": "ancestry", "params": { "task_id": 1 } }),
        )
        .await;
        assert_eq!(chain["goal_id"], 2, "{chain}");
        let chain =
            call(agent(ORG_B), "goal_manage", json!({ "action": "ancestry", "params": { "task_id": 2 } }))
                .await;
        assert_eq!(chain["goal_id"], Value::Null, "{chain}");
        let list = json!({ "action": "work_proposal_list", "params": {} });
        let v = call(agent(DEFAULT_ORG), "coordination_manage", list.clone()).await;
        assert_eq!(proposal_ids(&v), ["wp_0123456789ab"], "{v}");
        assert!(v["proposals"][0].get("org_id").is_none(), "{v}");
        let v = call(agent(ORG_B), "coordination_manage", list).await;
        assert_eq!(proposal_ids(&v), Vec::<String>::new(), "{v}");
    });
}

#[test]
fn the_triggers_refuse_every_cross_organization_reference() {
    let h = H::new();
    h.sql(
        "INSERT INTO tasks (id, org_id, title, project, created_at, updated_at) VALUES
             (10, 'default', 'A', 'web', 'x', 'x'), (20, 'org-b', 'B', 'web', 'x', 'x'),
             (21, 'org-b', 'B2', 'web', 'x', 'x');
         INSERT INTO goals (id, org_id, title, project, created_at, updated_at) VALUES
             (1, 'default', 'GA', 'web', 'x', 'x'), (2, 'org-b', 'GB', 'web', 'x', 'x');
         INSERT INTO task_goal_links (org_id, task_id, goal_id, linked_at) VALUES ('org-b', 20, 2, 'x');
         INSERT INTO work_proposals (id, org_id, title, proposer, created_at, updated_at) VALUES
             ('wp_aaaaaaaaaaaa', 'default', 'PA', 'a', 'x', 'x'), ('wp_bbbbbbbbbbbb', 'org-b', 'PB', 'b', 'x', 'x');
         INSERT INTO work_proposal_items (org_id, proposal_id, idx, title, filed_digest, contract_digest, task_id)
             VALUES ('org-b', 'wp_bbbbbbbbbbbb', 0, 'I', 'd', 'd', 20);",
    )
    .unwrap();
    let refused = |sql: &str| {
        let e = h.sql(sql).unwrap_err();
        assert!(e.contains("another organization"), "{sql}: {e}");
    };
    // A goal's parent.
    refused(
        "INSERT INTO goals (org_id, title, project, parent_goal_id, created_at, updated_at)
         VALUES ('org-b', 'X', 'web', 1, 'x', 'x')",
    );
    refused("UPDATE goals SET parent_goal_id = 1 WHERE id = 2");
    // A link's task, and a link's goal.
    refused("INSERT INTO task_goal_links (org_id, task_id, goal_id, linked_at) VALUES ('org-b', 10, 2, 'x')");
    refused("INSERT INTO task_goal_links (org_id, task_id, goal_id, linked_at) VALUES ('org-b', 21, 1, 'x')");
    refused("UPDATE task_goal_links SET goal_id = 1 WHERE task_id = 20");
    refused("UPDATE task_goal_links SET task_id = 10 WHERE task_id = 20");
    // An item's proposal, and an item's task.
    refused(
        "INSERT INTO work_proposal_items (org_id, proposal_id, idx, title, filed_digest, contract_digest)
         VALUES ('org-b', 'wp_aaaaaaaaaaaa', 0, 'I', 'd', 'd')",
    );
    refused(
        "INSERT INTO work_proposal_items (org_id, proposal_id, idx, title, filed_digest, contract_digest, task_id)
         VALUES ('org-b', 'wp_bbbbbbbbbbbb', 1, 'I', 'd', 'd', 10)",
    );
    refused("UPDATE work_proposal_items SET task_id = 10 WHERE proposal_id = 'wp_bbbbbbbbbbbb'");
    refused(
        "UPDATE work_proposal_items SET proposal_id = 'wp_aaaaaaaaaaaa' WHERE proposal_id = 'wp_bbbbbbbbbbbb'",
    );
    // The same rows inside one organization are accepted.
    h.sql(
        "INSERT INTO goals (id, org_id, title, project, parent_goal_id, created_at, updated_at)
             VALUES (3, 'org-b', 'GB child', 'web', 2, 'x', 'x');
         INSERT INTO task_goal_links (org_id, task_id, goal_id, linked_at) VALUES ('org-b', 21, 3, 'x');
         UPDATE work_proposal_items SET task_id = 21 WHERE proposal_id = 'wp_bbbbbbbbbbbb';",
    )
    .unwrap();
    // An unknown organization is refused by the generated trigger.
    for sql in [
        "INSERT INTO goals (org_id, title, created_at, updated_at) VALUES ('missing-org', 'X', 'x', 'x')",
        "INSERT INTO work_proposals (id, org_id, title, proposer, created_at, updated_at)
         VALUES ('wp_cccccccccccc', 'missing-org', 'P', 'p', 'x', 'x')",
    ] {
        let e = h.sql(sql).unwrap_err();
        assert!(e.contains("unknown organization"), "{sql}: {e}");
    }
}

// --- isolation through the tools ---------------------------------------------------------------

struct Side {
    who: Caller,
    root: i64,
    child: i64,
    task: i64,
    proposal: String,
}

async fn side(h: &H, org: &str) -> Side {
    let who = agent(org);
    let root = h.add_goal(&who, &format!("{org} root"), None).await;
    let child = h.add_goal(&who, &format!("{org} child"), Some(root)).await;
    let task = h.task(&who, &format!("{org} task"), "").await;
    h.goal_ok(&who, "link", json!({ "task_id": task, "goal_id": child })).await;
    let (proposal, _) = h.file(&who, &format!("{org} batch"), &format!("{org} item")).await;
    Side { who, root, child, task, proposal }
}

#[tokio::test]
async fn each_organization_sees_only_its_own_goals_and_proposals() {
    let h = H::new();
    let a = side(&h, DEFAULT_ORG).await;
    let b = side(&h, ORG_B).await;
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM goals WHERE org_id = 'org-b' AND id IN ({}, {})",
            b.root, b.child
        )),
        2
    );
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM task_goal_links WHERE org_id = 'org-b' AND task_id = {}",
            b.task
        )),
        1
    );
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM work_proposal_items WHERE org_id = 'org-b' AND proposal_id = '{}'",
            b.proposal
        )),
        1
    );
    let absent = ABSENT.to_string();

    for (me, them) in [(&a, &b), (&b, &a)] {
        let who = &me.who;
        let org = &who.org_id;
        // Reads.
        let v = h.goal_ok(who, "list", json!({})).await;
        assert_eq!(goal_ids(&v), [me.root, me.child], "{org}: {v}");
        assert!(v["goals"][0].get("org_id").is_none(), "{v}");
        let v = h.goal_ok(who, "tree", json!({ "project": "web" })).await;
        assert_eq!(v["tree"].as_array().unwrap().len(), 1, "{org}: {v}");
        assert_eq!(v["tree"][0]["id"], me.root, "{org}: {v}");
        let v = h.goal_ok(who, "get", json!({ "goal_id": me.child })).await;
        assert_eq!(v["ancestry"].as_array().unwrap().len(), 2, "{org}: {v}");
        for id in [them.root, them.child] {
            let got = h.goal(who, "get", json!({ "goal_id": id })).await;
            same_as_missing(
                &got,
                &h.goal(who, "get", json!({ "goal_id": ABSENT })).await,
                &id.to_string(),
                &absent,
            );
            let got =
                h.call(who, "platform_object_get", json!({ "kind": "goal", "id": id.to_string() })).await;
            let missing = h.call(who, "platform_object_get", json!({ "kind": "goal", "id": absent })).await;
            same_as_missing(&got, &missing, &id.to_string(), &absent);
        }
        let own =
            h.ok(who, "platform_object_get", json!({ "kind": "goal", "id": me.root.to_string() })).await;
        assert!(own["goal"].get("org_id").is_none() && own["goal"]["id"] == me.root, "{own}");
        let v = h.goal_ok(who, "ancestry", json!({ "task_id": me.task })).await;
        assert_eq!(v["goal_id"], me.child, "{org}: {v}");
        let chain: Vec<i64> =
            v["chain"].as_array().unwrap().iter().map(|g| g["id"].as_i64().unwrap()).collect();
        assert_eq!(chain, [me.root, me.child], "{org}");
        let e = h.goal(who, "ancestry", json!({ "task_id": them.task })).await.unwrap_err();
        assert_eq!(e.code(), "not_found", "{e}");
        let v = h.coord_ok(who, "work_proposal_list", json!({})).await;
        assert_eq!(proposal_ids(&v), std::slice::from_ref(&me.proposal), "{org}: {v}");
        let v = h.coord_ok(who, "work_proposal_get", json!({ "proposal_id": me.proposal })).await;
        assert!(
            v["proposal"].get("org_id").is_none() && v["proposal"]["items"].as_array().unwrap().len() == 1
        );
        let got = h.coord(who, "work_proposal_get", json!({ "proposal_id": them.proposal })).await;
        let missing = h.coord(who, "work_proposal_get", json!({ "proposal_id": ABSENT_WP })).await;
        same_as_missing(&got, &missing, &them.proposal, ABSENT_WP);

        // Writes on the other organization's goals and proposals answer as
        // for a missing one and change nothing.
        let before = (h.snapshot(), h.events());
        let r = them.root;
        for (action, id, params, absent_params) in [
            ("edit", r, json!({ "goal_id": r, "title": "x" }), json!({ "goal_id": ABSENT, "title": "x" })),
            ("close", r, json!({ "goal_id": r }), json!({ "goal_id": ABSENT })),
            ("reopen", r, json!({ "goal_id": r }), json!({ "goal_id": ABSENT })),
            (
                "link",
                r,
                json!({ "task_id": me.task, "goal_id": r }),
                json!({ "task_id": me.task, "goal_id": ABSENT }),
            ),
            (
                "unlink",
                them.child,
                json!({ "task_id": me.task, "goal_id": them.child }),
                json!({ "task_id": me.task, "goal_id": ABSENT }),
            ),
            (
                "add",
                r,
                json!({ "title": "x", "project": "web", "parent_goal_id": r }),
                json!({ "title": "x", "project": "web", "parent_goal_id": ABSENT }),
            ),
        ] {
            let got = h.goal(who, action, params).await;
            let missing = h.goal(who, action, absent_params).await;
            same_as_missing(&got, &missing, &id.to_string(), &absent);
        }
        // A task of the other organization is not this caller's to link.
        let e = h.goal(who, "link", json!({ "task_id": them.task, "goal_id": me.child })).await.unwrap_err();
        assert_eq!(e.code(), "not_found", "{e}");
        for (action, params) in [
            ("work_proposal_withdraw", json!({ "proposal_id": them.proposal })),
            ("work_proposal_get", json!({ "proposal_id": them.proposal })),
        ] {
            let got = h.coord(who, action, params).await;
            let missing = h.coord(who, action, json!({ "proposal_id": ABSENT_WP })).await;
            same_as_missing(&got, &missing, &them.proposal, ABSENT_WP);
        }
        assert_eq!((h.snapshot(), h.events()), before, "{org}: another organization's rows were changed");
    }

    // The default organization's human decides only its own organization's
    // proposals: organization B's answers as a missing one.
    let op = human(DEFAULT_ORG);
    let before = (h.snapshot(), h.events());
    let decide = |pid: &str| json!({ "proposal_id": pid, "decisions": [{ "index": 0, "approve": true }] });
    let got = h.coord(&op, "work_proposal_decide", decide(&b.proposal)).await;
    let missing = h.coord(&op, "work_proposal_decide", decide(ABSENT_WP)).await;
    same_as_missing(&got, &missing, &b.proposal, ABSENT_WP);
    assert_eq!((h.snapshot(), h.events()), before);

    // Recovery settles only the caller's organization's stuck items.
    h.sql(&format!(
        "UPDATE work_proposal_items SET status = 'approving', approving_by = 'x', approving_at = '2020-01-01T00:00:00+00:00'
         WHERE proposal_id IN ('{}', '{}')",
        a.proposal, b.proposal
    ))
    .unwrap();
    let v = h.coord_ok(&b.who, "work_proposal_recover", json!({})).await;
    assert_eq!(v["rolled_back"], json!([{ "proposal_id": b.proposal, "index": 0 }]), "{v}");
    assert_eq!(
        h.text(&format!("SELECT status FROM work_proposal_items WHERE proposal_id = '{}'", a.proposal))
            .unwrap(),
        "approving",
        "organization B's recovery left the default organization's item alone"
    );
    let v = h.coord_ok(&a.who, "work_proposal_recover", json!({})).await;
    assert_eq!(v["rolled_back"], json!([{ "proposal_id": a.proposal, "index": 0 }]), "{v}");

    // Each organization withdraws its own.
    for s in [&a, &b] {
        let v = h.coord_ok(&s.who, "work_proposal_withdraw", json!({ "proposal_id": s.proposal })).await;
        assert_eq!(v["proposal"]["status"], "withdrawn", "{v}");
    }
}

/// A proposal is decided in its own organization, and an approved item's
/// task is created there. `ua_org::authz` admits only the default
/// organization today, so organization B's human is refused (`org_mismatch`)
/// and nothing is written; the contract check of an organization-B task
/// then reads organization B's items only.
#[tokio::test]
async fn an_approval_creates_its_task_in_the_proposals_organization() {
    let h = H::new();
    let (pa, da) = h.file(&agent(DEFAULT_ORG), "A batch", "A item").await;
    let (pb, db) = h.file(&agent(ORG_B), "B batch", "B item").await;
    let decide = |pid: &str| json!({ "proposal_id": pid, "decisions": [{ "index": 0, "approve": true }] });

    // Organization B cannot decide yet: authority, not `org_unsupported`.
    let before = (h.snapshot(), h.events());
    let e = h.coord(&human(ORG_B), "work_proposal_decide", decide(&pb)).await.unwrap_err();
    assert_eq!(reason(&e), "org_mismatch", "{e}");
    let e = h.coord(&agent(ORG_B), "work_proposal_decide", decide(&pb)).await.unwrap_err();
    assert_eq!(reason(&e), "human_required", "{e}");
    assert_eq!((h.snapshot(), h.events()), before, "a refused decision writes nothing");

    // The default organization's approval creates a default task.
    let v = h.coord_ok(&human(DEFAULT_ORG), "work_proposal_decide", decide(&pa)).await;
    let ta = v["proposal"]["items"][0]["task_id"].as_i64().unwrap();
    assert_eq!(h.text(&format!("SELECT org_id FROM tasks WHERE id = {ta}")).unwrap(), DEFAULT_ORG);
    assert_eq!(
        h.text(&format!("SELECT notes FROM tasks WHERE id = {ta}")).unwrap(),
        contract_notes(&pa, &da)
    );

    // Organization B's item approved the way an approval would: its task in
    // organization B, carrying the contract block. B's claim passes the
    // contract check against B's own item.
    let tb = h.task(&agent(ORG_B), "B item", &contract_notes(&pb, &db)).await;
    h.sql(&format!(
        "UPDATE work_proposal_items SET status = 'approved', task_id = {tb} WHERE proposal_id = '{pb}';
         UPDATE work_proposals SET status = 'approved' WHERE id = '{pb}';"
    ))
    .unwrap();
    let claimed = h.ok(&agent(ORG_B), "task_claim", json!({ "id": tb })).await;
    assert_eq!(claimed["claimed"], true, "{claimed}");

    // A task naming the other organization's proposal is refused as naming
    // an unknown item, in both directions.
    for (who, pid, digest) in [(agent(DEFAULT_ORG), &pb, &db), (agent(ORG_B), &pa, &da)] {
        let title = if who.org_id == DEFAULT_ORG { "B item" } else { "A item" };
        let t = h.task(&who, title, &contract_notes(pid, digest)).await;
        let e = h.err(&who, "task_claim", json!({ "id": t })).await;
        assert_eq!(reason(&e), "contract_mismatch", "{e}");
        assert!(e.to_string().contains("unknown work proposal item"), "{e}");
    }
    // The default task still claims against its own item.
    h.ok(&agent(DEFAULT_ORG), "task_claim", json!({ "id": ta })).await;

    // An organization-B task whose notes lost the markers stays bound to its
    // organization-B item.
    let lost = h.task(&agent(ORG_B), "B lost", "").await;
    h.sql(&format!(
        "INSERT INTO work_proposal_items (org_id, proposal_id, idx, title, filed_digest, contract_digest, status,
             task_id) VALUES ('org-b', '{pb}', 1, 'B lost', 'd', 'd', 'approved', {lost})"
    ))
    .unwrap();
    let e = h.err(&agent(ORG_B), "task_claim", json!({ "id": lost })).await;
    assert!(e.to_string().contains("lost the contract"), "{e}");

    // An approval left half-done in organization B recovers forward to the
    // organization-B task that carries its contract.
    let (pb2, db2) = h.file(&agent(ORG_B), "B batch 2", "B item 2").await;
    // A default-organization task copying the block, older than B's, is not
    // B's to recover to.
    h.task(&agent(DEFAULT_ORG), "B item 2", &contract_notes(&pb2, &db2)).await;
    let tb2 = h.task(&agent(ORG_B), "B item 2", &contract_notes(&pb2, &db2)).await;
    h.sql(&format!(
        "UPDATE work_proposal_items SET status = 'approving', approving_by = 'operator',
         approving_at = '2020-01-01T00:00:00+00:00' WHERE proposal_id = '{pb2}'"
    ))
    .unwrap();
    let v = h.coord_ok(&agent(ORG_B), "work_proposal_recover", json!({})).await;
    assert_eq!(v["recovered_forward"], json!([{ "proposal_id": pb2, "index": 0, "task_id": tb2 }]), "{v}");
}

/// Defence in depth: with the reference triggers dropped and rows seeded
/// across organizations, the lookups still never follow a link or an item
/// into another organization.
#[tokio::test]
async fn the_lookups_never_follow_a_row_into_another_organization() {
    let h = H::new();
    let b = agent(ORG_B);
    let ga = h.add_goal(&agent(DEFAULT_ORG), "A goal", None).await;
    let gb = h.add_goal(&b, "B goal", None).await;
    let tb = h.task(&b, "B task", "").await;
    h.sql(&format!(
        "DROP TRIGGER task_goal_links_org_parent;
         DROP TRIGGER work_proposal_items_org_parent;
         INSERT INTO task_goal_links (org_id, task_id, goal_id, linked_at) VALUES ('default', {tb}, {ga}, 'x');
         INSERT INTO work_proposals (id, org_id, title, proposer, created_at, updated_at)
             VALUES ('wp_aaaaaaaaaaaa', 'default', 'PA', 'a', 'x', 'x');
         INSERT INTO work_proposal_items (org_id, proposal_id, idx, title, filed_digest, contract_digest, status,
             task_id) VALUES ('default', 'wp_aaaaaaaaaaaa', 0, 'I', 'd', 'd', 'approved', {tb});"
    ))
    .unwrap();
    // The default organization's link to B's task is not B's: no chain, no
    // link to remove, and no goal project holding the task in place.
    let v = h.goal_ok(&b, "ancestry", json!({ "task_id": tb })).await;
    assert_eq!(v["goal_id"], Value::Null, "{v}");
    let e = h.goal(&b, "unlink", json!({ "task_id": tb, "goal_id": ga })).await.unwrap_err();
    assert_eq!(e.code(), "not_found", "{e}");
    let e = h.goal(&b, "unlink", json!({ "task_id": tb, "goal_id": gb })).await.unwrap_err();
    assert!(e.to_string().contains("serves no goal"), "{e}");
    h.ok(&b, "task_update", json!({ "id": tb, "project": "other" })).await;
    // B's own link does hold it (goal B is in `web`).
    let tb2 = h.task(&b, "B task 2", "").await;
    h.goal_ok(&b, "link", json!({ "task_id": tb2, "goal_id": gb })).await;
    let e = h.err(&b, "task_update", json!({ "id": tb2, "project": "other" })).await;
    assert!(e.to_string().contains("serves a goal"), "{e}");
    // The default organization's approved item does not bind B's task.
    let claimed = h.ok(&b, "task_claim", json!({ "id": tb })).await;
    assert_eq!(claimed["claimed"], true, "{claimed}");

    // A default-organization item under B's proposal id is not B's item:
    // B reads and withdraws its own item only.
    let (pb, _) = h.file(&b, "B batch", "B item").await;
    h.sql(&format!(
        "INSERT INTO work_proposal_items (org_id, proposal_id, idx, title, filed_digest, contract_digest)
         VALUES ('default', '{pb}', 5, 'stray', 'd', 'd')"
    ))
    .unwrap();
    let v = h.coord_ok(&b, "work_proposal_get", json!({ "proposal_id": pb })).await;
    assert_eq!(v["proposal"]["items"].as_array().unwrap().len(), 1, "{v}");
    h.coord_ok(&b, "work_proposal_withdraw", json!({ "proposal_id": pb })).await;
    assert_eq!(
        h.text(&format!("SELECT status FROM work_proposal_items WHERE proposal_id = '{pb}' AND idx = 5"))
            .unwrap(),
        "pending"
    );

    // The contract check reads the task organization's item and proposal
    // only. An organization-B item filed under the default organization's
    // proposal id, and a default item filed under B's, each with a contract
    // the task would match, are not the default task's contract.
    let a = agent(DEFAULT_ORG);
    let (pa, _) = h.file(&a, "A batch", "A item").await;
    let (pc, dc) = h.file(&b, "C batch", "C item").await;
    let block = |pid: &str| contract_notes(pid, &dc).replace("#0]", "#7]");
    for (item_org, pid) in [(ORG_B, &pa), (DEFAULT_ORG, &pc)] {
        h.sql(&format!(
            "INSERT INTO work_proposal_items (org_id, proposal_id, idx, title, scope_json, filed_digest,
                 contract_digest, status) VALUES ('{item_org}', '{pid}', 7, 'C item', '{{\"files\":[],\"repo\":null}}',
                 '{dc}', '{dc}', 'approved')"
        ))
        .unwrap();
        let t = h.task(&a, "C item", &block(pid)).await;
        let e = h.err(&a, "task_claim", json!({ "id": t })).await;
        assert!(e.to_string().contains("unknown work proposal item"), "{item_org}: {e}");
    }
}

// --- refusals ----------------------------------------------------------------------------------

#[tokio::test]
async fn goal_manage_still_refuses_an_org_id_parameter() {
    let h = H::new();
    let b = agent(ORG_B);
    let before = (h.snapshot(), h.events());
    for (action, params) in [
        ("list", json!({ "org_id": DEFAULT_ORG })),
        ("add", json!({ "title": "x", "org_id": DEFAULT_ORG })),
        ("get", json!({ "goal_id": 1, "org_id": DEFAULT_ORG })),
    ] {
        let e = h.goal(&b, action, params).await.unwrap_err();
        assert_eq!(e.code(), "invalid_argument", "{action}: {e}");
    }
    assert_eq!((h.snapshot(), h.events()), before);
}

#[tokio::test]
async fn an_unknown_organization_is_refused_before_any_write() {
    let h = H::new();
    let ga = h.add_goal(&agent(DEFAULT_ORG), "A goal", None).await;
    let ta = h.task(&agent(DEFAULT_ORG), "A task", "").await;
    let (pa, _) = h.file(&agent(DEFAULT_ORG), "A batch", "A item").await;
    let ghost = agent(UNKNOWN);
    let before = (h.snapshot(), h.events());
    for (action, params) in [
        ("add", json!({ "title": "x" })),
        ("edit", json!({ "goal_id": ga, "title": "x" })),
        ("close", json!({ "goal_id": ga })),
        ("reopen", json!({ "goal_id": ga })),
        ("link", json!({ "task_id": ta, "goal_id": ga })),
        ("unlink", json!({ "task_id": ta, "goal_id": ga })),
    ] {
        let e = h.goal(&ghost, action, params).await.unwrap_err();
        assert_eq!(reason(&e), "unknown_organization", "{action}: {e}");
    }
    for (action, params) in [
        ("work_proposal_file", json!({ "title": "x", "items": [{ "title": "y" }] })),
        ("work_proposal_withdraw", json!({ "proposal_id": pa })),
        ("work_proposal_recover", json!({})),
    ] {
        let e = h.coord(&ghost, action, params).await.unwrap_err();
        assert_eq!(reason(&e), "unknown_organization", "{action}: {e}");
    }
    // Deciding is refused too: the registry refuses the organization before
    // the tool's authority check runs.
    let e = h
        .coord(
            &human(UNKNOWN),
            "work_proposal_decide",
            json!({ "proposal_id": pa, "decisions": [{ "index": 0, "approve": true }] }),
        )
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "unknown_organization", "{e}");
    assert_eq!((h.snapshot(), h.events()), before);
}

// --- the ledger --------------------------------------------------------------------------------

#[tokio::test]
async fn organization_b_text_and_labels_never_reach_the_default_ledger() {
    let h = H::new();
    let b = agent_named(B_AGENT, ORG_B);
    let g = h
        .goal_ok(&b, "add", json!({ "title": B_GOAL, "statement": B_STATEMENT, "project": "web" }))
        .await["goal"]["id"]
        .as_i64()
        .unwrap();
    h.goal_ok(&b, "edit", json!({ "goal_id": g, "title": B_GOAL_EDIT })).await;
    h.goal_ok(&b, "close", json!({ "goal_id": g, "reason": B_CLOSE })).await;
    h.goal_ok(&b, "reopen", json!({ "goal_id": g, "reason": B_REOPEN })).await;
    let t = h.task(&b, "B task", "").await;
    h.goal_ok(&b, "link", json!({ "task_id": t, "goal_id": g })).await;
    h.goal_ok(&b, "unlink", json!({ "task_id": t, "goal_id": g })).await;
    let filed = h
        .coord_ok(
            &b,
            "work_proposal_file",
            json!({ "title": B_PROPOSAL, "items": [{ "title": B_ITEM, "notes": B_NOTES }] }),
        )
        .await;
    let pid = filed["proposal"]["id"].as_str().unwrap().to_string();
    h.coord_ok(&b, "work_proposal_withdraw", json!({ "proposal_id": pid, "reason": B_WITHDRAW })).await;
    h.sql(&format!(
        "UPDATE work_proposal_items SET status = 'approving', approving_by = '{B_AGENT}',
         approving_at = '2020-01-01T00:00:00+00:00' WHERE proposal_id = '{pid}'"
    ))
    .unwrap();
    h.coord_ok(&b, "work_proposal_recover", json!({})).await;

    let rows: Vec<(String, String, Option<String>)> = h
        .hub
        .db()
        .read(|c| {
            Ok(c.prepare("SELECT channel, payload, originator FROM event_log ORDER BY seq")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?)
        })
        .unwrap();
    let ours: Vec<_> = rows
        .iter()
        .filter(|(c, _, _)| c.starts_with("agent.goal.") || c.starts_with("agent.work_proposal."))
        .collect();
    assert!(ours.len() >= 9, "the writes were ledgered: {ours:?}");
    for (channel, payload, originator) in &rows {
        for s in [
            B_GOAL,
            B_GOAL_EDIT,
            B_STATEMENT,
            B_CLOSE,
            B_REOPEN,
            B_AGENT,
            B_PROPOSAL,
            B_ITEM,
            B_NOTES,
            B_WITHDRAW,
        ] {
            assert!(!payload.contains(s), "{s:?} reached a default ledger payload ({channel}): {payload}");
            assert!(!originator.as_deref().unwrap_or_default().contains(s), "{s:?} is an originator");
        }
    }
    for (channel, _, originator) in &ours {
        assert_eq!(originator.as_deref(), Some("system"), "{channel}");
    }
    // Ids and statuses remain.
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM event_log WHERE channel = 'agent.work_proposal.withdrawn' \
             AND json_extract(payload, '$.proposal_id') = '{pid}' AND json_extract(payload, '$.status') = 'withdrawn'"
        )),
        1
    );
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM event_log WHERE channel = 'agent.goal.closed' \
             AND json_extract(payload, '$.goal_id') = {g} AND json_extract(payload, '$.status') = 'achieved'"
        )),
        1
    );

    // The default organization's events keep their text and originator.
    let a = agent_named("lead-1", DEFAULT_ORG);
    let ga = h.add_goal(&a, "A goal", None).await;
    h.goal_ok(&a, "close", json!({ "goal_id": ga, "reason": "A done" })).await;
    let p = h
        .text(&format!(
            "SELECT payload || '|' || originator FROM event_log WHERE channel = 'agent.goal.closed' \
             AND json_extract(payload, '$.goal_id') = {ga}"
        ))
        .unwrap();
    assert!(p.contains("\"reason\":\"A done\"") && p.ends_with("|lead-1"), "{p}");
    let (pa, _) = h.file(&a, "A batch", "A item").await;
    let p = h
        .text(&format!(
            "SELECT payload || '|' || originator FROM event_log WHERE channel = 'agent.work_proposal.filed' \
             AND json_extract(payload, '$.proposal_id') = '{pa}'"
        ))
        .unwrap();
    assert!(p.contains("\"proposer\":\"lead-1\"") && p.ends_with("|lead-1"), "{p}");
}

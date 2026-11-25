//! The node registry, the node work queue and dispatch runs are tenant data
//! (`docs/organization.md`, Scoping per subsystem).
//!
//! - `organization.v1.tools.dispatch` gives `dispatch_runs` and
//!   `dispatch_receipts` their `org_id` and triggers; `dispatch.v4.org_scope`
//!   keeps a run's task and a receipt's run in the row's organization.
//! - `node_queue.v2.tenant_keys` rebuilds `node_dispatch` with a `NOT NULL`
//!   `org_id` and its client launch keys unique per organization;
//!   `organization.v1.tools.nodes` gives the seven node tables their
//!   `org_id` and triggers; `node_queue.v2.org_scope` adds the org-led
//!   indexes and the same-organization reference triggers.
//!
//! The design under test: a node belongs to the organization that
//! registered it; work, claims, commands and follow-ups belong to the
//! organization of the caller who created them and may only target that
//! organization's nodes (another organization's node answers exactly like a
//! missing one); a node token claims and reports only its own
//! organization's work; hub-wide views list the default organization's nodes
//! and count the rest. No upgrade drops or rewrites a row beyond giving it
//! the default organization. A second organization is created at the
//! storage level, as no tool creates one yet, and its callers are built by
//! hand; its approvals are granted by SQL because `ua_org::authz` admits no
//! organization-B human yet. Every value here is fake.

use std::path::Path;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 5] = [
    "organization.v1.tools.dispatch",
    "dispatch.v4.org_scope",
    "node_queue.v2.tenant_keys",
    "organization.v1.tools.nodes",
    "node_queue.v2.org_scope",
];
const TABLES: [&str; 9] = [
    "nodes",
    "node_acceptance",
    "node_claim_ops",
    "node_command",
    "node_command_notice",
    "node_dispatch",
    "node_followups",
    "dispatch_runs",
    "dispatch_receipts",
];

const NODE_A: &str = "node-a";
const ROOT_A: &str = "/srv/work-a";
/// A node name no organization registered, to compare refusals with.
const MISSING_NODE: &str = "node-zz";
/// An item id no organization holds.
const MISSING_ITEM: &str = "nd-0000000000000000";

/// Organization-B values that must never reach the default organization's
/// ledger or another organization's replies.
const NODE_B: &str = "falcon-node-b";
const ROOT_B: &str = "/srv/osprey-root-not-real";
const B_DEVICE: &str = "kestrel-device-not-real";
const B_LEAD: &str = "kestrel-lead-not-real";
const B_PROMPT: &str = "osprey-prompt-not-real";
const B_PROGRESS: &str = "osprey-progress-not-real";
const B_OUTPUT: &str = "osprey-output-not-real";

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().take_while(|p| !PARTS.contains(&p.name)).collect()
}

fn add_org(db: &ua_store::Db, id: &str, status: &str) {
    let (id, status) = (id.to_string(), status.to_string());
    db.write(move |tx| {
        tx.execute(
            "INSERT INTO orgs (id, slug, display_name, status, allowed_profiles, created_at)
             VALUES (?1, ?1, 'Org', ?2, '[\"developer\",\"coordinator\",\"operator\"]', '2026-01-01T00:00:00+00:00')",
            [id, status],
        )?;
        Ok(())
    })
    .unwrap();
}

fn caller(label: &str, kind: ActorKind, org: &str) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some(format!("{label}-s")),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn device_a() -> Caller {
    caller("builder-1", ActorKind::Agent, DEFAULT_ORG)
}

fn lead_a() -> Caller {
    caller("lead-1", ActorKind::Agent, DEFAULT_ORG)
}

fn device_b() -> Caller {
    caller(B_DEVICE, ActorKind::Agent, ORG_B)
}

fn lead_b() -> Caller {
    caller(B_LEAD, ActorKind::Agent, ORG_B)
}

fn human() -> Caller {
    Caller {
        profile: Profile::Operator,
        enforce_profile: false,
        ..caller("operator", ActorKind::Human, DEFAULT_ORG)
    }
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

/// An answer with each of `names` replaced, to compare an answer about one
/// node or item with an answer about another.
fn norm(r: &Result<Value, UaError>, names: &[&str]) -> String {
    let mut s = match r {
        Ok(v) => format!("ok {v}"),
        Err(e) => format!("err {} {} {e}", e.code(), reason(e)),
    };
    for n in names {
        s = s.replace(n, "NAME");
    }
    s
}

/// Another organization's node, item or run must answer exactly like a
/// missing one.
fn same_as_missing(got: &Result<Value, UaError>, missing: &Result<Value, UaError>, names: &[&str]) {
    assert!(got.is_err(), "another organization's row must be refused: {got:?}");
    assert_eq!(
        norm(got, names),
        norm(missing, names),
        "another organization's row must answer as a missing one"
    );
}

fn facts(root: &str) -> Value {
    json!({
        "backends": ["codex", "acp:claude", "command", "acceptance"],
        "worktree_roots": [{ "path": root, "realpath": root, "exists": true }],
        "node_features": ["acp_followups", "session_settings", "acp_session_mcp"],
    })
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

    fn with(tweak: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into()];
        cfg.session_credentials_enabled = true;
        tweak(&mut cfg);
        let hub = Hub::in_memory(cfg).unwrap();
        add_org(hub.db(), ORG_B, "active");
        Self { hub, reg: builtin_registry(), _dir: dir }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{}/{}: {tool}({args}) failed: {e:?}", who.org_id, who.label),
        }
    }

    async fn manage(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "coordination_manage", json!({ "action": action, "params": params })).await
    }

    /// Grant a parked approval by SQL (no organization-B human can yet).
    fn approve(&self, id: i64) {
        self.hub
            .db()
            .write(move |tx| {
                tx.execute(
                    "UPDATE approvals SET status = 'approved', resolved_by = 'operator', resolved_at = ?2, \
                     updated_at = ?2 WHERE id = ?1",
                    rusqlite::params![id, ua_core::time::now()],
                )?;
                Ok(())
            })
            .unwrap();
    }

    /// Park the call, approve it, and retry it.
    async fn gated(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.call(who, tool, args.clone()).await {
            Err(UaError::ApprovalRequired { approval_id, .. }) => self.approve(approval_id),
            other => panic!("{tool}({args}): expected an approval, got {other:?}"),
        }
        self.ok(who, tool, args).await
    }

    async fn register(&self, who: &Caller, node: &str, root: &str) {
        self.ok(who, "node_register", json!({ "node": node, "facts": facts(root) })).await;
    }

    /// Register both organizations' nodes.
    async fn fleet(&self) {
        self.register(&device_a(), NODE_A, ROOT_A).await;
        self.register(&device_b(), NODE_B, ROOT_B).await;
    }

    async fn queue(&self, who: &Caller, node: &str, prompt: &str, extra: Value) -> String {
        let root = if node == NODE_B { ROOT_B } else { ROOT_A };
        let mut args =
            json!({ "node": node, "backend": "codex", "prompt": prompt, "cwd": format!("{root}/repo") });
        for (k, v) in extra.as_object().unwrap() {
            args[k] = v.clone();
        }
        self.gated(who, "node_dispatch", args).await["item_id"].as_str().unwrap().to_string()
    }

    fn count(&self, sql: &str) -> i64 {
        let sql = sql.to_string();
        self.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
    }

    fn text(&self, sql: &str) -> String {
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

    /// Row counts of the nine tables, as text.
    fn counts(&self) -> String {
        TABLES.iter().map(|t| format!("{t}={}", self.count(&format!("SELECT COUNT(*) FROM {t}")))).collect()
    }

    /// Every `event_log` row's channel, originator, dedupe key and payload.
    fn ledger(&self) -> Vec<(String, Option<String>, Option<String>, String)> {
        self.hub
            .db()
            .read(|c| {
                let mut stmt =
                    c.prepare("SELECT channel, originator, dedupe_key, payload FROM event_log ORDER BY seq")?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .unwrap()
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

const LEGACY_ROWS: &str = "
INSERT INTO tasks (id, title, created_at, updated_at) VALUES (1, 'Legacy task', 't0', 't0');
INSERT INTO nodes (node, agent, facts_json, registered_at, last_heartbeat, updated_at)
    VALUES ('legacy-node', 'builder-1', '{}', 't0', 't0', 't0');
INSERT INTO dispatch_runs (run_id, task_id, agent_label, state, actor, evidence_ref, created_at, updated_at)
    VALUES ('run-1-aaaaaaaa', 1, 'builder-1', 'finished', 'lead-1', 'node:legacy-node:nd-0000000000000001', 't0', 't0');
INSERT INTO dispatch_receipts (run_id, fence, task_id, agent_label, state, source, reported_by, receipt_hash, created_at)
    VALUES ('run-1-aaaaaaaa', 1, 1, 'builder-1', 'finished', 'node', 'builder-1', 'fake-hash', 't0');
INSERT INTO node_dispatch (id, node, agent, backend, prompt, cwd, timeout_s, run_id, task_id, status, created_by,
                           created_at, launch_key, updated_at)
    VALUES ('nd-0000000000000001', 'legacy-node', 'builder-1', 'codex', 'legacy prompt', '/srv/work', 60,
            'run-1-aaaaaaaa', 1, 'finished', 'lead-1', 't1', 'legacy-key-0001', 't1'),
           ('nd-0000000000000002', 'legacy-node', 'builder-1', 'command', 'command: ls', '/srv/work', 60,
            NULL, NULL, 'queued', 'lead-1', 't2', NULL, 't2');
INSERT INTO node_claim_ops (node, op_id, identity, issued_at, state, created_at, updated_at, fence_expires_at)
    VALUES ('legacy-node', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'builder-1', 1700000000, 'no_claim', 't0', 't0', 1);
INSERT INTO node_command (item_id, argv_json, owner_agent, created_at, updated_at)
    VALUES ('nd-0000000000000002', '[\"ls\"]', 'lead-1', 't2', 't2');
INSERT INTO node_command_notice (item_id, attempt, terminal, owner_agent, body, created_at)
    VALUES ('nd-0000000000000002', 1, 'finished', 'lead-1', 'fake notice', 't2');
INSERT INTO node_followups (id, item_id, seq, mode, body, idempotency_key, created_by, created_at, updated_at)
    VALUES ('nf-0000000000000001', 'nd-0000000000000001', 1, 'queue', 'fake follow-up', 'legacy-fu-key', 'lead-1',
            't1', 't1');
INSERT INTO node_acceptance (node, run_id, agent, state, started_by, started_at, updated_at)
    VALUES ('legacy-node', 'acc-0000000000000001', 'builder-1', 'failed', 'operator', 't0', 't0');
CREATE VIEW v_node_launch_keys AS SELECT id, launch_key FROM node_dispatch;
CREATE TRIGGER legacy_node_dispatch_touch AFTER UPDATE OF status ON node_dispatch BEGIN SELECT 1; END;
";

/// Open a legacy database (every part but this family's), run `prepare` on
/// it, then open the hub on it twice.
fn upgrade(prepare: &str) -> (tempfile::TempDir, Config) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.human_identities = vec!["operator".into()];
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        let prepare = prepare.to_string();
        db.write(move |tx| {
            tx.execute_batch(LEGACY_ROWS)?;
            tx.execute_batch(&prepare)?;
            Ok(())
        })
        .unwrap();
    }
    for _ in 0..2 {
        Hub::open(cfg.clone()).unwrap();
    }
    (dir, cfg)
}

#[tokio::test]
async fn a_legacy_database_upgrades_every_row_into_the_default_organization() {
    let rowids_before = {
        let dir = tempfile::tempdir().unwrap();
        let db = ua_store::Db::open(&Config::for_home(dir.path()).db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(LEGACY_ROWS)?;
            Ok(())
        })
        .unwrap();
        db.read(|c| {
            Ok(c.prepare("SELECT rowid || ':' || id FROM node_dispatch ORDER BY id")?
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?)
        })
        .unwrap()
    };
    let (_dir, cfg) = upgrade("");
    let hub = Hub::open(cfg).unwrap();
    hub.db()
        .read(|c| {
            let expect = [
                ("nodes", 1),
                ("node_acceptance", 1),
                ("node_claim_ops", 1),
                ("node_command", 1),
                ("node_command_notice", 1),
                ("node_dispatch", 2),
                ("node_followups", 1),
                ("dispatch_runs", 1),
                ("dispatch_receipts", 1),
            ];
            for (t, rows) in expect {
                let (n, default): (i64, i64) = c.query_row(
                    &format!("SELECT COUNT(*), COALESCE(SUM(org_id = 'default'), 0) FROM {t}"),
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                assert_eq!((n, default), (rows, rows), "{t}: nothing dropped, every row in default");
                let notnull: i64 = c.query_row(
                    &format!("SELECT \"notnull\" FROM pragma_table_info('{t}') WHERE name = 'org_id'"),
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(notnull, 1, "{t}");
                let triggers = names(c, "trigger", t);
                for want in [format!("{t}_org_exists"), format!("{t}_org_immutable")] {
                    assert!(triggers.contains(&want), "{want} missing: {triggers:?}");
                }
            }
            for want in
                ["node_dispatch_org_parent", "node_dispatch_org_parent_update", "legacy_node_dispatch_touch"]
            {
                assert!(names(c, "trigger", "node_dispatch").iter().any(|t| t == want), "{want}");
            }
            for (t, want) in [
                ("dispatch_runs", "dispatch_runs_org_parent"),
                ("dispatch_receipts", "dispatch_receipts_org_parent"),
                ("node_acceptance", "node_acceptance_org_parent"),
                ("node_claim_ops", "node_claim_ops_org_parent"),
                ("node_command", "node_command_org_parent"),
                ("node_command_notice", "node_command_notice_org_parent"),
                ("node_followups", "node_followups_org_parent"),
            ] {
                assert!(names(c, "trigger", t).iter().any(|n| n == want), "{want}");
            }
            // Items keep their ids and rowids (the queue orders by rowid), the
            // view and every index survive the rebuild.
            let rowids: Vec<String> = c
                .prepare("SELECT rowid || ':' || id FROM node_dispatch ORDER BY id")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            assert_eq!(rowids, rowids_before);
            let view: i64 = c.query_row(
                "SELECT COUNT(*) FROM v_node_launch_keys WHERE launch_key IS NOT NULL",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(view, 1);
            let indexes = names(c, "index", "node_dispatch");
            for want in [
                "idx_node_dispatch_node_status",
                "idx_node_dispatch_run",
                "idx_node_dispatch_launch_key",
                "idx_node_dispatch_org_node_status",
                "idx_node_dispatch_org_created",
            ] {
                assert!(indexes.iter().any(|i| i == want), "{want}: {indexes:?}");
            }
            let key_sql: String = c.query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'idx_node_dispatch_launch_key'",
                [],
                |r| r.get(0),
            )?;
            assert!(key_sql.contains("UNIQUE") && key_sql.contains("(org_id, launch_key)"), "{key_sql}");
            // Every new part is recorded once.
            for p in PARTS {
                let n: i64 =
                    c.query_row("SELECT COUNT(*) FROM schema_parts WHERE name = ?1", [p], |r| r.get(0))?;
                assert_eq!(n, 1, "{p}");
            }
            // The upgrade wrote no ledger row: nothing was dropped to account for.
            let n: i64 = c.query_row("SELECT COUNT(*) FROM event_log", [], |r| r.get(0))?;
            assert_eq!(n, 0);
            Ok(())
        })
        .unwrap();

    // Launch-key uniqueness is preserved: the legacy key still refuses a
    // second default-organization row.
    let dup = hub.db().write(|tx| {
        tx.execute_batch(
            "INSERT INTO node_dispatch (org_id, id, node, agent, backend, prompt, cwd, timeout_s, created_by, \
             created_at, launch_key, updated_at) VALUES ('default', 'nd-0000000000000009', 'legacy-node', \
             'builder-1', 'codex', 'p', '/srv/work', 60, 'lead-1', 't9', 'legacy-key-0001', 't9')",
        )?;
        Ok(())
    });
    assert!(dup.unwrap_err().to_string().contains("UNIQUE"), "the legacy launch key stays unique");
}

/// The rebuild is crash-safe: a `node_dispatch` that already carries a
/// nullable `org_id` (a rebuild interrupted before it was recorded) keeps
/// its organization and fills a `NULL` with the default.
#[tokio::test]
async fn an_interrupted_rebuild_keeps_or_fills_the_organization() {
    let (_dir, cfg) = upgrade(
        "ALTER TABLE node_dispatch ADD COLUMN org_id TEXT;
         UPDATE node_dispatch SET org_id = 'default' WHERE id = 'nd-0000000000000001';",
    );
    let hub = Hub::open(cfg).unwrap();
    let rows: Vec<String> = hub
        .db()
        .read(|c| {
            Ok(c.prepare("SELECT id || '=' || org_id FROM node_dispatch ORDER BY id")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?)
        })
        .unwrap();
    assert_eq!(rows, ["nd-0000000000000001=default", "nd-0000000000000002=default"]);
    let notnull: i64 = hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT \"notnull\" FROM pragma_table_info('node_dispatch') WHERE name = 'org_id'",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(notnull, 1);
}

#[tokio::test]
async fn each_organization_sees_only_its_own_nodes_work_and_runs() {
    let h = H::new();
    h.fleet().await;
    let a_item = h.queue(&lead_a(), NODE_A, "fake A prompt", json!({})).await;
    let b_item = h.queue(&lead_b(), NODE_B, B_PROMPT, json!({})).await;
    assert_eq!(h.text(&format!("SELECT org_id FROM node_dispatch WHERE id = '{b_item}'")), ORG_B);
    assert_eq!(h.text(&format!("SELECT org_id FROM nodes WHERE node = '{NODE_B}'")), ORG_B);

    // node_list: each organization's own nodes, even for an operator.
    let node_names = |v: &Value| -> Vec<String> {
        v["nodes"].as_array().unwrap().iter().map(|n| n["node"].as_str().unwrap().to_string()).collect()
    };
    assert_eq!(node_names(&h.ok(&human(), "node_list", json!({})).await), [NODE_A]);
    assert_eq!(node_names(&h.ok(&device_a(), "node_list", json!({})).await), [NODE_A]);
    assert_eq!(node_names(&h.ok(&device_b(), "node_list", json!({})).await), [NODE_B]);

    // node_items: an operator of the default organization never lists B's.
    let items = |v: &Value| -> Vec<String> {
        v["items"].as_array().unwrap().iter().map(|i| i["item_id"].as_str().unwrap().to_string()).collect()
    };
    assert_eq!(items(&h.ok(&human(), "node_items", json!({})).await), std::slice::from_ref(&a_item));
    assert_eq!(items(&h.ok(&lead_b(), "node_items", json!({})).await), std::slice::from_ref(&b_item));
    let got = h.call(&human(), "node_items", json!({ "item_id": b_item })).await;
    let missing = h.call(&human(), "node_items", json!({ "item_id": MISSING_ITEM })).await;
    same_as_missing(&got, &missing, &[&b_item, MISSING_ITEM]);

    // run_list / run_get: the node kind is scoped too.
    let runs = h.ok(&human(), "run_list", json!({ "kind": "node" })).await;
    let ids: Vec<&str> =
        runs["runs"].as_array().unwrap().iter().filter_map(|r| r["run_id"].as_str()).collect();
    assert_eq!(ids, [a_item.as_str()], "{runs}");
    let got = h.call(&human(), "run_get", json!({ "run_id": b_item })).await;
    let missing = h.call(&human(), "run_get", json!({ "run_id": MISSING_ITEM })).await;
    same_as_missing(&got, &missing, &[&b_item, MISSING_ITEM]);

    // Device acceptance summaries: the caller's organization's nodes only.
    let st = h.manage(&human(), "node_acceptance_status", json!({})).await.unwrap();
    assert!(!st.to_string().contains(NODE_B), "{st}");

    // Dispatch runs: B's routed run is invisible to the default organization.
    let tid =
        h.ok(&device_b(), "task_add", json!({ "title": "B routed task" })).await["id"].as_i64().unwrap();
    let out = h
        .gated(
            &device_b(),
            "dispatch_task",
            json!({ "task_id": tid, "agent": B_DEVICE, "node": NODE_B, "prompt": B_PROMPT }),
        )
        .await;
    let run_id = out["run_id"].as_str().unwrap().to_string();
    assert_eq!(h.text(&format!("SELECT org_id FROM dispatch_runs WHERE run_id = '{run_id}'")), ORG_B);
    let receipts = h.ok(&human(), "dispatch_delivery_receipts_list", json!({})).await;
    assert_eq!(receipts["count"], 0, "{receipts}");
    let mine = h.ok(&device_b(), "dispatch_delivery_receipts_list", json!({})).await;
    assert_eq!(mine["count"], 1, "{mine}");
    let fake_run = "run-999-ffffffff";
    for tool in ["dispatch_delivery_receipt", "dispatch_cancel"] {
        let got = h.call(&human(), tool, json!({ "run_id": run_id })).await;
        let missing = h.call(&human(), tool, json!({ "run_id": fake_run })).await;
        same_as_missing(&got, &missing, &[&run_id, fake_run]);
    }
    let runs = h.ok(&human(), "run_list", json!({ "kind": "dispatch" })).await;
    assert_eq!(runs["runs"], json!([]), "{runs}");

    // The doctor's fleet row lists the default organization's nodes and only
    // counts the others.
    let doctor = h.ok(&human(), "system_doctor", json!({})).await;
    let row = doctor["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "fleet_nodes").unwrap();
    assert!(row["detail"].as_str().unwrap().contains(NODE_A), "{row}");
    assert!(!row.to_string().contains(NODE_B), "{row}");
    assert_eq!(row["other_org_nodes"], json!({ "active": 1, "retired": 0 }), "{row}");
}

#[tokio::test]
async fn cross_organization_targeting_answers_like_a_missing_node() {
    let h = H::new();
    h.fleet().await;
    let a_item = h.queue(&lead_a(), NODE_A, "fake A prompt", json!({})).await;
    let before = h.counts();
    let pending_before = h.count("SELECT COUNT(*) FROM approvals");
    let names = [NODE_A, NODE_B, MISSING_NODE];

    // Queue work on another organization's node, either way round.
    for (who, theirs, root) in [(lead_b(), NODE_A, ROOT_A), (lead_a(), NODE_B, ROOT_B)] {
        let args = |node: &str| json!({ "node": node, "backend": "codex", "prompt": "p", "cwd": format!("{root}/x") });
        let got = h.call(&who, "node_dispatch", args(theirs)).await;
        let missing = h.call(&who, "node_dispatch", args(MISSING_NODE)).await;
        same_as_missing(&got, &missing, &names);
        // A supervised command and a routed dispatch run, the same way.
        let cmd = |node: &str| json!({ "node": node, "argv": ["ls"], "cwd": format!("{root}/x") });
        let got = h.manage(&who, "node_command_start", cmd(theirs)).await;
        let missing = h.manage(&who, "node_command_start", cmd(MISSING_NODE)).await;
        same_as_missing(&got, &missing, &names);
    }
    let tid = h.ok(&device_b(), "task_add", json!({ "title": "B task" })).await["id"].as_i64().unwrap();
    let route = |node: &str| json!({ "task_id": tid, "agent": B_DEVICE, "node": node, "prompt": "p" });
    let got = h.call(&device_b(), "dispatch_task", route(NODE_A)).await;
    let missing = h.call(&device_b(), "dispatch_task", route(MISSING_NODE)).await;
    same_as_missing(&got, &missing, &names);

    // The device plane: a node token of B on A's node.
    for (tool, args) in [
        ("node_claim", json!({})),
        ("node_heartbeat", json!({})),
        ("node_followups", json!({ "item_id": a_item })),
        ("node_events", json!({ "item_id": a_item, "events": [] })),
        ("node_receipt", json!({ "item_id": a_item, "receipt": { "status": "finished", "attempt": 1 } })),
    ] {
        let with = |node: &str| {
            let mut a = args.clone();
            a["node"] = json!(node);
            a
        };
        let got = h.call(&device_b(), tool, with(NODE_A)).await;
        let missing = h.call(&device_b(), tool, with(MISSING_NODE)).await;
        same_as_missing(&got, &missing, &names);
    }

    // Controlling another organization's item.
    let ids = [a_item.as_str(), MISSING_ITEM];
    for action in ["node_item_cancel", "node_item_restart", "node_command_status"] {
        let got = h.manage(&lead_b(), action, json!({ "item_id": a_item })).await;
        let missing = h.manage(&lead_b(), action, json!({ "item_id": MISSING_ITEM })).await;
        same_as_missing(&got, &missing, &ids);
    }
    let fu =
        |id: &str| json!({ "item_id": id, "mode": "queue", "body": "b", "idempotency_key": "fu-key-0001" });
    let got = h.call(&lead_b(), "node_followup", fu(&a_item)).await;
    let missing = h.call(&lead_b(), "node_followup", fu(MISSING_ITEM)).await;
    same_as_missing(&got, &missing, &ids);

    // Nothing moved, and no approval was parked for any of it.
    assert_eq!(h.counts(), before);
    assert_eq!(h.count("SELECT COUNT(*) FROM approvals"), pending_before);
    assert_eq!(h.text(&format!("SELECT status FROM node_dispatch WHERE id = '{a_item}'")), "queued");
}

#[tokio::test]
async fn a_node_token_of_another_organization_never_claims_default_work() {
    let h = H::new();
    h.fleet().await;
    let a_item = h.queue(&lead_a(), NODE_A, "fake A prompt", json!({})).await;
    let b_item = h.queue(&lead_b(), NODE_B, B_PROMPT, json!({})).await;

    // Even under the very label that owns A's node, a token of organization
    // B finds no such node: the claim is bound to the token's organization,
    // not to the label.
    let twin = caller("builder-1", ActorKind::Agent, ORG_B);
    let e = h.call(&twin, "node_claim", json!({ "node": NODE_A })).await.unwrap_err();
    assert_eq!(e.code(), "not_found", "{e:?}");
    let e = h.call(&twin, "node_heartbeat", json!({ "node": NODE_A, "running": a_item })).await.unwrap_err();
    assert_eq!(e.code(), "not_found", "{e:?}");
    // Registering the name in B is refused: node names are one hub namespace.
    let e =
        h.call(&twin, "node_register", json!({ "node": NODE_A, "facts": facts(ROOT_A) })).await.unwrap_err();
    assert_eq!(reason(&e), "node_owned_elsewhere", "{e:?}");
    assert_eq!(h.text(&format!("SELECT org_id FROM nodes WHERE node = '{NODE_A}'")), DEFAULT_ORG);
    assert_eq!(
        h.text(&format!("SELECT status || ':' || attempts FROM node_dispatch WHERE id = '{a_item}'")),
        "queued:0"
    );

    // Each node claims only its own organization's work.
    let got = h.ok(&device_b(), "node_claim", json!({ "node": NODE_B })).await;
    assert_eq!(got["item"]["item_id"], b_item.as_str());
    assert_eq!(h.ok(&device_b(), "node_claim", json!({ "node": NODE_B })).await["item"], Value::Null);
    let got = h.ok(&device_a(), "node_claim", json!({ "node": NODE_A })).await;
    assert_eq!(got["item"]["item_id"], a_item.as_str());

    // A durable claim operation lives in its node's organization.
    let op =
        json!({ "id": "b".repeat(32), "mode": "claim", "issued_at": jiff::Timestamp::now().as_second() });
    h.ok(&device_b(), "node_claim", json!({ "node": NODE_B, "claim_op": op })).await;
    assert_eq!(h.count(&format!("SELECT COUNT(*) FROM node_claim_ops WHERE org_id = '{ORG_B}'")), 1);

    // B's receipt settles B's item; B's session credential is checked in
    // B's own organization (session credentials carry one since the agents
    // family converted): this item is not an ACP item, the answer a default
    // node gets too.
    let r = h
        .ok(
            &device_b(),
            "node_receipt",
            json!({ "node": NODE_B, "item_id": b_item, "receipt": { "status": "finished", "attempt": 1, "text": B_OUTPUT } }),
        )
        .await;
    assert_eq!(r["status"], "finished");
    let e = h
        .call(
            &device_b(),
            "node_session_credential",
            json!({ "node": NODE_B, "item_id": b_item, "attempt": 1 }),
        )
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "not_acp", "{e:?}");
    // Device acceptance reads default-organization evidence, so another
    // organization's node is refused before anything is queued.
    let e = h.manage(&device_b(), "node_acceptance_start", json!({ "node": NODE_B })).await.unwrap_err();
    assert_eq!(reason(&e), "org_unsupported", "{e:?}");
    // Idle wakes run per organization: B's node polls B's sessions only
    // (it has none).
    let v = h.ok(&device_b(), "node_wake", json!({ "node": NODE_B, "offer_version": 3 })).await;
    assert_eq!(v, json!({ "wakes": [] }));
}

#[tokio::test]
async fn launch_and_follow_up_keys_are_per_organization() {
    let h = H::new();
    h.fleet().await;
    // An organization whose id contains `/`, and its prefix, each with a node.
    let (slashed, plain) = ("x/node_dispatch/y", "x");
    add_org(h.hub.db(), slashed, "active");
    add_org(h.hub.db(), plain, "active");
    let dev = |org: &str, n: &str| caller(&format!("dev-{n}"), ActorKind::Agent, org);
    let lead = |org: &str, n: &str| caller(&format!("lead-{n}"), ActorKind::Agent, org);
    h.register(&dev(slashed, "s"), "node-slash", "/srv/s").await;
    h.register(&dev(plain, "p"), "node-plain", "/srv/p").await;

    let key = "shared-launch-key-1";
    let args = |node: &str, root: &str| json!({ "node": node, "backend": "codex", "prompt": "same", "cwd": format!("{root}/r"), "launch_key": key });
    let a = h.gated(&lead_a(), "node_dispatch", args(NODE_A, ROOT_A)).await;
    let b = h.gated(&lead_b(), "node_dispatch", args(NODE_B, ROOT_B)).await;
    let s = h.gated(&lead(slashed, "s"), "node_dispatch", args("node-slash", "/srv/s")).await;
    let p = h.gated(&lead(plain, "p"), "node_dispatch", args("node-plain", "/srv/p")).await;
    let ids: std::collections::BTreeSet<&str> =
        [&a, &b, &s, &p].iter().map(|v| v["item_id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), 4, "one key, four organizations, four items");
    for v in [&a, &b, &s, &p] {
        assert!(v.get("replayed").is_none(), "{v}");
    }
    assert_eq!(h.count(&format!("SELECT COUNT(*) FROM node_dispatch WHERE launch_key = '{key}'")), 4);

    // A retry replays only the caller's own organization's item.
    let again = h.ok(&lead_b(), "node_dispatch", args(NODE_B, ROOT_B)).await;
    assert_eq!((again["item_id"].clone(), again["replayed"].clone()), (b["item_id"].clone(), json!(true)));
    let again = h.ok(&lead_a(), "node_dispatch", args(NODE_A, ROOT_A)).await;
    assert_eq!(again["item_id"], a["item_id"]);
    // The same key with other arguments conflicts inside one organization
    // only, and names nothing of the item.
    let mut other = args(NODE_B, ROOT_B);
    other["prompt"] = json!("different");
    let e = h.call(&lead_b(), "node_dispatch", other).await.unwrap_err();
    assert_eq!(reason(&e), "launch_key_reused", "{e:?}");
    assert!(!e.to_string().contains(b["item_id"].as_str().unwrap()));

    // Follow-up keys are keyed by the item, so they cannot meet either.
    let acp = |node: &str, root: &str| json!({ "node": node, "backend": "acp:claude", "prompt": "acp", "cwd": format!("{root}/r") });
    let a_acp = h.gated(&lead_a(), "node_dispatch", acp(NODE_A, ROOT_A)).await["item_id"]
        .as_str()
        .unwrap()
        .to_string();
    let b_acp = h.gated(&lead_b(), "node_dispatch", acp(NODE_B, ROOT_B)).await["item_id"]
        .as_str()
        .unwrap()
        .to_string();
    let fu = |id: &str| json!({ "item_id": id, "mode": "queue", "body": "same body", "idempotency_key": "fu-key-0001" });
    let fa = h.gated(&lead_a(), "node_followup", fu(&a_acp)).await;
    let fb = h.gated(&lead_b(), "node_followup", fu(&b_acp)).await;
    assert_ne!(fa["followup_id"], fb["followup_id"]);
    assert_eq!(fb["duplicate"], false);
    assert_eq!(h.ok(&lead_b(), "node_followup", fu(&b_acp)).await["followup_id"], fb["followup_id"]);
    assert_eq!(
        h.text(&format!(
            "SELECT org_id FROM node_followups WHERE id = '{}'",
            fb["followup_id"].as_str().unwrap()
        )),
        ORG_B
    );

    // Another organization's dedupe keys are digests: no node name or turn
    // id in the default organization's ledger.
    for (_, _, dedupe, _) in h.ledger() {
        let d = dedupe.unwrap_or_default();
        assert!(!d.contains(NODE_B) && !d.contains("node-slash"), "{d}");
    }
}

#[tokio::test]
async fn unknown_and_suspended_organizations_are_refused_before_any_write() {
    let h = H::new();
    h.fleet().await;
    h.queue(&lead_a(), NODE_A, "fake A prompt", json!({})).await;
    add_org(h.hub.db(), "org-paused", "suspended");
    let before = h.counts();
    for (org, code) in [(UNKNOWN, "unknown_organization"), ("org-paused", "organization_suspended")] {
        let ghost = caller("ghost-device", ActorKind::Agent, org);
        let e =
            h.call(&ghost, "node_register", json!({ "node": "ghost-node", "facts": facts("/srv/g") })).await;
        assert_eq!(reason(&e.unwrap_err()), code);
        // Writes with nothing to insert: the existence trigger never fires.
        for (tool, args) in [
            ("node_heartbeat", json!({ "node": NODE_A })),
            ("node_claim", json!({ "node": NODE_A })),
            (
                "node_dispatch",
                json!({ "node": NODE_A, "backend": "codex", "prompt": "p", "cwd": "/srv/work-a/x" }),
            ),
            ("dispatch_task", json!({ "task_id": 1, "agent": "ghost-device", "node": NODE_A })),
        ] {
            let e = h.call(&ghost, tool, args).await.unwrap_err();
            assert_eq!(reason(&e), code, "{tool}: {e:?}");
        }
        let e = h.manage(&ghost, "node_item_cancel", json!({ "item_id": MISSING_ITEM })).await.unwrap_err();
        assert_eq!(reason(&e), code);
    }
    assert_eq!(h.counts(), before);
}

#[tokio::test]
async fn organization_b_node_names_prompts_and_outputs_never_reach_the_default_ledger() {
    let h = H::new();
    h.fleet().await;
    let item = h.queue(&lead_b(), NODE_B, B_PROMPT, json!({ "backend": "acp:claude" })).await;
    h.ok(&device_b(), "node_claim", json!({ "node": NODE_B })).await;
    h.ok(&device_b(), "node_heartbeat", json!({ "node": NODE_B, "running": item, "progress": B_PROGRESS }))
        .await;
    h.ok(
        &device_b(),
        "node_events",
        json!({ "node": NODE_B, "item_id": item, "events": [
            { "kind": "session_open", "session_id": "osprey-session-not-real" },
            { "kind": "agent_message", "turn_id": "t1", "text": B_OUTPUT },
            { "kind": "turn_end", "turn_id": "t1" },
        ] }),
    )
    .await;
    h.ok(
        &device_b(),
        "node_receipt",
        json!({ "node": NODE_B, "item_id": item, "receipt": { "status": "failed", "attempt": 1, "text": B_OUTPUT, "reason": B_OUTPUT } }),
    )
    .await;
    // A routed dispatch run and its transitions.
    let tid =
        h.ok(&device_b(), "task_add", json!({ "title": "B ledger task" })).await["id"].as_i64().unwrap();
    let out = h
        .gated(
            &device_b(),
            "dispatch_task",
            json!({ "task_id": tid, "agent": B_DEVICE, "node": NODE_B, "prompt": B_PROMPT }),
        )
        .await;
    let run_id = out["run_id"].as_str().unwrap().to_string();
    h.ok(&device_b(), "dispatch_cancel", json!({ "run_id": run_id, "reason": B_OUTPUT })).await;

    let ledger = h.ledger();
    let node_events = ledger.iter().filter(|(c, ..)| c.starts_with("agent.node")).count();
    let transitions = ledger.iter().filter(|(c, ..)| c == "agent.dispatch.transition").count();
    assert!(node_events >= 6, "the events are still written: {node_events}");
    assert!(transitions >= 2, "{transitions}");
    for (channel, originator, dedupe, payload) in &ledger {
        let row = format!("{channel} {originator:?} {dedupe:?} {payload}");
        for secret in
            [NODE_B, ROOT_B, B_DEVICE, B_LEAD, B_PROMPT, B_PROGRESS, B_OUTPUT, "osprey-session-not-real"]
        {
            assert!(!row.contains(secret), "{secret} reached the default ledger: {row}");
        }
    }
    // Every organization-B event is the neutral system's, and keeps its ids.
    let b_rows: Vec<_> = ledger
        .iter()
        .filter(|(c, _, _, p)| {
            (c.starts_with("agent.node") || c == "agent.dispatch.transition")
                && (p.contains(&item) || p.contains(&run_id))
        })
        .collect();
    assert!(!b_rows.is_empty());
    for (_, originator, _, _) in &b_rows {
        assert_eq!(originator.as_deref(), Some("system"));
    }
}

#[tokio::test]
async fn the_organization_and_reference_triggers_refuse_bad_rows() {
    let h = H::new();
    h.fleet().await;
    let a_item = h.queue(&lead_a(), NODE_A, "fake A prompt", json!({})).await;
    let a_task = h.ok(&lead_a(), "task_add", json!({ "title": "A task" })).await["id"].as_i64().unwrap();
    h.sql(&format!(
        "INSERT INTO dispatch_runs (org_id, run_id, task_id, agent_label, state, actor, created_at, updated_at) \
         VALUES ('default', 'run-a-0001', {a_task}, 'builder-1', 'finished', 'lead-1', 't', 't')"
    ))
    .unwrap();
    let refuse = |sql: String, why: &str| {
        let e = h.sql(&sql).unwrap_err();
        assert!(e.contains(why), "{sql}: {e}");
    };
    // An unknown organization, on every table.
    refuse(
        format!(
            "INSERT INTO nodes (org_id, node, agent, registered_at, updated_at) VALUES ('{UNKNOWN}', 'n9', 'a', 't', 't')"
        ),
        "unknown organization",
    );
    refuse(
        format!(
            "INSERT INTO node_command (org_id, item_id, argv_json, owner_agent, created_at, updated_at) \
             VALUES ('{UNKNOWN}', '{MISSING_ITEM}', '[]', 'a', 't', 't')"
        ),
        "unknown organization",
    );
    // Organization B pointing at the default organization's node, item,
    // task and run.
    refuse(
        format!(
            "INSERT INTO node_dispatch (org_id, id, node, agent, backend, prompt, cwd, timeout_s, created_by, \
             created_at, updated_at) VALUES ('{ORG_B}', 'nd-00000000000000bb', '{NODE_A}', 'x', 'codex', 'p', '/c', 1, \
             'x', 't', 't')"
        ),
        "another organization",
    );
    for (table, cols, vals) in [
        (
            "node_command",
            "item_id, argv_json, owner_agent, created_at, updated_at",
            format!("'{a_item}', '[]', 'a', 't', 't'"),
        ),
        (
            "node_command_notice",
            "item_id, attempt, terminal, owner_agent, body, created_at",
            format!("'{a_item}', 1, 'finished', 'a', 'b', 't'"),
        ),
        (
            "node_followups",
            "id, item_id, seq, mode, body, idempotency_key, created_by, created_at, updated_at",
            format!("'nf-00000000000000bb', '{a_item}', 1, 'queue', 'b', 'k', 'x', 't', 't'"),
        ),
        (
            "node_claim_ops",
            "node, op_id, identity, issued_at, state, created_at, updated_at, fence_expires_at",
            format!("'{NODE_A}', 'op', 'x', 1, 'no_claim', 't', 't', 1"),
        ),
        (
            "node_acceptance",
            "node, run_id, agent, state, started_by, started_at, updated_at",
            format!("'{NODE_A}', 'acc', 'x', 'failed', 'x', 't', 't'"),
        ),
        (
            "dispatch_runs",
            "run_id, task_id, agent_label, state, actor, created_at, updated_at",
            format!("'run-b-0001', {a_task}, 'x', 'finished', 'x', 't', 't'"),
        ),
        (
            "dispatch_receipts",
            "run_id, fence, task_id, agent_label, state, source, reported_by, receipt_hash, created_at",
            format!("'run-a-0001', 1, {a_task}, 'x', 'finished', 's', 'x', 'h', 't'"),
        ),
    ] {
        refuse(
            format!("INSERT INTO {table} (org_id, {cols}) VALUES ('{ORG_B}', {vals})"),
            "another organization",
        );
    }
    // A row never moves between organizations.
    refuse(format!("UPDATE nodes SET org_id = '{ORG_B}' WHERE node = '{NODE_A}'"), "org_id cannot change");
    refuse(
        format!("UPDATE node_dispatch SET org_id = '{ORG_B}' WHERE id = '{a_item}'"),
        "org_id cannot change",
    );
}

/// The insert guard over this family's source: every `INSERT` into one of
/// the nine tables names `org_id` (the crate-wide guard in
/// `org_classification.rs` checks the same now that the tables left
/// `TENANT_MISSING_ORG_ID`; this one names the family's files).
#[test]
fn every_insert_into_a_node_or_dispatch_table_names_org_id() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                files.push(p);
            }
        }
    }
    let mut seen = 0;
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        for (i, _) in flat.match_indices("INSERT ") {
            let rest = &flat[i..];
            let Some(into) = rest.find(" INTO ") else { continue };
            if into > 30 {
                continue;
            }
            let after = &rest[into + 6..];
            let table: String =
                after.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            if !TABLES.contains(&table.as_str()) {
                continue;
            }
            let cols = after[table.len()..].trim_start();
            let Some(cols) = cols.strip_prefix('(') else { continue };
            let cols = &cols[..cols.find(')').unwrap_or(cols.len())];
            seen += 1;
            assert!(
                cols.contains("org_id"),
                "{}: INSERT INTO {table} ({cols}) does not name org_id",
                f.display()
            );
        }
    }
    assert!(seen >= 9, "the guard found {seen} inserts");
}

/// The `operator` human, but authenticated in organization B: the same
/// label, so only the organization keeps it from the hub-level authority.
fn operator_b() -> Caller {
    Caller {
        profile: Profile::Operator,
        enforce_profile: false,
        ..caller("operator", ActorKind::Human, ORG_B)
    }
}

const B_REASON: &str = "osprey-reason-not-real";

#[tokio::test]
async fn a_default_operator_recovers_a_name_another_organization_holds() {
    let h = H::new();
    // Organization B squats the name the default organization needs.
    h.register(&device_b(), NODE_B, ROOT_B).await;
    let e = h
        .call(&device_a(), "node_register", json!({ "node": NODE_B, "facts": facts(ROOT_A) }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "node_owned_elsewhere", "{e:?}");
    let ledger_before = h.ledger().len();

    // Without any_org every operator action stays in the caller's
    // organization: B's node answers as missing.
    for action in ["node_retire", "node_forget"] {
        let e = h.manage(&human(), action, json!({ "node": NODE_B, "reason": B_REASON })).await.unwrap_err();
        assert_eq!(e.code(), "not_found", "{action}: {e:?}");
    }
    // An organization-B caller, even under the operator's label, cannot use
    // the hub path; nor can the node's own agent.
    for who in [operator_b(), device_b(), lead_b()] {
        for action in ["node_retire", "node_forget"] {
            let e = h
                .manage(&who, action, json!({ "node": NODE_B, "reason": B_REASON, "any_org": true }))
                .await
                .unwrap_err();
            assert_eq!(reason(&e), "not_lifecycle_operator", "{}: {action}: {e:?}", who.label);
        }
    }
    // A default caller that is no lifecycle operator cannot either.
    let e = h
        .manage(&lead_a(), "node_retire", json!({ "node": NODE_B, "reason": B_REASON, "any_org": true }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "not_lifecycle_operator", "{e:?}");
    // Un-retire takes no any_org.
    let e = h
        .manage(&human(), "node_unretire", json!({ "node": NODE_B, "reason": B_REASON, "any_org": true }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), "invalid_argument", "{e:?}");
    assert_eq!(h.ledger().len(), ledger_before, "a refusal writes nothing");
    assert_eq!(
        h.text(&format!(
            "SELECT org_id || ':' || COALESCE(retired_at, 'active') FROM nodes WHERE node = '{NODE_B}'"
        )),
        format!("{ORG_B}:active")
    );

    // The default lifecycle operator retires, then forgets, B's node in B.
    let retired = h
        .manage(&human(), "node_retire", json!({ "node": NODE_B, "reason": B_REASON, "any_org": true }))
        .await
        .unwrap();
    let keys: Vec<&str> = retired.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["changed", "event_ulid", "hub_recovery", "node", "org_id", "retired"], "{retired}");
    assert_eq!(retired["org_id"], ORG_B);
    assert_eq!(retired["changed"], true);
    assert_eq!(
        h.text(&format!("SELECT org_id FROM nodes WHERE node = '{NODE_B}' AND retired_at IS NOT NULL")),
        ORG_B,
        "retired in its own organization"
    );
    // Again: unchanged, and still none of B's row (its retirement reason).
    let again = h
        .manage(&human(), "node_retire", json!({ "node": NODE_B, "reason": "fake second", "any_org": true }))
        .await
        .unwrap();
    assert_eq!(again["changed"], false);
    assert!(!again.to_string().contains(B_REASON), "{again}");
    let forgot = h
        .manage(&human(), "node_forget", json!({ "node": NODE_B, "reason": B_REASON, "any_org": true }))
        .await
        .unwrap();
    assert_eq!(forgot["forgotten"], true, "{forgot}");
    assert_eq!(forgot["org_id"], ORG_B);
    assert!(!forgot.to_string().contains(B_DEVICE), "the node's agent stays out: {forgot}");
    assert_eq!(h.count(&format!("SELECT COUNT(*) FROM nodes WHERE node = '{NODE_B}'")), 0);

    // The default organization can now register the name.
    h.register(&device_a(), NODE_B, ROOT_A).await;
    assert_eq!(h.text(&format!("SELECT org_id FROM nodes WHERE node = '{NODE_B}'")), DEFAULT_ORG);

    // The recovery's ledger entries are B's: the neutral originator and ids
    // only, none of B's node, agent, reason or the acting operator.
    let ledger = h.ledger();
    let recovery: Vec<_> =
        ledger.iter().filter(|(c, ..)| c == "agent.node.retire" || c == "agent.node.forget").collect();
    assert_eq!(recovery.len(), 2, "{recovery:?}");
    for (channel, originator, dedupe, payload) in recovery {
        assert_eq!(originator.as_deref(), Some("system"), "{channel}");
        assert_eq!(dedupe, &None);
        let v: Value = serde_json::from_str(payload).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["kind"], "{channel}: {payload}");
        for secret in [NODE_B, B_DEVICE, B_REASON, ROOT_B, "operator"] {
            assert!(!payload.contains(secret), "{secret} reached the default ledger: {payload}");
        }
    }
}

#[tokio::test]
async fn a_node_is_reassigned_only_within_its_organization() {
    let h = H::new();
    h.fleet().await;
    // B's agent works in B (it owns B's node): A's node is not moved to it.
    let e = h
        .manage(&human(), "node_reassign", json!({ "node": NODE_A, "to_agent": B_DEVICE, "reason": "fake" }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "agent_org_mismatch", "{e:?}");
    // Known through its node work too, whatever the case of the label.
    let lead_item = h.queue(&lead_b(), NODE_B, B_PROMPT, json!({})).await;
    assert!(!lead_item.is_empty());
    let ledger_before = h.ledger().len();
    let e = h
        .manage(
            &human(),
            "node_reassign",
            json!({ "node": NODE_A, "to_agent": B_DEVICE.to_uppercase(), "reason": "fake" }),
        )
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "agent_org_mismatch", "{e:?}");
    assert_eq!(h.text(&format!("SELECT agent FROM nodes WHERE node = '{NODE_A}'")), "builder-1");
    assert_eq!(h.ledger().len(), ledger_before);
    // A default agent, or a label with no known organization (the documented
    // limit), is accepted.
    let moved = h
        .manage(&human(), "node_reassign", json!({ "node": NODE_A, "to_agent": "lead-1", "reason": "fake" }))
        .await
        .unwrap();
    assert_eq!(moved["changed"], true, "{moved}");
    let moved = h
        .manage(
            &human(),
            "node_reassign",
            json!({ "node": NODE_A, "to_agent": "fresh-label-not-real", "reason": "fake" }),
        )
        .await
        .unwrap();
    assert_eq!(moved["agent"], "fresh-label-not-real", "{moved}");
}

#[tokio::test]
async fn another_organizations_dedupe_keys_carry_only_hub_ids() {
    use sha2::{Digest, Sha256};
    let h = H::new();
    h.fleet().await;
    let mut items = Vec::new();
    for (lead, device, node) in [(lead_a(), device_a(), NODE_A), (lead_b(), device_b(), NODE_B)] {
        let tid =
            h.ok(&lead, "task_add", json!({ "title": "fake dedupe task" })).await["id"].as_i64().unwrap();
        let item =
            h.queue(&lead, node, "fake prompt", json!({ "backend": "acp:claude", "task_id": tid })).await;
        h.ok(&device, "node_claim", json!({ "node": node })).await;
        let events = json!({ "node": node, "item_id": item, "events": [
            { "kind": "turn_end", "turn_id": "t1" },
        ] });
        h.ok(&device, "node_events", events).await;
        h.manage(&lead, "node_item_cancel", json!({ "item_id": item, "reason": "fake" })).await.unwrap();
        h.ok(&device, "node_heartbeat", json!({ "node": node, "running": item })).await;
        items.push(item);
    }
    let keys: Vec<String> = h.ledger().into_iter().filter_map(|(_, _, d, _)| d).collect();
    let (a, b) = (&items[0], &items[1]);
    // The default organization's keys are unchanged.
    assert!(keys.contains(&format!("turn_summary:{NODE_A}:{a}:t1")), "{keys:?}");
    assert!(keys.contains(&format!("cancel_relayed:{a}:1")), "{keys:?}");
    // B's keys are built from hub ids alone.
    let b_keys: Vec<&String> = keys.iter().filter(|k| k.contains(b.as_str())).collect();
    assert_eq!(b_keys.len(), 2, "{keys:?}");
    assert!(b_keys.iter().any(|k| k.starts_with(&format!("org:turn_summary:{b}:1:"))), "{b_keys:?}");
    assert!(b_keys.contains(&&format!("org:cancel_relayed:{b}:1")), "{b_keys:?}");
    // No key anywhere names B's node or is a digest of a key that does.
    let named = [format!("turn_summary:{NODE_B}:{b}:t1"), NODE_B.to_string()];
    let digests: Vec<String> = named.iter().map(|n| hex::encode(Sha256::digest(n.as_bytes()))).collect();
    for k in &keys {
        assert!(!k.contains(NODE_B), "{k}");
        for d in &digests {
            assert!(!k.contains(d.as_str()), "{k} is a digest of a named key");
        }
        if k.starts_with("org:") {
            assert!(!k.chars().skip(4).all(|c| c.is_ascii_hexdigit()), "an unkeyed digest: {k}");
        }
    }
}

#[tokio::test]
async fn session_wakes_answer_another_organizations_session_as_missing() {
    let h = H::new();
    h.fleet().await;
    // A default-organization session (its agent's wake rows would be the
    // default organization's).
    let a_agent = caller("wren-agent-a-not-real", ActorKind::Agent, DEFAULT_ORG);
    let sid = h.ok(&a_agent, "session_start", json!({ "kind": "interactive" })).await["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let before = h.count("SELECT COUNT(*) FROM session_wake");
    for who in [device_b(), operator_b()] {
        for (action, params) in [
            ("session_wake_opt_in", json!({ "session_id": "SID", "node": NODE_B })),
            ("session_wake_grant", json!({ "session_id": "SID" })),
            ("session_wake_decline", json!({ "session_id": "SID", "reason": "fake" })),
            ("session_wake_status", json!({ "session_id": "SID" })),
        ] {
            let with =
                |id: &str| serde_json::from_str::<Value>(&params.to_string().replace("SID", id)).unwrap();
            let got = h.manage(&who, action, with(&sid)).await;
            let missing = h.manage(&who, action, with("fake-session-1")).await;
            let norm = |r: &Result<Value, UaError>, id: &str| match r {
                Ok(v) => format!("ok {v}"),
                Err(e) => format!("err {} {}", e.code(), e.to_string().replace(id, "ID")),
            };
            assert!(got.is_err(), "{}: {action}: {got:?}", who.label);
            assert_eq!(norm(&got, &sid), norm(&missing, "fake-session-1"), "{}: {action}", who.label);
        }
    }
    assert_eq!(h.count("SELECT COUNT(*) FROM session_wake"), before);
    // The default organization's callers reach their own session.
    let v = h.manage(&human(), "session_wake_status", json!({ "session_id": sid })).await.unwrap();
    assert_eq!(v["session_id"], json!(sid), "{v}");
}

fn fleet_row(doctor: &Value) -> Value {
    doctor["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "fleet_nodes").cloned().unwrap()
}

#[tokio::test]
async fn the_doctor_counts_other_organizations_blocked_nodes_and_unsent_notices() {
    let h = H::with(|cfg| cfg.node_require_acceptance = true);
    h.fleet().await;
    h.register(&caller("osprey-second-device", ActorKind::Agent, ORG_B), "falcon-node-c", ROOT_B).await;
    let row = fleet_row(&h.ok(&human(), "system_doctor", json!({})).await);
    assert_eq!(row["other_org_nodes"], json!({ "active": 2, "retired": 0 }), "{row}");
    assert_eq!(row["other_org_nodes_not_accepted"], 2, "{row}");
    assert!(
        row["detail"].as_str().unwrap().contains("2 other-organization node(s) in service take no real work")
    );
    assert!(!row.to_string().contains(NODE_B) && !row.to_string().contains("falcon-node-c"), "{row}");
    assert!(row.get("other_org_unsent_command_notices").is_none(), "{row}");

    // One retired by hub recovery; an unsent B command notice.
    h.manage(&human(), "node_retire", json!({ "node": "falcon-node-c", "reason": "fake", "any_org": true }))
        .await
        .unwrap();
    h.sql(&format!(
        "INSERT INTO node_command_notice (item_id, attempt, terminal, owner_agent, body, created_at, org_id) \
         VALUES ('{MISSING_ITEM}', 1, 'finished', '{B_LEAD}', 'fake', '2026-01-01T00:00:00+00:00', '{ORG_B}')"
    ))
    .unwrap();
    let row = fleet_row(&h.ok(&human(), "system_doctor", json!({})).await);
    assert_eq!(row["other_org_nodes"], json!({ "active": 1, "retired": 1 }), "{row}");
    assert_eq!(row["other_org_nodes_not_accepted"], 1, "{row}");
    assert_eq!(row["other_org_unsent_command_notices"], 1, "{row}");

    // Without required acceptance, nothing is reported blocked.
    let h = H::new();
    h.fleet().await;
    let row = fleet_row(&h.ok(&human(), "system_doctor", json!({})).await);
    assert_eq!(row["other_org_nodes"], json!({ "active": 1, "retired": 0 }), "{row}");
    assert!(row.get("other_org_nodes_not_accepted").is_none(), "{row}");
    assert!(!row["detail"].as_str().unwrap().contains("take no real work"), "{row}");
}

/// Start a supervised command on `node` as `lead` (approved by SQL), claim
/// it as `device` and post its finished receipt. Returns the item id.
async fn run_command(h: &H, lead: &Caller, device: &Caller, node: &str, root: &str, arg: &str) -> String {
    let params = json!({ "node": node, "argv": ["ls", arg], "cwd": format!("{root}/repo") });
    let parked = h.manage(lead, "node_command_start", params.clone()).await.unwrap_err();
    let UaError::ApprovalRequired { approval_id, .. } = parked else {
        panic!("expected an approval: {parked:?}")
    };
    h.approve(approval_id);
    let id =
        h.manage(lead, "node_command_start", params).await.unwrap()["item_id"].as_str().unwrap().to_string();
    let claimed = h.ok(device, "node_claim", json!({ "node": node })).await;
    assert_eq!(claimed["item"]["item_id"], id.as_str(), "{claimed}");
    let token = claimed["item"]["command"]["fence_token"].as_str().unwrap().to_string();
    let receipt = json!({ "status": "finished", "attempt": 1, "exit_code": 0, "fence_token": token });
    h.ok(device, "node_receipt", json!({ "node": node, "item_id": id, "receipt": receipt })).await;
    id
}

/// Follow-up of the nodes conversion: now that the mailbox carries an
/// organization (`message_index.org_id`), a command notice of another
/// organization is mailed within that organization, to its own command
/// owner, and never through the default organization's mailbox; its text
/// stays out of the default ledger.
#[tokio::test]
async fn a_command_notice_is_mailed_within_its_own_organization() {
    let h = H::new();
    h.fleet().await;
    let a_item = run_command(&h, &lead_a(), &device_a(), NODE_A, ROOT_A, "fake-a-dir").await;
    let b_item = run_command(&h, &lead_b(), &device_b(), NODE_B, ROOT_B, B_OUTPUT).await;

    // Each receipt delivered its own notice, in its own organization.
    assert_eq!(h.count("SELECT COUNT(*) FROM node_command_notice WHERE sent_at IS NULL"), 0);
    for (org, item, owner) in [(DEFAULT_ORG, &a_item, "lead-1"), (ORG_B, &b_item, B_LEAD)] {
        let row = h.text(&format!(
            "SELECT m.org_id || '|' || m.recipient || '|' || m.sender FROM message_index m \
             JOIN node_command_notice n ON n.message_id = m.message_id AND n.org_id = m.org_id \
             WHERE n.item_id = '{item}'"
        ));
        assert_eq!(row, format!("{org}|{owner}|hub-node"));
    }
    assert_eq!(h.count(&format!("SELECT COUNT(*) FROM message_index WHERE recipient = '{B_LEAD}'")), 1);
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM message_index WHERE org_id = '{DEFAULT_ORG}' AND recipient = '{B_LEAD}'"
        )),
        0
    );

    // B's owner reads it in B; the default organization's owner sees only its own.
    let inbox = h.ok(&lead_b(), "message_list", json!({ "to_agent": B_LEAD })).await;
    let msgs = inbox["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1, "{inbox}");
    assert_eq!(msgs[0]["from_agent"], "hub-node");
    assert_eq!(msgs[0]["client_message_id"], format!("node-command-{b_item}-1-finished"));
    assert!(msgs[0]["body"].as_str().unwrap().contains(B_OUTPUT), "{inbox}");
    let a_inbox = h.ok(&lead_a(), "message_list", json!({ "to_agent": "lead-1" })).await;
    assert_eq!(a_inbox["messages"].as_array().unwrap().len(), 1, "{a_inbox}");
    assert!(!a_inbox.to_string().contains(B_OUTPUT) && !a_inbox.to_string().contains(&b_item), "{a_inbox}");

    // Nothing of B's notice reaches the default ledger as text or originator.
    for (channel, originator, dedupe, payload) in h.ledger() {
        let row = format!("{channel} {originator:?} {dedupe:?} {payload}");
        for secret in [B_OUTPUT, B_LEAD, NODE_B] {
            assert!(!row.contains(secret), "{secret} reached the default ledger: {row}");
        }
    }

    // A retried sweep sends nothing twice; the doctor counts no unsent notice.
    let swept = ua_tools::families::node_queue::sweep(&h.hub, None).unwrap();
    assert_eq!(swept["notices_delivered"], 0, "{swept}");
    assert_eq!(h.count("SELECT COUNT(*) FROM message_index WHERE sender = 'hub-node'"), 2);
}

/// An owed notice of another organization is retried by its node's sweep
/// (matched to the node within the notice's organization) and by the hub
/// sweep, and mailed in that organization.
#[tokio::test]
async fn an_owed_notice_of_another_organization_is_retried_within_it() {
    let h = H::new();
    h.fleet().await;
    let ts = "2026-01-01T00:00:00+00:00";
    for (org, item, node, owner) in [
        (ORG_B, "nd-00000000000000b1", NODE_B, B_LEAD),
        (DEFAULT_ORG, "nd-00000000000000a1", NODE_A, "lead-1"),
    ] {
        h.sql(&format!(
            "INSERT INTO node_dispatch (org_id, id, node, agent, backend, prompt, cwd, timeout_s, status, attempts, \
             created_by, created_at, updated_at) VALUES ('{org}', '{item}', '{node}', 'fake-agent', 'command', 'p', \
             '/srv', 60, 'finished', 1, '{owner}', '{ts}', '{ts}'); \
             INSERT INTO node_command_notice (org_id, item_id, attempt, terminal, owner_agent, body, created_at) \
             VALUES ('{org}', '{item}', 1, 'finished', '{owner}', 'fake done {B_OUTPUT}', '{ts}');"
        ))
        .unwrap();
    }
    let sent = |item: &str| {
        h.count(&format!("SELECT sent_at IS NOT NULL FROM node_command_notice WHERE item_id = '{item}'"))
    };
    ua_tools::families::node_queue::sweep(&h.hub, Some(NODE_B)).unwrap();
    assert_eq!((sent("nd-00000000000000b1"), sent("nd-00000000000000a1")), (1, 0));
    assert_eq!(
        h.text("SELECT org_id || '|' || recipient FROM message_index WHERE sender = 'hub-node'"),
        format!("{ORG_B}|{B_LEAD}")
    );
    ua_tools::families::node_queue::sweep(&h.hub, None).unwrap();
    assert_eq!(sent("nd-00000000000000a1"), 1);
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM message_index WHERE org_id = '{DEFAULT_ORG}' AND sender = 'hub-node'"
        )),
        1
    );
}

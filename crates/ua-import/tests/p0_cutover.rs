//! Regression tests for P0 #2702 import fidelity:
//! - `--drop-org-scope` enforcement on `harness_config_bundles.org_id` + P0 tables
//! - clearing stale `tasks.current_run_id` / `current_run_agent` (`queue_park` / `queue_health`)
//! - `work_proposals` / `work_proposal_items` frozen contracts & `work_proposal_recover`
//! - `task_holds` / `task_hold_members` defaults, active-root uniqueness & `task_hold(mode="resume")`
//! - `project_repo_bindings` slug + branch + GitHub URL normalization & `project_repo_get`

use std::path::PathBuf;

use rusqlite::{Connection, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::{ActorKind, Caller, Config, Profile, canonical, identity::Transport};
use ua_import::{Options, Report};
use ua_store::Db;
use ua_store::ledger;
use ua_tools::{Hub, builtin_registry};

const T0: &str = "2026-01-01T00:00:00+00:00";
const T_OLD: &str = "2025-11-01T00:00:00+00:00";

const PY_P0_SCHEMA: &str = "
CREATE TABLE agents (
  label TEXT PRIMARY KEY,
  kind TEXT NOT NULL DEFAULT 'unknown',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  priority TEXT NOT NULL DEFAULT 'med',
  parent_id INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  archived_at TEXT,
  claimed_by TEXT,
  claimed_at TEXT,
  lock_expires_at TEXT,
  project TEXT NOT NULL DEFAULT 'default',
  domain TEXT NOT NULL DEFAULT 'general',
  lane TEXT NOT NULL DEFAULT 'default',
  org_id TEXT,
  current_run_id TEXT,
  current_run_agent TEXT,
  cancel_requested INTEGER NOT NULL DEFAULT 0,
  ownership_generation INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE work_proposals (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  proposer TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  reporting_mode TEXT DEFAULT 'final_only',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  withdrawn_at TEXT,
  org_id TEXT
);
CREATE TABLE work_proposal_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proposal_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  title TEXT NOT NULL,
  notes TEXT DEFAULT '',
  scope_json TEXT DEFAULT '{}',
  priority TEXT DEFAULT 'med',
  status TEXT DEFAULT 'pending',
  filed_digest TEXT NOT NULL,
  contract_digest TEXT NOT NULL,
  edited INTEGER DEFAULT 0,
  approving_by TEXT,
  approving_at TEXT,
  decided_by TEXT,
  decided_at TEXT,
  task_id INTEGER,
  org_id TEXT
);
-- Intentionally omit idx_task_holds_active_root so tests can simulate legacy duplicate active holds.
CREATE TABLE task_holds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  root_task_id INTEGER NOT NULL,
  mode TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  reason TEXT DEFAULT '',
  release_policy TEXT DEFAULT 'manual',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  released_by TEXT,
  released_at TEXT,
  cancelling_at TEXT,
  org_id TEXT
);
CREATE TABLE task_hold_members (
  hold_id INTEGER NOT NULL,
  task_id INTEGER NOT NULL,
  status_at_hold TEXT NOT NULL,
  cancel_requested_by_hold INTEGER DEFAULT 0,
  cancelled_run_id TEXT,
  cancelled_run_agent TEXT,
  restored_at TEXT,
  PRIMARY KEY (hold_id, task_id)
);
CREATE TABLE project_repo_bindings (
  project TEXT PRIMARY KEY,
  repo TEXT NOT NULL,
  default_branch TEXT,
  bound_by TEXT NOT NULL,
  bound_at TEXT NOT NULL,
  org_id TEXT
);
CREATE TABLE harness_config_bundles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version TEXT NOT NULL UNIQUE,
  published_at TEXT NOT NULL,
  published_by TEXT NOT NULL,
  bundle_json TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 0,
  org_id TEXT
);
CREATE TABLE event_log (
  ulid TEXT PRIMARY KEY,
  channel TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  originator TEXT,
  episode_id TEXT,
  causal_parent_id TEXT,
  created_at TEXT NOT NULL,
  dedupe_key TEXT,
  prev_hash TEXT,
  entry_hash TEXT,
  org_id TEXT
);
";

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

fn new_source() -> (Fixture, Connection) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("py_p0.db");
    let c = Connection::open(&path).unwrap();
    c.execute_batch(PY_P0_SCHEMA).unwrap();
    let hash = ledger::compute_entry_hash(
        None,
        "01J0000000000000000000000",
        "agent.hub.started",
        "{}",
        Some("operator"),
        None,
        None,
        T0,
        None,
    );
    c.execute(
        "INSERT INTO event_log (rowid, ulid, channel, payload, originator, created_at, prev_hash, entry_hash) \
         VALUES (1, '01J0000000000000000000000', 'agent.hub.started', '{}', 'operator', ?1, ?2, ?3)",
        params![T0, ledger::GENESIS_HASH, hash],
    )
    .unwrap();
    (Fixture { _dir: dir, path }, c)
}

fn target() -> Db {
    Db::open_in_memory(&ua_import::schema_parts()).unwrap()
}

fn opts() -> Options {
    Options { drop_org_scope: true, ..Options::default() }
}

fn table<'r>(r: &'r Report, name: &str) -> &'r ua_import::TableReport {
    r.tables.iter().find(|t| t.table == name).unwrap()
}

fn n(db: &Db, sql: &str) -> i64 {
    db.read(|c| Ok(c.query_row(sql, [], |r| r.get(0))?)).unwrap()
}

fn contract_digest(title: &str, notes: &str, scope: &Value) -> String {
    let body = json!({ "notes": notes, "scope": scope, "title": title });
    hex::encode(Sha256::digest(canonical::to_string(&body).as_bytes()))
}

fn contract_notes(notes: &str, scope_json: &str, pid: &str, idx: i64, digest: &str, mode: &str) -> String {
    format!(
        "{notes}\n\n[proposal: {pid}#{idx}]\n[contract: {digest}]\n[scope: {scope_json}]\n[reporting: {mode}]\n[end contract]"
    )
}

fn human_coordinator() -> Caller {
    Caller {
        label: "operator".into(),
        kind: ActorKind::Human,
        profile: Profile::Coordinator,
        enforce_profile: true,
        session_key: Some("s-op".into()),
        transport: Transport::Mcp,
    }
}

fn agent(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s-agent".into()),
        transport: Transport::Mcp,
    }
}

#[test]
fn p0_tables_and_harness_config_bundles_enforce_drop_org_scope() {
    let (f, c) = new_source();
    c.execute(
        "INSERT INTO tasks (id, title, status, created_at, updated_at) VALUES (1, 'Root', 'open', ?1, ?1)",
        [T0],
    )
    .unwrap();
    c.execute(
        "INSERT INTO harness_config_bundles (id, version, published_at, published_by, bundle_json, active, org_id) \
         VALUES (1, 'v1', ?1, 'operator', '{}', 1, 'org-a')",
        [T0],
    )
    .unwrap();
    c.execute(
        "INSERT INTO work_proposals (id, title, proposer, status, reporting_mode, created_at, updated_at, org_id) \
         VALUES ('wp_0123456789ab', 'Prop', 'agent-1', 'pending', 'final_only', ?1, ?1, 'org-a')",
        [T0],
    )
    .unwrap();
    c.execute(
        "INSERT INTO task_holds (id, root_task_id, mode, status, reason, release_policy, created_by, created_at, org_id) \
         VALUES (1, 1, 'pause', 'released', 'old', 'manual', 'operator', ?1, 'org-a')",
        [T0],
    )
    .unwrap();
    c.execute(
        "INSERT INTO project_repo_bindings (project, repo, bound_by, bound_at, org_id) \
         VALUES ('alpha-proj', 'example/alpha-repo', 'operator', ?1, 'org-a')",
        [T0],
    )
    .unwrap();
    drop(c);

    let dry = ua_import::dry_run(&f.path).unwrap();
    for tbl in ["harness_config_bundles", "work_proposals", "task_holds", "project_repo_bindings"] {
        assert_eq!(dry.org_scoped_rows.get(tbl), Some(&1), "{:?}", dry.org_scoped_rows);
    }

    let db = target();
    let err = ua_import::import(&db, &f.path, &Options::default()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("harness_config_bundles: 1") && msg.contains("--drop-org-scope"), "{msg}");
    assert_eq!(n(&db, "SELECT COUNT(*) FROM harness_config_bundles"), 0);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM work_proposals"), 0);

    let ok = ua_import::import(&db, &f.path, &opts()).unwrap();
    assert!(ok.notes.iter().any(|note| note.contains("--drop-org-scope")));
    assert_eq!(table(&ok, "task_holds").copied, 1);
    let leaked: Option<String> = db
        .read(|conn| {
            Ok(conn.query_row("SELECT org_id FROM harness_config_bundles WHERE id = 1", [], |r| r.get(0))?)
        })
        .unwrap();
    assert_eq!(leaked, None, "harness_config_bundles.org_id must be dropped to NULL");

    // An all-NULL org_id source imports cleanly without --drop-org-scope.
    let (f_null, c_null) = new_source();
    c_null
        .execute(
            "INSERT INTO harness_config_bundles (id, version, published_at, published_by, bundle_json, active, org_id) \
             VALUES (1, 'v-null', ?1, 'operator', '{}', 1, NULL)",
            [T0],
        )
        .unwrap();
    drop(c_null);
    let db_null = target();
    let clean = ua_import::import(&db_null, &f_null.path, &Options::default()).unwrap();
    assert!(clean.org_scoped_rows.is_empty());
    assert_eq!(table(&clean, "harness_config_bundles").copied, 1);
}

#[tokio::test]
async fn stale_current_run_id_and_orphan_agent_clear_and_unblock_queue_park() {
    let t_fresh = ua_core::time::now();
    let (f, c) = new_source();
    c.execute_batch(&format!(
        "INSERT INTO agents (label, kind, created_at, updated_at) VALUES ('agent-1', 'claude', '{T0}', '{T0}');
         INSERT INTO tasks (id, title, status, created_at, updated_at, current_run_id, current_run_agent) VALUES
           (1, 'Stale task with dangling run', 'open', '{T_OLD}', '{T_OLD}', 'run-stale-1', 'agent-1'),
           (2, 'Orphan run agent task', 'open', '{t_fresh}', '{t_fresh}', NULL, 'agent-1'),
           (3, 'Fresh claimable task', 'open', '{t_fresh}', '{t_fresh}', NULL, NULL);"
    ))
    .unwrap();
    drop(c);

    let db = target();
    let r = ua_import::import(&db, &f.path, &opts()).unwrap();
    assert_eq!(table(&r, "tasks").dangling_refs_nulled, 2);
    assert!(
        r.notes
            .iter()
            .any(|note| note.contains("2 task(s) had stale current_run_id/current_run_agent cleared")),
        "{:?}",
        r.notes
    );
    for id in [1, 2] {
        let run_cols: (Option<String>, Option<String>) = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT current_run_id, current_run_agent FROM tasks WHERE id = ?1",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?)
            })
            .unwrap();
        assert_eq!(run_cols, (None, None), "task {id}");
    }

    let hub = Hub::new(Config::for_home(std::env::temp_dir()), db.clone());
    let reg = builtin_registry();
    let health = reg
        .call(
            &hub,
            &human_coordinator(),
            "coordination_manage",
            json!({ "action": "queue_health", "params": { "stale_days": 30 } }),
        )
        .await
        .unwrap();
    assert_eq!(health["stale"], json!(1), "{health}");
    assert_eq!(health["stale_actionable"], json!(1), "{health}");

    let parked = reg
        .call(
            &hub,
            &human_coordinator(),
            "coordination_manage",
            json!({ "action": "queue_park", "params": { "task_id": 1, "reason": "stale cleanup" } }),
        )
        .await
        .unwrap();
    assert_eq!(parked["parked"], json!(1), "{parked}");

    let err = reg.call(&hub, &agent("agent-1"), "task_claim", json!({ "id": 1 })).await.unwrap_err();
    assert_eq!(err.reason_code(), Some("task_parked"), "{err:?}");

    let claimed = reg.call(&hub, &agent("agent-1"), "task_claim", json!({ "id": 3 })).await.unwrap();
    assert_eq!(claimed["claimed"], json!(true), "{claimed}");
}

#[tokio::test]
async fn work_proposals_preserve_contracts_coerce_defaults_and_recover() {
    let (f, c) = new_source();
    let scope = json!({ "files": ["src/lib.rs"], "repo": "example/repo" });
    // Deliberately non-canonical key order / spacing for item 0 to verify byte-identical copy.
    let noncanonical_scope = r#"{"repo": "example/repo", "files": ["src/lib.rs"]}"#;
    let scope_json = canonical::to_string(&scope);
    let d_ok = contract_digest("Approved contract", "Follow spec", &scope);
    let n_ok = contract_notes("Follow spec", noncanonical_scope, "wp_0123456789ab", 0, &d_ok, "final_only");

    let d_drift = contract_digest("Frozen title", "Original spec", &scope);
    let n_drift = contract_notes("Original spec", &scope_json, "wp_0123456789ab", 1, &d_drift, "final_only");

    let d_fwd = contract_digest("Interrupted approval forward", "Spawned before crash", &scope);
    let n_fwd =
        contract_notes("Spawned before crash", &scope_json, "wp_fedcba987654", 1, &d_fwd, "final_only");
    let d_back = contract_digest("Interrupted approval rollback", "Never spawned", &scope);

    c.execute(
        "INSERT INTO tasks (id, title, notes, status, created_at, updated_at) VALUES \
         (10, 'Approved contract', ?1, 'open', ?4, ?4), \
         (11, 'Drifted title', ?2, 'open', ?4, ?4), \
         (12, 'Interrupted approval forward', ?3, 'open', ?4, ?4)",
        params![n_ok, n_drift, n_fwd, T0],
    )
    .unwrap();
    c.execute(
        "INSERT INTO work_proposals (id, title, proposer, status, reporting_mode, created_at, updated_at) VALUES \
         ('wp_0123456789ab', 'Prop A', 'agent-1', 'pending', 'final_only', ?1, ?1), \
         ('wp_fedcba987654', 'Prop B', 'agent-1', NULL, NULL, ?1, ?1)",
        [T0],
    )
    .unwrap();
    c.execute(
        "INSERT INTO work_proposal_items \
         (proposal_id, idx, title, notes, scope_json, priority, status, filed_digest, contract_digest, edited, approving_by, approving_at, decided_by, decided_at, task_id) \
         VALUES \
         ('wp_0123456789ab', 0, 'Approved contract', 'Follow spec', ?1, 'high', 'approved', ?2, ?2, 0, 'operator', ?3, 'operator', ?3, 10), \
         ('wp_0123456789ab', 1, 'Frozen title', 'Original spec', ?4, 'med', 'approved', ?5, ?5, 0, 'operator', ?3, 'operator', ?3, 11), \
         ('wp_0123456789ab', 2, 'Null defaults item', NULL, NULL, NULL, NULL, 'fd', 'cd', NULL, NULL, NULL, NULL, NULL, NULL), \
         ('wp_fedcba987654', 0, 'Interrupted approval rollback', 'Never spawned', ?4, 'med', 'approving', ?6, ?6, 0, 'operator', ?7, NULL, NULL, NULL), \
         ('wp_fedcba987654', 1, 'Interrupted approval forward', 'Spawned before crash', ?4, 'med', 'approving', ?8, ?8, 0, 'operator', ?7, NULL, NULL, NULL), \
         ('wp_missing0000', 0, 'Orphaned item', 'No parent proposal', ?4, 'med', 'pending', 'fd', 'cd', 0, NULL, NULL, NULL, NULL, NULL)",
        params![noncanonical_scope, d_ok, T0, scope_json, d_drift, d_back, T_OLD, d_fwd],
    )
    .unwrap();
    drop(c);

    let db = target();
    let r = ua_import::import(&db, &f.path, &opts()).unwrap();
    assert_eq!(table(&r, "work_proposal_items").copied, 5);
    assert_eq!(table(&r, "work_proposal_items").skipped.get("missing_proposal_id"), Some(&1));

    // Verify byte-identical preservation of non-canonical scope_json on item 0.
    let copied_scope: String = db
        .read(|conn| {
            Ok(conn.query_row(
                "SELECT scope_json FROM work_proposal_items WHERE proposal_id = 'wp_0123456789ab' AND idx = 0",
                [],
                |row| row.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(copied_scope, noncanonical_scope);

    // Check NULL -> DEFAULT coercions landed cleanly.
    let item2: (String, String, String, String, i64) = db
        .read(|conn| {
            Ok(conn.query_row(
                "SELECT notes, scope_json, priority, status, edited FROM work_proposal_items \
                 WHERE proposal_id = 'wp_0123456789ab' AND idx = 2",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )?)
        })
        .unwrap();
    assert_eq!(item2, ("".into(), "{}".into(), "med".into(), "pending".into(), 0));

    let hub = Hub::new(Config::for_home(std::env::temp_dir()), db.clone());
    let reg = builtin_registry();

    // Exact frozen contract passes claim.
    let ok = reg.call(&hub, &agent("agent-1"), "task_claim", json!({ "id": 10 })).await.unwrap();
    assert_eq!(ok["claimed"], json!(true), "{ok}");

    // Drifted title fails closed with contract_mismatch.
    let err = reg.call(&hub, &agent("agent-1"), "task_claim", json!({ "id": 11 })).await.unwrap_err();
    assert_eq!(err.reason_code(), Some("contract_mismatch"), "{err:?}");

    // Interrupted `approving` items settle cleanly via work_proposal_recover.
    let rec = reg
        .call(
            &hub,
            &human_coordinator(),
            "coordination_manage",
            json!({ "action": "work_proposal_recover", "params": { "older_than_s": 300 } }),
        )
        .await
        .unwrap();
    assert_eq!(rec["recovered_forward"].as_array().unwrap().len(), 1, "{rec}");
    assert_eq!(rec["recovered_forward"][0]["task_id"], json!(12));
    assert_eq!(rec["rolled_back"].as_array().unwrap().len(), 1, "{rec}");
    assert_eq!(rec["rolled_back"][0]["index"], json!(0));

    let ok12 = reg.call(&hub, &agent("agent-1"), "task_claim", json!({ "id": 12 })).await.unwrap();
    assert_eq!(ok12["claimed"], json!(true), "{ok12}");
    assert!(db.read(ledger::verify).unwrap().ok);
}

#[tokio::test]
async fn task_holds_coerce_defaults_block_claim_and_resume_unblocks() {
    let (f, c) = new_source();
    c.execute_batch(&format!(
        "INSERT INTO tasks (id, title, status, created_at, updated_at) VALUES (20, 'Held task', 'open', '{T0}', '{T0}');
         INSERT INTO task_holds (id, root_task_id, mode, status, reason, release_policy, created_by, created_at, released_by, released_at) VALUES
           (1, 20, 'pause', NULL, NULL, NULL, 'operator', '{T0}', NULL, NULL),
           (2, 20, 'pause', 'released', 'past', 'manual', 'operator', '{T_OLD}', 'operator', '{T_OLD}'),
           (3, 999, 'pause', 'active', 'orphan hold', 'manual', 'operator', '{T0}', NULL, NULL);
         INSERT INTO task_hold_members (hold_id, task_id, status_at_hold, cancel_requested_by_hold) VALUES
           (1, 20, 'open', NULL),
           (1, 999, 'open', 0);"
    ))
    .unwrap();
    drop(c);

    let db = target();
    let r = ua_import::import(&db, &f.path, &opts()).unwrap();
    assert_eq!(table(&r, "task_holds").copied, 2);
    assert_eq!(table(&r, "task_holds").skipped.get("missing_root_task_id"), Some(&1));
    assert_eq!(table(&r, "task_hold_members").copied, 1);
    assert_eq!(table(&r, "task_hold_members").skipped.get("missing_task_id"), Some(&1));

    let coerced: (String, String, String, i64) = db
        .read(|conn| {
            Ok(conn.query_row(
                "SELECT h.status, h.reason, h.release_policy, m.cancel_requested_by_hold \
                 FROM task_holds h JOIN task_hold_members m ON m.hold_id = h.id WHERE h.id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?)
        })
        .unwrap();
    assert_eq!(coerced, ("active".into(), "".into(), "manual".into(), 0));

    let hub = Hub::new(Config::for_home(std::env::temp_dir()), db.clone());
    let reg = builtin_registry();

    let held = reg.call(&hub, &agent("agent-1"), "task_claim", json!({ "id": 20 })).await.unwrap_err();
    assert_eq!(held.reason_code(), Some("task_held"), "{held:?}");

    let resumed = reg
        .call(
            &hub,
            &human_coordinator(),
            "coordination_manage",
            json!({
                "action": "task_hold",
                "params": { "root_task_id": 20, "mode": "resume", "reason": "resumed after cutover" }
            }),
        )
        .await
        .unwrap();
    assert_eq!(resumed["released"], json!(true), "{resumed}");

    let claimed = reg.call(&hub, &agent("agent-1"), "task_claim", json!({ "id": 20 })).await.unwrap();
    assert_eq!(claimed["claimed"], json!(true), "{claimed}");
}

#[test]
fn task_holds_duplicate_active_root_refuses_before_writing() {
    // 1. Intra-source duplicate active holds.
    let (f1, c1) = new_source();
    c1.execute_batch(&format!(
        "INSERT INTO tasks (id, title, status, created_at, updated_at) VALUES (20, 'T', 'open', '{T0}', '{T0}');
         INSERT INTO task_holds (id, root_task_id, mode, status, reason, release_policy, created_by, created_at) VALUES
           (1, 20, 'pause', 'active', 'first', 'manual', 'operator', '{T0}'),
           (2, 20, 'pause', NULL, 'second', 'manual', 'operator', '{T0}');"
    ))
    .unwrap();
    drop(c1);

    let db1 = target();
    let err1 = ua_import::import(&db1, &f1.path, &opts()).unwrap_err();
    let msg1 = format!("{err1:#}");
    assert!(msg1.contains("multiple") || msg1.contains("active holds"), "{msg1}");
    assert_eq!(n(&db1, "SELECT COUNT(*) FROM tasks"), 0);
    assert_eq!(n(&db1, "SELECT COUNT(*) FROM task_holds"), 0);

    // 2. Partial-unique index overlap against target DB (distinct PK ids, same active root_task_id).
    let (f2, c2) = new_source();
    c2.execute_batch(&format!(
        "INSERT INTO tasks (id, title, status, created_at, updated_at) VALUES (20, 'T', 'open', '{T0}', '{T0}');
         INSERT INTO task_holds (id, root_task_id, mode, status, reason, release_policy, created_by, created_at) VALUES
           (1, 20, 'pause', 'active', 'src hold', 'manual', 'operator', '{T0}');"
    ))
    .unwrap();
    drop(c2);

    let db2 = target();
    db2.write(|tx| {
        tx.execute(
            "INSERT INTO task_holds (id, root_task_id, mode, status, reason, release_policy, created_by, created_at) \
             VALUES (999, 20, 'pause', 'active', 'native hold', 'manual', 'operator', ?1)",
            [T0],
        )?;
        Ok(())
    })
    .unwrap();
    let err2 = ua_import::import(&db2, &f2.path, &opts()).unwrap_err();
    let msg2 = format!("{err2:#}");
    assert!(msg2.contains("active hold") && msg2.contains("nothing was written"), "{msg2}");
    assert_eq!(n(&db2, "SELECT COUNT(*) FROM tasks"), 0, "earlier tables must not be written");
    assert_eq!(n(&db2, "SELECT COUNT(*) FROM task_holds"), 1);
}

#[tokio::test]
async fn project_repo_bindings_normalize_validate_branch_and_refuse_overlaps() {
    let (f, c) = new_source();
    c.execute_batch(&format!(
        "INSERT INTO project_repo_bindings (project, repo, default_branch, bound_by, bound_at) VALUES
           (' alpha-proj ', 'https://github.com/Example/Alpha-Repo.git', ' main ', 'operator', '{T0}'),
           ('beta-proj', 'git@github.com:Example/Beta-Repo.git', '', 'operator', '{T0}'),
           ('gamma-proj', 'ssh://git@github.com/Example/Gamma.git', NULL, 'operator', '{T0}'),
           ('bad-host', 'https://gitlab.example.com/owner/repo.git', NULL, 'operator', '{T0}'),
           ('bad-branch', 'owner/repo', '--orphan', 'operator', '{T0}'),
           ('-bad-slug', 'owner/repo', NULL, 'operator', '{T0}');"
    ))
    .unwrap();
    drop(c);

    let dry = ua_import::dry_run(&f.path).unwrap();
    let b_dry = table(&dry, "project_repo_bindings");
    assert_eq!(b_dry.copied, 3);
    assert_eq!(b_dry.skipped.get("invalid_repo"), Some(&1));
    assert_eq!(b_dry.skipped.get("invalid_default_branch"), Some(&1));
    assert_eq!(b_dry.skipped.get("invalid_project"), Some(&1));

    let db = target();
    let r = ua_import::import(&db, &f.path, &opts()).unwrap();
    assert_eq!(table(&r, "project_repo_bindings").copied, 3);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM project_repo_bindings"), 3);

    let hub = Hub::new(Config::for_home(std::env::temp_dir()), db.clone());
    let reg = builtin_registry();
    let dev = agent("agent-1");

    let alpha = reg
        .call(
            &hub,
            &dev,
            "coordination_manage",
            json!({ "action": "project_repo_get", "params": { "project": "alpha-proj" } }),
        )
        .await
        .unwrap();
    assert_eq!(alpha["binding"]["repo"], json!("example/alpha-repo"), "{alpha}");
    assert_eq!(alpha["binding"]["default_branch"], json!("main"), "{alpha}");

    let beta = reg
        .call(
            &hub,
            &dev,
            "coordination_manage",
            json!({ "action": "project_repo_get", "params": { "project": "beta-proj" } }),
        )
        .await
        .unwrap();
    assert_eq!(beta["binding"]["repo"], json!("example/beta-repo"), "{beta}");
    assert_eq!(beta["binding"]["default_branch"], Value::Null, "{beta}");

    let gamma = reg
        .call(
            &hub,
            &dev,
            "coordination_manage",
            json!({ "action": "project_repo_get", "params": { "project": "gamma-proj" } }),
        )
        .await
        .unwrap();
    assert_eq!(gamma["binding"]["repo"], json!("example/gamma"), "{gamma}");

    // Idempotent rerun copies 0 rows.
    let rerun = ua_import::import(&db, &f.path, &opts()).unwrap();
    assert!(rerun.tables.iter().all(|t| t.copied == 0), "{:?}", rerun.tables);

    // Intra-source duplicate trimmed project slug refuses before writing.
    let (f_dup, c_dup) = new_source();
    c_dup
        .execute_batch(&format!(
            "INSERT INTO tasks (id, title, status, created_at, updated_at) VALUES (1, 'T', 'open', '{T0}', '{T0}');
             INSERT INTO project_repo_bindings (project, repo, bound_by, bound_at) VALUES
               (' alpha-proj ', 'owner/repo', 'operator', '{T0}'),
               ('alpha-proj', 'owner/other', 'operator', '{T0}');"
        ))
        .unwrap();
    drop(c_dup);
    let db_dup = target();
    let err_dup = ua_import::import(&db_dup, &f_dup.path, &opts()).unwrap_err();
    assert!(format!("{err_dup:#}").contains("duplicate project slug"));
    assert_eq!(n(&db_dup, "SELECT COUNT(*) FROM tasks"), 0);

    // Target trimmed PK overlap refuses before writing.
    let (f_hit, c_hit) = new_source();
    c_hit
        .execute_batch(&format!(
            "INSERT INTO tasks (id, title, status, created_at, updated_at) VALUES (1, 'T', 'open', '{T0}', '{T0}');
             INSERT INTO project_repo_bindings (project, repo, bound_by, bound_at) VALUES
               (' alpha-proj ', 'owner/repo', 'operator', '{T0}');"
        ))
        .unwrap();
    drop(c_hit);
    let db_hit = target();
    db_hit
        .write(|tx| {
            tx.execute(
                "INSERT INTO project_repo_bindings (project, repo, bound_by, bound_at) \
                 VALUES ('alpha-proj', 'owner/native', 'operator', ?1)",
                [T0],
            )?;
            Ok(())
        })
        .unwrap();
    let err_hit = ua_import::import(&db_hit, &f_hit.path, &opts()).unwrap_err();
    let msg_hit = format!("{err_hit:#}");
    assert!(msg_hit.contains("already holds a row"), "{msg_hit}");
    assert_eq!(n(&db_hit, "SELECT COUNT(*) FROM tasks"), 0);
    assert_eq!(n(&db_hit, "SELECT COUNT(*) FROM project_repo_bindings"), 1);
}

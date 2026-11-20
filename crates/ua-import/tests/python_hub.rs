//! Import a small Python-shaped hub database.
//!
//! The fixture keeps the tables, columns and ledger rows these tests read.
//! `org_id`, `agent_kind` and `device_node` are columns ua-rust does not store,
//! so the unmapped-column report has something to count. The three-event
//! ledger is hashed with the shared hash function, the first entry against
//! the reference value computed by the original implementation.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_import::{Options, Report};
use ua_store::Db;
use ua_store::ledger::{self, EventInput};
use ua_tools::{Hub, builtin_registry};

const PY_SCHEMA: &str = "
CREATE TABLE agents (
  label TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  known INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE agent_tokens (
  id INTEGER PRIMARY KEY,
  agent_label TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  hash_algo TEXT NOT NULL,
  status TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  rotated_from INTEGER,
  org_id TEXT,
  agent_kind TEXT
);
CREATE TABLE tasks (
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL,
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  parent_id INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  archived_at TEXT,
  org_id TEXT
);
CREATE TABLE task_dependencies (
  task_id INTEGER NOT NULL,
  depends_on_task_id INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE task_comments (
  task_id INTEGER NOT NULL,
  author TEXT NOT NULL,
  body TEXT NOT NULL,
  thread_revision INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE task_comment_threads (
  task_id INTEGER PRIMARY KEY,
  revision INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE goals (
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE task_goal_links (
  task_id INTEGER PRIMARY KEY,
  goal_id INTEGER NOT NULL,
  linked_at TEXT NOT NULL
);
CREATE TABLE plans (
  id TEXT PRIMARY KEY,
  goal TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE plan_steps (
  plan_id TEXT NOT NULL,
  step_idx INTEGER NOT NULL,
  description TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE plan_checkpoints (
  plan_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE delegations (
  from_agent TEXT NOT NULL,
  to_agent TEXT NOT NULL,
  task_id INTEGER NOT NULL,
  task_spec TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE memory (
  id TEXT PRIMARY KEY,
  title TEXT,
  content TEXT NOT NULL,
  tags TEXT NOT NULL,
  author TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE VIRTUAL TABLE memory_fts USING fts5(title, content);
CREATE TABLE memory_versions (
  note_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  content TEXT NOT NULL,
  tags TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  recorded_at TEXT NOT NULL
);
CREATE TABLE memory_embeddings (
  note_id TEXT PRIMARY KEY
);
CREATE TABLE approvals (
  id INTEGER PRIMARY KEY,
  tool TEXT NOT NULL,
  requested_by TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
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
  entry_hash TEXT
);
CREATE TABLE message_index (
  message_id TEXT NOT NULL,
  recipient TEXT NOT NULL,
  sender TEXT NOT NULL,
  act TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  event_ulid TEXT NOT NULL,
  created_at TEXT NOT NULL,
  event_seq INTEGER
);
CREATE TABLE message_reads (
  message_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  read_at TEXT NOT NULL,
  PRIMARY KEY (message_id, session_id)
);
CREATE TABLE nodes (
  node TEXT PRIMARY KEY,
  agent TEXT NOT NULL,
  device_node TEXT,
  facts_json TEXT,
  version TEXT,
  registered_at TEXT NOT NULL,
  last_heartbeat TEXT,
  updated_at TEXT NOT NULL,
  retired_at TEXT,
  retired_by TEXT,
  retired_reason TEXT,
  heartbeat_floor TEXT
);
CREATE TABLE graph_canvas_scenes (
  board_id TEXT PRIMARY KEY,
  scene_json TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE zulip_cursors (
  bot TEXT NOT NULL
);
";

const T0: &str = "2026-01-01T00:00:00+00:00";

fn sha_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// One ledger row as the Python hub stores it.
struct PyEvent {
    rowid: i64,
    ulid: &'static str,
    channel: &'static str,
    payload: &'static str,
    originator: Option<&'static str>,
    episode_id: Option<&'static str>,
    created_at: &'static str,
    dedupe_key: Option<&'static str>,
}

const EVENTS: [PyEvent; 3] = [
    // Exactly the inputs of the reference hash in ua-store's fixture.
    PyEvent {
        rowid: 5,
        ulid: "01J0000000000000000000000",
        channel: "agent.task.updated",
        payload: "{\"id\": 1, \"t\": \"café\"}",
        originator: Some("builder-1"),
        episode_id: None,
        created_at: T0,
        dedupe_key: None,
    },
    PyEvent {
        rowid: 6,
        ulid: "01J0000000000000000000001",
        channel: "agent.message.inform",
        payload: "{\"message_id\": \"m1\", \"body\": \"hello\", \"hop\": 0}",
        originator: Some("agent-1"),
        episode_id: Some("ep-1"),
        created_at: "2026-01-01T00:00:01+00:00",
        dedupe_key: None,
    },
    PyEvent {
        rowid: 7,
        ulid: "01J0000000000000000000002",
        channel: "agent.task.created",
        payload: "{\"id\": 4}",
        originator: None,
        episode_id: None,
        created_at: "2026-01-01T00:00:02+00:00",
        dedupe_key: Some("task-4-created"),
    },
];

fn insert_event(c: &Connection, e: &PyEvent, prev: Option<&str>) -> String {
    let hash = ledger::compute_entry_hash(
        prev,
        e.ulid,
        e.channel,
        e.payload,
        e.originator,
        e.episode_id,
        None,
        e.created_at,
        e.dedupe_key,
    );
    c.execute(
        "INSERT INTO event_log (rowid, ulid, channel, payload, originator, episode_id, created_at, dedupe_key, \
         prev_hash, entry_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            e.rowid,
            e.ulid,
            e.channel,
            e.payload,
            e.originator,
            e.episode_id,
            e.created_at,
            e.dedupe_key,
            prev.unwrap_or(ledger::GENESIS_HASH),
            hash
        ],
    )
    .unwrap();
    hash
}

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    hashes: Vec<String>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.db");
    let c = Connection::open(&path).unwrap();
    // Dangling references below stand in for rows an older hub left behind.
    c.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    c.execute_batch(PY_SCHEMA).unwrap();
    c.execute_batch(&format!(
        "
INSERT INTO agents (label, kind, known, created_at, updated_at) VALUES
  ('agent-1', 'claude', 1, '{T0}', '{T0}'), ('agent-2', 'codex', 1, '{T0}', '{T0}');
INSERT INTO agent_tokens (id, agent_label, token_hash, hash_algo, status, issued_at, rotated_from) VALUES
  (1, 'agent-1', '{h1}', 'sha256', 'rotated', '{T0}', NULL),
  (2, 'agent-1', '{h2}', 'sha256', 'active', '{T0}', 1),
  (3, 'agent-2', 'pbkdf2$abc', 'pbkdf2', 'active', '{T0}', NULL);
INSERT INTO tasks (id, title, notes, status, parent_id, created_at, updated_at, org_id) VALUES
  (1, 'Root task', 'the quokka plan', 'doing', NULL, '{T0}', '{T0}', 'org-a'),
  (2, 'Child of a later task', NULL, 'open', 4, '{T0}', '{T0}', NULL),
  (3, 'Orphan', NULL, 'open', 99, '{T0}', '{T0}', NULL),
  (4, 'Later parent', NULL, 'open', NULL, '{T0}', '{T0}', NULL);
INSERT INTO task_dependencies (task_id, depends_on_task_id, created_by, created_at) VALUES
  (2, 1, 'agent-1', '{T0}'), (3, 77, 'agent-1', '{T0}');
INSERT INTO task_comment_threads (task_id, revision, updated_at) VALUES (1, 1, '{T0}');
INSERT INTO task_comments (task_id, author, body, thread_revision, created_at) VALUES
  (1, 'agent-1', 'first comment', 1, '{T0}');
INSERT INTO goals (id, title, created_at, updated_at) VALUES (1, 'Ship it', '{T0}', '{T0}');
INSERT INTO task_goal_links (task_id, goal_id, linked_at) VALUES (1, 1, '{T0}');
INSERT INTO plans (id, goal, created_at, updated_at) VALUES ('p1', 'Plan the work', '{T0}', '{T0}');
INSERT INTO plan_steps (plan_id, step_idx, description, created_at, updated_at) VALUES
  ('p1', 0, 'step zero', '{T0}', '{T0}'), ('p1', 1, 'step one', '{T0}', '{T0}');
INSERT INTO plan_checkpoints (plan_id, seq, created_at) VALUES ('p1', 1, '{T0}');
INSERT INTO delegations (from_agent, to_agent, task_id, task_spec, created_at, updated_at) VALUES
  ('agent-1', 'agent-2', 1, '{{}}', '{T0}', '{T0}');
INSERT INTO memory (id, title, content, tags, author, created_at, updated_at) VALUES
  ('note-a', 'Wombat facts', 'wombats have cube shaped droppings', '[\"zoo\"]', 'agent-1', '{T0}', '{T0}'),
  ('note-b', 'Other', 'nothing to see', '[]', 'agent-2', '{T0}', '{T0}');
INSERT INTO memory_versions (note_id, version, content, tags, updated_at, recorded_at) VALUES
  ('note-a', 1, 'old text', '[]', '{T0}', '{T0}');
INSERT INTO memory_embeddings (note_id) VALUES ('note-a');
INSERT INTO approvals (id, tool, requested_by, status, created_at, updated_at) VALUES
  (1, 'fs_write', 'agent-1', 'consumed', '{T0}', '{T0}'),
  (2, 'fs_write', 'agent-1', 'denied', '{T0}', '{T0}'),
  (3, 'fs_write', 'agent-1', 'pending', '{T0}', '{T0}'),
  (4, 'fs_write', 'agent-1', 'approved', '{T0}', '{T0}');
INSERT INTO message_index (message_id, recipient, sender, act, conversation_id, event_ulid, created_at, event_seq)
  VALUES ('m1', 'agent-2', 'agent-1', 'inform', 'c1', '{u2}', '{T0}', NULL);
INSERT INTO message_reads (message_id, session_id, read_at) VALUES ('m1', 's1', '{T0}');
INSERT INTO zulip_cursors (bot) VALUES ('bot');
INSERT INTO graph_canvas_scenes (board_id, scene_json, updated_by, updated_at) VALUES
  ('default', '{{\"elements\": []}}', 'agent-1', '{T0}');
INSERT INTO nodes (node, agent, device_node, facts_json, version, registered_at, last_heartbeat, updated_at,
  retired_at, retired_by, retired_reason, heartbeat_floor) VALUES
  ('mac-1', 'agent-1', 'mac-1', '{{\"k\": 1}}', '0.9.1', '{T0}', '{T0}', '{T0}',
   NULL, NULL, NULL, NULL),
  ('old-box', 'agent-2', NULL, NULL, NULL, '{T0}', '{T0}', '{T0}', '{T0}', 'operator', 'decommissioned', '{T0}');
",
        h1 = sha_hex("token-one"),
        h2 = sha_hex("token-two"),
        u2 = EVENTS[1].ulid,
    ))
    .unwrap();
    let mut hashes = Vec::new();
    let mut prev: Option<String> = None;
    for e in &EVENTS {
        let h = insert_event(&c, e, prev.as_deref());
        prev = Some(h.clone());
        hashes.push(h);
    }
    drop(c);
    Fixture { _dir: dir, path, hashes }
}

fn file_sha(p: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(p).unwrap()))
}

fn target() -> Db {
    Db::open_in_memory(&ua_import::schema_parts()).unwrap()
}

fn opts() -> Options {
    Options { drop_org_scope: true, ..Options::default() }
}

fn n(db: &Db, sql: &str) -> i64 {
    db.read(|c| Ok(c.query_row(sql, [], |r| r.get(0))?)).unwrap()
}

fn table<'r>(r: &'r Report, name: &str) -> &'r ua_import::TableReport {
    r.tables.iter().find(|t| t.table == name).unwrap()
}

fn operator() -> Caller {
    Caller {
        label: "operator".into(),
        kind: ActorKind::Human,
        profile: Profile::Operator,
        enforce_profile: false,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

#[test]
fn fixture_ledger_matches_the_python_reference_hash() {
    let f = fixture();
    assert_eq!(f.hashes[0], include_str!("../../ua-store/tests/fixtures/py_hash.txt").trim());
}

#[tokio::test]
async fn import_copies_mapped_tables_and_the_chain_verifies() {
    let f = fixture();
    let before = file_sha(&f.path);
    let db = target();
    let r = ua_import::import(&db, &f.path, &opts()).unwrap();
    assert_eq!(file_sha(&f.path), before, "the source is never written");

    // Counts.
    assert_eq!(n(&db, "SELECT COUNT(*) FROM agents"), 2);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM tasks"), 4);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM task_dependencies"), 1);
    assert_eq!(table(&r, "task_dependencies").skipped.get("missing_depends_on_task_id"), Some(&1));
    assert_eq!(n(&db, "SELECT COUNT(*) FROM task_comments"), 1);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM task_comment_threads"), 1);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM goals"), 1);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM task_goal_links"), 1);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM plans"), 1);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM plan_steps"), 2);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM plan_checkpoints"), 1);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM delegations"), 1);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM memory"), 2);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM memory_versions"), 1);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM message_index"), 1);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM message_reads"), 1);
    assert_eq!(table(&r, "tasks").copied, 4);

    // Nodes: owner, version and retirement move across; host facts do not,
    // since ua-rust stores only facts it bounded itself.
    assert_eq!(n(&db, "SELECT COUNT(*) FROM nodes"), 2);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM nodes WHERE facts_json = '{}'"), 2);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM nodes WHERE node = 'old-box' AND retired_by = 'operator'"), 1);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM nodes WHERE node = 'mac-1' AND version = '0.9.1'"), 1);
    assert_eq!(r.unmapped_columns["nodes"]["device_node"], 1);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM graph_canvas_scenes"), 1);

    // Self references: a forward parent is restored, a dangling one is NULL.
    assert_eq!(n(&db, "SELECT parent_id FROM tasks WHERE id = 2"), 4);
    assert_eq!(n(&db, "SELECT parent_id IS NULL FROM tasks WHERE id = 3"), 1);
    assert_eq!(table(&r, "tasks").dangling_refs_nulled, 1);

    // Tokens: hashes in the verified scheme only.
    assert_eq!(n(&db, "SELECT COUNT(*) FROM agent_tokens"), 2);
    assert_eq!(n(&db, "SELECT rotated_from FROM agent_tokens WHERE id = 2"), 1);
    assert_eq!(table(&r, "agent_tokens").skipped.get("unsupported_token_hash"), Some(&1));
    let stored: String = db
        .read(|c| Ok(c.query_row("SELECT token_hash FROM agent_tokens WHERE id = 2", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(stored, sha_hex("token-two"));

    // Approvals: settled history only, never a live request or pass.
    assert_eq!(n(&db, "SELECT COUNT(*) FROM approvals"), 2);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM approvals WHERE status IN ('pending','approved')"), 0);
    assert_eq!(table(&r, "approvals").skipped.get("live_approval"), Some(&2));

    // Memory keeps ids, and the rebuilt index finds the note.
    let hit: String = db
        .read(|c| {
            Ok(c.query_row(
                "SELECT m.id FROM memory_fts f JOIN memory m ON m.seq = f.rowid WHERE memory_fts MATCH 'wombats'",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(hit, "note-a");
    assert_eq!(n(&db, "SELECT COUNT(*) FROM task_fts WHERE task_fts MATCH 'quokka'"), 1);

    // Message index: the missing event_seq is filled from the imported ledger.
    assert_eq!(n(&db, "SELECT event_seq FROM message_index WHERE message_id = 'm1'"), 6);

    // Ledger: seq, ids and hashes preserved.
    let rows: Vec<(i64, String, String)> = db
        .read(|c| {
            let mut s = c.prepare("SELECT seq, ulid, entry_hash FROM event_log ORDER BY seq")?;
            let v = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
            Ok(v)
        })
        .unwrap();
    let want: Vec<(i64, String, String)> =
        EVENTS.iter().zip(&f.hashes).map(|(e, h)| (e.rowid, e.ulid.to_string(), h.clone())).collect();
    assert_eq!(rows, want);
    let tl = r.target_ledger.as_ref().unwrap();
    assert!(tl.ok && tl.checked == 3, "{tl:?}");

    // Through the governed tool path as well.
    let hub = Hub::new(Config::for_home(std::env::temp_dir()), db.clone());
    let v: Value = builtin_registry().call(&hub, &operator(), "event_log_verify", json!({})).await.unwrap();
    assert_eq!(v["ok"], json!(true), "{v}");
    assert_eq!(v["checked"], json!(3));

    // New native events chain onto the imported head.
    db.write(|tx| ledger::append(tx, EventInput::new("agent.test.after_import", json!({})).by("tester")))
        .unwrap();
    let after = db.read(ledger::verify).unwrap();
    assert!(after.ok && after.checked == 4, "{after:?}");

    // Unmapped columns are reported, with how many values they held.
    assert_eq!(r.unmapped_columns["tasks"]["org_id"], 1);
    assert!(r.unmapped_tables.contains(&"zulip_cursors".to_string()));
    assert!(r.unmapped_tables.contains(&"memory_embeddings".to_string()));
    assert!(r.derived_tables.contains(&"memory_fts".to_string()));
}

#[test]
fn rerun_is_idempotent_and_resumes_from_the_last_key() {
    let f = fixture();
    let db = target();
    // Batches of one row exercise the per-batch progress records.
    let opts = Options { batch_size: 1, ..opts() };
    ua_import::import(&db, &f.path, &opts).unwrap();
    let snapshot = |db: &Db| {
        ["tasks", "memory", "event_log", "approvals", "agent_tokens", "message_index"]
            .map(|t| n(db, &format!("SELECT COUNT(*) FROM {t}")))
    };
    let first = snapshot(&db);

    let again = ua_import::import(&db, &f.path, &opts).unwrap();
    assert_eq!(snapshot(&db), first);
    assert!(again.tables.iter().all(|t| t.copied == 0), "{:?}", again.tables);
    let ev = table(&again, "event_log");
    assert_eq!((ev.already_imported, ev.total_copied, ev.last_key), (3, 3, 7));
    assert_eq!(table(&again, "approvals").total_skipped, 2);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM import_runs WHERE table_name = 'event_log' AND last_key = 7"), 1);

    // The source grows (the Python hub kept running): only new rows move.
    let c = Connection::open(&f.path).unwrap();
    c.execute(
        "INSERT INTO tasks (id, title, created_at, updated_at) VALUES (5, 'Added later', ?1, ?1)",
        [T0],
    )
    .unwrap();
    let e4 = PyEvent {
        rowid: 8,
        ulid: "01J0000000000000000000003",
        channel: "agent.task.created",
        payload: "{\"id\": 5}",
        originator: Some("agent-2"),
        episode_id: None,
        created_at: "2026-01-01T00:00:03+00:00",
        dedupe_key: None,
    };
    insert_event(&c, &e4, Some(&f.hashes[2]));
    drop(c);

    let third = ua_import::import(&db, &f.path, &opts).unwrap();
    assert_eq!(table(&third, "tasks").copied, 1);
    assert_eq!(table(&third, "event_log").copied, 1);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM tasks"), 5);
    let tl = third.target_ledger.unwrap();
    assert!(tl.ok && tl.checked == 4, "{tl:?}");
}

const DATA_TABLES: [&str; 6] = ["tasks", "memory", "event_log", "agents", "approvals", "import_runs"];

fn counts(db: &Db) -> Vec<i64> {
    DATA_TABLES.iter().map(|t| n(db, &format!("SELECT COUNT(*) FROM {t}"))).collect()
}

#[test]
fn a_target_with_its_own_events_refuses_before_any_write() {
    let f = fixture();
    let db = target();
    db.write(|tx| ledger::append(tx, EventInput::new("agent.native.event", json!({})))).unwrap();
    let before = counts(&db);
    let err = ua_import::import(&db, &f.path, &opts()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("interleave") && msg.contains("Catch-up imports"), "{msg}");
    assert_eq!(counts(&db), before, "earlier tables must not be written");
}

#[test]
fn a_catch_up_after_the_target_wrote_its_own_events_is_refused_up_front() {
    let f = fixture();
    let db = target();
    ua_import::import(&db, &f.path, &opts()).unwrap();
    db.write(|tx| ledger::append(tx, EventInput::new("agent.native.event", json!({})))).unwrap();
    let c = Connection::open(&f.path).unwrap();
    c.execute("INSERT INTO tasks (id, title, created_at, updated_at) VALUES (5, 'Later', ?1, ?1)", [T0])
        .unwrap();
    drop(c);
    let before = counts(&db);
    let err = ua_import::import(&db, &f.path, &opts()).unwrap_err();
    assert!(format!("{err:#}").contains("Catch-up imports"), "{err:#}");
    assert_eq!(counts(&db), before);
}

#[test]
fn an_id_collision_refuses_before_any_write() {
    let f = fixture();
    let db = target();
    // A row the target already owns, with the key of a source task.
    db.write(|tx| {
        tx.execute(
            "INSERT INTO tasks (id, title, status, created_at, updated_at) VALUES (3, 'Native', 'open', ?1, ?1)",
            [T0],
        )?;
        Ok(())
    })
    .unwrap();
    let before = counts(&db);
    let err = ua_import::import(&db, &f.path, &opts()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("tasks already holds a row") && msg.contains("nothing was written"), "{msg}");
    assert_eq!(counts(&db), before, "agents (copied before tasks) must not be written");
}

#[test]
fn org_scoped_rows_refuse_unless_the_scope_is_dropped() {
    let f = fixture();
    let db = target();
    let err = ua_import::import(&db, &f.path, &Options::default()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("tasks: 1") && msg.contains("--drop-org-scope"), "{msg}");
    assert_eq!(counts(&db), vec![0; DATA_TABLES.len()]);

    let r = ua_import::import(&db, &f.path, &opts()).unwrap();
    assert_eq!(r.org_scoped_rows.get("tasks"), Some(&1));
    assert_eq!(n(&db, "SELECT COUNT(*) FROM tasks"), 4);
}

#[test]
fn the_dry_run_reports_org_scope_either_way() {
    let f = fixture();
    let r = ua_import::dry_run(&f.path).unwrap();
    assert_eq!(r.org_scoped_rows.get("tasks"), Some(&1));
    assert_eq!(r.org_scoped_rows.len(), 1);
}

#[test]
fn dry_run_reports_without_writing() {
    let f = fixture();
    let before = file_sha(&f.path);
    let r = ua_import::dry_run(&f.path).unwrap();
    assert_eq!(file_sha(&f.path), before);
    assert!(r.dry_run && r.target_ledger.is_none());
    assert_eq!(table(&r, "tasks").source_rows, 4);
    assert_eq!(table(&r, "tasks").copied, 4);
    assert_eq!(table(&r, "approvals").copied, 2);
    assert_eq!(table(&r, "approvals").skipped.get("live_approval"), Some(&2));
    assert_eq!(table(&r, "agent_tokens").skipped.get("unsupported_token_hash"), Some(&1));
    assert_eq!(table(&r, "event_log").copied, 3);
    assert!(r.source_ledger.ok && r.source_ledger.checked == 3, "{:?}", r.source_ledger);
    assert_eq!(r.unmapped_tables, ["memory_embeddings", "zulip_cursors"]);
    assert!(r.derived_tables.iter().all(|t| t.starts_with("memory_fts")), "{:?}", r.derived_tables);
    assert_eq!(r.unmapped_columns["agent_tokens"].keys().collect::<Vec<_>>(), ["agent_kind", "org_id"]);
    assert_eq!(r.unmapped_columns["tasks"]["org_id"], 1);
}

#[test]
fn a_tampered_ledger_row_stops_the_import_before_any_write() {
    let f = fixture();
    let c = Connection::open(&f.path).unwrap();
    c.execute(
        "UPDATE event_log SET payload = '{\"message_id\": \"m1\", \"body\": \"forged\"}' WHERE rowid = 6",
        [],
    )
    .unwrap();
    drop(c);

    let dry = ua_import::dry_run(&f.path).unwrap();
    assert!(!dry.source_ledger.ok);
    assert_eq!(dry.source_ledger.first_bad_seq, Some(6));

    let db = target();
    let err = ua_import::import(&db, &f.path, &opts()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("seq 6") && msg.contains("entry_hash"), "{msg}");
    for t in ["tasks", "memory", "event_log", "import_runs"] {
        assert_eq!(n(&db, &format!("SELECT COUNT(*) FROM {t}")), 0, "{t} must stay empty");
    }
}

#[test]
fn an_imported_legacy_prefix_is_recorded_and_verified() {
    let f = fixture();
    let c = Connection::open(&f.path).unwrap();
    // Two rows the Python hub wrote before it hashed its ledger.
    for (rowid, ulid) in [(1, "01HZZZZZZZZZZZZZZZZZZZZZZ1"), (2, "01HZZZZZZZZZZZZZZZZZZZZZZ2")] {
        c.execute(
            "INSERT INTO event_log (rowid, ulid, channel, payload, created_at) \
             VALUES (?1, ?2, 'agent.legacy', '{}', '2025-12-31T00:00:00+00:00')",
            params![rowid, ulid],
        )
        .unwrap();
    }
    drop(c);
    let db = target();
    let r = ua_import::import(&db, &f.path, &opts()).unwrap();
    let tl = r.target_ledger.as_ref().unwrap();
    assert!(tl.ok && tl.checked == 3 && tl.unhashed_legacy_prefix == 2, "{tl:?}");
    assert_eq!(n(&db, "SELECT value FROM ledger_meta WHERE key = 'unhashed_legacy_prefix'"), 2);
    // A further unhashed row ahead of the chain is not explained by the record.
    db.write(|tx| {
        tx.execute(
            "INSERT INTO event_log (seq, ulid, channel, payload, created_at) \
             VALUES (0, '01HZZZZZZZZZZZZZZZZZZZZZZ0', 'forged', '{}', '2025-12-31T00:00:00+00:00')",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    let v = db.read(ledger::verify).unwrap();
    assert!(!v.ok && v.first_bad_seq == Some(0), "{v:?}");
}

#[test]
fn a_hashed_value_that_is_not_text_is_refused() {
    let f = fixture();
    let c = Connection::open(&f.path).unwrap();
    // A BLOB keeps its storage class even in a TEXT column. Its hash input is
    // not defined by the text encoding, so the importer refuses to guess.
    c.execute("UPDATE event_log SET channel = CAST(channel AS BLOB) WHERE rowid = 7", []).unwrap();
    drop(c);
    let err = ua_import::import(&target(), &f.path, &opts()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("seq 7") && msg.contains("byte-exactly"), "{msg}");
}

#[test]
fn a_missing_source_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let err = ua_import::dry_run(&dir.path().join("absent.db")).unwrap_err();
    assert!(err.to_string().contains("does not exist"), "{err}");
}

#[test]
fn python_parking_moves_to_its_own_columns_and_continuity_rows_copy() {
    let f = fixture();
    let c = Connection::open(&f.path).unwrap();
    // Python-hub shapes: parking was archived_at plus a notes line.
    c.execute_batch(&format!(
        "
CREATE TABLE task_workflow (task_id INTEGER PRIMARY KEY, stage TEXT, goal TEXT,
  done_json TEXT NOT NULL, revision INTEGER NOT NULL, updated_by TEXT, updated_at TEXT);
CREATE TABLE task_checks (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL,
  name TEXT NOT NULL, head_sha TEXT NOT NULL, outcome TEXT NOT NULL, grade TEXT NOT NULL,
  recorded_by TEXT NOT NULL, recorded_at TEXT NOT NULL);
CREATE TABLE session_handoff_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
  agent TEXT NOT NULL, task_id INTEGER, done TEXT NOT NULL, next_steps TEXT NOT NULL,
  state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, sealed_at TEXT);
INSERT INTO tasks (id, title, notes, status, parent_id, created_at, updated_at, archived_at) VALUES
  (10, 'Parked epic', 'the spec\n[parked @ 2026-02-01T00:00:00Z by operator] no movement in a month',
   'open', NULL, '{T0}', '{T0}', '{T0}'),
  (11, 'Folded child', '[folded-into: #10 @ 2026-02-01T00:00:00Z by operator] parent #10 parked: no movement',
   'blocked', 10, '{T0}', '{T0}', '{T0}'),
  (12, 'Filed work', '[parked @ 2026-02-01T00:00:00Z by operator] old', 'done', NULL, '{T0}', '{T0}', '{T0}'),
  (13, 'Plain archive', 'archived by hand', 'open', NULL, '{T0}', '{T0}', '{T0}');
INSERT INTO task_workflow (task_id, stage, goal, done_json, revision, updated_by, updated_at) VALUES
  (1, 'implement', 'ship it', '[\"schema\"]', 2, 'agent-1', '{T0}');
INSERT INTO task_checks (task_id, name, head_sha, outcome, grade, recorded_by, recorded_at) VALUES
  (1, 'tests', 'abcdef1', 'pass', 'attested', 'agent-1', '{T0}'),
  (99, 'lint', 'abcdef1', 'pass', 'attested', 'agent-1', '{T0}');
INSERT INTO session_handoff_notes (session_id, agent, task_id, done, next_steps, state, created_at, updated_at,
  sealed_at) VALUES ('s-1', 'agent-1', 1, '[\"a\"]', '[\"b\"]', 'sealed', '{T0}', '{T0}', '{T0}');
"
    ))
    .unwrap();
    drop(c);

    let db = target();
    let r = ua_import::import(&db, &f.path, &opts()).unwrap();
    type Parking = (Option<String>, Option<String>, Option<String>, Option<i64>, Option<String>);
    let parked: Parking = db
        .read(|c| {
            Ok(c.query_row(
                "SELECT parked_at, parked_by, parked_reason, folded_into, archived_at FROM tasks WHERE id = 10",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?)
        })
        .unwrap();
    assert_eq!(
        parked,
        (
            Some("2026-02-01T00:00:00Z".into()),
            Some("operator".into()),
            Some("no movement in a month".into()),
            None,
            None
        )
    );
    assert_eq!(n(&db, "SELECT folded_into FROM tasks WHERE id = 11"), 10);
    assert_eq!(n(&db, "SELECT archived_at IS NULL FROM tasks WHERE id = 11"), 1);
    // Finished archived work stays filed; a plain archive stays archived.
    assert_eq!(n(&db, "SELECT parked_at IS NULL AND archived_at IS NOT NULL FROM tasks WHERE id = 12"), 1);
    assert_eq!(n(&db, "SELECT parked_at IS NULL AND archived_at IS NOT NULL FROM tasks WHERE id = 13"), 1);
    assert!(r.notes.iter().any(|n| n.contains("2 parked task(s)")), "{:?}", r.notes);

    // Workflow records, checks and handoff notes copy by column name.
    assert_eq!(n(&db, "SELECT revision FROM task_workflow WHERE task_id = 1"), 2);
    assert_eq!(n(&db, "SELECT COUNT(*) FROM task_checks"), 1);
    assert_eq!(table(&r, "task_checks").skipped.get("missing_task_id"), Some(&1));
    assert_eq!(n(&db, "SELECT COUNT(*) FROM session_handoff_notes WHERE state = 'sealed'"), 1);

    // A second run changes nothing.
    let again = ua_import::import(&db, &f.path, &opts()).unwrap();
    assert!(!again.notes.iter().any(|n| n.contains("parked task(s)")), "{:?}", again.notes);
}

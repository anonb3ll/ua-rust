//! `idempotency_keys` is tenant data (`docs/organization.md`, "Global keys
//! and table rebuilds").
//!
//! - `idempotency.v2.tenant_keys` rebuilds the table around `(org_id, key)`.
//!   Every row keeps its rowid, key text, tool, result and timestamp; a row
//!   whose key carries the interim prefix of exactly one organization moves
//!   there, every other row lands in the default organization. Nothing is
//!   dropped or rewritten.
//! - `organization.v1.tools.idempotency` adds the organization triggers.
//!
//! Every reader filters on the caller's organization and every writer names
//! it; the writers keep their organization prefix in the key text. A second
//! organization is created at the storage level, as no tool creates one yet,
//! and its callers are built by hand. Every value here is fake.

use std::path::Path;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const PARTS: [&str; 2] = ["idempotency.v2.tenant_keys", "organization.v1.tools.idempotency"];

const ORG_B: &str = "org-b";
/// An organization whose id contains `/`, the separator of a stored key.
const ORG_SLASH: &str = "acme/ops";
/// Two organizations whose unescaped `task_add` prefixes can spell the same
/// key text: `org:acme/task_add:z/task_add:k` is `acme`'s key
/// `z/task_add:k` and `acme/task_add:z`'s key `k`.
const ORG_ACME: &str = "acme";
const ORG_ACME_LONG: &str = "acme/task_add:z";
/// An organization `orgs` does not hold when the upgrade runs.
const GHOST: &str = "ghost";

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

/// The parts a hub had before this conversion: every part up to the first
/// of [`PARTS`] (they are registered last).
fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().take_while(|p| !PARTS.contains(&p.name)).collect()
}

fn org_sql(id: &str) -> String {
    format!(
        "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) VALUES ('{id}', '{id}', 'Org', \
         '[\"developer\",\"coordinator\",\"operator\"]', '2026-01-01T00:00:00+00:00');"
    )
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

fn human(org: &str) -> Caller {
    Caller {
        kind: ActorKind::Human,
        profile: Profile::Operator,
        enforce_profile: false,
        ..agent("operator", org)
    }
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
        let h = Self { hub, reg: builtin_registry(), _dir: dir };
        for org in [ORG_B, ORG_SLASH, ORG_ACME, ORG_ACME_LONG] {
            h.sql(&org_sql(org)).unwrap();
        }
        h
    }

    fn open(cfg: Config) -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self { hub: Hub::open(cfg).unwrap(), reg: builtin_registry(), _dir: dir }
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
            Err(e) => panic!("{}/{}: {tool}({args}) failed: {e:?}", who.org_id, who.label),
        }
    }

    fn count(&self, sql: &str) -> i64 {
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

    /// Every receipt as `org_id|key|tool`, in key order.
    fn rows(&self) -> Vec<String> {
        self.hub
            .db()
            .read(|c| {
                Ok(c.prepare(
                    "SELECT org_id || '|' || key || '|' || tool FROM idempotency_keys ORDER BY key, org_id",
                )?
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?)
            })
            .unwrap()
    }

    async fn doctor_unplaced(&self, who: &Caller) -> Value {
        self.ok(who, "system_doctor", json!({})).await["database"]["idempotency_keys_unplaced"].clone()
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

// --- the upgrade -----------------------------------------------------------------------------

/// Organizations, tasks and receipts as a pre-rebuild hub stored them. Each
/// receipt's `result_json` is a fake stored reply.
fn legacy_rows() -> String {
    let mut sql: String = [ORG_B, ORG_SLASH, ORG_ACME, ORG_ACME_LONG].iter().map(|o| org_sql(o)).collect();
    sql.push_str(
        "
INSERT INTO tasks (id, org_id, title, created_at, updated_at) VALUES (7, 'acme/ops', 'Slash task', 't0', 't0');
INSERT INTO idempotency_keys (rowid, key, tool, result_json, created_at) VALUES
  (11, 'task_add:k1', 'task_add', '{\"id\":101,\"legacy\":\"default\"}', 't1'),
  (12, 'org:org-b/task_add:k1', 'task_add', '{\"id\":102,\"legacy\":\"org-b\"}', 't1'),
  (13, 'org:org-b/memory_save/builder-1/k2', 'memory_save', '{\"id\":\"mem-b\"}', 't1'),
  (14, 'org:acme%2Fops/message_send/courier/m1', 'message_send',
       '{\"accepted\":true,\"message_id\":\"msg-legacy-1\",\"from_agent\":\"courier\"}', 't1'),
  (15, 'org:acme/ops/task_update:builder-1:k3', 'task_update', '{\"id\":7,\"legacy\":\"acme/ops\"}', 't1'),
  (16, 'org:ghost/delegate:lead-1:k4', 'delegate', '{\"digest\":\"x\",\"result\":{\"delegation_id\":4242}}', 't1'),
  (17, 'org:acme/task_add:z/task_add:k', 'task_add', '{\"id\":103,\"legacy\":\"ambiguous\"}', 't1'),
  (18, 'memory_save/builder-1/k5', 'memory_save', '{\"id\":\"mem-a\"}', 't1'),
  (19, 'org:org-b/task_add:k9', 'memory_save', '{\"id\":104}', 't1');
CREATE INDEX idx_legacy_idempotency_tool ON idempotency_keys(tool);
CREATE VIEW v_legacy_idempotency AS SELECT key, tool FROM idempotency_keys;
CREATE TRIGGER legacy_idempotency_touch AFTER INSERT ON idempotency_keys BEGIN SELECT 1; END;
",
    );
    sql
}

/// Every receipt as `rowid|org_id|key|tool|result_json|created_at`.
fn full_rows(c: &rusqlite::Connection) -> Vec<String> {
    let org = if c.prepare("SELECT org_id FROM idempotency_keys").is_ok() {
        "COALESCE(org_id, 'NULL')"
    } else {
        "'-'"
    };
    c.prepare(&format!(
        "SELECT rowid || '|' || {org} || '|' || COALESCE(key, 'NULL') || '|' || tool || '|' || result_json || '|' || created_at \
         FROM idempotency_keys ORDER BY rowid"
    ))
    .unwrap()
    .query_map([], |r| r.get(0))
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

/// A legacy database (every part but this family's) with [`legacy_rows`]
/// and `prepare` run on it, opened with `extra` parts too.
fn legacy(prepare: &str, extra: &[ua_store::Part]) -> (tempfile::TempDir, Config, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.human_identities = vec!["operator".into()];
    let mut parts = old_parts();
    parts.extend_from_slice(extra);
    let db = ua_store::Db::open(&cfg.db_path(), &parts).unwrap();
    let (rows, prepare) = (legacy_rows(), prepare.to_string());
    db.write(move |tx| {
        tx.execute_batch(&rows)?;
        tx.execute_batch(&prepare)?;
        Ok(())
    })
    .unwrap();
    let before = db.read(|c| Ok(full_rows(c))).unwrap();
    (dir, cfg, before)
}

/// The organization each legacy receipt lands in, by rowid.
const PLACED: [(i64, &str); 9] = [
    (11, DEFAULT_ORG),
    (12, ORG_B),
    (13, ORG_B),
    (14, ORG_SLASH),
    (15, ORG_SLASH),
    // `ghost` is not in `orgs`: kept in the default organization.
    (16, DEFAULT_ORG),
    // Both `acme` and `acme/task_add:z` spell this key: ambiguous, kept in
    // the default organization.
    (17, DEFAULT_ORG),
    (18, DEFAULT_ORG),
    // The prefix names `org-b`, but for `task_add`, not this row's tool.
    (19, DEFAULT_ORG),
];

#[tokio::test]
async fn a_legacy_database_places_each_receipt_and_keeps_every_byte() {
    let (_dir, cfg, before) = legacy("", &[]);
    for _ in 0..2 {
        Hub::open(cfg.clone()).unwrap();
    }
    let h = H::open(cfg);
    h.hub
        .db()
        .read(|c| {
            // Nothing dropped; rowid, key, tool, result and timestamp unchanged.
            let after = full_rows(c);
            assert_eq!(after.len(), before.len());
            for (b, a) in before.iter().zip(&after) {
                let (rowid, rest) = b.split_once("|-|").unwrap();
                let rowid: i64 = rowid.parse().unwrap();
                let org = PLACED.iter().find(|(r, _)| *r == rowid).unwrap().1;
                assert_eq!(a, &format!("{rowid}|{org}|{rest}"), "receipt {rowid}");
            }
            // The key is `(org_id, key)` and `org_id` is NOT NULL.
            let pk: Vec<String> = c
                .prepare("SELECT name FROM pragma_table_info('idempotency_keys') WHERE pk > 0 ORDER BY pk")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            assert_eq!(pk, ["org_id", "key"]);
            let notnull: i64 = c.query_row(
                "SELECT \"notnull\" FROM pragma_table_info('idempotency_keys') WHERE name = 'org_id'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(notnull, 1);
            // Triggers, the index and the view survive; the organization
            // triggers are installed.
            let triggers = names(c, "trigger", "idempotency_keys");
            for want in
                ["idempotency_keys_org_exists", "idempotency_keys_org_immutable", "legacy_idempotency_touch"]
            {
                assert!(triggers.iter().any(|t| t == want), "{want}: {triggers:?}");
            }
            assert!(names(c, "index", "idempotency_keys").iter().any(|i| i == "idx_legacy_idempotency_tool"));
            let view: i64 = c.query_row("SELECT COUNT(*) FROM v_legacy_idempotency", [], |r| r.get(0))?;
            assert_eq!(view, 9);
            for p in PARTS {
                let n: i64 =
                    c.query_row("SELECT COUNT(*) FROM schema_parts WHERE name = ?1", [p], |r| r.get(0))?;
                assert_eq!(n, 1, "{p}");
            }
            // The audit record counts what stayed in the default
            // organization under a prefix, by row id, never by key text.
            let generated: String = c.query_row(
                "SELECT generated_sql FROM schema_procedures WHERE name = 'idempotency.v2.tenant_keys'",
                [],
                |r| r.get(0),
            )?;
            assert!(generated.contains("9 row(s) kept; 4 placed in another organization"), "{generated}");
            assert!(generated.contains("(rowid 16, 17, 19)"), "{generated}");
            assert!(!generated.contains("ghost") && !generated.contains("k4"), "{generated}");
            // Nothing was dropped or rewritten, so there is no ledger record.
            let n: i64 = c.query_row("SELECT COUNT(*) FROM event_log", [], |r| r.get(0))?;
            assert_eq!(n, 0);
            Ok(())
        })
        .unwrap();

    // The doctor counts the three receipts kept under an organization prefix,
    // for the default organization only (a hub-wide count).
    assert_eq!(h.doctor_unplaced(&human(DEFAULT_ORG)).await, json!(3));
    assert_eq!(h.doctor_unplaced(&human(ORG_B)).await, Value::Null);
    let doctor = h.ok(&human(DEFAULT_ORG), "system_doctor", json!({})).await;
    let db_row = doctor["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "database").unwrap();
    assert!(db_row["detail"].as_str().unwrap().contains("3 idempotency key(s) kept"), "{db_row}");
}

/// A retry in flight across the upgrade replays its own receipt, in its own
/// organization, through the real tools; a receipt kept in the default
/// organization under an unknown prefix never replays to anyone, even once
/// that organization exists.
#[tokio::test]
async fn pre_upgrade_receipts_replay_only_in_their_own_organization() {
    let (_dir, cfg, _) = legacy("", &[]);
    let h = H::open(cfg);

    let a = agent("builder-1", DEFAULT_ORG);
    let b = agent("builder-1", ORG_B);
    let slash = agent("builder-1", ORG_SLASH);
    let replay = h.ok(&a, "task_add", json!({ "title": "x", "idempotency_key": "k1" })).await;
    assert_eq!(replay, json!({ "id": 101, "legacy": "default" }));
    let replay = h.ok(&b, "task_add", json!({ "title": "x", "idempotency_key": "k1" })).await;
    assert_eq!(replay, json!({ "id": 102, "legacy": "org-b" }));
    let replay =
        h.ok(&slash, "task_update", json!({ "id": 7, "append_note": "x", "idempotency_key": "k3" })).await;
    assert_eq!(replay, json!({ "id": 7, "legacy": "acme/ops" }));
    let replay = h
        .ok(
            &agent("courier", ORG_SLASH),
            "message_send",
            json!({ "act": "inform", "to_agent": "to-x", "body": "x", "message_id": "m1" }),
        )
        .await;
    assert_eq!(replay["message_id"], "msg-legacy-1", "{replay}");
    assert_eq!(replay["duplicate"], true, "{replay}");

    // The ambiguous receipt answers in neither organization that spells it.
    for org in [ORG_ACME, ORG_ACME_LONG] {
        let key = if org == ORG_ACME { "z/task_add:k" } else { "k" };
        let r = h
            .ok(&agent("builder-1", org), "task_add", json!({ "title": "fresh", "idempotency_key": key }))
            .await;
        assert_ne!(r["legacy"], "ambiguous", "{org}: {r}");
        assert!(r["id"].as_i64().is_some_and(|id| id != 103), "{org}: {r}");
    }

    // `ghost` is created after the upgrade: its first delegation with the
    // key the kept receipt carries is fresh.
    h.sql(&org_sql(GHOST)).unwrap();
    let lead = agent("lead-1", GHOST);
    let r = h
        .ok(&lead, "delegate", json!({ "task_spec": SPEC, "to_agent": "builder-1", "idempotency_key": "k4" }))
        .await;
    assert_ne!(r["delegation_id"], 4242, "{r}");
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM delegations WHERE org_id = '{GHOST}' AND id = {}",
            r["delegation_id"]
        )),
        1
    );
    // Both rows exist, one per organization, with the same key text.
    assert_eq!(
        h.rows().into_iter().filter(|r| r.contains("|org:ghost/delegate:lead-1:k4|")).collect::<Vec<_>>(),
        ["default|org:ghost/delegate:lead-1:k4|delegate", "ghost|org:ghost/delegate:lead-1:k4|delegate"]
    );
}

/// The rebuild is crash-safe: re-run on a table it already rebuilt (the
/// process died before recording it), it keeps every row's organization and
/// changes nothing else.
#[tokio::test]
async fn an_interrupted_rebuild_re_runs_without_changing_a_row() {
    let keys: ua_store::Part = ua_tools::families::idempotency::TENANT_KEYS.into();
    // The first run committed; its record is gone. A row the first run
    // placed in organization B, then hand-moved, shows the re-run keeps the
    // stored organization rather than placing it again.
    let (_dir, cfg, rebuilt) = legacy(
        "UPDATE idempotency_keys SET org_id = 'default' WHERE rowid = 13;
         DELETE FROM schema_parts WHERE name = 'idempotency.v2.tenant_keys';
         DELETE FROM schema_procedures WHERE name = 'idempotency.v2.tenant_keys';",
        &[keys],
    );
    assert!(rebuilt.iter().any(|r| r.starts_with("13|default|")), "{rebuilt:?}");
    let h = H::open(cfg);
    assert_eq!(h.hub.db().read(|c| Ok(full_rows(c))).unwrap(), rebuilt);
    assert_eq!(h.count("SELECT COUNT(*) FROM schema_parts WHERE name = 'idempotency.v2.tenant_keys'"), 1);
}

/// A rebuild interrupted with a nullable `org_id` already present keeps a
/// stored organization and places a `NULL` by its prefix.
#[tokio::test]
async fn a_nullable_organization_column_is_kept_or_placed() {
    let (_dir, cfg, _) = legacy(
        "ALTER TABLE idempotency_keys ADD COLUMN org_id TEXT;
         UPDATE idempotency_keys SET org_id = 'default' WHERE rowid = 12;",
        &[],
    );
    let h = H::open(cfg);
    let rows = h.rows();
    assert!(rows.contains(&"default|org:org-b/task_add:k1|task_add".to_string()), "{rows:?}");
    assert!(rows.contains(&"org-b|org:org-b/memory_save/builder-1/k2|memory_save".to_string()), "{rows:?}");
}

/// A row with a NULL key stops the upgrade with its row id and a fix, and
/// changes nothing.
#[tokio::test]
async fn a_null_key_stops_the_upgrade_and_changes_nothing() {
    let (_dir, cfg, before) = legacy(
        "INSERT INTO idempotency_keys (rowid, key, tool, result_json, created_at) VALUES (40, NULL, 'x', '{}', 't');",
        &[],
    );
    let e = Hub::open(cfg.clone()).err().expect("the upgrade must stop").to_string();
    assert!(e.contains("NULL key") && e.contains("rowid 40"), "{e}");
    let after = full_rows(&rusqlite::Connection::open(cfg.db_path()).unwrap());
    assert_eq!(after, before, "the table is unchanged and has no org_id column");
    assert!(after.iter().any(|r| r.starts_with("40|-|NULL|")), "{after:?}");
}

// --- isolation through the tools -------------------------------------------------------------

/// The same key in three organizations (one with `/` in its id), through
/// every tool that stores receipts: each organization's first call is a
/// fresh call and each retry replays only its own receipt.
#[tokio::test]
async fn the_same_key_in_each_organization_replays_only_its_own_receipt() {
    let h = H::new();
    let orgs = [DEFAULT_ORG, ORG_B, ORG_SLASH];
    let mut firsts: Vec<Vec<Value>> = Vec::new();
    for org in orgs {
        let me = agent("builder-1", org);
        let lead = agent("lead-1", org);
        let task =
            h.ok(&me, "task_add", json!({ "title": format!("t {org}"), "idempotency_key": "same" })).await;
        let id = task["id"].as_i64().unwrap();
        let update = h
            .ok(
                &me,
                "task_update",
                json!({ "id": id, "append_note": format!("n {org}"), "idempotency_key": "same" }),
            )
            .await;
        let note = h
            .ok(
                &me,
                "memory_save",
                json!({ "content": format!("fake note {org}"), "idempotency_key": "same" }),
            )
            .await;
        let sent = h
            .ok(
                &me,
                "message_send",
                json!({ "act": "inform", "to_agent": "to-x", "body": "x", "message_id": "same" }),
            )
            .await;
        let delegated = h
            .ok(
                &lead,
                "delegate",
                json!({ "task_spec": SPEC, "to_agent": "builder-1", "idempotency_key": "same" }),
            )
            .await;
        assert_eq!(sent["duplicate"], false, "{org}: a fresh send, not a replay: {sent}");
        firsts.push(vec![task, update, note, sent, delegated]);
    }
    // Every organization got its own task, note, message and delegation.
    for i in [0usize, 2] {
        let ids: Vec<&Value> = firsts.iter().map(|f| &f[i]["id"]).collect();
        assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2], "{ids:?}");
    }
    let mids: Vec<&Value> = firsts.iter().map(|f| &f[3]["message_id"]).collect();
    assert!(mids[0] != mids[1] && mids[1] != mids[2] && mids[0] != mids[2], "{mids:?}");
    let dids: Vec<&Value> = firsts.iter().map(|f| &f[4]["delegation_id"]).collect();
    assert!(dids[0] != dids[1] && dids[1] != dids[2] && dids[0] != dids[2], "{dids:?}");

    // Each retry replays its own receipt.
    for (org, first) in orgs.iter().zip(&firsts) {
        let me = agent("builder-1", org);
        let lead = agent("lead-1", org);
        let id = first[0]["id"].as_i64().unwrap();
        assert_eq!(
            h.ok(&me, "task_add", json!({ "title": "other", "idempotency_key": "same" })).await,
            first[0]
        );
        assert_eq!(
            h.ok(&me, "task_update", json!({ "id": id, "append_note": "other", "idempotency_key": "same" }))
                .await,
            first[1]
        );
        assert_eq!(
            h.ok(
                &me,
                "memory_save",
                json!({ "content": format!("fake note {org}"), "idempotency_key": "same" })
            )
            .await,
            first[2]
        );
        let again = h
            .ok(
                &me,
                "message_send",
                json!({ "act": "inform", "to_agent": "to-x", "body": "x", "message_id": "same" }),
            )
            .await;
        assert_eq!(
            (again["duplicate"].clone(), again["message_id"].clone()),
            (json!(true), first[3]["message_id"].clone())
        );
        assert_eq!(
            h.ok(
                &lead,
                "delegate",
                json!({ "task_spec": SPEC, "to_agent": "builder-1", "idempotency_key": "same" })
            )
            .await,
            first[4]
        );
    }

    // One receipt per organization and tool, each carrying its own
    // organization in the column and in the key text.
    assert_eq!(h.rows(), expected_rows());
}

fn expected_rows() -> Vec<String> {
    let mut rows: Vec<String> = Vec::new();
    // Every writer escapes `%` and `/` in the organization id, so the
    // organization part of a key always ends at the first `/`.
    for (org, prefix) in
        [(DEFAULT_ORG, ""), (ORG_B, "org:org-b/"), (ORG_SLASH, "org:acme%2Fops/")]
    {
        rows.push(format!("{org}|{prefix}delegate:lead-1:same|delegate"));
        rows.push(format!("{org}|{prefix}memory_save/builder-1/same|memory_save"));
        rows.push(format!("{org}|{prefix}message_send/builder-1/same|message_send"));
        rows.push(format!("{org}|{prefix}task_add:same|task_add"));
        rows.push(format!("{org}|{prefix}task_update:builder-1:same|task_update"));
    }
    rows.sort_by(|a, b| {
        let (ao, ak) = a.split_once('|').unwrap();
        let (bo, bk) = b.split_once('|').unwrap();
        (ak, ao).cmp(&(bk, bo))
    });
    rows
}

/// Two organizations whose interim prefixes spelled the same key text (one
/// id is the other's followed by `/task_add:z`) keep two receipts: the
/// organization column tells them apart, and the escaped `/` in the longer
/// id keeps the key texts apart too.
#[tokio::test]
async fn an_organization_id_with_a_slash_never_shares_a_receipt() {
    let h = H::new();
    let short = agent("builder-1", ORG_ACME);
    let long = agent("builder-1", ORG_ACME_LONG);
    let a = h.ok(&short, "task_add", json!({ "title": "acme", "idempotency_key": "z/task_add:k" })).await;
    let b = h.ok(&long, "task_add", json!({ "title": "long", "idempotency_key": "k" })).await;
    assert_ne!(a["id"], b["id"], "a fresh task in each organization");
    assert_eq!(h.ok(&short, "task_add", json!({ "title": "x", "idempotency_key": "z/task_add:k" })).await, a);
    assert_eq!(h.ok(&long, "task_add", json!({ "title": "x", "idempotency_key": "k" })).await, b);
    assert_eq!(
        h.rows(),
        [
            "acme/task_add:z|org:acme%2Ftask_add:z/task_add:k|task_add",
            "acme|org:acme/task_add:z/task_add:k|task_add",
        ]
    );
    for (org, id) in [(ORG_ACME, &a["id"]), (ORG_ACME_LONG, &b["id"])] {
        assert_eq!(h.count(&format!("SELECT COUNT(*) FROM tasks WHERE org_id = '{org}' AND id = {id}")), 1);
    }
}

/// A receipt an organization with `/` in its id stored before organization
/// ids were escaped (`org:acme/ops/…`) still replays there, through
/// `task_add`, `task_update`, `delegate` and the delegation lookup, while new
/// receipts are stored escaped (`org:acme%2Fops/…`).
#[tokio::test]
async fn an_interim_unescaped_receipt_still_replays_in_its_organization() {
    let h = H::new();
    let me = agent("builder-1", ORG_SLASH);
    let lead = agent("lead-1", ORG_SLASH);
    let task = h.ok(&me, "task_add", json!({ "title": "slash", "idempotency_key": "i1" })).await;
    let id = task["id"].as_i64().unwrap();
    let update =
        h.ok(&me, "task_update", json!({ "id": id, "append_note": "n", "idempotency_key": "i2" })).await;
    let delegated = h
        .ok(&lead, "delegate", json!({ "task_spec": SPEC, "to_agent": "builder-1", "idempotency_key": "i3" }))
        .await;
    assert_eq!(
        h.rows(),
        [
            "acme/ops|org:acme%2Fops/delegate:lead-1:i3|delegate",
            "acme/ops|org:acme%2Fops/task_add:i1|task_add",
            "acme/ops|org:acme%2Fops/task_update:builder-1:i2|task_update",
        ]
    );
    // Rewrite each receipt to the interim, unescaped form.
    h.sql("UPDATE idempotency_keys SET key = replace(key, 'org:acme%2Fops/', 'org:acme/ops/')").unwrap();
    assert_eq!(h.count("SELECT COUNT(*) FROM idempotency_keys WHERE key LIKE 'org:acme/ops/%'"), 3);
    assert_eq!(h.ok(&me, "task_add", json!({ "title": "other", "idempotency_key": "i1" })).await, task);
    assert_eq!(
        h.ok(&me, "task_update", json!({ "id": id, "append_note": "other", "idempotency_key": "i2" })).await,
        update
    );
    assert_eq!(
        h.ok(&lead, "delegate", json!({ "task_spec": SPEC, "to_agent": "builder-1", "idempotency_key": "i3" }))
            .await,
        delegated
    );
    let found = h
        .ok(&lead, "delegation_manage", json!({ "action": "lookup", "params": { "idempotency_key": "i3" } }))
        .await;
    assert_eq!(found["state"], "committed", "{found}");
    assert_eq!(found["result"]["delegation_id"], delegated["delegation_id"], "{found}");
    // No second receipt was written: every retry replayed.
    assert_eq!(h.count("SELECT COUNT(*) FROM idempotency_keys"), 3);
    assert_eq!(h.count("SELECT COUNT(*) FROM tasks WHERE org_id = 'acme/ops' AND title = 'other'"), 0);
}

/// The lifecycle capture key is the caller's organization's too.
#[tokio::test]
async fn a_lifecycle_capture_key_is_per_organization() {
    let h = H::new();
    let args =
        json!({ "kind": "tool_start", "session_id": "s-1", "tool": "fs_read", "idempotency_key": "same" });
    let a = h.ok(&agent("builder-1", DEFAULT_ORG), "lifecycle_record", args.clone()).await;
    let b = h.ok(&agent("builder-1", ORG_B), "lifecycle_record", args.clone()).await;
    assert_eq!((a["accepted"].clone(), a["duplicate"].clone()), (json!(true), json!(false)), "{a}");
    assert_eq!((b["accepted"].clone(), b["duplicate"].clone()), (json!(true), json!(false)), "{b}");
    assert_ne!(a["event_id"], b["event_id"]);
    let again = h.ok(&agent("builder-1", ORG_B), "lifecycle_record", args).await;
    assert_eq!((again["duplicate"].clone(), again["event_id"].clone()), (json!(true), b["event_id"].clone()));
    assert_eq!(h.count("SELECT COUNT(*) FROM idempotency_keys WHERE tool = 'lifecycle_record'"), 2);
}

// --- triggers and the insert guard -------------------------------------------------------------

#[tokio::test]
async fn the_organization_triggers_refuse_bad_rows() {
    let h = H::new();
    let e = h
        .sql(
            "INSERT INTO idempotency_keys (org_id, key, tool, result_json, created_at) \
             VALUES ('missing-org', 'k', 'task_add', '{}', 't')",
        )
        .unwrap_err();
    assert!(e.contains("unknown organization"), "{e}");
    h.sql(
        "INSERT INTO idempotency_keys (org_id, key, tool, result_json, created_at) \
         VALUES ('org-b', 'k', 'task_add', '{}', 't')",
    )
    .unwrap();
    let e = h.sql("UPDATE idempotency_keys SET org_id = 'default' WHERE key = 'k'").unwrap_err();
    assert!(e.contains("org_id cannot change"), "{e}");
    // The same key text in two organizations is two rows; twice in one is refused.
    h.sql(
        "INSERT INTO idempotency_keys (org_id, key, tool, result_json, created_at) \
         VALUES ('default', 'k', 'task_add', '{}', 't')",
    )
    .unwrap();
    let e = h
        .sql(
            "INSERT INTO idempotency_keys (org_id, key, tool, result_json, created_at) \
             VALUES ('org-b', 'k', 'task_add', '{}', 't')",
        )
        .unwrap_err();
    assert!(e.contains("UNIQUE"), "{e}");
}

/// Every `INSERT INTO idempotency_keys` in the tool and memory crates names
/// `org_id` (`org_classification.rs` checks the same over the whole tree
/// now that the table left `TENANT_MISSING_ORG_ID`; this one names the
/// writers' crates and counts them).
#[test]
fn every_insert_into_idempotency_keys_names_org_id() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    let mut stack = vec![manifest.join("src"), manifest.join("../ua-memory/src")];
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
        for (i, _) in flat.match_indices("INSERT INTO idempotency_keys ") {
            let cols = flat[i + "INSERT INTO idempotency_keys ".len()..].trim_start();
            let Some(cols) = cols.strip_prefix('(') else {
                panic!("{}: INSERT INTO idempotency_keys has no column list", f.display())
            };
            let cols = &cols[..cols.find(')').unwrap_or(cols.len())];
            seen += 1;
            assert!(
                cols.contains("org_id"),
                "{}: INSERT INTO idempotency_keys ({cols}) does not name org_id",
                f.display()
            );
        }
    }
    // tasks, delegation, messaging, agents (lifecycle) and memory.
    assert!(seen >= 5, "the guard found {seen} inserts");
}

// --- the read guard ----------------------------------------------------------------------------

// The source scanner shared with `ua-core`'s guard tests.
#[path = "../../ua-core/tests/support/mod.rs"]
mod support;

/// The whole-table statements of the `idempotency.v2.tenant_keys` rebuild,
/// which reads every organization's rows by design (it counts, checks and
/// copies them). `(file suffix, statement from the table reference to the
/// end of its string literal)`, whitespace collapsed and lower-cased.
const UNSCOPED_ALLOWED: &[(&str, &str)] = &[
    ("ua-tools/src/families/idempotency.rs", "from idempotency_keys"),
    ("ua-tools/src/families/idempotency.rs", "from idempotency_keys where key is null order by rowid"),
    ("ua-tools/src/families/idempotency.rs", "from idempotency_keys k;"),
];

/// Every statement in `src` that reads, updates or deletes `idempotency_keys`
/// (`FROM`, `JOIN` or `UPDATE`) without naming `org_id`: the text from the
/// table reference to the end of its string literal, whitespace collapsed
/// and lower-cased. SQL is matched case-insensitively, and a statement split
/// over lines with `\` continuations is read as one.
fn unscoped_reads(src: &str) -> Vec<String> {
    let lower = src.to_ascii_lowercase();
    let mut out = Vec::new();
    for kw in ["from", "join", "update"] {
        let pat = format!("{kw} idempotency_keys");
        let mut at = 0;
        while let Some(i) = lower[at..].find(&pat).map(|i| at + i) {
            at = i + pat.len();
            let before_ok = i == 0 || !lower.as_bytes()[i - 1].is_ascii_alphanumeric();
            let after_ok = lower.as_bytes().get(at).is_none_or(|c| !(c.is_ascii_alphanumeric() || *c == b'_'));
            if !before_ok || !after_ok {
                continue;
            }
            // The rest of the string literal: up to the first unescaped `"`.
            let bytes = lower.as_bytes();
            let mut end = i;
            while end < bytes.len() && !(bytes[end] == b'"' && bytes[end - 1] != b'\\') {
                end += 1;
            }
            let stmt = lower[i..end].replace("\\\n", " ").replace("\\n", " ").replace("\\t", " ");
            let stmt = stmt.split_whitespace().collect::<Vec<_>>().join(" ");
            if !stmt.contains("org_id") {
                out.push(stmt);
            }
        }
    }
    out
}

/// Review follow-up N4 of the `idempotency_keys` rebuild: every statement in
/// non-test source that reads, updates or deletes `idempotency_keys` filters
/// on `org_id`, so no receipt is ever read across organizations. Only the
/// rebuild's own whole-table statements are exempt, each named above.
#[test]
fn every_read_of_idempotency_keys_filters_org_id() {
    let mut used = vec![0usize; UNSCOPED_ALLOWED.len()];
    let mut seen = 0;
    let mut offenders = Vec::new();
    for (path, src) in support::sources() {
        let raw = support::without_tests_raw(&src);
        seen += raw.to_ascii_lowercase().matches("idempotency_keys where org_id").count();
        let shown = path.display().to_string().replace('\\', "/");
        for stmt in unscoped_reads(&raw) {
            match UNSCOPED_ALLOWED.iter().position(|(f, s)| shown.ends_with(f) && *s == stmt) {
                Some(n) => used[n] += 1,
                None => offenders.push(format!("{shown}: {stmt}")),
            }
        }
    }
    assert!(offenders.is_empty(), "reads of idempotency_keys without org_id:\n{}", offenders.join("\n"));
    for (n, (f, s)) in UNSCOPED_ALLOWED.iter().enumerate() {
        assert!(used[n] > 0, "stale exemption: {f}: {s}");
    }
    // tasks, delegation, messaging, agents (lifecycle) and memory, at least.
    assert!(seen >= 5, "the guard found {seen} scoped reads");
}

/// The read guard bites: an unscoped read, join, update or delete is found,
/// in any case and across `\` line continuations, and a scoped one is not.
#[test]
fn the_read_guard_finds_unscoped_statements() {
    let bad = [
        r#"c.query_row("SELECT result_json FROM idempotency_keys WHERE key = ?1", [k], f)"#,
        "c.query_row(\"SELECT result_json FROM idempotency_keys \\\n     WHERE key = ?1 AND tool = ?2\", p, f)",
        r#"c.execute("select 1 from Idempotency_Keys where key = ?1", [k])"#,
        r#"c.query_row("SELECT t.id FROM tasks t JOIN idempotency_keys k ON k.key = t.title", [], f)"#,
        r#"c.execute("UPDATE idempotency_keys SET result_json = ?2 WHERE key = ?1", p)"#,
        r#"c.execute("DELETE FROM idempotency_keys WHERE created_at < ?1", [t])"#,
    ];
    for src in bad {
        assert_eq!(unscoped_reads(src).len(), 1, "missed: {src}");
    }
    let good = [
        r#"c.query_row("SELECT result_json FROM idempotency_keys WHERE org_id = ?1 AND key = ?2", p, f)"#,
        "c.query_row(\"SELECT result_json FROM idempotency_keys \\\n     WHERE org_id = ?1 AND key = ?2\", p, f)",
        r#"c.query_row("SELECT 1 FROM tasks t JOIN idempotency_keys k ON k.org_id = t.org_id AND k.key = t.title", [], f)"#,
        r#"c.execute("CREATE TABLE idempotency_keys_new (org_id TEXT)", [])"#,
        r#"c.query_row("SELECT 1 FROM idempotency_keys_new", [], f)"#,
    ];
    for src in good {
        assert!(unscoped_reads(src).is_empty(), "false hit: {src}");
    }
}

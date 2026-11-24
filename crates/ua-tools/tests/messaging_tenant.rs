//! `message_index`, `message_reads` and `relay_messages` are tenant data
//! (`docs/organization.md`, Scoping per subsystem).
//!
//! - `organization.v1.tools.messaging` gives the two mailbox tables their
//!   `org_id` and triggers; `messaging.v2.org_scope` adds another
//!   organization's payload column, the organization-led indexes and the
//!   rules that a read receipt and a reply stay in their message's
//!   organization.
//! - `organization.v1.tools.relay` gives the relay's drafts their `org_id`
//!   and triggers; `relay.v2.org_scope` adds the indexes and the rule that a
//!   draft's approval is in its own organization.
//!
//! No upgrade moves, rewrites or drops a row: every existing row is the
//! default organization's. A second organization is created at the storage
//! level, as no tool creates one yet, and its callers are built by hand.
//! Every value here is fake.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
/// An organization whose id contains `/`, the separator of a stored
/// idempotency key.
const ORG_SLASH: &str = "org-b/message_send";
const SUSPENDED: &str = "org-suspended";
/// A third organization.
const ORG_C: &str = "org-c";
/// Organization-B labels another organization also registers.
const BOB_B: &str = "bob-b";
const CAROL_B: &str = "carol-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 4] = [
    "organization.v1.tools.messaging",
    "messaging.v2.org_scope",
    "organization.v1.tools.relay",
    "relay.v2.org_scope",
];
/// A draft id no draft has, to compare another organization's answers with.
const ABSENT: i64 = 987_654;

/// Default-organization labels and text.
const A_SENDER: &str = "a-sender";
const A_READER: &str = "a-reader";
const A_BODY: &str = "heron default body";
/// Organization-B labels and text that must never reach the default
/// organization's ledger or replies.
const B_SENDER: &str = "b-sender-not-real";
const B_READER: &str = "b-reader-not-real";
const B_BODY: &str = "osprey-body-not-real";
const B_DONE: &str = "kestrel-done-not-real";
const B_CLIENT_ID: &str = "falcon-client-id";
/// An unchecked delegation id organization B's sender names.
const B_DELEGATION: i64 = 4_242_424;
/// A label used in both organizations.
const SHARED: &str = "shared-label";

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().filter(|p| !PARTS.contains(&p.name)).collect()
}

fn add_org(db: &ua_store::Db, id: &str, status: &str) {
    let (id, status) = (id.to_string(), status.to_string());
    db.write(move |tx| {
        tx.execute(
            "INSERT INTO orgs (id, slug, display_name, status, allowed_profiles, created_at)
             VALUES (?1, ?1, 'Org', ?2, '[\"developer\",\"coordinator\",\"operator\"]', '2026-01-01T00:00:00+00:00')",
            [&id, &status],
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

/// An agent on a profile that sees the relay.
fn relay_agent(label: &str, org: &str) -> Caller {
    Caller { profile: Profile::Coordinator, ..agent(label, org) }
}

fn human(label: &str, org: &str) -> Caller {
    Caller { kind: ActorKind::Human, profile: Profile::Operator, enforce_profile: false, ..agent(label, org) }
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

/// An answer with `id` in its text replaced, to compare an answer about one
/// row with an answer about another.
fn norm(r: &Result<Value, UaError>, id: &str) -> String {
    match r {
        Ok(v) => format!("ok {v}"),
        Err(e) => format!("err {} {}", e.code(), e.to_string().replace(id, "ID")),
    }
}

fn same_as_missing(got: &Result<Value, UaError>, id: &str, missing: &Result<Value, UaError>, absent: &str) {
    assert!(got.is_err(), "another organization's row must not answer: {got:?}");
    assert_eq!(
        norm(got, id),
        norm(missing, absent),
        "another organization's row must answer as a missing one"
    );
}

struct H {
    hub: Hub,
    reg: Registry,
    ws: PathBuf,
    _dir: tempfile::TempDir,
    _ws: tempfile::TempDir,
}

impl H {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ws_dir = tempfile::tempdir().unwrap();
        let ws = ws_dir.path().canonicalize().unwrap();
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into(), "b-operator".into()];
        cfg.workspace = Some(ws.clone());
        let hub = Hub::in_memory(cfg).unwrap();
        add_org(hub.db(), ORG_B, "active");
        add_org(hub.db(), ORG_SLASH, "active");
        add_org(hub.db(), SUSPENDED, "suspended");
        Self { hub, reg: builtin_registry(), ws, _dir: dir, _ws: ws_dir }
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

    async fn coord(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "coordination_manage", json!({ "action": action, "params": params })).await
    }

    async fn send(&self, who: &Caller, args: Value) -> Value {
        self.ok(who, "message_send", args).await
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

    /// Every row of the three tables and the idempotency receipts, as text:
    /// a refused call leaves it identical.
    fn snapshot(&self) -> String {
        self.hub
            .db()
            .read(|c| {
                let mut out = Vec::new();
                for t in ["message_index", "message_reads", "relay_messages", "idempotency_keys"] {
                    let mut stmt = c.prepare(&format!("SELECT * FROM {t} ORDER BY rowid"))?;
                    let n = stmt.column_count();
                    let rows = stmt.query_map([], |r| {
                        let mut row = Vec::new();
                        for i in 0..n {
                            row.push(format!("{:?}", r.get_ref(i)?));
                        }
                        Ok(row.join("|"))
                    })?;
                    out.push(format!("{t}: {}", rows.collect::<Result<Vec<_>, _>>()?.join("\n")));
                }
                Ok(out.join("\n"))
            })
            .unwrap()
    }

    /// The whole ledger as text, for leak checks.
    fn ledger_text(&self) -> String {
        self.hub
            .db()
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT channel, COALESCE(originator, ''), payload, COALESCE(episode_id, ''), \
                     COALESCE(causal_parent_id, ''), COALESCE(dedupe_key, '') FROM event_log ORDER BY seq",
                )?;
                let rows = stmt.query_map([], |r| {
                    Ok(format!(
                        "{} {} {} {} {} {}",
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?
                    ))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?.join("\n"))
            })
            .unwrap()
    }

    fn event_count(&self) -> i64 {
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

/// Whether any drop file exists under the workspace.
fn wt_written(h: &H) -> bool {
    walk(&h.ws).iter().any(|p| p.ends_with(".ua/interventions.jsonl"))
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

fn bodies(v: &Value) -> Vec<String> {
    v["messages"]
        .as_array()
        .unwrap_or_else(|| panic!("no messages in {v}"))
        .iter()
        .map(|m| m["body"].as_str().unwrap_or("<null>").to_string())
        .collect()
}

fn assert_no_b(text: &str, what: &str) {
    for needle in [B_SENDER, B_READER, B_BODY, B_DONE, B_CLIENT_ID] {
        assert!(!text.contains(needle), "{what} leaks {needle:?}: {text}");
    }
}

// --- schema ------------------------------------------------------------------------------------

#[test]
fn a_legacy_database_upgrades_with_nothing_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.human_identities = vec!["operator".into()];
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO message_index (message_id, recipient, sender, act, conversation_id, reply_to,
                     expects_reply, event_ulid, event_seq, created_at, target_session)
                 VALUES ('m-1', 'a-reader', 'a-sender', 'request', 'c-1', NULL, 1, 'U1', 1, '2026-01-01T00:00:00+00:00', NULL),
                        ('m-2', 'a-sender', 'a-reader', 'inform', 'c-1', 'm-1', 0, 'U2', 2, '2026-01-01T00:00:01+00:00', NULL),
                        ('m-3', 'a-reader', 'a-sender', 'inform', 'c-2', NULL, 0, 'U3', 3, '2026-01-01T00:00:02+00:00', 's-9');
                 INSERT INTO message_reads (message_id, session_id, read_at) VALUES ('m-1', 's-1', '2026-01-02T00:00:00+00:00');
                 INSERT INTO approvals (id, tool, payload, requested_by, status, created_at, updated_at)
                     VALUES (7, 'relay_manage', '{}', 'a-sender', 'pending', 'x', 'x');
                 INSERT INTO relay_messages (id, channel, target, text, text_sha256, chars, bytes, verdict,
                     findings, status, approval_id, requested_by, created_at, updated_at)
                 VALUES (5, 'github', 'owner/repo#1', 'hello', 'h', 5, 5, 'pass', '{}', 'pending_approval', 7,
                         'a-sender', 'x', 'x'),
                        (6, 'github', 'owner/repo#2', NULL, 'h2', 5, 5, 'block', '{}', 'blocked', NULL,
                         'a-sender', 'x', 'x');",
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
                // Every row is kept, unchanged, in the default organization.
                let msgs: Vec<(String, String, Option<String>, Option<String>)> = c
                    .prepare("SELECT message_id, org_id, reply_to, org_payload FROM message_index ORDER BY event_seq")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                    .collect::<Result<_, _>>()?;
                assert_eq!(
                    msgs,
                    [
                        ("m-1".into(), DEFAULT_ORG.into(), None, None),
                        ("m-2".into(), DEFAULT_ORG.into(), Some("m-1".into()), None),
                        ("m-3".into(), DEFAULT_ORG.into(), None, None),
                    ]
                );
                let reads: Vec<(String, String)> = c
                    .prepare("SELECT message_id, org_id FROM message_reads")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<_, _>>()?;
                assert_eq!(reads, [("m-1".into(), DEFAULT_ORG.into())]);
                let drafts: Vec<(i64, String, Option<i64>, String)> = c
                    .prepare("SELECT id, org_id, approval_id, status FROM relay_messages ORDER BY id")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                    .collect::<Result<_, _>>()?;
                assert_eq!(
                    drafts,
                    [
                        (5, DEFAULT_ORG.into(), Some(7), "pending_approval".into()),
                        (6, DEFAULT_ORG.into(), None, "blocked".into())
                    ]
                );
                for t in ["message_index", "message_reads", "relay_messages"] {
                    let notnull: i64 = c.query_row(
                        &format!("SELECT \"notnull\" FROM pragma_table_info('{t}') WHERE name = 'org_id'"),
                        [],
                        |r| r.get(0),
                    )?;
                    assert_eq!(notnull, 1, "{t}");
                    let triggers = names(c, "trigger", t);
                    for want in [format!("{t}_org_exists"), format!("{t}_org_immutable")] {
                        assert!(triggers.contains(&want), "{triggers:?}");
                    }
                }
                for (t, want) in [
                    ("message_reads", &["message_reads_org_parent", "message_reads_org_parent_update"][..]),
                    ("message_index", &["message_index_org_reply", "message_index_org_reply_update"][..]),
                    ("relay_messages", &["relay_messages_org_approval", "relay_messages_org_approval_update"][..]),
                ] {
                    let triggers = names(c, "trigger", t);
                    for w in want {
                        assert!(triggers.contains(&w.to_string()), "{t}: {triggers:?}");
                    }
                }
                for (t, want) in [
                    (
                        "message_index",
                        &[
                            "idx_message_index_org_recipient_seq",
                            "idx_message_index_org_sender_seq",
                            "idx_message_index_org_conversation",
                            "idx_message_index_org_task",
                        ][..],
                    ),
                    (
                        "relay_messages",
                        &[
                            "idx_relay_messages_org_status",
                            "idx_relay_messages_org_requester",
                            "idx_relay_messages_org_content",
                            "idx_relay_messages_org_approval",
                        ][..],
                    ),
                ] {
                    let idx = names(c, "index", t);
                    for w in want {
                        assert!(idx.contains(&w.to_string()), "{t}: {idx:?}");
                    }
                }
                Ok(())
            })
            .unwrap();
    }

    // Nothing is dropped, so nothing is recorded as dropped. A row never
    // moves to another organization.
    let hub = Hub::open(cfg).unwrap();
    add_org(hub.db(), ORG_B, "active");
    for sql in [
        "UPDATE message_index SET org_id = 'org-b' WHERE message_id = 'm-1'",
        "UPDATE message_reads SET org_id = 'org-b'",
        "UPDATE relay_messages SET org_id = 'org-b' WHERE id = 5",
    ] {
        let e = hub.db().write(|tx| Ok(tx.execute_batch(sql)?)).unwrap_err();
        assert!(e.to_string().contains("org_id cannot change"), "{sql}: {e}");
    }

    // The legacy mail answers through the tools, to its own organization,
    // in the shape it had.
    let reg = builtin_registry();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let ids = |v: &Value| -> Vec<String> {
            v["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["message_id"].as_str().unwrap().to_string())
                .collect()
        };
        // The operator reads every message; the recipient's label mail
        // leaves out m-3, which is addressed to one of its sessions.
        let all = reg.call(&hub, &human("operator", DEFAULT_ORG), "message_list", json!({})).await.unwrap();
        assert_eq!(ids(&all), ["m-1", "m-2", "m-3"], "{all}");
        let v = reg.call(&hub, &agent(A_READER, DEFAULT_ORG), "message_list", json!({})).await.unwrap();
        assert_eq!(ids(&v), ["m-1", "m-2"], "{v}");
        assert!(v["messages"][0].get("org_id").is_none(), "a reply keeps its shape: {v}");
        assert_eq!(v["messages"][0]["answered_by"], "m-2", "{v}");
        let b = reg.call(&hub, &agent(A_READER, ORG_B), "message_list", json!({})).await.unwrap();
        assert_eq!(b["total"], 0, "the same label in another organization reads none of it: {b}");
    });
}

#[test]
fn the_triggers_keep_receipts_replies_and_approvals_in_one_organization() {
    let h = H::new();
    h.sql(
        "INSERT INTO message_index (org_id, message_id, recipient, sender, act, conversation_id, event_ulid,
             event_seq, created_at) VALUES ('default', 'ma', 'r', 's', 'inform', 'c', 'UA', 1, 'x'),
                                         ('org-b', 'mb', 'r', 's', 'inform', 'c', 'UB', 2, 'x');
         INSERT INTO approvals (id, org_id, tool, payload, requested_by, status, created_at, updated_at)
             VALUES (70, 'default', 'relay_manage', '{}', 'r', 'pending', 'x', 'x'),
                    (71, 'org-b', 'relay_manage', '{}', 'r', 'pending', 'x', 'x');
         INSERT INTO relay_messages (id, org_id, channel, target, text_sha256, chars, bytes, verdict, status,
             approval_id, requested_by, created_at, updated_at)
             VALUES (40, 'default', 'github', 't', 'h', 1, 1, 'pass', 'draft', NULL, 'r', 'x', 'x');",
    )
    .unwrap();
    for (sql, want) in [
        (
            "INSERT INTO message_reads (org_id, message_id, session_id, read_at) VALUES ('org-b', 'ma', 's', 'x')",
            "message belongs to another organization",
        ),
        (
            "INSERT INTO message_reads (org_id, message_id, session_id, read_at) VALUES ('default', 'ma', 's', 'x');
             UPDATE message_reads SET message_id = 'mb' WHERE message_id = 'ma'",
            "message belongs to another organization",
        ),
        (
            "INSERT INTO message_index (org_id, message_id, recipient, sender, act, conversation_id, reply_to,
                 event_ulid, event_seq, created_at) VALUES ('org-b', 'mb2', 'r', 's', 'inform', 'c', 'ma', 'UB2', 3, 'x')",
            "reply_to belongs to another organization",
        ),
        ("UPDATE message_index SET reply_to = 'mb' WHERE message_id = 'ma'", "reply_to belongs to another organization"),
        ("UPDATE relay_messages SET approval_id = 71 WHERE id = 40", "approval belongs to another organization"),
        (
            "INSERT INTO relay_messages (org_id, channel, target, text_sha256, chars, bytes, verdict, status,
                 approval_id, requested_by, created_at, updated_at)
             VALUES ('org-b', 'github', 't', 'h', 1, 1, 'pass', 'draft', 70, 'r', 'x', 'x')",
            "approval belongs to another organization",
        ),
        (
            "INSERT INTO message_index (org_id, message_id, recipient, sender, act, conversation_id, event_ulid,
                 event_seq, created_at) VALUES ('missing-org', 'mu', 'r', 's', 'inform', 'c', 'UU', 9, 'x')",
            "unknown organization",
        ),
    ] {
        let e = h.sql(sql).unwrap_err();
        assert!(e.contains(want), "{sql}: {e}");
    }
    // An external reply_to and a same-organization one pass.
    h.sql(
        "INSERT INTO message_index (org_id, message_id, recipient, sender, act, conversation_id, reply_to,
             event_ulid, event_seq, created_at) VALUES ('org-b', 'mb3', 'r', 's', 'inform', 'c', 'mb', 'UB3', 4, 'x'),
                                                     ('org-b', 'mb4', 'r', 's', 'inform', 'c', 'ts:1', 'UB4', 5, 'x');
         UPDATE relay_messages SET approval_id = 70 WHERE id = 40;",
    )
    .unwrap();
}

// --- mailbox isolation --------------------------------------------------------------------------

/// Each organization's mail, sent through the tools.
struct Mail {
    a: Value,
    b: Value,
    b_handoff: Value,
    task_a: i64,
    task_b: i64,
}

async fn seed(h: &H) -> Mail {
    let (a_sender, b_sender) = (agent(A_SENDER, DEFAULT_ORG), agent(B_SENDER, ORG_B));
    let task_a = h.ok(&a_sender, "task_add", json!({ "title": "Heron task" })).await["id"].as_i64().unwrap();
    let task_b = h.ok(&b_sender, "task_add", json!({ "title": "Osprey task" })).await["id"].as_i64().unwrap();
    let a = h
        .send(
            &a_sender,
            json!({ "act": "request", "to_agent": A_READER, "body": A_BODY, "task_id": task_a,
                    "expects_reply": true, "message_id": "shared-client-id" }),
        )
        .await;
    h.send(
        &a_sender,
        json!({ "act": "handoff", "to_agent": A_READER, "body": "default handoff", "task_id": task_a,
                "handoff": { "done": ["default done"], "next_action": "go", "evidence": [{"kind": "task", "ref": "1"}] } }),
    )
    .await;
    let b = h
        .send(
            &b_sender,
            json!({ "act": "request", "to_agent": B_READER, "body": B_BODY, "task_id": task_a,
                    "expects_reply": true, "message_id": B_CLIENT_ID }),
        )
        .await;
    // Organization B's handoff about its own task, and one naming the
    // default organization's task id: neither reaches the default
    // organization's readers.
    let b_handoff = h
        .send(
            &b_sender,
            json!({ "act": "handoff", "to_agent": B_READER, "body": B_BODY, "task_id": task_b,
                    "delegation_id": B_DELEGATION,
                    "handoff": { "done": [B_DONE], "next_action": "go", "evidence": [{"kind": "task", "ref": "2"}] } }),
        )
        .await;
    h.send(
        &b_sender,
        json!({ "act": "handoff", "to_agent": B_READER, "body": B_BODY, "task_id": task_a,
                "handoff": { "done": [B_DONE] } }),
    )
    .await;
    Mail { a, b, b_handoff, task_a, task_b }
}

#[tokio::test]
async fn every_mailbox_read_is_isolated_per_organization() {
    let h = H::new();
    let m = seed(&h).await;
    let (a_reader, b_reader) = (agent(A_READER, DEFAULT_ORG), agent(B_READER, ORG_B));
    let (op_a, op_b) = (human("operator", DEFAULT_ORG), human("b-operator", ORG_B));
    let (a_sender, b_sender) = (agent(A_SENDER, DEFAULT_ORG), agent(B_SENDER, ORG_B));

    // Rows land in the sender's organization; another organization's
    // payload is kept on its row, the default organization's is not.
    assert_eq!(h.count("SELECT COUNT(*) FROM message_index WHERE org_id = 'default'"), 2);
    assert_eq!(h.count("SELECT COUNT(*) FROM message_index WHERE org_id = 'org-b'"), 3);
    assert_eq!(
        h.count("SELECT COUNT(*) FROM message_index WHERE org_id = 'default' AND org_payload IS NOT NULL"),
        0
    );
    assert_eq!(
        h.count("SELECT COUNT(*) FROM message_index WHERE org_id = 'org-b' AND org_payload IS NULL"),
        0
    );

    // message_list: the mail-unrestricted default reader sees every default
    // message and none of B's; B's reader sees exactly its own.
    let all_a = h.ok(&op_a, "message_list", json!({})).await;
    assert_eq!(bodies(&all_a), [A_BODY, "default handoff"], "{all_a}");
    assert_no_b(&all_a.to_string(), "the default list");
    let b_list = h.ok(&b_reader, "message_list", json!({})).await;
    assert_eq!(bodies(&b_list), [B_BODY, B_BODY, B_BODY], "{b_list}");
    assert_eq!(b_list["messages"][1]["handoff"]["done"], json!([B_DONE]), "{b_list}");
    assert!(!b_list.to_string().contains(A_BODY));
    let b_op = h.ok(&op_b, "message_list", json!({})).await;
    assert_eq!(
        b_op["total"], 0,
        "an organization-B operator is no mail reader of the default organization: {b_op}"
    );

    // Filters by another organization's ids find nothing.
    let b_mid = m.b["message_id"].as_str().unwrap();
    let b_conv = m.b["conversation_id"].as_str().unwrap();
    for args in [
        json!({ "message_id": b_mid }),
        json!({ "conversation_id": b_conv }),
        json!({ "client_message_id": B_CLIENT_ID }),
        json!({ "to_agent": B_READER }),
        json!({ "from_agent": B_SENDER }),
        json!({ "count_only": true, "to_agent": B_READER }),
    ] {
        let v = h.ok(&op_a, "message_list", args.clone()).await;
        assert!(v["total"] == 0 || v["count"] == 0, "{args}: {v}");
    }
    let a_mid = m.a["message_id"].as_str().unwrap();
    for args in [
        json!({ "message_id": a_mid }),
        json!({ "conversation_id": m.a["conversation_id"] }),
        json!({ "message_id": "shared-client-id" }),
    ] {
        let v = h.ok(&b_reader, "message_list", args.clone()).await;
        assert_eq!(v["total"], 0, "{args}: {v}");
    }

    // waiting_on_reply: each sender's own unanswered mail, in its organization.
    let w = h.ok(&b_sender, "message_list", json!({ "waiting_on_reply": true })).await;
    assert_eq!(w["total"], 1, "{w}");
    h.send(&b_reader, json!({ "act": "done", "body": "answered", "reply_to": b_mid })).await;
    let w = h.ok(&b_sender, "message_list", json!({ "waiting_on_reply": true })).await;
    assert_eq!(w["total"], 0, "{w}");
    let w = h.ok(&a_sender, "message_list", json!({ "waiting_on_reply": true })).await;
    assert_eq!(w["total"], 1, "B's answer does not answer the default organization's mail: {w}");

    // The same label in both organizations has two mailboxes.
    let (shared_a, shared_b) = (agent(SHARED, DEFAULT_ORG), agent(SHARED, ORG_B));
    h.send(&a_sender, json!({ "act": "inform", "to_agent": SHARED, "body": "default to shared" })).await;
    h.send(&b_sender, json!({ "act": "inform", "to_agent": SHARED, "body": B_BODY })).await;
    let inbox_b = h.coord(&shared_b, "message_inbox", json!({})).await.unwrap();
    assert_eq!(bodies(&inbox_b), [B_BODY]);
    assert_eq!((inbox_b["marked_read"].clone(), inbox_b["unread"].clone()), (json!(1), json!(0)));
    // B's read marked nothing of the default organization's mailbox.
    let unread_a = h.ok(&shared_a, "message_list", json!({ "unread_only": true })).await;
    assert_eq!(bodies(&unread_a), ["default to shared"], "{unread_a}");
    let inbox_a = h.coord(&shared_a, "message_inbox", json!({})).await.unwrap();
    assert_eq!(bodies(&inbox_a), ["default to shared"]);
    assert_no_b(&inbox_a.to_string(), "the default inbox");

    // message_ack: another organization's message answers as a missing one,
    // and acking through every seq touches only the caller's organization.
    let b_shared_id = inbox_b["messages"][0]["message_id"].as_str().unwrap().to_string();
    let got = h.coord(&shared_a, "message_ack", json!({ "message_id": b_shared_id })).await;
    let missing = h.coord(&shared_a, "message_ack", json!({ "message_id": "absent-id" })).await;
    same_as_missing(&got, &b_shared_id, &missing, "absent-id");
    let got = h.coord(&shared_a, "message_ack", json!({ "through": b_shared_id })).await;
    let missing = h.coord(&shared_a, "message_ack", json!({ "through": "absent-id" })).await;
    same_as_missing(&got, &b_shared_id, &missing, "absent-id");
    let acked = h.coord(&shared_b, "message_ack", json!({ "through": i64::MAX })).await.unwrap();
    assert_eq!(acked["acked"], 1, "{acked}");
    assert_eq!(
        h.count("SELECT COUNT(*) FROM message_index WHERE org_id = 'default' AND recipient = 'shared-label' AND acked_at IS NOT NULL"),
        0
    );
    let acked = h.coord(&shared_a, "message_ack", json!({ "through": i64::MAX })).await.unwrap();
    assert_eq!(acked["acked"], 1, "{acked}");

    // Replies and conversations: another organization's message and
    // conversation answer exactly as missing ones.
    let got =
        h.call(&a_reader, "message_send", json!({ "act": "inform", "body": "re", "reply_to": b_mid })).await;
    let missing = h
        .call(&a_reader, "message_send", json!({ "act": "inform", "body": "re", "reply_to": "absent-id" }))
        .await;
    same_as_missing(&got, b_mid, &missing, "absent-id");
    let got = h
        .call(
            &a_reader,
            "message_send",
            json!({ "act": "inform", "to_agent": A_SENDER, "body": "x", "conversation_id": b_conv }),
        )
        .await;
    let missing = h
        .call(
            &a_reader,
            "message_send",
            json!({ "act": "inform", "to_agent": A_SENDER, "body": "x", "conversation_id": "absent-conv" }),
        )
        .await;
    same_as_missing(&got, b_conv, &missing, "absent-conv");
    let a_conv = m.a["conversation_id"].as_str().unwrap();
    let got = h
        .call(
            &b_reader,
            "message_send",
            json!({ "act": "inform", "to_agent": B_SENDER, "body": "x", "conversation_id": a_conv }),
        )
        .await;
    let missing = h
        .call(
            &b_reader,
            "message_send",
            json!({ "act": "inform", "to_agent": B_SENDER, "body": "x", "conversation_id": "absent-conv" }),
        )
        .await;
    same_as_missing(&got, a_conv, &missing, "absent-conv");

    // Conversation threads (conversation_handoffs) answer another
    // organization's conversation as a missing one, for every reader.
    for who in [&op_a, &a_reader] {
        let got = h.coord(who, "conversation_handoffs", json!({ "conversation_id": b_conv })).await;
        let missing =
            h.coord(who, "conversation_handoffs", json!({ "conversation_id": "absent-conv" })).await;
        same_as_missing(&got, b_conv, &missing, "absent-conv");
        let got = h
            .coord(who, "conversation_handoff", json!({ "conversation_id": b_conv, "title": "steal it" }))
            .await;
        let missing = h
            .coord(
                who,
                "conversation_handoff",
                json!({ "conversation_id": "absent-conv", "title": "steal it" }),
            )
            .await;
        same_as_missing(&got, b_conv, &missing, "absent-conv");
    }
    let got = h.coord(&b_reader, "conversation_handoffs", json!({ "conversation_id": a_conv })).await;
    let missing =
        h.coord(&b_reader, "conversation_handoffs", json!({ "conversation_id": "absent-conv" })).await;
    same_as_missing(&got, a_conv, &missing, "absent-conv");
    h.coord(&b_reader, "conversation_handoffs", json!({ "conversation_id": b_conv })).await.unwrap();

    // session_packet: the prior handoff is the reader's organization's,
    // even for a task id another organization's message names.
    let p = h.ok(&op_a, "session_packet", json!({ "task_id": m.task_a })).await;
    assert_eq!(p["prior_handoff"]["handoff"]["done"], json!(["default done"]), "{p}");
    assert_no_b(&p.to_string(), "the default session packet");
    let p = h.ok(&b_reader, "session_packet", json!({ "task_id": m.task_b })).await;
    assert_eq!(p["prior_handoff"]["message_id"], m.b_handoff["message_id"], "{p}");
    assert_eq!(p["prior_handoff"]["handoff"]["done"], json!([B_DONE]), "{p}");

    // event_log_query: no default reader sees B's content, B's readers see
    // no default message event.
    for who in [&op_a, &a_reader] {
        let ev = h.ok(who, "event_log_query", json!({ "channel_prefix": "agent.", "limit": 1000 })).await;
        assert_no_b(&ev.to_string(), "the default ledger read");
    }
    for who in [&op_b, &b_reader] {
        let ev =
            h.ok(who, "event_log_query", json!({ "channel_prefix": "agent.message.", "limit": 1000 })).await;
        assert!(!ev.to_string().contains(A_BODY), "{ev}");
        assert_eq!(ev["events"].as_array().map(Vec::len), Some(0), "{ev}");
    }

    // export: the hub-wide manifest (default organization only) lists every
    // ledger row, B's message events among them, with none of B's content.
    let manifest = h
        .ok(&op_a, "export_migration_manifest", json!({ "events_since_ulid": "00000000000000000000000000" }))
        .await;
    assert!(manifest.to_string().contains(A_BODY), "the default organization's own rows are listed");
    assert_no_b(&manifest.to_string(), "the migration manifest");
    let e = h.call(&op_b, "export_migration_manifest", json!({})).await.unwrap_err();
    assert_eq!(reason(&e), "org_unsupported", "{e:?}");

    // The ledger as a whole carries none of B's content, labels or client
    // text; B's message events use the neutral originator.
    assert_no_b(&h.ledger_text(), "the ledger");
    let originators: Vec<String> = h
        .hub
        .db()
        .read(move |c| {
            let mut stmt =
                c.prepare("SELECT DISTINCT originator FROM event_log WHERE json_extract(payload, '$.message_id') IN (SELECT message_id FROM message_index WHERE org_id = 'org-b')")?;
            Ok(stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
        })
        .unwrap();
    assert_eq!(originators, ["system"]);
}

#[tokio::test]
async fn crew_view_shows_only_the_readers_organizations_mail() {
    let h = H::new();
    let m = seed(&h).await;
    let a_reader = agent(A_READER, DEFAULT_ORG);
    let (op_a, op_b) = (human("operator", DEFAULT_ORG), human("b-operator", ORG_B));
    let wt = h.ws.join("wt");
    std::fs::create_dir_all(&wt).unwrap();
    let sid = h
        .ok(
            &a_reader,
            "session_start",
            json!({ "kind": "interactive", "task_id": m.task_a, "worktree_path": wt.to_str().unwrap() }),
        )
        .await["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    // A crew request into the session in each organization, as the drop
    // file would name them (organization B's can only be planted by SQL:
    // no tool sends across organizations).
    let crew = format!("crew:{sid}");
    h.sql(&format!(
        "INSERT INTO message_index (org_id, message_id, recipient, sender, act, conversation_id, event_ulid,
             event_seq, created_at, org_payload)
         VALUES ('default', 'crew-a', '{A_READER}', 'operator', 'request', '{crew}', 'UCA', 900001, 'x', NULL),
                ('org-b', 'crew-b', '{A_READER}', '{B_SENDER}', 'request', '{crew}', 'UCB', 900002, 'x',
                 '{{\"body\": \"{B_BODY}\"}}');"
    ))
    .unwrap();
    std::fs::create_dir_all(wt.join(".ua")).unwrap();
    let lines = [("crew-a", &sid), ("crew-b", &sid)]
        .iter()
        .map(|(id, s)| json!({ "ts": "x", "session_id": s, "message_id": id }).to_string())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(wt.join(".ua/interventions.jsonl"), format!("{lines}\n")).unwrap();

    let v = h.ok(&op_a, "crew_view", json!({ "session_id": sid })).await;
    let ids: Vec<&str> = v["worktree_interventions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["message_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["crew-a"], "{v}");
    // Task-scoped mail: the default handoffs and request only, although B's
    // mail names the same task id.
    assert!(bodies(&v).contains(&A_BODY.to_string()), "{v}");
    assert_no_b(&v.to_string(), "the default crew view");
    assert_eq!(v["message_total"], 3, "{v}");

    // Every session is the default organization's: organization B's
    // callers can neither view nor steer one, and are refused before
    // anything is read, approved or written.
    let before = (h.snapshot(), h.event_count(), approvals(&h), wt_lines(&wt));
    for who in [&op_b, &agent(B_READER, ORG_B)] {
        for sid in [sid.as_str(), "no-such-session"] {
            let e = h.call(who, "crew_view", json!({ "session_id": sid })).await.unwrap_err();
            assert_eq!(reason(&e), "org_unsupported", "{e:?}");
            assert!(!e.to_string().contains(A_READER) && !e.to_string().contains("wt"), "{e:?}");
            let e = h
                .call(who, "crew_intervene", json!({ "session_id": sid, "message": B_BODY }))
                .await
                .unwrap_err();
            assert_eq!(reason(&e), "org_unsupported", "{e:?}");
        }
    }
    assert_eq!(
        (h.snapshot(), h.event_count(), approvals(&h), wt_lines(&wt)),
        before,
        "nothing written, no approval parked, no drop-file line"
    );
}

/// Every approval row, as text.
fn approvals(h: &H) -> String {
    h.hub
        .db()
        .read(|c| {
            let mut stmt = c.prepare("SELECT id, org_id, tool, status FROM approvals ORDER BY id")?;
            let rows = stmt.query_map([], |r| {
                Ok(format!(
                    "{}|{}|{}|{}",
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?
                ))
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?.join("\n"))
        })
        .unwrap()
}

fn wt_lines(wt: &Path) -> String {
    std::fs::read_to_string(wt.join(".ua/interventions.jsonl")).unwrap_or_default()
}

// --- sending ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_send_to_a_session_from_another_organization_is_refused_with_nothing_written() {
    let h = H::new();
    let a_reader = agent(A_READER, DEFAULT_ORG);
    // A registered default-organization agent with a live session.
    let sid = h.ok(&a_reader, "session_start", json!({ "kind": "interactive" })).await["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    h.ok(&agent("a-heartbeat", DEFAULT_ORG), "agent_heartbeat", json!({})).await;
    let (b_sender, op_b) = (agent(B_SENDER, ORG_B), human("b-operator", ORG_B));
    let before = (h.snapshot(), h.event_count());

    for who in [&b_sender, &op_b] {
        for args in [
            json!({ "act": "inform", "to_session": sid, "body": B_BODY }),
            json!({ "act": "inform", "to_session": "no-such-session", "body": B_BODY }),
            json!({ "act": "inform", "to_agent": A_READER, "to_session": sid, "body": B_BODY, "message_id": "k-1" }),
        ] {
            let e = h.call(who, "message_send", args.clone()).await.unwrap_err();
            assert_eq!(reason(&e), "cross_org_recipient", "{args}: {e:?}");
        }
        // A session of its own cannot be named either: every session is the
        // default organization's.
        for (tool, args) in [
            (
                "message_send",
                json!({ "act": "inform", "to_agent": B_READER, "body": "x", "from_session": sid }),
            ),
            ("message_list", json!({ "session_id": sid })),
        ] {
            let e = h.call(who, tool, args.clone()).await.unwrap_err();
            assert_eq!(reason(&e), "org_unsupported", "{tool}({args}): {e:?}");
        }
        for (action, params) in [
            ("message_inbox", json!({ "session_id": sid })),
            ("message_ack", json!({ "through": 5, "session_id": sid })),
        ] {
            let e = h.coord(who, action, params.clone()).await.unwrap_err();
            assert_eq!(reason(&e), "org_unsupported", "{action}({params}): {e:?}");
        }
    }
    assert_eq!((h.snapshot(), h.event_count()), before, "a refused send writes nothing");
    // crew_intervene is refused before its approval gate (crew_view's test
    // checks no approval is parked), so nothing reaches the drop file.
    let e = h.call(&op_b, "crew_intervene", json!({ "session_id": sid, "message": B_BODY })).await;
    assert_eq!(reason(&e.unwrap_err()), "org_unsupported");
    assert_eq!(h.snapshot(), before.0);
    assert!(!wt_written(&h), "no drop-file line");

    // Mail inside organization B still flows, to any label: one the default
    // organization registered too is organization B's mailbox there.
    for to in [B_READER, A_READER, "A-READER", "a-heartbeat"] {
        h.send(&b_sender, json!({ "act": "inform", "to_agent": to, "body": B_BODY })).await;
    }
    assert_eq!(h.count("SELECT COUNT(*) FROM message_index WHERE org_id = 'default'"), 0);
    assert_eq!(h.count("SELECT COUNT(*) FROM message_index WHERE org_id = 'org-b'"), 4);
    let inbox = h.ok(&a_reader, "message_list", json!({})).await;
    assert_eq!(inbox["total"], 0, "the default organization's reader gets none of it: {inbox}");
    assert_no_b(&h.ledger_text(), "the ledger");
}

/// Agents and sessions carry no organization yet, and any organization can
/// write them, so whether a label is registered never decides whether
/// another organization's mail reaches it, nor changes the send's reply.
#[tokio::test]
async fn registering_a_label_elsewhere_never_stops_or_changes_an_organizations_mail() {
    let h = H::new();
    add_org(h.hub.db(), ORG_C, "active");
    let b_sender = agent(B_SENDER, ORG_B);
    // A send's reply with its minted ids masked.
    let masked = |v: &Value| {
        let mut v = v.clone();
        for k in ["message_id", "event_ulid", "seq", "conversation_id"] {
            assert!(!v[k].is_null(), "{k} in {v}");
            v[k] = json!("<minted>");
        }
        v.to_string()
    };
    let send = |to: &'static str| {
        let b_sender = b_sender.clone();
        let h = &h;
        async move {
            h.send(&b_sender, json!({ "act": "request", "to_agent": to, "body": B_BODY, "task_id": 5 })).await
        }
    };

    let fresh_bob = masked(&send(BOB_B).await);
    let fresh_carol = masked(&send(CAROL_B).await);
    // A third organization heartbeats `bob-b`; the default organization
    // starts a session as `carol-b`.
    h.ok(&agent(BOB_B, ORG_C), "agent_heartbeat", json!({})).await;
    h.ok(&agent(CAROL_B, DEFAULT_ORG), "session_start", json!({ "kind": "interactive" })).await;
    assert_eq!(masked(&send(BOB_B).await), fresh_bob, "the reply is the same once the label is registered");
    assert_eq!(
        masked(&send(CAROL_B).await),
        fresh_carol,
        "the reply is the same once the label has a session"
    );

    // Organization B's own agent starts a session: its peers' mail still
    // reaches it, and it reads it as its label.
    let bob = agent(BOB_B, ORG_B);
    h.ok(&bob, "session_start", json!({ "kind": "interactive" })).await;
    send(BOB_B).await;
    let inbox = h.coord(&bob, "message_inbox", json!({})).await.unwrap();
    assert_eq!(bodies(&inbox), [B_BODY, B_BODY, B_BODY], "{inbox}");
    // The other organizations' `bob-b` and `carol-b` read none of it.
    for who in [agent(BOB_B, ORG_C), agent(BOB_B, DEFAULT_ORG), agent(CAROL_B, DEFAULT_ORG)] {
        let v = h.ok(&who, "message_list", json!({})).await;
        assert_eq!(v["total"], 0, "{}: {v}", who.org_id);
    }
    assert_eq!(h.count("SELECT COUNT(*) FROM message_index WHERE org_id <> 'org-b'"), 0);
    for needle in [BOB_B, CAROL_B, B_BODY] {
        let ledger = h.ledger_text();
        let messages =
            ledger.lines().filter(|l| l.starts_with("agent.message.")).collect::<Vec<_>>().join("\n");
        assert!(!messages.contains(needle), "a message event leaks {needle:?}: {messages}");
    }
}

#[tokio::test]
async fn an_unknown_or_suspended_organization_is_refused_before_any_write() {
    let h = H::new();
    let a_sender = agent(A_SENDER, DEFAULT_ORG);
    let sent = h.send(&a_sender, json!({ "act": "inform", "to_agent": A_READER, "body": A_BODY })).await;
    let before = (h.snapshot(), h.event_count());
    for (org, want) in [(UNKNOWN, "unknown_organization"), (SUSPENDED, "organization_suspended")] {
        let who = human(A_READER, org);
        let e = h
            .call(&who, "message_send", json!({ "act": "inform", "to_agent": "x", "body": "y" }))
            .await
            .unwrap_err();
        assert_eq!(reason(&e), want, "{org}: {e:?}");
        // Writes with nothing to insert: a read mark and an ack.
        let e = h.coord(&who, "message_inbox", json!({})).await.unwrap_err();
        assert_eq!(reason(&e), want, "{org}: {e:?}");
        for params in [json!({ "message_id": sent["message_id"] }), json!({ "through": i64::MAX })] {
            let e = h.coord(&who, "message_ack", params).await.unwrap_err();
            assert_eq!(reason(&e), want, "{org}: {e:?}");
        }
        let e = h
            .call(&who, "relay_manage", json!({ "action": "cancel", "params": { "draft_id": 1 } }))
            .await
            .unwrap_err();
        assert_eq!(reason(&e), want, "{org}: {e:?}");
        // Reads too: the mailbox, a conversation's handoffs, a handoff.
        for args in [json!({}), json!({ "session_id": "s-1" })] {
            let e = h.call(&who, "message_list", args.clone()).await.unwrap_err();
            assert_eq!(reason(&e), want, "{org} message_list({args}): {e:?}");
        }
        for (action, params) in [
            ("conversation_handoffs", json!({ "conversation_id": sent["conversation_id"] })),
            ("conversation_handoff", json!({ "conversation_id": sent["conversation_id"], "title": "t" })),
        ] {
            let e = h.coord(&who, action, params).await.unwrap_err();
            assert_eq!(reason(&e), want, "{org} {action}: {e:?}");
        }
        // crew_view refuses every session outside the default organization.
        let e = h.call(&who, "crew_view", json!({ "session_id": "s-1" })).await.unwrap_err();
        assert_eq!(reason(&e), "org_unsupported", "{org}: {e:?}");
    }
    assert_eq!((h.snapshot(), h.event_count()), before, "nothing changed");
}

// --- idempotency ---------------------------------------------------------------------------------

#[tokio::test]
async fn client_message_ids_are_isolated_per_organization() {
    let h = H::new();
    let key = "same-client-id";
    let senders = [
        (agent("courier", DEFAULT_ORG), "to-a"),
        (agent("courier", ORG_B), "to-b"),
        (agent("courier", ORG_SLASH), "to-slash"),
    ];
    let mut firsts = Vec::new();
    for (who, to) in &senders {
        let r = h.send(who, json!({ "act": "inform", "to_agent": to, "body": format!("first {}", who.org_id), "message_id": key })).await;
        assert_eq!(
            r["duplicate"], false,
            "{}: the same id in another organization is fresh: {r}",
            who.org_id
        );
        firsts.push(r);
    }
    let ids: std::collections::BTreeSet<&str> =
        firsts.iter().map(|r| r["message_id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), 3);
    // A retry replays only its own organization's first result.
    for ((who, to), first) in senders.iter().zip(&firsts) {
        let r =
            h.send(who, json!({ "act": "inform", "to_agent": to, "body": "retry", "message_id": key })).await;
        assert_eq!(
            (r["duplicate"].clone(), r["message_id"].clone()),
            (json!(true), first["message_id"].clone())
        );
        // The client id resolves as reply_to and message_id inside its own
        // organization only.
        let l = h.ok(who, "message_list", json!({ "message_id": key })).await;
        assert_eq!(l["total"], 1, "{l}");
        assert_eq!(l["messages"][0]["message_id"], first["message_id"]);
    }
    // The stored keys: the default form unchanged, the others prefixed with
    // their escaped organization.
    let keys: Vec<String> = h
        .hub
        .db()
        .read(|c| {
            let mut stmt =
                c.prepare("SELECT key FROM idempotency_keys WHERE tool = 'message_send' ORDER BY key")?;
            Ok(stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
        })
        .unwrap();
    assert_eq!(
        keys,
        [
            "message_send/courier/same-client-id",
            "org:org-b%2Fmessage_send/message_send/courier/same-client-id",
            "org:org-b/message_send/courier/same-client-id",
        ]
    );

    // A receipt under organization B's key that names another
    // organization's message is never replayed: refused, naming nothing.
    let default_mid = firsts[0]["message_id"].as_str().unwrap().to_string();
    let planted = json!({ "accepted": true, "message_id": default_mid, "body": A_BODY, "to_agent": "to-a" });
    h.sql(&format!(
        "INSERT INTO idempotency_keys (key, tool, result_json, created_at)
         VALUES ('org:org-b/message_send/courier/planted', 'message_send', '{planted}', 'x')"
    ))
    .unwrap();
    let before = h.snapshot();
    let e = h
        .call(
            &senders[1].0,
            "message_send",
            json!({ "act": "inform", "to_agent": "to-b", "body": "x", "message_id": "planted" }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), "conflict", "{e:?}");
    assert!(!e.to_string().contains(&default_mid) && !e.to_string().contains(A_BODY), "{e}");
    assert_eq!(h.snapshot(), before);
    // A pre-scoping key (`message_send:<id>`) was the default
    // organization's: another organization's sender never replays it.
    let legacy = json!({ "accepted": true, "from_agent": "courier", "message_id": "old-1" });
    h.sql(&format!(
        "INSERT INTO idempotency_keys (key, tool, result_json, created_at) VALUES ('message_send:old-1', 'message_send', '{legacy}', 'x')"
    ))
    .unwrap();
    let r = h
        .send(
            &senders[1].0,
            json!({ "act": "inform", "to_agent": "to-b", "body": "fresh", "message_id": "old-1" }),
        )
        .await;
    assert_eq!(r["duplicate"], false, "{r}");
    let r = h
        .send(
            &senders[0].0,
            json!({ "act": "inform", "to_agent": "to-a", "body": "retry", "message_id": "old-1" }),
        )
        .await;
    assert_eq!((r["duplicate"].clone(), r["message_id"].clone()), (json!(true), json!("old-1")));
}

// --- relay -----------------------------------------------------------------------------------------

#[tokio::test]
async fn relay_status_and_cancel_answer_another_organizations_draft_as_missing() {
    let h = H::new();
    h.sql(
        "INSERT INTO approvals (id, org_id, tool, payload, requested_by, status, created_at, updated_at)
             VALUES (80, 'default', 'relay_manage', '{}', 'relay-a', 'pending', 'x', 'x'),
                    (81, 'org-b', 'relay_manage', '{}', 'relay-b', 'pending', 'x', 'x');
         INSERT INTO relay_messages (id, org_id, channel, target, text, text_sha256, chars, bytes, verdict, status,
             approval_id, requested_by, created_at, updated_at)
             VALUES (50, 'default', 'github', 'owner-a/repo#1', 'heron text', 'h', 1, 1, 'pass', 'pending_approval',
                     80, 'relay-a', 'x', 'x'),
                    (51, 'org-b', 'github', 'owner-b/osprey#1', 'osprey-body-not-real', 'h', 1, 1, 'pass',
                     'pending_approval', 81, 'relay-b', 'x', 'x');",
    )
    .unwrap();
    let relay = |action: &str, params: Value| json!({ "action": action, "params": params });
    let before = (h.snapshot(), h.event_count());
    for (who, other, other_approval) in [
        (human("operator", DEFAULT_ORG), 51, 81),
        (relay_agent("relay-a", DEFAULT_ORG), 51, 81),
        (human("b-operator", ORG_B), 50, 80),
        (relay_agent("relay-b", ORG_B), 50, 80),
    ] {
        for action in ["status", "cancel"] {
            let got = h.call(&who, "relay_manage", relay(action, json!({ "draft_id": other }))).await;
            let missing = h.call(&who, "relay_manage", relay(action, json!({ "draft_id": ABSENT }))).await;
            assert_eq!(reason(got.as_ref().unwrap_err()), "not_found", "{action}: {got:?}");
            same_as_missing(&got, &other.to_string(), &missing, &ABSENT.to_string());
        }
        let got =
            h.call(&who, "relay_manage", relay("status", json!({ "approval_id": other_approval }))).await;
        let missing = h.call(&who, "relay_manage", relay("status", json!({ "approval_id": ABSENT }))).await;
        same_as_missing(&got, &other_approval.to_string(), &missing, &ABSENT.to_string());
        let list = h.ok(&who, "relay_manage", relay("list", json!({}))).await;
        let ids: Vec<i64> =
            list["drafts"].as_array().unwrap().iter().map(|d| d["draft_id"].as_i64().unwrap()).collect();
        assert!(!ids.contains(&other), "{}: {list}", who.org_id);
    }
    assert_eq!(
        (h.snapshot(), h.event_count()),
        before,
        "no refused call changed a draft or ledgered anything"
    );
    // Each organization still sees its own.
    let st =
        h.ok(&human("b-operator", ORG_B), "relay_manage", relay("status", json!({ "draft_id": 51 }))).await;
    assert_eq!(st["approval_status"], "pending", "{st}");
    let st = h
        .ok(&human("operator", DEFAULT_ORG), "relay_manage", relay("status", json!({ "approval_id": 80 })))
        .await;
    assert_eq!(st["draft_id"], 50, "{st}");

    // Sending stays the default organization's, and so do checking and
    // drafting (the hub's allowlist, gates and credential).
    for action in ["check", "draft", "request_send", "send"] {
        let params = match action {
            "check" | "draft" => json!({ "target": "owner-b/osprey#1", "text": "hello" }),
            "request_send" => json!({ "draft_id": 51 }),
            _ => json!({ "draft_id": 51, "text": "hello" }),
        };
        let e =
            h.call(&relay_agent("relay-b", ORG_B), "relay_manage", relay(action, params)).await.unwrap_err();
        assert_eq!(reason(&e), "org_unsupported", "{action}: {e:?}");
    }
    assert_no_b(&h.ledger_text(), "the ledger");
}

// --- ledger events -----------------------------------------------------------------------------

/// Another organization's message event carries no `task_id` or
/// `delegation_id` (unchecked integers its sender chooses); its own row
/// keeps them. The default organization's events are unchanged.
#[tokio::test]
async fn another_organizations_message_event_carries_no_task_or_delegation_id() {
    let h = H::new();
    let m = seed(&h).await;
    let event_of = "FROM event_log e JOIN message_index i ON i.event_ulid = e.ulid";
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) {event_of} WHERE i.org_id = 'org-b' \
             AND (json_extract(e.payload, '$.task_id') IS NOT NULL \
                  OR json_extract(e.payload, '$.delegation_id') IS NOT NULL)"
        )),
        0
    );
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) {event_of} WHERE i.org_id = 'org-b' \
             AND json_type(e.payload, '$.task_id') = 'null' AND json_type(e.payload, '$.delegation_id') = 'null'"
        )),
        3,
        "the payload keeps its shape"
    );
    assert_eq!(
        h.count(
            "SELECT COUNT(*) FROM message_index WHERE org_id = 'org-b' \
             AND json_extract(org_payload, '$.task_id') IS NOT NULL AND task_id IS NOT NULL"
        ),
        3
    );
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM message_index WHERE org_id = 'org-b' \
             AND json_extract(org_payload, '$.delegation_id') = {B_DELEGATION} AND delegation_id = {B_DELEGATION}"
        )),
        1
    );
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) {event_of} WHERE i.org_id = 'default' AND json_extract(e.payload, '$.task_id') = {}",
            m.task_a
        )),
        2,
        "the default organization's events keep their task id"
    );
    assert!(!h.ledger_text().contains(&B_DELEGATION.to_string()));
    // Organization B's reader still sees both on its mail.
    let b_list = h.ok(&agent(B_READER, ORG_B), "message_list", json!({})).await;
    let rows = b_list["messages"].as_array().unwrap();
    assert!(rows.iter().all(|r| r["task_id"].is_i64()), "{b_list}");
    assert!(rows.iter().any(|r| r["delegation_id"] == B_DELEGATION), "{b_list}");
}

/// A conversation handoff's event is written to the default ledger: another
/// organization's records neither its conversation id nor its actor (in the
/// payload or the dedupe key), and only that organization lists it. The
/// default organization's events and keys are byte for byte as before.
#[tokio::test]
async fn another_organizations_conversation_handoff_keeps_its_conversation_out_of_the_ledger() {
    let h = H::new();
    let m = seed(&h).await;
    let (a_sender, b_reader) = (agent(A_SENDER, DEFAULT_ORG), agent(B_READER, ORG_B));
    let op_a = human("operator", DEFAULT_ORG);
    let b_conv = m.b["conversation_id"].as_str().unwrap().to_string();
    let a_conv = m.a["conversation_id"].as_str().unwrap().to_string();

    let created = h
        .coord(
            &b_reader,
            "conversation_handoff",
            json!({ "conversation_id": b_conv, "title": "Osprey follow-up" }),
        )
        .await
        .unwrap();
    let created_id = created["task_id"].as_i64().unwrap();
    for _ in 0..2 {
        h.coord(&b_reader, "conversation_handoff", json!({ "conversation_id": b_conv, "task_id": m.task_b }))
            .await
            .unwrap();
    }
    // Relinking appends nothing; the created task's event is not repeated.
    h.coord(&b_reader, "conversation_handoff", json!({ "conversation_id": b_conv, "task_id": created_id }))
        .await
        .unwrap();
    let events = |org_b: bool| -> Vec<(String, String)> {
        let cond = if org_b { "LIKE 'org/%'" } else { "NOT LIKE 'org/%'" };
        let sql = format!(
            "SELECT json_extract(payload, '$.conversation_id'), dedupe_key FROM event_log \
             WHERE channel = 'agent.conversation.handoff' AND json_extract(payload, '$.conversation_id') {cond} \
             ORDER BY seq"
        );
        h.hub
            .db()
            .read(move |c| {
                let mut stmt = c.prepare(&sql)?;
                Ok(stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?)
            })
            .unwrap()
    };
    let b_events = events(true);
    assert_eq!(b_events.len(), 2, "{b_events:?}");
    assert_eq!(b_events[0].0, b_events[1].0, "one conversation, one digest");
    for (conv, key) in &b_events {
        assert_eq!(conv.len(), "org/".len() + 40, "{conv}");
        assert!(key.starts_with("conversation-handoff:org/"), "{key}");
        assert!(!key.contains(&b_conv) && !key.contains(B_READER), "{key}");
    }
    assert!(b_events[0].1.ends_with(":created") && !b_events[1].1.ends_with(":created"), "{b_events:?}");
    let ledger = h.ledger_text();
    assert!(!ledger.contains(&b_conv), "the ledger leaks organization B's conversation id: {ledger}");
    assert_no_b(&ledger, "the ledger");

    // Organization B lists its handoffs.
    let listed =
        h.coord(&b_reader, "conversation_handoffs", json!({ "conversation_id": b_conv })).await.unwrap();
    let mut ids: Vec<i64> =
        listed["handoffs"].as_array().unwrap().iter().map(|t| t["task_id"].as_i64().unwrap()).collect();
    ids.sort_unstable();
    let mut want = vec![m.task_b, created_id];
    want.sort_unstable();
    assert_eq!(ids, want, "{listed}");
    assert!(listed["handoffs"].as_array().unwrap().iter().all(|t| t["by"].is_null()), "{listed}");

    // A default operator reusing the leaked id opens its own conversation
    // and reads none of organization B's handoff rows.
    h.send(
        &op_a,
        json!({ "act": "inform", "to_agent": A_READER, "body": "reuse", "conversation_id": b_conv }),
    )
    .await;
    let v = h.coord(&op_a, "conversation_handoffs", json!({ "conversation_id": b_conv })).await.unwrap();
    assert_eq!((v["handoffs"].clone(), v["unaudited"].clone()), (json!([]), json!([])), "{v}");

    // The default organization's events and keys are unchanged.
    h.coord(&a_sender, "conversation_handoff", json!({ "conversation_id": a_conv, "task_id": m.task_a }))
        .await
        .unwrap();
    let a_created = h
        .coord(
            &a_sender,
            "conversation_handoff",
            json!({ "conversation_id": a_conv, "title": "Heron follow-up" }),
        )
        .await
        .unwrap();
    let a_task = a_created["task_id"].as_i64().unwrap();
    assert_eq!(
        events(false),
        [
            (a_conv.clone(), format!("conversation-handoff:{a_conv}:{}:{A_SENDER}", m.task_a)),
            (a_conv.clone(), format!("conversation-handoff:{a_conv}:{a_task}:{A_SENDER}:created")),
        ]
    );
    let v = h.coord(&a_sender, "conversation_handoffs", json!({ "conversation_id": a_conv })).await.unwrap();
    assert_eq!(v["handoffs"].as_array().map(Vec::len), Some(2), "{v}");
    assert_eq!(v["handoffs"][0]["by"], A_SENDER, "{v}");
}

/// A legacy draft linked to another organization's approval (the
/// same-organization trigger fires only on insert or update, so the
/// migration keeps such a link) reports no approval and cannot be cancelled:
/// the cancel fails closed, and neither row changes.
#[test]
fn a_legacy_draft_linked_to_another_organizations_approval_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.human_identities = vec!["operator".into()];
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        add_org(&db, ORG_B, "active");
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO approvals (id, org_id, tool, payload, requested_by, status, created_at, updated_at)
                     VALUES (9, 'org-b', 'relay_manage', '{}', 'relay-b', 'pending', 'x', 'x');
                 INSERT INTO relay_messages (id, channel, target, text, text_sha256, chars, bytes, verdict,
                     findings, status, approval_id, requested_by, created_at, updated_at)
                 VALUES (8, 'github', 'owner/repo#3', 'hello', 'h', 5, 5, 'pass', '{}', 'pending_approval', 9,
                         'operator', 'x', 'x');",
            )?;
            Ok(())
        })
        .unwrap();
    }
    let hub = Hub::open(cfg).unwrap();
    let rows = |hub: &Hub| -> String {
        hub.db()
            .read(|c| {
                let draft: String = c.query_row(
                    "SELECT org_id || '|' || status || '|' || approval_id || '|' || COALESCE(text, '') \
                     FROM relay_messages WHERE id = 8",
                    [],
                    |r| r.get(0),
                )?;
                let approval: String = c.query_row(
                    "SELECT org_id || '|' || status || '|' || payload FROM approvals WHERE id = 9",
                    [],
                    |r| r.get(0),
                )?;
                Ok(format!("{draft} {approval}"))
            })
            .unwrap()
    };
    let before = rows(&hub);
    assert_eq!(before, "default|pending_approval|9|hello org-b|pending|{}", "the link is kept");
    let reg = builtin_registry();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let op = human("operator", DEFAULT_ORG);
        let relay = |action: &str| json!({ "action": action, "params": { "draft_id": 8 } });
        let st = reg.call(&hub, &op, "relay_manage", relay("status")).await.unwrap();
        assert_eq!(
            (st["approval_status"].clone(), st["resolved_by"].clone()),
            (Value::Null, Value::Null),
            "{st}"
        );
        let e = reg.call(&hub, &op, "relay_manage", relay("cancel")).await.unwrap_err();
        assert_eq!(reason(&e), "not_found", "{e:?}");
        // Organization B cannot reach the draft through its approval either.
        let b = human("operator", ORG_B);
        let e = reg
            .call(&hub, &b, "relay_manage", json!({ "action": "status", "params": { "approval_id": 9 } }))
            .await
            .unwrap_err();
        assert_eq!(reason(&e), "not_found", "{e:?}");
    });
    assert_eq!(rows(&hub), before, "neither the draft nor the approval changed");
}

// --- the insert guard --------------------------------------------------------------------------

/// Every `INSERT` into the three tables in any crate's source names `org_id`
/// (`org_classification.rs` runs the general guard; this pins these tables).
#[test]
fn every_insert_into_the_messaging_tables_names_its_organization() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let mut files = Vec::new();
    let mut stack = vec![crates];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if p.is_dir() {
                if !["tests", "target", "benches"].contains(&name.as_str()) {
                    stack.push(p);
                }
            } else if name.ends_with(".rs") {
                files.push(p);
            }
        }
    }
    let mut seen = 0;
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        for table in ["message_index", "message_reads", "relay_messages"] {
            for needle in [format!("INTO {table} ("), format!("INTO {table}(")] {
                for (at, _) in text.match_indices(&needle) {
                    let rest = &text[at..];
                    let cols = &rest[..rest.find(')').unwrap()];
                    assert!(cols.contains("org_id"), "{}: {cols}", f.display());
                    seen += 1;
                }
            }
        }
    }
    // messaging.rs (the message, the read receipt and the session ack) and
    // relay/mod.rs (the draft).
    assert!(seen >= 4, "found {seen} inserts");
}

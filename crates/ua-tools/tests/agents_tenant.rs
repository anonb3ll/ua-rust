//! The agent and session tables are tenant data (`docs/organization.md`,
//! the agents and sessions family).
//!
//! - `organization.v1.tools.agents` gives `agents`, `agent_sessions`,
//!   `agent_tokens`, `agent_lifecycle`, `session_profiles`,
//!   `session_credentials`, `session_handoff_notes`, `session_wake` and
//!   `session_wake_offers` their `org_id` and triggers; `agents.v2.org_scope`
//!   adds the organization-led indexes and the triggers that keep every
//!   reference (a session's agent and task, a token's agent, a credential's
//!   node and item, a note's and a wake row's session) in one organization.
//! - An agent belongs to the organization of the credential it
//!   authenticates with; agent labels stay one hub-wide namespace.
//!
//! No upgrade moves, rewrites or drops a row: every existing row is the
//! default organization's. A second organization is created at the storage
//! level, as no tool creates one yet, and its callers are built by hand.
//! Every value here is fake.

use std::path::Path;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const SUSPENDED: &str = "org-suspended";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 2] = ["organization.v1.tools.agents", "agents.v2.org_scope"];
const TABLES: [&str; 9] = [
    "agents",
    "agent_sessions",
    "agent_tokens",
    "agent_lifecycle",
    "session_profiles",
    "session_credentials",
    "session_handoff_notes",
    "session_wake",
    "session_wake_offers",
];

/// Default-organization labels.
const A_AGENT: &str = "heron-agent";
const A_LEAD: &str = "heron-lead";
const A_DEVICE: &str = "builder-1";
const A_NODE: &str = "node-a";
const A_ROOT: &str = "/srv/work-a";

/// Organization-B labels and text that must never reach the default
/// organization's ledger or replies.
const B_AGENT: &str = "osprey-agent-not-real";
const B_PEER: &str = "kestrel-peer-not-real";
const B_DEVICE: &str = "kestrel-device-not-real";
const B_SQUAT: &str = "falcon-squat-not-real";
const B_HOST: &str = "osprey-host-not-real";
const B_BRANCH: &str = "osprey-branch-not-real";
const B_EXT: &str = "osprey-external-session-not-real";
const B_WORKTREE: &str = "/srv/osprey-worktree-not-real";
const B_TRANSCRIPT: &str = "/srv/osprey-transcript-not-real";
const B_KIND: &str = "osprey-kind-not-real";
const B_EXIT: &str = "osprey-exit-not-real";
const B_TOOL: &str = "osprey_tool_not_real";
const B_REASON: &str = "osprey reason not real";
const B_DONE: &str = "osprey finished item not real";
const B_NODE: &str = "falcon-node-b";
const B_ROOT: &str = "/srv/osprey-root-not-real";
/// Every organization-B value a leak check looks for.
const B_SECRETS: [&str; 15] = [
    B_AGENT,
    B_PEER,
    B_DEVICE,
    B_SQUAT,
    B_HOST,
    B_BRANCH,
    B_EXT,
    B_WORKTREE,
    B_TRANSCRIPT,
    B_KIND,
    B_EXIT,
    B_TOOL,
    B_REASON,
    B_DONE,
    B_NODE,
];

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

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().take_while(|p| !PARTS.contains(&p.name)).collect()
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
        profile: Profile::Coordinator,
        enforce_profile: true,
        session_key: Some(format!("{label}-s")),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn human(label: &str, org: &str) -> Caller {
    Caller { kind: ActorKind::Human, profile: Profile::Operator, enforce_profile: false, ..agent(label, org) }
}

fn operator() -> Caller {
    human("operator", DEFAULT_ORG)
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

fn facts(root: &str) -> Value {
    json!({
        "backends": ["codex", "acp:claude"],
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
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into()];
        cfg.lifecycle_operators = Some(vec!["operator".into(), "fleet-bot".into()]);
        cfg.session_credentials_enabled = true;
        let hub = Hub::in_memory(cfg).unwrap();
        add_org(hub.db(), ORG_B, "active");
        add_org(hub.db(), SUSPENDED, "suspended");
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

    async fn session(&self, who: &Caller, args: Value) -> String {
        self.ok(who, "session_start", args).await["session_id"].as_str().unwrap().to_string()
    }

    /// Grant a parked approval by SQL (no organization-B human can yet).
    fn approve(&self, id: i64) {
        let now = ua_core::time::now();
        self.sql(&format!(
            "UPDATE approvals SET status = 'approved', resolved_by = 'operator', resolved_at = '{now}', \
             updated_at = '{now}' WHERE id = {id}"
        ))
        .unwrap();
    }

    /// Park the call, approve each approval it asks for, and retry it.
    async fn gated(&self, who: &Caller, tool: &str, args: Value) -> Value {
        for _ in 0..3 {
            match self.call(who, tool, args.clone()).await {
                Err(UaError::ApprovalRequired { approval_id, .. }) => self.approve(approval_id),
                Ok(v) => return v,
                other => panic!("{tool}({args}): expected an approval, got {other:?}"),
            }
        }
        panic!("{tool}({args}): still gated")
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

    /// Every row of the nine tables and the event count, as text: a
    /// refused call leaves it identical.
    fn snapshot(&self) -> String {
        let mut out: Vec<String> = TABLES
            .iter()
            .map(|t| {
                let t = t.to_string();
                self.hub
                    .db()
                    .read(move |c| {
                        let mut stmt = c.prepare(&format!("SELECT * FROM {t} ORDER BY rowid"))?;
                        let n = stmt.column_count();
                        let rows = stmt.query_map([], |r| {
                            (0..n)
                                .map(|i| Ok(format!("{:?}", r.get_ref(i)?)))
                                .collect::<rusqlite::Result<Vec<_>>>()
                        })?;
                        let rows = rows.collect::<Result<Vec<_>, _>>()?;
                        Ok(format!("{t}: {rows:?}"))
                    })
                    .unwrap()
            })
            .collect();
        out.push(format!("events: {}", self.count("SELECT COUNT(*) FROM event_log")));
        out.join("\n")
    }

    /// The whole ledger as text, for leak checks.
    fn ledger_text(&self) -> String {
        self.hub
            .db()
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT channel, COALESCE(originator, ''), payload, COALESCE(episode_id, ''), \
                     COALESCE(dedupe_key, '') FROM event_log ORDER BY seq",
                )?;
                let rows = stmt.query_map([], |r| {
                    Ok(format!(
                        "{} {} {} {} {}",
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?
                    ))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?.join("\n"))
            })
            .unwrap()
    }
}

fn assert_no_b(text: &str, what: &str) {
    for needle in B_SECRETS {
        assert!(!text.contains(needle), "{what} leaks {needle:?}: {text}");
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

// --- the upgrade ---------------------------------------------------------------------------------

const LEGACY_ROWS: &str = "
INSERT INTO tasks (id, title, created_at, updated_at) VALUES (1, 'Legacy task', 't0', 't0');
INSERT INTO agents (label, kind, host, known, created_at, updated_at) VALUES ('builder-1', 'cli', 'box', 1, 't0', 't0');
INSERT INTO agent_sessions (id, agent, kind, status, started_at, last_heartbeat_at, task_id, host)
    VALUES ('s-legacy-1', 'builder-1', 'interactive', 'completed', 't0', 't0', 1, 'box'),
           ('s-legacy-2', 'builder-1', 'interactive', 'running', 't1', 't1', NULL, 'box');
INSERT INTO agent_tokens (agent_label, token_hash, issued_at) VALUES ('builder-1', 'legacy-token-hash', 't0');
INSERT INTO agent_lifecycle (agent, state, action, actor, since) VALUES ('builder-1', 'paused', 'pause', 'operator', 't0');
INSERT INTO session_profiles (identity, session_key, profile, updated_at) VALUES ('builder-1', 'k-1', 'research', 't0');
INSERT INTO nodes (node, agent, facts_json, registered_at, last_heartbeat, updated_at)
    VALUES ('legacy-node', 'builder-1', '{}', 't0', 't0', 't0');
INSERT INTO node_dispatch (id, node, agent, backend, prompt, cwd, timeout_s, status, created_by, created_at, updated_at)
    VALUES ('nd-0000000000000001', 'legacy-node', 'builder-1', 'acp:claude', 'p', '/srv/work', 60, 'finished',
            'lead-1', 't1', 't1');
INSERT INTO session_credentials (credential_id, token_sha256, agent_label, node, item_id, attempt, tools_json,
                                 issued_by, issued_at, idle_expires_at, expires_at, revoked_at)
    VALUES ('0123456789abcdef', 'legacy-cred-hash', 'builder-1', 'legacy-node', 'nd-0000000000000001', 1, '[]',
            'builder-1', 't1', 't1', 't1', 't2');
INSERT INTO session_handoff_notes (session_id, agent, task_id, done, next_steps, state, created_at, updated_at)
    VALUES ('s-legacy-1', 'builder-1', 1, '[\"d\"]', '[\"n\"]', 'draft', 't0', 't0');
INSERT INTO session_wake (session_id, opted_in, node, updated_at) VALUES ('s-legacy-2', 1, 'legacy-node', 't0');
INSERT INTO session_wake_offers (offer_id, session_id, node, offered_seq, offered_at, expires_at)
    VALUES ('00000000000000000000000000000001', 's-legacy-2', 'legacy-node', 1, 1.0, 2.0);
";

#[test]
fn a_legacy_database_upgrades_every_row_into_the_default_organization() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.human_identities = vec!["operator".into()];
    let counts = |c: &rusqlite::Connection| -> Vec<i64> {
        TABLES
            .iter()
            .map(|t| c.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0)).unwrap())
            .collect()
    };
    let before = {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(LEGACY_ROWS)?;
            Ok(())
        })
        .unwrap();
        db.read(|c| Ok(counts(c))).unwrap()
    };
    assert!(before.iter().all(|n| *n > 0), "every table has a legacy row: {before:?}");

    // Open the hub twice: the second open is idempotent.
    for _ in 0..2 {
        let hub = Hub::open(cfg.clone()).unwrap();
        hub.db()
            .read(|c| {
                assert_eq!(counts(c), before, "nothing dropped");
                for t in TABLES {
                    let other: i64 =
                        c.query_row(&format!("SELECT COUNT(*) FROM {t} WHERE org_id <> 'default'"), [], |r| r.get(0))?;
                    assert_eq!(other, 0, "{t}: every row lands in the default organization");
                    let triggers = names(c, "trigger", t);
                    for suffix in ["org_exists", "org_immutable"] {
                        assert!(triggers.contains(&format!("{t}_{suffix}")), "{t}: {triggers:?}");
                    }
                }
                for t in TABLES.iter().filter(|t| !matches!(**t, "agents")) {
                    let triggers = names(c, "trigger", t);
                    assert!(triggers.contains(&format!("{t}_org_parent")), "{t}: {triggers:?}");
                }
                // The legacy trigger the continuity family installed survives.
                assert!(names(c, "trigger", "session_handoff_notes").contains(&"session_handoff_notes_forward_only".into()));
                let recorded: i64 = c.query_row(
                    "SELECT COUNT(*) FROM schema_parts WHERE name IN ('organization.v1.tools.agents', 'agents.v2.org_scope')",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(recorded, 2);
                Ok(())
            })
            .unwrap();
    }
}

// --- isolation -------------------------------------------------------------------------------------

struct Seed {
    a_sid: String,
    b_sid: String,
}

async fn seed(h: &H) -> Seed {
    let (a, b) = (agent(A_AGENT, DEFAULT_ORG), agent(B_AGENT, ORG_B));
    h.ok(&a, "agent_heartbeat", json!({ "host": "heron-host", "kind": "cli" })).await;
    h.ok(&b, "agent_heartbeat", json!({ "host": B_HOST, "kind": "cli" })).await;
    let a_sid = h.session(&a, json!({ "kind": "interactive", "branch": "heron-branch" })).await;
    let b_sid = h
        .session(
            &b,
            json!({ "kind": B_KIND, "branch": B_BRANCH, "external_session_id": B_EXT,
                    "worktree_path": B_WORKTREE, "transcript_path": B_TRANSCRIPT, "host": B_HOST }),
        )
        .await;
    Seed { a_sid, b_sid }
}

#[tokio::test]
async fn every_read_is_isolated_per_organization() {
    let h = H::new();
    let s = seed(&h).await;
    let (a, b) = (agent(A_AGENT, DEFAULT_ORG), agent(B_AGENT, ORG_B));

    // Lists: each organization sees only its own agents and sessions.
    for (who, own_agent, own_sid, other_sid) in
        [(&a, A_AGENT, &s.a_sid, &s.b_sid), (&b, B_AGENT, &s.b_sid, &s.a_sid)]
    {
        let list = h.ok(who, "session_list", json!({})).await;
        let ids: Vec<&str> =
            list["sessions"].as_array().unwrap().iter().map(|x| x["id"].as_str().unwrap()).collect();
        assert_eq!(ids, [own_sid.as_str()], "{}: {list}", who.org_id);
        let live = h.ok(who, "session_list", json!({ "live_only": true })).await;
        assert!(!live.to_string().contains(other_sid.as_str()), "{live}");
        let agents = h.ok(who, "agent_list", json!({})).await;
        let labels: Vec<&str> =
            agents["agents"].as_array().unwrap().iter().map(|x| x["label"].as_str().unwrap()).collect();
        assert_eq!(labels, [own_agent], "{}: {agents}", who.org_id);
        let ctx = h.ok(who, "agent_context", json!({})).await;
        assert!(!ctx.to_string().contains(other_sid.as_str()), "{ctx}");
        let runs = h.ok(who, "run_list", json!({ "kind": "session" })).await;
        assert!(
            runs.to_string().contains(own_sid.as_str()) && !runs.to_string().contains(other_sid.as_str()),
            "{runs}"
        );
        let states = h.manage(who, "agent_states", json!({})).await.unwrap();
        assert!(
            !states.to_string().contains(if who.org_id == ORG_B { A_AGENT } else { B_AGENT }),
            "{states}"
        );
    }
    assert_no_b(&h.ok(&a, "agent_context", json!({})).await.to_string(), "the default agent_context");

    // By id: the other organization's session, agent and handoff answer as
    // missing ones.
    for (who, other) in [(&b, &s.a_sid), (&a, &s.b_sid)] {
        for (tool, args) in [
            ("session_packet", json!({ "session_id": "SID" })),
            ("crew_view", json!({ "session_id": "SID" })),
            ("run_get", json!({ "run_id": "SID", "kind": "session" })),
            ("platform_object_get", json!({ "kind": "session", "id": "SID" })),
            ("session_end", json!({ "session_id": "SID" })),
        ] {
            let with =
                |id: &str| serde_json::from_str::<Value>(&args.to_string().replace("SID", id)).unwrap();
            let got = h.call(who, tool, with(other)).await;
            let missing = h.call(who, tool, with("no-such-session")).await;
            same_as_missing(&got, other, &missing, "no-such-session");
        }
        for (action, params) in [
            ("session_handoff_recover", json!({ "session_id": "SID" })),
            ("session_wake_status", json!({ "session_id": "SID" })),
        ] {
            let with =
                |id: &str| serde_json::from_str::<Value>(&params.to_string().replace("SID", id)).unwrap();
            let got = h.manage(who, action, with(other)).await;
            let missing = h.manage(who, action, with("no-such-session")).await;
            same_as_missing(&got, other, &missing, "no-such-session");
        }
    }
    let (got, missing) = (
        h.call(&b, "platform_object_get", json!({ "kind": "agent", "id": A_AGENT })).await,
        h.call(&b, "platform_object_get", json!({ "kind": "agent", "id": "nobody-here" })).await,
    );
    same_as_missing(&got, A_AGENT, &missing, "nobody-here");
    // An agent of another organization reads as one with no lifecycle record.
    let st = h.manage(&b, "agent_state", json!({ "agent": A_AGENT })).await.unwrap();
    let unknown = h.manage(&b, "agent_state", json!({ "agent": "nobody-here" })).await.unwrap();
    assert_eq!(st.to_string().replace(A_AGENT, "X"), unknown.to_string().replace("nobody-here", "X"));
    // An own session reads in full, without `org_id`.
    let own = h.ok(&b, "platform_object_get", json!({ "kind": "session", "id": s.b_sid })).await;
    assert!(own.get("org_id").is_none() && !own.to_string().contains("\"org_id\""), "{own}");
    let view = h.ok(&b, "crew_view", json!({ "session_id": s.b_sid })).await;
    assert_eq!(view["session"]["id"], json!(s.b_sid), "{view}");

    // A lifecycle observation naming another organization's session joins
    // no session: it is recorded without one, and answers as for a missing
    // session.
    let rec = h
        .ok(&a, "lifecycle_record", json!({ "kind": "tool_start", "session_id": s.b_sid, "tool": "fs_read" }))
        .await;
    assert_eq!(rec["accepted"], true);
    assert_eq!(rec["session_id"], json!(s.b_sid));
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM event_log WHERE episode_id = '{}' OR payload LIKE '%{}%'",
            s.b_sid, s.b_sid
        )),
        h.count(&format!(
            "SELECT COUNT(*) FROM event_log WHERE channel GLOB 'agent.session.*' AND payload LIKE '%{}%'",
            s.b_sid
        )),
        "only B's own session events name it"
    );
    assert_no_b(&h.ledger_text(), "the ledger");
}

// --- the token and auth path --------------------------------------------------------------------

#[tokio::test]
async fn a_managed_token_resolves_to_its_agents_organization() {
    use ua_tools::families::tokens::{digest, held_outside_default, resolve_managed_token};
    let h = H::new();
    let b = agent(B_AGENT, ORG_B);
    h.ok(&b, "agent_heartbeat", json!({})).await;
    let (b_value, a_value, odd_value) = (
        "b-token-value-not-real-0123456789abcdef",
        "a-token-value-0123456789abcdef-x",
        "odd-token-value-0123456789abcdef-x",
    );
    h.sql(&format!(
        "INSERT INTO agent_tokens (org_id, agent_label, token_hash, issued_at) VALUES
             ('{ORG_B}', '{B_AGENT}', '{}', 't0'),
             ('default', '{A_AGENT}', '{}', 't0'),
             ('{ORG_B}', 'odd-agent', '{}', 't0');",
        digest(b_value),
        digest(a_value),
        digest(odd_value)
    ))
    .unwrap();
    // The agents row of `odd-agent` appears in the default organization
    // afterwards (only SQL can do this: every writer refuses the label).
    h.sql("INSERT INTO agents (org_id, label, created_at, updated_at) VALUES ('default', 'odd-agent', 't0', 't0');")
        .unwrap();
    let resolve = |v: &str| {
        let v = v.to_string();
        h.hub.db().read(move |c| resolve_managed_token(c, &v)).unwrap()
    };
    assert_eq!(resolve(b_value), Some((B_AGENT.to_string(), ORG_B.to_string())));
    assert_eq!(resolve(a_value), Some((A_AGENT.to_string(), DEFAULT_ORG.to_string())));
    assert_eq!(resolve(odd_value), None, "a token whose organization is not its agent's is refused");
    assert_eq!(resolve("never-issued-token-value-0123456789"), None);
    // A credential that always resolves to the default organization (a
    // static token, an OAuth grant) is refused for B's agent.
    let held = |l: &str| {
        let l = l.to_string();
        h.hub.db().read(move |c| held_outside_default(c, &l)).unwrap()
    };
    assert!(held(B_AGENT) && held(&B_AGENT.to_uppercase()));
    assert!(!held(A_AGENT) && !held("never-registered"));
    // A token cannot be inserted for another organization's agent at all.
    let e = h
        .sql(&format!(
            "INSERT INTO agent_tokens (org_id, agent_label, token_hash, issued_at) VALUES ('default', '{B_AGENT}', 'h-x', 't0');"
        ))
        .unwrap_err();
    assert!(e.contains("another organization"), "{e}");
}

// --- the label namespace and hub recovery --------------------------------------------------------

#[tokio::test]
async fn agent_labels_are_one_namespace_and_the_hub_can_recover_one() {
    let h = H::new();
    let (a, b) = (agent(A_AGENT, DEFAULT_ORG), agent(B_AGENT, ORG_B));
    h.ok(&a, "agent_heartbeat", json!({})).await;
    h.ok(&b, "agent_heartbeat", json!({})).await;
    let before = h.snapshot();
    // B may not take a label the default organization holds, in any case,
    // and the default organization may not take B's. The refusal names
    // neither organization.
    for (who, label) in [
        (agent(A_AGENT, ORG_B), A_AGENT),
        (agent(&A_AGENT.to_uppercase(), ORG_B), A_AGENT),
        (agent(B_AGENT, DEFAULT_ORG), B_AGENT),
    ] {
        for (tool, args) in [
            ("agent_heartbeat", json!({})),
            ("session_start", json!({ "kind": "interactive" })),
            ("profile_activate", json!({ "profile": "research" })),
        ] {
            let e = h.call(&who, tool, args).await.unwrap_err();
            assert_eq!(reason(&e), "agent_label_taken", "{}/{}: {tool}: {e:?}", who.org_id, who.label);
            assert!(!e.to_string().contains(ORG_B) && !e.to_string().contains(DEFAULT_ORG), "{e:?}");
        }
        let issuer = human("operator", if who.org_id == ORG_B { ORG_B } else { DEFAULT_ORG });
        let e = h
            .call(&issuer, "agent_token_issue", json!({ "agent_label": label, "value": "v".repeat(40) }))
            .await
            .unwrap_err();
        assert_eq!(reason(&e), "agent_label_taken", "{e:?}");
    }
    assert_eq!(h.snapshot(), before, "nothing written");

    // B squats a label; a default lifecycle change without hub recovery
    // refuses it as taken.
    let squat = agent(B_SQUAT, ORG_B);
    h.session(&squat, json!({ "kind": "interactive" })).await;
    h.sql(&format!(
        "INSERT INTO agent_tokens (org_id, agent_label, token_hash, issued_at) VALUES ('{ORG_B}', '{B_SQUAT}', 'squat-hash', 't0');"
    ))
    .unwrap();
    let fleet = agent("fleet-bot", DEFAULT_ORG);
    let e =
        h.manage(&fleet, "agent_retire", json!({ "agent": B_SQUAT, "reason": B_REASON })).await.unwrap_err();
    assert_eq!(reason(&e), "agent_label_taken", "{e:?}");
    // Only the default organization's lifecycle operators recover a label.
    for who in [agent(A_AGENT, DEFAULT_ORG), human("operator", ORG_B), agent("fleet-bot", ORG_B)] {
        let e = h
            .manage(&who, "agent_retire", json!({ "agent": B_SQUAT, "reason": B_REASON, "any_org": true }))
            .await
            .unwrap_err();
        assert_eq!(reason(&e), "not_lifecycle_operator", "{}/{}: {e:?}", who.org_id, who.label);
    }
    let e = h
        .manage(&fleet, "agent_forget", json!({ "agent": B_SQUAT, "reason": B_REASON, "any_org": true }))
        .await;
    assert_eq!(reason(&e.unwrap_err()), "agent_not_retired");

    // Hub recovery: retire, then forget, in B's organization, answered
    // without B's fields.
    let out = h
        .manage(&fleet, "agent_retire", json!({ "agent": B_SQUAT, "reason": B_REASON, "any_org": true }))
        .await
        .unwrap();
    let keys: Vec<&str> = out.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["agent", "changed", "hub_recovery", "org_id", "retired"], "{out}");
    assert_eq!(out["org_id"], ORG_B);
    assert_eq!(
        h.text(&format!("SELECT org_id || ':' || state FROM agent_lifecycle WHERE agent = '{B_SQUAT}'")),
        "org-b:retired"
    );
    assert_eq!(h.text("SELECT status FROM agent_tokens WHERE token_hash = 'squat-hash'"), "revoked");
    let out = h
        .manage(&fleet, "agent_forget", json!({ "agent": B_SQUAT, "reason": B_REASON, "any_org": true }))
        .await
        .unwrap();
    let keys: Vec<&str> = out.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["agent", "changed", "forgotten", "hub_recovery", "org_id"], "{out}");
    assert_eq!(h.count(&format!("SELECT COUNT(*) FROM agents WHERE label = '{B_SQUAT}'")), 0);
    assert_eq!(h.count(&format!("SELECT COUNT(*) FROM agent_lifecycle WHERE agent = '{B_SQUAT}'")), 0);
    // B's history stays in B; the label is free again.
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM agent_sessions WHERE agent = '{B_SQUAT}' AND org_id = 'org-b'"
        )),
        1
    );
    h.ok(&agent(B_SQUAT, DEFAULT_ORG), "agent_heartbeat", json!({})).await;
    assert_eq!(h.text(&format!("SELECT org_id FROM agents WHERE label = '{B_SQUAT}'")), DEFAULT_ORG);
    // The ledger names neither the squatted label nor the reason.
    let ledger = h.ledger_text();
    let lifecycle: Vec<&str> = ledger.lines().filter(|l| l.starts_with("agent.lifecycle ")).collect();
    assert_eq!(lifecycle.len(), 2, "{ledger}");
    for l in lifecycle {
        assert!(l.contains(" system ") && !l.contains(B_SQUAT) && !l.contains(B_REASON), "{l}");
    }
}

// --- lifted carve-outs ----------------------------------------------------------------------------

#[tokio::test]
async fn handoff_notes_and_lifecycle_work_inside_another_organization() {
    let h = H::new();
    let s = seed(&h).await;
    let (a, b) = (agent(A_AGENT, DEFAULT_ORG), agent(B_AGENT, ORG_B));
    let note = h
        .manage(
            &b,
            "session_handoff_propose",
            json!({ "session_id": s.b_sid, "done": [B_DONE], "next_steps": [B_DONE] }),
        )
        .await
        .unwrap();
    assert!(note.get("org_id").is_none(), "{note}");
    let id = note["id"].as_i64().unwrap();
    h.manage(&b, "session_handoff_seal", json!({ "note_id": id })).await.unwrap();
    let rec = h.manage(&b, "session_handoff_recover", json!({ "session_id": s.b_sid })).await.unwrap();
    assert_eq!(rec["note"]["id"], id, "{rec}");
    assert_eq!(h.text(&format!("SELECT org_id FROM session_handoff_notes WHERE id = {id}")), ORG_B);
    // The default organization's agent of the same session id or note id
    // finds nothing.
    for (action, params, missing) in [
        (
            "session_handoff_update",
            json!({ "note_id": id, "done": ["x"] }),
            json!({ "note_id": 987_654, "done": ["x"] }),
        ),
        ("session_handoff_discard", json!({ "note_id": id }), json!({ "note_id": 987_654 })),
        ("session_handoff_ack", json!({ "note_id": id }), json!({ "note_id": 987_654 })),
    ] {
        let got = h.manage(&a, action, params).await;
        let gone = h.manage(&a, action, missing).await;
        same_as_missing(&got, &id.to_string(), &gone, "987654");
    }
    let e = h
        .manage(
            &a,
            "session_handoff_propose",
            json!({ "session_id": s.b_sid, "done": ["x"], "next_steps": ["y"] }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), "not_found", "{e:?}");

    // B pauses itself: the row is B's, the states list is B's.
    h.manage(&b, "agent_pause", json!({ "agent": B_AGENT, "reason": B_REASON })).await.unwrap();
    assert_eq!(h.text(&format!("SELECT org_id FROM agent_lifecycle WHERE agent = '{B_AGENT}'")), ORG_B);
    let states = h.manage(&b, "agent_states", json!({})).await.unwrap();
    assert_eq!(states["agents"][0]["state"], "paused", "{states}");
    let a_states = h.manage(&a, "agent_states", json!({})).await.unwrap();
    assert_no_b(&a_states.to_string(), "the default agent_states");
    h.manage(&b, "agent_resume", json!({ "agent": B_AGENT })).await.unwrap();
    assert_no_b(&h.ledger_text(), "the ledger");
}

#[tokio::test]
async fn session_credentials_and_wakes_work_per_organization() {
    let h = H::new();
    let (b_device, b_lead) = (agent(B_DEVICE, ORG_B), agent(B_PEER, ORG_B));
    let a_device = agent(A_DEVICE, DEFAULT_ORG);
    h.ok(&a_device, "node_register", json!({ "node": A_NODE, "facts": facts(A_ROOT) })).await;
    h.ok(&b_device, "node_register", json!({ "node": B_NODE, "facts": facts(B_ROOT) })).await;

    // A session credential for B's ACP item is B's, and verifies into B.
    let item = h
        .gated(
            &b_lead,
            "node_dispatch",
            json!({ "node": B_NODE, "backend": "acp:claude", "prompt": "p", "cwd": format!("{B_ROOT}/repo") }),
        )
        .await["item_id"]
        .as_str()
        .unwrap()
        .to_string();
    let claimed = h.ok(&b_device, "node_claim", json!({ "node": B_NODE })).await;
    assert_eq!(claimed["item"]["item_id"], json!(item));
    let minted = h
        .ok(&b_device, "node_session_credential", json!({ "node": B_NODE, "item_id": item, "attempt": 1 }))
        .await;
    let value = minted["credential"].as_str().unwrap().to_string();
    assert_eq!(
        h.text(&format!(
            "SELECT org_id FROM session_credentials WHERE credential_id = '{}'",
            minted["credential_id"].as_str().unwrap()
        )),
        ORG_B
    );
    let v = ua_tools::families::node_queue::credentials::verify(&h.hub, &value).unwrap();
    assert_eq!((v.subject.as_str(), v.org.as_str()), (B_DEVICE, ORG_B));
    // The default organization's device cannot mint for B's item: B's node
    // is not its.
    let e = h
        .call(&a_device, "node_session_credential", json!({ "node": B_NODE, "item_id": item, "attempt": 1 }))
        .await
        .unwrap_err();
    let missing = h
        .call(
            &a_device,
            "node_session_credential",
            json!({ "node": "node-zz", "item_id": item, "attempt": 1 }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.to_string().replace(B_NODE, "N"), missing.to_string().replace("node-zz", "N"));

    // Idle-session wakes: B's own session asks through B's node, a B human
    // grants it, and only B's node is offered it once trigger mail waits.
    let b_sid = h
        .session(&b_device, json!({ "kind": "interactive", "external_session_id": B_EXT, "host": B_NODE }))
        .await;
    h.manage(&b_device, "session_wake_opt_in", json!({ "session_id": b_sid, "node": B_NODE })).await.unwrap();
    h.manage(&human("b-human-not-real", ORG_B), "session_wake_grant", json!({ "session_id": b_sid }))
        .await
        .unwrap();
    assert_eq!(h.text(&format!("SELECT org_id FROM session_wake WHERE session_id = '{b_sid}'")), ORG_B);
    h.ok(&b_lead, "message_send", json!({ "act": "request", "to_agent": B_DEVICE, "body": B_DONE })).await;
    h.sql("UPDATE message_index SET created_at = '2026-01-01T00:00:00+00:00' WHERE org_id = 'org-b';")
        .unwrap();
    // A default node (and the default organization's status) never sees it.
    let a_poll = h.ok(&a_device, "node_wake", json!({ "node": A_NODE, "offer_version": 3 })).await;
    assert_eq!(a_poll, json!({ "wakes": [] }));
    let status = h.manage(&operator(), "session_wake_status", json!({})).await.unwrap();
    assert_eq!(status["count"], 0, "{status}");
    let b_poll = h.ok(&b_device, "node_wake", json!({ "node": B_NODE, "offer_version": 3 })).await;
    let wakes = b_poll["wakes"].as_array().unwrap();
    assert_eq!(wakes.len(), 1, "{b_poll}");
    assert_eq!(wakes[0]["session_id"], json!(b_sid));
    assert_eq!(h.text("SELECT org_id FROM session_wake_offers"), ORG_B);
    let b_status = h.manage(&b_device, "session_wake_status", json!({})).await.unwrap();
    assert_eq!(b_status["count"], 1, "{b_status}");
    assert_no_b(&h.ledger_text(), "the ledger");
}

#[tokio::test]
async fn a_delegation_targets_only_the_delegators_organization() {
    let h = H::new();
    let (lead_a, b) = (agent(A_LEAD, DEFAULT_ORG), agent(B_AGENT, ORG_B));
    h.ok(&b, "agent_heartbeat", json!({})).await;
    h.ok(&agent(B_PEER, ORG_B), "agent_heartbeat", json!({})).await;
    let before = h.count("SELECT COUNT(*) FROM delegations");
    let got = h.call(&lead_a, "delegate", json!({ "to_agent": B_AGENT, "task_spec": SPEC })).await;
    assert_eq!(got.as_ref().unwrap_err().code(), "not_found", "{got:?}");
    assert_eq!(h.count("SELECT COUNT(*) FROM delegations"), before, "nothing created");
    assert_eq!(h.count("SELECT COUNT(*) FROM tasks"), 0, "no task either");
    // A label no organization holds, and an agent of the delegator's own
    // organization, are delegated to as before.
    h.ok(&lead_a, "delegate", json!({ "to_agent": "never-registered-agent", "task_spec": SPEC })).await;
    h.ok(&b, "delegate", json!({ "to_agent": B_PEER, "task_spec": SPEC })).await;
    assert_eq!(h.count("SELECT COUNT(*) FROM delegations WHERE org_id = 'org-b'"), 1);
    // B's agent claims its own delegation.
    let mine = h.ok(&agent(B_PEER, ORG_B), "delegate_list", json!({})).await;
    assert!(mine.to_string().contains(B_PEER), "{mine}");
    // The default organization's lead cannot delegate to B's agent in any
    // letter case either.
    let got =
        h.call(&lead_a, "delegate", json!({ "to_agent": B_PEER.to_uppercase(), "task_spec": SPEC })).await;
    assert_eq!(got.unwrap_err().code(), "not_found");
}

#[tokio::test]
async fn node_reassign_refuses_an_agent_of_another_organization() {
    let h = H::new();
    let a_device = agent(A_DEVICE, DEFAULT_ORG);
    h.ok(&a_device, "node_register", json!({ "node": A_NODE, "facts": facts(A_ROOT) })).await;
    // B's agent has an agent row and nothing else: no node, no work.
    h.ok(&agent(B_AGENT, ORG_B), "agent_heartbeat", json!({})).await;
    let e = h
        .manage(&operator(), "node_reassign", json!({ "node": A_NODE, "to_agent": B_AGENT, "reason": "x" }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "agent_org_mismatch", "{e:?}");
    let ok = h
        .manage(
            &operator(),
            "node_reassign",
            json!({ "node": A_NODE, "to_agent": "heron-second", "reason": "x" }),
        )
        .await
        .unwrap();
    assert_eq!(ok["changed"], true, "{ok}");
}

#[tokio::test]
async fn an_unknown_or_suspended_organization_is_refused_before_any_write() {
    let h = H::new();
    let s = seed(&h).await;
    let before = h.snapshot();
    for (org, want) in [(UNKNOWN, "unknown_organization"), (SUSPENDED, "organization_suspended")] {
        let who = agent("lark-agent", org);
        for (tool, args) in [
            ("agent_heartbeat", json!({})),
            ("session_start", json!({ "kind": "interactive" })),
            ("session_end", json!({ "session_id": s.a_sid })),
            ("profile_activate", json!({ "profile": "research" })),
        ] {
            let e = h.call(&who, tool, args).await.unwrap_err();
            assert_eq!(reason(&e), want, "{org}: {tool}: {e:?}");
        }
        for (action, params) in [
            ("session_handoff_propose", json!({ "session_id": s.a_sid, "done": ["x"], "next_steps": ["y"] })),
            ("session_wake_opt_in", json!({ "session_id": s.a_sid })),
            ("agent_pause", json!({ "agent": "lark-agent", "reason": "x" })),
        ] {
            let e = h.manage(&who, action, params).await.unwrap_err();
            assert_eq!(reason(&e), want, "{org}: {action}: {e:?}");
        }
        let e = h
            .call(
                &human("operator", org),
                "agent_token_issue",
                json!({ "agent_label": "lark-agent", "value": "v".repeat(40) }),
            )
            .await
            .unwrap_err();
        assert_eq!(reason(&e), want, "{org}: token issue: {e:?}");
        // A lifecycle observation is fire-and-forget: it reports the
        // capture failure and records nothing.
        let r = h.ok(&who, "lifecycle_record", json!({ "kind": "stop" })).await;
        assert_eq!(r["accepted"], false, "{r}");
    }
    assert_eq!(h.snapshot(), before, "nothing changed");
}

#[test]
fn the_triggers_keep_every_reference_in_one_organization() {
    let h = H::new();
    h.sql(&format!(
        "INSERT INTO agents (org_id, label, created_at, updated_at) VALUES ('default', '{A_AGENT}', 't', 't');
         INSERT INTO agents (org_id, label, created_at, updated_at) VALUES ('{ORG_B}', '{B_AGENT}', 't', 't');
         INSERT INTO agent_sessions (org_id, id, agent, kind, started_at, last_heartbeat_at)
             VALUES ('default', 's-a', '{A_AGENT}', 'k', 't', 't'), ('{ORG_B}', 's-b', '{B_AGENT}', 'k', 't', 't');
         INSERT INTO nodes (org_id, node, agent, facts_json, registered_at, last_heartbeat, updated_at)
             VALUES ('default', '{A_NODE}', '{A_AGENT}', '{{}}', 't', 't', 't');"
    ))
    .unwrap();
    for bad in [
        format!(
            "INSERT INTO agent_sessions (org_id, id, agent, kind, started_at, last_heartbeat_at) VALUES ('{ORG_B}', 's-x', '{A_AGENT}', 'k', 't', 't')"
        ),
        format!(
            "INSERT INTO agent_tokens (org_id, agent_label, token_hash, issued_at) VALUES ('{ORG_B}', '{A_AGENT}', 'h1', 't')"
        ),
        format!(
            "INSERT INTO agent_lifecycle (org_id, agent, state, action, actor, since) VALUES ('{ORG_B}', '{}', 'paused', 'pause', 'x', 't')",
            A_AGENT.to_uppercase()
        ),
        format!(
            "INSERT INTO session_profiles (org_id, identity, session_key, profile, updated_at) VALUES ('{ORG_B}', '{A_AGENT}', 'k', 'research', 't')"
        ),
        format!(
            "INSERT INTO session_handoff_notes (org_id, session_id, agent, done, next_steps, created_at, updated_at) VALUES ('{ORG_B}', 's-a', '{B_AGENT}', '[]', '[]', 't', 't')"
        ),
        format!("INSERT INTO session_wake (org_id, session_id, updated_at) VALUES ('{ORG_B}', 's-a', 't')"),
        format!(
            "INSERT INTO session_wake (org_id, session_id, node, updated_at) VALUES ('{ORG_B}', 's-b', '{A_NODE}', 't')"
        ),
        format!(
            "INSERT INTO session_wake_offers (org_id, offer_id, session_id, node, offered_seq, offered_at, expires_at) VALUES ('{ORG_B}', 'o1', 's-b', '{A_NODE}', 1, 1.0, 2.0)"
        ),
        format!(
            "INSERT INTO session_credentials (org_id, credential_id, token_sha256, agent_label, node, item_id, attempt, tools_json, issued_by, issued_at, idle_expires_at, expires_at) VALUES ('{ORG_B}', 'c1', 'h2', '{B_AGENT}', '{A_NODE}', 'nd-1', 1, '[]', 'x', 't', 't', 't')"
        ),
        format!("UPDATE agent_sessions SET agent = '{A_AGENT}' WHERE id = 's-b'"),
        "UPDATE agents SET org_id = 'default' WHERE org_id = 'org-b'".to_string(),
    ] {
        let e = h.sql(&bad).unwrap_err();
        assert!(e.contains("another organization") || e.contains("org_id cannot change"), "{bad}: {e}");
    }
    // Inside one organization each reference is accepted.
    h.sql(&format!(
        "INSERT INTO session_handoff_notes (org_id, session_id, agent, done, next_steps, created_at, updated_at)
             VALUES ('{ORG_B}', 's-b', '{B_AGENT}', '[]', '[]', 't', 't');
         INSERT INTO session_wake (org_id, session_id, updated_at) VALUES ('{ORG_B}', 's-b', 't');"
    ))
    .unwrap();
}

#[tokio::test]
async fn no_label_host_path_or_text_of_another_organization_reaches_the_ledger() {
    let h = H::new();
    let s = seed(&h).await;
    let b = agent(B_AGENT, ORG_B);
    h.ok(
        &b,
        "lifecycle_record",
        json!({ "kind": "tool_end", "session_id": s.b_sid, "tool": B_TOOL,
                                          "payload": { "note": B_REASON }, "idempotency_key": "k-1" }),
    )
    .await;
    let again = h
        .ok(
            &b,
            "lifecycle_record",
            json!({ "kind": "tool_end", "session_id": s.b_sid, "tool": B_TOOL, "idempotency_key": "k-1" }),
        )
        .await;
    assert_eq!(again["duplicate"], true);
    // The same client key in the default organization is a fresh key.
    let a_rec = h
        .ok(
            &agent(A_AGENT, DEFAULT_ORG),
            "lifecycle_record",
            json!({ "kind": "tool_end", "session_id": s.b_sid, "tool": "x", "idempotency_key": "k-1" }),
        )
        .await;
    assert_eq!(a_rec["duplicate"], false);
    h.ok(&b, "profile_activate", json!({ "profile": "research" })).await;
    h.ok(&b, "profile_reset", json!({})).await;
    h.manage(&b, "agent_terminate", json!({ "agent": B_AGENT, "reason": B_REASON })).await.unwrap();
    h.ok(&agent(B_PEER, ORG_B), "session_start", json!({ "kind": "interactive", "host": B_HOST })).await;
    h.ok(&b, "session_end", json!({ "session_id": s.b_sid, "exit_status": B_EXIT, "summary": B_REASON }))
        .await;
    h.ok(
        &human("b-human-not-real", ORG_B),
        "agent_token_issue",
        json!({ "agent_label": B_PEER, "value": "w".repeat(40) }),
    )
    .await;
    let ledger = h.ledger_text();
    assert_no_b(&ledger, "the ledger");
    // Every B event uses the neutral originator.
    let b_events = h.count(&format!(
        "SELECT COUNT(*) FROM event_log WHERE originator IN ('{B_AGENT}', '{B_PEER}', 'b-human-not-real')"
    ));
    assert_eq!(b_events, 0, "{ledger}");
    // The idempotency key of another organization is its own row of the
    // `(org_id, key)` table, beside the default organization's same key.
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM idempotency_keys WHERE org_id = '{ORG_B}' AND tool = 'lifecycle_record'"
        )),
        1
    );
    assert_eq!(h.count("SELECT COUNT(*) FROM idempotency_keys WHERE key LIKE 'org:%/lifecycle%'"), 0);
}

// --- the insert guard --------------------------------------------------------------------------

/// Every `INSERT` into the nine tables in any crate's non-test source names
/// `org_id` (`org_classification.rs` runs the general guard; this pins
/// these tables).
#[test]
fn every_insert_into_the_agent_tables_names_its_organization() {
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
        // Unit tests at the end of a file build their own schemas.
        let text = text.split("#[cfg(test)]").next().unwrap_or("");
        for table in TABLES {
            let needle = format!("INSERT INTO {table} (");
            let mut from = 0;
            while let Some(at) = text[from..].find(&needle) {
                let start = from + at;
                let cols = &text[start + needle.len()..];
                let cols = &cols[..cols.find(')').unwrap_or(cols.len())];
                assert!(cols.contains("org_id"), "{}: {table} insert without org_id: {cols}", f.display());
                seen += 1;
                from = start + needle.len();
            }
        }
    }
    assert!(seen >= 10, "found only {seen} inserts");
}

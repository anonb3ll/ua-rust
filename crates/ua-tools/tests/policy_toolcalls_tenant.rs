//! `policy_authorizations` and `tool_calls` are tenant data
//! (`docs/organization.md`, Scoping per subsystem).
//!
//! - `organization.v1.tools.policy_authorizations` gives `policy_authorizations`
//!   its `org_id` and triggers; `github.v3.policy_authorizations_org_scope`
//!   moves each existing authorization to its task's organization, adds the
//!   indexes led by `org_id` and keeps an authorization's task inside its own
//!   organization.
//! - `organization.v1.tools.tool_calls` gives `tool_calls` its `org_id` and
//!   triggers (every existing row is the default organization's);
//!   `core.v5.tool_calls_org_scope` adds the indexes led by `org_id`.
//!
//! Neither upgrade drops or rewrites a row beyond its organization. A second
//! organization is created at the storage level, as no tool creates one yet,
//! and its callers are built by hand. Every value here is fake.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 4] = [
    "organization.v1.tools.policy_authorizations",
    "github.v3.policy_authorizations_org_scope",
    "organization.v1.tools.tool_calls",
    "core.v5.tool_calls_org_scope",
];
/// An id no authorization (and no task) has, to compare another
/// organization's answers with.
const ABSENT: i64 = 987_654;

const REPO_A: &str = "owner-a/widgets-not-real";
/// Organization-B values that must never reach the default organization's
/// ledger or replies.
const B_REPO: &str = "owner-b/falcon-not-real";
const B_POLICY: &str = "osprey-policy-not-real";
const B_HUMAN: &str = "kestrel-counsel-not-real";
const HEAD_A: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const HEAD_B: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().filter(|p| !PARTS.contains(&p.name)).collect()
}

fn add_org(db: &ua_store::Db, id: &str) {
    db.write(|tx| {
        tx.execute(
            "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
             VALUES (?1, ?1, 'Org B', '[\"developer\",\"coordinator\",\"operator\"]', '2026-01-01T00:00:00+00:00')",
            [id],
        )?;
        Ok(())
    })
    .unwrap();
}

fn agent(label: &str, org: &str, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile,
        enforce_profile: true,
        session_key: Some(format!("{label}-s")),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn human(label: &str, org: &str) -> Caller {
    Caller { kind: ActorKind::Human, enforce_profile: false, ..agent(label, org, Profile::Operator) }
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

/// An answer with id `n` in its text replaced, to compare an answer about one
/// row with an answer about another.
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
        Self::with_policy(None)
    }

    fn with_policy(policy: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ws_dir = tempfile::tempdir().unwrap();
        let ws = ws_dir.path().canonicalize().unwrap();
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into(), B_HUMAN.into()];
        cfg.workspace = Some(ws.clone());
        if let Some(p) = policy {
            let path = dir.path().join("policy.yaml");
            std::fs::write(&path, p).unwrap();
            cfg.policy_file = Some(path);
        }
        let hub = Hub::in_memory(cfg).unwrap();
        add_org(hub.db(), ORG_B);
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

    /// Every authorization row, as text: a write that changes nothing leaves
    /// it identical.
    fn snapshot(&self) -> String {
        self.hub
            .db()
            .read(|c| {
                let mut stmt = c.prepare("SELECT * FROM policy_authorizations ORDER BY id")?;
                let n = stmt.column_count();
                let rows = stmt.query_map([], |r| {
                    let mut row = Vec::new();
                    for i in 0..n {
                        row.push(format!("{:?}", r.get_ref(i)?));
                    }
                    Ok(row.join("|"))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?.join("\n"))
            })
            .unwrap()
    }

    /// Every `event_log` row's channel, originator and payload, for leak checks.
    fn ledger(&self) -> Vec<(String, Option<String>, Value)> {
        self.hub
            .db()
            .read(|c| {
                let mut stmt =
                    c.prepare("SELECT channel, originator, payload FROM event_log ORDER BY seq")?;
                let rows = stmt.query_map([], |r| {
                    let p: String = r.get(2)?;
                    Ok((r.get(0)?, r.get(1)?, serde_json::from_str(&p).unwrap_or(Value::Null)))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .unwrap()
    }

    fn last_event(&self, channel: &str) -> (Option<String>, Value) {
        self.ledger().into_iter().rev().find(|(c, _, _)| c == channel).map(|(_, o, p)| (o, p)).unwrap()
    }

    /// Insert `n` failed calls of `tool` by `caller` in organization `org`.
    fn seed_calls(&self, org: &str, tool: &str, caller: &str, n: usize) {
        let (org, tool, caller) = (org.to_string(), tool.to_string(), caller.to_string());
        self.hub
            .db()
            .write(move |tx| {
                for _ in 0..n {
                    tx.execute(
                        "INSERT INTO tool_calls (org_id, tool, caller, profile, transport, started_at, duration_ms, \
                         outcome) VALUES (?1, ?2, ?3, 'coordinator', 'mcp', ?4, 10, 'internal')",
                        rusqlite::params![org, tool, caller, ua_core::time::now()],
                    )?;
                }
                Ok(())
            })
            .unwrap();
    }

    async fn task(&self, who: &Caller, title: &str) -> i64 {
        self.ok(who, "task_add", json!({ "title": title })).await["id"].as_i64().unwrap()
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

fn auth_ids(v: &Value) -> Vec<i64> {
    v["authorizations"].as_array().unwrap().iter().map(|a| a["id"].as_i64().unwrap()).collect()
}

// --- schema ------------------------------------------------------------------------------------

#[test]
fn a_legacy_database_upgrades_with_nothing_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.human_identities = vec!["operator".into(), B_HUMAN.into()];
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        add_org(&db, ORG_B);
        db.write(|tx| {
            tx.execute_batch(&format!(
                "INSERT INTO tasks (id, org_id, title, created_at, updated_at) VALUES
                     (1, 'default', 'Legacy default', 'x', 'x'), (2, 'org-b', 'Legacy b', 'x', 'x');
                 INSERT INTO policy_authorizations
                     (id, repo, pr, head_sha, task_id, policy_ref, authorized_by, created_at, expires_at)
                 VALUES (10, '{REPO_A}', 1, '{HEAD_A}', 1, 'a-policy', 'operator', 'x', '2999-01-01T00:00:00Z'),
                        (20, '{B_REPO}', 2, '{HEAD_B}', 2, '{B_POLICY}', 'operator', 'x', '2999-01-01T00:00:00Z'),
                        (30, '{REPO_A}', 3, '{HEAD_A}', 99, 'orphan-policy', 'operator', 'x', '2999-01-01T00:00:00Z');
                 INSERT INTO tool_calls (id, tool, caller, profile, transport, started_at, duration_ms, outcome)
                 VALUES (1, 'task_add', 'builder-1', 'developer', 'mcp', '2026-01-02T00:00:00+00:00', 5, 'ok'),
                        (2, 'task_list', 'builder-2', 'developer', 'mcp', '2026-01-02T00:00:01+00:00', 6, 'ok'),
                        (3, 'task_get', 'builder-1', 'developer', 'http', '2026-01-02T00:00:02+00:00', 7, 'denied');"
            ))?;
            Ok(())
        })
        .unwrap();
    }

    // Open twice: the upgrade is idempotent across restarts.
    for _ in 0..2 {
        let hub = Hub::open(cfg.clone()).unwrap();
        hub.db()
            .read(|c| {
                // Every authorization is kept, in its task's organization; the
                // one whose task is gone stays where every reader put it.
                let rows: Vec<(i64, String)> = c
                    .prepare("SELECT id, org_id FROM policy_authorizations ORDER BY id")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<_, _>>()?;
                assert_eq!(rows, [(10, DEFAULT_ORG.into()), (20, ORG_B.into()), (30, DEFAULT_ORG.into())]);
                // Every call row is kept, in the default organization, unchanged.
                let calls: Vec<(i64, String, String, i64, String)> = c
                    .prepare("SELECT id, org_id, tool, duration_ms, outcome FROM tool_calls ORDER BY id")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
                    .collect::<Result<_, _>>()?;
                assert_eq!(
                    calls,
                    [
                        (1, DEFAULT_ORG.into(), "task_add".into(), 5, "ok".into()),
                        (2, DEFAULT_ORG.into(), "task_list".into(), 6, "ok".into()),
                        (3, DEFAULT_ORG.into(), "task_get".into(), 7, "denied".into()),
                    ]
                );
                for t in ["policy_authorizations", "tool_calls"] {
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
                let triggers = names(c, "trigger", "policy_authorizations");
                for want in ["policy_authorizations_org_parent", "policy_authorizations_org_parent_update"] {
                    assert!(triggers.contains(&want.to_string()), "{triggers:?}");
                }
                let idx = names(c, "index", "policy_authorizations");
                for want in [
                    "idx_policy_authorizations_org_id",
                    "idx_policy_authorizations_org_head",
                    "idx_policy_authorizations_org_task",
                ] {
                    assert!(idx.contains(&want.to_string()), "{idx:?}");
                }
                let idx = names(c, "index", "tool_calls");
                for want in ["idx_tool_calls_org_started", "idx_tool_calls_org_caller"] {
                    assert!(idx.contains(&want.to_string()), "{idx:?}");
                }
                // The recreated immutability trigger is the generated one.
                let sql: String = c.query_row(
                    "SELECT sql FROM sqlite_master WHERE name = 'policy_authorizations_org_immutable'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(
                    sql,
                    "CREATE TRIGGER policy_authorizations_org_immutable BEFORE UPDATE OF org_id ON \
                     policy_authorizations WHEN OLD.org_id IS NOT NULL AND NEW.org_id IS NOT OLD.org_id \
                     BEGIN SELECT RAISE(ABORT, 'org_id cannot change'); END"
                );
                Ok(())
            })
            .unwrap();
    }

    let hub = Hub::open(cfg).unwrap();
    for sql in [
        "UPDATE policy_authorizations SET org_id = 'default' WHERE id = 20",
        "UPDATE tool_calls SET org_id = 'org-b' WHERE id = 1",
    ] {
        let e = hub.db().write(|tx| Ok(tx.execute_batch(sql)?)).unwrap_err();
        assert!(e.to_string().contains("org_id cannot change"), "{sql}: {e}");
    }

    // The legacy authorizations answer through the tools, each to its own
    // organization, in the shape they had.
    let reg = builtin_registry();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        for (who, want) in [(human("operator", DEFAULT_ORG), vec![30, 10]), (human(B_HUMAN, ORG_B), vec![20])]
        {
            let v = reg
                .call(&hub, &who, "policy_authorization_list", json!({ "include_inactive": true }))
                .await
                .unwrap();
            assert_eq!(auth_ids(&v), want, "{}: {v}", who.org_id);
            assert!(v["authorizations"][0].get("org_id").is_none(), "a reply keeps its shape: {v}");
        }
    });
}

/// Defence in depth: whatever a tool would check, the triggers keep an
/// authorization's task inside its own organization and refuse an unknown
/// organization in both tables.
#[test]
fn the_triggers_refuse_a_cross_organization_task_and_an_unknown_organization() {
    let h = H::new();
    h.sql(&format!(
        "INSERT INTO tasks (id, org_id, title, created_at, updated_at) VALUES
             (10, 'default', 'A', 'x', 'x'), (20, 'org-b', 'B', 'x', 'x');
         INSERT INTO policy_authorizations
             (id, org_id, repo, head_sha, task_id, policy_ref, authorized_by, created_at, expires_at)
         VALUES (1, 'default', 'r', '{HEAD_A}', 10, 'p', 'operator', 'x', 'x'),
                (2, 'org-b', 'r', '{HEAD_B}', 20, 'p', 'operator', 'x', 'x');"
    ))
    .unwrap();
    let before = h.snapshot();
    for (sql, want) in [
        (
            format!(
                "INSERT INTO policy_authorizations (org_id, repo, head_sha, task_id, policy_ref, authorized_by, \
                 created_at, expires_at) VALUES ('org-b', 'r', '{HEAD_A}', 10, 'p', 'o', 'x', 'x')"
            ),
            "task belongs to another organization",
        ),
        (
            format!(
                "INSERT INTO policy_authorizations (org_id, repo, head_sha, task_id, policy_ref, authorized_by, \
                 created_at, expires_at) VALUES ('default', 'r', '{HEAD_B}', 20, 'p', 'o', 'x', 'x')"
            ),
            "task belongs to another organization",
        ),
        (
            "UPDATE policy_authorizations SET task_id = 10 WHERE id = 2".into(),
            "task belongs to another organization",
        ),
        (
            "UPDATE policy_authorizations SET task_id = 20 WHERE id = 1".into(),
            "task belongs to another organization",
        ),
        ("UPDATE policy_authorizations SET org_id = 'org-b' WHERE id = 1".into(), "org_id cannot change"),
        (
            format!(
                "INSERT INTO policy_authorizations (org_id, repo, head_sha, task_id, policy_ref, authorized_by, \
                 created_at, expires_at) VALUES ('{UNKNOWN}', 'r', '{HEAD_A}', 999, 'p', 'o', 'x', 'x')"
            ),
            "",
        ),
        (
            format!(
                "INSERT INTO tool_calls (org_id, tool, caller, profile, transport, started_at, duration_ms, \
                 outcome) VALUES ('{UNKNOWN}', 't', 'c', 'developer', 'mcp', 'x', 1, 'ok')"
            ),
            "",
        ),
    ] {
        let e = h.sql(&sql).unwrap_err();
        assert!(e.contains(want), "{sql}: {e}");
    }
    assert_eq!(h.snapshot(), before);
    assert_eq!(h.count(&format!("SELECT COUNT(*) FROM tool_calls WHERE org_id = '{UNKNOWN}'")), 0);
}

// --- policy authorizations ---------------------------------------------------------------------

fn have_git() -> bool {
    Command::new("git").arg("--version").output().is_ok_and(|o| o.status.success())
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A workspace repository with branch `task-7` one commit ahead of main.
fn workspace_with_branch(ws: &Path) -> String {
    git(ws, &["init", "-q", "-b", "main"]);
    for (k, v) in [
        ("user.name", "builder-1"),
        ("user.email", "builder-1@example.invalid"),
        ("commit.gpgsign", "false"),
        ("core.hooksPath", "/dev/null"),
    ] {
        git(ws, &["config", k, v]);
    }
    std::fs::write(ws.join("README.md"), "readme\n").unwrap();
    git(ws, &["add", "README.md"]);
    git(ws, &["commit", "-q", "-m", "chore: initial commit"]);
    git(ws, &["checkout", "-q", "-b", "task-7"]);
    std::fs::write(ws.join("feature.txt"), "feature\n").unwrap();
    git(ws, &["add", "feature.txt"]);
    git(ws, &["commit", "-q", "-m", "feat: add feature"]);
    let head = git(ws, &["rev-parse", "HEAD"]);
    git(ws, &["checkout", "-q", "main"]);
    head
}

/// Two organizations each record, list, check and revoke their own
/// authorizations; the other's answers as a missing one everywhere, an
/// unknown organization changes nothing, and the default ledger never carries
/// organization B's repository, policy reference or human.
#[tokio::test]
async fn policy_authorizations_are_isolated_per_organization() {
    let h = H::new();
    let git_head = have_git().then(|| workspace_with_branch(&h.ws));
    let op_a = human("operator", DEFAULT_ORG);
    let op_b = human(B_HUMAN, ORG_B);
    // The same agent label in both organizations.
    let builder_a = agent("builder-1", DEFAULT_ORG, Profile::Developer);
    let builder_b = agent("builder-1", ORG_B, Profile::Developer);
    let lead_a = agent("lead-1", DEFAULT_ORG, Profile::Coordinator);

    h.ok(
        &op_a,
        "coordination_manage",
        json!({ "action": "project_repo_bind", "params": { "project": "default", "repo": REPO_A } }),
    )
    .await;
    // No caller outside the default organization can bind yet: seeded.
    h.sql(&format!(
        "INSERT INTO project_repo_bindings (org_id, project, repo, default_branch, bound_by, bound_at)
         VALUES ('org-b', 'default', '{B_REPO}', 'main', '{B_HUMAN}', '2026-01-02T00:00:00+00:00')"
    ))
    .unwrap();
    let ta = h.task(&builder_a, "A merge").await;
    let tb = h.task(&builder_b, "B merge").await;
    let head_a = git_head.clone().unwrap_or_else(|| HEAD_A.to_string());
    let rec = |repo: &str, head: &str, task: i64, policy: &str| {
        json!({ "repo": repo, "pr": 7, "head_sha": head, "task_id": task, "policy_ref": policy,
                "allow_in_flight": true })
    };

    let a = h.ok(&op_a, "policy_authorization_record", rec(REPO_A, &head_a, ta, "a-policy")).await;
    let auth_a = a["authorization"]["id"].as_i64().unwrap();
    assert!(a["authorization"].get("org_id").is_none(), "{a}");
    let b = h.ok(&op_b, "policy_authorization_record", rec(B_REPO, HEAD_B, tb, B_POLICY)).await;
    let auth_b = b["authorization"]["id"].as_i64().unwrap();
    assert!(b["authorization"].get("org_id").is_none(), "{b}");
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM policy_authorizations WHERE id = {auth_b} AND org_id = 'org-b'"
        )),
        1
    );

    // Organization B's event is in the default ledger without its names.
    let recorded = h
        .ledger()
        .into_iter()
        .find(|(c, _, p)| {
            c == "agent.github.policy_authorization.recorded" && p["authorization_id"] == auth_b
        })
        .unwrap();
    assert_eq!(recorded.1.as_deref(), Some("system"), "{recorded:?}");
    assert_eq!((recorded.2["repo"].clone(), recorded.2["policy_ref"].clone()), (Value::Null, Value::Null));
    assert_eq!(recorded.2["head_sha"], HEAD_B, "SHAs stay, as in the other GitHub events");
    assert!(recorded.2["payload_sha256"].is_string());

    let before = h.snapshot();
    let events = h.ledger().len();

    // Cross-organization references: another organization's task answers as
    // a missing one, and nothing is recorded.
    for (who, repo, head, other, policy) in
        [(&op_a, REPO_A, head_a.as_str(), tb, "a-policy"), (&op_b, B_REPO, HEAD_B, ta, B_POLICY)]
    {
        let got = h.call(who, "policy_authorization_record", rec(repo, head, other, policy)).await;
        let missing = h.call(who, "policy_authorization_record", rec(repo, head, ABSENT, policy)).await;
        assert!(got.is_err(), "{got:?}");
        same_as_missing(&got, &missing, other);
    }

    // Lists: each organization sees its own only, whatever the filter.
    for (who, own, other_task, other_repo) in [(&op_a, auth_a, tb, B_REPO), (&op_b, auth_b, ta, REPO_A)] {
        let all = h.ok(who, "policy_authorization_list", json!({ "include_inactive": true })).await;
        assert_eq!(auth_ids(&all), [own], "{all}");
        for filter in [json!({ "task_id": other_task }), json!({ "repo": other_repo })] {
            let mut f = filter.clone();
            f["include_inactive"] = json!(true);
            let v = h.ok(who, "policy_authorization_list", f).await;
            assert_eq!(v["count"], 0, "{filter}: {v}");
        }
    }
    let listed = h.ok(&op_a, "policy_authorization_list", json!({ "include_inactive": true })).await;
    for leak in [B_REPO, B_POLICY, B_HUMAN] {
        assert!(!listed.to_string().contains(leak), "{listed}");
    }

    // Revoking another organization's authorization answers as a missing one.
    for (who, other) in [(&op_a, auth_b), (&op_b, auth_a)] {
        let got = h.call(who, "policy_authorization_revoke", json!({ "id": other, "reason": "nope" })).await;
        let missing =
            h.call(who, "policy_authorization_revoke", json!({ "id": ABSENT, "reason": "nope" })).await;
        assert_eq!(got.as_ref().unwrap_err().code(), "not_found", "{got:?}");
        same_as_missing(&got, &missing, other);
    }

    // An unknown organization is refused before anything changes, including
    // a revoke that would insert nothing.
    let op_u = human("operator", UNKNOWN);
    let e = h.call(&op_u, "policy_authorization_record", rec(REPO_A, &head_a, ta, "u")).await.unwrap_err();
    assert_eq!(reason(&e), "unknown_organization", "{e:?}");
    let e = h.call(&op_u, "policy_authorization_revoke", json!({ "id": auth_a })).await.unwrap_err();
    assert_eq!(reason(&e), "unknown_organization", "{e:?}");

    assert_eq!(h.snapshot(), before, "no refused call changed an authorization");
    assert_eq!(h.ledger().len(), events, "no refused call ledgered anything");

    // The merge check sees only the caller's organization's rows. With force,
    // another organization's authorization is refused as one that does not
    // exist: no binding hash is read from it.
    let force = |id: i64| json!({ "task_id": ta, "policy_authorization_id": id, "force": true });
    for id in [auth_b, ABSENT, auth_a] {
        let e = h.call(&lead_a, "git_merge_task", force(id)).await.unwrap_err();
        assert_eq!(reason(&e), "policy_authorization_force", "{e:?}");
        let (_, p) = h.last_event("agent.approval.refused");
        assert_eq!(p["authorization_id"], id, "{p}");
        assert_eq!(p["approved_payload_sha256"].is_string(), id == auth_a, "{id}: {p}");
    }
    // The full check (`covering`), when git is here to reach it.
    if git_head.is_some() {
        h.sql(&format!("UPDATE tasks SET status = 'done', branch = 'task-7' WHERE id = {ta}")).unwrap();
        let dry = |id: i64| json!({ "task_id": ta, "policy_authorization_id": id, "dry_run": true });
        let got = h.call(&lead_a, "git_merge_task", dry(auth_b)).await;
        let missing = h.call(&lead_a, "git_merge_task", dry(ABSENT)).await;
        assert_eq!(got.as_ref().unwrap_err().code(), "not_found", "{got:?}");
        same_as_missing(&got, &missing, auth_b);
        let (_, p) = h.last_event("agent.approval.refused");
        assert_eq!(p["reason"], "no_matching_approval", "{p}");
        // Its own authorization is found (it is not refused as missing).
        let own = h.call(&lead_a, "git_merge_task", dry(auth_a)).await;
        if let Err(e) = &own {
            assert_ne!(e.code(), "not_found", "{e:?}");
        }
    }
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM policy_authorizations WHERE id = {auth_b} AND status = 'active'"
        )),
        1,
        "another organization's check never spends organization B's authorization"
    );

    // Organization B revokes its own; the event carries no reason or human.
    let v =
        h.ok(&op_b, "policy_authorization_revoke", json!({ "id": auth_b, "reason": "Falcon paused" })).await;
    assert_eq!(v["authorization"]["status"], "revoked", "{v}");
    let (by, p) = h.last_event("agent.github.policy_authorization.revoked");
    assert_eq!((by.as_deref(), p["reason"].clone()), (Some("system"), Value::Null), "{p}");
    assert_eq!(
        h.count(&format!(
            "SELECT COUNT(*) FROM policy_authorizations WHERE id = {auth_a} AND status = 'active'"
        )),
        1
    );

    // Nothing organization B named reaches the default organization's ledger.
    for (channel, originator, payload) in h.ledger() {
        let text = format!("{originator:?} {payload}");
        for leak in [B_REPO, B_POLICY, B_HUMAN, "Falcon paused"] {
            assert!(!text.contains(leak), "{channel}: {text}");
        }
    }
}

// --- tool calls --------------------------------------------------------------------------------

/// Every row the registry writes carries the caller's organization; an
/// unknown organization's call leaves no row.
#[tokio::test]
async fn tool_calls_record_the_callers_organization() {
    let h = H::new();
    let a = agent("shared-1", DEFAULT_ORG, Profile::Coordinator);
    let b = agent("shared-1", ORG_B, Profile::Coordinator);
    h.ok(&a, "profile_status", json!({})).await;
    h.ok(&b, "profile_status", json!({})).await;
    h.ok(&b, "profile_status", json!({})).await;
    let n = |org: &str| {
        h.count(&format!(
            "SELECT COUNT(*) FROM tool_calls WHERE org_id = '{org}' AND tool = 'profile_status' AND caller = 'shared-1'"
        ))
    };
    assert_eq!((n(DEFAULT_ORG), n(ORG_B)), (1, 2));

    let total = h.count("SELECT COUNT(*) FROM tool_calls");
    let _ = h.call(&agent("shared-1", UNKNOWN, Profile::Coordinator), "profile_status", json!({})).await;
    assert_eq!(h.count("SELECT COUNT(*) FROM tool_calls"), total, "an unknown organization records nothing");
}

/// The policy rate limits and cooldowns count calls in the caller's own
/// organization only, even for the same label; an unknown organization's
/// reservation fails closed.
#[tokio::test]
async fn policy_limits_count_calls_per_organization() {
    let h = H::with_policy(Some(
        "rules:\n  - {name: budget, type: rate_limit, tool: profile_status, max_calls: 2, window_seconds: 60}\n",
    ));
    let a = agent("shared-1", DEFAULT_ORG, Profile::Coordinator);
    let b = agent("shared-1", ORG_B, Profile::Coordinator);
    for who in [&a, &b] {
        h.ok(who, "profile_status", json!({})).await;
        h.ok(who, "profile_status", json!({})).await;
        let e = h.call(who, "profile_status", json!({})).await.unwrap_err();
        assert_eq!(reason(&e), "rate_limited", "{}: {e:?}", who.org_id);
    }
    let e = h.call(&agent("shared-1", UNKNOWN, Profile::Coordinator), "profile_status", json!({})).await;
    assert!(e.is_err(), "{e:?}");
    assert_eq!(h.count(&format!("SELECT COUNT(*) FROM tool_calls WHERE org_id = '{UNKNOWN}'")), 0);

    let h = H::with_policy(Some(
        "rules:\n  - {name: breathe, type: cooldown, tool: profile_status, cooldown_seconds: 600}\n",
    ));
    h.ok(&a, "profile_status", json!({})).await;
    assert_eq!(reason(&h.call(&a, "profile_status", json!({})).await.unwrap_err()), "episode_limited");
    // The same label in organization B is not in the default organization's cooldown.
    h.ok(&b, "profile_status", json!({})).await;
    assert_eq!(reason(&h.call(&b, "profile_status", json!({})).await.unwrap_err()), "episode_limited");
}

fn tools_in(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|t| t["tool"].as_str().unwrap().to_string()).collect()
}

fn subjects(v: &Value) -> Vec<String> {
    v["anomalies"].as_array().unwrap().iter().map(|a| a["subject"].as_str().unwrap().to_string()).collect()
}

/// Every telemetry reader (perf_summary, metrics_snapshot, check_anomalies'
/// tool_error_rate, mcp_health_telemetry, evidence_report's tool_call_window)
/// counts only the reader's organization's rows, even for the same caller
/// label and for an unrestricted reader; inside it a restricted reader counts
/// only its own calls.
#[tokio::test]
async fn every_telemetry_reader_sees_only_its_organizations_calls() {
    let h = H::new();
    let board = Caller::local("observer-1", Transport::Stdio);
    let a = agent("shared-1", DEFAULT_ORG, Profile::Coordinator);
    let b = agent("shared-1", ORG_B, Profile::Coordinator);
    let other_b = agent("other-2", ORG_B, Profile::Coordinator);

    let ta = h.task(&a, "A work").await;
    h.ok(&a, "task_claim", json!({ "id": ta })).await;
    let tb = h.task(&b, "B work").await;
    h.ok(&b, "task_claim", json!({ "id": tb })).await;
    h.seed_calls(DEFAULT_ORG, "probe_a", "shared-1", 25);
    h.seed_calls(ORG_B, "probe_b", "shared-1", 25);

    // perf_summary.
    for (who, sees, hidden) in [
        (&board, Some("probe_a"), "probe_b"),
        (&a, Some("probe_a"), "probe_b"),
        (&b, Some("probe_b"), "probe_a"),
        (&other_b, None, "probe_a"),
    ] {
        let v = h.ok(who, "perf_summary", json!({ "since_hours": 24 })).await;
        if let Some(t) = sees {
            assert_eq!(v["by_tool"][t]["calls"], 25, "{}/{}: {v}", who.org_id, who.label);
        }
        assert!(v["by_tool"].get(hidden).is_none(), "{}/{}: {v}", who.org_id, who.label);
    }
    let v = h.ok(&other_b, "perf_summary", json!({})).await;
    assert!(v["by_tool"].get("probe_b").is_none(), "a restricted reader counts only its own calls: {v}");

    // check_anomalies' tool_error_rate.
    for (who, sees, hidden) in
        [(&board, "tool:probe_a", "tool:probe_b"), (&b, "tool:probe_b", "tool:probe_a")]
    {
        let s = subjects(&h.ok(who, "check_anomalies", json!({})).await);
        assert!(s.contains(&sees.to_string()) && !s.contains(&hidden.to_string()), "{}: {s:?}", who.org_id);
    }

    // mcp_health_telemetry.
    for (who, sees, hidden) in [(&board, "probe_a", "probe_b"), (&b, "probe_b", "probe_a")] {
        let v = h.ok(who, "mcp_health_telemetry", json!({})).await;
        let top = tools_in(&v["calls"]["top_tools_24h"]);
        assert!(top.contains(&sees.to_string()) && !top.contains(&hidden.to_string()), "{top:?}");
    }

    // metrics_snapshot: the totals are exactly the reader's organization's
    // (and, restricted, its own) rows.
    for (who, filter) in [(&board, "org_id = 'default'"), (&b, "org_id = 'org-b' AND caller = 'shared-1'")] {
        let want = h.count(&format!("SELECT COUNT(*) FROM tool_calls WHERE page = 0 AND {filter}"));
        let v = h.ok(who, "metrics_snapshot", json!({})).await;
        assert_eq!(v["tool_calls_last_7_days"]["calls"], want, "{}: {v}", who.org_id);
    }

    // evidence_report's tool_call_window.
    for (who, task, sees, hidden) in
        [(&board, ta, "probe_a", "probe_b"), (&a, ta, "probe_a", "probe_b"), (&b, tb, "probe_b", "probe_a")]
    {
        let v = h.ok(who, "evidence_report", json!({ "task_id": task })).await;
        let calls = &v["records"][0]["tool_calls"];
        assert_eq!(calls["counted_callers"], json!(["shared-1"]), "{}: {calls}", who.org_id);
        assert_eq!(calls["by_tool"][sees]["calls"], 25, "{}: {calls}", who.org_id);
        assert!(calls["by_tool"].get(hidden).is_none(), "{}: {calls}", who.org_id);
    }
    // Another organization's task is not reported at all.
    let v = h.ok(&b, "evidence_report", json!({ "task_id": ta })).await;
    assert_eq!(v["total_records"], 0, "{v}");
}

// --- the insert guard --------------------------------------------------------------------------

/// Every `INSERT` into either table in any crate's source names `org_id`
/// (`org_classification.rs` runs the general guard; this pins both tables).
#[test]
fn every_insert_into_either_table_names_its_organization() {
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
        for table in ["tool_calls", "policy_authorizations"] {
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
    // registry.rs (the row and the reservation) and authz.rs (record).
    assert!(seen >= 3, "found {seen} inserts");
}

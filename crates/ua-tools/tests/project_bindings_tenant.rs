//! Organization keys, standalone table rebuild and tool isolation for
//! `project_repo_bindings`.

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::families::github::poll_once;
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 2] =
    ["governance.v2.project_bindings_tenant_keys", "organization.v1.tools.project_bindings"];

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().filter(|p| !PARTS.contains(&p.name)).collect()
}

fn add_org(hub: &Hub, id: &str) {
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
                 VALUES (?1, ?1, 'Org B', '[\"developer\",\"operator\"]', '2026-01-01T00:00:00+00:00')",
                [id],
            )?;
            Ok(())
        })
        .unwrap();
}

fn agent(org: &str) -> Caller {
    Caller {
        label: "lead-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("lead-1-s".into()),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn human(org: &str) -> Caller {
    Caller {
        label: "operator".into(),
        kind: ActorKind::Human,
        profile: Profile::Operator,
        enforce_profile: false,
        session_key: Some("operator-s".into()),
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
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into()];
        let hub = Hub::in_memory(cfg).unwrap();
        add_org(&hub, ORG_B);
        Self { hub, reg: builtin_registry(), _dir: dir }
    }

    async fn act(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.reg
            .call(&self.hub, who, "coordination_manage", json!({ "action": action, "params": params }))
            .await
    }

    async fn ok(&self, who: &Caller, action: &str, params: Value) -> Value {
        match self.act(who, action, params.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{action}({params}) failed: {e:?}"),
        }
    }

    async fn err(&self, who: &Caller, action: &str, params: Value) -> UaError {
        match self.act(who, action, params.clone()).await {
            Ok(v) => panic!("{action}({params}) should fail, got {v}"),
            Err(e) => e,
        }
    }

    /// Every binding row as `(org_id, project, repo)`.
    fn rows(&self) -> Vec<(String, String, String)> {
        self.hub
            .db()
            .read(|c| {
                Ok(c.prepare(
                    "SELECT org_id, project, repo FROM project_repo_bindings ORDER BY org_id, project",
                )?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?)
            })
            .unwrap()
    }

    fn events(&self, channel: &str) -> i64 {
        self.hub
            .db()
            .read(|c| {
                Ok(c.query_row("SELECT COUNT(*) FROM event_log WHERE channel = ?1", [channel], |r| r.get(0))?)
            })
            .unwrap()
    }

    /// Org B's binding, written directly: until memberships exist no caller
    /// of another organization holds operator authority, so the tools cannot
    /// bind for it.
    fn seed_org_b(&self, project: &str, repo: &str) {
        self.hub
            .db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO project_repo_bindings (org_id, project, repo, default_branch, bound_by, bound_at)
                     VALUES (?1, ?2, ?3, 'trunk', 'operator', '2026-01-02T00:00:00+00:00')",
                    [ORG_B, project, repo],
                )?;
                Ok(())
            })
            .unwrap();
    }
}

fn pk_columns(c: &rusqlite::Connection) -> Vec<String> {
    let mut cols: Vec<(i64, String)> = c
        .prepare("SELECT pk, name FROM pragma_table_info('project_repo_bindings') WHERE pk > 0")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    cols.sort();
    cols.into_iter().map(|(_, n)| n).collect()
}

fn count(c: &rusqlite::Connection, sql: &str, arg: &str) -> i64 {
    c.query_row(sql, [arg], |r| r.get(0)).unwrap()
}

#[test]
fn legacy_upgrade_rebuilds_the_key_and_keeps_bindings_triggers_and_views() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute(
                "INSERT INTO project_repo_bindings (project, repo, default_branch, bound_by, bound_at)
                 VALUES ('web', 'owner-a/repo', 'main', 'operator', '2026-01-02T00:00:00+00:00'),
                        ('api', 'owner-a/api', NULL, 'operator', '2026-01-03T00:00:00+00:00')",
                [],
            )?;
            // An extra index, trigger and view prove the rebuild keeps them.
            tx.execute_batch(
                "CREATE INDEX idx_project_repo_bindings_repo ON project_repo_bindings(repo);
                 CREATE VIEW v_bound_projects AS SELECT project, repo FROM project_repo_bindings;
                 CREATE TRIGGER trg_bindings_touch AFTER INSERT ON project_repo_bindings
                 BEGIN SELECT 1; END;",
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
                let rows: Vec<(String, String, String, Option<String>, String, String)> = c
                    .prepare(
                        "SELECT org_id, project, repo, default_branch, bound_by, bound_at
                         FROM project_repo_bindings ORDER BY project",
                    )?
                    .query_map([], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
                    })?
                    .collect::<Result<_, _>>()?;
                assert_eq!(
                    rows,
                    vec![
                        (
                            DEFAULT_ORG.into(),
                            "api".into(),
                            "owner-a/api".into(),
                            None,
                            "operator".into(),
                            "2026-01-03T00:00:00+00:00".into()
                        ),
                        (
                            DEFAULT_ORG.into(),
                            "web".into(),
                            "owner-a/repo".into(),
                            Some("main".into()),
                            "operator".into(),
                            "2026-01-02T00:00:00+00:00".into()
                        ),
                    ]
                );
                assert_eq!(pk_columns(c), ["org_id", "project"]);
                let org_notnull = count(
                    c,
                    "SELECT \"notnull\" FROM pragma_table_info('project_repo_bindings') WHERE name = ?1",
                    "org_id",
                );
                assert_eq!(org_notnull, 1);

                assert_eq!(
                    count(
                        c,
                        "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                        "idx_project_repo_bindings_repo"
                    ),
                    1
                );
                for trg in [
                    "trg_bindings_touch",
                    "project_repo_bindings_org_exists",
                    "project_repo_bindings_org_immutable",
                ] {
                    let n = count(
                        c,
                        "SELECT count(*) FROM sqlite_master \
                         WHERE type = 'trigger' AND tbl_name = 'project_repo_bindings' AND name = ?1",
                        trg,
                    );
                    assert_eq!(n, 1, "trigger {trg}");
                }
                let view_rows =
                    count(c, "SELECT count(*) FROM v_bound_projects WHERE repo LIKE ?1", "owner-a/%");
                assert_eq!(view_rows, 2);
                for part in PARTS {
                    assert_eq!(
                        count(c, "SELECT count(*) FROM schema_parts WHERE name = ?1", part),
                        1,
                        "{part}"
                    );
                }
                let fk: i64 = c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
                assert_eq!(fk, 1, "foreign keys restored");
                Ok(())
            })
            .unwrap();

        // The composite key: one binding per (organization, project).
        add_org_if_missing(&hub, ORG_B);
        hub.db()
            .write(|tx| {
                let dup = tx
                    .execute(
                        "INSERT INTO project_repo_bindings (org_id, project, repo, bound_by, bound_at)
                         VALUES ('default', 'web', 'owner-x/repo', 'operator', '2026-01-04T00:00:00+00:00')",
                        [],
                    )
                    .unwrap_err()
                    .to_string();
                assert!(dup.contains("UNIQUE constraint failed"), "{dup}");
                tx.execute(
                    "INSERT INTO project_repo_bindings (org_id, project, repo, bound_by, bound_at)
                     VALUES ('org-b', 'web', 'owner-b/repo', 'operator', '2026-01-04T00:00:00+00:00')",
                    [],
                )?;
                tx.execute("DELETE FROM project_repo_bindings WHERE org_id = 'org-b'", [])?;
                Ok(())
            })
            .unwrap();
    }
}

fn add_org_if_missing(hub: &Hub, id: &str) {
    let known: i64 = hub
        .db()
        .read(|c| Ok(c.query_row("SELECT count(*) FROM orgs WHERE id = ?1", [id], |r| r.get(0))?))
        .unwrap();
    if known == 0 {
        add_org(hub, id);
    }
}

#[test]
fn standalone_rebuild_is_safe_to_rerun_after_crash_before_recording() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let hub = Hub::open(cfg.clone()).unwrap();
        add_org(&hub, ORG_B);
        hub.db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO project_repo_bindings (org_id, project, repo, bound_by, bound_at)
                     VALUES ('default', 'shared', 'owner-a/repo', 'operator', '2026-01-02T00:00:00+00:00'),
                            ('org-b', 'shared', 'owner-b/repo', 'operator', '2026-01-02T00:00:00+00:00')",
                    [],
                )?;
                // A crash right after the rebuild committed, before the parts
                // were recorded and the triggers installed.
                tx.execute_batch(
                    "DROP TRIGGER project_repo_bindings_org_exists;
                     DROP TRIGGER project_repo_bindings_org_immutable;
                     DELETE FROM schema_parts WHERE name IN
                         ('governance.v2.project_bindings_tenant_keys', 'organization.v1.tools.project_bindings');
                     DELETE FROM schema_procedures WHERE name IN
                         ('governance.v2.project_bindings_tenant_keys', 'organization.v1.tools.project_bindings');",
                )?;
                Ok(())
            })
            .unwrap();
    }

    let hub = Hub::open(cfg.clone()).unwrap();
    hub.db()
        .read(|c| {
            let rows: Vec<(String, String)> = c
                .prepare(
                    "SELECT org_id, repo FROM project_repo_bindings WHERE project = 'shared' ORDER BY org_id",
                )?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            assert_eq!(
                rows,
                vec![("default".into(), "owner-a/repo".into()), ("org-b".into(), "owner-b/repo".into())]
            );
            assert_eq!(pk_columns(c), ["org_id", "project"]);
            for trg in ["project_repo_bindings_org_exists", "project_repo_bindings_org_immutable"] {
                assert_eq!(count(c, "SELECT count(*) FROM sqlite_master WHERE name = ?1", trg), 1, "{trg}");
            }
            for part in PARTS {
                assert_eq!(count(c, "SELECT count(*) FROM schema_parts WHERE name = ?1", part), 1, "{part}");
            }
            let fk: i64 = c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
            assert_eq!(fk, 1);
            Ok(())
        })
        .unwrap();
}

#[test]
fn failed_rebuild_rolls_back_cleanly_and_restores_foreign_keys() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute(
                "INSERT INTO project_repo_bindings (project, repo, bound_by, bound_at)
                 VALUES ('keep', 'owner-a/repo', 'operator', '2026-01-02T00:00:00+00:00')",
                [],
            )?;
            // A leftover staging table makes CREATE TABLE project_repo_bindings_new fail.
            tx.execute_batch("CREATE TABLE project_repo_bindings_new (x INTEGER);")?;
            Ok(())
        })
        .unwrap();
    }

    let err = Hub::open(cfg.clone()).err().expect("rebuild must fail").to_string();
    assert!(err.contains("governance.v2.project_bindings_tenant_keys"), "{err}");

    let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
    db.read(|c| {
        assert_eq!(
            count(
                c,
                "SELECT count(*) FROM pragma_table_info('project_repo_bindings') WHERE name = ?1",
                "org_id"
            ),
            0,
            "the original table is intact"
        );
        assert_eq!(pk_columns(c), ["project"]);
        let project: String = c.query_row("SELECT project FROM project_repo_bindings", [], |r| r.get(0))?;
        assert_eq!(project, "keep");
        let recorded: i64 = c.query_row(
            "SELECT count(*) FROM schema_parts WHERE name IN
                 ('governance.v2.project_bindings_tenant_keys', 'organization.v1.tools.project_bindings')",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(recorded, 0);
        let fk: i64 = c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
        assert_eq!(fk, 1);
        Ok(())
    })
    .unwrap();
}

#[test]
fn triggers_reject_unknown_org_and_org_reassignment() {
    let h = H::new();
    h.hub
        .db()
        .write(|tx| {
            let err = tx
                .execute(
                    "INSERT INTO project_repo_bindings (org_id, project, repo, bound_by, bound_at)
                     VALUES (?1, 'web', 'owner-a/repo', 'operator', '2026-01-02T00:00:00+00:00')",
                    [UNKNOWN],
                )
                .unwrap_err()
                .to_string();
            assert!(err.contains("unknown organization"), "{err}");

            tx.execute(
                "INSERT INTO project_repo_bindings (org_id, project, repo, bound_by, bound_at)
                 VALUES (?1, 'web', 'owner-a/repo', 'operator', '2026-01-02T00:00:00+00:00')",
                [DEFAULT_ORG],
            )?;
            let err = tx
                .execute(
                    "UPDATE project_repo_bindings SET org_id = ?1 WHERE org_id = ?2 AND project = 'web'",
                    [ORG_B, DEFAULT_ORG],
                )
                .unwrap_err()
                .to_string();
            assert!(err.contains("org_id cannot change"), "{err}");
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn organizations_bind_the_same_project_independently() {
    let h = H::new();
    let a = human(DEFAULT_ORG);

    // Both organizations bind the slug `web`, to different repositories.
    h.ok(
        &a,
        "project_repo_bind",
        json!({ "project": "web", "repo": "owner-a/repo", "default_branch": "main" }),
    )
    .await;
    h.seed_org_b("web", "owner-b/repo");
    h.seed_org_b("docs", "owner-b/docs");
    assert_eq!(
        h.rows(),
        [
            (DEFAULT_ORG.into(), "web".into(), "owner-a/repo".into()),
            (ORG_B.into(), "docs".into(), "owner-b/docs".into()),
            (ORG_B.into(), "web".into(), "owner-b/repo".into()),
        ]
    );

    // Each organization gets only its own binding, in the unchanged shape.
    let got_a = h.ok(&agent(DEFAULT_ORG), "project_repo_get", json!({ "project": "web" })).await;
    assert_eq!(got_a["binding"]["repo"], "owner-a/repo");
    assert_eq!(got_a["binding"]["default_branch"], "main");
    assert!(got_a["binding"].get("org_id").is_none(), "{got_a}");
    let got_b = h.ok(&agent(ORG_B), "project_repo_get", json!({ "project": "web" })).await;
    assert_eq!(got_b["binding"]["repo"], "owner-b/repo");
    assert_eq!(got_b["binding"]["default_branch"], "trunk");
    let none = h.ok(&agent(DEFAULT_ORG), "project_repo_get", json!({ "project": "docs" })).await;
    assert_eq!(none["binding"], Value::Null, "another organization's binding reads as missing");

    // Each lists its own projects; tasks are in the default organization only.
    h.reg
        .call(&h.hub, &agent(DEFAULT_ORG), "task_add", json!({ "title": "T", "project": "tasks-only" }))
        .await
        .unwrap();
    let list = |v: Value| -> Vec<(String, Value)> {
        v["projects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (p["project"].as_str().unwrap().to_string(), p["binding"]["repo"].clone()))
            .collect()
    };
    let list_a = list(h.ok(&agent(DEFAULT_ORG), "project_repo_list", json!({})).await);
    assert!(list_a.contains(&("web".into(), json!("owner-a/repo"))), "{list_a:?}");
    assert!(list_a.contains(&("tasks-only".into(), Value::Null)), "{list_a:?}");
    assert!(!list_a.iter().any(|(p, _)| p == "docs"), "{list_a:?}");
    let list_b = list(h.ok(&agent(ORG_B), "project_repo_list", json!({})).await);
    assert_eq!(list_b, [("docs".into(), json!("owner-b/docs")), ("web".into(), json!("owner-b/repo"))]);

    // Rebinding in the default organization upserts its own row only.
    h.ok(&a, "project_repo_bind", json!({ "project": "web", "repo": "owner-a/other" })).await;
    let got_b = h.ok(&agent(ORG_B), "project_repo_get", json!({ "project": "web" })).await;
    assert_eq!(got_b["binding"]["repo"], "owner-b/repo");

    // A caller of org B holds no operator authority until memberships exist,
    // so it cannot change bindings, and its refusal changes nothing.
    let before = h.rows();
    let e = h.err(&human(ORG_B), "project_repo_unbind", json!({ "project": "web" })).await;
    assert_eq!(reason(&e), "operator_required");
    let e =
        h.err(&human(ORG_B), "project_repo_bind", json!({ "project": "web", "repo": "owner-c/repo" })).await;
    assert_eq!(reason(&e), "operator_required");
    assert_eq!(h.rows(), before);

    // Unbinding in the default organization leaves org B's binding of the same slug.
    let un = h.ok(&a, "project_repo_unbind", json!({ "project": "web" })).await;
    assert_eq!(un["unbound"], true);
    assert_eq!(un["previous"]["repo"], "owner-a/other");
    assert_eq!(
        h.ok(&agent(DEFAULT_ORG), "project_repo_get", json!({ "project": "web" })).await["binding"],
        Value::Null
    );
    assert_eq!(
        h.ok(&agent(ORG_B), "project_repo_get", json!({ "project": "web" })).await["binding"]["repo"],
        "owner-b/repo"
    );
    // A second unbind finds nothing of its own, even though org B has the slug.
    let again = h.ok(&a, "project_repo_unbind", json!({ "project": "web" })).await;
    assert_eq!(again["unbound"], false);
    assert_eq!(
        h.rows(),
        [
            (ORG_B.into(), "docs".into(), "owner-b/docs".into()),
            (ORG_B.into(), "web".into(), "owner-b/repo".into())
        ]
    );
    assert_eq!(h.events("project.repo.bound"), 2);
    assert_eq!(h.events("project.repo.unbound"), 2);
}

#[tokio::test]
async fn an_unknown_organization_is_refused_before_any_write() {
    let h = H::new();
    h.ok(&human(DEFAULT_ORG), "project_repo_bind", json!({ "project": "web", "repo": "owner-a/repo" })).await;
    let before = h.rows();
    let bound = h.events("project.repo.bound");

    let e = h
        .err(&human(UNKNOWN), "project_repo_bind", json!({ "project": "web", "repo": "owner-b/repo" }))
        .await;
    assert_eq!(reason(&e), "unknown_organization");
    // The registry refuses the organization before the tool runs.
    assert!(e.to_string().contains("nothing ran and nothing was written"), "{e}");
    // An unbind has nothing to insert, so the existence trigger cannot catch it.
    let e = h.err(&human(UNKNOWN), "project_repo_unbind", json!({ "project": "web" })).await;
    assert_eq!(reason(&e), "unknown_organization");

    assert_eq!(h.rows(), before);
    assert_eq!(h.events("project.repo.bound"), bound);
    assert_eq!(h.events("project.repo.unbound"), 0);
    // Reads are refused the same way.
    for (tool, args) in [("project_repo_get", json!({ "project": "web" })), ("project_repo_list", json!({}))]
    {
        let e = h.err(&agent(UNKNOWN), tool, args).await;
        assert_eq!(reason(&e), "unknown_organization", "{tool}: {e}");
    }
}

// --- task-driven lookups -------------------------------------------------------------
//
// Tasks carry no `org_id` yet, so every lookup of a binding that starts from
// a task reads the default organization's bindings. Another organization's
// binding of the same project slug must never stand in for a missing or a
// different default binding: not in a CI check, a policy authorization, a
// commit deliverable, a merge's approval payload, merged-PR reconciliation
// or the GitHub poll.

/// Every request path the mock GitHub saw.
type Seen = Arc<Mutex<Vec<String>>>;

/// A local GitHub REST mock: an empty open-PR list for any repository, 404
/// for everything else. Nothing reaches the network.
async fn start_github() -> (Seen, String) {
    async fn serve(State(seen): State<Seen>, req: Request) -> Response {
        let path = req.uri().path().to_string();
        let found = path.starts_with("/repos/") && path.ends_with("/pulls");
        seen.lock().unwrap().push(path);
        if found {
            axum::Json(json!([])).into_response()
        } else {
            (StatusCode::NOT_FOUND, axum::Json(json!({ "message": "Not Found" }))).into_response()
        }
    }
    let seen: Seen = Arc::default();
    let app = Router::new().fallback(serve).with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (seen, format!("http://{addr}"))
}

fn have_git() -> bool {
    Command::new("git").arg("--version").output().is_ok_and(|o| o.status.success())
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

/// A workspace repository with branch `task-7` one commit ahead of main.
fn workspace_with_branch(ws: &Path) {
    git(ws, &["init", "-q", "-b", "main"]);
    for (k, v) in [
        ("user.name", "builder-1"),
        ("user.email", "builder-1@example.com"),
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
    git(ws, &["checkout", "-q", "main"]);
}

fn default_agent(label: &str, profile: Profile) -> Caller {
    Caller { label: label.into(), session_key: Some(format!("{label}-s")), profile, ..agent(DEFAULT_ORG) }
}

const FULL: &str = "abcdef1234567abcdef1234567abcdef12345678";

struct TaskH {
    h: H,
    seen: Seen,
    _ws: tempfile::TempDir,
}

impl TaskH {
    async fn new() -> Self {
        let (seen, base) = start_github().await;
        let ws_dir = tempfile::tempdir().unwrap();
        let ws = ws_dir.path().canonicalize().unwrap();
        workspace_with_branch(&ws);
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into()];
        cfg.workspace = Some(ws);
        cfg.fetch_allow_loopback = true;
        cfg.github_api_url = base;
        cfg.github_token_value = Some("test-token".to_string().into());
        cfg.github_web_host = Some("github.com".into());
        let hub = Hub::in_memory(cfg).unwrap();
        add_org(&hub, ORG_B);
        Self { h: H { hub, reg: builtin_registry(), _dir: dir }, seen, _ws: ws_dir }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.h.reg.call(&self.h.hub, who, tool, args).await
    }

    /// Requests the mock saw for `repo`.
    fn hits(&self, repo: &str) -> Vec<String> {
        let prefix = format!("/repos/{repo}/");
        self.seen.lock().unwrap().iter().filter(|p| p.starts_with(&prefix)).cloned().collect()
    }

    /// The `repo` a merge of `task` asks its one-time approval for.
    async fn merge_approval_repo(&self, task: i64) -> Value {
        let e = self
            .call(
                &default_agent("lead-2", Profile::Coordinator),
                "git_merge_task",
                json!({ "task_id": task }),
            )
            .await;
        let Err(UaError::ApprovalRequired { approval_id, .. }) = e else {
            panic!("git_merge_task should ask for an approval, got {e:?}");
        };
        let raw: String = self
            .h
            .hub
            .db()
            .read(move |c| {
                Ok(c.query_row("SELECT payload FROM approvals WHERE id = ?1", [approval_id], |r| r.get(0))?)
            })
            .unwrap();
        serde_json::from_str::<Value>(&raw).unwrap()["repo"].clone()
    }
}

#[tokio::test]
async fn task_driven_lookups_never_read_another_organizations_binding() {
    if !have_git() {
        eprintln!("git not installed; skipping");
        return;
    }
    let t = TaskH::new().await;
    let h = &t.h;
    let op = human(DEFAULT_ORG);
    let builder = default_agent("builder-1", Profile::Developer);
    let lead = default_agent("lead-2", Profile::Coordinator);

    // Org B binds `web`; a default-organization task works in `web`.
    h.seed_org_b("web", "owner-b/repo");
    let task = t.call(&builder, "task_add", json!({ "title": "web work", "project": "web" })).await.unwrap()
        ["id"]
        .as_i64()
        .unwrap();
    t.call(&builder, "task_claim", json!({ "id": task })).await.unwrap();
    // A finished task in `web` with a branch to merge, linking a PR of org B's repository.
    let done = t.call(&builder, "task_add", json!({ "title": "merge me", "project": "web" })).await.unwrap()
        ["id"]
        .as_i64()
        .unwrap();
    h.hub
        .db()
        .write(move |tx| {
            Ok(tx.execute("UPDATE tasks SET status = 'done', branch = 'task-7' WHERE id = ?1", [done])?)
        })
        .unwrap();
    h.hub
        .db()
        .write(move |tx| {
            Ok(tx.execute("UPDATE tasks SET evidence_ref = 'owner-b/repo#5' WHERE id = ?1", [task])?)
        })
        .unwrap();
    let record = |name: &str, repo: Option<&str>| {
        let mut r = json!({ "kind": "ci_run", "ref": "41" });
        if let Some(repo) = repo {
            r["repo"] = json!(repo);
        }
        json!({ "task_id": task, "name": name, "outcome": "pass", "head_sha": FULL, "ref": r })
    };
    let check = |v: &Value, name: &str| -> Value {
        v["checks"].as_array().unwrap().iter().find(|c| c["name"] == name).cloned().unwrap()
    };
    let authorize = |repo: &str| json!({ "repo": repo, "pr": 5, "head_sha": FULL, "task_id": task, "policy_ref": "release-policy-1" });

    // 1. No default binding at all.
    // A check names no repository: none is filled in from org B's binding.
    let v = h.ok(&builder, "task_check_record", record("ci-none", None)).await;
    assert_eq!(check(&v, "ci-none")["ref"]["repo"], Value::Null, "{v}");
    // A check naming org B's repository stays attested: the task's project
    // has no binding of its own, so nothing is verified and GitHub is not asked.
    let v = h.ok(&builder, "task_check_record", record("ci-b", Some("owner-b/repo"))).await;
    let c = check(&v, "ci-b");
    assert_eq!(c["grade"], "attested", "{c}");
    assert_eq!(c["verification"]["verdict"], "unverifiable", "{c}");
    assert!(c["verification"]["detail"].as_str().unwrap().contains("has no bound repository"), "{c}");
    // A policy authorization for org B's repository is refused.
    let e = t.call(&op, "policy_authorization_record", authorize("owner-b/repo")).await.unwrap_err();
    assert_eq!(reason(&e), "repo_not_bound", "{e:?}");
    // A commit deliverable needs the task's own binding.
    let e =
        t.call(&builder, "deliverable_create", json!({ "task_id": task, "title": "x" })).await.unwrap_err();
    assert_eq!(reason(&e), "repo_unbound", "{e:?}");
    // The merge would go into the workspace repository, not org B's.
    assert_eq!(t.merge_approval_repo(done).await, Value::Null);
    // Neither the poll nor merged-PR reconciliation touches org B's repository.
    let polled = poll_once(&h.hub).await.unwrap();
    assert_eq!(polled["repos"], json!([]), "{polled}");
    h.ok(&lead, "queue_close_merged", json!({})).await;

    // 2. The default organization binds another project to org B's repository
    //    name: the repository is now bound for it, but not to `web`.
    h.ok(&op, "project_repo_bind", json!({ "project": "api", "repo": "owner-b/repo" })).await;
    let e = t.call(&op, "policy_authorization_record", authorize("owner-b/repo")).await.unwrap_err();
    assert_eq!(reason(&e), "repo_mismatch", "{e:?}");
    let e =
        t.call(&builder, "deliverable_create", json!({ "task_id": task, "title": "x" })).await.unwrap_err();
    assert_eq!(reason(&e), "repo_unbound", "{e:?}");
    assert_eq!(t.merge_approval_repo(done).await, Value::Null);
    // The web task's PR link is in no default project bound to owner-b/repo,
    // so reconciliation never looks the PR up.
    h.ok(&lead, "queue_close_merged", json!({})).await;
    assert!(!t.hits("owner-b/repo").iter().any(|p| p.contains("/pulls/5")), "{:?}", t.hits("owner-b/repo"));
    h.ok(&op, "project_repo_unbind", json!({ "project": "api" })).await;

    // 3. The default organization binds `web` to its own repository.
    h.ok(&op, "project_repo_bind", json!({ "project": "web", "repo": "owner-a/repo" })).await;
    let e = t.call(&op, "policy_authorization_record", authorize("owner-b/repo")).await.unwrap_err();
    assert_eq!(reason(&e), "repo_not_bound", "{e:?}");
    let e = h.err(&builder, "task_check_record", record("ci-b2", Some("owner-b/repo"))).await;
    assert_eq!(reason(&e), "repo_mismatch", "{e:?}");
    let v = h.ok(&builder, "task_check_record", record("ci-a", None)).await;
    assert_eq!(check(&v, "ci-a")["ref"]["repo"], "owner-a/repo", "{v}");
    let ok = t.call(&op, "policy_authorization_record", authorize("owner-a/repo")).await.unwrap();
    assert_eq!(ok["authorization"]["valid"], true, "{ok}");
    assert_eq!(t.merge_approval_repo(done).await, "owner-a/repo");
    // BoundRepo::all, through the poll: the default organization's repository only.
    let polled = poll_once(&h.hub).await.unwrap();
    let repos: Vec<&str> =
        polled["repos"].as_array().unwrap().iter().map(|r| r["repo"].as_str().unwrap()).collect();
    assert_eq!(repos, ["owner-a/repo"], "{polled}");
    assert!(
        t.hits("owner-b/repo").is_empty(),
        "org B's repository was never asked: {:?}",
        t.hits("owner-b/repo")
    );
    assert!(!t.hits("owner-a/repo").is_empty());
}

//! The code family's table, `code_symbols`, is tenant data
//! (`docs/organization.md`, Scoping per subsystem): its part
//! `organization.v1.tools.code` gives it `org_id` and the generated
//! organization triggers, and every query of the symbol tools takes the
//! caller's organization.
//!
//! A second organization is created at the storage level, as no tool creates
//! one yet, and a caller in it is built by hand. The tool tests need the
//! `code-intel` feature; the schema tests run without it.

// Without `code-intel` only the schema tests run, and the tool helpers idle.
#![cfg_attr(not(feature = "code-intel"), allow(dead_code, unused_imports))]

use std::path::Path;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const PART: &str = "organization.v1.tools.code";
const OTHER: &str = "acme";

fn write(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn caller(org: &str) -> Caller {
    Caller {
        label: "builder-1".into(),
        kind: ActorKind::Agent,
        profile: PROFILE,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

/// The profile every test caller uses.
const PROFILE: Profile = Profile::Developer;

/// A second organization that allows the test callers' profile, so the tests
/// do not depend on `allowed_profiles` being unchecked.
fn add_org(hub: &Hub, id: &str) {
    let profiles = serde_json::to_string(&[PROFILE.as_str()]).unwrap();
    hub.db()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                 VALUES (?1, ?1, ?1, ?2, '2026-01-01T00:00:00+00:00')",
                [id, profiles.as_str()],
            )?;
            Ok(())
        })
        .unwrap();
}

/// `(org_id, symbol_name)` of every stored symbol, sorted.
fn stored(hub: &Hub) -> Vec<(String, String)> {
    hub.db()
        .read(|c| {
            let mut stmt =
                c.prepare("SELECT org_id, symbol_name FROM code_symbols ORDER BY org_id, symbol_name")?;
            Ok(stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?)
        })
        .unwrap()
}

fn trigger_names(hub: &Hub) -> Vec<String> {
    hub.db()
        .read(|c| {
            let mut stmt = c.prepare(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'code_symbols' ORDER BY name",
            )?;
            Ok(stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
        })
        .unwrap()
}

struct Env {
    _home: tempfile::TempDir,
    _ws: tempfile::TempDir,
    ws: std::path::PathBuf,
    hub: Hub,
    reg: Registry,
}

fn setup() -> Env {
    let home = tempfile::tempdir().unwrap();
    let ws_dir = tempfile::tempdir().unwrap();
    let ws = ws_dir.path().canonicalize().unwrap();
    write(&ws, "src/lib.rs", "pub fn shared_fn() {}\n");
    let mut cfg = Config::for_home(home.path());
    cfg.workspace = Some(ws.clone());
    let hub = Hub::in_memory(cfg).unwrap();
    add_org(&hub, OTHER);
    Env { _home: home, _ws: ws_dir, ws, hub, reg: builtin_registry() }
}

impl Env {
    async fn call(&self, org: &str, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, &caller(org), tool, args).await
    }

    async fn ok(&self, org: &str, tool: &str, args: Value) -> Value {
        self.call(org, tool, args.clone()).await.unwrap_or_else(|e| panic!("{org} {tool} {args}: {e}"))
    }
}

#[test]
fn the_table_carries_the_organization_and_its_triggers() {
    let env = setup();
    assert_eq!(trigger_names(&env.hub), ["code_symbols_org_exists", "code_symbols_org_immutable"]);
    let notnull: i64 = env
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT \"notnull\" FROM pragma_table_info('code_symbols') WHERE name = 'org_id'",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(notnull, 1);

    let insert = |org: &str| {
        let org = org.to_string();
        env.hub.db().write(move |tx| {
            tx.execute(
                "INSERT INTO code_symbols (org_id, workspace, file_path, language, symbol_name, symbol_type, \
                 symbol_kind, line_no) VALUES (?1, '/ws', 'a.rs', 'rust', 'f', 'function', 'fn', 1)",
                [&org],
            )?;
            Ok(())
        })
    };
    // An organization `orgs` does not hold is refused by the trigger.
    let err = insert("nowhere").unwrap_err().to_string();
    assert!(err.contains("unknown organization"), "{err}");
    insert(OTHER).unwrap();
    // A row never moves between organizations.
    let err = env
        .hub
        .db()
        .write(|tx| Ok(tx.execute("UPDATE code_symbols SET org_id = 'default'", [])?))
        .unwrap_err()
        .to_string();
    assert!(err.contains("org_id cannot change"), "{err}");
    assert_eq!(stored(&env.hub), [(OTHER.to_string(), "f".to_string())]);
}

/// A hub from before the part, with indexed symbols, upgrades: its rows land
/// in the default organization, the triggers are installed, and opening it
/// again applies nothing.
#[test]
fn an_upgraded_database_keeps_its_symbols_in_the_default_organization() {
    use ua_store::Part;
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path().join("home"));
    let old: Vec<Part> = ua_tools::schema_parts().into_iter().filter(|p| p.name != PART).collect();
    assert_eq!(old.len() + 1, ua_tools::schema_parts().len());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old).unwrap();
        db.write(|tx| {
            tx.execute(
                "INSERT INTO code_symbols (workspace, file_path, language, symbol_name, symbol_type, symbol_kind, \
                 line_no) VALUES ('/ws', 'a.rs', 'rust', 'before_upgrade', 'function', 'fn', 1)",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        let has_col: bool = db
            .read(|c| {
                Ok(c.query_row(
                    "SELECT count(*) FROM pragma_table_info('code_symbols') WHERE name = 'org_id'",
                    [],
                    |r| r.get::<_, i64>(0),
                )? == 1)
            })
            .unwrap();
        assert!(!has_col, "the old schema has no org_id");
    }
    let hub = Hub::open(cfg.clone()).unwrap();
    assert_eq!(stored(&hub), [("default".to_string(), "before_upgrade".to_string())]);
    assert_eq!(trigger_names(&hub), ["code_symbols_org_exists", "code_symbols_org_immutable"]);
    let generated: String = hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT generated_sql FROM schema_procedures WHERE name = ?1", [PART], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    assert!(generated.contains("ALTER TABLE code_symbols ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default'"));
    drop(hub);

    // Re-opening is idempotent: the part is recorded once and nothing changes.
    let hub = Hub::open(cfg).unwrap();
    let recorded: i64 = hub
        .db()
        .read(|c| Ok(c.query_row("SELECT count(*) FROM schema_parts WHERE name = ?1", [PART], |r| r.get(0))?))
        .unwrap();
    assert_eq!(recorded, 1);
    assert_eq!(stored(&hub), [("default".to_string(), "before_upgrade".to_string())]);
    assert_eq!(trigger_names(&hub), ["code_symbols_org_exists", "code_symbols_org_immutable"]);
}

/// The hub workspace is the default organization's (`workspace::sandbox`):
/// another organization's code tools are refused before any filesystem
/// access and store nothing. Its rows (made in SQL, as no tool can make
/// them until per-organization workspaces exist) never reach the default
/// organization's reads or re-indexing.
#[cfg(feature = "code-intel")]
#[tokio::test]
async fn another_organization_has_no_code_index_of_the_hub_workspace() {
    let env = setup();
    let default = ua_core::DEFAULT_ORG;
    let idx = env.ok(default, "fs_index_symbols", json!({})).await;
    assert_eq!(idx["symbols_indexed"], 1, "{idx}");

    let before = stored(&env.hub);
    for (tool, args) in [
        ("fs_index_symbols", json!({})),
        ("fs_search_symbols", json!({ "query": "shared_fn" })),
        ("fs_list_symbols", json!({ "file_path": "src/lib.rs" })),
        ("fs_repo_map", json!({})),
    ] {
        let err = env.call(OTHER, tool, args.clone()).await.unwrap_err();
        assert_eq!(err.reason_code(), Some("org_unsupported"), "{tool}({args}): {err}");
        assert!(!err.to_string().contains("shared_fn"), "{err}");
    }
    assert_eq!(stored(&env.hub), before, "nothing stored for the other organization");

    // Another organization's row under the same workspace key.
    let ws = env.ws.to_string_lossy().into_owned();
    env.hub
        .db()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO code_symbols (org_id, workspace, file_path, language, symbol_name, symbol_type, \
                 symbol_kind, line_no) VALUES (?1, ?2, 'src/other.rs', 'rust', 'other_only', 'function', 'fn', 1)",
                [OTHER, ws.as_str()],
            )?;
            Ok(())
        })
        .unwrap();
    // The default organization's reads stay its own.
    let res = env.ok(default, "fs_search_symbols", json!({ "query": "other_only" })).await;
    assert_eq!(res["results"], json!([]), "{res}");
    let map = env.ok(default, "fs_repo_map", json!({})).await;
    let text = map["repo_map"].as_str().unwrap();
    assert!(text.contains("src/lib.rs") && !text.contains("src/other.rs"), "{text}");
    // Re-indexing replaces only the default organization's rows, for the
    // whole workspace and for a subtree.
    std::fs::remove_file(env.ws.join("src/lib.rs")).unwrap();
    write(&env.ws, "src/next.rs", "pub fn next_fn() {}\n");
    env.ok(default, "fs_index_symbols", json!({})).await;
    env.ok(default, "fs_index_symbols", json!({ "path": "src" })).await;
    assert_eq!(
        stored(&env.hub),
        [(OTHER.to_string(), "other_only".to_string()), (default.to_string(), "next_fn".to_string())]
    );
}

#[cfg(feature = "code-intel")]
#[tokio::test]
async fn an_unknown_organization_is_refused_and_writes_nothing() {
    let env = setup();
    let before = stored(&env.hub);
    // Refused before the workspace is read (it is the default
    // organization's), so before the organization is even looked up.
    let err = env.call("nowhere", "fs_index_symbols", json!({})).await.unwrap_err();
    assert_eq!(err.reason_code(), Some("org_unsupported"), "{err}");
    std::fs::create_dir_all(env.ws.join("empty")).unwrap();
    let err = env.call("nowhere", "fs_index_symbols", json!({ "path": "empty" })).await.unwrap_err();
    assert_eq!(err.reason_code(), Some("org_unsupported"), "{err}");
    let err = env.call("nowhere", "fs_repo_map", json!({})).await.unwrap_err();
    assert_eq!(err.reason_code(), Some("org_unsupported"), "{err}");
    assert_eq!(stored(&env.hub), before);
    let events: i64 = env
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT count(*) FROM event_log WHERE channel = 'agent.code.indexed'", [], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    assert_eq!(events, 0, "no index event for a refused call");
}

#[cfg(feature = "code-intel")]
#[tokio::test]
async fn the_index_event_is_unchanged_for_the_default_organization() {
    let env = setup();
    env.ok(ua_core::DEFAULT_ORG, "fs_index_symbols", json!({})).await;
    let (org, payload): (String, String) = env
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT org_id, payload FROM event_log WHERE channel = 'agent.code.indexed'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .unwrap();
    assert_eq!(org, ua_core::DEFAULT_ORG);
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload, json!({ "path": ".", "files_indexed": 1, "symbols_indexed": 1 }));
}

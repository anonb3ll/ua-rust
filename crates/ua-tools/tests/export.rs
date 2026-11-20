//! Exports: tasks, memory and journal, inline and to workspace files.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

struct Env {
    _dir: tempfile::TempDir,
    workspace: std::path::PathBuf,
    vault: std::path::PathBuf,
    hub: Hub,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let vault = dir.path().join("vault");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&vault).unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.workspace = Some(workspace.clone());
    cfg.vault_path = Some(vault.clone());
    let hub = Hub::in_memory(cfg).unwrap();
    Env { _dir: dir, workspace, vault, hub }
}

fn agent(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some(format!("{label}-key")),
        transport: Transport::Mcp,
    }
}

async fn call(reg: &Registry, hub: &Hub, who: &Caller, tool: &str, args: Value) -> Value {
    reg.call(hub, who, tool, args).await.unwrap_or_else(|e| panic!("{tool} failed: {e}"))
}

/// Minimal RFC 4180 reader for the round trip.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            (true, '"') => quoted = false,
            (true, c) => field.push(c),
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut field)),
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            (false, c) => field.push(c),
        }
    }
    rows
}

#[tokio::test]
async fn tasks_round_trip_inline_and_to_file() {
    let e = env();
    let reg = builtin_registry();
    let who = agent("builder-1");
    let tricky = "quote \" comma, and more";
    call(&reg, &e.hub, &who, "task_add", json!({ "title": tricky, "notes": "n|1\nline two" })).await;
    let done =
        call(&reg, &e.hub, &who, "task_add", json!({ "title": "second" })).await["id"].as_i64().unwrap();
    call(&reg, &e.hub, &who, "task_update", json!({ "id": done, "status": "done" })).await;

    let csv = call(&reg, &e.hub, &who, "export_tasks", json!({ "write_to_vault": false })).await;
    assert_eq!(csv["rows"], 2);
    let rows = parse_csv(csv["content"].as_str().unwrap());
    assert_eq!(rows[0][0], "id");
    assert_eq!(rows[0].len(), 11);
    assert_eq!(rows[1][1], tricky);
    assert_eq!(rows[2][1], "second");

    let js = call(
        &reg,
        &e.hub,
        &who,
        "export_tasks",
        json!({ "format": "json", "status": "done", "write_to_vault": false }),
    )
    .await;
    let parsed: Vec<Value> = serde_json::from_str(js["content"].as_str().unwrap()).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0]["id"], done);
    assert_eq!(parsed[0]["status"], "done");

    let md =
        call(&reg, &e.hub, &who, "export_tasks", json!({ "format": "markdown", "write_to_vault": false }))
            .await;
    let md = md["content"].as_str().unwrap();
    assert!(md.starts_with("| id | title |"));
    assert!(md.contains("n\\|1"));

    // To a file in the workspace; two exports in the same second get distinct names.
    let a = call(&reg, &e.hub, &who, "export_tasks", json!({ "format": "json" })).await;
    let b = call(&reg, &e.hub, &who, "export_tasks", json!({ "format": "json" })).await;
    let (pa, pb) = (a["path"].as_str().unwrap(), b["path"].as_str().unwrap());
    assert!(pa.starts_with("exports/tasks-") && pa.ends_with(".json"), "{pa}");
    assert_ne!(pa, pb);
    assert_eq!(a["root"], "workspace");
    let on_disk = std::fs::read_to_string(e.workspace.join(pa)).unwrap();
    assert_eq!(on_disk.len() as u64, a["bytes"].as_u64().unwrap());
    let parsed: Vec<Value> = serde_json::from_str(&on_disk).unwrap();
    assert_eq!(parsed.len(), 2);

    let events =
        call(&reg, &e.hub, &who, "event_log_query", json!({ "channels": ["agent.export.written"] })).await;
    assert_eq!(events["count"], 2);

    for (args, code) in [
        (json!({ "format": "xml" }), "invalid_argument"),
        (json!({ "status": "someday" }), "invalid_argument"),
    ] {
        assert_eq!(reg.call(&e.hub, &who, "export_tasks", args).await.unwrap_err().code(), code);
    }
}

#[tokio::test]
async fn memory_round_trip_with_filters() {
    let e = env();
    let reg = builtin_registry();
    let who = agent("builder-1");
    call(
        &reg,
        &e.hub,
        &who,
        "memory_save",
        json!({ "content": "alpha body", "title": "alpha", "tags": ["keep"] }),
    )
    .await;
    call(
        &reg,
        &e.hub,
        &who,
        "memory_save",
        json!({ "content": "beta body", "title": "beta", "tags": ["other"] }),
    )
    .await;

    let out = call(&reg, &e.hub, &who, "export_memory", json!({ "write_to_vault": false })).await;
    assert_eq!(out["rows"], 2);
    let lines: Vec<Value> =
        out["content"].as_str().unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 2);
    let alpha = lines.iter().find(|n| n["title"] == "alpha").unwrap();
    assert_eq!(alpha["content"], "alpha body");
    assert_eq!(alpha["tags"], json!(["keep"]));
    assert_eq!(alpha["superseded"], false);

    let tagged =
        call(&reg, &e.hub, &who, "export_memory", json!({ "tag": "keep", "write_to_vault": false })).await;
    assert_eq!(tagged["rows"], 1);
    let future =
        call(&reg, &e.hub, &who, "export_memory", json!({ "since": "2999-01-01", "write_to_vault": false }))
            .await;
    assert_eq!(future["rows"], 0);

    let file = call(
        &reg,
        &e.hub,
        &who,
        "export_data",
        json!({ "action": "memory", "params": { "format": "json" } }),
    )
    .await;
    let text = std::fs::read_to_string(e.workspace.join(file["path"].as_str().unwrap())).unwrap();
    let parsed: Vec<Value> = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed.len(), 2);
}

#[tokio::test]
async fn journal_export_reads_every_namespace() {
    let e = env();
    let reg = builtin_registry();
    let who = agent("builder-1");
    let logs = e.vault.join("Logs");
    std::fs::create_dir_all(logs.join("Laptop")).unwrap();
    std::fs::write(
        logs.join("2026-07-10.md"),
        "# Journal\n- **09:15** [builder-1] fixed the build #ci #green\n- **10:00** [reviewer-1] approved\nnot a line\n",
    )
    .unwrap();
    std::fs::write(logs.join("Laptop").join("2026-07-11.md"), "- **08:00** [builder-1] travel notes\n")
        .unwrap();
    std::fs::write(logs.join("README.md"), "- **08:00** [builder-1] ignored, not a daily note\n").unwrap();

    let all = call(&reg, &e.hub, &who, "export_journal", json!({ "write_to_vault": false })).await;
    assert_eq!(all["rows"], 3);
    let rows: Vec<Value> =
        all["content"].as_str().unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(rows[0]["date"], "2026-07-10");
    assert_eq!(rows[0]["text"], "fixed the build");
    assert_eq!(rows[0]["tags"], json!(["ci", "green"]));
    assert_eq!(rows[0]["machine"], "desktop");
    assert_eq!(rows[2]["machine"], "laptop");

    let mine = call(
        &reg,
        &e.hub,
        &who,
        "export_data",
        json!({ "action": "journal", "params": { "agent": "builder-1", "since": "2026-07-11", "write_to_vault": false } }),
    )
    .await;
    assert_eq!(mine["rows"], 1);

    let err = reg.call(&e.hub, &who, "export_data", json!({ "action": "import" })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    assert!(err.to_string().contains("not implemented"), "{err}");
    let err = reg.call(&e.hub, &who, "export_data", json!({ "action": "rollback" })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let err = reg.call(&e.hub, &who, "export_data", json!({ "action": "nope" })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");

    // Without a vault, the journal export refuses.
    let bare = Hub::in_memory(Config::for_home(std::env::temp_dir())).unwrap();
    let err = reg.call(&bare, &who, "export_journal", json!({ "write_to_vault": false })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
}

#[tokio::test]
async fn denied_workspace_cannot_receive_files() {
    let e = env();
    let reg = builtin_registry();
    let mut cfg = e.hub.cfg().clone();
    cfg.agent_workspaces.insert("builder-1".into(), "deny".into());
    let hub = Hub::in_memory(cfg).unwrap();
    let who = agent("builder-1");
    let err = reg.call(&hub, &who, "export_tasks", json!({})).await.unwrap_err();
    assert_eq!(err.code(), "denied");
    // Inline still works.
    let ok = call(&reg, &hub, &who, "export_tasks", json!({ "write_to_vault": false })).await;
    assert_eq!(ok["rows"], 0);
}

//! Read-only migration manifests. Nothing in this file imports or rolls back.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

struct Env {
    _dir: tempfile::TempDir,
    workspace: std::path::PathBuf,
    hub: Hub,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.workspace = Some(workspace.clone());
    cfg.vault_path = Some(dir.path().join("vault"));
    let hub = Hub::in_memory(cfg).unwrap();
    Env { _dir: dir, workspace, hub }
}

fn agent() -> Caller {
    Caller {
        label: "builder-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("builder-1-key".into()),
        transport: Transport::Mcp,
    }
}

async fn call(reg: &Registry, hub: &Hub, tool: &str, args: Value) -> Value {
    reg.call(hub, &agent(), tool, args).await.unwrap_or_else(|e| panic!("{tool} failed: {e}"))
}

fn manifest_of(exported: &Value) -> Value {
    exported["manifest"].clone()
}

#[tokio::test]
async fn export_is_deterministic_and_compare_is_read_only() {
    let e = env();
    let reg = builtin_registry();
    assert!(reg.get("import_migration_manifest").is_none());
    assert!(reg.get("rollback_migration_import").is_none());

    call(&reg, &e.hub, "task_add", json!({"title": "ship the manifest"})).await;
    call(&reg, &e.hub, "memory_save", json!({"title": "note", "content": "remember this", "tags": ["ops"]}))
        .await;

    let first = call(&reg, &e.hub, "export_migration_manifest", json!({})).await;
    let second = call(&reg, &e.hub, "export_migration_manifest", json!({})).await;
    assert_eq!(first["fingerprint"], second["fingerprint"], "generated_at must not change the fingerprint");
    assert!(first["manifest"]["generated_at"].as_str().is_some());
    assert!(first["manifest"].get("generated_at").is_some());
    let mut without_clock = manifest_of(&first);
    without_clock.as_object_mut().unwrap().remove("generated_at");
    without_clock.as_object_mut().unwrap().remove("fingerprint");
    let mut other = manifest_of(&second);
    other.as_object_mut().unwrap().remove("generated_at");
    other.as_object_mut().unwrap().remove("fingerprint");
    assert_eq!(without_clock, other);
    let tasks = first["manifest"]["tasks"].as_array().unwrap();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0]["title"], "ship the manifest");
    assert_eq!(tasks[0]["status"], "open");
    assert!(first["manifest"]["memory"].as_array().unwrap().iter().any(|n| n["title"] == "note"));
    assert!(first["manifest"]["event_log"].is_array());
    assert_eq!(first["manifest"]["memory_entities"], json!([]));
    assert_eq!(first["manifest"]["memory_links"], json!([]));
    assert_eq!(first["manifest"]["manifest_version"], 1);
    assert!(first.get("content").and_then(Value::as_str).is_some_and(|s| s.ends_with('\n')));

    let before = first["fingerprint"].clone();
    let compared = call(
        &reg,
        &e.hub,
        "compare_migration_manifests",
        json!({"left": manifest_of(&first), "right": manifest_of(&second)}),
    )
    .await;
    assert_eq!(compared["same"], true);
    assert_eq!(compared["conflicts"], json!([]));
    assert_eq!(compared["requires_human_disposition"], false);
    let after = call(&reg, &e.hub, "export_migration_manifest", json!({})).await;
    assert_eq!(after["fingerprint"], before, "compare must not write");
}

#[tokio::test]
async fn compare_reports_edits_claims_duplicates_and_missing_parents() {
    let e = env();
    let reg = builtin_registry();
    let base = json!({
        "manifest_version": 1,
        "source_host": "left",
        "fingerprint": "aaa",
        "tasks": [
            {"id": 1, "title": "same", "notes": "body", "parent_id": null, "claimed_by": null},
            {"id": 2, "title": "edit", "notes": "v1", "parent_id": 1, "claimed_by": "builder-1"},
            {"id": 9, "title": "orphan", "notes": "", "parent_id": 99, "claimed_by": null}
        ],
        "memory": [
            {"id": "m1", "title": "shared", "content": "alpha"},
            {"id": "m2", "title": "only left", "content": "beta"}
        ]
    });
    let mut right = base.clone();
    right["source_host"] = json!("right");
    right["fingerprint"] = json!("bbb");
    right["tasks"][1]["notes"] = json!("v2");
    right["tasks"][1]["claimed_by"] = json!("reviewer-1");
    right["tasks"].as_array_mut().unwrap().retain(|t| t["id"] != 9);
    right["memory"].as_array_mut().unwrap().push(json!({"id": "m3", "title": "shared", "content": "alpha"}));

    let diff = call(&reg, &e.hub, "compare_migration_manifests", json!({"left": base, "right": right})).await;
    assert_eq!(diff["same"], false);
    assert_eq!(diff["requires_human_disposition"], true);
    let conflicts = diff["conflicts"].as_array().unwrap();
    assert!(conflicts.iter().any(|c| c["type"] == "active_claim_conflict" && c["id"] == "2"));
    assert!(conflicts.iter().any(|c| c["type"] == "left_only" && c["kind"] == "tasks" && c["id"] == "9"));
    assert!(conflicts.iter().any(|c| c["type"] == "missing_parent" && c["id"] == "9"));
    assert!(conflicts.iter().any(|c| c["type"] == "duplicate_candidate" && c["kind"] == "memory"));
    assert_eq!(diff["summary"]["tasks"]["changed"], 1);
    assert_eq!(diff["summary"]["tasks"]["same"], 1);

    let rejected = reg
        .call(&e.hub, &agent(), "export_data", json!({"action": "import", "params": {"manifest": base}}))
        .await
        .unwrap_err();
    assert!(rejected.to_string().contains("not implemented"), "{rejected}");

    let bad = reg
        .call(
            &e.hub,
            &agent(),
            "compare_migration_manifests",
            json!({"left": {"manifest_version": 2}, "right": {"manifest_version": 1}}),
        )
        .await
        .unwrap_err();
    assert!(bad.to_string().contains("unsupported"), "{bad}");

    let dup = reg
        .call(
            &e.hub,
            &agent(),
            "compare_migration_manifests",
            json!({
                "left": {
                    "manifest_version": 1,
                    "tasks": [],
                    "memory": [],
                    "memory_links": [
                        {"src_id": "a", "dst_id": "b", "rel": "see", "created_at": "t"},
                        {"src_id": "a", "dst_id": "b", "rel": "see", "created_at": "t"}
                    ]
                },
                "right": {"manifest_version": 1, "tasks": [], "memory": []}
            }),
        )
        .await
        .unwrap_err();
    assert!(dup.to_string().contains("duplicate graph keys"), "{dup}");
}

#[tokio::test]
async fn manifest_can_be_written_without_changing_tasks() {
    let e = env();
    let reg = builtin_registry();
    call(&reg, &e.hub, "task_add", json!({"title": "kept"})).await;
    let written = call(&reg, &e.hub, "export_migration_manifest", json!({"write_to_vault": true})).await;
    let path = e.workspace.join(written["path"].as_str().unwrap());
    assert!(path.is_file(), "{}", path.display());
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("kept"));
    let again = call(&reg, &e.hub, "export_migration_manifest", json!({})).await;
    assert_eq!(again["manifest"]["tasks"].as_array().unwrap().len(), 1);
}

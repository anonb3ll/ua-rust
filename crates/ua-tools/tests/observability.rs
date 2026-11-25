//! Observability: the doctor, perf stats from tool_calls, activity, anomalies
//! and schema telemetry.

use secrecy::SecretString;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const TOKEN: &str = "sup3r-s3cret-token-value";
const HOOK_PATH_SECRET: &str = "T000-B000-pathsecret";
const HOOK_HEADER_SECRET: &str = "Bearer webhook-header-secret";

fn mem_hub() -> Hub {
    Hub::in_memory(Config::for_home(std::env::temp_dir())).unwrap()
}

fn agent(label: &str, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile,
        enforce_profile: true,
        session_key: Some(format!("{label}-key")),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

async fn call(reg: &Registry, hub: &Hub, who: &Caller, tool: &str, args: Value) -> Value {
    reg.call(hub, who, tool, args).await.unwrap_or_else(|e| panic!("{tool} failed: {e}"))
}

fn exec(hub: &Hub, sql: &str) {
    let sql = sql.to_string();
    hub.db()
        .write(move |tx| {
            tx.execute_batch(&sql)?;
            Ok(())
        })
        .unwrap();
}

fn ago(secs: i64) -> String {
    let now = jiff::Timestamp::now();
    ua_core::time::format_ts(now.checked_sub(jiff::SignedDuration::from_secs(secs)).unwrap())
}

#[tokio::test]
async fn doctor_reports_every_capability_without_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.agent_tokens = Some(SecretString::from(format!("builder-1:{TOKEN}")));
    // Tokens exist but auth is explicitly switched off: the doctor flags it.
    cfg.enforce_auth = false;
    cfg.notify_webhook_url = Some(format!("https://hooks.example.com/services/{HOOK_PATH_SECRET}"));
    cfg.notify_webhook_secret = Some(SecretString::from(HOOK_HEADER_SECRET));
    cfg.approval_tools = vec!["event_log_verify".into()];
    std::fs::create_dir_all(cfg.workspace_root()).unwrap();
    let hub = Hub::open(cfg).unwrap();
    let reg = builtin_registry();
    let who = agent("reviewer-1", Profile::Lead);

    let report = call(&reg, &hub, &who, "system_doctor", json!({ "refresh": true })).await;
    let text = report.to_string();
    for secret in [TOKEN, HOOK_PATH_SECRET, "webhook-header-secret"] {
        assert!(!text.contains(secret), "doctor leaked a secret: {secret}");
    }

    let checks = report["checks"].as_array().unwrap();
    let status = |cap: &str| -> &str {
        checks
            .iter()
            .find(|c| c["capability"] == cap)
            .and_then(|c| c["status"].as_str())
            .unwrap_or_else(|| panic!("no {cap} row in {report}"))
    };
    for c in checks {
        assert!(c["detail"].is_string() && c["gate"].is_string(), "{c}");
        assert!(
            ["LIVE", "DORMANT", "DEGRADED", "MISCONFIGURED", "UNKNOWN"]
                .contains(&c["status"].as_str().unwrap()),
            "{c}"
        );
    }
    // Tokens exist but auth is not enforced.
    assert_eq!(status("hub_auth"), "DEGRADED");
    // Gated tools but no human who could approve them.
    assert_eq!(status("approval_gating"), "MISCONFIGURED");
    assert_eq!(status("vault"), "DORMANT");
    assert_eq!(status("workspace_root"), "LIVE");
    assert_eq!(status("database"), "LIVE");
    assert_eq!(status("schema"), "LIVE");
    assert_eq!(status("notify_webhook"), "LIVE");
    assert_eq!(status("search_provider"), "DORMANT");
    assert_eq!(status("http_bind"), "LIVE");
    assert!(["LIVE", "DORMANT"].contains(&status("ledger_chain")));
    // No notes yet, or no embeddings feature: either way nothing to embed.
    assert_eq!(status("semantic_search"), "DORMANT");
    // Optional Cargo features: the row and build.features follow this build.
    let all_default = cfg!(feature = "code-intel")
        && cfg!(feature = "readability")
        && cfg!(feature = "mcp-gateway")
        && cfg!(feature = "mcp-server");
    assert_eq!(status("build_features"), if all_default { "LIVE" } else { "DORMANT" });
    let features = &report["build"]["features"];
    assert_eq!(features["code_intel"], cfg!(feature = "code-intel"), "{features}");
    assert_eq!(features["readability"], cfg!(feature = "readability"), "{features}");
    assert_eq!(features["mcp_gateway"], cfg!(feature = "mcp-gateway"), "{features}");
    assert_eq!(features["mcp_server"], cfg!(feature = "mcp-server"), "{features}");
    assert!(features["embeddings"].is_boolean(), "{features}");
    let out: Vec<&str> = report["build"]["compiled_out_tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["tool"].as_str().unwrap())
        .collect();
    assert_eq!(out.contains(&"fs_repo_map"), !cfg!(feature = "code-intel"), "{out:?}");
    assert_eq!(out.contains(&"mcp_gateway"), !cfg!(feature = "mcp-gateway"), "{out:?}");
    assert_eq!(report["database"]["journal_mode"], "wal");
    assert_eq!(report["database"]["quick_check"], "ok");

    let total: i64 = report["summary"].as_object().unwrap().values().map(|v| v.as_i64().unwrap()).sum();
    assert_eq!(total as usize, checks.len());
    assert_eq!(report["cached"], false);
}

#[tokio::test]
async fn doctor_flags_a_tampered_ledger() {
    let hub = mem_hub();
    let reg = builtin_registry();
    let who = agent("builder-1", Profile::Developer);
    call(&reg, &hub, &who, "task_add", json!({ "title": "one" })).await;
    call(&reg, &hub, &who, "task_add", json!({ "title": "two" })).await;
    exec(&hub, "DROP TRIGGER event_log_no_update; UPDATE event_log SET payload = '{\"x\":1}' WHERE seq = 1;");
    let report = call(&reg, &hub, &who, "system_doctor", json!({})).await;
    let row =
        report["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "ledger_chain").unwrap();
    assert_eq!(row["status"], "DEGRADED", "{row}");

    let anomalies = call(&reg, &hub, &who, "check_anomalies", json!({})).await;
    assert!(anomalies["anomalies"].as_array().unwrap().iter().any(|a| a["rule"] == "ledger_chain"));

    // Unexpected table with no corresponding schema_parts entry degrades `schema`.
    exec(&hub, "CREATE TABLE rogue_table (x INTEGER);");
    let report = call(&reg, &hub, &who, "system_doctor", json!({})).await;
    let schema_row =
        report["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "schema").unwrap();
    assert_eq!(schema_row["status"], "DEGRADED", "{schema_row}");

    // Applying optional `import.v1` must stay LIVE (matching `ua doctor`) AND must NOT mask
    // unrelated rogue tables added afterwards.
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    std::fs::create_dir_all(cfg.workspace_root()).unwrap();
    drop(Hub::open(cfg.clone()).unwrap());
    let mut all_with_import = ua_tools::schema_parts();
    all_with_import.extend(ua_tools::optional_schema_parts());
    drop(ua_store::Db::open(&cfg.db_path(), &all_with_import).unwrap());
    let import_hub = Hub::open(cfg).unwrap();

    let clean_report = call(&reg, &import_hub, &who, "system_doctor", json!({ "refresh": true })).await;
    let clean_schema =
        clean_report["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "schema").unwrap();
    assert_eq!(clean_schema["status"], "LIVE", "{clean_schema}");
    assert!(
        !clean_schema["detail"].as_str().unwrap_or("").contains("another build"),
        "import.v1 should be recognized as optional, not extra: {clean_schema}"
    );

    exec(&import_hub, "CREATE TABLE rogue_after_import (x INTEGER);");
    let dirty_report = call(&reg, &import_hub, &who, "system_doctor", json!({ "refresh": true })).await;
    let dirty_schema =
        dirty_report["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "schema").unwrap();
    assert_eq!(dirty_schema["status"], "DEGRADED", "{dirty_schema}");
}

fn insert_calls(hub: &Hub, tool: &str, caller: &str, durations: &[i64], errors: usize, started_at: &str) {
    let (tool, caller, started_at) = (tool.to_string(), caller.to_string(), started_at.to_string());
    let durations = durations.to_vec();
    hub.db()
        .write(move |tx| {
            for (i, ms) in durations.iter().enumerate() {
                let outcome = if i < errors { "internal" } else { "ok" };
                tx.execute(
                    "INSERT INTO tool_calls (tool, caller, profile, transport, started_at, duration_ms, outcome) \
                     VALUES (?1, ?2, 'developer', 'mcp', ?3, ?4, ?5)",
                    rusqlite::params![tool, caller, started_at, ms, outcome],
                )?;
            }
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn perf_summary_from_tool_calls() {
    let hub = mem_hub();
    let reg = builtin_registry();
    // A local-trust reader is unrestricted: it sees every caller's rows.
    let who = Caller::local("observer-1", Transport::Stdio);
    let durations: Vec<i64> = (1..=100).collect();
    insert_calls(&hub, "synthetic_alpha", "builder-1", &durations, 10, &ua_core::time::now());
    insert_calls(&hub, "synthetic_beta", "builder-2", &[5, 7, 9, 11], 0, &ua_core::time::now());
    // Outside a 24 h window.
    insert_calls(&hub, "synthetic_alpha", "builder-1", &[100_000], 1, &ago(2 * 86_400));

    let perf = call(&reg, &hub, &who, "perf_summary", json!({ "since_hours": 24 })).await;
    let alpha = &perf["by_tool"]["synthetic_alpha"];
    assert_eq!(alpha["calls"], 100);
    assert_eq!(alpha["errors"], 10);
    assert_eq!(alpha["error_rate"], 0.1);
    assert_eq!(alpha["p50_latency_ms"], 50);
    assert_eq!(alpha["p95_latency_ms"], 95);
    assert_eq!(alpha["min_latency_ms"], 1);
    assert_eq!(alpha["max_latency_ms"], 100);
    assert_eq!(alpha["avg_latency_ms"], 50.5);
    assert_eq!(alpha["outcomes"]["internal"], 10);
    let beta = &perf["by_tool"]["synthetic_beta"];
    assert_eq!(beta["p50_latency_ms"], 7);
    assert_eq!(beta["error_rate"], 0.0);
    assert_eq!(perf["by_caller"]["builder-1"]["calls"], 100);
    assert_eq!(perf["by_caller"]["builder-2"]["calls"], 4);

    // A longer window includes the old row.
    let wide = call(&reg, &hub, &who, "perf_summary", json!({ "since_hours": 72 })).await;
    assert_eq!(wide["by_tool"]["synthetic_alpha"]["calls"], 101);
    assert_eq!(wide["by_tool"]["synthetic_alpha"]["max_latency_ms"], 100_000);

    // The consolidated tool returns the same numbers, under either action name.
    for action in ["performance", "perf_summary"] {
        let via = call(
            &reg,
            &hub,
            &who,
            "observability_manage",
            json!({ "action": action, "params": { "since_hours": 24 } }),
        )
        .await;
        assert_eq!(via["by_tool"]["synthetic_alpha"], perf["by_tool"]["synthetic_alpha"]);
    }

    // A tool failing at least half of 20+ calls is an anomaly.
    insert_calls(&hub, "synthetic_flaky", "builder-3", &[1; 20], 12, &ua_core::time::now());
    let anomalies = call(&reg, &hub, &who, "check_anomalies", json!({})).await;
    let list = anomalies["anomalies"].as_array().unwrap();
    assert!(list.iter().any(|a| a["rule"] == "tool_error_rate" && a["subject"] == "tool:synthetic_flaky"));
    assert!(!list.iter().any(|a| a["subject"] == "tool:synthetic_alpha"));
}

#[tokio::test]
async fn activity_metrics_and_task_anomalies() {
    let hub = mem_hub();
    let reg = builtin_registry();
    let who = agent("builder-1", Profile::Developer);
    let id = call(&reg, &hub, &who, "task_add", json!({ "title": "watch me" })).await["id"].as_i64().unwrap();
    call(&reg, &hub, &who, "memory_save", json!({ "content": "a note", "title": "n" })).await;

    let act = call(&reg, &hub, &who, "agent_activity", json!({ "kind": "task", "agent": "builder-1" })).await;
    let events = act["events"].as_array().unwrap();
    assert!(!events.is_empty());
    assert!(events.iter().all(|e| e["kind"] == "task"));
    assert!(
        events.iter().any(|e| e["ref_id"] == id.to_string().as_str() && e["summary"] == "agent.task.created")
    );
    assert_eq!(act["truncated"], false);

    let err = reg.call(&hub, &who, "agent_activity", json!({ "since": "last tuesday" })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let dated = call(&reg, &hub, &who, "agent_activity", json!({ "since": "2000-01-01" })).await;
    assert!(!dated["events"].as_array().unwrap().is_empty());

    let metrics = call(&reg, &hub, &who, "metrics_snapshot", json!({})).await;
    assert_eq!(metrics["tasks_by_status"]["open"], 1);
    assert!(metrics["events_last_7_days"]["builder-1"]["task"].as_i64().unwrap() >= 1);
    assert!(metrics["db_size_bytes"].as_i64().unwrap() > 0);
    assert_eq!(metrics["done_task_cycle_days"]["count"], 0);

    // A stale doing task and an old pending approval.
    let old = ago(10 * 86_400);
    exec(
        &hub,
        &format!(
            "INSERT INTO tasks (title, status, created_at, updated_at, claimed_by) VALUES ('stuck', 'doing', '{old}', '{old}', 'builder-9');
             INSERT INTO approvals (tool, payload, requested_by, status, created_at, updated_at) VALUES ('run_cmd', '{{}}', 'builder-9', 'pending', '{old}', '{old}');
             INSERT INTO tasks (title, notes, status, created_at, updated_at) VALUES ('shipped?', '[code-task]', 'done', '{old}', '{old}');"
        ),
    );
    let anomalies = call(&reg, &hub, &who, "observability_manage", json!({ "action": "anomalies" })).await;
    let rules: Vec<&str> =
        anomalies["anomalies"].as_array().unwrap().iter().map(|a| a["rule"].as_str().unwrap()).collect();
    assert!(rules.contains(&"stale_doing_task"), "{rules:?}");
    assert!(rules.contains(&"approval_queue_age"), "{rules:?}");
    assert!(rules.contains(&"unverified_done"), "{rules:?}");

    let bad = reg
        .call(&hub, &who, "observability_manage", json!({ "action": "runs_in_flight" }))
        .await
        .unwrap_err();
    assert_eq!(bad.code(), "invalid_argument");
    let bad = reg
        .call(&hub, &who, "observability_manage", json!({ "action": "activity", "params": { "bogus": 1 } }))
        .await
        .unwrap_err();
    assert_eq!(bad.code(), "invalid_argument");
}

#[tokio::test]
async fn activity_and_metrics_hide_restricted_events_from_outsiders() {
    let hub = mem_hub();
    let reg = builtin_registry();
    let (owner, peer, outsider) = (
        agent("builder-1", Profile::Developer),
        agent("builder-2", Profile::Developer),
        agent("builder-3", Profile::Developer),
    );
    let task = call(&reg, &hub, &owner, "task_add", json!({ "title": "review" })).await["id"].clone();

    // One row on each restricted channel, all originated by builder-1.
    let conv = call(
        &reg,
        &hub,
        &owner,
        "message_send",
        json!({ "act": "request", "to_agent": peer.label, "body": "private", "task_id": task }),
    )
    .await["conversation_id"]
        .clone();
    let sid = call(&reg, &hub, &owner, "session_start", json!({ "kind": "interactive", "task_id": task }))
        .await["session_id"]
        .clone();
    let note = call(
        &reg,
        &hub,
        &owner,
        "coordination_manage",
        json!({ "action": "session_handoff_propose",
                "params": { "session_id": sid, "done": ["a"], "next_steps": ["b"] } }),
    )
    .await;
    call(
        &reg,
        &hub,
        &owner,
        "coordination_manage",
        json!({ "action": "session_handoff_seal", "params": { "note_id": note["id"] } }),
    )
    .await;
    call(
        &reg,
        &hub,
        &owner,
        "coordination_manage",
        json!({ "action": "conversation_handoff", "params": { "conversation_id": conv, "task_id": task } }),
    )
    .await;

    let restricted = ["message", "lifecycle", "conversation"];
    let kinds = |v: &Value| -> Vec<String> {
        v["events"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap().to_string()).collect()
    };
    let activity = json!({ "action": "activity", "params": { "agent": "builder-1" } });
    let metrics = json!({ "action": "metrics", "params": {} });

    // The outsider's activity and metrics carry none of the restricted rows.
    let out = call(&reg, &hub, &outsider, "observability_manage", activity.clone()).await;
    assert!(kinds(&out).iter().all(|k| !restricted.contains(&k.as_str())), "{out}");
    let out_metrics = call(&reg, &hub, &outsider, "observability_manage", metrics.clone()).await;
    let out_b1 = &out_metrics["events_last_7_days"]["builder-1"];
    assert!(restricted.iter().all(|k| out_b1.get(*k).is_none()), "{out_b1}");

    // A party to the rows sees them in both views.
    let own = call(&reg, &hub, &owner, "observability_manage", activity).await;
    for k in restricted {
        assert!(kinds(&own).iter().any(|x| x == k), "{k} missing for the party: {own}");
    }
    let own_metrics = call(&reg, &hub, &owner, "observability_manage", metrics.clone()).await;
    let own_b1 = &own_metrics["events_last_7_days"]["builder-1"];
    for k in restricted {
        assert!(own_b1[k].as_i64().unwrap_or(0) >= 1, "{k} missing for the party: {own_b1}");
    }

    // The message recipient is not the originator: it still sees the message
    // row it received, and the conversation-handoff link it is a party to,
    // but not builder-1's private handoff note.
    let peer_view = json!({ "action": "activity", "params": { "agent": "builder-1" } });
    let seen = call(&reg, &hub, &peer, "observability_manage", peer_view).await;
    let seen_kinds = kinds(&seen);
    assert!(seen_kinds.iter().any(|k| k == "message"), "recipient misses its mail: {seen}");
    assert!(
        seen_kinds.iter().any(|k| k == "conversation"),
        "recipient misses the link it is a party to: {seen}"
    );
    assert!(seen_kinds.iter().all(|k| k != "lifecycle"), "recipient sees builder-1's private note: {seen}");
    let peer_metrics = call(&reg, &hub, &peer, "observability_manage", metrics).await;
    let peer_b1 = &peer_metrics["events_last_7_days"]["builder-1"];
    assert!(peer_b1["message"].as_i64().unwrap_or(0) >= 1, "{peer_b1}");
    assert!(peer_b1["lifecycle"].as_i64().unwrap_or(0) == 0, "{peer_b1}");
}

#[tokio::test]
async fn performance_counts_only_the_readers_own_calls() {
    let hub = mem_hub();
    let reg = builtin_registry();
    let (sender, outsider) = (agent("builder-1", Profile::Developer), agent("builder-3", Profile::Developer));
    call(
        &reg,
        &hub,
        &sender,
        "message_send",
        json!({ "act": "inform", "to_agent": "builder-2", "body": "private ping" }),
    )
    .await;

    let perf = json!({ "action": "performance", "params": {} });

    // The outsider sees only its own calls: builder-1's message_send is absent.
    let out = call(&reg, &hub, &outsider, "observability_manage", perf.clone()).await;
    assert_eq!(out["scope"], "own_calls");
    assert!(out["by_tool"].get("message_send").is_none(), "{out}");
    assert!(out["by_caller"].get("builder-1").is_none(), "{out}");

    // The agent sees its own calls.
    let own = call(&reg, &hub, &sender, "observability_manage", perf.clone()).await;
    assert_eq!(own["scope"], "own_calls");
    assert!(own["by_tool"]["message_send"]["calls"].as_i64().unwrap() >= 1, "{own}");
    assert!(own["by_caller"].get("builder-2").is_none(), "{own}");

    // A mail-unrestricted reader sees them all.
    let board = Caller::local("local", Transport::Stdio);
    let all = call(&reg, &hub, &board, "observability_manage", perf).await;
    assert_eq!(all["scope"], "all");
    assert!(all["by_tool"]["message_send"]["calls"].as_i64().unwrap() >= 1, "{all}");
    assert!(all["by_caller"]["builder-1"]["calls"].as_i64().unwrap() >= 1, "{all}");
}

#[tokio::test]
async fn remote_assistant_reaches_only_its_actions() {
    let hub = mem_hub();
    let reg = builtin_registry();
    let remote = agent("assistant-1", Profile::RemoteAssistant);
    let list = call(&reg, &hub, &remote, "observability_manage", json!({ "action": "agent_list" })).await;
    assert!(list["agents"].is_array());
    let ctx = call(&reg, &hub, &remote, "observability_manage", json!({ "action": "agent_context" })).await;
    assert!(ctx.is_object());
    let err =
        reg.call(&hub, &remote, "observability_manage", json!({ "action": "metrics" })).await.unwrap_err();
    assert_eq!(err.code(), "denied");
    // The legacy standalone tools are not on its surface.
    let err = reg.call(&hub, &remote, "perf_summary", json!({})).await.unwrap_err();
    assert_eq!(err.code(), "denied");
}

#[tokio::test]
async fn schema_fingerprint_and_call_counts() {
    let hub = mem_hub();
    let reg = builtin_registry();
    let dev = agent("builder-1", Profile::Developer);
    let first = call(&reg, &hub, &dev, "mcp_health_telemetry", json!({})).await;
    let fp = first["schema_fingerprint"].as_str().unwrap();
    assert_eq!(fp.len(), 16);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(first["semantic_schema_fingerprint"].as_str().unwrap().len(), 64);
    assert_eq!(first["semantic_schema_fingerprint_version"], 2);
    assert_eq!(first["tool_count"].as_u64().unwrap() as usize, reg.len());

    let second = call(&reg, &hub, &dev, "mcp_health_telemetry", json!({})).await;
    assert_eq!(second["schema_fingerprint"], first["schema_fingerprint"]);
    assert_eq!(second["registry_semantic_schema_fingerprint"], first["registry_semantic_schema_fingerprint"]);
    // The first call is now on record.
    assert!(second["calls"]["total_calls"].as_i64().unwrap() >= 1);
    assert!(
        second["calls"]["top_tools_24h"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["tool"] == "mcp_health_telemetry")
    );

    // A narrower surface has a different callable fingerprint, same registry one.
    let research = agent("reader-1", Profile::Research);
    let narrow = reg.call(&hub, &research, "mcp_health_telemetry", json!({})).await;
    if let Ok(narrow) = narrow {
        assert_ne!(narrow["schema_fingerprint"], first["schema_fingerprint"]);
        assert_eq!(narrow["registry_schema_fingerprint"], first["registry_schema_fingerprint"]);
    }
}

#[tokio::test]
async fn doctor_reports_slack_without_secrets() {
    let reg = builtin_registry();
    let who = agent("builder-1", Profile::Developer);
    let row = |report: &Value| {
        report["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "slack").unwrap().clone()
    };
    let hub = mem_hub();
    let off = row(&call(&reg, &hub, &who, "system_doctor", json!({})).await);
    assert_eq!(off["status"], "DORMANT", "{off}");

    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.slack_socket_mode = true;
    cfg.slack_app_token_value = Some(SecretString::from("xapp-1-doctor-secret".to_string()));
    let hub = Hub::in_memory(cfg).unwrap();
    let on = row(&call(&reg, &hub, &who, "system_doctor", json!({})).await);
    assert!(!on.to_string().contains("doctor-secret"), "{on}");
    if cfg!(feature = "slack-socket") {
        assert!(on["detail"].as_str().unwrap().contains("Socket Mode"), "{on}");
    } else {
        assert_eq!(on["status"], "MISCONFIGURED", "{on}");
        assert!(on["detail"].as_str().unwrap().contains("without the slack-socket feature"), "{on}");
    }
}

/// The vault and the workspace are the hub's filesystem, the default
/// organization's: another organization's doctor gets one neutral line for
/// each, the same whether the vault is absent, misconfigured or live, so it
/// learns neither whether the path exists nor whether a write directory is
/// writable. The default organization's doctor still reports each state.
#[tokio::test]
async fn doctor_tells_another_organization_nothing_about_the_hub_filesystem() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    std::fs::create_dir_all(vault.join("Inbox")).unwrap();
    let not_a_dir = dir.path().join("vault-file");
    std::fs::write(&not_a_dir, "fake").unwrap();
    let reg = builtin_registry();
    let other = Caller { org_id: "org-b".into(), ..agent("reviewer-1", Profile::Lead) };
    let mut seen_b = Vec::new();
    let mut seen_default = Vec::new();
    for (i, path) in [None, Some(not_a_dir.clone()), Some(vault.clone())].into_iter().enumerate() {
        let mut cfg = Config::for_home(dir.path().join(format!("home-{i}")));
        cfg.vault_path = path;
        cfg.vault_write_dirs = vec!["Inbox".into(), "Missing".into()];
        let hub = Hub::in_memory(cfg).unwrap();
        exec(
            &hub,
            "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) VALUES \
             ('org-b', 'org-b', 'Org B', '[\"lead\"]', '2026-01-01T00:00:00+00:00')",
        );
        let line = |report: &Value, cap: &str| {
            report["checks"].as_array().unwrap().iter().find(|c| c["capability"] == cap).cloned().unwrap()
        };
        let b = call(&reg, &hub, &other, "system_doctor", json!({})).await;
        for cap in ["vault", "workspace_root"] {
            let row = line(&b, cap);
            assert_eq!(row["status"], "DORMANT", "{row}");
            assert_eq!(row["detail"], "not available to this organization", "{row}");
        }
        assert!(!b.to_string().contains("write dir"), "{b}");
        seen_b.push((line(&b, "vault"), line(&b, "workspace_root")));
        let own = call(&reg, &hub, &agent("reviewer-1", Profile::Lead), "system_doctor", json!({})).await;
        seen_default.push(line(&own, "vault")["status"].clone());
    }
    assert!(seen_b.windows(2).all(|w| w[0] == w[1]), "{seen_b:?}");
    assert_eq!(seen_default, [json!("DORMANT"), json!("MISCONFIGURED"), json!("DEGRADED")]);
}

/// The hub's host, its shared database file and the policy file are the
/// default organization's: another organization's doctor gets no host
/// name, one neutral `database` line with no statistics (no file or WAL
/// size, page counts or deep `quick_check`) and one neutral `policy_file`
/// line, the same whether the policy file is absent, missing or present.
/// Its own lines (here `semantic_search`, over its own counts) stay, and
/// `hub_auth` is a neutral line. The default organization's doctor still
/// reports each.
#[tokio::test]
async fn doctor_tells_another_organization_nothing_about_the_hub_host_database_or_policy() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("fake-policy.yaml");
    std::fs::write(&policy, "rules: []\n").unwrap();
    let reg = builtin_registry();
    let other = Caller { org_id: "org-b".into(), ..agent("reviewer-1", Profile::Lead) };
    let line = |report: &Value, cap: &str| {
        report["checks"].as_array().unwrap().iter().find(|c| c["capability"] == cap).cloned().unwrap()
    };
    let mut seen_b = Vec::new();
    let mut seen_default = Vec::new();
    for (i, path) in [None, Some(dir.path().join("fake-missing-policy.yaml")), Some(policy.clone())]
        .into_iter()
        .enumerate()
    {
        let mut cfg = Config::for_home(dir.path().join(format!("home-{i}")));
        cfg.policy_file = path;
        let hub = Hub::open(cfg).unwrap();
        exec(
            &hub,
            "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) VALUES \
             ('org-b', 'org-b', 'Org B', '[\"lead\"]', '2026-01-01T00:00:00+00:00')",
        );
        let b = call(&reg, &hub, &other, "system_doctor", json!({ "refresh": true })).await;
        assert!(b["host"].is_null(), "{b}");
        assert!(b["database"].is_null(), "{b}");
        assert_eq!(b["deep_checks"], false, "{b}");
        for cap in ["database", "policy_file"] {
            let row = line(&b, cap);
            assert_eq!(row["status"], "DORMANT", "{row}");
            assert_eq!(row["detail"], "not available to this organization", "{row}");
        }
        let text = b.to_string();
        for hidden in ["bytes", "WAL", "journal_mode", "quick_check", "policy file"] {
            assert!(!text.contains(hidden), "{hidden} in {text}");
        }
        for cap in ["semantic_search", "hub_auth"] {
            line(&b, cap);
        }
        seen_b.push((line(&b, "database"), line(&b, "policy_file")));

        let own = call(&reg, &hub, &agent("reviewer-1", Profile::Lead), "system_doctor", json!({})).await;
        assert!(own["database"]["file_bytes"].as_i64().is_some_and(|n| n > 0), "{own}");
        assert!(line(&own, "database")["detail"].as_str().unwrap().contains("journal_mode="), "{own}");
        seen_default.push(line(&own, "policy_file")["status"].clone());
    }
    assert!(seen_b.windows(2).all(|w| w[0] == w[1]), "{seen_b:?}");
    assert_eq!(seen_default, [json!("DORMANT"), json!("MISCONFIGURED"), json!("LIVE")]);
}

const ORG_B: &str = "org-b";

fn add_org_b(hub: &Hub) {
    exec(
        hub,
        "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) VALUES \
         ('org-b', 'org-b', 'Org B', '[\"lead\"]', '2026-01-01T00:00:00+00:00')",
    );
}

fn org_b_lead() -> Caller {
    Caller { org_id: ORG_B.into(), ..agent("reviewer-1", Profile::Lead) }
}

fn check(report: &Value, cap: &str) -> Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["capability"] == cap)
        .cloned()
        .unwrap_or_else(|| panic!("no {cap} row in {report}"))
}

/// The fleet row is the reader's own: another organization's doctor names
/// its own nodes and heartbeats, never the default organization's (live,
/// retired or their heartbeats), and carries no `other_org_*` counts. The
/// hub's webhook (scheme, host, secret header, last delivery), schema and
/// auth configuration are neutral lines for it. The default organization's
/// doctor still reports each in full.
#[tokio::test]
async fn doctor_gives_another_organization_its_own_fleet_and_neutral_hub_lines() {
    const DEFAULT_NODE: &str = "fake-default-node-osprey";
    const RETIRED_NODE: &str = "fake-retired-node-heron";
    const B_NODE: &str = "fake-b-node-kestrel";
    const HOOK_HOST: &str = "fake-hook.example.test";
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.agent_tokens = Some(SecretString::from(format!("builder-1:{TOKEN}")));
    cfg.notify_webhook_url = Some(format!("https://{HOOK_HOST}/services/{HOOK_PATH_SECRET}"));
    cfg.notify_webhook_secret = Some(SecretString::from(HOOK_HEADER_SECRET));
    cfg.node_require_acceptance = true;
    let hub = Hub::open(cfg).unwrap();
    add_org_b(&hub);
    let (default_beat, b_beat) = (ago(4000), ago(10));
    exec(
        &hub,
        &format!(
            "INSERT INTO agents (org_id, label, created_at, updated_at) VALUES \
               ('default', 'fake-agent-a', 't', 't'), ('org-b', 'fake-agent-b', 't', 't'); \
             INSERT INTO nodes (org_id, node, agent, facts_json, registered_at, last_heartbeat, updated_at) VALUES \
               ('default', '{DEFAULT_NODE}', 'fake-agent-a', '{{}}', 't', '{default_beat}', 't'), \
               ('org-b', '{B_NODE}', 'fake-agent-b', '{{}}', 't', '{b_beat}', 't'); \
             INSERT INTO nodes (org_id, node, agent, facts_json, registered_at, last_heartbeat, updated_at, \
               retired_at) VALUES ('default', '{RETIRED_NODE}', 'fake-agent-a', '{{}}', 't', 't', 't', 't'); \
             INSERT INTO notify_outbox (org_id, kind, chars, status, last_error, created_at, updated_at) VALUES \
               ('default', 'notify', 1, 'failed', 'fake delivery error', 't', 't');"
        ),
    );
    let reg = builtin_registry();

    let b = call(&reg, &hub, &org_b_lead(), "system_doctor", json!({})).await;
    let fleet = check(&b, "fleet_nodes");
    assert_eq!(
        fleet["hosts"],
        json!([{ "node": B_NODE, "state": "live", "last_heartbeat": b_beat }]),
        "{fleet}"
    );
    assert!(fleet["detail"].as_str().unwrap().contains(B_NODE), "{fleet}");
    for key in
        ["other_org_nodes", "other_org_nodes_not_accepted", "other_org_unsent_command_notices", "retired"]
    {
        assert!(fleet.get(key).is_none(), "{key} in {fleet}");
    }
    let text = b.to_string();
    for hidden in [
        DEFAULT_NODE,
        RETIRED_NODE,
        default_beat.as_str(),
        "other-organization",
        HOOK_HOST,
        "https://",
        "secret header",
        "last delivery",
        "static tokens",
        "humans configured",
        "enforce_auth",
        "schema parts",
    ] {
        assert!(!text.contains(hidden), "{hidden} in {text}");
    }
    for cap in ["notify_webhook", "schema", "hub_auth"] {
        let row = check(&b, cap);
        assert_eq!(row["status"], "DORMANT", "{row}");
        assert_eq!(row["detail"], "not available to this organization", "{row}");
    }

    let own = call(&reg, &hub, &agent("reviewer-1", Profile::Lead), "system_doctor", json!({})).await;
    let fleet = check(&own, "fleet_nodes");
    let detail = fleet["detail"].as_str().unwrap();
    assert!(detail.contains(DEFAULT_NODE) && detail.contains(RETIRED_NODE), "{fleet}");
    assert!(!fleet.to_string().contains(B_NODE), "{fleet}");
    assert_eq!(fleet["hosts"][0]["last_heartbeat"], json!(default_beat), "{fleet}");
    assert_eq!(fleet["other_org_nodes"], json!({ "active": 1, "retired": 0 }), "{fleet}");
    assert_eq!(fleet["other_org_nodes_not_accepted"], 1, "{fleet}");
    let notify = check(&own, "notify_webhook");
    assert_eq!(notify["status"], "DEGRADED", "{notify}");
    let detail = notify["detail"].as_str().unwrap();
    assert!(detail.contains(HOOK_HOST) && detail.contains("the last delivery failed"), "{notify}");
    assert!(check(&own, "schema")["detail"].as_str().unwrap().contains("schema parts applied"), "{own}");
    assert!(
        check(&own, "hub_auth")["detail"].as_str().unwrap().contains("static tokens configured: 1"),
        "{own}"
    );
}

/// Another organization's ledger line and `ledger_chain` anomaly say only
/// whether the hub's ledger verifies: no entry count, seq or reason. It
/// reuses the hub's last full verify while that is fresh instead of
/// re-reading the whole ledger on every call (a tampered row goes unseen by
/// it until the next full verify), and a default-organization doctor's full
/// verify updates it.
#[tokio::test]
async fn another_organizations_ledger_line_is_neutral_and_reuses_the_last_full_verify() {
    let hub = mem_hub();
    add_org_b(&hub);
    let reg = builtin_registry();
    let who = agent("builder-1", Profile::Developer);
    call(&reg, &hub, &who, "task_add", json!({ "title": "fake one" })).await;
    call(&reg, &hub, &who, "task_add", json!({ "title": "fake two" })).await;
    let b = org_b_lead();
    let ledger_row = |r: &Value| check(r, "ledger_chain");
    let b_anomaly =
        |r: &Value| r["anomalies"].as_array().unwrap().iter().find(|a| a["rule"] == "ledger_chain").cloned();

    let row = ledger_row(&call(&reg, &hub, &b, "system_doctor", json!({})).await);
    assert_eq!(
        (row["status"].as_str(), row["detail"].as_str()),
        (Some("LIVE"), Some("the hub's ledger verifies"))
    );

    exec(&hub, "DROP TRIGGER event_log_no_update; UPDATE event_log SET payload = '{\"x\":1}' WHERE seq = 1;");
    // Reused: no new full verify for organization B's calls.
    let row = ledger_row(&call(&reg, &hub, &b, "system_doctor", json!({})).await);
    assert_eq!(row["status"], "LIVE", "{row}");
    assert_eq!(b_anomaly(&call(&reg, &hub, &b, "check_anomalies", json!({})).await), None);

    // The default organization's doctor verifies in full and says where.
    let row = ledger_row(&call(&reg, &hub, &who, "system_doctor", json!({})).await);
    assert_eq!(row["status"], "DEGRADED", "{row}");
    assert!(row["detail"].as_str().unwrap().contains("seq 1"), "{row}");

    let report = call(&reg, &hub, &b, "system_doctor", json!({})).await;
    let row = ledger_row(&report);
    assert_eq!(
        (row["status"].as_str(), row["detail"].as_str()),
        (Some("DEGRADED"), Some("the hub's ledger is broken"))
    );
    let anomalies = call(&reg, &hub, &b, "check_anomalies", json!({})).await;
    let a = b_anomaly(&anomalies).expect("a ledger_chain anomaly");
    assert_eq!(a["detail"], "the hub's ledger is broken", "{a}");
    for text in [report.to_string(), anomalies.to_string()] {
        for hidden in ["seq", "entries", "hash chain", "entry_hash", "prev_hash", "kB", "RAM"] {
            assert!(!text.contains(hidden), "{hidden} in {text}");
        }
    }
}

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
    cfg.notify_webhook_url = Some(format!("https://hooks.example.com/services/{HOOK_PATH_SECRET}"));
    cfg.notify_webhook_secret = Some(SecretString::from(HOOK_HEADER_SECRET));
    cfg.approval_tools = vec!["event_log_verify".into()];
    std::fs::create_dir_all(cfg.workspace_root()).unwrap();
    let hub = Hub::open(cfg).unwrap();
    let reg = builtin_registry();
    let who = agent("reviewer-1", Profile::Cto);

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
            ["LIVE", "DORMANT", "DEGRADED", "MISCONFIGURED", "UNKNOWN"].contains(&c["status"].as_str().unwrap()),
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
    exec(
        &hub,
        "DROP TRIGGER event_log_no_update; UPDATE event_log SET payload = '{\"x\":1}' WHERE seq = 1;",
    );
    let report = call(&reg, &hub, &who, "system_doctor", json!({})).await;
    let row = report["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "ledger_chain").unwrap();
    assert_eq!(row["status"], "DEGRADED", "{row}");

    let anomalies = call(&reg, &hub, &who, "check_anomalies", json!({})).await;
    assert!(anomalies["anomalies"].as_array().unwrap().iter().any(|a| a["rule"] == "ledger_chain"));
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
    let who = agent("observer-1", Profile::Developer);
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
    assert!(events.iter().any(|e| e["ref_id"] == id.to_string() && e["summary"] == "agent.task.created"));
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
    let rules: Vec<&str> = anomalies["anomalies"].as_array().unwrap().iter().map(|a| a["rule"].as_str().unwrap()).collect();
    assert!(rules.contains(&"stale_doing_task"), "{rules:?}");
    assert!(rules.contains(&"approval_queue_age"), "{rules:?}");
    assert!(rules.contains(&"unverified_done"), "{rules:?}");

    let bad = reg.call(&hub, &who, "observability_manage", json!({ "action": "runs_in_flight" })).await.unwrap_err();
    assert_eq!(bad.code(), "invalid_argument");
    let bad = reg
        .call(&hub, &who, "observability_manage", json!({ "action": "activity", "params": { "bogus": 1 } }))
        .await
        .unwrap_err();
    assert_eq!(bad.code(), "invalid_argument");
}

#[tokio::test]
async fn cloud_assistant_reaches_only_its_actions() {
    let hub = mem_hub();
    let reg = builtin_registry();
    let cloud = agent("assistant-1", Profile::CloudAssistant);
    let list = call(&reg, &hub, &cloud, "observability_manage", json!({ "action": "agent_list" })).await;
    assert!(list["agents"].is_array());
    let ctx = call(&reg, &hub, &cloud, "observability_manage", json!({ "action": "agent_context" })).await;
    assert!(ctx.is_object());
    let err = reg.call(&hub, &cloud, "observability_manage", json!({ "action": "metrics" })).await.unwrap_err();
    assert_eq!(err.code(), "denied");
    // The legacy standalone tools are not on its surface.
    let err = reg.call(&hub, &cloud, "perf_summary", json!({})).await.unwrap_err();
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
        second["calls"]["top_tools_24h"].as_array().unwrap().iter().any(|t| t["tool"] == "mcp_health_telemetry")
    );

    // A narrower surface has a different callable fingerprint, same registry one.
    let research = agent("reader-1", Profile::Research);
    let narrow = reg.call(&hub, &research, "mcp_health_telemetry", json!({})).await;
    if let Ok(narrow) = narrow {
        assert_ne!(narrow["schema_fingerprint"], first["schema_fingerprint"]);
        assert_eq!(narrow["registry_schema_fingerprint"], first["registry_schema_fingerprint"]);
    }
}

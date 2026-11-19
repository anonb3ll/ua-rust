//! Remote nodes: registration, heartbeats, bounded facts, liveness and
//! operator retirement, all through the governed registry.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn config() -> Config {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.human_identities = vec!["operator".into()];
    cfg
}

fn hub_with(cfg: Config) -> Hub {
    Hub::in_memory(cfg).unwrap()
}

fn hub() -> Hub {
    hub_with(config())
}

fn caller(label: &str, kind: ActorKind) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: None,
        transport: Transport::Http,
    }
}

fn agent(label: &str) -> Caller {
    caller(label, ActorKind::Agent)
}

fn operator() -> Caller {
    caller("operator", ActorKind::Human)
}

async fn call(reg: &Registry, hub: &Hub, who: &Caller, tool: &str, args: Value) -> Value {
    reg.call(hub, who, tool, args).await.unwrap_or_else(|e| panic!("{tool} failed: {e}"))
}

async fn fail(reg: &Registry, hub: &Hub, who: &Caller, tool: &str, args: Value) -> UaError {
    match reg.call(hub, who, tool, args).await {
        Ok(v) => panic!("{tool} should have failed, got {v}"),
        Err(e) => e,
    }
}

fn reason_code(e: &UaError) -> &str {
    match e {
        UaError::Denied { reason_code, .. } => reason_code,
        other => panic!("expected a denial, got {other:?}"),
    }
}

async fn manage(
    reg: &Registry,
    hub: &Hub,
    who: &Caller,
    action: &str,
    params: Value,
) -> Result<Value, UaError> {
    reg.call(hub, who, "coordination_manage", json!({ "action": action, "params": params })).await
}

fn count_events(hub: &Hub, channel: &str) -> i64 {
    let channel = channel.to_string();
    hub.db()
        .read(move |c| {
            Ok(c.query_row("SELECT COUNT(*) FROM event_log WHERE channel = ?1", [&channel], |r| r.get(0))?)
        })
        .unwrap()
}

/// Set a node's stored heartbeat `secs` seconds ago (negative: in the future).
fn beat_at(hub: &Hub, node: &str, secs: i64) {
    let ts = ua_core::time::format_ts(
        jiff::Timestamp::now().checked_sub(jiff::SignedDuration::from_secs(secs)).unwrap(),
    );
    let node = node.to_string();
    hub.db()
        .write(move |tx| {
            tx.execute("UPDATE nodes SET last_heartbeat = ?2 WHERE node = ?1", rusqlite::params![node, ts])?;
            Ok(())
        })
        .unwrap();
}

async fn list(reg: &Registry, hub: &Hub) -> Value {
    call(reg, hub, &agent("viewer-1"), "node_list", json!({})).await
}

async fn listed(reg: &Registry, hub: &Hub, node: &str) -> Value {
    let all = list(reg, hub).await;
    all["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["node"] == node)
        .cloned()
        .unwrap_or_else(|| panic!("{node} not listed in {all}"))
}

fn facts() -> Value {
    json!({
        "os": { "system": "Linux", "release": "6.1", "machine": "x86_64", "python": "3.12", "kernel_cmdline": "x" },
        "backends": ["claude", "codex"],
        "harnesses": { "claude": { "bin": "claude", "path": "/usr/bin/claude", "version": "1.0", "env": "dropped" } },
        "worktree_roots": [{ "path": "/srv/work", "realpath": "/srv/work", "exists": true, "worktrees": 3 }],
        "repos": [{ "root": "/srv/work", "root_realpath": "/srv/work", "name": "app", "path": "/srv/work/app", "realpath": "/srv/work/app" }],
        "surfaces": { "hermes_profiles": ["default"], "kanban_assignees": [] },
        "node_features": ["acp_followups"],
        "code_sha": SHA,
    })
}

#[tokio::test]
async fn register_heartbeat_and_list() {
    let (hub, reg) = (hub(), builtin_registry());
    let me = agent("builder-1");

    let out = call(
        &reg,
        &hub,
        &me,
        "node_register",
        json!({ "node": "node-a", "facts": facts(), "version": "0.1.0" }),
    )
    .await;
    assert_eq!(out["node"], "node-a");
    assert_eq!(out["agent"], "builder-1", "the owner is the verified caller");
    assert_eq!(out["first_registration"], true);
    assert_eq!(out["hub_features"], json!(["node_code_sha"]));
    assert_eq!(out["dropped_fact_keys"], json!([]));
    assert_eq!(count_events(&hub, "agent.node.register"), 1);

    let row = listed(&reg, &hub, "node-a").await;
    assert_eq!(row["agent"], "builder-1");
    assert_eq!(row["status"], "live");
    assert_eq!(row["heartbeat_status"], "online");
    assert_eq!(row["live"], true);
    assert_eq!(row["version"], "0.1.0");
    assert_eq!(row["backends"], json!(["claude", "codex"]));
    assert_eq!(row["worktree_roots"], json!(["/srv/work"]), "roots are listed as paths");
    assert_eq!(row["code_sha"], SHA);
    assert_eq!(
        row["os"],
        json!({ "system": "Linux", "release": "6.1", "machine": "x86_64", "python": "3.12" })
    );
    assert!(row["harnesses"]["claude"].get("env").is_none(), "unknown harness fields are dropped");
    assert_eq!(row["repos"][0]["name"], "app");

    // Heartbeats move the row only: no ledger event.
    let beat = call(&reg, &hub, &me, "node_heartbeat", json!({ "node": "node-a", "running": null })).await;
    assert_eq!(beat["cancel"], json!([]));
    call(&reg, &hub, &me, "node_heartbeat", json!({ "node": "node-a" })).await;
    assert_eq!(count_events(&hub, "agent.node.register"), 1);
    assert_eq!(count_events(&hub, "agent.node.heartbeat"), 0);

    // A heartbeat of advisory keys refreshes them and keeps the rest.
    let refresh = json!({ "surfaces": { "hermes_profiles": ["default", "ops"] }, "code_sha": "not-a-sha" });
    call(&reg, &hub, &me, "node_heartbeat", json!({ "node": "node-a", "facts": refresh })).await;
    let row = listed(&reg, &hub, "node-a").await;
    assert_eq!(row["surfaces"]["hermes_profiles"], json!(["default", "ops"]));
    assert_eq!(row["backends"], json!(["claude", "codex"]), "registration facts are kept");
    assert_eq!(row["code_sha"], Value::Null, "a malformed code_sha clears the stored one");

    // Any other key is a full replacement.
    call(&reg, &hub, &me, "node_heartbeat", json!({ "node": "node-a", "facts": { "backends": ["codex"] } }))
        .await;
    let row = listed(&reg, &hub, "node-a").await;
    assert_eq!(row["backends"], json!(["codex"]));
    assert_eq!(row["worktree_roots"], json!([]));

    // Re-registering is idempotent and not a first registration.
    let again = call(&reg, &hub, &me, "node_register", json!({ "node": "node-a" })).await;
    assert_eq!(again["first_registration"], false);
    assert_eq!(list(&reg, &hub).await["counts"]["live"], 1);

    // An unregistered node's heartbeat says so (a node re-registers on it).
    let e = fail(&reg, &hub, &me, "node_heartbeat", json!({ "node": "node-z" })).await;
    assert!(matches!(&e, UaError::NotFound(m) if m.contains("not registered")), "{e:?}");
}

#[tokio::test]
async fn a_node_name_belongs_to_the_label_that_registered_it() {
    let (hub, reg) = (hub(), builtin_registry());
    call(&reg, &hub, &agent("builder-1"), "node_register", json!({ "node": "node-a" })).await;

    let other = agent("builder-2");
    let e = fail(&reg, &hub, &other, "node_register", json!({ "node": "node-a" })).await;
    assert_eq!(reason_code(&e), "node_owned_elsewhere");
    let e = fail(&reg, &hub, &other, "node_heartbeat", json!({ "node": "node-a" })).await;
    assert_eq!(reason_code(&e), "node_owned_elsewhere");
    assert_eq!(listed(&reg, &hub, "node-a").await["agent"], "builder-1");

    // The owner cannot be named in the request.
    let e =
        fail(&reg, &hub, &other, "node_register", json!({ "node": "node-b", "agent": "builder-1" })).await;
    assert!(matches!(e, UaError::InvalidArgument(_)), "{e:?}");
}

#[tokio::test]
async fn humans_and_unverified_callers_have_no_node() {
    let (hub, reg) = (hub(), builtin_registry());
    let e = fail(&reg, &hub, &operator(), "node_register", json!({ "node": "node-a" })).await;
    assert_eq!(reason_code(&e), "agent_identity_required");
    let local = Caller::local("local", Transport::Stdio);
    let e = fail(&reg, &hub, &local, "node_register", json!({ "node": "node-a" })).await;
    assert!(matches!(e, UaError::Unauthenticated(_)), "{e:?}");
    let e = fail(&reg, &hub, &local, "node_heartbeat", json!({ "node": "node-a" })).await;
    assert!(matches!(e, UaError::Unauthenticated(_)), "{e:?}");
    assert_eq!(list(&reg, &hub).await["nodes"], json!([]));
}

#[tokio::test]
async fn oversized_and_unknown_facts_are_bounded() {
    let (hub, reg) = (hub(), builtin_registry());
    let me = agent("builder-1");

    let huge = json!({ "blob": "x".repeat(70_000) });
    let e = fail(&reg, &hub, &me, "node_register", json!({ "node": "node-a", "facts": huge })).await;
    assert!(matches!(&e, UaError::InvalidArgument(m) if m.contains("64000")), "{e:?}");
    let e =
        fail(&reg, &hub, &me, "node_register", json!({ "node": "node-a", "facts": ["not", "an", "object"] }))
            .await;
    assert!(matches!(e, UaError::InvalidArgument(_)), "{e:?}");
    let e =
        fail(&reg, &hub, &me, "node_register", json!({ "node": "node-a", "version": "v".repeat(65) })).await;
    assert!(matches!(e, UaError::InvalidArgument(_)), "{e:?}");
    let e = fail(&reg, &hub, &me, "node_register", json!({ "node": "../etc" })).await;
    assert!(matches!(e, UaError::InvalidArgument(_)), "{e:?}");

    let sessions: Vec<Value> = (0..120)
        .map(|i| {
            json!({
                "harness": "claude",
                "external_session_id": format!("s-{i}"),
                "cwd_realpath": format!("/srv/work/app-{i}"),
                "title": format!("  a   long\ttitle {}", "t".repeat(150)),
                "transcript": "never stored",
            })
        })
        .chain([
            json!({ "harness": "claude", "external_session_id": "outside", "cwd_realpath": "/etc" }),
            json!({ "harness": "claude", "external_session_id": "escape", "cwd_realpath": "/srv/work/../etc" }),
        ])
        .collect();
    let repos: Vec<Value> = (0..100)
        .map(|i| json!({ "root": "/srv/work", "root_realpath": "/srv/work", "name": format!("r{i}"), "path": "/srv/work/r", "realpath": "/srv/work/r" }))
        .collect();
    let report = json!({
        "worktree_roots": [{ "path": "/srv/work", "realpath": "/srv/work" }],
        "native_sessions": sessions,
        "repos": repos,
        "backends": ["claude", "bad name", "x".repeat(65)],
        "node_features": ["ok", "y".repeat(41)],
        "harness_config": { "bundle_version": "v1", "in_sync": ["a"], "skill_surfaces": ["a", "b"], "skills": ["s1"] },
        "vault_sync": { "status": "BOGUS" },
        "secret_blob": "dropped",
    });
    let out = call(&reg, &hub, &me, "node_register", json!({ "node": "node-a", "facts": report })).await;
    assert_eq!(out["dropped_fact_keys"], json!(["secret_blob", "vault_sync"]));

    let row = listed(&reg, &hub, "node-a").await;
    let sessions = row["native_sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 50, "native sessions are capped");
    assert!(sessions.iter().all(|s| s.get("transcript").is_none()));
    assert!(sessions.iter().all(|s| s["cwd"].as_str().unwrap().starts_with("/srv/work/")));
    let title = sessions[0]["title"].as_str().unwrap();
    assert!(title.starts_with("a long title ") && title.chars().count() == 120, "{title:?}");
    assert_eq!(row["repos"].as_array().unwrap().len(), 64, "repos are capped");
    assert_eq!(row["backends"], json!(["claude"]));
    assert_eq!(row["node_features"], json!(["ok"]));
    assert_eq!(row["harness_config"]["skill_surfaces"], json!(["a"]), "a skill surface must be in sync");
    assert_eq!(row["vault_sync"], Value::Null);

    // Nothing unbounded reached the database.
    let stored: String = hub
        .db()
        .read(|c| Ok(c.query_row("SELECT facts_json FROM nodes WHERE node = 'node-a'", [], |r| r.get(0))?))
        .unwrap();
    assert!(stored.len() <= 64_000);
    assert!(!stored.contains("secret_blob") && !stored.contains("never stored"));
}

#[tokio::test]
async fn liveness_is_derived_from_the_heartbeat_age() {
    let (hub, reg) = (hub(), builtin_registry());
    call(&reg, &hub, &agent("builder-1"), "node_register", json!({ "node": "node-a" })).await;
    for (age, status, graded) in [
        (60, "live", "online"),
        (200, "stale", "idle"),
        (7_200, "stale", "stale"),
        (2 * 86_400, "offline", "offline"),
        (-30, "live", "online"),
        (-600, "offline", "offline"),
    ] {
        beat_at(&hub, "node-a", age);
        let row = listed(&reg, &hub, "node-a").await;
        assert_eq!(
            (row["status"].as_str(), row["heartbeat_status"].as_str()),
            (Some(status), Some(graded)),
            "age {age}"
        );
        assert_eq!(row["live"], status == "live", "age {age}");
    }
}

#[tokio::test]
async fn only_lifecycle_operators_retire_nodes() {
    let (hub, reg) = (hub(), builtin_registry());
    let owner = agent("builder-1");
    call(&reg, &hub, &owner, "node_register", json!({ "node": "node-a" })).await;
    let params = json!({ "node": "node-a", "reason": "replaced by node-b" });

    let e = manage(&reg, &hub, &owner, "node_retire", params.clone()).await.unwrap_err();
    assert_eq!(reason_code(&e), "not_lifecycle_operator", "the node's own agent is not enough");
    let local = Caller::local("operator", Transport::Stdio);
    let e = manage(&reg, &hub, &local, "node_retire", params.clone()).await.unwrap_err();
    assert_eq!(reason_code(&e), "identity_required", "an unverified caller cannot claim the operator label");
    let e = manage(&reg, &hub, &operator(), "node_retire", json!({ "node": "node-a", "reason": "  " }))
        .await
        .unwrap_err();
    assert!(matches!(&e, UaError::InvalidArgument(m) if m.contains("reason")), "{e:?}");
    let e = manage(&reg, &hub, &operator(), "node_retire", json!({ "node": "node-q", "reason": "x" }))
        .await
        .unwrap_err();
    assert!(matches!(e, UaError::NotFound(_)), "{e:?}");
    assert_eq!(count_events(&hub, "agent.node.retire"), 0);

    // A configured operator list replaces the human default.
    let mut cfg = config();
    cfg.lifecycle_operators = Some(vec!["ops-bot".into()]);
    let hub = hub_with(cfg);
    call(&reg, &hub, &owner, "node_register", json!({ "node": "node-a" })).await;
    let e = manage(&reg, &hub, &operator(), "node_retire", params.clone()).await.unwrap_err();
    assert_eq!(reason_code(&e), "not_lifecycle_operator");
    let out = manage(&reg, &hub, &agent("ops-bot"), "node_retire", params).await.unwrap();
    assert_eq!(out["retired_by"], "ops-bot");
}

#[tokio::test]
async fn retire_and_unretire() {
    let (hub, reg) = (hub(), builtin_registry());
    let owner = agent("builder-1");
    call(&reg, &hub, &owner, "node_register", json!({ "node": "node-a" })).await;
    call(&reg, &hub, &owner, "node_register", json!({ "node": "node-b" })).await;
    beat_at(&hub, "node-a", 30);

    let out = manage(
        &reg,
        &hub,
        &operator(),
        "node_retire",
        json!({ "node": "node-a", "reason": "renamed  host" }),
    )
    .await
    .unwrap();
    assert_eq!(out["changed"], true);
    assert_eq!(out["retired_by"], "operator");
    assert_eq!(out["retired_reason"], "renamed host", "whitespace is collapsed");
    assert!(out["event_ulid"].is_string());
    assert_eq!(count_events(&hub, "agent.node.retire"), 1);

    // A repeat changes nothing and writes nothing.
    let again =
        manage(&reg, &hub, &operator(), "node_retire", json!({ "node": "node-a", "reason": "again" }))
            .await
            .unwrap();
    assert_eq!(again["changed"], false);
    assert_eq!(again["retired_reason"], "renamed host");
    assert_eq!(count_events(&hub, "agent.node.retire"), 1);

    // Out of the listing, named in retired_nodes.
    let all = list(&reg, &hub).await;
    assert!(all["nodes"].as_array().unwrap().iter().all(|n| n["node"] != "node-a"));
    assert_eq!(all["retired_nodes"][0]["node"], "node-a");
    assert_eq!(all["retired_nodes"][0]["retired_by"], "operator");

    // The owner is refused with node_retired; another label learns nothing.
    let e = fail(&reg, &hub, &owner, "node_heartbeat", json!({ "node": "node-a" })).await;
    assert_eq!(reason_code(&e), "node_retired");
    let e = fail(&reg, &hub, &owner, "node_register", json!({ "node": "node-a" })).await;
    assert_eq!(reason_code(&e), "node_retired");
    let e = fail(&reg, &hub, &agent("builder-2"), "node_heartbeat", json!({ "node": "node-a" })).await;
    assert_eq!(reason_code(&e), "node_owned_elsewhere");

    // Un-retire: back in the listing, but the pre-retirement beat is fenced.
    let out = manage(&reg, &hub, &operator(), "node_unretire", json!({ "node": "node-a", "reason": "back" }))
        .await
        .unwrap();
    assert_eq!(out["changed"], true);
    assert_eq!(out["retired_at"], Value::Null);
    assert_eq!(count_events(&hub, "agent.node.unretire"), 1);
    let row = listed(&reg, &hub, "node-a").await;
    assert_eq!(row["status"], "offline", "the stored beat predates the retirement");
    assert_eq!(row["live_heartbeat"], Value::Null);
    assert!(row["last_heartbeat"].is_string(), "the last-seen history is kept");
    let noop = manage(&reg, &hub, &operator(), "node_unretire", json!({ "node": "node-a", "reason": "x" }))
        .await
        .unwrap();
    assert_eq!(noop["changed"], false);

    // A fresh heartbeat makes it live again.
    call(&reg, &hub, &owner, "node_heartbeat", json!({ "node": "node-a" })).await;
    assert_eq!(listed(&reg, &hub, "node-a").await["status"], "live");
}

fn doctor_row(report: &Value) -> Value {
    report["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "fleet_nodes").cloned().unwrap()
}

#[tokio::test]
async fn doctor_reports_the_fleet() {
    let (hub, reg) = (hub(), builtin_registry());
    let who = agent("reviewer-1");
    let row = doctor_row(&call(&reg, &hub, &who, "system_doctor", json!({})).await);
    assert_eq!(row["status"], "DORMANT", "{row}");

    let owner = agent("builder-1");
    call(&reg, &hub, &owner, "node_register", json!({ "node": "node-a" })).await;
    call(&reg, &hub, &owner, "node_register", json!({ "node": "node-b" })).await;
    let row = doctor_row(&call(&reg, &hub, &who, "system_doctor", json!({})).await);
    assert_eq!(row["status"], "LIVE", "{row}");

    beat_at(&hub, "node-b", 3_600);
    let row = doctor_row(&call(&reg, &hub, &who, "system_doctor", json!({})).await);
    assert_eq!(row["status"], "DEGRADED", "{row}");
    let detail = row["detail"].as_str().unwrap();
    assert!(
        detail.contains("node-b stale (last heartbeat 60m ago)") && detail.contains("live: node-a"),
        "{detail}"
    );

    // A retired node is not a host: it is named once and does not degrade.
    manage(&reg, &hub, &operator(), "node_retire", json!({ "node": "node-b", "reason": "gone" }))
        .await
        .unwrap();
    let row = doctor_row(&call(&reg, &hub, &who, "system_doctor", json!({})).await);
    assert_eq!(row["status"], "LIVE", "{row}");
    assert_eq!(row["retired"], json!(["node-b"]));
}

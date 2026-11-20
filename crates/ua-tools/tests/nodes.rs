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

fn last_payload(hub: &Hub, channel: &str) -> Value {
    let channel = channel.to_string();
    hub.db()
        .read(move |c| {
            let text: String = c.query_row(
                "SELECT payload FROM event_log WHERE channel = ?1 ORDER BY seq DESC LIMIT 1",
                [&channel],
                |r| r.get(0),
            )?;
            Ok(serde_json::from_str(&text).unwrap())
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

/// The listing as a lifecycle operator sees it: full facts for every node.
async fn list(reg: &Registry, hub: &Hub) -> Value {
    call(reg, hub, &operator(), "node_list", json!({})).await
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
        "surfaces": { "profiles": ["default"], "assignees": [], "Bad-Key": ["x"], "queues": "not-a-list" },
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
    assert_eq!(
        out["hub_features"],
        json!(["node_code_sha", "acp_session_mcp", "node_wake_v3", "node_wake_live_sessions"])
    );
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
    assert_eq!(
        row["surfaces"],
        json!({ "profiles": ["default"], "assignees": [] }),
        "a bad surface key or a non-list value is dropped"
    );

    // Heartbeats move the row only: no ledger event.
    let beat = call(&reg, &hub, &me, "node_heartbeat", json!({ "node": "node-a", "running": null })).await;
    assert_eq!(beat["cancel"], json!([]));
    call(&reg, &hub, &me, "node_heartbeat", json!({ "node": "node-a" })).await;
    assert_eq!(count_events(&hub, "agent.node.register"), 1);
    assert_eq!(count_events(&hub, "agent.node.heartbeat"), 0);

    // A heartbeat of advisory keys refreshes them and keeps the rest.
    let refresh = json!({ "surfaces": { "profiles": ["default", "ops"] }, "code_sha": "not-a-sha" });
    call(&reg, &hub, &me, "node_heartbeat", json!({ "node": "node-a", "facts": refresh })).await;
    let row = listed(&reg, &hub, "node-a").await;
    assert_eq!(row["surfaces"], json!({ "profiles": ["default", "ops"] }));
    assert_eq!(row["backends"], json!(["claude", "codex"]), "registration facts are kept");
    assert_eq!(row["code_sha"], Value::Null, "a malformed code_sha clears the stored one");

    // Host facts cannot ride a heartbeat: they are dropped and reported, and
    // the beat still counts.
    let beat =
        json!({ "node": "node-a", "facts": { "backends": ["codex"], "worktree_roots": [], "surfaces": {} } });
    let out = call(&reg, &hub, &me, "node_heartbeat", beat).await;
    assert_eq!(out["dropped_fact_keys"], json!(["backends", "worktree_roots"]));
    let row = listed(&reg, &hub, "node-a").await;
    assert_eq!(row["backends"], json!(["claude", "codex"]));
    assert_eq!(row["worktree_roots"], json!(["/srv/work"]));
    assert_eq!(row["surfaces"], json!({}), "the advisory key was applied");
    assert_eq!(count_events(&hub, "agent.node.register"), 1);

    // An identical re-registration (a node restart) is not ledgered.
    let args = json!({ "node": "node-a", "facts": facts(), "version": "0.1.0" });
    let again = call(&reg, &hub, &me, "node_register", args).await;
    assert_eq!(again["first_registration"], false);
    assert_eq!((again["ledgered"].clone(), again["changed"].clone()), (json!(false), json!([])));
    assert_eq!(count_events(&hub, "agent.node.register"), 1);

    // A real change is, naming what changed, with no paths in the event.
    let mut moved = facts();
    moved["worktree_roots"] = json!([{ "path": "/srv/other", "realpath": "/srv/other" }]);
    let args = json!({ "node": "node-a", "facts": moved, "version": "0.2.0" });
    let out = call(&reg, &hub, &me, "node_register", args).await;
    assert_eq!(out["changed"], json!(["version", "worktree_roots"]));
    assert_eq!(count_events(&hub, "agent.node.register"), 2);
    let payload = last_payload(&hub, "agent.node.register");
    assert_eq!(payload["worktree_roots"], 1, "roots are counted, not listed");
    assert!(!payload.to_string().contains("/srv/"), "{payload}");
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

#[tokio::test]
async fn an_agent_holds_a_bounded_number_of_nodes() {
    let mut cfg = config();
    cfg.node_max_per_agent = 2;
    let (hub, reg) = (hub_with(cfg), builtin_registry());
    let me = agent("builder-1");
    call(&reg, &hub, &me, "node_register", json!({ "node": "node-a" })).await;
    call(&reg, &hub, &me, "node_register", json!({ "node": "node-b" })).await;
    let e = fail(&reg, &hub, &me, "node_register", json!({ "node": "node-c" })).await;
    assert_eq!(reason_code(&e), "node_limit");
    // Re-registering a node it already holds is not a new one.
    call(&reg, &hub, &me, "node_register", json!({ "node": "node-a", "version": "2" })).await;
    // Another agent has its own allowance.
    call(&reg, &hub, &agent("builder-2"), "node_register", json!({ "node": "node-c" })).await;
    // A retired node no longer counts.
    manage(&reg, &hub, &operator(), "node_retire", json!({ "node": "node-b", "reason": "gone" }))
        .await
        .unwrap();
    call(&reg, &hub, &me, "node_register", json!({ "node": "node-d" })).await;
}

#[tokio::test]
async fn operators_reassign_and_forget_node_names() {
    let (hub, reg) = (hub(), builtin_registry());
    let old = agent("builder-1");
    let new = agent("builder-1b");
    call(&reg, &hub, &old, "node_register", json!({ "node": "node-a" })).await;

    let params = json!({ "node": "node-a", "to_agent": "builder-1b", "reason": "label renamed" });
    let e = manage(&reg, &hub, &old, "node_reassign", params.clone()).await.unwrap_err();
    assert_eq!(reason_code(&e), "not_lifecycle_operator");
    let bad = json!({ "node": "node-a", "to_agent": "not a label", "reason": "x" });
    let e = manage(&reg, &hub, &operator(), "node_reassign", bad).await.unwrap_err();
    assert!(matches!(e, UaError::InvalidArgument(_)), "{e:?}");

    let out = manage(&reg, &hub, &operator(), "node_reassign", params.clone()).await.unwrap();
    assert_eq!((out["changed"].clone(), out["previous_agent"].clone()), (json!(true), json!("builder-1")));
    assert_eq!(count_events(&hub, "agent.node.reassign"), 1);
    let again = manage(&reg, &hub, &operator(), "node_reassign", params).await.unwrap();
    assert_eq!(again["changed"], false);
    assert_eq!(count_events(&hub, "agent.node.reassign"), 1);

    // The old label lost it; the new owner's node is fenced until it beats.
    let e = fail(&reg, &hub, &old, "node_heartbeat", json!({ "node": "node-a" })).await;
    assert_eq!(reason_code(&e), "node_owned_elsewhere");
    let row = listed(&reg, &hub, "node-a").await;
    assert_eq!((row["agent"].as_str(), row["status"].as_str()), (Some("builder-1b"), Some("offline")));
    call(&reg, &hub, &new, "node_register", json!({ "node": "node-a" })).await;
    assert_eq!(listed(&reg, &hub, "node-a").await["status"], "live");

    // Forget: operators only, and only a retired node.
    let forget = json!({ "node": "node-a", "reason": "host decommissioned" });
    let e = manage(&reg, &hub, &new, "node_forget", forget.clone()).await.unwrap_err();
    assert_eq!(reason_code(&e), "not_lifecycle_operator");
    let e = manage(&reg, &hub, &operator(), "node_forget", forget.clone()).await.unwrap_err();
    assert!(matches!(e, UaError::Conflict(_)), "a node in service is retired first: {e:?}");
    manage(&reg, &hub, &operator(), "node_retire", forget.clone()).await.unwrap();
    let out = manage(&reg, &hub, &operator(), "node_forget", forget.clone()).await.unwrap();
    assert_eq!(out["forgotten"], true);
    assert_eq!(count_events(&hub, "agent.node.forget"), 1);
    let e = manage(&reg, &hub, &operator(), "node_forget", forget).await.unwrap_err();
    assert!(matches!(e, UaError::NotFound(_)), "{e:?}");

    // The name is free again, for any label.
    let out = call(&reg, &hub, &old, "node_register", json!({ "node": "node-a" })).await;
    assert_eq!(out["first_registration"], true);
}

#[tokio::test]
async fn other_viewers_see_a_summary() {
    let (hub, reg) = (hub(), builtin_registry());
    call(&reg, &hub, &agent("builder-1"), "node_register", json!({ "node": "node-a", "facts": facts() }))
        .await;
    let session = json!({ "harness": "claude", "external_session_id": "s1", "cwd_realpath": "/srv/work/app", "title": "secret plan" });
    let beat = json!({ "node": "node-a", "facts": { "native_sessions": [session] } });
    call(&reg, &hub, &agent("builder-1"), "node_heartbeat", beat).await;

    let rows = |v: Value| v["nodes"][0].clone();
    let owner = rows(call(&reg, &hub, &agent("builder-1"), "node_list", json!({})).await);
    assert_eq!(owner["detail"], "full");
    assert_eq!(owner["native_sessions"][0]["title"], "secret plan");
    assert_eq!(rows(list(&reg, &hub).await)["detail"], "full", "lifecycle operators see full facts");

    for viewer in [agent("builder-2"), Caller::local("local", Transport::Stdio)] {
        let row = rows(call(&reg, &hub, &viewer, "node_list", json!({})).await);
        assert_eq!(row["detail"], "summary");
        assert_eq!((row["node"].as_str(), row["agent"].as_str()), (Some("node-a"), Some("builder-1")));
        assert_eq!((row["status"].as_str(), row["live"].as_bool()), (Some("live"), Some(true)));
        assert_eq!(row["backends"], json!(["claude", "codex"]));
        assert_eq!(row["harness_names"], json!(["claude"]));
        let text = row.to_string();
        for leak in ["/srv/work", "/usr/bin/claude", "secret plan", "repos", "worktree_roots"] {
            assert!(!text.contains(leak), "{leak} leaked to {}: {text}", viewer.label);
        }
    }
}

#[tokio::test]
async fn surfaces_are_a_bounded_map() {
    let (hub, reg) = (hub(), builtin_registry());
    let me = agent("builder-1");
    let mut surfaces = serde_json::Map::new();
    for i in 0..20 {
        surfaces.insert(format!("k{i:02}"), json!([format!("n{i}")]));
    }
    surfaces.insert("a".repeat(41), json!(["too-long-key"]));
    let names: Vec<String> = (0..60).map(|i| format!("name-{i}")).collect();
    surfaces.insert("k00".into(), json!(names));
    surfaces.insert("k01".into(), json!(["ok", "x".repeat(65), 7]));
    call(&reg, &hub, &me, "node_register", json!({ "node": "node-s", "facts": { "surfaces": surfaces } }))
        .await;
    let row = listed(&reg, &hub, "node-s").await;
    let got = row["surfaces"].as_object().unwrap();
    assert_eq!(got.len(), 16, "at most 16 keys");
    assert!(got.keys().all(|k| k.len() <= 40));
    assert_eq!(got["k00"].as_array().unwrap().len(), 50, "at most 50 names per key");
    assert_eq!(got["k01"], json!(["ok"]), "long or non-string names are skipped");
}

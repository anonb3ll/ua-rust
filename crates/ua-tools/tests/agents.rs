//! Agent registry, sessions and lifecycle capture.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

fn hub() -> Hub {
    Hub::in_memory(Config::for_home(std::env::temp_dir())).unwrap()
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

fn exec(hub: &Hub, sql: &str, arg: &str) {
    let (sql, arg) = (sql.to_string(), arg.to_string());
    hub.db()
        .write(move |tx| {
            tx.execute(&sql, [&arg])?;
            Ok(())
        })
        .unwrap();
}

fn count_events(hub: &Hub, channel: &str) -> i64 {
    let channel = channel.to_string();
    hub.db()
        .read(move |c| {
            Ok(c.query_row("SELECT COUNT(*) FROM event_log WHERE channel = ?1", [&channel], |r| r.get(0))?)
        })
        .unwrap()
}

fn find<'a>(list: &'a Value, key: &str, label: &str) -> &'a Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|a| a[key] == label)
        .unwrap_or_else(|| panic!("{label} not in {list}"))
}

#[tokio::test]
async fn heartbeat_and_liveness() {
    let (hub, reg) = (hub(), builtin_registry());
    let a = agent("builder-1");

    let beat = call(
        &reg,
        &hub,
        &a,
        "agent_heartbeat",
        json!({"agent": "someone-else", "kind": "cli", "host": "box-1"}),
    )
    .await;
    assert_eq!(beat["agent"], "builder-1", "the verified label wins");
    assert_eq!(beat["status"], "online");
    assert_eq!(beat["known"], true);
    assert_eq!(beat["host_recorded"], true);
    assert_eq!(count_events(&hub, "agent.agent.registered"), 1);
    call(&reg, &hub, &a, "agent_heartbeat", json!({})).await;
    assert_eq!(count_events(&hub, "agent.agent.registered"), 1, "only the first sighting is ledgered");

    // An unverified local caller may name the label it beats for.
    let local = Caller::local("local-agent", Transport::Stdio);
    let beat = call(&reg, &hub, &local, "agent_heartbeat", json!({"agent": "builder-2"})).await;
    assert_eq!(beat["agent"], "builder-2");
    assert_eq!(beat["known"], false);

    // Status is derived from last_seen at read time.
    exec(&hub, "UPDATE agents SET last_seen = '2000-01-01T00:00:00+00:00' WHERE label = ?1", "builder-2");
    let listed = call(&reg, &hub, &a, "agent_list", json!({})).await;
    let one = find(&listed["agents"], "label", "builder-1");
    assert_eq!(one["status"], "online");
    assert_eq!(one["kind"], "cli");
    assert_eq!(one["host"], "box-1");
    assert_eq!(find(&listed["agents"], "label", "builder-2")["status"], "offline");
    assert_eq!(listed["counts"]["online"], 1);
    assert_eq!(listed["counts"]["offline"], 1);

    let err = reg.call(&hub, &a, "agent_heartbeat", json!({"bogus": 1})).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
}

#[tokio::test]
async fn session_start_is_idempotent() {
    let (hub, reg) = (hub(), builtin_registry());
    let a = agent("builder-1");

    let first = call(
        &reg,
        &hub,
        &a,
        "session_start",
        json!({"kind": "interactive", "external_session_id": "ext-1", "host": "box-1", "meta": {"client": "cli"}}),
    )
    .await;
    assert_eq!(first["created"], true);
    assert_eq!(first["agent"], "builder-1");
    assert_eq!(first["live"], true);
    let sid = first["session_id"].as_str().unwrap().to_string();

    let again = call(
        &reg,
        &hub,
        &a,
        "session_start",
        json!({"kind": "interactive", "external_session_id": "ext-1", "branch": "feature-x"}),
    )
    .await;
    assert_eq!(again["session_id"], sid);
    assert_eq!(again["created"], false);
    assert_eq!(again["reopened"], false);
    assert_eq!(again["host"], "box-1", "a refresh keeps the stored host");
    assert_eq!(count_events(&hub, "agent.session.started"), 1);

    // Without an external id every call opens a new row.
    let other = call(&reg, &hub, &a, "session_start", json!({"kind": "executor"})).await;
    assert_ne!(other["session_id"], sid);
    assert_eq!(other["host"], "box-1", "a new session takes the host the label last used");

    // Ending and registering again reopens the same row.
    let ended =
        call(&reg, &hub, &a, "session_end", json!({"session_id": sid, "summary": "done for now"})).await;
    assert_eq!(ended["status"], "completed");
    let reopened =
        call(&reg, &hub, &a, "session_start", json!({"kind": "interactive", "external_session_id": "ext-1"}))
            .await;
    assert_eq!(reopened["session_id"], sid);
    assert_eq!(reopened["reopened"], true);
    assert_eq!(reopened["status"], "running");
    assert_eq!(count_events(&hub, "agent.session.reopened"), 1);

    // Another agent with the same external id gets its own session.
    let b = call(
        &reg,
        &hub,
        &agent("builder-2"),
        "session_start",
        json!({"kind": "interactive", "external_session_id": "ext-1"}),
    )
    .await;
    assert_ne!(b["session_id"], sid);

    // Identity rules.
    let err = reg
        .call(&hub, &a, "session_start", json!({"kind": "interactive", "agent": "builder-2"}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "denied");
    let err =
        reg.call(&hub, &agent("builder-2"), "session_end", json!({"session_id": sid})).await.unwrap_err();
    assert_eq!(err.code(), "denied");
    let err = reg.call(&hub, &a, "session_end", json!({"session_id": "missing"})).await.unwrap_err();
    assert_eq!(err.code(), "not_found");
    let err = reg
        .call(&hub, &a, "session_start", json!({"kind": "interactive", "task_id": 999}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "not_found");
    let err =
        reg.call(&hub, &a, "session_end", json!({"session_id": sid, "status": "weird"})).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");

    // Packets are not available; the result says so instead of failing.
    let packet =
        call(&reg, &hub, &a, "session_start", json!({"kind": "interactive", "include_packet": true})).await;
    assert!(packet["packet"].is_null());
    assert!(packet["packet_unavailable"].is_string());
}

#[tokio::test]
async fn session_list_liveness_and_reaping() {
    let (hub, reg) = (hub(), builtin_registry());
    let a = agent("builder-1");
    let start = |ext: &str| {
        let (reg, hub, a, ext) = (&reg, &hub, &a, ext.to_string());
        async move {
            call(reg, hub, a, "session_start", json!({"kind": "interactive", "external_session_id": ext}))
                .await["session_id"]
                .as_str()
                .unwrap()
                .to_string()
        }
    };
    let fresh = start("fresh").await;
    let quiet = start("quiet").await;
    let dead = start("dead").await;
    // 10 minutes old: still live. Two hours old: reaped to abandoned on the next read.
    let ago = |mins: i64| {
        let t = jiff::Timestamp::now() - jiff::SignedDuration::from_mins(mins);
        ua_core::time::format_ts(t)
    };
    hub.db()
        .write(|tx| {
            tx.execute(
                "UPDATE agent_sessions SET last_heartbeat_at = ?1 WHERE id = ?2",
                [ago(10), quiet.clone()],
            )?;
            tx.execute(
                "UPDATE agent_sessions SET last_heartbeat_at = ?1 WHERE id = ?2",
                [ago(120), dead.clone()],
            )?;
            Ok(())
        })
        .unwrap();

    let all = call(&reg, &hub, &a, "session_list", json!({})).await;
    assert_eq!(all["total"], 3);
    assert_eq!(all["open"], 2);
    assert_eq!(all["live"], 2);
    assert_eq!(find(&all["sessions"], "id", &dead)["status"], "abandoned");
    assert_eq!(find(&all["sessions"], "id", &dead)["live"], false);
    assert_eq!(
        find(&all["sessions"], "id", &fresh)["last_seen_at"],
        find(&all["sessions"], "id", &fresh)["last_heartbeat_at"]
    );
    assert_eq!(count_events(&hub, "agent.session.reaped"), 1);

    let live = call(&reg, &hub, &a, "session_list", json!({"live_only": true})).await;
    assert_eq!(live["total"], 2);
    assert!(live["sessions"].as_array().unwrap().iter().all(|s| s["live"] == true));
    let abandoned = call(&reg, &hub, &a, "session_list", json!({"status": "abandoned"})).await;
    assert_eq!(abandoned["total"], 1);
    let err = reg.call(&hub, &a, "session_list", json!({"status": "sleeping"})).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");

    // A reaped session comes back when its harness registers again.
    let back =
        call(&reg, &hub, &a, "session_start", json!({"kind": "interactive", "external_session_id": "dead"}))
            .await;
    assert_eq!(back["session_id"], dead);
    assert_eq!(back["reopened"], true);

    // agent_context lists peers with their live sessions.
    call(&reg, &hub, &agent("builder-2"), "agent_heartbeat", json!({})).await;
    let ctx = call(&reg, &hub, &agent("builder-2"), "agent_context", json!({})).await;
    assert_eq!(ctx["identity"], "builder-2");
    assert_eq!(ctx["profile"], "developer");
    assert_eq!(ctx["session_live_minutes"], 30);
    let peer = find(&ctx["peers"], "label", "builder-1");
    let sessions = peer["live_sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 3);
    assert!(sessions.iter().all(|s| s["agent"] == "builder-1" && s["session_id"].is_string()));
    assert!(find(&ctx["peers"], "label", "builder-2")["live_sessions"].as_array().unwrap().is_empty());
    let listed = call(&reg, &hub, &a, "agent_list", json!({})).await;
    assert_eq!(find(&listed["agents"], "label", "builder-1")["open_sessions"], 3);
}

#[tokio::test]
async fn lifecycle_record_capture() {
    let (hub, reg) = (hub(), builtin_registry());
    let a = agent("builder-1");

    let args = json!({
        "kind": "handoff", "task_id": 42, "idempotency_key": "task-42-handoff-1", "agent": "ignored",
        "payload": {"note": "ready", "prompt": "secret prompt", "nested": {"API_KEY": "x", "keep": 1},
                    "list": [{"token": "t", "ok": true}]},
    });
    let first = call(&reg, &hub, &a, "lifecycle_record", args.clone()).await;
    assert_eq!(first["accepted"], true);
    assert_eq!(first["duplicate"], false);
    assert_eq!(first["kind"], "handoff");
    let second = call(&reg, &hub, &a, "lifecycle_record", args).await;
    assert_eq!(second["duplicate"], true);
    assert_eq!(second["event_id"], first["event_id"]);
    assert_eq!(count_events(&hub, "agent.lifecycle.handoff"), 1);

    let events =
        call(&reg, &hub, &a, "event_log_query", json!({"channels": ["agent.lifecycle.handoff"]})).await;
    let event = &events["events"][0];
    assert_eq!(event["originator"], "builder-1");
    let payload = &event["payload"]["payload"];
    assert_eq!(payload, &json!({"note": "ready", "nested": {"keep": 1}, "list": [{"ok": true}]}));

    // The same client key under another session is a separate observation.
    let other = call(
        &reg,
        &hub,
        &a,
        "lifecycle_record",
        json!({"kind": "handoff", "session_id": "s-2", "idempotency_key": "task-42-handoff-1"}),
    )
    .await;
    assert_eq!(other["duplicate"], false);

    let unknown = call(&reg, &hub, &a, "lifecycle_record", json!({"kind": "dream"})).await;
    assert_eq!(unknown, json!({"accepted": false, "reason": "unknown_kind"}));
    let excluded =
        call(&reg, &hub, &a, "lifecycle_record", json!({"kind": "tool_start", "tool": "gemini_ask"})).await;
    assert_eq!(excluded["reason"], "excluded");
    let no_key = call(&reg, &hub, &a, "lifecycle_record", json!({"kind": "stop"})).await;
    let no_key_again = call(&reg, &hub, &a, "lifecycle_record", json!({"kind": "stop"})).await;
    assert_ne!(no_key["event_id"], no_key_again["event_id"]);
}

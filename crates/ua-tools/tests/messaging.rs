//! Messaging: send, list, threads, inbox, ack and session addressing.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaResult, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

fn hub() -> Hub {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.human_identities = vec!["operator".into()];
    Hub::in_memory(cfg).unwrap()
}

fn agent(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some(format!("{label}-key")),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

async fn call(reg: &Registry, hub: &Hub, who: &Caller, tool: &str, args: Value) -> Value {
    reg.call(hub, who, tool, args).await.unwrap_or_else(|e| panic!("{tool} failed: {e}"))
}

async fn send(reg: &Registry, hub: &Hub, from: &Caller, args: Value) -> Value {
    call(reg, hub, from, "message_send", args).await
}

async fn coord(reg: &Registry, hub: &Hub, who: &Caller, action: &str, params: Value) -> UaResult<Value> {
    reg.call(hub, who, "coordination_manage", json!({ "action": action, "params": params })).await
}

fn events(hub: &Hub, channel_prefix: &str) -> i64 {
    let prefix = channel_prefix.to_string();
    hub.db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM event_log WHERE substr(channel, 1, length(?1)) = ?1",
                [&prefix],
                |r| r.get(0),
            )?)
        })
        .unwrap()
}

#[tokio::test]
async fn send_list_and_reply_thread() {
    let (hub, reg) = (hub(), builtin_registry());
    let (a, b, c) = (agent("builder-1"), agent("builder-2"), agent("builder-3"));

    let sent = send(
        &reg,
        &hub,
        &a,
        json!({"act": "request", "to_agent": "builder-2", "body": "please review", "expects_reply": true,
               "message_id": "m-1", "task_id": 7, "from_agent": "spoofed-label"}),
    )
    .await;
    assert_eq!(sent["accepted"], true);
    assert_eq!(sent["duplicate"], false);
    assert_eq!(sent["from_agent"], "builder-1", "a verified sender cannot be spoofed");
    assert_eq!(sent["to_agent"], "builder-2");
    assert_eq!(sent["hop"], 0);
    assert_eq!(sent["availability"]["availability"], "unknown");
    let conversation = sent["conversation_id"].as_str().unwrap().to_string();

    // A retry with the same id returns the saved result and writes nothing.
    let again = send(
        &reg,
        &hub,
        &a,
        json!({"act": "request", "to_agent": "builder-2", "body": "please review", "message_id": "m-1"}),
    )
    .await;
    assert_eq!(again["duplicate"], true);
    assert_eq!(again["event_ulid"], sent["event_ulid"]);
    assert_eq!(events(&hub, "agent.message."), 1);
    // Another sender cannot reuse the id.
    let taken = reg
        .call(
            &hub,
            &c,
            "message_send",
            json!({"act": "inform", "to_agent": "builder-2", "body": "x", "message_id": "m-1"}),
        )
        .await
        .unwrap_err();
    assert_eq!(taken.code(), "conflict");

    // The recipient sees it, marked untrusted.
    let inbox = call(&reg, &hub, &b, "message_list", json!({"unread_only": true})).await;
    assert_eq!(inbox["total"], 1);
    assert_eq!(inbox["unread"], 1);
    let row = &inbox["messages"][0];
    assert_eq!(row["body"], "please review");
    assert_eq!(row["status"], "delivered");
    assert_eq!(row["task_id"], 7);
    assert_eq!(row["trust"]["level"], "untrusted");
    assert_eq!(row["trust"]["author"], "builder-1");
    // The sender's own copy is not marked.
    let mine = call(&reg, &hub, &a, "message_list", json!({})).await;
    assert!(mine["messages"][0].get("trust").is_none());

    // A third agent cannot read builder-2's mailbox or reply into the thread.
    let err = reg.call(&hub, &c, "message_list", json!({"to_agent": "builder-2"})).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let err = reg
        .call(
            &hub,
            &c,
            "message_send",
            json!({"act": "inform", "to_agent": "builder-1", "body": "hi", "reply_to": "m-1"}),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not a message you sent or received"), "{err}");

    let waiting = call(&reg, &hub, &a, "message_list", json!({"waiting_on_reply": true})).await;
    assert_eq!(waiting["total"], 1);

    // A reply with no address answers the parent's sender in the same conversation.
    let reply = send(&reg, &hub, &b, json!({"act": "done", "body": "looks good", "reply_to": "m-1"})).await;
    assert_eq!(reply["to_agent"], "builder-1");
    assert_eq!(reply["conversation_id"], conversation);
    assert_eq!(reply["hop"], 1);
    assert_eq!(reply["reply_to"], "m-1");

    let waiting = call(&reg, &hub, &a, "message_list", json!({"waiting_on_reply": true})).await;
    assert_eq!(waiting["total"], 0);
    let thread = call(&reg, &hub, &a, "message_list", json!({"conversation_id": conversation})).await;
    assert_eq!(thread["total"], 2);
    assert_eq!(thread["messages"][0]["status"], "answered");
    assert_eq!(thread["messages"][0]["answered_by"], reply["message_id"]);
    assert_eq!(thread["messages"][0]["delivery"]["terminal"], "answered");
    assert!(thread["messages"][0]["seq"].as_i64() < thread["messages"][1]["seq"].as_i64());

    // Cursor paging moves forward only.
    let first = thread["messages"][0]["seq"].as_i64().unwrap();
    let page = call(&reg, &hub, &a, "message_list", json!({"after_seq": first})).await;
    assert_eq!(page["total"], 1);
    assert_eq!(page["next_seq"], thread["messages"][1]["seq"]);
    let count = call(&reg, &hub, &a, "message_list", json!({"count_only": true})).await;
    assert_eq!(count["count"], 2);
    assert!(count["messages"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn send_cannot_name_a_conversation_it_is_not_in() {
    let (hub, reg) = (hub(), builtin_registry());
    let (a, b, c) = (agent("builder-1"), agent("builder-2"), agent("builder-3"));

    // A restricted caller starts a conversation by minting an id.
    let sent =
        send(&reg, &hub, &a, json!({"act": "request", "to_agent": "builder-2", "body": "private thread"}))
            .await;
    let conv = sent["conversation_id"].as_str().unwrap().to_string();

    // A foreign id and a missing one answer alike.
    let foreign = reg
        .call(
            &hub,
            &c,
            "message_send",
            json!({"act": "inform", "to_agent": "builder-2", "body": "let me in",
                   "conversation_id": conv}),
        )
        .await
        .unwrap_err();
    let missing = reg
        .call(
            &hub,
            &c,
            "message_send",
            json!({"act": "inform", "to_agent": "builder-2", "body": "new?",
                   "conversation_id": "conv-absent"}),
        )
        .await
        .unwrap_err();
    assert_eq!(foreign.code(), "not_found");
    assert_eq!(missing.code(), "not_found");
    assert_eq!(foreign.to_string(), missing.to_string());

    // A party continues its own conversation by id.
    let reply = send(
        &reg,
        &hub,
        &b,
        json!({"act": "inform", "to_agent": "builder-1", "body": "on it", "conversation_id": conv}),
    )
    .await;
    assert_eq!(reply["conversation_id"], conv);

    // An unrestricted caller may start a conversation under a chosen id.
    let board = Caller::local("local", Transport::Stdio);
    let named = send(
        &reg,
        &hub,
        &board,
        json!({"act": "inform", "to_agent": "builder-2", "body": "named", "conversation_id": "conv-named"}),
    )
    .await;
    assert_eq!(named["conversation_id"], "conv-named");
}

#[tokio::test]
async fn send_validation() {
    let (hub, reg) = (hub(), builtin_registry());
    let a = agent("builder-1");
    let bad = |args: Value| {
        let (reg, hub, a) = (&reg, &hub, &a);
        async move { reg.call(hub, a, "message_send", args).await.unwrap_err() }
    };
    assert!(
        bad(json!({"act": "shout", "to_agent": "builder-2", "body": "x"}))
            .await
            .to_string()
            .contains("act must be")
    );
    assert!(
        bad(json!({"act": "inform", "to_agent": "builder-2"})).await.to_string().contains("body is required")
    );
    assert!(
        bad(json!({"act": "inform", "to_agent": "builder-1", "body": "x"}))
            .await
            .to_string()
            .contains("must differ")
    );
    assert!(
        bad(json!({"act": "inform", "to_agent": "builder-2", "body": "x", "hop": 16}))
            .await
            .to_string()
            .contains("hop")
    );
    assert!(
        bad(json!({"act": "inform", "to_agent": "builder-2", "body": "x".repeat(4097)}))
            .await
            .to_string()
            .contains("4096")
    );
    assert!(
        bad(json!({"act": "inform", "to_office": "eng", "body": "x"}))
            .await
            .to_string()
            .contains("role addressing (to_office, to_role) is not supported")
    );
    assert!(
        bad(json!({"act": "inform", "to_agent": "builder-2", "body": "x", "handoff": {"done": "y"}}))
            .await
            .to_string()
            .contains("only accepted on act='handoff'")
    );
    assert!(
        bad(json!({"act": "inform", "to_agent": "builder-2", "body": "x", "conversation_id": "a]b"}))
            .await
            .to_string()
            .contains("conversation_id")
    );

    let untyped =
        send(&reg, &hub, &a, json!({"act": "handoff", "to_agent": "builder-2", "body": "over to you"})).await;
    assert_eq!(untyped["handoff_typed"], false);
    let typed = send(
        &reg,
        &hub,
        &a,
        json!({"act": "handoff", "to_agent": "builder-2", "body": "over to you",
               "handoff": {"done": ["tests pass"], "next_action": "merge", "reviewed_head_sha": "ABCDEF1",
                           "evidence": [{"kind": "pr", "ref": 12, "repo": "example/repo"}]}}),
    )
    .await;
    assert_eq!(typed["handoff_typed"], true);
    assert_eq!(typed["handoff_claims"], 2);
    let listed = call(&reg, &hub, &agent("builder-2"), "message_list", json!({"act": "handoff"})).await;
    assert_eq!(listed["messages"][1]["handoff"]["reviewed_head_sha"], "abcdef1");
    assert_eq!(listed["messages"][1]["handoff"]["evidence"][0]["ref"], "12");
}

#[tokio::test]
async fn loop_guards() {
    let (hub, reg) = (hub(), builtin_registry());
    let (a, b) = (agent("builder-1"), agent("builder-2"));
    let first = send(&reg, &hub, &a, json!({"act": "query", "to_agent": "builder-2", "body": "ok?"})).await;
    let second =
        send(&reg, &hub, &b, json!({"act": "inform", "body": "ok", "reply_to": first["message_id"]})).await;
    let third =
        send(&reg, &hub, &a, json!({"act": "inform", "body": "ok!", "reply_to": second["message_id"]})).await;
    assert!(third["loop_warning"].as_str().unwrap().contains("next short reply"), "{third}");
    let err = reg
        .call(
            &hub,
            &b,
            "message_send",
            json!({"act": "inform", "body": "ok", "reply_to": third["message_id"]}),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("short messages in a row"), "{err}");
    // A substantive body ends the run.
    let long = "x".repeat(250);
    send(&reg, &hub, &b, json!({"act": "inform", "body": long, "reply_to": third["message_id"]})).await;

    // Messages to a human are exempt from the guards.
    let human_chain =
        send(&reg, &hub, &a, json!({"act": "inform", "to_agent": "operator", "body": "hi", "hop": 15})).await;
    assert_eq!(human_chain["hop"], 15);
}

#[tokio::test]
async fn inbox_marks_read_and_ack() {
    let (hub, reg) = (hub(), builtin_registry());
    let (a, b) = (agent("builder-1"), agent("builder-2"));
    for i in 0..3 {
        send(&reg, &hub, &a, json!({"act": "inform", "to_agent": "builder-2", "body": format!("note {i}")}))
            .await;
    }
    // message_list never changes read state.
    call(&reg, &hub, &b, "message_list", json!({"unread_only": true})).await;
    let listed = call(&reg, &hub, &b, "message_list", json!({"unread_only": true})).await;
    assert_eq!(listed["unread"], 3);

    let inbox = coord(&reg, &hub, &b, "message_inbox", json!({"limit": 2})).await.unwrap();
    assert_eq!(inbox["total"], 2);
    assert_eq!(inbox["marked_read"], 2);
    assert_eq!(inbox["unread"], 1);
    assert_eq!(inbox["messages"][0]["status"], "read");
    assert_eq!(inbox["messages"][0]["trust"]["level"], "untrusted");
    let rest = coord(&reg, &hub, &b, "message_inbox", json!({})).await.unwrap();
    assert_eq!(rest["total"], 1);
    assert_eq!(rest["unread"], 0);
    assert_eq!(events(&hub, "agent.mailbox.read"), 2);

    // Ack one by id, then the rest through a seq cursor; a repeat is a no-op.
    let all = call(&reg, &hub, &b, "message_list", json!({})).await;
    let first_id = all["messages"][0]["message_id"].clone();
    let acked = coord(&reg, &hub, &b, "message_ack", json!({"message_id": first_id})).await.unwrap();
    assert_eq!(acked["acked"], 1);
    let through = coord(&reg, &hub, &b, "message_ack", json!({"through": all["next_seq"]})).await.unwrap();
    assert_eq!(through["acked"], 2);
    assert_eq!(through["through_seq"], all["next_seq"]);
    let again = coord(&reg, &hub, &b, "message_ack", json!({"through": all["next_seq"]})).await.unwrap();
    assert_eq!(again["acked"], 0);
    let after = call(&reg, &hub, &b, "message_list", json!({})).await;
    assert!(after["messages"].as_array().unwrap().iter().all(|m| !m["acked_at"].is_null()));
    assert_eq!(after["messages"][0]["delivery"]["state"], "acked");

    // Ack takes a message_id cursor too; only the recipient can ack; bad args refused.
    let err = coord(&reg, &hub, &a, "message_ack", json!({"message_id": first_id})).await.unwrap_err();
    assert!(err.to_string().contains("no message"), "{err}");
    let err = coord(&reg, &hub, &b, "message_ack", json!({"through": true})).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let err = coord(&reg, &hub, &b, "message_ack", json!({})).await.unwrap_err();
    assert!(err.to_string().contains("exactly one"), "{err}");
    let err = coord(&reg, &hub, &b, "message_ack", json!({"through": "nope"})).await.unwrap_err();
    assert!(err.to_string().contains("not a message_id"), "{err}");
}

#[tokio::test]
async fn coordination_actions() {
    let (hub, reg) = (hub(), builtin_registry());
    let a = agent("builder-1");
    let err = coord(&reg, &hub, &a, "dependency_add", json!({})).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let text = err.to_string();
    for action in ["message_inbox", "message_ack", "agent_list", "agent_context"] {
        assert!(text.contains(action), "{text}");
    }
    let err = coord(&reg, &hub, &a, "message_inbox", json!({"bogus": 1})).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let listed = coord(&reg, &hub, &a, "agent_list", json!({})).await.unwrap();
    assert!(listed["agents"].is_array());
    let context = coord(&reg, &hub, &a, "agent_context", json!(null)).await.unwrap();
    assert_eq!(context["identity"], "builder-1");
}

#[tokio::test]
async fn session_addressed_delivery() {
    let (hub, reg) = (hub(), builtin_registry());
    let (a, b) = (agent("builder-1"), agent("builder-2"));
    let start = |who: &Caller, ext: &str| {
        let (reg, hub, who, ext) = (&reg, &hub, who.clone(), ext.to_string());
        async move {
            call(reg, hub, &who, "session_start", json!({"kind": "interactive", "external_session_id": ext}))
                .await["session_id"]
                .as_str()
                .unwrap()
                .to_string()
        }
    };
    let s_a = start(&b, "ext-a").await;
    let s_b = start(&b, "ext-b").await;
    let s_sender = start(&a, "ext-s").await;

    // Session mail: only that session sees it.
    let sent = send(
        &reg,
        &hub,
        &a,
        json!({"act": "request", "to_session": s_a, "body": "for session a", "from_session": s_sender,
               "expects_reply": true}),
    )
    .await;
    assert_eq!(sent["to_agent"], "builder-2");
    assert_eq!(sent["to_session"], s_a);
    assert_eq!(sent["target_live"], true);
    assert_eq!(sent["availability"]["availability"], "available");
    let as_a = call(&reg, &hub, &b, "message_list", json!({"session_id": s_a})).await;
    assert_eq!(as_a["total"], 1);
    assert_eq!(as_a["unread"], 1);
    let as_b = call(&reg, &hub, &b, "message_list", json!({"session_id": s_b})).await;
    assert_eq!(as_b["total"], 0);
    let as_label = call(&reg, &hub, &b, "message_list", json!({})).await;
    assert_eq!(as_label["total"], 0);
    // A session that is not yours is refused like a missing one.
    let err = reg.call(&hub, &a, "message_list", json!({"session_id": s_a})).await.unwrap_err();
    assert!(err.to_string().contains("is not a session of"), "{err}");

    // A reply defaults to the asker's session.
    let reply =
        send(&reg, &hub, &b, json!({"act": "done", "body": "answered", "reply_to": sent["message_id"]}))
            .await;
    assert_eq!(reply["to_agent"], "builder-1");
    assert_eq!(reply["to_session"], s_sender);

    // Label mail read through one session stays unread for the other.
    send(&reg, &hub, &a, json!({"act": "inform", "to_agent": "builder-2", "body": "for everyone"})).await;
    let read_a = coord(&reg, &hub, &b, "message_inbox", json!({"session_id": s_a})).await.unwrap();
    assert_eq!(read_a["marked_read"], 2);
    assert_eq!(read_a["unread"], 0);
    let unread_b =
        call(&reg, &hub, &b, "message_list", json!({"session_id": s_b, "unread_only": true})).await;
    assert_eq!(unread_b["total"], 1);
    assert_eq!(unread_b["messages"][0]["body"], "for everyone");
    // Acking label mail without a session clears it for every session.
    let next = unread_b["next_seq"].clone();
    coord(&reg, &hub, &b, "message_ack", json!({"through": next})).await.unwrap();
    let unread_b = call(&reg, &hub, &b, "message_list", json!({"session_id": s_b, "count_only": true})).await;
    assert_eq!(unread_b["unread"], 0);

    // A quiet session falls back to label mail; an ended one is refused.
    hub.db()
        .write(|tx| {
            tx.execute(
                "UPDATE agent_sessions SET last_heartbeat_at = '2000-01-01T00:00:00+00:00' WHERE id = ?1",
                [&s_b],
            )?;
            Ok(())
        })
        .unwrap();
    let fell_back = send(&reg, &hub, &a, json!({"act": "inform", "to_session": s_b, "body": "late"})).await;
    assert!(fell_back["to_session"].is_null());
    assert_eq!(fell_back["session_fallback"]["reason"], "abandoned");
    assert_eq!(fell_back["session_fallback"]["delivered_as"], "label");

    call(&reg, &hub, &b, "session_end", json!({"session_id": s_a})).await;
    let err = reg
        .call(&hub, &a, "message_send", json!({"act": "inform", "to_session": s_a, "body": "too late"}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("has ended"), "{err}");
    let err = reg
        .call(&hub, &a, "message_send", json!({"act": "inform", "to_session": "no-such", "body": "x"}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "not_found");
    let err = reg
        .call(
            &hub,
            &a,
            "message_send",
            json!({"act": "inform", "to_session": s_sender, "to_agent": "builder-2", "body": "x"}),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("does not match session"), "{err}");
}

#[tokio::test]
async fn unverified_local_caller() {
    let (hub, reg) = (hub(), builtin_registry());
    let local = Caller::local("local-agent", Transport::Stdio);
    let sent =
        send(&reg, &hub, &local, json!({"act": "inform", "to_agent": "builder-2", "body": "from stdio"}))
            .await;
    assert_eq!(sent["from_agent"], "local-agent");
    let named = send(
        &reg,
        &hub,
        &local,
        json!({"act": "inform", "from_agent": "builder-9", "to_agent": "builder-2", "body": "x"}),
    )
    .await;
    assert_eq!(named["from_agent"], "builder-9");
    // A message board: it reads any mailbox it names; every row is marked
    // untrusted, and its sender as not verified.
    let listed = call(&reg, &hub, &local, "message_list", json!({"to_agent": "builder-2"})).await;
    assert_eq!(listed["total"], 2);
    let rows = listed["messages"].as_array().unwrap();
    assert!(rows.iter().all(|m| m["trust"]["level"] == "untrusted"));
    assert!(rows.iter().all(|m| m["sender_verified"] == false), "{listed}");
    assert_eq!(sent["sender_verified"], false);
}

/// With no verified identity, another label's mailbox is a board to read:
/// reading it never changes what its owner has read or acknowledged.
#[tokio::test]
async fn an_unverified_reader_leaves_another_mailbox_unread() {
    let (hub, reg) = (hub(), builtin_registry());
    let local = Caller::local("local-agent", Transport::Stdio);
    let (a, b) = (agent("builder-1"), agent("builder-2"));
    let first = send(&reg, &hub, &a, json!({"act": "inform", "to_agent": "builder-2", "body": "one"})).await;
    assert_eq!(first["sender_verified"], true);
    send(&reg, &hub, &a, json!({"act": "inform", "to_agent": "builder-2", "body": "two"})).await;
    send(&reg, &hub, &a, json!({"act": "inform", "to_agent": "local-agent", "body": "yours"})).await;

    // The board: listed in full, nothing marked, and it says so.
    let board = coord(&reg, &hub, &local, "message_inbox", json!({"to_agent": "builder-2"})).await.unwrap();
    assert_eq!(board["total"], 2);
    assert_eq!(board["marked_read"], 0);
    assert_eq!(board["mailbox"], "builder-2");
    assert!(board["read_state"].as_str().unwrap().starts_with("unchanged"), "{board}");
    assert!(board["messages"].as_array().unwrap().iter().all(|m| m["sender_verified"] == true));
    assert_eq!(events(&hub, "agent.mailbox.read"), 0);
    // Nor acknowledged, by one id or by a cursor, nor read as one of its sessions.
    let mid = first["message_id"].clone();
    for params in [
        json!({"to_agent": "builder-2", "message_id": mid}),
        json!({"to_agent": "builder-2", "through": 999}),
    ] {
        let e = coord(&reg, &hub, &local, "message_ack", params).await.unwrap_err();
        assert!(e.to_string().contains("only your own mailbox"), "{e}");
    }
    let e = coord(&reg, &hub, &local, "message_inbox", json!({"to_agent": "builder-2", "session_id": "s-1"}))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("not yours"), "{e}");
    // The owner still has both unread.
    let own = coord(&reg, &hub, &b, "message_inbox", json!({})).await.unwrap();
    assert_eq!(own["marked_read"], 2);

    // Its own mailbox works as before, named or not.
    let mine = coord(&reg, &hub, &local, "message_inbox", json!({"to_agent": "local-agent"})).await.unwrap();
    assert_eq!(mine["marked_read"], 1);
    assert!(mine.get("read_state").is_none());
    let acked = coord(&reg, &hub, &local, "message_ack", json!({"through": 999})).await.unwrap();
    assert_eq!(acked["mailbox"], "local-agent");

    // A caller with only the shared local label has no mailbox of its own: it
    // acts as the mailbox it names.
    send(&reg, &hub, &a, json!({"act": "inform", "to_agent": "builder-2", "body": "three"})).await;
    let shared = Caller::local(ua_core::identity::LOCAL_LABEL, Transport::Http);
    let named = coord(&reg, &hub, &shared, "message_inbox", json!({"to_agent": "builder-2"})).await.unwrap();
    assert_eq!(named["marked_read"], 1);
    coord(&reg, &hub, &shared, "message_ack", json!({"to_agent": "builder-2", "through": 999}))
        .await
        .unwrap();
}

/// Reading every mailbox: an operator (a verified human) may; an agent under
/// the coordinator profile may not, since a profile grants nothing. (An
/// unverified local caller is unchanged; see `unverified_local_caller`.)
#[tokio::test]
async fn reading_every_mailbox_needs_an_operator_not_the_coordinator_profile() {
    let (hub, reg) = (hub(), builtin_registry());
    send(&reg, &hub, &agent("builder-1"), json!({"act": "inform", "to_agent": "builder-2", "body": "hi"}))
        .await;
    let coordinator = Caller { profile: Profile::Coordinator, ..agent("lead-1") };
    let e = reg.call(&hub, &coordinator, "message_list", json!({"to_agent": "builder-2"})).await.unwrap_err();
    assert!(e.to_string().contains("outside your mailbox"), "{e}");
    let human = Caller { kind: ActorKind::Human, enforce_profile: false, ..agent("operator") };
    let listed = call(&reg, &hub, &human, "message_list", json!({"to_agent": "builder-2"})).await;
    assert_eq!(listed["total"], 1);
    // A verified agent reads its own mailbox.
    let own = call(&reg, &hub, &agent("builder-2"), "message_list", json!({})).await;
    assert_eq!(own["total"], 1);
}

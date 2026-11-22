//! Review follow-ups: scoped event streams, the approval detail's human
//! check, the host guard and dynamic client registration limits.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, Response, StatusCode, header};
use common::{TestHub, get, json_body, post_json};
use http_body_util::BodyExt;
use secrecy::SecretString;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_store::EventInput;
use ua_store::ledger;

const AGENT_A: &str = "agent-a-test-token-0001";
const AGENT_B: &str = "agent-b-test-token-0002";
const AGENT_C: &str = "agent-c-test-token-0004";
const OPERATOR: &str = "operator-test-token-0003";

/// Two agents with tokens: `agent-a` on the default profile, `agent-b` on
/// `public`, which does not include `event_log_query`.
fn stream_config() -> Config {
    let mut cfg = common::config();
    cfg.oauth_enabled = false;
    cfg.agent_tokens = Some(SecretString::from(format!(
        "agent-a:{AGENT_A},agent-b:{AGENT_B},agent-c:{AGENT_C},operator:{OPERATOR}"
    )));
    cfg.profiles.insert("agent-b".into(), "public".into());
    cfg
}

fn append(hub: &TestHub, channel: &str, i: usize) -> i64 {
    hub.state
        .hub
        .db()
        .write(|tx| {
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, channel, json!({ "i": i })).by("tester"))
        })
        .unwrap()
        .unwrap()
        .seq
}

/// Read an SSE body until `done` holds or a few seconds pass.
async fn read_sse(resp: Response<Body>, done: impl Fn(&str) -> bool) -> String {
    let mut body = resp.into_body();
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !done(&text) {
        match tokio::time::timeout_at(deadline, body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    text.push_str(&String::from_utf8_lossy(&data));
                }
            }
            _ => break,
        }
    }
    text
}

fn sse_ids(text: &str) -> Vec<i64> {
    text.lines().filter_map(|l| l.strip_prefix("id: ")).filter_map(|s| s.trim().parse().ok()).collect()
}

#[tokio::test]
async fn streams_share_mailbox_visibility_for_replayed_and_live_messages() {
    for path in ["/api/events/stream", "/ui/activity/stream"] {
        let hub = TestHub::new(stream_config());
        let sender = Caller {
            label: "builder-1".into(),
            kind: ActorKind::Agent,
            profile: Profile::Developer,
            enforce_profile: true,
            session_key: None,
            transport: Transport::Mcp,
            org_id: ua_core::DEFAULT_ORG.into(),
        };
        let send = async |recipient: &str| {
            hub.state
                .registry
                .call(
                    &hub.state.hub,
                    &sender,
                    "message_send",
                    json!({ "act": "inform", "to_agent": recipient, "body": "Build update" }),
                )
                .await
                .unwrap()["seq"]
                .as_i64()
                .unwrap()
        };

        send("builder-2").await;
        let replayed = send("agent-a").await;
        let mut req = get(path, None, Some(AGENT_A));
        req.headers_mut().insert("last-event-id", "0".parse().unwrap());
        let resp = hub.send(req).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");

        send("builder-2").await;
        let live = send("agent-a").await;
        let text = read_sse(resp, |t| t.contains(&format!("id: {live}\n"))).await;
        assert_eq!(sse_ids(&text), vec![replayed, live], "{path}: {text}");
    }
}

#[tokio::test]
async fn streams_hide_committed_handoff_rows_from_outsiders() {
    use ua_tools::families::events::EventReader;

    let hub = TestHub::new(stream_config());
    let agent = |label: &str| Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: None,
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    };
    let call = async |who: &Caller, tool: &str, args: Value| -> Value {
        hub.state.registry.call(&hub.state.hub, who, tool, args).await.unwrap()
    };
    let builder = agent("builder-1");

    // Committed rows before the streams open: a private message and a
    // conversation handoff agent-a is a party to, plus a sealed handoff note
    // that is builder-1's alone.
    call(
        &builder,
        "message_send",
        json!({ "act": "request", "to_agent": "agent-a", "body": "plan", "conversation_id": "conv-live" }),
    )
    .await;
    let task = call(&builder, "task_add", json!({ "title": "handed off" })).await["id"].clone();
    call(
        &builder,
        "coordination_manage",
        json!({ "action": "conversation_handoff",
                "params": { "conversation_id": "conv-live", "task_id": task } }),
    )
    .await;
    let sid = call(&builder, "session_start", json!({ "kind": "interactive" })).await["session_id"].clone();
    let note = call(
        &builder,
        "coordination_manage",
        json!({ "action": "session_handoff_propose",
                "params": { "session_id": sid, "done": ["a"], "next_steps": ["b"] } }),
    )
    .await;
    call(
        &builder,
        "coordination_manage",
        json!({ "action": "session_handoff_seal", "params": { "note_id": note["id"] } }),
    )
    .await;
    let last_of = |channel: &str| -> i64 {
        let ch = channel.to_string();
        hub.state
            .hub
            .db()
            .read(|c| {
                Ok(c.query_row("SELECT MAX(seq) FROM event_log WHERE channel = ?1", [&ch], |r| r.get(0))?)
            })
            .unwrap()
    };
    let conv_seq = last_of("agent.conversation.handoff");
    let note_seq = last_of("agent.lifecycle.handoff");
    let sentinel = append(&hub, "test.keep", 0);

    // `EventReader::includes` agrees: the committed rows authorize per reader.
    for (label, seq, want) in
        [("agent-a", conv_seq, true), ("agent-c", conv_seq, false), ("agent-c", note_seq, false)]
    {
        let reader = EventReader::new(hub.state.hub.cfg(), &agent(label));
        let seen = hub.state.hub.db().read(|c| reader.includes(c, seq)).unwrap();
        assert_eq!(seen, want, "{label} includes(seq {seq})");
    }

    // Backfilled streams follow the same rule: the participant gets the
    // conversation-handoff row, the outsider gets neither restricted row.
    let open = |token: &str| {
        let mut req = get("/api/events/stream", None, Some(token));
        req.headers_mut().insert("last-event-id", "0".parse().unwrap());
        req
    };
    let resp_a = hub.send(open(AGENT_A)).await;
    let resp_c = hub.send(open(AGENT_C)).await;
    assert_eq!(resp_a.status(), StatusCode::OK);
    assert_eq!(resp_c.status(), StatusCode::OK);
    let done = move |t: &str| t.contains(&format!("id: {sentinel}\n"));
    let text_a = read_sse(resp_a, done).await;
    let text_c = read_sse(resp_c, done).await;
    assert!(sse_ids(&text_a).contains(&conv_seq), "participant stream: {text_a}");
    assert!(!sse_ids(&text_a).contains(&note_seq), "participant stream: {text_a}");
    assert!(!sse_ids(&text_c).contains(&conv_seq), "outsider stream: {text_c}");
    assert!(!sse_ids(&text_c).contains(&note_seq), "outsider stream: {text_c}");
}

#[tokio::test]
async fn an_agent_without_event_log_query_cannot_open_either_stream() {
    let hub = TestHub::new(stream_config());
    for path in ["/api/events/stream", "/ui/activity/stream"] {
        let resp = hub.send(get(path, None, Some(AGENT_B))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
    }
    // The allowed agent gets a stream, and the refusal was a governed
    // decision like any other tool call.
    let resp = hub.send(get("/api/events/stream", None, Some(AGENT_A))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/event-stream"));
}

#[tokio::test]
async fn streams_apply_the_channel_scope_live() {
    let hub = TestHub::new(stream_config());
    let resp = hub.send(get("/api/events/stream?channel_prefix=test.keep", None, Some(AGENT_A))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    append(&hub, "test.drop", 0);
    let keep = append(&hub, "test.keep", 1);
    let text = read_sse(resp, |t| t.contains(&format!("id: {keep}"))).await;
    assert!(text.contains("event: test.keep"), "{text}");
    assert!(!text.contains("test.drop"), "{text}");
}

#[tokio::test]
async fn a_reconnect_with_last_event_id_gets_the_missed_rows() {
    let hub = TestHub::new(stream_config());
    let seen = append(&hub, "test.keep", 0);
    append(&hub, "test.drop", 1);
    let missed1 = append(&hub, "test.keep", 2);
    let missed2 = append(&hub, "test.keep", 3);
    for path in
        ["/api/events/stream?channel_prefix=test.keep", "/ui/activity/stream?channel_prefix=test.keep"]
    {
        let mut req = get(path, None, Some(AGENT_A));
        req.headers_mut().insert("last-event-id", seen.to_string().parse().unwrap());
        let resp = hub.send(req).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let text = read_sse(resp, |t| t.contains(&format!("id: {missed2}"))).await;
        assert_eq!(sse_ids(&text), vec![missed1, missed2], "{path}: {text}");
    }
    // Without a resume point the stream starts at the end of the ledger.
    let resp = hub.send(get("/api/events/stream?channel_prefix=test.keep", None, Some(AGENT_A))).await;
    let next = append(&hub, "test.keep", 4);
    let text = read_sse(resp, |t| t.contains(&format!("id: {next}"))).await;
    assert_eq!(sse_ids(&text), vec![next]);
}

#[tokio::test]
async fn a_lagging_stream_backfills_from_the_ledger() {
    let hub = TestHub::new(stream_config());
    let resp = hub.send(get("/api/events/stream?channel_prefix=test.keep", None, Some(AGENT_A))).await;
    // More rows than the broadcast buffer holds, before the client reads.
    let mut kept = Vec::new();
    for i in 0..1100 {
        if i % 200 == 0 {
            kept.push(append(&hub, "test.keep", i));
        } else {
            append(&hub, "test.noise", i);
        }
    }
    let last = *kept.last().unwrap();
    let text = read_sse(resp, |t| t.contains(&format!("id: {last}"))).await;
    assert_eq!(sse_ids(&text), kept, "{text}");
    assert!(!text.contains("event: gap"), "{text}");
}

/// The `data:` line after each `event: gap` line.
fn sse_gaps(text: &str) -> Vec<Value> {
    text.split("event: gap\n")
        .skip(1)
        .filter_map(|rest| rest.lines().next())
        .filter_map(|l| l.strip_prefix("data: "))
        .map(|d| serde_json::from_str(d).unwrap())
        .collect()
}

#[tokio::test]
async fn a_resume_past_the_backfill_cap_reports_the_rest_up_to_the_next_live_row() {
    let hub = TestHub::new(stream_config());
    let cap = ua_server::events::BACKFILL_CAP;
    let mut scoped = Vec::new();
    for i in 0..cap + 150 {
        if i % 50 == 0 {
            append(&hub, "test.noise", i);
        }
        scoped.push(append(&hub, "test.keep", i));
    }
    let mut req = get("/api/events/stream?channel_prefix=test.keep", None, Some(AGENT_A));
    req.headers_mut().insert("last-event-id", "0".parse().unwrap());
    let resp = hub.send(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let live = append(&hub, "test.keep", 0);
    scoped.push(live);
    let text = read_sse(resp, |t| t.contains(&format!("id: {live}\n"))).await;

    // Every scoped seq is either delivered or inside a reported gap.
    let ids = sse_ids(&text);
    let gaps = sse_gaps(&text);
    assert_eq!(gaps.len(), 1, "{gaps:?}");
    let (after, until) = (gaps[0]["after_seq"].as_i64().unwrap(), gaps[0]["until_seq"].as_i64());
    assert_eq!(gaps[0]["reason"], "backfill_limit");
    assert_eq!(after, scoped[cap - 1], "the gap starts at the last row read");
    assert_eq!(until, Some(live), "the gap ends at the next live row");
    for seq in &scoped {
        let in_gap = *seq > after && until.is_none_or(|u| *seq < u);
        assert!(ids.contains(seq) != in_gap, "seq {seq}: delivered or in the gap, exactly one");
    }
    assert_eq!(ids.len(), cap + 1);
}

#[tokio::test]
async fn the_activity_stream_renders_a_gap_as_its_range() {
    let hub = TestHub::new(stream_config());
    let cap = ua_server::events::BACKFILL_CAP;
    let mut last_read = 0;
    for i in 0..cap + 10 {
        let seq = append(&hub, "test.keep", i);
        if i + 1 == cap {
            last_read = seq;
        }
    }
    let mut req = get("/ui/activity/stream?channel_prefix=test.keep", None, Some(AGENT_A));
    req.headers_mut().insert("last-event-id", "0".parse().unwrap());
    let resp = hub.send(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let live = append(&hub, "test.keep", 0);
    let text = read_sse(resp, |t| t.contains(&format!("id: {live}\n"))).await;
    let expected = format!("Some events #{} to #{} could not be loaded", last_read + 1, live - 1);
    assert!(text.contains(&expected), "missing {expected:?}");
}

/// A managed token for `label`, as `agent_token_issue` stores it.
fn managed_token(hub: &TestHub, label: &str, token: &str) {
    use sha2::{Digest, Sha256};
    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    hub.state
        .hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO agent_tokens (agent_label, token_hash, issued_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![label, hash, ua_core::time::now()],
            )?;
            Ok(())
        })
        .unwrap();
}

/// Revoke `label`'s managed tokens the way the CLI does.
fn revoke_tokens(hub: &TestHub, label: &str) {
    hub.state
        .hub
        .db()
        .write(|tx| {
            tx.execute(
                "UPDATE agent_tokens SET status = 'revoked', revoked_at = ?2 WHERE agent_label = ?1",
                rusqlite::params![label, ua_core::time::now()],
            )?;
            ledger::append(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG, "agent.token.revoked", json!({ "agent": label }))
                    .by("cli"),
            )?;
            Ok(())
        })
        .unwrap();
}

/// Read an SSE body until it ends and return the `auth_revoked` reason it
/// sent last; `None` when it is still open after a few seconds. Fails when
/// it ended without a revocation notice, or sent anything after it.
async fn revoked_soon(resp: Response<Body>) -> Option<String> {
    let mut body = resp.into_body();
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    text.push_str(&String::from_utf8_lossy(&data));
                }
            }
            Ok(None) | Ok(Some(Err(_))) => break,
            Err(_) => return None,
        }
    }
    let at =
        text.rfind("event: auth_revoked\n").unwrap_or_else(|| panic!("no auth_revoked event in {text:?}"));
    let tail = &text[at..];
    let data = tail.lines().find_map(|l| l.strip_prefix("data: ")).expect("auth_revoked data");
    let v: Value = serde_json::from_str(data).unwrap();
    assert_eq!(v["auth_revoked"], true);
    assert!(
        !tail.lines().any(|l| l.starts_with("event: ") && l != "event: auth_revoked"),
        "events after the revocation: {tail:?}"
    );
    Some(v["reason"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn revoking_the_token_ends_an_open_stream() {
    let hub = TestHub::new(stream_config());
    const MANAGED: &str = "agent-c-managed-token-0004";
    managed_token(&hub, "agent-c", MANAGED);
    managed_token(&hub, "agent-d", "agent-d-managed-token-0005");
    let resp = hub.send(get("/api/events/stream?channel_prefix=test.keep", None, Some(MANAGED))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();

    // Another identity's revocation re-checks this stream but keeps it open.
    revoke_tokens(&hub, "agent-d");
    let keep = append(&hub, "test.keep", 0);
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !text.contains(&format!("id: {keep}\n")) {
        let frame = tokio::time::timeout_at(deadline, body.frame()).await.expect("stream stalled");
        let frame = frame.expect("stream ended on another identity's revocation").unwrap();
        if let Ok(data) = frame.into_data() {
            text.push_str(&String::from_utf8_lossy(&data));
        }
    }

    // Its own revocation ends it, without waiting for the periodic check.
    revoke_tokens(&hub, "agent-c");
    let reason = revoked_soon(Response::new(body)).await.expect("the stream outlived its token");
    assert_eq!(reason, "credential_invalid");
    // And a new stream with the revoked token is refused.
    let resp = hub.send(get("/api/events/stream", None, Some(MANAGED))).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logging_out_ends_an_open_activity_stream() {
    let hub = TestHub::new(stream_config());
    let cookie = hub.sign_in("operator").await;
    let csrf = hub.csrf(&cookie).await;
    let resp = hub.send(get("/ui/activity/stream", Some(&cookie), None)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let out = hub.send(common::form("/logout", &[("csrf", &csrf)], Some(&cookie))).await;
    assert!(out.status().is_redirection());
    let reason = revoked_soon(resp).await.expect("the stream outlived its session");
    assert_eq!(reason, "credential_invalid");
}

/// A private directory under the system temp dir, removed on drop.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("ua-hardening-{}", ulid::Ulid::generate()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A stream for `agent-a` (default profile) under a policy file in `dir`.
async fn policy_stream(
    dir: &std::path::Path,
    initial: &str,
) -> (TestHub, std::path::PathBuf, Response<Body>) {
    let path = dir.join("policy.yaml");
    std::fs::write(&path, initial).unwrap();
    let mut cfg = stream_config();
    cfg.policy_file = Some(path.clone());
    let hub = TestHub::new(cfg);
    let resp = hub.send(get("/api/events/stream?channel_prefix=test.keep", None, Some(AGENT_A))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    (hub, path, resp)
}

/// Rewrite the policy file and broadcast the change the way a config
/// revision does.
fn change_policy(hub: &TestHub, path: &std::path::Path, text: &str) {
    std::fs::write(path, text).unwrap();
    ua_tools::policy::invalidate(path);
    append(hub, "agent.config.revision", 0);
}

#[tokio::test]
async fn a_profile_overlay_that_narrows_access_ends_the_stream() {
    let dir = TempDir::new();
    let (hub, path, resp) = policy_stream(dir.path(), "version: 1\n").await;
    // `public` does not include event_log_query.
    std::fs::write(&path, "version: 1\nprofile_defaults:\n  agent-a: public\n").unwrap();
    ua_tools::policy::invalidate(&path);
    append(&hub, "agent.profile.changed", 0);
    assert_eq!(revoked_soon(resp).await.as_deref(), Some("profile_denied"));
}

#[tokio::test]
async fn a_policy_rule_that_denies_the_stream_ends_it() {
    let dir = TempDir::new();
    let (hub, path, resp) = policy_stream(dir.path(), "version: 1\n").await;
    let mut body = resp.into_body();
    // A rule for another agent re-checks the stream but keeps it open.
    change_policy(
        &hub,
        &path,
        "version: 1\nrules:\n  - name: other\n    type: tool\n    tool: event_log_query\n    action: deny\n    bind:\n      agent: agent-z\n",
    );
    let keep = append(&hub, "test.keep", 0);
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !text.contains(&format!("id: {keep}\n")) {
        let frame = tokio::time::timeout_at(deadline, body.frame()).await.expect("stream stalled");
        let frame = frame.expect("stream ended on another agent's rule").unwrap();
        if let Ok(data) = frame.into_data() {
            text.push_str(&String::from_utf8_lossy(&data));
        }
    }
    change_policy(
        &hub,
        &path,
        "version: 1\nrules:\n  - name: no-stream\n    type: tool\n    tool: event_log_query\n    action: deny\n    bind:\n      agent: agent-a\n",
    );
    assert_eq!(revoked_soon(Response::new(body)).await.as_deref(), Some("policy_denied"));
}

#[tokio::test]
async fn a_policy_that_newly_requires_approval_ends_the_stream() {
    let dir = TempDir::new();
    let (hub, path, resp) = policy_stream(dir.path(), "version: 1\n").await;
    change_policy(
        &hub,
        &path,
        "version: 1\nrules:\n  - name: gated\n    type: tool\n    tool: event_log_query\n    action: require_approval\n",
    );
    assert_eq!(revoked_soon(resp).await.as_deref(), Some("approval_required"));
}

#[tokio::test]
async fn throttles_do_not_end_an_admitted_stream() {
    // The stream's own admission is the one call these rules allow, so a
    // re-check that counted it would end the stream at once.
    let dir = TempDir::new();
    let throttled = "version: 1\nrules:\n  - name: spacing\n    type: cooldown\n    tool: event_log_query\n    cooldown_seconds: 600\n  - name: rate\n    type: rate_limit\n    tool: event_log_query\n    max_calls: 1\n    window_seconds: 600\n";
    let (hub, _path, resp) = policy_stream(dir.path(), throttled).await;
    append(&hub, "agent.profile.changed", 0);
    let keep = append(&hub, "test.keep", 1);
    let text = read_sse(resp, |t| t.contains(&format!("id: {keep}\n"))).await;
    assert!(text.contains(&format!("id: {keep}\n")), "stream ended: {text:?}");
    assert!(!text.contains("auth_revoked"));
    // A second stream is still throttled at open.
    let again = hub.send(get("/api/events/stream", None, Some(AGENT_A))).await;
    assert_ne!(again.status(), StatusCode::OK);
}

// ---------------------------------------------------------------- approvals

#[tokio::test]
async fn approval_detail_agrees_with_the_resolve_check() {
    // Auth off, and the anonymous local label is (mis)configured as human:
    // an unverified caller still may not approve, and the detail says so.
    let mut cfg = stream_config();
    cfg.enforce_auth = false;
    cfg.human_identities = vec!["operator".into(), "local".into()];
    cfg.approval_tools = vec!["task_add".into()];
    cfg.profiles.insert("operator".into(), "operator".into());
    let hub = TestHub::new(cfg);
    let builder = Caller {
        label: "builder-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: None,
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    };
    let id =
        match hub.state.registry.call(&hub.state.hub, &builder, "task_add", json!({ "title": "x" })).await {
            Err(UaError::ApprovalRequired { approval_id, .. }) => approval_id,
            other => panic!("expected a pending approval, got {other:?}"),
        };
    let detail = json_body(hub.send(get(&format!("/api/approvals/{id}"), None, None)).await).await;
    assert_eq!(detail["approver"]["may_approve"], "no", "{detail}");
    assert_eq!(detail["approver"]["reason"], "only a human operator can approve");
    let resp =
        hub.send(post_json("/api/action/approval", &json!({ "id": id, "decision": "approve" }), &[])).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // A verified human sees "yes" and can resolve.
    let detail = json_body(hub.send(get(&format!("/api/approvals/{id}"), None, Some(OPERATOR))).await).await;
    assert_eq!(detail["approver"]["may_approve"], "yes", "{detail}");
}

// ---------------------------------------------------------------- host guard

#[tokio::test]
async fn the_public_url_host_is_allowed_without_listing_it() {
    let mut cfg = stream_config();
    cfg.public_url = Some("https://hub.example.net".into());
    let hub = TestHub::new(cfg);
    for (host, status) in [
        ("hub.example.net", StatusCode::OK),
        ("hub.example.net:443", StatusCode::OK),
        ("localhost:8765", StatusCode::OK),
        ("rebound.example.com", StatusCode::FORBIDDEN),
    ] {
        let mut req = get("/api/whoami", None, Some(AGENT_A));
        req.headers_mut().insert(header::HOST, host.parse().unwrap());
        assert_eq!(hub.send(req).await.status(), status, "{host}");
    }
}

/// An HTTP/2 request carries the host in `:authority` (the URI) and may send
/// no `Host` header: the guard applies the same allowlist to it.
#[tokio::test]
async fn an_http2_authority_outside_the_allowlist_is_refused() {
    let mut cfg = stream_config();
    cfg.public_url = Some("https://hub.example.net".into());
    let hub = TestHub::new(cfg);
    for (uri, status) in [
        ("https://hub.example.net/api/whoami", StatusCode::OK),
        ("https://localhost:8765/api/whoami", StatusCode::OK),
        ("https://rebound.example.com/api/whoami", StatusCode::FORBIDDEN),
        ("https://rebound.example.com/ui/work", StatusCode::FORBIDDEN),
    ] {
        let req = Request::get(uri)
            .version(axum::http::Version::HTTP_2)
            .header(header::AUTHORIZATION, format!("Bearer {AGENT_A}"))
            .body(Body::empty())
            .unwrap();
        assert!(req.headers().get(header::HOST).is_none());
        assert_eq!(hub.send(req).await.status(), status, "{uri}");
    }
}

/// A shutdown cancels the server's token, and an open event stream ends on
/// it instead of holding the graceful shutdown open until its grace period.
#[tokio::test]
async fn open_event_streams_end_when_the_server_shuts_down() {
    use tower::ServiceExt;
    let hub = TestHub::new(stream_config());
    for path in ["/api/events/stream", "/ui/activity/stream"] {
        let ct = tokio_util::sync::CancellationToken::new();
        let app = ua_server::router(hub.state.clone(), ct.clone());
        let resp = app.clone().oneshot(get(path, None, Some(AGENT_A))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let mut body = resp.into_body();
        // Open and idle: nothing to read yet.
        assert!(tokio::time::timeout(Duration::from_millis(150), body.frame()).await.is_err(), "{path}");
        let ct = ct.clone();
        tokio::spawn(async move { ct.cancel() });
        let ended = tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(frame) = body.frame().await {
                frame.unwrap();
            }
        })
        .await;
        assert!(ended.is_ok(), "{path} stayed open after the shutdown token was cancelled");
    }
}

// ---------------------------------------------------------------- registration

fn register_from(addr: &str, body: &Value) -> Request<Body> {
    let mut req = post_json("/oauth/register", body, &[]);
    let peer: SocketAddr = addr.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    req
}

fn client_ids(hub: &TestHub) -> Vec<String> {
    hub.state
        .hub
        .db()
        .read(|c| {
            let mut stmt = c.prepare("SELECT client_id FROM oauth_clients ORDER BY client_id")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .unwrap()
}

fn grant(hub: &TestHub, client_id: &str) {
    let now = ua_core::time::now();
    hub.state
        .hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO oauth_grants (family_id, client_id, subject, approved_by, grant_type, scope, \
                 resource, created_at) VALUES (?1, ?2, 'remote-agent', 'operator', 'authorization_code', 'mcp', \
                 'https://hub.example.com/mcp', ?3)",
                rusqlite::params![format!("fam-{client_id}"), client_id, now],
            )?;
            Ok(())
        })
        .unwrap();
}

const CLIENT: &str = r#"{ "client_name": "Flood", "redirect_uris": ["http://127.0.0.1:9/cb"] }"#;

#[tokio::test]
async fn registration_is_rate_limited_per_address() {
    let mut cfg = common::config();
    cfg.oauth_dcr_rate_per_hour = 3;
    let hub = TestHub::new(cfg);
    let body: Value = serde_json::from_str(CLIENT).unwrap();
    for _ in 0..3 {
        assert_eq!(hub.send(register_from("192.0.2.10:5000", &body)).await.status(), StatusCode::CREATED);
    }
    let resp = hub.send(register_from("192.0.2.10:5001", &body)).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    // Another address is unaffected.
    assert_eq!(hub.send(register_from("192.0.2.11:5000", &body)).await.status(), StatusCode::CREATED);
    // Behind a loopback proxy the forwarded address is charged.
    for i in 0..3 {
        let mut req = register_from("127.0.0.1:40000", &body);
        req.headers_mut().insert("x-forwarded-for", format!("198.51.100.{i}").parse().unwrap());
        assert_eq!(hub.send(req).await.status(), StatusCode::CREATED);
    }
}

#[tokio::test]
async fn a_registration_flood_cannot_lock_out_clients() {
    let mut cfg = common::config();
    cfg.oauth_dcr_rate_per_hour = u32::MAX;
    let hub = TestHub::new(cfg);
    let body: Value = serde_json::from_str(CLIENT).unwrap();
    // A client that completed sign-in.
    let resp = hub.send(register_from("192.0.2.20:1", &body)).await;
    let granted = json_body(resp).await["client_id"].as_str().unwrap().to_string();
    grant(&hub, &granted);
    let max = ua_server::oauth::register::MAX_UNUSED_CLIENTS as usize;
    for i in 0..max + 5 {
        let resp = hub.send(register_from(&format!("192.0.2.21:{}", 1000 + i), &body)).await;
        assert_eq!(resp.status(), StatusCode::CREATED, "registration {i} was refused");
    }
    let ids = client_ids(&hub);
    assert_eq!(ids.len(), max + 1, "unused clients are capped, the granted one is extra");
    assert!(ids.contains(&granted), "a client with a grant is never evicted");
    // A legitimate registration after the flood still works.
    let resp = hub.send(register_from("192.0.2.22:1", &body)).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn pruning_frees_room_and_keeps_used_clients() {
    let hub = TestHub::new(common::config());
    let body: Value = serde_json::from_str(CLIENT).unwrap();
    let mut ids = Vec::new();
    for i in 0..3 {
        let resp = hub.send(register_from(&format!("192.0.2.30:{i}"), &body)).await;
        ids.push(json_body(resp).await["client_id"].as_str().unwrap().to_string());
    }
    grant(&hub, &ids[0]);
    // Age the first two past the TTL.
    hub.state
        .hub
        .db()
        .write(|tx| {
            tx.execute(
                "UPDATE oauth_clients SET created_at = '2000-01-01T00:00:00+00:00' WHERE client_id IN (?1, ?2)",
                rusqlite::params![ids[0], ids[1]],
            )?;
            Ok(())
        })
        .unwrap();
    let pruned = ua_server::oauth::register::prune_unused_clients(&hub.state.hub).await.unwrap();
    assert_eq!(pruned, 1);
    let left = client_ids(&hub);
    assert!(left.contains(&ids[0]), "granted: kept however old");
    assert!(!left.contains(&ids[1]), "old and never granted: pruned");
    assert!(left.contains(&ids[2]), "fresh: kept");
    let events = hub
        .state
        .hub
        .db()
        .read(|c| {
            ledger::query(
                c,
                &ledger::EventQuery {
                    channels: Some(vec!["agent.oauth.clients_pruned".into()]),
                    ..Default::default()
                },
            )
        })
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].payload["count"], 1);
}

// --- GitHub webhook ---------------------------------------------------------------------

const WEBHOOK_SECRET: &str = "webhook-secret-for-tests";

fn webhook(body: &Value, delivery: &str, event: &str, secret: &str) -> Request<Body> {
    let sig = ua_tools::families::github::signature_for(secret.as_bytes(), body.to_string().as_bytes());
    post_json(
        "/api/github/webhook",
        body,
        &[("x-github-event", event), ("x-github-delivery", delivery), ("x-hub-signature-256", &sig)],
    )
}

#[tokio::test]
async fn the_github_webhook_authenticates_by_signature_and_refuses_replays() {
    let mut cfg = stream_config();
    cfg.github_webhook_secret_value = Some(SecretString::from(WEBHOOK_SECRET));
    let hub = TestHub::new(cfg);
    let reg = &hub.state.registry;
    let human = Caller {
        label: "operator".into(),
        kind: ActorKind::Human,
        profile: Profile::Operator,
        enforce_profile: false,
        session_key: None,
        transport: Transport::Internal,
        org_id: ua_core::DEFAULT_ORG.into(),
    };
    reg.call(
        &hub.state.hub,
        &human,
        "coordination_manage",
        json!({ "action": "project_repo_bind", "params": { "project": "default", "repo": "example/repo" } }),
    )
    .await
    .unwrap();
    let task = reg
        .call(
            &hub.state.hub,
            &human,
            "task_add",
            json!({ "title": "feature", "notes": "closes: example/repo#4" }),
        )
        .await
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let merge = "0123456789abcdef0123456789abcdef01234567";
    let payload = json!({
        "action": "closed",
        "pull_request": { "number": 4, "merged": true, "merge_commit_sha": merge,
                          "head": { "ref": "feature" }, "base": { "ref": "main" },
                          "html_url": "https://github.com/example/repo/pull/4" },
        "repository": { "full_name": "example/repo", "default_branch": "main" },
    });

    // No bearer is needed, but the signature is.
    let resp = hub.send(webhook(&payload, "delivery-1", "pull_request", "wrong-secret")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(resp).await["error"], "bad_signature");
    let resp = hub.send(webhook(&payload, "delivery-1", "pull_request", WEBHOOK_SECRET)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["result"]["closed"][0]["task_id"], task, "{v}");
    let status: (String, Option<String>) = hub
        .state
        .hub
        .db()
        .read(move |c| {
            Ok(c.query_row("SELECT status, evidence_ref FROM tasks WHERE id = ?1", [task], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?)
        })
        .unwrap();
    assert_eq!(status, ("done".to_string(), Some(merge.to_string())));
    // The same delivery again is refused.
    let resp = hub.send(webhook(&payload, "delivery-1", "pull_request", WEBHOOK_SECRET)).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(resp).await["error"], "replayed");
    // So is the same signed body under a fresh delivery id (the headers are not signed).
    let resp = hub.send(webhook(&payload, "delivery-2", "pull_request", WEBHOOK_SECRET)).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(resp).await["error"], "replayed");
    // A form-encoded body never reaches the handler.
    let req = Request::post("/api/github/webhook")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-github-event", "ping")
        .body(Body::from("payload=%7B%7D"))
        .unwrap();
    assert_eq!(hub.send(req).await.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // Other /api routes still need a bearer.
    let resp = hub.send(post_json("/api/tools/task_list", &json!({}), &[])).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Without a configured secret the endpoint refuses everything.
    let hub2 = TestHub::new(stream_config());
    let resp = hub2.send(webhook(&payload, "delivery-2", "pull_request", WEBHOOK_SECRET)).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

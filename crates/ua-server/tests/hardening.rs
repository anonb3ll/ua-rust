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
const OPERATOR: &str = "operator-test-token-0003";

/// Two agents with tokens: `agent-a` on the default profile, `agent-b` on
/// `public`, which does not include `event_log_query`.
fn stream_config() -> Config {
    let mut cfg = common::config();
    cfg.oauth_enabled = false;
    cfg.agent_tokens =
        Some(SecretString::from(format!("agent-a:{AGENT_A},agent-b:{AGENT_B},operator:{OPERATOR}")));
    cfg.profiles.insert("agent-b".into(), "public".into());
    cfg
}

fn append(hub: &TestHub, channel: &str, i: usize) -> i64 {
    hub.state
        .hub
        .db()
        .write(|tx| ledger::append(tx, EventInput::new(channel, json!({ "i": i })).by("tester")))
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

#[tokio::test]
async fn a_backfill_that_cannot_be_complete_says_so() {
    let hub = TestHub::new(stream_config());
    let resp = hub.send(get("/api/events/stream?channel_prefix=test.keep", None, Some(AGENT_A))).await;
    let mut last = 0;
    for i in 0..1100 {
        last = append(&hub, "test.keep", i);
    }
    let text = read_sse(resp, |t| t.contains(&format!("id: {last}"))).await;
    assert!(text.contains("event: gap"), "a lost range must be visible");
    let gap: Value = text
        .split("event: gap\n")
        .nth(1)
        .and_then(|rest| rest.lines().next())
        .and_then(|l| l.strip_prefix("data: "))
        .map(|d| serde_json::from_str(d).unwrap())
        .unwrap();
    assert_eq!(gap["reason"], "backfill_limit");
    assert!(gap["until_seq"].as_i64().unwrap() > gap["after_seq"].as_i64().unwrap());
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

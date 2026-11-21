//! The Slack routes, end to end through the full router: signature first,
//! then admission (identity allowlist, replay, dedupe), then the command
//! through the governed registry path as the mapped identity.
//!
//! Requests are built here in the shapes Slack sends (form-encoded slash
//! commands, JSON Events API callbacks) and signed with a test secret. The
//! ids are made up.

mod common;

use axum::body::Body;
use axum::http::{Request, header};
use common::{TestHub, json_body, text_body};
use secrecy::SecretString;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, SlackIdentity, identity::Transport};
use ua_tools::families::slack;

const SECRET: &str = "test-signing-secret";
const TEAM: &str = "T0TEAM1";
/// Maps to the human `operator` (profile coordinator).
const HUMAN: &str = "U0HUMAN";
/// Maps to the agent `builder-1` (profile developer).
const DEV: &str = "U0DEV";
/// Maps to the agent `builder-2` (profile coordinator).
const AGENT: &str = "U0AGENT";
/// Not mapped.
const STRANGER: &str = "U0STRANGER";

fn map(user: &str, identity: &str) -> SlackIdentity {
    SlackIdentity { team_id: TEAM.into(), user_id: user.into(), identity: identity.into() }
}

fn slack_config() -> Config {
    let mut cfg = common::config();
    cfg.slack_enabled = true;
    cfg.slack_signing_secret = Some(SecretString::from(SECRET.to_string()));
    cfg.profiles.insert("operator".into(), "coordinator".into());
    cfg.profiles.insert("builder-1".into(), "developer".into());
    cfg.profiles.insert("builder-2".into(), "coordinator".into());
    cfg.approval_tools = vec!["task_delete".into()];
    cfg.slack_identities = vec![map(HUMAN, "operator"), map(DEV, "builder-1"), map(AGENT, "builder-2")];
    cfg.check_slack_identities().unwrap();
    cfg
}

fn now() -> i64 {
    ua_core::time::now_ms() / 1000
}

fn raw_request(path: &str, content_type: &str, body: Vec<u8>, headers: &[(&str, String)]) -> Request<Body> {
    let mut b = Request::post(path)
        .header(header::HOST, "hub.example.com")
        .header(header::CONTENT_TYPE, content_type);
    for (k, v) in headers {
        b = b.header(*k, v);
    }
    b.body(Body::from(body)).unwrap()
}

/// A request signed with `secret` at `ts`.
fn signed_with(secret: &str, path: &str, content_type: &str, body: &[u8], ts: i64) -> Request<Body> {
    let ts = ts.to_string();
    let sig = slack::slack_signature(secret, &ts, body);
    raw_request(
        path,
        content_type,
        body.to_vec(),
        &[("x-slack-request-timestamp", ts), ("x-slack-signature", sig)],
    )
}

fn signed(path: &str, content_type: &str, body: &[u8], ts: i64) -> Request<Body> {
    signed_with(SECRET, path, content_type, body, ts)
}

const FORM: &str = "application/x-www-form-urlencoded";

/// A slash command body in Slack's shape. `user_name` is set to a label the
/// hub knows, to show it is never read.
fn command_body(user: &str, command: &str, text: &str, trigger: &str) -> Vec<u8> {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("token", "deprecated-verification-token")
        .append_pair("team_id", TEAM)
        .append_pair("team_domain", "example")
        .append_pair("channel_id", "C0CHANNEL")
        .append_pair("channel_name", "general")
        .append_pair("user_id", user)
        .append_pair("user_name", "operator")
        .append_pair("command", command)
        .append_pair("text", text)
        .append_pair("api_app_id", "A0APP")
        .append_pair("trigger_id", trigger)
        .finish()
        .into_bytes()
}

fn command(user: &str, cmd: &str, text: &str, trigger: &str) -> Request<Body> {
    signed(slack_api_commands(), FORM, &command_body(user, cmd, text, trigger), now())
}

fn slack_api_commands() -> &'static str {
    ua_server::slack_api::COMMANDS_PATH
}

fn slack_api_events() -> &'static str {
    ua_server::slack_api::EVENTS_PATH
}

/// An Events API `event_callback` envelope in Slack's shape.
fn event_body(user: &str, event_id: &str, event_type: &str, text: &str) -> Vec<u8> {
    json!({
        "token": "deprecated-verification-token",
        "team_id": TEAM,
        "api_app_id": "A0APP",
        "type": "event_callback",
        "event_id": event_id,
        "event_time": now(),
        "event": {
            "type": event_type,
            "user": user,
            "text": text,
            "ts": "1700000000.000100",
            "channel": "C0CHANNEL",
            "event_ts": "1700000000.000100",
        },
    })
    .to_string()
    .into_bytes()
}

/// Wait for every command acknowledged so far to finish its work.
async fn settle(h: &TestHub) {
    h.state.calls.close();
    h.state.calls.wait().await;
    h.state.calls.reopen();
}

async fn scalar(h: &TestHub, sql: &'static str) -> i64 {
    h.state.hub.db().read_async(move |c| Ok(c.query_row(sql, [], |r| r.get(0))?)).await.unwrap()
}

/// Rows changed on the database connection since it opened (SQLite's
/// `total_changes()`, which counts rolled-back changes too). In memory the
/// hub has one connection, so an unchanged value means nothing was written.
async fn total_changes(h: &TestHub) -> i64 {
    scalar(h, "SELECT total_changes()").await
}

/// Ledger events on `channel`: (originator, payload).
async fn events(h: &TestHub, channel: &'static str) -> Vec<(String, Value)> {
    h.state
        .hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(
                "SELECT COALESCE(originator, ''), payload FROM event_log WHERE channel = ?1 ORDER BY seq",
            )?;
            let rows = stmt
                .query_map([channel], |r| {
                    let p: String = r.get(1)?;
                    Ok((r.get::<_, String>(0)?, serde_json::from_str(&p).unwrap_or(Value::Null)))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .unwrap()
}

async fn task_count(h: &TestHub) -> i64 {
    scalar(h, "SELECT COUNT(*) FROM tasks").await
}

fn agent(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: None,
        transport: Transport::Mcp,
    }
}

fn human(label: &str) -> Caller {
    Caller { kind: ActorKind::Human, profile: Profile::Coordinator, ..agent(label) }
}

/// A pending approval requested by `requester`: a gated `task_delete`.
async fn pending_approval(h: &TestHub, requester: &Caller) -> i64 {
    let reg = &h.state.registry;
    let task = reg.call(&h.state.hub, requester, "task_add", json!({ "title": "to delete" })).await.unwrap();
    let err = reg
        .call(&h.state.hub, requester, "task_delete", json!({ "id": task["id"] }))
        .await
        .expect_err("task_delete is gated");
    match err {
        ua_core::UaError::ApprovalRequired { approval_id, .. } => approval_id,
        other => panic!("expected approval_required, got {other}"),
    }
}

async fn approval(h: &TestHub, id: i64) -> (String, Option<String>) {
    h.state
        .hub
        .db()
        .read_async(move |c| {
            Ok(c.query_row("SELECT status, resolved_by FROM approvals WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?)
        })
        .await
        .unwrap()
}

/// The `executed` events, by originator.
async fn executed(h: &TestHub) -> Vec<(String, Value)> {
    events(h, "agent.slack.request.executed").await
}

// --- mounting -------------------------------------------------------------------

#[tokio::test]
async fn the_routes_are_off_by_default() {
    let mut cfg = common::config();
    cfg.slack_signing_secret = Some(SecretString::from(SECRET.to_string()));
    cfg.slack_identities = vec![map(HUMAN, "operator")];
    assert!(!cfg.slack_enabled);
    let h = TestHub::new(cfg);
    let r = h.send(command(HUMAN, "/contact", "", "1.2.a")).await;
    assert_eq!(r.status(), 404, "{}", text_body(r).await);
    let r = h
        .send(signed(
            slack_api_events(),
            "application/json",
            &event_body(HUMAN, "Ev01", "app_mention", "/contact"),
            now(),
        ))
        .await;
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn enabled_without_a_secret_the_routes_do_not_exist() {
    let mut cfg = slack_config();
    cfg.slack_signing_secret = None;
    let h = TestHub::new(cfg);
    assert_eq!(h.send(command(HUMAN, "/contact", "", "1.2.a")).await.status(), 404);
    let body = json!({ "type": "url_verification", "challenge": "abc" }).to_string();
    assert_eq!(
        h.send(signed(slack_api_events(), "application/json", body.as_bytes(), now())).await.status(),
        404
    );
}

// --- signature before state -----------------------------------------------------

#[tokio::test]
async fn every_bad_signature_is_a_401_before_any_database_write() {
    let h = TestHub::new(slack_config());
    let body = command_body(HUMAN, "/task", "write the report", "1.2.a");
    let ts = now().to_string();
    let good = slack::slack_signature(SECRET, &ts, &body);
    let cases: Vec<(&str, Vec<(&str, String)>)> = vec![
        ("missing both headers", vec![]),
        ("missing signature", vec![("x-slack-request-timestamp", ts.clone())]),
        ("missing timestamp", vec![("x-slack-signature", good.clone())]),
        (
            "malformed signature",
            vec![("x-slack-request-timestamp", ts.clone()), ("x-slack-signature", "v1=abc".into())],
        ),
        (
            "uppercase hex",
            vec![
                ("x-slack-request-timestamp", ts.clone()),
                ("x-slack-signature", good.to_uppercase().replace("V0=", "v0=")),
            ],
        ),
        (
            "malformed timestamp",
            vec![("x-slack-request-timestamp", format!("{ts}x")), ("x-slack-signature", good.clone())],
        ),
        (
            "stale",
            vec![
                ("x-slack-request-timestamp", (now() - 301).to_string()),
                ("x-slack-signature", slack::slack_signature(SECRET, &(now() - 301).to_string(), &body)),
            ],
        ),
        (
            "wrong secret",
            vec![
                ("x-slack-request-timestamp", ts.clone()),
                ("x-slack-signature", slack::slack_signature("other", &ts, &body)),
            ],
        ),
        (
            "signature of another body",
            vec![
                ("x-slack-request-timestamp", ts.clone()),
                ("x-slack-signature", slack::slack_signature(SECRET, &ts, b"x")),
            ],
        ),
    ];
    let before = total_changes(&h).await;
    let ledger_before = scalar(&h, "SELECT COUNT(*) FROM event_log").await;
    for (name, headers) in cases {
        for path in [slack_api_commands(), slack_api_events()] {
            let r = h.send(raw_request(path, FORM, body.clone(), &headers)).await;
            assert_eq!(r.status(), 401, "{name} on {path}");
        }
    }
    settle(&h).await;
    assert_eq!(total_changes(&h).await, before, "a refused signature wrote to the database");
    assert_eq!(scalar(&h, "SELECT COUNT(*) FROM event_log").await, ledger_before);
    assert_eq!(scalar(&h, "SELECT COUNT(*) FROM slack_seen_signatures").await, 0);
    assert_eq!(task_count(&h).await, 0);
}

#[tokio::test]
async fn an_oversized_body_is_refused_before_anything_else() {
    let h = TestHub::new(slack_config());
    let before = total_changes(&h).await;
    let mut body = command_body(HUMAN, "/task", "x", "1.2.a");
    body.resize(slack::MAX_BODY_BYTES + 1, b'a');
    let r = h.send(signed(slack_api_commands(), FORM, &body, now())).await;
    assert_eq!(r.status(), 413);
    let r = h.send(signed(slack_api_events(), "application/json", &body, now())).await;
    assert_eq!(r.status(), 413);
    assert_eq!(total_changes(&h).await, before);
}

#[tokio::test]
async fn a_replayed_signed_request_is_refused() {
    let h = TestHub::new(slack_config());
    let body = command_body(DEV, "/task", "write the report", "1.2.a");
    let ts = now();
    let first = h.send(signed(slack_api_commands(), FORM, &body, ts)).await;
    assert_eq!(first.status(), 200);
    let again = h.send(signed(slack_api_commands(), FORM, &body, ts)).await;
    assert_eq!(again.status(), 401, "the same signed bytes are accepted once");
    settle(&h).await;
    assert_eq!(task_count(&h).await, 1);
    assert_eq!(scalar(&h, "SELECT COUNT(*) FROM slack_seen_signatures").await, 1);
}

// --- url_verification -----------------------------------------------------------

#[tokio::test]
async fn url_verification_is_answered_only_when_signed() {
    let h = TestHub::new(slack_config());
    let body = json!({ "token": "x", "challenge": "3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P", "type": "url_verification" })
        .to_string();
    let r = h.send(signed(slack_api_events(), "application/json", body.as_bytes(), now())).await;
    assert_eq!(r.status(), 200);
    assert_eq!(json_body(r).await["challenge"], "3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P");
    let r =
        h.send(signed_with("other", slack_api_events(), "application/json", body.as_bytes(), now())).await;
    assert_eq!(r.status(), 401);
    let r = h.send(raw_request(slack_api_events(), "application/json", body.into_bytes(), &[])).await;
    assert_eq!(r.status(), 401);
}

// --- identity -------------------------------------------------------------------

#[tokio::test]
async fn an_unmapped_user_is_refused_with_no_side_effects() {
    let h = TestHub::new(slack_config());
    // user_name says "operator"; the pair (team, user) is not mapped.
    let ledger_before = scalar(&h, "SELECT COUNT(*) FROM event_log").await;
    let r = h.send(command(STRANGER, "/task", "write the report", "1.2.a")).await;
    assert_eq!(r.status(), 200);
    let text = json_body(r).await["text"].as_str().unwrap().to_string();
    assert!(text.contains("not mapped"), "{text}");
    // The same user id in another workspace is not the mapped user either.
    let mut other_team = String::from_utf8(command_body(HUMAN, "/task", "x", "1.2.b")).unwrap();
    other_team = other_team.replace(TEAM, "T0OTHER");
    let r = h.send(signed(slack_api_commands(), FORM, other_team.as_bytes(), now())).await;
    assert!(json_body(r).await["text"].as_str().unwrap().contains("not mapped"));
    settle(&h).await;
    assert_eq!(task_count(&h).await, 0);
    assert_eq!(scalar(&h, "SELECT COUNT(*) FROM tool_calls").await, 0);
    assert_eq!(scalar(&h, "SELECT COUNT(*) FROM slack_seen_deliveries").await, 0);
    assert_eq!(scalar(&h, "SELECT COUNT(*) FROM event_log").await, ledger_before, "no ledger row");
    assert!(executed(&h).await.is_empty());
    assert!(events(&h, "agent.slack.request.accepted").await.is_empty());
}

#[tokio::test]
async fn user_name_is_never_identity() {
    let h = TestHub::new(slack_config());
    let id = pending_approval(&h, &agent("builder-9")).await;
    // builder-1's Slack user, with user_name "operator" in the body.
    let r = h.send(command(DEV, "/approve", &id.to_string(), "1.2.a")).await;
    assert_eq!(r.status(), 200);
    settle(&h).await;
    assert_eq!(approval(&h, id).await.0, "pending", "a developer agent cannot approve");
    let ran = executed(&h).await;
    assert_eq!(ran.len(), 1);
    assert_eq!(ran[0].0, "builder-1", "attributed to the mapped identity, not user_name");
    assert_eq!(ran[0].1["ok"], false);
}

// --- dedupe ----------------------------------------------------------------------

#[tokio::test]
async fn a_repeated_trigger_id_runs_once() {
    let h = TestHub::new(slack_config());
    let body = command_body(DEV, "/task", "write the report", "1.2.a");
    let first = h.send(signed(slack_api_commands(), FORM, &body, now())).await;
    assert!(json_body(first).await["text"].as_str().unwrap().starts_with("Accepted /task"));
    // A new signature (other timestamp) over the same trigger id.
    let retry = h.send(signed(slack_api_commands(), FORM, &body, now() - 1)).await;
    assert_eq!(retry.status(), 200);
    assert_eq!(json_body(retry).await["text"], "Already received.");
    settle(&h).await;
    assert_eq!(task_count(&h).await, 1);
    let deduped = events(&h, "agent.slack.request.deduped").await;
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].0, "builder-1");
    assert_eq!(deduped[0].1["kind"], "command");
}

#[tokio::test]
async fn a_retried_event_id_runs_once() {
    let h = TestHub::new(slack_config());
    let body = event_body(DEV, "Ev0RETRY1", "app_mention", "<@U0BOT> /task write the report");
    let first = h.send(signed(slack_api_events(), "application/json", &body, now())).await;
    assert_eq!(first.status(), 200);
    // Slack's retry: same event_id, new timestamp and signature.
    let mut retry = signed(slack_api_events(), "application/json", &body, now() - 2);
    retry.headers_mut().insert("x-slack-retry-num", "1".parse().unwrap());
    assert_eq!(h.send(retry).await.status(), 200);
    settle(&h).await;
    assert_eq!(task_count(&h).await, 1);
    assert_eq!(events(&h, "agent.slack.request.deduped").await.len(), 1);
    assert_eq!(events(&h, "agent.slack.request.deduped").await[0].1["kind"], "event");
}

#[tokio::test]
async fn events_that_are_not_explicit_commands_change_nothing() {
    let h = TestHub::new(slack_config());
    let before = total_changes(&h).await;
    for (i, (kind, text)) in [
        ("app_mention", "<@U0BOT> task status is confusing"),
        ("message", "/task in a channel, not a direct message"),
        ("reaction_added", "/task"),
    ]
    .into_iter()
    .enumerate()
    {
        let body = event_body(DEV, &format!("Ev0IGN{i}"), kind, text);
        assert_eq!(h.send(signed(slack_api_events(), "application/json", &body, now())).await.status(), 200);
    }
    settle(&h).await;
    assert_eq!(total_changes(&h).await, before);
}

// --- governed execution ----------------------------------------------------------

#[tokio::test]
async fn a_command_runs_through_the_governed_path_as_the_mapped_identity() {
    let h = TestHub::new(slack_config());
    let r = h.send(command(DEV, "/task", "write the &lt;quarterly&gt; report", "1.2.a")).await;
    assert_eq!(r.status(), 200);
    settle(&h).await;
    let title: String = h
        .state
        .hub
        .db()
        .read_async(|c| Ok(c.query_row("SELECT title FROM tasks", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(title, "write the <quarterly> report");
    let (caller, transport): (String, String) = h
        .state
        .hub
        .db()
        .read_async(|c| {
            Ok(c.query_row("SELECT caller, transport FROM tool_calls WHERE tool = 'task_add'", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?)
        })
        .await
        .unwrap();
    assert_eq!(caller, "builder-1");
    assert_eq!(transport, "http");
    let accepted = events(&h, "agent.slack.request.accepted").await;
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].0, "builder-1");
    assert_eq!(accepted[0].1["command"], "task");
    let ran = executed(&h).await;
    assert_eq!(ran.len(), 1);
    assert_eq!(ran[0].0, "builder-1");
    assert_eq!(ran[0].1["tool"], "task_add");
    assert_eq!(ran[0].1["ok"], true);
    let created = events(&h, "agent.task.created").await;
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].0, "builder-1");
    // Neither the body nor the secret nor the signature reaches the ledger.
    let all: String = h
        .state
        .hub
        .db()
        .read_async(|c| {
            Ok(c.query_row(
                "SELECT group_concat(payload, ' ') FROM event_log WHERE channel LIKE 'agent.slack.%'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(!all.contains(SECRET) && !all.contains("v0=") && !all.contains("quarterly"), "{all}");
}

#[tokio::test]
async fn the_profile_still_applies_to_slack_commands() {
    let h = TestHub::new(slack_config());
    // builder-1 is a developer: approval_resolve is not in its profile.
    let id = pending_approval(&h, &agent("builder-9")).await;
    h.send(command(DEV, "/approve", &id.to_string(), "1.2.a")).await;
    settle(&h).await;
    let ran = executed(&h).await;
    assert_eq!(ran[0].1["reason_code"], "profile_denied");
}

#[tokio::test]
async fn an_invalid_command_is_refused_and_ledgered() {
    let h = TestHub::new(slack_config());
    let r = h.send(command(DEV, "/hub", "deploy everything", "1.2.a")).await;
    let text = json_body(r).await["text"].as_str().unwrap().to_string();
    assert!(text.contains("Unsupported"), "{text}");
    settle(&h).await;
    let refused = events(&h, "agent.slack.request.refused").await;
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].0, "builder-1");
    assert_eq!(refused[0].1["reason"], "invalid_command");
    assert!(executed(&h).await.is_empty());
    // A single app command carrying the command in its text works.
    let r = h.send(command(DEV, "/hub", "contact", "1.2.b")).await;
    let text = json_body(r).await["text"].as_str().unwrap().to_string();
    assert!(text.contains("builder-1"), "{text}");
}

// --- approvals --------------------------------------------------------------------

#[tokio::test]
async fn a_mapped_human_approves_as_themselves() {
    let h = TestHub::new(slack_config());
    let id = pending_approval(&h, &agent("builder-9")).await;
    let r = h.send(command(HUMAN, "/approve", &id.to_string(), "1.2.a")).await;
    assert_eq!(r.status(), 200);
    settle(&h).await;
    assert_eq!(approval(&h, id).await, ("approved".into(), Some("operator".into())));
    let resolved = events(&h, "agent.approval.resolved").await;
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].0, "operator");
    let ran = executed(&h).await;
    assert_eq!((ran[0].0.as_str(), ran[0].1["ok"].as_bool()), ("operator", Some(true)));
}

#[tokio::test]
async fn a_human_cannot_approve_their_own_request_from_slack() {
    let h = TestHub::new(slack_config());
    let id = pending_approval(&h, &human("operator")).await;
    h.send(command(HUMAN, "/approve", &id.to_string(), "1.2.a")).await;
    settle(&h).await;
    assert_eq!(approval(&h, id).await.0, "pending");
    assert_eq!(executed(&h).await[0].1["reason_code"], "self_approval");
}

#[tokio::test]
async fn a_mapped_agent_cannot_approve_even_with_a_broad_profile() {
    let h = TestHub::new(slack_config());
    let id = pending_approval(&h, &agent("builder-9")).await;
    // builder-2 is a coordinator: approval_resolve is in its profile, but it
    // is not a human.
    h.send(command(AGENT, "/approve", &id.to_string(), "1.2.a")).await;
    settle(&h).await;
    assert_eq!(approval(&h, id).await.0, "pending");
    let ran = executed(&h).await;
    assert_eq!(ran[0].0, "builder-2");
    assert_eq!(ran[0].1["reason_code"], "not_human");
}

// --- delivery ---------------------------------------------------------------------

#[tokio::test]
async fn a_response_url_off_the_slack_host_is_never_called() {
    let h = TestHub::new(slack_config());
    let mut body = String::from_utf8(command_body(DEV, "/task", "write the report", "1.2.a")).unwrap();
    body.push_str("&response_url=https%3A%2F%2Fhooks.example.com%2Fcommands%2Fx");
    let r = h.send(signed(slack_api_commands(), FORM, body.as_bytes(), now())).await;
    let text = text_body(r).await;
    assert!(text.contains("recorded in the hub ledger"), "{text}");
    settle(&h).await;
    assert_eq!(task_count(&h).await, 1);
    assert!(events(&h, "agent.slack.reply.failed").await.is_empty(), "nothing was attempted");
}

// --- round 1: unmapped traffic, app-posted messages --------------------------------

/// An event body with extra keys on the inner event.
fn event_with(user: &str, event_id: &str, event_type: &str, text: &str, extra: Value) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(&event_body(user, event_id, event_type, text)).unwrap();
    for (k, x) in extra.as_object().unwrap() {
        v["event"][k] = x.clone();
    }
    v.to_string().into_bytes()
}

#[tokio::test]
async fn unmapped_signed_requests_never_grow_the_ledger_and_replays_stay_refused() {
    let h = TestHub::new(slack_config());
    let ledger_before = scalar(&h, "SELECT COUNT(*) FROM event_log").await;
    let ts = now();
    let first_command = command_body(STRANGER, "/task", "write the report", "9.9.0");
    for i in 0..20 {
        let body = if i == 0 {
            first_command.clone()
        } else {
            command_body(STRANGER, "/task", "x", &format!("9.9.{i}"))
        };
        let r = h.send(signed(slack_api_commands(), FORM, &body, ts)).await;
        assert_eq!(r.status(), 200);
        let body = event_body(STRANGER, &format!("Ev0LOOP{i}"), "app_mention", "<@U0BOT> /task x");
        assert_eq!(h.send(signed(slack_api_events(), "application/json", &body, ts)).await.status(), 200);
    }
    settle(&h).await;
    assert_eq!(
        scalar(&h, "SELECT COUNT(*) FROM event_log").await,
        ledger_before,
        "unmapped traffic is not ledgered"
    );
    assert_eq!(task_count(&h).await, 0);
    // The signatures were still remembered: a replay is refused.
    let replay = h.send(signed(slack_api_commands(), FORM, &first_command, ts)).await;
    assert_eq!(replay.status(), 401);
    assert_eq!(scalar(&h, "SELECT COUNT(*) FROM slack_seen_signatures").await, 40);
}

#[tokio::test]
async fn approve_never_comes_through_the_events_api() {
    let h = TestHub::new(slack_config());
    let id = pending_approval(&h, &agent("builder-9")).await;
    let mention = event_body(HUMAN, "Ev0APP1", "app_mention", &format!("<@U0BOT> /approve {id}"));
    let dm =
        event_with(HUMAN, "Ev0APP2", "message", &format!("/approve {id}"), json!({ "channel_type": "im" }));
    for body in [mention, dm] {
        assert_eq!(h.send(signed(slack_api_events(), "application/json", &body, now())).await.status(), 200);
    }
    settle(&h).await;
    assert_eq!(approval(&h, id).await.0, "pending");
    assert!(executed(&h).await.is_empty());
    let refused = events(&h, "agent.slack.request.refused").await;
    assert_eq!(refused.len(), 2);
    for (who, p) in &refused {
        assert_eq!(who, "operator");
        assert_eq!(p["reason"], "approve_needs_slash_command", "the ledger says why");
    }
    // The slash command still approves.
    h.send(command(HUMAN, "/approve", &id.to_string(), "1.2.a")).await;
    settle(&h).await;
    assert_eq!(approval(&h, id).await, ("approved".into(), Some("operator".into())));
}

#[tokio::test]
async fn events_an_app_wrote_are_ignored() {
    let h = TestHub::new(slack_config());
    let before = total_changes(&h).await;
    for (i, extra) in [
        json!({ "app_id": "A0OTHERAPP" }),
        json!({ "bot_profile": { "id": "B0BOT", "app_id": "A0OTHERAPP" } }),
        json!({ "bot_id": "B0BOT" }),
        json!({ "subtype": "bot_message" }),
        json!({ "edited": { "user": HUMAN, "ts": "1700000000.000100" } }),
    ]
    .into_iter()
    .enumerate()
    {
        let body =
            event_with(HUMAN, &format!("Ev0BOT{i}"), "app_mention", "<@U0BOT> /task from an app", extra);
        assert_eq!(h.send(signed(slack_api_events(), "application/json", &body, now())).await.status(), 200);
    }
    settle(&h).await;
    assert_eq!(total_changes(&h).await, before);
    assert_eq!(task_count(&h).await, 0);
}

//! Zulip tools against a local stub that answers like the Zulip API. No test
//! contacts a real Zulip site, and no output includes the bot API key.
//!
//! Sensitive-looking strings (home paths, private addresses, credentials) are
//! assembled at run time so this file itself stays free of them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Form, Json, Router};
use base64::Engine;
use secrecy::SecretString;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_store::ledger::{self, EventQuery};
use ua_tools::{Hub, Registry, builtin_registry};

const KEY: &str = "zulip-test-key";
const EMAIL: &str = "bot@example.com";
const BOT_ID: i64 = 99;

// --- the stub -------------------------------------------------------------------------

#[derive(Clone, Default, Debug)]
struct Hit {
    method: String,
    path: String,
    query: HashMap<String, String>,
    form: HashMap<String, String>,
    auth_ok: bool,
}

#[derive(Default)]
struct Knobs {
    /// HTTP status for a send (200 by default).
    send_status: u16,
    /// Return the anchor message even when `include_anchor=false`.
    ignore_include_anchor: bool,
    /// Pad `users/me` past the reply cap.
    huge_me: bool,
}

struct AppState {
    hits: Arc<Mutex<Vec<Hit>>>,
    knobs: Arc<Mutex<Knobs>>,
    expected_auth: String,
}

fn auth_ok(headers: &HeaderMap, expected: &str) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(expected)
}

fn msg(id: i64, sender_id: i64, email: &str, content: &str) -> Value {
    json!({
        "id": id, "sender_id": sender_id, "sender_email": email, "sender_full_name": "Someone",
        "type": "stream", "subject": "status", "content": content, "timestamp": id,
    })
}

/// The stream's history, oldest first.
fn history() -> Vec<Value> {
    vec![
        msg(10, BOT_ID, EMAIL, "echo"),
        msg(12, 5, "person@example.com", "hello"),
        msg(13, 5, "person@example.com", "next"),
        // The bot under another address: still the bot, by id.
        msg(14, BOT_ID, "renamed-bot@example.com", "echo again"),
        // Another user whose address matches the bot's: not the bot.
        msg(15, 6, EMAIL, "lookalike"),
    ]
}

async fn on_send(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let ok = auth_ok(&headers, &state.expected_auth);
    state.hits.lock().unwrap().push(Hit {
        method: "POST".into(),
        path: "/api/v1/messages".into(),
        form,
        auth_ok: ok,
        ..Hit::default()
    });
    if !ok {
        return (StatusCode::UNAUTHORIZED, Json(json!({"result": "error", "msg": "bad auth"})));
    }
    let status = state.knobs.lock().unwrap().send_status;
    match status {
        200 => (StatusCode::OK, Json(json!({"result": "success", "id": 7}))),
        s => (StatusCode::from_u16(s).unwrap(), Json(json!({"result": "error", "msg": "stub refusal"}))),
    }
}

/// Zulip's window: `num_before` older than the anchor, the anchor itself
/// unless `include_anchor=false`, `num_after` newer.
async fn on_fetch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let ok = auth_ok(&headers, &state.expected_auth);
    state.hits.lock().unwrap().push(Hit {
        method: "GET".into(),
        path: "/api/v1/messages".into(),
        query: query.clone(),
        auth_ok: ok,
        ..Hit::default()
    });
    if !ok {
        return (StatusCode::UNAUTHORIZED, Json(json!({"result": "error"})));
    }
    let all = history();
    let ids: Vec<i64> = all.iter().map(|m| m["id"].as_i64().unwrap()).collect();
    let anchor = match query.get("anchor").map(String::as_str) {
        Some("newest") | None => *ids.last().unwrap(),
        Some(n) => n.parse().unwrap(),
    };
    let n = |k: &str| query.get(k).and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    let include = query.get("include_anchor").map(String::as_str) != Some("false")
        || state.knobs.lock().unwrap().ignore_include_anchor;
    let before: Vec<&Value> = all.iter().filter(|m| m["id"].as_i64().unwrap() < anchor).collect();
    let before = &before[before.len().saturating_sub(n("num_before"))..];
    let at = all.iter().filter(|m| include && m["id"].as_i64().unwrap() == anchor);
    let after = all.iter().filter(|m| m["id"].as_i64().unwrap() > anchor).take(n("num_after"));
    let messages: Vec<&Value> = before.iter().copied().chain(at).chain(after).collect();
    (StatusCode::OK, Json(json!({"result": "success", "messages": messages})))
}

async fn on_me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    let ok = auth_ok(&headers, &state.expected_auth);
    state.hits.lock().unwrap().push(Hit {
        method: "GET".into(),
        path: "/api/v1/users/me".into(),
        auth_ok: ok,
        ..Hit::default()
    });
    let mut me = json!({"result": "success", "user_id": BOT_ID, "email": EMAIL});
    if state.knobs.lock().unwrap().huge_me {
        me["padding"] = json!("x".repeat(200 * 1024));
    }
    (StatusCode::OK, Json(me))
}

struct Server {
    base: String,
    hits: Arc<Mutex<Vec<Hit>>>,
    knobs: Arc<Mutex<Knobs>>,
}

impl Server {
    fn hits(&self) -> Vec<Hit> {
        self.hits.lock().unwrap().clone()
    }

    fn sends(&self) -> Vec<Hit> {
        self.hits().into_iter().filter(|h| h.method == "POST").collect()
    }

    fn fetches(&self) -> Vec<Hit> {
        self.hits().into_iter().filter(|h| h.path == "/api/v1/messages" && h.method == "GET").collect()
    }
}

fn basic_header() -> String {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{EMAIL}:{KEY}"));
    format!("Basic {token}")
}

async fn spawn_server() -> Server {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let knobs = Arc::new(Mutex::new(Knobs { send_status: 200, ..Knobs::default() }));
    let state =
        Arc::new(AppState { hits: hits.clone(), knobs: knobs.clone(), expected_auth: basic_header() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/api/v1/messages", get(on_fetch).post(on_send))
        .route("/api/v1/users/me", get(on_me))
        .with_state(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Server { base: format!("http://{addr}"), hits, knobs }
}

// --- hub helpers ---------------------------------------------------------------------------

struct Env {
    _home: tempfile::TempDir,
    hub: Hub,
    reg: Registry,
}

fn caller(label: &str, kind: ActorKind, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

/// An agent on a profile that may speak publicly.
fn agent() -> Caller {
    caller("speaker-1", ActorKind::Agent, Profile::Coordinator)
}

fn human() -> Caller {
    Caller { enforce_profile: false, ..caller("operator", ActorKind::Human, Profile::Operator) }
}

fn base_config(home: &std::path::Path) -> Config {
    let mut cfg = Config::for_home(home);
    cfg.human_identities = vec!["operator".into()];
    cfg.fetch_allow_loopback = true;
    cfg.zulip_channels = [("ops", "ops"), ("requests", "Requests")]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    cfg.zulip_link_hosts = vec!["docs.example.com".into()];
    cfg.zulip_mention_allowlist = vec!["Jane Doe".into()];
    cfg.zulip_send_calls_per_hour = 1000;
    cfg
}

fn configured_with(site: &str, retired: Option<&str>, f: impl FnOnce(&mut Config)) -> Env {
    let home = tempfile::tempdir().unwrap();
    let mut cfg = base_config(home.path());
    cfg.zulip_site = Some(site.into());
    cfg.zulip_email = Some(EMAIL.into());
    cfg.zulip_api_key = Some(SecretString::from(KEY));
    cfg.zulip_retired = retired.map(str::to_string);
    f(&mut cfg);
    Env { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), _home: home }
}

fn configured(site: &str, retired: Option<&str>) -> Env {
    configured_with(site, retired, |_| {})
}

fn bare() -> Env {
    let home = tempfile::tempdir().unwrap();
    let cfg = base_config(home.path());
    Env { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), _home: home }
}

fn reason(e: &UaError) -> String {
    match e {
        UaError::ApprovalRequired { .. } => "approval_required".into(),
        e => e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string()),
    }
}

fn send_args(topic: &str, content: &str) -> Value {
    json!({"agent_label": "speaker-1", "channel": "requests", "topic": topic, "content": content})
}

impl Env {
    async fn call_as(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn call(&self, tool: &str, args: Value) -> Result<Value, UaError> {
        self.call_as(&agent(), tool, args).await
    }

    async fn send(&self, topic: &str, content: &str) -> Result<Value, UaError> {
        self.call("zulip_send_message", send_args(topic, content)).await
    }

    /// Send `content`: park the approval, approve it as a human, send again.
    async fn approved_send(&self, topic: &str, content: &str) -> Result<Value, UaError> {
        let id = match self.send(topic, content).await {
            Err(UaError::ApprovalRequired { approval_id, .. }) => approval_id,
            other => panic!("expected an approval request, got {other:?}"),
        };
        self.call_as(&human(), "approval_resolve", json!({"id": id, "decision": "approve"})).await.unwrap();
        self.send(topic, content).await
    }

    async fn fetch(&self, args: Value) -> Value {
        let mut a = json!({"agent_label": "speaker-1", "channel": "ops"});
        a.as_object_mut().unwrap().extend(args.as_object().unwrap().clone());
        self.call("zulip_fetch_messages", a).await.unwrap()
    }

    async fn events(&self, channel: &str) -> Vec<ledger::Event> {
        let q = EventQuery { channels: Some(vec![channel.to_string()]), ..Default::default() };
        self.hub.db().read_async(move |c| ledger::query(c, &q)).await.unwrap()
    }

    async fn pending_approvals(&self) -> i64 {
        self.hub
            .db()
            .read_async(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM approvals WHERE tool = 'zulip_send_message' AND status = 'pending'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap()
    }
}

fn assert_no_secret(value: &impl std::fmt::Display) {
    assert!(!value.to_string().contains(KEY), "tool output included the API key");
}

// --- configuration and profiles ----------------------------------------------------------------

#[tokio::test]
async fn unconfigured_tools_make_no_request() {
    let server = spawn_server().await;
    let env = bare();
    let send = env.send("t", "hi").await.unwrap_err();
    let fetch = env
        .call("zulip_fetch_messages", json!({"agent_label": "speaker-1", "channel": "ops"}))
        .await
        .unwrap_err();
    assert!(send.to_string().contains("not configured"), "{send}");
    assert!(fetch.to_string().contains("not configured"), "{fetch}");
    assert_no_secret(&send);
    assert_no_secret(&fetch);
    assert!(server.hits().is_empty());
}

#[tokio::test]
async fn retired_send_does_not_call_the_network() {
    let server = spawn_server().await;
    let env = configured(&server.base, None);
    let err = env.send("t", "hi").await.unwrap_err();
    assert!(err.to_string().contains("retired"), "{err}");
    assert_no_secret(&err);
    assert!(server.hits().is_empty());
    assert_eq!(env.pending_approvals().await, 0);
}

#[tokio::test]
async fn developer_lead_and_reviewer_cannot_send() {
    let server = spawn_server().await;
    let env = configured(&server.base, Some("0"));
    for (label, profile) in
        [("builder-1", Profile::Developer), ("lead-1", Profile::Lead), ("reviewer-1", Profile::Reviewer)]
    {
        let who = caller(label, ActorKind::Agent, profile);
        let mut args = send_args("t", "hi");
        args["agent_label"] = json!(label);
        let err = env.call_as(&who, "zulip_send_message", args).await.unwrap_err();
        assert_eq!(reason(&err), "profile_denied", "{profile:?}: {err}");
        let resolve = env
            .call_as(&who, "zulip_resolve_send", json!({"send_id": 1, "outcome": "delivered"}))
            .await
            .unwrap_err();
        assert_eq!(reason(&resolve), "profile_denied", "{profile:?}: {resolve}");
    }
    assert!(server.hits().is_empty());
    assert_eq!(env.pending_approvals().await, 0);
}

#[tokio::test]
async fn channels_come_from_config() {
    let server = spawn_server().await;
    let env = configured(&server.base, Some("false"));
    let err = env
        .call(
            "zulip_send_message",
            json!({"agent_label": "speaker-1", "channel": "coord", "topic": "t", "content": "hi"}),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("zulip_channels: ops, requests"), "{err}");

    // Without a table, the one channel is `general`.
    let env = configured_with(&server.base, Some("false"), |c| c.zulip_channels.clear());
    let mut args = send_args("t", "hi");
    args["channel"] = json!("general");
    assert_eq!(reason(&env.call("zulip_send_message", args).await.unwrap_err()), "approval_required");
    let ops = env.send("t", "hi").await.unwrap_err();
    assert!(ops.to_string().contains("zulip_channels: general"), "{ops}");
    assert!(server.hits().is_empty());
}

// --- approval binding ---------------------------------------------------------------------------

#[tokio::test]
async fn send_needs_a_human_approval_of_the_exact_text() {
    let server = spawn_server().await;
    let env = configured(&server.base, Some("0"));
    // Leading and trailing whitespace are part of the approved bytes.
    let content = "Build is green.\n\nSee the [notes](https://docs.example.com/ci).  \n";
    let first = env.send("status", content).await.unwrap_err();
    let approval_id = match first {
        UaError::ApprovalRequired { approval_id, .. } => approval_id,
        other => panic!("expected an approval request, got {other:?}"),
    };
    assert!(server.sends().is_empty(), "nothing is sent before a human approves");

    // The pending approval shows the exact text and binds its hash.
    let pending = env.call_as(&human(), "approval_pending", json!({})).await.unwrap();
    let row = pending["pending"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["id"] == approval_id))
        .cloned()
        .unwrap_or_else(|| panic!("approval {approval_id} not listed: {pending}"));
    let payload = &row["payload"];
    assert_eq!(payload["content"], content);
    assert_eq!(payload["stream"], "Requests");
    assert_eq!(payload["topic"], "status");
    assert_eq!(payload["content_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(payload["link_hosts"], json!(["docs.example.com"]));

    // An agent cannot approve its own send.
    let own = env.call("approval_resolve", json!({"id": approval_id, "decision": "approve"})).await;
    assert!(own.is_err(), "the requester must not approve its own send");
    env.call_as(&human(), "approval_resolve", json!({"id": approval_id, "decision": "approve"}))
        .await
        .unwrap();

    // Another text, or another topic, does not ride on that approval.
    let other_text = env.send("status", "Build is green.").await.unwrap_err();
    assert_eq!(reason(&other_text), "approval_required");
    let other_topic = env.send("other", content).await.unwrap_err();
    assert_eq!(reason(&other_topic), "approval_required");
    assert!(server.sends().is_empty());

    let sent = env.send("status", content).await.unwrap();
    assert_eq!(sent["sent"], true, "{sent}");
    assert_eq!(sent["message_id"], 7);
    assert_eq!(sent["approval_id"], approval_id);
    assert_no_secret(&sent);
    let sends = server.sends();
    assert_eq!(sends.len(), 1);
    assert!(sends[0].auth_ok, "stub rejected the basic-auth header");
    assert_eq!(sends[0].form.get("to").map(String::as_str), Some("Requests"));
    assert_eq!(sends[0].form.get("topic").map(String::as_str), Some("status"));
    assert_eq!(sends[0].form.get("content").map(String::as_str), Some(content));
    assert_eq!(sends[0].form.get("type").map(String::as_str), Some("stream"));

    // The pass is spent: the same text needs a new decision.
    let again = env.send("status", content).await.unwrap_err();
    assert_eq!(reason(&again), "approval_required");
    assert_eq!(server.sends().len(), 1);

    let events = env.events("agent.zulip.sent").await;
    assert_eq!(events.len(), 1);
    let p = &events[0].payload;
    assert_eq!(p["chars"], content.chars().count());
    assert_eq!(p["bytes"], content.len());
    assert_eq!(p["content_sha256"].as_str().unwrap().len(), 64);
    assert!(!p.to_string().contains("Build is green"), "the ledger never holds the text: {p}");
}

#[tokio::test]
async fn send_calls_are_rate_limited_per_caller() {
    let server = spawn_server().await;
    let env = configured_with(&server.base, Some("0"), |c| c.zulip_send_calls_per_hour = 2);
    for text in ["one", "two"] {
        assert_eq!(reason(&env.send("t", text).await.unwrap_err()), "approval_required");
    }
    let third = env.send("t", "three").await.unwrap_err();
    assert_eq!(reason(&third), "rate_limited", "{third}");
    assert_eq!(env.pending_approvals().await, 2);
}

// --- outbound gates ---------------------------------------------------------------------------

#[tokio::test]
async fn gates_refuse_unsafe_text_and_topics_before_any_approval() {
    let server = spawn_server().await;
    let env = configured(&server.base, Some("0"));
    let home = format!("/{}/{}/notes.txt", "home", "alice");
    let private = format!("http://{}.{}.{}.{}:8080/", 10, 0, 0, 1);
    let token = format!("{}{}", "ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
    let bidi = format!("fine {} text", '\u{202E}');
    let cases: Vec<(String, String, &str)> = vec![
        ("t".into(), format!("token {token}"), "secret"),
        ("t".into(), bidi, "hidden_unicode"),
        ("t".into(), format!("see {private}"), "private_address"),
        ("t".into(), format!("log at {home}"), "home_path"),
        ("t".into(), "ping @**all** now".into(), "zulip_wildcard"),
        ("t".into(), "ping @**everyone**".into(), "zulip_wildcard"),
        ("t".into(), "ping @**stream**".into(), "zulip_wildcard"),
        ("t".into(), "ping @**channel**".into(), "zulip_wildcard"),
        ("t".into(), "ping @**topic**".into(), "zulip_wildcard"),
        ("t".into(), "quietly @_**all**".into(), "zulip_wildcard"),
        ("t".into(), "ping @**All|123**".into(), "zulip_wildcard"),
        ("t".into(), "ping @*admins*".into(), "zulip_group_mention"),
        ("t".into(), "ping @_*admins*".into(), "zulip_group_mention"),
        ("t".into(), "ping @**John Roe**".into(), "mention"),
        ("t".into(), "see [x](https://other.example.org/a)".into(), "link_host"),
        ("t".into(), "![img](https://img.example.net/p.png)".into(), "link_host"),
        ("t".into(), "bare https://other.example.org/a link".into(), "link_host"),
        ("t".into(), "[mail](mailto:x@example.com)".into(), "link_host"),
        ("ping @**all**".into(), "fine".into(), "zulip_wildcard"),
        ("see https://other.example.org".into(), "fine".into(), "link_host"),
        (format!("token {token}"), "fine".into(), "secret"),
        ("two\nlines".into(), "fine".into(), "topic_line_break"),
    ];
    for (topic, content, category) in &cases {
        let err = env.send(topic, content).await.unwrap_err();
        assert_eq!(reason(&err), "zulip_blocked", "{topic:?} / {content:?}: {err}");
        assert!(err.to_string().contains(category), "{topic:?} / {content:?} lacks {category}: {err}");
        assert!(!err.to_string().contains(&token), "{err}");
    }
    assert_eq!(env.pending_approvals().await, 0, "a blocked text never reaches a human");
    assert!(server.hits().is_empty());

    // What the allowlists admit goes on to the approval.
    for content in [
        "thanks @**Jane Doe**",
        "docs: [ci](https://docs.example.com/ci) and https://api.docs.example.com/x",
        "a plain update with no links",
    ] {
        let err = env.send("t", content).await.unwrap_err();
        assert_eq!(reason(&err), "approval_required", "{content}: {err}");
    }
    let checked = env.events("agent.zulip.send_checked").await;
    assert_eq!(checked.len(), cases.len() + 3);
    for e in &checked {
        let p = e.payload.to_string();
        assert!(
            !p.contains("@**") && !p.contains(&token) && !p.contains("two"),
            "no text in the ledger: {p}"
        );
    }
}

// --- outcomes -----------------------------------------------------------------------------------

#[tokio::test]
async fn a_rejected_send_is_failed_and_recorded() {
    let server = spawn_server().await;
    let env = configured(&server.base, Some("0"));
    server.knobs.lock().unwrap().send_status = 400;
    let err = env.approved_send("t", "will be rejected").await.unwrap_err();
    assert!(err.to_string().contains("HTTP 400"), "{err}");
    assert!(err.to_string().contains("Nothing was posted"), "{err}");
    assert_no_secret(&err);
    let failed = env.events("agent.zulip.send_failed").await;
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].payload["http_status"], 400);
    assert_eq!(failed[0].payload["chars"], 16);
    assert!(failed[0].payload["content_sha256"].is_string());
    // A failed send does not block a new attempt.
    server.knobs.lock().unwrap().send_status = 200;
    assert_eq!(env.approved_send("t", "will be rejected").await.unwrap()["sent"], true);
}

#[tokio::test]
async fn a_refused_connection_is_failed() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let env = configured(&base, Some("0"));
    let err = env.approved_send("t", "nobody listens").await.unwrap_err();
    assert!(err.to_string().contains("never reached it"), "{err}");
    assert_eq!(env.events("agent.zulip.send_failed").await.len(), 1);
}

#[tokio::test]
async fn an_uncertain_send_blocks_a_resend_until_a_human_resolves_it() {
    for status in [503u16, 429, 500] {
        let server = spawn_server().await;
        let env = configured(&server.base, Some("0"));
        server.knobs.lock().unwrap().send_status = status;
        let err = env.approved_send("t", "maybe posted").await.unwrap_err();
        assert_eq!(reason(&err), "zulip_uncertain", "{status}: {err}");
        let uncertain = env.events("agent.zulip.send_uncertain").await;
        assert_eq!(uncertain.len(), 1, "{status}");
        let send_id = uncertain[0].payload["send_id"].as_i64().unwrap();
        assert!(uncertain[0].payload["content_sha256"].is_string());

        server.knobs.lock().unwrap().send_status = 200;
        let dup = env.send("t", "maybe posted").await.unwrap_err();
        assert_eq!(reason(&dup), "zulip_duplicate", "{status}: {dup}");
        assert_eq!(env.pending_approvals().await, 0, "a duplicate never reaches a human");
        // Other text, or another topic, is not blocked.
        assert_eq!(reason(&env.send("t", "something else").await.unwrap_err()), "approval_required");

        let agent_resolve = env
            .call("zulip_resolve_send", json!({"send_id": send_id, "outcome": "not_delivered"}))
            .await
            .unwrap_err();
        assert_eq!(reason(&agent_resolve), "not_human", "{agent_resolve}");
        let resolved = env
            .call_as(&human(), "zulip_resolve_send", json!({"send_id": send_id, "outcome": "not_delivered"}))
            .await
            .unwrap();
        assert_eq!(resolved["status"], "failed");
        assert_eq!(resolved["reposted"], false);
        assert_eq!(env.events("agent.zulip.resolved").await.len(), 1);
        assert_eq!(env.approved_send("t", "maybe posted").await.unwrap()["sent"], true);
        assert_eq!(server.sends().len(), 2, "{status}");
    }
}

// --- fetch ---------------------------------------------------------------------------------------

#[tokio::test]
async fn fetch_marks_messages_untrusted_and_skips_the_bot_by_id() {
    let server = spawn_server().await;
    let env = configured(&server.base, Some("off"));
    let first = env.fetch(json!({"limit": 20})).await;
    assert_eq!(first["received"], true, "{first}");
    assert_eq!(first["anchor"], "newest");
    assert_eq!(first["next_anchor"], 15);
    assert_eq!(first["untrusted"], true);
    assert!(first["untrusted_note"].as_str().unwrap().contains("untrusted"));
    let ids: Vec<i64> =
        first["messages"].as_array().unwrap().iter().map(|m| m["id"].as_i64().unwrap()).collect();
    assert_eq!(ids, vec![12, 13, 15], "the bot's messages (10, 14) are dropped by sender id");
    for m in first["messages"].as_array().unwrap() {
        assert_eq!(m["trust"]["level"], "untrusted", "{m}");
        assert_eq!(m["trust"]["source"], "zulip");
        assert_eq!(m["trust"]["author"], m["sender_email"]);
    }
    assert_no_secret(&first);
    let me = server.hits().into_iter().filter(|h| h.path == "/api/v1/users/me").count();
    assert_eq!(me, 1);
}

#[tokio::test]
async fn fetch_reads_after_the_anchor_and_never_returns_it() {
    for ignore in [false, true] {
        let server = spawn_server().await;
        server.knobs.lock().unwrap().ignore_include_anchor = ignore;
        let env = configured(&server.base, Some("off"));
        let got = env.fetch(json!({"anchor": "12"})).await;
        let ids: Vec<i64> =
            got["messages"].as_array().unwrap().iter().map(|m| m["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, vec![13, 15], "ignore_include_anchor={ignore}");
        assert_eq!(got["next_anchor"], 15);
        let q = &server.fetches()[0].query;
        assert_eq!(q.get("include_anchor").map(String::as_str), Some("false"));
        assert_eq!(q.get("anchor").map(String::as_str), Some("12"));
        assert_eq!(q.get("num_before").map(String::as_str), Some("0"));
        assert_eq!(q.get("apply_markdown").map(String::as_str), Some("false"));

        // The stored cursor continues from 15: nothing newer.
        let next = env.fetch(json!({})).await;
        assert_eq!(next["anchor"], "15");
        assert!(next["messages"].as_array().unwrap().is_empty(), "{next}");
        assert_eq!(next["next_anchor"], 15);
    }
}

#[tokio::test]
async fn an_older_anchor_does_not_move_the_cursor_back() {
    let server = spawn_server().await;
    let env = configured(&server.base, Some("off"));
    assert_eq!(env.fetch(json!({})).await["next_anchor"], 15);
    let older = env.fetch(json!({"anchor": "10", "limit": 1})).await;
    let ids: Vec<i64> =
        older["messages"].as_array().unwrap().iter().map(|m| m["id"].as_i64().unwrap()).collect();
    assert_eq!(ids, vec![12]);
    assert_eq!(older["next_anchor"], 15, "the cursor stays at the newest message seen");
    assert_eq!(env.fetch(json!({})).await["anchor"], "15");
}

#[tokio::test]
async fn concurrent_fetches_keep_the_cursor_monotonic() {
    let server = spawn_server().await;
    let env = configured(&server.base, Some("off"));
    for _ in 0..5 {
        let (a, b, c) = tokio::join!(
            env.fetch(json!({"anchor": "10", "limit": 1})),
            env.fetch(json!({"anchor": "newest"})),
            env.fetch(json!({"anchor": "12", "limit": 1})),
        );
        for r in [&a, &b, &c] {
            assert_eq!(r["received"], true, "{r}");
        }
        let cursor = env.fetch(json!({})).await;
        assert_eq!(cursor["anchor"], "15", "{cursor}");
    }
}

#[tokio::test]
async fn bad_anchors_are_refused() {
    let server = spawn_server().await;
    let env = configured(&server.base, Some("off"));
    for bad in ["-1", "1e3", "12a", "99999999999999999999", "oldest"] {
        let err = env
            .call(
                "zulip_fetch_messages",
                json!({"agent_label": "speaker-1", "channel": "ops", "anchor": bad}),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("anchor must be"), "{bad}: {err}");
    }
    assert!(server.hits().is_empty());
}

#[tokio::test]
async fn an_oversized_reply_is_refused() {
    let server = spawn_server().await;
    server.knobs.lock().unwrap().huge_me = true;
    let env = configured(&server.base, Some("off"));
    let got = env.fetch(json!({})).await;
    assert_eq!(got["received"], false, "{got}");
    assert!(got["error"].as_str().unwrap().contains("too large"), "{got}");
    assert!(server.fetches().is_empty());
}

// --- site checks ------------------------------------------------------------------------------

#[tokio::test]
async fn the_site_must_be_https_or_allowed_loopback_and_public() {
    let server = spawn_server().await;
    // Plain http to a public host.
    let env = configured("http://example.com", Some("no"));
    let err = env
        .call("zulip_fetch_messages", json!({"agent_label": "speaker-1", "channel": "ops"}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("https URL"), "{err}");

    // Plain http to loopback without fetch_allow_loopback.
    let env = configured_with(&server.base, Some("no"), |c| c.fetch_allow_loopback = false);
    let err = env.send("t", "hi").await.unwrap_err();
    assert!(err.to_string().contains("https URL"), "{err}");

    // https to a private address: refused before any request.
    let private = format!("https://{}.{}.{}.{}", 10, 0, 0, 1);
    let env = configured_with(&private, Some("no"), |c| c.fetch_allow_loopback = false);
    let got = env.fetch(json!({})).await;
    assert_eq!(got["received"], false, "{got}");
    assert!(got["error"].as_str().unwrap().contains("non-public"), "{got}");

    assert!(server.hits().is_empty());
}

#[tokio::test]
async fn a_caller_cannot_fetch_as_another_agent() {
    let server = spawn_server().await;
    let env = configured(&server.base, Some("off"));
    let rejected = env
        .call("zulip_fetch_messages", json!({"agent_label": "other-agent", "channel": "ops"}))
        .await
        .unwrap_err();
    assert!(rejected.to_string().contains("verified"), "{rejected}");
    assert_no_secret(&rejected);
    assert!(server.hits().is_empty());
}

#[tokio::test]
async fn the_doctor_reports_zulip() {
    let server = spawn_server().await;
    let row = |report: &Value| {
        report["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "zulip").cloned().unwrap()
    };
    let dormant = bare().call("system_doctor", json!({})).await.unwrap();
    assert_eq!(row(&dormant)["status"], "DORMANT");
    let live = configured(&server.base, None).call("system_doctor", json!({})).await.unwrap();
    assert_eq!(row(&live)["status"], "LIVE", "{}", row(&live));
    assert!(row(&live)["detail"].as_str().unwrap().contains("send retired"));
    assert_no_secret(&live);
    let partial = configured_with(&server.base, None, |c| c.zulip_api_key = None);
    let partial = partial.call("system_doctor", json!({})).await.unwrap();
    assert_eq!(row(&partial)["status"], "MISCONFIGURED");
    assert!(server.hits().is_empty());
}

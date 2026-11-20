//! Zulip tools against a local stub. No test contacts a real Zulip site, and
//! failure output never includes the bot API key.

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
use ua_tools::{Hub, Registry, builtin_registry};

const KEY: &str = "zulip-test-key";
const EMAIL: &str = "bot@example.com";

#[derive(Clone, Default)]
struct Hit {
    method: String,
    query: String,
    auth_ok: bool,
    stream: Option<String>,
    topic: Option<String>,
    content: Option<String>,
    kind: Option<String>,
}

struct AppState {
    hits: Arc<Mutex<Vec<Hit>>>,
    expected_auth: String,
}

fn auth_ok(headers: &HeaderMap, expected: &str) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(expected)
}

async fn on_send(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let ok = auth_ok(&headers, &state.expected_auth);
    state.hits.lock().unwrap().push(Hit {
        method: "POST".into(),
        query: String::new(),
        auth_ok: ok,
        stream: form.get("to").cloned(),
        topic: form.get("topic").cloned(),
        content: form.get("content").cloned(),
        kind: form.get("type").cloned(),
    });
    if !ok {
        return (StatusCode::UNAUTHORIZED, Json(json!({"result": "error"})));
    }
    (StatusCode::OK, Json(json!({"result": "success", "id": 7})))
}

async fn on_fetch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let ok = auth_ok(&headers, &state.expected_auth);
    let anchor = query.get("anchor").cloned().unwrap_or_default();
    state.hits.lock().unwrap().push(Hit {
        method: "GET".into(),
        query: query.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&"),
        auth_ok: ok,
        stream: None,
        topic: None,
        content: None,
        kind: None,
    });
    if !ok {
        return (StatusCode::UNAUTHORIZED, Json(json!({"result": "error"})));
    }
    let messages = if anchor == "12" {
        json!([{
            "id": 13,
            "sender_email": "person@example.com",
            "sender_full_name": "Person",
            "type": "stream",
            "subject": "status",
            "content": "next",
            "timestamp": 20
        }])
    } else {
        json!([
            {
                "id": 10,
                "sender_email": EMAIL,
                "sender_full_name": "Bot",
                "type": "stream",
                "subject": "status",
                "content": "echo",
                "timestamp": 10
            },
            {
                "id": 12,
                "sender_email": "person@example.com",
                "sender_full_name": "Person",
                "type": "stream",
                "subject": "status",
                "content": "hello",
                "timestamp": 12
            }
        ])
    };
    (StatusCode::OK, Json(json!({"result": "success", "messages": messages})))
}

struct Server {
    base: String,
    hits: Arc<Mutex<Vec<Hit>>>,
}

fn basic_header() -> String {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{EMAIL}:{KEY}"));
    format!("Basic {token}")
}

async fn spawn_server() -> Server {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let state = Arc::new(AppState { hits: hits.clone(), expected_auth: basic_header() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/api/v1/messages", get(on_fetch).post(on_send)).with_state(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Server { base: format!("http://{addr}"), hits }
}

struct Env {
    _home: tempfile::TempDir,
    hub: Hub,
    reg: Registry,
}

fn configured(site: &str, retired: Option<&str>) -> Env {
    let home = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(home.path());
    cfg.zulip_site = Some(site.into());
    cfg.zulip_email = Some(EMAIL.into());
    cfg.zulip_api_key = Some(SecretString::from(KEY));
    cfg.zulip_retired = retired.map(str::to_string);
    Env { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), _home: home }
}

fn bare() -> Env {
    let home = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(home.path());
    Env { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), _home: home }
}

fn agent() -> Caller {
    Caller {
        label: "builder-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

impl Env {
    async fn call(&self, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, &agent(), tool, args).await
    }
}

fn assert_no_secret(value: &impl std::fmt::Display) {
    let text = value.to_string();
    assert!(!text.contains(KEY), "tool output included the API key");
}

#[tokio::test]
async fn unconfigured_tools_make_no_request() {
    let server = spawn_server().await;
    let env = bare();
    let send = env
        .call(
            "zulip_send_message",
            json!({"agent_label": "builder-1", "channel": "ops", "topic": "t", "content": "hi"}),
        )
        .await
        .unwrap_err();
    let fetch = env
        .call("zulip_fetch_messages", json!({"agent_label": "builder-1", "channel": "ops"}))
        .await
        .unwrap_err();
    assert!(send.to_string().contains("not configured"), "{send}");
    assert!(fetch.to_string().contains("not configured"), "{fetch}");
    assert_no_secret(&send);
    assert_no_secret(&fetch);
    assert!(server.hits.lock().unwrap().is_empty());
}

#[tokio::test]
async fn retired_send_does_not_call_the_network() {
    let server = spawn_server().await;
    let env = configured(&server.base, None);
    let err = env
        .call(
            "zulip_send_message",
            json!({"agent_label": "builder-1", "channel": "ops", "topic": "t", "content": "hi"}),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("retired"), "{err}");
    assert_no_secret(&err);
    assert!(server.hits.lock().unwrap().is_empty());
}

#[tokio::test]
async fn send_posts_to_the_stub_without_leaking_the_key() {
    let server = spawn_server().await;
    let env = configured(&server.base, Some("0"));
    let sent = env
        .call(
            "zulip_send_message",
            json!({"agent_label": "builder-1", "channel": "requests", "topic": "status", "content": "hello"}),
        )
        .await
        .unwrap();
    assert_eq!(sent["sent"], true);
    assert_eq!(sent["message_id"], 7);
    assert_eq!(sent["channel"], "requests");
    assert_no_secret(&sent);
    let hits = server.hits.lock().unwrap();
    assert_eq!(hits.len(), 1);
    assert!(hits[0].auth_ok, "stub rejected the basic-auth header");
    assert_eq!(hits[0].stream.as_deref(), Some("Requests"));
    assert_eq!(hits[0].topic.as_deref(), Some("status"));
    assert_eq!(hits[0].content.as_deref(), Some("hello"));
    assert_eq!(hits[0].kind.as_deref(), Some("stream"));
}

#[tokio::test]
async fn fetch_advances_the_stored_cursor_and_skips_the_bot() {
    let server = spawn_server().await;
    let env = configured(&server.base, Some("off"));
    let first = env
        .call("zulip_fetch_messages", json!({"agent_label": "builder-1", "channel": "ops", "limit": 20}))
        .await
        .unwrap();
    assert_eq!(first["received"], true);
    assert_eq!(first["anchor"], "newest");
    assert_eq!(first["next_anchor"], 12);
    assert_eq!(first["messages"].as_array().unwrap().len(), 1, "the bot's own message must be omitted");
    assert_eq!(first["messages"][0]["content"], "hello");
    assert_no_secret(&first);

    let second = env
        .call("zulip_fetch_messages", json!({"agent_label": "builder-1", "channel": "ops"}))
        .await
        .unwrap();
    assert_eq!(second["anchor"], "12");
    assert_eq!(second["next_anchor"], 13);
    assert_eq!(second["messages"][0]["id"], 13);
    assert_no_secret(&second);

    let hits = server.hits.lock().unwrap();
    assert_eq!(hits.len(), 2);
    assert!(hits.iter().all(|h| h.auth_ok && h.method == "GET"));
    assert!(hits[0].query.contains("anchor=newest"), "{}", hits[0].query);
    assert!(hits[1].query.contains("anchor=12"), "{}", hits[1].query);
    assert!(hits[1].query.contains("num_before=0"), "{}", hits[1].query);
    assert!(hits[1].query.contains("apply_markdown=false"), "{}", hits[1].query);
}

#[tokio::test]
async fn bad_channel_site_and_api_error_stay_generic() {
    let server = spawn_server().await;
    let env = configured(&server.base, Some("false"));
    let channel = env
        .call(
            "zulip_send_message",
            json!({"agent_label": "builder-1", "channel": "general", "topic": "t", "content": "hi"}),
        )
        .await
        .unwrap_err();
    assert!(channel.to_string().contains("channel must be one of"), "{channel}");
    assert_no_secret(&channel);

    let mut cfg = Config::for_home(env._home.path());
    cfg.zulip_site = Some("http://example.com".into());
    cfg.zulip_email = Some(EMAIL.into());
    cfg.zulip_api_key = Some(SecretString::from(KEY));
    cfg.zulip_retired = Some("no".into());
    let blocked = Hub::in_memory(cfg).unwrap();
    let site = env
        .reg
        .call(
            &blocked,
            &agent(),
            "zulip_fetch_messages",
            json!({"agent_label": "builder-1", "channel": "ops"}),
        )
        .await
        .unwrap_err();
    assert!(site.to_string().contains("https URL"), "{site}");
    assert_no_secret(&site);
    assert!(server.hits.lock().unwrap().is_empty());

    let rejected = env
        .call("zulip_fetch_messages", json!({"agent_label": "other-agent", "channel": "ops"}))
        .await
        .unwrap_err();
    assert!(rejected.to_string().contains("verified"), "{rejected}");
    assert_no_secret(&rejected);
}

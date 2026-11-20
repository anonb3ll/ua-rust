//! `POST /api/slack/commands` and `POST /api/slack/events`: Slack ingress.
//!
//! Mounted only when `slack_enabled` is on and `UA_SLACK_SIGNING_SECRET` is
//! set ([`mount_status`]); otherwise both paths answer 404. Neither takes a
//! bearer token (Slack cannot send one): each request authenticates itself
//! with Slack's v0 signature. For every request, in this order:
//!
//! 1. The body is read as raw bytes, at most 64 KiB (`DefaultBodyLimit`;
//!    larger is 413).
//! 2. The signature is checked over those bytes
//!    ([`slack::verify_slack_signature`]) before anything parses them. A
//!    missing, malformed, stale or wrong signature is a 401, and no database
//!    transaction has been opened. Such refusals are logged by reason class,
//!    not ledgered: they are unauthenticated, and anyone could send them.
//! 3. The body is parsed (form for commands, JSON for events). An Events API
//!    `url_verification` answers its challenge here, with no state. Events
//!    that are not explicit commands are acknowledged and ignored, with no
//!    state.
//! 4. One write transaction ([`slack::admit`]) records the signature (a
//!    replay is a 401), maps (`team_id`, `user_id`) to a hub identity through
//!    `slack_identities`, dedupes on the trigger id or event id, and ledgers
//!    the outcome.
//! 5. Slack gets its answer (well inside its 3 seconds); the command then
//!    runs on a tracked task through [`ua_tools::Registry::call`] as the
//!    mapped identity, the same governed path as every other caller, and its
//!    outcome is ledgered ([`slack::record_executed`]). A slash command's
//!    result is posted to its `response_url` when that is
//!    `https://hooks.slack.com/...` ([`slack::response_url`]).
//!
//! Slack's `user_name` and display fields are never read.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, post};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Map, Value, json};
use ua_core::identity::Transport;
use ua_core::{ActorKind, Config};
use ua_tools::families::slack::{self, Admission, Delivery, DeliveryKind};

use crate::AppState;
use crate::auth::{AuthIdentity, caller_for};

/// Slash commands (form-encoded).
pub const COMMANDS_PATH: &str = "/api/slack/commands";
/// Events API callbacks (JSON).
pub const EVENTS_PATH: &str = "/api/slack/events";

/// Whether `path` is one of the Slack routes (public: they authenticate by
/// signature, and the commands route takes a form body).
pub fn is_slack_path(path: &str) -> bool {
    path == COMMANDS_PATH || path == EVENTS_PATH
}

/// The signing secret when the routes should be mounted, else why not (one
/// line for the startup log).
pub fn mount_status(cfg: &Config) -> Result<SecretString, &'static str> {
    if !cfg.slack_enabled {
        return Err("Slack routes not mounted: slack_enabled is false");
    }
    let Some(secret) = cfg.slack_signing_secret() else {
        return Err("Slack routes not mounted: slack_enabled is on but UA_SLACK_SIGNING_SECRET is not set");
    };
    if cfg.check_slack_identities().is_err() {
        return Err("Slack routes not mounted: slack_identities is invalid");
    }
    Ok(secret)
}

/// The routes, or, when [`mount_status`] says no, a plain 404 on both paths
/// that reads nothing (an unmatched POST would otherwise reach the UI's
/// fallback and its CSRF refusal, a 403 that looks like a live route).
pub fn routes(cfg: &Config) -> Router<AppState> {
    if mount_status(cfg).is_err() {
        let gone = || async { StatusCode::NOT_FOUND };
        return Router::new().route(COMMANDS_PATH, any(gone)).route(EVENTS_PATH, any(gone));
    }
    let limit = DefaultBodyLimit::max(slack::MAX_BODY_BYTES);
    Router::new()
        .route(COMMANDS_PATH, post(commands).layer(limit))
        .route(EVENTS_PATH, post(events).layer(limit))
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> &'a str {
    h.get(name).and_then(|v| v.to_str().ok()).unwrap_or_default()
}

fn now_s() -> i64 {
    ua_core::time::now_ms() / 1000
}

fn unauthorized(reason: &'static str) -> Response {
    tracing::info!(reason, "refused a Slack request");
    let body =
        json!({ "ok": false, "error": "unauthenticated", "message": "invalid Slack request signature" });
    (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response()
}

/// Step 2: the signature over the raw bytes. No database access.
fn verify(state: &AppState, headers: &HeaderMap, body: &[u8]) -> Result<(), Box<Response>> {
    // Re-read per request: the route exists only with a secret, but a
    // missing one must still fail closed.
    let Ok(secret) = mount_status(state.hub.cfg()) else {
        return Err(Box::new(unauthorized("not_configured")));
    };
    let ts = header(headers, "x-slack-request-timestamp");
    let sig = header(headers, "x-slack-signature");
    if ts.is_empty() || sig.is_empty() {
        return Err(Box::new(unauthorized("missing_signature")));
    }
    slack::verify_slack_signature(secret.expose_secret(), ts, body, sig, now_s()).map_err(|e| {
        Box::new(unauthorized(match e {
            slack::SignatureError::Stale => "stale",
            slack::SignatureError::BadSignature => "bad_signature",
        }))
    })
}

/// An ephemeral slash-command answer.
fn ephemeral(text: &str) -> Response {
    axum::Json(json!({ "response_type": "ephemeral", "text": text })).into_response()
}

/// What one verified request asks for.
struct Request {
    delivery: Delivery,
    parsed: Option<Value>,
    response_url: Option<url::Url>,
}

/// Step 4, then the answer: a slash command gets an ephemeral sentence
/// (never the body or anything from the hub but the mapped identity), an
/// event an empty 200 whatever happened, so Slack does not retry a refusal.
async fn admit_and_run(state: AppState, headers: &HeaderMap, body: Bytes, req: Request) -> Response {
    let is_command = req.delivery.kind == DeliveryKind::Trigger;
    let ts = header(headers, "x-slack-request-timestamp").to_string();
    let (hub, d) = (state.hub.clone(), req.delivery.clone());
    let raw = body.to_vec();
    let db = hub.db().clone();
    let admitted = db.write_async(move |tx| slack::admit(tx, hub.cfg(), &ts, &raw, now_s(), &d)).await;
    let ack = |text: &str| if is_command { ephemeral(text) } else { axum::Json(json!({})).into_response() };
    let (identity, human) = match admitted {
        Ok(Admission::Accepted { identity, human }) => (identity, human),
        Ok(Admission::Deduped { .. }) => return ack("Already received."),
        Ok(Admission::Refused { reason, .. }) => {
            return ack(match reason {
                "unmapped_identity" | "identity_retired" => {
                    "This Slack user is not mapped to a hub identity. Ask an operator to add it to slack_identities."
                }
                "invalid_command" => {
                    "Unsupported or malformed command. Use contact, task, assign, progress, blocker, review, plan, approve or status."
                }
                _ => "Malformed Slack request.",
            });
        }
        Err(e) if e.reason_code() == Some("replayed") => return unauthorized("replayed"),
        Err(e) => {
            tracing::warn!(code = e.code(), "could not record a Slack request");
            let body = json!({ "ok": false, "error": "internal", "message": "internal error" });
            return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(body)).into_response();
        }
    };
    let Some(parsed) = req.parsed else { return ack("Malformed Slack request.") };
    let command = parsed["command"].as_str().unwrap_or_default().to_string();
    // `contact` runs no tool: its answer is cheap and goes inline.
    let (text, response_url) = match (command.as_str(), req.response_url) {
        ("contact", _) => (slack::reply_text("contact", &identity, &Ok(json!({}))), None),
        (_, Some(u)) => (format!("Accepted /{command}. The result follows."), Some(u)),
        (_, None) => (format!("Accepted /{command}. The result is recorded in the hub ledger."), None),
    };
    let task_state = state.clone();
    state.calls.spawn(execute(task_state, identity, human, req.delivery, parsed, response_url));
    ack(&text)
}

/// Step 5, after the acknowledgement. Never panics: every failure is
/// ledgered or, if even that fails, logged.
async fn execute(
    state: AppState,
    identity: String,
    human: bool,
    d: Delivery,
    parsed: Value,
    response_url: Option<url::Url>,
) {
    let command = parsed["command"].as_str().unwrap_or_default().to_string();
    let id = AuthIdentity {
        label: identity.clone(),
        kind: if human { ActorKind::Human } else { ActorKind::Agent },
        verified: true,
        grant: None,
    };
    let caller = caller_for(&state, &id, None, Transport::Http);
    let (tool, outcome) = match slack::command_call(&parsed, &d.delivery_id) {
        Ok(Some(call)) => {
            (Some(call.tool), state.registry.call(&state.hub, &caller, call.tool, call.args).await)
        }
        Ok(None) => (None, Ok(json!({ "identity": identity }))),
        Err(e) => (None, Err(e)),
    };
    let reply = slack::reply_text(&command, &identity, &outcome);
    let (who, kind, dl, cmd) = (identity.clone(), d.kind, d.delivery_id.clone(), command.clone());
    let recorded = state
        .hub
        .db()
        .write_async(move |tx| slack::record_executed(tx, &who, kind, &dl, &cmd, tool, &outcome))
        .await;
    if let Err(e) = recorded {
        tracing::warn!(code = e.code(), "could not ledger a Slack command's outcome");
    }
    let Some(url) = response_url else { return };
    if let Err(reason) = slack::post_reply(state.hub.cfg(), &url, &reply).await {
        let (who, dl) = (identity, d.delivery_id);
        let recorded =
            state.hub.db().write_async(move |tx| slack::record_reply_failed(tx, &who, &dl, reason)).await;
        if let Err(e) = recorded {
            tracing::warn!(code = e.code(), "could not ledger a failed Slack reply");
        }
    }
}

/// Form fields; `None` when a field repeats (no parameter pollution) or the
/// body is not UTF-8.
fn form_fields(body: &[u8]) -> Option<Map<String, Value>> {
    std::str::from_utf8(body).ok()?;
    let mut out = Map::new();
    for (k, v) in url::form_urlencoded::parse(body) {
        if out.insert(k.into_owned(), Value::String(v.into_owned())).is_some() {
            return None;
        }
    }
    Some(out)
}

fn field<'a>(m: &'a Map<String, Value>, k: &str) -> &'a str {
    m.get(k).and_then(Value::as_str).unwrap_or_default()
}

async fn commands(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = verify(&state, &headers, &body) {
        return *r;
    }
    let fields = form_fields(&body);
    let empty = Map::new();
    let f = fields.as_ref().unwrap_or(&empty);
    // Identity is (team_id, user_id) only; user_name is never read.
    let (team_id, user_id, trigger_id) = (field(f, "team_id"), field(f, "user_id"), field(f, "trigger_id"));
    // `/task fix it` arrives as command=/task, text=fix it; a single app
    // command such as `/hub task fix it` carries the whole command in text.
    let name = field(f, "command").trim_start_matches('/').to_ascii_lowercase();
    let text = field(f, "text");
    let line = if is_command_word(&name) { format!("{name} {text}") } else { text.to_string() };
    let parsed = slack::parse_slack_command(&line).ok();
    let malformed =
        fields.is_none() || team_id.is_empty() || user_id.is_empty() || !slack::delivery_id_ok(trigger_id);
    let refusal = if malformed {
        Some("malformed_payload")
    } else if parsed.is_none() {
        Some("invalid_command")
    } else {
        None
    };
    let delivery = Delivery {
        kind: DeliveryKind::Trigger,
        delivery_id: trigger_id.to_string(),
        team_id: team_id.to_string(),
        user_id: user_id.to_string(),
        command: parsed.as_ref().and_then(|p| p["command"].as_str()).map(str::to_string),
        refusal,
    };
    let response_url = slack::response_url(field(f, "response_url"));
    admit_and_run(state, &headers, body, Request { delivery, parsed, response_url }).await
}

/// One of the nine command words (the parser refuses a bare word that needs
/// arguments, so this is checked on its own).
fn is_command_word(name: &str) -> bool {
    matches!(
        name,
        "approve" | "assign" | "blocker" | "contact" | "plan" | "progress" | "review" | "status" | "task"
    )
}

/// The first word of `text` after leading user mentions starts with `/`: an
/// explicit command. Natural-language messages never run anything.
fn explicit_command(text: &str) -> bool {
    let mut rest = text.trim_start();
    while let Some(after) = rest.strip_prefix("<@") {
        let Some(close) = after.find('>') else { return false };
        rest = after[close + 1..].trim_start();
    }
    rest.starts_with('/')
}

async fn events(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = verify(&state, &headers, &body) {
        return *r;
    }
    let ignore = || axum::Json(json!({})).into_response();
    let Ok(Value::Object(envelope)) = serde_json::from_slice::<Value>(&body) else {
        tracing::info!("ignored a signed Slack event that is not a JSON object");
        return ignore();
    };
    match envelope.get("type").and_then(Value::as_str) {
        Some("url_verification") => {
            // Signed like everything else (checked above); echo the challenge.
            let challenge = envelope.get("challenge").and_then(Value::as_str).unwrap_or_default();
            if challenge.is_empty() || challenge.len() > 256 {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({ "ok": false, "error": "bad_challenge" })),
                )
                    .into_response();
            }
            return axum::Json(json!({ "challenge": challenge })).into_response();
        }
        Some("event_callback") => {}
        _ => return ignore(),
    }
    let empty = Map::new();
    let event = envelope.get("event").and_then(Value::as_object).unwrap_or(&empty);
    let s =
        |m: &Map<String, Value>, k: &str| m.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let event_type = s(event, "type");
    let text = s(event, "text");
    // Only a message addressed to the app (a mention, or a direct message),
    // written by a person, and written as an explicit `/command`.
    let addressed =
        event_type == "app_mention" || (event_type == "message" && s(event, "channel_type") == "im");
    let by_person = !event.contains_key("bot_id") && !event.contains_key("subtype");
    if !addressed || !by_person || !explicit_command(&text) {
        return ignore();
    }
    // The user's own workspace: `user_team` or `team` on the event (shared
    // channels), else the envelope's.
    let team_id = [s(event, "user_team"), s(event, "team"), s(&envelope, "team_id")]
        .into_iter()
        .find(|t| !t.is_empty())
        .unwrap_or_default();
    let user_id = s(event, "user");
    let event_id = s(&envelope, "event_id");
    let parsed = slack::parse_slack_command(&text).ok();
    let malformed = team_id.is_empty() || user_id.is_empty() || !slack::delivery_id_ok(&event_id);
    let refusal = if malformed {
        Some("malformed_payload")
    } else if parsed.is_none() {
        Some("invalid_command")
    } else {
        None
    };
    let delivery = Delivery {
        kind: DeliveryKind::Event,
        delivery_id: event_id,
        team_id,
        user_id,
        command: parsed.as_ref().and_then(|p| p["command"].as_str()).map(str::to_string),
        refusal,
    };
    // Events carry no response_url; replies would need a bot token, which
    // this hub does not hold.
    admit_and_run(state, &headers, body, Request { delivery, parsed, response_url: None }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_commands_need_a_leading_slash_after_mentions() {
        assert!(explicit_command("/task fix it"));
        assert!(explicit_command("<@U0BOT> /status task-1"));
        assert!(explicit_command("<@U0BOT|hub>  <@U0OTHER> /plan x"));
        assert!(!explicit_command("<@U0BOT> task fix it"));
        assert!(!explicit_command("task status is confusing"));
        assert!(!explicit_command("<@U0BOT"));
    }

    #[test]
    fn a_repeated_form_field_is_malformed() {
        assert!(form_fields(b"user_id=U1&team_id=T1").is_some());
        assert!(form_fields(b"user_id=U1&user_id=U2").is_none());
        assert!(form_fields(&[0xff, 0xfe]).is_none());
    }

    #[test]
    fn the_routes_mount_only_with_the_gate_and_the_secret() {
        let mut cfg = Config::for_home(std::env::temp_dir());
        assert!(mount_status(&cfg).unwrap_err().contains("slack_enabled is false"));
        cfg.slack_signing_secret = Some(SecretString::from("s3cret".to_string()));
        assert!(mount_status(&cfg).unwrap_err().contains("slack_enabled is false"));
        cfg.slack_enabled = true;
        assert!(mount_status(&cfg).is_ok());
        cfg.slack_signing_secret = Some(SecretString::from("  ".to_string()));
        assert!(mount_status(&cfg).unwrap_err().contains("UA_SLACK_SIGNING_SECRET"));
        cfg.slack_signing_secret = None;
        assert!(mount_status(&cfg).unwrap_err().contains("UA_SLACK_SIGNING_SECRET"));
    }
}

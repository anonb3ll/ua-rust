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
//!    transaction has been opened. Such refusals are logged by reason class
//!    at debug level only, never ledgered: anyone could send them.
//! 3. The body is parsed (form for commands, JSON for events). An Events API
//!    `url_verification` answers its challenge here, with no state. Events
//!    that are not marked commands (`!task …` or `/task …` after any leading
//!    mentions; a bare word never is), direct messages not delivered to the
//!    app's bot (`authorizations[].is_bot`), and events an app wrote or that
//!    were edited (`bot_id`, `subtype`, `app_id`, `bot_profile`, `edited`)
//!    are acknowledged and ignored, with no state.
//! 4. One write transaction ([`slack::admit_claimed`]) records the signature (a
//!    replay is a 401), maps (`team_id`, `user_id`) to a hub identity through
//!    `slack_identities`, dedupes on the trigger id or event id, and ledgers
//!    the outcome. A request with no mapped identity adds no ledger row (any
//!    workspace member could send them in a loop); it is logged at debug.
//!    `approve` arrives only as a slash command: through the Events API it
//!    is refused, since an app holding a user's token can post as them.
//! 5. Slack gets its answer (well inside its 3 seconds); the command then
//!    runs on a tracked task through [`ua_tools::Registry::call`] as the
//!    mapped identity, the same governed path as every other caller, and its
//!    outcome is ledgered ([`slack::record_executed_under`], with the claim
//!    the admission took). A slash command's
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

/// Refusal reason for `approve` sent as a message (Events API).
const APPROVE_NOT_ON_EVENTS: &str = "approve_needs_slash_command";

/// Ledger, once, every Slack command admitted before the hub last stopped
/// with no recorded outcome ([`slack::sweep_abandoned`]; outcome unknown). `ua serve` runs this
/// before it binds, so before the routes take traffic.
pub async fn sweep_abandoned(hub: &ua_tools::Hub) -> ua_core::UaResult<usize> {
    hub.db().write_async(|tx| slack::sweep_abandoned(tx, now_s())).await
}

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
    // Debug only: unauthenticated traffic must not be able to grow the logs.
    tracing::debug!(reason, "refused a Slack request");
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

/// What one authenticated Slack delivery asks for, from either transport.
pub(crate) struct Request {
    pub(crate) delivery: Delivery,
    pub(crate) parsed: Option<Value>,
    pub(crate) response_url: Option<url::Url>,
}

/// What makes a delivery unique before its event or trigger id is read.
pub(crate) enum Replay {
    /// An HTTP request: its signed timestamp and raw body.
    Signed { timestamp: String, body: Vec<u8> },
    /// A Socket Mode envelope: its `envelope_id`.
    #[cfg_attr(not(feature = "slack-socket"), allow(dead_code))]
    Envelope(String),
}

/// How a delivery was answered by [`admit_and_run`].
pub(crate) enum Admitted {
    /// The sentence a slash command shows the user (events ignore it).
    Answer(String),
    /// The same signed bytes or envelope were accepted before.
    Replayed,
    /// The admission transaction failed.
    Internal,
}

/// Step 4, then the answer, for both transports: one admission transaction
/// ([`slack::admit_claimed`]), then the command on a tracked task as the mapped
/// human. The answer is a fixed sentence (never the body or anything from the
/// hub but the mapped identity).
pub(crate) async fn admit_and_run(state: AppState, replay: Replay, req: Request) -> Admitted {
    let (hub, d) = (state.hub.clone(), req.delivery.clone());
    let db = hub.db().clone();
    let admitted = db
        .write_async(move |tx| {
            let key = match &replay {
                Replay::Signed { timestamp, body } => slack::ReplayKey::Signed { timestamp, body },
                Replay::Envelope(id) => slack::ReplayKey::Envelope { envelope_id: id },
            };
            slack::admit_claimed(tx, hub.cfg(), key, now_s(), &d)
        })
        .await;
    let ack = |text: &str| Admitted::Answer(text.to_string());
    let (identity, claim) = match admitted {
        Ok((Admission::Accepted { identity }, claim)) => (identity, claim),
        Ok((Admission::Deduped { .. }, _)) => return ack("Already received."),
        Ok((Admission::Refused { reason, identity }, _)) => {
            if identity.is_none() {
                // Not ledgered (anyone in the workspace can send these); debug only.
                // The ids are what an operator adds to `slack_identities`; they
                // come from the signed body and are logged only when id-shaped.
                let id = |v: &str| {
                    let ok = !v.is_empty() && v.len() <= 32 && v.bytes().all(|b| b.is_ascii_alphanumeric());
                    if ok { v.to_string() } else { "-".to_string() }
                };
                tracing::debug!(
                    reason,
                    team_id = %id(&req.delivery.team_id),
                    user_id = %id(&req.delivery.user_id),
                    "refused an authenticated Slack request without a mapped identity"
                );
            }
            return ack(match reason {
                slack::APPROVE_NOT_ENABLED => {
                    "Approvals are not enabled for this Slack user (can_approve is off in slack_identities)."
                }
                "unmapped_identity" => {
                    "This Slack user is not mapped to a hub identity. Ask an operator to add it to slack_identities."
                }
                "invalid_command" => {
                    "Unsupported or malformed command. Use contact, task, assign, progress, blocker, review, plan, approve or status."
                }
                APPROVE_NOT_ON_EVENTS => {
                    "Approvals come only from the slash command (/approve), not from messages."
                }
                _ => "Malformed Slack request.",
            });
        }
        Err(e) if e.reason_code() == Some("replayed") => return Admitted::Replayed,
        Err(e) => {
            tracing::warn!(code = e.code(), "could not record a Slack request");
            return Admitted::Internal;
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
    state.calls.spawn(execute(task_state, identity, claim, req.delivery, parsed, response_url));
    ack(&text)
}

/// The HTTP answer for [`admit_and_run`]'s result: a slash command gets an
/// ephemeral sentence, an event an empty 200 whatever happened, so Slack
/// does not retry a refusal.
async fn http_admit(state: AppState, headers: &HeaderMap, body: Bytes, req: Request) -> Response {
    let is_command = req.delivery.kind == DeliveryKind::Trigger;
    let replay = Replay::Signed {
        timestamp: header(headers, "x-slack-request-timestamp").to_string(),
        body: body.to_vec(),
    };
    match admit_and_run(state, replay, req).await {
        Admitted::Answer(text) if is_command => ephemeral(&text),
        Admitted::Answer(_) => axum::Json(json!({})).into_response(),
        Admitted::Replayed => unauthorized("replayed"),
        Admitted::Internal => {
            let body = json!({ "ok": false, "error": "internal", "message": "internal error" });
            (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(body)).into_response()
        }
    }
}

/// Step 5, after the acknowledgement. Never panics: every failure is
/// ledgered or, if even that fails, logged.
async fn execute(
    state: AppState,
    identity: String,
    claim: Option<ua_ingress::inbound::Claim>,
    d: Delivery,
    parsed: Value,
    response_url: Option<url::Url>,
) {
    let command = parsed["command"].as_str().unwrap_or_default().to_string();
    // `slack_identities` maps only to `human_identities` (checked at load
    // and again on every lookup), the default organization's.
    let id = AuthIdentity::in_default(identity.clone(), ActorKind::Human, true);
    let caller = caller_for(&state, &id, None, Transport::Slack);
    // Refused, like a static token, while a row of another organization
    // holds the identity's label.
    let held = crate::auth::held_outside_default(&state, &identity).await;
    let (tool, outcome) = match slack::command_call(&parsed, &d.delivery_id) {
        _ if held => (
            None,
            Err(ua_core::UaError::denied(
                "agent_label_taken",
                "this Slack identity's label is held outside the default organization; nothing was run",
            )),
        ),
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
        .write_async(move |tx| {
            slack::record_executed_under(tx, claim.as_ref(), &who, kind, &dl, &cmd, tool, &outcome)
        })
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
    let req = command_request(fields.as_ref());
    http_admit(state, &headers, body, req).await
}

/// A slash command's fields (the HTTP form, or a Socket Mode
/// `slash_commands` payload), as a [`Request`]. `None` is a malformed body.
pub(crate) fn command_request(fields: Option<&Map<String, Value>>) -> Request {
    let empty = Map::new();
    let f = fields.unwrap_or(&empty);
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
    Request { delivery, parsed, response_url }
}

/// One of the nine command words (the parser refuses a bare word that needs
/// arguments, so this is checked on its own).
fn is_command_word(name: &str) -> bool {
    matches!(
        name,
        "approve" | "assign" | "blocker" | "contact" | "plan" | "progress" | "review" | "status" | "task"
    )
}

/// `text` after leading user mentions; `None` when a mention is unclosed.
fn after_mentions(text: &str) -> Option<&str> {
    let mut rest = text.trim_start();
    while let Some(after) = rest.strip_prefix("<@") {
        let close = after.find('>')?;
        rest = after[close + 1..].trim_start();
    }
    Some(rest)
}

/// The command in a message, when it is marked as one: after leading user
/// mentions, `/` or `!` immediately followed by one of the nine command words
/// (ignoring ASCII case, since phone keyboards capitalise), then whitespace
/// or the end: `!task fix it`, `@hub !status task-12`, `@hub /task fix it`.
/// Returns the text without mentions and marker, for the parser. A bare word
/// (`task done, thanks`) is never a command: ordinary conversation must not
/// write to the hub. `!` exists because Slack's composer takes a message
/// starting with `/` as a slash command and does not post it.
fn marked_command(text: &str) -> Option<&str> {
    let rest = after_mentions(text)?;
    let body = rest.strip_prefix('/').or_else(|| rest.strip_prefix('!'))?;
    let word = body.split(char::is_whitespace).next().unwrap_or_default();
    is_command_word(&word.to_ascii_lowercase()).then_some(body)
}

/// Whether the envelope says the event was delivered to the app's bot
/// (`authorizations: [{.., "is_bot": true}]`). A `message.im` subscribed as
/// a user event ("on behalf of users") carries the user's own DMs with
/// colleagues and only a user authorization; those never become commands.
fn bot_authorized(envelope: &Map<String, Value>) -> bool {
    envelope
        .get("authorizations")
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().any(|x| x.get("is_bot").and_then(Value::as_bool) == Some(true)))
}

async fn events(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = verify(&state, &headers, &body) {
        return *r;
    }
    let ignore = || axum::Json(json!({})).into_response();
    let Ok(Value::Object(envelope)) = serde_json::from_slice::<Value>(&body) else {
        tracing::debug!("ignored a signed Slack event that is not a JSON object");
        return ignore();
    };
    match event_request(&envelope) {
        EventRequest::Challenge(challenge) => axum::Json(json!({ "challenge": challenge })).into_response(),
        EventRequest::BadChallenge => {
            (StatusCode::BAD_REQUEST, axum::Json(json!({ "ok": false, "error": "bad_challenge" })))
                .into_response()
        }
        EventRequest::Ignore => ignore(),
        EventRequest::Run(req) => http_admit(state, &headers, body, *req).await,
    }
}

/// What an Events API envelope asks for.
pub(crate) enum EventRequest {
    /// `url_verification`: echo this challenge (HTTP only).
    Challenge(String),
    /// `url_verification` with a missing or oversized challenge.
    BadChallenge,
    /// Not a command, or not one this hub acts on: acknowledge, no state.
    Ignore,
    /// A marked command to admit.
    Run(Box<Request>),
}

/// Read an Events API envelope (the HTTP body, or a Socket Mode `events_api`
/// payload): the filters on who wrote it and whether it is a marked command,
/// then the [`Request`]. No database access.
pub(crate) fn event_request(envelope: &Map<String, Value>) -> EventRequest {
    let ignore = || EventRequest::Ignore;
    match envelope.get("type").and_then(Value::as_str) {
        Some("url_verification") => {
            let challenge = envelope.get("challenge").and_then(Value::as_str).unwrap_or_default();
            if challenge.is_empty() || challenge.len() > 256 {
                return EventRequest::BadChallenge;
            }
            return EventRequest::Challenge(challenge.to_string());
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
    // written by a person, and written as a command.
    let direct = event_type == "message" && s(event, "channel_type") == "im";
    let addressed = event_type == "app_mention" || direct;
    // Anything an app wrote, including a message an app posted with a user's
    // token on their behalf, is not a person typing: Slack marks such
    // messages with some of these keys. An edited message (`edited`) is not
    // run again either: the command already ran when it was first sent.
    let by_person =
        !["bot_id", "subtype", "app_id", "bot_profile", "edited"].iter().any(|k| event.contains_key(*k));
    // A direct message counts only when it was delivered to the app's bot,
    // not to a user-scoped subscription.
    let Some(command_text) = marked_command(&text) else { return ignore() };
    if !addressed || !by_person || (direct && !bot_authorized(envelope)) {
        return ignore();
    }
    // The user's own workspace: `user_team` or `team` on the event (shared
    // channels), else the envelope's.
    let team_id = [s(event, "user_team"), s(event, "team"), s(envelope, "team_id")]
        .into_iter()
        .find(|t| !t.is_empty())
        .unwrap_or_default();
    let user_id = s(event, "user");
    let event_id = s(envelope, "event_id");
    let parsed = slack::parse_slack_command(command_text).ok();
    let malformed = team_id.is_empty() || user_id.is_empty() || !slack::delivery_id_ok(&event_id);
    let is_approve =
        command_text.split(char::is_whitespace).next().is_some_and(|w| w.eq_ignore_ascii_case("approve"));
    let refusal = if malformed {
        Some("malformed_payload")
    } else if is_approve {
        // A message can be posted on a person's behalf by any app holding
        // their user token; a slash command can only be invoked by the
        // person. Approvals therefore never come through the Events API.
        Some(APPROVE_NOT_ON_EVENTS)
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
    EventRequest::Run(Box::new(Request { delivery, parsed, response_url: None }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_command_needs_a_marker_and_a_command_word() {
        assert_eq!(marked_command("!task fix it"), Some("task fix it"));
        assert_eq!(marked_command("/task fix it"), Some("task fix it"));
        assert_eq!(marked_command("<@U0BOT> !status task-1"), Some("status task-1"));
        assert_eq!(marked_command("<@U0BOT|hub>  <@U0OTHER> /Plan x"), Some("Plan x"));
        assert_eq!(marked_command("!approve 5"), Some("approve 5"));
        for text in [
            "task fix it",
            "Plan looks good to me",
            "Task done, thanks!",
            "Assign it to Bob tomorrow",
            "<@U0BOT> task fix it",
            "! task fix it",
            "!tasks fix it",
            "!taskfix it",
            "!hello",
            "<@U0BOT",
            "",
        ] {
            assert_eq!(marked_command(text), None, "{text:?}");
        }
    }

    #[test]
    fn only_a_bot_authorization_counts() {
        let env = |v: Value| v.as_object().unwrap().clone();
        assert!(bot_authorized(&env(json!({ "authorizations": [{ "user_id": "U0BOT", "is_bot": true }] }))));
        assert!(bot_authorized(&env(json!({ "authorizations": [{ "is_bot": false }, { "is_bot": true }] }))));
        assert!(!bot_authorized(&env(
            json!({ "authorizations": [{ "user_id": "U0HUMAN", "is_bot": false }] })
        )));
        assert!(!bot_authorized(&env(json!({ "authorizations": [{ "is_bot": "true" }] }))));
        assert!(!bot_authorized(&env(json!({}))));
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

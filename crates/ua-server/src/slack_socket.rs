//! Slack Socket Mode: Slack over an outbound WebSocket, for a hub with no
//! public URL (feature `slack-socket`).
//!
//! The hub calls `apps.connections.open` with the app-level token
//! (`UA_SLACK_APP_TOKEN`, `xapp-…`) and gets a one-time `wss://` URL; Slack
//! then sends `hello`, envelopes (`{envelope_id, type, payload,
//! accepts_response_payload}`) and `disconnect` messages over it. Each
//! envelope is acknowledged by sending `{envelope_id}` back (with an
//! ephemeral `payload` for a slash command that accepts one).
//!
//! Every envelope goes through the same functions as the signed HTTP routes
//! ([`crate::slack_api::command_request`], [`crate::slack_api::event_request`],
//! [`crate::slack_api::admit_and_run`]): the identity allowlist, `can_approve`,
//! approve only from slash commands, the event filters, the dedupe on event
//! and trigger ids, the governed call with the `slack` transport and the
//! ledger events. There is no signature: the WebSocket is authenticated by
//! the app token over TLS. In place of the signed bytes, the envelope id goes
//! into the replay table ([`ua_tools::families::slack::envelope_sha`]), so a
//! redelivered envelope is acknowledged again and runs nothing.
//!
//! Outbound safety: `apps.connections.open` goes only to `https://slack.com`
//! through the guarded web client; the socket URL must be `wss` on
//! `slack.com` or a subdomain, the default port and no user info
//! ([`ua_tools::families::slack::socket_url`]), every address it resolves to
//! must be public, and TLS is rustls with the platform verifier. Messages are
//! capped at 1 MiB and envelope payloads at 64 KiB; connects, the handshake
//! and idle connections time out; reconnects back off exponentially with
//! jitter, capped at a minute. An app token Slack refuses (`invalid_auth` and
//! the like) stops the transport with one log line.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use secrecy::SecretString;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_util::sync::CancellationToken;
use ua_tools::families::slack::{self, OpenError, SocketState};

use crate::AppState;
use crate::slack_api::{Admitted, EventRequest, Replay, admit_and_run, command_request, event_request};

/// Largest WebSocket message read; envelope payloads are further capped at
/// [`slack::MAX_BODY_BYTES`].
const MAX_MESSAGE: usize = 1024 * 1024;
/// Connect, TLS and WebSocket handshake, each.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// A connection with no frame at all for this long is dropped and reopened.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// How often the hub pings Slack.
const PING_EVERY: Duration = Duration::from_secs(30);
/// How long one envelope may take to be admitted before it is acknowledged
/// anyway (Slack wants an acknowledgement within about 3 seconds).
const ACK_DEADLINE: Duration = Duration::from_millis(2500);
/// Longest envelope id accepted.
const MAX_ENVELOPE_ID: usize = 128;

/// Reconnect delays: doubling from `base` to `cap`, each multiplied by a
/// random factor in [0.5, 1.0).
struct Backoff {
    base: Duration,
    cap: Duration,
    attempt: u32,
}

impl Backoff {
    fn new(test: bool) -> Self {
        if test {
            Self { base: Duration::from_millis(20), cap: Duration::from_millis(200), attempt: 0 }
        } else {
            Self { base: Duration::from_secs(1), cap: Duration::from_secs(60), attempt: 0 }
        }
    }

    fn next(&mut self) -> Duration {
        let exp = self.base.saturating_mul(1u32 << self.attempt.min(16)).min(self.cap);
        self.attempt = self.attempt.saturating_add(1);
        exp.mul_f64(rand::random_range(0.5..1.0))
    }

    fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// How a connection ended.
enum End {
    /// `ct` was cancelled; the socket was closed.
    Shutdown,
    /// Slack asked for a reconnect (`disconnect`) or closed the socket.
    /// `hello` says whether the connection got as far as Slack's `hello`.
    Reconnect { hello: bool, reason: String },
}

/// Run the transport until `ct` is cancelled or Slack refuses the token.
/// `ua serve` starts this on its task tracker when
/// [`slack::socket_status`] allows it.
pub async fn run(state: AppState, token: SecretString, ct: CancellationToken) {
    let cfg = state.hub.cfg().clone();
    let test = cfg.slack_socket_test_api.is_some();
    let mut backoff = Backoff::new(test);
    let _ = rustls::crypto::ring::default_provider().install_default();
    loop {
        if ct.is_cancelled() {
            break;
        }
        slack::set_socket_state(SocketState::Connecting);
        let delay = match slack::open_socket_url(&cfg, &token).await {
            Err(OpenError::Auth(code)) => {
                tracing::warn!(
                    error = %code,
                    "Slack Socket Mode stopped: Slack refused the app token; fix UA_SLACK_APP_TOKEN and restart"
                );
                slack::set_socket_state(SocketState::AuthFailed);
                return;
            }
            Err(OpenError::BadUrl(reason)) => {
                tracing::warn!(reason, "Slack Socket Mode: refused the socket URL Slack returned");
                let recorded =
                    state.hub.db().write_async(move |tx| slack::record_socket_url_refused(tx, reason)).await;
                if let Err(e) = recorded {
                    tracing::warn!(code = e.code(), "could not ledger a refused Slack socket URL");
                }
                backoff.next()
            }
            Err(OpenError::Transient(code)) => {
                tracing::info!(error = %code, "Slack Socket Mode: could not open a connection; retrying");
                backoff.next()
            }
            Ok(url) => match session(&state, &url, &ct, test).await {
                Ok(End::Shutdown) => break,
                Ok(End::Reconnect { hello, reason }) => {
                    tracing::info!(reason = %reason, "Slack Socket Mode: reconnecting");
                    if hello {
                        backoff.reset();
                        Duration::ZERO
                    } else {
                        backoff.next()
                    }
                }
                Err(why) => {
                    tracing::info!(error = %why, "Slack Socket Mode: connection failed; retrying");
                    backoff.next()
                }
            },
        };
        if !delay.is_zero() {
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = ct.cancelled() => break,
            }
        }
    }
    slack::set_socket_state(SocketState::Stopped);
}

/// A byte stream the WebSocket runs over: plain TCP (test hook only) or TLS.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// TCP (and, for `wss`, TLS) to the socket URL's host. Every resolved
/// address of a `wss` host must be public.
async fn connect(url: &url::Url) -> Result<Box<dyn Io>, String> {
    let host = url.host_str().ok_or("no host")?.to_string();
    let port = url.port_or_known_default().ok_or("no port")?;
    let lookup = tokio::net::lookup_host((host.as_str(), port));
    let addrs: Vec<SocketAddr> = tokio::time::timeout(CONNECT_TIMEOUT, lookup)
        .await
        .map_err(|_| "resolve timed out".to_string())?
        .map_err(|_| "could not resolve the socket host".to_string())?
        .collect();
    if addrs.is_empty() {
        return Err("the socket host resolved to no address".into());
    }
    let tls = url.scheme() == "wss";
    if tls && let Some(bad) = addrs.iter().find_map(|a| ua_tools::families::web::non_public_reason(a.ip())) {
        return Err(format!("the socket host resolves to a non-public address ({bad})"));
    }
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(&addrs[..]))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("connect failed: {}", e.kind()))?;
    if !tls {
        return Ok(Box::new(tcp));
    }
    use rustls_platform_verifier::ConfigVerifierExt;
    let config =
        rustls::ClientConfig::with_platform_verifier().map_err(|_| "TLS setup failed".to_string())?;
    let name =
        rustls::pki_types::ServerName::try_from(host).map_err(|_| "bad TLS server name".to_string())?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp))
        .await
        .map_err(|_| "TLS handshake timed out".to_string())?
        .map_err(|_| "TLS handshake failed".to_string())?;
    Ok(Box::new(stream))
}

/// One connection, from connect to `disconnect`, close or shutdown.
async fn session(
    state: &AppState,
    url: &url::Url,
    ct: &CancellationToken,
    _test: bool,
) -> Result<End, String> {
    let io = connect(url).await?;
    let config =
        WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
    let handshake = tokio_tungstenite::client_async_with_config(url.as_str(), io, Some(config));
    let (ws, _) = tokio::time::timeout(CONNECT_TIMEOUT, handshake)
        .await
        .map_err(|_| "WebSocket handshake timed out".to_string())?
        .map_err(|_| "WebSocket handshake failed".to_string())?;
    let (mut sink, mut stream) = ws.split();
    let mut hello = false;
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.tick().await;
    loop {
        let frame = tokio::select! {
            _ = ct.cancelled() => {
                let _ = sink.send(Message::Close(None)).await;
                let _ = sink.close().await;
                return Ok(End::Shutdown);
            }
            _ = ping.tick() => {
                sink.send(Message::Ping(Vec::new().into())).await.map_err(|_| "ping failed".to_string())?;
                continue;
            }
            f = tokio::time::timeout(IDLE_TIMEOUT, stream.next()) => f,
        };
        let msg = match frame {
            Err(_) => return Err("idle timeout".into()),
            Ok(None) => return Ok(End::Reconnect { hello, reason: "closed".into() }),
            Ok(Some(Err(_))) => return Err("read failed (or a message over the size limit)".into()),
            Ok(Some(Ok(m))) => m,
        };
        let text = match msg {
            Message::Text(t) => t,
            Message::Ping(p) => {
                let _ = sink.send(Message::Pong(p)).await;
                continue;
            }
            Message::Close(_) => return Ok(End::Reconnect { hello, reason: "closed".into() }),
            _ => continue,
        };
        let Ok(Value::Object(m)) = serde_json::from_str::<Value>(text.as_str()) else {
            tracing::debug!("Slack Socket Mode: ignored a message that is not a JSON object");
            continue;
        };
        match m.get("type").and_then(Value::as_str) {
            Some("hello") => {
                hello = true;
                slack::set_socket_state(SocketState::Connected);
                tracing::info!("Slack Socket Mode connected");
                continue;
            }
            Some("disconnect") => {
                let reason: String = m
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("unspecified")
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .take(64)
                    .collect();
                let _ = sink.close().await;
                return Ok(End::Reconnect { hello, reason });
            }
            _ => {}
        }
        if let Some(ack) = acknowledge(state, m).await {
            sink.send(Message::text(ack.to_string())).await.map_err(|_| "ack failed".to_string())?;
        }
    }
}

/// Admit one envelope on its own task, so a panic in it never ends the
/// connection, and build the acknowledgement. `None` when it cannot be
/// acknowledged (no usable envelope id) or must not be yet (the admission
/// transaction failed, so Slack should redeliver it).
async fn acknowledge(state: &AppState, envelope: Map<String, Value>) -> Option<Value> {
    let id = envelope.get("envelope_id").and_then(Value::as_str).unwrap_or_default().to_string();
    if id.is_empty() || id.len() > MAX_ENVELOPE_ID || !id.bytes().all(|b| b.is_ascii_graphic()) {
        tracing::debug!("Slack Socket Mode: ignored an envelope without a usable envelope_id");
        return None;
    }
    let bare = json!({ "envelope_id": id });
    let task = tokio::spawn(handle_envelope(state.clone(), id.clone(), envelope));
    match tokio::time::timeout(ACK_DEADLINE, task).await {
        Ok(Ok(Some(ack))) => Some(ack),
        Ok(Ok(None)) => None,
        Ok(Err(_)) => {
            tracing::warn!(
                "Slack Socket Mode: an envelope's handler failed; acknowledged without running it"
            );
            Some(bare)
        }
        // Slow: acknowledge now; the admission finishes on its own task.
        Err(_) => Some(bare),
    }
}

/// The work for one envelope. Same steps as the HTTP routes, from the
/// envelope's `payload`.
async fn handle_envelope(state: AppState, id: String, envelope: Map<String, Value>) -> Option<Value> {
    let bare = json!({ "envelope_id": id });
    let payload = envelope.get("payload").and_then(Value::as_object);
    let size = payload.map(|p| serde_json::to_vec(p).map(|v| v.len()).unwrap_or(usize::MAX)).unwrap_or(0);
    if size > slack::MAX_BODY_BYTES {
        tracing::debug!(size, "Slack Socket Mode: refused an envelope payload over 64 KiB");
        return Some(bare);
    }
    let accepts_payload = envelope.get("accepts_response_payload").and_then(Value::as_bool) == Some(true);
    let (req, is_command) = match (envelope.get("type").and_then(Value::as_str), payload) {
        (Some("slash_commands"), Some(p)) => (command_request(Some(p)), true),
        (Some("slash_commands"), None) => (command_request(None), true),
        // The payload of an `events_api` envelope is the Events API
        // `event_callback` body; anything else is not acted on.
        (Some("events_api"), Some(p)) => match event_request(p) {
            EventRequest::Run(req) => (*req, false),
            _ => return Some(bare),
        },
        // Interactions and anything new: acknowledged, not acted on.
        _ => return Some(bare),
    };
    match admit_and_run(state, Replay::Envelope(id.clone()), req).await {
        Admitted::Answer(text) if is_command && accepts_payload => Some(json!({
            "envelope_id": id,
            "payload": { "response_type": "ephemeral", "text": text },
        })),
        Admitted::Answer(_) | Admitted::Replayed => Some(bare),
        Admitted::Internal => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_its_cap_with_jitter() {
        let mut b = Backoff::new(false);
        let d: Vec<Duration> = (0..10).map(|_| b.next()).collect();
        assert!(d[0] >= Duration::from_millis(500) && d[0] < Duration::from_secs(1));
        assert!(d[3] >= Duration::from_secs(4) && d[3] < Duration::from_secs(8));
        assert!(d[9] >= Duration::from_secs(30) && d[9] < Duration::from_secs(60));
        b.reset();
        assert!(b.next() < Duration::from_secs(1));
    }
}

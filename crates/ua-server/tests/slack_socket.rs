//! Slack Socket Mode, end to end with no real network: an in-process HTTP
//! server stands in for `apps.connections.open` and an in-process WebSocket
//! server for Slack's socket. Envelopes are built here in the shapes Slack
//! documents; the ids are made up.

mod common;

use secrecy::SecretString;
use ua_core::{Config, SlackIdentity};
use ua_tools::families::slack;

const TEAM: &str = "T0TEAM1";
/// `operator`, coordinator, `can_approve`.
const HUMAN: &str = "U0HUMAN";
/// `plain-human`, coordinator, no `can_approve`.
const PLAIN: &str = "U0PLAIN";
const TOKEN: &str = "xapp-1-A0TEST-0-testtoken";

fn map(user: &str, identity: &str, can_approve: bool) -> SlackIdentity {
    SlackIdentity { team_id: TEAM.into(), user_id: user.into(), identity: identity.into(), can_approve }
}

/// Socket Mode on, the HTTP routes off and no signing secret.
fn socket_config(api: &str) -> Config {
    let mut cfg = common::config();
    cfg.slack_socket_mode = true;
    cfg.slack_app_token_value = Some(SecretString::from(TOKEN.to_string()));
    cfg.slack_socket_test_api = Some(api.to_string());
    cfg.human_identities = vec!["operator".into(), "plain-human".into()];
    cfg.profiles.insert("operator".into(), "coordinator".into());
    cfg.profiles.insert("plain-human".into(), "coordinator".into());
    cfg.approval_tools = vec!["task_delete".into()];
    cfg.slack_identities = vec![map(HUMAN, "operator", true), map(PLAIN, "plain-human", false)];
    cfg.check_slack_identities().unwrap();
    cfg
}

#[cfg(not(feature = "slack-socket"))]
#[tokio::test]
async fn without_the_feature_socket_mode_is_reported_not_compiled() {
    let cfg = socket_config("http://127.0.0.1:9");
    let why = slack::socket_status(&cfg).unwrap_err();
    assert!(why.contains("without the slack-socket feature"), "{why}");
    let h = common::TestHub::new(cfg);
    let ct = tokio_util::sync::CancellationToken::new();
    ua_server::start_slack_socket(&h.state, &ct);
    assert_eq!(h.state.calls.len(), 0, "nothing was started");
    assert_eq!(ua_tools::build_features()["slack_socket"], false);
}

#[cfg(feature = "slack-socket")]
mod socket {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::http::HeaderMap;
    use futures::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_util::sync::CancellationToken;
    use ua_core::{ActorKind, Caller, Profile, identity::Transport};

    use super::common::TestHub;
    use super::*;

    const STRANGER: &str = "U0STRANGER";

    /// One accepted socket: what the test sends, and what the hub sent back
    /// (`{"__closed": true}` when the hub closed it).
    struct Conn {
        out: mpsc::UnboundedSender<Message>,
        inbox: mpsc::UnboundedReceiver<Value>,
    }

    impl Conn {
        fn send(&self, v: Value) {
            self.out.send(Message::text(v.to_string())).unwrap();
        }

        async fn recv(&mut self) -> Value {
            tokio::time::timeout(Duration::from_secs(5), self.inbox.recv())
                .await
                .expect("the hub answered within 5 s")
                .expect("socket still open")
        }
    }

    /// How the stand-in behaves on one connection.
    #[derive(Clone, Copy, PartialEq)]
    enum Peer {
        /// `hello`, then reads (and so answers pings) and relays.
        Normal,
        /// `hello`, then nothing at all: no frames, no pongs.
        SilentAfterHello,
        /// The handshake, then nothing: no `hello`, no pongs.
        NoHello,
        /// The handshake, then reads (so answers pings) but never says `hello`.
        NoHelloAnswersPings,
    }

    /// The stand-in for Slack.
    struct MockSlack {
        api: String,
        opens: Arc<AtomicUsize>,
        /// Scripted `apps.connections.open` answers; empty means a good URL.
        answers: Arc<Mutex<VecDeque<Value>>>,
        conns: mpsc::UnboundedReceiver<Conn>,
        /// Behaviour of the next connections; empty means `Normal`.
        peers: Arc<Mutex<VecDeque<Peer>>>,
        /// Connections accepted (handshake done), whatever their behaviour.
        accepted: Arc<AtomicUsize>,
        /// This mock's socket URL, and the handshake URIs it saw.
        ws_url: String,
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl MockSlack {
        async fn start() -> Self {
            let ws = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let ticket: u64 = rand::random();
            let ws_url = format!("ws://{}/link/?ticket={ticket}&app_id=A0TEST", ws.local_addr().unwrap());
            let seen: Arc<Mutex<Vec<String>>> = Arc::default();
            let seen_w = seen.clone();
            let (conn_tx, conns) = mpsc::unbounded_channel();
            let peers: Arc<Mutex<VecDeque<Peer>>> = Arc::default();
            let accepted = Arc::new(AtomicUsize::new(0));
            let (ps, acc) = (peers.clone(), accepted.clone());
            tokio::spawn(async move {
                while let Ok((tcp, _)) = ws.accept().await {
                    let conn_tx = conn_tx.clone();
                    let (ps, acc) = (ps.clone(), acc.clone());
                    let seen = seen_w.clone();
                    let own = format!("ticket={ticket}&");
                    let peer_addr = tcp.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                    tokio::spawn(async move {
                        let mut uri = String::new();
                        // tungstenite's callback signature fixes the error type.
                        #[allow(clippy::result_large_err)]
                        let record = |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                                      resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                            uri = req.uri().to_string();
                            Ok(resp)
                        };
                        let Ok(socket) = tokio_tungstenite::accept_hdr_async(tcp, record).await else {
                            eprintln!(
                                "mock slack: a connection from {peer_addr} sent no WebSocket handshake"
                            );
                            return;
                        };
                        seen.lock().unwrap().push(format!("{uri} from {peer_addr}"));
                        // Only the hub's own handshake (this mock's ticket) takes a
                        // scripted behaviour. Anything else that connects to the
                        // port (a local port probe) must not consume one: that is
                        // what made the liveness tests flaky.
                        if !uri.contains(&own) {
                            eprintln!("mock slack: a handshake from {peer_addr} without this mock's ticket");
                            return;
                        }
                        let peer = ps.lock().unwrap().pop_front().unwrap_or(Peer::Normal);
                        acc.fetch_add(1, Ordering::SeqCst);
                        if peer == Peer::NoHello {
                            // Hold the socket open, read nothing, say nothing.
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            drop(socket);
                            return;
                        }
                        if peer == Peer::NoHelloAnswersPings {
                            // Reading answers pings; nothing is ever sent.
                            let (_sink, mut stream) = socket.split();
                            while let Some(Ok(_)) = stream.next().await {}
                            return;
                        }
                        let (mut sink, mut stream) = socket.split();
                        let hello = json!({
                            "type": "hello",
                            "num_connections": 1,
                            "connection_info": { "app_id": "A0TEST" },
                            "debug_info": { "host": "applink-test", "approximate_connection_time": 18060 },
                        });
                        let _ = sink.send(Message::text(hello.to_string())).await;
                        if peer == Peer::SilentAfterHello {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            drop((sink, stream));
                            return;
                        }
                        let (out, mut out_rx) = mpsc::unbounded_channel::<Message>();
                        let (in_tx, inbox) = mpsc::unbounded_channel();
                        let _ = conn_tx.send(Conn { out, inbox });
                        loop {
                            tokio::select! {
                                m = out_rx.recv() => match m {
                                    Some(m) => { let _ = sink.send(m).await; }
                                    None => break,
                                },
                                f = stream.next() => match f {
                                    Some(Ok(Message::Text(t))) => {
                                        let _ = in_tx.send(serde_json::from_str(t.as_str()).unwrap_or(Value::Null));
                                    }
                                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                                        let _ = in_tx.send(json!({ "__closed": true }));
                                        break;
                                    }
                                    _ => {}
                                },
                            }
                        }
                    });
                }
            });
            let opens = Arc::new(AtomicUsize::new(0));
            let answers: Arc<Mutex<VecDeque<Value>>> = Arc::default();
            let (o, a, url) = (opens.clone(), answers.clone(), ws_url.clone());
            let app = axum::Router::new().route(
                "/apps.connections.open",
                axum::routing::post(move |headers: HeaderMap| {
                    let (o, a, url) = (o.clone(), a.clone(), url.clone());
                    async move {
                        o.fetch_add(1, Ordering::SeqCst);
                        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
                        if auth != format!("Bearer {TOKEN}") {
                            return axum::Json(json!({ "ok": false, "error": "not_authed" }));
                        }
                        let next = a.lock().unwrap().pop_front();
                        axum::Json(next.unwrap_or_else(|| json!({ "ok": true, "url": url })))
                    }
                }),
            );
            let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let api = format!("http://{}", http.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(http, app).await.unwrap() });
            Self { api, opens, answers, conns, peers, accepted, ws_url, seen }
        }

        async fn next_conn(&mut self) -> Conn {
            tokio::time::timeout(Duration::from_secs(5), self.conns.recv())
                .await
                .expect("the hub connected within 5 s")
                .unwrap()
        }

        fn opens(&self) -> usize {
            self.opens.load(Ordering::SeqCst)
        }

        fn accepted(&self) -> usize {
            self.accepted.load(Ordering::SeqCst)
        }
    }

    /// The hub's log lines at info and above on this test's thread (the
    /// test runtime is single-threaded, so the transport's tasks log here).
    #[derive(Clone, Default)]
    struct Log(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Log {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Log {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    /// A hub with Socket Mode running against the mock.
    struct Rig {
        hub: TestHub,
        ct: CancellationToken,
        slack: MockSlack,
        log: Log,
        _log_guard: tracing::subscriber::DefaultGuard,
    }

    impl Rig {
        /// Wait (up to 5 s) for `n` accepted connections; on failure, show
        /// why each session ended.
        async fn wait_accepted(&self, n: usize) {
            for _ in 0..250 {
                if self.slack.accepted() >= n {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!(
                "only {} connection(s) accepted, expected {n}; url {}; seen {:?}; opens {}; tasks {}; peers left {}; transport log:\n{}",
                self.slack.accepted(),
                self.slack.ws_url,
                self.slack.seen.lock().unwrap(),
                self.slack.opens(),
                self.hub.state.calls.len(),
                self.slack.peers.lock().unwrap().len(),
                self.log.text()
            );
        }
    }

    async fn rig_with(tweak: impl FnOnce(&mut Config)) -> Rig {
        rig_answering(tweak, Vec::new()).await
    }

    /// A rig whose first `apps.connections.open` answers are `answers`.
    async fn rig_answering(tweak: impl FnOnce(&mut Config), answers: Vec<Value>) -> Rig {
        rig_full(tweak, answers, Vec::new()).await
    }

    async fn rig_full(tweak: impl FnOnce(&mut Config), answers: Vec<Value>, peers: Vec<Peer>) -> Rig {
        use tracing_subscriber::Layer;
        use tracing_subscriber::layer::SubscriberExt;
        let log = Log::default();
        let writer = log.clone();
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::EnvFilter::new("info"));
        let _log_guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
        let slack = MockSlack::start().await;
        slack.answers.lock().unwrap().extend(answers);
        slack.peers.lock().unwrap().extend(peers);
        let mut cfg = socket_config(&slack.api);
        tweak(&mut cfg);
        let hub = TestHub::new(cfg);
        let ct = CancellationToken::new();
        ua_server::start_slack_socket(&hub.state, &ct);
        Rig { hub, ct, slack, log, _log_guard }
    }

    async fn rig() -> (Rig, Conn) {
        let mut r = rig_with(|_| {}).await;
        let c = r.slack.next_conn().await;
        (r, c)
    }

    async fn scalar(h: &TestHub, sql: &'static str) -> i64 {
        h.state.hub.db().read_async(move |c| Ok(c.query_row(sql, [], |r| r.get(0))?)).await.unwrap()
    }

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

    /// Wait (up to 5 s) until `n` commands have recorded an outcome.
    async fn executed(h: &TestHub, n: usize) -> Vec<(String, Value)> {
        for _ in 0..250 {
            let rows = events(h, "agent.slack.request.executed").await;
            if rows.len() >= n {
                return rows;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("fewer than {n} commands finished");
    }

    async fn tasks(h: &TestHub) -> i64 {
        scalar(h, "SELECT COUNT(*) FROM tasks").await
    }

    fn slash(envelope_id: &str, user: &str, command: &str, text: &str, trigger: &str) -> Value {
        json!({
            "envelope_id": envelope_id,
            "type": "slash_commands",
            "accepts_response_payload": true,
            "payload": {
                "token": "deprecated-verification-token",
                "team_id": TEAM,
                "team_domain": "example",
                "channel_id": "C0CHANNEL",
                "channel_name": "general",
                "user_id": user,
                "user_name": "operator",
                "command": command,
                "text": text,
                "api_app_id": "A0TEST",
                "response_url": "",
                "trigger_id": trigger,
            },
        })
    }

    fn event(envelope_id: &str, user: &str, event_id: &str, event_type: &str, text: &str) -> Value {
        let mut ev = json!({
            "type": event_type,
            "user": user,
            "text": text,
            "ts": "1700000000.000100",
            "channel": "D0DIRECT",
            "event_ts": "1700000000.000100",
        });
        if event_type == "message" {
            ev["channel_type"] = json!("im");
        }
        json!({
            "envelope_id": envelope_id,
            "type": "events_api",
            "accepts_response_payload": false,
            "retry_attempt": 0,
            "retry_reason": "",
            "payload": {
                "token": "deprecated-verification-token",
                "team_id": TEAM,
                "api_app_id": "A0TEST",
                "type": "event_callback",
                "event_id": event_id,
                "event_time": 1_700_000_000,
                "authorizations": [{
                    "enterprise_id": null,
                    "team_id": TEAM,
                    "user_id": "U0BOT",
                    "is_bot": true,
                    "is_enterprise_install": false,
                }],
                "event": ev,
            },
        })
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

    async fn pending_approval(h: &TestHub, requester: &Caller) -> i64 {
        let reg = &h.state.registry;
        let task =
            reg.call(&h.state.hub, requester, "task_add", json!({ "title": "to delete" })).await.unwrap();
        match reg.call(&h.state.hub, requester, "task_delete", json!({ "id": task["id"] })).await {
            Err(ua_core::UaError::ApprovalRequired { approval_id, .. }) => approval_id,
            other => panic!("expected approval_required, got {other:?}"),
        }
    }

    async fn approval_status(h: &TestHub, id: i64) -> String {
        h.state
            .hub
            .db()
            .read_async(move |c| {
                Ok(c.query_row("SELECT status FROM approvals WHERE id = ?1", [id], |r| r.get(0))?)
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_slash_command_runs_once_and_the_ack_carries_the_answer() {
        let (r, mut c) = rig().await;
        assert!(r.hub.state.hub.cfg().slack_signing_secret().is_none(), "no signing secret needed");
        c.send(slash("env-1", HUMAN, "/task", "write the report", "7.1.a"));
        let ack = c.recv().await;
        assert_eq!(ack["envelope_id"], "env-1");
        assert_eq!(ack["payload"]["response_type"], "ephemeral");
        assert!(ack["payload"]["text"].as_str().unwrap().starts_with("Accepted /task"), "{ack}");
        let ran = executed(&r.hub, 1).await;
        assert_eq!((ran[0].0.as_str(), ran[0].1["tool"].as_str()), ("operator", Some("task_add")));
        assert_eq!(tasks(&r.hub).await, 1);
        let transport: String = r
            .hub
            .state
            .hub
            .db()
            .read_async(|c| {
                Ok(c.query_row("SELECT transport FROM tool_calls WHERE tool = 'task_add'", [], |r| r.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(transport, "slack");
        assert_eq!(events(&r.hub, "agent.slack.envelope_accepted").await.len(), 1);
        // No token anywhere in the ledger.
        let all: String = r
            .hub
            .state
            .hub
            .db()
            .read_async(|c| {
                Ok(c.query_row("SELECT group_concat(payload, ' ') FROM event_log", [], |r| r.get(0))?)
            })
            .await
            .unwrap();
        assert!(!all.contains("xapp-"), "{all}");
    }

    #[tokio::test]
    async fn an_events_api_envelope_with_a_marked_command_runs() {
        let (r, mut c) = rig().await;
        c.send(event("env-e1", HUMAN, "Ev0SOCK1", "app_mention", "<@U0BOT> !task from a mention"));
        assert_eq!(c.recv().await, json!({ "envelope_id": "env-e1" }));
        c.send(event("env-e2", HUMAN, "Ev0SOCK2", "message", "!task from a direct message"));
        assert_eq!(c.recv().await, json!({ "envelope_id": "env-e2" }));
        // Unmarked conversation is acknowledged and ignored.
        c.send(event("env-e3", HUMAN, "Ev0SOCK3", "message", "Task done, thanks!"));
        assert_eq!(c.recv().await, json!({ "envelope_id": "env-e3" }));
        executed(&r.hub, 2).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(tasks(&r.hub).await, 2);
    }

    #[tokio::test]
    async fn a_redelivered_envelope_runs_once() {
        let (r, mut c) = rig().await;
        let env = slash("env-r1", HUMAN, "/task", "once", "7.2.a");
        c.send(env.clone());
        assert!(c.recv().await["payload"]["text"].as_str().unwrap().starts_with("Accepted"));
        // Slack redelivers an envelope it saw no acknowledgement for.
        c.send(env);
        assert_eq!(c.recv().await, json!({ "envelope_id": "env-r1" }), "acknowledged again, nothing run");
        // A new envelope carrying the same trigger id: the delivery dedupe.
        c.send(slash("env-r2", HUMAN, "/task", "once", "7.2.a"));
        assert_eq!(c.recv().await["payload"]["text"], "Already received.");
        // The same for an event id.
        c.send(event("env-r3", HUMAN, "Ev0DUP", "app_mention", "<@U0BOT> !task again"));
        c.recv().await;
        c.send(event("env-r4", HUMAN, "Ev0DUP", "app_mention", "<@U0BOT> !task again"));
        c.recv().await;
        executed(&r.hub, 2).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(tasks(&r.hub).await, 2);
        assert_eq!(events(&r.hub, "agent.slack.request.deduped").await.len(), 2);
    }

    #[tokio::test]
    async fn an_unmapped_user_changes_nothing() {
        let (r, mut c) = rig().await;
        let before = scalar(&r.hub, "SELECT COUNT(*) FROM event_log").await;
        c.send(slash("env-u1", STRANGER, "/task", "x", "7.3.a"));
        let ack = c.recv().await;
        assert!(ack["payload"]["text"].as_str().unwrap().contains("not mapped"), "{ack}");
        c.send(event("env-u2", STRANGER, "Ev0UNM", "app_mention", "<@U0BOT> !task x"));
        assert_eq!(c.recv().await, json!({ "envelope_id": "env-u2" }));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(scalar(&r.hub, "SELECT COUNT(*) FROM event_log").await, before, "no ledger row");
        assert_eq!(tasks(&r.hub).await, 0);
    }

    #[tokio::test]
    async fn approve_follows_can_approve_and_separation_of_duties() {
        let (r, mut c) = rig().await;
        // With can_approve: approved.
        let id = pending_approval(&r.hub, &agent("builder-9")).await;
        c.send(slash("env-a1", HUMAN, "/approve", &id.to_string(), "7.4.a"));
        c.recv().await;
        executed(&r.hub, 1).await;
        assert_eq!(approval_status(&r.hub, id).await, "approved");
        // Without can_approve: refused before anything runs.
        let id2 = pending_approval(&r.hub, &agent("builder-9")).await;
        c.send(slash("env-a2", PLAIN, "/approve", &id2.to_string(), "7.4.b"));
        let ack = c.recv().await;
        assert!(ack["payload"]["text"].as_str().unwrap().contains("Approvals are not enabled"), "{ack}");
        assert_eq!(approval_status(&r.hub, id2).await, "pending");
        // Separation of duties: the requester cannot approve their own request.
        let own = Caller { kind: ActorKind::Human, profile: Profile::Coordinator, ..agent("operator") };
        let id3 = pending_approval(&r.hub, &own).await;
        c.send(slash("env-a3", HUMAN, "/approve", &id3.to_string(), "7.4.c"));
        c.recv().await;
        let ran = executed(&r.hub, 2).await;
        assert_eq!(ran[1].1["reason_code"], "self_approval");
        assert_eq!(approval_status(&r.hub, id3).await, "pending");
    }

    #[tokio::test]
    async fn approve_inside_an_event_envelope_is_refused() {
        let (r, mut c) = rig().await;
        let id = pending_approval(&r.hub, &agent("builder-9")).await;
        c.send(event("env-ae", HUMAN, "Ev0APPR", "message", &format!("!approve {id}")));
        assert_eq!(c.recv().await, json!({ "envelope_id": "env-ae" }));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(approval_status(&r.hub, id).await, "pending");
        let refused = events(&r.hub, "agent.slack.request.refused").await;
        assert_eq!(refused[0].1["reason"], "approve_needs_slash_command");
    }

    #[tokio::test]
    async fn an_oversized_envelope_is_refused() {
        let (r, mut c) = rig().await;
        let before = scalar(&r.hub, "SELECT COUNT(*) FROM event_log").await;
        let big = "x".repeat(slack::MAX_BODY_BYTES + 1);
        c.send(slash("env-big", HUMAN, "/task", &big, "7.5.a"));
        assert_eq!(c.recv().await, json!({ "envelope_id": "env-big" }), "acknowledged, not run");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(scalar(&r.hub, "SELECT COUNT(*) FROM event_log").await, before);
        assert_eq!(tasks(&r.hub).await, 0);
        // The connection is still usable.
        c.send(slash("env-ok", HUMAN, "/task", "small", "7.5.b"));
        assert!(c.recv().await["payload"].is_object());
    }

    #[tokio::test]
    async fn a_disconnect_message_makes_the_hub_reconnect() {
        let (mut r, mut c) = rig().await;
        assert_eq!(r.slack.opens(), 1);
        c.send(json!({ "type": "disconnect", "reason": "refresh_requested", "debug_info": { "host": "wss-test" } }));
        assert_eq!(c.recv().await, json!({ "__closed": true }), "the hub closed the old socket");
        let mut c2 = r.slack.next_conn().await;
        assert_eq!(r.slack.opens(), 2, "a fresh apps.connections.open");
        c2.send(slash("env-d1", HUMAN, "/contact", "", "7.6.a"));
        assert!(c2.recv().await["payload"]["text"].as_str().unwrap().contains("operator"));
    }

    #[tokio::test]
    async fn a_socket_url_off_slack_is_refused_and_ledgered() {
        let evil = json!({ "ok": true, "url": "wss://evil.example.com/link/?ticket=1" });
        let mut r = rig_answering(|_| {}, vec![evil.clone(), evil.clone(), evil]).await;
        let mut refused = Vec::new();
        for _ in 0..250 {
            refused = events(&r.hub, "agent.slack.socket.url_refused").await;
            if !refused.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!refused.is_empty(), "the refused URL was ledgered");
        assert_eq!(refused[0].1, json!({ "reason": "not_slack_host" }));
        assert!(!refused[0].1.to_string().contains("evil"), "the URL itself is not recorded");
        // After the refusals it backs off and retries; the next good URL works.
        let _c = r.slack.next_conn().await;
        assert!(r.slack.opens() >= 4);
        // Three refusals of the same reason, one ledger row.
        assert_eq!(events(&r.hub, "agent.slack.socket.url_refused").await.len(), 1);
        r.ct.cancel();
    }

    #[tokio::test]
    async fn an_auth_failure_stops_retrying() {
        let slack = MockSlack::start().await;
        let mut cfg = socket_config(&slack.api);
        cfg.slack_app_token_value = Some(SecretString::from("xapp-1-wrong".to_string()));
        let hub = TestHub::new(cfg);
        let ct = CancellationToken::new();
        ua_server::start_slack_socket(&hub.state, &ct);
        for _ in 0..250 {
            if hub.state.calls.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(hub.state.calls.is_empty(), "the transport stopped by itself");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(slack.opens(), 1, "no retry after not_authed");
    }

    #[tokio::test]
    async fn shutdown_closes_the_socket() {
        let (r, mut c) = rig().await;
        r.ct.cancel();
        assert_eq!(c.recv().await, json!({ "__closed": true }));
        r.hub.state.calls.close();
        tokio::time::timeout(Duration::from_secs(5), r.hub.state.calls.wait())
            .await
            .expect("the transport ended");
    }

    #[tokio::test]
    async fn a_delivery_on_both_transports_runs_once() {
        let secret = "test-signing-secret";
        let (r, mut c) = {
            let mut r = rig_with(|cfg| {
                cfg.slack_enabled = true;
                cfg.slack_signing_secret = Some(SecretString::from(secret.to_string()));
            })
            .await;
            let c = r.slack.next_conn().await;
            (r, c)
        };
        // Over HTTP first.
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("team_id", TEAM)
            .append_pair("user_id", HUMAN)
            .append_pair("command", "/task")
            .append_pair("text", "both ways")
            .append_pair("trigger_id", "7.7.a")
            .finish();
        let ts = (ua_core::time::now_ms() / 1000).to_string();
        let sig = slack::slack_signature(secret, &ts, body.as_bytes());
        let req = axum::http::Request::post(ua_server::slack_api::COMMANDS_PATH)
            .header("host", "hub.example.com")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("x-slack-request-timestamp", ts)
            .header("x-slack-signature", sig)
            .body(axum::body::Body::from(body))
            .unwrap();
        assert_eq!(r.hub.send(req).await.status(), 200);
        // Then the same trigger over the socket.
        c.send(slash("env-b1", HUMAN, "/task", "both ways", "7.7.a"));
        assert_eq!(c.recv().await["payload"]["text"], "Already received.");
        executed(&r.hub, 1).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(tasks(&r.hub).await, 1);
    }

    // --- liveness (test timings: idle and hello 1.5 s, a ping every 150 ms,
    // ack deadline 500 ms) ---------------------------------------------------

    #[tokio::test]
    async fn a_peer_that_goes_silent_after_hello_is_dropped_and_reconnected() {
        let r = rig_full(|_| {}, Vec::new(), vec![Peer::SilentAfterHello]).await;
        r.wait_accepted(2).await;
        assert!(r.slack.opens() >= 2, "a fresh apps.connections.open for the new connection");
        r.ct.cancel();
    }

    #[tokio::test]
    async fn a_peer_that_never_says_hello_is_dropped_too() {
        let r = rig_full(|_| {}, Vec::new(), vec![Peer::NoHello]).await;
        r.wait_accepted(2).await;
        r.ct.cancel();
    }

    #[tokio::test]
    async fn a_peer_that_answers_pings_but_never_says_hello_is_dropped() {
        let r = rig_full(|_| {}, Vec::new(), vec![Peer::NoHelloAnswersPings]).await;
        r.wait_accepted(2).await;
        assert!(r.log.text().contains("no hello from Slack"), "{}", r.log.text());
        r.ct.cancel();
    }

    /// The reviewer's case: a slow admission (the database writer held for
    /// two seconds) must not stop the socket being read, so a peer that
    /// answers pings keeps its connection.
    #[tokio::test]
    async fn a_slow_admission_does_not_drop_a_healthy_connection() {
        let (r, mut c) = rig().await;
        let db = r.hub.state.hub.db().clone();
        let held = tokio::task::spawn_blocking(move || {
            db.write(|_| {
                std::thread::sleep(Duration::from_secs(2));
                Ok(())
            })
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        c.send(slash("env-slow", HUMAN, "/task", "slow", "7.9.a"));
        // Acknowledged at the (test) deadline, while admission waits.
        assert_eq!(c.recv().await, json!({ "envelope_id": "env-slow" }));
        held.await.unwrap().unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(r.slack.accepted(), 1, "no reconnect; log:\n{}", r.log.text());
        assert_eq!(r.slack.opens(), 1);
        executed(&r.hub, 1).await;
        r.ct.cancel();
    }

    #[tokio::test]
    async fn a_peer_that_answers_pings_stays_connected() {
        let (r, mut c) = rig().await;
        // Well past the idle deadline, with nothing but pings and pongs.
        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert_eq!(r.slack.accepted(), 1, "no reconnect");
        assert_eq!(r.slack.opens(), 1);
        c.send(slash("env-live", HUMAN, "/contact", "", "7.8.a"));
        assert!(c.recv().await["payload"]["text"].as_str().unwrap().contains("operator"));
        r.ct.cancel();
    }
}

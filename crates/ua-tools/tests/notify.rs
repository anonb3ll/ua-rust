//! Notifications: the outbox, webhook delivery with retries, digests and
//! profile gating.

use std::sync::{Arc, Mutex};

use secrecy::SecretString;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const HEADER_SECRET: &str = "Bearer test-webhook-secret";

/// One request the test server received.
#[derive(Debug, Clone)]
struct Seen {
    head: String,
    body: Value,
}

/// A loopback HTTP server answering with `statuses` in turn (the last one repeats).
async fn server(statuses: Vec<u16>) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        let mut n = 0usize;
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (head, body) = loop {
                let Ok(k) = sock.read(&mut chunk).await else { break (String::new(), Vec::new()) };
                if k == 0 {
                    break (String::new(), Vec::new());
                }
                buf.extend_from_slice(&chunk[..k]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let mut body = buf[end + 4..].to_vec();
                    while body.len() < len {
                        let Ok(k) = sock.read(&mut chunk).await else { break };
                        if k == 0 {
                            break;
                        }
                        body.extend_from_slice(&chunk[..k]);
                    }
                    break (head, body);
                }
            };
            // Only the hook's own POST is recorded and uses up a scripted
            // status; a stray connection or request is dropped unanswered.
            if !head.starts_with("post /hooks/path-secret ") {
                continue;
            }
            let status = statuses[n.min(statuses.len() - 1)];
            n += 1;
            log.lock()
                .unwrap()
                .push(Seen { head, body: serde_json::from_slice(&body).unwrap_or(Value::Null) });
            let reply = format!("HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            let _ = sock.write_all(reply.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    (format!("http://{addr}/hooks/path-secret"), seen)
}

fn hub_with(url: Option<String>) -> Hub {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.notify_webhook_url = url;
    cfg.notify_webhook_secret = Some(SecretString::from(HEADER_SECRET));
    cfg.notify_max_attempts = 3;
    Hub::in_memory(cfg).unwrap()
}

fn caller(label: &str, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile,
        enforce_profile: true,
        session_key: Some(format!("{label}-key")),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

fn staff() -> Caller {
    caller("coord-1", Profile::Coordinator)
}

async fn call(reg: &Registry, hub: &Hub, who: &Caller, tool: &str, args: Value) -> Value {
    reg.call(hub, who, tool, args).await.unwrap_or_else(|e| panic!("{tool} failed: {e}"))
}

fn outbox_message(hub: &Hub, id: i64) -> Option<String> {
    hub.db()
        .read(
            move |c| Ok(c.query_row("SELECT message FROM notify_outbox WHERE id = ?1", [id], |r| r.get(0))?),
        )
        .unwrap()
}

#[tokio::test]
async fn unconfigured_notifications_stay_in_the_outbox() {
    let hub = hub_with(None);
    let reg = builtin_registry();
    let who = staff();
    let res = call(&reg, &hub, &who, "notify", json!({ "message": "  build is green  " })).await;
    assert_eq!(res["delivered"], false);
    assert_eq!(res["status"], "not_configured");
    assert_eq!(res["chars"], 14);
    assert_eq!(res["attempts"], 0);
    let id = res["outbox_id"].as_i64().unwrap();
    // Kept for a later resend.
    assert_eq!(outbox_message(&hub, id).as_deref(), Some("build is green"));

    let status = call(&reg, &hub, &who, "notify_delivery_status", json!({})).await;
    assert_eq!(status["configured"], false);
    assert_eq!(status["count"], 1);
    assert_eq!(status["last_delivery"]["status"], "not_configured");
    assert_eq!(status["failure_count"], 1);
    assert!(!status.to_string().contains("build is green"), "status must not carry message text");

    let err = reg.call(&hub, &who, "notify", json!({ "message": "   " })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");

    let long = "x".repeat(9000);
    let res = call(&reg, &hub, &who, "notify", json!({ "message": long })).await;
    assert_eq!(res["chars"].as_u64().unwrap(), 8000 + "\n…(truncated)".chars().count() as u64);

    let events =
        call(&reg, &hub, &who, "event_log_query", json!({ "channels": ["agent.notify.queued"] })).await;
    assert_eq!(events["count"], 2);
    assert!(!events.to_string().contains("build is green"));
}

#[tokio::test]
async fn webhook_delivery_retries_server_errors() {
    let (url, seen) = server(vec![503, 200]).await;
    let hub = hub_with(Some(url));
    let reg = builtin_registry();
    let who = staff();
    let res = call(&reg, &hub, &who, "notify", json!({ "message": "deploy finished", "timeout_s": 5 })).await;
    assert_eq!(res["delivered"], true, "{res}");
    assert_eq!(res["status"], "delivered");
    assert_eq!(res["attempts"], 2);
    assert_eq!(res["http_status"], 200);

    let got = seen.lock().unwrap().clone();
    assert_eq!(got.len(), 2);
    let last = &got[1];
    assert!(last.head.starts_with("post /hooks/path-secret "), "{}", last.head);
    assert!(last.head.contains(&format!("authorization: {}", HEADER_SECRET.to_ascii_lowercase())));
    assert_eq!(last.body["text"], "deploy finished");
    assert_eq!(last.body["kind"], "notify");
    assert_eq!(last.body["agent"], "coord-1");
    assert_eq!(last.body["outbox_id"], res["outbox_id"]);

    // Delivered text is cleared from the outbox.
    assert_eq!(outbox_message(&hub, res["outbox_id"].as_i64().unwrap()), None);
    let status = call(&reg, &hub, &who, "notify_delivery_status", json!({ "limit": 5 })).await;
    assert_eq!(status["configured"], true);
    assert_eq!(status["success_count"], 1);
    assert_eq!(status["deliveries"][0]["attempts"], 2);
    let text = status.to_string();
    assert!(
        !text.contains("deploy finished")
            && !text.contains("path-secret")
            && !text.contains("test-webhook-secret")
    );

    let delivered =
        call(&reg, &hub, &who, "event_log_query", json!({ "channels": ["agent.notify.delivered"] })).await;
    assert_eq!(delivered["count"], 1);
}

#[tokio::test]
async fn client_errors_are_not_retried() {
    let (url, seen) = server(vec![400]).await;
    let hub = hub_with(Some(url));
    let reg = builtin_registry();
    let res = call(&reg, &hub, &staff(), "notify", json!({ "message": "bad payload" })).await;
    assert_eq!(res["delivered"], false);
    assert_eq!(res["status"], "failed");
    assert_eq!(res["attempts"], 1);
    assert_eq!(res["http_status"], 400);
    assert_eq!(seen.lock().unwrap().len(), 1);
    // A failed message is kept for a resend.
    assert_eq!(outbox_message(&hub, res["outbox_id"].as_i64().unwrap()).as_deref(), Some("bad payload"));

    // A dead endpoint fails after every attempt, without leaking the URL.
    // Port 1 is privileged: it cannot be bound without root and is never
    // handed out as an ephemeral port, so nothing can come to listen there
    // (a dropped ephemeral listener's port could be reused before the connect).
    let hub = hub_with(Some("http://127.0.0.1:1/hooks/path-secret".to_string()));
    let res = call(&reg, &hub, &staff(), "notify", json!({ "message": "nobody home", "timeout_s": 2 })).await;
    assert_eq!(res["status"], "failed");
    assert_eq!(res["attempts"], 3);
    assert!(!res.to_string().contains("path-secret"), "{res}");
}

#[tokio::test]
async fn digests_batch_and_flush() {
    let (url, seen) = server(vec![200]).await;
    let hub = hub_with(Some(url));
    let reg = builtin_registry();
    let dev = caller("builder-1", Profile::Developer);

    let q = call(
        &reg,
        &hub,
        &dev,
        "batch_notify",
        json!({ "messages": ["first", " ", "second"], "category": "audit", "max_batch_size": 3 }),
    )
    .await;
    assert_eq!(q["queued"], 2);
    assert_eq!(q["total_pending"], 2);
    assert_eq!(q["flushed"], false);
    // A verified caller cannot queue under another label.
    let err = reg
        .call(&hub, &dev, "batch_notify", json!({ "messages": ["x"], "agent": "someone-else" }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "denied");

    let status = call(&reg, &hub, &dev, "notify_delivery_status", json!({})).await;
    assert_eq!(status["pending_digest"]["audit"], 2);

    let flushed = call(&reg, &hub, &dev, "flush_digest", json!({ "category": "audit" })).await;
    assert_eq!(flushed["flushed_count"], 2);
    assert_eq!(flushed["delivered"], true);
    let got = seen.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    let text = got[0].body["text"].as_str().unwrap();
    assert!(text.contains("[audit] [builder-1]: first") && text.contains("second"), "{text}");
    assert_eq!(got[0].body["kind"], "digest");

    let empty = call(&reg, &hub, &dev, "flush_digest", json!({})).await;
    assert_eq!(empty["flushed_count"], 0);

    // Reaching max_batch_size flushes on its own.
    let auto =
        call(&reg, &hub, &dev, "batch_notify", json!({ "messages": ["a", "b"], "max_batch_size": 2 })).await;
    assert_eq!(auto["flushed"], true);
    assert_eq!(auto["total_pending"], 0);
    assert_eq!(auto["delivery_result"]["flushed_count"], 2);
}

#[tokio::test]
async fn notify_keeps_the_profile_gate() {
    let hub = hub_with(None);
    let reg = builtin_registry();
    for profile in [Profile::Developer, Profile::Reviewer] {
        let err = reg
            .call(&hub, &caller("builder-1", profile), "notify", json!({ "message": "hi" }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "denied", "{profile}");
    }
    call(&reg, &hub, &staff(), "notify", json!({ "message": "hi" })).await;
    // The read-only status stays visible to developers.
    call(&reg, &hub, &caller("builder-1", Profile::Developer), "notify_delivery_status", json!({})).await;
}

#[tokio::test]
async fn credentials_in_the_url_are_sent_as_basic_auth() {
    let (url, seen) = server(vec![200]).await;
    let url = url.replacen("http://", "http://hook-user:p%40ss@", 1);
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.notify_webhook_url = Some(url);
    let hub = Hub::in_memory(cfg).unwrap();
    let res = call(&builtin_registry(), &hub, &staff(), "notify", json!({ "message": "hi" })).await;
    assert_eq!(res["delivered"], true, "{res}");
    let head = seen.lock().unwrap()[0].head.clone();
    // base64("hook-user:p@ss"), lowercased by the test server.
    assert!(head.contains("authorization: basic ag9vay11c2vyonbac3m="), "{head}");
    assert!(!head.contains("hook-user"), "the URL went without its credentials: {head}");
}

#[tokio::test]
async fn a_link_local_webhook_is_refused_without_retry() {
    // Link-local over https with a secret, and over plain http without a
    // secret, both pass notify's config check and are refused by ua-ingress
    // without retry or leaking the path.
    let hub = hub_with(Some("https://169.254.169.254/hooks/path-secret".to_string()));
    let res =
        call(&builtin_registry(), &hub, &staff(), "notify", json!({ "message": "x", "timeout_s": 2 })).await;
    assert_eq!(res["status"], "failed");
    assert_eq!(res["attempts"], 1, "a policy refusal is not retried: {res}");
    assert_eq!(res["error"], "webhook address refused (link-local (includes cloud metadata))");
    assert!(!res.to_string().contains("path-secret"), "{res}");

    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.notify_webhook_url = Some("http://169.254.169.254/hooks/path-secret".to_string());
    cfg.notify_max_attempts = 3;
    let hub_no_secret = Hub::in_memory(cfg).unwrap();
    let res = call(
        &builtin_registry(),
        &hub_no_secret,
        &staff(),
        "notify",
        json!({ "message": "x", "timeout_s": 2 }),
    )
    .await;
    assert_eq!(res["status"], "failed");
    assert_eq!(res["attempts"], 1, "a policy refusal is not retried: {res}");
    assert_eq!(res["error"], "webhook address refused (link-local (includes cloud metadata))");
    assert!(!res.to_string().contains("path-secret"), "{res}");
}

#[tokio::test]
async fn cleartext_http_webhook_with_credentials_is_refused_early() {
    let reg = builtin_registry();
    let who = staff();

    // 1. Secret header over plain http to a public IP, an RFC 1918 IP, and a
    //    non-loopback hostname — each fails early before any resolution.
    for url in [
        "http://93.184.215.14/hooks/path-secret",
        "http://10.20.30.40/hooks/path-secret",
        "http://hooks.example.com/hooks/path-secret",
    ] {
        let hub = hub_with(Some(url.to_string()));
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reg.call(&hub, &who, "notify", json!({ "message": "hi", "timeout_s": 2 })),
        )
        .await
        .expect("must refuse before resolving or connecting")
        .unwrap_err();
        assert_eq!(err.code(), "invalid_argument", "{url}: {err}");
        let msg = err.to_string();
        assert!(msg.contains("plain http") && msg.contains("https"), "{url}: {msg}");
        assert!(
            !msg.contains("path-secret") && !msg.contains(HEADER_SECRET),
            "error must not leak URL path or secret: {msg}"
        );
    }

    // 2. URL credentials (Basic auth) over plain http to non-loopback without
    //    `notify_webhook_secret` — also fails early without leaking credentials.
    for url in [
        "http://hook-user:p%40ss@10.20.30.40/hooks/path-secret",
        "http://hook-user:p%40ss@93.184.215.14/hooks/path-secret",
        "http://hook-user:p%40ss@hooks.example.com/hooks/path-secret",
    ] {
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.notify_webhook_url = Some(url.to_string());
        cfg.notify_max_attempts = 3;
        let hub = Hub::in_memory(cfg).unwrap();
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reg.call(&hub, &who, "notify", json!({ "message": "hi", "timeout_s": 2 })),
        )
        .await
        .expect("must refuse before resolving or connecting")
        .unwrap_err();
        assert_eq!(err.code(), "invalid_argument", "{url}: {err}");
        let msg = err.to_string();
        assert!(msg.contains("plain http") && msg.contains("https"), "{url}: {msg}");
        for secret in ["hook-user", "p@ss", "p%40ss", "path-secret"] {
            assert!(!msg.contains(secret), "error leaked {secret}: {msg}");
        }
    }
}

#[tokio::test]
async fn https_webhook_with_secret_passes_config_check_and_starts_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let saw_tls = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let saw_tls_task = saw_tls.clone();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut b = [0u8; 1];
            if sock.read_exact(&mut b).await.is_ok() && b[0] == 0x16 {
                saw_tls_task.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
    });
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.notify_webhook_url = Some(format!("https://{addr}/hooks/path-secret"));
    cfg.notify_webhook_secret = Some(SecretString::from(HEADER_SECRET));
    cfg.notify_max_attempts = 1;
    let hub = Hub::in_memory(cfg).unwrap();
    let res =
        call(&builtin_registry(), &hub, &staff(), "notify", json!({ "message": "hi", "timeout_s": 2 })).await;
    assert_eq!(res["status"], "failed", "dummy listener closes after ClientHello: {res}");
    assert_eq!(res["attempts"], 1);
    assert!(saw_tls.load(std::sync::atomic::Ordering::SeqCst), "expected TLS ClientHello");
}

#[tokio::test]
async fn plain_http_webhook_without_credentials_delivers_on_loopback() {
    let (url, seen) = server(vec![200]).await;
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.notify_webhook_url = Some(url);
    cfg.notify_max_attempts = 1;
    let hub = Hub::in_memory(cfg).unwrap();
    let res = call(&builtin_registry(), &hub, &staff(), "notify", json!({ "message": "hi" })).await;
    assert_eq!(res["delivered"], true, "{res}");
    assert_eq!(seen.lock().unwrap().len(), 1);
}

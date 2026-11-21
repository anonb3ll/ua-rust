//! Each property of [`Outbound`], against small HTTP servers on loopback.

use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::policy::{Hosts, SLACK_RESPONSE_URL};

/// A loopback HTTP/1.1 server. `answer` gets the request head and returns
/// the raw response; `None` keeps the connection open without answering.
struct Server {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Server {
    async fn start(answer: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (log, answer) = (seen.clone(), Arc::new(answer));
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let (log, answer) = (log.clone(), answer.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let head_end = loop {
                        let Ok(n) = sock.read(&mut tmp).await else { return };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let len = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().to_string())
                        })
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(0);
                    while buf.len() < head_end + len {
                        let Ok(n) = sock.read(&mut tmp).await else { return };
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let request = String::from_utf8_lossy(&buf).to_string();
                    log.lock().unwrap().push(request.clone());
                    match answer(&request) {
                        Some(resp) => {
                            let _ = sock.write_all(resp.as_bytes()).await;
                            let _ = sock.shutdown().await;
                        }
                        None => tokio::time::sleep(Duration::from_secs(30)).await,
                    }
                });
            }
        });
        Server { addr, seen }
    }

    fn url(&self, path: &str) -> Url {
        Url::parse(&format!("http://{}{path}", self.addr)).unwrap()
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

fn ok(body: &str) -> Option<String> {
    Some(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()))
}

fn redirect(status: u16, to: &str) -> Option<String> {
    Some(format!(
        "HTTP/1.1 {status} Moved\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ))
}

/// A policy for loopback test servers: any host, http allowed, loopback
/// admitted, any port.
const LOCAL: Policy = Policy {
    name: "test.local",
    schemes: Schemes::HttpOrHttps,
    hosts: Hosts::Any,
    default_port_only: false,
    addresses: Addresses::PublicOrLoopback,
    max_redirects: 0,
    max_body_bytes: 1024,
    connect_timeout: Duration::from_secs(5),
    request_timeout: Duration::from_secs(5),
    total_timeout: Duration::from_secs(10),
};

/// A lookup that answers `name` with `addrs` and fails every other name.
fn fake_lookup(name: &'static str, addrs: Vec<SocketAddr>) -> Lookup {
    Arc::new(move |host: &str| {
        let answer = if host == name {
            Ok(addrs.clone())
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test name"))
        };
        Box::pin(async move { answer })
    })
}

// --- policies ----------------------------------------------------------------

#[test]
fn unknown_and_invalid_policies_build_no_client() {
    assert!(matches!(Outbound::named("no.such.policy"), Err(OutboundError::UnknownPolicy(_))));
    assert!(Outbound::named("slack.response_url").is_ok());
    let bad = Policy { max_body_bytes: 0, ..LOCAL };
    assert!(matches!(Outbound::new(bad), Err(OutboundError::InvalidPolicy { .. })));
}

#[tokio::test]
async fn a_url_outside_the_policy_is_refused_before_any_connection() {
    let server = Server::start(|_| ok("hi")).await;
    let out = Outbound::new(SLACK_RESPONSE_URL).unwrap();
    let err = out.send(Request::get(server.url("/"))).await.err().unwrap();
    assert!(matches!(err, OutboundError::UrlRefused { .. }), "{err:?}");
    assert!(server.seen().is_empty());
}

// --- the address check ---------------------------------------------------------

#[tokio::test]
async fn an_ip_literal_outside_the_address_class_is_refused_before_connecting() {
    let server = Server::start(|_| ok("hi")).await;
    let public_only = Policy { addresses: Addresses::Public, ..LOCAL };
    let out = Outbound::new(public_only).unwrap();
    let err = out.send(Request::get(server.url("/"))).await.err().unwrap();
    assert!(matches!(err, OutboundError::AddressRefused { reason: "loopback", .. }), "{err:?}");
    assert!(server.seen().is_empty(), "nothing reached the server");
}

#[tokio::test]
async fn the_resolver_refuses_a_name_that_resolves_outside_the_class() {
    let server = Server::start(|_| ok("hi")).await;
    let policy = Policy { hosts: Hosts::Exactly(&["svc.test"]), addresses: Addresses::Public, ..LOCAL };
    let out = Outbound::with_lookup(policy, fake_lookup("svc.test", vec![server.addr])).unwrap();
    let url = Url::parse(&format!("http://svc.test:{}/", server.addr.port())).unwrap();
    // The URL passes the policy (a DNS name on the list); only the resolver
    // sees the address.
    policy.check_url(&url).unwrap();
    let err = out.send(Request::get(url)).await.err().unwrap();
    match err {
        OutboundError::AddressRefused { host, ip, reason } => {
            assert_eq!(host, "svc.test");
            assert_eq!(ip, server.addr.ip());
            assert_eq!(reason, "loopback");
        }
        other => panic!("expected an address refusal, got {other:?}"),
    }
    assert!(server.seen().is_empty(), "nothing reached the server");
}

#[tokio::test]
async fn the_connection_goes_to_the_address_the_resolver_checked() {
    let server = Server::start(|_| ok("hi")).await;
    let policy = Policy { hosts: Hosts::Exactly(&["svc.test"]), ..LOCAL };
    // `svc.test` exists only in the fake lookup, so reaching the server
    // proves the connector dialled the address the guarded resolver returned.
    let out = Outbound::with_lookup(policy, fake_lookup("svc.test", vec![server.addr])).unwrap();
    let url = Url::parse(&format!("http://svc.test:{}/", server.addr.port())).unwrap();
    let resp = out.send(Request::get(url)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.remote_addr(), server.addr);
    assert_eq!(resp.body().await.unwrap().bytes, b"hi");
    assert_eq!(server.seen().len(), 1);
}

#[tokio::test]
async fn one_bad_address_poisons_the_whole_answer() {
    let server = Server::start(|_| ok("hi")).await;
    let private: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let policy = Policy { hosts: Hosts::Exactly(&["svc.test"]), ..LOCAL };
    let out = Outbound::with_lookup(policy, fake_lookup("svc.test", vec![server.addr, private])).unwrap();
    let url = Url::parse(&format!("http://svc.test:{}/", server.addr.port())).unwrap();
    let err = out.send(Request::get(url)).await.err().unwrap();
    assert!(matches!(err, OutboundError::AddressRefused { reason: "private", .. }), "{err:?}");
    assert!(server.seen().is_empty());
}

#[tokio::test]
async fn a_failed_lookup_is_a_transport_error() {
    let policy = Policy { hosts: Hosts::Exactly(&["other.test"]), ..LOCAL };
    let out = Outbound::with_lookup(policy, fake_lookup("svc.test", vec![])).unwrap();
    let err = out.send(Request::get(Url::parse("http://other.test/").unwrap())).await.err().unwrap();
    assert!(matches!(err, OutboundError::Transport(_)), "{err:?}");
}

// --- redirects -------------------------------------------------------------------

#[tokio::test]
async fn with_redirects_off_a_redirect_is_returned_not_followed() {
    let server =
        Server::start(|req| if req.starts_with("GET /a ") { redirect(302, "/b") } else { ok("b") }).await;
    let out = Outbound::new(LOCAL).unwrap();
    let resp = out.send(Request::get(server.url("/a"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(server.seen().len(), 1, "the Location was not followed");
}

#[tokio::test]
async fn allowed_redirects_are_followed_and_counted() {
    let server = Server::start(|req| {
        let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
        match path.as_str() {
            "/1" => redirect(302, "/2"),
            "/2" => redirect(307, "/3"),
            "/3" => ok("three"),
            "/loop" => redirect(302, "/loop"),
            _ => ok("other"),
        }
    })
    .await;
    let out = Outbound::new(Policy { max_redirects: 2, ..LOCAL }).unwrap();
    let resp = out.send(Request::get(server.url("/1"))).await.unwrap();
    assert_eq!(resp.url().path(), "/3");
    assert_eq!(resp.body().await.unwrap().bytes, b"three");
    let err = out.send(Request::get(server.url("/loop"))).await.err().unwrap();
    assert!(matches!(err, OutboundError::Redirect(_)), "{err:?}");
}

#[tokio::test]
async fn every_redirect_hop_is_checked_against_the_policy() {
    let server = Server::start(|req| {
        if req.starts_with("GET /private ") {
            redirect(302, "http://10.0.0.1/")
        } else if req.starts_with("GET /elsewhere ") {
            redirect(302, "http://evil.example.com/")
        } else {
            redirect(302, "ftp://127.0.0.1/")
        }
    })
    .await;
    let out = Outbound::new(Policy { max_redirects: 3, ..LOCAL }).unwrap();
    let err = out.send(Request::get(server.url("/private"))).await.err().unwrap();
    assert!(matches!(err, OutboundError::AddressRefused { reason: "private", .. }), "{err:?}");
    let err = out.send(Request::get(server.url("/scheme"))).await.err().unwrap();
    assert!(matches!(err, OutboundError::UrlRefused { .. }), "{err:?}");

    let named = Policy { hosts: Hosts::Exactly(&["svc.test"]), max_redirects: 3, ..LOCAL };
    let out = Outbound::with_lookup(named, fake_lookup("svc.test", vec![server.addr])).unwrap();
    let url = Url::parse(&format!("http://svc.test:{}/elsewhere", server.addr.port())).unwrap();
    let err = out.send(Request::get(url)).await.err().unwrap();
    assert!(matches!(err, OutboundError::UrlRefused { why: "host not allowed", .. }), "{err:?}");
}

// --- secret headers ------------------------------------------------------------------

#[test]
fn credential_headers_must_be_secret_headers() {
    let url = Url::parse("https://api.example.com/").unwrap();
    for name in ["Authorization", "proxy-authorization", "Cookie", "X-Subscription-Token", "x-api-key"] {
        let err = Request::get(url.clone()).header(name, "v").err().unwrap();
        assert!(matches!(err, OutboundError::HeaderRefused(_)), "{name}");
    }
    assert!(Request::get(url.clone()).header("Accept", "application/json").is_ok());
    assert!(Request::get(url).secret_header("Authorization", "Bearer x").is_ok());
}

#[tokio::test]
async fn a_secret_header_never_follows_a_redirect_to_another_origin() {
    let other = Server::start(|_| ok("other")).await;
    let target = other.url("/landing").to_string();
    let first = Server::start(move |req| {
        if req.starts_with("GET /same ") {
            redirect(302, "/after")
        } else if req.starts_with("GET /after ") {
            ok("same")
        } else {
            redirect(302, &target)
        }
    })
    .await;
    let out = Outbound::new(Policy { max_redirects: 3, ..LOCAL }).unwrap();

    let req = Request::get(first.url("/away"))
        .secret_header("Authorization", "Bearer s3cr3t")
        .unwrap()
        .secret_header("X-Subscription-Token", "t0ken")
        .unwrap()
        .header("Accept", "text/plain")
        .unwrap();
    let resp = out.send(req).await.unwrap();
    assert_eq!(resp.body().await.unwrap().bytes, b"other");
    let at_first = first.seen().join("\n").to_ascii_lowercase();
    assert!(at_first.contains("authorization: bearer s3cr3t"), "{at_first}");
    assert!(at_first.contains("x-subscription-token: t0ken"));
    let at_other = other.seen().join("\n").to_ascii_lowercase();
    assert!(at_other.contains("accept: text/plain"), "plain headers still go: {at_other}");
    assert!(!at_other.contains("s3cr3t") && !at_other.contains("t0ken"), "{at_other}");
    assert!(!at_other.contains("authorization") && !at_other.contains("x-subscription-token"));

    // A redirect within the same origin keeps it.
    let req = Request::get(first.url("/same")).secret_header("Authorization", "Bearer again").unwrap();
    out.send(req).await.unwrap();
    let after = first.seen().into_iter().filter(|r| r.starts_with("GET /after ")).collect::<Vec<_>>();
    assert_eq!(after.len(), 1);
    assert!(after[0].to_ascii_lowercase().contains("authorization: bearer again"));
}

// --- the body cap ----------------------------------------------------------------------

#[tokio::test]
async fn every_read_path_is_capped() {
    let big = "x".repeat(5000);
    let body = big.clone();
    let server = Server::start(move |req| {
        if req.starts_with("GET /unsized ") {
            Some(format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{body}"))
        } else if req.starts_with("GET /json ") {
            ok(&format!("{{\"k\":\"{body}\"}}"))
        } else {
            ok(&body)
        }
    })
    .await;
    let out = Outbound::new(LOCAL).unwrap();
    let get = |p: &str| out.send(Request::get(server.url(p)));

    let b = get("/sized").await.unwrap().body().await.unwrap();
    assert_eq!((b.bytes.len(), b.truncated), (1024, true));
    let b = get("/unsized").await.unwrap().body().await.unwrap();
    assert_eq!((b.bytes.len(), b.truncated), (1024, true));
    for p in ["/sized", "/unsized"] {
        let err = get(p).await.unwrap().bytes().await.err().unwrap();
        assert_eq!(err, OutboundError::TooLarge { limit: 1024 }, "{p}");
    }
    let err = get("/json").await.unwrap().json::<serde_json::Value>().await.err().unwrap();
    assert_eq!(err, OutboundError::TooLarge { limit: 1024 });

    let small = Server::start(|_| ok("{\"k\":1}")).await;
    let resp = out.send(Request::get(small.url("/"))).await.unwrap();
    let b = resp.body().await.unwrap();
    assert!(!b.truncated);
    let v: serde_json::Value = out.send(Request::get(small.url("/"))).await.unwrap().json().await.unwrap();
    assert_eq!(v["k"], 1);
}

// --- timeouts -----------------------------------------------------------------------------

#[tokio::test]
async fn a_server_that_never_answers_times_out() {
    let server = Server::start(|_| None).await;
    let quick = Policy {
        request_timeout: Duration::from_millis(300),
        total_timeout: Duration::from_millis(600),
        ..LOCAL
    };
    let out = Outbound::new(quick).unwrap();
    let started = std::time::Instant::now();
    let err = out.send(Request::get(server.url("/"))).await.err().unwrap();
    assert_eq!(err, OutboundError::Timeout);
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn a_body_that_stalls_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut tmp = [0u8; 4096];
        let _ = sock.read(&mut tmp).await;
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nstart").await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let quick = Policy {
        request_timeout: Duration::from_secs(5),
        total_timeout: Duration::from_millis(500),
        ..LOCAL
    };
    let out = Outbound::new(quick).unwrap();
    let url = Url::parse(&format!("http://{addr}/")).unwrap();
    let resp = out.send(Request::get(url)).await.unwrap();
    let started = std::time::Instant::now();
    assert_eq!(resp.body().await.err().unwrap(), OutboundError::Timeout);
    assert!(started.elapsed() < Duration::from_secs(3));
}

// --- requests ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_json_post_carries_its_body_and_content_type() {
    let server = Server::start(|_| ok("")).await;
    let out = Outbound::new(LOCAL).unwrap();
    let req = Request::post(server.url("/hook")).json(&serde_json::json!({"text": "hello"})).unwrap();
    let resp = out.send(req).await.unwrap();
    assert!(resp.status().is_success());
    let seen = server.seen().join("\n");
    assert!(seen.starts_with("POST /hook HTTP/1.1"), "{seen}");
    assert!(seen.to_ascii_lowercase().contains("content-type: application/json"));
    assert!(seen.to_ascii_lowercase().contains(&format!("user-agent: {}", USER_AGENT.to_ascii_lowercase())));
    assert!(seen.ends_with("{\"text\":\"hello\"}"), "{seen}");
}

#[test]
fn errors_become_hub_errors_with_stable_codes() {
    let e: ua_core::UaError = OutboundError::AddressRefused {
        host: "h".into(),
        ip: "10.0.0.1".parse().unwrap(),
        reason: "private",
    }
    .into();
    assert_eq!(e.reason_code(), Some("ssrf_blocked"));
    let e: ua_core::UaError = OutboundError::UrlRefused { policy: "p", why: "w" }.into();
    assert_eq!(e.reason_code(), Some("outbound_refused"));
}

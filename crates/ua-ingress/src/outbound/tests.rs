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
    allow_scheme_downgrade: false,
    accept_invalid_certs: false,
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
async fn a_failed_lookup_is_a_lookup_error() {
    let policy = Policy { hosts: Hosts::Exactly(&["other.test"]), ..LOCAL };
    let out = Outbound::with_lookup(policy, fake_lookup("svc.test", vec![])).unwrap();
    let err = out.send(Request::get(Url::parse("http://other.test/").unwrap())).await.err().unwrap();
    assert!(matches!(err, OutboundError::Lookup { ref host, .. } if host == "other.test"), "{err:?}");
    // An empty answer is a lookup failure too.
    let policy = Policy { hosts: Hosts::Exactly(&["svc.test"]), ..LOCAL };
    let out = Outbound::with_lookup(policy, fake_lookup("svc.test", vec![])).unwrap();
    let err = out.send(Request::get(Url::parse("http://svc.test/").unwrap())).await.err().unwrap();
    assert_eq!(err, OutboundError::Lookup { host: "svc.test".into(), why: "no address".into() });
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

// --- cross-origin hops -------------------------------------------------------------------------

/// Two loopback servers on different ports: different origins.
async fn two_origins(
    first_answer: impl Fn(&str, &str) -> Option<String> + Send + Sync + 'static,
) -> (Server, Server) {
    let other = Server::start(|_| ok("other")).await;
    let other_base = format!("http://{}", other.addr);
    let first = Server::start(move |req| first_answer(req, &other_base)).await;
    (first, other)
}

#[tokio::test]
async fn a_plain_header_stays_with_the_origin_it_was_built_for() {
    let (first, other) = two_origins(|req, other| {
        if req.starts_with("GET /away ") {
            redirect(302, &format!("{other}/landing"))
        } else if req.starts_with("GET /same ") {
            redirect(302, "/after")
        } else {
            ok("same")
        }
    })
    .await;
    let out = Outbound::new(Policy { max_redirects: 3, ..LOCAL }).unwrap();
    // A credential under a name the word list does not know.
    let build = |path: &str| {
        Request::get(first.url(path))
            .header("X-Custom-Auth", "hunter2")
            .unwrap()
            .header("Accept", "text/plain")
            .unwrap()
            .header("Accept-Language", "en")
            .unwrap()
            .header("X-Trace", "abc")
            .unwrap()
    };
    out.send(build("/away")).await.unwrap();
    let at_first = first.seen().join("\n").to_ascii_lowercase();
    assert!(at_first.contains("x-custom-auth: hunter2") && at_first.contains("x-trace: abc"), "{at_first}");
    let at_other = other.seen().join("\n").to_ascii_lowercase();
    assert!(at_other.contains("accept: text/plain"), "{at_other}");
    assert!(at_other.contains("accept-language: en"), "{at_other}");
    assert!(!at_other.contains("hunter2") && !at_other.contains("x-custom-auth"), "{at_other}");
    assert!(!at_other.contains("x-trace"), "{at_other}");

    // Within the origin, every header follows.
    out.send(build("/same")).await.unwrap();
    let after: Vec<String> = first.seen().into_iter().filter(|r| r.starts_with("GET /after ")).collect();
    assert!(after[0].to_ascii_lowercase().contains("x-custom-auth: hunter2"));
}

#[tokio::test]
async fn a_body_is_never_resent_to_another_origin() {
    let (first, other) = two_origins(|req, other| {
        let path = req.split_whitespace().nth(1).unwrap_or("/");
        match path {
            "/307" => redirect(307, &format!("{other}/landing")),
            "/308" => redirect(308, &format!("{other}/landing")),
            "/303" => redirect(303, &format!("{other}/landing")),
            "/same307" => redirect(307, "/landed"),
            _ => ok("done"),
        }
    })
    .await;
    let out = Outbound::new(Policy { max_redirects: 3, ..LOCAL }).unwrap();
    let post =
        |path: &str| Request::post(first.url(path)).json(&serde_json::json!({"k": "payload"})).unwrap();
    for path in ["/307", "/308"] {
        let err = out.send(post(path)).await.err().unwrap();
        assert!(
            matches!(err, OutboundError::Redirect(ref why) if why.contains("resend the request body")),
            "{err:?}"
        );
    }
    assert!(other.seen().is_empty(), "nothing reached the other origin");

    // 303 becomes a GET without the body or its content type.
    out.send(post("/303")).await.unwrap();
    let at_other = other.seen().join("\n");
    assert!(at_other.starts_with("GET /landing "), "{at_other}");
    assert!(!at_other.contains("payload") && !at_other.to_ascii_lowercase().contains("content-type"));

    // A 307 within the origin resends the body, as it must.
    out.send(post("/same307")).await.unwrap();
    let landed: Vec<String> = first.seen().into_iter().filter(|r| r.starts_with("POST /landed ")).collect();
    assert_eq!(landed.len(), 1);
    assert!(landed[0].ends_with("{\"k\":\"payload\"}"));
}

#[test]
fn a_redirect_from_https_to_http_is_refused_unless_the_policy_allows_it() {
    let strict = Outbound::new(Policy { max_redirects: 3, ..LOCAL }).unwrap();
    let home = Url::parse("https://a.example.com/").unwrap().origin();
    let mut req = Request::get(Url::parse("https://a.example.com/start").unwrap());
    let err =
        strict.follow(&mut req, &home, StatusCode::FOUND, Some("http://a.example.com/next")).err().unwrap();
    assert!(matches!(err, OutboundError::Redirect(ref why) if why.contains("https to http")), "{err:?}");
    assert_eq!(req.url.as_str(), "https://a.example.com/start", "the request is unchanged");
    // https to https elsewhere and http to https are fine.
    strict.follow(&mut req, &home, StatusCode::FOUND, Some("https://b.example.com/x")).unwrap();
    let mut plain = Request::get(Url::parse("http://a.example.com/").unwrap());
    strict.follow(&mut plain, &home, StatusCode::FOUND, Some("https://a.example.com/")).unwrap();

    let lax = Outbound::new(Policy { max_redirects: 3, allow_scheme_downgrade: true, ..LOCAL }).unwrap();
    let mut req = Request::get(Url::parse("https://a.example.com/start").unwrap());
    lax.follow(&mut req, &home, StatusCode::FOUND, Some("http://a.example.com/next")).unwrap();
    assert_eq!(req.url.scheme(), "http");
    // Only `web.page` follows a downgrade: it carries no credentials, and
    // its callers may fetch plain http pages directly anyway.
    for p in crate::policy::POLICIES {
        assert_eq!(p.allow_scheme_downgrade, p.name == "web.page", "{}", p.name);
    }
    // A downgrade changes the origin, so it carries no caller header.
    let page = Request::get(Url::parse("https://a.example.com/").unwrap())
        .header("X-Trace", "t")
        .unwrap()
        .secret_header("Authorization", "Bearer x")
        .unwrap();
    assert_ne!(
        Url::parse("http://a.example.com/").unwrap().origin(),
        page.url().origin(),
        "the scheme is part of the origin"
    );
}

// --- the peer-address re-check ----------------------------------------------------------------

#[tokio::test]
async fn a_peer_outside_the_class_is_refused_after_the_resolver_passed_it() {
    let server = Server::start(|_| ok("hi")).await;
    let policy = Policy { hosts: Hosts::Exactly(&["svc.test"]), addresses: Addresses::Public, ..LOCAL };
    // The resolver is given a looser rule than the policy, so its answer
    // (loopback) passes and the connection is made: only the peer check is
    // left to refuse it.
    let out = Outbound::with_seams(
        policy,
        fake_lookup("svc.test", vec![server.addr]),
        Addresses::PublicOrLoopback,
        reqwest::Response::remote_addr,
    )
    .unwrap();
    let url = Url::parse(&format!("http://svc.test:{}/", server.addr.port())).unwrap();
    let err = out.send(Request::get(url)).await.err().unwrap();
    assert!(
        matches!(err, OutboundError::PeerRefused { reason: "loopback", ref host, .. } if host == "svc.test"),
        "{err:?}"
    );
    // The check runs after the response head: the request did go out.
    assert_eq!(server.seen().len(), 1);
}

#[tokio::test]
async fn a_missing_peer_address_is_refused() {
    let server = Server::start(|_| ok("hi")).await;
    let out = Outbound::with_seams(LOCAL, system_lookup(), LOCAL.addresses, |_| None).unwrap();
    let err = out.send(Request::get(server.url("/"))).await.err().unwrap();
    assert_eq!(err, OutboundError::Unverified);
}

// --- the Slack reply policy ---------------------------------------------------------------------

// The Slack reply policy follows no redirect and allows no downgrade.
const _: () = assert!(SLACK_RESPONSE_URL.max_redirects == 0 && !SLACK_RESPONSE_URL.allow_scheme_downgrade);

#[tokio::test]
async fn the_slack_reply_policy_never_follows_a_redirect() {
    let other = Server::start(|_| ok("other")).await;
    let target = other.url("/elsewhere").to_string();
    let hooks = Server::start(move |_| redirect(307, &target)).await;
    // The Slack policy, loosened only so a plain loopback server can stand in
    // for the hooks host.
    let policy = Policy {
        schemes: Schemes::HttpOrHttps,
        default_port_only: false,
        addresses: Addresses::PublicOrLoopback,
        ..SLACK_RESPONSE_URL
    };
    let out = Outbound::with_lookup(policy, fake_lookup("hooks.slack.com", vec![hooks.addr])).unwrap();
    let url = Url::parse(&format!("http://hooks.slack.com:{}/commands/T0/1/abc", hooks.addr.port())).unwrap();
    let req = Request::post(url).json(&serde_json::json!({"text": "hi"})).unwrap();
    let resp = out.send(req).await.unwrap();
    // Returned as it is; `post_reply` reports a non-success status as `status`.
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(!resp.status().is_success());
    assert_eq!(hooks.seen().len(), 1);
    assert!(other.seen().is_empty(), "the Location was not followed");
}

#[tokio::test]
async fn a_chain_that_leaves_the_origin_never_brings_credentials_back() {
    // A sends the client to B; B sends it back to a path of its choosing on
    // A. Each server learns the other's address once both are listening.
    let to_b: Arc<Mutex<String>> = Arc::default();
    let to_a: Arc<Mutex<String>> = Arc::default();
    let (tb, ta) = (to_b.clone(), to_a.clone());
    let a = Server::start(move |req| {
        if req.starts_with("GET /start ") { redirect(302, &tb.lock().unwrap()) } else { ok("chosen") }
    })
    .await;
    let b = Server::start(move |_| redirect(302, &ta.lock().unwrap())).await;
    *to_b.lock().unwrap() = b.url("/bounce").to_string();
    *to_a.lock().unwrap() = a.url("/chosen-by-b").to_string();

    let out = Outbound::new(Policy { max_redirects: 3, ..LOCAL }).unwrap();
    let req = Request::get(a.url("/start"))
        .header("X-Custom-Auth", "hunter2")
        .unwrap()
        .header("Accept", "text/plain")
        .unwrap()
        .secret_header("Authorization", "Bearer s3cr3t")
        .unwrap();
    let resp = out.send(req).await.unwrap();
    assert_eq!(resp.url().path(), "/chosen-by-b");
    assert_eq!(resp.body().await.unwrap().bytes, b"chosen");

    let seen = a.seen();
    let start = seen.iter().find(|r| r.starts_with("GET /start ")).unwrap().to_ascii_lowercase();
    assert!(start.contains("x-custom-auth: hunter2") && start.contains("authorization: bearer s3cr3t"));
    let back = seen.iter().find(|r| r.starts_with("GET /chosen-by-b ")).unwrap().to_ascii_lowercase();
    assert!(back.contains("accept: text/plain"), "the allow list still travels: {back}");
    assert!(!back.contains("hunter2") && !back.contains("x-custom-auth"), "{back}");
    assert!(!back.contains("s3cr3t") && !back.contains("authorization"), "{back}");
    let at_b = b.seen().join("\n").to_ascii_lowercase();
    assert!(!at_b.contains("hunter2") && !at_b.contains("s3cr3t"), "{at_b}");
}

#[tokio::test]
async fn a_refused_connection_is_not_sent() {
    // Port 1 is privileged and never handed out, so nothing listens there.
    let out = Outbound::new(LOCAL).unwrap();
    let err = out.send(Request::get(Url::parse("http://127.0.0.1:1/").unwrap())).await.err().unwrap();
    assert!(matches!(err, OutboundError::NotSent { timed_out: false, .. }), "{err:?}");
}

#[tokio::test]
async fn bytes_within_takes_the_smaller_limit() {
    let server = Server::start(|_| ok(&"y".repeat(500))).await;
    let out = Outbound::new(LOCAL).unwrap();
    let err = out.send(Request::get(server.url("/"))).await.unwrap().bytes_within(100).await.err().unwrap();
    assert_eq!(err, OutboundError::TooLarge { limit: 100 });
    let b = out.send(Request::get(server.url("/"))).await.unwrap().bytes_within(10_000).await.unwrap();
    assert_eq!(b.len(), 500, "under both limits");
}

#[test]
fn the_loopback_test_hook_widens_only_addresses_schemes_hosts_and_ports() {
    let hooked = crate::policy::SLACK_WEB_API.loopback_test_hook();
    assert_eq!(hooked.addresses, Addresses::PublicOrLoopback);
    assert_eq!(
        (hooked.schemes, hooked.hosts, hooked.default_port_only),
        (Schemes::HttpOrHttps, Hosts::Any, false)
    );
    assert_eq!(
        (hooked.max_redirects, hooked.allow_scheme_downgrade, hooked.max_body_bytes, hooked.total_timeout),
        (0, false, 16 * 1024, Duration::from_secs(15))
    );
    assert!(hooked.check_url(&Url::parse("http://127.0.0.1:9/").unwrap()).is_ok());
    assert!(hooked.check_url(&Url::parse("http://10.0.0.1/").unwrap()).is_err());
}

#[tokio::test]
async fn a_same_origin_hop_after_a_return_stays_stripped() {
    // A -> B -> A (/back) -> A (/again): the last hop is within A, but the
    // chain left A once, so it still carries no caller header.
    let to_b: Arc<Mutex<String>> = Arc::default();
    let to_a: Arc<Mutex<String>> = Arc::default();
    let (tb, ta) = (to_b.clone(), to_a.clone());
    let a = Server::start(move |req| {
        if req.starts_with("GET /start ") {
            redirect(302, &tb.lock().unwrap())
        } else if req.starts_with("GET /back ") {
            redirect(302, "/again")
        } else {
            ok("again")
        }
    })
    .await;
    let b = Server::start(move |_| redirect(302, &ta.lock().unwrap())).await;
    *to_b.lock().unwrap() = b.url("/bounce").to_string();
    *to_a.lock().unwrap() = a.url("/back").to_string();

    let out = Outbound::new(Policy { max_redirects: 4, ..LOCAL }).unwrap();
    let req = Request::get(a.url("/start"))
        .header("X-Custom-Auth", "hunter2")
        .unwrap()
        .secret_header("Authorization", "Bearer s3cr3t")
        .unwrap();
    let resp = out.send(req).await.unwrap();
    assert_eq!(resp.url().path(), "/again");
    let seen = a.seen();
    for path in ["/back", "/again"] {
        let r = seen.iter().find(|r| r.starts_with(&format!("GET {path} "))).unwrap().to_ascii_lowercase();
        assert!(!r.contains("hunter2") && !r.contains("x-custom-auth"), "{path}: {r}");
        assert!(!r.contains("s3cr3t") && !r.contains("authorization"), "{path}: {r}");
    }
}

#[tokio::test]
async fn the_loopback_only_policy_reaches_loopback_and_nothing_else() {
    let server = Server::start(|_| ok("live")).await;
    let out = Outbound::pinned(crate::policy::OBSIDIAN_LOCAL, &server.url("/")).unwrap();
    let resp = out.send(Request::get(server.url("/"))).await.unwrap();
    assert_eq!(resp.body().await.unwrap().bytes, b"live");
    // A name that resolves off this host is refused before anything is sent.
    let public: SocketAddr = "93.184.215.14:443".parse().unwrap();
    let vault = Url::parse("https://vault.test/").unwrap();
    let out = Outbound::pinned_with_lookup(
        crate::policy::OBSIDIAN_LOCAL,
        &vault,
        fake_lookup("vault.test", vec![public]),
    )
    .unwrap();
    let err = out.send(Request::get(vault)).await.err().unwrap();
    assert!(matches!(err, OutboundError::AddressRefused { reason: "not loopback", .. }), "{err:?}");
}

// --- relaxed policies and pinned clients -----------------------------------------

#[test]
fn a_relaxed_policy_builds_no_unpinned_client() {
    use crate::policy::{GITHUB_ENTERPRISE, NOTIFY_WEBHOOK, OBSIDIAN_LOCAL};
    for p in [GITHUB_ENTERPRISE, NOTIFY_WEBHOOK, OBSIDIAN_LOCAL] {
        assert!(matches!(Outbound::new(p), Err(OutboundError::InvalidPolicy { .. })), "{}", p.name);
        assert!(
            matches!(Outbound::new(p.loopback_test_hook()), Err(OutboundError::InvalidPolicy { .. })),
            "{}",
            p.name
        );
        assert!(matches!(Outbound::named(p.name), Err(OutboundError::UnknownPolicy(_))), "{}", p.name);
    }
    // Nor a hand-made one, pinned or not.
    let odd = Policy { addresses: Addresses::OperatorConfigured, ..LOCAL };
    let origin = Url::parse("http://127.0.0.1:9/").unwrap();
    assert!(matches!(Outbound::new(odd), Err(OutboundError::InvalidPolicy { .. })));
    assert!(matches!(Outbound::pinned(odd, &origin), Err(OutboundError::InvalidPolicy { .. })));
    let odd_tls = Policy { accept_invalid_certs: true, ..OBSIDIAN_LOCAL };
    assert!(Outbound::pinned(odd_tls, &origin).is_ok(), "the same values are OBSIDIAN_LOCAL itself");
    let odd_tls = Policy { name: "odd.tls", ..OBSIDIAN_LOCAL };
    assert!(matches!(Outbound::pinned(odd_tls, &origin), Err(OutboundError::InvalidPolicy { .. })));
}

#[tokio::test]
async fn a_pinned_origin_outside_the_policy_is_refused_on_use() {
    let metadata = Url::parse("http://169.254.169.254/").unwrap();
    let out = Outbound::pinned(crate::policy::NOTIFY_WEBHOOK, &metadata).unwrap();
    let err = out.send(Request::post(metadata)).await.err().unwrap();
    assert!(matches!(err, OutboundError::AddressRefused { .. }), "{err:?}");
}

#[tokio::test]
async fn a_pinned_client_sends_only_to_its_origin() {
    let home = Server::start(|_| ok("home")).await;
    let other = Server::start(|_| ok("other")).await;
    let out = Outbound::pinned(crate::policy::NOTIFY_WEBHOOK, &home.url("/hooks/x")).unwrap();
    let resp = out.send(Request::post(home.url("/another/path"))).await.unwrap();
    assert_eq!(resp.body().await.unwrap().bytes, b"home", "any path on the origin");

    let port = home.addr.port();
    let elsewhere = [
        other.url("/hooks/x").to_string(),                   // another port
        format!("https://127.0.0.1:{port}/hooks/x"),         // another scheme
        format!("http://localhost:{port}/hooks/x"),          // another host, same address
        format!("http://[::ffff:127.0.0.1]:{port}/hooks/x"), // an IP literal that is not the origin
        format!("http://127.0.0.2:{port}/hooks/x"),          // another host
    ];
    for url in elsewhere {
        let err = out.send(Request::post(Url::parse(&url).unwrap())).await.err().unwrap();
        assert!(
            matches!(err, OutboundError::UrlRefused { why: "not the origin this client is pinned to", .. }),
            "{url}: {err:?}"
        );
    }
    assert!(other.seen().is_empty(), "nothing reached another origin");
    assert_eq!(home.seen().len(), 1);
    // A strict policy may be pinned too, with the same effect.
    let strict = Outbound::pinned(LOCAL, &home.url("/")).unwrap();
    assert!(strict.send(Request::get(other.url("/"))).await.is_err());
}

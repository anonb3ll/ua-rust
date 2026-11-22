//! `Outbound` ignores proxy settings from the environment. This is its own
//! test binary because it sets process environment variables.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use ua_ingress::{Addresses, Hosts, Outbound, Policy, Request, Schemes, Url};

/// Accepts connections, records the first bytes of each, answers 200.
async fn listener() -> (String, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = l.accept().await {
            let mut buf = [0u8; 2048];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            log.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ =
                sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
        }
    });
    (format!("http://{addr}"), seen)
}

#[tokio::test]
async fn proxy_environment_variables_are_ignored() {
    let (proxy, at_proxy) = listener().await;
    let (server, at_server) = listener().await;
    // SAFETY: this binary has one test, and nothing else runs while it sets
    // these variables.
    unsafe {
        for k in ["NO_PROXY", "no_proxy", "REQUEST_METHOD"] {
            std::env::remove_var(k);
        }
        for k in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
            std::env::set_var(k, &proxy);
        }
    }
    let url = Url::parse(&format!("{server}/target")).unwrap();

    // Control: a default client does use the variables, so the test would
    // see a proxied request if Outbound honoured them.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let plain = reqwest::Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
    let _ = plain.get(url.clone()).send().await;
    assert_eq!(at_proxy.lock().unwrap().len(), 1, "the control request went through the proxy");
    assert!(at_proxy.lock().unwrap()[0].contains("/target"));
    assert!(at_server.lock().unwrap().is_empty());

    let policy = Policy {
        name: "test.no_proxy",
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
    let resp = Outbound::new(policy).unwrap().send(Request::get(url)).await.unwrap();
    assert!(resp.status().is_success());
    assert_eq!(at_proxy.lock().unwrap().len(), 1, "Outbound sent nothing to the proxy");
    assert_eq!(at_server.lock().unwrap().len(), 1, "Outbound went straight to the server");
}

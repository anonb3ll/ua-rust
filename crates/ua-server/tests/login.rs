//! Browser sign-in: login links, the session cookie, CSRF and the `/mcp`
//! cookie refusal.

mod common;

use axum::http::header;
use common::*;
use serde_json::json;

#[tokio::test]
async fn login_link_is_single_use() {
    let hub = TestHub::new(config());
    let url = ua_server::login::create_login_link(&hub.state.hub, "operator", "test").unwrap();
    assert!(url.starts_with("https://hub.example.com/login/link?token=ual_"));
    let token = query_param(&url, "token").unwrap();

    // A GET (a link preview) shows a button and does not consume the link.
    let page = hub.send(get(&format!("/login/link?token={token}"), None, None)).await;
    assert_eq!(page.status(), 200);
    assert!(set_cookie_header(&page).is_none());

    let first = hub.send(form("/login/link", &[("token", &token)], None)).await;
    assert!(first.status().is_redirection());
    assert_eq!(location(&first), "/login/passkeys");
    let raw = set_cookie_header(&first).unwrap();
    for attr in ["HttpOnly", "SameSite=Lax", "Secure", "Path=/"] {
        assert!(raw.contains(attr), "session cookie lacks {attr}: {raw}");
    }
    // The cookie is encrypted: it does not carry the session id in clear.
    assert!(!raw.contains("uis_"));

    let second = hub.send(form("/login/link", &[("token", &token)], None)).await;
    assert_eq!(second.status(), 400);
    assert!(set_cookie_header(&second).is_none());
}

#[tokio::test]
async fn login_link_expires_and_is_human_only() {
    let hub = TestHub::new(config());
    assert!(ua_server::login::create_login_link(&hub.state.hub, "remote-agent", "test").is_err());

    let url = ua_server::login::create_login_link(&hub.state.hub, "operator", "test").unwrap();
    let token = query_param(&url, "token").unwrap();
    hub.state
        .hub
        .db()
        .write(|tx| {
            tx.execute("UPDATE login_links SET expires_at = '2000-01-01T00:00:00Z'", [])?;
            Ok(())
        })
        .unwrap();
    let resp = hub.send(form("/login/link", &[("token", &token)], None)).await;
    assert_eq!(resp.status(), 400);
    assert!(set_cookie_header(&resp).is_none());

    let bogus = hub.send(form("/login/link", &[("token", "ual_not-a-real-link")], None)).await;
    assert_eq!(bogus.status(), 400);
}

#[tokio::test]
async fn insecure_cookie_flag_for_localhost() {
    let mut cfg = config();
    cfg.ui_cookie_secure = false;
    let hub = TestHub::new(cfg);
    let url = ua_server::login::create_login_link(&hub.state.hub, "operator", "test").unwrap();
    let token = query_param(&url, "token").unwrap();
    let resp = hub.send(form("/login/link", &[("token", &token)], None)).await;
    let raw = set_cookie_header(&resp).unwrap();
    assert!(raw.contains("HttpOnly") && !raw.contains("Secure"));
}

#[tokio::test]
async fn session_helper_exposes_csrf_and_enforces_it() {
    let hub = TestHub::new(config());
    let cookie = hub.sign_in("operator").await;

    let resp = hub.send(get("/api/session", Some(&cookie), None)).await;
    assert_eq!(resp.status(), 200);
    let v = json_body(resp).await;
    assert_eq!(v["identity"], "operator");
    assert_eq!(v["kind"], "human");
    assert_eq!(v["auth"], "cookie");
    assert_eq!(v["csrf_header"], "X-CSRF-Token");
    let csrf = v["csrf_token"].as_str().unwrap().to_string();
    assert!(csrf.len() >= 32);

    // GET needs no CSRF token.
    let who = hub.send(get("/api/whoami", Some(&cookie), None)).await;
    assert_eq!(who.status(), 200);
    assert_eq!(json_body(who).await["identity"], "operator");

    // A state-changing cookie request without the header is refused.
    let call = |h: Vec<(&'static str, String)>| {
        let mut headers: Vec<(&str, &str)> = vec![("cookie", cookie.as_str())];
        headers.extend(h.iter().map(|(k, v)| (*k, v.as_str())));
        post_json("/api/tools/agent_token_list", &json!({}), &headers)
    };
    assert_eq!(hub.send(call(vec![])).await.status(), 403);
    assert_eq!(hub.send(call(vec![("x-csrf-token", "wrong".into())])).await.status(), 403);
    let ok = hub.send(call(vec![("x-csrf-token", csrf.clone())])).await;
    assert_eq!(ok.status(), 200);
}

#[tokio::test]
async fn logout_ends_the_session() {
    let hub = TestHub::new(config());
    let cookie = hub.sign_in("operator").await;
    let csrf = hub.csrf(&cookie).await;

    // Logout without the CSRF token is refused.
    let refused = hub.send(form("/logout", &[], Some(&cookie))).await;
    assert_eq!(refused.status(), 403);

    let out = hub.send(form("/logout", &[("csrf", &csrf)], Some(&cookie))).await;
    assert!(out.status().is_redirection());
    let cleared = set_cookie_header(&out).unwrap();
    assert!(cleared.contains("Max-Age=0"));

    let after = hub.send(get("/api/whoami", Some(&cookie), None)).await;
    assert_eq!(after.status(), 401);
}

#[cfg(feature = "mcp-server")]
#[tokio::test]
async fn cookie_is_never_accepted_on_mcp() {
    let hub = TestHub::new(config());
    let cookie = hub.sign_in("operator").await;
    let csrf = hub.csrf(&cookie).await;
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } }
    });
    let resp = hub
        .send(post_json(
            "/mcp",
            &init,
            &[
                ("cookie", &cookie),
                ("x-csrf-token", &csrf),
                ("accept", "application/json, text/event-stream"),
                ("host", "localhost"),
            ],
        ))
        .await;
    assert_eq!(resp.status(), 401);
    let challenge = resp.headers().get(header::WWW_AUTHENTICATE).unwrap().to_str().unwrap().to_string();
    assert!(
        challenge.contains(
            "resource_metadata=\"https://hub.example.com/.well-known/oauth-protected-resource/mcp\""
        )
    );
}

#[tokio::test]
async fn ui_without_session_redirects_to_login() {
    let hub = TestHub::new(config());
    let resp = hub.send(get("/ui/tasks?x=1", None, None)).await;
    assert!(resp.status().is_redirection());
    let to = location(&resp);
    assert!(to.starts_with("/login?next="));
    assert_eq!(query_param(&to, "next").as_deref(), Some("/ui/tasks?x=1"));

    let login = hub.send(get("/login", None, None)).await;
    assert_eq!(login.status(), 200);
    let page = text_body(login).await;
    assert!(page.contains("passkey"));
}

#[tokio::test]
async fn passkey_start_does_not_reveal_identities() {
    let hub = TestHub::new(config());
    // Neither an unknown label nor a human without passkeys gets a challenge,
    // and both get the same answer.
    let a = hub.send(post_json("/login/passkey/start", &json!({ "label": "nobody" }), &[])).await;
    let b = hub.send(post_json("/login/passkey/start", &json!({ "label": "operator" }), &[])).await;
    assert_eq!(a.status(), 400);
    assert_eq!(b.status(), 400);
    assert_eq!(json_body(a).await, json_body(b).await);

    // Registration needs a session and the CSRF header.
    let anon = hub.send(post_json("/login/passkeys/register/start", &json!({}), &[])).await;
    assert_eq!(anon.status(), 401);
    let cookie = hub.sign_in("operator").await;
    let no_csrf =
        hub.send(post_json("/login/passkeys/register/start", &json!({}), &[("cookie", &cookie)])).await;
    assert_eq!(no_csrf.status(), 403);
    let csrf = hub.csrf(&cookie).await;
    let ok = hub
        .send(post_json(
            "/login/passkeys/register/start",
            &json!({}),
            &[("cookie", &cookie), ("x-csrf-token", &csrf)],
        ))
        .await;
    assert_eq!(ok.status(), 200);
    let v = json_body(ok).await;
    assert!(v["state_id"].as_str().unwrap().starts_with("uaw_"));
    assert!(v["options"]["publicKey"]["challenge"].is_string());
    assert_eq!(v["options"]["publicKey"]["rp"]["id"], "hub.example.com");
}

/// The cookie key is cached in the app state: once a session exists, an
/// authenticated request does not read `ui_keys` (deleting the row changes
/// nothing), and invalidating the cache makes the hub read the table again
/// (here: mint a new key, so the old cookie no longer decrypts).
#[tokio::test]
async fn the_cookie_key_is_cached_and_invalidation_rereads_it() {
    let hub = TestHub::new(config());
    let cookie = hub.sign_in("operator").await;
    let key_rows = |hub: &TestHub| -> i64 {
        hub.state
            .hub
            .db()
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM ui_keys", [], |r| r.get(0))?))
            .unwrap()
    };
    assert_eq!(key_rows(&hub), 1);
    hub.state
        .hub
        .db()
        .write(|tx| {
            tx.execute("DELETE FROM ui_keys", [])?;
            Ok(())
        })
        .unwrap();

    let resp = hub.send(get("/api/session", Some(&cookie), None)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(json_body(resp).await["auth"], "cookie");
    assert_eq!(key_rows(&hub), 0, "an authenticated request served from the cache reads no key row");

    hub.state.cookie_key.invalidate();
    let resp = hub.send(get("/ui/work", Some(&cookie), None)).await;
    assert!(resp.status().is_redirection(), "a replaced key signs the browser out: {}", resp.status());
    assert!(location(&resp).starts_with("/login?next="));
    assert_eq!(key_rows(&hub), 1, "the miss re-read ui_keys and created a fresh key");
}

/// Every `<script` tag in `html` loads a file (has `src=`); none is inline.
fn no_inline_script(html: &str) -> bool {
    html.match_indices("<script").all(|(i, _)| html[i..].split('>').next().unwrap().contains(" src=\""))
}

fn assert_strict_csp(resp: &axum::http::Response<axum::body::Body>) {
    let csp = resp.headers().get(header::CONTENT_SECURITY_POLICY).expect("CSP").to_str().unwrap().to_string();
    assert!(csp.contains("script-src 'self'"), "{csp}");
    assert!(csp.contains("style-src 'self'"), "{csp}");
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(!csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"), "{csp}");
}

/// The sign-in and passkey pages run no inline script or style: the script
/// and stylesheet are files served by the hub (without a session), and the
/// page passes its values in data- attributes, HTML-escaped.
#[tokio::test]
async fn sign_in_pages_run_under_a_csp_without_inline_script() {
    let hub = TestHub::new(config());
    let resp = hub.send(get("/login?next=/ui/tasks%3Fx%3D1%22%3E%3Cb%3E", None, None)).await;
    assert_eq!(resp.status(), 200);
    assert_strict_csp(&resp);
    let html = text_body(resp).await;
    assert!(no_inline_script(&html), "{html}");
    assert!(!html.contains("<style"), "{html}");
    assert!(html.contains("<script src=\"/login/assets/login.js\" defer></script>"), "{html}");
    assert!(html.contains("data-next=\"/ui/tasks?x=1&quot;&gt;&lt;b&gt;\""), "{html}");

    let cookie = hub.sign_in("operator").await;
    let resp = hub.send(get("/login/passkeys", Some(&cookie), None)).await;
    assert_eq!(resp.status(), 200);
    assert_strict_csp(&resp);
    let html = text_body(resp).await;
    assert!(no_inline_script(&html), "{html}");
    let csrf = hub.csrf(&cookie).await;
    assert!(html.contains(&format!("data-csrf=\"{csrf}\"")), "{html}");

    for (path, mime, needle) in [
        ("/login/assets/login.js", "text/javascript", "navigator.credentials.get"),
        ("/login/assets/page.css", "text/css", ".card"),
    ] {
        let resp = hub.send(get(path, None, None)).await;
        assert_eq!(resp.status(), 200, "{path}");
        assert!(resp.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with(mime), "{path}");
        assert_eq!(resp.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert!(text_body(resp).await.contains(needle), "{path}");
    }
}

/// The cached copy lapses after its TTL: a key deleted outside the hub
/// stops decrypting cookies then. A sign-in never encrypts with a cached
/// copy the table no longer holds.
#[tokio::test]
async fn the_cached_cookie_key_lapses_and_sign_in_uses_the_stored_key() {
    use std::sync::Arc;
    use std::time::Duration;
    let hub = TestHub::new(config());
    let mut state = hub.state.clone();
    state.cookie_key = Arc::new(ua_server::login::CookieKeyCache::with_ttl(Duration::from_millis(200)));
    let app = ua_server::router(state, tokio_util::sync::CancellationToken::new());
    let send = |req| {
        let app = app.clone();
        async move { tower::ServiceExt::oneshot(app, req).await.unwrap() }
    };
    let cookie = hub.sign_in("operator").await;
    assert_eq!(send(get("/api/session", Some(&cookie), None)).await.status(), 200);
    let delete_key = || {
        hub.state
            .hub
            .db()
            .write(|tx| {
                tx.execute("DELETE FROM ui_keys", [])?;
                Ok(())
            })
            .unwrap()
    };
    delete_key();
    // Within the TTL the cached copy still reads the cookie.
    assert_eq!(json_body(send(get("/api/session", Some(&cookie), None)).await).await["auth"], "cookie");
    tokio::time::sleep(Duration::from_millis(300)).await;
    // After it, the table is read again: a new key, the old cookie is gone.
    assert_ne!(json_body(send(get("/api/session", Some(&cookie), None)).await).await["auth"], "cookie");

    // A sign-in right after the row is deleted again (the cache still holds
    // the previous key) encrypts with the key the table holds now, so the
    // new cookie keeps working once the cache lapses.
    let url = ua_server::login::create_login_link(&hub.state.hub, "operator", "test").unwrap();
    let token = query_param(&url, "token").unwrap();
    delete_key();
    let resp = send(form("/login/link", &[("token", &token)], None)).await;
    let fresh = session_cookie(&resp).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(json_body(send(get("/api/session", Some(&fresh), None)).await).await["auth"], "cookie");
}

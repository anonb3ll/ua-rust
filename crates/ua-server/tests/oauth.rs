//! The OAuth 2.1 authorization server: discovery, the authorization code
//! flow with PKCE, refresh rotation, revocation and bearer validation.

mod common;

use axum::http::{StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const REDIRECT: &str = "https://client.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-test-verifier";

fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn register(hub: &TestHub, body: Value) -> (StatusCode, Value) {
    let resp = hub.send(post_json("/oauth/register", &body, &[])).await;
    let status = resp.status();
    (status, json_body(resp).await)
}

async fn public_client(hub: &TestHub) -> String {
    let (status, v) =
        register(hub, json!({ "client_name": "Test client", "redirect_uris": [REDIRECT] })).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert!(v.get("client_secret").is_none());
    v["client_id"].as_str().unwrap().to_string()
}

fn hidden(page: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = page.find(&marker).unwrap_or_else(|| panic!("no {name} field")) + marker.len();
    page[start..].split('"').next().unwrap().to_string()
}

fn authorize_url(client_id: &str, verifier: &str, resource: Option<&str>) -> String {
    let mut pairs = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.to_string()),
        ("redirect_uri", REDIRECT.to_string()),
        ("scope", "mcp".to_string()),
        ("state", "xyz".to_string()),
        ("code_challenge", challenge(verifier)),
        ("code_challenge_method", "S256".to_string()),
    ];
    if let Some(r) = resource {
        pairs.push(("resource", r.to_string()));
    }
    let q = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish();
    format!("/oauth/authorize?{q}")
}

/// Drive the consent page as a signed-in human; returns the code.
async fn authorize(
    hub: &TestHub,
    cookie: &str,
    client_id: &str,
    verifier: &str,
    resource: Option<&str>,
) -> String {
    let page = hub.send(get(&authorize_url(client_id, verifier, resource), Some(cookie), None)).await;
    assert_eq!(page.status(), 200);
    assert_eq!(page.headers().get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    // The consent page runs under the strict page CSP: no inline style or
    // script (its style is the hub's stylesheet), and its form may still
    // redirect to the client.
    let csp = page.headers().get(header::CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap().to_string();
    assert!(csp.contains("script-src 'self'") && csp.contains("style-src 'self'"), "{csp}");
    assert!(!csp.contains("unsafe-inline") && !csp.contains("form-action"), "{csp}");
    let html = text_body(page).await;
    assert!(html.contains("Test client"));
    assert!(!html.contains("<style") && !html.contains("<script"), "{html}");
    assert!(html.contains("href=\"/login/assets/page.css\""));
    let (rid, csrf) = (hidden(&html, "request_id"), hidden(&html, "csrf"));
    let resp = hub
        .send(form(
            "/oauth/authorize",
            &[("request_id", &rid), ("csrf", &csrf), ("decision", "approve"), ("identity", "remote-agent")],
            Some(cookie),
        ))
        .await;
    assert!(resp.status().is_redirection(), "{}", resp.status());
    let to = location(&resp);
    assert!(to.starts_with(REDIRECT));
    assert_eq!(query_param(&to, "state").as_deref(), Some("xyz"));
    assert_eq!(query_param(&to, "iss").as_deref(), Some(BASE));
    query_param(&to, "code").expect("redirect carries a code")
}

async fn token(hub: &TestHub, pairs: &[(&str, &str)]) -> (StatusCode, Value) {
    let resp = hub.send(form("/oauth/token", pairs, None)).await;
    let status = resp.status();
    assert_eq!(resp.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
    (status, json_body(resp).await)
}

async fn exchange(hub: &TestHub, client_id: &str, code: &str, verifier: &str) -> (StatusCode, Value) {
    token(
        hub,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", verifier),
        ],
    )
    .await
}

async fn refresh(hub: &TestHub, client_id: &str, rt: &str) -> (StatusCode, Value) {
    token(hub, &[("grant_type", "refresh_token"), ("client_id", client_id), ("refresh_token", rt)]).await
}

async fn mcp_initialize_status(hub: &TestHub, access: &str) -> StatusCode {
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } }
    });
    let auth = format!("Bearer {access}");
    hub.send(post_json(
        "/mcp",
        &init,
        &[("authorization", &auth), ("accept", "application/json, text/event-stream"), ("host", "localhost")],
    ))
    .await
    .status()
}

#[tokio::test]
async fn metadata_documents() {
    let hub = TestHub::new(config());
    let resp = hub.send(get("/.well-known/oauth-authorization-server", None, None)).await;
    assert_eq!(resp.status(), 200);
    let m = json_body(resp).await;
    assert_eq!(m["issuer"], BASE);
    assert_eq!(m["authorization_endpoint"], "https://hub.example.com/oauth/authorize");
    assert_eq!(m["token_endpoint"], "https://hub.example.com/oauth/token");
    assert_eq!(m["revocation_endpoint"], "https://hub.example.com/oauth/revoke");
    assert_eq!(m["registration_endpoint"], "https://hub.example.com/oauth/register");
    assert_eq!(m["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(m["authorization_response_iss_parameter_supported"], true);
    assert_eq!(m["client_id_metadata_document_supported"], false);

    let pr = json_body(hub.send(get("/.well-known/oauth-protected-resource/mcp", None, None)).await).await;
    assert_eq!(pr["resource"], "https://hub.example.com/mcp");
    assert_eq!(pr["authorization_servers"], json!([BASE]));
    let root = json_body(hub.send(get("/.well-known/oauth-protected-resource", None, None)).await).await;
    assert_eq!(root["resource"], BASE);

    // With OAuth off the endpoints do not exist and the challenge is bare.
    let mut cfg = config();
    cfg.oauth_enabled = false;
    let off = TestHub::new(cfg);
    assert_eq!(off.send(get("/.well-known/oauth-authorization-server", None, None)).await.status(), 404);
    let r = off.send(get("/api/whoami", None, None)).await;
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers().get(header::WWW_AUTHENTICATE).unwrap(), "Bearer realm=\"ua\"");
}

#[tokio::test]
async fn unauthenticated_requests_get_the_rfc9728_challenge() {
    let hub = TestHub::new(config());
    for (path, bearer) in [("/api/whoami", None), ("/api/whoami", Some("uao_bogus")), ("/mcp", None)] {
        let resp = hub.send(get(path, None, bearer)).await;
        assert_eq!(resp.status(), 401, "{path}");
        let h = resp.headers().get(header::WWW_AUTHENTICATE).unwrap().to_str().unwrap().to_string();
        assert!(h.starts_with("Bearer "));
        assert!(h.contains(
            "resource_metadata=\"https://hub.example.com/.well-known/oauth-protected-resource/mcp\""
        ));
        assert_eq!(h.contains("error=\"invalid_token\""), bearer.is_some(), "{h}");
    }
}

#[tokio::test]
async fn full_authorization_code_flow() {
    let hub = TestHub::new(config());
    let client_id = public_client(&hub).await;

    // Without a session the human is sent to sign in first.
    let resp = hub.send(get(&authorize_url(&client_id, VERIFIER, None), None, None)).await;
    assert!(resp.status().is_redirection());
    assert!(location(&resp).starts_with("/login?next=%2Foauth%2Fauthorize"));

    let cookie = hub.sign_in("operator").await;
    let code = authorize(&hub, &cookie, &client_id, VERIFIER, None).await;
    assert!(code.starts_with("uac_"));
    let (status, t) = exchange(&hub, &client_id, &code, VERIFIER).await;
    assert_eq!(status, 200, "{t}");
    assert_eq!(t["token_type"], "Bearer");
    assert_eq!(t["scope"], "mcp");
    let access = t["access_token"].as_str().unwrap();
    assert!(access.starts_with("uao_"));
    assert!(t["refresh_token"].as_str().unwrap().starts_with("uar_"));

    // The token is good on /mcp, as the bound agent identity...
    assert_eq!(mcp_initialize_status(&hub, access).await, StatusCode::OK);
    // ...but its audience is /mcp, so /api refuses it.
    assert_eq!(hub.send(get("/api/whoami", None, Some(access))).await.status(), 401);

    // Only digests are stored.
    let stored: i64 = hub
        .state
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM oauth_tokens WHERE token_hash = ?1", [access], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    assert_eq!(stored, 0);

    // A replayed code is refused and revokes what the first exchange issued.
    let (status, e) = exchange(&hub, &client_id, &code, VERIFIER).await;
    assert_eq!(status, 400);
    assert_eq!(e["error"], "invalid_grant");
    assert_eq!(mcp_initialize_status(&hub, access).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn hub_wide_resource_reaches_the_api_with_the_oauth_profile() {
    let hub = TestHub::new(config());
    let client_id = public_client(&hub).await;
    let cookie = hub.sign_in("operator").await;
    let code = authorize(&hub, &cookie, &client_id, VERIFIER, Some("https://hub.example.com/")).await;
    let (status, t) = exchange(&hub, &client_id, &code, VERIFIER).await;
    assert_eq!(status, 200, "{t}");
    let resp = hub.send(get("/api/whoami", None, t["access_token"].as_str())).await;
    assert_eq!(resp.status(), 200);
    let v = json_body(resp).await;
    assert_eq!(v["identity"], "remote-agent");
    assert_eq!(v["kind"], "agent");
    assert_eq!(v["profile"], "public");
}

#[tokio::test]
async fn authorization_request_refusals() {
    let hub = TestHub::new(config());
    let client_id = public_client(&hub).await;
    let cookie = hub.sign_in("operator").await;

    // An unregistered redirect URI is never redirected to.
    let bad_redirect =
        authorize_url(&client_id, VERIFIER, None).replace("client.example.com", "evil.example.com");
    let resp = hub.send(get(&bad_redirect, Some(&cookie), None)).await;
    assert_eq!(resp.status(), 400);
    assert!(resp.headers().get(header::LOCATION).is_none());

    // Missing PKCE, or plain PKCE, is returned to the client as an error.
    for (from, to) in
        [("&code_challenge_method=S256", ""), ("code_challenge_method=S256", "code_challenge_method=plain")]
    {
        let url = authorize_url(&client_id, VERIFIER, None).replace(from, to);
        let resp = hub.send(get(&url, Some(&cookie), None)).await;
        assert!(resp.status().is_redirection());
        let to = location(&resp);
        assert_eq!(query_param(&to, "error").as_deref(), Some("invalid_request"));
        assert_eq!(query_param(&to, "iss").as_deref(), Some(BASE));
    }

    // A foreign resource indicator is refused.
    let url = authorize_url(&client_id, VERIFIER, Some("https://other.example.com/mcp"));
    let resp = hub.send(get(&url, Some(&cookie), None)).await;
    assert_eq!(query_param(&location(&resp), "error").as_deref(), Some("invalid_target"));

    // A consent form without the session's CSRF token is refused.
    let page =
        text_body(hub.send(get(&authorize_url(&client_id, VERIFIER, None), Some(&cookie), None)).await).await;
    let rid = hidden(&page, "request_id");
    let resp = hub
        .send(form(
            "/oauth/authorize",
            &[("request_id", &rid), ("csrf", "wrong"), ("decision", "approve"), ("identity", "remote-agent")],
            Some(&cookie),
        ))
        .await;
    assert_eq!(resp.status(), 403);

    // A human identity may not be granted, even with a valid form.
    let csrf = hidden(&page, "csrf");
    let resp = hub
        .send(form(
            "/oauth/authorize",
            &[("request_id", &rid), ("csrf", &csrf), ("decision", "approve"), ("identity", "operator")],
            Some(&cookie),
        ))
        .await;
    assert_eq!(resp.status(), 400);

    // Deny redirects with access_denied.
    let page =
        text_body(hub.send(get(&authorize_url(&client_id, VERIFIER, None), Some(&cookie), None)).await).await;
    let resp = hub
        .send(form(
            "/oauth/authorize",
            &[
                ("request_id", &hidden(&page, "request_id")),
                ("csrf", &hidden(&page, "csrf")),
                ("decision", "deny"),
            ],
            Some(&cookie),
        ))
        .await;
    assert_eq!(query_param(&location(&resp), "error").as_deref(), Some("access_denied"));
}

#[tokio::test]
async fn wrong_verifier_is_refused() {
    let hub = TestHub::new(config());
    let client_id = public_client(&hub).await;
    let cookie = hub.sign_in("operator").await;
    let code = authorize(&hub, &cookie, &client_id, VERIFIER, None).await;
    let other = "x".repeat(50);
    let (status, e) = exchange(&hub, &client_id, &code, &other).await;
    assert_eq!(status, 400);
    assert_eq!(e["error"], "invalid_grant");
    // The code is burned by the failed attempt.
    let (status, _) = exchange(&hub, &client_id, &code, VERIFIER).await;
    assert_eq!(status, 400);

    // Another client cannot redeem a code.
    let code = authorize(&hub, &cookie, &client_id, VERIFIER, None).await;
    let thief = public_client(&hub).await;
    let (status, e) = exchange(&hub, &thief, &code, VERIFIER).await;
    assert_eq!(status, 400);
    assert_eq!(e["error"], "invalid_grant");
}

#[tokio::test]
async fn refresh_rotation_and_reuse_detection() {
    let hub = TestHub::new(config());
    let client_id = public_client(&hub).await;
    let cookie = hub.sign_in("operator").await;
    let code = authorize(&hub, &cookie, &client_id, VERIFIER, None).await;
    let (_, first) = exchange(&hub, &client_id, &code, VERIFIER).await;
    let rt1 = first["refresh_token"].as_str().unwrap().to_string();

    let (status, second) = refresh(&hub, &client_id, &rt1).await;
    assert_eq!(status, 200, "{second}");
    let rt2 = second["refresh_token"].as_str().unwrap().to_string();
    let at2 = second["access_token"].as_str().unwrap().to_string();
    assert_ne!(rt1, rt2);
    assert_eq!(mcp_initialize_status(&hub, &at2).await, StatusCode::OK);

    // Presenting the rotated token again is theft: the whole sign-in ends.
    let (status, e) = refresh(&hub, &client_id, &rt1).await;
    assert_eq!(status, 400);
    assert_eq!(e["error"], "invalid_grant");
    assert_eq!(mcp_initialize_status(&hub, &at2).await, StatusCode::UNAUTHORIZED);
    let (status, _) = refresh(&hub, &client_id, &rt2).await;
    assert_eq!(status, 400);

    let sessions = hub
        .state
        .registry
        .call(&hub.state.hub, &ua_core::Caller::system(), "oauth_device_manage", json!({}))
        .await
        .unwrap();
    assert_eq!(sessions["session_count"], 0);
}

#[tokio::test]
async fn revocation() {
    let hub = TestHub::new(config());
    let client_id = public_client(&hub).await;
    let cookie = hub.sign_in("operator").await;
    let code = authorize(&hub, &cookie, &client_id, VERIFIER, None).await;
    let (_, t) = exchange(&hub, &client_id, &code, VERIFIER).await;
    let (at, rt) = (t["access_token"].as_str().unwrap(), t["refresh_token"].as_str().unwrap());

    // Unknown tokens answer 200 (RFC 7009 §2.2).
    let resp =
        hub.send(form("/oauth/revoke", &[("client_id", &client_id), ("token", "uao_unknown")], None)).await;
    assert_eq!(resp.status(), 200);

    // Another client cannot revoke this client's token.
    let other = public_client(&hub).await;
    hub.send(form("/oauth/revoke", &[("client_id", &other), ("token", at)], None)).await;
    assert_eq!(mcp_initialize_status(&hub, at).await, StatusCode::OK);

    let resp = hub.send(form("/oauth/revoke", &[("client_id", &client_id), ("token", at)], None)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(mcp_initialize_status(&hub, at).await, StatusCode::UNAUTHORIZED);

    // Revoking the refresh token ends the grant.
    hub.send(form("/oauth/revoke", &[("client_id", &client_id), ("token", rt)], None)).await;
    let (status, _) = refresh(&hub, &client_id, rt).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn client_credentials_for_configured_clients() {
    let mut cfg = config();
    cfg.oauth_client_credentials =
        Some("svc-1|test-client-secret-value|remote-agent,bad|x|operator".to_string().into());
    let hub = TestHub::new(cfg);

    let basic = |id: &str, secret: &str| format!("Basic {}", STANDARD.encode(format!("{id}:{secret}")));
    let send = |auth: String| {
        let body = "grant_type=client_credentials";
        axum::http::Request::post("/oauth/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::AUTHORIZATION, auth)
            .body(axum::body::Body::from(body))
            .unwrap()
    };
    let resp = hub.send(send(basic("svc-1", "wrong-secret"))).await;
    assert_eq!(resp.status(), 401);
    assert_eq!(json_body(resp).await["error"], "invalid_client");

    // A configured client bound to a human identity is refused.
    let resp = hub.send(send(basic("bad", "x"))).await;
    assert_eq!(resp.status(), 400);
    assert_eq!(json_body(resp).await["error"], "unauthorized_client");

    let resp = hub.send(send(basic("svc-1", "test-client-secret-value"))).await;
    assert_eq!(resp.status(), 200);
    let t = json_body(resp).await;
    assert!(t.get("refresh_token").is_none());
    assert_eq!(mcp_initialize_status(&hub, t["access_token"].as_str().unwrap()).await, StatusCode::OK);

    // Public clients may not use client_credentials.
    let client_id = public_client(&hub).await;
    let (status, e) = token(&hub, &[("grant_type", "client_credentials"), ("client_id", &client_id)]).await;
    assert_eq!(status, 400);
    assert_eq!(e["error"], "unauthorized_client");
}

#[tokio::test]
async fn dynamic_registration_rules() {
    let hub = TestHub::new(config());
    for bad in [
        json!({ "redirect_uris": [] }),
        json!({ "redirect_uris": ["http://evil.example.com/cb"] }),
        json!({ "redirect_uris": ["javascript:alert(1)"] }),
        json!({ "redirect_uris": ["https://a.example.com/cb#frag"] }),
        json!({ "redirect_uris": [REDIRECT], "grant_types": ["client_credentials"] }),
    ] {
        let (status, _) = register(&hub, bad.clone()).await;
        assert_eq!(status, 400, "{bad}");
    }
    let (status, v) = register(
        &hub,
        json!({ "redirect_uris": ["http://127.0.0.1/cb"], "token_endpoint_auth_method": "client_secret_basic" }),
    )
    .await;
    assert_eq!(status, 201);
    let secret = v["client_secret"].as_str().unwrap();
    let stored: String = hub
        .state
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT secret_hash FROM oauth_clients WHERE client_id = ?1",
                [&v["client_id"].as_str()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_ne!(stored, secret);

    let mut cfg = config();
    cfg.oauth_dcr_enabled = false;
    let off = TestHub::new(cfg);
    let resp = off.send(post_json("/oauth/register", &json!({ "redirect_uris": [REDIRECT] }), &[])).await;
    assert_eq!(resp.status(), 404);
    let m = json_body(off.send(get("/.well-known/oauth-authorization-server", None, None)).await).await;
    assert!(m.get("registration_endpoint").is_none());
}

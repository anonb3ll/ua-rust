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
    // The page names the resource the grant reaches, and words it for MCP
    // only when that is /mcp (never in a build without mcp-server).
    let granted = match resource {
        Some(r) => r.trim_end_matches('/').to_string(),
        None if ua_server::MCP_SERVER => format!("{BASE}/mcp"),
        None => BASE.to_string(),
    };
    assert!(html.contains(&format!("Resource: <code>{granted}</code>")), "{html}");
    let wording = if granted.ends_with("/mcp") { "this hub's MCP tools" } else { "this hub's API and tools" };
    assert!(html.contains(wording), "{html}");
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

/// Status of a call made with `access`: an MCP initialize on `/mcp`. A build
/// without the `mcp-server` feature has no `/mcp` and issues hub-wide tokens
/// by default, so there it is `GET /api/whoami`.
async fn mcp_initialize_status(hub: &TestHub, access: &str) -> StatusCode {
    if !ua_server::MCP_SERVER {
        return hub.send(get("/api/whoami", None, Some(access))).await.status();
    }
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

    let pr = hub.send(get("/.well-known/oauth-protected-resource/mcp", None, None)).await;
    if ua_server::MCP_SERVER {
        let pr = json_body(pr).await;
        assert_eq!(pr["resource"], "https://hub.example.com/mcp");
        assert_eq!(pr["authorization_servers"], json!([BASE]));
    } else {
        // No /mcp in this build, so no resource document for it.
        assert_eq!(pr.status(), 404);
    }
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
    let mut paths = vec![("/api/whoami", None), ("/api/whoami", Some("uao_bogus"))];
    if ua_server::MCP_SERVER {
        paths.push(("/mcp", None));
    }
    // Without the mcp-server feature the challenge points at the root
    // document: there is no /mcp resource.
    let metadata = if ua_server::MCP_SERVER {
        "resource_metadata=\"https://hub.example.com/.well-known/oauth-protected-resource/mcp\""
    } else {
        "resource_metadata=\"https://hub.example.com/.well-known/oauth-protected-resource\""
    };
    for (path, bearer) in paths {
        let resp = hub.send(get(path, None, bearer)).await;
        assert_eq!(resp.status(), 401, "{path}");
        let h = resp.headers().get(header::WWW_AUTHENTICATE).unwrap().to_str().unwrap().to_string();
        assert!(h.starts_with("Bearer "));
        assert!(h.contains(metadata), "{h}");
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
    if ua_server::MCP_SERVER {
        // ...but its audience is /mcp, so /api refuses it.
        assert_eq!(hub.send(get("/api/whoami", None, Some(access))).await.status(), 401);
    } else {
        // Without the mcp-server feature the default audience is the hub.
        let row: String = hub
            .state
            .hub
            .db()
            .read(|c| Ok(c.query_row("SELECT resource FROM oauth_tokens LIMIT 1", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(row, BASE);
    }

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

// --- client_credentials refusals -----------------------------------------------------

const CC_SECRET: &str = "test-client-secret-value";

/// A hub with three configured clients: `svc-1` acts as `svc-agent`, which
/// has a `profiles` entry; `svc-2` as `remote-agent`, an `oauth_identities`
/// label that gets `oauth_profile`; `svc-3` as `bare-agent`, which has no
/// profile configured at all.
fn cc_hub() -> TestHub {
    let mut cfg = config();
    cfg.oauth_client_credentials = Some(
        format!("svc-1|{CC_SECRET}|svc-agent,svc-2|{CC_SECRET}|remote-agent,svc-3|{CC_SECRET}|bare-agent")
            .into(),
    );
    cfg.profiles.insert("svc-agent".into(), "reviewer".into());
    TestHub::new(cfg)
}

/// A `client_credentials` request from `client_id` with extra parameters.
async fn cc_token(hub: &TestHub, client_id: &str, extra: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut pairs =
        vec![("grant_type", "client_credentials"), ("client_id", client_id), ("client_secret", CC_SECRET)];
    pairs.extend_from_slice(extra);
    token(hub, &pairs).await
}

/// The scope recorded on the grant and on every token of `access`'s family.
fn recorded_scopes(hub: &TestHub, access: &str) -> (String, Vec<String>) {
    let hash = hex::encode(Sha256::digest(access.as_bytes()));
    hub.state
        .hub
        .db()
        .read(|c| {
            let (family, grant_scope): (String, String) = c.query_row(
                "SELECT g.family_id, g.scope FROM oauth_tokens t JOIN oauth_grants g ON g.family_id = t.family_id \
                 WHERE t.token_hash = ?1",
                [&hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let mut stmt = c.prepare("SELECT scope FROM oauth_tokens WHERE family_id = ?1")?;
            let scopes = stmt.query_map([&family], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
            Ok((grant_scope, scopes))
        })
        .unwrap()
}

#[tokio::test]
async fn client_credentials_issues_the_granted_scope_under_the_configured_profile() {
    let hub = cc_hub();
    let (status, t) = cc_token(&hub, "svc-1", &[("scope", "mcp"), ("resource", BASE)]).await;
    assert_eq!(status, 200, "{t}");
    assert_eq!(t["scope"], "mcp");
    assert!(t.get("refresh_token").is_none());
    let access = t["access_token"].as_str().unwrap();
    assert_eq!(recorded_scopes(&hub, access), ("mcp".to_string(), vec!["mcp".to_string()]));
    let v = json_body(hub.send(get("/api/whoami", None, Some(access))).await).await;
    assert_eq!(v["identity"], "svc-agent");
    assert_eq!(v["kind"], "agent");
    assert_eq!(v["profile"], "reviewer", "the identity's configured profile, not developer: {v}");

    // No scope requested: the client's allowed scope is granted.
    let (status, t) = cc_token(&hub, "svc-1", &[]).await;
    assert_eq!(status, 200, "{t}");
    assert_eq!(t["scope"], "mcp");

    // An `oauth_identities` label gets `oauth_profile`.
    let (status, t) = cc_token(&hub, "svc-2", &[("resource", BASE)]).await;
    assert_eq!(status, 200, "{t}");
    let v = json_body(hub.send(get("/api/whoami", None, t["access_token"].as_str())).await).await;
    assert_eq!(v["identity"], "remote-agent");
    assert_eq!(v["profile"], "public", "{v}");
}

#[tokio::test]
async fn client_credentials_refuses_a_scope_the_client_is_not_allowed() {
    let hub = cc_hub();
    for scope in ["admin", "mcp admin", "MCP", "mcp offline_access"] {
        let (status, e) = cc_token(&hub, "svc-1", &[("scope", scope)]).await;
        assert_eq!(status, 400, "{scope}: {e}");
        assert_eq!(e["error"], "invalid_scope", "{scope}: {e}");
    }
    let issued: i64 = hub
        .state
        .hub
        .db()
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM oauth_tokens", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(issued, 0, "a refused scope mints nothing");
}

#[tokio::test]
async fn client_credentials_refuses_an_identity_without_a_configured_profile() {
    let hub = cc_hub();
    let (status, e) = cc_token(&hub, "svc-3", &[]).await;
    assert_eq!(status, 400, "{e}");
    assert_eq!(e["error"], "unauthorized_client", "{e}");
    assert!(e["error_description"].as_str().unwrap().contains("profile"), "{e}");

    // A profile name the hub does not know does not count either: it would
    // fall back to developer.
    let mut cfg = config();
    cfg.oauth_client_credentials = Some(format!("svc-3|{CC_SECRET}|bare-agent").into());
    cfg.profiles.insert("bare-agent".into(), "no-such-profile".into());
    let hub = TestHub::new(cfg);
    let (status, e) = cc_token(&hub, "svc-3", &[]).await;
    assert_eq!(status, 400, "{e}");
    assert_eq!(e["error"], "unauthorized_client", "{e}");

    // Opting in is explicit: a `profiles` entry, developer included.
    let mut cfg = config();
    cfg.oauth_client_credentials = Some(format!("svc-3|{CC_SECRET}|bare-agent").into());
    cfg.profiles.insert("bare-agent".into(), "developer".into());
    let hub = TestHub::new(cfg);
    let (status, t) = cc_token(&hub, "svc-3", &[("resource", BASE)]).await;
    assert_eq!(status, 200, "{t}");
    let v = json_body(hub.send(get("/api/whoami", None, t["access_token"].as_str())).await).await;
    assert_eq!(v["profile"], "developer", "{v}");
}

#[tokio::test]
async fn client_credentials_refuses_a_retired_identity() {
    let hub = cc_hub();
    let operator = ua_core::Caller {
        label: "operator".into(),
        kind: ua_core::ActorKind::Human,
        profile: ua_core::Profile::Developer,
        enforce_profile: true,
        session_key: None,
        transport: ua_core::identity::Transport::Http,
    };
    let manage = |action: &'static str| json!({ "action": action, "params": { "agent": "svc-agent", "reason": "decommissioned" } });
    hub.state
        .registry
        .call(&hub.state.hub, &operator, "coordination_manage", manage("agent_retire"))
        .await
        .unwrap();

    // As for a human identity: the client may not act as this identity.
    let (status, e) = cc_token(&hub, "svc-1", &[]).await;
    assert_eq!(status, 400, "{e}");
    assert_eq!(e["error"], "unauthorized_client", "{e}");
    let grants: i64 = hub
        .state
        .hub
        .db()
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM oauth_grants", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(grants, 0, "a retired identity gets no grant");

    hub.state
        .registry
        .call(&hub.state.hub, &operator, "coordination_manage", manage("agent_unretire"))
        .await
        .unwrap();
    let (status, t) = cc_token(&hub, "svc-1", &[]).await;
    assert_eq!(status, 200, "{t}");
}

#[tokio::test]
async fn client_credentials_refuses_a_client_not_registered_for_the_grant() {
    let hub = cc_hub();
    // A registered confidential client: it holds a secret but was registered
    // for authorization_code only.
    let (status, v) = register(
        &hub,
        json!({ "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "client_secret_post" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let (id, secret) = (v["client_id"].as_str().unwrap(), v["client_secret"].as_str().unwrap());
    let (status, e) =
        token(&hub, &[("grant_type", "client_credentials"), ("client_id", id), ("client_secret", secret)])
            .await;
    assert_eq!(status, 400, "{e}");
    assert_eq!(e["error"], "unauthorized_client", "{e}");
}

#[tokio::test]
async fn a_code_for_an_identity_retired_after_consent_is_refused() {
    let hub = TestHub::new(config());
    let client_id = public_client(&hub).await;
    let cookie = hub.sign_in("operator").await;
    let code = authorize(&hub, &cookie, &client_id, VERIFIER, None).await;
    let operator = ua_core::Caller {
        label: "operator".into(),
        kind: ua_core::ActorKind::Human,
        profile: ua_core::Profile::Developer,
        enforce_profile: true,
        session_key: None,
        transport: ua_core::identity::Transport::Http,
    };
    hub.state
        .registry
        .call(
            &hub.state.hub,
            &operator,
            "coordination_manage",
            json!({ "action": "agent_retire", "params": { "agent": "remote-agent", "reason": "decommissioned" } }),
        )
        .await
        .unwrap();
    let (status, e) = exchange(&hub, &client_id, &code, VERIFIER).await;
    assert_eq!(status, 400, "{e}");
    assert_eq!(e["error"], "invalid_grant", "{e}");
}

// --- profile and identity checks after the configuration changed --------------------

/// The same hub database served under a changed configuration, as after a
/// restart with an edited config file.
fn reconfigured(hub: &TestHub, tweak: impl FnOnce(&mut ua_core::Config)) -> TestHub {
    let mut cfg = hub.state.hub.cfg().clone();
    tweak(&mut cfg);
    let state = ua_server::AppState::new(
        ua_tools::Hub::new(cfg, hub.state.hub.db().clone()),
        hub.state.registry.clone(),
    );
    let app = ua_server::router(state.clone(), tokio_util::sync::CancellationToken::new());
    TestHub { state, app }
}

/// A signed-in consent and code exchange for `remote-agent`: the tokens.
async fn remote_agent_tokens(hub: &TestHub) -> (String, Value) {
    let client_id = public_client(hub).await;
    let cookie = hub.sign_in("operator").await;
    let code = authorize(hub, &cookie, &client_id, VERIFIER, Some(BASE)).await;
    let (status, t) = exchange(hub, &client_id, &code, VERIFIER).await;
    assert_eq!(status, 200, "{t}");
    (client_id, t)
}

#[tokio::test]
async fn refresh_is_refused_once_the_identity_left_oauth_identities() {
    let hub = TestHub::new(config());
    let (client_id, t) = remote_agent_tokens(&hub).await;
    // The label keeps an explicit profile; only its OAuth eligibility ends.
    let later = reconfigured(&hub, |c| c.oauth_identities.clear());
    assert_eq!(later.state.hub.cfg().profiles.get("remote-agent").map(String::as_str), Some("public"));
    let (status, e) = refresh(&later, &client_id, t["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, 400, "{e}");
    assert_eq!(e["error"], "invalid_grant", "{e}");
    assert!(e["error_description"].as_str().unwrap().contains("OAuth identity"), "{e}");
}

#[tokio::test]
async fn refresh_is_refused_once_the_identity_lost_its_profile() {
    let hub = TestHub::new(config());
    let (client_id, t) = remote_agent_tokens(&hub).await;
    let later = reconfigured(&hub, |c| {
        c.profiles.remove("remote-agent");
    });
    let (status, e) = refresh(&later, &client_id, t["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, 400, "{e}");
    assert_eq!(e["error"], "invalid_grant", "{e}");
    assert!(e["error_description"].as_str().unwrap().contains("profile"), "{e}");
    // A code exchanged after the profile was removed is refused too.
    let client_id = public_client(&hub).await;
    let cookie = hub.sign_in("operator").await;
    let code = authorize(&hub, &cookie, &client_id, VERIFIER, None).await;
    let (status, e) = exchange(&later, &client_id, &code, VERIFIER).await;
    assert_eq!(status, 400, "{e}");
    assert_eq!(e["error"], "invalid_grant", "{e}");
}

#[tokio::test]
async fn a_live_bearer_whose_profile_was_removed_never_resolves_to_developer() {
    let hub = cc_hub();
    let (status, cc) = cc_token(&hub, "svc-1", &[("resource", BASE)]).await;
    assert_eq!(status, 200, "{cc}");
    let (_, code) = remote_agent_tokens(&hub).await;
    for access in [cc["access_token"].as_str().unwrap(), code["access_token"].as_str().unwrap()] {
        let before = json_body(hub.send(get("/api/whoami", None, Some(access))).await).await;
        assert_ne!(before["profile"], "developer", "{before}");

        let later = reconfigured(&hub, |c| c.profiles.clear());
        let resp = later.send(get("/api/whoami", None, Some(access))).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{access}");
        assert_eq!(mcp_initialize_status(&later, access).await, StatusCode::UNAUTHORIZED);
        // An unknown profile name would fall back to developer as well.
        let later = reconfigured(&hub, |c| {
            for p in c.profiles.values_mut() {
                *p = "no-such-profile".into();
            }
        });
        assert_eq!(
            later.send(get("/api/whoami", None, Some(access))).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn an_unknown_client_and_a_wrong_secret_get_the_same_answer() {
    let hub = cc_hub();
    let pairs = |id: &'static str| {
        vec![
            ("grant_type", "client_credentials"),
            ("client_id", id),
            ("client_secret", "not-the-secret-value"),
        ]
    };
    let (s1, unknown) = token(&hub, &pairs("no-such-client")).await;
    let (s2, wrong) = token(&hub, &pairs("svc-1")).await;
    assert_eq!((s1, s2), (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED));
    assert_eq!(unknown, wrong);
    // A public client presenting a secret is answered the same way.
    let client_id = public_client(&hub).await;
    let (s3, public) =
        token(&hub, &[("grant_type", "refresh_token"), ("client_id", &client_id), ("client_secret", "x")])
            .await;
    assert_eq!(s3, StatusCode::UNAUTHORIZED);
    assert_eq!(public, wrong);
}

/// A build without the mcp-server feature has no /mcp resource: naming it
/// explicitly is refused at the authorization endpoint and for
/// client_credentials alike.
#[cfg(not(feature = "mcp-server"))]
#[tokio::test]
async fn without_an_mcp_server_the_mcp_resource_is_refused() {
    let mcp = format!("{BASE}/mcp");
    let hub = cc_hub();
    let client_id = public_client(&hub).await;
    let cookie = hub.sign_in("operator").await;
    let resp = hub.send(get(&authorize_url(&client_id, VERIFIER, Some(&mcp)), Some(&cookie), None)).await;
    assert!(resp.status().is_redirection());
    assert_eq!(query_param(&location(&resp), "error").as_deref(), Some("invalid_target"));

    let (status, e) = cc_token(&hub, "svc-1", &[("resource", &mcp)]).await;
    assert_eq!(status, 400, "{e}");
    assert_eq!(e["error"], "invalid_target", "{e}");
    // Without a resource the token is hub-wide and reaches /api.
    let (status, t) = cc_token(&hub, "svc-1", &[]).await;
    assert_eq!(status, 200, "{t}");
    assert_eq!(hub.send(get("/api/whoami", None, t["access_token"].as_str())).await.status(), 200);
}

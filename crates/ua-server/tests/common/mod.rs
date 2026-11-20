//! Shared helpers for the HTTP auth tests: an in-memory hub behind the full
//! router, driven with `tower::ServiceExt::oneshot`.

#![allow(dead_code)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, header};
use http_body_util::BodyExt;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use ua_core::Config;
use ua_server::AppState;
use ua_tools::{Hub, builtin_registry};

pub const BASE: &str = "https://hub.example.com";

pub fn config() -> Config {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.public_url = Some(BASE.into());
    cfg.enforce_auth = true;
    cfg.oauth_enabled = true;
    cfg.human_identities = vec!["operator".into()];
    cfg.oauth_identities = vec!["remote-agent".into()];
    cfg.apply_oauth_profiles();
    cfg
}

pub struct TestHub {
    pub state: AppState,
    pub app: Router,
}

impl TestHub {
    pub fn new(cfg: Config) -> Self {
        let hub = Hub::in_memory(cfg).unwrap();
        let state = AppState::new(hub, Arc::new(builtin_registry()));
        let app = ua_server::router(state.clone(), CancellationToken::new());
        Self { state, app }
    }

    pub async fn send(&self, req: Request<Body>) -> Response<Body> {
        self.app.clone().oneshot(req).await.unwrap()
    }

    /// Open a browser session through a login link; returns the `Cookie`
    /// header value.
    pub async fn sign_in(&self, label: &str) -> String {
        let url = ua_server::login::create_login_link(&self.state.hub, label, "test").unwrap();
        let token = url.split("token=").nth(1).unwrap().to_string();
        let resp = self.send(form("/login/link", &[("token", &token)], None)).await;
        assert!(resp.status().is_redirection(), "login link refused: {}", resp.status());
        session_cookie(&resp).expect("login link sets a session cookie")
    }

    /// The CSRF token of a cookie session, from `GET /api/session`.
    pub async fn csrf(&self, cookie: &str) -> String {
        let resp = self.send(get("/api/session", Some(cookie), None)).await;
        assert_eq!(resp.status(), 200);
        let v = json_body(resp).await;
        v["csrf_token"].as_str().unwrap().to_string()
    }
}

pub fn get(path: &str, cookie: Option<&str>, bearer: Option<&str>) -> Request<Body> {
    let mut b = Request::get(path);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::empty()).unwrap()
}

pub fn form(path: &str, pairs: &[(&str, &str)], cookie: Option<&str>) -> Request<Body> {
    let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish();
    let mut b = Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::from(body)).unwrap()
}

pub fn post_json(path: &str, body: &Value, headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

pub async fn text_body(resp: Response<Body>) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

pub async fn json_body(resp: Response<Body>) -> Value {
    serde_json::from_str(&text_body(resp).await).unwrap()
}

/// The raw `Set-Cookie` header for the session cookie.
pub fn set_cookie_header(resp: &Response<Body>) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("ua_session="))
        .map(str::to_string)
}

/// The `name=value` pair of the session cookie, ready for a `Cookie` header.
pub fn session_cookie(resp: &Response<Body>) -> Option<String> {
    set_cookie_header(resp).map(|v| v.split(';').next().unwrap().to_string())
}

pub fn location(resp: &Response<Body>) -> String {
    resp.headers().get(header::LOCATION).unwrap().to_str().unwrap().to_string()
}

/// A query parameter of a URL (absolute or path-only).
pub fn query_param(url: &str, name: &str) -> Option<String> {
    let full = if url.starts_with('/') { format!("{BASE}{url}") } else { url.to_string() };
    url::Url::parse(&full).ok()?.query_pairs().find(|(k, _)| k == name).map(|(_, v)| v.to_string())
}

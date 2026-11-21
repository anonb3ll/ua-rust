//! Web family: SSRF refusals, redirects, extraction and search parsing.
//!
//! No test touches the network. A local axum server on 127.0.0.1 stands in
//! for the web; `Config::fetch_allow_loopback` (a test-only switch) lets the
//! fetch reach it while every other non-public range stays refused.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::families::web::{html_to_markdown, parse_ddg};
use ua_tools::{Hub, Registry, builtin_registry};

const ARTICLE: &str = r#"<!doctype html>
<html><head><title>Field Notes | Example</title></head>
<body>
<nav><a href="/">Home</a> <a href="/about">About</a></nav>
<article>
<h1>Tending a Rust Garden</h1>
<p>Compilers are patient gardeners. This paragraph is long enough to be the main content of the page,
and it keeps going so the readability scorer is confident it found the article body rather than chrome.</p>
<p>A second paragraph talks about <strong>borrow checking</strong> and lifetimes in some detail, again with
enough words that the extraction treats it as real prose worth keeping in the output.</p>
<ul><li>Water daily</li><li>Prune weekly</li></ul>
</article>
<footer>Copyright example.com</footer>
<script>window.tracking = true;</script>
</body></html>"#;

const DDG_HTML: &str = r#"<html><body>
<div class="result results_links results_links_deep result--ad">
  <a class="result__a" href="https://duckduckgo.com/y.js?ad_provider=x">Sponsored thing</a>
</div>
<div class="result results_links results_links_deep web-result">
  <div class="links_main links_deep result__body">
    <h2 class="result__title"><a rel="nofollow" class="result__a"
      href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fone&amp;rut=abc">First   result</a></h2>
    <a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fone">The <b>first</b> snippet.</a>
  </div>
</div>
<div class="result results_links results_links_deep web-result">
  <h2 class="result__title"><a rel="nofollow" class="result__a"
    href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Ftwo%3Fq%3D1&amp;rut=def">Second result</a></h2>
  <a class="result__snippet">Second snippet.</a>
</div>
<div class="result results_links web-result">
  <h2 class="result__title"><a class="result__a" href="https://example.net/three">Third</a></h2>
</div>
</body></html>"#;

const DDG_LITE: &str = r#"<html><body><table>
<tr class="result-sponsored"><td><a rel="nofollow" href="https://duckduckgo.com/y.js?x=1" class='result-link'>Ad</a></td></tr>
<tr><td>1.&nbsp;</td><td><a rel="nofollow" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Flite" class='result-link'>Lite one</a></td></tr>
<tr><td>&nbsp;</td><td class='result-snippet'>Lite snippet one.</td></tr>
<tr><td>2.&nbsp;</td><td><a rel="nofollow" href="https://example.org/lite2" class='result-link'>Lite two</a></td></tr>
<tr><td>&nbsp;</td><td class='result-snippet'>Lite snippet two.</td></tr>
</table></body></html>"#;

const PNG_1X2: &[u8] = &[
    0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n', 0, 0, 0, 13, b'I', b'H', b'D', b'R', 0, 0, 0, 1, 0, 0,
    0, 2, 8, 6, 0, 0, 0,
];

struct Server {
    addr: SocketAddr,
    search_hits: Arc<AtomicUsize>,
}

async fn redirect(to: String) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, to)]).into_response()
}

async fn spawn_server() -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let search_hits = Arc::new(AtomicUsize::new(0));
    let hits = search_hits.clone();
    let app = Router::new()
        .route("/article", get(|| async { ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], ARTICLE) }))
        .route("/plain", get(|| async { ([(header::CONTENT_TYPE, "text/plain")], "just text\nline two") }))
        .route(
            "/latin1",
            get(|| async {
                ([(header::CONTENT_TYPE, "text/plain; charset=iso-8859-1")], b"caf\xe9".to_vec())
            }),
        )
        .route(
            "/image",
            get(|| async { ([(header::CONTENT_TYPE, "application/octet-stream")], PNG_1X2.to_vec()) }),
        )
        .route(
            "/doc.pdf",
            get(|| async { ([(header::CONTENT_TYPE, "application/pdf")], b"%PDF-1.4\n%fake\n".to_vec()) }),
        )
        .route(
            "/big",
            get(|| async { ([(header::CONTENT_TYPE, "text/plain")], "a".repeat(3 * 1024 * 1024)) }),
        )
        .route("/missing", get(|| async { StatusCode::NOT_FOUND }))
        .route("/to-private", get(|| redirect("http://10.0.0.1/".into())))
        .route("/to-metadata", get(|| redirect("http://169.254.169.254/latest/meta-data/".into())))
        .route("/to-file", get(|| redirect("file:///etc/passwd".into())))
        .route("/to-article", get(|| redirect("/article".into())))
        .route("/loop", get(|| redirect("/loop".into())))
        .route(
            "/chain/{n}",
            get(|Path(n): Path<u32>| async move {
                if n == 0 {
                    redirect("/plain".into()).await
                } else {
                    redirect(format!("/chain/{}", n - 1)).await
                }
            }),
        )
        .route(
            "/ddg",
            any(move |_h: HeaderMap| {
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    ([(header::CONTENT_TYPE, "text/html")], DDG_HTML)
                }
            }),
        )
        .route(
            "/ddg-challenge",
            any(|| async {
                ([(header::CONTENT_TYPE, "text/html")], "<div class=\"anomaly-modal\">bots</div>")
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Server { addr, search_hits }
}

struct Env {
    _home: tempfile::TempDir,
    hub: Hub,
    reg: Registry,
}

fn env_with(tweak: impl FnOnce(&mut Config)) -> Env {
    let home = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(home.path());
    cfg.workspace = Some(home.path().to_path_buf());
    // Keep the tests independent of the machine's environment.
    cfg.search_provider = "ddg".into();
    tweak(&mut cfg);
    Env { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), _home: home }
}

fn agent() -> Caller {
    Caller {
        label: "researcher-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

impl Env {
    async fn call(&self, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, &agent(), tool, args).await
    }

    async fn fetch(&self, url: &str) -> Result<Value, UaError> {
        self.call("web_fetch", json!({ "url": url })).await
    }
}

fn reason(e: &UaError) -> String {
    match e {
        UaError::Denied { reason_code, .. } => reason_code.clone(),
        other => other.code().to_string(),
    }
}

#[tokio::test]
async fn refuses_non_public_hosts() {
    let env = env_with(|_| {});
    for url in [
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://192.168.1.10:8080/x",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[fd00::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://0.0.0.0/",
        "http://100.64.0.1/",
        "http://localhost/",
    ] {
        let err = env.fetch(url).await.unwrap_err();
        assert_eq!(reason(&err), "ssrf_blocked", "{url}: {err}");
    }
    for url in ["file:///etc/passwd", "ftp://example.com/", "gopher://example.com/", "not a url"] {
        let err = env.fetch(url).await.unwrap_err();
        assert_eq!(err.code(), "invalid_argument", "{url}: {err}");
    }
}

#[tokio::test]
async fn loopback_is_refused_without_the_test_switch() {
    let srv = spawn_server().await;
    let env = env_with(|_| {});
    let err = env.fetch(&format!("http://{}/article", srv.addr)).await.unwrap_err();
    assert_eq!(reason(&err), "ssrf_blocked");
}

#[tokio::test]
async fn redirects_are_rechecked_and_capped() {
    let srv = spawn_server().await;
    let env = env_with(|c| c.fetch_allow_loopback = true);
    let base = format!("http://{}", srv.addr);

    // The loopback switch admits loopback only: private and metadata hops stay refused.
    for path in ["/to-private", "/to-metadata"] {
        let err = env.fetch(&format!("{base}{path}")).await.unwrap_err();
        assert_eq!(reason(&err), "ssrf_blocked", "{path}: {err}");
    }
    let err = env.fetch(&format!("{base}/to-file")).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let err = env.fetch("http://10.1.2.3/").await.unwrap_err();
    assert_eq!(reason(&err), "ssrf_blocked");

    // Five redirects are followed, a sixth is not.
    let ok = env.fetch(&format!("{base}/chain/4")).await.unwrap();
    assert!(ok["final_url"].as_str().unwrap().ends_with("/plain"));
    let err = env.fetch(&format!("{base}/chain/5")).await.unwrap_err();
    assert!(err.to_string().contains("redirects"), "{err}");
    let err = env.fetch(&format!("{base}/loop")).await.unwrap_err();
    assert!(err.to_string().contains("redirects"), "{err}");

    let followed = env.fetch(&format!("{base}/to-article")).await.unwrap();
    assert!(followed["final_url"].as_str().unwrap().ends_with("/article"));
    assert_eq!(followed["url"], format!("{base}/to-article"));
}

#[tokio::test]
async fn extracts_readable_markdown() {
    let srv = spawn_server().await;
    let env = env_with(|c| c.fetch_allow_loopback = true);
    let base = format!("http://{}", srv.addr);

    let page = env.fetch(&format!("{base}/article")).await.unwrap();
    let content = page["content"].as_str().unwrap();
    assert!(content.contains("Compilers are patient gardeners"), "{content}");
    assert!(content.contains("**borrow checking**"), "{content}");
    assert!(content.contains("Water daily"), "{content}");
    assert!(!content.contains("window.tracking"), "{content}");
    assert!(
        page["title"].as_str().unwrap().contains("Field Notes")
            || page["title"].as_str().unwrap().contains("Rust Garden")
    );
    assert_eq!(page["untrusted"], true);
    assert_eq!(page["truncated"], false);
    // The article is found with the readability feature; without it the
    // whole page is converted, and the result says so.
    let expected = if cfg!(feature = "readability") { "readability" } else { "full-page" };
    assert_eq!(page["extraction"], expected, "{page}");

    let raw = env.call("web_fetch", json!({ "url": format!("{base}/article"), "raw": true })).await.unwrap();
    assert!(raw["content"].as_str().unwrap().starts_with("<!doctype html>"));
    assert_eq!(raw["title"], Value::Null);
    assert_eq!(raw.get("extraction"), None, "raw bodies are not converted");

    let capped =
        env.call("web_fetch", json!({ "url": format!("{base}/article"), "max_chars": 10 })).await.unwrap();
    assert_eq!(capped["content"].as_str().unwrap().chars().count(), 100, "max_chars is clamped to 100");
    assert_eq!(capped["truncated"], true);

    let plain = env.fetch(&format!("{base}/plain")).await.unwrap();
    assert_eq!(plain["content"], "just text\nline two");
    let latin = env.fetch(&format!("{base}/latin1")).await.unwrap();
    assert_eq!(latin["content"], "café");

    let big =
        env.call("web_fetch", json!({ "url": format!("{base}/big"), "max_chars": 200000 })).await.unwrap();
    assert_eq!(big["truncated"], true);

    let err = env.fetch(&format!("{base}/missing")).await.unwrap_err();
    assert!(err.to_string().contains("404"), "{err}");
}

#[tokio::test]
async fn binary_bodies_come_back_as_base64() {
    let srv = spawn_server().await;
    let env = env_with(|c| c.fetch_allow_loopback = true);
    let base = format!("http://{}", srv.addr);

    let img = env.fetch(&format!("{base}/image")).await.unwrap();
    assert_eq!(img["kind"], "image");
    assert_eq!(img["mime"], "image/png");
    assert!(img["note"].as_str().unwrap().contains("1x2"), "{img}");

    let pdf = env.fetch(&format!("{base}/doc.pdf")).await.unwrap();
    assert_eq!(pdf["kind"], "pdf");
    assert!(pdf["base64"].as_str().unwrap().starts_with("JVBERi0"));
    assert!(pdf["note"].as_str().unwrap().contains("no in-process PDF text extraction"));
    let asked =
        env.call("web_fetch", json!({ "url": format!("{base}/doc.pdf"), "pdf_base64": true })).await.unwrap();
    assert!(!asked["note"].as_str().unwrap().contains("no in-process"));
}

#[test]
fn parses_ddg_result_pages() {
    let hits = parse_ddg(DDG_HTML, 10).unwrap();
    let urls: Vec<&str> = hits.iter().map(|h| h.url.as_str()).collect();
    assert_eq!(urls, ["https://example.com/one", "https://example.org/two?q=1", "https://example.net/three"]);
    assert_eq!(hits[0].title, "First result");
    assert_eq!(hits[0].snippet, "The first snippet.");
    assert_eq!(parse_ddg(DDG_HTML, 1).unwrap().len(), 1);

    let lite = parse_ddg(DDG_LITE, 10).unwrap();
    assert_eq!(lite.len(), 2);
    assert_eq!(lite[0].url, "https://example.com/lite");
    assert_eq!(lite[0].snippet, "Lite snippet one.");
    assert_eq!(lite[1].title, "Lite two");

    assert!(parse_ddg("<div class=\"anomaly-modal\">x</div>", 5).is_err());
    assert!(parse_ddg("<html><body>No results.</body></html>", 5).unwrap().is_empty());
}

#[test]
fn converts_fixture_html() {
    let (title, md) = html_to_markdown(ARTICLE, Some("https://example.com/notes"));
    assert!(title.is_some());
    assert!(md.contains("Tending a Rust Garden") || md.contains("Compilers are patient"), "{md}");
    assert!(md.contains("Water daily") && md.contains("Prune weekly"), "{md}");
    assert!(!md.contains("tracking"));
}

#[tokio::test]
async fn search_parses_and_caches() {
    let srv = spawn_server().await;
    let env = env_with(|c| {
        c.fetch_allow_loopback = true;
        c.search_endpoint = Some(format!("http://{}/ddg", srv.addr));
    });
    let first = env.call("web_search", json!({ "query": "rust gardens", "max_results": 2 })).await.unwrap();
    assert_eq!(first["provider"], "ddg");
    assert_eq!(first["cached"], false);
    assert_eq!(first["results"].as_array().unwrap().len(), 2);
    assert_eq!(first["results"][0]["url"], "https://example.com/one");

    let second = env.call("web_search", json!({ "query": "rust gardens", "max_results": 2 })).await.unwrap();
    assert_eq!(second["cached"], true);
    assert_eq!(second["results"], first["results"]);
    assert!(second["fetched_at"].is_string());
    assert_eq!(srv.search_hits.load(Ordering::SeqCst), 1, "the second answer came from the cache");

    let err = env.call("web_search", json!({ "query": "   " })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
}

#[tokio::test]
async fn search_reports_bot_challenges_and_bad_providers() {
    let srv = spawn_server().await;
    let env = env_with(|c| {
        c.fetch_allow_loopback = true;
        c.search_endpoint = Some(format!("http://{}/ddg-challenge", srv.addr));
    });
    let err = env.call("web_search", json!({ "query": "anything" })).await.unwrap_err();
    assert!(err.to_string().contains("bot challenge"), "{err}");

    let env = env_with(|c| c.search_provider = "altavista".into());
    let err = env.call("web_search", json!({ "query": "x" })).await.unwrap_err();
    assert!(err.to_string().contains("unknown search provider"), "{err}");

    // A search endpoint on a private host is refused like any fetch.
    let env = env_with(|c| c.search_endpoint = Some("http://10.0.0.1/html/".into()));
    let err = env.call("web_search", json!({ "query": "x" })).await.unwrap_err();
    assert_eq!(reason(&err), "ssrf_blocked");
}

#[tokio::test]
async fn credentials_in_the_url_are_refused_before_any_request() {
    let srv = spawn_server().await;
    let env = env_with(|c| c.fetch_allow_loopback = true);
    let err = env.fetch(&format!("http://user:pw@{}/article", srv.addr)).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument", "{err}");
    assert!(err.to_string().contains("credentials in the URL"), "{err}");
}

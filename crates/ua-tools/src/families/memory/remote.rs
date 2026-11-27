//! HTTP-backed memory embedders (`ollama` and `openai_compat`) guarded by
//! `ua_ingress::Outbound`.
//!
//! Privacy and egress invariants (`docs/memory.md` §2):
//! - The endpoint host is resolved ONCE (`ua_ingress::resolve_endpoint`).
//! - If ANY resolved IP is non-loopback, the endpoint is **remote**.
//! - A remote endpoint is refused unless the calling organization has
//!   `orgs.allow_remote_embedder = 1`.
//! - The HTTP client is built with `Outbound::pinned_to_addrs` pinned to the
//!   exact checked addresses and origin, with `redirect::Policy::none()`
//!   (`max_redirects = 0`) and `no_proxy()`, so DNS rebinding, redirects, and
//!   `HTTP(S)_PROXY` can never move a request off the checked address.
//! - API keys for `openai_compat` come exclusively from `UA_EMBED_API_KEY`
//!   (`Config::embed_api_key`) and are attached via `Request::secret_header`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use ua_core::Config;
use ua_ingress::policy::{EMBEDDER_LOCAL, EMBEDDER_REMOTE};
use ua_ingress::{
    Lookup, Outbound, Request, ResolvedEndpoint, Url, resolve_endpoint, resolve_endpoint_with_lookup,
};
use ua_memory::{EmbedError, Embedder, HttpEmbedderRequest};

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
const AUTO_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        return handle.block_on(fut);
    }
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let rt = RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("build embedder runtime")
    });
    rt.block_on(fut)
}

/// Resolve `raw_url` once, enforce the loopback/remote privacy gate, and build
/// an `Outbound` client pinned to the exact resolved addresses and origin.
pub async fn build_guarded_client(
    raw_url: &str,
    allow_remote: bool,
    lookup: Option<Lookup>,
) -> Result<(Url, ResolvedEndpoint, Outbound), String> {
    let url = Url::parse(raw_url).map_err(|e| format!("invalid embedder URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("embedder URL scheme {:?} is not http or https", url.scheme()));
    }
    let resolved = match lookup {
        Some(l) => resolve_endpoint_with_lookup(&url, RESOLVE_TIMEOUT, l).await,
        None => resolve_endpoint(&url, RESOLVE_TIMEOUT).await,
    }
    .map_err(|e| e.to_string())?;

    if resolved.is_remote && !allow_remote {
        return Err(format!(
            "embedder host {:?} resolves to a non-loopback address and allow_remote_embedder is off",
            resolved.host
        ));
    }
    let policy = if resolved.is_remote { EMBEDDER_REMOTE } else { EMBEDDER_LOCAL };
    let client =
        Outbound::pinned_to_addrs(policy, &url, resolved.addrs.clone()).map_err(|e| e.to_string())?;
    Ok((url, resolved, client))
}

// ── Ollama embedder ────────────────────────────────────────────────────────

pub struct OllamaEmbedder {
    base_url: Url,
    model: String,
    revision: String,
    client: Outbound,
}

#[derive(Deserialize)]
struct OllamaEmbedResponse {
    embeddings: Vec<Vec<f32>>,
}

#[derive(Deserialize)]
struct OllamaShowResponse {
    #[serde(default)]
    digest: Option<String>,
    #[serde(default)]
    modified_at: Option<String>,
    #[serde(default)]
    details: Option<OllamaShowDetails>,
}

#[derive(Deserialize)]
struct OllamaShowDetails {
    #[serde(default)]
    quantization_level: Option<String>,
}

fn ollama_revision_cache() -> &'static Mutex<HashMap<(String, String), String>> {
    static CACHE: OnceLock<Mutex<HashMap<(String, String), String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached_ollama_revision(origin: &str, model: &str) -> Option<String> {
    ollama_revision_cache().lock().ok()?.get(&(origin.to_string(), model.to_string())).cloned()
}

fn store_ollama_revision(origin: &str, model: &str, rev: &str) {
    if let Ok(mut map) = ollama_revision_cache().lock() {
        map.insert((origin.to_string(), model.to_string()), rev.to_string());
    }
}

fn ollama_endpoint(base: &Url, suffix: &str) -> Result<Url, EmbedError> {
    let mut u = base.clone();
    let trimmed = u.path().trim_end_matches('/');
    u.set_path(&format!("{trimmed}{suffix}"));
    Ok(u)
}

async fn probe_ollama_model(base: &Url, client: &Outbound, model: &str, timeout: Duration) -> Option<String> {
    let url = ollama_endpoint(base, "/api/show").ok()?;
    let req = Request::post(url).json(&json!({ "model": model })).ok()?;
    let resp = tokio::time::timeout(timeout, client.send(req)).await.ok()?.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let parsed: OllamaShowResponse = resp.json().await.ok()?;
    let rev = parsed
        .digest
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            parsed
                .details
                .as_ref()
                .and_then(|d| d.quantization_level.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .or_else(|| parsed.modified_at.as_deref().map(str::trim).filter(|s| !s.is_empty()))
        .unwrap_or("present")
        .to_string();
    Some(rev)
}

/// Build a guarded Ollama embedder using an optional custom DNS lookup (for tests).
pub async fn build_ollama_embedder(
    base_url: &str,
    model: &str,
    allow_remote: bool,
    require_probe: bool,
    lookup: Option<Lookup>,
) -> Result<Arc<dyn Embedder>, String> {
    let model = model.trim();
    if model.is_empty() {
        return Err("memory.ollama_model is empty".into());
    }
    let (url, _resolved, client) = build_guarded_client(base_url, allow_remote, lookup).await?;
    let origin = url.origin().ascii_serialization();
    let probe_timeout = if require_probe { AUTO_PROBE_TIMEOUT } else { Duration::from_secs(3) };
    let revision = match probe_ollama_model(&url, &client, model, probe_timeout).await {
        Some(rev) => {
            store_ollama_revision(&origin, model, &rev);
            rev
        }
        None if require_probe => {
            return Err(format!("loopback Ollama at {origin} does not serve model {model:?}"));
        }
        None => match cached_ollama_revision(&origin, model) {
            Some(last_good) => last_good,
            None => {
                return Err(format!(
                    "Ollama at {origin} is unreachable or does not serve model {model:?}; \
                     refusing to embed without a pinned revision"
                ));
            }
        },
    };
    Ok(Arc::new(OllamaEmbedder { base_url: url, model: model.to_string(), revision, client }))
}

impl Embedder for OllamaEmbedder {
    fn model(&self) -> &str {
        &self.model
    }

    fn backend(&self) -> &str {
        "ollama"
    }

    fn revision(&self) -> &str {
        &self.revision
    }

    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let url = ollama_endpoint(&self.base_url, "/api/embed")?;
        let req = Request::post(url)
            .json(&json!({ "model": self.model, "input": texts }))
            .map_err(|e| EmbedError::runtime(e.to_string()))?;
        let resp = block_on(self.client.send(req)).map_err(|e| EmbedError {
            category: "model_acquisition",
            message: format!("ollama embedder unreachable: {e}"),
        })?;
        let status = resp.status();
        if !status.is_success() {
            return Err(EmbedError::runtime(format!("ollama embedder returned HTTP {}", status.as_u16())));
        }
        let body: OllamaEmbedResponse =
            block_on(resp.json()).map_err(|e| EmbedError::runtime(e.to_string()))?;
        if body.embeddings.len() != texts.len() {
            return Err(EmbedError::runtime(format!(
                "ollama embedder returned {} vectors for {} texts",
                body.embeddings.len(),
                texts.len()
            )));
        }
        Ok(body.embeddings)
    }
}

// ── OpenAI-compatible embedder ─────────────────────────────────────────────

pub struct OpenAiCompatEmbedder {
    endpoint_url: Url,
    model: String,
    revision: String,
    api_key: Option<SecretString>,
    client: Outbound,
}

#[derive(Deserialize)]
struct OpenAiEmbedResponse {
    data: Vec<OpenAiEmbedItem>,
}

#[derive(Deserialize)]
struct OpenAiEmbedItem {
    index: usize,
    embedding: Vec<f32>,
}

fn openai_endpoint(base: &Url) -> Url {
    let mut u = base.clone();
    let trimmed = u.path().trim_end_matches('/');
    if trimmed.ends_with("/embeddings") {
        // Caller supplied the full `/v1/embeddings` path.
    } else if trimmed.ends_with("/v1") {
        u.set_path(&format!("{trimmed}/embeddings"));
    } else {
        u.set_path(&format!("{trimmed}/v1/embeddings"));
    }
    u
}

/// Build a guarded OpenAI-compatible `/v1/embeddings` embedder.
pub async fn build_openai_compat_embedder(
    base_url: &str,
    model: &str,
    api_key: Option<SecretString>,
    allow_remote: bool,
    lookup: Option<Lookup>,
) -> Result<Arc<dyn Embedder>, String> {
    let model = model.trim();
    if model.is_empty() {
        return Err("embedder model name is empty".into());
    }
    let (url, resolved, client) = build_guarded_client(base_url, allow_remote, lookup).await?;
    if resolved.is_remote && api_key.is_some() && url.scheme() != "https" {
        return Err(
            "refusing to send UA_EMBED_API_KEY over plain http to a remote openai_compat endpoint; use https"
                .into(),
        );
    }
    let endpoint_url = openai_endpoint(&url);
    let revision = ua_memory::openai_compat_revision(base_url);
    Ok(Arc::new(OpenAiCompatEmbedder { endpoint_url, model: model.to_string(), revision, api_key, client }))
}

impl Embedder for OpenAiCompatEmbedder {
    fn model(&self) -> &str {
        &self.model
    }

    fn backend(&self) -> &str {
        "openai_compat"
    }

    fn revision(&self) -> &str {
        &self.revision
    }

    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let mut req = Request::post(self.endpoint_url.clone())
            .json(&json!({ "model": self.model, "input": texts }))
            .map_err(|e| EmbedError::runtime(e.to_string()))?;
        if let Some(key) = &self.api_key {
            req = req
                .secret_header("authorization", &format!("Bearer {}", key.expose_secret()))
                .map_err(|e| EmbedError::runtime(e.to_string()))?;
        }
        let resp = block_on(self.client.send(req)).map_err(|e| EmbedError {
            category: "model_acquisition",
            message: format!("openai_compat embedder unreachable: {e}"),
        })?;
        let status = resp.status();
        if matches!(status.as_u16(), 401 | 403) {
            return Err(EmbedError {
                category: "model_acquisition",
                message: format!("openai_compat embedder authentication refused (HTTP {})", status.as_u16()),
            });
        }
        if !status.is_success() {
            return Err(EmbedError::runtime(format!(
                "openai_compat embedder returned HTTP {}",
                status.as_u16()
            )));
        }
        let mut body: OpenAiEmbedResponse =
            block_on(resp.json()).map_err(|e| EmbedError::runtime(e.to_string()))?;
        if body.data.len() != texts.len() {
            return Err(EmbedError::runtime(format!(
                "openai_compat embedder returned {} vectors for {} texts",
                body.data.len(),
                texts.len()
            )));
        }
        body.data.sort_by_key(|item| item.index);
        Ok(body.data.into_iter().map(|item| item.embedding).collect())
    }
}

// ── Factory registration ───────────────────────────────────────────────────

fn resolve_http_embedder(cfg: &Config, req: HttpEmbedderRequest) -> Option<Arc<dyn Embedder>> {
    match req {
        HttpEmbedderRequest::AutoLoopbackOllama => block_on(build_ollama_embedder(
            &cfg.memory.ollama_url,
            &cfg.memory.ollama_model,
            false, // auto mode NEVER uses a remote endpoint
            true,  // must actually serve ollama_model
            None,
        ))
        .ok(),
        HttpEmbedderRequest::ExplicitOllama { allow_remote } => {
            match block_on(build_ollama_embedder(
                &cfg.memory.ollama_url,
                &cfg.memory.ollama_model,
                allow_remote,
                false,
                None,
            )) {
                Ok(e) => Some(e),
                Err(why) => {
                    tracing::debug!(error = %why, "ollama embedder unavailable");
                    None
                }
            }
        }
        HttpEmbedderRequest::ExplicitOpenAiCompat { allow_remote } => {
            let url = cfg.memory.openai_compat_url.as_deref()?;
            let model = cfg.memory.openai_compat_model.as_deref().unwrap_or(&cfg.embed_model);
            match block_on(build_openai_compat_embedder(url, model, cfg.embed_api_key(), allow_remote, None))
            {
                Ok(e) => Some(e),
                Err(why) => {
                    tracing::debug!(error = %why, "openai_compat embedder unavailable");
                    None
                }
            }
        }
    }
}

/// Register the `ua_ingress::Outbound`-backed HTTP embedder factory in
/// `ua_memory` once per process.
pub fn install_http_embedder_factory() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        ua_memory::register_http_embedder_factory(Arc::new(resolve_http_embedder));
    });
}

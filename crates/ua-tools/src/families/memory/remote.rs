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

use std::collections::HashSet;
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

use super::doctor::{cached_ollama_revision, record_host_remote, store_ollama_revision};

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
const AUTO_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_CACHED_HOSTS: usize = 1024;

fn attempted_hosts() -> &'static Mutex<HashSet<String>> {
    static SET: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(HashSet::new()))
}

fn record_host_attempt(host: &str) {
    if let Ok(mut set) = attempted_hosts().lock() {
        let key = host.to_ascii_lowercase();
        if set.len() >= MAX_CACHED_HOSTS && !set.contains(&key) {
            set.clear();
        }
        set.insert(key);
    }
}

/// Whether `build_guarded_client` ever attempted DNS resolution for `host` in
/// this process (exposed for zero-network `system_doctor` regression tests).
#[doc(hidden)]
pub fn host_lookup_attempted(host: &str) -> bool {
    attempted_hosts().lock().ok().is_some_and(|set| set.contains(&host.to_ascii_lowercase()))
}

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
    let use_real_dns = lookup.is_none();
    if use_real_dns && let Some(host) = url.host_str() {
        record_host_attempt(host);
    }
    let resolved = match lookup {
        Some(l) => resolve_endpoint_with_lookup(&url, RESOLVE_TIMEOUT, l).await,
        None => resolve_endpoint(&url, RESOLVE_TIMEOUT).await,
    }
    .map_err(|e| e.to_string())?;
    if use_real_dns {
        record_host_remote(&resolved.host, resolved.is_remote);
    }

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
}

#[derive(Deserialize)]
struct OllamaTagsResponse {
    #[serde(default)]
    models: Vec<OllamaTagEntry>,
}

#[derive(Deserialize)]
struct OllamaTagEntry {
    #[serde(default)]
    name: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    digest: Option<String>,
}

fn normalize_ollama_model_tag(model: &str) -> String {
    let trimmed = model.trim();
    // Only treat `:` after the last `/` as a tag separator so registry ports
    // like `registry.local:5000/ns/embed` still normalize to `:latest`.
    let after_slash = trimmed.rsplit_once('/').map_or(trimmed, |(_, tail)| tail);
    if after_slash.contains(':') { trimmed.to_string() } else { format!("{trimmed}:latest") }
}

fn ollama_endpoint(base: &Url, suffix: &str) -> Result<Url, EmbedError> {
    let mut u = base.clone();
    let trimmed = u.path().trim_end_matches('/');
    u.set_path(&format!("{trimmed}{suffix}"));
    Ok(u)
}

async fn probe_ollama_tags_digest(
    base: &Url,
    client: &Outbound,
    model: &str,
    timeout: Duration,
) -> Option<String> {
    if timeout.is_zero() {
        return None;
    }
    let url = ollama_endpoint(base, "/api/tags").ok()?;
    let req = Request::get(url);
    let resp = tokio::time::timeout(timeout, client.send(req)).await.ok()?.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let parsed: OllamaTagsResponse = resp.json().await.ok()?;
    let target = model.trim();
    let target_norm = normalize_ollama_model_tag(target);
    for entry in parsed.models {
        let name_matches =
            entry.name.trim() == target || normalize_ollama_model_tag(&entry.name) == target_norm;
        let model_matches = entry
            .model
            .as_deref()
            .is_some_and(|m| m.trim() == target || normalize_ollama_model_tag(m) == target_norm);
        if (name_matches || model_matches)
            && let Some(digest) = entry.digest.as_deref().map(str::trim).filter(|s| !s.is_empty())
        {
            return Some(digest.to_string());
        }
    }
    None
}

enum OllamaProbe {
    /// Confirmed model presence AND obtained a real content-addressed digest.
    Digest(String),
    /// `/api/show` confirmed the model is served, but neither `/api/show` nor
    /// `/api/tags` yielded a digest (e.g. transient `/api/tags` failure). Never
    /// overwrites a cached digest with unstable metadata such as `quantization_level`.
    ServedWithoutDigest,
    /// Endpoint unreachable or `/api/show` reported the model is not served.
    Unavailable,
}

async fn probe_ollama_model(base: &Url, client: &Outbound, model: &str, timeout: Duration) -> OllamaProbe {
    let deadline = tokio::time::Instant::now() + timeout;
    let Ok(url) = ollama_endpoint(base, "/api/show") else {
        return OllamaProbe::Unavailable;
    };
    let Ok(req) = Request::post(url).json(&json!({ "model": model })) else {
        return OllamaProbe::Unavailable;
    };
    let Ok(Ok(resp)) = tokio::time::timeout(timeout, client.send(req)).await else {
        return OllamaProbe::Unavailable;
    };
    if !resp.status().is_success() {
        return OllamaProbe::Unavailable;
    }
    let Ok(parsed) = resp.json::<OllamaShowResponse>().await else {
        return OllamaProbe::Unavailable;
    };
    if let Some(digest) = parsed.digest.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        return OllamaProbe::Digest(digest.to_string());
    }
    // Real Ollama `/api/show` omits `digest`; query `/api/tags` on the same
    // pinned client so only a real content-addressed digest establishes or
    // updates the vector identity.
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if let Some(digest) = probe_ollama_tags_digest(base, client, model, remaining).await {
        return OllamaProbe::Digest(digest);
    }
    OllamaProbe::ServedWithoutDigest
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
        OllamaProbe::Digest(rev) => {
            store_ollama_revision(&origin, model, &rev);
            rev
        }
        OllamaProbe::ServedWithoutDigest => match cached_ollama_revision(&origin, model) {
            Some(last_good) => last_good,
            None => {
                return Err(format!(
                    "Ollama at {origin} serves {model:?} but /api/show and /api/tags returned no digest; \
                     refusing to embed without a pinned revision"
                ));
            }
        },
        OllamaProbe::Unavailable if require_probe => {
            return Err(format!("loopback Ollama at {origin} does not serve model {model:?}"));
        }
        OllamaProbe::Unavailable => match cached_ollama_revision(&origin, model) {
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
        if matches!(status.as_u16(), 401 | 403) {
            return Err(EmbedError::auth_refused(format!(
                "ollama embedder authentication refused (HTTP {})",
                status.as_u16()
            )));
        }
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
            return Err(EmbedError::auth_refused(format!(
                "openai_compat embedder authentication refused (HTTP {})",
                status.as_u16()
            )));
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

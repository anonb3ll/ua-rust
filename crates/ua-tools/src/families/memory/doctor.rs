//! Zero-network embedder readiness inspection for `system_doctor`.
//!
//! This module is intentionally isolated from `remote.rs` and kept under a
//! strict import allowlist enforced by
//! `crates/ua-tools/tests/memory_embedder.rs`: it may never import HTTP
//! clients, DNS resolvers, async runtimes, or sibling `remote.rs` helpers.
//! `remote.rs` populates the two in-memory caches below when real embedder
//! calls resolve a host or read an Ollama digest; `system_doctor` reads only
//! those in-memory caches and local configuration.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

use ua_core::Config;
use ua_ingress::Url;
use ua_ingress::addr;
use ua_memory::{local_embedder, openai_compat_revision, registered_embedder, vector_identity};
use url::Host;

const MAX_CACHED_HOSTS: usize = 1024;

fn host_remote_cache() -> &'static Mutex<HashMap<String, bool>> {
    static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn record_host_remote(host: &str, is_remote: bool) {
    if let Ok(mut map) = host_remote_cache().lock() {
        let key = host.to_ascii_lowercase();
        if map.len() >= MAX_CACHED_HOSTS && !map.contains_key(&key) {
            map.clear();
        }
        map.insert(key, is_remote);
    }
}

fn cached_host_remote(host: &str) -> Option<bool> {
    host_remote_cache().lock().ok()?.get(&host.to_ascii_lowercase()).copied()
}

fn ollama_revision_cache() -> &'static Mutex<HashMap<(String, String), String>> {
    static CACHE: OnceLock<Mutex<HashMap<(String, String), String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn cached_ollama_revision(origin: &str, model: &str) -> Option<String> {
    ollama_revision_cache().lock().ok()?.get(&(origin.to_string(), model.to_string())).cloned()
}

pub(super) fn store_ollama_revision(origin: &str, model: &str, rev: &str) {
    if let Ok(mut map) = ollama_revision_cache().lock() {
        map.insert((origin.to_string(), model.to_string()), rev.to_string());
    }
}

/// Readiness classification for `system_doctor`, computed strictly without DNS
/// lookups or HTTP probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorEmbedderAvailability {
    /// Active vector identity is known locally (registered embedder, local
    /// ONNX model on disk, `openai_compat` URL permitted for this org, or
    /// Ollama with a previously cached revision).
    Available,
    /// Ollama is configured and permitted for this org, but no embedder call
    /// has probed it in this process yet (`system_doctor` never touches the
    /// network).
    Unprobed,
    /// Unavailable for this org (off, missing local model, remote endpoint
    /// blocked by `allow_remote_embedder`, cleartext API key over remote HTTP,
    /// or invalid URL).
    Unavailable,
}

/// Zero-network embedder snapshot for `system_doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorEmbedderState {
    pub availability: DoctorEmbedderAvailability,
    pub active_identity: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalHostClass {
    Loopback,
    Remote,
    UnresolvedDomain,
    Refused,
}

fn classify_literal_ip(ip: IpAddr) -> LocalHostClass {
    if addr::is_loopback(ip) {
        LocalHostClass::Loopback
    } else if !addr::is_cloud_metadata(ip) && (addr::is_public(ip) || addr::is_private_network(ip)) {
        LocalHostClass::Remote
    } else {
        LocalHostClass::Refused
    }
}

fn classify_url_host_without_dns(url: &Url) -> LocalHostClass {
    match url.host() {
        Some(Host::Ipv4(v4)) => classify_literal_ip(IpAddr::V4(v4)),
        Some(Host::Ipv6(v6)) => classify_literal_ip(IpAddr::V6(v6)),
        Some(Host::Domain(host)) => match cached_host_remote(host) {
            Some(false) => LocalHostClass::Loopback,
            Some(true) => LocalHostClass::Remote,
            None if host.eq_ignore_ascii_case("localhost") => LocalHostClass::Loopback,
            None => LocalHostClass::UnresolvedDomain,
        },
        None => LocalHostClass::Refused,
    }
}

fn parse_valid_http_url(raw_url: &str) -> Option<Url> {
    let url = Url::parse(raw_url).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    url.host()?;
    Some(url)
}

/// Inspect embedder readiness and active canonical identity for `system_doctor`
/// without performing any DNS lookup, HTTP probe, or model download.
pub fn inspect_embedder_for_doctor(cfg: &Config, allow_remote: bool) -> DoctorEmbedderState {
    if let Some(e) = registered_embedder(cfg, allow_remote) {
        return if e.available() {
            DoctorEmbedderState {
                availability: DoctorEmbedderAvailability::Available,
                active_identity: Some(e.identity()),
            }
        } else {
            DoctorEmbedderState {
                availability: DoctorEmbedderAvailability::Unavailable,
                active_identity: None,
            }
        };
    }

    match cfg.memory.embedder.trim().to_ascii_lowercase().as_str() {
        "off" => DoctorEmbedderState {
            availability: DoctorEmbedderAvailability::Unavailable,
            active_identity: None,
        },
        "local" => match local_embedder(cfg) {
            Some(e) if e.available() => DoctorEmbedderState {
                availability: DoctorEmbedderAvailability::Available,
                active_identity: Some(e.identity()),
            },
            _ => DoctorEmbedderState {
                availability: DoctorEmbedderAvailability::Unavailable,
                active_identity: None,
            },
        },
        "ollama" => {
            let model = cfg.memory.ollama_model.trim();
            let Some(url) = parse_valid_http_url(&cfg.memory.ollama_url).filter(|_| !model.is_empty()) else {
                return DoctorEmbedderState {
                    availability: DoctorEmbedderAvailability::Unavailable,
                    active_identity: None,
                };
            };
            let class = classify_url_host_without_dns(&url);
            let permitted = match class {
                LocalHostClass::Loopback => true,
                LocalHostClass::Remote | LocalHostClass::UnresolvedDomain => allow_remote,
                LocalHostClass::Refused => false,
            };
            if !permitted {
                return DoctorEmbedderState {
                    availability: DoctorEmbedderAvailability::Unavailable,
                    active_identity: None,
                };
            }
            let origin = url.origin().ascii_serialization();
            match cached_ollama_revision(&origin, model) {
                Some(rev) => DoctorEmbedderState {
                    availability: DoctorEmbedderAvailability::Available,
                    active_identity: Some(vector_identity("ollama", model, &rev)),
                },
                None => DoctorEmbedderState {
                    availability: DoctorEmbedderAvailability::Unprobed,
                    active_identity: None,
                },
            }
        }
        "openai_compat" => {
            let Some(raw_url) = cfg.memory.openai_compat_url.as_deref() else {
                return DoctorEmbedderState {
                    availability: DoctorEmbedderAvailability::Unavailable,
                    active_identity: None,
                };
            };
            let model = cfg.memory.openai_compat_model.as_deref().unwrap_or(&cfg.embed_model).trim();
            let Some(url) = parse_valid_http_url(raw_url).filter(|_| !model.is_empty()) else {
                return DoctorEmbedderState {
                    availability: DoctorEmbedderAvailability::Unavailable,
                    active_identity: None,
                };
            };
            let class = classify_url_host_without_dns(&url);
            let permitted = match class {
                LocalHostClass::Loopback => true,
                LocalHostClass::Remote | LocalHostClass::UnresolvedDomain => allow_remote,
                LocalHostClass::Refused => false,
            };
            if !permitted {
                return DoctorEmbedderState {
                    availability: DoctorEmbedderAvailability::Unavailable,
                    active_identity: None,
                };
            }
            if !matches!(class, LocalHostClass::Loopback)
                && cfg.embed_api_key().is_some()
                && url.scheme() != "https"
            {
                return DoctorEmbedderState {
                    availability: DoctorEmbedderAvailability::Unavailable,
                    active_identity: None,
                };
            }
            let rev = openai_compat_revision(raw_url);
            DoctorEmbedderState {
                availability: DoctorEmbedderAvailability::Available,
                active_identity: Some(vector_identity("openai_compat", model, &rev)),
            }
        }
        // `auto`: local ONNX on disk if present, else a previously probed loopback Ollama.
        _ => {
            if let Some(e) = local_embedder(cfg)
                && e.available()
            {
                return DoctorEmbedderState {
                    availability: DoctorEmbedderAvailability::Available,
                    active_identity: Some(e.identity()),
                };
            }
            let model = cfg.memory.ollama_model.trim();
            if let Some(url) = parse_valid_http_url(&cfg.memory.ollama_url).filter(|_| !model.is_empty())
                && classify_url_host_without_dns(&url) == LocalHostClass::Loopback
                && let Some(rev) = cached_ollama_revision(&url.origin().ascii_serialization(), model)
            {
                return DoctorEmbedderState {
                    availability: DoctorEmbedderAvailability::Available,
                    active_identity: Some(vector_identity("ollama", model, &rev)),
                };
            }
            DoctorEmbedderState {
                availability: DoctorEmbedderAvailability::Unavailable,
                active_identity: None,
            }
        }
    }
}

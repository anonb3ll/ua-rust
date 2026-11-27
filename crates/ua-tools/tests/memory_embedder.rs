//! Default embedder configuration, per-org remote egress gating,
//! DNS-rebinding / redirect / proxy defenses, offline model fetch verification,
//! and `system_doctor` readiness (docs/memory.md §2, acceptance items 6 & 7).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, identity::Transport};
use ua_ingress::policy::MODEL_DOWNLOAD;
use ua_ingress::{Lookup, Outbound};
use ua_tools::families::memory::models::{PinnedFile, PinnedModel};
use ua_tools::families::memory::models_fetch::{fetch_pinned_with_client, local_model_status};
use ua_tools::families::memory::remote::{
    build_guarded_client, build_ollama_embedder, build_openai_compat_embedder,
};
use ua_tools::{Hub, builtin_registry};

fn agent(label: &str, org: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some(format!("{label}-s")),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn human(org: &str) -> Caller {
    Caller {
        label: "operator".into(),
        kind: ActorKind::Human,
        profile: Profile::Operator,
        enforce_profile: false,
        session_key: Some("op-s".into()),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

async fn bind_axum(app: Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, handle)
}

/// `[memory]` TOML parsing, validation, and refusal of secrets in TOML.
#[test]
fn memory_config_parses_and_refuses_secrets_or_unknown_mode() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.toml");
    std::fs::write(
        &good,
        r#"
embed_model = "BAAI/bge-small-en-v1.5"
[memory]
embedder = "ollama"
ollama_model = "nomic-embed-text"
ollama_url = "http://127.0.0.1:11434/"
openai_compat_url = "https://embeddings.example.com/"
"#,
    )
    .unwrap();
    let cfg = Config::load_from(&good).unwrap();
    assert_eq!(cfg.memory.embedder, "ollama");
    assert_eq!(cfg.memory.ollama_model, "nomic-embed-text");
    assert_eq!(cfg.memory.ollama_url, "http://127.0.0.1:11434");
    assert_eq!(cfg.memory.openai_compat_url.as_deref(), Some("https://embeddings.example.com"));

    // Invalid embedder mode is refused.
    let bad_mode = dir.path().join("bad_mode.toml");
    std::fs::write(&bad_mode, "[memory]\nembedder = \"magic\"\n").unwrap();
    let err = Config::load_from(&bad_mode).unwrap_err().to_string();
    assert!(err.contains("memory.embedder"), "{err}");

    // Putting an API key in `[memory]` TOML is refused (`deny_unknown_fields`).
    let secret_in_toml = dir.path().join("secret.toml");
    std::fs::write(&secret_in_toml, "[memory]\napi_key = \"sk-test\"\n").unwrap();
    assert!(Config::load_from(&secret_in_toml).is_err());

    // Even naming the internal Rust field (`embed_api_key_value`) in TOML MUST
    // NOT populate the secret (`#[serde(skip)]`, never `skip_serializing` — catches M5).
    let raw_field_toml = dir.path().join("raw_field.toml");
    std::fs::write(&raw_field_toml, "embed_api_key_value = \"sk-leaked-from-toml\"\n").unwrap();
    let cfg_raw = Config::load_from(&raw_field_toml).unwrap();
    assert!(cfg_raw.embed_api_key_value.is_none(), "embed_api_key_value must never deserialize from TOML");
    assert!(cfg_raw.embed_api_key().is_none(), "TOML value must never surface via embed_api_key()");
}

/// Acceptance item 6: with no local model present, `system_doctor` reports
/// `DEGRADED` (when `local` is requested or `embeddings` is compiled in) and
/// save, search, and `system_doctor` never download anything.
#[tokio::test]
async fn absent_local_model_never_downloads_and_doctor_reports_degraded() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.memory.embedder = "local".into();
    cfg.human_identities = vec!["operator".into()];
    let hub = Hub::in_memory(cfg).unwrap();
    let reg = builtin_registry();
    let b1 = agent("builder-1", DEFAULT_ORG);
    let op = human(DEFAULT_ORG);

    // Save and search work lexically without creating or downloading any model files.
    let saved = reg
        .call(&hub, &b1, "memory_save", json!({ "title": "Airgap", "content": "Offline cache note." }))
        .await
        .unwrap();
    assert_eq!(saved["created"], true);
    let searched = reg.call(&hub, &b1, "memory_search", json!({ "query": "Offline" })).await.unwrap();
    assert_eq!(searched["retrieval"]["mode"], "lexical_fallback");
    assert_eq!(searched["results"][0]["id"], saved["id"]);

    // `system_doctor` reports `semantic_search` as DEGRADED and downloads nothing.
    let doctor = reg.call(&hub, &op, "system_doctor", json!({})).await.unwrap();
    let sem =
        doctor["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "semantic_search").unwrap();
    assert_eq!(sem["status"], "DEGRADED", "{sem}");
    assert!(!dir.path().join("models").exists(), "save/search/doctor must never create or download models");
}

/// Acceptance item 6: `auto` picks a loopback Ollama serving `ollama_model`,
/// and `openai_compat` sends `Authorization: Bearer <UA_EMBED_API_KEY>`.
#[tokio::test]
async fn loopback_ollama_auto_and_openai_compat_work_through_registry() {
    let auth_hits = Arc::new(AtomicUsize::new(0));
    let auth_hits_cl = auth_hits.clone();

    let app = Router::new()
        .route("/api/show", post(|| async { Json(json!({ "digest": "sha256:ollama-test-digest" })) }))
        .route(
            "/api/embed",
            post(|Json(body): Json<Value>| async move {
                let inputs = body["input"].as_array().unwrap();
                let vecs: Vec<Vec<f32>> = inputs
                    .iter()
                    .map(|v| {
                        let s = v.as_str().unwrap_or("").to_lowercase();
                        if s.contains("car") || s.contains("automobile") {
                            vec![1.0, 0.0, 0.0]
                        } else {
                            vec![0.0, 1.0, 0.0]
                        }
                    })
                    .collect();
                Json(json!({ "embeddings": vecs }))
            }),
        )
        .route(
            "/v1/embeddings",
            post(move |headers: HeaderMap, Json(body): Json<Value>| {
                let hits = auth_hits_cl.clone();
                async move {
                    if headers.get("authorization").and_then(|v| v.to_str().ok())
                        == Some("Bearer test-secret-key")
                    {
                        hits.fetch_add(1, Ordering::SeqCst);
                    } else {
                        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" })))
                            .into_response();
                    }
                    let inputs = body["input"].as_array().unwrap();
                    let data: Vec<Value> = inputs
                        .iter()
                        .enumerate()
                        .map(|(idx, v)| {
                            let s = v.as_str().unwrap_or("").to_lowercase();
                            let emb = if s.contains("quokka") || s.contains("marsupial") {
                                vec![1.0, 0.0, 0.0]
                            } else {
                                vec![0.0, 1.0, 0.0]
                            };
                            json!({ "index": idx, "embedding": emb })
                        })
                        .collect();
                    Json(json!({ "data": data })).into_response()
                }
            }),
        );
    let (addr, _srv) = bind_axum(app).await;

    // 1. `auto` mode picks loopback Ollama serving `ollama_model`.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.memory.embedder = "auto".into();
    cfg.memory.ollama_url = format!("http://{addr}");
    cfg.memory.ollama_model = "nomic-embed-text".into();
    let hub = Hub::in_memory(cfg).unwrap();
    let reg = builtin_registry();
    let b1 = agent("builder-1", DEFAULT_ORG);

    let car_id = reg
        .call(&hub, &b1, "memory_save", json!({ "title": "Garage", "content": "The car is parked." }))
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let stored_model: String = hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT model FROM memory_embeddings WHERE note_id = ?1", [&car_id], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    assert_eq!(stored_model, "ollama:nomic-embed-text@sha256:ollama-test-digest");

    let hit = reg.call(&hub, &b1, "memory_search", json!({ "query": "automobile" })).await.unwrap();
    assert_eq!(hit["retrieval"]["mode"], "hybrid", "{hit}");
    assert_eq!(hit["results"][0]["id"], car_id, "{hit}");

    // 2. `openai_compat` on loopback sends Bearer token via secret_header.
    let mut oai_cfg = Config::for_home(dir.path());
    oai_cfg.memory.embedder = "openai_compat".into();
    oai_cfg.memory.openai_compat_url = Some(format!("http://{addr}"));
    oai_cfg.memory.openai_compat_model = Some("text-embedding-3-small".into());
    oai_cfg.embed_api_key_value = Some(SecretString::from("test-secret-key".to_string()));
    let oai_hub = Hub::in_memory(oai_cfg).unwrap();
    let q_id = reg
        .call(&oai_hub, &b1, "memory_save", json!({ "title": "Island", "content": "A quokka smiled." }))
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let q_hit = reg.call(&oai_hub, &b1, "memory_search", json!({ "query": "marsupial" })).await.unwrap();
    assert_eq!(q_hit["results"][0]["id"], q_id, "{q_hit}");
    assert!(auth_hits.load(Ordering::SeqCst) >= 2, "expected authenticated save + search calls");
}

/// Acceptance item 6: an endpoint resolving to ANY non-loopback address is
/// classified remote and refused unless `orgs.allow_remote_embedder = 1`,
/// including explicit `ollama` with a remote URL and mixed DNS answers.
#[tokio::test]
async fn remote_endpoint_is_blocked_without_org_allow_remote_embedder() {
    let mixed_lookup: Lookup = Arc::new(|_| {
        Box::pin(async {
            Ok(vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 0),
            ])
        })
    });
    // Mixed [loopback, private] is remote -> refused when allow_remote = false.
    let err = build_guarded_client("http://embed.internal:11434", false, Some(mixed_lookup.clone()))
        .await
        .err()
        .expect("mixed answer must be refused when allow_remote=false");
    assert!(err.contains("allow_remote_embedder"), "{err}");

    // Same mixed answer is allowed when allow_remote = true.
    let (_url, resolved, _client) =
        build_guarded_client("http://embed.internal:11434", true, Some(mixed_lookup))
            .await
            .expect("allowed when allow_remote=true");
    assert!(resolved.is_remote);

    // Cloud metadata is ALWAYS refused even when allow_remote = true.
    let meta_lookup: Lookup = Arc::new(|_| {
        Box::pin(async { Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 0)]) })
    });
    assert!(build_guarded_client("http://meta.test:80", true, Some(meta_lookup)).await.is_err());

    // Plain `http://` to a remote `openai_compat` endpoint with an API key is REFUSED
    // so Bearer credentials never travel in cleartext.
    let remote_only_lookup: Lookup = Arc::new(|_| {
        Box::pin(async { Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)), 0)]) })
    });
    let cleartext_err = build_openai_compat_embedder(
        "http://embed.internal:8080",
        "text-embedding-3-small",
        Some(SecretString::from("sk-never-cleartext".to_string())),
        true,
        Some(remote_only_lookup.clone()),
    )
    .await
    .err()
    .expect("remote http:// with API key must be refused");
    assert!(cleartext_err.contains("plain http"), "{cleartext_err}");

    // Same remote endpoint over `https://` succeeds and binds endpoint host:port into revision.
    let https_remote = build_openai_compat_embedder(
        "https://embed.internal:8443",
        "text-embedding-3-small",
        Some(SecretString::from("sk-over-tls".to_string())),
        true,
        Some(remote_only_lookup),
    )
    .await
    .expect("https remote with allow_remote=true succeeds");
    assert_eq!(https_remote.revision(), "embed.internal:8443/v1");

    // Ollama probe failure refuses to embed when no prior good revision is cached,
    // and keeps the last good revision (no `@unpinned` churn) once one has been seen.
    let fail_probe = Arc::new(AtomicUsize::new(1));
    let fail_probe_cl = fail_probe.clone();
    let probe_app = Router::new().route(
        "/api/show",
        post(move || {
            let f = fail_probe_cl.clone();
            async move {
                if f.load(Ordering::SeqCst) == 1 {
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "down" }))).into_response()
                } else {
                    Json(json!({ "digest": "sha256:stable-ollama-rev" })).into_response()
                }
            }
        }),
    );
    let (probe_addr, _probe_srv) = bind_axum(probe_app).await;
    let probe_url = format!("http://{probe_addr}");
    assert!(
        build_ollama_embedder(&probe_url, "probe-test-model", false, false, None).await.is_err(),
        "must refuse to embed with unpinned revision when probe has never succeeded"
    );
    fail_probe.store(0, Ordering::SeqCst);
    let ok_ollama = build_ollama_embedder(&probe_url, "probe-test-model", false, false, None)
        .await
        .expect("probe succeeds");
    assert_eq!(ok_ollama.revision(), "sha256:stable-ollama-rev");
    fail_probe.store(1, Ordering::SeqCst);
    let cached_ollama = build_ollama_embedder(&probe_url, "probe-test-model", false, false, None)
        .await
        .expect("keeps last good revision on transient probe failure");
    assert_eq!(cached_ollama.revision(), "sha256:stable-ollama-rev");

    // End-to-end org gate check: remote endpoints are refused for an org with
    // `allow_remote_embedder = 0` (lexical fallback) and accepted for an org
    // with `allow_remote_embedder = 1`.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.memory.embedder = "openai_compat".into();
    cfg.memory.openai_compat_url = Some("https://10.20.30.40:8443".into());
    cfg.memory.openai_compat_model = Some("remote-embed-v1".into());
    let hub = Hub::in_memory(cfg.clone()).unwrap();
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, allow_remote_embedder, created_at) \
                 VALUES ('org-remote', 'org-remote', 'Org Remote', '[\"developer\"]', 1, '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

    // Default org (`allow_remote_embedder = 0`): gets unavailable NoopEmbedder,
    // and `system_doctor` reports DEGRADED (not LIVE).
    let default_emb = ua_tools::families::memory::embedder_for_org(hub.db(), &cfg, DEFAULT_ORG).await;
    assert!(!default_emb.available(), "org without allow_remote_embedder must stay lexical-only");
    assert_eq!(default_emb.backend(), "noop");
    let reg = builtin_registry();
    let doc_def = reg.call(&hub, &agent("builder-1", DEFAULT_ORG), "system_doctor", json!({})).await.unwrap();
    let sem_def =
        doc_def["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "semantic_search").unwrap();
    assert_eq!(sem_def["status"], "DEGRADED", "blocked remote org must show DEGRADED: {sem_def}");

    // `org-remote` (`allow_remote_embedder = 1`): gets the `openai_compat` embedder.
    let remote_emb = ua_tools::families::memory::embedder_for_org(hub.db(), &cfg, "org-remote").await;
    assert!(remote_emb.available());
    assert_eq!(remote_emb.backend(), "openai_compat");

    // Explicit `ollama` pointing at a remote IP is also blocked for default org.
    let mut cfg_ol = cfg.clone();
    cfg_ol.memory.embedder = "ollama".into();
    cfg_ol.memory.ollama_url = "http://10.20.30.40:11434".into();
    let default_ol = ua_tools::families::memory::embedder_for_org(hub.db(), &cfg_ol, DEFAULT_ORG).await;
    assert!(!default_ol.available());
    assert_eq!(default_ol.backend(), "noop");
}

/// Acceptance item 6: DNS rebinding after the check, a 302 redirect, and an
/// `HTTP_PROXY` setting each fail to move a request off the checked address.
#[tokio::test]
async fn dns_rebinding_redirect_and_http_proxy_cannot_move_request_off_checked_address() {
    // 1. DNS rebinding: resolver returns 127.0.0.1 on call #1 (the check) and
    //    returns 198.51.100.99 on any subsequent call. Because the client pins
    //    the checked addresses from call #1, call #2 MUST NEVER happen and the
    //    embed request MUST still hit the checked 127.0.0.1 server.
    let good_hits = Arc::new(AtomicUsize::new(0));
    let good_hits_cl = good_hits.clone();
    let good_app = Router::new()
        .route("/api/show", post(|| async { Json(json!({ "digest": "sha256:pinned-rev" })) }))
        .route(
            "/api/embed",
            post(move |Json(body): Json<Value>| {
                let hits = good_hits_cl.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let n = body["input"].as_array().unwrap().len();
                    Json(json!({ "embeddings": vec![vec![1.0f32, 0.0]; n] }))
                }
            }),
        );
    let (good_addr, _good_srv) = bind_axum(good_app).await;

    let dns_calls = Arc::new(AtomicUsize::new(0));
    let dns_calls_cl = dns_calls.clone();
    let rebinding_lookup: Lookup = Arc::new(move |_| {
        let n = dns_calls_cl.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if n == 0 {
                Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0)])
            } else {
                Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99)), 0)])
            }
        })
    });

    let emb = build_ollama_embedder(
        &format!("http://rebind.example.test:{}", good_addr.port()),
        "nomic-embed-text",
        false,
        true,
        Some(rebinding_lookup),
    )
    .await
    .expect("first lookup was loopback and pinned");
    let vecs = tokio::task::spawn_blocking(move || emb.embed(&["hello".into()])).await.unwrap().unwrap();
    assert_eq!(vecs.len(), 1);
    assert_eq!(dns_calls.load(Ordering::SeqCst), 1, "host must be resolved exactly once");
    assert_eq!(good_hits.load(Ordering::SeqCst), 1, "request must hit the checked address");

    // 2. Redirect: server A redirects to server B -> embedder refuses 302 and
    //    server B receives ZERO requests.
    let trap_hits = Arc::new(AtomicUsize::new(0));
    let trap_hits_cl = trap_hits.clone();
    let trap_app = Router::new().fallback(move || {
        let hits = trap_hits_cl.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            Json(json!({ "embeddings": [[1.0, 0.0]] }))
        }
    });
    let (trap_addr, _trap_srv) = bind_axum(trap_app).await;

    let redirect_target = format!("http://{trap_addr}/api/embed");
    let redir_app = Router::new()
        .route("/api/show", post(|| async { Json(json!({ "digest": "sha256:redir-rev" })) }))
        .route(
            "/api/embed",
            post(move || {
                let target = redirect_target.clone();
                async move { Redirect::temporary(&target) }
            }),
        );
    let (redir_addr, _redir_srv) = bind_axum(redir_app).await;

    let redir_emb =
        build_ollama_embedder(&format!("http://{redir_addr}"), "nomic-embed-text", false, false, None)
            .await
            .unwrap();
    let err = tokio::task::spawn_blocking(move || redir_emb.embed(&["secret note".into()]))
        .await
        .unwrap()
        .unwrap_err();
    assert!(err.message.contains("307") || err.message.contains("302"), "{err:?}");
    assert_eq!(trap_hits.load(Ordering::SeqCst), 0, "redirect target must never be contacted");

    // 3. Proxy bypass check: `ua_ingress::Outbound` always sets `no_proxy()`,
    //    so even when a proxy listener is running on loopback, requests go
    //    straight to the pinned server (verified directly in ua-ingress's
    //    dedicated subprocess test `tests/no_proxy.rs`, and confirmed here
    //    by sending to our pinned client).
    let direct_emb =
        build_ollama_embedder(&format!("http://{good_addr}"), "nomic-embed-text", false, false, None)
            .await
            .unwrap();
    let out =
        tokio::task::spawn_blocking(move || direct_emb.embed(&["check".into()])).await.unwrap().unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(good_hits.load(Ordering::SeqCst), 2);
}

/// Offline verification of `ua memory models fetch`: downloads files, verifies
/// SHA-256, skips on re-run, and refuses a tampered/corrupted payload without
/// leaving partial files behind.
#[tokio::test]
async fn model_fetch_verifies_sha256_and_rejects_corruption() {
    const PAYLOAD: &[u8] = b"fake-onnx-model-bytes-for-sha256-test";
    let expected_sha: &'static str = Box::leak(hex::encode(Sha256::digest(PAYLOAD)).into_boxed_str());
    let files: &'static [PinnedFile] = Box::leak(Box::new([PinnedFile {
        rel_path: "onnx/model.onnx",
        size_bytes: PAYLOAD.len() as u64,
        sha256: expected_sha,
    }]));
    let spec: &'static PinnedModel = Box::leak(Box::new(PinnedModel {
        canonical_id: "test/tiny-embed",
        slug: "tiny-embed",
        hf_repo: "test/tiny-embed",
        revision: "0123456789abcdef",
        aliases: &["test/tiny-embed"],
        files,
    }));

    let corrupt = Arc::new(AtomicUsize::new(0));
    let corrupt_cl = corrupt.clone();
    let app = Router::new().route(
        "/onnx/model.onnx",
        get(move || {
            let c = corrupt_cl.clone();
            async move {
                if c.load(Ordering::SeqCst) == 0 {
                    (StatusCode::OK, PAYLOAD)
                } else {
                    (StatusCode::OK, b"CORRUPTED-model-bytes-same-length!!!!".as_slice())
                }
            }
        }),
    );
    let (addr, _srv) = bind_axum(app).await;
    let client = Outbound::new(MODEL_DOWNLOAD.loopback_test_hook()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let base = format!("http://{addr}");

    // 1. Corrupt payload is rejected and leaves no installed or `.part` file.
    corrupt.store(1, Ordering::SeqCst);
    let err = fetch_pinned_with_client(dir.path(), spec, &client, Some(&base), false).await.unwrap_err();
    assert!(err.to_string().contains("SHA-256 mismatch"), "{err}");
    let installed = dir.path().join("models/tiny-embed/0123456789abcdef/onnx/model.onnx");
    assert!(!installed.exists());
    assert!(!installed.with_extension("part").exists());

    // 2. Valid payload succeeds, installs atomically, and second call is idempotent.
    corrupt.store(0, Ordering::SeqCst);
    let rep1 = fetch_pinned_with_client(dir.path(), spec, &client, Some(&base), false).await.unwrap();
    assert_eq!(rep1.downloaded, ["onnx/model.onnx"]);
    assert!(rep1.already_present.is_empty());
    assert!(installed.is_file());

    let rep2 = fetch_pinned_with_client(dir.path(), spec, &client, Some(&base), false).await.unwrap();
    assert!(rep2.downloaded.is_empty());
    assert_eq!(rep2.already_present, ["onnx/model.onnx"]);

    // 3. `local_model_status` for the default pinned model reports missing without downloading.
    let status = local_model_status(dir.path(), "BAAI/bge-small-en-v1.5", false);
    assert!(!status.present);
    assert!(status.detail.contains("ua memory models fetch"), "{status:?}");
}

/// `system_doctor`'s embedded count excludes stale vectors (wrong identity,
/// imported rows, or mismatched `content_sha`) and reports them as stale until
/// backfill re-embeds them.
#[tokio::test]
async fn doctor_embedded_count_excludes_stale_vectors_until_backfill() {
    let app = Router::new()
        .route("/api/show", post(|| async { Json(json!({ "digest": "sha256:doc-rev-1" })) }))
        .route(
            "/api/embed",
            post(|Json(body): Json<Value>| async move {
                let n = body["input"].as_array().unwrap().len();
                Json(json!({ "embeddings": vec![vec![1.0f32, 0.0]; n] }))
            }),
        );
    let (addr, _srv) = bind_axum(app).await;

    let dir = tempfile::tempdir().unwrap();
    let reg = builtin_registry();
    let caller = agent("builder-1", DEFAULT_ORG);

    // First confirm userinfo in `ollama_url` is redacted in `system_doctor` output.
    {
        let mut cfg_ui = Config::for_home(dir.path());
        cfg_ui.memory.embedder = "ollama".into();
        cfg_ui.memory.ollama_model = "nomic-embed-text".into();
        cfg_ui.memory.ollama_url = format!("http://secret-user:secret-pass@{addr}");
        let hub_ui = Hub::in_memory(cfg_ui).unwrap();
        let doc_ui = reg.call(&hub_ui, &caller, "system_doctor", json!({})).await.unwrap();
        let row_ui = doc_ui["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["capability"] == "semantic_search")
            .unwrap();
        let detail_ui = row_ui["detail"].as_str().unwrap();
        assert!(
            !detail_ui.contains("secret-user") && !detail_ui.contains("secret-pass"),
            "doctor must redact URL userinfo: {detail_ui}"
        );
    }

    let mut cfg = Config::for_home(dir.path());
    cfg.memory.embedder = "ollama".into();
    cfg.memory.ollama_model = "nomic-embed-text".into();
    cfg.memory.ollama_url = format!("http://{addr}");

    let hub = Hub::in_memory(cfg).unwrap();

    // Plant two live notes in `default` with stale embeddings (one imported,
    // one with outdated content_sha), PLUS a live embedded note in `org-other`
    // so dropping the org filter in `embedding_freshness_counts` fails (catches P3).
    let vec_bytes: Vec<u8> = [1.0f32, 0.0f32].iter().flat_map(|f| f.to_le_bytes()).collect();
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                 VALUES ('org-other', 'org-other', 'Org Other', '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            tx.execute(
                "INSERT INTO memory (id, org_id, title, content, tags, created_at, updated_at) VALUES \
                 ('n-imp', 'default', 'Imported', 'imported body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'), \
                 ('n-sha', 'default', 'Edited', 'edited body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'), \
                 ('n-other', 'org-other', 'Other org', 'other body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            tx.execute(
                "INSERT INTO memory_embeddings (org_id, note_id, model, dim, embedding, content_sha, updated_at) VALUES \
                 ('default', 'n-imp', 'import:bge-small', 2, ?1, '', '2026-01-01T00:00:00+00:00'), \
                 ('default', 'n-sha', 'ollama:nomic-embed-text@sha256:doc-rev-1', 2, ?1, 'stale-sha', '2026-01-01T00:00:00+00:00'), \
                 ('org-other', 'n-other', 'ollama:nomic-embed-text@sha256:doc-rev-1', 2, ?1, 'other-sha', '2026-01-01T00:00:00+00:00')",
                [&vec_bytes],
            )?;
            Ok(())
        })
        .unwrap();

    let doc_before = reg.call(&hub, &caller, "system_doctor", json!({})).await.unwrap();
    let row_before = doc_before["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["capability"] == "semantic_search")
        .unwrap();
    let detail_before = row_before["detail"].as_str().unwrap();
    assert!(
        !detail_before.contains("secret-user") && !detail_before.contains("secret-pass"),
        "doctor must redact URL userinfo: {detail_before}"
    );
    assert!(
        detail_before.contains("0 of 2 notes embedded (2 stale)"),
        "doctor must exclude stale vectors and other orgs from embedded count: {detail_before}"
    );

    // Backfill re-embeds both; doctor now reports 2 of 2 embedded and no stale count.
    let maint = reg.call(&hub, &caller, "recall_maintenance", json!({})).await.unwrap();
    assert_eq!(maint["embeddings"]["notes_embedded"], 2, "{maint}");

    let doc_after = reg.call(&hub, &caller, "system_doctor", json!({})).await.unwrap();
    let row_after = doc_after["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["capability"] == "semantic_search")
        .unwrap();
    let detail_after = row_after["detail"].as_str().unwrap();
    assert!(
        detail_after.contains("2 of 2 notes embedded") && !detail_after.contains("stale"),
        "after backfill, doctor should report 2 of 2 fresh: {detail_after}"
    );

    // Verify `openai_compat` doctor freshness uses the EXACT same revision as `OpenAiCompatEmbedder`
    // (no `v1` vs `remote` drift).
    let oa_app = Router::new().route(
        "/v1/embeddings",
        post(|Json(body): Json<Value>| async move {
            let n = body["input"].as_array().unwrap().len();
            let data: Vec<Value> =
                (0..n).map(|i| json!({ "index": i, "embedding": [1.0f32, 0.0] })).collect();
            Json(json!({ "data": data }))
        }),
    );
    let (oa_addr, _oa_srv) = bind_axum(oa_app).await;
    let oa_dir = tempfile::tempdir().unwrap();
    let mut oa_cfg = Config::for_home(oa_dir.path());
    oa_cfg.memory.embedder = "openai_compat".into();
    oa_cfg.memory.openai_compat_url = Some(format!("http://{oa_addr}"));
    oa_cfg.memory.openai_compat_model = Some("text-embedding-3-small".into());
    let oa_hub = Hub::in_memory(oa_cfg).unwrap();
    reg.call(&oa_hub, &caller, "memory_save", json!({ "title": "OA", "content": "fresh openai note" }))
        .await
        .unwrap();
    let oa_doc = reg.call(&oa_hub, &caller, "system_doctor", json!({})).await.unwrap();
    let oa_row =
        oa_doc["checks"].as_array().unwrap().iter().find(|c| c["capability"] == "semantic_search").unwrap();
    let oa_detail = oa_row["detail"].as_str().unwrap();
    assert_eq!(oa_row["status"], "LIVE", "{oa_row}");
    assert!(
        oa_detail.contains("1 of 1 notes embedded") && !oa_detail.contains("stale"),
        "openai_compat doctor must count freshly embedded note as fresh: {oa_detail}"
    );
}

/// Startup background backfill automatically re-embeds stale/missing notes
/// across every active organization (strictly per org), skips suspended orgs,
/// and stops cleanly on cancellation.
#[tokio::test]
async fn startup_backfill_automatically_reembeds_active_orgs_and_skips_suspended() {
    let app = Router::new()
        .route("/api/show", post(|| async { Json(json!({ "digest": "sha256:startup-rev" })) }))
        .route(
            "/api/embed",
            post(|Json(body): Json<Value>| async move {
                let n = body["input"].as_array().unwrap().len();
                Json(json!({ "embeddings": vec![vec![1.0f32, 0.0]; n] }))
            }),
        );
    let (addr, _srv) = bind_axum(app).await;

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.memory.embedder = "off".into();
    let hub_off = Hub::in_memory(cfg.clone()).unwrap();
    assert!(
        ua_tools::families::memory::spawn_backfill(&hub_off, tokio_util::sync::CancellationToken::new())
            .is_none(),
        "embedder = off should not spawn a background backfill task"
    );

    cfg.memory.embedder = "ollama".into();
    cfg.memory.ollama_model = "nomic-embed-text".into();
    cfg.memory.ollama_url = format!("http://{addr}");
    let hub = Hub::in_memory(cfg).unwrap();

    // Seed suspended org that sorts BEFORE the active org (`org-0-suspended` < `org-z-active`)
    // so checking `embedded_active == 2` can never race ahead of processing the suspended org
    // (catches P2).
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, status, allowed_profiles, created_at) VALUES \
                 ('org-0-suspended', 'org-0-suspended', 'Org Suspended', 'suspended', '[\"developer\"]', '2026-01-01T00:00:00+00:00'), \
                 ('org-z-active', 'org-z-active', 'Org Active', 'active', '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            tx.execute(
                "INSERT INTO memory (id, org_id, title, content, tags, created_at, updated_at) VALUES \
                 ('n-def', 'default', 'Default', 'default body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'), \
                 ('n-sus', 'org-0-suspended', 'Suspended', 'suspended body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'), \
                 ('n-act', 'org-z-active', 'Active', 'active body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

    let ct = tokio_util::sync::CancellationToken::new();
    let handle = ua_tools::families::memory::spawn_backfill(&hub, ct.clone()).expect("spawns backfill");

    // Wait for `org-z-active` (which sorts AFTER `org-0-suspended`) to be embedded.
    let mut embedded_active = 0i64;
    for _ in 0..40 {
        embedded_active = hub
            .db()
            .read(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM memory_embeddings \
                     WHERE model = 'ollama:nomic-embed-text@sha256:startup-rev' \
                       AND content_sha <> '' \
                       AND org_id IN ('default', 'org-z-active')",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        if embedded_active == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(embedded_active, 2, "startup backfill must automatically embed all active orgs");

    let embedded_suspended: i64 = hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM memory_embeddings WHERE org_id = 'org-0-suspended'",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(embedded_suspended, 0, "suspended orgs must never be backfilled");

    ct.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("backfill task exits promptly on cancellation")
        .expect("backfill task does not panic");

    // Deterministic check: `backfill_all_orgs_step` never includes `org-0-suspended`.
    let step_reports =
        ua_tools::families::memory::backfill_all_orgs_step(hub.db(), hub.cfg(), 8).await.unwrap();
    let step_orgs: Vec<&str> = step_reports.iter().map(|(o, _)| o.as_str()).collect();
    assert_eq!(step_orgs, vec!["default", "org-z-active"]);
}

/// Persistently failing notes (e.g. a remote backend rejecting oversized notes)
/// never starve later notes, report attempted batches so stalls are visible,
/// set `has_more` only when untried stale notes remain, and avoid infinite
/// retry storms until the note's content or active identity changes.
#[tokio::test]
async fn failing_notes_never_starve_later_notes_and_avoid_retry_storm() {
    let app = Router::new()
        .route("/api/show", post(|| async { Json(json!({ "digest": "sha256:starve-rev" })) }))
        .route(
            "/api/embed",
            post(|Json(body): Json<Value>| async move {
                let inputs = body["input"].as_array().unwrap();
                if inputs.iter().any(|v| v.as_str().is_some_and(|s| s.contains("REJECT_ME"))) {
                    return (StatusCode::BAD_REQUEST, Json(json!({ "error": "input rejected" })))
                        .into_response();
                }
                Json(json!({ "embeddings": vec![vec![1.0f32, 0.0]; inputs.len()] })).into_response()
            }),
        );
    let (addr, _srv) = bind_axum(app).await;

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.memory.embedder = "ollama".into();
    cfg.memory.ollama_model = "nomic-embed-text".into();
    cfg.memory.ollama_url = format!("http://{addr}");

    // Case 1: 64 always-failing notes followed by 1 good note.
    let hub = Hub::in_memory(cfg.clone()).unwrap();
    let reg = builtin_registry();
    let caller = agent("builder-1", DEFAULT_ORG);
    hub.db()
        .write(|tx| {
            for i in 0..64 {
                tx.execute(
                    "INSERT INTO memory (id, org_id, title, content, tags, created_at, updated_at) \
                     VALUES (?1, 'default', ?2, 'REJECT_ME payload', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                    rusqlite::params![format!("bad-{i:02}"), format!("Bad {i}")],
                )?;
            }
            tx.execute(
                "INSERT INTO memory (id, org_id, title, content, tags, created_at, updated_at) \
                 VALUES ('good-65', 'default', 'Good tail', 'valid tail body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

    // Pass 1: hits the 8-batch cap on the 64 failing notes, reports attempted
    // batches = 8 and has_more = true because good-65 is untried past the cursor.
    let p1 = reg.call(&hub, &caller, "recall_maintenance", json!({})).await.unwrap();
    assert_eq!(p1["embeddings"]["batches"], 8, "attempted batches must be visible: {p1}");
    assert_eq!(p1["embeddings"]["notes_embedded"], 0, "{p1}");
    assert_eq!(p1["embeddings"]["failed"], 64, "{p1}");
    assert_eq!(p1["embeddings"]["has_more"], true, "{p1}");

    // Pass 2: resumes past the cursor and embeds good-65 instead of starving it!
    let p2 = reg.call(&hub, &caller, "recall_maintenance", json!({})).await.unwrap();
    assert_eq!(p2["embeddings"]["batches"], 1, "{p2}");
    assert_eq!(p2["embeddings"]["notes_embedded"], 1, "good-65 must not be starved: {p2}");
    assert_eq!(p2["embeddings"]["failed"], 0, "{p2}");
    assert_eq!(p2["embeddings"]["has_more"], false, "{p2}");

    let good_embedded: i64 = hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM memory_embeddings WHERE note_id = 'good-65' AND content_sha <> ''",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(good_embedded, 1);

    // Pass 3: failing notes are in (identity, content_sha) cooldown -> no retry storm.
    let p3 = reg.call(&hub, &caller, "recall_maintenance", json!({})).await.unwrap();
    assert_eq!(p3["embeddings"]["batches"], 0, "{p3}");
    assert_eq!(p3["embeddings"]["failed"], 0, "{p3}");
    assert_eq!(p3["embeddings"]["has_more"], false, "{p3}");

    // Editing bad-00 changes its content_sha so it leaves cooldown immediately.
    hub.db()
        .write(|tx| {
            tx.execute("UPDATE memory SET content = 'now valid body' WHERE id = 'bad-00'", [])?;
            Ok(())
        })
        .unwrap();
    let p4 = reg.call(&hub, &caller, "recall_maintenance", json!({})).await.unwrap();
    assert_eq!(p4["embeddings"]["batches"], 1, "{p4}");
    assert_eq!(p4["embeddings"]["notes_embedded"], 1, "edited note must retry immediately: {p4}");
    assert_eq!(p4["embeddings"]["has_more"], false, "{p4}");

    // Case 2: 64 always-failing notes with NO untried notes after them -> has_more = false.
    let hub2 = Hub::in_memory(cfg).unwrap();
    hub2.db()
        .write(|tx| {
            for i in 0..64 {
                tx.execute(
                    "INSERT INTO memory (id, org_id, title, content, tags, created_at, updated_at) \
                     VALUES (?1, 'default', ?2, 'REJECT_ME payload', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                    rusqlite::params![format!("only-bad-{i:02}"), format!("Only Bad {i}")],
                )?;
            }
            Ok(())
        })
        .unwrap();
    let only_bad = reg.call(&hub2, &caller, "recall_maintenance", json!({})).await.unwrap();
    assert_eq!(only_bad["embeddings"]["batches"], 8, "{only_bad}");
    assert_eq!(only_bad["embeddings"]["failed"], 64, "{only_bad}");
    assert_eq!(
        only_bad["embeddings"]["has_more"], false,
        "no untried stale notes remain past the 64th note: {only_bad}"
    );
}

/// Catches M6 (`save.rs` ignoring org `allow_remote_embedder`) and P1
/// (`maintenance.rs` backfill ignoring org `allow_remote_embedder`).
#[tokio::test]
async fn save_and_backfill_enforce_per_org_allow_remote_embedder_gate() {
    use std::sync::Mutex;
    use ua_tools::families::memory::{EmbedError, Embedder, register_remote_embedder};

    struct RecordingRemoteEmbedder {
        model: String,
        seen: Arc<Mutex<Vec<String>>>,
    }
    impl Embedder for RecordingRemoteEmbedder {
        fn model(&self) -> &str {
            &self.model
        }
        fn backend(&self) -> &str {
            "openai_compat"
        }
        fn revision(&self) -> &str {
            "remote.test:443/v1"
        }
        fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
            self.seen.lock().unwrap().extend(texts.iter().cloned());
            Ok(vec![vec![1.0, 0.0]; texts.len()])
        }
    }

    let model = "remote-gated-save-and-backfill-test";
    let seen = Arc::new(Mutex::new(Vec::new()));
    register_remote_embedder(Arc::new(RecordingRemoteEmbedder { model: model.into(), seen: seen.clone() }));

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.embed_model = model.into();
    let hub = Hub::in_memory(cfg).unwrap();
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, allow_remote_embedder, created_at) \
                 VALUES ('org-remote-ok', 'org-remote-ok', 'Org Remote OK', '[\"developer\"]', 1, '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

    let reg = builtin_registry();
    let c_def = agent("b-def", DEFAULT_ORG);
    let c_rem = agent("b-rem", "org-remote-ok");

    // 1. M6: `memory_save` in `default` (`allow_remote_embedder = 0`) MUST NOT
    //    send text to the remote embedder or write a vector; `org-remote-ok` MUST.
    seen.lock().unwrap().clear();
    reg.call(&hub, &c_def, "memory_save", json!({ "title": "DefSave", "content": "default-secret-save" }))
        .await
        .unwrap();
    reg.call(&hub, &c_rem, "memory_save", json!({ "title": "RemSave", "content": "remote-allowed-save" }))
        .await
        .unwrap();
    {
        let inputs = seen.lock().unwrap();
        assert!(
            inputs.iter().all(|s| !s.contains("default-secret-save")),
            "default org leaked on save: {inputs:?}"
        );
        assert!(
            inputs.iter().any(|s| s.contains("remote-allowed-save")),
            "remote org must embed on save: {inputs:?}"
        );
    }
    let def_vecs: i64 = hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM memory_embeddings WHERE org_id = 'default'", [], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    let rem_vecs: i64 = hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM memory_embeddings WHERE org_id = 'org-remote-ok'",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(def_vecs, 0);
    assert_eq!(rem_vecs, 1);

    // 2. P1: plant unembedded notes in both orgs, run `backfill_all_orgs_step`:
    //    `default` MUST NOT send text to the remote embedder; `org-remote-ok` MUST.
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO memory (id, org_id, title, content, tags, created_at, updated_at) VALUES \
                 ('bf-def', 'default', 'DefBF', 'default-secret-backfill', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'), \
                 ('bf-rem', 'org-remote-ok', 'RemBF', 'remote-allowed-backfill', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    seen.lock().unwrap().clear();
    let reports = ua_tools::families::memory::backfill_all_orgs_step(hub.db(), hub.cfg(), 8).await.unwrap();
    let def_rep = reports.iter().find(|(o, _)| o == "default").unwrap();
    let rem_rep = reports.iter().find(|(o, _)| o == "org-remote-ok").unwrap();
    assert!(!def_rep.1.available, "default org must see unavailable remote embedder");
    assert_eq!(def_rep.1.notes_embedded, 0);
    assert!(rem_rep.1.available);
    assert_eq!(rem_rep.1.notes_embedded, 1);
    {
        let inputs = seen.lock().unwrap();
        assert!(
            inputs.iter().all(|s| !s.contains("default-secret-backfill")),
            "default org leaked during backfill: {inputs:?}"
        );
        assert!(
            inputs.iter().any(|s| s.contains("remote-allowed-backfill")),
            "remote org must embed during backfill: {inputs:?}"
        );
    }
}

/// Background `spawn_backfill` must NEVER hot-loop on HTTP 401 (revoked key)
/// or on a corpus of 70 permanently-failing notes (HTTP 400).
#[tokio::test]
async fn spawn_backfill_stops_without_hot_looping_on_401_or_failing_corpus() {
    // 1. Revoked key (HTTP 401): stops after the VERY FIRST request, never
    //    re-sending note text and the Bearer key 64+ times.
    let hits_401 = Arc::new(AtomicUsize::new(0));
    let hits_401_cl = hits_401.clone();
    let app_401 = Router::new().route(
        "/v1/embeddings",
        post(move || {
            let h = hits_401_cl.clone();
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid api key" })))
            }
        }),
    );
    let (addr_401, _srv_401) = bind_axum(app_401).await;
    let dir1 = tempfile::tempdir().unwrap();
    let mut cfg1 = Config::for_home(dir1.path());
    cfg1.memory.embedder = "openai_compat".into();
    cfg1.memory.openai_compat_url = Some(format!("http://{addr_401}"));
    cfg1.memory.openai_compat_model = Some("m".into());
    let hub1 = Hub::in_memory(cfg1).unwrap();
    hub1.db()
        .write(|tx| {
            for i in 0..70 {
                tx.execute(
                    "INSERT INTO memory (id, org_id, title, content, tags, created_at, updated_at) \
                     VALUES (?1, 'default', 'T', 'body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                    [format!("n401-{i:02}")],
                )?;
            }
            Ok(())
        })
        .unwrap();

    let ct1 = tokio_util::sync::CancellationToken::new();
    let h1 = ua_tools::families::memory::spawn_backfill(&hub1, ct1.clone()).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    ct1.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(2), h1).await.unwrap().unwrap();
    assert_eq!(
        hits_401.load(Ordering::SeqCst),
        1,
        "401 auth failure must stop backfill after 1 request without hot-looping"
    );

    // 2. 70 permanently-rejected notes (HTTP 400): bounded to 1 pass (<= 64 calls)
    //    because zero progress stops the tight catch-up loop (no 64 -> 128 -> 192 storm).
    let hits_400 = Arc::new(AtomicUsize::new(0));
    let hits_400_cl = hits_400.clone();
    let app_400 = Router::new().route(
        "/v1/embeddings",
        post(move || {
            let h = hits_400_cl.clone();
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                (StatusCode::BAD_REQUEST, Json(json!({ "error": "too long" })))
            }
        }),
    );
    let (addr_400, _srv_400) = bind_axum(app_400).await;
    let dir2 = tempfile::tempdir().unwrap();
    let mut cfg2 = Config::for_home(dir2.path());
    cfg2.memory.embedder = "openai_compat".into();
    cfg2.memory.openai_compat_url = Some(format!("http://{addr_400}"));
    cfg2.memory.openai_compat_model = Some("m".into());
    let hub2 = Hub::in_memory(cfg2).unwrap();
    hub2.db()
        .write(|tx| {
            for i in 0..70 {
                tx.execute(
                    "INSERT INTO memory (id, org_id, title, content, tags, created_at, updated_at) \
                     VALUES (?1, 'default', 'T', 'body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                    [format!("n400-{i:02}")],
                )?;
            }
            Ok(())
        })
        .unwrap();

    let ct2 = tokio_util::sync::CancellationToken::new();
    let h2 = ua_tools::families::memory::spawn_backfill(&hub2, ct2.clone()).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    ct2.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(2), h2).await.unwrap().unwrap();
    let total_400 = hits_400.load(Ordering::SeqCst);
    assert!(
        (1..=64).contains(&total_400),
        "zero-progress catch-up loop must stop after at most 1 bounded pass (64), got {total_400}"
    );
}

/// Hub #2813 (1): HTTP 401/403 (`auth_refused`) puts background backfill on
/// exponential backoff (1m -> 2m -> 4m -> ... -> 60m) measured on
/// `Config.clock`, so a revoked key does not retry every minute; a successful
/// embed resets the backoff immediately.
#[tokio::test]
async fn auth_refused_backfill_uses_exponential_backoff_on_injected_clock() {
    use jiff::Timestamp;
    use std::sync::atomic::AtomicBool;
    use ua_core::time::Clock;

    let revoked = Arc::new(AtomicBool::new(true));
    let revoked_cl = revoked.clone();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_cl = hits.clone();
    let app = Router::new().route(
        "/v1/embeddings",
        post(move |Json(body): Json<Value>| {
            let rev = revoked_cl.clone();
            let h = hits_cl.clone();
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                if rev.load(Ordering::SeqCst) {
                    return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "revoked key" })))
                        .into_response();
                }
                let n = body["input"].as_array().unwrap().len();
                let data: Vec<Value> =
                    (0..n).map(|i| json!({ "index": i, "embedding": [1.0f32, 0.0] })).collect();
                Json(json!({ "data": data })).into_response()
            }
        }),
    );
    let (addr, _srv) = bind_axum(app).await;

    let dir = tempfile::tempdir().unwrap();
    let base_ms: i64 = 1_700_000_000_000;
    let cfg_at = |offset_ms: i64| {
        let mut cfg = Config::for_home(dir.path());
        cfg.memory.embedder = "openai_compat".into();
        cfg.memory.openai_compat_url = Some(format!("http://{addr}"));
        cfg.memory.openai_compat_model = Some("m".into());
        cfg.clock = Clock::Fixed(Timestamp::from_millisecond(base_ms + offset_ms).unwrap());
        cfg
    };

    let hub = Hub::in_memory(cfg_at(0)).unwrap();
    // Register the HTTP embedder factory once (as `builtin_registry()` does).
    let _ = builtin_registry();
    hub.db()
        .write(|tx| {
            for i in 0..4 {
                tx.execute(
                    "INSERT INTO memory (id, org_id, title, content, tags, created_at, updated_at) \
                     VALUES (?1, 'default', 'T', 'body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                    [format!("auth-{i}")],
                )?;
            }
            Ok(())
        })
        .unwrap();

    // t=0: first 401 -> stops after 1 request, sets 60s backoff.
    let r0 = ua_tools::families::memory::backfill_all_orgs_step(hub.db(), &cfg_at(0), 8).await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(r0[0].1.stopped_unavailable && r0[0].1.stopped_auth_refused, "{r0:?}");

    // t=30s and t=59.999s: skipped without any network request.
    let r1 = ua_tools::families::memory::backfill_all_orgs_step(hub.db(), &cfg_at(30_000), 8).await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(r1[0].1.stopped_auth_refused, "{r1:?}");
    let _ = ua_tools::families::memory::backfill_all_orgs_step(hub.db(), &cfg_at(59_999), 8).await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // t=60s: retries once -> 401 again -> backoff doubles to 120s (until t=180s).
    let r2 = ua_tools::families::memory::backfill_all_orgs_step(hub.db(), &cfg_at(60_000), 8).await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert!(r2[0].1.stopped_auth_refused, "{r2:?}");

    // t=120s (a 1-minute tick) and t=179.999s: skipped (proves backoff doubled, not flat 60s).
    let _ = ua_tools::families::memory::backfill_all_orgs_step(hub.db(), &cfg_at(120_000), 8).await.unwrap();
    let _ = ua_tools::families::memory::backfill_all_orgs_step(hub.db(), &cfg_at(179_999), 8).await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    // t=180s: retries once -> 401 -> backoff doubles to 240s (until t=420s).
    let _ = ua_tools::families::memory::backfill_all_orgs_step(hub.db(), &cfg_at(180_000), 8).await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 3);

    // t=300s (2 minutes later): still skipped inside the 240s window, including manual `recall_maintenance`.
    let _ = ua_tools::families::memory::backfill_all_orgs_step(hub.db(), &cfg_at(300_000), 8).await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    let manual_rep = ua_tools::families::memory::backfill_embeddings(hub.db(), &cfg_at(300_000), DEFAULT_ORG)
        .await
        .unwrap();
    assert!(
        manual_rep.stopped_auth_refused,
        "manual recall_maintenance must respect backoff: {manual_rep:?}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 3, "manual recall_maintenance must not bypass auth backoff");

    // Escalate through 480s (#4), 960s (#5), 1920s (#6), then #7 caps at 3600s (NOT 3840s).
    let mut t_ms: i64 = 420_000; // failure #4 -> 480s
    for expected_delay_ms in [480_000i64, 960_000, 1_920_000, 3_600_000] {
        let before = hits.load(Ordering::SeqCst);
        let rep =
            ua_tools::families::memory::backfill_all_orgs_step(hub.db(), &cfg_at(t_ms), 8).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), before + 1, "expected retry at t={t_ms}");
        assert!(rep[0].1.stopped_auth_refused);
        // 1 ms before delay expires: still skipped.
        let _ = ua_tools::families::memory::backfill_all_orgs_step(
            hub.db(),
            &cfg_at(t_ms + expected_delay_ms - 1),
            8,
        )
        .await
        .unwrap();
        assert_eq!(
            hits.load(Ordering::SeqCst),
            before + 1,
            "must stay backed off for {expected_delay_ms} ms"
        );
        t_ms += expected_delay_ms;
    }
    // At exactly +3600s after failure #7 (where unclamped 2^6*60s = 3840s would still skip),
    // verify the 3600s cap triggers a retry, then recover on 200 and verify clear-on-success.
    revoked.store(false, Ordering::SeqCst);
    let r_ok = ua_tools::families::memory::backfill_all_orgs_step(hub.db(), &cfg_at(t_ms), 8).await.unwrap();
    assert_eq!(r_ok[0].1.notes_embedded, 4, "3600s cap must retry and embed on recovery: {r_ok:?}");
    assert!(!r_ok[0].1.stopped_auth_refused, "{r_ok:?}");

    // Clear-on-success check: add a new unembedded note and flip back to 401.
    // Backoff must reset to the 60s base (NOT stay at 3600s).
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO memory (id, org_id, title, content, tags, created_at, updated_at) \
                 VALUES ('auth-after-reset', 'default', 'T', 'body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    revoked.store(true, Ordering::SeqCst);
    let hits_before_reset = hits.load(Ordering::SeqCst);
    let _ =
        ua_tools::families::memory::backfill_all_orgs_step(hub.db(), &cfg_at(t_ms + 1_000), 8).await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), hits_before_reset + 1);
    let _ = ua_tools::families::memory::backfill_all_orgs_step(hub.db(), &cfg_at(t_ms + 60_999), 8)
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), hits_before_reset + 1);
    let _ = ua_tools::families::memory::backfill_all_orgs_step(hub.db(), &cfg_at(t_ms + 61_000), 8)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        hits_before_reset + 2,
        "backoff must reset to 60s after a successful embed (clear-on-success)"
    );
}

/// Hub #2813 (2): `system_doctor` performs ZERO network probes (`/api/show` or
/// `/api/tags`) and ZERO DNS lookups (even for unflagged orgs with unresolvable
/// hostnames), reading only cached revisions and local policy.
#[tokio::test]
async fn system_doctor_makes_zero_network_or_dns_calls_for_ollama_and_unflagged_orgs() {
    use ua_tools::families::memory::remote::{DoctorEmbedderAvailability, inspect_embedder_for_doctor};

    let show_hits = Arc::new(AtomicUsize::new(0));
    let show_hits_cl = show_hits.clone();
    let tags_hits = Arc::new(AtomicUsize::new(0));
    let tags_hits_cl = tags_hits.clone();
    let app = Router::new()
        .route(
            "/api/show",
            post(move || {
                let h = show_hits_cl.clone();
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    Json(json!({ "details": { "quantization_level": "F16" } }))
                }
            }),
        )
        .route(
            "/api/tags",
            get(move || {
                let h = tags_hits_cl.clone();
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    Json(json!({
                        "models": [{ "name": "zero-net-doctor-model:latest", "digest": "sha256:zero-net-rev" }]
                    }))
                }
            }),
        )
        .route(
            "/api/embed",
            post(|Json(body): Json<Value>| async move {
                let n = body["input"].as_array().unwrap().len();
                Json(json!({ "embeddings": vec![vec![1.0f32, 0.0]; n] }))
            }),
        );
    let (addr, _srv) = bind_axum(app).await;

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.memory.embedder = "ollama".into();
    cfg.memory.ollama_url = format!("http://{addr}");
    cfg.memory.ollama_model = "zero-net-doctor-model".into();
    let hub = Hub::in_memory(cfg).unwrap();
    let reg = builtin_registry();
    let caller = agent("builder-1", DEFAULT_ORG);

    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO memory (id, org_id, title, content, tags, created_at, updated_at) VALUES \
                 ('zn-1', 'default', 'One', 'body one', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

    // 1. Before any embedder call: `system_doctor` makes ZERO `/api/show` or `/api/tags` calls.
    let doc_before = reg.call(&hub, &caller, "system_doctor", json!({})).await.unwrap();
    assert_eq!(show_hits.load(Ordering::SeqCst), 0, "system_doctor must never call /api/show");
    assert_eq!(tags_hits.load(Ordering::SeqCst), 0, "system_doctor must never call /api/tags");
    let sem_before = doc_before["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["capability"] == "semantic_search")
        .unwrap();
    assert_eq!(sem_before["status"], "DEGRADED", "{sem_before}");
    let detail_before = sem_before["detail"].as_str().unwrap();
    assert!(
        detail_before.contains("not yet probed") && detail_before.contains("0 of 1 notes embedded"),
        "{detail_before}"
    );

    // 2. Backfill probes Ollama once and populates the revision cache.
    let maint = reg.call(&hub, &caller, "recall_maintenance", json!({})).await.unwrap();
    assert_eq!(maint["embeddings"]["notes_embedded"], 1, "{maint}");
    assert!(show_hits.load(Ordering::SeqCst) >= 1 && tags_hits.load(Ordering::SeqCst) >= 1);

    // 3. After backfill: `system_doctor` reads the cached revision with ZERO network calls.
    show_hits.store(0, Ordering::SeqCst);
    tags_hits.store(0, Ordering::SeqCst);
    let doc_after = reg.call(&hub, &caller, "system_doctor", json!({})).await.unwrap();
    assert_eq!(show_hits.load(Ordering::SeqCst), 0, "system_doctor must use cached revision, not /api/show");
    assert_eq!(tags_hits.load(Ordering::SeqCst), 0, "system_doctor must use cached revision, not /api/tags");
    let sem_after = doc_after["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["capability"] == "semantic_search")
        .unwrap();
    assert_eq!(sem_after["status"], "LIVE", "{sem_after}");
    assert!(sem_after["detail"].as_str().unwrap().contains("1 of 1 notes embedded"), "{sem_after}");

    // 4. Unflagged org (`allow_remote_embedder = 0`) with an unresolvable domain name:
    //    fails closed without attempting any DNS lookup (for both `openai_compat`
    //    and `ollama`).
    let unflagged_oai_host = "never-resolve-oai-in-doctor.invalid";
    let mut cfg_unflagged = Config::for_home(dir.path());
    cfg_unflagged.memory.embedder = "openai_compat".into();
    cfg_unflagged.memory.openai_compat_url = Some(format!("https://{unflagged_oai_host}:8443"));
    cfg_unflagged.memory.openai_compat_model = Some("m".into());
    let st = inspect_embedder_for_doctor(&cfg_unflagged, false);
    assert_eq!(st.availability, DoctorEmbedderAvailability::Unavailable);
    assert!(st.active_identity.is_none());

    let hub_unflagged = Hub::in_memory(cfg_unflagged).unwrap();
    let doc_unflagged = reg.call(&hub_unflagged, &caller, "system_doctor", json!({})).await.unwrap();
    assert!(
        !ua_tools::families::memory::remote::host_lookup_attempted(unflagged_oai_host),
        "system_doctor must never perform DNS lookup for an unflagged openai_compat org"
    );
    let sem_unflagged = doc_unflagged["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["capability"] == "semantic_search")
        .unwrap();
    assert_eq!(sem_unflagged["status"], "DEGRADED", "{sem_unflagged}");

    let unflagged_ol_host = "never-resolve-ollama-in-doctor.invalid";
    let mut cfg_ol_unflagged = Config::for_home(dir.path());
    cfg_ol_unflagged.memory.embedder = "ollama".into();
    cfg_ol_unflagged.memory.ollama_url = format!("https://{unflagged_ol_host}:11434");
    let hub_ol_unflagged = Hub::in_memory(cfg_ol_unflagged).unwrap();
    let doc_ol_unflagged = reg.call(&hub_ol_unflagged, &caller, "system_doctor", json!({})).await.unwrap();
    assert!(
        !ua_tools::families::memory::remote::host_lookup_attempted(unflagged_ol_host),
        "system_doctor must never perform DNS lookup for an unflagged ollama org"
    );
    let sem_ol_unflagged = doc_ol_unflagged["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["capability"] == "semantic_search")
        .unwrap();
    assert_eq!(sem_ol_unflagged["status"], "DEGRADED", "{sem_ol_unflagged}");

    // 5. Literal non-routable / link-local / cloud-metadata IPs are refused by
    //    `EMBEDDER_REMOTE.addresses.check(ip)` even when `allow_remote_embedder = 1`.
    for bad_url in ["https://169.254.169.254:443", "https://0.0.0.0:443", "https://[fe80::1]:443"] {
        let mut cfg_bad = Config::for_home(dir.path());
        cfg_bad.memory.embedder = "openai_compat".into();
        cfg_bad.memory.openai_compat_url = Some(bad_url.into());
        cfg_bad.memory.openai_compat_model = Some("m".into());
        let st_bad = inspect_embedder_for_doctor(&cfg_bad, true);
        assert_eq!(
            st_bad.availability,
            DoctorEmbedderAvailability::Unavailable,
            "flagged org must still refuse {bad_url}"
        );
        let hub_bad = Hub::in_memory(cfg_bad).unwrap();
        hub_bad
            .db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO orgs (id, slug, display_name, allowed_profiles, allow_remote_embedder, created_at) \
                     VALUES ('org-flag', 'org-flag', 'Flagged', '[\"developer\"]', 1, '2026-01-01T00:00:00+00:00')",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        let doc_bad =
            reg.call(&hub_bad, &agent("b-flag", "org-flag"), "system_doctor", json!({})).await.unwrap();
        let sem_bad = doc_bad["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["capability"] == "semantic_search")
            .unwrap();
        assert_eq!(sem_bad["status"], "DEGRADED", "doctor must not show {bad_url} as LIVE: {sem_bad}");
    }
}

/// Hub #2813 (3): real Ollama `/api/show` omits `digest`, so the embedder
/// reads the content-addressed `digest` from `GET /api/tags` (with `:latest`
/// tag normalization). Re-pulling the same tag with new weights changes the
/// active vector identity, stops scoring old vectors, and triggers backfill.
#[tokio::test]
async fn ollama_same_tag_repull_changes_identity_via_api_tags_digest() {
    use std::sync::Mutex;

    let current_digest = Arc::new(Mutex::new("sha256:pull-v1".to_string()));
    let digest_cl = current_digest.clone();
    let app = Router::new()
        // Real Ollama `/api/show` omits `digest` and only has unchanging metadata (`F16`).
        .route("/api/show", post(|| async { Json(json!({ "details": { "quantization_level": "F16" } })) }))
        .route(
            "/api/tags",
            get(move || {
                let d = digest_cl.clone();
                async move {
                    let digest = d.lock().unwrap().clone();
                    Json(json!({
                        "models": [
                            { "name": "other-model:latest", "digest": "sha256:unrelated" },
                            { "name": "nomic-embed-text:latest", "digest": digest }
                        ]
                    }))
                }
            }),
        )
        .route(
            "/api/embed",
            post(|Json(body): Json<Value>| async move {
                let inputs = body["input"].as_array().unwrap();
                let vecs: Vec<Vec<f32>> = inputs
                    .iter()
                    .map(|v| {
                        let s = v.as_str().unwrap_or("").to_lowercase();
                        if s.contains("car") || s.contains("automobile") {
                            vec![1.0, 0.0, 0.0]
                        } else {
                            vec![0.0, 1.0, 0.0]
                        }
                    })
                    .collect();
                Json(json!({ "embeddings": vecs }))
            }),
        );
    let (addr, _srv) = bind_axum(app).await;

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.memory.embedder = "ollama".into();
    cfg.memory.ollama_url = format!("http://{addr}");
    // Tagless name tests `:latest` normalization against `/api/tags`.
    cfg.memory.ollama_model = "nomic-embed-text".into();
    let hub = Hub::in_memory(cfg).unwrap();
    let reg = builtin_registry();
    let b1 = agent("builder-1", DEFAULT_ORG);

    // 1. Initial pull (`sha256:pull-v1`): save embeds under `pull-v1` and hybrid search hits.
    let saved = reg
        .call(&hub, &b1, "memory_save", json!({ "title": "Garage", "content": "The car is parked." }))
        .await
        .unwrap();
    let note_id = saved["id"].as_str().unwrap().to_string();
    let model_v1: String = hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT model FROM memory_embeddings WHERE note_id = ?1", [&note_id], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    assert_eq!(model_v1, "ollama:nomic-embed-text@sha256:pull-v1");

    let hit_v1 = reg.call(&hub, &b1, "memory_search", json!({ "query": "automobile" })).await.unwrap();
    assert_eq!(hit_v1["retrieval"]["mode"], "hybrid", "{hit_v1}");
    assert_eq!(hit_v1["results"][0]["id"], note_id, "{hit_v1}");

    // 2. Operator re-pulls `nomic-embed-text` (same tag, new weights -> new digest in `/api/tags`).
    *current_digest.lock().unwrap() = "sha256:pull-v2".to_string();

    // Old `pull-v1` vector must NOT be scored against a `pull-v2` query vector.
    let hit_stale = reg.call(&hub, &b1, "memory_search", json!({ "query": "automobile" })).await.unwrap();
    assert!(
        hit_stale["results"].as_array().unwrap().is_empty(),
        "stale v1 vector must not score after same-tag re-pull: {hit_stale}"
    );

    // `system_doctor` reads the refreshed cache (`pull-v2`) and reports the v1 vector as stale.
    let doc_stale = reg.call(&hub, &b1, "system_doctor", json!({})).await.unwrap();
    let sem_stale = doc_stale["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["capability"] == "semantic_search")
        .unwrap();
    assert!(
        sem_stale["detail"].as_str().unwrap().contains("0 of 1 notes embedded (1 stale)"),
        "doctor must flag v1 vector as stale after re-pull: {sem_stale}"
    );

    // 3. Backfill re-embeds under `sha256:pull-v2`, restoring hybrid search and doctor freshness.
    let maint = reg.call(&hub, &b1, "recall_maintenance", json!({})).await.unwrap();
    assert_eq!(maint["embeddings"]["notes_embedded"], 1, "{maint}");
    let model_v2: String = hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT model FROM memory_embeddings WHERE note_id = ?1", [&note_id], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    assert_eq!(model_v2, "ollama:nomic-embed-text@sha256:pull-v2");

    let hit_v2 = reg.call(&hub, &b1, "memory_search", json!({ "query": "automobile" })).await.unwrap();
    assert_eq!(hit_v2["retrieval"]["mode"], "hybrid", "{hit_v2}");
    assert_eq!(hit_v2["results"][0]["id"], note_id, "{hit_v2}");
}

/// Hub #2813 review regression: when `/api/show` omits `digest` and `/api/tags`
/// flakes (alternating 200 and 500), the embedder must keep the cached digest
/// and NEVER overwrite it with `quantization_level` (`@digest <-> @F16` churn).
/// Also verifies `:latest` normalization preserves registry host ports
/// (`registry.local:5000/ns/embed` -> `registry.local:5000/ns/embed:latest`).
#[tokio::test]
async fn ollama_flaky_api_tags_keeps_cached_digest_and_supports_registry_port_tags() {
    let tags_fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let tags_fail_cl = tags_fail.clone();
    let app = Router::new()
        .route("/api/show", post(|| async { Json(json!({ "details": { "quantization_level": "F16" } })) }))
        .route(
            "/api/tags",
            get(move || {
                let f = tags_fail_cl.clone();
                async move {
                    if f.load(Ordering::SeqCst) {
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "tags timeout" })))
                            .into_response();
                    }
                    Json(json!({
                        "models": [
                            { "name": "registry.local:5000/ns/embed:latest", "digest": "sha256:abc123" }
                        ]
                    }))
                    .into_response()
                }
            }),
        );
    let (addr, _srv) = bind_axum(app).await;
    let url = format!("http://{addr}");
    let model = "registry.local:5000/ns/embed";

    // 1. Before any digest has been read, a failing `/api/tags` must fail the probe
    //    rather than inventing an `@F16` revision.
    assert!(
        build_ollama_embedder(&url, model, false, false, None).await.is_err(),
        "must refuse to fall back to quantization_level when /api/tags has never succeeded"
    );

    // 2. Successful `/api/tags` matches `registry.local:5000/ns/embed` -> `:latest`
    //    and caches `sha256:abc123`.
    tags_fail.store(false, Ordering::SeqCst);
    let e1 = build_ollama_embedder(&url, model, false, false, None)
        .await
        .expect("registry-port model tag must match :latest in /api/tags");
    assert_eq!(e1.revision(), "sha256:abc123");

    // 3. Alternating `/api/tags` failures in both explicit and auto modes must keep
    //    `sha256:abc123` and NEVER flip to `F16`.
    for i in 0..4 {
        let should_fail = i % 2 == 0;
        tags_fail.store(should_fail, Ordering::SeqCst);
        let e_explicit = build_ollama_embedder(&url, model, false, false, None)
            .await
            .expect("explicit keeps cached digest when /api/tags flakes");
        assert_eq!(e_explicit.revision(), "sha256:abc123", "explicit flipped on iter {i}");
        let e_auto = build_ollama_embedder(&url, model, false, true, None)
            .await
            .expect("auto keeps cached digest when /api/show succeeds and /api/tags flakes");
        assert_eq!(e_auto.revision(), "sha256:abc123", "auto flipped on iter {i}");
    }
}

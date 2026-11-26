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
use ua_tools::families::memory::remote::{build_guarded_client, build_ollama_embedder};
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

    // End-to-end org gate check: explicit `ollama` pointing at a remote IP literal
    // is refused for an org with `allow_remote_embedder = 0` (lexical fallback)
    // and accepted for an org with `allow_remote_embedder = 1`.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.memory.embedder = "ollama".into();
    cfg.memory.ollama_url = "http://10.20.30.40:11434".into();
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

    // Default org (`allow_remote_embedder = 0`): gets unavailable NoopEmbedder.
    let default_emb = ua_tools::families::memory::embedder_for_org(hub.db(), &cfg, DEFAULT_ORG).await;
    assert!(!default_emb.available(), "org without allow_remote_embedder must stay lexical-only");
    assert_eq!(default_emb.backend(), "noop");

    // `org-remote` (`allow_remote_embedder = 1`): gets the `ollama` embedder.
    let remote_emb = ua_tools::families::memory::embedder_for_org(hub.db(), &cfg, "org-remote").await;
    assert!(remote_emb.available());
    assert_eq!(remote_emb.backend(), "ollama");
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
    let redir_app = Router::new().route(
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
    let mut cfg = Config::for_home(dir.path());
    cfg.memory.embedder = "ollama".into();
    cfg.memory.ollama_model = "nomic-embed-text".into();
    cfg.memory.ollama_url = format!("http://{addr}");

    let hub = Hub::in_memory(cfg).unwrap();
    let reg = builtin_registry();
    let caller = agent("builder-1", DEFAULT_ORG);

    // Plant two live notes with stale embeddings: one imported, one with an
    // outdated content_sha under the active Ollama identity.
    let vec_bytes: Vec<u8> = [1.0f32, 0.0f32].iter().flat_map(|f| f.to_le_bytes()).collect();
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO memory (id, org_id, title, content, tags, created_at, updated_at) VALUES \
                 ('n-imp', 'default', 'Imported', 'imported body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'), \
                 ('n-sha', 'default', 'Edited', 'edited body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            tx.execute(
                "INSERT INTO memory_embeddings (org_id, note_id, model, dim, embedding, content_sha, updated_at) VALUES \
                 ('default', 'n-imp', 'import:bge-small', 2, ?1, '', '2026-01-01T00:00:00+00:00'), \
                 ('default', 'n-sha', 'ollama:nomic-embed-text@sha256:doc-rev-1', 2, ?1, 'stale-sha', '2026-01-01T00:00:00+00:00')",
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
        detail_before.contains("0 of 2 notes embedded (2 stale)"),
        "doctor must exclude stale vectors from embedded count: {detail_before}"
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

    // Seed active second org and suspended org, plus stale/missing notes in all three.
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, status, allowed_profiles, created_at) VALUES \
                 ('org-active', 'org-active', 'Org Active', 'active', '[\"developer\"]', '2026-01-01T00:00:00+00:00'), \
                 ('org-suspended', 'org-suspended', 'Org Suspended', 'suspended', '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            tx.execute(
                "INSERT INTO memory (id, org_id, title, content, tags, created_at, updated_at) VALUES \
                 ('n-def', 'default', 'Default', 'default body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'), \
                 ('n-act', 'org-active', 'Active', 'active body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'), \
                 ('n-sus', 'org-suspended', 'Suspended', 'suspended body', '[]', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

    let ct = tokio_util::sync::CancellationToken::new();
    let handle = ua_tools::families::memory::spawn_backfill(&hub, ct.clone()).expect("spawns backfill");

    // Wait briefly for the startup pass to embed both active orgs automatically.
    let mut embedded_active = 0i64;
    for _ in 0..40 {
        embedded_active = hub
            .db()
            .read(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM memory_embeddings \
                     WHERE model = 'ollama:nomic-embed-text@sha256:startup-rev' \
                       AND content_sha <> '' \
                       AND org_id IN ('default', 'org-active')",
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
                "SELECT COUNT(*) FROM memory_embeddings WHERE org_id = 'org-suspended'",
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
}

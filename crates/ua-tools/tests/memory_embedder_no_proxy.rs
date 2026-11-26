//! HTTP embedders ignore `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`.
//! Dedicated single-test binary because it mutates process environment variables.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use ua_tools::families::memory::remote::{build_ollama_embedder, build_openai_compat_embedder};

#[tokio::test]
async fn http_proxy_env_cannot_divert_embedder_requests() {
    let proxy_hits = Arc::new(AtomicUsize::new(0));
    let proxy_hits_cl = proxy_hits.clone();
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_app = Router::new().fallback(move || {
        let hits = proxy_hits_cl.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            Json(json!({ "embeddings": [[9.0, 9.0]] }))
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(proxy_listener, proxy_app).await;
    });

    let server_hits = Arc::new(AtomicUsize::new(0));
    let server_hits_cl = server_hits.clone();
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let server_app = Router::new()
        .route(
            "/api/embed",
            post(move |Json(body): Json<Value>| {
                let hits = server_hits_cl.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let n = body["input"].as_array().unwrap().len();
                    Json(json!({ "embeddings": vec![vec![1.0f32, 0.0]; n] }))
                }
            }),
        )
        .route(
            "/v1/embeddings",
            post(move |Json(body): Json<Value>| async move {
                let n = body["input"].as_array().unwrap().len();
                let data: Vec<Value> =
                    (0..n).map(|i| json!({ "index": i, "embedding": [1.0f32, 0.0] })).collect();
                Json(json!({ "data": data }))
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(server_listener, server_app).await;
    });

    // SAFETY: single-test binary; no concurrent env readers.
    unsafe {
        for k in ["NO_PROXY", "no_proxy"] {
            std::env::remove_var(k);
        }
        let proxy_url = format!("http://{proxy_addr}");
        for k in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
            std::env::set_var(k, &proxy_url);
        }
    }

    let ollama =
        build_ollama_embedder(&format!("http://{server_addr}"), "nomic-embed-text", false, false, None)
            .await
            .unwrap();
    let out = tokio::task::spawn_blocking(move || ollama.embed(&["hello".into()])).await.unwrap().unwrap();
    assert_eq!(out, vec![vec![1.0f32, 0.0]]);

    let oai =
        build_openai_compat_embedder(&format!("http://{server_addr}"), "m", None, false, None).await.unwrap();
    let out2 = tokio::task::spawn_blocking(move || oai.embed(&["hello".into()])).await.unwrap().unwrap();
    assert_eq!(out2, vec![vec![1.0f32, 0.0]]);

    assert_eq!(server_hits.load(Ordering::SeqCst), 1, "Ollama embedder must hit the checked server directly");
    assert_eq!(proxy_hits.load(Ordering::SeqCst), 0, "HTTP_PROXY must never receive embedder traffic");
}

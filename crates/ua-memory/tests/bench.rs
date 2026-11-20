//! The fixture bench is the CI gate: same report twice, and no class under
//! `bench/floor.json`. LongMemEval-S is not required here.

use ua_memory::bench::{Kind, Options};

#[tokio::test]
async fn fixture_bench_is_deterministic_and_meets_its_floor() {
    let a = ua_memory::bench::run(Options::fixture()).await.unwrap();
    let b = ua_memory::bench::run(Options::fixture()).await.unwrap();
    assert_eq!(a, b, "fixture report changed between runs");
    // The recorded floor is the default build: lexical only, no embedder.
    #[cfg(not(feature = "embeddings"))]
    {
        assert_eq!(a["build"]["embeddings"], serde_json::json!(false));
        assert_eq!(a["retrieval"]["mode"], "lexical_fallback");
    }
    assert_eq!(a["floor"]["ok"], serde_json::json!(true), "{a}");
}

#[tokio::test]
async fn longmemeval_absent_file_names_the_pin_and_the_command() {
    let err = ua_memory::bench::run(Options {
        kind: Kind::LongMemEval,
        data: Some("missing-longmemeval.json".into()),
        limit: None,
    })
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("d6f21ea9d60a0d56f34a05b609c79c88a451d2ae03597821ea3d5a9678c3a442"), "{msg}");
    assert!(msg.contains("cargo run -p ua-memory --bin memory-bench -- --longmemeval"), "{msg}");
    assert!(msg.contains("curl"), "{msg}");
}

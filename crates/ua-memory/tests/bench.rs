//! The fixture bench is the CI gate: the same bytes twice, and no class under
//! `bench/floor.json`. LongMemEval-S is not required here, and nothing here
//! touches the network.

use ua_memory::bench::{EmbedOptions, Kind, Options};

#[tokio::test]
async fn fixture_bench_is_deterministic_and_meets_its_floor() {
    let a = ua_memory::bench::run(Options::fixture()).await.unwrap();
    let b = ua_memory::bench::run(Options::fixture()).await.unwrap();
    // Byte-identical output, as the binary prints it, not only equal values.
    let (ja, jb) = (serde_json::to_string_pretty(&a).unwrap(), serde_json::to_string_pretty(&b).unwrap());
    assert_eq!(ja, jb, "fixture report changed between runs");
    assert_eq!(ua_memory::bench::table(&a), ua_memory::bench::table(&b));
    // The run reads the injected clock, not the wall clock.
    assert_eq!(a["clock"], ua_memory::bench::BENCH_NOW);
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
        ids: None,
        embed: None,
    })
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("d6f21ea9d60a0d56f34a05b609c79c88a451d2ae03597821ea3d5a9678c3a442"), "{msg}");
    assert!(msg.contains("cargo run -p ua-memory --bin memory-bench -- --longmemeval"), "{msg}");
    assert!(msg.contains("curl"), "{msg}");
}

#[tokio::test]
async fn embed_option_fails_fast_when_unavailable_or_model_missing() {
    let dir = tempfile::tempdir().unwrap();
    let err = ua_memory::bench::run(Options {
        kind: Kind::Fixture,
        data: None,
        limit: None,
        ids: None,
        embed: Some(EmbedOptions {
            home: dir.path().to_path_buf(),
            model: "BAAI/bge-small-en-v1.5".into(),
            no_chunks: false,
        }),
    })
    .await
    .unwrap_err();
    let msg = err.to_string();
    if ua_memory::EMBEDDINGS_ENABLED {
        assert!(msg.contains("ua memory models fetch"), "{msg}");
    } else {
        assert!(msg.contains("--features embeddings"), "{msg}");
    }
}

#[test]
fn committed_strat120_ids_file_lists_120_unique_non_abstention_ids() {
    let raw = include_str!("../bench/longmemeval-strat120-seed2145.txt");
    let ids: Vec<&str> =
        raw.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    let unique: std::collections::HashSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), 120);
    assert_eq!(unique.len(), 120);
    assert!(ids.iter().all(|id| !id.ends_with("_abs")));
}

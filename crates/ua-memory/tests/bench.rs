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
    use sha2::{Digest, Sha256};

    let raw = include_str!("../bench/longmemeval-strat120-seed2145.txt");
    let ids: Vec<&str> =
        raw.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    let unique: std::collections::HashSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), 120);
    assert_eq!(unique.len(), 120);
    assert!(ids.iter().all(|id| !id.ends_with("_abs")));
    // Pin the exact seed-2145 stratified list so swapping any ID fails CI.
    let digest = hex::encode(Sha256::digest(ids.join("\n").as_bytes()));
    assert_eq!(digest, "15c6e9acf9ed35b117f080a4bf039cf2787ccd9a477a300b8c282dd33de728ef");
}

#[cfg(feature = "embeddings")]
#[tokio::test]
async fn embed_option_fails_instead_of_silently_falling_back_on_corrupt_model() {
    // Plant right-sized sparse files so `check_local_model_presence` reports
    // `Present`, then SHA-256 verification fails at embed time and search falls
    // back to `lexical_fallback`. `--embed` must return an error, not `Ok`.
    let dir = tempfile::tempdir().unwrap();
    let spec = &ua_memory::models::BGE_SMALL_EN_V15;
    let model_dir = ua_memory::models::model_dir(dir.path(), spec);
    for f in spec.files {
        let p = model_dir.join(f.rel_path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let file = std::fs::File::create(&p).unwrap();
        file.set_len(f.size_bytes).unwrap();
    }
    let err = ua_memory::bench::run(Options {
        kind: Kind::Fixture,
        data: None,
        limit: None,
        ids: None,
        embed: Some(EmbedOptions {
            home: dir.path().to_path_buf(),
            model: spec.canonical_id.into(),
            no_chunks: false,
        }),
    })
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("--embed requested hybrid retrieval") && msg.contains("lexical_fallback"),
        "expected hard failure on lexical fallback, got: {msg}"
    );
}

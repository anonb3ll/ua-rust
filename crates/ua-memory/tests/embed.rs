//! Vector storage and the no-op embedder.

use ua_memory::embed::*;

#[test]
fn blob_round_trip_is_little_endian() {
    let v = [1.0f32, -0.5, 3.25];
    let b = to_blob(&v);
    assert_eq!(&b[0..4], &1.0f32.to_le_bytes());
    assert_eq!(from_blob(&b), v);
}

#[test]
fn cosine_basics() {
    assert!((cosine(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-6);
    assert_eq!(cosine(&[1.0, 0.0], &[0.0, 1.0]), 0.0);
    assert_eq!(cosine(&[1.0], &[1.0, 2.0]), 0.0);
    assert_eq!(cosine(&[0.0, 0.0], &[1.0, 2.0]), 0.0);
}

#[test]
fn noop_is_unavailable() {
    let e = NoopEmbedder::new("m");
    assert!(!e.available());
    assert_eq!(embed_one(&e, "x".into()).unwrap_err().category, "disabled");
}

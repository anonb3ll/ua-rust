//! The memory schema parts are released, so they are checksum-locked:
//! `ua-store` refuses a database whose recorded checksum (SHA-256 of a part's
//! `sql`) differs from the part it is given. Change the schema with a new,
//! versioned part, never by editing one of these.

use sha2::{Digest, Sha256};

#[test]
fn released_parts_keep_their_names_and_checksums() {
    let got: Vec<(&str, String)> = ua_memory::schema_parts()
        .iter()
        .map(|p| (p.name, hex::encode(Sha256::digest(p.sql.as_bytes()))))
        .collect();
    let want = [
        ("memory.v1", "b33acb6f01fbd9696f985d2f747fff80a7a9df996fbc1f099afb8f91d9d3da87"),
        ("memory_versions.v1", "75272536d9b177559d9f926926c66e10f08f26ca8477a5c02746ef0aa43b1c4b"),
        ("memory_embeddings.v1", "4dc3a332dcde0452ae852f4a33d2b93a279f4672bdf4d0c505cbfd0da7590d56"),
    ];
    let want: Vec<(&str, String)> = want.iter().map(|(n, c)| (*n, c.to_string())).collect();
    assert_eq!(got, want);
}

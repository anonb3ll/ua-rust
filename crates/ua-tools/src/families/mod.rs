//! Tool families. Each module owns its schema parts and registers its tools.
//!
//! To add a family: create `families/<name>.rs` with a `pub fn schema_parts()`
//! (if it has tables) and `pub fn register(r: &mut Registry)`, then add one
//! line to each list below. Keep the lists alphabetical to make merges easy.

pub mod core_schema;
pub mod events;
pub mod workspace;

use ua_store::SchemaPart;

use crate::registry::Registry;

pub fn schema_parts() -> Vec<SchemaPart> {
    let mut parts = vec![core_schema::SCHEMA];
    // family schema parts (alphabetical)
    let _ = &mut parts;
    parts
}

pub fn register(r: &mut Registry) {
    // family registrations (alphabetical)
    events::register(r);
    workspace::register(r);
}

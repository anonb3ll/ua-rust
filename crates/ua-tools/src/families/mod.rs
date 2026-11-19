//! Tool families. Each module owns its schema parts and registers its tools.

pub mod events;

use ua_store::SchemaPart;

use crate::registry::Registry;

pub fn schema_parts() -> Vec<SchemaPart> {
    Vec::new()
}

pub fn register(r: &mut Registry) {
    events::register(r);
}

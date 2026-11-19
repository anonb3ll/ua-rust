//! Tool families. Each module owns its schema parts and registers its tools.
//!
//! To add a family: create `families/<name>.rs` with a `pub fn schema_parts()`
//! (if it has tables) and `pub fn register(r: &mut Registry)`, then add one
//! line to each list below. Keep the lists alphabetical to make merges easy.

pub mod agents;
pub mod audit;
pub mod code;
pub mod core_schema;
pub mod cycles;
pub mod delegation;
pub mod dispatch;
pub mod events;
pub mod evidence;
pub mod export;
pub mod injection;
pub mod memory;
pub mod messaging;
pub mod notify;
pub mod observability;
pub mod plans;
pub mod routines;
pub mod sessions_lifecycle;
pub mod skills;
pub mod tasks;
pub mod tokens;
pub mod vault;
pub mod web;
pub mod workflows;
pub mod workspace;

use ua_store::SchemaPart;

use crate::registry::Registry;

pub fn schema_parts() -> Vec<SchemaPart> {
    let mut parts = vec![core_schema::SCHEMA, core_schema::SCHEMA_V2];
    // family schema parts (alphabetical)
    parts.extend(code::schema_parts());
    parts.extend(dispatch::schema_parts());
    parts.extend(memory::schema_parts());
    parts.extend(tasks::schema_parts());
    parts.extend(tokens::schema_parts());
    parts.extend(vault::schema_parts());
    parts.push(cycles::SCHEMA);
    parts.push(delegation::SCHEMA);
    parts.push(messaging::SCHEMA);
    parts.push(notify::SCHEMA);
    parts.push(plans::SCHEMA);
    parts.push(routines::SCHEMA);
    parts.push(web::SCHEMA);
    parts.push(workflows::SCHEMA);
    parts
}

pub fn register(r: &mut Registry) {
    // family registrations (alphabetical)
    agents::register(r);
    audit::register(r);
    code::register(r);
    cycles::register(r);
    delegation::register(r);
    dispatch::register(r);
    events::register(r);
    evidence::register(r);
    export::register(r);
    injection::register(r);
    memory::register(r);
    messaging::register(r);
    notify::register(r);
    observability::register(r);
    plans::register(r);
    routines::register(r);
    sessions_lifecycle::register(r);
    skills::register(r);
    tasks::register(r);
    tokens::register(r);
    vault::register(r);
    web::register(r);
    workflows::register(r);
    workspace::register(r);
}

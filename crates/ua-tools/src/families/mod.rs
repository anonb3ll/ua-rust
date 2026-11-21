//! Tool families. Each module owns its schema parts and registers its tools.
//!
//! To add a family: create `families/<name>.rs` with a `pub fn schema_parts()`
//! (if it has tables) and `pub fn register(r: &mut Registry)`, then add one
//! line to each list below. Keep the lists alphabetical to make merges easy.

pub mod agents;
pub mod audit;
pub mod capability;
pub mod code;
pub mod continuity;
pub mod core_schema;
pub mod cycles;
pub mod delegation;
pub mod dispatch;
pub mod events;
pub mod evidence;
pub mod export;
pub mod github;
pub mod governance;
pub mod graph;
pub mod harness_config;
pub mod injection;
pub mod managed_secrets;
pub mod mcp;
pub mod memory;
pub mod messaging;
pub mod node_queue;
pub mod nodes;
pub mod notify;
pub mod observability;
pub mod plans;
pub mod platform;
pub mod provider_accounts;
pub mod relay;
pub mod routines;
pub mod runs;
pub mod sessions_lifecycle;
pub mod skill_registry;
pub mod skills;
pub mod slack;
pub mod tasks;
pub mod tokens;
pub mod vault;
pub mod wake;
pub mod web;
pub mod workflows;
pub mod workspace;
pub mod zulip;

use ua_store::SchemaPart;

use crate::registry::Registry;

pub fn schema_parts() -> Vec<SchemaPart> {
    let mut parts =
        vec![core_schema::SCHEMA, core_schema::SCHEMA_V2, core_schema::SCHEMA_V3, core_schema::SCHEMA_V4];
    // family schema parts (alphabetical)
    parts.extend(code::schema_parts());
    parts.extend(continuity::schema_parts());
    parts.extend(dispatch::schema_parts());
    parts.extend(memory::schema_parts());
    parts.extend(tasks::schema_parts());
    parts.extend(tokens::schema_parts());
    parts.extend(vault::schema_parts());
    parts.push(cycles::SCHEMA);
    parts.push(delegation::SCHEMA);
    parts.push(github::SCHEMA);
    parts.push(github::HARDENING_SCHEMA);
    parts.push(governance::SCHEMA);
    parts.push(graph::SCHEMA);
    parts.push(harness_config::SCHEMA);
    parts.push(harness_config::SCHEMA_V2);
    parts.push(managed_secrets::SCHEMA);
    parts.push(mcp::SCHEMA);
    parts.push(messaging::SCHEMA);
    parts.extend(node_queue::schema_parts());
    parts.push(nodes::SCHEMA);
    parts.push(notify::SCHEMA);
    parts.push(plans::SCHEMA);
    parts.push(provider_accounts::SCHEMA);
    parts.push(relay::SCHEMA);
    parts.push(routines::SCHEMA);
    parts.push(skill_registry::SCHEMA);
    parts.push(slack::SCHEMA);
    parts.push(slack::SCHEMA_V2);
    parts.push(wake::SCHEMA);
    parts.push(wake::SCHEMA_V2);
    parts.push(web::SCHEMA);
    parts.push(workflows::SCHEMA);
    parts.push(zulip::SCHEMA);
    parts
}

pub fn register(r: &mut Registry) {
    // family registrations (alphabetical)
    agents::register(r);
    audit::register(r);
    capability::register(r);
    code::register(r);
    cycles::register(r);
    delegation::register(r);
    dispatch::register(r);
    events::register(r);
    evidence::register(r);
    export::register(r);
    github::register(r);
    governance::register(r);
    graph::register(r);
    harness_config::register(r);
    injection::register(r);
    managed_secrets::register(r);
    mcp::register(r);
    memory::register(r);
    messaging::register(r);
    node_queue::register(r);
    nodes::register(r);
    notify::register(r);
    observability::register(r);
    plans::register(r);
    provider_accounts::register(r);
    platform::register(r);
    relay::register(r);
    routines::register(r);
    runs::register(r);
    sessions_lifecycle::register(r);
    skill_registry::register(r);
    skills::register(r);
    slack::register(r);
    tasks::register(r);
    tokens::register(r);
    vault::register(r);
    wake::register(r);
    web::register(r);
    workflows::register(r);
    workspace::register(r);
    zulip::register(r);
}

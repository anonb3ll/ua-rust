//! Tools and the governed call path.
//!
//! [`Registry::call`] is the single chokepoint every adapter (MCP, HTTP, CLI,
//! UI) goes through. In order it:
//!
//! 1. finds the tool,
//! 2. checks the caller's profile exposes it (and the `action`, for
//!    consolidated `*_manage` tools),
//! 3. evaluates the approval gate: a matching one-time approval is consumed,
//!    a denial is returned, otherwise a pending approval is parked,
//! 4. validates and deserializes the arguments (unknown fields are refused),
//! 5. runs the tool.
//!
//! Refusals are written to the ledger as `agent.gateway.decision` events.

pub mod approvals;
pub mod families;
pub mod hub;
pub mod registry;
pub mod sessions;

pub use hub::Hub;
pub use registry::{Registry, ToolCtx, ToolDef, tool};

use ua_store::SchemaPart;

/// Every schema part, in application order.
pub fn schema_parts() -> Vec<SchemaPart> {
    let mut parts =
        vec![ua_store::ledger::SCHEMA, approvals::SCHEMA, sessions::SCHEMA, sessions::TOKENS_SCHEMA];
    parts.extend(families::schema_parts());
    parts
}

/// The full registry of built-in tools.
pub fn builtin_registry() -> Registry {
    let mut r = Registry::default();
    approvals::register(&mut r);
    sessions::register(&mut r);
    families::register(&mut r);
    r
}

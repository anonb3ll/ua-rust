//! Tools and the governed call path.
//!
//! [`Registry::call`] is the single chokepoint every adapter (MCP, HTTP, CLI,
//! UI) goes through. In order it:
//!
//! 1. finds the tool,
//! 2. checks the caller's profile exposes it (and the `action`, for
//!    consolidated `*_manage` tools); a policy-file profile overlay may lower
//!    an agent's profile first,
//! 3. evaluates the policy file ([`policy`]): deny, rate limit, or
//!    require_approval, failing closed when the file cannot be loaded,
//! 4. for always-gated (prod) tools, refuses anonymous network callers and
//!    revoked or unscoped agents before any approval pass is looked at,
//! 5. evaluates the approval gate: a matching one-time approval is consumed,
//!    a denial is returned, otherwise a pending approval is parked,
//! 6. validates and deserializes the arguments (unknown fields are refused),
//! 7. runs the tool.
//!
//! Refusals are written to the ledger as `agent.gateway.decision` events.

pub mod approvals;
pub mod config_revisions;
pub mod families;
pub mod hub;
pub mod policy;
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
    parts.push(config_revisions::SCHEMA);
    parts
}

/// The full registry of built-in tools.
pub fn builtin_registry() -> Registry {
    let mut r = Registry::default();
    approvals::register(&mut r);
    config_revisions::register(&mut r);
    sessions::register(&mut r);
    families::register(&mut r);
    r
}

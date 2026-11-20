//! Tools and the governed call path.
//!
//! [`Registry::call`] is the single chokepoint every adapter (MCP, HTTP, CLI,
//! UI) goes through. In order it:
//!
//! 1. finds the tool, refuses any call outside the narrow grant of a
//!    hub-internal identity that holds one (the GitHub connector's
//!    `hub-github`: see [`families::github`]), and holds a session-credential
//!    request to its grant ([`grant`]),
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
pub mod ci;
pub mod config_revisions;
pub mod families;
pub mod grant;
pub mod hub;
pub mod policy;
pub mod registry;
pub mod sessions;

pub use hub::Hub;
pub use registry::{ApprovalRequest, HandlerGate, Registry, ToolCtx, ToolDef, tool};

use ua_store::SchemaPart;

/// Every schema part, in application order.
pub fn schema_parts() -> Vec<SchemaPart> {
    let mut parts =
        vec![ua_store::ledger::SCHEMA, approvals::SCHEMA, sessions::SCHEMA, sessions::TOKENS_SCHEMA];
    parts.push(ua_store::ledger::META_SCHEMA);
    parts.extend(families::schema_parts());
    parts.push(config_revisions::SCHEMA);
    parts
}

/// Optional schema parts recognized by this build (applied only by optional
/// commands such as `ua import`, not on every `Hub::open`).
pub fn optional_schema_parts() -> Vec<SchemaPart> {
    vec![ua_store::schema::IMPORT_SCHEMA]
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

/// The built-in registry, built once per process. For code that only reads
/// the tool table (catalogs, doctors, name lists); a server that serves
/// calls holds its own [`builtin_registry`].
pub fn builtin_registry_shared() -> &'static Registry {
    static REGISTRY: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(builtin_registry)
}

#[cfg(test)]
mod profile_table_tests {
    //! The profile table (`ua-core/src/profiles.json`) names tools and
    //! consolidated actions as plain strings. These checks keep it in step
    //! with what this hub registers, so a list never carries a dead name.

    use std::collections::BTreeSet;

    use ua_core::Profile;

    use crate::families::{delegation, messaging, observability, plans};

    /// Whether the consolidated tool `tool` accepts `action` (raw, as a
    /// caller sends it), for the tools whose actions a profile lists.
    fn accepts(tool: &str, action: &str) -> bool {
        match tool {
            "coordination_manage" => messaging::COORDINATION_ACTIONS.contains(&action),
            "plan_manage" => plans::canonical_action(action).is_ok(),
            "observability_manage" => observability::canonical_action(action).is_ok(),
            "delegation_manage" => delegation::canonical_action(action).is_ok(),
            _ => false,
        }
    }

    fn registered() -> BTreeSet<&'static str> {
        crate::builtin_registry_shared().all().map(|t| t.name).collect()
    }

    #[test]
    fn every_profile_tool_name_is_registered() {
        let names = registered();
        let mut dead = Vec::new();
        for (key, list) in Profile::tool_lists() {
            dead.extend(list.iter().filter(|n| !names.contains(n.as_str())).map(|n| format!("{key}: {n}")));
        }
        assert!(dead.is_empty(), "profiles.json names tools this hub does not register: {dead:#?}");
    }

    #[test]
    fn every_consolidated_legacy_name_is_a_tool_or_an_action() {
        // A legacy name is either still registered (hidden from filtered
        // listings) or now an action of `coordination_manage`.
        let names = registered();
        let dead: Vec<&String> = Profile::consolidated_legacy_tools()
            .iter()
            .filter(|n| !names.contains(n.as_str()) && !accepts("coordination_manage", n))
            .collect();
        assert!(dead.is_empty(), "CONSOLIDATED_LEGACY_TOOLS names nothing this hub serves: {dead:#?}");
    }

    #[test]
    fn every_profile_action_is_accepted_by_a_tool_the_profile_sees() {
        let names = registered();
        let lists = Profile::action_lists();
        for (key, profile) in [
            ("RESEARCH_ALLOWED_ACTIONS", Profile::Research),
            ("REMOTE_ASSISTANT_ALLOWED_ACTIONS", Profile::RemoteAssistant),
        ] {
            let (_, actions) = lists.iter().find(|(k, _)| *k == key).expect("action list exists");
            let tools: Vec<&str> = names.iter().copied().filter(|t| profile.allows_tool(t)).collect();
            let dead: Vec<&String> =
                actions.iter().filter(|a| !tools.iter().any(|t| accepts(t, a))).collect();
            assert!(dead.is_empty(), "{key} names actions no {profile} tool accepts: {dead:#?}");
        }
        assert_eq!(lists.len(), 2, "a new action list needs a profile in this test");
    }
}

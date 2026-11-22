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
//!    an agent's profile first. A call of a tool that dispatches on an
//!    `action` is resolved through [`routes`]: when the action runs a
//!    standalone tool's handler, steps 2 to 5 also apply under that tool's
//!    name (or under `tool:action` when it has none),
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
pub mod routes;
pub mod sessions;

pub use hub::Hub;
pub use registry::{ApprovalRequest, HandlerGate, Registry, ToolCtx, ToolDef, tool};

use ua_store::{Part, SchemaPart};

/// Every schema part, in application order.
pub fn schema_parts() -> Vec<Part> {
    let mut parts: Vec<SchemaPart> = vec![
        ua_store::ledger::SCHEMA,
        approvals::SCHEMA,
        approvals::SCHEMA_V2,
        sessions::SCHEMA,
        sessions::TOKENS_SCHEMA,
    ];
    parts.push(ua_store::ledger::META_SCHEMA);
    let mut parts = ua_store::schema::parts(&parts);
    // `orgs`, the default organization and the ledger's organization columns.
    parts.push(ua_store::org::STORE_PART.into());
    parts.extend(families::schema_parts().into_iter().map(Part::from));
    // The organization column and triggers of the code family's table.
    parts.push(families::code::TENANT_PART.into());
    parts.push(families::graph::TENANT_KEYS.into());
    parts.push(families::graph::TENANT_PART.into());
    // The organization key rebuild and triggers of the web search cache table.
    parts.push(families::web::TENANT_KEYS.into());
    parts.push(families::web::TENANT_PART.into());
    // The organization key rebuild and triggers of the skill registry tables.
    parts.push(families::skill_registry::TENANT_KEYS.into());
    parts.push(families::skill_registry::TENANT_PART.into());
    // The organization key rebuild and triggers of the project repository bindings table.
    parts.push(families::governance::PROJECT_BINDINGS_TENANT_KEYS.into());
    parts.push(families::governance::PROJECT_BINDINGS_TENANT_PART.into());
    // The organization column and triggers of the notification tables (no
    // key rebuild: neither family has a key beyond an AUTOINCREMENT id).
    parts.push(families::notify::TENANT_PART.into());
    parts.push(families::notify::ORG_INDEXES.into());
    parts.push(families::zulip::TENANT_PART.into());
    // The organization key rebuild and triggers of the harness config tables.
    parts.push(families::harness_config::TENANT_KEYS.into());
    parts.push(families::harness_config::TENANT_PART.into());
    // The organization column, triggers, indexes and same-organization rules
    // of the routine and workflow-run tables (no key rebuild: their keys are
    // AUTOINCREMENT ids and hub-generated run ids).
    parts.push(families::routines::TENANT_PART.into());
    parts.push(families::routines::ORG_SCHEMA.into());
    parts.push(families::workflows::TENANT_PART.into());
    parts.push(families::workflows::ORG_SCHEMA.into());
    parts.push(config_revisions::SCHEMA.into());
    // The inbound-delivery table (`ua-ingress`), then the copy of the GitHub
    // family's delivery rows into it. Both need `organization.v1.store` and
    // the GitHub parts above.
    parts.extend(ua_ingress::inbound::schema_parts());
    parts.push(families::github::INBOUND_COPY.into());
    // Then the Slack family's replay keys and delivery ids.
    parts.push(families::slack::INBOUND_COPY.into());
    // Deliverables and their revisions (`ua-deliverables`), born
    // tenant-scoped: they need `organization.v1.store`.
    parts.extend(families::deliverables::schema_parts());
    parts
}

/// Optional schema parts recognized by this build (applied only by optional
/// commands such as `ua import`, not on every `Hub::open`).
///
/// A part that only some builds of this version apply (one gated by a Cargo
/// feature) must still be named by every build: when its feature is off, list
/// it here. Otherwise a lean build takes a database a full build of the same
/// version made for one from a newer build, and refuses it
/// ([`known_schema_part_names`]).
pub fn optional_schema_parts() -> Vec<Part> {
    vec![ua_store::schema::IMPORT_SCHEMA.into()]
}

/// Every part name this build knows: [`schema_parts`] and
/// [`optional_schema_parts`]. A database that records any other part was
/// written by a newer build, and opening it for serving or writing is refused
/// (`docs/operations.md`, "Older builds and a newer database").
pub fn known_schema_part_names() -> Vec<&'static str> {
    schema_parts().iter().chain(optional_schema_parts().iter()).map(|p| p.name).collect()
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

/// One optional Cargo feature of this build, as callers see it.
#[derive(Debug, Clone, Copy)]
pub struct BuildFeature {
    /// The Cargo feature name (`code-intel`).
    pub feature: &'static str,
    /// The key in [`build_features`] (`code_intel`).
    pub key: &'static str,
    /// Whether this build has it.
    pub enabled: bool,
    /// Tools registered only with it.
    pub tools: &'static [&'static str],
    /// What a build without it lacks.
    pub without: &'static str,
}

/// The optional Cargo features, in report order. `code-intel`,
/// `readability`, `mcp-gateway` and `mcp-server` are default features;
/// `embeddings` is off by default.
pub const BUILD_FEATURES: &[BuildFeature] = &[
    BuildFeature {
        feature: "code-intel",
        key: "code_intel",
        enabled: cfg!(feature = "code-intel"),
        tools: &["fs_index_symbols", "fs_list_symbols", "fs_search_symbols", "fs_repo_map"],
        without: "no tree-sitter symbol tools (fs_index_symbols, fs_list_symbols, fs_search_symbols, fs_repo_map)",
    },
    BuildFeature {
        feature: "readability",
        key: "readability",
        enabled: cfg!(feature = "readability"),
        tools: &[],
        without: "web_fetch and dash_view convert the whole HTML page (extraction: \"full-page\")",
    },
    BuildFeature {
        feature: "mcp-gateway",
        key: "mcp_gateway",
        enabled: cfg!(feature = "mcp-gateway"),
        tools: &["mcp_gateway"],
        without: "no downstream MCP client: no mcp_gateway tool, and mcp_server_register refuses",
    },
    BuildFeature {
        feature: "mcp-server",
        key: "mcp_server",
        enabled: cfg!(feature = "mcp-server"),
        tools: &[],
        without: "the hub serves no MCP: no /mcp route and no `ua mcp`; the JSON API at /api remains",
    },
    BuildFeature {
        feature: "slack-socket",
        key: "slack_socket",
        enabled: cfg!(feature = "slack-socket"),
        tools: &[],
        without: "no Slack Socket Mode: Slack reaches the hub only through the signed HTTP routes, which need a public URL",
    },
    BuildFeature {
        feature: "embeddings",
        key: "embeddings",
        enabled: ua_memory::EMBEDDINGS_ENABLED,
        tools: &[],
        without: "memory search is lexical (FTS5) only",
    },
];

/// Which optional Cargo features this build has, keyed by
/// [`BuildFeature::key`]: `{code_intel, readability, mcp_gateway, mcp_server,
/// slack_socket, embeddings}`.
pub fn build_features() -> serde_json::Value {
    serde_json::Value::Object(BUILD_FEATURES.iter().map(|f| (f.key.to_string(), f.enabled.into())).collect())
}

/// Tools this build does not register because a feature is off, with the
/// Cargo feature that adds each.
pub fn compiled_out_tools() -> impl Iterator<Item = (&'static str, &'static str)> {
    BUILD_FEATURES.iter().filter(|f| !f.enabled).flat_map(|f| f.tools.iter().map(move |t| (*t, f.feature)))
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
        // profiles.json is one table for every build: a tool a disabled
        // feature leaves out still counts, as long as BUILD_FEATURES names it.
        let names = registered();
        let compiled_out: BTreeSet<&str> = crate::compiled_out_tools().map(|(t, _)| t).collect();
        let mut dead = Vec::new();
        for (key, list) in Profile::tool_lists() {
            dead.extend(
                list.iter()
                    .filter(|n| !names.contains(n.as_str()) && !compiled_out.contains(n.as_str()))
                    .map(|n| format!("{key}: {n}")),
            );
        }
        assert!(dead.is_empty(), "profiles.json names tools this hub does not register: {dead:#?}");
    }

    #[test]
    fn build_features_name_exactly_the_tools_they_gate() {
        // A feature's tools are registered when it is on and absent when it
        // is off, so compiled_out_tools() and the catalog stay truthful.
        let names = registered();
        for f in crate::BUILD_FEATURES {
            for t in f.tools {
                assert_eq!(
                    names.contains(t),
                    f.enabled,
                    "{t} (feature {}, enabled {})",
                    f.feature,
                    f.enabled
                );
            }
        }
        let report = crate::build_features();
        let keys: Vec<&str> = report.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys.len(), crate::BUILD_FEATURES.len());
        for k in ["code_intel", "readability", "mcp_gateway", "mcp_server", "embeddings"] {
            assert!(report[k].is_boolean(), "{k}: {report}");
        }
        assert_eq!(report["code_intel"], cfg!(feature = "code-intel"));
        assert_eq!(report["mcp_gateway"], cfg!(feature = "mcp-gateway"));
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

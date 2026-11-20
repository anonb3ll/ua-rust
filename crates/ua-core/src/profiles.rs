//! Session profiles: capability overlays that decide which tools a session sees.
//!
//! A profile is not an identity. It is bound to the verified identity plus the
//! client session, and is chosen by the hub, never by prompt text. Deny-list
//! profiles (`developer`, `lead`, `reviewer`) keep new tools reachable until
//! someone denies them; allow-list profiles (`research`, `operator`, `public`,
//! the remote profiles) cannot be widened by registering a new tool.
//!
//! The tool lists are data (`profiles.json`), carried over from the original
//! implementation so the contracts match.
//!
//! Profile names are capability tiers. The original implementation used other
//! names for five of them; those names are accepted as aliases wherever a
//! profile name is parsed (see [`Profile::LEGACY_ALIASES`]), and every output
//! uses the current name.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    Developer,
    /// The developer surface plus review and verification tools.
    #[serde(alias = "cto")]
    Lead,
    /// Reads and reviews; cannot write files, claim work or delegate.
    #[serde(alias = "steward")]
    Reviewer,
    /// Every tool; the identity that holds config authority.
    #[serde(alias = "chief-of-staff")]
    Coordinator,
    Operator,
    Research,
    Public,
    /// A remote assistant: memory reads, messages and task listing.
    #[serde(alias = "cloud-assistant")]
    RemoteAssistant,
    /// The remote assistant surface plus vault access confined to `Wiki/`.
    #[serde(alias = "cloud-vault-steward")]
    RemoteVaultCurator,
    AcpSession,
}

impl Profile {
    pub const ALL: [Profile; 10] = [
        Profile::Developer,
        Profile::Lead,
        Profile::Reviewer,
        Profile::Coordinator,
        Profile::Operator,
        Profile::Research,
        Profile::Public,
        Profile::RemoteAssistant,
        Profile::RemoteVaultCurator,
        Profile::AcpSession,
    ];

    /// Names the original implementation used, accepted when parsing a
    /// profile name for compatibility with its configuration and data.
    pub const LEGACY_ALIASES: [(&'static str, Profile); 5] = [
        ("cto", Profile::Lead),
        ("steward", Profile::Reviewer),
        ("chief-of-staff", Profile::Coordinator),
        ("cloud-assistant", Profile::RemoteAssistant),
        ("cloud-vault-steward", Profile::RemoteVaultCurator),
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Developer => "developer",
            Profile::Lead => "lead",
            Profile::Reviewer => "reviewer",
            Profile::Coordinator => "coordinator",
            Profile::Operator => "operator",
            Profile::Research => "research",
            Profile::Public => "public",
            Profile::RemoteAssistant => "remote-assistant",
            Profile::RemoteVaultCurator => "remote-vault-curator",
            Profile::AcpSession => "acp-session",
        }
    }

    /// Whether the profile may be assigned to an identity: activated with
    /// `profile_activate`, named in `profiles`, `oauth_profile` or a policy
    /// `profile_defaults` / overlay entry. `acp-session` is not: only a
    /// verified session credential runs under it, and only with its grant.
    pub fn assignable(self) -> bool {
        self != Profile::AcpSession
    }

    /// Parse `name` as a profile an identity may be given (see
    /// [`Profile::assignable`]).
    pub fn parse_assignable(name: &str) -> Result<Profile, String> {
        let p: Profile = name.parse()?;
        if !p.assignable() {
            return Err(format!(
                "profile {p} is reserved for session credentials and cannot be activated or configured"
            ));
        }
        Ok(p)
    }

    /// The legacy alias of this profile, if it had another name.
    pub fn legacy_alias(self) -> Option<&'static str> {
        Self::LEGACY_ALIASES.iter().find(|(_, p)| *p == self).map(|(n, _)| *n)
    }

    /// The current name for `name` when it is a profile name or a legacy
    /// alias, else `None`.
    pub fn canonical_name(name: &str) -> Option<&'static str> {
        name.parse::<Profile>().ok().map(Profile::as_str)
    }

    /// Privilege rank used for activation: an agent may switch only to a
    /// profile ranked no higher than its default. Humans may go higher.
    pub fn rank(self) -> u8 {
        match self {
            Profile::Public => 0,
            Profile::RemoteAssistant => 1,
            Profile::RemoteVaultCurator => 2,
            Profile::Research => 3,
            Profile::AcpSession => 3,
            Profile::Operator => 4,
            Profile::Reviewer => 5,
            Profile::Developer => 6,
            Profile::Lead => 7,
            Profile::Coordinator => 8,
        }
    }

    /// Whether the profile exposes `tool`.
    pub fn allows_tool(self, tool: &str) -> bool {
        let s = &*SETS;
        match self {
            Profile::Coordinator => true,
            Profile::Developer => !s.developer_denied.contains(tool),
            Profile::Lead => s.lead_extra.contains(tool) || !s.developer_denied.contains(tool),
            Profile::Reviewer => !s.reviewer_denied.contains(tool),
            Profile::Operator => s.operator_allowed.contains(tool),
            Profile::Research => s.research_allowed.contains(tool),
            Profile::Public => s.public_allowed.contains(tool),
            Profile::RemoteAssistant => s.remote_assistant_allowed.contains(tool),
            Profile::RemoteVaultCurator => s.remote_vault_curator_allowed.contains(tool),
            // A session credential for one claimed ACP node item: a fixed
            // read/report set, narrowed further by the credential's grant.
            Profile::AcpSession => s.acp_session_allowed.contains(tool),
        }
    }

    /// Whether the profile may run `action` of a consolidated `*_manage` tool.
    /// Deny-list profiles may run every action of a tool they can see.
    pub fn allows_action(self, tool: &str, action: &str) -> bool {
        if !self.allows_tool(tool) {
            return false;
        }
        let s = &*SETS;
        match self {
            Profile::Research => s.research_actions.contains(action),
            // No consolidated manager is in the set; `task_comment`'s
            // actions are scoped to the bound task by the session grant.
            Profile::AcpSession => true,
            Profile::RemoteAssistant | Profile::RemoteVaultCurator => {
                s.remote_assistant_actions.contains(action)
            }
            Profile::Public => false,
            _ => true,
        }
    }

    /// Legacy tool names superseded by a consolidated manager. Hidden from
    /// profile-filtered listings, still callable by unfiltered local clients.
    pub fn is_legacy_alias(tool: &str) -> bool {
        SETS.consolidated_legacy.contains(tool)
    }

    /// Every tool-name list in the profile table, keyed as in `profiles.json`.
    /// For consistency checks against the tool registry.
    pub fn tool_lists() -> Vec<(&'static str, &'static BTreeSet<String>)> {
        let s = &*SETS;
        vec![
            ("DEVELOPER_DENIED_TOOLS", &s.developer_denied),
            ("LEAD_EXTRA_TOOLS", &s.lead_extra),
            ("REVIEWER_DENIED_TOOLS", &s.reviewer_denied),
            ("RESEARCH_ALLOWED_TOOLS", &s.research_allowed),
            ("OPERATOR_ALLOWED_TOOLS", &s.operator_allowed),
            ("PUBLIC_ALLOWED_TOOLS", &s.public_allowed),
            ("REMOTE_ASSISTANT_ALLOWED_TOOLS", &s.remote_assistant_allowed),
            ("REMOTE_VAULT_CURATOR_ALLOWED_TOOLS", &s.remote_vault_curator_allowed),
            ("ACP_SESSION_ALLOWED_TOOLS", &s.acp_session_allowed),
        ]
    }

    /// Every action-name list in the profile table, keyed as in `profiles.json`.
    pub fn action_lists() -> Vec<(&'static str, &'static BTreeSet<String>)> {
        let s = &*SETS;
        vec![
            ("RESEARCH_ALLOWED_ACTIONS", &s.research_actions),
            ("REMOTE_ASSISTANT_ALLOWED_ACTIONS", &s.remote_assistant_actions),
        ]
    }

    /// The `CONSOLIDATED_LEGACY_TOOLS` list.
    pub fn consolidated_legacy_tools() -> &'static BTreeSet<String> {
        &SETS.consolidated_legacy
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Profile {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Profile::ALL
            .into_iter()
            .find(|p| p.as_str() == s)
            .or_else(|| Profile::LEGACY_ALIASES.iter().find(|(n, _)| *n == s).map(|(_, p)| *p))
            .ok_or_else(|| format!("unknown profile {s:?}"))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
struct RawSets {
    developer_denied_tools: BTreeSet<String>,
    lead_extra_tools: BTreeSet<String>,
    reviewer_denied_tools: BTreeSet<String>,
    research_allowed_tools: BTreeSet<String>,
    operator_allowed_tools: BTreeSet<String>,
    public_allowed_tools: BTreeSet<String>,
    remote_assistant_allowed_tools: BTreeSet<String>,
    remote_vault_curator_allowed_tools: BTreeSet<String>,
    acp_session_allowed_tools: BTreeSet<String>,
    research_allowed_actions: BTreeSet<String>,
    remote_assistant_allowed_actions: BTreeSet<String>,
    consolidated_legacy_tools: BTreeSet<String>,
}

struct Sets {
    developer_denied: BTreeSet<String>,
    lead_extra: BTreeSet<String>,
    reviewer_denied: BTreeSet<String>,
    research_allowed: BTreeSet<String>,
    operator_allowed: BTreeSet<String>,
    public_allowed: BTreeSet<String>,
    remote_assistant_allowed: BTreeSet<String>,
    remote_vault_curator_allowed: BTreeSet<String>,
    acp_session_allowed: BTreeSet<String>,
    research_actions: BTreeSet<String>,
    remote_assistant_actions: BTreeSet<String>,
    consolidated_legacy: BTreeSet<String>,
}

static SETS: LazyLock<Sets> = LazyLock::new(|| {
    let raw: RawSets = serde_json::from_str(include_str!("profiles.json")).expect("profiles.json is valid");
    Sets {
        developer_denied: raw.developer_denied_tools,
        lead_extra: raw.lead_extra_tools,
        reviewer_denied: raw.reviewer_denied_tools,
        research_allowed: raw.research_allowed_tools,
        operator_allowed: raw.operator_allowed_tools,
        public_allowed: raw.public_allowed_tools,
        remote_assistant_allowed: raw.remote_assistant_allowed_tools,
        remote_vault_curator_allowed: raw.remote_vault_curator_allowed_tools,
        acp_session_allowed: raw.acp_session_allowed_tools,
        research_actions: raw.research_allowed_actions,
        remote_assistant_actions: raw.remote_assistant_allowed_actions,
        consolidated_legacy: raw.consolidated_legacy_tools,
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_and_allow_lists() {
        assert!(Profile::Developer.allows_tool("task_add"));
        assert!(!Profile::Developer.allows_tool("approval_resolve"));
        assert!(Profile::Developer.allows_tool("some_tool_added_later"));
        assert!(Profile::Lead.allows_tool("event_log_verify"));
        assert!(!Profile::Developer.allows_tool("profile_activate"));
        assert!(Profile::Lead.allows_tool("some_tool_added_later"));
        assert!(!Profile::Lead.allows_tool("approval_resolve"));
        assert!(!Profile::Reviewer.allows_tool("fs_write"));
        assert!(Profile::Reviewer.allows_tool("fs_read"));
        assert!(Profile::Operator.allows_tool("approval_resolve"));
        assert!(!Profile::Operator.allows_tool("some_tool_added_later"));
        assert!(Profile::Public.allows_tool("task_add"));
        assert!(!Profile::Public.allows_tool("memory_search"));
        assert!(!Profile::Research.allows_tool("run_cmd"));
        assert!(Profile::Coordinator.allows_tool("anything"));
        assert!(Profile::AcpSession.allows_tool("task_comment"));
        assert!(!Profile::AcpSession.allows_tool("task_add"));
        assert!(!Profile::AcpSession.allows_tool("profile_activate"));
        // A node session credential must not read other agents' notes or
        // write notes in its owner's name.
        for t in ["memory_get", "memory_list", "memory_save", "memory_search"] {
            assert!(!Profile::AcpSession.allows_tool(t), "{t}");
        }
    }

    #[test]
    fn acp_session_is_not_assignable() {
        assert!(!Profile::AcpSession.assignable());
        assert!(Profile::parse_assignable("acp-session").is_err());
        for p in Profile::ALL.into_iter().filter(|p| *p != Profile::AcpSession) {
            assert_eq!(Profile::parse_assignable(p.as_str()), Ok(p));
        }
        assert_eq!(Profile::parse_assignable("cto"), Ok(Profile::Lead));
    }

    #[test]
    fn only_profiles_meant_to_speak_publicly_see_the_relay() {
        for p in [Profile::Developer, Profile::Lead, Profile::Reviewer, Profile::Research, Profile::Public] {
            assert!(!p.allows_tool("relay_manage"), "{p} must not see relay_manage");
        }
        assert!(Profile::Coordinator.allows_tool("relay_manage"));
    }

    #[test]
    fn migration_manifests_are_denied_to_developer_and_lead() {
        for tool in ["export_migration_manifest", "compare_migration_manifests"] {
            assert!(!Profile::Developer.allows_tool(tool), "developer must not see {tool}");
            // Lead inherits the developer deny list.
            assert!(!Profile::Lead.allows_tool(tool), "lead must not see {tool}");
            assert!(!Profile::Reviewer.allows_tool(tool), "reviewer must not see {tool}");
            assert!(Profile::Coordinator.allows_tool(tool), "coordinator must see {tool}");
        }
        // The plain exports stay available to developers.
        assert!(Profile::Developer.allows_tool("export_data"));
    }

    #[test]
    fn only_profiles_meant_to_speak_publicly_can_send_to_zulip() {
        for tool in ["zulip_send_message", "zulip_resolve_send"] {
            for p in Profile::ALL.into_iter().filter(|p| *p != Profile::Coordinator) {
                assert!(!p.allows_tool(tool), "{p} must not see {tool}");
            }
            assert!(Profile::Coordinator.allows_tool(tool));
        }
    }

    #[test]
    fn names_round_trip() {
        for p in Profile::ALL {
            assert_eq!(p.as_str().parse::<Profile>().unwrap(), p);
            assert_eq!(p.to_string(), p.as_str());
        }
    }

    #[test]
    fn legacy_names_parse_to_the_current_profile() {
        for (old, p) in Profile::LEGACY_ALIASES {
            assert_eq!(old.parse::<Profile>().unwrap(), p);
            assert_eq!(Profile::canonical_name(old), Some(p.as_str()));
            assert_eq!(p.legacy_alias(), Some(old));
            assert_ne!(p.as_str(), old, "an alias is not the current name");
            let via_serde: Profile = serde_json::from_value(serde_json::json!(old)).unwrap();
            assert_eq!(via_serde, p);
            assert_eq!(serde_json::to_value(p).unwrap(), serde_json::json!(p.as_str()));
        }
        assert_eq!(Profile::Developer.legacy_alias(), None);
        assert!("nobody".parse::<Profile>().is_err());
        assert_eq!(Profile::canonical_name("nobody"), None);
    }

    #[test]
    fn profile_table_lists_every_profile() {
        let raw: serde_json::Value = serde_json::from_str(include_str!("profiles.json")).unwrap();
        let listed: BTreeSet<&str> =
            raw["VALID_PROFILES"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        let known: BTreeSet<&str> = Profile::ALL.iter().map(|p| p.as_str()).collect();
        assert_eq!(listed, known);
    }
}

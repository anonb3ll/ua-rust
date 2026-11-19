//! Session profiles: capability overlays that decide which tools a session sees.
//!
//! A profile is not an identity. It is bound to the verified identity plus the
//! client session, and is chosen by the hub, never by prompt text. Deny-list
//! profiles (`developer`, `cto`, `steward`) keep new tools reachable until
//! someone denies them; allow-list profiles (`research`, `operator`, `public`,
//! the cloud profiles) cannot be widened by registering a new tool.
//!
//! The tool lists are data (`profiles.json`), carried over from the original
//! implementation so the contracts match.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    Developer,
    Cto,
    Steward,
    ChiefOfStaff,
    Operator,
    Research,
    Public,
    CloudAssistant,
    CloudVaultSteward,
    AcpSession,
}

impl Profile {
    pub const ALL: [Profile; 10] = [
        Profile::Developer,
        Profile::Cto,
        Profile::Steward,
        Profile::ChiefOfStaff,
        Profile::Operator,
        Profile::Research,
        Profile::Public,
        Profile::CloudAssistant,
        Profile::CloudVaultSteward,
        Profile::AcpSession,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Developer => "developer",
            Profile::Cto => "cto",
            Profile::Steward => "steward",
            Profile::ChiefOfStaff => "chief-of-staff",
            Profile::Operator => "operator",
            Profile::Research => "research",
            Profile::Public => "public",
            Profile::CloudAssistant => "cloud-assistant",
            Profile::CloudVaultSteward => "cloud-vault-steward",
            Profile::AcpSession => "acp-session",
        }
    }

    /// Privilege rank used for activation: an agent may switch only to a
    /// profile ranked no higher than its default. Humans may go higher.
    pub fn rank(self) -> u8 {
        match self {
            Profile::Public => 0,
            Profile::CloudAssistant => 1,
            Profile::CloudVaultSteward => 2,
            Profile::Research => 3,
            Profile::AcpSession => 3,
            Profile::Operator => 4,
            Profile::Steward => 5,
            Profile::Developer => 6,
            Profile::Cto => 7,
            Profile::ChiefOfStaff => 8,
        }
    }

    /// Whether the profile exposes `tool`.
    pub fn allows_tool(self, tool: &str) -> bool {
        let s = &*SETS;
        match self {
            Profile::ChiefOfStaff => true,
            Profile::Developer => !s.developer_denied.contains(tool),
            Profile::Cto => s.cto_extra.contains(tool) || !s.developer_denied.contains(tool),
            Profile::Steward => !s.steward_denied.contains(tool),
            Profile::Operator => s.operator_allowed.contains(tool),
            Profile::Research => s.research_allowed.contains(tool),
            Profile::Public => s.public_allowed.contains(tool),
            Profile::CloudAssistant => s.cloud_assistant_allowed.contains(tool),
            Profile::CloudVaultSteward => s.cloud_vault_steward_allowed.contains(tool),
            // An ACP session runs one delegated task: the research surface.
            Profile::AcpSession => s.research_allowed.contains(tool),
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
            Profile::Research | Profile::AcpSession => s.research_actions.contains(action),
            Profile::CloudAssistant | Profile::CloudVaultSteward => {
                s.cloud_assistant_actions.contains(action)
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
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Profile {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Profile::ALL.into_iter().find(|p| p.as_str() == s).ok_or_else(|| format!("unknown profile {s:?}"))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
struct RawSets {
    developer_denied_tools: BTreeSet<String>,
    cto_extra_tools: BTreeSet<String>,
    steward_denied_tools: BTreeSet<String>,
    research_allowed_tools: BTreeSet<String>,
    operator_allowed_tools: BTreeSet<String>,
    public_allowed_tools: BTreeSet<String>,
    cloud_assistant_allowed_tools: BTreeSet<String>,
    cloud_vault_steward_allowed_tools: BTreeSet<String>,
    research_allowed_actions: BTreeSet<String>,
    cloud_assistant_allowed_actions: BTreeSet<String>,
    consolidated_legacy_tools: BTreeSet<String>,
}

struct Sets {
    developer_denied: BTreeSet<String>,
    cto_extra: BTreeSet<String>,
    steward_denied: BTreeSet<String>,
    research_allowed: BTreeSet<String>,
    operator_allowed: BTreeSet<String>,
    public_allowed: BTreeSet<String>,
    cloud_assistant_allowed: BTreeSet<String>,
    cloud_vault_steward_allowed: BTreeSet<String>,
    research_actions: BTreeSet<String>,
    cloud_assistant_actions: BTreeSet<String>,
    consolidated_legacy: BTreeSet<String>,
}

static SETS: LazyLock<Sets> = LazyLock::new(|| {
    let raw: RawSets = serde_json::from_str(include_str!("profiles.json")).expect("profiles.json is valid");
    Sets {
        developer_denied: raw.developer_denied_tools,
        cto_extra: raw.cto_extra_tools,
        steward_denied: raw.steward_denied_tools,
        research_allowed: raw.research_allowed_tools,
        operator_allowed: raw.operator_allowed_tools,
        public_allowed: raw.public_allowed_tools,
        cloud_assistant_allowed: raw.cloud_assistant_allowed_tools,
        cloud_vault_steward_allowed: raw.cloud_vault_steward_allowed_tools,
        research_actions: raw.research_allowed_actions,
        cloud_assistant_actions: raw.cloud_assistant_allowed_actions,
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
        assert!(Profile::Cto.allows_tool("review_and_notify"));
        assert!(!Profile::Cto.allows_tool("approval_resolve"));
        assert!(Profile::Operator.allows_tool("approval_resolve"));
        assert!(!Profile::Operator.allows_tool("some_tool_added_later"));
        assert!(Profile::Public.allows_tool("task_add"));
        assert!(!Profile::Public.allows_tool("memory_search"));
        assert!(!Profile::Research.allows_tool("run_cmd"));
        assert!(Profile::ChiefOfStaff.allows_tool("anything"));
    }

    #[test]
    fn names_round_trip() {
        for p in Profile::ALL {
            assert_eq!(p.as_str().parse::<Profile>().unwrap(), p);
        }
    }
}

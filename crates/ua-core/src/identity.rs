//! Who is calling.

use serde::{Deserialize, Serialize};

use crate::org::DEFAULT_ORG;

use crate::profiles::Profile;

/// What kind of principal a verified identity is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// An AI agent or automated worker.
    Agent,
    /// A human operator. Only humans resolve approvals or issue tokens.
    Human,
    /// The hub itself (schedulers, reapers).
    System,
    /// No verified credential (stdio, or HTTP with auth not enforced).
    Anonymous,
}

/// Which adapter a call came through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Stdio,
    Http,
    Mcp,
    Cli,
    Ui,
    Internal,
    /// The signed Slack routes (`/api/slack/*`): a person typing in Slack,
    /// mapped to a human identity by `slack_identities`. Never treated as
    /// more trusted than `Http`; it is not a browser or passkey session.
    Slack,
}

/// The verified caller of one tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Caller {
    /// Identity label, e.g. `builder-1`. For anonymous callers this is the
    /// configured local default.
    pub label: String,
    pub kind: ActorKind,
    /// Active capability overlay.
    pub profile: Profile,
    /// Whether the profile filter is enforced. Stdio and unauthenticated HTTP
    /// keep the full surface so a local IDE process is not silently reduced.
    pub enforce_profile: bool,
    /// Client session key, when the client supplied one.
    pub session_key: Option<String>,
    pub transport: Transport,
    /// The organization the caller acts in. Always [`DEFAULT_ORG`] until
    /// memberships exist (`docs/organization.md`); nothing reads it for
    /// authority yet. Missing in serialized form means the default.
    #[serde(default = "default_org")]
    pub org_id: String,
}

fn default_org() -> String {
    DEFAULT_ORG.to_string()
}

/// The label of an unauthenticated local caller that configured none. It
/// names nobody: every such caller shares it.
pub const LOCAL_LABEL: &str = "local";

impl Caller {
    /// A local, unauthenticated caller with the full tool surface.
    pub fn local(label: impl Into<String>, transport: Transport) -> Self {
        Self {
            label: label.into(),
            kind: ActorKind::Anonymous,
            profile: Profile::Developer,
            enforce_profile: false,
            session_key: None,
            transport,
            org_id: DEFAULT_ORG.into(),
        }
    }

    /// The hub acting on its own behalf, in the default organization (hub
    /// maintenance runs there). There is no organization-free caller.
    pub fn system() -> Self {
        Self::system_for(DEFAULT_ORG)
    }

    /// The hub acting for organization `org_id`: a system job working on
    /// that organization's rows (`docs/organization.md`, Decisions).
    pub fn system_for(org_id: impl Into<String>) -> Self {
        Self {
            label: "system".into(),
            kind: ActorKind::System,
            profile: Profile::Coordinator,
            enforce_profile: false,
            session_key: None,
            transport: Transport::Internal,
            org_id: org_id.into(),
        }
    }

    pub fn is_human(&self) -> bool {
        self.kind == ActorKind::Human
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_caller_has_an_organization() {
        assert_eq!(Caller::system().org_id, DEFAULT_ORG);
        assert_eq!(Caller::local("builder-1", Transport::Stdio).org_id, DEFAULT_ORG);
        let job = Caller::system_for("org-b");
        assert_eq!(
            (job.org_id.as_str(), job.label.as_str(), job.kind),
            ("org-b", "system", ActorKind::System)
        );
    }

    #[test]
    fn a_serialized_caller_without_org_id_reads_as_the_default() {
        let mut v = serde_json::to_value(Caller::local("builder-1", Transport::Http)).unwrap();
        assert_eq!(v["org_id"], DEFAULT_ORG);
        v.as_object_mut().unwrap().remove("org_id");
        let back: Caller = serde_json::from_value(v).unwrap();
        assert_eq!(back.org_id, DEFAULT_ORG);
    }
}

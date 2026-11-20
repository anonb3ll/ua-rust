//! Who is calling.

use serde::{Deserialize, Serialize};

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
}

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
        }
    }

    /// The hub acting on its own behalf.
    pub fn system() -> Self {
        Self {
            label: "system".into(),
            kind: ActorKind::System,
            profile: Profile::Coordinator,
            enforce_profile: false,
            session_key: None,
            transport: Transport::Internal,
        }
    }

    pub fn is_human(&self) -> bool {
        self.kind == ActorKind::Human
    }
}

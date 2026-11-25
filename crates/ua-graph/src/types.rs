//! Closed node/edge kinds, endpoint-kind matrix, validated provenance, and
//! temporal normalization (`docs/graph.md`).

use std::fmt;

use serde::{Deserialize, Serialize};
use ua_core::time::{format_ts, parse_ts};
use ua_core::{UaError, UaResult};

/// Maximum UTF-8 byte length of `graph_nodes.external_id`.
pub const EXTERNAL_ID_MAX_BYTES: usize = 256;
/// Maximum UTF-8 byte length of `graph_nodes.display_label`.
pub const DISPLAY_LABEL_MAX_BYTES: usize = 256;
/// Maximum UTF-8 byte length of `graph_nodes.meta_json`.
pub const NODE_META_MAX_BYTES: usize = 8_192;
/// Maximum UTF-8 byte length of `graph_edges.meta_json`.
pub const EDGE_META_MAX_BYTES: usize = 4_096;
/// Maximum UTF-8 byte length of `graph_edges.assertion_scope`.
pub const ASSERTION_SCOPE_MAX_BYTES: usize = 128;
/// Maximum UTF-8 byte length of `asserted_by` (`PrincipalId`).
pub const PRINCIPAL_ID_MAX_BYTES: usize = 128;
/// Maximum UTF-8 byte length of `source_ref`.
pub const SOURCE_REF_MAX_BYTES: usize = 256;

/// Closed set of `graph_nodes.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Agent,
    Person,
    Skill,
    MemoryNote,
    MemoryEntity,
    Task,
    Goal,
    Plan,
    Run,
    Deliverable,
    VaultNote,
    Approval,
    PolicyRevision,
}

impl NodeKind {
    pub const ALL: [NodeKind; 13] = [
        NodeKind::Agent,
        NodeKind::Person,
        NodeKind::Skill,
        NodeKind::MemoryNote,
        NodeKind::MemoryEntity,
        NodeKind::Task,
        NodeKind::Goal,
        NodeKind::Plan,
        NodeKind::Run,
        NodeKind::Deliverable,
        NodeKind::VaultNote,
        NodeKind::Approval,
        NodeKind::PolicyRevision,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            NodeKind::Agent => "agent",
            NodeKind::Person => "person",
            NodeKind::Skill => "skill",
            NodeKind::MemoryNote => "memory_note",
            NodeKind::MemoryEntity => "memory_entity",
            NodeKind::Task => "task",
            NodeKind::Goal => "goal",
            NodeKind::Plan => "plan",
            NodeKind::Run => "run",
            NodeKind::Deliverable => "deliverable",
            NodeKind::VaultNote => "vault_note",
            NodeKind::Approval => "approval",
            NodeKind::PolicyRevision => "policy_revision",
        }
    }

    pub fn parse(raw: &str) -> UaResult<Self> {
        match raw.trim() {
            "agent" => Ok(Self::Agent),
            "person" => Ok(Self::Person),
            "skill" => Ok(Self::Skill),
            "memory_note" => Ok(Self::MemoryNote),
            "memory_entity" => Ok(Self::MemoryEntity),
            "task" => Ok(Self::Task),
            "goal" => Ok(Self::Goal),
            "plan" => Ok(Self::Plan),
            "run" => Ok(Self::Run),
            "deliverable" => Ok(Self::Deliverable),
            "vault_note" => Ok(Self::VaultNote),
            "approval" => Ok(Self::Approval),
            "policy_revision" => Ok(Self::PolicyRevision),
            other => Err(UaError::invalid(format!("unknown graph node kind {other:?}"))),
        }
    }
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Closed set of `graph_edges.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    DependsOn,
    SubtaskOf,
    ServesGoal,
    GoalParent,
    PlanTracks,
    DelegatedTo,
    Executes,
    ExecutedBy,
    Produces,
    UsesSkill,
    ReviewedBy,
    ApprovedBy,
    GovernedBy,
    DelegatesTo,
    Reviews,
    EscalatesTo,
    CanObserve,
    Mentions,
    LinksTo,
    PromotedFrom,
    Supersedes,
    Contradicts,
    Evidence,
    Extends,
    Derives,
}

impl EdgeKind {
    pub const ALL: [EdgeKind; 25] = [
        EdgeKind::DependsOn,
        EdgeKind::SubtaskOf,
        EdgeKind::ServesGoal,
        EdgeKind::GoalParent,
        EdgeKind::PlanTracks,
        EdgeKind::DelegatedTo,
        EdgeKind::Executes,
        EdgeKind::ExecutedBy,
        EdgeKind::Produces,
        EdgeKind::UsesSkill,
        EdgeKind::ReviewedBy,
        EdgeKind::ApprovedBy,
        EdgeKind::GovernedBy,
        EdgeKind::DelegatesTo,
        EdgeKind::Reviews,
        EdgeKind::EscalatesTo,
        EdgeKind::CanObserve,
        EdgeKind::Mentions,
        EdgeKind::LinksTo,
        EdgeKind::PromotedFrom,
        EdgeKind::Supersedes,
        EdgeKind::Contradicts,
        EdgeKind::Evidence,
        EdgeKind::Extends,
        EdgeKind::Derives,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            EdgeKind::DependsOn => "depends_on",
            EdgeKind::SubtaskOf => "subtask_of",
            EdgeKind::ServesGoal => "serves_goal",
            EdgeKind::GoalParent => "goal_parent",
            EdgeKind::PlanTracks => "plan_tracks",
            EdgeKind::DelegatedTo => "delegated_to",
            EdgeKind::Executes => "executes",
            EdgeKind::ExecutedBy => "executed_by",
            EdgeKind::Produces => "produces",
            EdgeKind::UsesSkill => "uses_skill",
            EdgeKind::ReviewedBy => "reviewed_by",
            EdgeKind::ApprovedBy => "approved_by",
            EdgeKind::GovernedBy => "governed_by",
            EdgeKind::DelegatesTo => "delegates_to",
            EdgeKind::Reviews => "reviews",
            EdgeKind::EscalatesTo => "escalates_to",
            EdgeKind::CanObserve => "can_observe",
            EdgeKind::Mentions => "mentions",
            EdgeKind::LinksTo => "links_to",
            EdgeKind::PromotedFrom => "promoted_from",
            EdgeKind::Supersedes => "supersedes",
            EdgeKind::Contradicts => "contradicts",
            EdgeKind::Evidence => "evidence",
            EdgeKind::Extends => "extends",
            EdgeKind::Derives => "derives",
        }
    }

    pub fn parse(raw: &str) -> UaResult<Self> {
        match raw.trim() {
            "depends_on" => Ok(Self::DependsOn),
            "subtask_of" => Ok(Self::SubtaskOf),
            "serves_goal" => Ok(Self::ServesGoal),
            "goal_parent" => Ok(Self::GoalParent),
            "plan_tracks" => Ok(Self::PlanTracks),
            "delegated_to" => Ok(Self::DelegatedTo),
            "executes" => Ok(Self::Executes),
            "executed_by" => Ok(Self::ExecutedBy),
            "produces" => Ok(Self::Produces),
            "uses_skill" => Ok(Self::UsesSkill),
            "reviewed_by" => Ok(Self::ReviewedBy),
            "approved_by" => Ok(Self::ApprovedBy),
            "governed_by" => Ok(Self::GovernedBy),
            "delegates_to" => Ok(Self::DelegatesTo),
            "reviews" => Ok(Self::Reviews),
            "escalates_to" => Ok(Self::EscalatesTo),
            "can_observe" => Ok(Self::CanObserve),
            "mentions" => Ok(Self::Mentions),
            "links_to" => Ok(Self::LinksTo),
            "promoted_from" => Ok(Self::PromotedFrom),
            "supersedes" => Ok(Self::Supersedes),
            "contradicts" => Ok(Self::Contradicts),
            "evidence" => Ok(Self::Evidence),
            "extends" => Ok(Self::Extends),
            "derives" => Ok(Self::Derives),
            other => Err(UaError::invalid(format!("unknown graph edge kind {other:?}"))),
        }
    }

    /// Whether `(src, dst)` satisfies the allowed `Source -> Target` pair in
    /// `docs/graph.md` (Typed edge kinds).
    pub const fn allowed_endpoints(self, src: NodeKind, dst: NodeKind) -> bool {
        use NodeKind::*;
        match self {
            EdgeKind::DependsOn => matches!((src, dst), (Task, Task)),
            EdgeKind::SubtaskOf => matches!((src, dst), (Task, Task)),
            EdgeKind::ServesGoal => matches!((src, dst), (Task, Goal)),
            EdgeKind::GoalParent => matches!((src, dst), (Goal, Goal)),
            EdgeKind::PlanTracks => matches!((src, dst), (Plan, Task)),
            EdgeKind::DelegatedTo => matches!((src, dst), (Task, Agent)),
            EdgeKind::Executes => matches!((src, dst), (Run, Task | Plan)),
            EdgeKind::ExecutedBy => matches!((src, dst), (Run, Agent | Person)),
            EdgeKind::Produces => matches!((src, dst), (Run | Task, Deliverable)),
            EdgeKind::UsesSkill => matches!((src, dst), (Agent | Run, Skill)),
            EdgeKind::ReviewedBy => matches!((src, dst), (Deliverable, Agent | Person)),
            EdgeKind::ApprovedBy => matches!((src, dst), (Deliverable | Run, Person)),
            EdgeKind::GovernedBy => matches!((src, dst), (Approval | Run, PolicyRevision)),
            EdgeKind::DelegatesTo => matches!((src, dst), (Agent, Agent)),
            EdgeKind::Reviews => matches!((src, dst), (Agent, Agent)),
            EdgeKind::EscalatesTo => matches!((src, dst), (Agent, Agent | Person)),
            EdgeKind::CanObserve => matches!((src, dst), (Agent, Agent)),
            EdgeKind::Mentions => matches!((src, dst), (MemoryNote | VaultNote, MemoryEntity)),
            EdgeKind::LinksTo => matches!((src, dst), (VaultNote, VaultNote)),
            EdgeKind::PromotedFrom => {
                matches!((src, dst), (VaultNote, MemoryNote) | (MemoryNote, VaultNote))
            }
            EdgeKind::Supersedes => matches!((src, dst), (MemoryNote, MemoryNote)),
            EdgeKind::Contradicts => matches!((src, dst), (MemoryNote, MemoryNote)),
            EdgeKind::Evidence => {
                matches!((src, dst), (MemoryNote, MemoryNote | Task | Run | Deliverable))
            }
            EdgeKind::Extends => matches!((src, dst), (MemoryNote, MemoryNote)),
            EdgeKind::Derives => matches!((src, dst), (MemoryNote, MemoryNote)),
        }
    }

    /// Whether this edge kind is enforced acyclic at write time.
    pub const fn is_acyclic(self) -> bool {
        matches!(
            self,
            EdgeKind::DependsOn
                | EdgeKind::SubtaskOf
                | EdgeKind::GoalParent
                | EdgeKind::DelegatesTo
                | EdgeKind::EscalatesTo
        )
    }

    /// Whether this edge kind has N:1 single-outgoing-live cardinality.
    pub const fn is_single_out(self) -> bool {
        matches!(
            self,
            EdgeKind::ServesGoal
                | EdgeKind::SubtaskOf
                | EdgeKind::GoalParent
                | EdgeKind::Executes
                | EdgeKind::ExecutedBy
                | EdgeKind::GovernedBy
        )
    }

    /// Whether this edge kind may be written or retracted via the generic
    /// `graph_edge_assert` / `graph_edge_retract` tools.
    ///
    /// Strictly limited to `extends`, `contradicts`, `links_to`, and
    /// `plan_tracks`. All other kinds (including `mentions` and `evidence`)
    /// are domain-owned only.
    pub const fn is_generic_assertable(self) -> bool {
        matches!(self, EdgeKind::Extends | EdgeKind::Contradicts | EdgeKind::LinksTo | EdgeKind::PlanTracks)
    }

    /// Whether this edge kind is a lineage edge (never closed by topical
    /// retirement; audit traces stay walkable).
    pub const fn is_lineage(self) -> bool {
        matches!(
            self,
            EdgeKind::Executes
                | EdgeKind::ExecutedBy
                | EdgeKind::Produces
                | EdgeKind::ReviewedBy
                | EdgeKind::ApprovedBy
                | EdgeKind::GovernedBy
                | EdgeKind::PromotedFrom
                | EdgeKind::Supersedes
                | EdgeKind::Evidence
                | EdgeKind::Derives
        )
    }
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validated opaque principal identifier (`asserted_by`).
///
/// The literal `'system'` (case-insensitive) is reserved and cannot be built
/// through [`PrincipalId::new`] or deserialized; internal hub writes must call
/// [`PrincipalId::system`] explicitly.
///
/// Pre-#2790: in `'default'`, carries the verified caller label (to be
/// backfilled by #2790); in non-default organizations, only `'system'` is
/// permitted until #2790 provides immutable principal IDs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct PrincipalId(String);

impl<'de> Deserialize<'de> for PrincipalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

impl PrincipalId {
    /// Construct a non-system principal identifier.
    ///
    /// Refuses empty strings, values over [`PRINCIPAL_ID_MAX_BYTES`], control
    /// characters, and the reserved `'system'` identifier (case-insensitive).
    pub fn new(raw: impl Into<String>) -> UaResult<Self> {
        let s = raw.into();
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.len() > PRINCIPAL_ID_MAX_BYTES {
            return Err(UaError::invalid(format!("principal id must be 1-{PRINCIPAL_ID_MAX_BYTES} bytes")));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(UaError::invalid("principal id must not contain control characters"));
        }
        if trimmed.eq_ignore_ascii_case("system") {
            return Err(UaError::invalid_code(
                "reserved_principal_id",
                "principal id \"system\" is reserved for internal hub writes; use PrincipalId::system()",
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn system() -> Self {
        Self("system".to_string())
    }

    pub fn is_system(&self) -> bool {
        self.0 == "system"
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Kind of the principal recorded in `asserted_by_kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertedByKind {
    Agent,
    Person,
    Node,
    System,
}

impl AssertedByKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            AssertedByKind::Agent => "agent",
            AssertedByKind::Person => "person",
            AssertedByKind::Node => "node",
            AssertedByKind::System => "system",
        }
    }
}

/// Provenance source class (`source_kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Tool,
    Event,
    Mirror,
    Import,
}

impl SourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            SourceKind::Tool => "tool",
            SourceKind::Event => "event",
            SourceKind::Mirror => "mirror",
            SourceKind::Import => "import",
        }
    }
}

/// Lifecycle state of an edge (`graph_edges.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeState {
    Active,
    Proposed,
}

impl EdgeState {
    pub const fn as_str(self) -> &'static str {
        match self {
            EdgeState::Active => "active",
            EdgeState::Proposed => "proposed",
        }
    }
}

/// Node visibility tier (`graph_nodes.visibility`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Private,
    Team,
    Org,
}

impl Visibility {
    pub const fn as_str(self) -> &'static str {
        match self {
            Visibility::Private => "private",
            Visibility::Team => "team",
            Visibility::Org => "org",
        }
    }
}

/// Owner type for `visibility = 'private'` nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerType {
    Human,
    Agent,
    Org,
}

impl OwnerType {
    pub const fn as_str(self) -> &'static str {
        match self {
            OwnerType::Human => "human",
            OwnerType::Agent => "agent",
            OwnerType::Org => "org",
        }
    }
}

/// Walk direction for Personalized PageRank (`seed_expand`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalkDirection {
    Undirected,
    Out,
}

/// Immutable provenance stamped on a node or edge write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub asserted_by: PrincipalId,
    pub asserted_by_kind: AssertedByKind,
    pub source_kind: SourceKind,
    pub source_ref: String,
}

impl Provenance {
    pub fn validate(&self) -> UaResult<()> {
        let is_sys_id = self.asserted_by.is_system();
        let is_sys_kind = self.asserted_by_kind == AssertedByKind::System;
        if is_sys_id != is_sys_kind {
            return Err(UaError::invalid(
                "asserted_by = 'system' requires asserted_by_kind = 'system' and vice versa",
            ));
        }
        let sr = self.source_ref.trim();
        if sr.is_empty() || sr.len() > SOURCE_REF_MAX_BYTES {
            return Err(UaError::invalid(format!("source_ref must be 1-{SOURCE_REF_MAX_BYTES} bytes")));
        }
        if sr.chars().any(char::is_control) {
            return Err(UaError::invalid("source_ref must not contain control characters"));
        }
        Ok(())
    }
}

/// Validate and normalize an RFC 3339 timestamp to fixed-width UTC
/// (`YYYY-MM-DDTHH:MM:SS+00:00`) so lexical ordering equals chronological order.
pub fn normalize_timestamp(raw: &str, field: &str) -> UaResult<String> {
    let ts = parse_ts(raw.trim())
        .ok_or_else(|| UaError::invalid(format!("{field} must be a valid RFC 3339 timestamp")))?;
    Ok(format_ts(ts))
}

/// Validate a JSON metadata value and serialize it within `max_bytes`.
pub fn encode_meta_json(meta: Option<&serde_json::Value>, max_bytes: usize) -> UaResult<String> {
    let s = match meta {
        None => "{}".to_string(),
        Some(v) => {
            if !v.is_object() {
                return Err(UaError::invalid("meta_json must be a JSON object"));
            }
            serde_json::to_string(v)?
        }
    };
    if s.len() > max_bytes {
        return Err(UaError::invalid(format!("meta_json exceeds maximum size of {max_bytes} bytes")));
    }
    Ok(s)
}

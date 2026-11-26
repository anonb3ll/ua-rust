//! Governed graph writes: domain-only `graph_node_ensure`, typed edge
//! assertions with hard-bounded acyclicity checks, and edge retraction
//! (`docs/graph.md`).

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use ua_core::{DEFAULT_ORG, UaError, UaResult};
use ua_store::graph::{
    AcyclicReachOutcome, GraphEdgeRow, GraphNodeRow, GraphRead, GraphRepo, NewGraphEdge, NewGraphNode,
    VisibilityScope,
};
use ulid::Ulid;

use crate::types::{
    ASSERTION_SCOPE_MAX_BYTES, AssertedByKind, DISPLAY_LABEL_MAX_BYTES, EDGE_META_MAX_BYTES,
    EXTERNAL_ID_MAX_BYTES, EdgeKind, EdgeState, NODE_META_MAX_BYTES, NodeKind, OwnerType, PrincipalId,
    Provenance, SourceKind, Visibility, encode_meta_json, normalize_timestamp,
};

/// Ledger channel for node creation.
pub const EVENT_NODE_CREATED: &str = "agent.graph.node_created";
/// Ledger channel for edge assertion.
pub const EVENT_EDGE_ASSERTED: &str = "agent.graph.edge_asserted";
/// Ledger channel for edge retraction.
pub const EVENT_EDGE_RETRACTED: &str = "agent.graph.edge_retracted";

/// Maximum nodes visited during one write-time acyclicity check.
pub const CYCLE_CHECK_MAX_NODES: usize = 1_000;
/// Maximum edges visited during one write-time acyclicity check.
pub const CYCLE_CHECK_MAX_EDGES: usize = 5_000;
/// Wall-clock deadline (ms) for one write-time acyclicity check.
pub const CYCLE_CHECK_DEADLINE_MS: u64 = 50;

/// Bounds governing one write-time acyclicity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CycleCheckBounds {
    pub max_nodes: usize,
    pub max_edges: usize,
    pub deadline_ms: u64,
}

impl CycleCheckBounds {
    /// Default write-time acyclicity bounds for a specific edge kind.
    pub const fn for_kind(kind: EdgeKind) -> Self {
        match kind {
            EdgeKind::DependsOn
            | EdgeKind::SubtaskOf
            | EdgeKind::GoalParent
            | EdgeKind::DelegatesTo
            | EdgeKind::EscalatesTo => Self {
                max_nodes: CYCLE_CHECK_MAX_NODES,
                max_edges: CYCLE_CHECK_MAX_EDGES,
                deadline_ms: CYCLE_CHECK_DEADLINE_MS,
            },
            _ => Self {
                max_nodes: CYCLE_CHECK_MAX_NODES,
                max_edges: CYCLE_CHECK_MAX_EDGES,
                deadline_ms: CYCLE_CHECK_DEADLINE_MS,
            },
        }
    }
}

impl Default for CycleCheckBounds {
    fn default() -> Self {
        Self {
            max_nodes: CYCLE_CHECK_MAX_NODES,
            max_edges: CYCLE_CHECK_MAX_EDGES,
            deadline_ms: CYCLE_CHECK_DEADLINE_MS,
        }
    }
}

/// Per-edge-kind write-time acyclicity bounds (`docs/graph.md`).
///
/// Parameterizes node, edge, and deadline caps independently for each acyclic
/// edge kind (`depends_on`, `subtask_of`, `goal_parent`, `delegates_to`,
/// `escalates_to`) so individual domains (for example `depends_on` in C2+) can
/// tune their own caps without widening other kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CycleCheckPolicy {
    pub depends_on: CycleCheckBounds,
    pub subtask_of: CycleCheckBounds,
    pub goal_parent: CycleCheckBounds,
    pub delegates_to: CycleCheckBounds,
    pub escalates_to: CycleCheckBounds,
}

impl Default for CycleCheckPolicy {
    fn default() -> Self {
        Self {
            depends_on: CycleCheckBounds::for_kind(EdgeKind::DependsOn),
            subtask_of: CycleCheckBounds::for_kind(EdgeKind::SubtaskOf),
            goal_parent: CycleCheckBounds::for_kind(EdgeKind::GoalParent),
            delegates_to: CycleCheckBounds::for_kind(EdgeKind::DelegatesTo),
            escalates_to: CycleCheckBounds::for_kind(EdgeKind::EscalatesTo),
        }
    }
}

impl CycleCheckPolicy {
    /// Apply uniform `bounds` to every acyclic edge kind.
    pub const fn all(bounds: CycleCheckBounds) -> Self {
        Self {
            depends_on: bounds,
            subtask_of: bounds,
            goal_parent: bounds,
            delegates_to: bounds,
            escalates_to: bounds,
        }
    }

    /// Return the configured bounds for `kind`, or `None` when `kind` is not
    /// enforced acyclic.
    pub const fn bounds_for(&self, kind: EdgeKind) -> Option<CycleCheckBounds> {
        match kind {
            EdgeKind::DependsOn => Some(self.depends_on),
            EdgeKind::SubtaskOf => Some(self.subtask_of),
            EdgeKind::GoalParent => Some(self.goal_parent),
            EdgeKind::DelegatesTo => Some(self.delegates_to),
            EdgeKind::EscalatesTo => Some(self.escalates_to),
            _ => None,
        }
    }

    /// Return a copy of this policy with `bounds` set for `kind` (no-op for
    /// non-acyclic kinds).
    pub const fn with_kind(mut self, kind: EdgeKind, bounds: CycleCheckBounds) -> Self {
        match kind {
            EdgeKind::DependsOn => self.depends_on = bounds,
            EdgeKind::SubtaskOf => self.subtask_of = bounds,
            EdgeKind::GoalParent => self.goal_parent = bounds,
            EdgeKind::DelegatesTo => self.delegates_to = bounds,
            EdgeKind::EscalatesTo => self.escalates_to = bounds,
            _ => {}
        }
        self
    }
}

/// Request for the internal domain-only [`graph_node_ensure`] primitive.
#[derive(Debug, Clone)]
pub struct EnsureNodeRequest {
    pub org_id: String,
    pub kind: NodeKind,
    pub external_id: String,
    pub display_label: Option<String>,
    pub visibility: Visibility,
    pub team_id: Option<String>,
    pub owner_type: Option<OwnerType>,
    pub owner_id: Option<String>,
    pub provenance: Provenance,
    pub meta_json: Option<Value>,
    /// Per-organization node quota (`0` disables the quota check).
    pub max_nodes_per_org: u64,
}

/// Request to assert a new graph edge.
#[derive(Debug, Clone)]
pub struct AssertEdgeRequest {
    pub org_id: String,
    pub src_id: String,
    pub dst_id: String,
    pub kind: EdgeKind,
    pub assertion_scope: String,
    pub state: EdgeState,
    pub weight: f64,
    pub provenance: Provenance,
    /// Optional explicit `valid_from` (permitted only for `SourceKind::Import`).
    pub valid_from: Option<String>,
    /// Optional explicit `valid_to` (refused for generic assertions; must be `<= now`).
    pub valid_to: Option<String>,
    pub meta_json: Option<Value>,
    /// Caller's visibility scope; both endpoints must be visible in `org_id`.
    pub scope: VisibilityScope,
    /// True when invoked from the public `graph_edge_assert` tool (restricts to
    /// generic-assertable kinds and enforces `contradicts` as `proposed`).
    pub generic: bool,
    /// Per-organization edge quota (`0` disables the quota check).
    pub max_edges_per_org: u64,
    /// Per-node live (`valid_to IS NULL`) incident edge cap (`0` disables the check).
    pub max_live_edges_per_node: u64,
    /// Per-edge-kind write-time acyclicity bounds (each acyclic kind defaults to
    /// `1,000` nodes / `5,000` edges / `50 ms`).
    pub cycle_bounds: CycleCheckPolicy,
}

/// Request to retract (close with `valid_to = now`) an existing live edge.
#[derive(Debug, Clone)]
pub struct RetractEdgeRequest {
    pub org_id: String,
    pub edge_id: String,
    pub retractor: PrincipalId,
    pub retractor_kind: AssertedByKind,
    /// Optional explicit `valid_to` (defaults to current hub time; must be `<= now`).
    pub valid_to: Option<String>,
    /// True when invoked from the public `graph_edge_retract` tool (refuses
    /// domain-owned edge kinds).
    pub generic: bool,
}

fn check_non_default_org_principal(org_id: &str, prov: &Provenance) -> UaResult<()> {
    if org_id != DEFAULT_ORG {
        let is_system_mirror_or_import = prov.asserted_by.is_system()
            && prov.asserted_by_kind == AssertedByKind::System
            && matches!(prov.source_kind, SourceKind::Mirror | SourceKind::Import);
        if !is_system_mirror_or_import {
            return Err(UaError::denied(
                "principal_id_required",
                format!(
                    "non-system graph writes in non-default organization {org_id:?} are refused until \
                     immutable principal IDs (#2790) land"
                ),
            ));
        }
    }
    Ok(())
}

/// Fail-closed bounded reachability check: verifies no live same-kind path from
/// `dst_id` back to `src_id` exists in `org_id`.
///
/// Returns:
/// - `Ok(())` when reachable nodes are exhausted without reaching `src_id`;
/// - `Err(invalid_argument, reason_code = "cycle_detected")` on a real cycle;
/// - `Err(invalid_argument, reason_code = "cycle_check_bound_exceeded")` when
///   any of `(max_nodes, max_edges, deadline_ms)` is exceeded before exhaustion.
pub fn check_acyclic<R: GraphRead>(
    repo: &mut R,
    org_id: &str,
    src_id: &str,
    dst_id: &str,
    kind: EdgeKind,
    bounds: CycleCheckBounds,
) -> UaResult<()> {
    if src_id == dst_id {
        return Err(UaError::invalid_code(
            "cycle_detected",
            format!("edge {kind} from {src_id} to itself would create a cycle"),
        ));
    }
    let started = Instant::now();
    let deadline = Duration::from_millis(bounds.deadline_ms);
    if bounds.deadline_ms == 0 || started.elapsed() >= deadline {
        return Err(UaError::invalid_code(
            "cycle_check_bound_exceeded",
            format!("acyclicity check for {kind} exceeded deadline of {} ms", bounds.deadline_ms),
        ));
    }
    let outcome = repo.bounded_acyclic_reach(
        org_id,
        src_id,
        dst_id,
        kind.as_str(),
        bounds.max_nodes,
        bounds.max_edges,
        started + deadline,
    )?;
    if started.elapsed() >= deadline {
        return Err(UaError::invalid_code(
            "cycle_check_bound_exceeded",
            format!("acyclicity check for {kind} exceeded deadline of {} ms", bounds.deadline_ms),
        ));
    }
    match outcome {
        AcyclicReachOutcome::Acyclic => Ok(()),
        AcyclicReachOutcome::CycleDetected => Err(UaError::invalid_code(
            "cycle_detected",
            format!("asserting {kind} ({src_id} -> {dst_id}) would create a cycle"),
        )),
        AcyclicReachOutcome::BoundExceeded(which) => Err(UaError::invalid_code(
            "cycle_check_bound_exceeded",
            format!(
                "acyclicity check for {kind} exceeded {which} cap (max_nodes={}, max_edges={})",
                bounds.max_nodes, bounds.max_edges
            ),
        )),
    }
}

/// Domain-only internal primitive: create a `graph_nodes` row if
/// `(org_id, kind, external_id)` is absent, and touch nothing if it already
/// exists. Never exposed as a public tool (`docs/graph.md`, Security model §1).
pub fn graph_node_ensure<R: GraphRepo>(
    repo: &mut R,
    req: EnsureNodeRequest,
) -> UaResult<(GraphNodeRow, bool)> {
    repo.require_org_exists(&req.org_id)?;
    req.provenance.validate()?;
    check_non_default_org_principal(&req.org_id, &req.provenance)?;

    let ext = req.external_id.trim();
    if ext.is_empty() || ext.len() > EXTERNAL_ID_MAX_BYTES {
        return Err(UaError::invalid(format!("external_id must be 1-{EXTERNAL_ID_MAX_BYTES} bytes")));
    }
    if ext.chars().any(char::is_control) {
        return Err(UaError::invalid("external_id must not contain control characters"));
    }
    if let Some(ref lbl) = req.display_label
        && lbl.len() > DISPLAY_LABEL_MAX_BYTES
    {
        return Err(UaError::invalid(format!(
            "display_label must be at most {DISPLAY_LABEL_MAX_BYTES} bytes"
        )));
    }
    match req.visibility {
        Visibility::Team => {
            if req.team_id.as_deref().map(str::trim).is_none_or(str::is_empty) {
                return Err(UaError::invalid("team visibility requires team_id"));
            }
        }
        Visibility::Private => {
            if req.owner_type.is_none() || req.owner_id.as_deref().map(str::trim).is_none_or(str::is_empty) {
                return Err(UaError::invalid("private visibility requires owner_type and owner_id"));
            }
        }
        Visibility::Org => {}
    }
    let meta_json = encode_meta_json(req.meta_json.as_ref(), NODE_META_MAX_BYTES)?;

    if let Some(existing) = repo.find_node_by_external_internal(&req.org_id, req.kind.as_str(), ext)? {
        return Ok((existing, false));
    }

    if req.max_nodes_per_org > 0 {
        let count = repo.count_org_nodes(&req.org_id)?;
        if count >= req.max_nodes_per_org {
            return Err(UaError::denied(
                "graph_quota_exceeded",
                format!(
                    "organization {:?} has reached graph_max_nodes_per_org ({})",
                    req.org_id, req.max_nodes_per_org
                ),
            ));
        }
    }

    let id = Ulid::generate().to_string();
    let now_str = ua_core::time::now();

    // ORG-EVENT-DEFAULT: non-default org events omit display_label, external_id,
    // and meta_json, and stamp originator 'system'.
    let is_default = req.org_id == DEFAULT_ORG;
    let originator = if is_default { req.provenance.asserted_by.as_str() } else { "system" };
    let payload = if is_default {
        json!({
            "org_id": req.org_id,
            "node_id": id,
            "kind": req.kind.as_str(),
            "external_id": ext,
            "visibility": req.visibility.as_str(),
            "asserted_by": req.provenance.asserted_by.as_str(),
            "asserted_by_kind": req.provenance.asserted_by_kind.as_str(),
        })
    } else {
        json!({
            "org_id": req.org_id,
            "node_id": id,
            "kind": req.kind.as_str(),
            "visibility": req.visibility.as_str(),
        })
    };
    let seq = repo.record_event(EVENT_NODE_CREATED, payload, originator)?;
    let (source_kind, source_ref) = match (req.provenance.source_kind, seq) {
        (SourceKind::Event, Some(s)) => (SourceKind::Event.as_str().to_string(), format!("event:{s}")),
        (SourceKind::Event, None) => {
            (SourceKind::Tool.as_str().to_string(), req.provenance.source_ref.trim().to_string())
        }
        (k, _) => (k.as_str().to_string(), req.provenance.source_ref.trim().to_string()),
    };

    let new_node = NewGraphNode {
        id,
        org_id: req.org_id,
        kind: req.kind.as_str().to_string(),
        external_id: ext.to_string(),
        display_label: req.display_label,
        visibility: req.visibility.as_str().to_string(),
        team_id: req.team_id,
        owner_type: req.owner_type.map(|o| o.as_str().to_string()),
        owner_id: req.owner_id,
        asserted_by: req.provenance.asserted_by.as_str().to_string(),
        asserted_by_kind: req.provenance.asserted_by_kind.as_str().to_string(),
        source_kind,
        source_ref,
        meta_json,
        created_at: now_str.clone(),
        updated_at: now_str,
    };
    repo.ensure_node(&new_node)
}

/// Assert a typed graph edge inside the caller's write transaction.
///
/// Never creates missing nodes; both endpoints must already exist in `org_id`
/// and be visible in `req.scope` (else returns `not_found`, identical for
/// nonexistent, foreign-org, and hidden endpoints).
pub fn assert_edge<R: GraphRepo>(repo: &mut R, req: AssertEdgeRequest) -> UaResult<GraphEdgeRow> {
    repo.require_org_exists(&req.org_id)?;
    req.provenance.validate()?;

    if req.generic && !req.kind.is_generic_assertable() {
        return Err(UaError::denied(
            "domain_owned_edge",
            format!(
                "edge kind {:?} is domain-owned and cannot be asserted via generic graph tools",
                req.kind.as_str()
            ),
        ));
    }
    check_non_default_org_principal(&req.org_id, &req.provenance)?;

    if !req.weight.is_finite() || req.weight <= 0.0 || req.weight > 1000.0 {
        return Err(UaError::invalid("weight must be finite and in (0.0, 1000.0]"));
    }
    if req.generic && !req.assertion_scope.is_empty() {
        return Err(UaError::denied(
            "reserved_assertion_scope",
            "generic graph edge assertions must use an empty assertion_scope; scoped assertions are reserved for domain code",
        ));
    }
    if req.assertion_scope.len() > ASSERTION_SCOPE_MAX_BYTES {
        return Err(UaError::invalid(format!(
            "assertion_scope must be at most {ASSERTION_SCOPE_MAX_BYTES} bytes"
        )));
    }
    if req.assertion_scope.chars().any(char::is_control) {
        return Err(UaError::invalid("assertion_scope must not contain control characters"));
    }
    if req.src_id.trim().is_empty() || req.dst_id.trim().is_empty() {
        return Err(UaError::invalid("src_id and dst_id must be non-empty"));
    }
    if req.src_id == req.dst_id {
        return Err(UaError::invalid("self-loop edges (src_id == dst_id) are not allowed"));
    }

    // Generic assertions: `contradicts` must be `proposed`; other generic kinds must be `active`.
    if req.generic {
        match req.kind {
            EdgeKind::Contradicts if req.state != EdgeState::Proposed => {
                return Err(UaError::invalid("generic contradicts assertions must use state = 'proposed'"));
            }
            EdgeKind::Contradicts => {}
            _ if req.state != EdgeState::Active => {
                return Err(UaError::invalid("only contradicts edges may use state = 'proposed'"));
            }
            _ => {}
        }
        if req.valid_from.is_some() {
            return Err(UaError::invalid(
                "generic edge assertions cannot supply valid_from (set by hub to asserted_at)",
            ));
        }
        if req.valid_to.is_some() {
            return Err(UaError::invalid(
                "generic edge assertions cannot supply valid_to (assert live, retract later)",
            ));
        }
    } else if req.state == EdgeState::Proposed && req.kind != EdgeKind::Contradicts {
        return Err(UaError::invalid("only contradicts edges may use state = 'proposed'"));
    }

    let meta_json = encode_meta_json(req.meta_json.as_ref(), EDGE_META_MAX_BYTES)?;

    // Zero existence oracle: both endpoints must exist in org_id and be visible.
    let src = repo
        .get_node_by_id(&req.org_id, &req.src_id, &req.scope)?
        .ok_or_else(|| UaError::not_found("graph endpoint node not found"))?;
    let dst = repo
        .get_node_by_id(&req.org_id, &req.dst_id, &req.scope)?
        .ok_or_else(|| UaError::not_found("graph endpoint node not found"))?;

    let src_kind = NodeKind::parse(&src.kind)?;
    let dst_kind = NodeKind::parse(&dst.kind)?;
    if !req.kind.allowed_endpoints(src_kind, dst_kind) {
        return Err(UaError::invalid_code(
            "invalid_endpoint_kind",
            format!(
                "edge kind {:?} does not allow endpoints ({} -> {})",
                req.kind.as_str(),
                src_kind.as_str(),
                dst_kind.as_str()
            ),
        ));
    }

    if req.max_edges_per_org > 0 {
        let count = repo.count_org_edges(&req.org_id)?;
        if count >= req.max_edges_per_org {
            return Err(UaError::denied(
                "graph_quota_exceeded",
                format!(
                    "organization {:?} has reached graph_max_edges_per_org ({})",
                    req.org_id, req.max_edges_per_org
                ),
            ));
        }
    }

    if req.max_live_edges_per_node > 0 && req.valid_to.is_none() {
        let cap = req.max_live_edges_per_node.min(usize::MAX as u64) as usize;
        for endpoint_id in [&src.id, &dst.id] {
            let live_count = repo.count_node_live_edges_capped(&req.org_id, endpoint_id, cap)?;
            if live_count >= cap {
                return Err(UaError::denied(
                    "node_edge_limit_exceeded",
                    format!(
                        "graph node {endpoint_id} has reached graph_max_live_edges_per_node ({})",
                        req.max_live_edges_per_node
                    ),
                ));
            }
        }
    }

    // Write-time bounded acyclicity check (fail-closed), parameterized per edge kind.
    if req.valid_to.is_none()
        && let Some(bounds) = req.cycle_bounds.bounds_for(req.kind)
    {
        check_acyclic(repo, &req.org_id, &src.id, &dst.id, req.kind, bounds)?;
    }

    let edge_id = Ulid::generate().to_string();
    let asserted_at = ua_core::time::now();
    let valid_from = match req.valid_from.as_deref() {
        Some(raw) => {
            if req.provenance.source_kind != SourceKind::Import {
                return Err(UaError::invalid("valid_from may be supplied only for source_kind = 'import'"));
            }
            let vf = normalize_timestamp(raw, "valid_from")?;
            if vf > asserted_at {
                return Err(UaError::invalid("import valid_from must be <= asserted_at"));
            }
            vf
        }
        None => asserted_at.clone(),
    };
    let valid_to = match req.valid_to.as_deref() {
        Some(raw) => {
            let vt = normalize_timestamp(raw, "valid_to")?;
            if vt > asserted_at {
                return Err(UaError::invalid_code("future_valid_to", "valid_to must be <= current hub time"));
            }
            if vt < valid_from {
                return Err(UaError::invalid("valid_to must be >= valid_from"));
            }
            Some(vt)
        }
        None => None,
    };

    // Same-transaction ledger append; if insert_edge fails on a uniqueness
    // constraint, the enclosing WriteTx rolls back both writes atomically.
    let is_default = req.org_id == DEFAULT_ORG;
    let originator = if is_default { req.provenance.asserted_by.as_str() } else { "system" };
    let payload = if is_default {
        json!({
            "org_id": req.org_id,
            "edge_id": edge_id,
            "src_id": src.id,
            "dst_id": dst.id,
            "kind": req.kind.as_str(),
            "state": req.state.as_str(),
            "asserted_by": req.provenance.asserted_by.as_str(),
            "asserted_by_kind": req.provenance.asserted_by_kind.as_str(),
        })
    } else {
        json!({
            "org_id": req.org_id,
            "edge_id": edge_id,
            "src_id": src.id,
            "dst_id": dst.id,
            "kind": req.kind.as_str(),
            "state": req.state.as_str(),
        })
    };
    let seq = repo.record_event(EVENT_EDGE_ASSERTED, payload, originator)?;
    let (source_kind, source_ref) = match (req.provenance.source_kind, seq) {
        (SourceKind::Event | SourceKind::Tool, Some(s)) if req.generic => {
            (SourceKind::Event.as_str().to_string(), format!("event:{s}"))
        }
        (SourceKind::Event, Some(s)) => (SourceKind::Event.as_str().to_string(), format!("event:{s}")),
        (SourceKind::Event, None) => {
            (SourceKind::Tool.as_str().to_string(), req.provenance.source_ref.trim().to_string())
        }
        (k, _) => (k.as_str().to_string(), req.provenance.source_ref.trim().to_string()),
    };

    let new_edge = NewGraphEdge {
        id: edge_id,
        org_id: req.org_id,
        src_id: src.id,
        dst_id: dst.id,
        kind: req.kind.as_str().to_string(),
        assertion_scope: req.assertion_scope,
        state: req.state.as_str().to_string(),
        weight: req.weight,
        asserted_by: req.provenance.asserted_by.as_str().to_string(),
        asserted_by_kind: req.provenance.asserted_by_kind.as_str().to_string(),
        asserted_at,
        source_kind,
        source_ref,
        valid_from,
        valid_to,
        meta_json,
    };
    repo.insert_edge(&new_edge)
}

/// Retract (close with `valid_to`) a live graph edge, preserving `as_of`
/// history and original `asserted_by`.
///
/// Authority checks (original asserter vs `Operator`/`LifecycleOperator`) run
/// in `ua-tools` (`families/graph_store.rs`) via `ua-org::authz` before calling
/// this function.
pub fn retract_edge<R: GraphRepo>(repo: &mut R, req: RetractEdgeRequest) -> UaResult<GraphEdgeRow> {
    repo.require_org_exists(&req.org_id)?;
    if req.org_id != DEFAULT_ORG && req.retractor_kind != AssertedByKind::System {
        return Err(UaError::denied(
            "principal_id_required",
            format!(
                "non-system graph writes in non-default organization {:?} are refused until \
                 immutable principal IDs (#2790) land",
                req.org_id
            ),
        ));
    }

    let edge = repo
        .get_edge_by_id(&req.org_id, &req.edge_id)?
        .ok_or_else(|| UaError::not_found("graph edge not found"))?;
    let kind = EdgeKind::parse(&edge.kind)?;
    if req.generic && !kind.is_generic_assertable() {
        return Err(UaError::denied(
            "domain_owned_edge",
            format!(
                "edge kind {:?} is domain-owned and cannot be retracted via generic graph tools",
                kind.as_str()
            ),
        ));
    }
    if edge.valid_to.is_some() {
        return Err(UaError::conflict_code(
            "edge_already_closed",
            format!("graph edge {} is already retracted/closed", edge.id),
        ));
    }

    let vt = match req.valid_to.as_deref() {
        Some(raw) => normalize_timestamp(raw, "valid_to")?,
        None => ua_core::time::now(),
    };
    let closed = repo
        .close_edge(&req.org_id, &edge.id, &vt)?
        .ok_or_else(|| UaError::not_found("graph edge not found"))?;

    let is_default = req.org_id == DEFAULT_ORG;
    let originator = if is_default { req.retractor.as_str() } else { "system" };
    let payload = if is_default {
        json!({
            "org_id": req.org_id,
            "edge_id": closed.id,
            "src_id": closed.src_id,
            "dst_id": closed.dst_id,
            "kind": closed.kind,
            "valid_to": closed.valid_to,
            "retracted_by": req.retractor.as_str(),
            "retracted_by_kind": req.retractor_kind.as_str(),
        })
    } else {
        json!({
            "org_id": req.org_id,
            "edge_id": closed.id,
            "src_id": closed.src_id,
            "dst_id": closed.dst_id,
            "kind": closed.kind,
            "valid_to": closed.valid_to,
        })
    };
    repo.record_event(EVENT_EDGE_RETRACTED, payload, originator)?;
    Ok(closed)
}

//! Governed graph store tools: the registry layer over [`ua_graph`] and
//! [`ua_store::graph`] (`docs/graph.md`, C1).
//!
//! Tools (read-only):
//! - `graph_node_get`
//! - `graph_neighbors`
//! - `graph_traverse`
//! - `graph_shortest_path`
//! - `graph_expand`
//!
//! Tools (write, governed):
//! - `graph_edge_assert`
//! - `graph_edge_retract`
//!
//! There is intentionally **no** public `graph_node_upsert` tool: nodes are
//! created and updated only through their owning domain code paths via the
//! internal `ua_graph::graph_node_ensure` primitive.
//!
//! All authority checks (`ua_org::authz`) run here before calling `ua_graph`.
//! Every query and write binds `org_id` strictly from `ctx.caller.org_id`
//! (tool arguments never accept an `org_id`).

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{DEFAULT_ORG, UaError, UaResult};
use ua_graph::{
    AssertEdgeRequest, AssertedByKind, CycleCheckBounds, EdgeKind, EdgeState, KHopRequest, NeighborsRequest,
    NodeKind, PrincipalId, Provenance, RetractEdgeRequest, SeedExpandRequest, SeedInput, ShortestPathRequest,
    SourceKind, WalkDirection,
};
use ua_org::authz::{Authority, Authz, human, verified_label};
use ua_store::Part;
use ua_store::graph::{AdjacencyCursor, EdgeDirection, GraphRead, SqliteGraph, VisibilityScope};

use crate::registry::{Registry, ToolCtx, tool};

const FAMILY: &str = "graph_store";

pub fn schema_parts() -> Vec<Part> {
    ua_graph::schema_parts()
}

// ---------------------------------------------------------------------------
// Tool argument structs (deny_unknown_fields, no org_id parameter)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeGetArgs {
    /// Surrogate node ID (ULID). Mutually exclusive with `(kind, external_id)`.
    pub node_id: Option<String>,
    /// Closed node kind when looking up by domain identity (e.g. `task`, `memory_note`).
    pub kind: Option<String>,
    /// Immutable domain identifier when looking up by `(kind, external_id)`.
    pub external_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CursorArg {
    /// Weight of the last edge from the previous page.
    pub weight: f64,
    /// RFC 3339 UTC `asserted_at` of the last edge from the previous page.
    pub asserted_at: String,
    /// Edge ID of the last edge from the previous page.
    pub edge_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NeighborsArgs {
    /// Surrogate node ID (ULID). Mutually exclusive with `(kind, external_id)`.
    pub node_id: Option<String>,
    /// Closed node kind when resolving the seed by domain identity.
    pub kind: Option<String>,
    /// Immutable domain identifier when resolving the seed by `(kind, external_id)`.
    pub external_id: Option<String>,
    /// Traversal direction: `out`, `in`, or `both` (default `both`).
    pub direction: Option<String>,
    /// Optional allowlist of edge kinds.
    pub edge_kinds: Option<Vec<String>>,
    /// Optional allowlist of adjacent node kinds.
    pub node_kinds: Option<Vec<String>>,
    /// Optional RFC 3339 timestamp for historical point-in-time (`as_of`) reads.
    pub as_of: Option<String>,
    /// Include `proposed` contradiction edges in addition to `active` edges (default `false`).
    #[serde(default)]
    pub include_proposed: bool,
    /// Page size, 1-200 (default 50).
    pub limit: Option<usize>,
    /// Keyset pagination cursor returned by a previous `graph_neighbors` call.
    pub cursor: Option<CursorArg>,
    /// Per-call wall-clock deadline in ms, 1-2000 (default 500).
    pub deadline_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraverseArgs {
    /// Seed node IDs (1-20).
    pub seed_ids: Vec<String>,
    /// Maximum BFS hops from seeds, 1-4 (default 2).
    pub max_hops: Option<usize>,
    /// Traversal direction: `out`, `in`, or `both` (default `both`).
    pub direction: Option<String>,
    /// Optional allowlist of edge kinds.
    pub edge_kinds: Option<Vec<String>>,
    /// Optional allowlist of neighbor node kinds.
    pub node_kinds: Option<Vec<String>>,
    /// Optional RFC 3339 timestamp for historical `as_of` reads.
    pub as_of: Option<String>,
    /// Include `proposed` contradiction edges (default `false`).
    #[serde(default)]
    pub include_proposed: bool,
    /// Maximum nodes returned, 1-500 (default 100).
    pub max_nodes: Option<usize>,
    /// Maximum edges returned, 1-1000 (default 250).
    pub max_edges: Option<usize>,
    /// Maximum edges expanded per pivot node, 1-200 (default 50).
    pub max_degree_per_node: Option<usize>,
    /// Maximum edges scanned across the expansion, 1-10000 (default 2000).
    pub max_visited_edges: Option<usize>,
    /// Optional eligible-degree hub cutoff: nodes with eligible degree above this are skipped as pivots.
    pub skip_hubs_over: Option<usize>,
    /// Per-call wall-clock deadline in ms, 1-2000 (default 500).
    pub deadline_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShortestPathArgs {
    /// Source node ID (ULID).
    pub from_id: String,
    /// Destination node ID (ULID).
    pub to_id: String,
    /// Traversal direction: `out` (default), `in`, or `both`.
    pub direction: Option<String>,
    /// Optional allowlist of edge kinds.
    pub edge_kinds: Option<Vec<String>>,
    /// Optional allowlist of intermediate/endpoint node kinds.
    pub node_kinds: Option<Vec<String>>,
    /// Optional RFC 3339 timestamp for historical `as_of` reads.
    pub as_of: Option<String>,
    /// Include `proposed` contradiction edges (default `false`).
    #[serde(default)]
    pub include_proposed: bool,
    /// Maximum path depth, 0-6 (default 4).
    pub max_depth: Option<usize>,
    /// Per-call wall-clock deadline in ms, 1-2000 (default 500).
    pub deadline_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SeedArg {
    /// Seed node ID (ULID).
    pub node_id: String,
    /// Positive finite teleport weight (normalized across visible seeds).
    #[serde(default = "default_weight")]
    pub weight: f64,
}

fn default_weight() -> f64 {
    1.0
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpandArgs {
    /// Weighted seed nodes (1-50).
    pub seeds: Vec<SeedArg>,
    /// Optional allowlist of edge kinds.
    pub edge_kinds: Option<Vec<String>>,
    /// Optional allowlist of node kinds.
    pub node_kinds: Option<Vec<String>>,
    /// Optional RFC 3339 timestamp for historical `as_of` reads.
    pub as_of: Option<String>,
    /// Include `proposed` contradiction edges (default `false`).
    #[serde(default)]
    pub include_proposed: bool,
    /// Walk direction: `undirected` (default) or `out`.
    pub walk_direction: Option<String>,
    /// Damping factor, clamped to 0.10..=0.95 (default 0.85).
    pub damping: Option<f64>,
    /// Power iteration cap, 1-50 (default 30).
    pub max_iters: Option<usize>,
    /// Convergence tolerance, clamped to 1e-9..=1e-2 (default 1e-6).
    pub eps: Option<f64>,
    /// Maximum ranked results returned, 1-50 (default 10).
    pub max_results: Option<usize>,
    /// Optional eligible-degree hub filter.
    pub skip_hubs_over: Option<usize>,
    /// Per-call wall-clock deadline in ms, 1-2000 (default 500).
    pub deadline_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EdgeAssertArgs {
    /// Existing source node ID in the caller's organization (never auto-created).
    pub src_id: String,
    /// Existing target node ID in the caller's organization (never auto-created).
    pub dst_id: String,
    /// Generic-assertable edge kind: `extends`, `contradicts`, `links_to`, or `plan_tracks`.
    pub kind: String,
    /// Optional assertion scope (<= 128 bytes), e.g. `note:<id>`. Defaults to empty string.
    #[serde(default)]
    pub assertion_scope: String,
    /// Optional edge state (`proposed` required for `contradicts`, `active` for other generic kinds).
    pub state: Option<String>,
    /// Edge weight in `(0.0, 1000.0]` (default `1.0`).
    pub weight: Option<f64>,
    /// Optional JSON object metadata (<= 4 KiB serialized).
    pub meta_json: Option<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EdgeRetractArgs {
    /// Live edge ID (ULID) in the caller's organization to close with `valid_to = now`.
    pub edge_id: String,
}

// ---------------------------------------------------------------------------
// Parsing & caller scope helpers
// ---------------------------------------------------------------------------

fn caller_scope(ctx: &ToolCtx) -> VisibilityScope {
    match verified_label(&ctx.caller) {
        Some(label) => {
            let owner_type = if human(&ctx.caller) { "human" } else { "agent" };
            VisibilityScope::for_principal(owner_type, label, Vec::new())
        }
        None => VisibilityScope::org_only(),
    }
}

fn verified_writer(ctx: &ToolCtx) -> UaResult<(PrincipalId, AssertedByKind)> {
    let label = verified_label(&ctx.caller).ok_or_else(|| {
        UaError::denied("unverified_identity", "graph edge writes require a verified human or agent identity")
    })?;
    let principal = PrincipalId::new(label)?;
    let kind = if human(&ctx.caller) { AssertedByKind::Person } else { AssertedByKind::Agent };
    Ok((principal, kind))
}

fn parse_direction(raw: Option<&str>, default: EdgeDirection) -> UaResult<EdgeDirection> {
    match raw.map(str::trim) {
        None => Ok(default),
        Some("out") => Ok(EdgeDirection::Out),
        Some("in") => Ok(EdgeDirection::In),
        Some("both") => Ok(EdgeDirection::Both),
        Some(other) => {
            Err(UaError::invalid(format!("direction must be \"out\", \"in\", or \"both\", not {other:?}")))
        }
    }
}

fn parse_walk_direction(raw: Option<&str>) -> UaResult<WalkDirection> {
    match raw.map(str::trim) {
        None | Some("undirected") => Ok(WalkDirection::Undirected),
        Some("out") => Ok(WalkDirection::Out),
        Some(other) => {
            Err(UaError::invalid(format!("walk_direction must be \"undirected\" or \"out\", not {other:?}")))
        }
    }
}

fn parse_edge_kinds(raw: Option<Vec<String>>) -> UaResult<Vec<EdgeKind>> {
    raw.unwrap_or_default().into_iter().map(|s| EdgeKind::parse(&s)).collect()
}

fn parse_node_kinds(raw: Option<Vec<String>>) -> UaResult<Vec<NodeKind>> {
    raw.unwrap_or_default().into_iter().map(|s| NodeKind::parse(&s)).collect()
}

fn parse_edge_state(raw: Option<&str>, kind: EdgeKind) -> UaResult<EdgeState> {
    match raw.map(str::trim) {
        None => Ok(if kind == EdgeKind::Contradicts { EdgeState::Proposed } else { EdgeState::Active }),
        Some("active") => Ok(EdgeState::Active),
        Some("proposed") => Ok(EdgeState::Proposed),
        Some(other) => {
            Err(UaError::invalid(format!("state must be \"active\" or \"proposed\", not {other:?}")))
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_node_get(ctx: ToolCtx, a: NodeGetArgs) -> UaResult<Value> {
    let org_id = ctx.caller.org_id.clone();
    let scope = caller_scope(&ctx);
    let kind = a.kind.as_deref().map(NodeKind::parse).transpose()?;
    ctx.hub
        .db()
        .read_async(move |conn| {
            let mut repo = SqliteGraph::new(conn);
            let node = ua_graph::node_get(
                &mut repo,
                &org_id,
                a.node_id.as_deref(),
                kind,
                a.external_id.as_deref(),
                &scope,
            )?;
            Ok(json!({ "node": node }))
        })
        .await
}

async fn handle_neighbors(ctx: ToolCtx, a: NeighborsArgs) -> UaResult<Value> {
    let org_id = ctx.caller.org_id.clone();
    let scope = caller_scope(&ctx);
    let kind = a.kind.as_deref().map(NodeKind::parse).transpose()?;
    let direction = parse_direction(a.direction.as_deref(), EdgeDirection::Both)?;
    let edge_kinds = parse_edge_kinds(a.edge_kinds)?;
    let node_kinds = parse_node_kinds(a.node_kinds)?;
    let cursor = a.cursor.map(|c| AdjacencyCursor {
        weight: c.weight,
        asserted_at: c.asserted_at,
        edge_id: c.edge_id,
    });
    let req = NeighborsRequest {
        org_id,
        node_id: a.node_id,
        kind,
        external_id: a.external_id,
        direction,
        edge_kinds,
        node_kinds,
        as_of: a.as_of,
        include_proposed: a.include_proposed,
        limit: a.limit,
        cursor,
        deadline_ms: a.deadline_ms,
        scope,
    };
    ctx.hub
        .db()
        .read_async(move |conn| {
            let mut repo = SqliteGraph::new(conn);
            let res = ua_graph::neighbors(&mut repo, req)?;
            Ok(serde_json::to_value(res)?)
        })
        .await
}

async fn handle_traverse(ctx: ToolCtx, a: TraverseArgs) -> UaResult<Value> {
    let org_id = ctx.caller.org_id.clone();
    let scope = caller_scope(&ctx);
    let direction = parse_direction(a.direction.as_deref(), EdgeDirection::Both)?;
    let edge_kinds = parse_edge_kinds(a.edge_kinds)?;
    let node_kinds = parse_node_kinds(a.node_kinds)?;
    let req = KHopRequest {
        org_id,
        seed_ids: a.seed_ids,
        max_hops: a.max_hops,
        direction,
        edge_kinds,
        node_kinds,
        as_of: a.as_of,
        include_proposed: a.include_proposed,
        max_nodes: a.max_nodes,
        max_edges: a.max_edges,
        max_degree_per_node: a.max_degree_per_node,
        max_visited_edges: a.max_visited_edges,
        skip_hubs_over: a.skip_hubs_over,
        deadline_ms: a.deadline_ms,
        scope,
    };
    ctx.hub
        .db()
        .read_async(move |conn| {
            let mut repo = SqliteGraph::new(conn);
            let res = ua_graph::k_hop(&mut repo, req)?;
            Ok(serde_json::to_value(res)?)
        })
        .await
}

async fn handle_shortest_path(ctx: ToolCtx, a: ShortestPathArgs) -> UaResult<Value> {
    let org_id = ctx.caller.org_id.clone();
    let scope = caller_scope(&ctx);
    let direction = parse_direction(a.direction.as_deref(), EdgeDirection::Out)?;
    let edge_kinds = parse_edge_kinds(a.edge_kinds)?;
    let node_kinds = parse_node_kinds(a.node_kinds)?;
    let req = ShortestPathRequest {
        org_id,
        from_id: a.from_id,
        to_id: a.to_id,
        direction,
        edge_kinds,
        node_kinds,
        as_of: a.as_of,
        include_proposed: a.include_proposed,
        max_depth: a.max_depth,
        deadline_ms: a.deadline_ms,
        scope,
    };
    ctx.hub
        .db()
        .read_async(move |conn| {
            let mut repo = SqliteGraph::new(conn);
            let res = ua_graph::shortest_path(&mut repo, req)?;
            Ok(serde_json::to_value(res)?)
        })
        .await
}

async fn handle_expand(ctx: ToolCtx, a: ExpandArgs) -> UaResult<Value> {
    let org_id = ctx.caller.org_id.clone();
    let scope = caller_scope(&ctx);
    let walk_direction = parse_walk_direction(a.walk_direction.as_deref())?;
    let edge_kinds = parse_edge_kinds(a.edge_kinds)?;
    let node_kinds = parse_node_kinds(a.node_kinds)?;
    let seeds = a.seeds.into_iter().map(|s| SeedInput { node_id: s.node_id, weight: s.weight }).collect();
    let req = SeedExpandRequest {
        org_id,
        seeds,
        edge_kinds,
        node_kinds,
        as_of: a.as_of,
        include_proposed: a.include_proposed,
        walk_direction,
        damping: a.damping,
        max_iters: a.max_iters,
        eps: a.eps,
        max_results: a.max_results,
        skip_hubs_over: a.skip_hubs_over,
        deadline_ms: a.deadline_ms,
        scope,
    };
    ctx.hub
        .db()
        .read_async(move |conn| {
            let mut repo = SqliteGraph::new(conn);
            let res = ua_graph::seed_expand(&mut repo, req)?;
            Ok(serde_json::to_value(res)?)
        })
        .await
}

async fn handle_edge_assert(ctx: ToolCtx, a: EdgeAssertArgs) -> UaResult<Value> {
    let (principal, asserted_by_kind) = verified_writer(&ctx)?;
    let org_id = ctx.caller.org_id.clone();
    if org_id != DEFAULT_ORG {
        return Err(UaError::denied(
            "principal_id_required",
            format!(
                "non-system graph edge writes in non-default organization {org_id:?} are refused until \
                 immutable principal IDs (#2790) land"
            ),
        ));
    }
    let kind = EdgeKind::parse(&a.kind)?;
    if !kind.is_generic_assertable() {
        return Err(UaError::denied(
            "domain_owned_edge",
            format!(
                "edge kind {:?} is domain-owned and cannot be asserted via graph_edge_assert",
                kind.as_str()
            ),
        ));
    }
    let state = parse_edge_state(a.state.as_deref(), kind)?;
    let scope = caller_scope(&ctx);
    let max_edges_per_org = ctx.hub.cfg().graph_max_edges_per_org;
    let provenance = Provenance {
        asserted_by: principal,
        asserted_by_kind,
        source_kind: SourceKind::Event,
        source_ref: "tool:graph_edge_assert".to_string(),
    };
    let req = AssertEdgeRequest {
        org_id,
        src_id: a.src_id,
        dst_id: a.dst_id,
        kind,
        assertion_scope: a.assertion_scope,
        state,
        weight: a.weight.unwrap_or(1.0),
        provenance,
        valid_from: None,
        valid_to: None,
        meta_json: a.meta_json,
        scope,
        generic: true,
        max_edges_per_org,
        cycle_bounds: CycleCheckBounds::default(),
    };
    ctx.hub
        .db()
        .write_async(move |tx| {
            let edge = ua_graph::assert_edge(tx, req)?;
            Ok(json!({ "edge": edge }))
        })
        .await
}

async fn handle_edge_retract(ctx: ToolCtx, a: EdgeRetractArgs) -> UaResult<Value> {
    let (retractor, retractor_kind) = verified_writer(&ctx)?;
    let org_id = ctx.caller.org_id.clone();
    if org_id != DEFAULT_ORG {
        return Err(UaError::denied(
            "principal_id_required",
            format!(
                "non-system graph edge retractions in non-default organization {org_id:?} are refused until \
                 immutable principal IDs (#2790) land"
            ),
        ));
    }
    let edge_id = a.edge_id.trim().to_string();
    if edge_id.is_empty() {
        return Err(UaError::invalid("edge_id must not be empty"));
    }
    let ctx2 = ctx.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let edge = tx
                .get_edge_by_id(&org_id, &edge_id)?
                .ok_or_else(|| UaError::not_found("graph edge not found"))?;
            let kind = EdgeKind::parse(&edge.kind)?;
            if !kind.is_generic_assertable() {
                return Err(UaError::denied(
                    "domain_owned_edge",
                    format!(
                        "edge kind {:?} is domain-owned and cannot be retracted via graph_edge_retract",
                        kind.as_str()
                    ),
                ));
            }
            if edge.asserted_by != retractor.as_str() {
                Authz::new(ctx2.hub.cfg()).require(
                    &ctx2.caller,
                    &[Authority::Operator, Authority::LifecycleOperator],
                    &org_id,
                )?;
            }
            let closed = ua_graph::retract_edge(
                tx,
                RetractEdgeRequest {
                    org_id,
                    edge_id,
                    retractor,
                    retractor_kind,
                    valid_to: None,
                    generic: true,
                },
            )?;
            Ok(json!({ "edge": closed }))
        })
        .await
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "graph_node_get",
            "Fetch a single visible node in the caller's organization by surrogate node_id or (kind, external_id). Returns {node}.",
            handle_node_get,
        )
        .family(FAMILY)
        .read_only(),
    );
    r.add(
        tool(
            "graph_neighbors",
            "Return bounded 1-hop incident edges and adjacent visible nodes for a seed node in the caller's organization, ordered deterministically by (weight DESC, asserted_at DESC, edge_id ASC) with cursor pagination.",
            handle_neighbors,
        )
        .family(FAMILY)
        .read_only(),
    );
    r.add(
        tool(
            "graph_traverse",
            "Bounded k-hop BFS expansion from 1-20 seed nodes in the caller's organization with hard caps on hops (<=4), degree (<=200), scanned edges (<=10000), returned nodes (<=500), returned edges (<=1000), and wall-clock deadline.",
            handle_traverse,
        )
        .family(FAMILY)
        .read_only(),
    );
    r.add(
        tool(
            "graph_shortest_path",
            "Bounded bidirectional BFS shortest path between two visible nodes in the caller's organization (max_depth <= 6, max expanded nodes 5000, max expanded edges 10000).",
            handle_shortest_path,
        )
        .family(FAMILY)
        .read_only(),
    );
    r.add(
        tool(
            "graph_expand",
            "Personalized PageRank (Haveliwala 2002) expansion from 1-50 weighted seed nodes over visible edges in the caller's organization; exact on small subgraphs and bounded 2-hop ego subgraph on large org graphs.",
            handle_expand,
        )
        .family(FAMILY)
        .read_only(),
    );
    r.add(
        tool(
            "graph_edge_assert",
            "Assert a generic-assertable typed graph edge (extends, contradicts as proposed, links_to, or plan_tracks) between two existing visible nodes in the caller's organization. Never creates nodes; refuses domain-owned edge kinds.",
            handle_edge_assert,
        )
        .family(FAMILY),
    );
    r.add(
        tool(
            "graph_edge_retract",
            "Retract (close with valid_to = now) a live generic-assertable graph edge in the caller's organization. Allowed for the original asserter, an operator, or a lifecycle operator.",
            handle_edge_retract,
        )
        .family(FAMILY),
    );
}

//! Bounded graph traversals (`docs/graph.md`, Query shapes and hard bounds):
//!
//! 1. [`neighbors`] — 1-hop deterministic cursor-paginated adjacency
//! 2. [`k_hop`] — level-by-level BFS with hard degree, scan, node, edge, and deadline bounds
//! 3. [`shortest_path`] — bounded bidirectional BFS alternating the smaller frontier
//! 4. [`seed_expand`] — Personalized PageRank (Haveliwala 2002), exact on small
//!    eligible slices (`<= 5,000` nodes, `<= 25,000` edges) and bounded 2-hop ego
//!    subgraph on larger org graphs.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use ua_core::{UaError, UaResult};
use ua_store::graph::{
    AdjacencyCursor, AdjacencyQuery, EdgeDirection, EdgeFilter, GraphEdgeRow, GraphNodeRow, GraphRead,
    VisibilityScope,
};

use crate::types::{EdgeKind, NodeKind, WalkDirection, normalize_timestamp};

pub const DEFAULT_DEADLINE_MS: u64 = 500;
pub const MAX_DEADLINE_MS: u64 = 2_000;

pub const NEIGHBORS_DEFAULT_LIMIT: usize = 50;
pub const NEIGHBORS_MAX_LIMIT: usize = 200;

pub const KHOP_MAX_SEEDS: usize = 20;
pub const KHOP_DEFAULT_HOPS: usize = 2;
pub const KHOP_MAX_HOPS: usize = 4;
pub const KHOP_DEFAULT_DEGREE: usize = 50;
pub const KHOP_MAX_DEGREE: usize = 200;
pub const KHOP_DEFAULT_VISITED_EDGES: usize = 2_000;
pub const KHOP_MAX_VISITED_EDGES: usize = 10_000;
pub const KHOP_DEFAULT_NODES: usize = 100;
pub const KHOP_MAX_NODES: usize = 500;
pub const KHOP_DEFAULT_EDGES: usize = 250;
pub const KHOP_MAX_EDGES: usize = 1_000;

pub const SHORTEST_PATH_DEFAULT_DEPTH: usize = 4;
pub const SHORTEST_PATH_MAX_DEPTH: usize = 6;
pub const SHORTEST_PATH_MAX_NODES: usize = 5_000;
pub const SHORTEST_PATH_MAX_EDGES: usize = 10_000;

pub const PPR_MAX_SEEDS: usize = 50;
pub const PPR_DEFAULT_DAMPING: f64 = 0.85;
pub const PPR_MIN_DAMPING: f64 = 0.10;
pub const PPR_MAX_DAMPING: f64 = 0.95;
pub const PPR_DEFAULT_ITERS: usize = 30;
pub const PPR_MAX_ITERS: usize = 50;
pub const PPR_DEFAULT_EPS: f64 = 1e-6;
pub const PPR_MIN_EPS: f64 = 1e-9;
pub const PPR_MAX_EPS: f64 = 1e-2;
pub const PPR_DEFAULT_RESULTS: usize = 10;
pub const PPR_MAX_RESULTS: usize = 50;
pub const PPR_EXACT_NODE_CAP: usize = 5_000;
pub const PPR_EXACT_EDGE_CAP: usize = 25_000;
pub const PPR_EGO_MAX_DEGREE: usize = 200;

fn build_filter(
    as_of: Option<&str>,
    edge_kinds: &[EdgeKind],
    node_kinds: &[NodeKind],
    include_proposed: bool,
) -> UaResult<EdgeFilter> {
    let as_of_norm = match as_of {
        Some(raw) => normalize_timestamp(raw, "as_of")?,
        None => ua_core::time::now(),
    };
    Ok(EdgeFilter {
        as_of: as_of_norm,
        edge_kinds: edge_kinds.iter().map(|k| k.as_str().to_string()).collect(),
        node_kinds: node_kinds.iter().map(|k| k.as_str().to_string()).collect(),
        include_proposed,
    })
}

fn clamp_deadline(ms: Option<u64>) -> Duration {
    Duration::from_millis(ms.unwrap_or(DEFAULT_DEADLINE_MS).clamp(1, MAX_DEADLINE_MS))
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

// ---------------------------------------------------------------------------
// 0. Node point lookup
// ---------------------------------------------------------------------------

/// Look up one visible node by `id` or `(kind, external_id)` in `org_id`.
/// Returns `not_found` identically for missing, foreign-org, and hidden nodes.
pub fn node_get<R: GraphRead>(
    repo: &mut R,
    org_id: &str,
    node_id: Option<&str>,
    kind: Option<NodeKind>,
    external_id: Option<&str>,
    scope: &VisibilityScope,
) -> UaResult<GraphNodeRow> {
    repo.require_org_exists(org_id)?;
    let row = match (node_id, kind, external_id) {
        (Some(id), None, None) => {
            if id.trim().is_empty() {
                return Err(UaError::invalid("node_id must not be empty"));
            }
            repo.get_node_by_id(org_id, id.trim(), scope)?
        }
        (None, Some(k), Some(ext)) => {
            if ext.trim().is_empty() {
                return Err(UaError::invalid("external_id must not be empty"));
            }
            repo.get_node_by_external(org_id, k.as_str(), ext.trim(), scope)?
        }
        _ => {
            return Err(UaError::invalid("provide either node_id, or both kind and external_id (not both)"));
        }
    };
    row.ok_or_else(|| UaError::not_found("graph node not found"))
}

// ---------------------------------------------------------------------------
// 1. neighbors (1-hop adjacency)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NeighborsRequest {
    pub org_id: String,
    pub node_id: Option<String>,
    pub kind: Option<NodeKind>,
    pub external_id: Option<String>,
    pub direction: EdgeDirection,
    pub edge_kinds: Vec<EdgeKind>,
    pub node_kinds: Vec<NodeKind>,
    pub as_of: Option<String>,
    pub include_proposed: bool,
    pub limit: Option<usize>,
    pub cursor: Option<AdjacencyCursor>,
    pub deadline_ms: Option<u64>,
    pub scope: VisibilityScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborItem {
    pub node: GraphNodeRow,
    pub edge: GraphEdgeRow,
    pub direction: EdgeDirection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborsResult {
    pub node: GraphNodeRow,
    pub neighbors: Vec<NeighborItem>,
    pub truncated: bool,
    pub next_cursor: Option<AdjacencyCursor>,
}

pub fn neighbors<R: GraphRead>(repo: &mut R, req: NeighborsRequest) -> UaResult<NeighborsResult> {
    let seed = node_get(
        repo,
        &req.org_id,
        req.node_id.as_deref(),
        req.kind,
        req.external_id.as_deref(),
        &req.scope,
    )?;
    let filter = build_filter(req.as_of.as_deref(), &req.edge_kinds, &req.node_kinds, req.include_proposed)?;
    let limit = req.limit.unwrap_or(NEIGHBORS_DEFAULT_LIMIT).clamp(1, NEIGHBORS_MAX_LIMIT);
    let _deadline = clamp_deadline(req.deadline_ms);

    let mut entries = repo.adjacent_edges(&AdjacencyQuery {
        org_id: req.org_id,
        node_id: seed.id.clone(),
        direction: req.direction,
        filter,
        scope: req.scope,
        limit: limit + 1,
        cursor: req.cursor,
    })?;

    let truncated = entries.len() > limit;
    if truncated {
        entries.truncate(limit);
    }
    let next_cursor = if truncated {
        entries.last().map(|e| AdjacencyCursor {
            weight: e.edge.weight,
            asserted_at: e.edge.asserted_at.clone(),
            edge_id: e.edge.id.clone(),
        })
    } else {
        None
    };

    let neighbors = entries
        .into_iter()
        .map(|e| NeighborItem { node: e.neighbor, edge: e.edge, direction: e.direction })
        .collect();

    Ok(NeighborsResult { node: seed, neighbors, truncated, next_cursor })
}

// ---------------------------------------------------------------------------
// 2. k_hop (bounded BFS expansion)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct KHopRequest {
    pub org_id: String,
    pub seed_ids: Vec<String>,
    pub max_hops: Option<usize>,
    pub direction: EdgeDirection,
    pub edge_kinds: Vec<EdgeKind>,
    pub node_kinds: Vec<NodeKind>,
    pub as_of: Option<String>,
    pub include_proposed: bool,
    pub max_nodes: Option<usize>,
    pub max_edges: Option<usize>,
    pub max_degree_per_node: Option<usize>,
    pub max_visited_edges: Option<usize>,
    pub skip_hubs_over: Option<usize>,
    pub deadline_ms: Option<u64>,
    pub scope: VisibilityScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KHopResult {
    pub nodes: Vec<GraphNodeRow>,
    pub edges: Vec<GraphEdgeRow>,
    pub hops_completed: usize,
    pub visited_edges: usize,
    pub truncated: bool,
    pub truncation_reason: Option<String>,
}

pub fn k_hop<R: GraphRead>(repo: &mut R, req: KHopRequest) -> UaResult<KHopResult> {
    repo.require_org_exists(&req.org_id)?;
    if req.seed_ids.is_empty() || req.seed_ids.len() > KHOP_MAX_SEEDS {
        return Err(UaError::invalid(format!(
            "seed_ids must contain between 1 and {KHOP_MAX_SEEDS} node IDs"
        )));
    }
    let max_hops = req.max_hops.unwrap_or(KHOP_DEFAULT_HOPS);
    if max_hops == 0 || max_hops > KHOP_MAX_HOPS {
        return Err(UaError::invalid(format!("max_hops must be between 1 and {KHOP_MAX_HOPS}")));
    }
    let max_nodes = req.max_nodes.unwrap_or(KHOP_DEFAULT_NODES).clamp(1, KHOP_MAX_NODES);
    let max_edges = req.max_edges.unwrap_or(KHOP_DEFAULT_EDGES).clamp(1, KHOP_MAX_EDGES);
    let max_degree = req.max_degree_per_node.unwrap_or(KHOP_DEFAULT_DEGREE).clamp(1, KHOP_MAX_DEGREE);
    let max_visited_edges =
        req.max_visited_edges.unwrap_or(KHOP_DEFAULT_VISITED_EDGES).clamp(1, KHOP_MAX_VISITED_EDGES);
    let deadline = clamp_deadline(req.deadline_ms);
    let started = Instant::now();
    let filter = build_filter(req.as_of.as_deref(), &req.edge_kinds, &req.node_kinds, req.include_proposed)?;

    // Resolve visible seeds (missing/foreign/hidden seeds are silently dropped: zero existence oracle).
    let visible_seeds = repo.get_nodes_by_ids(&req.org_id, &req.seed_ids, &req.scope)?;
    let visible_by_id: HashMap<&str, &GraphNodeRow> =
        visible_seeds.iter().map(|n| (n.id.as_str(), n)).collect();

    let mut visited_nodes: HashSet<String> = HashSet::new();
    let mut ordered_node_ids: Vec<String> = Vec::new();
    let mut frontier: Vec<String> = Vec::new();
    let mut seen_edges: HashSet<i64> = HashSet::new();
    let mut ordered_edge_rowids: Vec<i64> = Vec::new();

    for sid in &req.seed_ids {
        if let Some(node) = visible_by_id.get(sid.as_str())
            && visited_nodes.insert(node.id.clone())
        {
            ordered_node_ids.push(node.id.clone());
            frontier.push(node.id.clone());
        }
    }

    let mut truncated = false;
    let mut truncation_reason: Option<String> = None;
    let mut visited_edges: usize = 0;
    let mut hops_completed: usize = 0;

    if ordered_node_ids.len() > max_nodes {
        ordered_node_ids.truncate(max_nodes);
        frontier.truncate(max_nodes);
        truncated = true;
        truncation_reason = Some("node_cap".to_string());
    }

    'hops: for _hop in 0..max_hops {
        if frontier.is_empty() {
            break;
        }
        let mut next_frontier: Vec<String> = Vec::new();
        for pivot in &frontier {
            if started.elapsed() >= deadline {
                truncated = true;
                truncation_reason = Some("deadline".to_string());
                break 'hops;
            }
            if let Some(hub_cap) = req.skip_hubs_over {
                let deg = repo.eligible_degree(
                    &req.org_id,
                    pivot,
                    req.direction,
                    &filter,
                    &req.scope,
                    hub_cap.saturating_add(1),
                )?;
                if deg > hub_cap {
                    continue;
                }
            }
            let adj = repo.compact_adjacent(
                &req.org_id,
                pivot,
                req.direction,
                &filter,
                &req.scope,
                max_degree + 1,
            )?;
            let mut degree_truncated = false;
            let iter_len = if adj.len() > max_degree {
                degree_truncated = true;
                max_degree
            } else {
                adj.len()
            };
            if degree_truncated && !truncated {
                truncated = true;
                truncation_reason = Some("degree_cap".to_string());
            }
            for e in adj.into_iter().take(iter_len) {
                visited_edges += 1;
                if visited_edges > max_visited_edges {
                    truncated = true;
                    truncation_reason = Some("scan_budget".to_string());
                    break 'hops;
                }
                if seen_edges.contains(&e.rowid) {
                    continue;
                }
                let is_new_node = !visited_nodes.contains(&e.neighbor_id);
                if is_new_node && ordered_node_ids.len() >= max_nodes {
                    truncated = true;
                    truncation_reason = Some("node_cap".to_string());
                    break 'hops;
                }
                if ordered_edge_rowids.len() >= max_edges {
                    truncated = true;
                    truncation_reason = Some("edge_cap".to_string());
                    break 'hops;
                }
                seen_edges.insert(e.rowid);
                ordered_edge_rowids.push(e.rowid);
                if is_new_node {
                    visited_nodes.insert(e.neighbor_id.clone());
                    ordered_node_ids.push(e.neighbor_id.clone());
                    next_frontier.push(e.neighbor_id);
                }
            }
        }
        hops_completed += 1;
        frontier = next_frontier;
    }

    // Hydrate full node and edge rows preserving deterministic discovery order.
    let node_rows = repo.get_nodes_by_ids(&req.org_id, &ordered_node_ids, &req.scope)?;
    let mut node_map: HashMap<String, GraphNodeRow> =
        node_rows.into_iter().map(|n| (n.id.clone(), n)).collect();
    let nodes: Vec<GraphNodeRow> = ordered_node_ids.iter().filter_map(|id| node_map.remove(id)).collect();

    let edge_rows = repo.get_edges_by_rowids(&req.org_id, &ordered_edge_rowids)?;
    let mut edge_map: HashMap<i64, GraphEdgeRow> = edge_rows.into_iter().collect();
    let edges: Vec<GraphEdgeRow> =
        ordered_edge_rowids.iter().filter_map(|rid| edge_map.remove(rid)).collect();

    Ok(KHopResult { nodes, edges, hops_completed, visited_edges, truncated, truncation_reason })
}

// ---------------------------------------------------------------------------
// 3. shortest_path (bounded bidirectional BFS)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ShortestPathRequest {
    pub org_id: String,
    pub from_id: String,
    pub to_id: String,
    pub direction: EdgeDirection,
    pub edge_kinds: Vec<EdgeKind>,
    pub node_kinds: Vec<NodeKind>,
    pub as_of: Option<String>,
    pub include_proposed: bool,
    pub max_depth: Option<usize>,
    pub deadline_ms: Option<u64>,
    pub scope: VisibilityScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShortestPathResult {
    pub found: bool,
    pub hops: usize,
    pub node_ids: Vec<String>,
    pub edge_ids: Vec<String>,
    pub truncated: bool,
    pub truncation_reason: Option<String>,
}

fn invert_dir(d: EdgeDirection) -> EdgeDirection {
    match d {
        EdgeDirection::Out => EdgeDirection::In,
        EdgeDirection::In => EdgeDirection::Out,
        EdgeDirection::Both => EdgeDirection::Both,
    }
}

pub fn shortest_path<R: GraphRead>(repo: &mut R, req: ShortestPathRequest) -> UaResult<ShortestPathResult> {
    repo.require_org_exists(&req.org_id)?;
    let max_depth = req.max_depth.unwrap_or(SHORTEST_PATH_DEFAULT_DEPTH);
    if max_depth > SHORTEST_PATH_MAX_DEPTH {
        return Err(UaError::invalid(format!("max_depth must be at most {SHORTEST_PATH_MAX_DEPTH}")));
    }
    let deadline = clamp_deadline(req.deadline_ms);
    let started = Instant::now();
    let filter = build_filter(req.as_of.as_deref(), &req.edge_kinds, &req.node_kinds, req.include_proposed)?;

    // Zero existence oracle: both endpoints must exist in org_id and be visible.
    let from = repo
        .get_node_by_id(&req.org_id, &req.from_id, &req.scope)?
        .ok_or_else(|| UaError::not_found("graph node not found"))?;
    let to = repo
        .get_node_by_id(&req.org_id, &req.to_id, &req.scope)?
        .ok_or_else(|| UaError::not_found("graph node not found"))?;

    if from.id == to.id {
        return Ok(ShortestPathResult {
            found: true,
            hops: 0,
            node_ids: vec![from.id],
            edge_ids: Vec::new(),
            truncated: false,
            truncation_reason: None,
        });
    }
    if max_depth == 0 {
        return Ok(ShortestPathResult {
            found: false,
            hops: 0,
            node_ids: Vec::new(),
            edge_ids: Vec::new(),
            truncated: false,
            truncation_reason: None,
        });
    }

    // Bidirectional BFS: map node_id -> (parent_node_id, via_edge_rowid)
    let mut fwd_parent: HashMap<String, Option<(String, i64)>> = HashMap::new();
    let mut bwd_parent: HashMap<String, Option<(String, i64)>> = HashMap::new();
    fwd_parent.insert(from.id.clone(), None);
    bwd_parent.insert(to.id.clone(), None);

    let mut fwd_frontier: Vec<String> = vec![from.id.clone()];
    let mut bwd_frontier: Vec<String> = vec![to.id.clone()];
    let mut fwd_depth: usize = 0;
    let mut bwd_depth: usize = 0;

    let mut expanded_nodes: usize = 2;
    let mut expanded_edges: usize = 0;
    let mut truncated = false;
    let mut truncation_reason: Option<String> = None;

    let fwd_dir = req.direction;
    let bwd_dir = invert_dir(req.direction);

    let reconstruct = |meet: &str,
                       fwd_p: &HashMap<String, Option<(String, i64)>>,
                       bwd_p: &HashMap<String, Option<(String, i64)>>|
     -> (Vec<String>, Vec<i64>) {
        // Walk backward from meet to `from`
        let mut left_nodes = vec![meet.to_string()];
        let mut left_edges = Vec::new();
        let mut cur = meet;
        while let Some(Some((prev, rid))) = fwd_p.get(cur) {
            left_nodes.push(prev.clone());
            left_edges.push(*rid);
            cur = prev.as_str();
        }
        left_nodes.reverse();
        left_edges.reverse();

        // Walk forward from meet to `to`
        let mut cur = meet;
        while let Some(Some((next, rid))) = bwd_p.get(cur) {
            left_nodes.push(next.clone());
            left_edges.push(*rid);
            cur = next.as_str();
        }
        (left_nodes, left_edges)
    };

    while !fwd_frontier.is_empty() && !bwd_frontier.is_empty() && (fwd_depth + bwd_depth) < max_depth {
        if started.elapsed() >= deadline {
            truncated = true;
            truncation_reason = Some("deadline".to_string());
            break;
        }
        let expand_fwd = fwd_frontier.len() <= bwd_frontier.len();
        let (curr_frontier, dir) = if expand_fwd {
            (std::mem::take(&mut fwd_frontier), fwd_dir)
        } else {
            (std::mem::take(&mut bwd_frontier), bwd_dir)
        };

        let mut next_frontier_set: BTreeSet<String> = BTreeSet::new();
        let mut candidate_meetings: Vec<(Vec<String>, Vec<i64>)> = Vec::new();

        // Track best deterministic parent (by rowid ASC) for each newly discovered node at this level.
        let mut level_new: HashMap<String, (String, i64)> = HashMap::new();

        for u in curr_frontier {
            if started.elapsed() >= deadline {
                truncated = true;
                truncation_reason = Some("deadline".to_string());
                break;
            }
            let rem_edges = SHORTEST_PATH_MAX_EDGES.saturating_sub(expanded_edges);
            if rem_edges == 0 {
                truncated = true;
                truncation_reason = Some("edge_cap".to_string());
                break;
            }
            let adj = repo.compact_adjacent(
                &req.org_id,
                &u,
                dir,
                &filter,
                &req.scope,
                rem_edges.min(SHORTEST_PATH_MAX_EDGES) + 1,
            )?;
            for e in adj {
                expanded_edges += 1;
                if expanded_edges > SHORTEST_PATH_MAX_EDGES {
                    truncated = true;
                    truncation_reason = Some("edge_cap".to_string());
                    break;
                }
                let v = e.neighbor_id;
                let already_mine =
                    if expand_fwd { fwd_parent.contains_key(&v) } else { bwd_parent.contains_key(&v) };
                if already_mine {
                    continue;
                }
                let entry = level_new.entry(v.clone());
                match entry {
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert((u.clone(), e.rowid));
                        next_frontier_set.insert(v.clone());
                    }
                    std::collections::hash_map::Entry::Occupied(mut slot) => {
                        if e.rowid < slot.get().1 {
                            *slot.get_mut() = (u.clone(), e.rowid);
                        }
                    }
                }
            }
            if truncated {
                break;
            }
        }

        for (v, (parent, rid)) in level_new {
            expanded_nodes += 1;
            if expanded_nodes > SHORTEST_PATH_MAX_NODES {
                truncated = true;
                truncation_reason = Some("node_cap".to_string());
                break;
            }
            if expand_fwd {
                fwd_parent.insert(v.clone(), Some((parent, rid)));
                if bwd_parent.contains_key(&v) {
                    candidate_meetings.push(reconstruct(&v, &fwd_parent, &bwd_parent));
                }
            } else {
                bwd_parent.insert(v.clone(), Some((parent, rid)));
                if fwd_parent.contains_key(&v) {
                    candidate_meetings.push(reconstruct(&v, &fwd_parent, &bwd_parent));
                }
            }
        }

        if !candidate_meetings.is_empty() {
            // Hydrate only the winning depth's candidate edge rowids and tie-break by edge_id ASC.
            let mut needed_rowids: Vec<i64> =
                candidate_meetings.iter().flat_map(|(_, rids)| rids.iter().copied()).collect();
            needed_rowids.sort_unstable();
            needed_rowids.dedup();
            let resolved: HashMap<i64, String> = repo
                .get_edges_by_rowids(&req.org_id, &needed_rowids)?
                .into_iter()
                .map(|(rid, e)| (rid, e.id))
                .collect();
            let mut best: Option<(Vec<String>, Vec<String>)> = None;
            for (nodes, rids) in candidate_meetings {
                let eids: Vec<String> = rids.iter().filter_map(|rid| resolved.get(rid).cloned()).collect();
                if eids.len() == rids.len() && best.as_ref().is_none_or(|b| eids < b.1) {
                    best = Some((nodes, eids));
                }
            }
            if let Some((node_ids, edge_ids)) = best {
                let hops = edge_ids.len();
                return Ok(ShortestPathResult {
                    found: true,
                    hops,
                    node_ids,
                    edge_ids,
                    truncated: false,
                    truncation_reason: None,
                });
            }
        }

        if truncated {
            break;
        }
        let next_vec: Vec<String> = next_frontier_set.into_iter().collect();
        if expand_fwd {
            fwd_depth += 1;
            fwd_frontier = next_vec;
        } else {
            bwd_depth += 1;
            bwd_frontier = next_vec;
        }
    }

    Ok(ShortestPathResult {
        found: false,
        hops: 0,
        node_ids: Vec::new(),
        edge_ids: Vec::new(),
        truncated,
        truncation_reason,
    })
}

// ---------------------------------------------------------------------------
// 4. seed_expand (Personalized PageRank — Haveliwala 2002)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SeedInput {
    pub node_id: String,
    pub weight: f64,
}

#[derive(Debug, Clone)]
pub struct SeedExpandRequest {
    pub org_id: String,
    pub seeds: Vec<SeedInput>,
    pub edge_kinds: Vec<EdgeKind>,
    pub node_kinds: Vec<NodeKind>,
    pub as_of: Option<String>,
    pub include_proposed: bool,
    pub walk_direction: WalkDirection,
    pub damping: Option<f64>,
    pub max_iters: Option<usize>,
    pub eps: Option<f64>,
    pub max_results: Option<usize>,
    pub skip_hubs_over: Option<usize>,
    pub deadline_ms: Option<u64>,
    pub scope: VisibilityScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedExpandItem {
    pub node_id: String,
    pub kind: String,
    pub external_id: String,
    pub display_label: Option<String>,
    pub pagerank: f64,
    pub pagerank_norm: f64,
    pub links_out: usize,
    pub links_in: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedExpandGraphStats {
    pub nodes: usize,
    pub edges: usize,
    pub seeds: usize,
    pub iterations: usize,
    pub exact: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedExpandResult {
    pub results: Vec<SeedExpandItem>,
    pub graph: SeedExpandGraphStats,
}

pub fn seed_expand<R: GraphRead>(repo: &mut R, req: SeedExpandRequest) -> UaResult<SeedExpandResult> {
    repo.require_org_exists(&req.org_id)?;
    if req.seeds.is_empty() || req.seeds.len() > PPR_MAX_SEEDS {
        return Err(UaError::invalid(format!("seeds must contain between 1 and {PPR_MAX_SEEDS} entries")));
    }
    for s in &req.seeds {
        if s.node_id.trim().is_empty() {
            return Err(UaError::invalid("seed node_id must not be empty"));
        }
        if !s.weight.is_finite() || s.weight <= 0.0 {
            return Err(UaError::invalid("seed weight must be finite and > 0.0"));
        }
    }

    let damping = req.damping.unwrap_or(PPR_DEFAULT_DAMPING).clamp(PPR_MIN_DAMPING, PPR_MAX_DAMPING);
    let max_iters = req.max_iters.unwrap_or(PPR_DEFAULT_ITERS).clamp(1, PPR_MAX_ITERS);
    let eps = req.eps.unwrap_or(PPR_DEFAULT_EPS).clamp(PPR_MIN_EPS, PPR_MAX_EPS);
    let max_results = req.max_results.unwrap_or(PPR_DEFAULT_RESULTS).clamp(1, PPR_MAX_RESULTS);
    let deadline = clamp_deadline(req.deadline_ms);
    let started = Instant::now();

    let filter = build_filter(req.as_of.as_deref(), &req.edge_kinds, &req.node_kinds, req.include_proposed)?;

    // Resolve visible seeds (missing/foreign/hidden seeds are silently dropped: zero existence oracle).
    let raw_seed_ids: Vec<String> = req.seeds.iter().map(|s| s.node_id.clone()).collect();
    let visible_seed_rows = repo.get_nodes_by_ids(&req.org_id, &raw_seed_ids, &req.scope)?;
    let visible_set: HashSet<&str> = visible_seed_rows.iter().map(|n| n.id.as_str()).collect();
    let mut seed_weights: BTreeMap<String, f64> = BTreeMap::new();
    for s in &req.seeds {
        if visible_set.contains(s.node_id.as_str()) {
            *seed_weights.entry(s.node_id.clone()).or_insert(0.0) += s.weight;
        }
    }
    if seed_weights.is_empty() {
        return Ok(SeedExpandResult {
            results: Vec::new(),
            graph: SeedExpandGraphStats {
                nodes: 0,
                edges: 0,
                seeds: 0,
                iterations: 0,
                exact: true,
                truncated: false,
            },
        });
    }

    // Attempt exact slice first; fall back to bounded 2-hop ego subgraph if org exceeds caps.
    let EgoSubgraph { node_ids, edges: directed_edges, exact, mut truncated } = if let Some(slice) =
        repo.exact_ppr_slice(&req.org_id, &filter, &req.scope, PPR_EXACT_NODE_CAP, PPR_EXACT_EDGE_CAP)?
    {
        EgoSubgraph { node_ids: slice.node_ids, edges: slice.edges, exact: true, truncated: false }
    } else {
        extract_bounded_ego(
            repo,
            &req.org_id,
            &seed_weights,
            req.walk_direction,
            &filter,
            &req.scope,
            req.skip_hubs_over,
            started,
            deadline,
        )?
    };

    // Index nodes densely 0..n
    let mut id_to_idx: HashMap<String, usize> = HashMap::with_capacity(node_ids.len());
    let mut idx_to_id: Vec<String> = Vec::with_capacity(node_ids.len());
    for id in node_ids {
        if !id_to_idx.contains_key(&id) {
            let idx = idx_to_id.len();
            id_to_idx.insert(id.clone(), idx);
            idx_to_id.push(id);
        }
    }
    for sid in seed_weights.keys() {
        if !id_to_idx.contains_key(sid) {
            let idx = idx_to_id.len();
            id_to_idx.insert(sid.clone(), idx);
            idx_to_id.push(sid.clone());
        }
    }
    let n = idx_to_id.len();

    // Build directed out/in counts and optional hub filter (for exact slice mode).
    let mut out_adj: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n];
    let mut in_adj: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n];
    let mut out_deg: Vec<usize> = vec![0; n];
    let mut in_deg: Vec<usize> = vec![0; n];

    // First compute raw degrees if hub-skipping is active in exact mode.
    let hub_blocked: Vec<bool> = if exact {
        if let Some(hub_cap) = req.skip_hubs_over {
            let mut deg = vec![0usize; n];
            for (s, d, _) in &directed_edges {
                if let (Some(&si), Some(&di)) = (id_to_idx.get(s), id_to_idx.get(d))
                    && si != di
                {
                    deg[si] += 1;
                    if req.walk_direction == WalkDirection::Undirected {
                        deg[di] += 1;
                    }
                }
            }
            deg.into_iter()
                .enumerate()
                .map(|(i, d)| d > hub_cap && !seed_weights.contains_key(&idx_to_id[i]))
                .collect()
        } else {
            vec![false; n]
        }
    } else {
        vec![false; n]
    };

    let mut edge_count = 0usize;
    for (s, d, w) in directed_edges {
        if let (Some(&si), Some(&di)) = (id_to_idx.get(&s), id_to_idx.get(&d)) {
            if si == di || hub_blocked[si] || hub_blocked[di] {
                continue;
            }
            out_adj[si].push((di, w));
            in_adj[di].push((si, w));
            out_deg[si] += 1;
            in_deg[di] += 1;
            edge_count += 1;
        }
    }

    // Build transition adjacency matching `walk_direction` using flat sorted
    // vectors (zero BTreeMap allocations). Taking max weight on mutual pairs
    // matches `vault_query.rs` bit-for-bit on unit-weight graphs.
    let mut dedup_max = |mut pairs: Vec<(usize, f64)>| -> (Vec<(usize, f64)>, f64) {
        if pairs.is_empty() {
            return (pairs, 0.0);
        }
        pairs.sort_unstable_by_key(|&(j, _)| j);
        let mut write = 0usize;
        for read in 1..pairs.len() {
            if pairs[read].0 == pairs[write].0 {
                pairs[write].1 = pairs[write].1.max(pairs[read].1);
            } else {
                write += 1;
                pairs[write] = pairs[read];
            }
        }
        pairs.truncate(write + 1);
        let sum: f64 = pairs.iter().map(|&(_, w)| w).sum();
        (pairs, sum)
    };
    let transitions: Vec<(Vec<(usize, f64)>, f64)> = match req.walk_direction {
        WalkDirection::Out => out_adj.into_iter().map(&mut dedup_max).collect(),
        WalkDirection::Undirected => (0..n)
            .map(|i| {
                let mut combined = Vec::with_capacity(out_adj[i].len() + in_adj[i].len());
                combined.extend_from_slice(&out_adj[i]);
                combined.extend_from_slice(&in_adj[i]);
                dedup_max(combined)
            })
            .collect(),
    };

    // Teleport vector normalized to sum = 1.0
    let total_seed_weight: f64 = seed_weights.values().sum();
    let mut teleport = vec![0.0f64; n];
    for (sid, w) in &seed_weights {
        if let Some(&idx) = id_to_idx.get(sid) {
            teleport[idx] = w / total_seed_weight;
        }
    }

    // Haveliwala (2002) power iteration with dangling-mass redistribution to teleport.
    let mut p = teleport.clone();
    let mut iterations = 0usize;
    for _ in 0..max_iters {
        if started.elapsed() >= deadline {
            truncated = true;
            break;
        }
        iterations += 1;
        let mut next: Vec<f64> = teleport.iter().map(|t| (1.0 - damping) * t).collect();
        let mut dangling = 0.0f64;
        for i in 0..n {
            let mass = damping * p[i];
            if mass == 0.0 {
                continue;
            }
            let (ref nbrs, w_sum) = transitions[i];
            if nbrs.is_empty() || w_sum <= 0.0 {
                dangling += mass;
            } else {
                for &(j, w) in nbrs {
                    next[j] += mass * (w / w_sum);
                }
            }
        }
        if dangling > 0.0 {
            for i in 0..n {
                if teleport[i] > 0.0 {
                    next[i] += dangling * teleport[i];
                }
            }
        }
        let delta: f64 = (0..n).map(|i| (next[i] - p[i]).abs()).sum();
        p = next;
        if delta < eps {
            break;
        }
    }

    let max_ppr = p.iter().copied().fold(0.0f64, f64::max);
    let mut ranked: Vec<(f64, usize)> = (0..n).filter(|&i| p[i] > 0.0).map(|i| (p[i], i)).collect();
    ranked.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| idx_to_id[a.1].cmp(&idx_to_id[b.1])));
    ranked.truncate(max_results);

    let winner_ids: Vec<String> = ranked.iter().map(|&(_, i)| idx_to_id[i].clone()).collect();
    let winner_rows = repo.get_nodes_by_ids(&req.org_id, &winner_ids, &req.scope)?;
    let row_map: HashMap<String, GraphNodeRow> = winner_rows.into_iter().map(|r| (r.id.clone(), r)).collect();

    let results = ranked
        .into_iter()
        .filter_map(|(score, i)| {
            let id = &idx_to_id[i];
            let row = row_map.get(id)?;
            let norm = if max_ppr > 0.0 { score / max_ppr } else { 0.0 };
            Some(SeedExpandItem {
                node_id: row.id.clone(),
                kind: row.kind.clone(),
                external_id: row.external_id.clone(),
                display_label: row.display_label.clone(),
                pagerank: round4(score),
                pagerank_norm: round4(norm),
                links_out: out_deg[i],
                links_in: in_deg[i],
            })
        })
        .collect();

    Ok(SeedExpandResult {
        results,
        graph: SeedExpandGraphStats {
            nodes: n,
            edges: edge_count,
            seeds: seed_weights.len(),
            iterations,
            exact,
            truncated,
        },
    })
}

struct EgoSubgraph {
    node_ids: Vec<String>,
    edges: Vec<(String, String, f64)>,
    exact: bool,
    truncated: bool,
}

/// Bounded 2-hop ego subgraph extraction around visible seeds when the org's
/// eligible graph exceeds `(PPR_EXACT_NODE_CAP, PPR_EXACT_EDGE_CAP)`.
#[allow(clippy::too_many_arguments)]
fn extract_bounded_ego<R: GraphRead>(
    repo: &mut R,
    org_id: &str,
    seed_weights: &BTreeMap<String, f64>,
    walk_direction: WalkDirection,
    filter: &EdgeFilter,
    scope: &VisibilityScope,
    skip_hubs_over: Option<usize>,
    started: Instant,
    deadline: Duration,
) -> UaResult<EgoSubgraph> {
    let dir = match walk_direction {
        WalkDirection::Undirected => EdgeDirection::Both,
        WalkDirection::Out => EdgeDirection::Out,
    };

    let mut nodes: HashSet<String> = HashSet::with_capacity(512);
    let mut ordered_nodes: Vec<String> = Vec::with_capacity(512);
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    let mut seen_edges: HashSet<i64> = HashSet::with_capacity(1024);
    let mut edges: Vec<(String, String, f64)> = Vec::with_capacity(1024);
    let mut truncated = false;

    for sid in seed_weights.keys() {
        if nodes.insert(sid.clone()) {
            ordered_nodes.push(sid.clone());
            queue.push_back((sid.clone(), 0));
        }
    }

    let push_batch = |u: &str,
                      depth: usize,
                      adj: &mut Vec<ua_store::graph::CompactAdjEdge>,
                      req_cap: usize,
                      nodes: &mut HashSet<String>,
                      ordered_nodes: &mut Vec<String>,
                      queue: &mut VecDeque<(String, usize)>,
                      seen_edges: &mut HashSet<i64>,
                      edges: &mut Vec<(String, String, f64)>,
                      truncated: &mut bool| {
        let iter_len = if adj.len() > req_cap {
            *truncated = true;
            req_cap
        } else {
            adj.len()
        };
        for e in adj.drain(..iter_len) {
            if seen_edges.contains(&e.rowid) {
                continue;
            }
            if edges.len() >= PPR_EXACT_EDGE_CAP {
                *truncated = true;
                break;
            }
            let is_new = !nodes.contains(&e.neighbor_id);
            if is_new && ordered_nodes.len() >= PPR_EXACT_NODE_CAP {
                *truncated = true;
                continue;
            }
            seen_edges.insert(e.rowid);
            let (s, d) = match e.direction {
                EdgeDirection::Out => (u.to_string(), e.neighbor_id.clone()),
                EdgeDirection::In => (e.neighbor_id.clone(), u.to_string()),
                EdgeDirection::Both => unreachable!("compact edges carry Out or In"),
            };
            edges.push((s, d, e.weight));
            if is_new {
                nodes.insert(e.neighbor_id.clone());
                ordered_nodes.push(e.neighbor_id.clone());
                if depth + 1 < 2 {
                    queue.push_back((e.neighbor_id, depth + 1));
                }
            }
        }
    };

    match skip_hubs_over {
        None => {
            let mut adj_buf = Vec::with_capacity(PPR_EGO_MAX_DEGREE + 1);
            repo.with_compact_adjacent(org_id, dir, filter, scope, |step| {
                while let Some((u, depth)) = queue.pop_front() {
                    if depth >= 2 {
                        continue;
                    }
                    if started.elapsed() >= deadline {
                        truncated = true;
                        break;
                    }
                    let rem = PPR_EXACT_EDGE_CAP.saturating_sub(edges.len());
                    let cap = PPR_EGO_MAX_DEGREE.min(rem);
                    if cap == 0 {
                        truncated = true;
                        break;
                    }
                    step(&u, dir, cap + 1, &mut adj_buf)?;
                    push_batch(
                        &u,
                        depth,
                        &mut adj_buf,
                        cap,
                        &mut nodes,
                        &mut ordered_nodes,
                        &mut queue,
                        &mut seen_edges,
                        &mut edges,
                        &mut truncated,
                    );
                    if edges.len() >= PPR_EXACT_EDGE_CAP || ordered_nodes.len() >= PPR_EXACT_NODE_CAP {
                        truncated = true;
                        break;
                    }
                }
                Ok(())
            })?;
        }
        Some(hub_cap) => {
            while let Some((u, depth)) = queue.pop_front() {
                if depth >= 2 {
                    continue;
                }
                if started.elapsed() >= deadline {
                    truncated = true;
                    break;
                }
                if depth > 0 {
                    let deg =
                        repo.eligible_degree(org_id, &u, dir, filter, scope, hub_cap.saturating_add(1))?;
                    if deg > hub_cap {
                        continue;
                    }
                }
                let rem = PPR_EXACT_EDGE_CAP.saturating_sub(edges.len());
                let cap = PPR_EGO_MAX_DEGREE.min(rem);
                if cap == 0 {
                    truncated = true;
                    break;
                }
                let mut adj = repo.compact_adjacent(org_id, &u, dir, filter, scope, cap + 1)?;
                push_batch(
                    &u,
                    depth,
                    &mut adj,
                    cap,
                    &mut nodes,
                    &mut ordered_nodes,
                    &mut queue,
                    &mut seen_edges,
                    &mut edges,
                    &mut truncated,
                );
                if edges.len() >= PPR_EXACT_EDGE_CAP || ordered_nodes.len() >= PPR_EXACT_NODE_CAP {
                    truncated = true;
                    break;
                }
            }
        }
    }

    Ok(EgoSubgraph { node_ids: ordered_nodes, edges, exact: false, truncated })
}

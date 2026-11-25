//! Shared tenant-scoped graph store domain (`docs/graph.md`, C1).
//!
//! This crate owns:
//! - the `graph.v1` and `organization.v1.graph` schema parts ([`schema`]),
//! - the closed node/edge kind enums, endpoint-kind matrix, and validated
//!   provenance types ([`types`]),
//! - domain-internal `graph_node_ensure`, governed edge assertion with
//!   hard-bounded write-time acyclicity checks, and edge retraction ([`write`]),
//! - bounded graph traversals: `neighbors`, `k_hop`, bidirectional
//!   `shortest_path`, and `seed_expand` Personalized PageRank ([`query`]).
//!
//! Depends on `ua-core` and `ua-store` only; never on `ua-org` or the tool
//! registry (`tests/dependencies.rs`). Authority checks run in `ua-tools`
//! (`families/graph_store.rs`) before calling here.

pub mod query;
pub mod schema;
pub mod types;
pub mod write;

pub use query::{
    KHopRequest, KHopResult, MAX_SKIP_HUBS_OVER, NeighborItem, NeighborsRequest, NeighborsResult,
    SeedExpandGraphStats, SeedExpandItem, SeedExpandRequest, SeedExpandResult, SeedInput,
    ShortestPathRequest, ShortestPathResult, k_hop, neighbors, node_get, seed_expand, shortest_path,
};
pub use schema::{COUNTERS_SCHEMA, COUNTERS_TENANT_PART, SCHEMA, TENANT_PART, schema_parts};
pub use types::{
    AssertedByKind, EdgeKind, EdgeState, NodeKind, OwnerType, PrincipalId, Provenance, SourceKind,
    Visibility, WalkDirection, normalize_timestamp,
};
pub use write::{
    AssertEdgeRequest, CYCLE_CHECK_DEADLINE_MS, CYCLE_CHECK_MAX_EDGES, CYCLE_CHECK_MAX_NODES,
    CycleCheckBounds, EVENT_EDGE_ASSERTED, EVENT_EDGE_RETRACTED, EVENT_NODE_CREATED, EnsureNodeRequest,
    RetractEdgeRequest, assert_edge, check_acyclic, graph_node_ensure, retract_edge,
};

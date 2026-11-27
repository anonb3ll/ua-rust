//! Shared graph store persistence (`docs/graph.md`, C1).
//!
//! Exposes plain Rust row types and bounded adjacency primitives ([`GraphRead`]
//! and [`GraphRepo`]) over `graph_nodes` and `graph_edges`, keeping `rusqlite`
//! out of the public signatures so `ua-graph` stays backend-independent while
//! writes commit atomically inside the hub's [`WriteTx`] alongside
//! [`crate::ledger::append`].
//!
//! Domain validation (endpoint-kind matrix, generic vs domain-owned edges) and
//! traversal algorithms (`k_hop`, bidirectional `shortest_path`, `seed_expand`
//! PPR) live in `ua-graph`. This module enforces storage-level defense-in-depth
//! invariants:
//!
//! 1. Every query binds `org_id` explicitly and runs the caller's visibility
//!    predicate inside the innermost SQL query before degree counts or `LIMIT`.
//! 2. Pre-#2790 non-default-org principal fence: non-`'system'` `asserted_by`
//!    writes for `org_id != 'default'` are refused (`principal_id_required`).
//! 3. Temporal write invariants: `valid_to <= now` on insert and close,
//!    `valid_to >= valid_from`, and `valid_from == asserted_at` except for
//!    `source_kind == "import"` (which requires `valid_from <= asserted_at`).

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, ErrorCode, OptionalExtension, Row, params, params_from_iter};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ua_core::time::{format_ts, now, parse_ts};
use ua_core::{DEFAULT_ORG, UaError, UaResult};

use crate::db::{WriteTx, instant_to_deadline_nanos};
use crate::ledger::{self, EventInput};

/// Reason code returned when a SQLite progress handler interrupts a graph query
/// at its wall-clock deadline.
pub const DEADLINE_REASON_CODE: &str = "query_deadline_exceeded";

/// True when `err` represents a graph query aborted at its wall-clock deadline.
pub fn is_deadline_error(err: &UaError) -> bool {
    err.reason_code() == Some(DEADLINE_REASON_CODE)
}

fn deadline_error() -> UaError {
    UaError::invalid_code(DEADLINE_REASON_CODE, "graph query exceeded wall-clock deadline")
}

/// Clamp a `usize` SQL `LIMIT` to `i64::MAX` so large values (such as
/// `usize::MAX`) never wrap to `-1` (unlimited) in SQLite.
fn sql_limit(n: usize) -> i64 {
    n.min(i64::MAX as usize) as i64
}

fn map_sql_err(err: rusqlite::Error) -> UaError {
    if let rusqlite::Error::SqliteFailure(ffi_err, _) = &err
        && ffi_err.code == ErrorCode::OperationInterrupted
    {
        return deadline_error();
    }
    UaError::from(err)
}

/// Run `f` with a SQLite `progress_handler` wired to `deadline`, always
/// clearing the handler on normal return, error, or panic so pooled
/// connections never retain a stale hook.
fn run_with_conn_deadline<R, F, T>(
    repo: &mut R,
    get_conn: impl Fn(&mut R) -> &mut Connection,
    deadline: Instant,
    f: F,
) -> UaResult<T>
where
    F: FnOnce(&mut R) -> UaResult<T>,
{
    if Instant::now() >= deadline {
        return Err(deadline_error());
    }
    get_conn(repo).progress_handler(2_000, Some(move || Instant::now() >= deadline)).map_err(map_sql_err)?;
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(repo)));
    let _ = get_conn(repo).progress_handler(0, None::<fn() -> bool>);
    match res {
        Ok(r) => r,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// Run `f` while arming an atomic deadline slot checked by the writer
/// connection's SQLite progress handler, always disarming on return or panic.
fn run_with_atomic_deadline<F, T>(slot: Option<&AtomicU64>, deadline: Instant, f: F) -> UaResult<T>
where
    F: FnOnce() -> UaResult<T>,
{
    if Instant::now() >= deadline {
        return Err(deadline_error());
    }
    let prev = slot.map(|s| s.swap(instant_to_deadline_nanos(deadline), Ordering::Relaxed));
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    if let (Some(s), Some(p)) = (slot, prev) {
        s.store(p, Ordering::Relaxed);
    }
    match res {
        Ok(r) => r,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// One row of `graph_nodes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNodeRow {
    pub id: String,
    pub org_id: String,
    pub kind: String,
    pub external_id: String,
    pub display_label: Option<String>,
    pub visibility: String,
    pub team_id: Option<String>,
    pub owner_type: Option<String>,
    pub owner_id: Option<String>,
    pub asserted_by: String,
    pub asserted_by_kind: String,
    pub source_kind: String,
    pub source_ref: String,
    pub meta_json: String,
    pub created_at: String,
    pub updated_at: String,
    pub archived_at: Option<String>,
}

/// Parameters for inserting a new `graph_nodes` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGraphNode {
    pub id: String,
    pub org_id: String,
    pub kind: String,
    pub external_id: String,
    pub display_label: Option<String>,
    pub visibility: String,
    pub team_id: Option<String>,
    pub owner_type: Option<String>,
    pub owner_id: Option<String>,
    pub asserted_by: String,
    pub asserted_by_kind: String,
    pub source_kind: String,
    pub source_ref: String,
    pub meta_json: String,
    pub created_at: String,
    pub updated_at: String,
}

/// New values for the mutable columns of an existing `graph_nodes` row
/// (`docs/graph.md`, C2 slice 1).
///
/// Immutable identity and provenance columns (`id`, `org_id`, `kind`,
/// `external_id`, `asserted_by`, `asserted_by_kind`, `source_kind`,
/// `source_ref`, `created_at`) are never modified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNodePatch {
    pub display_label: Option<String>,
    pub visibility: String,
    pub team_id: Option<String>,
    pub owner_type: Option<String>,
    pub owner_id: Option<String>,
    pub meta_json: String,
    pub archived_at: Option<String>,
    pub updated_at: String,
}

/// One row of `graph_edges`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphEdgeRow {
    pub id: String,
    pub org_id: String,
    pub src_id: String,
    pub dst_id: String,
    pub kind: String,
    pub assertion_scope: String,
    pub state: String,
    pub weight: f64,
    pub asserted_by: String,
    pub asserted_by_kind: String,
    pub asserted_at: String,
    pub source_kind: String,
    pub source_ref: String,
    pub valid_from: String,
    pub valid_to: Option<String>,
    pub meta_json: String,
}

/// Parameters for inserting a new `graph_edges` row.
#[derive(Debug, Clone, PartialEq)]
pub struct NewGraphEdge {
    pub id: String,
    pub org_id: String,
    pub src_id: String,
    pub dst_id: String,
    pub kind: String,
    pub assertion_scope: String,
    pub state: String,
    pub weight: f64,
    pub asserted_by: String,
    pub asserted_by_kind: String,
    pub asserted_at: String,
    pub source_kind: String,
    pub source_ref: String,
    pub valid_from: String,
    pub valid_to: Option<String>,
    pub meta_json: String,
}

/// Direction of an adjacency query or returned incident edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeDirection {
    Out,
    In,
    Both,
}

/// Caller visibility scope applied inside every SQL node/edge query.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VisibilityScope {
    /// Owner type (`"human"` or `"agent"`) when the caller is a verified principal.
    pub owner_type: Option<String>,
    /// Owner identifier (principal ID / verified label) for `visibility = 'private'` matches.
    pub owner_id: Option<String>,
    /// Team IDs the caller belongs to for `visibility = 'team'` matches.
    pub team_ids: Vec<String>,
}

impl VisibilityScope {
    /// Sees only `visibility = 'org'` nodes (safe default for unverified callers).
    pub fn org_only() -> Self {
        Self::default()
    }

    /// Sees `visibility = 'org'`, caller's `private` nodes, and caller's `team` nodes.
    pub fn for_principal(
        owner_type: impl Into<String>,
        owner_id: impl Into<String>,
        team_ids: Vec<String>,
    ) -> Self {
        Self { owner_type: Some(owner_type.into()), owner_id: Some(owner_id.into()), team_ids }
    }
}

/// Filter applied to edges and neighbor nodes in bounded adjacency queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeFilter {
    /// Normalized fixed-width UTC RFC 3339 timestamp (`YYYY-MM-DDTHH:MM:SS+00:00`).
    pub as_of: String,
    /// Optional allowlist of edge kinds; empty means all kinds.
    pub edge_kinds: Vec<String>,
    /// Optional allowlist of neighbor node kinds; empty means all kinds.
    pub node_kinds: Vec<String>,
    /// Include `state = 'proposed'` edges in addition to `state = 'active'`.
    pub include_proposed: bool,
}

/// Deterministic keyset cursor matching `ORDER BY weight DESC, asserted_at DESC, id ASC`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdjacencyCursor {
    pub weight: f64,
    pub asserted_at: String,
    pub edge_id: String,
}

/// Bounded 1-hop adjacency query.
#[derive(Debug, Clone)]
pub struct AdjacencyQuery {
    pub org_id: String,
    pub node_id: String,
    pub direction: EdgeDirection,
    pub filter: EdgeFilter,
    pub scope: VisibilityScope,
    pub limit: usize,
    pub cursor: Option<AdjacencyCursor>,
}

/// One incident edge plus its adjacent visible node.
#[derive(Debug, Clone, PartialEq)]
pub struct AdjacencyEntry {
    pub edge: GraphEdgeRow,
    pub neighbor: GraphNodeRow,
    /// `Out` when `edge.src_id == seed`, `In` when `edge.dst_id == seed`.
    pub direction: EdgeDirection,
}

/// Compact edge record returned by covering-index adjacency scans for BFS / PPR.
#[derive(Debug, Clone, PartialEq)]
pub struct CompactAdjEdge {
    pub rowid: i64,
    pub neighbor_id: String,
    pub weight: f64,
    pub direction: EdgeDirection,
}

/// Outcome of a bounded covering-index live-edge reachability probe used by
/// write-time acyclicity checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcyclicReachOutcome {
    /// Exhausted all reachable live nodes and edges within bounds without reaching `src_id`.
    Acyclic,
    /// Found a live same-kind path from `dst_id` back to `src_id`.
    CycleDetected,
    /// Exceeded `max_nodes` or `max_edges` before exhausting reachable nodes.
    BoundExceeded(&'static str),
}

/// Full eligible subgraph when small enough for exact Personalized PageRank.
#[derive(Debug, Clone)]
pub struct ExactPprSlice {
    pub node_ids: Vec<String>,
    pub edges: Vec<(String, String, f64)>,
}

/// Read-only bounded graph primitives. Implemented for [`SqliteGraph`] and [`WriteTx`].
pub trait GraphRead {
    /// Verify `org_id` exists in `orgs`.
    fn require_org_exists(&mut self, org_id: &str) -> UaResult<()>;

    /// Fetch one visible, non-archived node by surrogate `id` in `org_id`.
    fn get_node_by_id(
        &mut self,
        org_id: &str,
        id: &str,
        scope: &VisibilityScope,
    ) -> UaResult<Option<GraphNodeRow>>;

    /// Fetch one visible, non-archived node by `(kind, external_id)` in `org_id`.
    fn get_node_by_external(
        &mut self,
        org_id: &str,
        kind: &str,
        external_id: &str,
        scope: &VisibilityScope,
    ) -> UaResult<Option<GraphNodeRow>>;

    /// Fetch visible, non-archived nodes for a bounded slice of `ids` in `org_id`.
    fn get_nodes_by_ids(
        &mut self,
        org_id: &str,
        ids: &[String],
        scope: &VisibilityScope,
    ) -> UaResult<Vec<GraphNodeRow>>;

    /// Fetch one edge by `id` in `org_id` (regardless of `valid_to`).
    fn get_edge_by_id(&mut self, org_id: &str, id: &str) -> UaResult<Option<GraphEdgeRow>>;

    /// Fetch full edges by `ids` in `org_id`.
    fn get_edges_by_ids(&mut self, org_id: &str, ids: &[String]) -> UaResult<Vec<GraphEdgeRow>>;

    /// Fetch full edges by SQLite `rowid`s in `org_id` (used to hydrate results
    /// discovered via covering-index [`compact_adjacent`] scans).
    fn get_edges_by_rowids(&mut self, org_id: &str, rowids: &[i64]) -> UaResult<Vec<(i64, GraphEdgeRow)>>;

    /// Count rows in `graph_nodes` for `org_id` (O(1) via `graph_org_counts`).
    fn count_org_nodes(&mut self, org_id: &str) -> UaResult<u64>;

    /// Count rows in `graph_edges` for `org_id` (O(1) via `graph_org_counts`).
    fn count_org_edges(&mut self, org_id: &str) -> UaResult<u64>;

    /// Bounded count of live (`valid_to IS NULL`) incident edges (out + in) for
    /// `node_id` in `org_id`, stopping once `cap` is reached.
    fn count_node_live_edges_capped(&mut self, org_id: &str, node_id: &str, cap: usize) -> UaResult<usize>;

    /// Execute `f` with a SQLite progress-handler wall-clock deadline installed
    /// on the underlying connection, clearing it unconditionally on return.
    fn with_deadline<F, T>(&mut self, deadline: Instant, f: F) -> UaResult<T>
    where
        Self: Sized,
        F: FnOnce(&mut Self) -> UaResult<T>;

    /// Bounded 1-hop adjacency with full edge and neighbor node rows.
    fn adjacent_edges(&mut self, query: &AdjacencyQuery) -> UaResult<Vec<AdjacencyEntry>>;

    /// Bounded 1-hop compact adjacency (skips metadata columns for fast BFS / PPR).
    /// Ordered deterministically by `weight DESC, rowid ASC`.
    fn compact_adjacent(
        &mut self,
        org_id: &str,
        node_id: &str,
        direction: EdgeDirection,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        limit: usize,
    ) -> UaResult<Vec<CompactAdjEdge>>;

    /// Hold prepared covering-index statements for `direction` across a
    /// multi-pivot traversal (`k_hop`, `shortest_path`, `seed_expand` ego),
    /// invoking `f` with a reusable bounded adjacency stepper
    /// `step(node_id, dir, limit, out)`.
    #[allow(clippy::type_complexity)]
    fn with_compact_adjacent<F, T>(
        &mut self,
        org_id: &str,
        directions: EdgeDirection,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        f: F,
    ) -> UaResult<T>
    where
        F: FnOnce(
            &mut dyn FnMut(&str, EdgeDirection, usize, &mut Vec<CompactAdjEdge>) -> UaResult<()>,
        ) -> UaResult<T>;

    /// Bounded covering-index reachability probe from `dst_id` toward `src_id`
    /// over live (`state = 'active'`, `valid_to IS NULL`) edges of `kind` in
    /// `org_id`, capped at `max_nodes` visited nodes, `max_edges` visited edges,
    /// and a SQLite `progress_handler` wall-clock `deadline`.
    #[allow(clippy::too_many_arguments)]
    fn bounded_acyclic_reach(
        &mut self,
        org_id: &str,
        src_id: &str,
        dst_id: &str,
        kind: &str,
        max_nodes: usize,
        max_edges: usize,
        deadline: Instant,
    ) -> UaResult<AcyclicReachOutcome>;

    /// Bounded count of caller-eligible incident edges for `node_id` up to `cap_plus_one`.
    /// Stops scanning as soon as `cap_plus_one` eligible edges are observed.
    #[allow(clippy::too_many_arguments)]
    fn eligible_degree(
        &mut self,
        org_id: &str,
        node_id: &str,
        direction: EdgeDirection,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        cap_plus_one: usize,
    ) -> UaResult<usize>;

    /// Bounded outgoing live (`valid_to IS NULL`, `state = 'active'`) targets of
    /// `kind` from `src_id` in `org_id`, appended into `out`. Used by the
    /// write-time acyclicity check.
    fn outgoing_live_targets_of_kind_into(
        &mut self,
        org_id: &str,
        src_id: &str,
        kind: &str,
        limit: usize,
        out: &mut Vec<String>,
    ) -> UaResult<()>;

    /// Bounded outgoing live (`valid_to IS NULL`, `state = 'active'`) targets of
    /// `kind` from `src_id` in `org_id`. Used by the write-time acyclicity check.
    fn outgoing_live_targets_of_kind(
        &mut self,
        org_id: &str,
        src_id: &str,
        kind: &str,
        limit: usize,
    ) -> UaResult<Vec<String>> {
        let mut out = Vec::new();
        self.outgoing_live_targets_of_kind_into(org_id, src_id, kind, limit, &mut out)?;
        Ok(out)
    }

    /// Load the full eligible filtered slice for exact PPR if and only if it fits
    /// within `(max_nodes, max_edges)`; returns `Ok(None)` immediately when
    /// either cap is exceeded.
    fn exact_ppr_slice(
        &mut self,
        org_id: &str,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        max_nodes: usize,
        max_edges: usize,
    ) -> UaResult<Option<ExactPprSlice>>;
}

/// Low-level write graph primitives, running inside the caller's write transaction.
///
/// # Low-level storage primitives
///
/// Methods on [`GraphRepo`] enforce only storage-level defense-in-depth checks
/// (tenant existence, pre-#2790 non-default-org provenance, and temporal
/// `valid_to <= now` / `valid_from` invariants). They intentionally skip domain
/// rules — endpoint-kind matrix, domain-owned edge fence, generic empty-scope
/// enforcement, write-time acyclicity checks, quotas, and ledger appends.
/// Production callers MUST go through `ua-graph` (`graph_node_ensure`,
/// `graph_node_update`, `assert_edge`, `graph_edge_update_weight`,
/// `retract_edge`) rather than calling these methods directly,
/// except for controlled bulk import/backfill paths that uphold those
/// invariants themselves.
pub trait GraphRepo: GraphRead {
    /// Look up an existing node by `(org_id, id)` without visibility or
    /// `archived_at` filtering, for domain-internal [`graph_node_update`].
    fn find_node_by_id_internal(&mut self, org_id: &str, id: &str) -> UaResult<Option<GraphNodeRow>>;

    /// Look up an existing node by `(org_id, kind, external_id)` without
    /// visibility filtering, for domain-internal [`ensure_node`] idempotency.
    fn find_node_by_external_internal(
        &mut self,
        org_id: &str,
        kind: &str,
        external_id: &str,
    ) -> UaResult<Option<GraphNodeRow>>;

    /// **Low-level unchecked storage primitive.** Create a node row if
    /// `(org_id, kind, external_id)` is absent, touching nothing if it already
    /// exists. Skips quotas, kind/visibility validation, and ledger appends;
    /// callers should use `ua_graph::graph_node_ensure`.
    fn ensure_node(&mut self, node: &NewGraphNode) -> UaResult<(GraphNodeRow, bool)>;

    /// **Low-level unchecked storage primitive.** Update only the mutable
    /// columns of an existing `graph_nodes` row in `org_id`. Callers MUST go
    /// through `ua_graph::graph_node_update` (enforced by `update_guard`).
    fn update_node_mutable(
        &mut self,
        org_id: &str,
        id: &str,
        patch: &GraphNodePatch,
    ) -> UaResult<Option<GraphNodeRow>>;

    /// **Low-level unchecked storage primitive.** Insert a single edge row.
    /// Enforces non-default-org provenance and temporal invariants only; skips
    /// endpoint-kind validation, domain-owned edge fence, acyclicity checks,
    /// quotas, and ledger appends. Callers must use `ua_graph::assert_edge`.
    fn insert_edge(&mut self, edge: &NewGraphEdge) -> UaResult<GraphEdgeRow>;

    /// **Low-level unchecked storage primitive.** Update `weight` on a live
    /// (`valid_to IS NULL`) edge in `org_id`. Callers MUST go through
    /// `ua_graph::graph_edge_update_weight` (enforced by `update_guard`).
    fn update_edge_weight(
        &mut self,
        org_id: &str,
        edge_id: &str,
        weight: f64,
    ) -> UaResult<Option<GraphEdgeRow>>;

    /// **Low-level unchecked storage primitive.** Batch-insert nodes inside the
    /// caller's open transaction using a cached prepared statement (provenance
    /// checks only; skips quotas and ledger appends). Intended for controlled
    /// bulk backfill/import only.
    fn insert_nodes_batch(&mut self, nodes: &[NewGraphNode]) -> UaResult<usize>;

    /// **Low-level unchecked storage primitive.** Batch-insert edges inside the
    /// caller's open transaction using a cached prepared statement (provenance
    /// and temporal checks only; skips endpoint-kind, domain-owned, acyclicity,
    /// quota, and ledger checks). Intended for controlled bulk backfill/import only.
    fn insert_edges_batch(&mut self, edges: &[NewGraphEdge]) -> UaResult<usize>;

    /// Close a currently live (`valid_to IS NULL`) edge by stamping `valid_to`.
    /// Validates `valid_to <= now` and `valid_to >= valid_from`.
    fn close_edge(&mut self, org_id: &str, edge_id: &str, valid_to: &str) -> UaResult<Option<GraphEdgeRow>>;

    /// Append a ledger event in the same write transaction and return its `seq`
    /// (if ledger recording is enabled; returns `None` only when deduped).
    fn record_event(&mut self, channel: &str, payload: Value, originator: &str) -> UaResult<Option<i64>>;
}

/// Borrowed SQLite reader implementing [`GraphRead`].
pub struct SqliteGraph<'a> {
    conn: &'a mut Connection,
}

impl<'a> SqliteGraph<'a> {
    pub fn new(conn: &'a mut Connection) -> Self {
        Self { conn }
    }
}

/// Insert-only SQLite graph handle over a shared [`Connection`] for schema
/// migration procedures and bulk importers (`ua-import`) that must run inside
/// an existing migration/import transaction without appending to `event_log`
/// (`docs/organization.md`, item 11: a schema part cannot append to the
/// hash-chained ledger).
///
/// Implements [`GraphRead`] and the ensure/insert methods of [`GraphRepo`] so
/// migrations and importers still run full `ua-graph` domain validation
/// (`graph_node_ensure`, `assert_edge`). Update and close operations are
/// refused.
///
/// **Guarded:** `crates/ua-graph/tests/update_guard.rs` enforces that only
/// explicitly allowlisted migration/import modules may reference
/// `MigrationGraph`; runtime tool handlers and `ua-server` must always write
/// through `&mut WriteTx<'_>` so ledger events are recorded.
pub struct MigrationGraph<'a> {
    conn: &'a Connection,
}

impl<'a> MigrationGraph<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers (defense-in-depth inside ua-store)
// ---------------------------------------------------------------------------

/// Fast-path check for an already-normalized 25-byte RFC 3339 UTC timestamp
/// (`YYYY-MM-DDTHH:MM:SS+00:00`) to avoid `jiff` parse/format overhead on hot
/// batch writes.
fn is_canonical_utc_ts(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 25
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || &b[19..] != b"+00:00"
    {
        return false;
    }
    let digit = |i: usize| b[i].is_ascii_digit();
    if !(digit(0)
        && digit(1)
        && digit(2)
        && digit(3)
        && digit(5)
        && digit(6)
        && digit(8)
        && digit(9)
        && digit(11)
        && digit(12)
        && digit(14)
        && digit(15)
        && digit(17)
        && digit(18))
    {
        return false;
    }
    let two = |i: usize| (b[i] - b'0') * 10 + (b[i + 1] - b'0');
    let month = two(5);
    let day = two(8);
    let hour = two(11);
    let min = two(14);
    let sec = two(17);
    (1..=12).contains(&month) && (1..=31).contains(&day) && hour <= 23 && min <= 59 && sec <= 59
}

fn normalize_ts_cow<'a>(raw: &'a str, field: &str) -> UaResult<Cow<'a, str>> {
    let trimmed = raw.trim();
    if is_canonical_utc_ts(trimmed) {
        return Ok(Cow::Borrowed(trimmed));
    }
    let ts = parse_ts(trimmed)
        .ok_or_else(|| UaError::invalid(format!("{field} must be a valid RFC 3339 timestamp")))?;
    Ok(Cow::Owned(format_ts(ts)))
}

type EdgeTemporalCow<'a> = (Cow<'a, str>, Cow<'a, str>, Option<Cow<'a, str>>);

fn check_edge_temporal_cow<'a>(
    source_kind: &str,
    asserted_at: &'a str,
    valid_from: &'a str,
    valid_to: Option<&'a str>,
    now_str: &str,
) -> UaResult<EdgeTemporalCow<'a>> {
    let a = normalize_ts_cow(asserted_at, "asserted_at")?;
    let vf = normalize_ts_cow(valid_from, "valid_from")?;
    if source_kind == "import" {
        if vf.as_ref() > a.as_ref() {
            return Err(UaError::invalid("import edge valid_from must be <= asserted_at"));
        }
    } else if vf.as_ref() != a.as_ref() {
        return Err(UaError::invalid(
            "valid_from must equal asserted_at for non-import edges (backdating is refused)",
        ));
    }
    let vt = match valid_to {
        Some(raw) => {
            let v = normalize_ts_cow(raw, "valid_to")?;
            if v.as_ref() > now_str {
                return Err(UaError::invalid_code(
                    "future_valid_to",
                    "valid_to must be <= current hub time (future-dated valid_to is refused)",
                ));
            }
            if v.as_ref() < vf.as_ref() {
                return Err(UaError::invalid("valid_to must be >= valid_from"));
            }
            Some(v)
        }
        None => None,
    };
    Ok((a, vf, vt))
}

/// Normalize and validate an RFC 3339 timestamp to fixed-width UTC
/// (`YYYY-MM-DDTHH:MM:SS+00:00`).
fn normalize_ts(raw: &str, field: &str) -> UaResult<String> {
    normalize_ts_cow(raw, field).map(Cow::into_owned)
}

/// Enforce the pre-#2790 non-default-org provenance fence (`docs/graph.md`,
/// Provenance and temporal validity, ruling 2) plus symmetric `'system'`
/// consistency.
fn check_provenance(
    org_id: &str,
    asserted_by: &str,
    asserted_by_kind: &str,
    source_kind: &str,
) -> UaResult<()> {
    let is_system_by = asserted_by == "system";
    let is_system_kind = asserted_by_kind == "system";
    if is_system_by != is_system_kind {
        return Err(UaError::invalid(
            "asserted_by = 'system' requires asserted_by_kind = 'system' and vice versa",
        ));
    }
    if org_id != DEFAULT_ORG
        && !(is_system_by && is_system_kind && matches!(source_kind, "mirror" | "import"))
    {
        return Err(UaError::denied(
            "principal_id_required",
            format!(
                "non-system graph writes in non-default organization {org_id:?} are refused until \
                 immutable principal IDs (#2790) land"
            ),
        ));
    }
    Ok(())
}

/// Enforce write-time temporal validity invariants (`docs/graph.md`, Validity
/// and `as_of` reads):
/// - `valid_from` equals `asserted_at` for `source_kind` in `('tool','event','mirror')`;
/// - `valid_from <= asserted_at` for `source_kind == 'import'`;
/// - `valid_to <= now` when present (no future-dated `valid_to` on insert or close);
/// - `valid_to >= valid_from` when present.
fn check_edge_temporal(
    source_kind: &str,
    asserted_at: &str,
    valid_from: &str,
    valid_to: Option<&str>,
    now_str: &str,
) -> UaResult<(String, String, Option<String>)> {
    let a = normalize_ts(asserted_at, "asserted_at")?;
    let vf = normalize_ts(valid_from, "valid_from")?;
    if source_kind == "import" {
        if vf > a {
            return Err(UaError::invalid("import edge valid_from must be <= asserted_at"));
        }
    } else if vf != a {
        return Err(UaError::invalid(
            "valid_from must equal asserted_at for non-import edges (backdating is refused)",
        ));
    }
    let vt = match valid_to {
        Some(raw) => {
            let v = normalize_ts(raw, "valid_to")?;
            if v.as_str() > now_str {
                return Err(UaError::invalid_code(
                    "future_valid_to",
                    "valid_to must be <= current hub time (future-dated valid_to is refused)",
                ));
            }
            if v < vf {
                return Err(UaError::invalid("valid_to must be >= valid_from"));
            }
            Some(v)
        }
        None => None,
    };
    Ok((a, vf, vt))
}

// ---------------------------------------------------------------------------
// Row decoders and SQL builders
// ---------------------------------------------------------------------------

const NODE_COLS: &str = "id, org_id, kind, external_id, display_label, visibility, team_id, \
    owner_type, owner_id, asserted_by, asserted_by_kind, source_kind, source_ref, meta_json, \
    created_at, updated_at, archived_at";

const NODE_COLS_N: &str = "n.id, n.org_id, n.kind, n.external_id, n.display_label, n.visibility, \
    n.team_id, n.owner_type, n.owner_id, n.asserted_by, n.asserted_by_kind, n.source_kind, \
    n.source_ref, n.meta_json, n.created_at, n.updated_at, n.archived_at";

const EDGE_COLS: &str = "id, org_id, src_id, dst_id, kind, assertion_scope, state, weight, \
    asserted_by, asserted_by_kind, asserted_at, source_kind, source_ref, valid_from, valid_to, \
    meta_json";

const EDGE_COLS_E: &str = "e.id, e.org_id, e.src_id, e.dst_id, e.kind, e.assertion_scope, \
    e.state, e.weight, e.asserted_by, e.asserted_by_kind, e.asserted_at, e.source_kind, \
    e.source_ref, e.valid_from, e.valid_to, e.meta_json";

fn decode_node(r: &Row<'_>, off: usize) -> rusqlite::Result<GraphNodeRow> {
    Ok(GraphNodeRow {
        id: r.get(off)?,
        org_id: r.get(off + 1)?,
        kind: r.get(off + 2)?,
        external_id: r.get(off + 3)?,
        display_label: r.get(off + 4)?,
        visibility: r.get(off + 5)?,
        team_id: r.get(off + 6)?,
        owner_type: r.get(off + 7)?,
        owner_id: r.get(off + 8)?,
        asserted_by: r.get(off + 9)?,
        asserted_by_kind: r.get(off + 10)?,
        source_kind: r.get(off + 11)?,
        source_ref: r.get(off + 12)?,
        meta_json: r.get(off + 13)?,
        created_at: r.get(off + 14)?,
        updated_at: r.get(off + 15)?,
        archived_at: r.get(off + 16)?,
    })
}

fn decode_edge(r: &Row<'_>, off: usize) -> rusqlite::Result<GraphEdgeRow> {
    Ok(GraphEdgeRow {
        id: r.get(off)?,
        org_id: r.get(off + 1)?,
        src_id: r.get(off + 2)?,
        dst_id: r.get(off + 3)?,
        kind: r.get(off + 4)?,
        assertion_scope: r.get(off + 5)?,
        state: r.get(off + 6)?,
        weight: r.get(off + 7)?,
        asserted_by: r.get(off + 8)?,
        asserted_by_kind: r.get(off + 9)?,
        asserted_at: r.get(off + 10)?,
        source_kind: r.get(off + 11)?,
        source_ref: r.get(off + 12)?,
        valid_from: r.get(off + 13)?,
        valid_to: r.get(off + 14)?,
        meta_json: r.get(off + 15)?,
    })
}

/// Append a parameterized visibility predicate on node alias `alias` (e.g. `"n"` or `""`).
fn push_visibility_sql(sql: &mut String, bind: &mut Vec<SqlValue>, alias: &str, scope: &VisibilityScope) {
    let p = if alias.is_empty() { String::new() } else { format!("{alias}.") };
    sql.push_str(&format!(" AND {p}archived_at IS NULL AND ({p}visibility = 'org'"));
    if let (Some(ot), Some(oid)) = (&scope.owner_type, &scope.owner_id) {
        bind.push(SqlValue::Text(ot.clone()));
        let ot_idx = bind.len();
        bind.push(SqlValue::Text(oid.clone()));
        let oid_idx = bind.len();
        sql.push_str(&format!(
            " OR ({p}visibility = 'private' AND {p}owner_type = ?{ot_idx} AND {p}owner_id = ?{oid_idx})"
        ));
    }
    if !scope.team_ids.is_empty() {
        let mut placeholders = Vec::with_capacity(scope.team_ids.len());
        for tid in &scope.team_ids {
            bind.push(SqlValue::Text(tid.clone()));
            placeholders.push(format!("?{}", bind.len()));
        }
        sql.push_str(&format!(" OR ({p}visibility = 'team' AND {p}team_id IN ({}))", placeholders.join(",")));
    }
    sql.push(')');
}

/// Append edge temporal, state, and optional kind filters for alias `e` and node alias `n`.
fn push_edge_and_node_filter_sql(sql: &mut String, bind: &mut Vec<SqlValue>, filter: &EdgeFilter) {
    if filter.include_proposed {
        sql.push_str(" AND e.state IN ('active','proposed')");
    } else {
        sql.push_str(" AND e.state = 'active'");
    }
    bind.push(SqlValue::Text(filter.as_of.clone()));
    let as_of_idx = bind.len();
    sql.push_str(&format!(
        " AND e.valid_from <= ?{as_of_idx} AND (e.valid_to IS NULL OR ?{as_of_idx} < e.valid_to)"
    ));
    if !filter.edge_kinds.is_empty() {
        let mut ph = Vec::with_capacity(filter.edge_kinds.len());
        for k in &filter.edge_kinds {
            bind.push(SqlValue::Text(k.clone()));
            ph.push(format!("?{}", bind.len()));
        }
        sql.push_str(&format!(" AND e.kind IN ({})", ph.join(",")));
    }
    if !filter.node_kinds.is_empty() {
        let mut ph = Vec::with_capacity(filter.node_kinds.len());
        for k in &filter.node_kinds {
            bind.push(SqlValue::Text(k.clone()));
            ph.push(format!("?{}", bind.len()));
        }
        sql.push_str(&format!(" AND n.kind IN ({})", ph.join(",")));
    }
}

/// Append keyset cursor predicate matching `ORDER BY e.weight DESC, e.asserted_at DESC, e.id ASC`.
fn push_cursor_sql(sql: &mut String, bind: &mut Vec<SqlValue>, cursor: Option<&AdjacencyCursor>) {
    let Some(c) = cursor else { return };
    bind.push(SqlValue::Real(c.weight));
    let w = bind.len();
    bind.push(SqlValue::Text(c.asserted_at.clone()));
    let a = bind.len();
    bind.push(SqlValue::Text(c.edge_id.clone()));
    let id = bind.len();
    sql.push_str(&format!(
        " AND (e.weight < ?{w} OR (e.weight = ?{w} AND e.asserted_at < ?{a}) \
         OR (e.weight = ?{w} AND e.asserted_at = ?{a} AND e.id > ?{id}))"
    ));
}

// ---------------------------------------------------------------------------
// SQLite query implementations
// ---------------------------------------------------------------------------

fn require_org_exists_sql(conn: &Connection, org_id: &str) -> UaResult<()> {
    let found = conn.query_row("SELECT 1 FROM orgs WHERE id = ?1", [org_id], |_| Ok(())).optional()?;
    if found.is_none() {
        return Err(UaError::denied(
            "unknown_organization",
            format!("organization {org_id:?} does not exist"),
        ));
    }
    Ok(())
}

fn get_node_by_id_sql(
    conn: &Connection,
    org_id: &str,
    id: &str,
    scope: &VisibilityScope,
) -> UaResult<Option<GraphNodeRow>> {
    let mut sql = format!("SELECT {NODE_COLS} FROM graph_nodes WHERE org_id = ?1 AND id = ?2");
    let mut bind = vec![SqlValue::Text(org_id.to_string()), SqlValue::Text(id.to_string())];
    push_visibility_sql(&mut sql, &mut bind, "", scope);
    let mut stmt = conn.prepare_cached(&sql).map_err(map_sql_err)?;
    stmt.query_row(params_from_iter(bind.iter()), |r| decode_node(r, 0)).optional().map_err(map_sql_err)
}

fn get_node_by_external_sql(
    conn: &Connection,
    org_id: &str,
    kind: &str,
    external_id: &str,
    scope: &VisibilityScope,
) -> UaResult<Option<GraphNodeRow>> {
    let mut sql =
        format!("SELECT {NODE_COLS} FROM graph_nodes WHERE org_id = ?1 AND kind = ?2 AND external_id = ?3");
    let mut bind = vec![
        SqlValue::Text(org_id.to_string()),
        SqlValue::Text(kind.to_string()),
        SqlValue::Text(external_id.to_string()),
    ];
    push_visibility_sql(&mut sql, &mut bind, "", scope);
    let mut stmt = conn.prepare_cached(&sql).map_err(map_sql_err)?;
    stmt.query_row(params_from_iter(bind.iter()), |r| decode_node(r, 0)).optional().map_err(map_sql_err)
}

fn get_nodes_by_ids_sql(
    conn: &Connection,
    org_id: &str,
    ids: &[String],
    scope: &VisibilityScope,
) -> UaResult<Vec<GraphNodeRow>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(ids.len());
    // Chunk IN clauses to stay well below SQLite's variable limit.
    for chunk in ids.chunks(400) {
        let mut sql = format!("SELECT {NODE_COLS} FROM graph_nodes WHERE org_id = ?1 AND id IN (");
        let mut bind = vec![SqlValue::Text(org_id.to_string())];
        let mut ph = Vec::with_capacity(chunk.len());
        for id in chunk {
            bind.push(SqlValue::Text(id.clone()));
            ph.push(format!("?{}", bind.len()));
        }
        sql.push_str(&ph.join(","));
        sql.push(')');
        push_visibility_sql(&mut sql, &mut bind, "", scope);
        let mut stmt = conn.prepare(&sql).map_err(map_sql_err)?;
        let rows = stmt
            .query_map(params_from_iter(bind.iter()), |r| decode_node(r, 0))
            .map_err(map_sql_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql_err)?;
        out.extend(rows);
    }
    Ok(out)
}

fn get_edge_by_id_sql(conn: &Connection, org_id: &str, id: &str) -> UaResult<Option<GraphEdgeRow>> {
    let mut stmt = conn
        .prepare_cached(&format!("SELECT {EDGE_COLS} FROM graph_edges WHERE org_id = ?1 AND id = ?2"))
        .map_err(map_sql_err)?;
    stmt.query_row(params![org_id, id], |r| decode_edge(r, 0)).optional().map_err(map_sql_err)
}

fn get_edges_by_ids_sql(conn: &Connection, org_id: &str, ids: &[String]) -> UaResult<Vec<GraphEdgeRow>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(ids.len());
    for chunk in ids.chunks(400) {
        let mut sql = format!("SELECT {EDGE_COLS} FROM graph_edges WHERE org_id = ?1 AND id IN (");
        let mut bind = vec![SqlValue::Text(org_id.to_string())];
        let mut ph = Vec::with_capacity(chunk.len());
        for id in chunk {
            bind.push(SqlValue::Text(id.clone()));
            ph.push(format!("?{}", bind.len()));
        }
        sql.push_str(&ph.join(","));
        sql.push(')');
        let mut stmt = conn.prepare(&sql).map_err(map_sql_err)?;
        let rows = stmt
            .query_map(params_from_iter(bind.iter()), |r| decode_edge(r, 0))
            .map_err(map_sql_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql_err)?;
        out.extend(rows);
    }
    Ok(out)
}

fn get_edges_by_rowids_sql(
    conn: &Connection,
    org_id: &str,
    rowids: &[i64],
) -> UaResult<Vec<(i64, GraphEdgeRow)>> {
    if rowids.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(rowids.len());
    for chunk in rowids.chunks(400) {
        let mut sql = format!("SELECT rowid, {EDGE_COLS} FROM graph_edges WHERE org_id = ?1 AND rowid IN (");
        let mut bind = vec![SqlValue::Text(org_id.to_string())];
        let mut ph = Vec::with_capacity(chunk.len());
        for &rid in chunk {
            bind.push(SqlValue::Integer(rid));
            ph.push(format!("?{}", bind.len()));
        }
        sql.push_str(&ph.join(","));
        sql.push(')');
        let mut stmt = conn.prepare(&sql).map_err(map_sql_err)?;
        let rows = stmt
            .query_map(params_from_iter(bind.iter()), |r| Ok((r.get::<_, i64>(0)?, decode_edge(r, 1)?)))
            .map_err(map_sql_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql_err)?;
        out.extend(rows);
    }
    Ok(out)
}

fn count_org_nodes_sql(conn: &Connection, org_id: &str) -> UaResult<u64> {
    let mut stmt = conn
        .prepare_cached("SELECT COALESCE((SELECT node_count FROM graph_org_counts WHERE org_id = ?1), 0)")
        .map_err(map_sql_err)?;
    let n: i64 = stmt.query_row([org_id], |r| r.get(0)).map_err(map_sql_err)?;
    Ok(n.max(0) as u64)
}

fn count_org_edges_sql(conn: &Connection, org_id: &str) -> UaResult<u64> {
    let mut stmt = conn
        .prepare_cached("SELECT COALESCE((SELECT edge_count FROM graph_org_counts WHERE org_id = ?1), 0)")
        .map_err(map_sql_err)?;
    let n: i64 = stmt.query_row([org_id], |r| r.get(0)).map_err(map_sql_err)?;
    Ok(n.max(0) as u64)
}

fn count_node_live_edges_capped_sql(
    conn: &Connection,
    org_id: &str,
    node_id: &str,
    cap: usize,
) -> UaResult<usize> {
    if cap == 0 {
        return Ok(0);
    }
    let mut out_stmt = conn
        .prepare_cached(
            "SELECT COUNT(*) FROM ( \
                 SELECT 1 FROM graph_edges INDEXED BY idx_graph_edges_out \
                 WHERE org_id = ?1 AND src_id = ?2 AND valid_to IS NULL \
                 LIMIT ?3 \
             )",
        )
        .map_err(map_sql_err)?;
    let out_n: i64 =
        out_stmt.query_row(params![org_id, node_id, sql_limit(cap)], |r| r.get(0)).map_err(map_sql_err)?;
    let out = out_n.max(0) as usize;
    if out >= cap {
        return Ok(cap);
    }
    let rem = cap - out;
    let mut in_stmt = conn
        .prepare_cached(
            "SELECT COUNT(*) FROM ( \
                 SELECT 1 FROM graph_edges INDEXED BY idx_graph_edges_in \
                 WHERE org_id = ?1 AND dst_id = ?2 AND valid_to IS NULL \
                 LIMIT ?3 \
             )",
        )
        .map_err(map_sql_err)?;
    let in_n: i64 =
        in_stmt.query_row(params![org_id, node_id, sql_limit(rem)], |r| r.get(0)).map_err(map_sql_err)?;
    Ok((out + in_n.max(0) as usize).min(cap))
}

fn query_directed_full(
    conn: &Connection,
    q: &AdjacencyQuery,
    dir: EdgeDirection,
) -> UaResult<Vec<AdjacencyEntry>> {
    let (seed_col, nbr_col) = match dir {
        EdgeDirection::Out => ("src_id", "dst_id"),
        EdgeDirection::In => ("dst_id", "src_id"),
        EdgeDirection::Both => unreachable!("caller splits Both into Out + In"),
    };
    let mut sql = format!(
        "SELECT {EDGE_COLS_E}, {NODE_COLS_N} \
         FROM graph_edges e \
         JOIN graph_nodes n ON n.org_id = e.org_id AND n.id = e.{nbr_col} \
         WHERE e.org_id = ?1 AND e.{seed_col} = ?2"
    );
    let mut bind = vec![SqlValue::Text(q.org_id.clone()), SqlValue::Text(q.node_id.clone())];
    push_visibility_sql(&mut sql, &mut bind, "n", &q.scope);
    push_edge_and_node_filter_sql(&mut sql, &mut bind, &q.filter);
    push_cursor_sql(&mut sql, &mut bind, q.cursor.as_ref());
    bind.push(SqlValue::Integer(sql_limit(q.limit)));
    let lim = bind.len();
    sql.push_str(&format!(" ORDER BY e.weight DESC, e.asserted_at DESC, e.id ASC LIMIT ?{lim}"));

    let mut stmt = conn.prepare_cached(&sql).map_err(map_sql_err)?;
    let rows = stmt
        .query_map(params_from_iter(bind.iter()), |r| {
            let edge = decode_edge(r, 0)?;
            let neighbor = decode_node(r, 16)?;
            Ok(AdjacencyEntry { edge, neighbor, direction: dir })
        })
        .map_err(map_sql_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sql_err)?;
    Ok(rows)
}

fn cmp_adj_key(w_a: f64, at_a: &str, id_a: &str, w_b: f64, at_b: &str, id_b: &str) -> std::cmp::Ordering {
    w_b.total_cmp(&w_a).then_with(|| at_b.cmp(at_a)).then_with(|| id_a.cmp(id_b))
}

fn adjacent_edges_sql(conn: &Connection, q: &AdjacencyQuery) -> UaResult<Vec<AdjacencyEntry>> {
    if q.limit == 0 {
        return Ok(Vec::new());
    }
    match q.direction {
        EdgeDirection::Out | EdgeDirection::In => query_directed_full(conn, q, q.direction),
        EdgeDirection::Both => {
            let mut out = query_directed_full(conn, q, EdgeDirection::Out)?;
            let incoming = query_directed_full(conn, q, EdgeDirection::In)?;
            out.extend(incoming);
            out.sort_by(|a, b| {
                cmp_adj_key(
                    a.edge.weight,
                    &a.edge.asserted_at,
                    &a.edge.id,
                    b.edge.weight,
                    &b.edge.asserted_at,
                    &b.edge.id,
                )
            });
            out.truncate(q.limit);
            Ok(out)
        }
    }
}

/// Build the covering-index SQL and constant bind list for one direction of
/// `compact_adjacent`. Slot 2 (`?2`) is `node_id` and slot `lim_idx` is `limit`.
fn build_compact_sql(
    org_id: &str,
    dir: EdgeDirection,
    filter: &EdgeFilter,
    scope: &VisibilityScope,
) -> (String, Vec<SqlValue>, usize) {
    let (seed_col, nbr_col, idx_name) = match dir {
        EdgeDirection::Out => ("src_id", "dst_id", "idx_graph_edges_out"),
        EdgeDirection::In => ("dst_id", "src_id", "idx_graph_edges_in"),
        EdgeDirection::Both => unreachable!("caller splits Both into Out + In"),
    };
    // Selects ONLY columns covered by idx_graph_edges_out / idx_graph_edges_in + rowid,
    // avoiding main-table B-tree fetches on graph_edges and avoiding duplicate String reads.
    let mut sql = format!(
        "SELECT e.rowid, e.{nbr_col}, e.weight \
         FROM graph_edges e INDEXED BY {idx_name} \
         JOIN graph_nodes n ON n.org_id = e.org_id AND n.id = e.{nbr_col} \
         WHERE e.org_id = ?1 AND e.{seed_col} = ?2"
    );
    let mut bind = vec![SqlValue::Text(org_id.to_string()), SqlValue::Text(String::new())];
    push_visibility_sql(&mut sql, &mut bind, "n", scope);
    push_edge_and_node_filter_sql(&mut sql, &mut bind, filter);
    bind.push(SqlValue::Integer(0));
    let lim = bind.len();
    sql.push_str(&format!(" ORDER BY e.weight DESC, e.rowid ASC LIMIT ?{lim}"));
    (sql, bind, lim)
}

fn step_compact_stmt(
    stmt: &mut rusqlite::Statement<'_>,
    node_id: &str,
    lim_idx: usize,
    limit: usize,
    dir: EdgeDirection,
    out: &mut Vec<CompactAdjEdge>,
) -> UaResult<()> {
    stmt.raw_bind_parameter(2, node_id).map_err(map_sql_err)?;
    stmt.raw_bind_parameter(lim_idx, sql_limit(limit)).map_err(map_sql_err)?;
    let mut rows = stmt.raw_query();
    while let Some(r) = rows.next().map_err(map_sql_err)? {
        out.push(CompactAdjEdge {
            rowid: r.get(0).map_err(map_sql_err)?,
            neighbor_id: r.get(1).map_err(map_sql_err)?,
            weight: r.get(2).map_err(map_sql_err)?,
            direction: dir,
        });
    }
    Ok(())
}

fn query_directed_compact(
    conn: &Connection,
    org_id: &str,
    node_id: &str,
    dir: EdgeDirection,
    filter: &EdgeFilter,
    scope: &VisibilityScope,
    limit: usize,
) -> UaResult<Vec<CompactAdjEdge>> {
    let (sql, bind, lim_idx) = build_compact_sql(org_id, dir, filter, scope);
    let mut stmt = conn.prepare_cached(&sql).map_err(map_sql_err)?;
    for (i, v) in bind.iter().enumerate() {
        stmt.raw_bind_parameter(i + 1, v).map_err(map_sql_err)?;
    }
    let mut out = Vec::with_capacity(limit.min(256));
    step_compact_stmt(&mut stmt, node_id, lim_idx, limit, dir, &mut out)?;
    Ok(out)
}

fn compact_adjacent_sql(
    conn: &Connection,
    org_id: &str,
    node_id: &str,
    direction: EdgeDirection,
    filter: &EdgeFilter,
    scope: &VisibilityScope,
    limit: usize,
) -> UaResult<Vec<CompactAdjEdge>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    match direction {
        EdgeDirection::Out | EdgeDirection::In => {
            query_directed_compact(conn, org_id, node_id, direction, filter, scope, limit)
        }
        EdgeDirection::Both => {
            let mut out =
                query_directed_compact(conn, org_id, node_id, EdgeDirection::Out, filter, scope, limit)?;
            let incoming =
                query_directed_compact(conn, org_id, node_id, EdgeDirection::In, filter, scope, limit)?;
            out.extend(incoming);
            out.sort_by(|a, b| b.weight.total_cmp(&a.weight).then_with(|| a.rowid.cmp(&b.rowid)));
            out.truncate(limit);
            Ok(out)
        }
    }
}

#[allow(clippy::type_complexity)]
fn with_compact_adjacent_sql<F, T>(
    conn: &Connection,
    org_id: &str,
    directions: EdgeDirection,
    filter: &EdgeFilter,
    scope: &VisibilityScope,
    f: F,
) -> UaResult<T>
where
    F: FnOnce(
        &mut dyn FnMut(&str, EdgeDirection, usize, &mut Vec<CompactAdjEdge>) -> UaResult<()>,
    ) -> UaResult<T>,
{
    let mut out_stmt = if matches!(directions, EdgeDirection::Out | EdgeDirection::Both) {
        let (sql, bind, lim_idx) = build_compact_sql(org_id, EdgeDirection::Out, filter, scope);
        let mut s = conn.prepare_cached(&sql).map_err(map_sql_err)?;
        for (i, v) in bind.iter().enumerate() {
            s.raw_bind_parameter(i + 1, v).map_err(map_sql_err)?;
        }
        Some((s, lim_idx))
    } else {
        None
    };
    let mut in_stmt = if matches!(directions, EdgeDirection::In | EdgeDirection::Both) {
        let (sql, bind, lim_idx) = build_compact_sql(org_id, EdgeDirection::In, filter, scope);
        let mut s = conn.prepare_cached(&sql).map_err(map_sql_err)?;
        for (i, v) in bind.iter().enumerate() {
            s.raw_bind_parameter(i + 1, v).map_err(map_sql_err)?;
        }
        Some((s, lim_idx))
    } else {
        None
    };

    let mut step =
        |node_id: &str, dir: EdgeDirection, limit: usize, out: &mut Vec<CompactAdjEdge>| -> UaResult<()> {
            out.clear();
            if limit == 0 {
                return Ok(());
            }
            match dir {
                EdgeDirection::Out => {
                    let (stmt, lim_idx) =
                        out_stmt.as_mut().ok_or_else(|| UaError::internal("out statement not prepared"))?;
                    step_compact_stmt(stmt, node_id, *lim_idx, limit, EdgeDirection::Out, out)
                }
                EdgeDirection::In => {
                    let (stmt, lim_idx) =
                        in_stmt.as_mut().ok_or_else(|| UaError::internal("in statement not prepared"))?;
                    step_compact_stmt(stmt, node_id, *lim_idx, limit, EdgeDirection::In, out)
                }
                EdgeDirection::Both => {
                    let (os, ol) =
                        out_stmt.as_mut().ok_or_else(|| UaError::internal("out statement not prepared"))?;
                    step_compact_stmt(os, node_id, *ol, limit, EdgeDirection::Out, out)?;
                    let (is, il) =
                        in_stmt.as_mut().ok_or_else(|| UaError::internal("in statement not prepared"))?;
                    step_compact_stmt(is, node_id, *il, limit, EdgeDirection::In, out)?;
                    out.sort_by(|a, b| b.weight.total_cmp(&a.weight).then_with(|| a.rowid.cmp(&b.rowid)));
                    out.truncate(limit);
                    Ok(())
                }
            }
        };
    f(&mut step)
}

/// Runs the bounded reachability SQL assuming the caller has already installed
/// a SQLite progress-handler deadline (`run_with_conn_deadline` or
/// `run_with_atomic_deadline`).
fn bounded_acyclic_reach_sql_inner(
    conn: &Connection,
    org_id: &str,
    src_id: &str,
    dst_id: &str,
    kind: &str,
    max_nodes: usize,
    max_edges: usize,
) -> UaResult<AcyclicReachOutcome> {
    // Single covering-index bounded reachability CTE (`CROSS JOIN` forces
    // `r` -> covering index `idx_graph_edges_out(org_id, src_id, kind, state, valid_to)`).
    let mut node_stmt = conn
        .prepare_cached(
            "WITH RECURSIVE r(id) AS ( \
                 SELECT ?2 \
                 UNION \
                 SELECT e.dst_id \
                 FROM r CROSS JOIN graph_edges e INDEXED BY idx_graph_edges_out \
                 WHERE e.org_id = ?1 AND e.src_id = r.id AND e.kind = ?3 \
                   AND e.state = 'active' AND e.valid_to IS NULL \
             ) \
             SELECT COUNT(*) AS n_nodes, \
                    COALESCE(MAX(CASE WHEN id = ?4 THEN 1 ELSE 0 END), 0) AS hit_src \
             FROM (SELECT id FROM r LIMIT ?5)",
        )
        .map_err(map_sql_err)?;
    let (n_nodes, hit_src): (i64, i64) = match node_stmt
        .query_row(params![org_id, dst_id, kind, src_id, sql_limit(max_nodes.saturating_add(1))], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(map_sql_err)
    {
        Ok(pair) => pair,
        Err(err) if is_deadline_error(&err) => {
            return Ok(AcyclicReachOutcome::BoundExceeded("deadline"));
        }
        Err(err) => return Err(err),
    };
    if hit_src != 0 {
        return Ok(AcyclicReachOutcome::CycleDetected);
    }
    if n_nodes as usize > max_nodes {
        return Ok(AcyclicReachOutcome::BoundExceeded("visited_nodes"));
    }
    // Only check visited-edge cap when reachable subgraph has enough nodes/edges
    // that it could exceed `max_edges` (note a simple DAG of N nodes has at most
    // N*(N-1)/2 edges, or N-1 for a tree/chain; still check when max_edges < n_nodes
    // or whenever n_nodes >= 2 and total possible edges > max_edges).
    let n_u = n_nodes.max(0) as usize;
    if n_u > 1 && (n_u > max_edges || n_u.saturating_mul(n_u) > max_edges) {
        let mut edge_stmt = conn
            .prepare_cached(
                "WITH RECURSIVE r(id) AS ( \
                     SELECT ?2 \
                     UNION \
                     SELECT e.dst_id \
                     FROM r CROSS JOIN graph_edges e INDEXED BY idx_graph_edges_out \
                     WHERE e.org_id = ?1 AND e.src_id = r.id AND e.kind = ?3 \
                       AND e.state = 'active' AND e.valid_to IS NULL \
                 ) \
                 SELECT COUNT(*) FROM ( \
                     SELECT 1 \
                     FROM (SELECT id FROM r LIMIT ?4) rn \
                     CROSS JOIN graph_edges e INDEXED BY idx_graph_edges_out \
                     WHERE e.org_id = ?1 AND e.src_id = rn.id AND e.kind = ?3 \
                       AND e.state = 'active' AND e.valid_to IS NULL \
                     LIMIT ?5 \
                 )",
            )
            .map_err(map_sql_err)?;
        let n_edges: i64 = match edge_stmt
            .query_row(
                params![org_id, dst_id, kind, sql_limit(max_nodes), sql_limit(max_edges.saturating_add(1))],
                |r| r.get(0),
            )
            .map_err(map_sql_err)
        {
            Ok(n) => n,
            Err(err) if is_deadline_error(&err) => {
                return Ok(AcyclicReachOutcome::BoundExceeded("deadline"));
            }
            Err(err) => return Err(err),
        };
        if n_edges as usize > max_edges {
            return Ok(AcyclicReachOutcome::BoundExceeded("visited_edges"));
        }
    }
    Ok(AcyclicReachOutcome::Acyclic)
}

fn eligible_degree_dir(
    conn: &Connection,
    org_id: &str,
    node_id: &str,
    dir: EdgeDirection,
    filter: &EdgeFilter,
    scope: &VisibilityScope,
    cap_plus_one: usize,
) -> UaResult<usize> {
    let (seed_col, nbr_col) = match dir {
        EdgeDirection::Out => ("src_id", "dst_id"),
        EdgeDirection::In => ("dst_id", "src_id"),
        EdgeDirection::Both => unreachable!("caller splits Both into Out + In"),
    };
    let mut sql = format!(
        "SELECT COUNT(*) FROM ( \
         SELECT 1 FROM graph_edges e \
         JOIN graph_nodes n ON n.org_id = e.org_id AND n.id = e.{nbr_col} \
         WHERE e.org_id = ?1 AND e.{seed_col} = ?2"
    );
    let mut bind = vec![SqlValue::Text(org_id.to_string()), SqlValue::Text(node_id.to_string())];
    push_visibility_sql(&mut sql, &mut bind, "n", scope);
    push_edge_and_node_filter_sql(&mut sql, &mut bind, filter);
    bind.push(SqlValue::Integer(sql_limit(cap_plus_one)));
    let lim = bind.len();
    sql.push_str(&format!(" LIMIT ?{lim})"));

    let mut stmt = conn.prepare_cached(&sql).map_err(map_sql_err)?;
    let n: i64 = stmt.query_row(params_from_iter(bind.iter()), |r| r.get(0)).map_err(map_sql_err)?;
    Ok(n.max(0) as usize)
}

#[allow(clippy::too_many_arguments)]
fn eligible_degree_sql(
    conn: &Connection,
    org_id: &str,
    node_id: &str,
    direction: EdgeDirection,
    filter: &EdgeFilter,
    scope: &VisibilityScope,
    cap_plus_one: usize,
) -> UaResult<usize> {
    if cap_plus_one == 0 {
        return Ok(0);
    }
    match direction {
        EdgeDirection::Out | EdgeDirection::In => {
            eligible_degree_dir(conn, org_id, node_id, direction, filter, scope, cap_plus_one)
        }
        EdgeDirection::Both => {
            let out =
                eligible_degree_dir(conn, org_id, node_id, EdgeDirection::Out, filter, scope, cap_plus_one)?;
            if out >= cap_plus_one {
                return Ok(cap_plus_one);
            }
            let rem = cap_plus_one - out;
            let inc = eligible_degree_dir(conn, org_id, node_id, EdgeDirection::In, filter, scope, rem)?;
            Ok((out + inc).min(cap_plus_one))
        }
    }
}

fn outgoing_live_targets_of_kind_into_sql(
    conn: &Connection,
    org_id: &str,
    src_id: &str,
    kind: &str,
    limit: usize,
    out: &mut Vec<String>,
) -> UaResult<()> {
    out.clear();
    // Covered by idx_graph_edges_out(org_id, src_id, kind, state, valid_to, valid_from, dst_id, weight).
    let mut stmt = conn
        .prepare_cached(
            "SELECT dst_id FROM graph_edges \
             WHERE org_id = ?1 AND src_id = ?2 AND kind = ?3 AND state = 'active' AND valid_to IS NULL \
             LIMIT ?4",
        )
        .map_err(map_sql_err)?;
    let mut rows = stmt.query(params![org_id, src_id, kind, sql_limit(limit)]).map_err(map_sql_err)?;
    while let Some(r) = rows.next().map_err(map_sql_err)? {
        out.push(r.get::<_, String>(0).map_err(map_sql_err)?);
    }
    Ok(())
}

fn exact_ppr_slice_sql(
    conn: &Connection,
    org_id: &str,
    filter: &EdgeFilter,
    scope: &VisibilityScope,
    max_nodes: usize,
    max_edges: usize,
) -> UaResult<Option<ExactPprSlice>> {
    // Fast bounded node-cap check first: avoids scanning edges when org exceeds max_nodes.
    let mut nsql = String::from("SELECT id FROM graph_nodes WHERE org_id = ?1");
    let mut nbind = vec![SqlValue::Text(org_id.to_string())];
    push_visibility_sql(&mut nsql, &mut nbind, "", scope);
    if !filter.node_kinds.is_empty() {
        let mut ph = Vec::with_capacity(filter.node_kinds.len());
        for k in &filter.node_kinds {
            nbind.push(SqlValue::Text(k.clone()));
            ph.push(format!("?{}", nbind.len()));
        }
        nsql.push_str(&format!(" AND kind IN ({})", ph.join(",")));
    }
    nbind.push(SqlValue::Integer(sql_limit(max_nodes.saturating_add(1))));
    let nlim = nbind.len();
    nsql.push_str(&format!(" LIMIT ?{nlim}"));

    let node_ids: Vec<String> = {
        let mut stmt = conn.prepare_cached(&nsql).map_err(map_sql_err)?;
        stmt.query_map(params_from_iter(nbind.iter()), |r| r.get::<_, String>(0))
            .map_err(map_sql_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql_err)?
    };
    if node_ids.len() > max_nodes {
        return Ok(None);
    }
    let visible: HashSet<&str> = node_ids.iter().map(String::as_str).collect();

    // Bounded covering-index scan over `idx_graph_edges_out` filtered in-memory
    // against the exact visible node set (`visible`, <= max_nodes). Caps BOTH
    // matched edges (`max_edges`) and total scanned edges (`scan_cap = 2 * max_edges`)
    // so selective node-kind/visibility filters cannot trigger an unbounded org scan.
    // Callers also install `with_deadline` so SQLite's `progress_handler` enforces
    // the wall-clock deadline mid-scan.
    let scan_cap = max_edges.saturating_mul(2).max(max_edges);
    let mut esql = String::from(
        "SELECT src_id, dst_id, weight FROM graph_edges INDEXED BY idx_graph_edges_out WHERE org_id = ?1",
    );
    let mut ebind = vec![SqlValue::Text(org_id.to_string())];
    if filter.include_proposed {
        esql.push_str(" AND state IN ('active','proposed')");
    } else {
        esql.push_str(" AND state = 'active'");
    }
    ebind.push(SqlValue::Text(filter.as_of.clone()));
    let as_of_idx = ebind.len();
    esql.push_str(&format!(
        " AND valid_from <= ?{as_of_idx} AND (valid_to IS NULL OR ?{as_of_idx} < valid_to)"
    ));
    if !filter.edge_kinds.is_empty() {
        let mut ph = Vec::with_capacity(filter.edge_kinds.len());
        for k in &filter.edge_kinds {
            ebind.push(SqlValue::Text(k.clone()));
            ph.push(format!("?{}", ebind.len()));
        }
        esql.push_str(&format!(" AND kind IN ({})", ph.join(",")));
    }
    ebind.push(SqlValue::Integer(sql_limit(scan_cap.saturating_add(1))));
    let elim = ebind.len();
    esql.push_str(&format!(" LIMIT ?{elim}"));

    let mut edges: Vec<(String, String, f64)> = Vec::new();
    let mut scanned = 0usize;
    {
        let mut stmt = conn.prepare_cached(&esql).map_err(map_sql_err)?;
        let mut rows = stmt.query(params_from_iter(ebind.iter())).map_err(map_sql_err)?;
        while let Some(r) = rows.next().map_err(map_sql_err)? {
            scanned += 1;
            if scanned > scan_cap {
                return Ok(None);
            }
            let s: String = r.get(0).map_err(map_sql_err)?;
            if !visible.contains(s.as_str()) {
                continue;
            }
            let d: String = r.get(1).map_err(map_sql_err)?;
            if !visible.contains(d.as_str()) {
                continue;
            }
            if edges.len() >= max_edges {
                return Ok(None);
            }
            let w: f64 = r.get(2).map_err(map_sql_err)?;
            edges.push((s, d, w));
        }
    }
    Ok(Some(ExactPprSlice { node_ids, edges }))
}

// ---------------------------------------------------------------------------
// Trait implementations
// ---------------------------------------------------------------------------

impl GraphRead for SqliteGraph<'_> {
    fn require_org_exists(&mut self, org_id: &str) -> UaResult<()> {
        require_org_exists_sql(self.conn, org_id)
    }
    fn get_node_by_id(
        &mut self,
        org_id: &str,
        id: &str,
        scope: &VisibilityScope,
    ) -> UaResult<Option<GraphNodeRow>> {
        get_node_by_id_sql(self.conn, org_id, id, scope)
    }
    fn get_node_by_external(
        &mut self,
        org_id: &str,
        kind: &str,
        external_id: &str,
        scope: &VisibilityScope,
    ) -> UaResult<Option<GraphNodeRow>> {
        get_node_by_external_sql(self.conn, org_id, kind, external_id, scope)
    }
    fn get_nodes_by_ids(
        &mut self,
        org_id: &str,
        ids: &[String],
        scope: &VisibilityScope,
    ) -> UaResult<Vec<GraphNodeRow>> {
        get_nodes_by_ids_sql(self.conn, org_id, ids, scope)
    }
    fn get_edge_by_id(&mut self, org_id: &str, id: &str) -> UaResult<Option<GraphEdgeRow>> {
        get_edge_by_id_sql(self.conn, org_id, id)
    }
    fn get_edges_by_ids(&mut self, org_id: &str, ids: &[String]) -> UaResult<Vec<GraphEdgeRow>> {
        get_edges_by_ids_sql(self.conn, org_id, ids)
    }
    fn get_edges_by_rowids(&mut self, org_id: &str, rowids: &[i64]) -> UaResult<Vec<(i64, GraphEdgeRow)>> {
        get_edges_by_rowids_sql(self.conn, org_id, rowids)
    }
    fn count_org_nodes(&mut self, org_id: &str) -> UaResult<u64> {
        count_org_nodes_sql(self.conn, org_id)
    }
    fn count_org_edges(&mut self, org_id: &str) -> UaResult<u64> {
        count_org_edges_sql(self.conn, org_id)
    }
    fn count_node_live_edges_capped(&mut self, org_id: &str, node_id: &str, cap: usize) -> UaResult<usize> {
        count_node_live_edges_capped_sql(self.conn, org_id, node_id, cap)
    }
    fn with_deadline<F, T>(&mut self, deadline: Instant, f: F) -> UaResult<T>
    where
        Self: Sized,
        F: FnOnce(&mut Self) -> UaResult<T>,
    {
        run_with_conn_deadline(self, |g| g.conn, deadline, f)
    }
    fn adjacent_edges(&mut self, query: &AdjacencyQuery) -> UaResult<Vec<AdjacencyEntry>> {
        adjacent_edges_sql(self.conn, query)
    }
    fn compact_adjacent(
        &mut self,
        org_id: &str,
        node_id: &str,
        direction: EdgeDirection,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        limit: usize,
    ) -> UaResult<Vec<CompactAdjEdge>> {
        compact_adjacent_sql(self.conn, org_id, node_id, direction, filter, scope, limit)
    }
    #[allow(clippy::type_complexity)]
    fn with_compact_adjacent<F, T>(
        &mut self,
        org_id: &str,
        directions: EdgeDirection,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        f: F,
    ) -> UaResult<T>
    where
        F: FnOnce(
            &mut dyn FnMut(&str, EdgeDirection, usize, &mut Vec<CompactAdjEdge>) -> UaResult<()>,
        ) -> UaResult<T>,
    {
        with_compact_adjacent_sql(self.conn, org_id, directions, filter, scope, f)
    }
    fn bounded_acyclic_reach(
        &mut self,
        org_id: &str,
        src_id: &str,
        dst_id: &str,
        kind: &str,
        max_nodes: usize,
        max_edges: usize,
        deadline: Instant,
    ) -> UaResult<AcyclicReachOutcome> {
        match run_with_conn_deadline(
            self,
            |g| g.conn,
            deadline,
            |g| bounded_acyclic_reach_sql_inner(g.conn, org_id, src_id, dst_id, kind, max_nodes, max_edges),
        ) {
            Ok(o) => Ok(o),
            Err(err) if is_deadline_error(&err) => Ok(AcyclicReachOutcome::BoundExceeded("deadline")),
            Err(err) => Err(err),
        }
    }
    fn eligible_degree(
        &mut self,
        org_id: &str,
        node_id: &str,
        direction: EdgeDirection,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        cap_plus_one: usize,
    ) -> UaResult<usize> {
        eligible_degree_sql(self.conn, org_id, node_id, direction, filter, scope, cap_plus_one)
    }
    fn outgoing_live_targets_of_kind_into(
        &mut self,
        org_id: &str,
        src_id: &str,
        kind: &str,
        limit: usize,
        out: &mut Vec<String>,
    ) -> UaResult<()> {
        outgoing_live_targets_of_kind_into_sql(self.conn, org_id, src_id, kind, limit, out)
    }
    fn exact_ppr_slice(
        &mut self,
        org_id: &str,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        max_nodes: usize,
        max_edges: usize,
    ) -> UaResult<Option<ExactPprSlice>> {
        exact_ppr_slice_sql(self.conn, org_id, filter, scope, max_nodes, max_edges)
    }
}

impl GraphRead for WriteTx<'_> {
    fn require_org_exists(&mut self, org_id: &str) -> UaResult<()> {
        require_org_exists_sql(self, org_id)
    }
    fn get_node_by_id(
        &mut self,
        org_id: &str,
        id: &str,
        scope: &VisibilityScope,
    ) -> UaResult<Option<GraphNodeRow>> {
        get_node_by_id_sql(self, org_id, id, scope)
    }
    fn get_node_by_external(
        &mut self,
        org_id: &str,
        kind: &str,
        external_id: &str,
        scope: &VisibilityScope,
    ) -> UaResult<Option<GraphNodeRow>> {
        get_node_by_external_sql(self, org_id, kind, external_id, scope)
    }
    fn get_nodes_by_ids(
        &mut self,
        org_id: &str,
        ids: &[String],
        scope: &VisibilityScope,
    ) -> UaResult<Vec<GraphNodeRow>> {
        get_nodes_by_ids_sql(self, org_id, ids, scope)
    }
    fn get_edge_by_id(&mut self, org_id: &str, id: &str) -> UaResult<Option<GraphEdgeRow>> {
        get_edge_by_id_sql(self, org_id, id)
    }
    fn get_edges_by_ids(&mut self, org_id: &str, ids: &[String]) -> UaResult<Vec<GraphEdgeRow>> {
        get_edges_by_ids_sql(self, org_id, ids)
    }
    fn get_edges_by_rowids(&mut self, org_id: &str, rowids: &[i64]) -> UaResult<Vec<(i64, GraphEdgeRow)>> {
        get_edges_by_rowids_sql(self, org_id, rowids)
    }
    fn count_org_nodes(&mut self, org_id: &str) -> UaResult<u64> {
        count_org_nodes_sql(self, org_id)
    }
    fn count_org_edges(&mut self, org_id: &str) -> UaResult<u64> {
        count_org_edges_sql(self, org_id)
    }
    fn count_node_live_edges_capped(&mut self, org_id: &str, node_id: &str, cap: usize) -> UaResult<usize> {
        count_node_live_edges_capped_sql(self, org_id, node_id, cap)
    }
    fn with_deadline<F, T>(&mut self, deadline: Instant, f: F) -> UaResult<T>
    where
        Self: Sized,
        F: FnOnce(&mut Self) -> UaResult<T>,
    {
        let slot = self.deadline_slot();
        run_with_atomic_deadline(slot.as_deref(), deadline, || f(self))
    }
    fn adjacent_edges(&mut self, query: &AdjacencyQuery) -> UaResult<Vec<AdjacencyEntry>> {
        adjacent_edges_sql(self, query)
    }
    fn compact_adjacent(
        &mut self,
        org_id: &str,
        node_id: &str,
        direction: EdgeDirection,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        limit: usize,
    ) -> UaResult<Vec<CompactAdjEdge>> {
        compact_adjacent_sql(self, org_id, node_id, direction, filter, scope, limit)
    }
    #[allow(clippy::type_complexity)]
    fn with_compact_adjacent<F, T>(
        &mut self,
        org_id: &str,
        directions: EdgeDirection,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        f: F,
    ) -> UaResult<T>
    where
        F: FnOnce(
            &mut dyn FnMut(&str, EdgeDirection, usize, &mut Vec<CompactAdjEdge>) -> UaResult<()>,
        ) -> UaResult<T>,
    {
        with_compact_adjacent_sql(self, org_id, directions, filter, scope, f)
    }
    fn bounded_acyclic_reach(
        &mut self,
        org_id: &str,
        src_id: &str,
        dst_id: &str,
        kind: &str,
        max_nodes: usize,
        max_edges: usize,
        deadline: Instant,
    ) -> UaResult<AcyclicReachOutcome> {
        let slot = self.deadline_slot();
        match run_with_atomic_deadline(slot.as_deref(), deadline, || {
            bounded_acyclic_reach_sql_inner(self, org_id, src_id, dst_id, kind, max_nodes, max_edges)
        }) {
            Ok(o) => Ok(o),
            Err(err) if is_deadline_error(&err) => Ok(AcyclicReachOutcome::BoundExceeded("deadline")),
            Err(err) => Err(err),
        }
    }
    fn eligible_degree(
        &mut self,
        org_id: &str,
        node_id: &str,
        direction: EdgeDirection,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        cap_plus_one: usize,
    ) -> UaResult<usize> {
        eligible_degree_sql(self, org_id, node_id, direction, filter, scope, cap_plus_one)
    }
    fn outgoing_live_targets_of_kind_into(
        &mut self,
        org_id: &str,
        src_id: &str,
        kind: &str,
        limit: usize,
        out: &mut Vec<String>,
    ) -> UaResult<()> {
        outgoing_live_targets_of_kind_into_sql(self, org_id, src_id, kind, limit, out)
    }
    fn exact_ppr_slice(
        &mut self,
        org_id: &str,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        max_nodes: usize,
        max_edges: usize,
    ) -> UaResult<Option<ExactPprSlice>> {
        exact_ppr_slice_sql(self, org_id, filter, scope, max_nodes, max_edges)
    }
}

const INSERT_NODE_SQL: &str = "INSERT INTO graph_nodes (\
    id, org_id, kind, external_id, display_label, visibility, team_id, owner_type, owner_id, \
    asserted_by, asserted_by_kind, source_kind, source_ref, meta_json, created_at, updated_at\
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)";

const INSERT_EDGE_SQL: &str = "INSERT INTO graph_edges (\
    id, org_id, src_id, dst_id, kind, assertion_scope, state, weight, \
    asserted_by, asserted_by_kind, asserted_at, source_kind, source_ref, \
    valid_from, valid_to, meta_json\
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)";

impl GraphRead for MigrationGraph<'_> {
    fn require_org_exists(&mut self, org_id: &str) -> UaResult<()> {
        require_org_exists_sql(self.conn, org_id)
    }
    fn get_node_by_id(
        &mut self,
        org_id: &str,
        id: &str,
        scope: &VisibilityScope,
    ) -> UaResult<Option<GraphNodeRow>> {
        get_node_by_id_sql(self.conn, org_id, id, scope)
    }
    fn get_node_by_external(
        &mut self,
        org_id: &str,
        kind: &str,
        external_id: &str,
        scope: &VisibilityScope,
    ) -> UaResult<Option<GraphNodeRow>> {
        get_node_by_external_sql(self.conn, org_id, kind, external_id, scope)
    }
    fn get_nodes_by_ids(
        &mut self,
        org_id: &str,
        ids: &[String],
        scope: &VisibilityScope,
    ) -> UaResult<Vec<GraphNodeRow>> {
        get_nodes_by_ids_sql(self.conn, org_id, ids, scope)
    }
    fn get_edge_by_id(&mut self, org_id: &str, id: &str) -> UaResult<Option<GraphEdgeRow>> {
        get_edge_by_id_sql(self.conn, org_id, id)
    }
    fn get_edges_by_ids(&mut self, org_id: &str, ids: &[String]) -> UaResult<Vec<GraphEdgeRow>> {
        get_edges_by_ids_sql(self.conn, org_id, ids)
    }
    fn get_edges_by_rowids(&mut self, org_id: &str, rowids: &[i64]) -> UaResult<Vec<(i64, GraphEdgeRow)>> {
        get_edges_by_rowids_sql(self.conn, org_id, rowids)
    }
    fn count_org_nodes(&mut self, org_id: &str) -> UaResult<u64> {
        count_org_nodes_sql(self.conn, org_id)
    }
    fn count_org_edges(&mut self, org_id: &str) -> UaResult<u64> {
        count_org_edges_sql(self.conn, org_id)
    }
    fn count_node_live_edges_capped(&mut self, org_id: &str, node_id: &str, cap: usize) -> UaResult<usize> {
        count_node_live_edges_capped_sql(self.conn, org_id, node_id, cap)
    }
    fn with_deadline<F, T>(&mut self, deadline: Instant, f: F) -> UaResult<T>
    where
        Self: Sized,
        F: FnOnce(&mut Self) -> UaResult<T>,
    {
        if Instant::now() >= deadline {
            return Err(deadline_error());
        }
        let out = f(self)?;
        if Instant::now() >= deadline {
            return Err(deadline_error());
        }
        Ok(out)
    }
    fn adjacent_edges(&mut self, query: &AdjacencyQuery) -> UaResult<Vec<AdjacencyEntry>> {
        adjacent_edges_sql(self.conn, query)
    }
    fn compact_adjacent(
        &mut self,
        org_id: &str,
        node_id: &str,
        direction: EdgeDirection,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        limit: usize,
    ) -> UaResult<Vec<CompactAdjEdge>> {
        compact_adjacent_sql(self.conn, org_id, node_id, direction, filter, scope, limit)
    }
    #[allow(clippy::type_complexity)]
    fn with_compact_adjacent<F, T>(
        &mut self,
        org_id: &str,
        directions: EdgeDirection,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        f: F,
    ) -> UaResult<T>
    where
        F: FnOnce(
            &mut dyn FnMut(&str, EdgeDirection, usize, &mut Vec<CompactAdjEdge>) -> UaResult<()>,
        ) -> UaResult<T>,
    {
        with_compact_adjacent_sql(self.conn, org_id, directions, filter, scope, f)
    }
    fn bounded_acyclic_reach(
        &mut self,
        org_id: &str,
        src_id: &str,
        dst_id: &str,
        kind: &str,
        max_nodes: usize,
        max_edges: usize,
        deadline: Instant,
    ) -> UaResult<AcyclicReachOutcome> {
        if Instant::now() >= deadline {
            return Ok(AcyclicReachOutcome::BoundExceeded("deadline"));
        }
        bounded_acyclic_reach_sql_inner(self.conn, org_id, src_id, dst_id, kind, max_nodes, max_edges)
    }
    fn eligible_degree(
        &mut self,
        org_id: &str,
        node_id: &str,
        direction: EdgeDirection,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        cap_plus_one: usize,
    ) -> UaResult<usize> {
        eligible_degree_sql(self.conn, org_id, node_id, direction, filter, scope, cap_plus_one)
    }
    fn outgoing_live_targets_of_kind_into(
        &mut self,
        org_id: &str,
        src_id: &str,
        kind: &str,
        limit: usize,
        out: &mut Vec<String>,
    ) -> UaResult<()> {
        outgoing_live_targets_of_kind_into_sql(self.conn, org_id, src_id, kind, limit, out)
    }
    fn exact_ppr_slice(
        &mut self,
        org_id: &str,
        filter: &EdgeFilter,
        scope: &VisibilityScope,
        max_nodes: usize,
        max_edges: usize,
    ) -> UaResult<Option<ExactPprSlice>> {
        exact_ppr_slice_sql(self.conn, org_id, filter, scope, max_nodes, max_edges)
    }
}

fn find_node_by_id_internal_sql(conn: &Connection, org_id: &str, id: &str) -> UaResult<Option<GraphNodeRow>> {
    let mut stmt =
        conn.prepare_cached(&format!("SELECT {NODE_COLS} FROM graph_nodes WHERE org_id = ?1 AND id = ?2"))?;
    Ok(stmt.query_row(params![org_id, id], |r| decode_node(r, 0)).optional()?)
}

fn find_node_by_external_internal_sql(
    conn: &Connection,
    org_id: &str,
    kind: &str,
    external_id: &str,
) -> UaResult<Option<GraphNodeRow>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {NODE_COLS} FROM graph_nodes WHERE org_id = ?1 AND kind = ?2 AND external_id = ?3"
    ))?;
    Ok(stmt.query_row(params![org_id, kind, external_id], |r| decode_node(r, 0)).optional()?)
}

fn ensure_node_sql(conn: &Connection, node: &NewGraphNode) -> UaResult<(GraphNodeRow, bool)> {
    check_provenance(&node.org_id, &node.asserted_by, &node.asserted_by_kind, &node.source_kind)?;
    let existing: Option<GraphNodeRow> =
        find_node_by_external_internal_sql(conn, &node.org_id, &node.kind, &node.external_id)?;
    if let Some(row) = existing {
        return Ok((row, false));
    }
    let created_at = normalize_ts(&node.created_at, "created_at")?;
    let updated_at = normalize_ts(&node.updated_at, "updated_at")?;
    {
        let mut stmt = conn.prepare_cached(INSERT_NODE_SQL)?;
        stmt.execute(params![
            node.id,
            node.org_id,
            node.kind,
            node.external_id,
            node.display_label,
            node.visibility,
            node.team_id,
            node.owner_type,
            node.owner_id,
            node.asserted_by,
            node.asserted_by_kind,
            node.source_kind,
            node.source_ref,
            node.meta_json,
            created_at,
            updated_at,
        ])?;
    }
    let row = GraphNodeRow {
        id: node.id.clone(),
        org_id: node.org_id.clone(),
        kind: node.kind.clone(),
        external_id: node.external_id.clone(),
        display_label: node.display_label.clone(),
        visibility: node.visibility.clone(),
        team_id: node.team_id.clone(),
        owner_type: node.owner_type.clone(),
        owner_id: node.owner_id.clone(),
        asserted_by: node.asserted_by.clone(),
        asserted_by_kind: node.asserted_by_kind.clone(),
        source_kind: node.source_kind.clone(),
        source_ref: node.source_ref.clone(),
        meta_json: node.meta_json.clone(),
        created_at,
        updated_at,
        archived_at: None,
    };
    Ok((row, true))
}

fn insert_edge_sql(conn: &Connection, edge: &NewGraphEdge) -> UaResult<GraphEdgeRow> {
    check_provenance(&edge.org_id, &edge.asserted_by, &edge.asserted_by_kind, &edge.source_kind)?;
    let now_str = now();
    let (asserted_at, valid_from, valid_to) = check_edge_temporal(
        &edge.source_kind,
        &edge.asserted_at,
        &edge.valid_from,
        edge.valid_to.as_deref(),
        &now_str,
    )?;
    {
        let mut stmt = conn.prepare_cached(INSERT_EDGE_SQL)?;
        stmt.execute(params![
            edge.id,
            edge.org_id,
            edge.src_id,
            edge.dst_id,
            edge.kind,
            edge.assertion_scope,
            edge.state,
            edge.weight,
            edge.asserted_by,
            edge.asserted_by_kind,
            asserted_at,
            edge.source_kind,
            edge.source_ref,
            valid_from,
            valid_to,
            edge.meta_json,
        ])?;
    }
    Ok(GraphEdgeRow {
        id: edge.id.clone(),
        org_id: edge.org_id.clone(),
        src_id: edge.src_id.clone(),
        dst_id: edge.dst_id.clone(),
        kind: edge.kind.clone(),
        assertion_scope: edge.assertion_scope.clone(),
        state: edge.state.clone(),
        weight: edge.weight,
        asserted_by: edge.asserted_by.clone(),
        asserted_by_kind: edge.asserted_by_kind.clone(),
        asserted_at,
        source_kind: edge.source_kind.clone(),
        source_ref: edge.source_ref.clone(),
        valid_from,
        valid_to,
        meta_json: edge.meta_json.clone(),
    })
}

fn insert_nodes_batch_sql(conn: &Connection, nodes: &[NewGraphNode]) -> UaResult<usize> {
    for n in nodes {
        check_provenance(&n.org_id, &n.asserted_by, &n.asserted_by_kind, &n.source_kind)?;
    }
    let mut stmt = conn.prepare_cached(INSERT_NODE_SQL)?;
    let mut inserted = 0usize;
    for n in nodes {
        let created_at = normalize_ts(&n.created_at, "created_at")?;
        let updated_at = normalize_ts(&n.updated_at, "updated_at")?;
        stmt.execute(params![
            n.id,
            n.org_id,
            n.kind,
            n.external_id,
            n.display_label,
            n.visibility,
            n.team_id,
            n.owner_type,
            n.owner_id,
            n.asserted_by,
            n.asserted_by_kind,
            n.source_kind,
            n.source_ref,
            n.meta_json,
            created_at,
            updated_at,
        ])?;
        inserted += 1;
    }
    Ok(inserted)
}

fn insert_edges_batch_sql(conn: &Connection, edges: &[NewGraphEdge]) -> UaResult<usize> {
    let now_str = now();
    let mut normalized = Vec::with_capacity(edges.len());
    for e in edges {
        check_provenance(&e.org_id, &e.asserted_by, &e.asserted_by_kind, &e.source_kind)?;
        normalized.push(check_edge_temporal_cow(
            &e.source_kind,
            &e.asserted_at,
            &e.valid_from,
            e.valid_to.as_deref(),
            &now_str,
        )?);
    }
    let mut stmt = conn.prepare_cached(INSERT_EDGE_SQL)?;
    let mut inserted = 0usize;
    for (e, (asserted_at, valid_from, valid_to)) in edges.iter().zip(normalized.iter()) {
        stmt.execute(params![
            e.id,
            e.org_id,
            e.src_id,
            e.dst_id,
            e.kind,
            e.assertion_scope,
            e.state,
            e.weight,
            e.asserted_by,
            e.asserted_by_kind,
            asserted_at.as_ref(),
            e.source_kind,
            e.source_ref,
            valid_from.as_ref(),
            valid_to.as_deref(),
            e.meta_json,
        ])?;
        inserted += 1;
    }
    Ok(inserted)
}

impl GraphRepo for MigrationGraph<'_> {
    fn find_node_by_id_internal(&mut self, org_id: &str, id: &str) -> UaResult<Option<GraphNodeRow>> {
        find_node_by_id_internal_sql(self.conn, org_id, id)
    }

    fn find_node_by_external_internal(
        &mut self,
        org_id: &str,
        kind: &str,
        external_id: &str,
    ) -> UaResult<Option<GraphNodeRow>> {
        find_node_by_external_internal_sql(self.conn, org_id, kind, external_id)
    }

    fn ensure_node(&mut self, node: &NewGraphNode) -> UaResult<(GraphNodeRow, bool)> {
        ensure_node_sql(self.conn, node)
    }

    fn update_node_mutable(
        &mut self,
        _org_id: &str,
        _id: &str,
        _patch: &GraphNodePatch,
    ) -> UaResult<Option<GraphNodeRow>> {
        Err(UaError::invalid(
            "MigrationGraph is insert-only; node updates are not supported during migration",
        ))
    }

    fn insert_edge(&mut self, edge: &NewGraphEdge) -> UaResult<GraphEdgeRow> {
        insert_edge_sql(self.conn, edge)
    }

    fn update_edge_weight(
        &mut self,
        _org_id: &str,
        _edge_id: &str,
        _weight: f64,
    ) -> UaResult<Option<GraphEdgeRow>> {
        Err(UaError::invalid(
            "MigrationGraph is insert-only; edge updates are not supported during migration",
        ))
    }

    fn insert_nodes_batch(&mut self, nodes: &[NewGraphNode]) -> UaResult<usize> {
        insert_nodes_batch_sql(self.conn, nodes)
    }

    fn insert_edges_batch(&mut self, edges: &[NewGraphEdge]) -> UaResult<usize> {
        insert_edges_batch_sql(self.conn, edges)
    }

    fn close_edge(
        &mut self,
        _org_id: &str,
        _edge_id: &str,
        _valid_to: &str,
    ) -> UaResult<Option<GraphEdgeRow>> {
        Err(UaError::invalid(
            "MigrationGraph is insert-only; closing edges is not supported during migration",
        ))
    }

    fn record_event(&mut self, _channel: &str, _payload: Value, _originator: &str) -> UaResult<Option<i64>> {
        // Schema parts and bulk importers must not append to the hash-chained ledger.
        Ok(None)
    }
}

impl GraphRepo for WriteTx<'_> {
    fn find_node_by_id_internal(&mut self, org_id: &str, id: &str) -> UaResult<Option<GraphNodeRow>> {
        find_node_by_id_internal_sql(self, org_id, id)
    }

    fn find_node_by_external_internal(
        &mut self,
        org_id: &str,
        kind: &str,
        external_id: &str,
    ) -> UaResult<Option<GraphNodeRow>> {
        find_node_by_external_internal_sql(self, org_id, kind, external_id)
    }

    fn ensure_node(&mut self, node: &NewGraphNode) -> UaResult<(GraphNodeRow, bool)> {
        ensure_node_sql(self, node)
    }

    fn update_node_mutable(
        &mut self,
        org_id: &str,
        id: &str,
        patch: &GraphNodePatch,
    ) -> UaResult<Option<GraphNodeRow>> {
        let now_str = now();
        let updated_at = normalize_ts(&patch.updated_at, "updated_at")?;
        let archived_at = match patch.archived_at.as_deref() {
            Some(raw) => {
                let ts = normalize_ts(raw, "archived_at")?;
                if ts > now_str {
                    return Err(UaError::invalid_code(
                        "future_archived_at",
                        "archived_at must be <= current hub time",
                    ));
                }
                Some(ts)
            }
            None => None,
        };
        let changed = {
            let mut stmt = self.prepare_cached(
                "UPDATE graph_nodes \
                 SET display_label = ?1, visibility = ?2, team_id = ?3, owner_type = ?4, \
                     owner_id = ?5, meta_json = ?6, archived_at = ?7, updated_at = ?8 \
                 WHERE org_id = ?9 AND id = ?10",
            )?;
            stmt.execute(params![
                patch.display_label,
                patch.visibility,
                patch.team_id,
                patch.owner_type,
                patch.owner_id,
                patch.meta_json,
                archived_at,
                updated_at,
                org_id,
                id,
            ])?
        };
        if changed == 0 {
            return Ok(None);
        }
        self.find_node_by_id_internal(org_id, id)
    }

    fn insert_edge(&mut self, edge: &NewGraphEdge) -> UaResult<GraphEdgeRow> {
        insert_edge_sql(self, edge)
    }

    fn insert_nodes_batch(&mut self, nodes: &[NewGraphNode]) -> UaResult<usize> {
        insert_nodes_batch_sql(self, nodes)
    }

    fn insert_edges_batch(&mut self, edges: &[NewGraphEdge]) -> UaResult<usize> {
        insert_edges_batch_sql(self, edges)
    }

    fn close_edge(&mut self, org_id: &str, edge_id: &str, valid_to: &str) -> UaResult<Option<GraphEdgeRow>> {
        let now_str = now();
        let vt = normalize_ts(valid_to, "valid_to")?;
        if vt > now_str {
            return Err(UaError::invalid_code(
                "future_valid_to",
                "valid_to must be <= current hub time (future-dated valid_to is refused)",
            ));
        }
        let Some(existing) = get_edge_by_id_sql(self, org_id, edge_id)? else {
            return Ok(None);
        };
        if existing.valid_to.is_some() {
            return Err(UaError::conflict_code(
                "edge_already_closed",
                format!("graph edge {edge_id} is already closed"),
            ));
        }
        if vt < existing.valid_from {
            return Err(UaError::invalid("valid_to must be >= valid_from"));
        }
        {
            let mut stmt = self.prepare_cached(
                "UPDATE graph_edges SET valid_to = ?1 \
                 WHERE org_id = ?2 AND id = ?3 AND valid_to IS NULL",
            )?;
            let n = stmt.execute(params![vt, org_id, edge_id])?;
            if n == 0 {
                return Err(UaError::conflict_code(
                    "edge_already_closed",
                    format!("graph edge {edge_id} is already closed"),
                ));
            }
        }
        let mut closed = existing;
        closed.valid_to = Some(vt);
        Ok(Some(closed))
    }

    fn update_edge_weight(
        &mut self,
        org_id: &str,
        edge_id: &str,
        weight: f64,
    ) -> UaResult<Option<GraphEdgeRow>> {
        if !weight.is_finite() || weight <= 0.0 || weight > 1000.0 {
            return Err(UaError::invalid("weight must be finite and in (0.0, 1000.0]"));
        }
        let Some(existing) = get_edge_by_id_sql(self, org_id, edge_id)? else {
            return Ok(None);
        };
        if existing.valid_to.is_some() {
            return Err(UaError::conflict_code(
                "edge_already_closed",
                format!("graph edge {edge_id} is already closed"),
            ));
        }
        {
            let mut stmt = self.prepare_cached(
                "UPDATE graph_edges SET weight = ?1 \
                 WHERE org_id = ?2 AND id = ?3 AND valid_to IS NULL",
            )?;
            let n = stmt.execute(params![weight, org_id, edge_id])?;
            if n == 0 {
                return Err(UaError::conflict_code(
                    "edge_already_closed",
                    format!("graph edge {edge_id} is already closed"),
                ));
            }
        }
        let mut updated = existing;
        updated.weight = weight;
        Ok(Some(updated))
    }

    fn record_event(&mut self, channel: &str, payload: Value, originator: &str) -> UaResult<Option<i64>> {
        let ev = ledger::append(self, EventInput::new(DEFAULT_ORG, channel, payload).by(originator))?;
        Ok(ev.map(|e| e.seq))
    }
}

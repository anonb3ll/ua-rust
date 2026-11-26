# Graph store

Status: **design, not implemented** (C1 gate: independent review + benchmark
floor + CI/Cloud Build green). Scope: track C, slice C0 (#2717). This
document is the review gate for the shared graph store before any code lands.
Its companions are [organization.md](organization.md), [memory.md](memory.md),
[deliverables.md](deliverables.md), and [evidence-export.md](evidence-export.md).

## Why one graph store

Today relationships in ua-rust live in separate, domain-private tables and
ad-hoc code paths:

- `task_dependencies` (`crates/ua-tools/src/families/core_schema.rs`) holds the
  task prerequisite DAG and runs its own recursive CTE cycle check in
  `crates/ua-tools/src/families/tasks/graph.rs`.
- `task_goal_links` and `goals.parent_goal_id`
  (`crates/ua-tools/src/families/tasks/mod.rs`, `tasks/goals.rs`) hold the goal
  why-chain and the single goal each task serves.
- `graph_canvas_scenes` and `graph_canvas_revisions`
  (`crates/ua-tools/src/families/graph.rs`) store Excalidraw scenes and parse
  them into task and dependency **suggestions** only; it is not an edge store.
- `vault_query` (`crates/ua-tools/src/families/vault/query.rs`) reads every
  markdown note under the vault path from disk on every query, extracts
  `[[wikilinks]]`, and runs Personalized PageRank in memory.
- `memory_entities` and `memory_links` are referenced in
  `crates/ua-tools/src/families/export.rs` (`GRAPH_TABLES`) for Python-hub
  migration manifest parity and designed in [memory.md](memory.md) §4–§5, but do
  not yet exist in `ua-memory` (`crates/ua-memory/src/search.rs` currently
  reports that memory notes have no topical link graph).
- Upcoming consumers — team-spec topology edges ([organization.md](organization.md)),
  the compliance provenance graph ([evidence-export.md](evidence-export.md),
  track G3), and a dependency-driven workflow runner (track C3) — each need
  tenant-scoped, provenance-carrying relationships.

Adding another bespoke edge table per subsystem would duplicate tenant fencing,
visibility enforcement, traversal bounds, and provenance rules. This design
specifies **one shared graph store** — a new workspace crate (`ua-graph`) backed
by `GraphRepo` on SQLite — that carries typed, tenant-scoped, provenance-bearing
edges with temporal validity and hard traversal bounds.

**Slice boundary.** C0 is this document. C1 builds the store, schema,
governed tools, and benchmark floor without rewriting any existing consumer.
Consumer migrations happen one subsystem at a time in C2.

## Data model

### Canonical node identity

Every node lives in `graph_nodes`, scoped to one organization (`org_id`), with:

- an immutable surrogate primary key `id` (ULID) used by all `graph_edges`
  endpoints, and
- a unique domain key `(org_id, kind, external_id)` where `external_id` is the
  domain object's immutable identifier (never a mutable display label).

Using a surrogate `id` plus `(org_id, kind, external_id)` keeps edge joins
uniform across integer IDs (`tasks`), ULIDs (`plans`, `workflow_runs`), content
hashes (`skill_versions`, `deliverable_revisions`), and normalized entity keys,
while letting display labels change (for example an agent rename or a vault note
move) without rewriting edges.

**`display_label` rule:** `graph_nodes.display_label` is display-only metadata
— it is **never an identity**, **never a join key**, and **never written to the
default ledger for another organization** (redacted to `null` under
`ORG-EVENT-DEFAULT`, matching `external_id` and `meta_json`).

### Node kinds

`graph_nodes.kind` is a closed, versioned set enforced by a SQLite `CHECK`
constraint and a Rust enum in `ua-graph`:

| Kind | `external_id` format | Sub-org visibility | Notes |
| --- | --- | --- | --- |
| `agent` | Immutable agent ID (see [Identity transition](#provenance-and-temporal-validity)) | `org` | Never keyed by mutable agent label. |
| `person` | Immutable user ID (`users.id`) | `org` | Never keyed by mutable human label. |
| `skill` | Content-addressed skill version ID or `(name, version)` key | `org` | Feeds skill assignment and execution lineage. |
| `memory_note` | `memory.id` | `private` / `team` / `org` | Authoritative visibility lives in `memory` ([memory.md](memory.md) §3). |
| `memory_entity` | `<entity_kind>:<normalized_value>` | Derived from referencing notes | `entity_kind` in `task`, `branch`, `project`, `service`, `agent`, `wikilink` ([memory.md](memory.md) §4). |
| `task` | Decimal `tasks.id` | `org` (extensible) | Tasks stay org-local ([organization.md](organization.md), Decision 3). |
| `goal` | Decimal `goals.id` | `org` | Supports `serves_goal` and `goal_parent` why-chains. |
| `plan` | `plans.id` | `org` | Planning record; steps addressed on `plans` unless promoted. |
| `run` | `<run_kind>:<id>` (`dispatch`, `workflow`, `session`, `node`, `tool_call`) | `org` (or seat-observed) | Unifies execution attempts across dispatch, workflows, sessions, and nodes. |
| `deliverable` | `<deliverable_id>` or `<deliverable_id>:rev:<rev_no>` | `org` | Immutable artifact or revision ([deliverables.md](deliverables.md)). |
| `vault_note` | Normalized vault-relative path (or stable note ID once vault ingest lands) | `org` (default org while vault is default-only) | Markdown notes linked by `[[wikilinks]]`. |
| `approval` | Decimal `approvals.id` | `org` | Extension point for compliance provenance (track G3). |
| `policy_revision` | Policy revision ID / digest | `org` | Extension point for compliance provenance (track G3). |

### Typed edge kinds

`graph_edges.kind` is also a closed, versioned set. Arbitrary caller-chosen edge
strings are refused so typos cannot split traversals and structural invariants
remain enforceable.

| Edge kind | Source → Target | Direction | Cardinality | Invariants | Lifecycle class | Authoritative writer |
| --- | --- | --- | --- | --- | --- | --- |
| `depends_on` | `task → task` | Directed (dependent waits on prerequisite) | M:N | Acyclic, no self-loop | Topical | `tasks` (`dependency_add` / `dependency_remove`) |
| `subtask_of` | `task → task` | Directed (child → parent) | N:1 | Acyclic tree, no self-loop | Topical | `tasks` (projection of `tasks.parent_id`) |
| `serves_goal` | `task → goal` | Directed (task serves goal) | N:1 | At most one live edge per task | Topical | `tasks` (`goal_manage`) |
| `goal_parent` | `goal → goal` | Directed (child → parent) | N:1 | Acyclic, max depth 8, no self-loop | Topical | `tasks` (projection of `goals.parent_goal_id`) |
| `plan_tracks` | `plan → task` | Directed | M:N | — | Topical | `plans` or governed `graph_edge_assert` |
| `delegated_to` | `task → agent` | Directed | M:N | One active primary per delegation | Lineage / topical | `delegation` |
| `executes` | `run → task \| plan` | Directed | N:1 | One live target per run | Lineage | `dispatch` / `workflows` / `sessions` |
| `executed_by` | `run → agent \| person` | Directed | N:1 | One actor per run | Lineage | `dispatch` / `workflows` / `sessions` |
| `produces` | `run \| task → deliverable` | Directed | M:N | — (deliverable uniqueness stays in `ua-deliverables`) | Lineage | `deliverables` |
| `uses_skill` | `agent \| run → skill` | Directed | M:N | — | Lineage / topical | `skill_registry` / `dispatch` |
| `reviewed_by` | `deliverable → agent \| person` | Directed | M:N | Self-review refused by domain layer | Lineage | `continuity` / review gate |
| `approved_by` | `deliverable \| run → person` | Directed | M:N | Verified human; cites `approval` / event seq | Lineage | `approvals` / `policy_authorizations` |
| `governed_by` | `approval \| run → policy_revision` | Directed | N:1 | Immutable policy binding | Lineage | `approvals` / `policy` |
| `delegates_to` | `agent → agent` | Directed | M:N | Acyclic within team, no self-loop | Topical | `ua-org` (`team_specs` projection) |
| `reviews` | `agent → agent` | Directed | M:N | No self-loop | Topical | `ua-org` (`team_specs` projection) |
| `escalates_to` | `agent → agent \| person` | Directed | M:N | Acyclic, no self-loop | Topical | `ua-org` (`team_specs` projection) |
| `can_observe` | `agent → agent` | Directed | M:N | No self-loop | Topical | `ua-org` (`team_specs` projection) |
| `mentions` | `memory_note \| vault_note → memory_entity` | Directed | M:N | Max 64 live entities per `memory_note`; domain-owned only (never generic) | Topical | `ua-memory` / vault ingest |
| `links_to` | `vault_note → vault_note` | Directed (`[[wikilink]]`; walked undirected in PPR) | M:N | No self-loop | Topical | `vault` ingest / governed tool |
| `promoted_from` | `vault_note ↔ memory_note` | Directed (derived → source) | M:N | No self-loop | Lineage | `vault` (`promote` / `ingest`) |
| `supersedes` | `memory_note → memory_note` | Directed (newer → older) | M:N | No self-loop | Lineage | `ua-memory` (`memory.superseded_by`) |
| `contradicts` | `memory_note → memory_note` | Directed as asserted; queried bidirectionally | M:N | No self-loop; supports `state = 'proposed'` | Topical | `ua-memory` / contradiction workbench |
| `evidence` | `memory_note → memory_note \| task \| run \| deliverable` | Directed | M:N | No self-loop; domain-owned only (never generic) | Lineage | `ua-memory` (`memory.evidence`) |
| `extends` | `memory_note → memory_note` | Directed | M:N | No self-loop | Topical | `ua-memory` or governed `graph_edge_assert` |
| `derives` | `memory_note → memory_note` | Directed (source → summary, per [memory.md](memory.md) §4) | M:N | No self-loop | Lineage | `ua-memory` (`memory_consolidate_commit`) |

Before every insert (both generic and domain-owned), `ua-graph` validates that
`(src_node.kind, dst_node.kind)` satisfies the allowed `Source → Target` pair in
the table above for `edge.kind`, refusing mismatches (for example `depends_on`
between `goal` nodes) with `invalid_argument` (`invalid_endpoint_kind`).

Cardinality constraints marked `N:1` are enforced in SQLite by a partial unique
index over live rows (`WHERE valid_to IS NULL`). Acyclicity constraints
(`depends_on`, `subtask_of`, `goal_parent`, `delegates_to`, `escalates_to`) are
enforced inside the write transaction before insert by a **hard-bounded
reachability check** within `org_id` over live edges of the same kind:

- **Hard write-time cycle-check bounds (per-kind parameterized):**
  `CycleCheckPolicy` parameterizes `(max_nodes, max_edges, deadline_ms)`
  independently per acyclic edge kind (`depends_on`, `subtask_of`,
  `goal_parent`, `delegates_to`, `escalates_to`); every kind defaults to
  `CYCLE_CHECK_MAX_NODES = 1,000` visited nodes, `CYCLE_CHECK_MAX_EDGES = 5,000`
  visited edges, and a `CYCLE_CHECK_DEADLINE_MS = 50` ms wall-clock budget.
- **Distinct reason codes (fail-closed):**
  - If the check detects a real path from `dst_id` back to `src_id`, the write
    is refused with `invalid_argument` and reason code `cycle_detected`
    (preserving C2 parity with `dependency_add`).
  - If the check hits any of the three bounds before exhausting reachable nodes,
    the write is refused with `invalid_argument` and a distinct reason code
    `cycle_check_bound_exceeded` (never guessed or allowed unverified, while
    letting callers distinguish a scale/load bound hit from a real cycle).
- **Mirror and direct-write behavior on bound hit:** because a domain mirror
  runs in the **same write transaction** as its authoritative table write
  (`subtask_of`, `goal_parent`, `delegates_to`, `escalates_to`), a
  `cycle_check_bound_exceeded` refusal aborts and rolls back the entire write
  transaction rather than letting the authoritative table and `graph_edges`
  diverge. Note that **retrying helps only for the 50 ms wall-clock deadline**;
  the `1,000`-node and `5,000`-edge caps are deterministic. (Bounded trees such
  as `goals.parent_goal_id`, capped at depth 8, visit at most 8 edges and cannot
  trigger the node or edge caps.) For `depends_on`, which C2 writes directly to
  `graph_edges` rather than mirroring, this adds `cycle_check_bound_exceeded` as
  an explicit contract change (see the migration map below). Because the check
  is bounded inside the write transaction, every insert stays strictly
  sub-linear in total graph size and prevents quadratic blowup on pathological
  chains.

## Provenance and temporal validity

### Node and edge provenance

Every row in both `graph_nodes` and `graph_edges` carries mandatory, immutable
provenance columns (protected by the `graph_nodes_identity_immutable` and
`graph_edges_provenance_immutable` triggers):

| Column | Tables | Type | Meaning |
| --- | --- | --- | --- |
| `asserted_by` | `graph_nodes`, `graph_edges` | `TEXT NOT NULL` | **Principal ID** of the actor that created the node or asserted the edge (stable agent ID, node ID, or user ID — never a note ID or overloaded scope). `'system'` is used only for hub-internal deterministic projections (schema backfills, mirrors). |
| `asserted_by_kind` | `graph_nodes`, `graph_edges` | `TEXT NOT NULL` | One of `'agent'`, `'person'`, `'node'`, `'system'`. |
| `asserted_at` | `graph_edges` (`created_at` on `graph_nodes`) | `TEXT NOT NULL` | RFC 3339 UTC timestamp (`+00:00`) when the hub recorded the row. |
| `source_kind` | `graph_nodes`, `graph_edges` | `TEXT NOT NULL` | One of `'tool'`, `'event'`, `'mirror'`, `'import'`. |
| `source_ref` | `graph_nodes`, `graph_edges` | `TEXT NOT NULL` | Concrete source identifier: `event:<seq>` (preferred when recorded in the same write transaction), `tool:<tool_name>:<call_id>`, `mirror:<table>:<pk>`, or `import:<source_hash>`. |
| `assertion_scope` | `graph_edges` | `TEXT NOT NULL DEFAULT ''` | Optional scope distinguishing independent assertions of the same `(src_id, dst_id, kind)` — for example `note:<note_id>` when multiple memory notes independently assert the same topical link so the edge stays live until every asserting note retires ([memory.md](memory.md) §4). Empty string `''` for structural edges. |

**Identity transition (ruling 2, pre-#2790):** `asserted_by` means **only** the
asserting principal (note-level assertion scope always lives in
`assertion_scope`). Immutable agent and node IDs land under hub #2790 (gated on
the #2794 identity contract). C1 ships with an opaque, validated `PrincipalId`
wrapper without blocking on #2790, under two strict rules:

1. **Default organization (`org_id = 'default'`) before #2790:** `asserted_by`
   stores a **provisional** value (the verified caller label, marked explicitly
   in the `graph.v1` DDL below) that **#2790's migration backfills** to stable
   principal IDs. Later readers must not treat pre-#2790 `'default'` values as
   permanent identities until that backfill completes.
2. **Non-default organizations (`org_id != 'default'`) before #2790:** any
   non-`'system'` `asserted_by` write (`asserted_by_kind` in `'agent'`,
   `'person'`, `'node'`) for an organization other than `'default'` is
   **refused** (`principal_id_required`) until #2790 supplies immutable
   principal IDs, so mutable labels never enter multi-org rows. Deterministic
   hub-internal `'system'` projections (`asserted_by = 'system'`,
   `asserted_by_kind = 'system'`, `source_kind` in `'mirror'`, `'import'`,
   including the C1 benchmark's org-B fixture seeded inside the bench harness)
   are permitted because `'system'` is a fixed hub constant, not a mutable
   caller label. This rule is enforced at **both** layers: in `ua-tools`
   (`families/graph_store.rs`) before opening a write transaction, and as a
   defense-in-depth invariant inside `GraphRepo` in `ua-store` on every insert.

**Ledger linkage.** Every node creation and edge assertion/retraction appends an
`agent.graph.node_created`, `agent.graph.edge_asserted`, or
`agent.graph.edge_retracted` event to `event_log` in the same write transaction,
and records `source_kind = 'event'`, `source_ref = 'event:<seq>'` (or
`source_kind = 'mirror'` with the enclosing domain event's `seq` for mirrored
domain writes).

### Validity and `as_of` reads

Every edge carries a half-open validity interval `[valid_from, valid_to)` in
normalized RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SS+00:00`, matching
`ua_core::time::now()`):

- `valid_from TEXT NOT NULL`: set by the hub to `asserted_at` on every normal
  write (`source_kind` in `'tool'`, `'event'`, `'mirror'`); callers cannot
  supply a backdated `valid_from` to rewrite `as_of` history. Only
  `source_kind = 'import'` may supply a historical `valid_from <= asserted_at`.
- `valid_to TEXT`: `NULL` while the edge is currently valid. Retracting,
  expiring, or retiring an edge sets `valid_to` (once) rather than deleting the
  row, so historical traversals remain reproducible. **Write-time validation in
  `ua-graph` requires `valid_to <= now`** (no future-dated `valid_to` on insert
  or update). Because no live edge can carry a future `valid_to`, the partial
  unique indexes (`WHERE valid_to IS NULL`, including
  `idx_graph_edges_single_out_live` for `N:1` edges) stay in exact agreement
  with current reads (`valid_to IS NULL OR :now < valid_to`).
- `CHECK (valid_to IS NULL OR valid_to >= valid_from)` rejects inverted
  intervals.
- All timestamps are validated and normalized to fixed-width UTC on write so
  SQLite's lexicographical comparison equals chronological order.

**Read predicates:**

- **Current read (`as_of` omitted, evaluated at `now`):**
  ```sql
  state = 'active'
    AND valid_from <= :now
    AND (valid_to IS NULL OR :now < valid_to)
  ```
- **Historical read (`as_of = T`):**
  ```sql
  state = 'active'
    AND valid_from <= :as_of
    AND (valid_to IS NULL OR :as_of < valid_to)
  ```

The same predicate applies to every hop of a traversal (`neighbors`, `k_hop`,
`shortest_path`, `seed_expand`). A proposed contradiction (`state = 'proposed'`)
is excluded from all standard traversals unless a caller explicitly requests
proposed edges (for example the contradiction workbench).

**Lineage vs topical edges and the mirror-close carve-out (ruling 3).**
Following [memory.md](memory.md) §4, topical retirement (superseding,
invalidating, or narrowing an asserting note) sets `valid_to` only on
**topical** edges (`extends`, `mentions`, accepted `contradicts`, `links_to`,
etc.). **Lineage** edges (`supersedes`, `derives`, `evidence`, `produces`,
`executes`, `executed_by`, `approved_by`, `governed_by`, `reviewed_by`,
`promoted_from`) are never closed by topical retirement, keeping audit and
provenance traces walkable.

**Mirror-close carve-out:** an authoritative domain column change that
invalidates a mirrored edge (for example `memory_restore` clearing
`memory.superseded_by`) is **not** topical retirement — it closes the mirrored
edge (`source_kind = 'mirror'`, or the enclosing domain event `seq`) by
stamping `valid_to = now` (never `DELETE`), keeping the mirror synchronized
with its authoritative table while preserving `as_of` history. If the
authoritative column is later re-set, re-mirroring inserts a **new** edge row
with a new ULID, `valid_from`, and provenance; the partial unique index
(`WHERE valid_to IS NULL`) permits historical rows while guaranteeing at most
one currently live row per `(org_id, src_id, dst_id, kind, assertion_scope)`.

## Tenant isolation (`org_id` scoping)

`graph_nodes` and `graph_edges` are **born tenant-scoped**, following the same
pattern as `ua-deliverables` (`crates/ua-deliverables/src/schema.rs`) and
[organization.md](organization.md):

1. **Columns from birth.** Both tables declare `org_id TEXT NOT NULL` (with no
   silent default on writes) in `graph.v1`.
2. **Generated organization triggers.** `organization.v1.graph` invokes
   `ua_store::org::tenant_part("organization.v1.graph", &["graph_nodes", "graph_edges"])`,
   installing:
   - `graph_nodes_org_exists` and `graph_nodes_org_immutable`,
   - `graph_edges_org_exists` and `graph_edges_org_immutable`.
3. **Cross-org endpoint fence.** `graph_edges` declares composite foreign keys
   `FOREIGN KEY (org_id, src_id) REFERENCES graph_nodes(org_id, id)` and
   `FOREIGN KEY (org_id, dst_id) REFERENCES graph_nodes(org_id, id)`, backed by
   explicit `BEFORE INSERT` and `BEFORE UPDATE` triggers that abort if either
   endpoint is absent or carries a different `org_id`. No cross-org edge can
   exist in storage even if `PRAGMA foreign_keys` is disabled.
4. **Mandatory `WHERE` fence.** Every query — point lookups, adjacency scans,
   every BFS frontier expansion, bidirectional shortest-path steps, PPR
   subgraph extraction, and write-time cycle checks — binds `org_id = :org_id`
   from `Caller.org_id` (never from tool arguments). Every index is led by
   `org_id`.
5. **Classification and insert guard.** Both tables are added to `TENANT` in
   `crates/ua-tools/tests/org_classification.rs` in the same PR that introduces
   `graph.v1` (never to `TENANT_MISSING_ORG_ID`), so the CI insert guard
   verifies every non-test `INSERT` names `org_id`.
6. **Organization-level ledger redaction.** Until per-organization ledger
   events (`hash_v = 2`) switch over, `ORG-EVENT-DEFAULT` sites for non-default
   organizations write only neutral IDs and edge/node kinds (never display
   labels, `external_id` text, or `meta_json`) with originator `'system'`,
   matching [organization.md](organization.md).

## Query shapes and hard bounds

Every query runs on the SQLite reader pool (`read_async`), accepts `org_id` from
the verified caller, an optional `as_of` timestamp, optional `edge_kinds` /
`node_kinds` allowlists, and a caller visibility scope. Every query enforces a
hard per-call wall-clock deadline (`deadline_ms`, default `500`, max `2_000`)
and returns explicit truncation metadata (`truncated: bool`,
`truncation_reason: Option<String>`).

### 1. `neighbors` (1-hop adjacency)

Returns immediate incident edges and adjacent nodes for one seed node.

- **Inputs:** `node_id` (or `(kind, external_id)`), `direction` (`out` | `in` |
  `both`, default `both`), `edge_kinds?`, `node_kinds?`, `as_of?`, `limit`,
  `cursor?`.
- **Caps:** `limit` default `50`, hard max `200`.
- **Ordering:** deterministic `(weight DESC, asserted_at DESC, edge_id ASC)`.
- **Output:** `{ node, neighbors: [{ node, edge, direction }], truncated, next_cursor }`.

### 2. `k_hop` (bounded BFS expansion)

Expands outward from one or more seed nodes up to `max_hops`. Implemented as
level-by-level BFS in Rust over indexed `GraphRepo` adjacency reads (never an
unbounded SQLite `WITH RECURSIVE`), maintaining a `visited` node set so cycles
never loop.

- **Inputs:** `seed_ids` (1–20), `max_hops`, `direction` (`out` | `in` |
  `both`), `edge_kinds?`, `node_kinds?`, `as_of?`, `max_nodes`, `max_edges`,
  `max_degree_per_node`, `skip_hubs_over?`.
- **Hard caps (clamped or refused if exceeded):**

| Bound | Default | Hard max | Behavior when exceeded |
| --- | ---: | ---: | --- |
| `seed_ids.len()` | — | 20 | Refuse `invalid_argument` |
| `max_hops` | 2 | 4 | Refuse `invalid_argument` |
| `max_degree_per_node` | 50 | 200 | Truncate node's frontier; set `truncated = true` |
| `max_visited_edges` (scan budget) | 2,000 | 10,000 | Stop expansion; `truncation_reason = "scan_budget"` |
| `max_nodes` returned | 100 | 500 | Stop expansion; `truncation_reason = "node_cap"` |
| `max_edges` returned | 250 | 1,000 | Stop expansion; `truncation_reason = "edge_cap"` |

- **`skip_hubs_over`:** Optional degree threshold (counted strictly over
  caller-eligible edges). Nodes whose eligible degree exceeds it are skipped as
  expansion pivots (used by the memory entity leg's hub cutoff of 25).
- **Output:** `{ nodes, edges, hops_completed, visited_edges, truncated, truncation_reason }`.

### 3. `shortest_path` (bounded bidirectional BFS)

Finds a shortest path between `from_id` and `to_id` over eligible edges at
`as_of`. Implemented as bidirectional BFS alternating the smaller frontier.

- **Inputs:** `from_id`, `to_id`, `direction` (`out` | `in` | `both`, default
  `out`), `edge_kinds?`, `node_kinds?`, `as_of?`, `max_depth`.
- **Hard caps:**
  - `max_depth`: default `4`, hard max `6` (refuse > 6 with `invalid_argument`).
  - `max_expanded_nodes`: hard max `5,000`.
  - `max_expanded_edges`: hard max `10,000`.
- **Tie breaking:** deterministic by `edge_id ASC`.
- **Output:** `{ found, hops, node_ids, edge_ids, truncated, truncation_reason }`.
  If either endpoint is missing, outside `org_id`, or outside the caller's
  visibility scope, returns `not_found` identically to a nonexistent ID.

### 4. `seed_expand` (Personalized PageRank)

Generalizes `vault_query`'s lexical-seed + Personalized PageRank walk
(`crates/ua-tools/src/families/vault/query.rs`: Haveliwala 2002 power iteration,
`DAMPING = 0.85`, `MAX_ITERS = 30`, `EPS = 1e-6`, undirected edge union,
dangling mass redistributed to the teleport vector, `max_results` capped at 50)
to operate over `graph_edges`.

- **Inputs:**
  - `seeds`: 1–50 `(node_id, weight)` pairs with positive finite weights
    (normalized into the teleport distribution `t`).
  - `edge_kinds?`, `node_kinds?`, `as_of?`.
  - `walk_direction`: `undirected` (default, matching `vault_query`) or `out`.
  - `damping`: default `0.85`, clamped to `0.10..=0.95`.
  - `max_iters`: default `30`, hard max `50`.
  - `eps`: default `1e-6`, clamped to `1e-9..=1e-2`.
  - `max_results`: default `10`, hard max `50`.
  - `skip_hubs_over?`: optional eligible-degree hub filter.
- **Bounded subgraph extraction (for large graphs):**
  - `vault_query` today loads the entire vault into memory because vaults hold
    hundreds to low thousands of notes. Over a 100k-edge org graph, loading the
    entire org per query would violate latency and memory bounds.
  - Therefore `seed_expand` checks whether the filtered eligible slice fits
    within `PPR_EXACT_NODE_CAP = 5,000` nodes and `PPR_EXACT_EDGE_CAP = 25,000`
    edges:
    - **Fits:** run exact power iteration on the full eligible slice (matching
      `vault_query`'s math bit-for-bit, including dangling-mass redistribution
      to `teleport` and weighted edge shares proportional to `edge.weight`).
    - **Exceeds:** extract a bounded 2-hop ego subgraph around `seeds` capped at
      `5,000` nodes, `25,000` edges, and `max_degree_per_node = 200` (highest
      `weight` edges first, ties by `edge_id ASC`), then run power iteration on
      that ego subgraph.
- **Output:** `{ results: [{ node_id, kind, external_id, display_label, pagerank, pagerank_norm, links_out, links_in }], graph: { nodes, edges, seeds, iterations, exact, truncated } }`.
  Caller-specific blending (`0.5 * lexical_norm + 0.5 * pagerank_norm` in
  `vault_query`, or RRF leg fusion in `ua-memory`) stays in the caller.

## SQLite schema, indexes, and backend mapping

### Crate placement and schema parts

- **Crate:** `crates/ua-graph`, depending only on `ua-core` and `ua-store`
  (matching `ua-deliverables`, enforced by a
  `crates/ua-graph/tests/dependencies.rs` guard test; note that `ua-memory` also
  depends on `ua-org`). All `ua_org::authz` checks (including
  operator/lifecycle-operator checks for `graph_edge_retract`) run in
  `ua-tools` (`crates/ua-tools/src/families/graph_store.rs`) before calling
  `ua-graph`.
- **Tool registration:** `crates/ua-tools/src/families/graph_store.rs` (keeping
  `crates/ua-tools/src/families/graph.rs` untouched for the planning canvas).
- **No new crate dependencies.** Everything needed (`rusqlite`, `ulid`, `jiff`,
  `serde`, `serde_json`) is already in workspace `Cargo.toml`; `docs/stack.md`
  requires no new entry.
- **Schema parts** (applied after `organization.v1.store`):
  1. `graph.v1` (`SchemaPart` in `ua-graph`) — creates `graph_nodes`,
     `graph_edges`, indexes, endpoint fence triggers, and immutability triggers.
  2. `organization.v1.graph` (`Procedure` via
     `ua_store::org::tenant_part("organization.v1.graph", &["graph_nodes", "graph_edges"])`)
     — installs `*_org_exists` and `*_org_immutable`.
  3. `graph.v2.counters` (`SchemaPart` in `ua-graph`) — creates
     `graph_org_counts(org_id, node_count, edge_count)`, backfills existing org
     totals, and installs `AFTER INSERT` triggers (`graph_nodes_count_ai`,
     `graph_edges_count_ai`) so per-org node and edge quota checks run in O(1)
     inside the write transaction.
  4. `organization.v1.graph_counters` (`Procedure` via
     `ua_store::org::tenant_part("organization.v1.graph_counters", &["graph_org_counts"])`)
     — installs `graph_org_counts_org_exists` and
     `graph_org_counts_org_immutable`.
  5. `graph.v3.counters_no_delete` (`SchemaPart` in `ua-graph`) — installs
     `graph_org_counts_no_delete` (`BEFORE DELETE ON graph_org_counts`) so
     counter rows cannot be deleted to reset quota accounting.

### DDL (`graph.v1`)

```sql
CREATE TABLE IF NOT EXISTS graph_nodes (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL,
    kind             TEXT NOT NULL CHECK (kind IN (
                         'agent','person','skill','memory_note','memory_entity',
                         'task','goal','plan','run','deliverable','vault_note',
                         'approval','policy_revision'
                     )),
    external_id      TEXT NOT NULL CHECK (length(external_id) BETWEEN 1 AND 256),
    -- Display-only metadata: never an identity, never a join key, and never
    -- written to the default ledger for non-default organizations.
    display_label    TEXT CHECK (display_label IS NULL OR length(display_label) <= 256),
    visibility       TEXT NOT NULL DEFAULT 'org'
                     CHECK (visibility IN ('private','team','org')),
    team_id          TEXT,
    owner_type       TEXT CHECK (owner_type IS NULL OR owner_type IN ('human','agent','org')),
    owner_id         TEXT,
    -- Immutable node provenance (symmetric with graph_edges).
    -- PROVISIONAL PRE-#2790: for org_id = 'default', asserted_by carries the
    -- verified caller label until #2790 lands and backfills stable principal
    -- IDs. Non-default org asserted_by writes are refused until #2790 lands.
    asserted_by      TEXT NOT NULL CHECK (length(asserted_by) BETWEEN 1 AND 128),
    asserted_by_kind TEXT NOT NULL CHECK (asserted_by_kind IN ('agent','person','node','system')),
    source_kind      TEXT NOT NULL CHECK (source_kind IN ('tool','event','mirror','import')),
    source_ref       TEXT NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 256),
    meta_json        TEXT NOT NULL DEFAULT '{}'
                     CHECK (json_valid(meta_json) AND length(meta_json) <= 8192),
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    archived_at      TEXT,
    UNIQUE (org_id, kind, external_id),
    UNIQUE (org_id, id),
    CHECK (visibility != 'team' OR team_id IS NOT NULL),
    CHECK (visibility != 'private' OR (owner_type IS NOT NULL AND owner_id IS NOT NULL)),
    CHECK ((asserted_by = 'system') = (asserted_by_kind = 'system'))
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_org_kind_vis
    ON graph_nodes (org_id, kind, visibility, team_id, owner_id)
    WHERE archived_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_graph_nodes_source
    ON graph_nodes (org_id, source_kind, source_ref);

CREATE TRIGGER IF NOT EXISTS graph_nodes_identity_immutable
BEFORE UPDATE OF id, kind, external_id, asserted_by, asserted_by_kind,
                 source_kind, source_ref, created_at ON graph_nodes
BEGIN
    SELECT RAISE(ABORT, 'graph node identity and provenance are immutable');
END;

CREATE TRIGGER IF NOT EXISTS graph_nodes_no_delete
BEFORE DELETE ON graph_nodes
BEGIN
    SELECT RAISE(ABORT, 'graph nodes are archived, never deleted');
END;

CREATE TABLE IF NOT EXISTS graph_edges (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL,
    src_id           TEXT NOT NULL,
    dst_id           TEXT NOT NULL,
    kind             TEXT NOT NULL CHECK (kind IN (
                         'depends_on','subtask_of','serves_goal','goal_parent',
                         'plan_tracks','delegated_to','executes','executed_by',
                         'produces','uses_skill','reviewed_by','approved_by',
                         'governed_by','delegates_to','reviews','escalates_to',
                         'can_observe','mentions','links_to','promoted_from',
                         'supersedes','contradicts','evidence','extends','derives'
                     )),
    assertion_scope  TEXT NOT NULL DEFAULT '' CHECK (length(assertion_scope) <= 128),
    state            TEXT NOT NULL DEFAULT 'active'
                     CHECK (state IN ('active','proposed')),
    weight           REAL NOT NULL DEFAULT 1.0 CHECK (weight > 0.0 AND weight <= 1000.0),
    -- PROVISIONAL PRE-#2790: principal ID only (note scope lives in
    -- assertion_scope). For org_id = 'default', asserted_by carries the
    -- verified caller label until #2790 lands and backfills stable principal
    -- IDs. Non-default org asserted_by writes are refused until #2790 lands.
    asserted_by      TEXT NOT NULL CHECK (length(asserted_by) BETWEEN 1 AND 128),
    asserted_by_kind TEXT NOT NULL CHECK (asserted_by_kind IN ('agent','person','node','system')),
    asserted_at      TEXT NOT NULL,
    source_kind      TEXT NOT NULL CHECK (source_kind IN ('tool','event','mirror','import')),
    source_ref       TEXT NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 256),
    valid_from       TEXT NOT NULL,
    valid_to         TEXT,
    meta_json        TEXT NOT NULL DEFAULT '{}'
                     CHECK (json_valid(meta_json) AND length(meta_json) <= 4096),
    CHECK (src_id != dst_id),
    CHECK (state = 'active' OR kind = 'contradicts'),
    CHECK (valid_to IS NULL OR valid_to >= valid_from),
    CHECK ((asserted_by = 'system') = (asserted_by_kind = 'system')),
    FOREIGN KEY (org_id, src_id) REFERENCES graph_nodes(org_id, id),
    FOREIGN KEY (org_id, dst_id) REFERENCES graph_nodes(org_id, id)
);

-- At most one currently live edge per (org, src, dst, kind, assertion_scope).
CREATE UNIQUE INDEX IF NOT EXISTS idx_graph_edges_live_unique
    ON graph_edges (org_id, src_id, dst_id, kind, assertion_scope)
    WHERE valid_to IS NULL;

-- N:1 cardinality enforcement for single-parent / single-target live edges.
CREATE UNIQUE INDEX IF NOT EXISTS idx_graph_edges_single_out_live
    ON graph_edges (org_id, src_id, kind)
    WHERE valid_to IS NULL
      AND kind IN ('serves_goal','subtask_of','goal_parent','executes','executed_by','governed_by');

-- Hot adjacency indexes (covering dst/src, weight, validity, state).
CREATE INDEX IF NOT EXISTS idx_graph_edges_out
    ON graph_edges (org_id, src_id, kind, state, valid_to, valid_from, dst_id, weight);
CREATE INDEX IF NOT EXISTS idx_graph_edges_in
    ON graph_edges (org_id, dst_id, kind, state, valid_to, valid_from, src_id, weight);

-- Kind-scoped scans, provenance reconciliation, and actor audits.
CREATE INDEX IF NOT EXISTS idx_graph_edges_org_kind_live
    ON graph_edges (org_id, kind, state, valid_to, asserted_at);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source
    ON graph_edges (org_id, source_kind, source_ref);
CREATE INDEX IF NOT EXISTS idx_graph_edges_asserted_by
    ON graph_edges (org_id, asserted_by, asserted_at);

-- Defense-in-depth cross-org endpoint fence (holds even with foreign_keys OFF).
CREATE TRIGGER IF NOT EXISTS graph_edges_org_endpoints_insert
BEFORE INSERT ON graph_edges
WHEN NOT EXISTS (SELECT 1 FROM graph_nodes WHERE id = NEW.src_id AND org_id = NEW.org_id)
  OR NOT EXISTS (SELECT 1 FROM graph_nodes WHERE id = NEW.dst_id AND org_id = NEW.org_id)
BEGIN
    SELECT RAISE(ABORT, 'graph edge endpoints must exist in the edge organization');
END;

CREATE TRIGGER IF NOT EXISTS graph_edges_org_endpoints_update
BEFORE UPDATE ON graph_edges
WHEN NOT EXISTS (SELECT 1 FROM graph_nodes WHERE id = NEW.src_id AND org_id = NEW.org_id)
  OR NOT EXISTS (SELECT 1 FROM graph_nodes WHERE id = NEW.dst_id AND org_id = NEW.org_id)
BEGIN
    SELECT RAISE(ABORT, 'graph edge endpoints must exist in the edge organization');
END;

CREATE TRIGGER IF NOT EXISTS graph_edges_provenance_immutable
BEFORE UPDATE OF id, src_id, dst_id, kind, assertion_scope,
                 asserted_by, asserted_by_kind, asserted_at,
                 source_kind, source_ref, valid_from ON graph_edges
BEGIN
    SELECT RAISE(ABORT, 'graph edge endpoints and provenance are immutable');
END;

CREATE TRIGGER IF NOT EXISTS graph_edges_valid_to_once
BEFORE UPDATE OF valid_to ON graph_edges
WHEN OLD.valid_to IS NOT NULL AND NEW.valid_to IS NOT OLD.valid_to
BEGIN
    SELECT RAISE(ABORT, 'a closed graph edge cannot be reopened; assert a new edge');
END;

CREATE TRIGGER IF NOT EXISTS graph_edges_state_no_revert
BEFORE UPDATE OF state ON graph_edges
WHEN OLD.state = 'active' AND NEW.state != 'active'
BEGIN
    SELECT RAISE(ABORT, 'an active graph edge cannot revert to proposed');
END;

CREATE TRIGGER IF NOT EXISTS graph_edges_no_delete
BEFORE DELETE ON graph_edges
BEGIN
    SELECT RAISE(ABORT, 'graph edges are closed with valid_to, never deleted');
END;
```

### Repository trait and second-backend mapping

Following the `OrgRepo` ([organization.md](organization.md)) and `MemoryRepo`
([memory.md](memory.md)) precedent, the synchronous `GraphRepo` trait and its
SQLite implementation live in `ua-store` exposing plain Rust domain types (zero
`rusqlite` types in the public signature) and **bounded adjacency primitives
only**, so writes run inside the hub's existing write transaction and commit
atomically with `ledger::append`, while `ua-store` stays free of tool logic.
Traversal algorithms (`k_hop`, bidirectional `shortest_path`, `seed_expand`
PPR) and domain validation live in `ua-graph` and call `GraphRepo` for
bounded, org- and visibility-filtered adjacency reads.

*(Note on crate boundaries: `crates/ua-memory/tests/boundary.rs` guards which
crates may depend on `ua-memory` — today exclusively `ua-tools` — not
`ua-memory`'s own dependencies. Placing `GraphRepo` in `ua-store` follows the
repo-in-`ua-store` precedent so `ua-memory`, `ua-org`, and `ua-graph` all share
the same storage primitives without circular crate dependencies.)*

Mapping to a second backend (PostgreSQL, roadmap Phase 3):

| SQLite construct | PostgreSQL mapping | Notes |
| --- | --- | --- |
| `TEXT` timestamps (fixed-width RFC 3339 UTC) | `TIMESTAMPTZ` (or `TEXT` if wire-parity preferred) | Half-open `[valid_from, valid_to)` translates directly; optional `tstzrange` later. |
| `meta_json TEXT CHECK (json_valid(...))` | `JSONB` | Same byte-length cap validated in `ua-graph` before insert. |
| Wide covering B-tree (`idx_graph_edges_out/in`) | `CREATE INDEX ... ON graph_edges (org_id, src_id, kind, state, valid_to, valid_from) INCLUDE (dst_id, weight)` | Index-only adjacency scans with smaller key size. |
| Partial unique indexes (`WHERE valid_to IS NULL`) | Identical PostgreSQL syntax | Same concurrency guarantees under `READ COMMITTED` / `SERIALIZABLE`. |
| Composite FK + `BEFORE INSERT` org triggers | Identical composite FK + optional PostgreSQL Row-Level Security (`RLS`) | Explicit `WHERE org_id = $1` remains mandatory; RLS is defense-in-depth only. |
| `GraphRepo` synchronous methods on `WriteTx` | Transaction-scoped handle on `sqlx` / `tokio-postgres` (or async trait migration across all repos together) | No graph-specific database (Neo4j, Cypher) is required; relational adjacency tables keep transactional parity with the ledger. |

## Migration map for existing edge tables

**Rule for C1:** C1 introduces `ua-graph`, `graph.v1`, `organization.v1.graph`,
and the governed graph tools, and **rewrites zero existing consumers**. Existing
tables, tool contracts, and tests remain untouched until C2.

| Existing surface | Location | Current role | C1 | C2+ disposition |
| --- | --- | --- | --- | --- |
| `task_dependencies` | `crates/ua-tools/src/families/core_schema.rs:46`, `tasks/graph.rs` | Explicit task prerequisite DAG (`dependency_add`, `dependency_list`, `dependency_remove`) with CTE cycle check and creator-only delete. | Unchanged | **Move in C2** to `graph_edges(kind = 'depends_on')`, written directly (not mirrored) behind `dependency_*`. **Explicit contract change:** JSON shapes and `cycle_detected` stay identical, but a dependency subgraph exceeding `1,000` reachable nodes / `5,000` reachable edges / `50 ms` from the new edge now returns `invalid_argument` (`cycle_check_bound_exceeded`) where today's CTE has no bound (retrying helps only for the 50 ms deadline; node/edge caps are deterministic). **Sequencing:** in non-default organizations, `dependency_*` waits for `#2790`, because there is no immutable principal ID yet and stamping `'system'` would lose the creator identity that creator-only delete relies on. |
| `task_goal_links` | `crates/ua-tools/src/families/tasks/mod.rs:93`, `tasks/goals.rs` | Single goal a task serves (`goal_manage` `link`/`unlink`/`ancestry`). | Unchanged | **Move in C2** to `graph_edges(kind = 'serves_goal')`, keeping N:1 uniqueness via `idx_graph_edges_single_out_live` and preserving the `goal_manage` contract. |
| `goals.parent_goal_id` | `crates/ua-tools/src/families/tasks/mod.rs:84` | Why-chain tree column (max depth 8). | Unchanged | **Stays** authoritative on `goals`; optional read-only mirror to `goal_parent` in C2 if cross-domain traversals need it. |
| `graph_canvas_scenes`, `graph_canvas_revisions` | `crates/ua-tools/src/families/graph.rs` | Excalidraw scene blob store + deterministic parser emitting `task_suggestions` and `dependency_suggestions` (**proposals only**). | Unchanged | **Stays as-is.** Canvas scenes are visual documents, never an authoritative edge store. Post-C2 UI/tools may render a `ua-graph` subgraph onto a board, while human-approved proposals still create real edges through domain tools. |
| `memory_entities`, `memory_links` | `crates/ua-tools/src/families/export.rs:586` (`GRAPH_TABLES`), [memory.md](memory.md) §4–§5 | Do not exist in `crates/` today; `export.rs` checks `has_table()` for Python-hub migration manifests. | Unchanged | **No separate tables (`graph.v1` is the only edge store).** `memory.md` §4's model stands while its storage section is superseded by `graph_nodes` / `graph_edges` (amended in Memory v2 `#2799`, not C2). Memory §4 entity/link writes go through `GraphRepo` once C1 lands; `export.rs::GRAPH_TABLES` reads from `ua-graph` (or a compatibility view). |
| `vault_query` (`[[wikilink]]` PPR) | `crates/ua-tools/src/families/vault/query.rs` | On-the-fly disk walk + undirected Personalized PageRank over markdown files. | Unchanged | **Stays disk-authoritative in C1.** In C2+ (with track B9 content-hash vault ingest), `vault_query` can read indexed `vault_note` / `links_to` rows through `seed_expand`, keeping the disk walk as fallback for unindexed vaults. |
| Relational FKs (`tasks.parent_id`, `deliverables.task_id`, `delegations.task_id`, `task_hold_members`, `plan_steps.plan_id`) | Their owning families | Core relational invariants enforced by owning tables. | Unchanged | **Stay authoritative** on their owning tables; projected into `graph_edges` (`subtask_of`, `produces`, `delegated_to`) in the same write transaction only where cross-domain traversal or G3 provenance needs them. For acyclic mirrors (`subtask_of`), a `cycle_check_bound_exceeded` refusal rolls back the enclosing transaction (retryable only on the 50 ms deadline; node/edge caps are deterministic). |
| Team-spec topology (`delegates_to`, `reviews`, `escalates_to`, `can_observe`) | [organization.md](organization.md) (`team_specs`) | Enforced seat interaction rules inside append-only canonical JSON specs. | Unchanged | **Authoritative in `team_specs`**; projected into `graph_edges` on spec commit in C2+ in the same write transaction for graph queries and visualization, never editable directly via `graph_edge_assert`. For acyclic mirrors (`delegates_to`, `escalates_to`), a `cycle_check_bound_exceeded` refusal rolls back the spec commit (retryable only on the 50 ms deadline; node/edge caps are deterministic). |

## Alignment with `memory.md` step 5

[memory.md](memory.md) §4 and §5 specify the entity/link store and the graph
retrieval leg in Memory v2's build order. `ua-graph` lines up with §5 as
follows:

- **Exact §5 traversal semantics and caps:** The memory graph leg runs as a
  caller-scoped expansion from up to **5 seed notes** returned by the content
  legs, reading at most **16 entities per seed** (`MAX_SEED_ENTITIES`), fanout
  **10 per seed**, scan budget **100** (`fanout × 10`), returning at most **20**
  notes, and skipping any `memory_entity` whose **caller-eligible** degree
  exceeds **25** (hub cutoff). It walks both:
  1. 1-hop live, accepted (`state = 'active'`, `valid_to IS NULL` / active at
     `as_of`) note-to-note edges (`supersedes`, `contradicts`, `evidence`,
     `extends`, `derives`) in either direction, and
  2. 2-hop co-entity neighbors (`memory_note --mentions--> memory_entity <--mentions-- memory_note`).
- **Eligibility before every cap and degree count:** Matching [memory.md](memory.md)
  §5, every node-visibility filter (`org_id`, `visibility`, `team_id`,
  `owner_type`, `owner_id`, `superseded_by`, `as_of`, expiry) executes inside
  the innermost SQL query **before** computing entity document frequency,
  evaluating the >25 hub cutoff, or applying scan/fanout caps. Hidden notes in
  the same organization never push an entity over the hub cutoff, shift a
  neighbor's score, or consume scan budget.
- **Mapping to `ua-graph` primitives:**
  - `memory_entities(org_id, note_id, kind, value, retired_at)` maps to
    `graph_nodes(kind = 'memory_entity', external_id = '<kind>:<value>')` +
    `graph_edges(kind = 'mentions', valid_to = retired_at)`.
  - `memory_links(org_id, src_id, dst_id, rel, asserted_by, proposed, actor, created_at, retired_at)`
    maps to `graph_edges(kind = rel, assertion_scope = 'note:<asserting_note_id>', state = 'proposed'|'active', asserted_by = <stable_principal_id>, valid_to = retired_at)`.

### Architectural rulings with `memory.md` (resolved in C0)

1. **One edge store, not two:** `graph.v1` is the **only** edge store. Do not
   create `memory.links.v1`, `memory_entities`, or `memory_links` tables.
   [memory.md](memory.md) §4's *model* stands while its *storage section* is
   superseded by `graph_nodes` / `graph_edges` (that doc amendment belongs with
   Memory v2 `#2799`, not C2). Sequencing: the Memory §4 entity/link slice
   waits for C1 or writes directly against `GraphRepo`.
2. **`asserted_by` means only the principal:** `asserted_by` is always the
   asserting principal (`PrincipalId`); memory's per-note assertion ownership
   ("keep live until every asserting note retires") lives in
   `assertion_scope = 'note:<note_id>'`. Pre-#2790, `'default'` rows store a
   provisional label backfilled by #2790, and non-default org `asserted_by`
   writes are refused until #2790 lands.
3. **Close with `valid_to`, never delete (with mirror-close carve-out):**
   `graph_edges_no_delete` stands. When an authoritative domain column changes
   (for example `memory_restore` clearing `superseded_by`), the owning domain
   closes its mirrored edge (`source_kind = 'mirror'` or enclosing event `seq`)
   by setting `valid_to = now` — distinct from topical retirement. Re-mirroring
   inserts a new row with a new ULID, permitted by `idx_graph_edges_live_unique`.
4. **`GraphRepo` in `ua-store`:** `GraphRepo` and its SQLite implementation
   live in `ua-store` (beside `OrgRepo` and `MemoryRepo`), exposing bounded
   adjacency primitives only while `k_hop`, `shortest_path`, and `seed_expand`
   stay in `ua-graph`. (`crates/ua-memory/tests/boundary.rs` guards which
   crates may depend on `ua-memory` — `["ua-tools"]` — not `ua-memory`'s own
   dependencies; `ua-memory` already depends on `ua-org` for `authz`.)

## Benchmark floor (C1 acceptance gate)

C1 must include a reproducible benchmark harness (invoked as a bench binary or
`--release` bench test, never shipping fixture data inside the production `ua`
library) and **meet or beat every floor below before merge**.

### Fixture shape

- **Determinism:** fixed PRNG seed (`0x5541_4752_4150_4801`), on-disk SQLite
  WAL database in a temporary directory (measures real page-cache and WAL
  behavior, not `:memory:`), `PRAGMA foreign_keys = ON`, all `graph.v1` and
  `organization.v1.graph` triggers and indexes active.
- **Scale:**
  - **20,000 nodes** and **100,000 live edges** (`valid_to IS NULL`) plus
    **10,000 historical closed edges** (`valid_to IS NOT NULL`), total 110,000
    edge rows.
  - **2 organizations:** 90,000 live edges in org A (`'default'`) and 10,000
    live edges in org B (seeded inside the bench harness using
    `asserted_by = 'system'`, `asserted_by_kind = 'system'`,
    `source_kind = 'import'`, respecting the pre-#2790 non-default-org
    principal rule), exercising `org_id` index selectivity on every read.
- **Degree distribution** (heavy-tailed, matching task/memory/vault graphs):
  - 70.0% ordinary nodes (degree 2–10),
  - 25.0% medium nodes (degree 11–50),
  - 4.5% high-degree nodes (degree 51–200),
  - 0.5% super-hubs (degree 500–2,000, exercising degree-cap and hub-skip
    guards).
- **Kind and visibility mix:**
  - Nodes: 40% `memory_note`, 25% `memory_entity`, 15% `task`, 10% `vault_note`,
    10% across `agent`, `person`, `skill`, `plan`, `run`, `deliverable`.
  - Visibility: 85% `org`, 10% `team` (across 5 teams), 5% `private` (across 20
    owners).
  - Edges: 35% `mentions`, 20% `links_to`, 15% `depends_on`, 10% `extends`, 10%
    `evidence`, 10% across `produces`, `executes`, `delegates_to`, `supersedes`.

### Required C1 floors

Measured in `--release` with warmed SQLite page cache over 200 deterministic
queries per workload (reporting p50, p95, p99, and hardware/SQLite version in
the C1 PR):

| Workload | Parameters | Floor |
| --- | --- | --- |
| Batched edge insert | 1,000 edges/tx across 100k edges, triggers + indexes active | **≥ 15,000 edges/sec** |
| Single governed edge write (normal) | 1 edge + `ledger::append` in one write transaction, including write-time acyclicity check on a 500-hop `depends_on` chain | **≤ 3 ms p95** |
| Cycle-check bound-hit probe | 1 `depends_on` write exceeding `CYCLE_CHECK_MAX_NODES` (1,000) / `CYCLE_CHECK_MAX_EDGES` (5,000) / `CYCLE_CHECK_DEADLINE_MS` (50 ms) | **≤ 60 ms p95**, refused with `invalid_argument` (`cycle_check_bound_exceeded`) |
| 2-hop `k_hop` (100k edges) | 3 seeds, `max_hops = 2`, `max_degree_per_node = 50`, `max_nodes = 100`, `as_of` active, org-fenced | **≤ 15 ms p95** (≤ 25 ms p95 with `memory_note` sub-org visibility filter) |
| `seed_expand` PPR (100k edges) | 5 seeds, 2-hop bounded subgraph (≤5,000 nodes, ≤25,000 edges), `damping = 0.85`, `max_iters = 30`, `eps = 1e-6`, `max_results = 10` | **≤ 40 ms p95** (≤ 20 ms p95 on exact ≤5k-node subgraphs) |
| `shortest_path` (100k edges) | Bidirectional BFS, `max_depth = 4`, `max_expanded_edges = 10,000` | **≤ 15 ms p95** |
| Super-hub DoS probe | `k_hop` (`max_hops = 3`) and `seed_expand` seeded directly on a 2,000-edge super-hub | **≤ 50 ms p95**, bounded memory, `truncated = true` |

**SQLite writer memory budget:** `ua-store` sets `PRAGMA cache_size = -16384`
(16 MiB) and `PRAGMA wal_autocheckpoint = 4000` (16 MiB WAL threshold) on the
**single writer connection only** (+14 MiB over SQLite's 2 MiB default, total
across the hub). Read pool connections keep SQLite's default 2 MiB page cache
and `mmap_size` is left unset. Measured on the 100k-edge fixture with quotas
enabled, stock SQLite writer defaults yield `8,223 edges/sec` batched insert and
`3.89 ms` p95 (`27.53 ms` p99) single governed writes due to index cache spills
and mid-burst checkpoints, versus `16,383 edges/sec` and `2.53 ms` p95
(`2.86 ms` p99) with the 16 MiB writer-only budget.

## Security model

### Cross-org probing and same-org visibility

- **Caller-bound tenancy:** `org_id` always comes from the verified
  `Caller.org_id`. Tool argument structs use `#[serde(deny_unknown_fields)]`
  and never accept an `org_id` parameter. Unknown or suspended organizations
  are refused at `Registry::admit` before any handler runs.
- **Zero existence oracle across organizations:** Any lookup, traversal,
  shortest-path query, or edge write naming a `node_id`, `(kind, external_id)`,
  or `edge_id` that exists only in another organization returns the **exact
  same error or empty result** (`not_found` for point/endpoint queries, empty
  list for expansions) as an identifier that does not exist anywhere in the hub.
  Error text never discloses foreign counts, labels, or node kinds.
- **Same-org visibility without side channels:** For node kinds that carry
  sub-org visibility (`memory_note`, and any future restricted kind), the
  caller's visibility predicate runs inside every adjacency query **before**
  degree counts, hub cutoffs, PPR transition normalization, shortest-path
  expansion, and result caps. An outsider in the same organization receives
  identical output before and after hidden nodes and edges are added (the Step 4
  before/after invariant in [software-factory.md](software-factory.md)).

### Bounded traversal against DoS

- **Hard non-overridable caps:** Every read operation clamps or refuses bounds
  above its hard maximum (`max_hops ≤ 4`, `max_depth ≤ 6`, `seed_ids ≤ 20` / 50
  for PPR, `max_degree_per_node ≤ 200`, `max_visited_edges ≤ 10,000` / 25,000
  for PPR, `max_nodes ≤ 500`, `max_edges ≤ 1,000`, `max_iters ≤ 50`,
  `deadline_ms ≤ 2,000`). Write-time acyclicity checks enforce
  `CYCLE_CHECK_MAX_NODES = 1,000`, `CYCLE_CHECK_MAX_EDGES = 5,000`, and
  `CYCLE_CHECK_DEADLINE_MS = 50` ms, refusing `invalid_argument` with distinct
  reason codes `cycle_detected` (real cycle) vs `cycle_check_bound_exceeded`
  (any bound exceeded).
- **Cycle immunity:** All traversals track visited node IDs in memory; cyclic
  subgraphs cannot cause infinite recursion or exponential blowup.
- **Storage and payload caps:** Configurable per-organization quotas
  (`graph_max_nodes_per_org`, `graph_max_edges_per_org`, enforced in O(1) via
  `graph_org_counts`), per-node live-edge cap (`graph_max_live_edges_per_node`,
  default `5,000`, counting live outgoing + incoming edges on both endpoints and
  refusing with `node_edge_limit_exceeded`), JSON metadata byte limits (`8 KiB`
  on nodes, `4 KiB` on edges), `external_id` length limit (256), and standard
  policy rate limits on write tools.

### Who may create/mutate nodes and assert/retract edges

All graph reads and writes pass through `Registry::call` (profile → policy →
approval gate → typed arguments → handler → same-transaction ledger event).
Authority comes from `ua-org::authz` (identity and membership), never from a
session profile:

1. **No public `graph_node_upsert` tool; nodes are domain-owned per kind.**
   C1 exposes **no** public generic node-creation or node-upsert tool. Instead,
   `ua-graph` / `GraphRepo` exposes an internal
   `graph_node_ensure(org_id, kind, external_id, provenance)` primitive for
   **domain code paths only**: it creates the node row if absent (recording its
   immutable provenance) and touches nothing else if the row already exists.
   Both node creation and every mutable-field update (`visibility`, `team_id`,
   `owner_type`, `owner_id`, `display_label`, `meta_json`, `archived_at`) are
   domain-owned per node kind — `visibility`, `owner_*`, and `team_id` change
   only through the owning domain code path. This prevents forging `approval`,
   `policy_revision`, or `person` nodes and prevents flipping an existing
   `person`/`agent` node to `private` through a generic tool.
2. **Domain-owned edges cannot be forged via generic graph tools.** Edges
   representing governance, approvals, deliverables, team topology, memory
   entity indexing, memory evidence, or authoritative domain links
   (`approved_by`, `governed_by`, `reviewed_by`, `produces`, `executes`,
   `executed_by`, `delegates_to`, `reviews`, `escalates_to`, `can_observe`,
   `depends_on`, `subtask_of`, `serves_goal`, `goal_parent`, `delegated_to`,
   `uses_skill`, `promoted_from`, `supersedes`, `derives`, `mentions`,
   `evidence`) may be written **only** by their owning domain code path. Calling
   generic `graph_edge_assert` or `graph_edge_retract` with one of those kinds
   is refused (`domain_owned_edge`). In particular, `mentions` is strictly
   domain-owned by `ua-memory` / vault ingest (drives the memory graph leg's hub
   cutoff and PPR retrieval scores), and `evidence` is strictly domain-owned by
   `ua-memory` (`memory.evidence` is the single authority with owner-only
   `task:` refs; allowing generic assertions would bypass the owner rule and
   shift the memory graph leg).
3. **Generic assertions (`extends`, `contradicts` as `proposed`, `links_to`,
   `plan_tracks`):**
   - **Never create nodes:** `graph_edge_assert` never creates missing nodes;
     both endpoint nodes must already exist in the caller's organization
     (`org_id`), else the call returns `not_found` identically for missing and
     foreign-org endpoints (zero existence oracle). In C1, domain code paths and
     tests create nodes via internal `graph_node_ensure`.
   - Require a verified caller (`ActorKind::Human` or `ActorKind::Agent`) in
     the target organization; anonymous callers cannot write.
   - Until #2790 supplies immutable principal IDs, non-`'system'` writes for any
     organization other than `'default'` are refused (`principal_id_required`)
     in both `ua-tools` (`families/graph_store.rs`) and `GraphRepo` in
     `ua-store`.
   - Require read visibility on **both** endpoint nodes (prevents linking to or
     probing hidden records), and validate endpoint node kinds against the typed
     edge table (`invalid_endpoint_kind`).
   - Require `valid_from = asserted_at` (no caller-supplied backdating) and
     `valid_to IS NULL` on assert (`valid_to <= now` on retract).
   - Every write records `asserted_by` from the verified caller's `PrincipalId`
     (never caller-supplied).
4. **Retraction (`graph_edge_retract`, sets `valid_to = now`):**
   - Allowed only on generic-assertable edge kinds, for the original
     `asserted_by` principal, an `Authority::Operator` (`org_admin`+ once
     memberships land), or `Authority::LifecycleOperator` for fleet maintenance
     — all checked via `ua_org::authz::require` in `ua-tools`
     (`families/graph_store.rs`) before calling `ua-graph`.
   - Retracting another principal's edge as an operator records the retractor
     in the `agent.graph.edge_retracted` ledger event while leaving the edge's
     original `asserted_by` untouched.
5. **Profile exposure (C1):**
   - Read tools (`graph_node_get`, `graph_neighbors`, `graph_traverse`,
     `graph_shortest_path`, `graph_expand`) are `.read_only()` and exposed to
     standard read-capable profiles.
   - Write tools (`graph_edge_assert`, `graph_edge_retract`) are omitted from
     read-only profiles (`public`, `research`, `reviewer`) and remain subject to
     `approval_tools` and policy rules. There is no `graph_node_upsert` tool.

## Slices and gates

| Slice | Scope | Gate |
| --- | --- | --- |
| **C0** | This document (`docs/graph.md`). | CTO design read + independent diff read. No code. |
| **C1** | `GraphRepo` (SQLite) in `ua-store`, `crates/ua-graph`, `graph.v1` + `organization.v1.graph`, `org_classification.rs` entry, governed tools (`graph_node_get`, `graph_neighbors`, `graph_traverse`, `graph_shortest_path`, `graph_expand`, `graph_edge_assert`, `graph_edge_retract`), internal `graph_node_ensure`, isolation & DoS tests, benchmark harness meeting [Benchmark floor](#benchmark-floor-c1-acceptance-gate). | Independent review + benchmark floor + CI/Cloud Build green. |
| **C2** | Consumer migrations, one PR per consumer: `task_dependencies`, `task_goal_links`, Memory §4/§5 graph leg on `GraphRepo`, optional `vault_query` indexed PPR, `team_specs` topology projection. | Per-consumer parity + isolation tests. |
| **C3** | Dependency-driven workflow graph runner replacing YAML workflow engine and LangGraph surface. | Separate design amendment before code. |

**What C1 must not do:** no consumer rewrites, no `graph.links.v1`, no
`memory_links` / `memory_entities` tables, no `graph_node_upsert` public tool,
and no label-based identity in a non-default organization.

## Remaining open questions (C2 / CI details)

1. **Authoritative visibility for `memory_note` nodes in C2.** `graph_nodes`
   carries `visibility`, `team_id`, `owner_type`, and `owner_id` so graph
   queries work uniformly in C1. In C2, should `memory_note` visibility be read
   by joining `memory` directly in SQL (zero drift risk when a note narrows from
   `org` to `private`, at one PK join per candidate) or kept synchronized via an
   `AFTER UPDATE` trigger on `memory` in the same write transaction?
2. **CI benchmark enforcement.** Shared CI runners have variable CPU timing.
   Confirm whether CI should run a smaller deterministic smoke fixture (for
   example 10k edges + super-hub DoS + B4 cycle-check bound) while the full
   100k-edge floor is verified on a pinned local/Cloud Build run and recorded
   in the C1 PR.

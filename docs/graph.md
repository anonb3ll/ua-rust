# Graph store

Status: **design, not implemented.** Scope: track C, slice C0 (#2717). This
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
| `produces` | `run \| task → deliverable` | Directed | M:N | 1 commit deliverable per task | Lineage | `deliverables` |
| `uses_skill` | `agent \| run → skill` | Directed | M:N | — | Lineage / topical | `skill_registry` / `dispatch` |
| `reviewed_by` | `deliverable → agent \| person` | Directed | M:N | Self-review refused by domain layer | Lineage | `continuity` / review gate |
| `approved_by` | `deliverable \| run → person` | Directed | M:N | Verified human; cites `approval` / event seq | Lineage | `approvals` / `policy_authorizations` |
| `governed_by` | `approval \| run → policy_revision` | Directed | N:1 | Immutable policy binding | Lineage | `approvals` / `policy` |
| `delegates_to` | `agent → agent` | Directed | M:N | Acyclic within team, no self-loop | Topical | `ua-org` (`team_specs` projection) |
| `reviews` | `agent → agent` | Directed | M:N | No self-loop | Topical | `ua-org` (`team_specs` projection) |
| `escalates_to` | `agent → agent \| person` | Directed | M:N | Acyclic, no self-loop | Topical | `ua-org` (`team_specs` projection) |
| `can_observe` | `agent → agent` | Directed | M:N | No self-loop | Topical | `ua-org` (`team_specs` projection) |
| `mentions` | `memory_note \| vault_note → memory_entity` | Directed | M:N | Max 64 live entities per `memory_note` | Topical | `ua-memory` / vault ingest |
| `links_to` | `vault_note → vault_note` | Directed (`[[wikilink]]`; walked undirected in PPR) | M:N | No self-loop | Topical | `vault` ingest / governed tool |
| `promoted_from` | `vault_note ↔ memory_note` | Directed (derived → source) | M:N | No self-loop | Lineage | `vault` (`promote` / `ingest`) |
| `supersedes` | `memory_note → memory_note` | Directed (newer → older) | M:N | No self-loop | Lineage | `ua-memory` (`memory.superseded_by`) |
| `contradicts` | `memory_note → memory_note` | Directed as asserted; queried bidirectionally | M:N | No self-loop; supports `state = 'proposed'` | Topical | `ua-memory` / contradiction workbench |
| `evidence` | `memory_note → memory_note \| task \| run \| deliverable` | Directed | M:N | No self-loop | Lineage | `ua-memory` (`memory.evidence`) |
| `extends` | `memory_note → memory_note` | Directed | M:N | No self-loop | Topical | `ua-memory` or governed `graph_edge_assert` |
| `derives` | `memory_note → memory_note` | Directed (source → summary, per [memory.md](memory.md) §4) | M:N | No self-loop | Lineage | `ua-memory` (`memory_consolidate_commit`) |

Cardinality constraints marked `N:1` are enforced in SQLite by a partial unique
index over live rows (`WHERE valid_to IS NULL`). Acyclicity constraints
(`depends_on`, `subtask_of`, `goal_parent`, `delegates_to`, `escalates_to`) are
enforced in the write transaction before insert by a bounded reachability check
within `org_id` (the same check `dependency_add` runs today).

## Provenance and temporal validity

### Edge provenance

Every row in `graph_edges` carries mandatory, immutable provenance columns:

| Column | Type | Meaning |
| --- | --- | --- |
| `asserted_by` | `TEXT NOT NULL` | **Immutable principal ID** of the actor that asserted the edge (stable agent ID, node ID, or user ID — never a mutable display label). `'system'` is used only for hub-internal deterministic projections (schema backfills, mirrors). |
| `asserted_by_kind` | `TEXT NOT NULL` | One of `'agent'`, `'person'`, `'node'`, `'system'`. |
| `asserted_at` | `TEXT NOT NULL` | RFC 3339 UTC timestamp (`+00:00`) when the hub recorded the assertion. |
| `source_kind` | `TEXT NOT NULL` | One of `'tool'`, `'event'`, `'mirror'`, `'import'`. |
| `source_ref` | `TEXT NOT NULL` | Concrete source identifier: `event:<seq>` (preferred when recorded in the same write transaction), `tool:<tool_name>:<call_id>`, `mirror:<table>:<pk>`, or `import:<source_hash>`. |
| `assertion_scope` | `TEXT NOT NULL DEFAULT ''` | Optional scope distinguishing independent assertions of the same `(src_id, dst_id, kind)` — for example `note:<note_id>` when multiple memory notes independently assert the same topical link so the edge stays live until every asserting note retires ([memory.md](memory.md) §4). Empty string `''` for structural edges. |

**Identity transition.** Immutable agent and node IDs land under the
organization-local identity track (hub #2790, gated on the #2794 identity
contract). C1 represents `asserted_by` through a dedicated `PrincipalId` type
in `ua-graph` rather than raw label strings, so once `Caller` carries stable
principal IDs, `ua-graph` records them directly with no schema change. If C1
ships ahead of #2790, a single-org `'default'` transition rule is explicitly
tracked in [Open questions](#open-questions) (#2) so mutable labels never leak
into multi-org rows.

**Ledger linkage.** Every edge assertion and retraction appends an
`agent.graph.edge_asserted` or `agent.graph.edge_retracted` event to `event_log`
in the same write transaction, and records `source_kind = 'event'`,
`source_ref = 'event:<seq>'` (or the enclosing domain event's `seq` for mirrored
domain writes).

### Validity and `as_of` reads

Every edge carries a half-open validity interval `[valid_from, valid_to)` in
normalized RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SS+00:00`, matching
`ua_core::time::now()`):

- `valid_from TEXT NOT NULL`: defaults to `asserted_at` when not supplied.
- `valid_to TEXT`: `NULL` while the edge is currently valid. Retracting,
  expiring, or retiring an edge sets `valid_to` (once) rather than deleting the
  row, so historical traversals remain reproducible.
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

**Lineage vs topical edges.** Following [memory.md](memory.md) §4, topical
retirement (superseding, invalidating, or narrowing an asserting note) sets
`valid_to` only on **topical** edges (`extends`, `mentions`, accepted
`contradicts`, `links_to`, etc.). **Lineage** edges (`supersedes`, `derives`,
`evidence`, `produces`, `executes`, `executed_by`, `approved_by`,
`governed_by`, `promoted_from`) are never closed by topical retirement, keeping
audit and provenance traces walkable.

Re-asserting a previously closed edge inserts a new row with a new ULID,
`valid_from`, and provenance; the partial unique index (`WHERE valid_to IS NULL`)
permits historical rows while guaranteeing at most one currently live row per
`(org_id, src_id, dst_id, kind, assertion_scope)`.

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
  (matching `ua-deliverables` and `ua-memory`, enforced by a
  `crates/ua-graph/tests/dependencies.rs` guard test).
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

### DDL (`graph.v1`)

```sql
CREATE TABLE IF NOT EXISTS graph_nodes (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN (
                      'agent','person','skill','memory_note','memory_entity',
                      'task','goal','plan','run','deliverable','vault_note',
                      'approval','policy_revision'
                  )),
    external_id   TEXT NOT NULL CHECK (length(external_id) BETWEEN 1 AND 256),
    display_label TEXT CHECK (display_label IS NULL OR length(display_label) <= 256),
    visibility    TEXT NOT NULL DEFAULT 'org'
                  CHECK (visibility IN ('private','team','org')),
    team_id       TEXT,
    owner_type    TEXT CHECK (owner_type IS NULL OR owner_type IN ('human','agent','org')),
    owner_id      TEXT,
    meta_json     TEXT NOT NULL DEFAULT '{}'
                  CHECK (json_valid(meta_json) AND length(meta_json) <= 8192),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    archived_at   TEXT,
    UNIQUE (org_id, kind, external_id),
    UNIQUE (org_id, id),
    CHECK (visibility != 'team' OR team_id IS NOT NULL),
    CHECK (visibility != 'private' OR (owner_type IS NOT NULL AND owner_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_org_kind_vis
    ON graph_nodes (org_id, kind, visibility, team_id, owner_id)
    WHERE archived_at IS NULL;

CREATE TRIGGER IF NOT EXISTS graph_nodes_identity_immutable
BEFORE UPDATE OF kind, external_id, created_at ON graph_nodes
BEGIN
    SELECT RAISE(ABORT, 'graph node kind, external_id and created_at are immutable');
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

CREATE TRIGGER IF NOT EXISTS graph_edges_provenance_immutable
BEFORE UPDATE OF src_id, dst_id, kind, assertion_scope,
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

Following `OrgRepo` ([organization.md](organization.md)) and `MemoryRepo`
([memory.md](memory.md)), storage access sits behind a synchronous `GraphRepo`
trait exposing plain Rust domain types (zero `rusqlite` types in the public
signature) so writes run inside the hub's existing write transaction and commit
atomically with `ledger::append`. Traversal algorithms (`k_hop`, bidirectional
`shortest_path`, `seed_expand` PPR) live in `ua-graph` and call `GraphRepo` for
bounded, org- and visibility-filtered adjacency reads.

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
| `task_dependencies` | `crates/ua-tools/src/families/core_schema.rs:46`, `tasks/graph.rs` | Explicit task prerequisite DAG (`dependency_add`, `dependency_list`, `dependency_remove`) with CTE cycle check and creator-only delete. | Unchanged | **Move in C2** to `graph_edges(kind = 'depends_on')` behind the existing `dependency_*` tool contract (same JSON shapes and errors). Creator check migrates from `created_by` label to `asserted_by` stable principal ID once #2790 lands. |
| `task_goal_links` | `crates/ua-tools/src/families/tasks/mod.rs:93`, `tasks/goals.rs` | Single goal a task serves (`goal_manage` `link`/`unlink`/`ancestry`). | Unchanged | **Move in C2** to `graph_edges(kind = 'serves_goal')`, keeping N:1 uniqueness via `idx_graph_edges_single_out_live` and preserving the `goal_manage` contract. |
| `goals.parent_goal_id` | `crates/ua-tools/src/families/tasks/mod.rs:84` | Why-chain tree column (max depth 8). | Unchanged | **Stays** authoritative on `goals`; optional read-only mirror to `goal_parent` in C2 if cross-domain traversals need it. |
| `graph_canvas_scenes`, `graph_canvas_revisions` | `crates/ua-tools/src/families/graph.rs` | Excalidraw scene blob store + deterministic parser emitting `task_suggestions` and `dependency_suggestions` (**proposals only**). | Unchanged | **Stays as-is.** Canvas scenes are visual documents, never an authoritative edge store. Post-C2 UI/tools may render a `ua-graph` subgraph onto a board, while human-approved proposals still create real edges through domain tools. |
| `memory_entities`, `memory_links` | `crates/ua-tools/src/families/export.rs:586` (`GRAPH_TABLES`), [memory.md](memory.md) §4–§5 | Not yet created in `ua-memory`; `export.rs` checks `has_table()` for Python-hub migration manifests. | Unchanged | **Converge in C2** (or adopt `ua-graph` directly if C1 lands ahead of Memory §4 — see [Alignment with memory.md step 5](#alignment-with-memorymd-step-5)). `export.rs::GRAPH_TABLES` reads from `ua-graph` (or a compatibility view) so migration manifests stay backward-compatible. |
| `vault_query` (`[[wikilink]]` PPR) | `crates/ua-tools/src/families/vault/query.rs` | On-the-fly disk walk + undirected Personalized PageRank over markdown files. | Unchanged | **Stays disk-authoritative in C1.** In C2+ (with track B9 content-hash vault ingest), `vault_query` can read indexed `vault_note` / `links_to` rows through `seed_expand`, keeping the disk walk as fallback for unindexed vaults. |
| Relational FKs (`tasks.parent_id`, `deliverables.task_id`, `delegations.task_id`, `task_hold_members`, `plan_steps.plan_id`) | Their owning families | Core relational invariants enforced by owning tables. | Unchanged | **Stay authoritative** on their owning tables; projected into `graph_edges` (`subtask_of`, `produces`, `delegated_to`) only where cross-domain traversal or G3 provenance needs them. |
| Team-spec topology (`delegates_to`, `reviews`, `escalates_to`, `can_observe`) | [organization.md](organization.md) (`team_specs`) | Enforced seat interaction rules inside append-only canonical JSON specs. | Unchanged | **Authoritative in `team_specs`**; projected into `graph_edges` on spec commit in C2+ for graph queries and visualization, never editable directly via `graph_edge_assert`. |

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

### Reconciliation points with `memory.md` (flagged without modifying `memory.md`)

1. **Single vs second edge store:** [memory.md](memory.md) §4 currently defines
   dedicated `memory_entities` and `memory_links` tables in `memory.links.v1`.
   Roadmap §7.3(4) calls for deciding on the unified graph store before a second
   edge store is built. If C1 lands before Memory §4, Memory §4 can write
   directly through `GraphRepo` (avoiding duplicate tables); if Memory §4 lands
   first, C2 converges them behind `GraphRepo` and retires the duplicate tables.
2. **Meaning of `asserted_by`:** In `memory.md` §4, `memory_links.asserted_by`
   is the *asserting note ID* (so two notes asserting the same edge keep it live
   until both retire) and `actor` is a nullable label string. In `ua-graph`,
   `asserted_by` is always the *stable principal ID* (never a label), and
   note-level assertion ownership moves to `assertion_scope = 'note:<note_id>'`.
   Both invariants are preserved without overloading one column.
3. **Hard delete on mirror update vs append-only `valid_to`:** `memory.md` §4's
   `memory_links_mirror_supersedes` trigger `DELETE`s an old mirrored edge when
   `memory_restore` clears `superseded_by`. Under `graph_edges_no_delete`,
   clearing an authoritative link instead stamps `valid_to = now`, hiding it
   from live reads while preserving `as_of` history.
4. **Crate dependency boundary:** `crates/ua-memory/tests/boundary.rs` restricts
   `ua-memory`'s workspace dependencies. Placing the `GraphRepo` trait and its
   SQLite implementation in `ua-store` lets `ua-memory` consume the shared graph
   store without adding a crate dependency between `ua-memory` and `ua-graph`.

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
  - **2 organizations:** 90,000 live edges in org A and 10,000 live edges in
    org B, exercising `org_id` index selectivity on every read.
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
| Single governed edge write | 1 edge + `ledger::append` in one write transaction | **≤ 3 ms p95** |
| 2-hop `k_hop` (100k edges) | 3 seeds, `max_hops = 2`, `max_degree_per_node = 50`, `max_nodes = 100`, `as_of` active, org-fenced | **≤ 15 ms p95** (≤ 25 ms p95 with `memory_note` sub-org visibility filter) |
| `seed_expand` PPR (100k edges) | 5 seeds, 2-hop bounded subgraph (≤5,000 nodes, ≤25,000 edges), `damping = 0.85`, `max_iters = 30`, `eps = 1e-6`, `max_results = 10` | **≤ 40 ms p95** (≤ 20 ms p95 on exact ≤5k-node subgraphs) |
| `shortest_path` (100k edges) | Bidirectional BFS, `max_depth = 4`, `max_expanded_edges = 10,000` | **≤ 15 ms p95** |
| Super-hub DoS probe | `k_hop` (`max_hops = 3`) and `seed_expand` seeded directly on a 2,000-edge super-hub | **≤ 50 ms p95**, bounded memory, `truncated = true` |

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
  `deadline_ms ≤ 2,000`).
- **Cycle immunity:** All traversals track visited node IDs in memory; cyclic
  subgraphs cannot cause infinite recursion or exponential blowup.
- **Storage and payload caps:** Configurable per-organization quotas
  (`graph_max_nodes_per_org`, `graph_max_edges_per_org`), JSON metadata byte
  limits (`8 KiB` on nodes, `4 KiB` on edges), `external_id` length limit (256),
  and standard policy rate limits on write tools.

### Who may assert and retract edges

All graph reads and writes pass through `Registry::call` (profile → policy →
approval gate → typed arguments → handler → same-transaction ledger event).
Authority comes from `ua-org::authz` (identity and membership), never from a
session profile:

1. **Domain-owned edges cannot be forged via generic graph tools.** Edges
   representing governance, approvals, deliverables, team topology, or
   authoritative domain links (`approved_by`, `governed_by`, `reviewed_by`,
   `produces`, `executes`, `executed_by`, `delegates_to`, `reviews`,
   `escalates_to`, `can_observe`, `depends_on`, `serves_goal`, `supersedes`,
   `derives`) may be written **only** by their owning domain code path. Calling
   generic `graph_edge_assert` or `graph_edge_retract` with one of those kinds
   is refused (`domain_owned_edge`).
2. **Generic assertions (`extends`, `evidence`, `contradicts` as `proposed`,
   `mentions`, `links_to`, `plan_tracks`):**
   - Require a verified caller (`ActorKind::Human` or `ActorKind::Agent`) in
     the target organization; anonymous callers cannot write.
   - Require read visibility on **both** endpoint nodes (prevents linking to or
     probing hidden records).
   - Every write records `asserted_by` from the verified caller's immutable
     principal ID (never caller-supplied).
3. **Retraction (`graph_edge_retract`, sets `valid_to`):**
   - Allowed for the original `asserted_by` principal, an `Authority::Operator`
     (`org_admin`+ once memberships land), or `Authority::LifecycleOperator`
     for fleet maintenance — all checked via `ua_org::authz::require` in the
     edge's organization.
   - Retracting another principal's edge as an operator records the retractor
     in the `agent.graph.edge_retracted` ledger event while leaving the edge's
     original `asserted_by` untouched.
4. **Profile exposure (C1):**
   - Read tools (`graph_node_get`, `graph_neighbors`, `graph_traverse`,
     `graph_shortest_path`, `graph_expand`) are `.read_only()` and exposed to
     standard read-capable profiles.
   - Write tools (`graph_node_upsert`, `graph_edge_assert`,
     `graph_edge_retract`) are omitted from read-only profiles (`public`,
     `research`, `reviewer`) and remain subject to `approval_tools` and policy
     rules.

## Slices and gates

| Slice | Scope | Gate |
| --- | --- | --- |
| **C0** | This document (`docs/graph.md`). | Architecture review and independent diff read. No code. |
| **C1** | `crates/ua-graph`, `GraphRepo` (SQLite), `graph.v1` + `organization.v1.graph`, `org_classification.rs` entry, governed tools, isolation & DoS tests, benchmark harness meeting [Benchmark floor](#benchmark-floor-c1-acceptance-gate). Rewrites zero existing consumers. | Independent review + benchmark floor + CI/Cloud Build green. |
| **C2** | Consumer migrations, one PR per consumer: `task_dependencies`, `task_goal_links`, Memory §4/§5 graph leg convergence, optional `vault_query` indexed PPR, `team_specs` topology projection. | Per-consumer parity + isolation tests. |
| **C3** | Dependency-driven workflow graph runner replacing YAML workflow engine and LangGraph surface. | Separate design amendment before code. |

## Open questions

Resolve these before C1 implementation starts:

1. **Memory §4/§5 convergence order (roadmap §7.3(4)).** Should Memory v2
   (#2683 / #2799) adopt `ua-graph` directly for its entity/link store (if C1
   lands ahead of Memory §4), or ship `memory_entities` / `memory_links` first
   and converge onto `ua-graph` in C2?
2. **Pre-#2790 `asserted_by` representation in C1.** Immutable agent/node IDs
   (#2790) wait on the #2794 identity contract. Should C1 block until `Caller`
   carries stable principal IDs, or ship C1 behind a typed `PrincipalId` wrapper
   that is default-org-only until #2790 lands and backfills `'default'` rows
   when stable IDs arrive?
3. **Where `GraphRepo` lives.** Placing the `GraphRepo` trait and its SQLite
   implementation in `ua-store` (beside `OrgRepo` and `MemoryRepo`) lets
   `ua-memory` and `ua-org` call it in C2 without loosening their crate boundary
   tests; `ua-graph` then holds domain types, validation, and traversal
   algorithms (`k_hop`, `shortest_path`, `seed_expand`). Confirm this split vs
   keeping `GraphRepo` inside `ua-graph`.
4. **Authoritative visibility for `memory_note` nodes.** `graph_nodes` carries
   `visibility`, `team_id`, `owner_type`, and `owner_id` so graph queries work
   uniformly in C1. In C2, should `memory_note` visibility be read by joining
   `memory` directly in SQL (zero drift risk when a note narrows from `org` to
   `private`, at one PK join per candidate) or kept synchronized via an
   `AFTER UPDATE` trigger on `memory` in the same write transaction?
5. **Append-only closure (`valid_to`) vs hard delete on `memory_restore`.**
   When `memory_restore` clears `superseded_by`, `memory.md` §4's mirror
   trigger currently deletes the mirrored edge. Confirm that closing with
   `valid_to = now` (preserving `as_of` history under `graph_edges_no_delete`)
   is the intended behavior once converged.
6. **CI benchmark enforcement.** Shared CI runners have variable CPU timing.
   Confirm whether CI should run a smaller deterministic smoke fixture (for
   example 10k edges + super-hub DoS bound) while the full 100k-edge floor is
   verified on a pinned local/Cloud Build run and recorded in the PR.
